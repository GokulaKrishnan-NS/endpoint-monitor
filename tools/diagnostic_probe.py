"""
End-to-End Diagnostic Probe for the Endpoint Security Monitor.

The probe starts the real monitoring engine, launches a harmless long running
child process that carries a unique marker in its command line and verifies
the complete observation pipeline:

  1. process creation
  2. collection through polling (and the Windows event log when enabled)
  3. process identity / metadata normalization
  4. parent and ancestry resolution
  5. command detector invocation
  6. risk calculation
  7. event ingestion and de-duplication
  8. alert generation (only when the input actually warrants one)
  9. GUI / event history delivery
 10. clean shutdown and resource cleanup

The probe never downloads or executes a payload.  A benign process being
*visible* does not imply that a security *alert* must be produced - the two
are asserted separately.

Usage:
    python tools/diagnostic_probe.py [--config config/config.json] [--wait 20]
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.ui.engine import MonitoringEngine  # noqa: E402


LONG_LIVED_MARKER = "ESM_AUDIT_2026"
SHORT_LIVED_MARKER = "ESM_AUDIT_SHORT_2026"


def launch_probe_child(marker: str, lifetime_seconds: int = 45) -> subprocess.Popen:
    """Launch a harmless, long running child process carrying the marker."""
    command = [
        sys.executable,
        "-c",
        f"import time; time.sleep({int(lifetime_seconds)})",
        marker,
    ]
    return subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def launch_short_lived_child(marker: str) -> subprocess.Popen:
    """Launch a child process that exits immediately."""
    command = [sys.executable, "-c", "pass", marker]
    return subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _find_marker_process(engine: MonitoringEngine, marker: str) -> Optional[Dict[str, Any]]:
    """Return the process snapshot entry that carries the marker."""
    for proc in engine.get_processes_snapshot().values():
        cmdline = proc.get("cmdline") or []
        if any(marker in str(part) for part in cmdline):
            return proc
    return None


def _find_marker_event(engine: MonitoringEngine, marker: str):
    """Return the evaluated event for the marker process (if any)."""
    for event in engine.get_events_snapshot():
        cmdline = event.command_line or []
        if any(marker in str(part) for part in cmdline):
            return event
    return None


def run_probe(
    config_path: str = "config/config.json",
    poll_interval: float = 1.0,
    wait_seconds: float = 20.0,
    lifetime_seconds: int = 45,
    include_short_lived: bool = True,
) -> Dict[str, Any]:
    """
    Run the complete diagnostic probe and return a structured report.

    Every entry in ``report["checks"]`` is either ``True`` (verified),
    ``False`` (failed) or ``None`` (not applicable in this environment).
    """
    checks: Dict[str, Optional[bool]] = {
        "process_visible_via_polling": False,
        "identity_has_creation_time": None,
        "parent_resolved": None,
        "command_detector_invoked": False,
        "risk_calculated": False,
        "event_ingested": False,
        "event_history_contains_process": False,
        "no_false_alert_for_benign_process": False,
        "short_lived_captured_by_telemetry": None,
        "engine_stopped_cleanly": False,
    }
    details: Dict[str, Any] = {}

    baseline_dir = tempfile.mkdtemp(prefix="esm-probe-baseline-")
    baseline_path = os.path.join(baseline_dir, "baseline.json")

    engine = MonitoringEngine(
        config_path=config_path,
        poll_interval=poll_interval,
        baseline_path=baseline_path,
    )

    child: Optional[subprocess.Popen] = None
    short_child: Optional[subprocess.Popen] = None

    try:
        engine.start()

        # ------------------------------------------------------------------
        # Long running child process
        # ------------------------------------------------------------------
        child = launch_probe_child(LONG_LIVED_MARKER, lifetime_seconds)
        details["child_pid"] = child.pid

        deadline = time.time() + wait_seconds
        observed_proc = None
        event = None
        while time.time() < deadline:
            if not observed_proc:
                observed_proc = _find_marker_process(engine, LONG_LIVED_MARKER)
            if not event:
                event = _find_marker_event(engine, LONG_LIVED_MARKER)
            if observed_proc and event and event.metadata.get("command_detector_invoked") is not None:
                break
            time.sleep(0.1)

        checks["process_visible_via_polling"] = observed_proc is not None
        details["observed_process"] = (
            {
                "pid": observed_proc.get("pid"),
                "ppid": observed_proc.get("ppid"),
                "name": observed_proc.get("name"),
                "parent_name": observed_proc.get("parent_name"),
                "create_time": observed_proc.get("create_time"),
            }
            if observed_proc
            else None
        )

        if observed_proc:
            checks["identity_has_creation_time"] = observed_proc.get("create_time") is not None
            checks["parent_resolved"] = bool(observed_proc.get("parent_name"))
        else:
            checks["identity_has_creation_time"] = False
            checks["parent_resolved"] = False

        checks["event_ingested"] = event is not None

        if event is not None:
            detector_invoked = bool(event.metadata.get("command_detector_invoked", False))
            engine_invocations = engine.get_command_detector_invocations()
            checks["command_detector_invoked"] = detector_invoked and (engine_invocations > 0)
            checks["risk_calculated"] = event.risk_score >= 0
            details["observed_event"] = {
                "event_type": event.event_type,
                "source": event.source,
                "severity": event.severity,
                "risk_score": event.risk_score,
                "risk_level": event.risk_level,
                "indicators": list(event.indicators),
                "command_detector_invoked": detector_invoked,
            }
        else:
            checks["command_detector_invoked"] = False
            checks["risk_calculated"] = False
            details["observed_event"] = None

        alerts = [
            alert
            for alert in engine.get_alerts_snapshot()
            if alert.pid is not None and observed_proc and alert.pid == observed_proc.get("pid")
        ]
        # A benign process must be visible without producing a security alert.
        checks["no_false_alert_for_benign_process"] = len(alerts) == 0 if observed_proc else False
        details["alerts_for_probe_process"] = len(alerts)

        # Event history delivery (the mechanism the GUI consumes)
        checks["event_history_contains_process"] = event is not None
        queue_events = engine.poll_new_events(max_items=500)
        details["queued_events_delivered"] = len(queue_events)

        # ------------------------------------------------------------------
        # Short lived child process
        # ------------------------------------------------------------------
        telemetry_status = engine.get_process_telemetry_status()
        details["process_telemetry"] = telemetry_status

        if include_short_lived:
            short_child = launch_short_lived_child(SHORT_LIVED_MARKER)
            short_deadline = time.time() + max(2.0, poll_interval * 2)
            short_observed = None
            short_event = None
            while time.time() < short_deadline:
                if not short_observed:
                    short_observed = _find_marker_process(engine, SHORT_LIVED_MARKER)
                if not short_event:
                    short_event = _find_marker_event(engine, SHORT_LIVED_MARKER)
                if short_observed or short_event:
                    break
                time.sleep(0.1)
            details["short_lived_observed_via_polling"] = short_observed is not None
            details["short_lived_event_ingested"] = short_event is not None

            if telemetry_status.get("enabled") and telemetry_status.get("status") == "AVAILABLE":
                # The event source is active: a short lived process must be
                # captured through the event driven path.
                checks["short_lived_captured_by_telemetry"] = short_event is not None
            else:
                # Not verifiable without an enabled and accessible event source.
                checks["short_lived_captured_by_telemetry"] = None
        else:
            checks["short_lived_captured_by_telemetry"] = None

    finally:
        # ------------------------------------------------------------------
        # Clean shutdown and resource cleanup
        # ------------------------------------------------------------------
        for proc in (short_child, child):
            if proc is None:
                continue
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

        engine.stop(timeout=2.0)
        checks["engine_stopped_cleanly"] = engine.status == "STOPPED"

        try:
            import shutil

            shutil.rmtree(baseline_dir, ignore_errors=True)
        except Exception:
            pass

    report: Dict[str, Any] = {
        "marker": LONG_LIVED_MARKER,
        "checks": checks,
        "details": details,
        "passed": all(value is not False for value in checks.values()),
    }
    return report


def format_report(report: Dict[str, Any]) -> str:
    """Render the probe report as human readable text."""
    lines = [
        "=" * 74,
        "ENDPOINT SECURITY MONITOR - END-TO-END DIAGNOSTIC PROBE",
        "=" * 74,
        f" Marker: {report['marker']}",
        "",
        " Checks:",
    ]

    for name, value in report["checks"].items():
        if value is True:
            status = "PASS"
        elif value is False:
            status = "FAIL"
        else:
            status = "SKIP"
        lines.append(f"   [{status}] {name}")

    lines.append("")
    lines.append(" Details:")
    lines.append(json.dumps(report["details"], indent=2, default=str))
    lines.append("=" * 74)
    lines.append(f" RESULT: {'PASSED' if report['passed'] else 'FAILED'}")
    lines.append("=" * 74)

    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    """Command line entry point for the diagnostic probe."""
    parser = argparse.ArgumentParser(description="Endpoint Security Monitor diagnostic probe")
    parser.add_argument("--config", default="config/config.json", help="Configuration file")
    parser.add_argument("--wait", type=float, default=20.0, help="Seconds to wait for visibility")
    parser.add_argument("--poll-interval", type=float, default=1.0, help="Engine poll interval")
    args = parser.parse_args(argv)

    report = run_probe(
        config_path=args.config,
        poll_interval=args.poll_interval,
        wait_seconds=args.wait,
    )

    print(format_report(report))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())

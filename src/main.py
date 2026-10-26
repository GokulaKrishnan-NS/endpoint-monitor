import os
import sys

# Ensure root project directory is in sys.path when script is executed directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import json
import time

from src.alerts.alert_manager import show_alert
from src.analysis.process_tree import ProcessTree, ProcessTreeAnalyzer
from src.baseline.baseline_engine import BaselineEngine
from src.detectors.command_detector import detect_command_indicators
from src.detectors.risk_detector import calculate_risk
from src.models.event import Event
from src.monitors.network_monitor import NetworkMonitor
from src.monitors.process_monitor import (
    ProcessIdentityRegistry,
    get_new_processes,
    get_running_processes,
)
from src.monitors.resource_monitor import ResourceMonitor
from src.monitors.sysmon_telemetry import (
    SysmonNetworkRecord,
    SysmonProcessRecord,
    SysmonTelemetryCollector,
    SysmonTelemetryCorrelator,
    SysmonTelemetryStatus,
)
from src.monitors.windows_process_telemetry import (
    ProcessTelemetryCorrelator,
    TelemetryStatus,
    WindowsProcessTelemetryCollector,
)
from src.enforcement.windows_firewall import WindowsFirewallEnforcer
from src.ui.cli import run_cli_loop
from src.ui.dashboard import SecurityDashboardApp, is_gui_available
from src.ui.engine import MonitoringEngine
from src.utils.logger import setup_logger


def process_event_from_dict(process_info, process_tree=None, tree_analyzer=None):
    """
    Construct a standardized Event object from raw process dictionary,
    resolve hierarchical process-tree lineage, run command indicator analysis,
    evaluate suspicious parent-child relationships, and score combined risk.
    """
    event = Event.from_process_info(process_info)

    # 1. Analyze command line for suspicious indicators
    event.indicators = detect_command_indicators(event.command_line)

    # 2. Process Tree Analysis
    if tree_analyzer is None:
        tree_analyzer = ProcessTreeAnalyzer()

    tree_analysis = tree_analyzer.analyze_process(process_info, process_tree)
    event.metadata["process_tree"] = tree_analysis

    # Incorporate process-tree indicators (e.g. suspicious_process_lineage)
    for ind in tree_analysis.get("indicators", []):
        if ind not in event.indicators:
            event.indicators.append(ind)

    # 3. Calculate overall risk using command indicators, process context, and tree findings
    risk_result = calculate_risk(
        event.indicators,
        process_info,
        tree_findings=tree_analysis.get("findings"),
    )

    event.risk_score = risk_result["score"]
    event.risk_level = risk_result["level"]
    event.risk_reasons = risk_result["reasons"]
    event.severity = risk_result["level"]

    return event


def report_suspicious_event(event, logger):
    """
    Print and log a standardized suspicious process event, including
    process-tree lineage and hierarchy visualization if present.
    """
    message = (
        f"Suspicious process detected | "
        f"PID: {event.pid} | "
        f"Process: {event.process_name} | "
        f"Parent: {event.parent_process_name} | "
        f"Risk: {event.risk_level} | "
        f"Score: {event.risk_score}"
    )

    print("\n" + "=" * 60)
    print(message)

    # Display Process Tree Visualization if available
    tree_meta = event.metadata.get("process_tree", {})
    if tree_meta.get("tree_rendered"):
        print("Process Lineage Tree:")
        print(tree_meta["tree_rendered"])

    print("Indicators:")
    for indicator in event.indicators:
        print(f"  - {indicator}")

    print("Reasons:")
    for reason in event.risk_reasons:
        print(f"  - {reason}")

    print("=" * 60)

    logger.warning(message)

    if tree_meta.get("lineage"):
        lineage_str = " -> ".join(tree_meta["lineage"])
        logger.warning(f"Process Lineage: {lineage_str}")

    for reason in event.risk_reasons:
        logger.warning(f"Reason: {reason}")


def report_suspicious_network_event(event, logger):
    """
    Print and log a standardized suspicious network connection event.
    """
    net_info = event.network_info or {}
    remote_addr = net_info.get("remote_address") or "N/A"
    local_addr = net_info.get("local_address") or "N/A"
    protocol = net_info.get("protocol") or "TCP"

    message = (
        f"Suspicious network connection detected | "
        f"PID: {event.pid} | "
        f"Process: {event.process_name} | "
        f"Protocol: {protocol} | "
        f"Local: {local_addr} | "
        f"Remote: {remote_addr} | "
        f"Risk: {event.risk_level} | "
        f"Score: {event.risk_score}"
    )

    print("\n" + "@" * 60)
    print(message)

    print("Indicators:")
    for indicator in event.indicators:
        print(f"  - {indicator}")

    print("Reasons:")
    for reason in event.risk_reasons:
        print(f"  - {reason}")

    print("@" * 60)

    logger.warning(message)
    for reason in event.risk_reasons:
        logger.warning(f"Network Anomaly Reason: {reason}")


def report_behavioral_anomaly(event, anomaly_result, logger):
    """
    Print and log a behavioral baseline anomaly event.
    """
    message = (
        f"Behavioral Anomaly detected | "
        f"PID: {event.pid} | "
        f"Process: {event.process_name} | "
        f"Parent: {event.parent_process_name} | "
        f"Anomaly Level: {anomaly_result['anomaly_level']} | "
        f"Anomaly Score: {anomaly_result['anomaly_score']}"
    )

    print("\n" + "!" * 60)
    print(message)

    print("Behavioral Deviation Reasons:")
    for reason in anomaly_result["reasons"]:
        print(f"  - {reason}")

    print("!" * 60)

    logger.warning(message)
    for reason in anomaly_result["reasons"]:
        logger.warning(f"Baseline Anomaly Reason: {reason}")


def run_single_scan(logger):
    """Execute a single-pass initial security snapshot scan."""
    print("Endpoint Security Monitor started.")
    logger.info("Endpoint Security Monitor started.")
    show_alert("System initialized successfully.")

    # Initialize components
    baseline_engine = BaselineEngine()
    tree_analyzer = ProcessTreeAnalyzer()
    network_monitor = NetworkMonitor(logger=logger)
    resource_monitor = ResourceMonitor(logger=logger)

    # Resource Monitoring initial check
    resource_result = resource_monitor.check_resources()
    cpu_metrics = resource_result["metrics"]["cpu"]
    mem_metrics = resource_result["metrics"]["memory"]
    print(
        f"System Resources: CPU: {cpu_metrics['percent']:.1f}% | "
        f"Memory: {mem_metrics['formatted']}"
    )
    logger.info(
        f"System resources initial check - CPU: {cpu_metrics['percent']:.1f}%, "
        f"Memory: {mem_metrics['formatted']}"
    )

    # Process Monitoring initial scan
    processes = get_running_processes()
    print(f"Monitoring {len(processes)} running processes.")
    logger.info(f"Process monitor detected {len(processes)} running processes.")

    # Build hierarchical Process Tree from initial snapshot
    process_tree = ProcessTree.build(processes)
    print(f"Process tree constructed: {len(process_tree.nodes)} nodes resolved.")
    logger.info(f"Process tree constructed: {len(process_tree.nodes)} nodes resolved.")

    for pid, process in processes.items():
        event = process_event_from_dict(
            process,
            process_tree=process_tree,
            tree_analyzer=tree_analyzer,
        )

        anomaly_result = baseline_engine.analyze_event(event)
        event.metadata["baseline_anomaly"] = anomaly_result
        baseline_engine.collect_event(event)

        if event.indicators:
            report_suspicious_event(event, logger)

        if anomaly_result.get("is_anomaly"):
            report_behavioral_anomaly(event, anomaly_result, logger)

    baseline_engine.save_baseline()

    # Network Monitoring initial check
    net_result = network_monitor.check_connections(
        processes=processes,
        process_tree=process_tree,
        new_only=False,
    )
    print(
        f"Network Monitor: {net_result['total_connections']} active connections checked "
        f"({net_result['outbound_connections']} outbound)."
    )
    logger.info(
        f"Network monitor checked {net_result['total_connections']} connections "
        f"({net_result['outbound_connections']} outbound)."
    )

    for net_event in net_result["suspicious_events"]:
        report_suspicious_network_event(net_event, logger)

    return processes, resource_monitor, baseline_engine, tree_analyzer, network_monitor, process_tree


def main():
    logger = setup_logger()

    # Help information
    if "--help" in sys.argv or "-h" in sys.argv:
        print(
            "\nEndpoint Monitor - Host Intrusion Detection & Application Control System (Phase 6 Release)\n\n"
            "Usage:\n"
            "    python src/main.py [OPTIONS]\n\n"
            "Options:\n"
            "    --ui                Launch graphical desktop dashboard (native Tkinter)\n"
            "    --cli, --dashboard  Launch interactive terminal console dashboard\n"
            "    --scan              Execute a single-pass system security audit snapshot\n"
            "    --continuous, -c    Execute continuous real-time monitoring loop\n"
            "    --help, -h          Show this help message and exit\n"
        )
        return

    # Mode 1: Graphical Desktop Dashboard (default when display is available or --ui)
    if "--ui" in sys.argv or (len(sys.argv) == 1 and is_gui_available()):
        if not is_gui_available():
            print("Error: Graphical display not available. Use --cli or --continuous instead.")
            sys.exit(1)
        print("Launching Desktop Security Dashboard UI...")
        engine = MonitoringEngine()
        app = SecurityDashboardApp(engine=engine)
        app.run()
        return

    # Mode 2: Interactive Terminal Console Dashboard
    if "--cli" in sys.argv or "--dashboard" in sys.argv:
        engine = MonitoringEngine()
        run_cli_loop(engine)
        return

    # Mode 3 & 4: Command-Line Single Scan or Continuous Loop
    processes, resource_monitor, baseline_engine, tree_analyzer, network_monitor, process_tree = run_single_scan(logger)

def load_telemetry_config(config_path="config/config.json"):
    """Load telemetry and enforcement configuration from JSON file without importing execution subsystem."""
    if not os.path.exists(config_path):
        return {}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            ce = data.get("controlled_execution", {})
            return {
                "windows_process_telemetry": ce.get("windows_process_telemetry", {}),
                "sysmon_telemetry": ce.get("sysmon_telemetry", {}),
                "firewall_enforcement": ce.get("firewall_enforcement", {}),
            }
    except Exception:
        return {}


def run_continuous_loop(
    logger,
    processes,
    resource_monitor,
    baseline_engine,
    tree_analyzer,
    network_monitor,
    process_tree,
    config=None,
    sysmon_collector=None,
    windows_collector=None,
    firewall_enforcer=None,
    max_iterations=None,
    sleep_fn=time.sleep,
):
    """
    Execute continuous monitoring loop integrating psutil polling,
    Windows Security 4688 telemetry, Sysmon telemetry, and Windows Firewall enforcement.
    """
    config = config or load_telemetry_config("config/config.json")
    process_identities = ProcessIdentityRegistry(tolerance=5.0)

    # Seed known initial processes into identity registry
    for pid, proc in processes.items():
        process_identities.register(pid, proc.get("create_time"), source="initial")

    # Windows Firewall enforcement adapter
    if firewall_enforcer is None:
        fw_cfg = config.get("firewall_enforcement", {}) or {}
        firewall_enforcer = WindowsFirewallEnforcer(config=fw_cfg)
    logger.info(firewall_enforcer.get_startup_status_message())

    # Windows Security 4688 process telemetry
    wpt_cfg = config.get("windows_process_telemetry", {}) or {}
    windows_active = bool(wpt_cfg.get("enabled", False)) or (windows_collector is not None)
    if windows_collector is None:
        windows_collector = WindowsProcessTelemetryCollector(
            channel=wpt_cfg.get("channel", "Security"),
            event_id=wpt_cfg.get("event_id", 4688),
            max_events_per_query=wpt_cfg.get("max_events_per_query", 200),
            query_timeout=wpt_cfg.get("query_timeout_seconds", 10.0),
        )
    windows_correlator = ProcessTelemetryCorrelator()
    if windows_active:
        windows_collector.seed_baseline()
        logger.info(f"Windows Security 4688 telemetry status: {windows_collector.status}")

    # Sysmon telemetry
    sysmon_cfg = config.get("sysmon_telemetry", {}) or {}
    sysmon_active = bool(sysmon_cfg.get("enabled", False)) or (sysmon_collector is not None)
    if sysmon_collector is None:
        sysmon_collector = SysmonTelemetryCollector(
            channel=sysmon_cfg.get("channel", "Microsoft-Windows-Sysmon/Operational"),
            enable_process_events=sysmon_cfg.get("enable_process_events", True),
            enable_network_events=sysmon_cfg.get("enable_network_events", True),
            max_events_per_query=sysmon_cfg.get("max_events_per_query", 200),
            query_timeout=sysmon_cfg.get("query_timeout_seconds", 10.0),
        )
    sysmon_correlator = SysmonTelemetryCorrelator()
    if sysmon_active:
        sysmon_collector.seed_baseline()

    diag = sysmon_collector.get_status_snapshot()
    logger.info(
        f"Sysmon telemetry status: {diag['status']} | "
        f"Event ID 1: {diag['process_events_enabled']} | "
        f"Event ID 3: {diag['event_id_3_logging_status']}"
    )

    previous_processes = processes
    iteration = 0

    while max_iterations is None or iteration < max_iterations:
        iteration += 1
        sleep_fn(resource_monitor.check_interval)

        # 1. Periodic resource monitoring check
        resource_monitor.check_resources()

        # 2. Periodic process monitoring check for newly launched processes (psutil polling)
        current_processes = get_running_processes()
        new_processes = get_new_processes(previous_processes, current_processes)

        # Rebuild / update process tree with current snapshot
        process_tree = ProcessTree.build(current_processes)

        for process in new_processes:
            pid = process.get("pid")
            create_time = process.get("create_time")
            if process_identities.matches(pid, create_time):
                continue
            process_identities.register(pid, create_time, source="process_monitor")

            event = process_event_from_dict(
                process,
                process_tree=process_tree,
                tree_analyzer=tree_analyzer,
            )

            anomaly_result = baseline_engine.analyze_event(event)
            event.metadata["baseline_anomaly"] = anomaly_result
            baseline_engine.collect_event(event)

            if event.indicators:
                report_suspicious_event(event, logger)

            if anomaly_result.get("is_anomaly"):
                report_behavioral_anomaly(event, anomaly_result, logger)

        # 3. Windows Security 4688 telemetry records (if active)
        if windows_active and windows_collector.status != TelemetryStatus.UNAVAILABLE:
            try:
                win_records = windows_collector.query_live_events()
                for w_rec in win_records:
                    if process_identities.matches(w_rec.pid, w_rec.timestamp):
                        continue
                    process_identities.register(w_rec.pid, w_rec.timestamp, source="windows_process_telemetry")
                    w_event = windows_correlator.to_event(w_rec, running_processes=current_processes)
                    w_event.indicators = detect_command_indicators(w_event.command_line)

                    tree_analysis = tree_analyzer.analyze_process(
                        windows_correlator.to_process_info(w_rec, current_processes),
                        process_tree,
                    )
                    w_event.metadata["process_tree"] = tree_analysis
                    for ind in tree_analysis.get("indicators", []):
                        if ind not in w_event.indicators:
                            w_event.indicators.append(ind)

                    risk_result = calculate_risk(
                        w_event.indicators,
                        windows_correlator.to_process_info(w_rec, current_processes),
                        tree_findings=tree_analysis.get("findings"),
                    )
                    w_event.risk_score = risk_result["score"]
                    w_event.risk_level = risk_result["level"]
                    w_event.risk_reasons = risk_result["reasons"]
                    w_event.severity = risk_result["level"]

                    anomaly_result = baseline_engine.analyze_event(w_event)
                    w_event.metadata["baseline_anomaly"] = anomaly_result
                    baseline_engine.collect_event(w_event)

                    if w_event.indicators:
                        report_suspicious_event(w_event, logger)
                    if anomaly_result.get("is_anomaly"):
                        report_behavioral_anomaly(w_event, anomaly_result, logger)
            except Exception as e:
                logger.warning(f"Windows process telemetry collection failed: {e}")

        # 4. Sysmon telemetry records (Event ID 1 & Event ID 3)
        if sysmon_active and sysmon_collector.status != SysmonTelemetryStatus.UNAVAILABLE:
            try:
                sysmon_records = sysmon_collector.query_live_events()
                for s_rec in sysmon_records:
                    if isinstance(s_rec, SysmonProcessRecord) or getattr(s_rec, "event_id", 0) == 1:
                        guid = getattr(s_rec, "process_guid", None)
                        if process_identities.matches(s_rec.pid, s_rec.timestamp, process_guid=guid):
                            continue
                        process_identities.register(
                            s_rec.pid,
                            s_rec.timestamp,
                            source="sysmon",
                            process_guid=guid,
                        )

                        s_event = sysmon_correlator.to_event(
                            s_rec,
                            running_processes=current_processes,
                            process_tree=process_tree,
                            tree_analyzer=tree_analyzer,
                        )

                        anomaly_result = baseline_engine.analyze_event(s_event)
                        s_event.metadata["baseline_anomaly"] = anomaly_result
                        baseline_engine.collect_event(s_event)

                        if s_event.indicators:
                            report_suspicious_event(s_event, logger)

                        if anomaly_result.get("is_anomaly"):
                            report_behavioral_anomaly(s_event, anomaly_result, logger)

                    elif isinstance(s_rec, SysmonNetworkRecord) or getattr(s_rec, "event_id", 0) == 3:
                        conn = s_rec.to_network_connection()
                        findings = network_monitor.evaluate_connection(
                            conn,
                            process_info=current_processes.get(s_rec.pid),
                            process_tree=process_tree,
                        )
                        s_net_event = sysmon_correlator.to_network_event(
                            s_rec,
                            findings=findings,
                            network_monitor=network_monitor,
                            process_tree=process_tree,
                        )
                        if findings.get("is_suspicious") and network_monitor.tracker.should_alert(conn):
                            report_suspicious_network_event(s_net_event, logger)
                            try:
                                enf_res = firewall_enforcer.process_network_event(
                                    s_net_event,
                                    running_processes=current_processes,
                                )
                                if enf_res and enf_res.policy_decision == "BLOCK":
                                    logger.info(
                                        f"Firewall policy: {enf_res.policy_decision} | "
                                        f"Enforcement: {enf_res.enforcement_status} | "
                                        f"Rule: {getattr(enf_res.rule_record, 'rule_name', None)}"
                                    )
                            except Exception as enf_err:
                                logger.error(f"Firewall enforcement error: {enf_err}")
            except Exception as e:
                logger.warning(f"Sysmon telemetry collection failed: {e}")

        # 5. Periodic network monitoring check (new connections only to avoid alert spam)
        net_cycle = network_monitor.check_connections(
            processes=current_processes,
            process_tree=process_tree,
            new_only=True,
        )
        for net_event in net_cycle.get("suspicious_events", []):
            report_suspicious_network_event(net_event, logger)
            try:
                enf_res = firewall_enforcer.process_network_event(
                    net_event,
                    running_processes=current_processes,
                )
                if enf_res and enf_res.policy_decision == "BLOCK":
                    logger.info(
                        f"Firewall policy: {enf_res.policy_decision} | "
                        f"Enforcement: {enf_res.enforcement_status} | "
                        f"Rule: {getattr(enf_res.rule_record, 'rule_name', None)}"
                    )
            except Exception as enf_err:
                logger.error(f"Firewall enforcement error: {enf_err}")

        previous_processes = current_processes
        baseline_engine.save_baseline()

    return previous_processes, process_tree, process_identities


def main():
    logger = setup_logger()

    # Help information
    if "--help" in sys.argv or "-h" in sys.argv:
        print(
            "\nEndpoint Monitor - Host Intrusion Detection & Application Control System (Phase 6 Release)\n\n"
            "Usage:\n"
            "    python src/main.py [OPTIONS]\n\n"
            "Options:\n"
            "    --ui                Launch graphical desktop dashboard (native Tkinter)\n"
            "    --cli, --dashboard  Launch interactive terminal console dashboard\n"
            "    --scan              Execute a single-pass system security audit snapshot\n"
            "    --continuous, -c    Execute continuous real-time monitoring loop\n"
            "    --help, -h          Show this help message and exit\n"
        )
        return

    # Mode 1: Graphical Desktop Dashboard (default when display is available or --ui)
    if "--ui" in sys.argv or (len(sys.argv) == 1 and is_gui_available()):
        if not is_gui_available():
            print("Error: Graphical display not available. Use --cli or --continuous instead.")
            sys.exit(1)
        print("Launching Desktop Security Dashboard UI...")
        engine = MonitoringEngine()
        app = SecurityDashboardApp(engine=engine)
        app.run()
        return

    # Mode 2: Interactive Terminal Console Dashboard
    if "--cli" in sys.argv or "--dashboard" in sys.argv:
        engine = MonitoringEngine()
        run_cli_loop(engine)
        return

    # Mode 3 & 4: Command-Line Single Scan or Continuous Loop
    processes, resource_monitor, baseline_engine, tree_analyzer, network_monitor, process_tree = run_single_scan(logger)

    # Optional continuous monitoring mode
    if "--continuous" in sys.argv or "-c" in sys.argv:
        print(
            f"\nEntering continuous monitoring mode "
            f"(Interval: {resource_monitor.check_interval}s, Press Ctrl+C to stop)..."
        )
        logger.info("Entering continuous monitoring mode.")

        try:
            run_continuous_loop(
                logger=logger,
                processes=processes,
                resource_monitor=resource_monitor,
                baseline_engine=baseline_engine,
                tree_analyzer=tree_analyzer,
                network_monitor=network_monitor,
                process_tree=process_tree,
            )
        except KeyboardInterrupt:
            print("\nEndpoint Security Monitor stopped cleanly.")
            logger.info("Endpoint Security Monitor stopped cleanly by user.")


if __name__ == "__main__":
    main()

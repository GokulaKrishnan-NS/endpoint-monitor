"""
Network Monitoring Module

Observes active network connections (TCP/UDP), associates them with owning
processes, identifies network anomalies and risk indicators (unusual ports,
unexpected network binaries, non-standard outbound script connections, and
correlations with suspicious process lineages), formats standardized Events,
and supports continuous monitoring with duplicate alert suppression.
"""

import json
import logging
import os
import socket
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import psutil

from src.models.event import Event
from src.detectors.risk_detector import calculate_risk


DEFAULT_NETWORK_CONFIG = {
    "enabled": True,
    "check_interval": 5,
    "suspicious_ports": [
        21,      # FTP
        23,      # Telnet
        69,      # TFTP
        1337,    # Common hacker/backdoor port
        4444,    # Metasploit default payload listener
        5555,    # ADB / Freeciv / Trojan port
        6667,    # IRC default (common botnet C2)
        8888,    # Alternative HTTP / Proxy
        9999,    # Common backdoor / malware listener
        12345,   # NetBus Trojan
        31337,   # Back Orifice
    ],
    "unexpected_processes": [
        "notepad.exe",
        "calc.exe",
        "mspaint.exe",
        "cmd.exe",
        "spoolsv.exe",
        "taskhostw.exe",
        "regsvr32.exe",
        "mshta.exe",
    ],
    "script_interpreters": [
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "bash.exe",
        "sh.exe",
        "python.exe",
    ],
    "standard_outbound_ports": [80, 443, 8080, 8443, 53],
}


def is_loopback_or_local(ip: Optional[str]) -> bool:
    """Check if an IP address is localhost, loopback, or unspecified."""
    if not ip:
        return True
    ip = ip.strip().lower()
    return (
        ip in ("127.0.0.1", "localhost", "::1", "0.0.0.0", "::")
        or ip.startswith("127.")
    )


def is_private_ip(ip: Optional[str]) -> bool:
    """Check if an IP address falls within RFC 1918 private ranges."""
    if not ip:
        return False
    if is_loopback_or_local(ip):
        return True
    if ip.startswith("10.") or ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        try:
            parts = ip.split(".")
            second_octet = int(parts[1])
            return 16 <= second_octet <= 31
        except (IndexError, ValueError):
            pass
    return False


class NetworkConnection:
    """
    Normalized representation of an individual active network connection.
    """

    def __init__(
        self,
        pid: Optional[int],
        protocol: str,
        local_ip: str,
        local_port: int,
        remote_ip: Optional[str] = None,
        remote_port: Optional[int] = None,
        status: str = "NONE",
        process_name: Optional[str] = None,
        parent_process_name: Optional[str] = None,
        timestamp: Optional[float] = None,
    ):
        self.pid: Optional[int] = pid
        self.protocol: str = protocol.upper()
        self.local_ip: str = local_ip
        self.local_port: int = local_port
        self.remote_ip: Optional[str] = remote_ip
        self.remote_port: Optional[int] = remote_port
        self.status: str = status
        self.process_name: Optional[str] = process_name
        self.parent_process_name: Optional[str] = parent_process_name
        self.timestamp: float = timestamp or time.time()

        # Outbound if remote address exists and is not listening/loopback
        self.is_outbound: bool = (
            self.remote_ip is not None
            and self.remote_port is not None
            and self.status != "LISTEN"
        )

    @property
    def key(self) -> Tuple:
        """Unique identifier tuple for connection state tracking."""
        return (
            self.pid,
            self.protocol,
            self.local_ip,
            self.local_port,
            self.remote_ip,
            self.remote_port,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize connection to a standard dictionary."""
        return {
            "pid": self.pid,
            "process_name": self.process_name,
            "parent_process_name": self.parent_process_name,
            "protocol": self.protocol,
            "local_ip": self.local_ip,
            "local_port": self.local_port,
            "local_address": f"{self.local_ip}:{self.local_port}",
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "remote_address": (
                f"{self.remote_ip}:{self.remote_port}"
                if self.remote_ip and self.remote_port
                else None
            ),
            "status": self.status,
            "is_outbound": self.is_outbound,
            "timestamp": self.timestamp,
        }

    def __repr__(self) -> str:
        remote = f"{self.remote_ip}:{self.remote_port}" if self.remote_ip else "N/A"
        return (
            f"<NetworkConnection {self.protocol} {self.local_ip}:{self.local_port} -> "
            f"{remote} ({self.status}) pid={self.pid} proc={self.process_name}>"
        )


class NetworkStateTracker:
    """
    Maintains historical connection state to detect newly established
    connections and suppress duplicate alerts for ongoing connections.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.known_connections: Dict[Tuple, float] = {}
        self.alerted_connections: Set[Tuple] = set()

    def update(
        self, connections: List[NetworkConnection]
    ) -> Tuple[List[NetworkConnection], List[NetworkConnection]]:
        """
        Update the state tracker with a new batch of connections.
        Returns a tuple: (new_connections, all_active_connections).
        """
        with self._lock:
            current_keys = set()
            new_conns = []

            for conn in connections:
                k = conn.key
                current_keys.add(k)
                if k not in self.known_connections:
                    self.known_connections[k] = conn.timestamp
                    new_conns.append(conn)

            # Prune closed/disappeared connections
            stale_keys = [k for k in self.known_connections if k not in current_keys]
            for k in stale_keys:
                del self.known_connections[k]
                self.alerted_connections.discard(k)

            return new_conns, connections

    def should_alert(self, conn: NetworkConnection) -> bool:
        """
        Check if an alert should be emitted for this connection.
        Returns True if not previously alerted, and marks as alerted.
        """
        with self._lock:
            k = conn.key
            if k not in self.alerted_connections:
                self.alerted_connections.add(k)
                return True
            return False

    def reset(self) -> None:
        """Clear all tracked connection state."""
        with self._lock:
            self.known_connections.clear()
            self.alerted_connections.clear()


def load_network_config(config_path: str = "config/config.json") -> Dict[str, Any]:
    """
    Load network monitoring configuration from JSON file, falling back to defaults.
    """
    config = dict(DEFAULT_NETWORK_CONFIG)

    if not os.path.exists(config_path):
        return config

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return config
            data = json.loads(content)
            net_cfg = data.get("network_monitor", {})

            for k in [
                "enabled",
                "check_interval",
                "suspicious_ports",
                "unexpected_processes",
                "script_interpreters",
                "standard_outbound_ports",
            ]:
                if k in net_cfg:
                    config[k] = net_cfg[k]

    except Exception as e:
        logging.getLogger("endpoint_monitor").debug(
            f"Could not load network_monitor config from {config_path}: {e}"
        )

    return config


class NetworkMonitor:
    """
    Main Network Monitoring Class.
    Observes active sockets, maps to processes, detects anomalous network activity,
    and constructs standardized Events.
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        config_path: str = "config/config.json",
        logger: Optional[logging.Logger] = None,
    ):
        self.config = config if config is not None else load_network_config(config_path)
        self.logger = logger or logging.getLogger("endpoint_monitor")
        self.enabled: bool = self.config.get("enabled", True)
        self.check_interval: int = self.config.get("check_interval", 5)

        self.suspicious_ports: Set[int] = set(
            self.config.get("suspicious_ports", DEFAULT_NETWORK_CONFIG["suspicious_ports"])
        )
        self.unexpected_processes: Set[str] = {
            p.lower()
            for p in self.config.get(
                "unexpected_processes", DEFAULT_NETWORK_CONFIG["unexpected_processes"]
            )
        }
        self.script_interpreters: Set[str] = {
            s.lower()
            for s in self.config.get(
                "script_interpreters", DEFAULT_NETWORK_CONFIG["script_interpreters"]
            )
        }
        self.standard_outbound_ports: Set[int] = set(
            self.config.get(
                "standard_outbound_ports",
                DEFAULT_NETWORK_CONFIG["standard_outbound_ports"],
            )
        )

        self.state_tracker = NetworkStateTracker()
        self._stop_event = threading.Event()
        self._bg_thread: Optional[threading.Thread] = None

    def get_active_connections(
        self, processes: Optional[Dict[int, Dict[str, Any]]] = None
    ) -> List[NetworkConnection]:
        """
        Collect active network connections via psutil.net_connections(),
        associating each socket with its owning process and parent process.
        Handles missing PIDs and permission boundaries gracefully.
        """
        connections: List[NetworkConnection] = []

        try:
            raw_conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, psutil.Error, OSError) as e:
            self.logger.debug(f"Unable to query network connections: {e}")
            return connections

        for sconn in raw_conns:
            try:
                pid = sconn.pid

                # Protocol resolution
                if sconn.type == socket.SOCK_STREAM:
                    protocol = "TCP"
                elif sconn.type == socket.SOCK_DGRAM:
                    protocol = "UDP"
                else:
                    protocol = "UNKNOWN"

                # Address resolution
                laddr = sconn.laddr
                local_ip = laddr.ip if laddr else "0.0.0.0"
                local_port = laddr.port if laddr else 0

                raddr = sconn.raddr
                remote_ip = raddr.ip if raddr else None
                remote_port = raddr.port if raddr else None

                status = sconn.status or "NONE"

                # Process association
                process_name: Optional[str] = None
                parent_process_name: Optional[str] = None

                if pid is not None:
                    if processes and pid in processes:
                        pinfo = processes[pid]
                        process_name = pinfo.get("name")
                        parent_process_name = pinfo.get("parent_name")
                    else:
                        try:
                            proc = psutil.Process(pid)
                            process_name = proc.name()
                            try:
                                parent = proc.parent()
                                if parent:
                                    parent_process_name = parent.name()
                            except (
                                psutil.NoSuchProcess,
                                psutil.AccessDenied,
                                psutil.ZombieProcess,
                            ):
                                pass
                        except (
                            psutil.NoSuchProcess,
                            psutil.AccessDenied,
                            psutil.ZombieProcess,
                        ):
                            process_name = "unknown"

                conn = NetworkConnection(
                    pid=pid,
                    protocol=protocol,
                    local_ip=local_ip,
                    local_port=local_port,
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    status=status,
                    process_name=process_name,
                    parent_process_name=parent_process_name,
                )
                connections.append(conn)

            except Exception as ex:
                self.logger.debug(f"Error parsing connection: {ex}")
                continue

        return connections

    def detect_anomalies(
        self,
        conn: NetworkConnection,
        process_info: Optional[Dict[str, Any]] = None,
        process_tree: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate an active connection against heuristic security rules.
        Returns a dictionary containing matched indicators, reasons, scores,
        and severity.
        """
        findings: List[Dict[str, Any]] = []
        proc_name_lower = (conn.process_name or "").lower().strip()

        # 1. Suspicious / Unusual Destination Port
        if conn.remote_port and conn.remote_port in self.suspicious_ports:
            findings.append({
                "type": "SUSPICIOUS_PORT",
                "indicator": "suspicious_destination_port",
                "score": 4,
                "severity": "MEDIUM",
                "reason": (
                    f"Connection to suspicious destination port {conn.remote_port} "
                    f"({conn.process_name or 'PID ' + str(conn.pid)})"
                ),
            })

        # 2. Unexpected Network-Initiating Process
        if conn.is_outbound and proc_name_lower in self.unexpected_processes:
            findings.append({
                "type": "UNEXPECTED_PROCESS",
                "indicator": "unexpected_network_process",
                "score": 4,
                "severity": "MEDIUM",
                "reason": (
                    f"Unexpected process initiating network connection: {conn.process_name} "
                    f"-> {conn.remote_ip}:{conn.remote_port}"
                ),
            })

        # 3. Script Interpreter Outbound Call to Non-Standard Port
        if (
            conn.is_outbound
            and proc_name_lower in self.script_interpreters
            and conn.remote_port
            and conn.remote_port not in self.standard_outbound_ports
            and not is_loopback_or_local(conn.remote_ip)
        ):
            findings.append({
                "type": "SCRIPT_NON_STANDARD_PORT",
                "indicator": "suspicious_outbound_connection",
                "score": 4,
                "severity": "MEDIUM",
                "reason": (
                    f"Script interpreter outbound connection to non-standard port: "
                    f"{conn.process_name} -> {conn.remote_ip}:{conn.remote_port}"
                ),
            })

        # 4. Network Activity Associated with Already-Suspicious Process
        is_suspicious_parentage = False
        if process_info:
            indicators = process_info.get("indicators", [])
            # Check command indicators or suspicious process lineage
            if (
                "encoded_command" in indicators
                or "hidden_execution" in indicators
                or "download_and_execute" in indicators
                or "suspicious_process_lineage" in indicators
                or "multi_level_shell_chain" in indicators
            ):
                is_suspicious_parentage = True

        if is_suspicious_parentage and conn.is_outbound:
            findings.append({
                "type": "SUSPICIOUS_PROCESS_NETWORK",
                "indicator": "network_activity_suspicious_process",
                "score": 4,
                "severity": "HIGH",
                "reason": (
                    f"Outbound network connection originating from already-suspicious process: "
                    f"{conn.process_name} (PID: {conn.pid}) -> {conn.remote_ip}:{conn.remote_port}"
                ),
            })

        # 5. Unusual Connection State (e.g. SYN_SENT on non-standard port)
        if (
            conn.status == "SYN_SENT"
            and conn.remote_port
            and conn.remote_port not in self.standard_outbound_ports
            and not is_loopback_or_local(conn.remote_ip)
        ):
            findings.append({
                "type": "UNUSUAL_STATE",
                "indicator": "unusual_network_state",
                "score": 2,
                "severity": "LOW",
                "reason": (
                    f"Unusual connection state {conn.status} to {conn.remote_ip}:{conn.remote_port} "
                    f"by {conn.process_name}"
                ),
            })

        # Aggregate results
        indicators: List[str] = []
        reasons: List[str] = []
        total_score = 0

        for f in findings:
            ind = f.get("indicator")
            if ind and ind not in indicators:
                indicators.append(ind)
            reason = f.get("reason")
            if reason and reason not in reasons:
                reasons.append(reason)
            total_score += f.get("score", 0)

        severity = "LOW"
        if any(f.get("severity") == "HIGH" for f in findings) or total_score >= 7:
            severity = "HIGH"
        elif any(f.get("severity") == "MEDIUM" for f in findings) or total_score >= 3:
            severity = "MEDIUM"

        return {
            "is_suspicious": len(findings) > 0,
            "total_score": total_score,
            "severity": severity,
            "indicators": indicators,
            "reasons": reasons,
            "findings": findings,
        }

    def create_network_event(
        self,
        conn: NetworkConnection,
        findings: Optional[Dict[str, Any]] = None,
    ) -> Event:
        """
        Construct a standardized Event from a NetworkConnection and anomaly evaluation.
        """
        findings = findings or {}
        indicators = findings.get("indicators", [])

        # Calculate final risk score through existing risk detector
        risk_result = calculate_risk(
            indicators=indicators,
            process_info={"pid": conn.pid, "name": conn.process_name},
            tree_findings=findings.get("findings"),
        )

        event = Event(
            event_type="network_connection",
            source="network_monitor",
            severity=risk_result["level"],
            pid=conn.pid,
            process_name=conn.process_name,
            parent_process_name=conn.parent_process_name,
            network_info=conn.to_dict(),
            indicators=indicators,
            risk_score=risk_result["score"],
            risk_level=risk_result["level"],
            risk_reasons=risk_result["reasons"],
            metadata={"network_findings": findings},
        )
        return event

    def check_connections(
        self,
        processes: Optional[Dict[int, Dict[str, Any]]] = None,
        process_tree: Optional[Any] = None,
        new_only: bool = False,
    ) -> Dict[str, Any]:
        """
        Perform a network connection scan cycle.
        If new_only is True, filters to only newly established connections and
        suppresses duplicate alerts for already-seen active connections.
        """
        all_conns = self.get_active_connections(processes=processes)
        new_conns, active_conns = self.state_tracker.update(all_conns)

        target_conns = new_conns if new_only else active_conns
        events: List[Event] = []
        suspicious_events: List[Event] = []
        outbound_count = sum(1 for c in all_conns if c.is_outbound)

        for conn in target_conns:
            # Check duplicate alert suppression in continuous mode
            if new_only and not self.state_tracker.should_alert(conn):
                continue

            pinfo = processes.get(conn.pid) if (processes and conn.pid) else None
            anomaly_data = self.detect_anomalies(
                conn, process_info=pinfo, process_tree=process_tree
            )

            event = self.create_network_event(conn, findings=anomaly_data)
            events.append(event)

            if anomaly_data.get("is_suspicious"):
                suspicious_events.append(event)

        return {
            "total_connections": len(all_conns),
            "outbound_connections": outbound_count,
            "evaluated_connections": len(target_conns),
            "events": events,
            "suspicious_events": suspicious_events,
        }

    def start_monitoring(self, stop_event: Optional[threading.Event] = None) -> None:
        """
        Run continuous network monitoring loop until stop_event is set or KeyboardInterrupt.
        """
        event = stop_event or self._stop_event
        self.logger.info("Network Monitor loop started.")

        try:
            while not event.is_set():
                try:
                    result = self.check_connections(new_only=True)
                    for s_event in result["suspicious_events"]:
                        msg = (
                            f"Suspicious network connection | PID: {s_event.pid} | "
                            f"Process: {s_event.process_name} | "
                            f"Remote: {s_event.network_info.get('remote_address')} | "
                            f"Risk: {s_event.risk_level} | Score: {s_event.risk_score}"
                        )
                        self.logger.warning(msg)
                except Exception as e:
                    self.logger.error(f"Unexpected error in network monitor cycle: {e}")

                if event.wait(timeout=self.check_interval):
                    break
        except KeyboardInterrupt:
            self.logger.info("Network Monitor received interrupt signal.")
        finally:
            self.logger.info("Network Monitor loop terminated cleanly.")

    def start_background(self) -> threading.Thread:
        """
        Start continuous network monitoring in a background daemon thread.
        """
        self._stop_event.clear()
        self._bg_thread = threading.Thread(
            target=self.start_monitoring,
            args=(self._stop_event,),
            name="NetworkMonitorThread",
            daemon=True,
        )
        self._bg_thread.start()
        return self._bg_thread

    def stop(self) -> None:
        """
        Signal background thread to stop and wait for termination.
        """
        self._stop_event.set()
        if self._bg_thread and self._bg_thread.is_alive():
            self._bg_thread.join(timeout=self.check_interval + 1)


if __name__ == "__main__":
    print("Running standalone Network Monitor snapshot...")
    monitor = NetworkMonitor()
    res = monitor.check_connections()
    print(f"Total connections observed: {res['total_connections']}")
    print(f"Outbound connections: {res['outbound_connections']}")
    print(f"Suspicious connections detected: {len(res['suspicious_events'])}")
    for ev in res["suspicious_events"]:
        print(f"  - [{ev.risk_level}] PID {ev.pid} ({ev.process_name}) -> {ev.network_info.get('remote_address')}")
        for r in ev.risk_reasons:
            print(f"      * {r}")

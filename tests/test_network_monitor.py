import unittest
from unittest.mock import MagicMock, patch
import socket
import psutil

from src.monitors.network_monitor import (
    NetworkConnection,
    NetworkStateTracker,
    NetworkMonitor,
    is_loopback_or_local,
    is_private_ip,
)
from src.models.event import Event
from src.detectors.risk_detector import calculate_risk


class TestNetworkMonitor(unittest.TestCase):
    """
    Test suite for Network Monitoring module:
    1. Normal active connection
    2. New connection detection
    3. Multiple connections
    4. Process-to-connection association
    5. Missing/disappeared PID
    6. Permission/access errors
    7. Continuous monitoring
    8. Duplicate-alert suppression
    9. Integration with Event model
    10. Integration with detection/correlation/risk pipeline
    """

    def setUp(self):
        self.monitor = NetworkMonitor()

    # 1. Normal active connection
    def test_normal_active_connection(self):
        """Standard web browser outbound connection (port 443) is classified as LOW risk."""
        conn = NetworkConnection(
            pid=5000,
            protocol="TCP",
            local_ip="192.168.1.50",
            local_port=54321,
            remote_ip="142.250.190.46",  # Google IP
            remote_port=443,
            status="ESTABLISHED",
            process_name="chrome.exe",
            parent_process_name="explorer.exe",
        )
        anomaly = self.monitor.detect_anomalies(conn)

        self.assertFalse(anomaly["is_suspicious"])
        self.assertEqual(anomaly["total_score"], 0)
        self.assertEqual(anomaly["severity"], "LOW")
        self.assertEqual(anomaly["indicators"], [])

    # 2. New connection detection
    def test_new_connection_detection(self):
        """State tracker recognizes newly observed connections on first arrival."""
        tracker = NetworkStateTracker()
        conn1 = NetworkConnection(
            pid=100,
            protocol="TCP",
            local_ip="10.0.0.1",
            local_port=1111,
            remote_ip="1.1.1.1",
            remote_port=53,
        )

        new_conns, active_conns = tracker.update([conn1])
        self.assertEqual(len(new_conns), 1)
        self.assertEqual(new_conns[0].key, conn1.key)

    # 3. Multiple connections
    def test_multiple_connections_processing(self):
        """Processes a batch of multiple connections in a single scan cycle."""
        conns = [
            NetworkConnection(
                pid=1001,
                protocol="TCP",
                local_ip="127.0.0.1",
                local_port=8080,
                status="LISTEN",
                process_name="node.exe",
            ),
            NetworkConnection(
                pid=1002,
                protocol="TCP",
                local_ip="192.168.1.10",
                local_port=49152,
                remote_ip="8.8.8.8",
                remote_port=53,
                status="ESTABLISHED",
                process_name="dns.exe",
            ),
            NetworkConnection(
                pid=1003,
                protocol="UDP",
                local_ip="0.0.0.0",
                local_port=50000,
                status="NONE",
                process_name="game.exe",
            ),
        ]

        tracker = NetworkStateTracker()
        new_conns, active_conns = tracker.update(conns)
        self.assertEqual(len(new_conns), 3)
        self.assertEqual(len(active_conns), 3)

    # 4. Process-to-connection association
    def test_process_to_connection_association(self):
        """Associates socket telemetry with process name and parent from process table."""
        processes = {
            2400: {
                "pid": 2400,
                "name": "msedge.exe",
                "parent_name": "explorer.exe",
                "username": "user",
            }
        }

        mock_sconn = MagicMock()
        mock_sconn.pid = 2400
        mock_sconn.type = socket.SOCK_STREAM
        mock_sconn.laddr = MagicMock(ip="192.168.1.100", port=50123)
        mock_sconn.raddr = MagicMock(ip="20.112.52.29", port=443)
        mock_sconn.status = "ESTABLISHED"

        with patch("psutil.net_connections", return_value=[mock_sconn]):
            conns = self.monitor.get_active_connections(processes=processes)
            self.assertEqual(len(conns), 1)
            self.assertEqual(conns[0].pid, 2400)
            self.assertEqual(conns[0].process_name, "msedge.exe")
            self.assertEqual(conns[0].parent_process_name, "explorer.exe")
            self.assertTrue(conns[0].is_outbound)

    # 5. Missing / disappeared PID
    def test_missing_disappeared_pid(self):
        """Handles disappeared processes where PID is None or process exited cleanly."""
        mock_sconn_none = MagicMock()
        mock_sconn_none.pid = None
        mock_sconn_none.type = socket.SOCK_STREAM
        mock_sconn_none.laddr = MagicMock(ip="0.0.0.0", port=135)
        mock_sconn_none.raddr = ()
        mock_sconn_none.status = "LISTEN"

        mock_sconn_exited = MagicMock()
        mock_sconn_exited.pid = 99999
        mock_sconn_exited.type = socket.SOCK_STREAM
        mock_sconn_exited.laddr = MagicMock(ip="10.0.0.5", port=4444)
        mock_sconn_exited.raddr = MagicMock(ip="198.51.100.1", port=4444)
        mock_sconn_exited.status = "ESTABLISHED"

        with patch("psutil.net_connections", return_value=[mock_sconn_none, mock_sconn_exited]):
            with patch("psutil.Process", side_effect=psutil.NoSuchProcess(pid=99999)):
                conns = self.monitor.get_active_connections(processes={})
                self.assertEqual(len(conns), 2)
                self.assertIsNone(conns[0].pid)
                self.assertIsNone(conns[0].process_name)
                self.assertEqual(conns[1].pid, 99999)
                self.assertEqual(conns[1].process_name, "unknown")

    # 6. Permission / access errors
    def test_permission_access_errors(self):
        """Handles psutil.AccessDenied gracefully without raising unhandled exceptions."""
        with patch("psutil.net_connections", side_effect=psutil.AccessDenied()):
            conns = self.monitor.get_active_connections()
            self.assertEqual(conns, [])

    # 7. Continuous monitoring
    def test_continuous_monitoring_new_connection(self):
        """Simulates continuous monitoring loop detecting newly spawned connection."""
        conn1 = NetworkConnection(
            pid=100,
            protocol="TCP",
            local_ip="10.0.0.1",
            local_port=1000,
            remote_ip="8.8.8.8",
            remote_port=53,
        )
        conn2 = NetworkConnection(
            pid=200,
            protocol="TCP",
            local_ip="10.0.0.1",
            local_port=2000,
            remote_ip="1.2.3.4",
            remote_port=4444,  # Suspicious port
            process_name="powershell.exe",
        )

        tracker = self.monitor.state_tracker
        # Cycle 1: conn1 observed
        new_c1, _ = tracker.update([conn1])
        self.assertEqual(len(new_c1), 1)

        # Cycle 2: conn1 still active, conn2 newly opened
        new_c2, _ = tracker.update([conn1, conn2])
        self.assertEqual(len(new_c2), 1)
        self.assertEqual(new_c2[0].key, conn2.key)

    # 8. Duplicate-alert suppression
    def test_duplicate_alert_suppression(self):
        """Suppresses repeated alerts for an ongoing unchanged connection."""
        conn = NetworkConnection(
            pid=300,
            protocol="TCP",
            local_ip="10.0.0.1",
            local_port=3000,
            remote_ip="103.21.244.0",
            remote_port=1337,  # Suspicious port
            process_name="cmd.exe",
        )
        tracker = self.monitor.state_tracker

        # First alert check: should alert
        self.assertTrue(tracker.should_alert(conn))

        # Subsequent check on identical connection: should NOT alert
        self.assertFalse(tracker.should_alert(conn))

    # 9. Integration with the Event model
    def test_integration_with_event_model(self):
        """Verifies Event instantiation with network_info, indicators, and JSON serialization."""
        conn = NetworkConnection(
            pid=400,
            protocol="TCP",
            local_ip="192.168.1.15",
            local_port=49888,
            remote_ip="203.0.113.5",
            remote_port=4444,
            status="ESTABLISHED",
            process_name="powershell.exe",
            parent_process_name="winword.exe",
        )

        findings = {
            "is_suspicious": True,
            "indicators": ["suspicious_destination_port"],
            "findings": [
                {
                    "indicator": "suspicious_destination_port",
                    "reason": "Connection to suspicious destination port 4444",
                }
            ],
        }

        event = self.monitor.create_network_event(conn, findings=findings)

        self.assertIsInstance(event, Event)
        self.assertEqual(event.event_type, "network_connection")
        self.assertEqual(event.source, "network_monitor")
        self.assertEqual(event.pid, 400)
        self.assertEqual(event.process_name, "powershell.exe")
        self.assertIn("suspicious_destination_port", event.indicators)
        self.assertGreaterEqual(event.risk_score, 4)
        self.assertEqual(event.risk_level, "MEDIUM")

        # Verify network_info block
        net_dict = event.network_info
        self.assertIsNotNone(net_dict)
        self.assertEqual(net_dict["remote_port"], 4444)
        self.assertEqual(net_dict["protocol"], "TCP")

        # Verify serialization
        serialized = event.to_dict()
        self.assertEqual(serialized["event_type"], "network_connection")
        self.assertIn("network_info", serialized)

    # 10. Integration with detection/correlation/risk pipeline
    def test_composite_risk_correlation(self):
        """
        Verifies composite risk escalation:
        Process with encoded command (+4) + suspicious lineage (+4) +
        unexpected network connection (+4) -> High severity composite risk (12 points).
        """
        # Unexpected network process rule: cmd.exe initiating outbound connection
        conn = NetworkConnection(
            pid=900,
            protocol="TCP",
            local_ip="192.168.1.20",
            local_port=51234,
            remote_ip="198.51.100.99",
            remote_port=4444,  # Suspicious port
            status="ESTABLISHED",
            process_name="cmd.exe",
            parent_process_name="chrome.exe",
        )

        process_info = {
            "pid": 900,
            "name": "cmd.exe",
            "parent_name": "chrome.exe",
            "indicators": ["suspicious_process_lineage", "encoded_command"],
        }

        anomaly = self.monitor.detect_anomalies(conn, process_info=process_info)

        self.assertTrue(anomaly["is_suspicious"])
        self.assertIn("suspicious_destination_port", anomaly["indicators"])
        self.assertIn("unexpected_network_process", anomaly["indicators"])
        self.assertIn("network_activity_suspicious_process", anomaly["indicators"])

        # Create combined Event
        event = self.monitor.create_network_event(conn, findings=anomaly)

        # Composite risk calculation
        all_indicators = list(set(process_info["indicators"] + event.indicators))
        composite_risk = calculate_risk(
            indicators=all_indicators,
            process_info=process_info,
            network_findings=anomaly.get("findings"),
        )

        self.assertGreaterEqual(composite_risk["score"], 12)
        self.assertEqual(composite_risk["level"], "HIGH")
        self.assertTrue(any("4444" in r for r in composite_risk["reasons"]))


if __name__ == "__main__":
    unittest.main()

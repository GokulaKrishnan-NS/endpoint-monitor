"""
Unit tests for LoginMonitor module (src/monitors/login_monitor.py).
"""

from collections import namedtuple
import unittest
from unittest.mock import MagicMock, patch

from src.models.event import Event
from src.monitors.login_monitor import LoginMonitor

# Helper tuple matching psutil.users() suser structure
_MockSUser = namedtuple("_MockSUser", ["name", "terminal", "host", "started", "pid"])


class TestLoginMonitor(unittest.TestCase):
    """Test suite for user logon and session monitoring."""

    def setUp(self):
        self.logger = MagicMock()
        self.monitor = LoginMonitor(logger=self.logger)

    def test_init(self):
        self.assertIsNotNone(self.monitor.logger)
        self.assertEqual(self.monitor._known_users, {})

    @patch("psutil.users")
    def test_get_active_sessions_normal(self, mock_users):
        mock_users.return_value = [
            _MockSUser(name="alice", terminal="console", host="localhost", started=1700000000.0, pid=1001),
            _MockSUser(name="bob", terminal="tty1", host="", started=1700000100.0, pid=1002),
        ]

        sessions = self.monitor.get_active_sessions()
        self.assertEqual(len(sessions), 2)
        self.assertEqual(sessions[0]["username"], "alice")
        self.assertEqual(sessions[0]["terminal"], "console")
        self.assertEqual(sessions[0]["host"], "localhost")
        self.assertEqual(sessions[0]["pid"], 1001)

        self.assertEqual(sessions[1]["username"], "bob")
        self.assertEqual(sessions[1]["host"], "localhost")

    @patch("psutil.users")
    def test_get_active_sessions_exception_handled_safely(self, mock_users):
        mock_users.side_effect = RuntimeError("Access denied to session table")

        sessions = self.monitor.get_active_sessions()
        self.assertEqual(sessions, [])
        self.logger.debug.assert_called_once()

    @patch("psutil.users")
    def test_check_logon_events_standard_user(self, mock_users):
        mock_users.return_value = [
            _MockSUser(name="standard_user", terminal="console", host="localhost", started=1700000000.0, pid=2000),
        ]

        events = self.monitor.check_logon_events()
        self.assertEqual(len(events), 1)

        evt = events[0]
        self.assertIsInstance(evt, Event)
        self.assertEqual(evt.event_type, "user_logon")
        self.assertEqual(evt.source, "login_monitor")
        self.assertEqual(evt.username, "standard_user")
        self.assertEqual(evt.pid, 2000)
        self.assertEqual(evt.severity, "LOW")
        self.assertEqual(evt.risk_level, "LOW")
        self.assertEqual(evt.risk_score, 0)
        self.assertEqual(evt.indicators, [])
        self.assertTrue(evt.metadata["is_new_user"])

        # Second check: user is no longer new
        events_2 = self.monitor.check_logon_events()
        self.assertEqual(len(events_2), 1)
        self.assertFalse(events_2[0].metadata["is_new_user"])

    @patch("psutil.users")
    def test_check_logon_events_remote_session(self, mock_users):
        mock_users.return_value = [
            _MockSUser(name="admin_user", terminal="RDP-Tcp#1", host="192.168.1.55", started=1700000050.0, pid=3000),
        ]

        events = self.monitor.check_logon_events()
        self.assertEqual(len(events), 1)

        evt = events[0]
        self.assertIn("remote_session_detected", evt.indicators)
        self.assertGreaterEqual(evt.risk_score, 2)
        self.assertTrue(any("192.168.1.55" in r for r in evt.risk_reasons))

    @patch("psutil.users")
    def test_check_logon_events_service_account_interactive(self, mock_users):
        mock_users.return_value = [
            _MockSUser(name="svc_backup", terminal="console", host="localhost", started=1700000080.0, pid=4000),
        ]

        events = self.monitor.check_logon_events()
        self.assertEqual(len(events), 1)

        evt = events[0]
        self.assertIn("service_account_interactive_logon", evt.indicators)
        self.assertGreaterEqual(evt.risk_score, 3)
        self.assertEqual(evt.severity, "MEDIUM")
        self.assertEqual(evt.risk_level, "MEDIUM")

    @patch("psutil.users")
    def test_check_logon_events_combined_risk(self, mock_users):
        mock_users.return_value = [
            _MockSUser(name="sql_admin", terminal="RDP-Tcp#2", host="10.0.0.99", started=1700000090.0, pid=5000),
        ]

        events = self.monitor.check_logon_events()
        self.assertEqual(len(events), 1)

        evt = events[0]
        self.assertIn("remote_session_detected", evt.indicators)
        self.assertIn("service_account_interactive_logon", evt.indicators)
        self.assertEqual(evt.risk_score, 5)  # 2 (remote) + 3 (service)
        self.assertEqual(evt.risk_level, "MEDIUM")

    @patch("psutil.users")
    def test_check_logon_events_new_only_deduplication(self, mock_users):
        mock_users.return_value = [
            _MockSUser(name="alice", terminal="console", host="localhost", started=1700000000.0, pid=6000),
        ]
        # First scan with new_only=True returns the new session
        first_events = self.monitor.check_logon_events(new_only=True)
        self.assertEqual(len(first_events), 1)
        self.assertEqual(first_events[0].username, "alice")
        self.assertEqual(first_events[0].event_type, "user_logon")

        # Second scan with same session and new_only=True yields 0 events
        second_events = self.monitor.check_logon_events(new_only=True)
        self.assertEqual(len(second_events), 0)

    @patch("psutil.users")
    def test_check_logon_events_session_ended(self, mock_users):
        mock_users.return_value = [
            _MockSUser(name="bob", terminal="console", host="localhost", started=1700000000.0, pid=7000),
        ]
        self.monitor.check_logon_events(new_only=True)

        # Bob logs out
        mock_users.return_value = []
        end_events = self.monitor.check_logon_events(new_only=True)
        self.assertEqual(len(end_events), 1)
        self.assertEqual(end_events[0].event_type, "user_session_ended")
        self.assertEqual(end_events[0].username, "bob")
        self.assertEqual(end_events[0].pid, 7000)


if __name__ == "__main__":
    unittest.main()


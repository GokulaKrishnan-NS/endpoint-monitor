import unittest
import json
import time

from src.models.event import Event
from src.main import process_event_from_dict


class TestEventModel(unittest.TestCase):

    def test_default_event_instantiation(self):
        event = Event()
        self.assertIsNotNone(event.event_id)
        self.assertTrue(isinstance(event.timestamp, float))
        self.assertEqual(event.severity, "LOW")
        self.assertEqual(event.indicators, [])
        self.assertEqual(event.risk_score, 0)
        self.assertIsNone(event.pid)
        self.assertIsNone(event.file_path)
        self.assertIsNone(event.resource_metrics)

    def test_from_process_info(self):
        proc_info = {
            "pid": 1234,
            "ppid": 5678,
            "name": "powershell.exe",
            "parent_name": "explorer.exe",
            "username": "user",
            "cmdline": ["powershell.exe", "-enc", "abc"],
        }
        event = Event.from_process_info(proc_info)
        self.assertEqual(event.event_type, "process_start")
        self.assertEqual(event.source, "process_monitor")
        self.assertEqual(event.pid, 1234)
        self.assertEqual(event.ppid, 5678)
        self.assertEqual(event.process_name, "powershell.exe")
        self.assertEqual(event.parent_process_name, "explorer.exe")
        self.assertEqual(event.username, "user")
        self.assertEqual(event.command_line, ["powershell.exe", "-enc", "abc"])

    def test_to_dict_serialization(self):
        event = Event(
            event_type="resource_anomaly",
            source="resource_monitor",
            severity="MEDIUM",
            resource_metrics={"resource": "CPU", "usage": 92.5},
        )
        data = event.to_dict()
        self.assertIsInstance(data, dict)
        self.assertEqual(data["event_type"], "resource_anomaly")
        self.assertEqual(data["source"], "resource_monitor")
        self.assertEqual(data["severity"], "MEDIUM")
        self.assertEqual(data["resource_metrics"]["usage"], 92.5)

        # Verify JSON serializability
        json_str = json.dumps(data)
        self.assertIsInstance(json_str, str)
        self.assertIn("resource_anomaly", json_str)

    def test_optional_field_safety(self):
        # File event does not use process/resource fields
        file_event = Event(
            event_type="file_action",
            source="file_monitor",
            file_path="monitored_folder/test.txt",
            file_action="created",
        )
        self.assertIsNone(file_event.pid)
        self.assertIsNone(file_event.resource_metrics)
        self.assertIsNone(file_event.network_info)
        self.assertEqual(file_event.file_path, "monitored_folder/test.txt")

    def test_realistic_suspicious_process_event(self):
        proc_info = {
            "pid": 16288,
            "ppid": 3668,
            "name": "powershell.exe",
            "parent_name": "powershell.exe",
            "username": "SYSTEM",
            "cmdline": ["powershell.exe", "-windowstyle", "hidden", "-enc", "aW1wb3J0"],
            "cpu_percent": 12.0,
            "memory_percent": 15.0,
        }
        event = process_event_from_dict(proc_info)
        self.assertEqual(event.pid, 16288)
        self.assertEqual(event.process_name, "powershell.exe")
        self.assertIn("encoded_command", event.indicators)
        self.assertIn("hidden_execution", event.indicators)
        # score = 4 (encoded) + 3 (hidden) + 1 (privileged SYSTEM) = 8
        self.assertEqual(event.risk_score, 8)
        self.assertEqual(event.risk_level, "HIGH")
        self.assertEqual(event.severity, "HIGH")

    def test_resource_anomaly_event_creation(self):
        res_event = Event(
            event_type="resource_anomaly",
            source="resource_monitor",
            severity="MEDIUM",
            resource_metrics={"resource": "MEMORY", "usage": 86.4, "is_sustained": True},
            risk_score=3,
            risk_level="MEDIUM",
            risk_reasons=["Sustained elevated memory usage"],
        )
        self.assertEqual(res_event.event_type, "resource_anomaly")
        self.assertEqual(res_event.source, "resource_monitor")
        self.assertEqual(res_event.severity, "MEDIUM")
        self.assertEqual(res_event.resource_metrics["usage"], 86.4)
        self.assertEqual(res_event.risk_score, 3)

    def test_file_action_event_creation(self):
        file_event = Event(
            event_type="file_action",
            source="file_monitor",
            severity="WARNING",
            file_path="monitored_folder/doc.txt",
            file_action="deleted",
        )
        self.assertEqual(file_event.event_type, "file_action")
        self.assertEqual(file_event.source, "file_monitor")
        self.assertEqual(file_event.severity, "WARNING")
        self.assertEqual(file_event.file_action, "deleted")


if __name__ == "__main__":
    unittest.main()

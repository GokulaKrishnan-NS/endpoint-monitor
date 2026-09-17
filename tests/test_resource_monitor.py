import unittest
import os
import tempfile
import json

from src.monitors.resource_monitor import (
    ResourceMonitor,
    ResourceStateTracker,
    format_bytes,
    get_default_mount_point,
    load_config,
)


class TestResourceMonitor(unittest.TestCase):

    def test_format_bytes(self):
        self.assertEqual(format_bytes(None), "N/A")
        self.assertEqual(format_bytes("invalid"), "N/A")
        self.assertEqual(format_bytes(500), "500.00 B")
        self.assertEqual(format_bytes(1024), "1.00 KB")
        self.assertEqual(format_bytes(1024 * 1024 * 1024), "1.00 GB")

    def test_get_default_mount_point(self):
        mount_point = get_default_mount_point()
        self.assertIsInstance(mount_point, str)
        self.assertTrue(len(mount_point) > 0)

    def test_load_config_nonexistent_and_empty(self):
        config_nonexistent = load_config("nonexistent_path_12345.json")
        self.assertIn("check_interval", config_nonexistent)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            f.write("")
            temp_path = f.name

        try:
            config_empty = load_config(temp_path)
            self.assertIn("check_interval", config_empty)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_resource_state_tracker_transitions(self):
        tracker = ResourceStateTracker(
            name="CPU",
            medium_threshold=70.0,
            high_threshold=90.0,
            sustained_samples=3,
        )
        self.assertEqual(tracker.current_state, "NORMAL")

        # 1. Normal usage sample -> no alert
        alerts = tracker.update(50.0)
        self.assertEqual(len(alerts), 0)

        # 2. Medium threshold crossing -> WARNING alert
        alerts = tracker.update(75.0)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "WARNING")
        self.assertEqual(alerts[0]["severity"], "MEDIUM")
        self.assertEqual(tracker.current_state, "MEDIUM")

        # 3. High threshold crossing -> ALERT alert
        alerts = tracker.update(95.0)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "ALERT")
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(tracker.current_state, "HIGH")

        # 4. Sustained high usage (2 more high samples to hit sustained_samples=3)
        tracker.update(95.0)
        sustained_alerts = tracker.update(95.0)
        self.assertEqual(len(sustained_alerts), 1)
        self.assertTrue(sustained_alerts[0]["is_sustained"])

        # 5. Recovery to normal -> RECOVERY alert
        rec_alerts = tracker.update(40.0)
        self.assertEqual(len(rec_alerts), 1)
        self.assertEqual(rec_alerts[0]["type"], "RECOVERY")
        self.assertEqual(tracker.current_state, "NORMAL")

    def test_collect_metrics(self):
        monitor = ResourceMonitor()
        metrics = monitor.collect_metrics()
        self.assertIn("timestamp", metrics)
        self.assertIn("cpu", metrics)
        self.assertIn("memory", metrics)
        self.assertIn("percent", metrics["cpu"])
        self.assertIn("percent", metrics["memory"])

    def test_check_resources(self):
        monitor = ResourceMonitor()
        result = monitor.check_resources()
        self.assertIn("metrics", result)
        self.assertIn("alerts", result)
        self.assertIn("overall_severity", result)
        self.assertIn(result["overall_severity"], ["LOW", "MEDIUM", "HIGH"])


if __name__ == "__main__":
    unittest.main()

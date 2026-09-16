import unittest
import os
import tempfile
import json

from src.baseline.baseline_engine import BaselineEngine, Z_SCORE_THRESHOLD
from src.models.event import Event


class TestBaselineEngine(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.storage_path = os.path.join(self.temp_dir.name, "test_baseline.json")
        self.engine = BaselineEngine(storage_path=self.storage_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_initial_state(self):
        self.assertEqual(self.engine.total_observed_events, 0)
        self.assertEqual(self.engine.process_profiles, {})
        self.assertEqual(self.engine.cpu_samples, [])
        self.assertEqual(self.engine.memory_samples, [])

    def test_collect_clean_event(self):
        event = Event(
            event_type="process_start",
            source="process_monitor",
            pid=100,
            ppid=1,
            process_name="notepad.exe",
            parent_process_name="explorer.exe",
            username="user1",
            risk_score=0,
            indicators=[],
        )
        self.engine.collect_event(event)
        self.assertEqual(self.engine.total_observed_events, 1)
        self.assertIn("notepad.exe", self.engine.process_profiles)
        profile = self.engine.process_profiles["notepad.exe"]
        self.assertEqual(profile["execution_count"], 1)
        self.assertIn("explorer.exe", profile["known_parents"])
        self.assertIn("user1", profile["known_users"])

    def test_poisoning_prevention(self):
        suspicious_event = Event(
            event_type="process_start",
            source="process_monitor",
            pid=200,
            ppid=1,
            process_name="malware.exe",
            parent_process_name="cmd.exe",
            username="user1",
            indicators=["encoded_command"],
            risk_score=4,
        )
        self.engine.collect_event(suspicious_event)

        # Event should be rejected from baseline learning
        self.assertEqual(self.engine.total_observed_events, 0)
        self.assertNotIn("malware.exe", self.engine.process_profiles)

    def test_warmup_phase_behavior(self):
        event = Event(
            event_type="process_start",
            source="process_monitor",
            pid=300,
            process_name="unknown_tool.exe",
            parent_process_name="browser.exe",
            username="user1",
        )
        # In warm-up mode (total_observed_events < 20)
        result = self.engine.analyze_event(event)
        self.assertEqual(result["status"], "LEARNING")
        self.assertFalse(result["is_anomaly"])

    def test_anomaly_detection_after_warmup(self):
        # Simulate warm-up phase by collecting 25 clean explorer->notepad events
        for i in range(25):
            clean_evt = Event(
                event_type="process_start",
                source="process_monitor",
                pid=1000 + i,
                process_name="notepad.exe",
                parent_process_name="explorer.exe",
                username="user1",
                risk_score=0,
                indicators=[],
            )
            self.engine.collect_event(clean_evt)

        self.assertGreaterEqual(self.engine.total_observed_events, 20)

        # Test normal event (matching known baseline)
        normal_evt = Event(
            event_type="process_start",
            source="process_monitor",
            pid=2000,
            process_name="notepad.exe",
            parent_process_name="explorer.exe",
            username="user1",
        )
        res_normal = self.engine.analyze_event(normal_evt)
        self.assertEqual(res_normal["status"], "ENFORCING")
        self.assertFalse(res_normal["is_anomaly"])
        self.assertEqual(res_normal["anomaly_score"], 0)

        # Test anomalous lineage event (msedgewebview2.exe -> notepad.exe)
        abnormal_evt = Event(
            event_type="process_start",
            source="process_monitor",
            pid=2001,
            process_name="notepad.exe",
            parent_process_name="msedgewebview2.exe",
            username="user1",
        )
        res_abnormal = self.engine.analyze_event(abnormal_evt)
        self.assertEqual(res_abnormal["status"], "ENFORCING")
        self.assertTrue(res_abnormal["is_anomaly"])
        self.assertGreaterEqual(res_abnormal["anomaly_score"], 3)
        self.assertEqual(res_abnormal["anomaly_level"], "MEDIUM")
        self.assertTrue(any("Unseen parent-child lineage" in r for r in res_abnormal["reasons"]))

    def test_unseen_user_context_anomaly(self):
        # Warm up with user1
        for i in range(25):
            clean_evt = Event(
                event_type="process_start",
                source="process_monitor",
                pid=1000 + i,
                process_name="calc.exe",
                parent_process_name="explorer.exe",
                username="user1",
            )
            self.engine.collect_event(clean_evt)

        # Execute calc.exe with unseen user2 + unseen lineage (cmd.exe)
        anom_evt = Event(
            event_type="process_start",
            source="process_monitor",
            pid=3000,
            process_name="calc.exe",
            parent_process_name="cmd.exe",
            username="user2",
        )
        res = self.engine.analyze_event(anom_evt)
        self.assertTrue(res["is_anomaly"])
        self.assertGreaterEqual(res["anomaly_score"], 5)  # 3 (lineage) + 2 (user) = 5
        self.assertEqual(res["anomaly_level"], "HIGH")

    def test_resource_zscore_calculation(self):
        samples = [10.0, 12.0, 11.0, 10.5, 11.5, 10.0, 12.5, 11.0, 10.8, 11.2]
        stats = self.engine.compute_stats(samples)
        self.assertAlmostEqual(stats["mean"], 11.05, places=1)
        self.assertGreater(stats["stddev"], 0.0)

        z = self.engine.compute_z_score(25.0, stats["mean"], stats["stddev"])
        self.assertGreater(z, Z_SCORE_THRESHOLD)

    def test_resource_zscore_spike_anomaly(self):
        # Collect 15 stable CPU metric samples (~10%)
        for i in range(15):
            res_evt = Event(
                event_type="resource_anomaly",
                source="resource_monitor",
                resource_metrics={"cpu": {"percent": 10.0 + (i % 3)}},
            )
            self.engine.collect_event(res_evt)

        # Trigger spike at 95% CPU
        spike_evt = Event(
            event_type="resource_anomaly",
            source="resource_monitor",
            resource_metrics={"cpu": {"percent": 95.0}},
        )
        res = self.engine.analyze_event(spike_evt)
        self.assertTrue(any("Abnormal CPU usage spike" in r for r in res["reasons"]))

    def test_missing_optional_fields_safety(self):
        # Event missing process details and resource details
        sparse_evt = Event(
            event_type="process_start",
            source="process_monitor",
            process_name=None,
            parent_process_name=None,
            username=None,
        )
        res = self.engine.analyze_event(sparse_evt)
        self.assertEqual(res["anomaly_score"], 0)
        self.assertFalse(res["is_anomaly"])

        # Should not crash on collect_event
        self.engine.collect_event(sparse_evt)

    def test_save_and_load_baseline(self):
        clean_evt = Event(
            event_type="process_start",
            source="process_monitor",
            pid=100,
            process_name="cmd.exe",
            parent_process_name="explorer.exe",
            username="user1",
        )
        self.engine.collect_event(clean_evt)
        self.engine.save_baseline()

        self.assertTrue(os.path.exists(self.storage_path))

        # Load into fresh engine
        new_engine = BaselineEngine(storage_path=self.storage_path)
        self.assertEqual(new_engine.total_observed_events, 1)
        self.assertIn("cmd.exe", new_engine.process_profiles)


if __name__ == "__main__":
    unittest.main()

import unittest
import os
from unittest.mock import patch, MagicMock

from src.monitors.process_monitor import (
    ProcessIdentityRegistry,
    get_parent_process_name,
    get_process_identity,
    get_running_processes,
    get_new_processes,
    is_same_process,
)


class TestProcessMonitor(unittest.TestCase):

    def test_get_parent_process_name_valid(self):
        # Current process parent PID should exist
        parent_name = get_parent_process_name(os.getppid())
        self.assertTrue(parent_name is None or isinstance(parent_name, str))

    def test_get_parent_process_name_invalid(self):
        # Extremely high PID should raise NoSuchProcess internally and return None
        parent_name = get_parent_process_name(99999999)
        self.assertIsNone(parent_name)

    def test_get_running_processes(self):
        processes = get_running_processes()
        self.assertIsInstance(processes, dict)
        self.assertGreater(len(processes), 0)

        # Check structure of at least one process
        sample_pid = next(iter(processes))
        proc_info = processes[sample_pid]
        expected_keys = {
            "pid",
            "ppid",
            "name",
            "exe",
            "username",
            "status",
            "create_time",
            "cpu_percent",
            "memory_percent",
            "cmdline",
            "parent_name",
        }
        self.assertTrue(expected_keys.issubset(proc_info.keys()))

    def test_deterministic_live_process_snapshot(self):
        """
        Deterministic live-process test that launches a benign child process,
        confirms its PID and executable are collected while it remains alive,
        and cleans it up reliably.
        """
        import subprocess
        import sys
        marker_cmd = [sys.executable, "-c", "import time; time.sleep(15)"]
        child = subprocess.Popen(marker_cmd)
        try:
            procs = get_running_processes()
            self.assertIn(child.pid, procs)
            child_info = procs[child.pid]
            self.assertEqual(child_info["pid"], child.pid)
            self.assertIn("python", (child_info.get("name") or "").lower())
            self.assertTrue(child_info.get("exe") is None or "python" in child_info["exe"].lower())
            self.assertEqual(child_info["ppid"], os.getpid())
            self.assertIsNotNone(child_info.get("create_time"))
        finally:
            child.terminate()
            try:
                child.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=2.0)

    def test_get_new_processes(self):
        previous = {
            100: {"pid": 100, "name": "system.exe"},
            101: {"pid": 101, "name": "explorer.exe"},
        }
        current = {
            100: {"pid": 100, "name": "system.exe"},
            101: {"pid": 101, "name": "explorer.exe"},
            102: {"pid": 102, "name": "cmd.exe"},
        }

        new_procs = get_new_processes(previous, current)
        self.assertEqual(len(new_procs), 1)
        self.assertEqual(new_procs[0]["pid"], 102)
        self.assertEqual(new_procs[0]["name"], "cmd.exe")

    def test_get_new_processes_no_change(self):
        previous = {100: {"pid": 100, "name": "system.exe"}}
        current = {100: {"pid": 100, "name": "system.exe"}}

        new_procs = get_new_processes(previous, current)
        self.assertEqual(len(new_procs), 0)

    def test_get_parent_process_name_none_and_nonpositive(self):
        import psutil
        own_name = psutil.Process().name()

        # ppid=None must return None and NEVER resolve to current monitor process
        res_none = get_parent_process_name(None)
        self.assertIsNone(res_none)
        self.assertNotEqual(res_none, own_name)

        # Zero and negative PPIDs must safely return None
        self.assertIsNone(get_parent_process_name(0))
        self.assertIsNone(get_parent_process_name(-1))
        self.assertIsNone(get_parent_process_name(-9999))

        # Boolean and non-integer types must safely return None
        self.assertIsNone(get_parent_process_name(True))
        self.assertIsNone(get_parent_process_name(False))
        self.assertIsNone(get_parent_process_name("invalid"))

    def test_get_parent_process_name_mocked_valid(self):
        mock_proc = MagicMock()
        mock_proc.name.return_value = "explorer.exe"

        with patch("psutil.Process", return_value=mock_proc) as mock_psutil_proc:
            name = get_parent_process_name(1234)
            self.assertEqual(name, "explorer.exe")
            mock_psutil_proc.assert_called_once_with(1234)

    def test_get_parent_process_name_disappearing_and_errors(self):
        import psutil

        for exc in (
            psutil.NoSuchProcess(1234),
            psutil.AccessDenied(1234),
            psutil.ZombieProcess(1234),
            OSError("System call error"),
            ValueError("Bad PID"),
        ):
            with patch("psutil.Process", side_effect=exc):
                self.assertIsNone(get_parent_process_name(1234))

    def test_get_new_processes_pid_reuse_changed_creation_time(self):
        previous = {
            200: {
                "pid": 200,
                "name": "first_worker.exe",
                "create_time": 1000.0,
            }
        }
        current = {
            200: {
                "pid": 200,
                "name": "recycled_worker.exe",
                "create_time": 1005.0,
            }
        }

        new_procs = get_new_processes(previous, current)
        self.assertEqual(len(new_procs), 1)
        self.assertEqual(new_procs[0]["pid"], 200)
        self.assertEqual(new_procs[0]["name"], "recycled_worker.exe")
        self.assertEqual(new_procs[0]["create_time"], 1005.0)

    def test_get_new_processes_pid_reuse_unchanged_creation_time(self):
        previous = {
            200: {
                "pid": 200,
                "name": "running_worker.exe",
                "create_time": 1000.0,
            }
        }
        current = {
            200: {
                "pid": 200,
                "name": "running_worker.exe",
                "create_time": 1000.0,
            }
        }

        new_procs = get_new_processes(previous, current)
        self.assertEqual(len(new_procs), 0)

    def test_get_new_processes_missing_creation_time_metadata(self):
        # When either previous or current snapshot lacks create_time,
        # conservatively treat as unchanged to avoid false duplicate detections
        cases = [
            (
                {200: {"pid": 200, "name": "worker.exe"}},  # no create_time
                {200: {"pid": 200, "name": "worker.exe", "create_time": 1000.0}},
            ),
            (
                {200: {"pid": 200, "name": "worker.exe", "create_time": 1000.0}},
                {200: {"pid": 200, "name": "worker.exe"}},  # no create_time
            ),
            (
                {200: {"pid": 200, "name": "worker.exe", "create_time": None}},
                {200: {"pid": 200, "name": "worker.exe", "create_time": 1000.0}},
            ),
            (
                {200: {"pid": 200, "name": "worker.exe", "create_time": None}},
                {200: {"pid": 200, "name": "worker.exe", "create_time": None}},
            ),
        ]

        for prev_snap, curr_snap in cases:
            new_procs = get_new_processes(prev_snap, curr_snap)
            self.assertEqual(len(new_procs), 0)

    def test_get_new_processes_first_snapshot(self):
        previous = {}
        current = {
            100: {"pid": 100, "name": "system.exe", "create_time": 1000.0},
            101: {"pid": 101, "name": "services.exe", "create_time": 1001.0},
        }

        new_procs = get_new_processes(previous, current)
        self.assertEqual(len(new_procs), 2)
        pids = {p["pid"] for p in new_procs}
        self.assertEqual(pids, {100, 101})

    def test_get_new_processes_edge_cases(self):
        # Empty inputs
        self.assertEqual(get_new_processes({}, {}), [])
        self.assertEqual(get_new_processes(None, {}), [])
        self.assertEqual(get_new_processes({}, None), [])

        # Malformed entries in dictionary
        previous = {100: "not-a-dict"}
        current = {100: {"pid": 100, "name": "repaired.exe", "create_time": 1000.0}}
        new_procs = get_new_processes(previous, current)
        self.assertEqual(len(new_procs), 1)
        self.assertEqual(new_procs[0]["name"], "repaired.exe")

    def test_get_process_identity(self):
        pid, create_time = get_process_identity(
            {"pid": 42, "create_time": 1234.5}
        )
        self.assertEqual(pid, 42)
        self.assertEqual(create_time, 1234.5)

        # Missing or unusable values are reported as None
        pid, create_time = get_process_identity({"pid": 42})
        self.assertEqual(pid, 42)
        self.assertIsNone(create_time)

        pid, create_time = get_process_identity({"pid": 42, "create_time": "bad"})
        self.assertIsNone(create_time)

        pid, create_time = get_process_identity("not-a-dict")
        self.assertIsNone(pid)
        self.assertIsNone(create_time)

    def test_is_same_process(self):
        base = {"pid": 10, "create_time": 1000.0}

        self.assertTrue(is_same_process(base, dict(base)))
        # Recycled PID (different creation time) is a different process
        self.assertFalse(
            is_same_process(base, {"pid": 10, "create_time": 2000.0})
        )
        # Different PID is never the same process
        self.assertFalse(
            is_same_process(base, {"pid": 11, "create_time": 1000.0})
        )
        # Unknown creation time is treated conservatively as unchanged
        self.assertTrue(is_same_process(base, {"pid": 10}))
        self.assertTrue(is_same_process({"pid": 10}, dict(base)))


class TestProcessIdentityRegistry(unittest.TestCase):
    """The identity registry correlates polling and event driven telemetry."""

    def test_unseen_pid_is_new(self):
        registry = ProcessIdentityRegistry(tolerance=5.0)
        self.assertTrue(registry.is_new(100, 1000.0))
        self.assertFalse(registry.matches(100, 1000.0))

    def test_registered_identity_matches(self):
        registry = ProcessIdentityRegistry(tolerance=5.0)
        registry.register(100, 1000.0, source="polling")
        self.assertTrue(registry.matches(100, 1000.0))
        self.assertTrue(registry.matches(100, 1002.0))
        self.assertFalse(registry.is_new(100, 1000.0))

    def test_pid_reuse_is_detected(self):
        registry = ProcessIdentityRegistry(tolerance=5.0)
        registry.register(100, 1000.0)
        # A recycled PID has a completely different creation time
        self.assertTrue(registry.is_new(100, 5000.0))
        registry.register(100, 5000.0)
        self.assertTrue(registry.matches(100, 5001.0))

    def test_missing_timestamps_are_conservative(self):
        registry = ProcessIdentityRegistry(tolerance=5.0)
        registry.register(100, None)
        self.assertTrue(registry.matches(100, 1000.0))
        self.assertTrue(registry.matches(100, None))

    def test_capacity_is_bounded(self):
        registry = ProcessIdentityRegistry(tolerance=5.0, capacity=10)
        for index in range(100):
            registry.register(index, float(index))
        self.assertLessEqual(len(registry), 10)

    def test_source_tracking_and_clear(self):
        registry = ProcessIdentityRegistry()
        registry.register(7, 10.0, source="telemetry")
        self.assertEqual(registry.get_source(7), "telemetry")
        registry.clear()
        self.assertEqual(len(registry), 0)
        self.assertFalse(registry.matches(7, 10.0))


if __name__ == "__main__":
    unittest.main()

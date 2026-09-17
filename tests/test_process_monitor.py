import unittest
import os
from unittest.mock import patch, MagicMock

from src.monitors.process_monitor import (
    get_parent_process_name,
    get_running_processes,
    get_new_processes,
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
            "username",
            "status",
            "create_time",
            "cpu_percent",
            "memory_percent",
            "cmdline",
            "parent_name",
        }
        self.assertTrue(expected_keys.issubset(proc_info.keys()))

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


if __name__ == "__main__":
    unittest.main()

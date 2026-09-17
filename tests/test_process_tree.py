import unittest

from src.analysis.process_tree import (
    ProcessNode,
    ProcessTree,
    ProcessTreeAnalyzer,
    build_process_tree,
)
from src.main import process_event_from_dict
from src.models.event import Event


class TestProcessTreeAnalysis(unittest.TestCase):
    """
    Test suite for Process-Tree Analysis:
    - Normal parent-child relationships
    - Suspicious parent-child relationships
    - Multi-level process chains
    - Missing/disappeared processes
    - Permission / invalid PIDs / cyclic relationships
    - Continuous monitoring tree updates
    - Integration with standardized Event and Risk pipelines
    - Tree ASCII visualization rendering
    - Configurable rules override
    """

    def setUp(self):
        self.analyzer = ProcessTreeAnalyzer()

    # 1. Normal parent-child relationship
    def test_normal_parent_child_relationship(self):
        """A benign parent-child relationship (e.g. explorer.exe -> notepad.exe) is LOW risk."""
        processes = {
            100: {
                "pid": 100,
                "ppid": 1,
                "name": "explorer.exe",
                "parent_name": "userinit.exe",
                "username": "user",
                "cmdline": ["explorer.exe"],
            },
            200: {
                "pid": 200,
                "ppid": 100,
                "name": "notepad.exe",
                "parent_name": "explorer.exe",
                "username": "user",
                "cmdline": ["notepad.exe", "file.txt"],
            },
        }

        tree = ProcessTree.build(processes)
        analysis = self.analyzer.analyze_process(processes[200], tree)

        self.assertFalse(analysis["is_suspicious"])
        self.assertEqual(analysis["total_score"], 0)
        self.assertEqual(analysis["severity"], "LOW")
        self.assertEqual(analysis["indicators"], [])
        self.assertEqual(analysis["reasons"], [])
        self.assertEqual(analysis["lineage"], ["userinit.exe", "explorer.exe", "notepad.exe"])

    # 2. Suspicious parent-child relationship: Browser spawning PowerShell
    def test_suspicious_parent_child_browser_spawning_shell(self):
        """Browser spawning PowerShell triggers suspicious lineage and elevates risk."""
        processes = {
            100: {
                "pid": 100,
                "ppid": 1,
                "name": "explorer.exe",
                "parent_name": "winlogon.exe",
            },
            500: {
                "pid": 500,
                "ppid": 100,
                "name": "chrome.exe",
                "parent_name": "explorer.exe",
            },
            600: {
                "pid": 600,
                "ppid": 500,
                "name": "powershell.exe",
                "parent_name": "chrome.exe",
                "cmdline": ["powershell.exe", "-nop"],
            },
        }

        tree = ProcessTree.build(processes)
        analysis = self.analyzer.analyze_process(processes[600], tree)

        self.assertTrue(analysis["is_suspicious"])
        self.assertIn("suspicious_process_lineage", analysis["indicators"])
        self.assertGreaterEqual(analysis["total_score"], 4)
        self.assertIn(analysis["severity"], ["MEDIUM", "HIGH"])
        self.assertTrue(
            any("chrome.exe -> powershell.exe" in r for r in analysis["reasons"])
        )

    # 3. Suspicious parent-child relationship: Office spawning CMD
    def test_suspicious_parent_child_office_spawning_cmd(self):
        """Office application spawning command shell triggers HIGH severity lineage."""
        proc_info = {
            "pid": 3001,
            "ppid": 2001,
            "name": "cmd.exe",
            "parent_name": "winword.exe",
            "cmdline": ["cmd.exe", "/c", "calc.exe"],
        }
        analysis = self.analyzer.analyze_process(proc_info, None)

        self.assertTrue(analysis["is_suspicious"])
        self.assertIn("suspicious_process_lineage", analysis["indicators"])
        self.assertEqual(analysis["severity"], "HIGH")
        self.assertEqual(analysis["total_score"], 5)
        self.assertTrue(
            any("winword.exe -> cmd.exe" in r for r in analysis["reasons"])
        )

    # 4. Multi-level process chain
    def test_multi_level_process_chain(self):
        """
        Multi-level chain:
        explorer.exe -> chrome.exe -> powershell.exe -> cmd.exe
        Resolves full ancestry and detects multi-level shell invocation chain.
        """
        processes = {
            10: {"pid": 10, "ppid": 1, "name": "explorer.exe"},
            20: {"pid": 20, "ppid": 10, "name": "chrome.exe"},
            30: {"pid": 30, "ppid": 20, "name": "powershell.exe"},
            40: {"pid": 40, "ppid": 30, "name": "cmd.exe"},
        }

        tree = ProcessTree.build(processes)
        cmd_node = tree.get_node(40)
        self.assertIsNotNone(cmd_node)

        # Verify lineage resolution
        lineage = tree.get_lineage(40)
        self.assertEqual(lineage, ["explorer.exe", "chrome.exe", "powershell.exe", "cmd.exe"])

        # Analyze process 40 (cmd.exe)
        analysis = self.analyzer.analyze_process(processes[40], tree)

        self.assertTrue(analysis["is_suspicious"])
        # Should detect multi_level_shell_chain and shell_spawning_shell
        self.assertIn("multi_level_shell_chain", analysis["indicators"])
        self.assertEqual(analysis["severity"], "HIGH")
        self.assertGreaterEqual(analysis["total_score"], 7)
        self.assertEqual(analysis["depth"], 4)

        # Verify ASCII tree contains TARGET and hierarchy
        rendered = analysis["tree_rendered"]
        self.assertIn("chrome.exe", rendered)
        self.assertIn("powershell.exe", rendered)
        self.assertIn("cmd.exe (PID: 40) [TARGET]", rendered)

    # 5. Missing / disappeared process
    def test_missing_disappeared_parent(self):
        """
        When parent process has terminated/exited and is absent from snapshot,
        the tree builds cleanly and uses captured parent_name telemetry.
        """
        processes = {
            999: {
                "pid": 999,
                "ppid": 5555,  # 5555 is not in snapshot
                "name": "powershell.exe",
                "parent_name": "brave.exe",  # Terminated browser
                "cmdline": ["powershell.exe"],
            }
        }

        tree = ProcessTree.build(processes)
        node = tree.get_node(999)
        self.assertIsNotNone(node)
        self.assertIsNone(node.parent)  # Missing parent handled safely

        lineage = tree.get_lineage(999)
        self.assertEqual(lineage, ["brave.exe", "powershell.exe"])

        analysis = self.analyzer.analyze_process(processes[999], tree)
        self.assertTrue(analysis["is_suspicious"])
        self.assertIn("suspicious_process_lineage", analysis["indicators"])
        self.assertTrue(
            any("brave.exe -> powershell.exe" in r for r in analysis["reasons"])
        )

    # 6. Permission errors and invalid PIDs
    def test_permission_and_invalid_pids(self):
        """
        Handles negative PIDs, non-integer PIDs, cycles, and empty structures safely.
        """
        malformed_processes = {
            -1: {"pid": -1, "ppid": 0, "name": "bad.exe"},
            "invalid": {"pid": "not_an_int", "ppid": 1, "name": "bad2.exe"},
            10: {"pid": 10, "ppid": 10, "name": "self_parent.exe"},  # Self-parent loop
            20: {"pid": 20, "ppid": 30, "name": "cycle_a.exe"},
            30: {"pid": 30, "ppid": 20, "name": "cycle_b.exe"},  # Cycle 20 <-> 30
            40: {"pid": 40, "ppid": None, "name": None},  # None name
        }

        # Must build without throwing exceptions or infinite loops
        tree = ProcessTree.build(malformed_processes)
        self.assertIsInstance(tree, ProcessTree)

        # Self-parent node should be in roots
        node10 = tree.get_node(10)
        self.assertIsNotNone(node10)
        self.assertIn(node10, tree.roots)

        # Ancestry of cycle should terminate safely
        chain20 = tree.get_ancestry_chain(20)
        self.assertTrue(len(chain20) <= 2)

        # None name handled gracefully
        node40 = tree.get_node(40)
        self.assertEqual(node40.name, "unknown")

    # 7. Continuous monitoring dynamic tree updates
    def test_continuous_monitoring_tree_updates(self):
        """
        Simulates consecutive monitoring cycles where new processes spawn
        and are dynamically attached to the hierarchy.
        """
        initial_snapshot = {
            100: {"pid": 100, "ppid": 1, "name": "explorer.exe"},
            200: {"pid": 200, "ppid": 100, "name": "chrome.exe"},
        }
        tree1 = ProcessTree.build(initial_snapshot)
        self.assertEqual(len(tree1.nodes), 2)

        # Next cycle: user or exploit spawns powershell from chrome
        updated_snapshot = dict(initial_snapshot)
        updated_snapshot[300] = {
            "pid": 300,
            "ppid": 200,
            "name": "powershell.exe",
            "parent_name": "chrome.exe",
        }

        tree2 = ProcessTree.build(updated_snapshot)
        self.assertEqual(len(tree2.nodes), 3)

        new_node = tree2.get_node(300)
        self.assertEqual(new_node.parent.name, "chrome.exe")
        self.assertEqual(new_node.parent.parent.name, "explorer.exe")

        analysis = self.analyzer.analyze_process(updated_snapshot[300], tree2)
        self.assertTrue(analysis["is_suspicious"])
        self.assertIn("suspicious_process_lineage", analysis["indicators"])

    # 8. Integration with standardized Event and Risk pipeline
    def test_integration_with_event_and_risk_pipeline(self):
        """
        End-to-end integration:
        process dictionary -> process_event_from_dict()
        -> Event object with process_tree metadata, indicators, and elevated risk score.
        """
        processes = {
            100: {"pid": 100, "ppid": 1, "name": "explorer.exe"},
            200: {"pid": 200, "ppid": 100, "name": "chrome.exe"},
            300: {
                "pid": 300,
                "ppid": 200,
                "name": "powershell.exe",
                "parent_name": "chrome.exe",
                "username": "SYSTEM",
                "cmdline": ["powershell.exe", "-enc", "SQBFAFgA"],
            },
        }
        tree = ProcessTree.build(processes)

        event = process_event_from_dict(
            processes[300],
            process_tree=tree,
            tree_analyzer=self.analyzer,
        )

        self.assertIsInstance(event, Event)
        self.assertEqual(event.pid, 300)
        self.assertEqual(event.process_name, "powershell.exe")

        # Indicators should contain both command and process-tree tags
        self.assertIn("encoded_command", event.indicators)
        self.assertIn("suspicious_process_lineage", event.indicators)

        # Risk score calculation:
        # 4 (encoded_command) + 4 (suspicious_process_lineage) + 1 (privileged SYSTEM) = 9
        self.assertGreaterEqual(event.risk_score, 8)
        self.assertEqual(event.risk_level, "HIGH")
        self.assertEqual(event.severity, "HIGH")

        # Metadata should contain process-tree analysis
        tree_meta = event.metadata.get("process_tree")
        self.assertIsNotNone(tree_meta)
        self.assertTrue(tree_meta["is_suspicious"])
        self.assertEqual(tree_meta["lineage"], ["explorer.exe", "chrome.exe", "powershell.exe"])
        self.assertIn("chrome.exe", tree_meta["tree_rendered"])

        # Reasons should clearly explain the lineage finding
        self.assertTrue(
            any("chrome.exe -> powershell.exe" in r for r in event.risk_reasons)
        )

    # 9. Tree ASCII visualization rendering
    def test_tree_ascii_rendering(self):
        """Verifies tree formatting and target marker."""
        processes = {
            1: {"pid": 1, "ppid": 0, "name": "system.exe"},
            2: {"pid": 2, "ppid": 1, "name": "service.exe"},
            3: {"pid": 3, "ppid": 2, "name": "worker.exe"},
        }
        tree = ProcessTree.build(processes)
        rendered = tree.render_tree(3)

        self.assertIn("system.exe (PID: 1)", rendered)
        self.assertIn("+-- service.exe (PID: 2)", rendered)
        self.assertIn("+-- worker.exe (PID: 3) [TARGET]", rendered)

    # 10. Custom configuration override
    def test_custom_configuration_override(self):
        """Custom rules can be configured to detect proprietary or application-specific pairs."""
        custom_config = {
            "enabled": True,
            "max_tree_depth": 5,
            "suspicious_rules": [
                {
                    "parents": ["custom_daemon.exe"],
                    "children": ["custom_shell.exe"],
                    "indicator": "custom_lineage_anomaly",
                    "score": 6,
                    "severity": "HIGH",
                    "reason": "Custom daemon spawned custom shell",
                }
            ],
            "multi_level_rules": [],
        }
        custom_analyzer = ProcessTreeAnalyzer(config=custom_config)

        proc_info = {
            "pid": 777,
            "ppid": 666,
            "name": "custom_shell.exe",
            "parent_name": "custom_daemon.exe",
        }
        analysis = custom_analyzer.analyze_process(proc_info, None)

        self.assertTrue(analysis["is_suspicious"])
        self.assertIn("custom_lineage_anomaly", analysis["indicators"])
        self.assertEqual(analysis["total_score"], 6)
        self.assertEqual(analysis["severity"], "HIGH")


if __name__ == "__main__":
    unittest.main()

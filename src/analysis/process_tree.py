"""
Process-Tree Analysis Module

Constructs hierarchical process trees using PID, PPID, process name, and
parent-process context. Detects suspicious parent-child relationships and
multi-level execution chains using configurable rules and heuristics,
integrating findings into the standardized Event model and risk pipeline.
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional, Set, Tuple


DEFAULT_PROCESS_TREE_CONFIG = {
    "enabled": True,
    "max_tree_depth": 10,
    "suspicious_rules": [
        {
            "parents": [
                "chrome.exe",
                "firefox.exe",
                "msedge.exe",
                "brave.exe",
                "opera.exe",
                "iexplore.exe",
                "safari.exe",
                "msedgewebview2.exe",
            ],
            "children": [
                "cmd.exe",
                "powershell.exe",
                "pwsh.exe",
                "bash.exe",
                "sh.exe",
                "wscript.exe",
                "cscript.exe",
                "certutil.exe",
                "mshta.exe",
            ],
            "indicator": "suspicious_process_lineage",
            "score": 4,
            "severity": "MEDIUM",
            "reason": "Web browser spawned command shell or script host",
        },
        {
            "parents": [
                "winword.exe",
                "excel.exe",
                "powerpnt.exe",
                "outlook.exe",
                "msaccess.exe",
                "acrobat.exe",
                "acrord32.exe",
            ],
            "children": [
                "cmd.exe",
                "powershell.exe",
                "pwsh.exe",
                "wscript.exe",
                "cscript.exe",
                "mshta.exe",
                "regsvr32.exe",
                "rundll32.exe",
                "certutil.exe",
                "schtasks.exe",
            ],
            "indicator": "suspicious_process_lineage",
            "score": 5,
            "severity": "HIGH",
            "reason": "Office/Productivity application spawned command interpreter or script host",
        },
        {
            "parents": [
                "w3wp.exe",
                "httpd.exe",
                "nginx.exe",
                "tomcat.exe",
                "sqlservr.exe",
                "postgres.exe",
                "mysqld.exe",
            ],
            "children": [
                "cmd.exe",
                "powershell.exe",
                "pwsh.exe",
                "bash.exe",
                "sh.exe",
                "whoami.exe",
                "net.exe",
            ],
            "indicator": "suspicious_process_lineage",
            "score": 5,
            "severity": "HIGH",
            "reason": "Server or database daemon spawned command shell",
        },
        {
            "parents": [
                "calc.exe",
                "notepad.exe",
                "spoolsv.exe",
            ],
            "children": [
                "cmd.exe",
                "powershell.exe",
                "pwsh.exe",
                "rundll32.exe",
                "regsvr32.exe",
            ],
            "indicator": "suspicious_process_lineage",
            "score": 4,
            "severity": "MEDIUM",
            "reason": "Unusual desktop utility spawned command interpreter",
        },
        {
            "parents": ["powershell.exe", "pwsh.exe"],
            "children": ["cmd.exe"],
            "indicator": "shell_spawning_shell",
            "score": 2,
            "severity": "LOW",
            "reason": "PowerShell spawned CMD shell",
        },
        {
            "parents": ["cmd.exe"],
            "children": ["powershell.exe", "pwsh.exe"],
            "indicator": "shell_spawning_shell",
            "score": 2,
            "severity": "LOW",
            "reason": "CMD spawned PowerShell shell",
        },
    ],
    "multi_level_rules": [
        {
            "ancestor_apps": [
                "chrome.exe",
                "firefox.exe",
                "msedge.exe",
                "brave.exe",
                "winword.exe",
                "excel.exe",
                "outlook.exe",
                "powerpnt.exe",
            ],
            "target_shells": [
                "cmd.exe",
                "powershell.exe",
                "pwsh.exe",
                "bash.exe",
                "sh.exe",
            ],
            "min_depth": 2,
            "indicator": "multi_level_shell_chain",
            "score": 5,
            "severity": "HIGH",
            "reason": "Multi-level execution chain from untrusted application to command shell",
        }
    ],
}


class ProcessNode:
    """
    Represents an individual process node within a hierarchical process tree.
    """

    def __init__(
        self,
        pid: int,
        ppid: Optional[int] = None,
        name: Optional[str] = None,
        parent_name: Optional[str] = None,
        username: Optional[str] = None,
        cmdline: Optional[List[str]] = None,
        cpu_percent: Optional[float] = None,
        memory_percent: Optional[float] = None,
        create_time: Optional[float] = None,
        status: Optional[str] = None,
    ):
        self.pid: int = pid
        self.ppid: Optional[int] = ppid
        self.name: str = name or "unknown"
        self.parent_name: Optional[str] = parent_name
        self.username: Optional[str] = username
        self.cmdline: List[str] = cmdline or []
        self.cpu_percent: float = cpu_percent or 0.0
        self.memory_percent: float = memory_percent or 0.0
        self.create_time: Optional[float] = create_time
        self.status: Optional[str] = status

        self.parent: Optional["ProcessNode"] = None
        self.children: List["ProcessNode"] = []

    def add_child(self, child: "ProcessNode") -> None:
        """Add a child node to this process node."""
        if child not in self.children:
            self.children.append(child)
            child.parent = self

    def to_dict(self) -> Dict[str, Any]:
        """Convert the process node into a serializable dictionary."""
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "name": self.name,
            "parent_name": self.parent_name,
            "username": self.username,
            "cmdline": self.cmdline,
            "children_pids": [c.pid for c in self.children],
        }

    def __repr__(self) -> str:
        return f"<ProcessNode pid={self.pid} name={self.name} ppid={self.ppid}>"


class ProcessTree:
    """
    Hierarchical representation of running processes.
    Enables parent-child link resolution, lineage traversal, and ASCII rendering.
    """

    def __init__(self):
        self.nodes: Dict[int, ProcessNode] = {}
        self.roots: List[ProcessNode] = []

    @classmethod
    def build(cls, processes: Dict[int, Dict[str, Any]]) -> "ProcessTree":
        """
        Build a ProcessTree from an existing processes dictionary snapshot
        (as returned by get_running_processes()).
        Handles missing parents, invalid PIDs, and self-referencing loops cleanly.
        """
        tree = cls()
        if not processes:
            return tree

        # Step 1: Instantiate all ProcessNode objects
        for pid_key, pinfo in processes.items():
            try:
                pid = int(pinfo.get("pid", pid_key))
            except (ValueError, TypeError):
                continue

            if pid < 0:
                continue

            ppid_val = pinfo.get("ppid")
            try:
                ppid = int(ppid_val) if ppid_val is not None else None
            except (ValueError, TypeError):
                ppid = None

            node = ProcessNode(
                pid=pid,
                ppid=ppid,
                name=pinfo.get("name"),
                parent_name=pinfo.get("parent_name"),
                username=pinfo.get("username"),
                cmdline=pinfo.get("cmdline"),
                cpu_percent=pinfo.get("cpu_percent"),
                memory_percent=pinfo.get("memory_percent"),
                create_time=pinfo.get("create_time"),
                status=pinfo.get("status"),
            )
            tree.nodes[pid] = node

        # Step 2: Establish parent-child links while preventing loops
        for pid, node in tree.nodes.items():
            ppid = node.ppid

            # Self-parenting or invalid parent
            if ppid is None or ppid == pid:
                tree.roots.append(node)
                continue

            parent_node = tree.nodes.get(ppid)
            if parent_node:
                # Cycle check before attaching
                curr = parent_node
                cycle_detected = False
                visited: Set[int] = {pid}
                while curr is not None:
                    if curr.pid in visited:
                        cycle_detected = True
                        break
                    visited.add(curr.pid)
                    curr = curr.parent

                if not cycle_detected:
                    parent_node.add_child(node)
                else:
                    tree.roots.append(node)
            else:
                # Parent exited / disappeared / not in current snapshot
                tree.roots.append(node)

        return tree

    def get_node(self, pid: int) -> Optional[ProcessNode]:
        """Retrieve a ProcessNode by PID."""
        return self.nodes.get(pid)

    def get_ancestry_chain(self, pid: int) -> List[ProcessNode]:
        """
        Return the list of ProcessNodes from the top-level root ancestor
        down to the node with the specified PID: [root, ..., parent, node].
        """
        node = self.get_node(pid)
        if not node:
            return []

        chain: List[ProcessNode] = []
        curr: Optional[ProcessNode] = node
        visited: Set[int] = set()

        while curr is not None and curr.pid not in visited:
            chain.append(curr)
            visited.add(curr.pid)
            curr = curr.parent

        chain.reverse()
        return chain

    def get_lineage(self, pid: int) -> List[str]:
        """
        Return the list of process names representing the execution lineage.
        If the root ancestor's parent exited but parent_name was captured in telemetry,
        the missing parent name is prepended for completeness.
        """
        chain = self.get_ancestry_chain(pid)
        if not chain:
            node = self.get_node(pid)
            if node:
                return [node.name]
            return []

        lineage = [p.name for p in chain]

        # If the root node has a recorded parent_name that was not in the snapshot,
        # prepend it so the lineage reflects the original caller
        root = chain[0]
        if root.parent is None and root.parent_name:
            if root.parent_name.lower() != root.name.lower():
                lineage.insert(0, root.parent_name)

        return lineage

    def render_tree(self, pid: int, max_depth: int = 10) -> str:
        """
        Format a clean ASCII representation of the process lineage
        and immediate children for the specified PID.
        """
        node = self.get_node(pid)
        if not node:
            return f"Process (PID: {pid}) [Not in active tree]"

        chain = self.get_ancestry_chain(pid)
        if not chain:
            return f"{node.name} (PID: {node.pid})"

        lines: List[str] = []

        # If root had an external parent that already terminated, display it
        root = chain[0]
        indent_level = 0
        if root.parent is None and root.parent_name and root.parent_name.lower() != root.name.lower():
            lines.append(f"{root.parent_name} [Terminated Parent]")
            indent_level += 1

        for i, pnode in enumerate(chain):
            indent = "      " * (indent_level + i - 1) if (indent_level + i) > 0 else ""
            prefix = "+-- " if (indent_level + i) > 0 else ""
            marker = " [TARGET]" if pnode.pid == pid else ""
            lines.append(f"{indent}{prefix}{pnode.name} (PID: {pnode.pid}){marker}")

        # If target has children, display first-level children
        child_indent = "      " * (indent_level + len(chain) - 1)
        for child in node.children[:3]:
            lines.append(f"{child_indent}+-- {child.name} (PID: {child.pid})")
        if len(node.children) > 3:
            lines.append(f"{child_indent}+-- ... ({len(node.children) - 3} more children)")

        return "\n".join(lines)


def load_process_tree_config(config_path: str = "config/config.json") -> Dict[str, Any]:
    """
    Load process tree configuration from JSON file, falling back to defaults.
    """
    config = dict(DEFAULT_PROCESS_TREE_CONFIG)

    if not os.path.exists(config_path):
        return config

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return config
            data = json.loads(content)
            pt_config = data.get("process_tree", {})

            if "enabled" in pt_config:
                config["enabled"] = bool(pt_config["enabled"])
            if "max_tree_depth" in pt_config:
                config["max_tree_depth"] = int(pt_config["max_tree_depth"])
            if "suspicious_rules" in pt_config:
                config["suspicious_rules"] = pt_config["suspicious_rules"]
            if "multi_level_rules" in pt_config:
                config["multi_level_rules"] = pt_config["multi_level_rules"]

    except Exception as e:
        logging.getLogger("endpoint_monitor").debug(
            f"Could not load process_tree config from {config_path}: {e}"
        )

    return config


class ProcessTreeAnalyzer:
    """
    Detects suspicious parent-child relationships and multi-level execution chains.
    Evaluates process trees against configurable security heuristics.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None, config_path: str = "config/config.json"):
        self.config: Dict[str, Any] = config if config is not None else load_process_tree_config(config_path)
        self.logger = logging.getLogger("endpoint_monitor")
        self.enabled: bool = self.config.get("enabled", True)
        self.max_tree_depth: int = self.config.get("max_tree_depth", 10)
        self.suspicious_rules: List[Dict[str, Any]] = self.config.get("suspicious_rules", [])
        self.multi_level_rules: List[Dict[str, Any]] = self.config.get("multi_level_rules", [])

    def evaluate_parent_child(self, parent_name: Optional[str], child_name: Optional[str]) -> List[Dict[str, Any]]:
        """
        Evaluate a parent-child relationship against configured suspicious rules.
        Returns a list of matched rule finding dictionaries.
        """
        if not self.enabled or not parent_name or not child_name:
            return []

        p_lower = parent_name.lower().strip()
        c_lower = child_name.lower().strip()
        findings: List[Dict[str, Any]] = []

        for rule in self.suspicious_rules:
            rule_parents = [p.lower().strip() for p in rule.get("parents", [])]
            rule_children = [c.lower().strip() for c in rule.get("children", [])]

            if p_lower in rule_parents and c_lower in rule_children:
                score = rule.get("score", 4)
                severity = rule.get("severity", "MEDIUM")
                rule_reason = rule.get("reason", "Suspicious parent-child relationship detected")
                indicator = rule.get("indicator", "suspicious_process_lineage")

                findings.append({
                    "type": "PARENT_CHILD",
                    "indicator": indicator,
                    "parent": parent_name,
                    "child": child_name,
                    "score": score,
                    "severity": severity,
                    "reason": f"Suspicious process lineage: {parent_name} -> {child_name} ({rule_reason})",
                })

        return findings

    def evaluate_ancestry_chain(self, chain: List[ProcessNode]) -> List[Dict[str, Any]]:
        """
        Evaluate a multi-level execution chain (e.g. explorer -> chrome -> powershell -> cmd)
        to identify deep or indirect shell invocation chains.
        """
        if not self.enabled or not chain or len(chain) < 2:
            return []

        findings: List[Dict[str, Any]] = []
        chain_names = [node.name.lower() for node in chain]
        chain_str = " -> ".join([node.name for node in chain])

        for rule in self.multi_level_rules:
            ancestor_apps = [a.lower().strip() for a in rule.get("ancestor_apps", [])]
            target_shells = [s.lower().strip() for s in rule.get("target_shells", [])]
            min_depth = rule.get("min_depth", 2)

            # Check if any ancestor matches ancestor_apps and target matches target_shells
            target_node = chain[-1]
            if target_node.name.lower() not in target_shells:
                continue

            for idx, ancestor_name in enumerate(chain_names[:-1]):
                if ancestor_name in ancestor_apps:
                    depth = len(chain) - 1 - idx
                    if depth >= min_depth:
                        score = rule.get("score", 5)
                        severity = rule.get("severity", "HIGH")
                        reason_template = rule.get(
                            "reason", "Multi-level suspicious execution chain detected"
                        )
                        indicator = rule.get("indicator", "multi_level_shell_chain")

                        findings.append({
                            "type": "MULTI_LEVEL_CHAIN",
                            "indicator": indicator,
                            "ancestor": chain[idx].name,
                            "target": target_node.name,
                            "depth": depth,
                            "score": score,
                            "severity": severity,
                            "reason": f"Suspicious execution chain: {chain_str} ({reason_template})",
                        })
                        break

        return findings

    def analyze_process(
        self,
        process_info: Dict[str, Any],
        tree: Optional[ProcessTree] = None,
    ) -> Dict[str, Any]:
        """
        Perform complete process-tree analysis on a process dictionary.
        Returns a structured analysis dictionary containing findings, indicators,
        risk score contribution, lineage list, and ASCII tree representation.
        """
        pid = process_info.get("pid")
        proc_name = process_info.get("name") or "unknown"
        parent_name = process_info.get("parent_name")

        # Lineage and chain resolution
        lineage: List[str] = []
        chain: List[ProcessNode] = []
        tree_rendered = ""

        if tree and pid is not None:
            node = tree.get_node(pid)
            if node and node.parent and not parent_name:
                parent_name = node.parent.name
            chain = tree.get_ancestry_chain(pid)
            lineage = tree.get_lineage(pid)
            tree_rendered = tree.render_tree(pid, max_depth=self.max_tree_depth)

        # Fallback lineage if node was not attached in tree
        if not lineage:
            if parent_name:
                lineage = [parent_name, proc_name]
            else:
                lineage = [proc_name]

        if not tree_rendered:
            if parent_name:
                tree_rendered = f"{parent_name}\n+-- {proc_name} (PID: {pid})"
            else:
                tree_rendered = f"{proc_name} (PID: {pid})"

        # Evaluate rules
        all_findings: List[Dict[str, Any]] = []

        # 1. Direct Parent -> Child evaluation
        direct_findings = self.evaluate_parent_child(parent_name, proc_name)
        all_findings.extend(direct_findings)

        # 2. Multi-level Ancestry Chain evaluation
        if chain:
            chain_findings = self.evaluate_ancestry_chain(chain)
            all_findings.extend(chain_findings)

        # Aggregate indicators and scores
        indicators: List[str] = []
        reasons: List[str] = []
        total_score = 0

        for finding in all_findings:
            ind = finding.get("indicator")
            if ind and ind not in indicators:
                indicators.append(ind)

            reason = finding.get("reason")
            if reason and reason not in reasons:
                reasons.append(reason)

            total_score += finding.get("score", 0)

        # Deduce highest severity from findings
        severity = "LOW"
        if any(f.get("severity") == "HIGH" for f in all_findings) or total_score >= 7:
            severity = "HIGH"
        elif any(f.get("severity") == "MEDIUM" for f in all_findings) or total_score >= 3:
            severity = "MEDIUM"

        return {
            "is_suspicious": len(all_findings) > 0,
            "total_score": total_score,
            "severity": severity,
            "indicators": indicators,
            "reasons": reasons,
            "lineage": lineage,
            "depth": len(lineage),
            "tree_rendered": tree_rendered,
            "findings": all_findings,
        }


def build_process_tree(processes: Dict[int, Dict[str, Any]]) -> ProcessTree:
    """
    Convenience helper function to construct a ProcessTree from a processes dictionary.
    """
    return ProcessTree.build(processes)

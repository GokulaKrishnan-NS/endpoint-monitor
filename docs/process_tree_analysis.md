# Process-Tree Analysis

## 1. What is Process-Tree Analysis?

**Process-Tree Analysis** is an endpoint security intelligence feature that maps running processes into a hierarchical parent-child execution graph. By tracking Process IDs (PIDs) and Parent Process IDs (PPIDs), the engine traces the complete lineage of process execution—from top-level user shells or system managers down through intermediaries to the executing binary.

This hierarchy allows the Endpoint Monitor to identify suspicious process spawning patterns—such as a web browser or office application unexpectedly spawning a shell (`powershell.exe`, `cmd.exe`) or deep multi-level process chains often seen in Living-off-the-Land (LotL) and remote code execution (RCE) attacks.

---

## 2. Why is it Needed?

Modern malware and advanced adversaries rarely execute obvious standalone malicious executables. Instead, they exploit legitimate host binaries and user applications to launch secondary command interpreters:

1. **Drive-by & Browser Exploits**: A compromised browser tab (`chrome.exe`, `msedge.exe`) executing malicious JavaScript to spawn `powershell.exe` or `cmd.exe`.
2. **Malicious Office Documents**: A macro-enabled Word or Excel document (`winword.exe`, `excel.exe`) executing a macro that calls `wscript.exe`, `cscript.exe`, or `powershell.exe`.
3. **Web Server & SQL Injection Exploits**: A web server daemon (`httpd.exe`, `w3wp.exe`) or database service (`postgres.exe`, `sqlservr.exe`) spawning an interactive shell (`sh`, `bash`, `cmd.exe`).
4. **Shell Chaining & Obfuscation**: Cascading execution chains (e.g. `explorer.exe -> chrome.exe -> powershell.exe -> cmd.exe`) where the ultimate malicious command is isolated several levels away from the initial ingress vector.

Without Process-Tree Analysis, an endpoint monitor evaluating `cmd.exe` in isolation only sees a standard command interpreter. With Process-Tree Analysis, the monitor inspects the complete ancestor chain and flags the anomalous lineage.

---

## 3. How the Process Tree is Constructed

The process tree is constructed without duplicate process enumeration. It directly consumes the existing `processes` dictionary collected by `process_monitor.get_running_processes()`.

### Step-by-Step Construction Algorithm:

1. **Node Instantiation**:
   For each process in the snapshot dictionary, a `ProcessNode` instance is created containing `pid`, `ppid`, `name`, `parent_name`, `username`, `cmdline`, and performance metrics.
2. **PID Validation & Sanitization**:
   Negative PIDs, non-integer PIDs, and malformed telemetry are filtered out safely.
3. **Parent-Child Link Resolution**:
   For each node:
   - If `node.ppid` exists in the tree and `node.ppid != node.pid`:
     - A cycle detection loop verifies that attaching `node` to `parent` will not create a circular reference.
     - If clean, `parent.add_child(node)` links `parent -> child` and sets `node.parent = parent`.
   - If `node.ppid` is missing (the parent already exited) or equal to `node.pid` (self-parenting root like System Idle):
     - The node is classified as a tree root (`tree.roots.append(node)`).
     - Its `parent_name` captured in initial telemetry is preserved so the lineage remains complete.
4. **Lineage Traversal (`get_lineage`)**:
   Walks `node.parent` pointers from the target process up to the root ancestor, reversing the chain to produce `[root, ..., parent, target]`.
5. **ASCII Hierarchy Rendering (`render_tree`)**:
   Generates a clear ASCII tree visualizing the execution ancestry and first-level children of the target process using universal terminal-safe connectors (`+-- `).

```text
explorer.exe (PID: 13400)
+-- chrome.exe (PID: 29204)
      +-- cmd.exe (PID: 11196) [TARGET]
            +-- mc-extn-browserhost.exe (PID: 7032)
            +-- conhost.exe (PID: 18228)
```

---

## 4. Detection Logic & Heuristics

The detection engine (`ProcessTreeAnalyzer`) applies two complementary detection layers:

### A. Direct Parent-Child Rules

Evaluates direct parent-child relationships against security rules defined in `config/config.json`:

| Parent Applications | Child Applications | Risk Indicator | Severity | Points | Rationale |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Browsers (`chrome.exe`, `firefox.exe`, `msedge.exe`, `brave.exe`, etc.) | Shells (`cmd.exe`, `powershell.exe`, `pwsh.exe`, `bash.exe`, etc.) | `suspicious_process_lineage` | `MEDIUM` | +4 | Web browser spawned command interpreter (RCE / drive-by compromise). |
| Office Suite (`winword.exe`, `excel.exe`, `powerpnt.exe`, `outlook.exe`) | Shells & Script Hosts (`cmd.exe`, `powershell.exe`, `wscript.exe`, `mshta.exe`) | `suspicious_process_lineage` | `HIGH` | +5 | Office document spawned script host or shell (macro/payload exploit). |
| Server Daemons (`w3wp.exe`, `nginx.exe`, `postgres.exe`, `sqlservr.exe`) | Shells & Reconnaissance (`cmd.exe`, `powershell.exe`, `whoami.exe`, `net.exe`) | `suspicious_process_lineage` | `HIGH` | +5 | Web server or database engine spawned shell (web shell / command injection). |
| Desktop Utilities (`calc.exe`, `notepad.exe`, `spoolsv.exe`) | Interpreters & Injection Targets (`cmd.exe`, `powershell.exe`, `rundll32.exe`) | `suspicious_process_lineage` | `MEDIUM` | +4 | Benign utility spawned interpreter (process injection / masquerading). |
| Shells (`powershell.exe`, `cmd.exe`) | Secondary Shells (`cmd.exe`, `powershell.exe`) | `shell_spawning_shell` | `LOW` | +2 | Shell spawning another shell (secondary command execution). |

### B. Multi-Level Execution Chain Rules

Evaluates the full ancestry chain (`get_ancestry_chain`) to identify deep or indirect invocations where an untrusted application spawned an intermediary that subsequently spawned a shell.

* **Rule**: If an ancestor within depth $\ge 2$ is an untrusted application (e.g. `chrome.exe`, `winword.exe`) and the terminal target is a shell (`cmd.exe`, `powershell.exe`), the engine flags:
  - Indicator: `multi_level_shell_chain`
  - Severity: `HIGH` (+5 points)
  - Explanation: `Suspicious execution chain: explorer.exe -> chrome.exe -> powershell.exe -> cmd.exe`

---

## 5. End-to-End Data Flow

```text
               +----------------------------------+
               |    src/monitors/process_monitor  |
               |   (get_running_processes / new)  |
               +----------------------------------+
                                 |
                                 | processes snapshot (Dict[pid, process_info])
                                 v
               +----------------------------------+
               |    src/analysis/process_tree.py  |
               | - ProcessTree.build(processes)   |
               | - ProcessTreeAnalyzer.analyze()  |
               +----------------------------------+
                                 |
                                 | lineage, tree ASCII, indicators, tree findings
                                 v
               +----------------------------------+
               |       src/models/event.py        |
               | - Event.from_process_info()      |
               | - event.metadata["process_tree"] |
               | - event.indicators               |
               +----------------------------------+
                                 |
                                 v
               +----------------------------------+
               |  src/detectors/risk_detector.py  |
               | - Scores tree indicators (+4/+5) |
               | - Incorporates lineage reasons   |
               +----------------------------------+
                                 |
                                 v
               +----------------------------------+
               |  src/baseline/baseline_engine.py |
               | - Evaluates baseline deviations  |
               | - Filters out suspicious events  |
               +----------------------------------+
                                 |
                                 v
               +----------------------------------+
               |            src/main.py           |
               | - Logs to logs/security.log      |
               | - Formatted console tree alerts  |
               +----------------------------------+
```

---

## 6. Files Involved & Changes

| File | Status | Description |
| :--- | :--- | :--- |
| `src/analysis/__init__.py` | **Created** | Package initialization exporting `ProcessNode`, `ProcessTree`, `ProcessTreeAnalyzer`, and `build_process_tree`. |
| `src/analysis/process_tree.py` | **Created** | Core implementation of `ProcessNode`, `ProcessTree`, tree building, cycle detection, ASCII rendering, and `ProcessTreeAnalyzer`. |
| `config/config.json` | **Modified** | Added configurable `"process_tree"` section with suspicious parent-child rules and multi-level chain rules. |
| `src/detectors/risk_detector.py` | **Modified** | Added process tree indicators (`suspicious_process_lineage`, `multi_level_shell_chain`, `shell_spawning_shell`) to `INDICATOR_SCORES` and supported `tree_findings` parameter. |
| `src/main.py` | **Modified** | Integrated `ProcessTree.build()` and `ProcessTreeAnalyzer.analyze_process()` into initial scan and continuous monitoring loop; formatted ASCII tree in console and logged lineage to `logs/security.log`. |
| `tests/test_process_tree.py` | **Created** | 10 comprehensive unit tests verifying normal, suspicious, multi-level, exited parent, cyclic PIDs, continuous updates, event pipeline integration, ASCII tree, and custom configurations. |
| `docs/process_tree_analysis.md` | **Created** | Complete technical documentation, architecture, execution flows, and viva questions. |

---

## 7. Functions & Classes Added / Modified

### Classes Added:

- **`ProcessNode` (`src/analysis/process_tree.py`)**:
  - Encapsulates individual process metadata (`pid`, `ppid`, `name`, `parent_name`, `cmdline`, `username`).
  - Maintains `parent: Optional[ProcessNode]` and `children: List[ProcessNode]` bidirectional references.
  - Provides `to_dict()` for structured serialization.
- **`ProcessTree` (`src/analysis/process_tree.py`)**:
  - `build(processes)`: Class method to build hierarchical graph from snapshot dictionary with cycle prevention.
  - `get_node(pid)`: Lookup node by PID.
  - `get_ancestry_chain(pid)`: Traversal returning list of `ProcessNode` objects from root to target.
  - `get_lineage(pid)`: Returns list of process names in lineage order.
  - `render_tree(pid, max_depth)`: Formats ASCII tree representation with `[TARGET]` identifier.
- **`ProcessTreeAnalyzer` (`src/analysis/process_tree.py`)**:
  - `evaluate_parent_child(parent_name, child_name)`: Heuristic matching against configured suspicious rules.
  - `evaluate_ancestry_chain(chain)`: Detects multi-level suspicious chains.
  - `analyze_process(process_info, tree)`: Comprehensive evaluation producing indicators, scores, severity, reasons, and rendered tree.

### Functions Modified:

- **`calculate_risk()` (`src/detectors/risk_detector.py`)**:
  - Enhanced signature: `calculate_risk(indicators, process_info=None, tree_findings=None)`.
  - Added tree lineage indicator scores (+4 for `suspicious_process_lineage`, +5 for `multi_level_shell_chain`, +2 for `shell_spawning_shell`).
  - Incorporates specific explanatory reasons from `tree_findings`.
- **`process_event_from_dict()` (`src/main.py`)**:
  - Enhanced signature: `process_event_from_dict(process_info, process_tree=None, tree_analyzer=None)`.
  - Analyzes process within tree context and attaches `event.metadata["process_tree"]`.
- **`report_suspicious_event()` (`src/main.py`)**:
  - Prints ASCII process tree visualization to console and logs `Process Lineage: <lineage>` to `logs/security.log`.
- **`main()` (`src/main.py`)**:
  - Builds `process_tree = ProcessTree.build(processes)` on startup and rebuilds it dynamically when `new_processes` arrive in continuous mode.

---

## 8. Integration with `main.py`

In `main.py`, Process Tree Analysis operates directly between process retrieval and Event construction:

1. **Initial Startup**:
   ```python
   processes = get_running_processes()
   process_tree = ProcessTree.build(processes)
   tree_analyzer = ProcessTreeAnalyzer()
   ```
2. **Per-Process Processing**:
   ```python
   event = process_event_from_dict(
       process,
       process_tree=process_tree,
       tree_analyzer=tree_analyzer,
   )
   ```
3. **Alerting & Logging**:
   When an event contains suspicious indicators (command or tree lineage):
   ```text
   ============================================================
   Suspicious process detected | PID: 11196 | Process: cmd.exe | Parent: chrome.exe | Risk: MEDIUM | Score: 4
   Process Lineage Tree:
   explorer.exe (PID: 13400)
   +-- chrome.exe (PID: 29204)
         +-- cmd.exe (PID: 11196) [TARGET]
               +-- mc-extn-browserhost.exe (PID: 7032)
               +-- conhost.exe (PID: 18228)
   Indicators:
     - suspicious_process_lineage
   Reasons:
     - Suspicious Process Lineage (+4)
     - Suspicious process lineage: chrome.exe -> cmd.exe (Web browser spawned command shell or script host)
   ============================================================
   ```
4. **Continuous Mode**:
   When `new_processes` arrive in the continuous monitoring loop, `process_tree` is rebuilt from `current_processes` so new children are placed in the current hierarchy.

---

## 9. How Risk Assessment is Affected

Process-Tree Analysis contributes directly to the quantitative risk scoring model:

1. **Independent Evidence Addition**:
   A shell like `cmd.exe` running with no arguments has a baseline score of 0 (`LOW`). When spawned by `chrome.exe`, the `suspicious_process_lineage` indicator is attached, adding **+4 points** and elevating severity to **`MEDIUM`**.
2. **Compounded Suspicion**:
   If `powershell.exe` runs with an encoded command (`-enc`, +4 points) AND was spawned by an office app (`winword.exe`, +5 points) under `SYSTEM` (+1 point), the cumulative score becomes **10 points** (`HIGH` severity).
3. **Multi-Level Escalation**:
   If an attack invokes an indirect shell chain (`chrome.exe -> intermediary.exe -> cmd.exe`), the `multi_level_shell_chain` rule triggers, contributing **+5 points** (`HIGH` severity).

---

## 10. Test Cases & Validation Results

The entire project test suite consists of **57 tests** executed with Python 3.13, passing with **100% success rate**:

```bash
& "C:\Users\Sudarshnan\AppData\Local\Programs\Python\Python313\python.exe" -m unittest discover -s tests -v
```

### Test Coverage in `tests/test_process_tree.py`:
- `test_normal_parent_child_relationship`: Benign relationship (`explorer.exe -> notepad.exe`) produces 0 risk points and `LOW` severity.
- `test_suspicious_parent_child_browser_spawning_shell`: Detects `chrome.exe -> powershell.exe`, adds `suspicious_process_lineage` indicator (+4 points).
- `test_suspicious_parent_child_office_spawning_cmd`: Detects `winword.exe -> cmd.exe`, assigns `HIGH` severity (+5 points).
- `test_multi_level_process_chain`: Traces `explorer -> chrome -> powershell -> cmd`, identifies `multi_level_shell_chain` and `shell_spawning_shell`.
- `test_missing_disappeared_parent`: Handles exited parent PIDs safely by falling back to captured parent telemetry.
- `test_permission_and_invalid_pids`: Verifies negative PIDs, non-integer PIDs, self-referencing loops (`pid == ppid`), and cyclic relationships do not crash the engine.
- `test_continuous_monitoring_tree_updates`: Verifies incremental tree updates across multiple monitoring intervals.
- `test_integration_with_event_and_risk_pipeline`: Verifies end-to-end integration into `Event`, `calculate_risk`, and `metadata`.
- `test_tree_ascii_rendering`: Validates formatted ASCII tree output and target marker.
- `test_custom_configuration_override`: Validates configurable rules override from custom settings.

---

## 11. Known Limitations

1. **PID Recycling**:
   On Windows and Linux, operating systems reuse PIDs after processes exit. If an old parent process terminates and its PID is reassigned to an unrelated process before the snapshot is taken, a false parent-child relationship could be inferred. Process creation timestamps (`create_time`) help mitigate this, but transient short-lived processes may occasionally be misattributed.
2. **Missing Intermediaries (Ghost Parents)**:
   If an adversary launches a process that quickly spawns a payload and terminates immediately within milliseconds (e.g. dropper scripts), the intermediate process may exit before the polling interval captures it, resulting in a disconnected parent.
3. **Parent Process Spoofing**:
   Advanced Windows techniques (e.g. using `CreateProcess` with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`) allow malicious actors with administrative privileges to spoof their PPID to point to an innocent process (such as `explorer.exe` or `spoolsv.exe`).

---

## 12. Possible Future Improvements

1. **Process Creation Time Disambiguation**:
   Incorporate process creation timestamps into tree linking to verify that `parent.create_time < child.create_time`, eliminating PID recycling ambiguity.
2. **Kernel Event Integration (ETW / eBPF)**:
   Integrate Event Tracing for Windows (ETW) or Linux eBPF for real-time, asynchronous process creation callbacks rather than polling snapshots.
3. **Process Ancestry Whitelisting**:
   Allow configuring legitimate exceptions (e.g. developer IDEs like `code.exe` or `antigravity.exe` spawning shells) to prevent false positives in development environments.
4. **Graph-Based Visualization**:
   Export process trees in Graphviz DOT or D3.js format for interactive security dashboard visualization.

---

## 13. Viva / Review Questions & Answers

### Q1: What is the difference between direct parent-child analysis and multi-level process tree analysis?
**Answer**: Direct parent-child analysis only evaluates the immediate caller (`parent -> child`), which can be bypassed if an attacker inserts an intermediate utility (e.g., `browser -> benign_helper -> shell`). Multi-level process tree analysis evaluates the full ancestry chain from the root process down to the target, detecting anomalous lineages regardless of depth.

### Q2: How does your implementation avoid duplicate process enumeration overhead?
**Answer**: It directly reuses the `processes` snapshot dictionary already collected by `process_monitor.get_running_processes()`. Building the tree is an in-memory dictionary traversal without making any additional system calls or `psutil` queries.

### Q3: How does the system handle a process whose parent has already exited before the snapshot was taken?
**Answer**: When a node's PPID is not found in the active processes snapshot, the node is safely treated as a root node (`tree.roots.append(node)`). It preserves the `parent_name` captured during the process inspection, allowing lineage traversal (`get_lineage`) and rule evaluation to remain complete.

### Q4: How does Process-Tree Analysis integrate with the existing `Event` model?
**Answer**: Process tree analysis results are stored in `event.metadata["process_tree"]`, including the resolved lineage list, depth, and ASCII-rendered tree. Any detected indicators (e.g., `suspicious_process_lineage`) are appended to `event.indicators`, which are then evaluated by `calculate_risk()` to determine the final risk score and severity.

### Q5: How does the tree builder prevent infinite loops caused by cyclic PIDs or self-parenting processes?
**Answer**: During tree linking, the builder checks if `ppid == pid` (e.g. System Idle Process) and immediately marks the node as a root. Furthermore, when linking a child to a parent, it executes a loop with a `visited` set to detect and break any cyclic ancestry before assigning references.

### Q6: Why are ASCII tree connectors (`+-- `) used instead of Unicode box-drawing characters (`└── `)?
**Answer**: On Windows systems, PowerShell and Command Prompt consoles often default to legacy code pages like `cp1252` or `cp437`, which cannot encode Unicode box-drawing characters without throwing `UnicodeEncodeError`. Using ASCII-safe connectors ensures universal compatibility across all platforms and encodings.

### Q7: Does Process-Tree Analysis automatically classify every browser-spawned shell as malware?
**Answer**: No. Following defense-in-depth principles, it classifies the event as an anomaly/suspicious indicator (`suspicious_process_lineage`) with a score of 4 (`MEDIUM` severity). It provides explainable evidence to the analyst rather than prematurely claiming malware.

### Q8: How does continuous monitoring keep the process tree up to date?
**Answer**: On each continuous monitoring interval, `process_monitor.get_running_processes()` captures the latest process table. `ProcessTree.build()` rebuilds the tree in sub-millisecond time, ensuring that newly spawned processes (`get_new_processes`) are evaluated in the context of the live process hierarchy.


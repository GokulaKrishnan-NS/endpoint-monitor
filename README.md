# Endpoint Security Monitor

A modular, enterprise-grade Python endpoint monitoring and controlled execution system designed for Windows endpoints. It observes process and system activity, identifies suspicious behavior, analyzes hierarchical process lineage, calculates composite risk, logs alerts, and provides application-level execution gating alongside operating system application-control telemetry.

---

## 1. Architectural Overview & Control Tiers

Endpoint Monitor distinguishes three strict tiers of execution control to balance system visibility and prevention without compromising endpoint stability:

```mermaid
flowchart TD
    subgraph TierA["Tier A: Controlled Application Execution (Implemented)"]
        Req[ExecutionRequest] --> Policy[Security Policy & Risk Check]
        Policy --> DualGate[Dual-Gate Safety Check<br/>dry_run=True, allow_active=False]
        DualGate -->|Allowed & Active| Launcher[ControlledLauncher / Subprocess]
        DualGate -->|Blocked / Dry-Run| Suppressed[Execution Suppressed & Logged]
    end

    subgraph TierB["Tier B: OS-Enforced Application Control (Phase 4 Integration)"]
        ExternalLaunch[External Launch<br/>CMD, PowerShell, Explorer] --> KernelGate[Windows Kernel / CI.dll / AppLocker]
        KernelGate -->|Policy Allowed| OSExec[Process Runs]
        KernelGate -->|Policy Blocked| OSBlock[Access Denied by OS]
        KernelGate -.->|Audit / Block Event| WinEventLog[Event Log<br/>CodeIntegrity / AppLocker]
    end

    subgraph TierC["Tier C: Dynamic Risk-Based Pre-Execution Prevention (Advanced)"]
        KernelHook[Kernel Callback<br/>PsSetCreateProcessNotifyRoutineEx] --> InterceptQuery[Synchronous Query to Python]
        InterceptQuery --> DynamicRisk[Risk Detector Engine]
        DynamicRisk -->|Approved| ResumeSpawn[Resume Process Creation]
        DynamicRisk -->|Rejected| AbortSpawn[Abort Creation (STATUS_ACCESS_DENIED)]
    end
```

| Tier | Enforcement Point | Mechanism | Coverage Scope | Real-Time Python Risk Evaluation |
| :--- | :--- | :--- | :--- | :--- |
| **Tier A** | Application Space | `ControlledExecutionService` + `ControlledLauncher` | Processes spawned deliberately through Python service | **Yes** (Evaluated per-request before launch) |
| **Tier B** | Windows Kernel (`CI.dll`) / AppLocker | Microsoft App Control for Business (WDAC) / AppLocker | **All** binaries across Windows | **No** (Enforced by Windows static policy; ingested via telemetry) |
| **Tier C** | OS Kernel Interception | Custom Kernel Callback / Driver | System-wide pre-execution | **Yes** (Requires signed kernel driver & WHQL attestation) |

> [!IMPORTANT]
> **Tier A cannot provide Tier B or Tier C.** Tier A only gates execution requests routed through Python. External processes launched via PowerShell, CMD, or Explorer are governed at the OS level by Windows App Control for Business (WDAC) / AppLocker policies, whose audit and enforcement events are ingested, normalized, and correlated by Endpoint Monitor.

---

## 2. Core Subsystems

1. **Process Monitoring & Process Tree Analysis**:
   - Collects live process snapshots via `psutil`.
   - Resolves hierarchical parent-child relationships and detects suspicious lineages (e.g., browsers or office apps spawning command shells) and multi-level execution chains.
2. **Behavioral Baseline Engine**:
   - Profiles clean baseline execution patterns and flags behavioral anomalies using Z-score deviations and unseen parent-child pairs.
3. **Command & Heuristic Detection**:
   - Detects command chaining, obfuscated/encoded strings, hidden execution, and download-and-execute one-liners.
4. **System Resource Monitoring**:
   - Gathers CPU, physical memory, swap/pagefile, and disk utilization metrics.
   - Tracks sustained usage threshold spikes over configurable sample windows.
5. **Network & File Monitoring**:
   - Observes active socket connections, mapping connections to process owners and flagging non-standard ports used by script interpreters.
   - Watches local folders via `watchdog` to audit file creation, modification, deletion, and movement.
6. **Controlled Execution Service**:
   - Strictly validates execution requests, canonicalizes binaries, bounds output streams, and enforces timeouts.
   - Redacts sensitive credentials, tokens, and secrets across execution arguments, returned objects, logs, and alerts.
7. **Windows Application Control Telemetry**:
   - Collects and normalizes live Windows Event Log records from `Microsoft-Windows-CodeIntegrity/Operational` (WDAC events 3076, 3077, 3033, 3089) and `Microsoft-Windows-AppLocker/EXE and DLL` (events 8001, 8002, 8003, 8004).
   - Dynamically translates NT kernel device paths (`\Device\HarddiskVolume3\...`) to standard Win32 DOS drive letters (`C:\...`).
8. **User Interface & Integration**:
   - Multi-tabbed native desktop console built on Python's standard `tkinter.ttk` (Overview Dashboard, Process Explorer, Alerts & Event History, Resource Monitor, Network/File Activity, Controlled Execution Console).
   - Formatted interactive terminal dashboard for headless server environments.

---

## 3. Critical Safety Defaults

To safeguard endpoint stability and prevent unintended system disruption, Endpoint Monitor uses fail-closed security defaults configured in `config/config.json`:

```json
"controlled_execution": {
  "enabled": true,
  "dry_run": true,
  "interception_enabled": false,
  "score_threshold": 7,
  "blocked_severities": ["HIGH"],
  "blocked_indicators": [],
  "fail_closed": true,
  "launcher": {
    "allow_active_execution": false,
    "default_timeout_seconds": 30,
    "max_output_bytes": 65536,
    "allowed_working_directories": []
  },
  "windows_enforcement": {
    "enabled": false,
    "channels": [
      "Microsoft-Windows-CodeIntegrity/Operational",
      "Microsoft-Windows-AppLocker/EXE and DLL"
    ],
    "poll_interval_seconds": 5.0,
    "max_events_per_query": 50,
    "correlate_with_processes": true,
    "alert_on_blocks": true
  }
}
```

- `dry_run = True`: Validates execution requests against security policy and risk engines without spawning real processes.
- `allow_active_execution = False`: Prohibits active child process spawning unless explicitly enabled in trusted configuration.
- `interception_enabled = False`: Blocks monkey-patching or unreviewed execution hooks.
- `windows_enforcement.enabled = False`: Live Windows Event Log polling remains inactive until explicitly enabled.

---

## 4. Environment Setup & Installation

### Prerequisites
- **Operating System**: Windows 11 (or Windows 10 build 19041+). Cross-platform fallback supported for development and testing.
- **Python Version**: Python 3.10+ (tested and verified on Python 3.13.15 64-bit).
- **Privileges**: Standard user permissions are sufficient for passive monitoring, desktop UI, and audit telemetry reading. Administrator privileges are required only when authoring or deploying OS-level WDAC binary policies into Windows system directories.

### Setup Steps

1. **Clone the repository**:
   ```powershell
   git clone https://github.com/GokulaKrishnan-NS/endpoint-monitor.git
   cd endpoint-monitor
   ```

2. **Create and activate the virtual environment**:
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

3. **Install dependencies**:
   ```powershell
   python -m pip install -r requirements.txt
   ```

4. **Verify installation**:
   ```powershell
   python -B -m unittest discover -s tests -v
   ```

---

## 5. Application Modes & Usage

Endpoint Monitor supports four operational execution modes:

### Mode 1 — Native Desktop Dashboard UI (Default)
Launches the full interactive graphical console:
```powershell
python src/main.py --ui
```
*(Or simply run `python src/main.py` without arguments on a desktop machine).*

**Features of the Desktop UI:**
- **Overview Dashboard**: High-level KPI cards, live CPU/Memory/Disk progress gauges, OS policy telemetry status, and recent critical alerts.
- **Process Explorer**: Real-time process table with instantaneous keyword search, severity filtering (`HIGH`, `MEDIUM`, `LOW`), process tree lineage, and detailed risk analysis.
- **Alerts & Events Tab**: Unified security event timeline with source filtering, severity filtering, and JSON raw metadata inspector.
- **System Resources Tab**: In-depth breakdown of physical memory, swap memory, disk mount points, and sustained spike tracker.
- **Network & File Activity**: Live socket connection log (flagging non-standard ports) and monitored directory file modification tracking.
- **Controlled Execution Console**: Interactive test harness to submit mock execution requests, test risk gating, and inspect policy decisions safely under dry-run conditions.

### Mode 2 — Interactive Terminal Console Dashboard
For headless servers, SSH sessions, or terminal environments:
```powershell
python src/main.py --cli
```
Displays an ASCII live security dashboard refreshing periodically with real-time metrics, high-risk processes, and active alerts.

### Mode 3 — Continuous Monitoring Daemon
Runs headless background continuous monitoring logging directly to `logs/`:
```powershell
python src/main.py --continuous
```

### Mode 4 — Single-Pass Security Snapshot Scan
Executes a single evaluation pass across system processes, baseline profiles, resources, and network sockets:
```powershell
python src/main.py --scan
```

---

## 6. Running Tests

The test suite contains **238 automated unit and integration tests** covering all subsystems:

```powershell
# Run the complete test suite
python -B -m unittest discover -s tests -v

# Run targeted test suites
python -B -m unittest tests/test_e2e_workflow.py -v
python -B -m unittest tests/test_login_monitor.py -v
python -B -m unittest tests/test_ui.py -v
python -B -m unittest tests/test_windows_enforcement.py -v
python -B -m unittest tests/test_execution_service.py -v
python -B -m unittest tests/test_controlled_launcher.py -v
python -B -m unittest tests/test_process_tree.py -v
```

All tests run deterministically with zero network calls and complete in ~22 seconds.

---

## 7. Project Structure

```text
endpoint-monitor/
├── config/
│   ├── baseline.json                    # Saved behavioral baseline profiles
│   └── config.json                      # Master configuration (thresholds, rules, safe defaults)
├── docs/
│   ├── behavioral_baseline.md           # Behavioral anomaly detection documentation
│   ├── common_event_model.md            # Standard Event dataclass specification
│   ├── end_to_end_validation.md        # Comprehensive 12-stage validation & benchmark report
│   ├── network_monitoring.md            # Network socket inspection documentation
│   ├── phase_4_os_execution_prevention.md # Phase 4 OS execution control architecture
│   ├── process_tree_analysis.md         # Process tree hierarchy and lineage rules
│   ├── security_review.md               # Security threat model & hardening review
│   └── user_interface.md                # Desktop & CLI UI architecture specification
├── logs/                                # Security and audit event logs
├── monitored_folder/                    # Watchdog file monitoring target directory
├── src/
│   ├── alerts/
│   │   └── alert_manager.py             # Alert dispatch and console notification
│   ├── analysis/
│   │   └── process_tree.py              # Hierarchical process tree builder & analyzer
│   ├── baseline/
│   │   └── baseline_engine.py           # Statistical and lineage baseline profiler
│   ├── detectors/
│   │   ├── command_detector.py          # Command line obfuscation & indicator detector
│   │   └── risk_detector.py             # Composite heuristic risk scoring engine
│   ├── execution/
│   │   ├── config.py                    # Controlled execution configuration loader
│   │   ├── controller.py                # Phase 1 execution controller
│   │   ├── launcher.py                  # Phase 2 controlled process launcher
│   │   ├── policy.py                    # Pre-launch security policy evaluator
│   │   ├── service.py                   # Phase 3 execution service & redaction
│   │   └── windows_enforcement.py       # Phase 4 Windows WDAC/AppLocker telemetry
│   ├── models/
│   │   ├── event.py                     # Standardized Event model
│   │   └── execution_request.py         # ExecutionRequest & ExecutionDecision models
│   ├── monitors/
│   │   ├── file_monitor.py              # Watchdog file system event monitor
│   │   ├── login_monitor.py             # User session and logon monitor
│   │   ├── network_monitor.py           # Socket & network connection monitor
│   │   ├── process_monitor.py           # Process snapshot and lifecycle monitor
│   │   └── resource_monitor.py          # CPU, RAM, Disk, Swap resource monitor
│   ├── ui/
│   │   ├── adapter.py                   # Data formatting, filtering, and sorting adapter
│   │   ├── cli.py                       # Formatted terminal dashboard
│   │   ├── dashboard.py                 # Tkinter desktop graphical user interface
│   │   └── engine.py                    # Thread-safe background monitoring controller
│   ├── utils/
│   │   └── logger.py                    # Structured logging utility
│   └── main.py                          # Application entry point
├── tests/                               # Comprehensive unit and integration test suite
├── notice.txt                           # Environment setup notices
├── requirements.txt                     # Project dependencies (psutil, watchdog)
└── README.md                            # Main project documentation
```

---

## 8. Known Limitations & Security Boundaries

1. **Pre-Execution Scope**:
   - The Python `ControlledExecutionService` mediates execution requests submitted directly to the service. It does not hook arbitrary external process launches executed outside the application.
   - System-wide pre-execution prevention is achieved through OS-level policies (Microsoft App Control for Business / WDAC), which enforce code-signing and path rules in the kernel.
2. **AppLocker Platform Support**:
   - AppLocker enforcement requires Windows Enterprise or Education editions. On Windows Home editions, AppLocker rules cannot be enforced (telemetry remains available in audit mode).
3. **Dynamic Risk-Based Pre-Execution Prevention**:
   - Synchronously evaluating Python risk scores prior to every process launch across the entire Windows operating system requires an OS kernel driver (`PsSetCreateProcessNotifyRoutineEx`) and Microsoft WHQL code-signing. Pure user-mode API hooking is intentionally avoided to preserve operating system stability.


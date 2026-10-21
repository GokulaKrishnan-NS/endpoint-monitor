# Endpoint Monitor — Security Architecture & Hardening Review (Phase 6 Release)

## 1. Threat Model & Trust Boundaries

The **Endpoint Monitor** architecture defines three distinct trust zones:

```mermaid
graph TD
    subgraph Zone1["Untrusted Inputs"]
        A["External CLI Arguments"]
        B["ExecutionRequest Payloads"]
        C["Host Process & Network Events"]
        D["Windows Event Log XML"]
    end

    subgraph Zone2["Inspection & Policy Boundary"]
        E["Input Schema Validator"]
        F["Regex Channel Whitelist"]
        G["Secret Redaction Filter"]
        H["ExecutionPolicy (Fail-Closed)"]
    end

    subgraph Zone3["Execution & Presentation Core"]
        I["ControlledLauncher (Dual-Gate)"]
        J["Bounded In-Memory Telemetry"]
        K["Audit Log & Dashboard UI"]
    end

    A --> E
    B --> E
    C --> G
    D --> F
    F --> G
    E --> H
    H -->|Allowed & Gates Open| I
    H -->|Blocked or Dry-Run| J
    G --> J
    J --> K
```

### Trust Boundary Analysis
1. **Application-Controlled Execution (Tier A)**: Applications requesting process launching via the monitor service must pass strict JSON schema validation, regex argument inspection, and policy threshold scoring.
2. **OS-Level Enforcement Telemetry (Tier B)**: Native Windows AppLocker and WDAC event streams are treated as untrusted XML input. They are parsed with namespace-agnostic secure element trees and normalized from internal NT device paths (`\Device\HarddiskVolumeX`) to standard DOS drive letters.
3. **Dynamic Kernel Interception (Tier C)**: The Python monitoring application does not attempt to hook kernel drivers or execute code inside Ring 0. It relies strictly on supported Win32 telemetry channels and controlled execution wrappers.

---

## 2. Fail-Closed Security Policy Architecture

The system enforces fail-closed behavior across all execution and evaluation paths:

- **Dual-Gate Safety Control**:
  Process execution strictly requires two independent configuration flags to be concurrently enabled:
  $$\text{Can Execute} = (\text{dry\_run} == \text{False}) \land (\text{allow\_active\_execution} == \text{True})$$
  By default, `dry_run = True` and `allow_active_execution = False`. If either gate is closed, processes are NEVER spawned.
- **Corrupted or Malformed Request Handling**:
  If an `ExecutionRequest` contains non-string elements, null bytes (`\0`), empty command lists, or malformed PIDs, the schema validator immediately rejects the request with `VALIDATION_FAILED` and `executed=False`.
- **Policy Exception Handling**:
  If the risk detector, command analyzer, or process tree module raises an unexpected exception during evaluation, the policy defaults to `DecisionStatus.BLOCK` with maximum risk score ($999$) and logs an audit failure event.

---

## 3. Sensitive Data Redaction & Privacy Controls

To prevent sensitive credentials, passwords, access tokens, and API keys from leaking into log files, terminal dashboards, or desktop UI views, the platform implements multi-layer automated sanitization:

### Redaction Rules
1. **Flag-Based Masking**:
   Any parameter immediately following sensitive command-line flags (`-p`, `--password`, `--passwd`, `--pwd`, `-t`, `--token`, `--access-token`, `--auth-token`, `--api-key`, `--client-secret`, `--bearer`) is automatically replaced with `[REDACTED]`.
2. **Inline Assignment Masking**:
   Arguments structured as `--password=secret` or `API_KEY=xyz` are masked via regular expressions matching sensitive prefix patterns.
3. **Embedded URL Credentials**:
   URLs containing embedded authentication (`http://admin:secret@host/`) have the password component masked (`http://admin:[REDACTED]@host/`).
4. **Bearer Tokens**:
   Strings matching `Bearer <token>` are masked to `Bearer [REDACTED]`.
5. **Immutable Object Sanitization**:
   Sanitization functions (`_sanitize_decision`, `_sanitize_event_dict`) generate sanitized copies of objects before adding them to bounded telemetry queues or returning them to callers, ensuring raw sensitive strings never leak into presentation memory.

---

## 4. Subprocess & Command-Injection Hardening

- **No Shell Execution**:
  All subprocess invocations throughout the application (`ControlledLauncher`, `WindowsEnforcementCollector`) pass arguments strictly as structured lists (`List[str]`), with `shell=False` explicitly enforced.
- **Strict Channel Name Whitelisting**:
  Before querying Windows Event Log channels via `wevtutil.exe`, `query_live_events()` validates channel names against the regex `^[A-Za-z0-9_\-\.\/ ]+$`. Any input containing shell metacharacters (`;`, `&`, `|`, `` ` ``, `$`, `\n`) is rejected immediately.
- **Null-Byte Rejection**:
  All input paths, executable names, and command-line arguments are scanned for null characters (`\0`), preventing null-byte poisoning attacks.

---

## 5. Denial-of-Service & Resource Boundedness

- **Memory Bounded Queues**:
  The `MonitoringEngine` stores events, alerts, errors, and execution records using `collections.deque` instances with hard capacities:
  - Events: 1,000 maximum
  - Alerts: 500 maximum
  - Resource History: 100 maximum
  - Errors: 50 maximum
  When capacity is reached, older entries are dropped using FIFO eviction, preventing memory exhaustion under sustained event floods.
- **Thread Lifecycle & Non-Blocking Joins**:
  Background worker threads are daemonized and monitored with explicit `threading.Event` primitives. The `stop()` routine enforces strict, non-blocking join timeouts ($0.20\text{ s}$ for workers, $0.10\text{ s}$ for watchdog observers), eliminating hanging processes during system shutdown.

---

## 6. Operating System Compatibility & Deployment Guidelines

| Environment | Supported Features | Limitations / Required Precautions |
| :--- | :--- | :--- |
| **Windows 11 Home** *(Current Development Host)* | Passive process monitoring, resource tracking, network monitoring, controlled execution gating, UI dashboards, and WDAC audit-mode log ingestion. | AppLocker Group Policy not natively supported in Home edition (requires Enterprise/Education). WDAC Enforce mode must **NOT** be enabled on developer's primary machine to avoid boot lockouts. |
| **Windows 11 Enterprise / Windows Server** *(Production Target)* | Full WDAC enforcement (Code Integrity 3077), AppLocker execution blocks (8004), centralized event forwarding (WEF), and GPO policy distribution. | Requires administrative privilege (`SeSecurityPrivilege`) to configure Code Integrity policies and read privileged security logs. |


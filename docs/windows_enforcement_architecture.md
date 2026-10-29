# Windows Endpoint Security Enforcement Architecture (Phase 2)

## 1. Executive Summary & Host Inspection

### Host Platform Details
- **Operating System**: Windows 11 Enterprise / Pro (Build 10.0.26200, 64-bit AMD64)
- **Runtime Environment**: Python 3.13.4 (64-bit MSC v.1943)
- **Compilation Toolchain**: Microsoft Visual Studio / Windows Driver Kit (WDK) is **not installed** on this development host.
- **Driver Signing State**: Windows Driver Signature Enforcement is active; test-signing mode is not enabled on host (`bcdedit /set testsigning on` requires Administrator and OS reboot).

### Architectural Philosophy
The objective of Phase 2 is **actual Windows enforcement**, transitioning from passive telemetry and post-facto detection to deterministic, preemptive prevention. In accordance with zero-trust endpoint security principles:
1. **Separation of Intent vs. Enforcement**: An alert, risk score, or requested `BLOCK` policy decision does not prove that Windows prevented an operation. Enforcement outcomes are tracked independently (`VERIFIED_BLOCKED`, `VERIFIED_ALLOWED`, `POLICY_DECIDED_ONLY`, `FAILED_UNENFORCED`).
2. **Fail-Closed Semantics**: If policy cannot be verified, approval queues saturate, or native services disconnect, intermediate and high-risk operations are denied by default.
3. **Execution Time Budget**: Kernel callbacks must never wait synchronously for Python interpreters, network I/O, disk writes, or GUI user interaction.

---

## 2. Process Enforcement Architecture

### A. Supported Enforcement Layers

| Layer | Mechanism | Scope | Latency Budget | Enforcement Capability |
| :--- | :--- | :--- | :--- | :--- |
| **Layer 1: Controlled Execution** | `ControlledLauncher` | Application-invoked child processes | User-mode (< 5ms) | Pre-spawn gating, argument canonicalization, working directory confinement, environment sanitization, single-use approval token verification. |
| **Layer 2: Static System Policy** | AppLocker / WDAC (App Control for Business) | Host-wide binaries, scripts, and DLLs | Kernel (< 1ms) | Cryptographic signature enforcement, publisher rules, path rules, and hash allowlists. Managed via OS policy XML/CIP. |
| **Layer 3: Dynamic Kernel Interception** | `PsSetCreateProcessNotifyRoutineEx` | Host-wide process creation | Kernel (< 20µs callback budget) | Pre-execution process blocking via `CreationStatus = STATUS_ACCESS_DENIED`. Queries user-mode service via inverted-call model. |

---

### B. Dynamic Kernel Interception Design (`PsSetCreateProcessNotifyRoutineEx`)

```
   [ External Application or Shell ]
                 │
                 ▼ (Calls CreateProcess / NtCreateUserProcess)
   [ Windows NT Kernel (Executive) ]
                 │
                 ▼
   [ PsSetCreateProcessNotifyRoutineEx Callback ]
                 │
                 ├── 1. Check in-memory Fast-Path Cache (Exact Exe Hash / Path Allowlist)
                 │      ├─► Hit (ALLOW): Return STATUS_SUCCESS immediately (< 5µs)
                 │      └─► Hit (MANDATORY BLOCK): Set CreationStatus = STATUS_ACCESS_DENIED (< 5µs)
                 │
                 ├── 2. Slow-Path: Inverted Call to Privileged User-Mode Service
                 │      ├─► Callback passes Process ID, Parent PID, ImageFileName, CommandLine
                 │      ├─► Kernel waits with bounded timeout (max 50ms) via KeWaitForSingleObject
                 │      │
                 │      ▼
         [ User-Mode Privileged Service (EndpointSecurityService) ]
                 │
                 ├── Match Policy & Mandatory Rules
                 ├── If Risk < Approval Threshold: Return ALLOW
                 ├── If Risk >= Block Threshold: Return BLOCK
                 └── If Approval Threshold <= Risk < Block Threshold:
                         ├─► CANNOT wait for interactive GUI on kernel callback!
                         ├─► Service returns BLOCK_PENDING_APPROVAL to Driver
                         ├─► Driver sets CreationStatus = STATUS_ACCESS_DENIED
                         ├─► Service enqueues ApprovalRequest in ApprovalManager
                         └─► GUI prompts operator; on approval, emits Single-Use Token
                                 └─► Caller performs Controlled Retry with Token!
```

#### Why Callbacks Cannot Suspend for GUI Approval
A process-creation callback in Windows executes in the context of the thread creating the process (e.g. `explorer.exe`, `services.exe`, `svchost.exe`, or a build tool). It holds internal executive locks. Suspending this thread indefinitely while waiting for an operator to click an "Approve" button in a GUI will:
1. Deadlock critical Windows desktop subsystems.
2. Trigger watchdog bugchecks (BSOD `DPC_WATCHDOG_VIOLATION` or thread pool exhaustion).
3. Introduce race conditions against PID recycling.

**Phase 2 Resolution**: When an intermediate-risk launch cannot be resolved within the strict 50ms native budget, the kernel callback **denies the initial launch** (`STATUS_ACCESS_DENIED`), records the pending approval request in `ApprovalManager`, notifies the GUI, and requires an **authorized, controlled retry** once approved.

---

### C. Process Execution Guarantees & Critical Limitations

#### What Process Enforcement Guarantees
- Any executable launched via `ControlledLauncher` is strictly gated before invocation.
- Canonical path resolution prevents directory traversal, symlink spoofing, and NULL-byte injections.
- Working directory containment ensures processes cannot execute from untrusted temporary folders.
- With the native driver loaded, new binary images (`.exe`) spawned host-wide cannot initialize user-mode execution if denied by `CreationStatus = STATUS_ACCESS_DENIED`.

#### Critical Coverage Limitations
1. **Commands Inside Existing Interpreters**: `PsSetCreateProcessNotifyRoutineEx` intercepts the creation of **new processes**. It does **NOT** intercept:
   - Built-in shell commands executed inside an already running `cmd.exe` (e.g. `dir`, `cd`, `echo`, `copy`, `del`, `set`).
   - Built-in cmdlets and scripts executed inside an already running PowerShell session without spawning a sub-process (e.g. `Invoke-Expression`, `Add-Type`, in-memory scriptblocks).
2. **Interpreted Scripts**: Executing `python.exe script.py` spawns `python.exe` (intercepted), but subsequent script activity within that Python runtime is not a separate process creation.
3. **In-Memory Injection & Process Hollowing**: Advanced memory injection (e.g. `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`) into an already permitted process does not trigger `PsSetCreateProcessNotifyRoutineEx`.
4. **Protected Processes Light (PPL)**: Windows restricts kernel notification interactions with certain antimalware and system protected processes.

---

## 3. Windows Filtering Platform (WFP) Network Enforcement

### A. Supported WFP Enforcement Layers

WFP operates across multiple filtering layers in the network stack:
- **`FWPM_LAYER_ALE_AUTH_CONNECT_V4`**: Evaluates outbound IPv4 connection attempts (TCP SYN, initial UDP datagram) before network transmission.
- **`FWPM_LAYER_ALE_AUTH_CONNECT_V6`**: Evaluates outbound IPv6 connection attempts before network transmission.
- **`FWPM_LAYER_ALE_AUTH_LISTEN_V4` / `_V6`**: Controls local port binding and listener creation.
- **`FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4` / `_V6`**: Authorizes local port allocations.

```
   [ Application Socket / Connect Request ]
                 │
                 ▼
   [ Windows Kernel TCP/IP Stack (tcpip.sys) ]
                 │
                 ▼
   [ WFP ALE Connect Authorization Layer (FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6) ]
                 │
                 ├── 1. Evaluate Dynamic WFP Rules (User-Mode Engine / Sublayer)
                 │      ├─► Mandatory Blocked Port/IP: FWP_ACTION_BLOCK
                 │      ├─► Low-Risk / Allowed: FWP_ACTION_PERMIT
                 │      └─► Intermediate Risk / Unknown Target:
                 │              │
                 │              ├── [Driver Mode]: FwpsPendOperation0 (ALE Pend Workflow, timeout 2s)
                 │              │       └─► Query Service; if timeout/no token -> FwpsCompleteOperation0(FWP_ACTION_BLOCK)
                 │              │
                 │              └── [User-Mode Policy / Fail-Safe Mode]:
                 │                      ├─► Initial connection dropped/blocked (FWP_ACTION_BLOCK)
                 │                      ├─► Approval request enqueued to GUI
                 │                      └─► Upon approval, dynamic temporary permit rule installed for destination!
                 │
                 ▼
   [ Network Interface (Physical / Loopback) ]
```

### B. Network Coverage & Limitations

#### What WFP Enforcement Guarantees
- Interception of outbound TCP connection requests (SYN) and UDP socket flows prior to packet transmission.
- Accurate extraction of target IPv4, IPv6, destination port, transport protocol, and calling Process ID (`ProcessId` in ALE metadata).
- Deterministic blocking of unauthorized ports (e.g. IRC 6667, C2 1337/4444) and prohibited IP addresses.
- Support for loopback (`127.0.0.1`, `::1`), local subnet, and wide-area connections.

#### Critical Coverage Limitations
1. **Encrypted Payloads (TLS/HTTPS)**: WFP ALE operates at Layers 3 and 4 (Network & Transport). It **does not inspect or decrypt TLS traffic**, and cannot view HTTPS URLs, request headers, cookies, or HTTP methods (`GET`/`POST`).
2. **Existing Connections**: A dynamic block rule applied after a TCP handshake has already completed may require TCP reset or socket teardown (`SetTcpEntry` or connection invalidation) rather than packet drop alone.
3. **DNS Resolution vs. Direct IP**: WFP receives the target IP address and port; DNS domain resolution occurs prior to the connection attempt. DNS spoofing or fast-flux domains require DNS-layer inspection (`FWPM_LAYER_DATAGRAM_DATA_V4` on UDP 53 or DNS Client telemetry).

---

## 4. Approval and Failure Semantics

### Threshold Semantics
- **Score < `approval_threshold` (default: 4)**: `ALLOW` (unless matching a mandatory block rule).
- **`approval_threshold` <= Score < `block_threshold` (default: 4..6)**: `REQUIRE_APPROVAL`.
- **Score >= `block_threshold` (default: >= 7)**: `BLOCK`.
- **Mandatory Block Rules**: Explicitly blocked executables, ports, IPs, or indicators strictly override any risk score, resulting in `BLOCK` with `MANDATORY_RULE` provenance.

### Failure Semantics (Fail-Closed)
- **Service Disconnection**: If user-mode service is offline, kernel/driver components default to `BLOCK` for intermediate/untrusted requests.
- **Queue Saturation**: If `ApprovalManager` reaches maximum capacity (`max_pending = 100`), incoming requests fail-closed with `BLOCK`.
- **Approval Expiry**: Pending approvals have a bounded lifetime (default: 60s). Expired requests transition to `EXPIRED` and cannot be consumed.
- **Replay & PID Recycling**: Single-use authorization tokens are invalidated immediately upon first consumption. Process creation time is verified to reject reused PIDs.

---

## 5. Development Host Blocker & VM Testing Strategy

### Blocker Analysis
1. **Compilation Environment**: The development host lacks Visual Studio 2022 C/C++ build tools and the Windows Driver Kit (WDK 10.0.26100+).
2. **Driver Signing**: Loading a kernel-mode driver on 64-bit Windows requires either a Microsoft WHQL/Attestation signature or a test certificate with `TESTSIGNING` boot configuration enabled.
3. **Safety Constraint**: Per operating instructions, non-destructive user-mode enforcement, testable WFP management, and mock interfaces are implemented on the dev host; full kernel driver installation must be performed on an isolated test VM.

### Safe VM Deployment & Rollback Instructions
See Section 9 of the Final Report for step-by-step PowerShell commands.

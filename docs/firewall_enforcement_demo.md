# Windows Defender Firewall Enforcement: Manual Demonstration Procedure

This document provides a complete, reproducible manual demonstration procedure for **Native Windows Defender Firewall Enforcement** in the `endpoint-monitor` project.

---

## 1. Architecture Overview & Safety Principles

The Windows Firewall enforcement adapter operates under four distinct architectural phases:

```
[ Network Telemetry / Event ]
              │ (Sysmon Event ID 3 or NetworkMonitor polling)
              ▼
[ Phase 1: Detection & Risk Scoring ] ──> Normalized Event with risk score & indicators
              │
              ▼
[ Phase 2: Policy Decision ]          ──> Separation of scoring from action:
              │                           - Is enforcement enabled?
              │                           - Is binary on allowed_executables list?
              │                           - Does score meet block_threshold or severity?
              │                           - Is executable path explicitly known?
              ▼
[ Phase 3: OS Rule Application ]      ──> Argument-safe execution via netsh.exe:
              │                           - Scoped explicitly: program="<abs_path>", remoteip, remoteport
              │                           - Dedicated prefix: EndpointMonitor_Block_<binary>_<port>_<id>
              │                           - Verified exit code and stderr
              ▼
[ Phase 4: Network Verification ]     ──> Prospective packet blocking at the OS TCP/IP stack
```

### Important Distinctions: Telemetry vs. Enforcement

- **Telemetry is not interception:** Sysmon Event ID 3 and socket polling are historical evidence of connections that occurred. Adding a firewall rule operates **prospectively**; it blocks subsequent outbound SYN packets and connections from that binary. It cannot retroactively revoke packets that have already traversed the physical network interface.
- **Safe defaults:** By default, enforcement is disabled (`"enabled": false`) and dry-run is enabled (`"dry_run": true`). Live OS rule creation requires explicit operator configuration and elevated Administrator privileges.
- **Rule ownership & isolation:** All rules created by this application use the strict prefix `EndpointMonitor_Block_`. Cleanup functions **never** invoke `name=all` or touch rules created by the operating system, other services, or the user.

---

## 2. Step-by-Step Manual Demonstration Procedure

Open an **Elevated Administrator PowerShell** window in `D:\projects\endpoint-monitor`:

```powershell
cd D:\projects\endpoint-monitor
```

---

### Step 1: Check Windows Firewall Status

Verify that the Windows Defender Firewall service is running and active on the host:

```powershell
Get-NetFirewallProfile | Select-Object Name, Enabled
```

*Expected Output:*
```text
Name     Enabled
----     -------
Domain      True
Private     True
Public      True
```

---

### Step 2: Configure Live Firewall Enforcement

By default, firewall enforcement is disabled and set to dry-run mode. Enable live enforcement for testing by configuring `config/config.json`:

```powershell
$config = Get-Content config\config.json -Raw | ConvertFrom-Json
$config.controlled_execution.firewall_enforcement.enabled = $true
$config.controlled_execution.firewall_enforcement.dry_run = $false
$config.controlled_execution.firewall_enforcement.auto_block_suspicious = $true
$config.controlled_execution.firewall_enforcement.block_threshold = 7
$config | ConvertTo-Json -Depth 10 | Set-Content config\config.json -Encoding utf8
```

Verify that the configuration is updated:

```powershell
(Get-Content config\config.json -Raw | ConvertFrom-Json).controlled_execution.firewall_enforcement
```

*Expected Output:*
```text
enabled               : True
dry_run               : False
auto_block_suspicious : True
block_threshold       : 7
blocked_severities    : {HIGH}
...
```

---

### Step 3: Start the Endpoint Monitor with Administrator Privileges

Launch the Endpoint Monitor in continuous monitoring mode in a dedicated PowerShell terminal:

```powershell
python src/main.py --continuous
```

*Expected Startup Output in `logs/security_audit.log` or Console:*
```text
[FIREWALL ENFORCEMENT] Windows Firewall enforcement is LIVE ENABLED (Admin permissions verified). Outbound block rules will be applied for authorized policy violations.
Entering continuous monitoring mode...
```

---

### Step 4: Generate a Controlled, Harmless Test Event

Use a narrowly scoped target (e.g. `curl.exe` to a documentation test address `203.0.113.195` on suspicious port `4444`):

```powershell
# In a second PowerShell terminal:
Start-Process -FilePath "C:\Windows\System32\curl.exe" -ArgumentList "--connect-timeout 5", "http://203.0.113.195:4444" -NoNewWindow
```

---

### Step 5: Confirm That the Monitor Requested Enforcement

Check `logs/security_audit.log` to confirm the detection pipeline scored the event, applied policy, and executed the firewall rule:

```powershell
Get-Content logs\security_audit.log -Tail 30 | Select-String "FIREWALL|Firewall policy"
```

*Expected Log Output:*
```text
[FIREWALL ENFORCEMENT] Applied live outbound block rule 'EndpointMonitor_Block_curl.exe_4444_...' for C:\Windows\System32\curl.exe -> 203.0.113.195:4444
Firewall policy: BLOCK | Enforcement: VERIFIED_BLOCKED | Rule: EndpointMonitor_Block_curl.exe_4444_...
```

Notice:
1. **Detection:** Detected outbound connection on suspicious port 4444.
2. **Policy Decision:** Evaluated as `BLOCK` (exceeded threshold / high severity).
3. **OS Rule Application:** `VERIFIED_BLOCKED` recorded with exact rule name and scope.

---

### Step 6: Confirm the Firewall Rule Was Actually Installed in Windows

Verify via native PowerShell cmdlet `Get-NetFirewallRule`:

```powershell
Get-NetFirewallRule -Name "EndpointMonitor_Block_*" | Select-Object Name, DisplayName, Direction, Action, Enabled
```

Or verify via `netsh.exe`:

```powershell
netsh.exe advfirewall firewall show rule name="EndpointMonitor_Block_*"
```

*Expected Output:*
```text
Rule Name:                            EndpointMonitor_Block_curl.exe_4444_123456
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            Out
Profiles:                             Domain,Private,Public
Grouping:                             Endpoint Monitor Enforcement
LocalIP:                              Any
RemoteIP:                             203.0.113.195/32
Protocol:                             TCP
LocalPort:                            Any
RemotePort:                           4444
Edge traversal:                       No
Action:                               Block
```

---

### Step 7: Verify Connection Failure Caused by the Test Rule

Attempt to connect with `curl.exe` to the blocked remote IP and port:

```powershell
curl.exe --connect-timeout 3 http://203.0.113.195:4444
```

*Expected Outcome:* The connection fails immediately with an error indicating connection refused / blocked by firewall policy.

---

### Step 8: Remove the Test Rule Through the Application's Cleanup Mechanism

Use the application's native, idempotent cleanup method:

```powershell
python -c "from src.enforcement.windows_firewall import WindowsFirewallEnforcer; enforcer = WindowsFirewallEnforcer(); count = enforcer.cleanup(); print(f'Successfully removed {count} owned rules.')"
```

*Expected Output:*
```text
Successfully removed 1 owned rules.
```

If run a second time, the cleanup is completely idempotent:
```powershell
python -c "from src.enforcement.windows_firewall import WindowsFirewallEnforcer; enforcer = WindowsFirewallEnforcer(); count = enforcer.cleanup(); print(f'Successfully removed {count} owned rules.')"
```
*Expected Output:*
```text
Successfully removed 0 owned rules.
```

---

### Step 9: Verify Connectivity Is Restored

Confirm the rule is no longer present in Windows Defender Firewall:

```powershell
Get-NetFirewallRule -Name "EndpointMonitor_Block_*" -ErrorAction SilentlyContinue
```

*Expected Output:* Empty output (no matching rules found).

---

### Step 10: Confirm Unrelated Firewall Rules Remain Untouched

Confirm that system, OS, and third-party rules are intact:

```powershell
$allRules = Get-NetFirewallRule
Write-Host "Total system firewall rules remaining:" $allRules.Count
```

*Expected Output:* Hundreds of Windows default rules remain active and unaltered. The application never touched any rule outside its own prefix.

---

### Step 11: Restore Safe Defaults

Once testing is complete, restore the safe defaults in `config/config.json`:

```powershell
$config = Get-Content config\config.json -Raw | ConvertFrom-Json
$config.controlled_execution.firewall_enforcement.enabled = $false
$config.controlled_execution.firewall_enforcement.dry_run = $true
$config | ConvertTo-Json -Depth 10 | Set-Content config\config.json -Encoding utf8
```

---

## 3. Summary of Safety Guarantees

| Feature | Implementation Guarantee |
|---|---|
| **Subprocess Execution** | Uses argument list execution `["netsh.exe", ...]`; never uses `shell=True` or string interpolation. |
| **Rule Scope** | Requires explicit absolute path to executable; rejects wildcards or blank paths. |
| **Target Endpoints** | Strictly validates IPv4/IPv6 addresses; rejects broadcast, multicast, and `0.0.0.0`. |
| **Rule Ownership** | Prefixes all rules with `EndpointMonitor_Block_`; rejects deletion of any rule without this prefix. |
| **Idempotence** | Gracefully handles non-existent rules during deletion (`No rules match`); never fails or crashes. |
| **Fault Isolation** | Exceptions in the firewall subsystem are caught and logged; background monitoring and telemetry continue uninterrupted. |

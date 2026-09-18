# Network Monitoring Module

## 1. What is the Network Monitoring Module?

The **Network Monitoring Module** is an endpoint security telemetry component that observes active local and outbound network connections (TCP/UDP) on the host machine. It associates active sockets with their owning Process IDs (PIDs), process names, and parent-process lineages.

By monitoring active network endpoints, the system identifies anomalous network activities—such as unexpected processes initiating outbound connections (e.g., `cmd.exe` or `notepad.exe`), connections to known suspicious ports (e.g., 4444, 1337), script engines (`powershell.exe`, `wscript.exe`) connecting to non-standard remote ports, and outbound connections originating from processes that have already been flagged as suspicious by command detection or process-tree analysis.

---

## 2. Why is it Needed?

Endpoints are primary targets for cyber attacks where post-exploitation behavior relies heavily on network communications:

1. **Command and Control (C2) Channels**: Malware routinely establishes outbound TCP/UDP beacons to attacker-controlled infrastructure.
2. **Reverse Shells**: Exploits frequently spawn command shells (`cmd.exe`, `powershell.exe`, `sh`, `bash`) that connect back to attacker listeners on non-standard ports (e.g. 4444, 1337).
3. **Data Exfiltration**: Internal files and stolen credentials are transmitted via unexpected non-browser binaries.
4. **Living-off-the-Land (LotL) Network Execution**: Attackers abuse built-in utilities (`powershell.exe`, `certutil.exe`, `regsvr32.exe`) to download payloads over raw network sockets.

Without Network Monitoring, process-level analysis can only evaluate command lines and hierarchy. Network monitoring provides the critical link between process activity and external network communications.

---

## 3. Architecture & Data Flow

```text
               +----------------------------------+
               |        psutil.net_connections    |
               |        (Active socket table)     |
               +----------------------------------+
                                 |
                                 | Raw sockets (fd, laddr, raddr, status, pid)
                                 v
               +----------------------------------+
               |  src/monitors/network_monitor.py |
               | - NetworkConnection              |
               | - NetworkStateTracker            |
               | - Process association via PID    |
               +----------------------------------+
                                 |
                                 | Network anomaly evaluation
                                 v
               +----------------------------------+
               |       src/models/event.py        |
               | - Event(event_type="network_     |
               |         connection")             |
               | - event.network_info             |
               +----------------------------------+
                                 |
                                 v
               +----------------------------------+
               |  src/detectors/risk_detector.py  |
               | - Evaluates network indicators   |
               | - Composite risk scoring         |
               +----------------------------------+
                                 |
                                 v
               +----------------------------------+
               |            src/main.py           |
               | - Snapshot & Continuous modes    |
               | - Duplicate alert suppression    |
               | - Structured logs/security.log   |
               +----------------------------------+
```

---

## 4. APIs & Libraries Used

* **`psutil` (`psutil.net_connections(kind="inet")`)**: Queries active system-wide IPv4 and IPv6 network connections without requiring administrative privileges for accessible user-level sockets.
* **`psutil.Process(pid)`**: Fallback process telemetry lookup when a connection's PID is not already present in the existing process snapshot dictionary.
* **`socket`**: Standard library constants (`socket.SOCK_STREAM` for TCP, `socket.SOCK_DGRAM` for UDP).
* **`threading`**: Thread synchronization (`threading.Lock` and `threading.Event`) for thread-safe state tracking and background monitoring.

---

## 5. Telemetry Data Collected

For every active connection, a `NetworkConnection` object captures:

| Field | Type | Description |
| :--- | :--- | :--- |
| `pid` | `Optional[int]` | Owning Process ID. |
| `process_name` | `Optional[str]` | Executable name associated with the PID (e.g., `chrome.exe`). |
| `parent_process_name` | `Optional[str]` | Executable name of the parent process (e.g., `explorer.exe`). |
| `protocol` | `str` | `"TCP"` or `"UDP"`. |
| `local_ip` | `str` | Source IP address on the host (e.g., `192.168.1.50`). |
| `local_port` | `int` | Source port on the host (e.g., `51234`). |
| `remote_ip` | `Optional[str]` | Destination IP address (e.g., `93.184.216.34`). |
| `remote_port` | `Optional[int]` | Destination port (e.g., `443`). |
| `status` | `str` | Socket state (`ESTABLISHED`, `LISTEN`, `TIME_WAIT`, `SYN_SENT`, `NONE`). |
| `is_outbound` | `bool` | True if connection has a remote IP/port and is not in `LISTEN` state. |
| `timestamp` | `float` | Epoch timestamp of connection observation. |

---

## 6. Detection Logic & Heuristics

Connections are evaluated against deterministic, explainable security rules configured in `config/config.json`:

### Rule 1: Suspicious / Unusual Destination Port
* **Condition**: Remote port matches known malicious or backdoor ports (e.g. 21, 23, 69, 1337, 4444, 5555, 6667, 8888, 9999, 12345, 31337).
* **Indicator**: `suspicious_destination_port` (+4 points, `MEDIUM`).
* **Explanation**: `Connection to suspicious destination port {port} ({process})`.

### Rule 2: Unexpected Network-Initiating Process
* **Condition**: Outbound connection initiated by a process that normally does not require network access (e.g. `notepad.exe`, `calc.exe`, `cmd.exe`, `spoolsv.exe`, `taskhostw.exe`, `regsvr32.exe`, `mshta.exe`).
* **Indicator**: `unexpected_network_process` (+4 points, `MEDIUM`).
* **Explanation**: `Unexpected process initiating network connection: {process} -> {remote_ip}:{remote_port}`.

### Rule 3: Script Interpreter Outbound Call to Non-Standard Port
* **Condition**: A script engine (`powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `bash.exe`, `python.exe`) establishes an outbound connection to an external remote port other than standard web ports (80, 443, 8080, 8443, 53).
* **Indicator**: `suspicious_outbound_connection` (+4 points, `MEDIUM`).
* **Explanation**: `Script interpreter outbound connection to non-standard port: {process} -> {remote_ip}:{remote_port}`.

### Rule 4: Network Activity Associated with Already-Suspicious Process
* **Condition**: An outbound network connection originates from a process that already triggered suspicious command indicators (`encoded_command`, `hidden_execution`) or suspicious process-tree lineage (`suspicious_process_lineage`, `multi_level_shell_chain`).
* **Indicator**: `network_activity_suspicious_process` (+4 points, `HIGH`).
* **Explanation**: `Outbound network connection originating from already-suspicious process: {process} (PID: {pid}) -> {remote_ip}:{remote_port}`.

### Rule 5: Unusual Network Connection State
* **Condition**: Connection remains in `SYN_SENT` status to a non-standard external port, indicating potential port scanning or failing C2 callback.
* **Indicator**: `unusual_network_state` (+2 points, `LOW`).
* **Explanation**: `Unusual connection state {status} to {remote_ip}:{remote_port} by {process}`.

---

## 7. Standardized Event Structure

Network events conform to the project's standardized `Event` schema:

```json
{
  "event_id": "8f3b2d10-3456-4cde-8901-abcdef123456",
  "timestamp": 1789700000.0,
  "event_type": "network_connection",
  "source": "network_monitor",
  "severity": "HIGH",
  "pid": 11196,
  "ppid": 29204,
  "process_name": "cmd.exe",
  "parent_process_name": "chrome.exe",
  "network_info": {
    "pid": 11196,
    "process_name": "cmd.exe",
    "parent_process_name": "chrome.exe",
    "protocol": "TCP",
    "local_ip": "192.168.1.50",
    "local_port": 51234,
    "local_address": "192.168.1.50:51234",
    "remote_ip": "198.51.100.99",
    "remote_port": 4444,
    "remote_address": "198.51.100.99:4444",
    "status": "ESTABLISHED",
    "is_outbound": true,
    "timestamp": 1789700000.0
  },
  "indicators": [
    "suspicious_destination_port",
    "unexpected_network_process",
    "network_activity_suspicious_process"
  ],
  "risk_score": 12,
  "risk_level": "HIGH",
  "risk_reasons": [
    "Suspicious Destination Port (+4)",
    "Unexpected Network Process (+4)",
    "Network Activity Suspicious Process (+4)",
    "Connection to suspicious destination port 4444 (cmd.exe)"
  ],
  "metadata": {
    "network_findings": { ... }
  }
}
```

---

## 8. Integration with `main.py`

### 1. Snapshot Mode (Default Execution)
During initial startup:
1. `NetworkMonitor` audits current active sockets.
2. Matches sockets against the initial `processes` table and `process_tree`.
3. Displays connection count and reports any anomalous sockets:
   ```text
   Network Monitor: 192 active connections checked (80 outbound).
   ```

### 2. Continuous Monitoring Mode (`--continuous`)
In the continuous loop:
1. `network_monitor.check_connections(new_only=True)` evaluates newly opened sockets.
2. `NetworkStateTracker.should_alert(conn)` ensures that persistent, ongoing connections do not flood logs on every tick.
3. Only newly established suspicious sockets trigger console banners and log entries.

---

## 9. Risk & Correlation Integration (Composite Risk)

Network monitoring findings do not declare malware in isolation; they serve as quantitative evidence in the composite risk scoring engine:

$$\text{Composite Risk Score} = \text{Command Points} + \text{Tree Lineage Points} + \text{Network Telemetry Points} + \text{Context Points}$$

### Example Composite Escalation:
* Process `cmd.exe` spawned by `chrome.exe` $\rightarrow$ `suspicious_process_lineage` (+4 points, `MEDIUM`).
* `cmd.exe` makes outbound connection to port `4444` $\rightarrow$ `suspicious_destination_port` (+4 points) + `unexpected_network_process` (+4 points) + `network_activity_suspicious_process` (+4 points).
* **Total Composite Score = 16 points (`HIGH` / Critical Alert)**.

---

## 10. Test Cases & Validation Results

The test suite in `tests/test_network_monitor.py` covers 10 dedicated scenarios:

| Test Case | Purpose | Result |
| :--- | :--- | :--- |
| `test_normal_active_connection` | Validates that benign browsing traffic (port 443) is marked `LOW` risk. | `PASSED` |
| `test_new_connection_detection` | Verifies `NetworkStateTracker` identifies new connections on first observation. | `PASSED` |
| `test_multiple_connections_processing` | Verifies bulk socket processing across TCP and UDP. | `PASSED` |
| `test_process_to_connection_association` | Verifies mapping from socket PID to process name and parent process. | `PASSED` |
| `test_missing_disappeared_pid` | Handles exited PIDs and unmapped sockets without crashing. | `PASSED` |
| `test_permission_access_errors` | Verifies `psutil.AccessDenied` is caught cleanly without unhandled exceptions. | `PASSED` |
| `test_continuous_monitoring_new_connection` | Simulates consecutive monitoring ticks detecting newly established connections. | `PASSED` |
| `test_duplicate_alert_suppression` | Verifies ongoing active connections do not re-trigger alerts. | `PASSED` |
| `test_integration_with_event_model` | Verifies `Event` creation, `network_info` population, and JSON serialization. | `PASSED` |
| `test_composite_risk_correlation` | Validates multi-factor risk score escalation across process + tree + network. | `PASSED` |

Full test suite validation: **67 tests ran, 67 passed (100% success rate)**.

---

## 11. Known Limitations

1. **Short-Lived Ephemeral Sockets**:
   Connections that open, transmit packets, and close within milliseconds between polling intervals (e.g. DNS queries or UDP bursts) may not be caught by snapshot polling.
2. **Encrypted Payload Inspection**:
   The module inspects connection metadata (IPs, ports, protocols, and processes) rather than performing Deep Packet Inspection (DPI) or SSL/TLS decryption.
3. **Privileged Connection Visibility**:
   On Windows, connections owned by certain system-protected processes (`SYSTEM`, `csrss.exe`) may return `None` for PID unless the monitor is executed with elevated administrative rights.

---

## 12. Future Improvements

1. **DNS Query Resolution & Reverse Lookups**:
   Perform asynchronous reverse DNS resolution to map remote IP addresses to domain names (with caching to prevent latency).
2. **IP Reputation & GeoIP Integration**:
   Cross-reference external remote IPs against threat intelligence feeds (e.g., AlienVault OTX, AbuseIPDB) and GeoIP databases.
3. **Bandwidth & Packet Thresholds**:
   Track byte counters (`io_counters`) per socket to detect volumetric exfiltration bursts.
4. **Kernel-Level Event Tracing**:
   Integrate Windows ETW (`Microsoft-Windows-TCPIP` provider) or Linux eBPF for zero-latency, event-driven network socket tracking.

---

## 13. Viva / Review Questions & Answers

### Q1: What is the primary purpose of Network Monitoring in an endpoint security monitor?
**Answer**: It correlates host-level process execution with active network sockets, identifying when processes initiate abnormal outbound connections (such as reverse shells or C2 communications) to external endpoints.

### Q2: How does the network monitor associate a socket connection with its owning process?
**Answer**: `psutil.net_connections(kind="inet")` provides the `pid` attribute for each connection. The monitor resolves this PID against the existing `processes` dictionary collected by `process_monitor` (or queries `psutil.Process(pid)`), retrieving the process name and parent process without redundant system calls.

### Q3: How does the monitor prevent duplicate alert spam during continuous monitoring?
**Answer**: It uses `NetworkStateTracker` which indexes connections by a unique tuple `(pid, protocol, local_ip, local_port, remote_ip, remote_port)`. An alert is emitted only once when the connection is first established; ongoing connections are recognized as already alerted and suppressed until closed.

### Q4: How is network activity integrated into the existing `Event` model?
**Answer**: The monitor creates standard `Event` instances with `event_type="network_connection"` and `source="network_monitor"`, populating the pre-existing `event.network_info` dictionary with local/remote addresses, ports, protocol, and connection state.

### Q5: What happens if a process terminates between when a connection was opened and when the scan runs?
**Answer**: The monitor catches `psutil.NoSuchProcess` and `psutil.AccessDenied` gracefully, recording the PID with process name as `"unknown"` or using previously recorded snapshot telemetry without raising unhandled exceptions.

### Q6: What is an "unexpected network process" and why is it suspicious?
**Answer**: An unexpected network process is a utility (such as `notepad.exe`, `calc.exe`, or `cmd.exe`) that has no legitimate operational reason to establish an outbound Internet connection. An outbound socket from such a binary strongly suggests process injection or abuse as a reverse shell.

### Q7: How does composite risk scoring work with network events?
**Answer**: Network indicators (e.g., `suspicious_destination_port` +4, `unexpected_network_process` +4) are passed into `calculate_risk()`. When combined with process-level indicators (e.g. `encoded_command` +4 or `suspicious_process_lineage` +4), the scores additively compound to escalate the severity to `HIGH`.

### Q8: Does the network monitor require third-party packet-capture libraries like WinPcap or Npcap?
**Answer**: No. It relies purely on standard OS socket telemetry exposed by Python's `psutil.net_connections()`, ensuring portability, zero installation overhead, and low CPU consumption.


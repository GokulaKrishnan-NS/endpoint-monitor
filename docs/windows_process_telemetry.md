# Windows Process-Creation Telemetry (Security Event 4688)

This document describes the optional, Windows-specific, event-driven process
collection source that complements the psutil polling monitor.

---

## 1. Purpose and Scope

The polling monitor (`src/monitors/process_monitor.py`) enumerates the running
process table with `psutil`.  A process that starts **and** exits between two
polls is never observed by polling.  On a busy endpoint, short-lived helper
processes (script hosts, launchers, download stubs) therefore remain
invisible.

The process-creation telemetry source reads **Security Event 4688**
("A new process has been created") from the Windows Event Log and feeds the
*existing* monitoring pipeline:

```
Windows Event Log (Security / 4688)
        |
        v
WindowsProcessTelemetryCollector   (incremental wevtutil query, bounded de-dup)
        |
        v
ProcessTelemetryCorrelator         (normalizes into the standard process model)
        |
        v
MonitoringEngine._collect_process_telemetry()
        |
        +--> ProcessIdentityRegistry  (correlation with the polling monitor)
        +--> _evaluate_process_event() (command detection, tree analysis, risk)
        +--> _ingest_event()           (bounded event history + alert queue)
```

The telemetry source is **not** a parallel alert system: it produces the same
`Event` objects, uses the same command detector, the same risk scoring and
the same event history as every other monitor.

---

## 2. Enabling the Source

The source is **disabled by default** and is configured through the existing
configuration file (`config/config.json`):

```json
"controlled_execution": {
  "...": "...",
  "windows_process_telemetry": {
    "enabled": false,
    "channel": "Security",
    "event_id": 4688,
    "max_events_per_query": 200,
    "query_timeout_seconds": 10.0,
    "dedup_tolerance_seconds": 5.0,
    "require_command_line": false
  }
}
```

| Setting | Default | Meaning |
| :--- | :--- | :--- |
| `enabled` | `false` | Master switch.  When disabled nothing is queried. |
| `channel` | `Security` | Windows Event Log channel that carries the 4688 records. |
| `event_id` | `4688` | Event identifier of the process-creation record. |
| `max_events_per_query` | `200` | Maximum number of records read per query. |
| `query_timeout_seconds` | `10.0` | Timeout for a single `wevtutil` query. |
| `dedup_tolerance_seconds` | `5.0` | Creation-time tolerance used when correlating polling and telemetry. |
| `require_command_line` | `false` | Reserved for deployments that require command lines; the value is reported honestly as *unavailable* when the audit policy does not include it. |

The safe defaults are preserved: enabling the telemetry source never changes
`dry_run`, `interception_enabled` or `allow_active_execution`.

---

## 3. Target Machine Requirements

The monitor **never** changes the audit policy automatically.  The following
configuration has to be in place on the endpoint:

1. **Advanced Audit Policy - Process Creation**

   ```powershell
   auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
   ```

2. **Command line inclusion (optional but recommended)**

   ```
   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit
       ProcessCreationIncludeCmdLine (REG_DWORD) = 1
   ```

   Without this value the 4688 record contains no command line.  The monitor
   reports the field as *unavailable* (`None`) instead of pretending that the
   process had an empty command line.

3. **Administrative privileges** are required to read the `Security` channel.
   All other monitoring functionality - polling, resource, network, file,
   logon telemetry, the desktop UI and the controlled execution service -
   works without administrative privileges.

### Validating the fields on the target machine

The record layout depends on the Windows version and the audit configuration.
The integration test validates the fields that are actually produced:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_windows_process_telemetry.py -v -rs
```

The test is skipped (never failed) when the channel cannot be read or when
the audit policy is disabled.

---

## 4. Collection Mechanism

* `wevtutil.exe qe <channel> /q:<xpath> /c:<n> /f:xml` is used to read the
  channel.  No third party dependency and no driver is required.
* The collector tracks the highest `EventRecordID` it has already processed
  and queries with `EventRecordID > <last seen>` so that a burst of process
  creations is never truncated.
* On the first query the collector seeds a baseline at the newest existing
  record: only processes created **after** the monitor started are reported.
* Records are de-duplicated with a bounded cache so that an overlapping
  query can never produce the same event twice.

---

## 5. Correlation With the Polling Monitor

Process identity is `(PID, creation time)` - a PID alone is not an identity,
because Windows recycles PIDs.

`ProcessIdentityRegistry` (`src/monitors/process_monitor.py`) records every
process instance that has already been reported, no matter whether it was
observed by polling or by the event log:

* the same process instance is reported **once**,
* a recycled PID is reported **again** (the creation time differs),
* an unknown creation time is treated conservatively as "already known".

When a telemetry record describes a process that the polling monitor has
already reported, the telemetry evidence is attached to the existing event
(`metadata["telemetry_confirmed"]`) instead of creating a second event.

---

## 6. Graceful Degradation

| Situation | Behaviour |
| :--- | :--- |
| `wevtutil.exe` not found | Source marked `UNAVAILABLE` (`wevtutil_not_found`), warning logged, polling continues. |
| Access denied (no elevation) | Source marked `UNAVAILABLE` (`access_denied`), clear warning logged, polling continues. |
| Channel not present | Source marked `UNAVAILABLE` (`channel_unavailable`), polling continues. |
| Query timeout | Transient error recorded, the source stays usable. |
| Malformed XML / malformed fields | The record is skipped, the collector keeps working. |
| Missing command line | The field is reported as unavailable (`None`), never as an empty string. |

The status of the source is exposed through
`MonitoringEngine.get_process_telemetry_status()` and in the state snapshot
(`process_telemetry`), so the UI and the terminal dashboard can show whether
the event driven coverage is actually active.

---

## 7. Observation, Detection, Alerting, Prevention

| Stage | What the telemetry source contributes |
| :--- | :--- |
| **Observation** | Catches process creation events that polling misses (short-lived processes). |
| **Detection** | Feeds the same command detector and process-tree analysis as the polling monitor. |
| **Alerting** | Produces the same `Event` objects; the alert threshold is unchanged. |
| **Prevention** | **None.**  Security event 4688 is a *post*-execution record.  It cannot block a process.  Pre-execution prevention remains the responsibility of Windows App Control for Business (WDAC) / AppLocker and of the controlled execution service for requests that are routed through it. |

---

## 8. Security Boundaries

* The monitor never modifies the system audit policy, never installs a
  service or driver, never changes firewall rules and never disables
  Defender or tamper protection.
* The user-space controlled launcher does **not** intercept all Windows
  process creation - it only mediates execution requests that are submitted
  to the Python service.
* Reading the Security channel is a privileged operation; the telemetry
  source therefore degrades to "unavailable" instead of failing the whole
  monitor.

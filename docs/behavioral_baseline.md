# Behavioral Baseline

## 1. What is Behavioral Baseline?

A **Behavioral Baseline** is a security monitoring feature that learns what normal system execution looks like on a computer over time. Instead of relying solely on static signature rules or fixed thresholds, a behavioral baseline tracks recurring process lineages, user accounts, and system resource distributions. 

When a process executes under unusual conditions (such as a browser spawning a command shell, or a known application running under an unexpected user account), the behavioral baseline identifies the deviation and flags it as an anomaly.

---

## 2. Why Do We Need It?

Static detection rules (such as matching string patterns like `-enc` or `download_and_execute`) are essential but insufficient on their own for several reasons:

1. **Living-off-the-Land (LotL) Attacks**: Attackers frequently use legitimate system utilities (`cmd.exe`, `powershell.exe`, `certutil.exe`) without using obvious suspicious arguments. Static rules will not flag a normal `cmd.exe` command line, but a behavioral baseline detects when `cmd.exe` is spawned by an unexpected parent process like `msedgewebview2.exe`.
2. **Context-Specific Anomalies**: On one system, running a script under `SYSTEM` privileges may be routine, while on another it is rare. A behavioral baseline adapts to the specific environment.
3. **Dynamic Resource Anomalies**: A static CPU threshold (e.g. 90%) may trigger false alarms during normal heavy workloads. Statistical baselining tracks standard deviations to flag true statistical outliers ($Z > 2.5$).

---

## 3. How Our Implementation Works

The feature is implemented in [src/baseline/baseline_engine.py](file:///c:/Users/ACER/projects/endpoint-monitor/src/baseline/baseline_engine.py) via the `BaselineEngine` class.

* **Integration with Common Event Model**: The engine listens directly to standardized `Event` instances created by Feature 1.
* **Warm-up / Learning Phase**: During the initial execution window (first 20 events), the engine records process profiles quietly (`status="LEARNING"`) without raising false alarms.
* **Enforcement Phase**: Once sufficient data is collected, incoming events are evaluated against stored profiles (`status="ENFORCING"`).
* **Poisoning Prevention**: Only clean events (`risk_score == 0` and `indicators == []`) are allowed to update baseline profiles. Suspicious events are evaluated for anomalies but rejected from training data.
* **JSON Persistence**: Baseline profiles are serialized to [config/baseline.json](file:///c:/Users/ACER/projects/endpoint-monitor/config/baseline.json) so learned behavior persists across system restarts.

---

## 4. Files Involved

| File | Status | Purpose |
| :--- | :--- | :--- |
| [src/baseline/__init__.py](file:///c:/Users/ACER/projects/endpoint-monitor/src/baseline/__init__.py) | **Created** | Package initialization file exporting `BaselineEngine`. |
| [src/baseline/baseline_engine.py](file:///c:/Users/ACER/projects/endpoint-monitor/src/baseline/baseline_engine.py) | **Created** | Core implementation of `BaselineEngine` (statistics, collection, Z-score, anomaly scoring, JSON persistence). |
| [tests/test_baseline.py](file:///c:/Users/ACER/projects/endpoint-monitor/tests/test_baseline.py) | **Created** | Unit tests for learning, warm-up phase, lineage anomalies, Z-score math, poisoning prevention, and file persistence. |
| [src/main.py](file:///c:/Users/ACER/projects/endpoint-monitor/src/main.py) | **Modified** | Integrated `BaselineEngine` to evaluate events (`analyze_event`), collect clean telemetry (`collect_event`), save profiles (`save_baseline`), and output behavioral anomaly alerts (`report_behavioral_anomaly`). |
| [docs/behavioral_baseline.md](file:///c:/Users/ACER/projects/endpoint-monitor/docs/behavioral_baseline.md) | **Created** | Comprehensive technical documentation. |

---

## 5. Baseline Data Stored

Baseline profiles are stored in [config/baseline.json](file:///c:/Users/ACER/projects/endpoint-monitor/config/baseline.json) with the following structure:

```json
{
  "total_observed_events": 45,
  "process_profiles": {
    "notepad.exe": {
      "execution_count": 12,
      "known_parents": ["explorer.exe"],
      "known_users": ["GREENAPPLE\\ACER"]
    },
    "cmd.exe": {
      "execution_count": 8,
      "known_parents": ["explorer.exe", "code.exe"],
      "known_users": ["GREENAPPLE\\ACER"]
    }
  },
  "cpu_samples": [10.5, 12.0, 11.2, 9.8, 14.1],
  "memory_samples": [70.1, 70.2, 70.0, 71.2, 70.5]
}
```

---

## 6. Baseline Calculation

### A. Process Execution Profiles (Frequency & Lineage Sets)
For each process executable (lowercased), the baseline maintains:
* `execution_count`: Incremented per clean observation.
* `known_parents`: List of unique parent process names observed spawning this process.
* `known_users`: List of unique user accounts observed running this process.

### B. Resource Usage Distributions (Mean & Standard Deviation)
For continuous numerical metrics (CPU and Memory percentages), the engine computes the sample arithmetic mean ($\mu$) and sample standard deviation ($\sigma$):

$$\mu = \frac{1}{N} \sum_{i=1}^{N} x_i, \quad \sigma = \sqrt{\frac{1}{N - 1} \sum_{i=1}^{N} (x_i - \mu)^2}$$

When a new resource metric value $x$ is evaluated:

$$Z = \frac{x - \mu}{\sigma}$$

If $Z > 2.5$, the metric is classified as a statistical spike anomaly.

---

## 7. Anomaly Detection

When an `Event` is passed to `baseline_engine.analyze_event(event)`:

1. **Execution Checks**:
   * **Unseen Process Executable**: Process name not in `process_profiles` $\rightarrow$ **+2 points**.
   * **Unseen Parent-Child Lineage**: Parent process not in `known_parents` $\rightarrow$ **+3 points**.
   * **Unseen User Context**: User account not in `known_users` $\rightarrow$ **+2 points**.
2. **Resource Z-Score Checks**:
   * CPU $Z > 2.5$ $\rightarrow$ **+2 points**.
   * Memory $Z > 2.5$ $\rightarrow$ **+2 points**.
3. **Severity Thresholds**:
   * Score $\ge 5$: `HIGH` Anomaly.
   * Score $\ge 3$: `MEDIUM` Anomaly.
   * Score $< 3$: `LOW` / Normal.
4. **Warm-up Protection**: If `total_observed_events < 20`, `is_anomaly` evaluates to `False` and `status` is set to `"LEARNING"`.

---

## 8. Thresholds and Assumptions

All thresholds are project-specific, deterministic heuristics:

| Parameter | Value | Description / Justification |
| :--- | :--- | :--- |
| `WARMUP_EVENT_THRESHOLD` | `20` | Minimum global process observations required before enforcing baseline anomalies. |
| `RESOURCE_MIN_SAMPLES` | `10` | Minimum resource metric samples required before calculating standard deviation. |
| `Z_SCORE_THRESHOLD` | `2.5` | Standard deviations cutoff for flagging abnormal resource usage spikes. |
| `POINTS_UNSEEN_PROCESS` | `2` | Anomaly points assigned for a process executable never seen on the host. |
| `POINTS_UNSEEN_LINEAGE` | `3` | Anomaly points assigned for an unusual parent-child process relationship. |
| `POINTS_UNSEEN_USER` | `2` | Anomaly points assigned for a process running under an unrecorded user account. |
| `POINTS_RESOURCE_SPIKE` | `2` | Anomaly points assigned for a resource Z-score exceeding 2.5. |

---

## 9. Classes and Functions

### `BaselineEngine` ([src/baseline/baseline_engine.py](file:///c:/Users/ACER/projects/endpoint-monitor/src/baseline/baseline_engine.py))
* **What it does**: Main engine managing baseline learning, statistics computation, anomaly comparison, and JSON file persistence.

#### Methods:
* **`load_baseline()`**: Loads stored profile data from `config/baseline.json`.
* **`save_baseline()`**: Writes updated profile data to `config/baseline.json`.
* **`compute_stats(samples: List[float]) -> Dict[str, float]`**: Calculates mean ($\mu$), standard deviation ($\sigma$), and sample count ($N$).
* **`compute_z_score(value, mean, stddev) -> float`**: Calculates Z-score $Z = (x - \mu)/\sigma$.
* **`collect_event(event: Event) -> None`**: Updates baseline profiles using clean events (`risk_score == 0` and `indicators == []`).
* **`analyze_event(event: Event) -> Dict[str, Any]`**: Evaluates event against stored profiles and returns anomaly result dictionary.
* **`report_behavioral_anomaly(event, anomaly_result, logger)` ([src/main.py](file:///c:/Users/ACER/projects/endpoint-monitor/src/main.py))**: Formats and logs behavioral anomaly warnings.

---

## 10. Complete Execution Flow

```text
Process / Resource Monitor
            ↓
  Event.from_process_info()
            ↓
detect_command_indicators() & calculate_risk()
            ↓
   BaselineEngine.analyze_event(event)
            ↓
  Attach result to event.metadata["baseline_anomaly"]
            ↓
   BaselineEngine.collect_event(event)  <-- (IF risk_score == 0 AND indicators == [])
            ↓
   report_behavioral_anomaly() & logger.warning()  <-- (IF is_anomaly is True)
            ↓
   BaselineEngine.save_baseline()
```

---

## 11. Example Trace: Normal Process vs Abnormal Lineage

### 1. Normal Observation Phase
During initial system scanning, `explorer.exe` spawns `cmd.exe` under user `GREENAPPLE\ACER` 25 times:
* Baseline profile updated in `process_profiles["cmd.exe"]`:
  ```json
  "known_parents": ["explorer.exe"],
  "known_users": ["GREENAPPLE\\ACER"]
  ```

### 2. Anomaly Occurrence
An edge browser background component `msedgewebview2.exe` unexpectedly spawns `cmd.exe`:
* `Event` created: `process_name="cmd.exe"`, `parent_process_name="msedgewebview2.exe"`, `username="GREENAPPLE\\ACER"`.

### 3. Baseline Comparison
`baseline_engine.analyze_event(event)` evaluates the event:
* `cmd.exe` is known $\rightarrow$ +0 points.
* `GREENAPPLE\ACER` is known for `cmd.exe` $\rightarrow$ +0 points.
* Parent `msedgewebview2.exe` is NOT in `known_parents: ["explorer.exe"]` $\rightarrow$ **+3 points**.

### 4. Anomaly Result
```python
{
    "is_anomaly": True,
    "anomaly_score": 3,
    "anomaly_level": "MEDIUM",
    "reasons": [
        "Unseen parent-child lineage: msedgewebview2.exe -> cmd.exe (+3)"
    ],
    "status": "ENFORCING"
}
```

### 5. Application Action
* Alerts formatted banner printed:
  ```text
  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  Behavioral Anomaly detected | PID: 31096 | Process: cmd.exe | Parent: msedgewebview2.exe | Anomaly Level: MEDIUM | Anomaly Score: 3
  Behavioral Deviation Reasons:
    - Unseen parent-child lineage: msedgewebview2.exe -> cmd.exe (+3)
  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  ```
* Written to `logs/security.log`.
* `collect_event` rejects updating `cmd.exe`'s known parent list because this anomaly requires investigation.

---

## 12. Python Concepts Used

* **Classes & Object-Oriented Design**: `BaselineEngine` encapsulates state, statistics, and evaluation logic.
* **Standard Library Dependencies**: Uses standard Python modules (`json`, `math`, `os`, `logging`, `typing`, `collections`).
* **Set Membership Testing**: Uses `not in` checks on `known_parents` and `known_users` lists.
* **Statistical Mathematics**: Sample mean ($\mu$) and standard deviation ($\sigma$) with sample variance ($N-1$).
* **File Persistence**: Uses `json.dump` and `json.load` for readable profile storage.

---

## 13. Security Value for Endpoint Security

* **Detects Living-off-the-Land (LotL) Attacks**: Catches legitimate binaries executed from unexpected parent processes without needing static signature rules.
* **Host-Adaptive**: Automatically learns the software ecosystem of the specific host computer.
* **Explainable Output**: Every anomaly result explicitly states the reason (e.g. `Unseen parent-child lineage`) and exact point weights.

---

## 14. Limitations

* **Single-Host Scope**: Baseline data is stored locally in `config/baseline.json` and is not synchronized across a network.
* **Heuristic Cutoffs**: Uses deterministic point weights and $Z=2.5$ cutoffs rather than machine learning classifiers.
* **Initial Warm-up Period**: Requires 20 process events before enforcement mode activates.

---

## 15. Future Integration Capabilities

* **Process-Tree Analysis**: Lineage data (`known_parents`) will form the backbone for full multi-level process execution graphs.
* **Network Monitoring**: The engine will track `known_remote_ports` per process when network telemetry is introduced.
* **Event Correlation & Composite Risk**: `anomaly_score` will feed into multi-event risk rules alongside static command risk scores.

---

## 16. Viva Questions & Answers

1. **Q: What is the main purpose of the Behavioral Baseline feature?**
   *A: It establishes a profile of normal host activity (process execution patterns, parent-child lineages, user accounts, and resource usage distributions) to detect abnormal deviations in real time.*

2. **Q: How does the baseline prevent poisoning from malicious events?**
   *A: Events with `risk_score > 0` or non-empty `indicators` are rejected from `collect_event()`, ensuring suspicious activity never updates the normal profile.*

3. **Q: How is resource usage baselined mathematically?**
   *A: It computes the sample mean ($\mu$) and standard deviation ($\sigma$) over a sliding window of metric samples and computes the Z-score $Z = (x - \mu)/\sigma$. A value with $Z > 2.5$ is flagged as an anomaly.*

4. **Q: What happens during the system warm-up phase?**
   *A: During the first 20 events (`WARMUP_EVENT_THRESHOLD`), the engine runs in `LEARNING` mode: events build baseline profiles silently without raising anomaly alerts.*

5. **Q: How are process lineage anomalies detected?**
   *A: The engine maintains a list of `known_parents` per process. If a process is spawned by a parent not in its `known_parents` list, +3 anomaly points are assigned.*

6. **Q: Where is baseline data stored?**
   *A: In `config/baseline.json` via standard JSON serialization.*

7. **Q: What is the difference between static command detection and behavioral baseline detection?**
   *A: Static command detection flags specific suspicious strings (like `-enc`), whereas behavioral baselining flags structural deviations (like an unusual parent process) even if the command string appears normal.*

8. **Q: How does the Behavioral Baseline integrate with the Common Event Model?**
   *A: The engine accepts standard `Event` instances, reads process/resource attributes, and attaches its evaluation result directly to `event.metadata["baseline_anomaly"]`.*

9. **Q: Why are point weights and $Z=2.5$ used instead of machine learning?**
   *A: To keep the detection engine deterministic, explainable, lightweight, and free from external heavy dependencies or training complexity.*

10. **Q: What anomaly score triggers a `HIGH` behavioral severity?**
    *A: An anomaly score $\ge 5$ triggers `HIGH`, $3..4$ triggers `MEDIUM`, and $< 3$ is `LOW`/normal.*

---

## 17. Implementation Summary

* **Files Created**:
  * [src/baseline/__init__.py](file:///c:/Users/ACER/projects/endpoint-monitor/src/baseline/__init__.py)
  * [src/baseline/baseline_engine.py](file:///c:/Users/ACER/projects/endpoint-monitor/src/baseline/baseline_engine.py)
  * [tests/test_baseline.py](file:///c:/Users/ACER/projects/endpoint-monitor/tests/test_baseline.py)
  * [docs/behavioral_baseline.md](file:///c:/Users/ACER/projects/endpoint-monitor/docs/behavioral_baseline.md)
* **Files Modified**:
  * [src/main.py](file:///c:/Users/ACER/projects/endpoint-monitor/src/main.py)
* **Classes Added**:
  * `BaselineEngine` (`src/baseline/baseline_engine.py`)
* **Functions Added / Modified**:
  * `BaselineEngine.load_baseline()`
  * `BaselineEngine.save_baseline()`
  * `BaselineEngine.compute_stats()`
  * `BaselineEngine.compute_z_score()`
  * `BaselineEngine.collect_event()`
  * `BaselineEngine.analyze_event()`
  * `report_behavioral_anomaly()` (`src/main.py`)
* **Dependencies Added**: None (uses standard library modules `json`, `math`, `os`, `logging`, `typing`, `collections`).

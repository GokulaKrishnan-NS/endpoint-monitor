import json
import math
import os
import logging
from typing import Dict, Any, List, Optional
from collections import deque

from src.models.event import Event


# Heuristic Project Constants (Explainable, non-ML rules)
DEFAULT_BASELINE_PATH = "config/baseline.json"
WARMUP_EVENT_THRESHOLD = 20      # Global process event count before enforcement mode
RESOURCE_MIN_SAMPLES = 10        # Minimum resource metric samples before Z-score evaluation
Z_SCORE_THRESHOLD = 2.5          # Standard deviations threshold for resource spikes

# Heuristic Anomaly Points
POINTS_UNSEEN_PROCESS = 2
POINTS_UNSEEN_LINEAGE = 3
POINTS_UNSEEN_USER = 2
POINTS_RESOURCE_SPIKE = 2


class BaselineEngine:
    """
    Behavioral Baseline Engine.
    Tracks normal process execution profiles, parent-child lineages, user contexts,
    and system resource distributions (mean and standard deviation).
    """

    def __init__(self, storage_path: str = DEFAULT_BASELINE_PATH):
        self.storage_path = storage_path
        self.logger = logging.getLogger("endpoint_monitor")

        # Internal state structures
        self.total_observed_events: int = 0
        self.process_profiles: Dict[str, Dict[str, Any]] = {}
        self.cpu_samples: List[float] = []
        self.memory_samples: List[float] = []

        self.load_baseline()

    def load_baseline(self) -> None:
        """
        Load baseline profile data from storage_path if it exists.
        """
        if not os.path.exists(self.storage_path):
            return

        try:
            with open(self.storage_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    return
                data = json.loads(content)
                self.total_observed_events = data.get("total_observed_events", 0)
                self.process_profiles = data.get("process_profiles", {})
                self.cpu_samples = data.get("cpu_samples", [])
                self.memory_samples = data.get("memory_samples", [])
        except Exception as e:
            self.logger.debug(f"Could not load baseline from {self.storage_path}: {e}")

    def save_baseline(self) -> None:
        """
        Serialize baseline profile data to storage_path.
        """
        try:
            os.makedirs(os.path.dirname(self.storage_path) or ".", exist_ok=True)
            data = {
                "total_observed_events": self.total_observed_events,
                "process_profiles": self.process_profiles,
                "cpu_samples": self.cpu_samples[-100:],     # Keep last 100 samples
                "memory_samples": self.memory_samples[-100:], # Keep last 100 samples
            }
            with open(self.storage_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.logger.debug(f"Could not save baseline to {self.storage_path}: {e}")

    # =========================================================================
    # 1. BASELINE CALCULATION (Statistical Helpers)
    # =========================================================================

    def compute_stats(self, samples: List[float]) -> Dict[str, float]:
        """
        Calculate arithmetic mean (μ) and standard deviation (σ) for a list of samples.
        """
        if not samples or len(samples) < 2:
            return {"mean": 0.0, "stddev": 0.0, "count": len(samples)}

        n = len(samples)
        mean = sum(samples) / n
        variance = sum((x - mean) ** 2 for x in samples) / (n - 1)
        stddev = math.sqrt(variance)

        return {"mean": mean, "stddev": stddev, "count": n}

    def compute_z_score(self, value: float, mean: float, stddev: float) -> float:
        """
        Calculate Z-score: Z = (x - μ) / σ.
        Returns 0.0 if standard deviation is zero.
        """
        if stddev == 0.0:
            return 0.0
        return (value - mean) / stddev

    # =========================================================================
    # 2. BASELINE COLLECTION (Learning Phase)
    # =========================================================================

    def collect_event(self, event: Event) -> None:
        """
        Collect normal telemetry to build baseline profiles.

        POISONING PREVENTION:
        Rejects any event that contains suspicious indicators or risk_score > 0
        to avoid treating malicious behavior as normal.
        """
        # Reject suspicious events from baseline profiles
        if event.risk_score > 0 or len(event.indicators) > 0:
            return

        self.total_observed_events += 1

        # Process Baseline Collection
        if event.event_type == "process_start" and event.process_name:
            proc_name = event.process_name.lower()

            if proc_name not in self.process_profiles:
                self.process_profiles[proc_name] = {
                    "execution_count": 0,
                    "known_parents": [],
                    "known_users": [],
                }

            profile = self.process_profiles[proc_name]
            profile["execution_count"] += 1

            if event.parent_process_name:
                parent_name = event.parent_process_name.lower()
                if parent_name not in profile["known_parents"]:
                    profile["known_parents"].append(parent_name)

            if event.username:
                user_name = event.username.lower()
                if user_name not in profile["known_users"]:
                    profile["known_users"].append(user_name)

        # Resource Baseline Collection
        if event.resource_metrics:
            metrics = event.resource_metrics
            if "cpu" in metrics and "percent" in metrics["cpu"]:
                self.cpu_samples.append(float(metrics["cpu"]["percent"]))
                if len(self.cpu_samples) > 100:
                    self.cpu_samples.pop(0)

            if "memory" in metrics and "percent" in metrics["memory"]:
                self.memory_samples.append(float(metrics["memory"]["percent"]))
                if len(self.memory_samples) > 100:
                    self.memory_samples.pop(0)

    # =========================================================================
    # 3. ANOMALY COMPARISON & RESULT GENERATION
    # =========================================================================

    def analyze_event(self, event: Event) -> Dict[str, Any]:
        """
        Compare an incoming Event against learned baseline statistics.
        Returns an anomaly evaluation dictionary.
        """
        score = 0
        reasons: List[str] = []

        # Determine if engine is in warm-up (learning) mode
        is_warmup = self.total_observed_events < WARMUP_EVENT_THRESHOLD
        status = "LEARNING" if is_warmup else "ENFORCING"

        # Evaluate Process Execution Anomalies
        if event.event_type == "process_start" and event.process_name:
            proc_name = event.process_name.lower()

            if proc_name not in self.process_profiles:
                if not is_warmup:
                    score += POINTS_UNSEEN_PROCESS
                    reasons.append(
                        f"Unseen process executable: {event.process_name} (+{POINTS_UNSEEN_PROCESS})"
                    )
            else:
                profile = self.process_profiles[proc_name]

                # Parent-child lineage anomaly
                if event.parent_process_name:
                    parent_name = event.parent_process_name.lower()
                    if parent_name not in profile["known_parents"]:
                        if not is_warmup:
                            score += POINTS_UNSEEN_LINEAGE
                            reasons.append(
                                f"Unseen parent-child lineage: {event.parent_process_name} -> "
                                f"{event.process_name} (+{POINTS_UNSEEN_LINEAGE})"
                            )

                # User context anomaly
                if event.username:
                    user_name = event.username.lower()
                    if user_name not in profile["known_users"]:
                        if not is_warmup:
                            score += POINTS_UNSEEN_USER
                            reasons.append(
                                f"Unseen user context for {event.process_name}: "
                                f"{event.username} (+{POINTS_UNSEEN_USER})"
                            )

        # Evaluate Resource Metric Anomalies (Z-score evaluation)
        if event.resource_metrics:
            metrics = event.resource_metrics

            if "cpu" in metrics and "percent" in metrics["cpu"]:
                cpu_val = float(metrics["cpu"]["percent"])
                if len(self.cpu_samples) >= RESOURCE_MIN_SAMPLES:
                    stats = self.compute_stats(self.cpu_samples)
                    z_score = self.compute_z_score(cpu_val, stats["mean"], stats["stddev"])
                    if z_score > Z_SCORE_THRESHOLD:
                        score += POINTS_RESOURCE_SPIKE
                        reasons.append(
                            f"Abnormal CPU usage spike (Z-score: {z_score:.2f} > {Z_SCORE_THRESHOLD}) "
                            f"(+{POINTS_RESOURCE_SPIKE})"
                        )

            if "memory" in metrics and "percent" in metrics["memory"]:
                mem_val = float(metrics["memory"]["percent"])
                if len(self.memory_samples) >= RESOURCE_MIN_SAMPLES:
                    stats = self.compute_stats(self.memory_samples)
                    z_score = self.compute_z_score(mem_val, stats["mean"], stats["stddev"])
                    if z_score > Z_SCORE_THRESHOLD:
                        score += POINTS_RESOURCE_SPIKE
                        reasons.append(
                            f"Abnormal Memory usage spike (Z-score: {z_score:.2f} > {Z_SCORE_THRESHOLD}) "
                            f"(+{POINTS_RESOURCE_SPIKE})"
                        )

        # Severity Classification
        if score >= 5:
            level = "HIGH"
        elif score >= 3:
            level = "MEDIUM"
        else:
            level = "LOW"

        is_anomaly = score >= 3 and not is_warmup

        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": score,
            "anomaly_level": level,
            "reasons": reasons,
            "status": status,
        }

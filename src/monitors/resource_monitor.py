"""
Resource / System Monitoring Module

Continuously monitors system-level resource usage (CPU, RAM, Swap, Disk, I/O)
using psutil. Identifies abnormal consumption, detects sustained usage spikes,
suppresses duplicate alert spam, logs structured security events, and handles
clean recovery and shutdown.
"""

import json
import logging
import os
import sys
import threading
import time
from collections import deque
import psutil

from src.utils.logger import setup_logger
from src.alerts.alert_manager import show_alert


DEFAULT_CONFIG = {
    "check_interval": 5,
    "cpu": {
        "medium_threshold": 70.0,
        "high_threshold": 90.0,
        "sustained_samples": 3,
    },
    "memory": {
        "medium_threshold": 70.0,
        "high_threshold": 90.0,
        "sustained_samples": 3,
    },
    "swap": {
        "enabled": True,
        "medium_threshold": 70.0,
        "high_threshold": 90.0,
        "sustained_samples": 3,
    },
    "disk": {
        "enabled": True,
        "medium_threshold": 80.0,
        "high_threshold": 90.0,
        "sustained_samples": 3,
        "mount_point": "default",
    },
}


def format_bytes(bytes_value):
    """
    Convert bytes into a human-readable string (e.g. 8.20 GB).
    """
    if bytes_value is None:
        return "N/A"
    try:
        val = float(bytes_value)
        for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
            if abs(val) < 1024.0:
                return f"{val:.2f} {unit}"
            val /= 1024.0
        return f"{val:.2f} EB"
    except (ValueError, TypeError):
        return "N/A"


def get_default_mount_point():
    """
    Return default root filesystem mount point ('C:\\' on Windows, '/' on Unix).
    """
    if os.name == "nt":
        drive = os.path.splitdrive(os.path.abspath("."))[0]
        return f"{drive}\\" if drive else "C:\\"
    return "/"


def load_config(config_path="config/config.json"):
    """
    Load resource monitor configuration from file, falling back to defaults.
    """
    config = dict(DEFAULT_CONFIG)

    if not os.path.exists(config_path):
        return config

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return config
            data = json.loads(content)
            rm_config = data.get("resource_monitor", {})

            if "check_interval" in rm_config:
                config["check_interval"] = rm_config["check_interval"]

            for section in ["cpu", "memory", "swap", "disk"]:
                if section in rm_config:
                    merged = dict(config.get(section, {}))
                    merged.update(rm_config[section])
                    config[section] = merged

    except Exception as e:
        # Fallback cleanly to defaults if reading/parsing fails
        logging.getLogger("endpoint_monitor").debug(
            f"Could not load {config_path}, using default config: {e}"
        )

    return config


class ResourceStateTracker:
    """
    Tracks historical samples, sustained duration, state transitions,
    and alert suppression for an individual monitored resource.
    """

    def __init__(self, name, medium_threshold, high_threshold, sustained_samples, max_history=20):
        self.name = name
        self.medium_threshold = medium_threshold
        self.high_threshold = high_threshold
        self.sustained_samples = sustained_samples

        self.history = deque(maxlen=max_history)
        self.consecutive_high = 0
        self.consecutive_medium = 0
        self.consecutive_normal = 0

        self.current_state = "NORMAL"  # "NORMAL", "MEDIUM", "HIGH"
        self.sustained_alert_logged = False
        self.last_logged_usage = 0.0

    def update(self, usage):
        """
        Record a new usage sample and evaluate state changes, alerts,
        sustained detection, and recoveries.

        Returns a list of alert dicts:
        [{
            "type": "ALERT" | "WARNING" | "RECOVERY",
            "resource": name,
            "usage": float,
            "severity": "LOW" | "MEDIUM" | "HIGH",
            "message": str,
            "is_sustained": bool
        }]
        """
        self.history.append(usage)
        alerts = []

        # Update sample counters
        if usage >= self.high_threshold:
            self.consecutive_high += 1
            self.consecutive_medium = 0
            self.consecutive_normal = 0
            sample_state = "HIGH"
        elif usage >= self.medium_threshold:
            self.consecutive_medium += 1
            self.consecutive_high = 0
            self.consecutive_normal = 0
            sample_state = "MEDIUM"
        else:
            self.consecutive_normal += 1
            self.consecutive_high = 0
            self.consecutive_medium = 0
            sample_state = "NORMAL"

        # Case 1: Recovery to NORMAL
        if sample_state == "NORMAL":
            if self.current_state != "NORMAL":
                alerts.append({
                    "type": "RECOVERY",
                    "resource": self.name.upper(),
                    "usage": usage,
                    "severity": "LOW",
                    "message": (
                        f"RESOURCE RECOVERY | {self.name.upper()} | "
                        f"Usage returned to normal: {usage:.1f}% | Severity: LOW"
                    ),
                    "is_sustained": False,
                })
                self.current_state = "NORMAL"
                self.sustained_alert_logged = False
                self.last_logged_usage = usage
            return alerts

        # Case 2: Escalation to HIGH from NORMAL or MEDIUM
        if sample_state == "HIGH":
            if self.current_state != "HIGH":
                alerts.append({
                    "type": "ALERT",
                    "resource": self.name.upper(),
                    "usage": usage,
                    "severity": "HIGH",
                    "message": (
                        f"RESOURCE ALERT | {self.name.upper()} | "
                        f"Abnormally high usage exceeded threshold: {usage:.1f}% | Severity: HIGH"
                    ),
                    "is_sustained": False,
                })
                self.current_state = "HIGH"
                self.sustained_alert_logged = False
                self.last_logged_usage = usage

            # Check for sustained condition
            if (
                self.consecutive_high >= self.sustained_samples
                and not self.sustained_alert_logged
            ):
                alerts.append({
                    "type": "ALERT",
                    "resource": self.name.upper(),
                    "usage": usage,
                    "severity": "HIGH",
                    "message": (
                        f"RESOURCE ALERT | {self.name.upper()} | "
                        f"Sustained high usage detected ({self.consecutive_high} consecutive samples >= "
                        f"{self.high_threshold:.1f}%, current: {usage:.1f}%) | Severity: HIGH"
                    ),
                    "is_sustained": True,
                })
                self.sustained_alert_logged = True
                self.last_logged_usage = usage

            # Check for significant shift while elevated (alert suppression allows meaningful shifts)
            elif (
                self.sustained_alert_logged
                and abs(usage - self.last_logged_usage) >= 10.0
            ):
                alerts.append({
                    "type": "ALERT",
                    "resource": self.name.upper(),
                    "usage": usage,
                    "severity": "HIGH",
                    "message": (
                        f"RESOURCE ALERT | {self.name.upper()} | "
                        f"Usage shifted significantly while elevated: {usage:.1f}% "
                        f"(previously {self.last_logged_usage:.1f}%) | Severity: HIGH"
                    ),
                    "is_sustained": False,
                })
                self.last_logged_usage = usage

            return alerts

        # Case 3: Sample is MEDIUM
        if sample_state == "MEDIUM":
            if self.current_state == "NORMAL":
                alerts.append({
                    "type": "WARNING",
                    "resource": self.name.upper(),
                    "usage": usage,
                    "severity": "MEDIUM",
                    "message": (
                        f"RESOURCE WARNING | {self.name.upper()} | "
                        f"Elevated usage exceeded threshold: {usage:.1f}% | Severity: MEDIUM"
                    ),
                    "is_sustained": False,
                })
                self.current_state = "MEDIUM"
                self.sustained_alert_logged = False
                self.last_logged_usage = usage

            elif self.current_state == "HIGH":
                # De-escalated from HIGH to MEDIUM
                alerts.append({
                    "type": "WARNING",
                    "resource": self.name.upper(),
                    "usage": usage,
                    "severity": "MEDIUM",
                    "message": (
                        f"RESOURCE WARNING | {self.name.upper()} | "
                        f"Usage de-escalated from HIGH to MEDIUM: {usage:.1f}% | Severity: MEDIUM"
                    ),
                    "is_sustained": False,
                })
                self.current_state = "MEDIUM"
                self.sustained_alert_logged = False
                self.last_logged_usage = usage

            # Check for sustained condition
            if (
                self.consecutive_medium >= self.sustained_samples
                and not self.sustained_alert_logged
            ):
                alerts.append({
                    "type": "WARNING",
                    "resource": self.name.upper(),
                    "usage": usage,
                    "severity": "MEDIUM",
                    "message": (
                        f"RESOURCE WARNING | {self.name.upper()} | "
                        f"Sustained elevated usage detected ({self.consecutive_medium} consecutive samples >= "
                        f"{self.medium_threshold:.1f}%, current: {usage:.1f}%) | Severity: MEDIUM"
                    ),
                    "is_sustained": True,
                })
                self.sustained_alert_logged = True
                self.last_logged_usage = usage

            elif (
                self.sustained_alert_logged
                and abs(usage - self.last_logged_usage) >= 10.0
            ):
                alerts.append({
                    "type": "WARNING",
                    "resource": self.name.upper(),
                    "usage": usage,
                    "severity": "MEDIUM",
                    "message": (
                        f"RESOURCE WARNING | {self.name.upper()} | "
                        f"Usage shifted significantly while elevated: {usage:.1f}% "
                        f"(previously {self.last_logged_usage:.1f}%) | Severity: MEDIUM"
                    ),
                    "is_sustained": False,
                })
                self.last_logged_usage = usage

            return alerts

        return alerts


class ResourceMonitor:
    """
    Main Resource and System Monitoring class.

    Monitors system-level CPU, Memory, Swap, Disk, and I/O metrics.
    Identifies abnormal consumption and sustained usage patterns.
    Integrates with existing security logging and alert manager.
    """

    def __init__(self, config=None, config_path="config/config.json", logger=None):
        self.config = config if config is not None else load_config(config_path)
        self.logger = logger or logging.getLogger("endpoint_monitor")
        self.check_interval = self.config.get("check_interval", 5)

        # Pre-warm psutil CPU measurement baseline so the first call is valid
        try:
            psutil.cpu_percent(interval=None)
            psutil.cpu_percent(interval=None, percpu=True)
        except Exception:
            pass

        # Initialize state trackers for each metric
        cpu_cfg = self.config.get("cpu", {})
        mem_cfg = self.config.get("memory", {})
        swap_cfg = self.config.get("swap", {})
        disk_cfg = self.config.get("disk", {})

        self.cpu_tracker = ResourceStateTracker(
            name="CPU",
            medium_threshold=cpu_cfg.get("medium_threshold", 70.0),
            high_threshold=cpu_cfg.get("high_threshold", 90.0),
            sustained_samples=cpu_cfg.get("sustained_samples", 3),
        )

        self.memory_tracker = ResourceStateTracker(
            name="Memory",
            medium_threshold=mem_cfg.get("medium_threshold", 70.0),
            high_threshold=mem_cfg.get("high_threshold", 90.0),
            sustained_samples=mem_cfg.get("sustained_samples", 3),
        )

        self.swap_tracker = ResourceStateTracker(
            name="Swap",
            medium_threshold=swap_cfg.get("medium_threshold", 70.0),
            high_threshold=swap_cfg.get("high_threshold", 90.0),
            sustained_samples=swap_cfg.get("sustained_samples", 3),
        )

        self.disk_tracker = ResourceStateTracker(
            name="Disk",
            medium_threshold=disk_cfg.get("medium_threshold", 80.0),
            high_threshold=disk_cfg.get("high_threshold", 90.0),
            sustained_samples=disk_cfg.get("sustained_samples", 3),
        )

        self._last_cpu_time = 0.0
        self._stop_event = threading.Event()
        self._bg_thread = None

    def get_cpu_metrics(self, interval=None):
        """
        Collect CPU usage statistics:
        - Overall usage percentage
        - Per-core percentage
        - Logical and physical core counts

        Ensures the initial measurement is meaningful by using a short
        sampling window (0.1s) if elapsed time since last call is too small.
        """
        try:
            now = time.time()
            if interval is None:
                if self._last_cpu_time == 0.0 or (now - self._last_cpu_time) < 0.1:
                    sample_interval = 0.1
                else:
                    sample_interval = None
            else:
                sample_interval = interval

            percent = psutil.cpu_percent(interval=sample_interval)
            per_cpu = psutil.cpu_percent(interval=None, percpu=True)
            self._last_cpu_time = time.time()
            logical_count = psutil.cpu_count(logical=True)
            physical_count = psutil.cpu_count(logical=False)

            return {
                "percent": percent,
                "per_cpu": per_cpu,
                "logical_count": logical_count,
                "physical_count": physical_count,
            }
        except Exception as e:
            self.logger.error(f"Error collecting CPU metrics: {e}")
            return {
                "percent": 0.0,
                "per_cpu": [],
                "logical_count": None,
                "physical_count": None,
                "error": str(e),
            }

    def get_memory_metrics(self):
        """
        Collect virtual memory (RAM) statistics:
        - Total, Available, Used RAM
        - Usage percentage
        - Formatted human-readable strings
        """
        try:
            vm = psutil.virtual_memory()
            total_gb = vm.total / (1024 ** 3)
            used_gb = vm.used / (1024 ** 3)
            available_gb = vm.available / (1024 ** 3)

            return {
                "total": vm.total,
                "available": vm.available,
                "used": vm.used,
                "percent": vm.percent,
                "total_gb": total_gb,
                "used_gb": used_gb,
                "available_gb": available_gb,
                "formatted": f"{used_gb:.2f} GB / {total_gb:.2f} GB ({vm.percent:.1f}%)",
            }
        except Exception as e:
            self.logger.error(f"Error collecting memory metrics: {e}")
            return {
                "total": 0,
                "available": 0,
                "used": 0,
                "percent": 0.0,
                "total_gb": 0.0,
                "used_gb": 0.0,
                "available_gb": 0.0,
                "formatted": "N/A",
                "error": str(e),
            }

    def get_swap_metrics(self):
        """
        Collect swap memory statistics (optional, handled gracefully).
        """
        if not self.config.get("swap", {}).get("enabled", True):
            return None

        try:
            sm = psutil.swap_memory()
            total_gb = sm.total / (1024 ** 3)
            used_gb = sm.used / (1024 ** 3)
            free_gb = sm.free / (1024 ** 3)

            return {
                "total": sm.total,
                "used": sm.used,
                "free": sm.free,
                "percent": sm.percent,
                "total_gb": total_gb,
                "used_gb": used_gb,
                "free_gb": free_gb,
                "formatted": f"{used_gb:.2f} GB / {total_gb:.2f} GB ({sm.percent:.1f}%)",
            }
        except Exception as e:
            self.logger.debug(f"Swap metrics unavailable: {e}")
            return None

    def get_disk_metrics(self):
        """
        Collect disk usage statistics (optional, handled gracefully).
        """
        disk_cfg = self.config.get("disk", {})
        if not disk_cfg.get("enabled", True):
            return None

        mount_point = disk_cfg.get("mount_point", "default")
        if mount_point == "default" or not mount_point:
            mount_point = get_default_mount_point()

        try:
            du = psutil.disk_usage(mount_point)
            total_gb = du.total / (1024 ** 3)
            used_gb = du.used / (1024 ** 3)
            free_gb = du.free / (1024 ** 3)

            return {
                "mount_point": mount_point,
                "total": du.total,
                "used": du.used,
                "free": du.free,
                "percent": du.percent,
                "total_gb": total_gb,
                "used_gb": used_gb,
                "free_gb": free_gb,
                "formatted": f"{used_gb:.2f} GB / {total_gb:.2f} GB ({du.percent:.1f}%)",
            }
        except Exception as e:
            self.logger.debug(f"Disk metrics unavailable for {mount_point}: {e}")
            return None

    def get_io_metrics(self):
        """
        Collect disk and network I/O counters (optional).
        """
        io_data = {}
        try:
            disk_io = psutil.disk_io_counters()
            if disk_io:
                io_data["disk"] = {
                    "read_bytes": disk_io.read_bytes,
                    "write_bytes": disk_io.write_bytes,
                    "read_count": disk_io.read_count,
                    "write_count": disk_io.write_count,
                }
        except Exception:
            pass

        try:
            net_io = psutil.net_io_counters()
            if net_io:
                io_data["network"] = {
                    "bytes_sent": net_io.bytes_sent,
                    "bytes_recv": net_io.bytes_recv,
                    "packets_sent": net_io.packets_sent,
                    "packets_recv": net_io.packets_recv,
                }
        except Exception:
            pass

        return io_data if io_data else None

    def collect_metrics(self):
        """
        Collect all system metrics safely into a structured dictionary.
        """
        return {
            "timestamp": time.time(),
            "cpu": self.get_cpu_metrics(),
            "memory": self.get_memory_metrics(),
            "swap": self.get_swap_metrics(),
            "disk": self.get_disk_metrics(),
            "io": self.get_io_metrics(),
        }

    def evaluate_metrics(self, metrics):
        """
        Evaluate collected metrics against thresholds and state trackers.
        Returns a list of generated alert dictionaries and an overall risk level.
        """
        alerts = []

        # Evaluate CPU
        cpu_metrics = metrics.get("cpu", {})
        cpu_usage = cpu_metrics.get("percent", 0.0)
        alerts.extend(self.cpu_tracker.update(cpu_usage))

        # Evaluate Memory
        mem_metrics = metrics.get("memory", {})
        mem_usage = mem_metrics.get("percent", 0.0)
        alerts.extend(self.memory_tracker.update(mem_usage))

        # Evaluate Swap if enabled
        swap_metrics = metrics.get("swap")
        if swap_metrics and "percent" in swap_metrics:
            alerts.extend(self.swap_tracker.update(swap_metrics["percent"]))

        # Evaluate Disk if enabled
        disk_metrics = metrics.get("disk")
        if disk_metrics and "percent" in disk_metrics:
            alerts.extend(self.disk_tracker.update(disk_metrics["percent"]))

        # Determine overall resource severity level
        states = [
            self.cpu_tracker.current_state,
            self.memory_tracker.current_state,
        ]
        if self.swap_tracker.current_state != "NORMAL":
            states.append(self.swap_tracker.current_state)
        if self.disk_tracker.current_state != "NORMAL":
            states.append(self.disk_tracker.current_state)

        if "HIGH" in states:
            overall_severity = "HIGH"
        elif "MEDIUM" in states:
            overall_severity = "MEDIUM"
        else:
            overall_severity = "LOW"

        return {
            "alerts": alerts,
            "overall_severity": overall_severity,
        }

    def log_and_dispatch_alerts(self, alerts):
        """
        Write generated alerts to security logger and user alert interface.
        """
        for alert in alerts:
            msg = alert["message"]
            severity = alert["severity"]

            if severity == "HIGH":
                self.logger.warning(msg)
                show_alert(msg)
            elif severity == "MEDIUM":
                self.logger.warning(msg)
                show_alert(msg)
            else:
                self.logger.info(msg)
                show_alert(msg)

    def check_resources(self):
        """
        Perform a single resource snapshot collection and threshold check.
        Logs any generated alerts and returns the evaluation results.
        """
        metrics = self.collect_metrics()
        evaluation = self.evaluate_metrics(metrics)
        self.log_and_dispatch_alerts(evaluation["alerts"])

        return {
            "metrics": metrics,
            "alerts": evaluation["alerts"],
            "overall_severity": evaluation["overall_severity"],
        }

    def start_monitoring(self, stop_event=None):
        """
        Run continuous monitoring loop until stop_event is set or KeyboardInterrupt.
        """
        event = stop_event or self._stop_event
        self.logger.info("Resource Monitor loop started.")

        try:
            while not event.is_set():
                try:
                    self.check_resources()
                except Exception as e:
                    self.logger.error(f"Unexpected error in resource monitor cycle: {e}")

                # Wait for next interval or stop event
                if event.wait(timeout=self.check_interval):
                    break

        except KeyboardInterrupt:
            self.logger.info("Resource Monitor received interrupt signal.")
        finally:
            self.logger.info("Resource Monitor loop terminated cleanly.")

    def start_background(self):
        """
        Start continuous resource monitoring in a background daemon thread.
        Returns the thread object.
        """
        self._stop_event.clear()
        self._bg_thread = threading.Thread(
            target=self.start_monitoring,
            args=(self._stop_event,),
            name="ResourceMonitorThread",
            daemon=True,
        )
        self._bg_thread.start()
        return self._bg_thread

    def stop(self):
        """
        Signal the monitor to stop and wait for the background thread to finish.
        """
        self._stop_event.set()
        if self._bg_thread and self._bg_thread.is_alive():
            self._bg_thread.join(timeout=self.check_interval + 1)


def monitor_resources_once(logger=None, config_path="config/config.json"):
    """
    Convenience function to perform a single resource check.
    """
    monitor = ResourceMonitor(logger=logger, config_path=config_path)
    return monitor.check_resources()


if __name__ == "__main__":
    setup_logger()
    print("Starting Resource Monitor in standalone mode (Press Ctrl+C to stop)...")
    monitor = ResourceMonitor()
    try:
        monitor.start_monitoring()
    except KeyboardInterrupt:
        print("\nResource Monitor stopped.")

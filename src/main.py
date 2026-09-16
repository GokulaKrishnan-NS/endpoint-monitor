import os
import sys

# Ensure root project directory is in sys.path when script is executed directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import time

from src.utils.logger import setup_logger
from src.alerts.alert_manager import show_alert
from src.monitors.process_monitor import get_running_processes, get_new_processes
from src.monitors.resource_monitor import ResourceMonitor
from src.detectors.command_detector import detect_command_indicators
from src.detectors.risk_detector import calculate_risk
from src.models.event import Event
from src.baseline.baseline_engine import BaselineEngine


def process_event_from_dict(process_info):
    """
    Construct a standardized Event object from raw process dictionary,
    run command indicator analysis and risk scoring, and update event fields.
    """
    event = Event.from_process_info(process_info)

    # Analyze command line for indicators
    event.indicators = detect_command_indicators(event.command_line)

    # Calculate risk using indicators and process context
    risk_result = calculate_risk(event.indicators, process_info)

    event.risk_score = risk_result["score"]
    event.risk_level = risk_result["level"]
    event.risk_reasons = risk_result["reasons"]
    event.severity = risk_result["level"]

    return event


def report_suspicious_event(event, logger):
    """
    Print and log a standardized suspicious process event.
    """
    message = (
        f"Suspicious process detected | "
        f"PID: {event.pid} | "
        f"Process: {event.process_name} | "
        f"Parent: {event.parent_process_name} | "
        f"Risk: {event.risk_level} | "
        f"Score: {event.risk_score}"
    )

    print("\n" + "=" * 60)
    print(message)

    print("Indicators:")
    for indicator in event.indicators:
        print(f"  - {indicator}")

    print("Reasons:")
    for reason in event.risk_reasons:
        print(f"  - {reason}")

    print("=" * 60)

    logger.warning(message)

    for reason in event.risk_reasons:
        logger.warning(f"Reason: {reason}")


def report_behavioral_anomaly(event, anomaly_result, logger):
    """
    Print and log a behavioral baseline anomaly event.
    """
    message = (
        f"Behavioral Anomaly detected | "
        f"PID: {event.pid} | "
        f"Process: {event.process_name} | "
        f"Parent: {event.parent_process_name} | "
        f"Anomaly Level: {anomaly_result['anomaly_level']} | "
        f"Anomaly Score: {anomaly_result['anomaly_score']}"
    )

    print("\n" + "!" * 60)
    print(message)

    print("Behavioral Deviation Reasons:")
    for reason in anomaly_result["reasons"]:
        print(f"  - {reason}")

    print("!" * 60)

    logger.warning(message)
    for reason in anomaly_result["reasons"]:
        logger.warning(f"Baseline Anomaly Reason: {reason}")


def main():
    logger = setup_logger()

    print("Endpoint Security Monitor started.")
    logger.info("Endpoint Security Monitor started.")

    show_alert("System initialized successfully.")

    # Initialize Behavioral Baseline Engine
    baseline_engine = BaselineEngine()

    # Resource Monitoring initial snapshot check
    resource_monitor = ResourceMonitor(logger=logger)
    resource_result = resource_monitor.check_resources()

    cpu_metrics = resource_result["metrics"]["cpu"]
    mem_metrics = resource_result["metrics"]["memory"]
    print(
        f"System Resources: CPU: {cpu_metrics['percent']:.1f}% | "
        f"Memory: {mem_metrics['formatted']}"
    )
    logger.info(
        f"System resources initial check - CPU: {cpu_metrics['percent']:.1f}%, "
        f"Memory: {mem_metrics['formatted']}"
    )

    # Process Monitoring initial scan
    processes = get_running_processes()

    print(f"Monitoring {len(processes)} running processes.")
    logger.info(
        f"Process monitor detected {len(processes)} running processes."
    )

    for pid, process in processes.items():
        event = process_event_from_dict(process)

        # Behavioral baseline evaluation
        anomaly_result = baseline_engine.analyze_event(event)
        event.metadata["baseline_anomaly"] = anomaly_result

        # Collect clean events into baseline profiles
        baseline_engine.collect_event(event)

        # Report static rule indicators if present
        if event.indicators:
            report_suspicious_event(event, logger)

        # Report behavioral anomalies if detected
        if anomaly_result.get("is_anomaly"):
            report_behavioral_anomaly(event, anomaly_result, logger)

    baseline_engine.save_baseline()

    # Optional continuous monitoring mode
    if "--continuous" in sys.argv or "-c" in sys.argv:
        print(
            f"\nEntering continuous monitoring mode "
            f"(Interval: {resource_monitor.check_interval}s, Press Ctrl+C to stop)..."
        )
        logger.info("Entering continuous monitoring mode.")
        previous_processes = processes

        try:
            while True:
                time.sleep(resource_monitor.check_interval)

                # Periodic resource monitoring check
                resource_monitor.check_resources()

                # Periodic process monitoring check for newly launched processes
                current_processes = get_running_processes()
                new_processes = get_new_processes(previous_processes, current_processes)

                for process in new_processes:
                    event = process_event_from_dict(process)

                    anomaly_result = baseline_engine.analyze_event(event)
                    event.metadata["baseline_anomaly"] = anomaly_result

                    baseline_engine.collect_event(event)

                    if event.indicators:
                        report_suspicious_event(event, logger)

                    if anomaly_result.get("is_anomaly"):
                        report_behavioral_anomaly(event, anomaly_result, logger)

                previous_processes = current_processes
                baseline_engine.save_baseline()

        except KeyboardInterrupt:
            print("\nEndpoint Security Monitor stopped cleanly.")
            logger.info("Endpoint Security Monitor stopped cleanly by user.")


if __name__ == "__main__":
    main()

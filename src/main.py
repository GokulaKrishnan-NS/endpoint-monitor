import os
import sys

# Ensure root project directory is in sys.path when script is executed directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import time

from src.utils.logger import setup_logger
from src.alerts.alert_manager import show_alert
from src.monitors.process_monitor import get_running_processes, get_new_processes
from src.monitors.resource_monitor import ResourceMonitor
from src.monitors.network_monitor import NetworkMonitor
from src.detectors.command_detector import detect_command_indicators
from src.detectors.risk_detector import calculate_risk
from src.models.event import Event
from src.baseline.baseline_engine import BaselineEngine
from src.analysis.process_tree import ProcessTree, ProcessTreeAnalyzer


def process_event_from_dict(process_info, process_tree=None, tree_analyzer=None):
    """
    Construct a standardized Event object from raw process dictionary,
    resolve hierarchical process-tree lineage, run command indicator analysis,
    evaluate suspicious parent-child relationships, and score combined risk.
    """
    event = Event.from_process_info(process_info)

    # 1. Analyze command line for suspicious indicators
    event.indicators = detect_command_indicators(event.command_line)

    # 2. Process Tree Analysis
    if tree_analyzer is None:
        tree_analyzer = ProcessTreeAnalyzer()

    tree_analysis = tree_analyzer.analyze_process(process_info, process_tree)
    event.metadata["process_tree"] = tree_analysis

    # Incorporate process-tree indicators (e.g. suspicious_process_lineage)
    for ind in tree_analysis.get("indicators", []):
        if ind not in event.indicators:
            event.indicators.append(ind)

    # 3. Calculate overall risk using command indicators, process context, and tree findings
    risk_result = calculate_risk(
        event.indicators,
        process_info,
        tree_findings=tree_analysis.get("findings"),
    )

    event.risk_score = risk_result["score"]
    event.risk_level = risk_result["level"]
    event.risk_reasons = risk_result["reasons"]
    event.severity = risk_result["level"]

    return event


def report_suspicious_event(event, logger):
    """
    Print and log a standardized suspicious process event, including
    process-tree lineage and hierarchy visualization if present.
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

    # Display Process Tree Visualization if available
    tree_meta = event.metadata.get("process_tree", {})
    if tree_meta.get("tree_rendered"):
        print("Process Lineage Tree:")
        print(tree_meta["tree_rendered"])

    print("Indicators:")
    for indicator in event.indicators:
        print(f"  - {indicator}")

    print("Reasons:")
    for reason in event.risk_reasons:
        print(f"  - {reason}")

    print("=" * 60)

    logger.warning(message)

    if tree_meta.get("lineage"):
        lineage_str = " -> ".join(tree_meta["lineage"])
        logger.warning(f"Process Lineage: {lineage_str}")

    for reason in event.risk_reasons:
        logger.warning(f"Reason: {reason}")


def report_suspicious_network_event(event, logger):
    """
    Print and log a standardized suspicious network connection event.
    """
    net_info = event.network_info or {}
    remote_addr = net_info.get("remote_address") or "N/A"
    local_addr = net_info.get("local_address") or "N/A"
    protocol = net_info.get("protocol") or "TCP"

    message = (
        f"Suspicious network connection detected | "
        f"PID: {event.pid} | "
        f"Process: {event.process_name} | "
        f"Protocol: {protocol} | "
        f"Local: {local_addr} | "
        f"Remote: {remote_addr} | "
        f"Risk: {event.risk_level} | "
        f"Score: {event.risk_score}"
    )

    print("\n" + "@" * 60)
    print(message)

    print("Indicators:")
    for indicator in event.indicators:
        print(f"  - {indicator}")

    print("Reasons:")
    for reason in event.risk_reasons:
        print(f"  - {reason}")

    print("@" * 60)

    logger.warning(message)
    for reason in event.risk_reasons:
        logger.warning(f"Network Anomaly Reason: {reason}")


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

    # Initialize Behavioral Baseline Engine and Process Tree Analyzer
    baseline_engine = BaselineEngine()
    tree_analyzer = ProcessTreeAnalyzer()
    network_monitor = NetworkMonitor(logger=logger)

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

    # Build hierarchical Process Tree from initial snapshot
    process_tree = ProcessTree.build(processes)
    print(f"Process tree constructed: {len(process_tree.nodes)} nodes resolved.")
    logger.info(f"Process tree constructed: {len(process_tree.nodes)} nodes resolved.")

    for pid, process in processes.items():
        event = process_event_from_dict(
            process,
            process_tree=process_tree,
            tree_analyzer=tree_analyzer,
        )

        # Behavioral baseline evaluation
        anomaly_result = baseline_engine.analyze_event(event)
        event.metadata["baseline_anomaly"] = anomaly_result

        # Collect clean events into baseline profiles
        baseline_engine.collect_event(event)

        # Report static rule and process-tree indicators if present
        if event.indicators:
            report_suspicious_event(event, logger)

        # Report behavioral anomalies if detected
        if anomaly_result.get("is_anomaly"):
            report_behavioral_anomaly(event, anomaly_result, logger)

    baseline_engine.save_baseline()

    # Network Monitoring initial snapshot check
    net_result = network_monitor.check_connections(
        processes=processes,
        process_tree=process_tree,
        new_only=False,
    )
    print(
        f"Network Monitor: {net_result['total_connections']} active connections checked "
        f"({net_result['outbound_connections']} outbound)."
    )
    logger.info(
        f"Network monitor checked {net_result['total_connections']} connections "
        f"({net_result['outbound_connections']} outbound)."
    )

    for net_event in net_result["suspicious_events"]:
        report_suspicious_network_event(net_event, logger)

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

                # Rebuild / update process tree with current snapshot
                process_tree = ProcessTree.build(current_processes)

                for process in new_processes:
                    event = process_event_from_dict(
                        process,
                        process_tree=process_tree,
                        tree_analyzer=tree_analyzer,
                    )

                    anomaly_result = baseline_engine.analyze_event(event)
                    event.metadata["baseline_anomaly"] = anomaly_result

                    baseline_engine.collect_event(event)

                    if event.indicators:
                        report_suspicious_event(event, logger)

                    if anomaly_result.get("is_anomaly"):
                        report_behavioral_anomaly(event, anomaly_result, logger)

                # Periodic network monitoring check (new connections only to avoid alert spam)
                net_cycle = network_monitor.check_connections(
                    processes=current_processes,
                    process_tree=process_tree,
                    new_only=True,
                )
                for net_event in net_cycle["suspicious_events"]:
                    report_suspicious_network_event(net_event, logger)

                previous_processes = current_processes
                baseline_engine.save_baseline()

        except KeyboardInterrupt:
            print("\nEndpoint Security Monitor stopped cleanly.")
            logger.info("Endpoint Security Monitor stopped cleanly by user.")

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
                    command_line = process.get("cmdline")
                    indicators = detect_command_indicators(command_line)
                    risk_result = calculate_risk(indicators, process)

                    score = risk_result["score"]
                    level = risk_result["level"]
                    reasons = risk_result["reasons"]

                    if indicators:
                        message = (
                            f"Suspicious process detected | "
                            f"PID: {process.get('pid')} | "
                            f"Process: {process.get('name')} | "
                            f"Parent: {process.get('parent_name')} | "
                            f"Risk: {level} | "
                            f"Score: {score}"
                        )

                        print("\n" + "=" * 60)
                        print(message)

                        print("Indicators:")
                        for indicator in indicators:
                            print(f"  - {indicator}")

                        print("Reasons:")
                        for reason in reasons:
                            print(f"  - {reason}")

                        print("=" * 60)

                        logger.warning(message)

                        for reason in reasons:
                            logger.warning(f"Reason: {reason}")

                previous_processes = current_processes

        except KeyboardInterrupt:
            print("\nEndpoint Security Monitor stopped cleanly.")
            logger.info("Endpoint Security Monitor stopped cleanly by user.")


if __name__ == "__main__":
    main()

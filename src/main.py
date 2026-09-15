import sys
import time

from src.utils.logger import setup_logger
from src.alerts.alert_manager import show_alert
from src.monitors.process_monitor import get_running_processes, get_new_processes
from src.monitors.resource_monitor import ResourceMonitor
from src.detectors.command_detector import detect_command_indicators
from src.detectors.risk_detector import calculate_risk


def main():
    logger = setup_logger()

    print("Endpoint Security Monitor started.")
    logger.info("Endpoint Security Monitor started.")

    show_alert("System initialized successfully.")

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

        command_line = process.get("cmdline")

        # Analyze the command line for suspicious indicators
        indicators = detect_command_indicators(command_line)

        # Calculate risk using indicators and process context
        risk_result = calculate_risk(
            indicators,
            process
        )

        score = risk_result["score"]
        level = risk_result["level"]
        reasons = risk_result["reasons"]

        # Only report processes that contain suspicious indicators
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

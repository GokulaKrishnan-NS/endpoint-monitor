from src.utils.logger import setup_logger
from src.alerts.alert_manager import show_alert
from src.monitors.process_monitor import get_running_processes
from src.detectors.command_detector import detect_command_indicators
from src.detectors.risk_detector import calculate_risk


def main():
    logger = setup_logger()

    print("Endpoint Security Monitor started.")
    logger.info("Endpoint Security Monitor started.")

    show_alert("System initialized successfully.")

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


if __name__ == "__main__":
    main()
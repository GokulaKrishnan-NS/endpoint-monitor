from src.utils.logger import setup_logger
from src.alerts.alert_manager import show_alert
from src.monitors.process_monitor import get_running_processes
from src.detectors.command_detector import detect_suspicious_command
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

    for process in processes:
        command_line = process.get("cmdline")

        suspicious_command = detect_suspicious_command(command_line)

        if suspicious_command:
            risk_result = calculate_risk(
                suspicious_command,
                process
            )

            risk = risk_result["level"]
            score = risk_result["score"]

            message = (
                f"Suspicious command detected: "
                f"{suspicious_command} | "
                f"PID: {process.get('pid')} | "
                f"Process: {process.get('name')} | "
                f"Risk: {risk} | "
                f"Score: {score}"
            )

            print(message)
            logger.warning(message)


if __name__ == "__main__":
    main()
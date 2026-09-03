from src.utils.logger import setup_logger
from src.alerts.alert_manager import show_alert


def main():
    logger = setup_logger()

    print("Endpoint Security Monitor started.")
    logger.info("Endpoint Security Monitor started.")

    show_alert("System initialized successfully.")


if __name__ == "__main__":
    main()

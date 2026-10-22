"""
Windows Service Host for Endpoint Security Service (Phase 1 Foundation).

Provides service hosting capabilities and CLI management for running the
privileged EndpointSecurityService as a persistent background process or
native Windows Service.

Windows Service Installation Instructions (Run in elevated PowerShell / Command Prompt):
========================================================================================
1. Create Service:
   sc.exe create "EndpointSecurityService" binPath= "C:\\Path\\To\\python.exe D:\\projects\\endpoint-monitor\\src\\execution\\windows_service.py --service" start= auto DisplayName= "Endpoint Security Enforcement Service"

2. Start Service:
   sc.exe start "EndpointSecurityService"

3. Query Service Status:
   sc.exe query "EndpointSecurityService"

4. Stop Service:
   sc.exe stop "EndpointSecurityService"

5. Delete Service:
   sc.exe delete "EndpointSecurityService"
"""

import argparse
import logging
import os
import signal
import sys
import time

# Ensure project root is in sys.path
_project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from src.execution.service_foundation import EndpointSecurityService
from src.utils.logger import setup_logger


def run_service_standalone(ipc_port: int = 50244, config_path: str = "config/config.json") -> None:
    """Run the privileged service in standalone background mode."""
    logger = setup_logger()
    logger.info("Initializing EndpointSecurityService...")

    service = EndpointSecurityService(
        config_path=config_path,
        ipc_port=ipc_port,
        enable_ipc=True,
        logger_instance=logger,
    )

    def handle_signal(sig, frame):
        logger.info(f"Received shutdown signal ({sig}). Stopping service...")
        service.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    service.start()
    logger.info(f"EndpointSecurityService is active. IPC listening on 127.0.0.1:{service.ipc_port}")

    try:
        while service.is_running():
            time.sleep(1.0)
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received. Shutting down...")
    finally:
        service.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Endpoint Security Service Host")
    parser.add_argument("--standalone", action="store_true", help="Run service in standalone console mode")
    parser.add_argument("--port", type=int, default=50244, help="IPC loopback port (default: 50244)")
    parser.add_argument("--config", type=str, default="config/config.json", help="Path to config.json")
    args = parser.parse_args()

    run_service_standalone(ipc_port=args.port, config_path=args.config)


if __name__ == "__main__":
    main()

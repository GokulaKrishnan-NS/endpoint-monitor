import unittest
import os
import sys
import io
import logging
from unittest.mock import patch

from src.utils.logger import setup_logger
from src.alerts.alert_manager import show_alert


class TestUtilsAndAlerts(unittest.TestCase):

    def test_logger_setup(self):
        logger = setup_logger()
        self.assertEqual(logger.name, "endpoint_monitor")
        self.assertTrue(os.path.exists("logs"))
        self.assertTrue(os.path.exists("logs/security.log"))

        # Verify writing log message works
        test_msg = "Test baseline log verification entry"
        logger.info(test_msg)

        with open("logs/security.log", "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn(test_msg, content)

    def test_show_alert_output(self):
        captured_output = io.StringIO()
        sys.stdout = captured_output
        try:
            show_alert("Test alert system message")
            sys.stdout = sys.__stdout__
            output_str = captured_output.getvalue().strip()
            self.assertEqual(output_str, "[ALERT] Test alert system message")
        finally:
            sys.stdout = sys.__stdout__


if __name__ == "__main__":
    unittest.main()

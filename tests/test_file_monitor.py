import unittest
from unittest.mock import MagicMock, patch

# Note: src/monitors/file_monitor.py executes an un-guarded 'while True: time.sleep(1)'
# loop at module scope upon import. We patch 'time.sleep' to raise KeyboardInterrupt
# during import to safely break out of the infinite loop without modifying production code.
with patch("time.sleep", side_effect=KeyboardInterrupt):
    from src.monitors.file_monitor import FileMonitor


class TestFileMonitor(unittest.TestCase):

    def setUp(self):
        self.handler = FileMonitor()

    def test_file_created_event(self):
        event = MagicMock()
        event.is_directory = False
        event.src_path = "monitored_folder/test.txt"

        with patch("builtins.print") as mock_print, patch("logging.info") as mock_log:
            self.handler.on_created(event)
            mock_print.assert_called_once_with("FILE CREATED: monitored_folder/test.txt")
            mock_log.assert_called_once_with("FILE CREATED: monitored_folder/test.txt")

    def test_directory_created_event_ignored(self):
        event = MagicMock()
        event.is_directory = True

        with patch("builtins.print") as mock_print:
            self.handler.on_created(event)
            mock_print.assert_not_called()

    def test_file_modified_event(self):
        event = MagicMock()
        event.is_directory = False
        event.src_path = "monitored_folder/test.txt"

        with patch("builtins.print") as mock_print, patch("logging.info") as mock_log:
            self.handler.on_modified(event)
            mock_print.assert_called_once_with("FILE MODIFIED: monitored_folder/test.txt")

    def test_file_deleted_event(self):
        event = MagicMock()
        event.is_directory = False
        event.src_path = "monitored_folder/test.txt"

        with patch("builtins.print") as mock_print, patch("logging.warning") as mock_log:
            self.handler.on_deleted(event)
            mock_print.assert_called_once_with("FILE DELETED: monitored_folder/test.txt")
            mock_log.assert_called_once_with("FILE DELETED: monitored_folder/test.txt")

    def test_file_moved_event(self):
        event = MagicMock()
        event.is_directory = False
        event.src_path = "monitored_folder/test.txt"
        event.dest_path = "monitored_folder/moved.txt"

        with patch("builtins.print") as mock_print, patch("logging.info") as mock_log:
            self.handler.on_moved(event)
            mock_print.assert_called_once_with(
                "FILE MOVED: monitored_folder/test.txt -> monitored_folder/moved.txt"
            )


if __name__ == "__main__":
    unittest.main()

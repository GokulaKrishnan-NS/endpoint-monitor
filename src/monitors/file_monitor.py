import os
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from src.models.event import Event

MONITORED_FOLDER = "monitored_folder"
LOG_FOLDER = "logs"
LOG_FILE = os.path.join(LOG_FOLDER, "file_events.log")


os.makedirs(MONITORED_FOLDER, exist_ok=True)
os.makedirs(LOG_FOLDER, exist_ok=True)


logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


class FileMonitor(FileSystemEventHandler):

    def create_event(self, action, src_path, dest_path=None, severity="LOW"):
        """
        Helper to construct a standardized Event from file system changes.
        """
        return Event(
            event_type="file_action",
            source="file_monitor",
            severity=severity,
            file_path=src_path,
            file_action=action,
            dest_path=dest_path,
        )

    def on_created(self, event):
        if not event.is_directory:
            evt = self.create_event(action="created", src_path=event.src_path, severity="LOW")
            message = f"FILE CREATED: {evt.file_path}"
            print(message)
            logging.info(message)
            return evt

    def on_modified(self, event):
        if not event.is_directory:
            evt = self.create_event(action="modified", src_path=event.src_path, severity="LOW")
            message = f"FILE MODIFIED: {evt.file_path}"
            print(message)
            logging.info(message)
            return evt

    def on_deleted(self, event):
        if not event.is_directory:
            evt = self.create_event(action="deleted", src_path=event.src_path, severity="WARNING")
            message = f"FILE DELETED: {evt.file_path}"
            print(message)
            logging.warning(message)
            return evt

    def on_moved(self, event):
        if not event.is_directory:
            evt = self.create_event(
                action="moved",
                src_path=event.src_path,
                dest_path=event.dest_path,
                severity="LOW",
            )
            message = f"FILE MOVED: {evt.file_path} -> {evt.dest_path}"
            print(message)
            logging.info(message)
            return evt


if __name__ == "__main__":
    event_handler = FileMonitor()
    observer = Observer()
    observer.schedule(
        event_handler,
        MONITORED_FOLDER,
        recursive=True
    )
    observer.start()

    print("File Monitoring Started")
    print("Monitoring Folder:", MONITORED_FOLDER)
    print("Press Ctrl+C to stop")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()

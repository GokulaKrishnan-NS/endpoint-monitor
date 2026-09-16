import os
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


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

    def on_created(self, event):

        if not event.is_directory:

            message = f"FILE CREATED: {event.src_path}"

            print(message)
            logging.info(message)

    def on_modified(self, event):

        if not event.is_directory:

            message = f"FILE MODIFIED: {event.src_path}"

            print(message)
            logging.info(message)

    def on_deleted(self, event):

        if not event.is_directory:

            message = f"FILE DELETED: {event.src_path}"

            print(message)
            logging.warning(message)

    def on_moved(self, event):

        if not event.is_directory:

            message = (
                f"FILE MOVED: {event.src_path} "
                f"-> {event.dest_path}"
            )

            print(message)
            logging.info(message)


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

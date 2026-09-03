import psutil


def get_running_processes():
    processes = []

    for process in psutil.process_iter(
        ["pid", "name", "username", "cpu_percent", "memory_percent", "cmdline"]
    ):
        try:
            processes.append(process.info)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return processes
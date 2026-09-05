import psutil


def get_parent_process_name(ppid):
    """
    Return the name of the parent process.
    """

    try:
        return psutil.Process(ppid).name()

    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess,
    ):
        return None


def get_running_processes():
    """
    Collect information about all currently running processes.
    """

    processes = {}

    attributes = [
        "pid",
        "ppid",
        "name",
        "username",
        "status",
        "create_time",
        "cpu_percent",
        "memory_percent",
        "cmdline",
    ]

    for process in psutil.process_iter(attributes):
        try:
            process_info = process.info

            process_info["parent_name"] = get_parent_process_name(
                process_info["ppid"]
            )

            processes[process_info["pid"]] = process_info

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            continue

    return processes


def get_new_processes(previous_processes, current_processes):
    """
    Compare two process snapshots and return newly created processes.
    """

    previous_pids = set(previous_processes.keys())

    new_processes = []

    for pid, process_info in current_processes.items():

        if pid not in previous_pids:
            new_processes.append(process_info)

    return new_processes
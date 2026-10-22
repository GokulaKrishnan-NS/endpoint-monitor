import threading
from collections import OrderedDict
from typing import Optional, Tuple

import psutil


def get_parent_process_name(ppid):
    """
    Return the name of the parent process.

    Returns None when the parent cannot be resolved (invalid PPID, vanished
    parent, access denied, zombie process).  psutil.Process() is never called
    with an invalid PID.
    """

    if ppid is None or isinstance(ppid, bool) or not isinstance(ppid, int) or ppid <= 0:
        return None

    try:
        return psutil.Process(ppid).name()

    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess,
        OSError,
        ValueError,
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
            if not process_info or process_info.get("pid") is None:
                continue

            processes[process_info["pid"]] = process_info

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            continue

    # Resolve parent process names efficiently:
    # 1. Look up parent in the freshly collected snapshot dictionary (fast, in-memory).
    # 2. For remaining parents, query get_parent_process_name with per-scan caching.
    parent_cache = {}
    for process_info in processes.values():
        ppid = process_info.get("ppid")
        if ppid is None or isinstance(ppid, bool) or not isinstance(ppid, int) or ppid <= 0:
            process_info["parent_name"] = None
            continue

        if ppid in parent_cache:
            process_info["parent_name"] = parent_cache[ppid]
            continue

        if ppid in processes:
            parent_name = processes[ppid].get("name")
            parent_cache[ppid] = parent_name
            process_info["parent_name"] = parent_name
            continue

        parent_name = get_parent_process_name(ppid)
        parent_cache[ppid] = parent_name
        process_info["parent_name"] = parent_name

    return processes


def get_process_identity(process_info) -> Tuple[Optional[int], Optional[float]]:
    """
    Return the stable identity tuple (pid, create_time) for a process entry.

    The creation timestamp is what distinguishes two different processes that
    share the same PID after the OS recycles it.  A missing / unusable
    creation time is reported as None so callers can apply their own
    conservative policy.
    """

    if not isinstance(process_info, dict):
        return None, None

    pid = process_info.get("pid")
    if pid is not None:
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            pid = None

    create_time = process_info.get("create_time")
    if create_time is not None:
        try:
            create_time = float(create_time)
        except (TypeError, ValueError):
            create_time = None

    return pid, create_time


def is_same_process(previous_info, current_info) -> bool:
    """
    Decide whether two snapshot entries describe the same running process.

    The comparison is intentionally based on PID *and* creation time so that a
    recycled PID is reported as a brand new process.  When either side does
    not expose a creation timestamp the entries are treated as the same
    process (conservative: avoids emitting a duplicate event on every poll).
    """

    prev_pid, prev_create = get_process_identity(previous_info)
    curr_pid, curr_create = get_process_identity(current_info)

    if prev_pid is None or curr_pid is None or prev_pid != curr_pid:
        return False

    if prev_create is None or curr_create is None:
        return True

    return abs(prev_create - curr_create) <= 1e-6


def get_new_processes(previous_processes, current_processes):
    """
    Compare two process snapshots and return newly created processes.

    A process is considered new when its PID was not present before, or when
    the PID was recycled (creation timestamp changed).
    """

    if not isinstance(current_processes, dict):
        return []

    if not isinstance(previous_processes, dict):
        previous_processes = {}

    new_processes = []

    for pid, process_info in current_processes.items():
        if not isinstance(process_info, dict):
            continue

        if pid not in previous_processes:
            new_processes.append(process_info)
            continue

        prev_info = previous_processes[pid]
        if not isinstance(prev_info, dict):
            new_processes.append(process_info)
            continue

        if not is_same_process(prev_info, process_info):
            new_processes.append(process_info)

    return new_processes


class ProcessIdentityRegistry:
    """
    Tracks observed process identities (PID + creation time).

    Used to correlate the psutil polling monitor with the Windows
    process-creation telemetry source so that the very same process instance
    is never reported twice, while a recycled PID is still reported as new.
    """

    def __init__(self, tolerance: float = 5.0, capacity: int = 5000) -> None:
        self.tolerance = max(0.0, float(tolerance))
        self.capacity = max(1, int(capacity))
        self._entries: "OrderedDict[int, Tuple[Optional[float], str]]" = OrderedDict()
        self._lock = threading.Lock()

    def register(self, pid, create_time, source: str = "polling") -> None:
        """Record a process instance as already observed."""
        if pid is None:
            return
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return

        if create_time is not None:
            try:
                create_time = float(create_time)
            except (TypeError, ValueError):
                create_time = None

        with self._lock:
            self._entries[pid] = (create_time, source)
            self._entries.move_to_end(pid)
            while len(self._entries) > self.capacity:
                self._entries.popitem(last=False)

    def matches(self, pid, create_time) -> bool:
        """
        Return True when the given PID/creation-time pair was already observed.

        When either timestamp is unknown the entry is treated as a match to
        remain conservative and avoid duplicate security events.
        """
        if pid is None:
            return False
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return False

        with self._lock:
            entry = self._entries.get(pid)

        if entry is None:
            return False

        known_create, _source = entry

        if known_create is None or create_time is None:
            return True

        try:
            return abs(float(known_create) - float(create_time)) <= self.tolerance
        except (TypeError, ValueError):
            return True

    def is_new(self, pid, create_time) -> bool:
        """Inverse of :meth:`matches`."""
        return not self.matches(pid, create_time)

    def get_source(self, pid) -> Optional[str]:
        """Return the collection source that first reported this PID."""
        if pid is None:
            return None
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return None
        with self._lock:
            entry = self._entries.get(pid)
        return entry[1] if entry else None

    def clear(self) -> None:
        """Forget every recorded identity."""
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

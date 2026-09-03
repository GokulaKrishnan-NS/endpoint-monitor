SUSPICIOUS_COMMANDS = [
    "nmap",
    "nc",
    "netcat",
    "wget",
    "curl",
    "chmod",
    "chown",
    "bash",
    "sh",
    "python",
    "python3",
]


def detect_suspicious_command(cmdline):
    if not cmdline:
        return None

    command = " ".join(cmdline).lower()

    for suspicious in SUSPICIOUS_COMMANDS:
        if suspicious in command:
            return suspicious

    return None
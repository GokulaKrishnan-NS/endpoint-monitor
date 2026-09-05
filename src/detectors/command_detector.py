import re


def detect_command_indicators(cmdline):
    """
    Analyze a process command line and return security-relevant indicators.
    """

    indicators = []

    if not cmdline:
        return indicators

    command = " ".join(cmdline).lower()

    # Detect common encoded-command indicators
    encoded_patterns = [
        r"-enc\b",
        r"-encodedcommand\b",
        r"frombase64string",
        r"base64\s+-d",
    ]

    for pattern in encoded_patterns:
        if re.search(pattern, command):
            indicators.append("encoded_command")
            break

    # Detect shell command chaining.
    # This is only an indicator, not proof of malicious activity.
    chain_patterns = [
        "&&",
        "||",
    ]

    for pattern in chain_patterns:
        if pattern in command:
            indicators.append("command_chaining")
            break

    # Detect potential download-and-execute behavior
    download_tools = [
        "curl",
        "wget",
    ]

    execution_indicators = [
        "| sh",
        "| bash",
        "| cmd",
        "| powershell",
    ]

    has_download_tool = any(
        tool in command for tool in download_tools
    )

    has_execution = any(
        pattern in command for pattern in execution_indicators
    )

    if has_download_tool and has_execution:
        indicators.append("download_and_execute")

    # Detect hidden execution patterns commonly used on Windows
    hidden_patterns = [
        "-windowstyle hidden",
        "-w hidden",
        "windowstyle hidden",
    ]

    for pattern in hidden_patterns:
        if pattern in command:
            indicators.append("hidden_execution")
            break

    return indicators
INDICATOR_SCORES = {
    "encoded_command": 4,
    "command_chaining": 2,
    "download_and_execute": 5,
    "hidden_execution": 3,
    "suspicious_process_lineage": 4,
    "multi_level_shell_chain": 5,
    "shell_spawning_shell": 2,
    "suspicious_destination_port": 4,
    "unexpected_network_process": 4,
    "suspicious_outbound_connection": 4,
    "network_activity_suspicious_process": 4,
    "unusual_network_state": 2,
}


def calculate_risk(
    indicators,
    process_info=None,
    tree_findings=None,
    network_findings=None,
):
    """
    Calculate a risk score based on detected indicators,
    process context, process tree lineage findings, and network telemetry.
    """

    score = 0
    reasons = []

    # Score command, process-tree, and network indicators
    for indicator in indicators:
        if indicator in INDICATOR_SCORES:
            points = INDICATOR_SCORES[indicator]

            score += points

            reasons.append(
                f"{indicator.replace('_', ' ').title()} (+{points})"
            )

    # Add specific tree lineage explanatory reasons if provided
    if tree_findings:
        for finding in tree_findings:
            reason = finding.get("reason")
            if reason and reason not in reasons:
                reasons.append(reason)

    # Add specific network explanatory reasons if provided
    if network_findings:
        for finding in network_findings:
            reason = finding.get("reason")
            if reason and reason not in reasons:
                reasons.append(reason)

    # Add process context indicators
    if process_info:
        username = process_info.get("username")

        # Privileged execution is only an additional indicator,
        # not malicious by itself.
        if username:
            username_lower = username.lower()

            if username_lower == "root" or username_lower == "system":
                score += 1
                reasons.append("Privileged execution context (+1)")

        # Resource usage indicators
        cpu_percent = process_info.get("cpu_percent", 0) or 0
        memory_percent = process_info.get("memory_percent", 0) or 0

        if cpu_percent >= 80:
            score += 1
            reasons.append("High CPU usage (+1)")

        if memory_percent >= 70:
            score += 1
            reasons.append("High memory usage (+1)")

    # Determine severity level
    if score >= 7:
        level = "HIGH"

    elif score >= 3:
        level = "MEDIUM"

    else:
        level = "LOW"

    return {
        "score": score,
        "level": level,
        "reasons": reasons,
    }
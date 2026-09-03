HIGH_RISK_COMMANDS = [
    "nmap",
    "nc",
    "netcat"
]

MEDIUM_RISK_COMMANDS = [
    "curl",
    "wget",
    "chmod",
    "chown"
]


def calculate_risk(suspicious_command, process_info=None):
    if suspicious_command is None:
        return {
            "score": 0,
            "level": "LOW"
        }

    score = 2

    if suspicious_command in HIGH_RISK_COMMANDS:
        score += 3

    elif suspicious_command in MEDIUM_RISK_COMMANDS:
        score += 1

    if process_info:
        username = process_info.get("username")

        if username in ["root", "SYSTEM"]:
            score += 2

    if score >= 5:
        level = "HIGH"

    elif score >= 3:
        level = "MEDIUM"

    else:
        level = "LOW"

    return {
        "score": score,
        "level": level
    }
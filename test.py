from src.detectors.risk_detector import calculate_risk


test_cases = [
    ("nmap", {"username": "user"}),
    ("nmap", {"username": "root"}),
    ("curl", {"username": "user"}),
    ("curl", {"username": "root"}),
    ("bash", {"username": "user"}),
    (None, {"username": "user"})
]


for command, process_info in test_cases:
    result = calculate_risk(command, process_info)

    print(f"Command : {command}")
    print(f"User    : {process_info['username']}")
    print(f"Score   : {result['score']}")
    print(f"Risk    : {result['level']}")
    print("-" * 40)
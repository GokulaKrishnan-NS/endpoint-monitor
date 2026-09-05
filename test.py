from src.detectors.risk_detector import calculate_risk


test_cases = [

    # Completely normal
    (
        [],
        {
            "username": "GREENAPPLE\\ACER",
            "cpu_percent": 10,
            "memory_percent": 5,
        }
    ),

    # Command chaining
    (
        ["command_chaining"],
        {
            "username": "GREENAPPLE\\ACER",
            "cpu_percent": 10,
            "memory_percent": 5,
        }
    ),

    # Hidden execution
    (
        ["hidden_execution"],
        {
            "username": "GREENAPPLE\\ACER",
            "cpu_percent": 10,
            "memory_percent": 5,
        }
    ),

    # Encoded command + hidden execution
    (
        [
            "encoded_command",
            "hidden_execution",
        ],
        {
            "username": "GREENAPPLE\\ACER",
            "cpu_percent": 10,
            "memory_percent": 5,
        }
    ),

    # Download and execute
    (
        ["download_and_execute"],
        {
            "username": "GREENAPPLE\\ACER",
            "cpu_percent": 10,
            "memory_percent": 5,
        }
    ),
]


for indicators, process_info in test_cases:

    result = calculate_risk(
        indicators,
        process_info,
    )

    print("\nIndicators:")
    print(indicators)

    print(f"Score: {result['score']}")
    print(f"Risk Level: {result['level']}")

    print("Reasons:")

    if result["reasons"]:
        for reason in result["reasons"]:
            print(f"  - {reason}")
    else:
        print("  - No suspicious indicators")

    print("-" * 50)
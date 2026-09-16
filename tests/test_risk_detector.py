import unittest

from src.detectors.risk_detector import calculate_risk, INDICATOR_SCORES


class TestRiskDetector(unittest.TestCase):

    def test_no_indicators_normal_process(self):
        result = calculate_risk([], {"username": "user", "cpu_percent": 10, "memory_percent": 20})
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["level"], "LOW")
        self.assertEqual(result["reasons"], [])

    def test_single_indicators_score_and_reasons(self):
        for indicator, score in INDICATOR_SCORES.items():
            with self.subTest(indicator=indicator):
                result = calculate_risk([indicator])
                self.assertEqual(result["score"], score)
                expected_reason_snippet = indicator.replace("_", " ").title()
                self.assertTrue(any(expected_reason_snippet in r for r in result["reasons"]))

    def test_privileged_user_context(self):
        for root_user in ["root", "SYSTEM", "system", "ROOT"]:
            with self.subTest(root_user=root_user):
                result = calculate_risk([], {"username": root_user})
                self.assertEqual(result["score"], 1)
                self.assertIn("Privileged execution context (+1)", result["reasons"])

    def test_high_resource_usage_context(self):
        result = calculate_risk([], {"cpu_percent": 85, "memory_percent": 75})
        self.assertEqual(result["score"], 2)
        self.assertIn("High CPU usage (+1)", result["reasons"])
        self.assertIn("High memory usage (+1)", result["reasons"])

    def test_severity_level_thresholds(self):
        # LOW (< 3)
        res_low = calculate_risk(["command_chaining"])  # score = 2
        self.assertEqual(res_low["level"], "LOW")

        # MEDIUM (3 <= score < 7)
        res_med1 = calculate_risk(["hidden_execution"])  # score = 3
        self.assertEqual(res_med1["level"], "MEDIUM")

        res_med2 = calculate_risk(["download_and_execute"])  # score = 5
        self.assertEqual(res_med2["level"], "MEDIUM")

        # HIGH (score >= 7)
        res_high = calculate_risk(["encoded_command", "hidden_execution"])  # 4 + 3 = 7
        self.assertEqual(res_high["level"], "HIGH")


if __name__ == "__main__":
    unittest.main()

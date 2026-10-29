"""
Command Line Indicator Detection Module.

Token-aware analysis of process command lines.  The detector accepts either a
raw command line string or an argument sequence (as produced by ``psutil``)
and produces a list of security-relevant indicator names.

The module deliberately separates three different concepts:

* an *indicator*  - a suspicious pattern observed in a command line,
* a *finding*     - an indicator plus the surrounding process context,
* an *alert*      - a finding whose accumulated risk score crosses the
  configured alert threshold (handled by the risk detector / engine).

Matching is context aware: switches are only interpreted as switches when the
command context supports it, so ordinary command lines do not produce
false positives.
"""

import threading
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple


# ---------------------------------------------------------------------------
# Known shell / interpreter families
# ---------------------------------------------------------------------------

SHELL_FAMILY: Dict[str, str] = {
    "cmd": "cmd",
    "cmd.exe": "cmd",
    "bash": "posix",
    "bash.exe": "posix",
    "sh": "posix",
    "sh.exe": "posix",
    "zsh": "posix",
    "powershell": "powershell",
    "powershell.exe": "powershell",
    "pwsh": "powershell",
    "pwsh.exe": "powershell",
    "powershell_ise.exe": "powershell",
}

POWERSHELL_HOSTS: Set[str] = {
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
    "powershell_ise.exe",
}


# ---------------------------------------------------------------------------
# Encoded command switches
# ---------------------------------------------------------------------------

_ENCODED_SWITCH_EXACT: Set[str] = {"encodedcommand"}

# Any unambiguous prefix of "-EncodedCommand" is accepted by PowerShell
# ("-enc", "-enco", "-encodedcommand", ...).
_ENCODED_SWITCH_PREFIXES: Set[str] = {
    "encodedcommand"[:i] for i in range(3, len("encodedcommand") + 1)
}

# Short forms that are only meaningful inside a PowerShell host.
_ENCODED_SWITCH_SHORT: Set[str] = {"e", "ec"}


# ---------------------------------------------------------------------------
# Hidden window switches
# ---------------------------------------------------------------------------

_HIDDEN_SWITCH_FULL: Set[str] = {"windowstyle"} | {
    "windowstyle"[:i] for i in range(6, len("windowstyle") + 1)
}

_HIDDEN_SWITCH_ABBREV: Set[str] = {"w", "win"}

_HIDDEN_WINDOW_VALUES: Set[str] = {"hidden", "1", "minimized", "minimised"}


# ---------------------------------------------------------------------------
# Download / execution primitives
# ---------------------------------------------------------------------------

_DOWNLOAD_TOKEN_NAMES: Set[str] = {
    "curl",
    "curl.exe",
    "wget",
    "wget.exe",
    "certutil",
    "certutil.exe",
    "bitsadmin",
    "bitsadmin.exe",
    "iwr",
    "irm",
    "invoke-webrequest",
    "invoke-restmethod",
    "downloadfile",
    "webclient",
    "net.webclient",
}

# Distinctive cmdlet names that are matched as substrings because they are
# usually glued to a method call, e.g. "(New-Object Net.WebClient).DownloadString".
_DOWNLOAD_SUBSTRINGS: Tuple[str, ...] = (
    "downloadstring",
    "downloadfile",
    "invoke-webrequest",
    "invoke-restmethod",
)

_EXEC_TOKEN_NAMES: Set[str] = {
    "sh",
    "bash",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
    "mshta",
    "mshta.exe",
    "rundll32",
    "rundll32.exe",
    "regsvr32",
    "regsvr32.exe",
    "cscript",
    "cscript.exe",
    "wscript",
    "wscript.exe",
}

_EXEC_SUBSTRINGS: Tuple[str, ...] = ("invoke-expression",)

# Primitives that retrieve a script directly into memory and are therefore
# treated as download *and* execution primitives.
_IMPLICIT_EXEC_NAMES: Set[str] = {"downloadstring"}

_DYNAMIC_EXEC_NAMES: Set[str] = {"iex", "invoke-expression"}


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------


def split_command_line(raw_command: str) -> List[str]:
    """
    Split a raw command line string into tokens.

    The splitter honours single and double quotes so that a quoted argument
    containing spaces stays a single token.  Quote characters are preserved so
    that downstream matching can still tell quoted from unquoted content.
    """

    if not isinstance(raw_command, str) or not raw_command.strip():
        return []

    tokens: List[str] = []
    current: List[str] = []
    quote_char: Optional[str] = None
    quoted = False

    for char in raw_command:
        if quote_char is not None:
            if char == quote_char:
                quote_char = None
                current.append(char)
            else:
                current.append(char)
            continue

        if char in ('"', "'"):
            quote_char = char
            quoted = True
            current.append(char)
            continue

        if char.isspace():
            if current:
                tokens.append("".join(current))
                current = []
            quoted = False
            continue

        current.append(char)

    if current:
        tokens.append("".join(current))

    return tokens


def normalize_command_line(cmdline: Any) -> List[str]:
    """
    Normalize the supported command line representations into a token list.

    Supported inputs:
      * ``None`` / empty value          -> empty token list
      * ``str``                          -> quote aware tokenization
      * ``list`` / ``tuple`` of strings -> used as-is (already tokenized)
    """

    if cmdline is None:
        return []

    if isinstance(cmdline, str):
        return split_command_line(cmdline)

    if isinstance(cmdline, (list, tuple)):
        tokens: List[str] = []
        for item in cmdline:
            if item is None:
                continue
            if isinstance(item, str):
                if not item:
                    continue
                tokens.append(item)
            else:
                tokens.append(str(item))
        return tokens

    return []


def _base_executable(tokens: Sequence[str]) -> str:
    """Return the lowercase base name of the executable in a token list."""
    if not tokens:
        return ""
    first = str(tokens[0]).strip().strip('"').strip("'")
    if not first:
        return ""
    base = first.replace("/", "\\").rsplit("\\", 1)[-1]
    return base.lower()


def _expand_words(tokens: Sequence[str]) -> List[str]:
    """
    Expand tokens into whitespace separated words.

    A command line captured by the operating system may deliver a whole
    nested command as a single argument (for example
    ``cmd.exe /c "powershell -enc <base64>"``).  Splitting the tokens into
    words allows switch and operator matching to work on the nested command
    as well.
    """
    words: List[str] = []
    for token in tokens:
        text = str(token)
        if not text:
            continue
        parts = text.split()
        if parts:
            words.extend(parts)
        else:
            words.append(text)
    return words


def _parse_switch(token: str) -> Optional[Tuple[str, Optional[str], str]]:
    """
    Parse a switch token into (name, inline_value, prefix).

    ``None`` is returned when the token is not a switch.
    """
    if not token:
        return None

    text = token.strip()
    if len(text) < 2:
        return None

    prefix = text[0]
    if prefix not in "-/":
        return None

    body = text[1:]
    if not body:
        return None

    inline_value: Optional[str] = None
    if ":" in body:
        body, _, inline_value = body.partition(":")
        inline_value = inline_value.strip().lower() or None

    name = body.strip().lower()
    if not name:
        return None

    return name, inline_value, prefix


# ---------------------------------------------------------------------------
# Individual indicator checks
# ---------------------------------------------------------------------------


def _detect_encoded_command(words: Sequence[str], base_exe: str) -> bool:
    """Detect PowerShell encoded-command switches."""
    for token in words:
        switch = _parse_switch(token)
        if switch is None:
            continue

        name, _inline_value, prefix = switch

        if name in _ENCODED_SWITCH_EXACT or name in _ENCODED_SWITCH_PREFIXES:
            return True

        if name in _ENCODED_SWITCH_SHORT:
            # "/e" is the cmd.exe echo switch and must not be treated as an
            # encoded command.  "-e"/"-ec" are only meaningful in PowerShell.
            if prefix == "/":
                continue
            if base_exe in POWERSHELL_HOSTS:
                return True

    return False


def _detect_base64_payload(words: Sequence[str]) -> bool:
    """Detect base64 decoding constructs used to hide payloads."""
    for token in words:
        if "frombase64string" in str(token).lower():
            return True

    for index, token in enumerate(words[:-1]):
        if str(token).strip().strip('"').lower() != "base64":
            continue
        follower = str(words[index + 1]).strip().strip('"').lower()
        if follower in ("-d", "--decode", "-decode", "/d"):
            return True

    return False


def _detect_hidden_window(words: Sequence[str], base_exe: str) -> bool:
    """Detect hidden / minimized window options."""
    for index, token in enumerate(words):
        switch = _parse_switch(token)
        if switch is None:
            continue

        name, inline_value, _prefix = switch

        is_full = name in _HIDDEN_SWITCH_FULL
        is_abbrev = name in _HIDDEN_SWITCH_ABBREV

        if not (is_full or is_abbrev):
            continue

        # Abbreviated "-w" / "-win" only mean "-WindowStyle" inside a
        # PowerShell host; elsewhere they are unrelated switches.
        if is_abbrev and not is_full and base_exe not in POWERSHELL_HOSTS:
            continue

        value = inline_value
        if value is None and index + 1 < len(words):
            value = str(words[index + 1]).strip().strip('"').strip("'").lower()

        if value and value in _HIDDEN_WINDOW_VALUES:
            return True

    return False


def _extract_operators(words: Sequence[str]) -> Set[str]:
    """
    Extract shell operators that are meaningful outside of quoted strings.

    The detector works on word granularity, therefore operators are only
    recognised in positions where a shell would actually split the command.
    """
    operators: Set[str] = set()

    for part in words:
        if "&&" in part:
            operators.add("and_and")
        if "||" in part:
            operators.add("or_or")
        if "|" in part and "||" not in part:
            operators.add("pipe")
        if part == "&":
            operators.add("ampersand")
        if part == ";" or part.endswith(";") or part.startswith(";"):
            operators.add("semicolon")

    return operators


def _detect_chaining(words: Sequence[str], base_exe: str) -> bool:
    """
    Detect shell command chaining.

    Chaining operators are only interpreted for known shell interpreters, so
    a stray ";" or "&" inside an ordinary program argument is not reported.
    """
    family = SHELL_FAMILY.get(base_exe)
    if family is None:
        return False

    operators = _extract_operators(words)

    if "and_and" in operators or "or_or" in operators:
        return True

    if family in ("powershell", "posix") and "semicolon" in operators:
        return True

    if family in ("cmd", "posix") and "ampersand" in operators:
        return True

    return False


def _detect_primitives(words: Sequence[str]) -> Tuple[Set[str], Set[str]]:
    """Return the download and execution primitives found in a word list."""
    downloads: Set[str] = set()
    executions: Set[str] = set()

    for token in words:
        text = str(token).strip().strip('"').strip("'")
        if not text:
            continue

        lowered = text.lower()
        base = lowered.replace("/", "\\").rsplit("\\", 1)[-1]

        if lowered in _DOWNLOAD_TOKEN_NAMES or base in _DOWNLOAD_TOKEN_NAMES:
            downloads.add(lowered)

        for needle in _DOWNLOAD_SUBSTRINGS:
            if needle in lowered:
                downloads.add(needle)

        if lowered in _EXEC_TOKEN_NAMES or base in _EXEC_TOKEN_NAMES:
            executions.add(lowered)

        for needle in _EXEC_SUBSTRINGS:
            if needle in lowered:
                executions.add(needle)

        if lowered in _IMPLICIT_EXEC_NAMES or base in _IMPLICIT_EXEC_NAMES:
            executions.add(lowered)

    return downloads, executions


def _detect_dynamic_execution(words: Sequence[str]) -> bool:
    """Detect dynamic code execution primitives (Invoke-Expression / iex)."""
    for token in words:
        text = str(token).strip().strip('"').strip("'").lower()
        if not text:
            continue
        base = text.replace("/", "\\").rsplit("\\", 1)[-1]
        if text in _DYNAMIC_EXEC_NAMES or base in _DYNAMIC_EXEC_NAMES:
            return True
        for needle in _EXEC_SUBSTRINGS:
            if needle in text:
                return True
    return False


def _detect_parent_shell_pipeline(words: Sequence[str], context: Dict[str, Any]) -> bool:
    """
    Detect a download-and-execute pipeline whose operators were consumed by a
    parent shell.

    ``cmd.exe /c "curl http://host/x | sh"`` creates two processes: the
    downloader and the interpreter.  The pipe operator never appears in the
    child command line, so the parent's command line is required to observe
    the full behaviour.
    """
    parent_command = context.get("parent_cmdline")
    parent_name = str(context.get("parent_name") or "").strip().lower()

    if not parent_command or parent_name not in SHELL_FAMILY:
        return False

    parent_words = _expand_words(normalize_command_line(parent_command))
    if not parent_words:
        return False

    segments: List[List[str]] = [[]]
    for word in parent_words:
        if "|" in word and "||" not in word:
            segments.append([])
            continue
        segments[-1].append(word)

    if len(segments) < 2:
        return False

    download_side, execution_side = segments[0], segments[-1]

    downloads, _executions = _detect_primitives(download_side)
    if not downloads:
        return False

    child_base = _base_executable(words)
    if not child_base:
        return False

    for candidate in execution_side:
        if _base_executable([candidate]) == child_base:
            return True

    return False


# ---------------------------------------------------------------------------
# Instrumentation and Invocation Tracking
# ---------------------------------------------------------------------------

_DETECTOR_LOCK = threading.Lock()
_DETECTOR_INVOCATIONS: int = 0


def get_command_detector_invocations() -> int:
    """Return total number of completed detect_command_indicators invocations."""
    with _DETECTOR_LOCK:
        return _DETECTOR_INVOCATIONS


def reset_command_detector_invocations() -> None:
    """Reset the invocation counter (for testing)."""
    global _DETECTOR_INVOCATIONS
    with _DETECTOR_LOCK:
        _DETECTOR_INVOCATIONS = 0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_command_indicators(cmdline: Any, context: Optional[Dict[str, Any]] = None) -> List[str]:
    """
    Analyze a process command line and return security-relevant indicators.

    ``cmdline`` may be a raw command line string or an argument sequence.
    ``context`` is optional and may provide additional correlation context
    such as ``parent_name`` and ``parent_cmdline`` which is required to
    observe shell pipelines whose operators are consumed by a parent shell.
    """

    tokens = normalize_command_line(cmdline)
    if not tokens:
        with _DETECTOR_LOCK:
            global _DETECTOR_INVOCATIONS
            _DETECTOR_INVOCATIONS += 1
        return []

    base_exe = _base_executable(tokens)
    words = _expand_words(tokens)
    context_map: Dict[str, Any] = context if isinstance(context, dict) else {}

    indicators: List[str] = []

    if _detect_encoded_command(words, base_exe) or _detect_base64_payload(words):
        indicators.append("encoded_command")

    if _detect_hidden_window(words, base_exe):
        indicators.append("hidden_execution")

    if _detect_chaining(words, base_exe):
        indicators.append("command_chaining")

    downloads, executions = _detect_primitives(words)

    if downloads and executions:
        indicators.append("download_and_execute")
    elif _detect_parent_shell_pipeline(words, context_map):
        # The pipe operator was interpreted by the parent shell and is absent
        # from the child command line.
        indicators.append("download_and_execute")

    if _detect_dynamic_execution(words):
        indicators.append("dynamic_code_execution")

    with _DETECTOR_LOCK:
        _DETECTOR_INVOCATIONS += 1

    return indicators

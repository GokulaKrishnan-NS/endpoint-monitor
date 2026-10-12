"""
Controlled Process Launcher Module (Phase 2).

Provides ControlledLauncher and LaunchResult for safe, bounded, and gated
process creation following strict pre-launch policy validation.
"""

from dataclasses import asdict, dataclass, field
import logging
import os
import shutil
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional, Set

from src.execution.config import load_execution_config
from src.execution.policy import ExecutionPolicy
from src.models.execution_request import (
    DecisionStatus,
    ExecutionDecision,
    ExecutionRequest,
)


@dataclass
class LaunchResult:
    """
    Structured outcome of a controlled process launch attempt.
    """
    request_id: str
    decision: ExecutionDecision
    executed: bool = False
    pid: Optional[int] = None
    returncode: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    timed_out: bool = False
    error: Optional[str] = None
    execution_time_seconds: float = 0.0
    timestamp: float = field(default_factory=time.time)

    @property
    def truncated(self) -> bool:
        """Convenience property indicating whether either output stream was truncated."""
        return self.stdout_truncated or self.stderr_truncated

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to a serializable dictionary."""
        d = asdict(self)
        d["truncated"] = self.truncated
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LaunchResult":
        """Reconstruct a LaunchResult from a dictionary."""
        decision_raw = data.get("decision", {})
        if isinstance(decision_raw, dict):
            decision = ExecutionDecision.from_dict(decision_raw)
        else:
            decision = decision_raw

        return cls(
            request_id=data.get("request_id", ""),
            decision=decision,
            executed=data.get("executed", False),
            pid=data.get("pid"),
            returncode=data.get("returncode"),
            stdout=data.get("stdout", ""),
            stderr=data.get("stderr", ""),
            stdout_truncated=data.get("stdout_truncated", False),
            stderr_truncated=data.get("stderr_truncated", False),
            timed_out=data.get("timed_out", False),
            error=data.get("error"),
            execution_time_seconds=data.get("execution_time_seconds", 0.0),
            timestamp=data.get("timestamp", time.time()),
        )


def _resolve_canonical_executable(exe_name_or_path: str) -> Optional[str]:
    """
    Resolve a command or path to its absolute canonical target file.
    Returns normalized canonical path if found and is a file, else None.
    """
    if not isinstance(exe_name_or_path, str) or not exe_name_or_path.strip():
        return None

    stripped = exe_name_or_path.strip()

    # If already a path with directory component or existing file
    if os.path.dirname(stripped) or os.path.exists(stripped):
        if os.path.isfile(stripped):
            return os.path.realpath(stripped)
        return None

    # Search PATH via shutil.which
    found = shutil.which(stripped)
    if found and os.path.isfile(found):
        return os.path.realpath(found)

    return None


def _is_same_canonical_file(path_a: str, path_b: str) -> bool:
    """
    Determine if two paths point to the exact same canonical file on disk.
    Uses os.path.samefile where supported, falling back to case-normalized realpaths.
    """
    try:
        return os.path.samefile(path_a, path_b)
    except (AttributeError, OSError):
        pass

    real_a = os.path.realpath(path_a)
    real_b = os.path.realpath(path_b)
    if os.name == "nt":
        return os.path.normcase(real_a) == os.path.normcase(real_b)
    return real_a == real_b


def _is_cwd_permitted(target_cwd: str, allowed_dirs: List[str]) -> bool:
    """
    Verify working directory against allowed directories using canonical path
    and path-component containment. When allowlist is empty, permits only the
    current working directory.
    """
    canonical_target = os.path.realpath(target_cwd)
    if not os.path.isdir(canonical_target):
        return False

    norm_target = os.path.normcase(canonical_target) if os.name == "nt" else canonical_target

    if not allowed_dirs:
        canonical_cwd = os.path.realpath(os.getcwd())
        norm_cwd = os.path.normcase(canonical_cwd) if os.name == "nt" else canonical_cwd
        return norm_target == norm_cwd

    for allowed in allowed_dirs:
        canonical_allowed = os.path.realpath(allowed)
        if not os.path.isdir(canonical_allowed):
            continue

        try:
            common = os.path.commonpath([canonical_allowed, canonical_target])
            norm_common = os.path.normcase(common) if os.name == "nt" else common
            norm_allowed = os.path.normcase(canonical_allowed) if os.name == "nt" else canonical_allowed
            if norm_common == norm_allowed:
                return True
        except ValueError:
            # Different drives on Windows
            continue

    return False


def _stream_reader(
    pipe,
    byte_limit: int,
    output_container: List[bytes],
    truncated_flag: List[bool],
) -> None:
    """
    Thread target that reads from an open pipe in chunks.
    Accumulates bytes up to byte_limit. Once byte_limit is reached, marks
    truncated_flag[0] = True and continues draining the pipe until EOF to
    prevent child processes from stalling on saturated OS pipe buffers.
    """
    collected = bytearray()
    chunk_size = 4096

    try:
        while True:
            chunk = pipe.read(chunk_size)
            if not chunk:
                break

            current_len = len(collected)
            if current_len < byte_limit:
                available = byte_limit - current_len
                if len(chunk) <= available:
                    collected.extend(chunk)
                else:
                    collected.extend(chunk[:available])
                    truncated_flag[0] = True
            else:
                truncated_flag[0] = True
    except Exception:
        pass
    finally:
        try:
            pipe.close()
        except Exception:
            pass

    output_container.append(bytes(collected))


class ControlledLauncher:
    """
    Secure process execution launcher that gates process creation through:
    1. Executable and argument vector canonical consistency validation.
    2. Working directory component-aware boundary enforcement.
    3. String-to-string environment overrides validation.
    4. ExecutionPolicy evaluation before spawn.
    5. Dual trusted configuration gates (dry_run == False and allow_active_execution == True).
    6. subprocess.Popen with shell=False, stdin=DEVNULL, bounded I/O capture,
       and robust direct-child timeout reaping.
    """

    def __init__(
        self,
        policy: Optional[ExecutionPolicy] = None,
        config: Optional[Dict[str, Any]] = None,
        config_path: str = "config/config.json",
        track_pids: bool = False,
    ):
        self.config: Dict[str, Any] = (
            config if config is not None else load_execution_config(config_path)
        )
        self.policy: ExecutionPolicy = (
            policy if policy is not None else ExecutionPolicy(config=self.config, config_path=config_path)
        )
        self.logger = logging.getLogger("endpoint_monitor")
        self.track_pids: bool = track_pids
        self.active_pids: Set[int] = set()

        # Dual trusted gates
        dry_run_val = self.config.get("dry_run", True)
        self.dry_run: bool = dry_run_val if isinstance(dry_run_val, bool) else True

        launcher_cfg = self.config.get("launcher", {})
        if not isinstance(launcher_cfg, dict):
            launcher_cfg = {}

        allow_active_val = launcher_cfg.get("allow_active_execution", False)
        self.allow_active_execution: bool = (
            allow_active_val if isinstance(allow_active_val, bool) else False
        )

        timeout_val = launcher_cfg.get("default_timeout_seconds", 30)
        if isinstance(timeout_val, (int, float)) and not isinstance(timeout_val, bool) and timeout_val > 0:
            self.default_timeout_seconds: float = float(timeout_val)
        else:
            self.default_timeout_seconds = 30.0

        max_out_val = launcher_cfg.get("max_output_bytes", 65536)
        if isinstance(max_out_val, int) and not isinstance(max_out_val, bool) and max_out_val > 0:
            self.max_output_bytes: int = max_out_val
        else:
            self.max_output_bytes = 65536

        allowed_dirs_val = launcher_cfg.get("allowed_working_directories", [])
        if isinstance(allowed_dirs_val, list):
            self.allowed_working_directories: List[str] = [
                str(d) for d in allowed_dirs_val if isinstance(d, str)
            ]
        else:
            self.allowed_working_directories = []

    def launch(
        self,
        request: ExecutionRequest,
        timeout: Optional[float] = None,
        capture_output: bool = True,
        env: Optional[Dict[str, str]] = None,
    ) -> LaunchResult:
        """
        Evaluate and conditionally execute a process request.

        Process creation is permitted ONLY when:
        1. Request is valid and executable and argument vector consistently resolve
           to the same canonical file.
        2. Working directory is permitted by containment allowlist.
        3. Environment overrides are valid string-to-string mappings.
        4. Policy evaluation yields ALLOW.
        5. dry_run is False and allow_active_execution is True in trusted config.

        Note on environment variables:
        Inherited environment variables from the host process are passed through
        and are NOT sanitized or filtered. Caller environment overrides provide
        supplemental or replaced keys only.

        Note on descendant processes:
        Timeout cleanup guarantees termination and reaping of the direct child
        PID only. Detached or orphaned descendant processes spawned by the child
        are not guaranteed to be terminated.
        """
        start_time = time.time()

        # Step 1: Validate input request object
        if not isinstance(request, ExecutionRequest):
            err_msg = f"Invalid request type: expected ExecutionRequest, got {type(request).__name__}"
            self.logger.warning(err_msg)
            dummy_dec = ExecutionDecision(
                request_id="",
                decision=DecisionStatus.BLOCK,
                risk_score=999,
                risk_level="UNKNOWN",
                reasons=[err_msg],
                dry_run=self.dry_run,
                executed=False,
                error=err_msg,
            )
            return LaunchResult(
                request_id="",
                decision=dummy_dec,
                executed=False,
                error=err_msg,
                execution_time_seconds=time.time() - start_time,
            )

        is_valid, validation_err = request.validate()
        if not is_valid:
            err_msg = f"Request validation failed: {validation_err}"
            self.logger.warning(f"Request {request.request_id} failed validation: {validation_err}")
            dummy_dec = ExecutionDecision(
                request_id=request.request_id,
                decision=DecisionStatus.BLOCK,
                risk_score=999,
                risk_level="UNKNOWN",
                reasons=[err_msg],
                dry_run=self.dry_run,
                executed=False,
                error=err_msg,
            )
            return LaunchResult(
                request_id=request.request_id,
                decision=dummy_dec,
                executed=False,
                error=err_msg,
                execution_time_seconds=time.time() - start_time,
            )

        # Step 2: Canonical executable consistency resolution
        resolved_exe = _resolve_canonical_executable(request.executable)
        if not resolved_exe:
            err_msg = f"Executable '{request.executable}' could not be resolved to a valid file on disk"
            self.logger.warning(err_msg)
            dec = ExecutionDecision(
                request_id=request.request_id,
                decision=DecisionStatus.BLOCK,
                risk_score=999,
                risk_level="UNKNOWN",
                reasons=[err_msg],
                dry_run=self.dry_run,
                executed=False,
                error=err_msg,
            )
            return LaunchResult(
                request_id=request.request_id,
                decision=dec,
                executed=False,
                error=err_msg,
                execution_time_seconds=time.time() - start_time,
            )

        cmd0 = request.command_line[0]
        resolved_cmd0 = _resolve_canonical_executable(cmd0)
        if not resolved_cmd0:
            err_msg = f"Command line argument vector [0] '{cmd0}' could not be resolved to a valid file"
            self.logger.warning(err_msg)
            dec = ExecutionDecision(
                request_id=request.request_id,
                decision=DecisionStatus.BLOCK,
                risk_score=999,
                risk_level="UNKNOWN",
                reasons=[err_msg],
                dry_run=self.dry_run,
                executed=False,
                error=err_msg,
            )
            return LaunchResult(
                request_id=request.request_id,
                decision=dec,
                executed=False,
                error=err_msg,
                execution_time_seconds=time.time() - start_time,
            )

        if not _is_same_canonical_file(resolved_exe, resolved_cmd0):
            err_msg = (
                f"Executable mismatch: request.executable resolved to '{resolved_exe}' "
                f"but command_line[0] resolved to '{resolved_cmd0}'"
            )
            self.logger.warning(err_msg)
            dec = ExecutionDecision(
                request_id=request.request_id,
                decision=DecisionStatus.BLOCK,
                risk_score=999,
                risk_level="UNKNOWN",
                reasons=[err_msg],
                dry_run=self.dry_run,
                executed=False,
                error=err_msg,
            )
            return LaunchResult(
                request_id=request.request_id,
                decision=dec,
                executed=False,
                error=err_msg,
                execution_time_seconds=time.time() - start_time,
            )

        # Step 3: Working directory boundary validation
        target_cwd = request.working_directory or os.getcwd()
        if not _is_cwd_permitted(target_cwd, self.allowed_working_directories):
            err_msg = (
                f"Working directory '{target_cwd}' is not permitted by allowed working "
                f"directories policy ({self.allowed_working_directories or 'CWD only'})"
            )
            self.logger.warning(err_msg)
            dec = ExecutionDecision(
                request_id=request.request_id,
                decision=DecisionStatus.BLOCK,
                risk_score=999,
                risk_level="UNKNOWN",
                reasons=[err_msg],
                dry_run=self.dry_run,
                executed=False,
                error=err_msg,
            )
            return LaunchResult(
                request_id=request.request_id,
                decision=dec,
                executed=False,
                error=err_msg,
                execution_time_seconds=time.time() - start_time,
            )
        canonical_cwd = os.path.realpath(target_cwd)

        # Step 4: Environment overrides validation
        merged_env = os.environ.copy()
        if env is not None:
            if not isinstance(env, dict):
                err_msg = f"Environment overrides must be a dictionary, got {type(env).__name__}"
                self.logger.warning(err_msg)
                dec = ExecutionDecision(
                    request_id=request.request_id,
                    decision=DecisionStatus.BLOCK,
                    risk_score=999,
                    risk_level="UNKNOWN",
                    reasons=[err_msg],
                    dry_run=self.dry_run,
                    executed=False,
                    error=err_msg,
                )
                return LaunchResult(
                    request_id=request.request_id,
                    decision=dec,
                    executed=False,
                    error=err_msg,
                    execution_time_seconds=time.time() - start_time,
                )

            for k, v in env.items():
                if not isinstance(k, str) or not isinstance(v, str):
                    err_msg = (
                        f"Environment override entry '{k}'={v!r} must have string key "
                        f"and string value"
                    )
                    self.logger.warning(err_msg)
                    dec = ExecutionDecision(
                        request_id=request.request_id,
                        decision=DecisionStatus.BLOCK,
                        risk_score=999,
                        risk_level="UNKNOWN",
                        reasons=[err_msg],
                        dry_run=self.dry_run,
                        executed=False,
                        error=err_msg,
                    )
                    return LaunchResult(
                        request_id=request.request_id,
                        decision=dec,
                        executed=False,
                        error=err_msg,
                        execution_time_seconds=time.time() - start_time,
                    )
                merged_env[k] = v

        # Step 5: Exact argument vector and policy evaluation
        # The vector evaluated by policy MUST be the exact vector passed to Popen
        exact_args = [resolved_exe] + list(request.command_line[1:])
        eval_request = ExecutionRequest(
            executable=resolved_exe,
            command_line=exact_args,
            request_id=request.request_id,
            timestamp=request.timestamp,
            parent_pid=request.parent_pid,
            parent_process_name=request.parent_process_name,
            username=request.username,
            working_directory=canonical_cwd,
            metadata=dict(request.metadata),
        )

        decision = self.policy.evaluate(eval_request)
        decision.dry_run = self.dry_run
        decision.executed = False

        if decision.decision != DecisionStatus.ALLOW:
            self.logger.warning(
                f"[CONTROLLED LAUNCHER] Execution request {request.request_id} for "
                f"'{resolved_exe}' was BLOCKED by policy. Reasons: {decision.reasons}"
            )
            return LaunchResult(
                request_id=request.request_id,
                decision=decision,
                executed=False,
                error="Execution blocked by policy",
                execution_time_seconds=time.time() - start_time,
            )

        # Step 6: Trusted dual execution gates check
        # Never allow request fields to override these trusted gates
        if self.dry_run:
            msg = "Active process execution suppressed: dry_run is True in trusted configuration"
            self.logger.info(f"[CONTROLLED LAUNCHER] {msg} for request {request.request_id}")
            decision.executed = False
            return LaunchResult(
                request_id=request.request_id,
                decision=decision,
                executed=False,
                error=msg,
                execution_time_seconds=time.time() - start_time,
            )

        if not self.allow_active_execution:
            msg = (
                "Active process execution prohibited: allow_active_execution is False "
                "in trusted configuration"
            )
            self.logger.warning(f"[CONTROLLED LAUNCHER] {msg} for request {request.request_id}")
            decision.executed = False
            return LaunchResult(
                request_id=request.request_id,
                decision=decision,
                executed=False,
                error=msg,
                execution_time_seconds=time.time() - start_time,
            )

        # Step 7: Process Spawning via subprocess.Popen
        # executed=True is defined ONLY when subprocess.Popen successfully creates child
        actual_timeout = timeout if (timeout is not None and timeout > 0) else self.default_timeout_seconds

        try:
            proc = subprocess.Popen(
                args=exact_args,
                executable=resolved_exe,
                cwd=canonical_cwd,
                env=merged_env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE if capture_output else subprocess.DEVNULL,
                stderr=subprocess.PIPE if capture_output else subprocess.DEVNULL,
                shell=False,
            )
        except Exception as exc:
            err_msg = f"Failed to spawn process '{resolved_exe}': {exc}"
            self.logger.error(err_msg, exc_info=True)
            decision.executed = False
            return LaunchResult(
                request_id=request.request_id,
                decision=decision,
                executed=False,
                error=err_msg,
                execution_time_seconds=time.time() - start_time,
            )

        # Process creation succeeded
        child_pid = proc.pid
        if self.track_pids:
            self.active_pids.add(child_pid)

        decision.executed = True

        stdout_buf: List[bytes] = []
        stderr_buf: List[bytes] = []
        stdout_trunc = [False]
        stderr_trunc = [False]
        threads: List[threading.Thread] = []

        if capture_output and proc.stdout:
            t_out = threading.Thread(
                target=_stream_reader,
                args=(proc.stdout, self.max_output_bytes, stdout_buf, stdout_trunc),
                daemon=True,
            )
            threads.append(t_out)
            t_out.start()

        if capture_output and proc.stderr:
            t_err = threading.Thread(
                target=_stream_reader,
                args=(proc.stderr, self.max_output_bytes, stderr_buf, stderr_trunc),
                daemon=True,
            )
            threads.append(t_err)
            t_err.start()

        timed_out = False
        returncode: Optional[int] = None
        error: Optional[str] = None

        # Wait for completion or timeout
        try:
            returncode = proc.wait(timeout=actual_timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            error = f"Process timed out after {actual_timeout} seconds"
            self.logger.warning(
                f"[CONTROLLED LAUNCHER] Process {child_pid} timed out after {actual_timeout}s. "
                f"Terminating direct child."
            )

            # Direct-child termination with short grace period
            try:
                proc.terminate()
            except ProcessLookupError:
                pass
            except Exception as e:
                self.logger.debug(f"Error terminating process {child_pid}: {e}")

            # Grace period
            try:
                returncode = proc.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                except Exception as e:
                    self.logger.debug(f"Error killing process {child_pid}: {e}")

                try:
                    returncode = proc.wait(timeout=1.0)
                except Exception:
                    returncode = proc.poll()
        except Exception as exc:
            error = f"Error during process wait: {exc}"
            returncode = proc.poll()
        finally:
            if self.track_pids and child_pid in self.active_pids:
                self.active_pids.discard(child_pid)

            # Join stream readers to collect output
            for t in threads:
                t.join(timeout=1.0)

        # Decode output buffers safely
        stdout_str = (
            stdout_buf[0].decode("utf-8", errors="replace") if stdout_buf else ""
        )
        stderr_str = (
            stderr_buf[0].decode("utf-8", errors="replace") if stderr_buf else ""
        )

        return LaunchResult(
            request_id=request.request_id,
            decision=decision,
            executed=True,
            pid=child_pid,
            returncode=returncode,
            stdout=stdout_str,
            stderr=stderr_str,
            stdout_truncated=stdout_trunc[0],
            stderr_truncated=stderr_trunc[0],
            timed_out=timed_out,
            error=error,
            execution_time_seconds=time.time() - start_time,
        )

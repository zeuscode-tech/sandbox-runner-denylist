"""Development-time subprocess guardrail with a denylist and path jail.

This module intentionally is *not* an operating-system security boundary.  It
does not provide namespaces, seccomp, containers, a VM, filesystem mounts, or
network isolation.  It rejects common unsafe command shapes before spawning a
child and bounds time/output for commands that are allowed.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Optional, Sequence, Tuple, Union


DENIED_EXIT_CODE = -100
TIMED_OUT_EXIT_CODE = -101

DEFAULT_DENYLIST = frozenset(
    {
        "base64",
        "chmod",
        "chown",
        "curl",
        "dd",
        "doas",
        "eval",
        "exec",
        "halt",
        "iptables",
        "kill",
        "mkfs",
        "mkfs.ext4",
        "mkfs.fat",
        "mount",
        "nc",
        "ncat",
        "pkill",
        "poweroff",
        "reboot",
        "rm",
        "shutdown",
        "su",
        "sudo",
        "telnet",
        "ufw",
        "umount",
        "wget",
    }
)

DEFAULT_INTERPRETER_BLOCK = frozenset(
    {
        "awk",
        "bash",
        "deno",
        "fish",
        "lua",
        "node",
        "perl",
        "php",
        "python",
        "python3",
        "ruby",
        "sh",
        "tclsh",
        "zsh",
    }
)

DEFAULT_MAX_OUTPUT_BYTES = 64 * 1024
DEFAULT_TIMEOUT_SECONDS = 30.0
TRUNCATION_MARKER = b"\n[sandbox: output truncated]\n"

_SHELL_METACHARS = (";", "|", "&", ">", "<", "`", "$(", "${", "\n", "\r")
_PATH_HINT = re.compile(r"[/\\]|^\.{1,2}$")
_INTERPRETER_SHORT_FLAG = re.compile(r"^-[ce](?:$|[^-].*)")
_INTERPRETER_LONG_FLAGS = frozenset({"--eval", "--exec", "--command"})


@dataclass
class SandboxResult:
    """Structured outcome suitable for logging and downstream evaluation."""

    argv: list
    exit_code: int
    stdout: bytes = b""
    stderr: bytes = b""
    truncated: bool = False
    timed_out: bool = False
    denied: bool = False
    reason: str = ""
    duration_ms: float = 0.0

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.denied and not self.timed_out

    def to_dict(self) -> dict:
        """Return a JSON-serializable observation without duplicating output."""

        return {
            "argv": list(self.argv),
            "exit_code": self.exit_code,
            "stdout_bytes": len(self.stdout),
            "stderr_bytes": len(self.stderr),
            "truncated": self.truncated,
            "timed_out": self.timed_out,
            "denied": self.denied,
            "reason": self.reason,
            "duration_ms": round(self.duration_ms, 2),
        }


@dataclass
class SandboxConfig:
    """Configuration for :class:`Sandbox`.

    ``allow_shell`` defaults to false because a denylist cannot safely parse
    arbitrary shell programs.  Enabling it is an explicit trust decision, not
    a stronger sandbox mode.
    """

    project_root: Union[str, os.PathLike]
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    denylist: frozenset = field(default_factory=lambda: DEFAULT_DENYLIST)
    interpreter_block: frozenset = field(
        default_factory=lambda: DEFAULT_INTERPRETER_BLOCK
    )
    env_allowlist: Tuple[str, ...] = (
        "PATH",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TERM",
        "SYSTEMROOT",
        "WINDIR",
        "PATHEXT",
    )
    allow_shell: bool = False

    def __post_init__(self) -> None:
        root = os.path.realpath(os.fspath(self.project_root))
        if not os.path.isdir(root):
            raise ValueError("project_root must be an existing directory")
        if isinstance(self.max_output_bytes, bool) or self.max_output_bytes < 0:
            raise ValueError("max_output_bytes must be a non-negative integer")
        if isinstance(self.timeout_seconds, bool) or self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")

        self.project_root = root
        self.denylist = frozenset(str(item).casefold() for item in self.denylist)
        self.interpreter_block = frozenset(
            str(item).casefold() for item in self.interpreter_block
        )


def _basename(executable: str) -> str:
    name = os.path.basename(executable.strip()).casefold()
    return name[:-4] if name.endswith(".exe") else name


def _denial(argv: Sequence[str], reason: str) -> SandboxResult:
    return SandboxResult(
        argv=list(argv),
        exit_code=DENIED_EXIT_CODE,
        denied=True,
        reason=reason,
    )


def _check_executable_denylist(
    argv: Sequence[str], config: SandboxConfig
) -> Optional[str]:
    if not argv:
        return "empty argv"
    executable = _basename(argv[0])
    if not executable:
        return "executable has no basename"
    if executable in config.denylist:
        return "executable {!r} is on the denylist".format(executable)
    return None


def _is_interpreter(name: str, blocked: frozenset) -> bool:
    if name in blocked:
        return True
    # Cover common versioned Python executables (python3.12, python312).
    return "python" in blocked and bool(re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", name))


def _check_argv_interpreter(
    argv: Sequence[str], config: SandboxConfig
) -> Optional[str]:
    if not argv:
        return None
    name = _basename(argv[0])
    if not _is_interpreter(name, config.interpreter_block):
        return None
    for arg in argv[1:]:
        if _INTERPRETER_SHORT_FLAG.match(arg) or arg in _INTERPRETER_LONG_FLAGS:
            return (
                "interpreter {!r} invoked with refused inline-code flag {!r}; "
                "use a script file inside project_root"
            ).format(name, arg)
    return None


def _check_shell_metachars(argv: Sequence[str], shell: bool) -> Optional[str]:
    if shell:
        return None
    for arg in argv:
        for metachar in _SHELL_METACHARS:
            if metachar in arg:
                return "argv contains shell metacharacter {!r} in {!r}".format(
                    metachar, arg
                )
    return None


def _option_value(arg: str) -> str:
    """Inspect the value part of ``--option=path`` without ignoring flags."""

    if arg.startswith("-") and "=" in arg:
        return arg.split("=", 1)[1]
    return arg


def _looks_like_path(arg: str, base_dir: str) -> bool:
    candidate = _option_value(arg)
    if not candidate:
        return False
    if _PATH_HINT.search(candidate):
        return True
    return os.path.lexists(os.path.join(base_dir, candidate))


def _is_within(root: str, candidate: str) -> bool:
    try:
        return os.path.commonpath((root, candidate)) == root
    except ValueError:
        # Different drives on Windows cannot share a common path.
        return False


def _resolve_cwd(cwd: Optional[Union[str, os.PathLike]], root: str) -> str:
    if cwd is None:
        return root
    value = os.fspath(cwd)
    if not os.path.isabs(value):
        value = os.path.join(root, value)
    return os.path.realpath(value)


def _check_path_jail(
    argv: Sequence[str],
    config: SandboxConfig,
    base_dir: Optional[str] = None,
) -> Optional[str]:
    root = str(config.project_root)
    base = base_dir or root
    for raw_arg in argv[1:]:
        if not _looks_like_path(raw_arg, base):
            continue
        arg = _option_value(raw_arg)
        candidate = arg if os.path.isabs(arg) else os.path.join(base, arg)
        resolved = os.path.realpath(candidate)
        if not _is_within(root, resolved):
            return (
                "path argument {!r} resolves outside project_root "
                "({!r} is not under {!r})"
            ).format(raw_arg, resolved, root)
    return None


def truncate_stream(data: bytes, max_bytes: int) -> Tuple[bytes, bool]:
    """Truncate bytes deterministically and append an explicit marker."""

    if len(data) <= max_bytes:
        return data, False
    return data[:max_bytes] + TRUNCATION_MARKER, True


def _scrubbed_environment(
    allowlist: Sequence[str], parent: Mapping[str, str]
) -> dict:
    return {key: parent[key] for key in allowlist if key in parent}


def _kill_process_group(process: subprocess.Popen) -> None:
    """Best-effort termination of the child and descendants."""

    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:  # pragma: no cover - exercised on Windows
            process.kill()
    except (OSError, ProcessLookupError):
        try:
            process.kill()
        except OSError:
            pass


@dataclass
class Sandbox:
    """Run preflight-checked subprocesses inside a path-based project jail."""

    config: SandboxConfig

    def run(
        self,
        argv: Union[str, Sequence[str]],
        *,
        shell: bool = False,
        cwd: Optional[Union[str, os.PathLike]] = None,
        stdin: Optional[bytes] = None,
    ) -> SandboxResult:
        normalized, input_reason = self._normalize_argv(argv, shell)
        if input_reason:
            return _denial(normalized, input_reason)

        if shell and not self.config.allow_shell:
            return _denial(
                normalized,
                "shell=True is disabled; set allow_shell=True only for trusted input",
            )

        real_cwd = _resolve_cwd(cwd, str(self.config.project_root))
        if not _is_within(str(self.config.project_root), real_cwd):
            return _denial(normalized, "cwd {!r} is outside project_root".format(cwd))
        if not os.path.isdir(real_cwd):
            return _denial(normalized, "cwd {!r} is not an existing directory".format(cwd))

        checks = (
            _check_executable_denylist(normalized, self.config),
            _check_argv_interpreter(normalized, self.config),
            _check_shell_metachars(normalized, shell),
            _check_path_jail(normalized, self.config, real_cwd),
        )
        for reason in checks:
            if reason:
                return _denial(normalized, reason)

        command = normalized[0] if shell else normalized
        return self._execute(command, normalized, shell, real_cwd, stdin)

    @staticmethod
    def _normalize_argv(
        argv: Union[str, Sequence[str]], shell: bool
    ) -> Tuple[list, Optional[str]]:
        if isinstance(argv, str):
            normalized = [argv]
            if not shell:
                return normalized, "argv must be a sequence of strings when shell=False"
            if not argv.strip():
                return normalized, "empty command string"
            return normalized, None

        try:
            normalized = list(argv)
        except TypeError:
            return [], "argv must be a string or a sequence of strings"
        if not normalized:
            return [], "empty argv"
        if any(not isinstance(arg, str) for arg in normalized):
            return normalized, "every argv item must be a string"
        if any("\x00" in arg for arg in normalized):
            return normalized, "argv must not contain NUL bytes"
        if shell:
            return normalized, "shell=True requires one trusted command string"
        return normalized, None

    def _execute(
        self,
        command: Union[str, Sequence[str]],
        argv: Sequence[str],
        shell: bool,
        cwd: str,
        stdin: Optional[bytes],
    ) -> SandboxResult:
        env = _scrubbed_environment(self.config.env_allowlist, os.environ)
        process_options = {}
        if os.name == "posix":
            process_options["start_new_session"] = True
        elif os.name == "nt":  # pragma: no cover - exercised on Windows
            process_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

        started = time.perf_counter()
        try:
            process = subprocess.Popen(
                command,
                shell=shell,
                cwd=cwd,
                env=env,
                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                **process_options,
            )
            try:
                stdout_raw, stderr_raw = process.communicate(
                    input=stdin, timeout=self.config.timeout_seconds
                )
            except subprocess.TimeoutExpired:
                _kill_process_group(process)
                stdout_raw, stderr_raw = process.communicate()
                return self._make_result(
                    argv,
                    TIMED_OUT_EXIT_CODE,
                    stdout_raw,
                    stderr_raw,
                    started,
                    timed_out=True,
                    reason="wall-clock timeout after {}s".format(
                        self.config.timeout_seconds
                    ),
                )
        except FileNotFoundError as exc:
            return _denial(argv, "executable not found: {}".format(exc))
        except (PermissionError, OSError) as exc:
            elapsed = (time.perf_counter() - started) * 1000.0
            return SandboxResult(
                argv=list(argv),
                exit_code=126,
                stderr=str(exc).encode("utf-8", errors="replace"),
                reason="process could not be started",
                duration_ms=elapsed,
            )

        return self._make_result(
            argv,
            process.returncode,
            stdout_raw,
            stderr_raw,
            started,
        )

    def _make_result(
        self,
        argv: Sequence[str],
        exit_code: int,
        stdout_raw: bytes,
        stderr_raw: bytes,
        started: float,
        *,
        timed_out: bool = False,
        reason: str = "",
    ) -> SandboxResult:
        stdout, stdout_truncated = truncate_stream(
            stdout_raw or b"", self.config.max_output_bytes
        )
        stderr, stderr_truncated = truncate_stream(
            stderr_raw or b"", self.config.max_output_bytes
        )
        return SandboxResult(
            argv=list(argv),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            truncated=stdout_truncated or stderr_truncated,
            timed_out=timed_out,
            reason=reason,
            duration_ms=(time.perf_counter() - started) * 1000.0,
        )


def _write_demo_script(path: Path, source: str) -> None:
    path.write_text(source, encoding="utf-8")


def run_demo() -> int:
    """Run only harmless examples and verify every expected outcome."""

    with tempfile.TemporaryDirectory(prefix="sandbox-runner-demo-") as parent:
        parent_path = Path(parent)
        root = parent_path / "project"
        root.mkdir()
        (root / "hello.txt").write_text("hello from the project jail\n", encoding="utf-8")
        (parent_path / "outside.txt").write_text("harmless outside fixture\n", encoding="utf-8")
        _write_demo_script(root / "read_file.py", "from pathlib import Path\nprint(Path('hello.txt').read_text().strip())\n")
        _write_demo_script(root / "slow.py", "import time\ntime.sleep(0.20)\n")
        _write_demo_script(root / "loud.py", "print('x' * 256)\n")

        sandbox = Sandbox(
            SandboxConfig(
                project_root=root,
                denylist=DEFAULT_DENYLIST | {"blocked-demo"},
                timeout_seconds=1.0,
                max_output_bytes=48,
            )
        )
        timeout_sandbox = Sandbox(
            SandboxConfig(
                project_root=root,
                timeout_seconds=0.05,
                max_output_bytes=48,
            )
        )

        outcomes = {
            "allowed_script": sandbox.run([sys.executable, "read_file.py"]),
            "denied_name": sandbox.run(["blocked-demo", "hello.txt"]),
            "denied_inline_code": sandbox.run(
                [sys.executable, "-c", "print('this is never executed')"]
            ),
            "denied_metachar": sandbox.run(["echo", "alpha;beta"]),
            "denied_path_escape": sandbox.run([sys.executable, "../outside.txt"]),
            "timed_out": timeout_sandbox.run([sys.executable, "slow.py"]),
            "truncated": sandbox.run([sys.executable, "loud.py"]),
        }

        expected = {
            "allowed_script": outcomes["allowed_script"].ok,
            "denied_name": outcomes["denied_name"].denied,
            "denied_inline_code": outcomes["denied_inline_code"].denied,
            "denied_metachar": outcomes["denied_metachar"].denied,
            "denied_path_escape": outcomes["denied_path_escape"].denied,
            "timed_out": outcomes["timed_out"].timed_out,
            "truncated": outcomes["truncated"].truncated,
        }
        report = {
            "warning": "development guardrail only; no OS-level isolation",
            "all_expectations_met": all(expected.values()),
            "expectations": expected,
            "outcomes": {name: value.to_dict() for name, value in outcomes.items()},
        }
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report["all_expectations_met"] else 1


if __name__ == "__main__":
    sys.exit(run_demo())

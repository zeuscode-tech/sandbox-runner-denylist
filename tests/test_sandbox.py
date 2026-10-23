from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from main import (
    DENIED_EXIT_CODE,
    TIMED_OUT_EXIT_CODE,
    TRUNCATION_MARKER,
    Sandbox,
    SandboxConfig,
    _check_executable_denylist,
    _check_argv_interpreter,
    _check_path_jail,
    _check_shell_metachars,
    truncate_stream,
)


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    (root / "data.txt").write_text("inside\n", encoding="utf-8")
    (root / "sub").mkdir()
    return root


@pytest.fixture
def config(project: Path) -> SandboxConfig:
    return SandboxConfig(project_root=project, timeout_seconds=0.5)


def write_script(root: Path, name: str, source: str) -> None:
    (root / name).write_text(source, encoding="utf-8")


def test_config_resolves_root_and_validates_values(project: Path) -> None:
    cfg = SandboxConfig(project_root=project / "sub" / "..")
    assert cfg.project_root == os.path.realpath(project)

    with pytest.raises(ValueError, match="existing directory"):
        SandboxConfig(project_root=project / "missing")
    with pytest.raises(ValueError, match="non-negative"):
        SandboxConfig(project_root=project, max_output_bytes=-1)
    with pytest.raises(ValueError, match="greater than zero"):
        SandboxConfig(project_root=project, timeout_seconds=0)


@pytest.mark.parametrize("executable", ["rm", "/bin/rm", "/usr/bin/sudo", "RM.exe"])
def test_denylist_matches_executable_basename(
    executable: str, config: SandboxConfig
) -> None:
    reason = _check_executable_denylist([executable], config)
    assert reason is not None
    assert "denylist" in reason


def test_custom_denylist_is_normalized(project: Path) -> None:
    cfg = SandboxConfig(project_root=project, denylist=frozenset({"BLOCKED-DEMO"}))
    assert _check_executable_denylist(["blocked-demo"], cfg)


@pytest.mark.parametrize(
    "argv",
    [
        ["python3", "-c", "print('safe but refused')"],
        ["python3.12", "-cprint('safe but refused')"],
        ["node", "--eval", "1 + 1"],
        ["bash", "-ce", "echo harmless"],
        ["perl", "-e", "print 1"],
    ],
)
def test_interpreter_inline_code_is_denied(argv: list, config: SandboxConfig) -> None:
    assert _check_argv_interpreter(argv, config) is not None


def test_interpreter_script_file_is_allowed(config: SandboxConfig) -> None:
    assert _check_argv_interpreter(["python3", "script.py"], config) is None


@pytest.mark.parametrize("value", ["a;b", "a|b", "a&b", "$(date)", "a>b", "a\nb"])
def test_shell_metacharacters_are_refused_when_shell_is_off(value: str) -> None:
    assert _check_shell_metachars(["echo", value], shell=False) is not None
    assert _check_shell_metachars(["echo", value], shell=True) is None


def test_path_jail_allows_inside_and_rejects_escape(
    project: Path, config: SandboxConfig, tmp_path: Path
) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")

    assert _check_path_jail(["tool", "data.txt"], config) is None
    assert _check_path_jail(["tool", "sub/new.txt"], config) is None
    assert _check_path_jail(["tool", "../outside.txt"], config) is not None
    assert _check_path_jail(["tool", str(outside)], config) is not None
    assert _check_path_jail(["tool", "--output=" + str(outside)], config) is not None


def test_path_jail_rejects_symlink_escape(
    project: Path, config: SandboxConfig, tmp_path: Path
) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    link = project / "link.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")

    reason = _check_path_jail(["tool", "link.txt"], config)
    assert reason is not None
    assert "outside project_root" in reason


def test_relative_cwd_is_resolved_inside_project(project: Path) -> None:
    write_script(project / "sub", "show.py", "print('subdir')\n")
    sandbox = Sandbox(SandboxConfig(project_root=project))

    result = sandbox.run([sys.executable, "show.py"], cwd="sub")

    assert result.ok
    assert result.stdout == b"subdir\n"


def test_cwd_outside_project_is_denied(project: Path, tmp_path: Path) -> None:
    sandbox = Sandbox(SandboxConfig(project_root=project))

    result = sandbox.run([sys.executable, "missing.py"], cwd=tmp_path)

    assert result.denied
    assert result.exit_code == DENIED_EXIT_CODE
    assert "outside project_root" in result.reason


def test_allowed_command_captures_output_and_exit_code(project: Path) -> None:
    write_script(
        project,
        "result.py",
        "import sys\nprint('stdout')\nprint('stderr', file=sys.stderr)\nsys.exit(3)\n",
    )
    sandbox = Sandbox(SandboxConfig(project_root=project))

    result = sandbox.run([sys.executable, "result.py"])

    assert result.exit_code == 3
    assert result.stdout == b"stdout\n"
    assert result.stderr == b"stderr\n"
    assert not result.denied
    assert not result.timed_out
    assert not result.ok
    assert result.duration_ms >= 0


def test_environment_is_scrubbed(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_script(
        project,
        "env.py",
        "import os\nprint(os.environ.get('SANDBOX_TEST_SECRET', 'missing'))\n",
    )
    monkeypatch.setenv("SANDBOX_TEST_SECRET", "must-not-leak")
    sandbox = Sandbox(SandboxConfig(project_root=project))

    result = sandbox.run([sys.executable, "env.py"])

    assert result.ok
    assert result.stdout == b"missing\n"


def test_stdin_is_supported(project: Path) -> None:
    write_script(project, "stdin.py", "import sys\nprint(sys.stdin.buffer.read().decode())\n")
    sandbox = Sandbox(SandboxConfig(project_root=project))

    result = sandbox.run([sys.executable, "stdin.py"], stdin=b"hello")

    assert result.ok
    assert result.stdout == b"hello\n"


def test_timeout_returns_sentinel_and_partial_output(project: Path) -> None:
    write_script(
        project,
        "slow.py",
        "import time\nprint('started', flush=True)\ntime.sleep(2)\n",
    )
    sandbox = Sandbox(SandboxConfig(project_root=project, timeout_seconds=0.05))

    result = sandbox.run([sys.executable, "slow.py"])

    assert result.exit_code == TIMED_OUT_EXIT_CODE
    assert result.timed_out
    assert not result.denied
    assert b"started" in result.stdout
    assert "wall-clock timeout" in result.reason


def test_output_is_truncated_per_stream_with_marker(project: Path) -> None:
    write_script(
        project,
        "loud.py",
        "import sys\nprint('o' * 100)\nprint('e' * 100, file=sys.stderr)\n",
    )
    sandbox = Sandbox(SandboxConfig(project_root=project, max_output_bytes=12))

    result = sandbox.run([sys.executable, "loud.py"])

    assert result.exit_code == 0
    assert result.truncated
    assert result.stdout.endswith(TRUNCATION_MARKER)
    assert result.stderr.endswith(TRUNCATION_MARKER)
    assert result.stdout.startswith(b"o" * 12)


def test_truncate_stream_boundary() -> None:
    assert truncate_stream(b"abc", 3) == (b"abc", False)
    assert truncate_stream(b"abcd", 3) == (b"abc" + TRUNCATION_MARKER, True)
    assert truncate_stream(b"x", 0) == (TRUNCATION_MARKER, True)


def test_shell_mode_is_disabled_by_default(project: Path) -> None:
    sandbox = Sandbox(SandboxConfig(project_root=project))

    result = sandbox.run("echo harmless", shell=True)

    assert result.denied
    assert "shell=True is disabled" in result.reason


@pytest.mark.parametrize(
    "argv, reason_fragment",
    [
        ([], "empty argv"),
        ("echo hello", "sequence of strings"),
        (["echo", 42], "every argv item"),
        (["echo", "bad\x00arg"], "NUL"),
    ],
)
def test_invalid_argv_is_structurally_denied(
    argv: object, reason_fragment: str, project: Path
) -> None:
    sandbox = Sandbox(SandboxConfig(project_root=project))

    result = sandbox.run(argv)  # type: ignore[arg-type]

    assert result.denied
    assert result.exit_code == DENIED_EXIT_CODE
    assert reason_fragment in result.reason


def test_missing_executable_has_structured_denial(project: Path) -> None:
    sandbox = Sandbox(SandboxConfig(project_root=project))

    result = sandbox.run(["definitely-not-a-real-executable-26"])

    assert result.denied
    assert result.exit_code == DENIED_EXIT_CODE
    assert "executable not found" in result.reason


def test_result_to_dict_is_json_serializable(project: Path) -> None:
    write_script(project, "ok.py", "print('ok')\n")
    result = Sandbox(SandboxConfig(project_root=project)).run(
        [sys.executable, "ok.py"]
    )

    payload = result.to_dict()
    assert json.loads(json.dumps(payload))["exit_code"] == 0
    assert payload["stdout_bytes"] == 3
    assert "stdout" not in payload

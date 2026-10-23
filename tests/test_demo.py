from __future__ import annotations

import json

from main import run_demo


def test_demo_is_safe_and_self_verifying(capsys) -> None:
    assert run_demo() == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["all_expectations_met"] is True
    assert payload["warning"] == "development guardrail only; no OS-level isolation"
    assert all(payload["expectations"].values())

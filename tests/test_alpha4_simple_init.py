from __future__ import annotations

from pathlib import Path

import pytest

from promin.simple_init import (
    DEFAULT_SIMPLE_PREFLIGHT_FILES,
    AdvancedInitConfiguration,
    build_simple_init_plan,
)


def test_simple_init_defaults_are_bounded_and_repeatable(tmp_path: Path) -> None:
    first = build_simple_init_plan(tmp_path)
    second = build_simple_init_plan(tmp_path)

    assert first == second
    assert first["preflight"]["max_files"] == DEFAULT_SIMPLE_PREFLIGHT_FILES
    assert first["preflight"]["full_repository_scan"] is False
    assert first["init_capability_selection"]["status"] == "UNAVAILABLE"
    assert first["authority"] is False
    assert first["pass_credit"] is False


def test_advanced_simple_init_configuration_is_explicit_and_bounded(
    tmp_path: Path,
) -> None:
    source = tmp_path / "main.py"
    source.write_text("print('bounded')\n", encoding="utf-8")

    plan = build_simple_init_plan(
        tmp_path,
        AdvancedInitConfiguration(
            goal="Run the bounded project check",
            autonomy="standing-reversible",
            language="en",
            profiles=("general-development",),
            max_preflight_files=32,
        ),
    )

    assert plan["goal"] == "Run the bounded project check"
    assert plan["autonomy"] == "standing-reversible"
    assert plan["reporting_language"] == "en"
    assert plan["preflight"]["max_files"] == 32
    assert plan["preflight"]["full_repository_scan"] is False
    assert plan["profile_layers"][:2] == ["general-development", "standing-reversible"]


def test_advanced_simple_init_rejects_unbounded_preflight_request(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="max_preflight_files"):
        build_simple_init_plan(
            tmp_path,
            AdvancedInitConfiguration(max_preflight_files=10_001),
        )

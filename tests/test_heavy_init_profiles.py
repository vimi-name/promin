from __future__ import annotations

import json
from pathlib import Path

import pytest

from promin import __main__ as cli
from promin.init_profiles import (
    InitProfileError,
    load_init_profile,
    resolve_init_experience,
)
from promin.service import ServiceError


_ASSET_ROOT = Path(__file__).resolve().parents[1] / "capability_profiles"


def _standard_profile() -> dict[str, object]:
    return load_init_profile(_ASSET_ROOT / "standard-init.json")


def test_default_experience_is_minimal_one_click_without_language_inference() -> None:
    result = resolve_init_experience(_standard_profile())

    assert result["experience"] == "minimal"
    assert result["languages"] == []
    assert result["capability_selections"] == []
    assert result["capability_selection_source"] == "minimal-one-click"
    assert result["weak_model_semantic_decisions"] is False
    assert result["model_inference_used"] is False
    assert result["host_probe_performed"] is False
    assert result["status"] == "CONFIGURED_PENDING_HOST_OBSERVATION"
    assert result["acceptance_pass"] is False


def test_minimal_one_click_is_deterministic_for_every_generic_language() -> None:
    first = resolve_init_experience(
        _standard_profile(),
        experience="minimal",
        languages=("python", "csharp", "cpp", "javascript", "java", "c"),
    )
    second = resolve_init_experience(
        _standard_profile(),
        experience="minimal",
        languages=("c", "cpp", "csharp", "java", "javascript", "python"),
    )

    assert first == second
    assert first["experience"] == "minimal"
    assert first["languages"] == ["c", "cpp", "csharp", "java", "javascript", "python"]
    assert first["profile_precedence"] == [
        "default",
        "host-profile",
        "project-package",
        "cli",
        "interactive-user",
    ]
    assert first["capability_precedence"] == [
        "installed-language-catalog",
        "minimal-one-click",
    ]
    assert first["capability_selection_source"] == "minimal-one-click"
    assert first["weak_model_semantic_decisions"] is False
    assert first["model_inference_used"] is False
    assert first["host_probe_performed"] is False
    assert first["authority_granted"] is False
    assert first["pass_credit"] is False
    assert first["acceptance_pass"] is False
    assert len(first["experience_digest"]) == 64

    selected = first["capability_selections"]
    assert [item["profile_id"] for item in selected] == [
        "c-family-semantic",
        "csharp-semantic",
        "javascript-typescript-semantic",
        "jvm-semantic",
        "python-semantic",
    ]
    assert selected[0]["languages"] == ["c", "cpp"]
    assert [item["tools"]["items"] for item in selected] == [
        ["canonical-compilation-database", "clangd", "clang-tidy"],
        ["dotnet-compiler", "roslyn-analyzers"],
        ["eslint", "typescript-compiler"],
        ["javac", "checkstyle"],
        ["python-compileall", "ruff"],
    ]
    assert all(item["tools"]["mode"] == "profile-default" for item in selected)
    assert all(item["pass_credit"] is False for item in selected)
    assert all(len(item["selection_digest"]) == 64 for item in selected)


def test_expert_full_registered_overrides_have_source_precedence_and_stable_digests() -> None:
    expert = {
        "java": {
            "capability_id": "java-language",
            "documentation": [
                "java-documentation-generator",
                "java-language-specification",
            ],
            "tools": ["java-static-analysis", "java-compiler-check"],
        },
        "python": {
            "capability_id": "python-language",
            "documentation": [
                "python-documentation-generator",
                "python-language-reference",
            ],
            "tools": ["python-static-analysis", "python-compile-check"],
        },
    }
    result = resolve_init_experience(
        _standard_profile(),
        experience="expert",
        languages=("python", "java"),
        host_override={"analysis_profile": "standard"},
        cli_override={"analysis_profile": "diagnostic", "agent_slots": 3},
        expert_selections=expert,
        expert_source="owner",
    )
    reordered = resolve_init_experience(
        _standard_profile(),
        experience="expert",
        languages=("java", "python"),
        host_override={"analysis_profile": "standard"},
        cli_override={"analysis_profile": "diagnostic", "agent_slots": 3},
        expert_selections={"python": expert["python"], "java": expert["java"]},
        expert_source="owner",
    )

    assert result == reordered
    assert result["profile"]["effective"]["analysis_profile"] == "diagnostic"
    assert result["profile_provenance"]["analysis_profile"] == "cli"
    assert result["applied_profile_sources"] == ["default", "host-profile", "cli"]
    assert result["capability_precedence"] == [
        "installed-language-catalog",
        "owner",
    ]
    assert result["capability_selection_source"] == "owner"
    assert result["languages"] == ["java", "python"]
    assert result["weak_model_semantic_decisions"] is False

    java, python = result["capability_selections"]
    assert java["profile_id"] == "jvm-semantic"
    assert java["documentation"] == {
        "mode": "accept",
        "items": ["public-contract-index", "api-documentation"],
    }
    assert java["tools"] == {
        "mode": "accept",
        "items": ["javac", "checkstyle"],
    }
    assert python["profile_id"] == "python-semantic"
    assert python["documentation"] == {
        "mode": "accept",
        "items": ["public-contract-index", "api-documentation"],
    }
    assert python["tools"] == {
        "mode": "accept",
        "items": ["python-compileall", "ruff"],
    }
    assert all(item["selection_source"] == "owner" for item in (java, python))
    assert all(item["authority_granted"] is False for item in (java, python))
    assert all(item["acceptance_pass"] is False for item in (java, python))


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        (
            {"experience": "minimal", "languages": ("rust",)},
            "not a supported language alias",
        ),
        (
            {
                "experience": "minimal",
                "languages": ("python",),
                "expert_selections": {},
            },
            "minimal one-click",
        ),
        (
            {
                "experience": "expert",
                "languages": ("python",),
                "expert_selections": {
                    "python": {
                        "capability_id": "python-language",
                        "documentation": ["python-language-reference"],
                        "tools": ["python-compile-check"],
                    }
                },
                "expert_source": "weak-model",
            },
            "owner, cli, or interactive-user",
        ),
        (
            {
                "experience": "expert",
                "languages": ("python",),
                "expert_selections": {
                    "python": {
                        "capability_id": "python-language",
                        "documentation": ["unknown-python-document"],
                        "tools": ["python-compile-check"],
                    }
                },
                "expert_source": "owner",
            },
            "unknown expert python documentation",
        ),
        (
            {
                "experience": "expert",
                "languages": ("python",),
                "expert_selections": {
                    "python": {
                        "capability_id": "python-language",
                        "documentation": ["python-language-reference"],
                        "tools": ["python-static-analysis"],
                    }
                },
                "expert_source": "owner",
            },
            "omits required tool",
        ),
    ],
)
def test_experience_rejects_unknown_or_untrusted_semantic_input(
    kwargs: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(InitProfileError, match=message):
        resolve_init_experience(_standard_profile(), **kwargs)  # type: ignore[arg-type]


def _parse_guided_init(tmp_path: Path, *arguments: str):
    return cli._parser().parse_args(
        ["--root", str(tmp_path), "--no-telemetry", "init", *arguments]
    )


def test_cli_yes_uses_minimal_one_click_and_applies_without_legacy_questions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The public command binds a real plan before it calls the apply seam."""

    (tmp_path / "tool.py").write_text("print('ok')\n", encoding="utf-8")
    applied: list[tuple[Path, dict[str, object]]] = []
    real_apply = cli.apply_plan

    def observed_apply(root: Path, plan: dict[str, object]) -> dict[str, object]:
        applied.append((root, plan))
        return real_apply(root, plan)

    monkeypatch.setattr(cli, "apply_plan", observed_apply)

    result = cli._run(_parse_guided_init(tmp_path, "--yes"))

    assert result["status"] == "created"
    assert len(applied) == 1
    root, plan = applied[0]
    assert root == tmp_path.resolve()
    assert (tmp_path / ".promin" / "init" / "activation.json").is_file()
    selection = plan["init_capability_selection"]
    assert isinstance(selection, dict)
    assert selection["status"] == "UNAVAILABLE"
    assert selection["selection_source"] == "default"
    assert selection["authority_granted"] is False
    assert selection["pass_credit"] is False
    assert selection["acceptance_pass"] is False
    experience = result["init_experience"]
    assert experience["experience"] == "minimal"
    assert experience["status"] == "CONFIGURED_PENDING_HOST_OBSERVATION"
    assert experience["languages"] == ["python"]
    assert experience["weak_model_semantic_decisions"] is False
    assert experience["model_inference_used"] is False
    assert experience["host_probe_performed"] is False
    assert experience["authority_granted"] is False
    assert experience["pass_credit"] is False
    assert experience["acceptance_pass"] is False
    assert experience["capability_selections"][0]["profile_id"] == "python-semantic"
    assert experience["capability_selections"][0]["languages"] == ["python"]


def test_cli_expert_capabilities_bind_explicit_registered_selections_before_apply(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selections_path = tmp_path / "expert-selections.json"
    selections_path.write_text(
        json.dumps(
            {
                "python": {
                    "capability_id": "python-language",
                    "documentation": [
                        "python-language-reference",
                        "python-documentation-generator",
                    ],
                    "tools": [
                        "python-compile-check",
                        "python-static-analysis",
                    ],
                }
            }
        ),
        encoding="utf-8",
    )
    applied: list[dict[str, object]] = []

    def fake_apply(root: Path, plan: dict[str, object]) -> dict[str, object]:
        del root
        applied.append(plan)
        return {
            "record_type": "InitializationResult",
            "status": "created",
            "authority": False,
            "pass_credit": False,
            "acceptance_pass": False,
        }

    monkeypatch.setattr(cli, "apply_plan", fake_apply)

    result = cli._run(
        _parse_guided_init(
            tmp_path,
            "--init-experience",
            "expert",
            "--capability-language",
            "python",
            "--capability-selections",
            str(selections_path),
            "--yes",
        )
    )

    assert result["status"] == "created"
    assert len(applied) == 1
    selection = applied[0]["init_capability_selection"]
    assert isinstance(selection, dict)
    assert selection["status"] == "UNAVAILABLE"
    assert selection["selection_source"] == "cli"
    assert len(selection["selection_digest"]) == 64
    experience = result["init_experience"]
    assert experience["experience"] == "expert"
    assert experience["languages"] == ["python"]
    selected_python = experience["capability_selections"][0]
    assert selected_python["profile_id"] == "python-semantic"
    assert selected_python["documentation"] == {
        "mode": "accept",
        "items": ["public-contract-index", "api-documentation"],
    }
    assert selected_python["tools"] == {
        "mode": "accept",
        "items": ["python-compileall", "ruff"],
    }
    assert selected_python["authority_granted"] is False
    assert selected_python["pass_credit"] is False
    assert selected_python["acceptance_pass"] is False


@pytest.mark.parametrize(
    ("language", "selection", "message"),
    [
        (
            "rust",
            {
                "rust": {
                    "capability_id": "rust-language",
                    "documentation": ["rust-language-reference"],
                    "tools": ["rust-compile-check"],
                }
            },
            "not a supported language alias",
        ),
        (
            "python",
            {
                "python": {
                    "capability_id": "python-language",
                    "documentation": ["python-language-reference"],
                }
            },
            "unsupported field set",
        ),
    ],
)
def test_cli_expert_rejects_unknown_or_incomplete_selection_before_apply(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    language: str,
    selection: dict[str, object],
    message: str,
) -> None:
    selections_path = tmp_path / "invalid-expert-selections.json"
    selections_path.write_text(json.dumps(selection), encoding="utf-8")
    applied = False

    def fake_apply(root: Path, plan: dict[str, object]) -> dict[str, object]:
        del root, plan
        nonlocal applied
        applied = True
        return {}

    monkeypatch.setattr(cli, "apply_plan", fake_apply)

    with pytest.raises(ServiceError, match=message):
        cli._run(
            _parse_guided_init(
                tmp_path,
                "--init-experience",
                "expert",
                "--capability-language",
                language,
                "--capability-selections",
                str(selections_path),
                "--yes",
            )
        )
    assert applied is False


def test_cli_rejects_ambiguous_legacy_and_minimal_capability_selectors_before_apply(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    applied = False

    def fake_apply(root: Path, plan: dict[str, object]) -> dict[str, object]:
        del root, plan
        nonlocal applied
        applied = True
        return {}

    monkeypatch.setattr(cli, "apply_plan", fake_apply)

    with pytest.raises(ServiceError, match="cannot be combined"):
        cli._run(
            _parse_guided_init(
                tmp_path,
                "--init-experience",
                "minimal",
                "--documentation",
                "decline",
                "--verification",
                "decline",
                "--yes",
            )
        )
    assert applied is False


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (("--dry-run",), "require complete hidden expert plan inputs"),
        (("--review-plan",), "require complete hidden expert plan inputs"),
        (("--emit-plan", "expert-output"), "require complete hidden expert plan inputs"),
        (("--activation-proofs", "proofs.json"), "require complete hidden expert plan inputs"),
        (("--standard-bundle", "bundle"), "requires all standard/preset"),
    ],
)
def test_cli_rejects_incomplete_hidden_expert_options_before_guided_apply(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    arguments: tuple[str, ...],
    message: str,
) -> None:
    applied = False

    def fake_apply(root: Path, plan: dict[str, object]) -> dict[str, object]:
        del root, plan
        nonlocal applied
        applied = True
        return {}

    monkeypatch.setattr(cli, "apply_plan", fake_apply)

    def guided_must_not_run(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise AssertionError("incomplete hidden expert input reached guided init")

    monkeypatch.setattr(cli, "_guided_init", guided_must_not_run)

    with pytest.raises(ServiceError, match=message):
        cli._run(_parse_guided_init(tmp_path, *arguments))
    assert applied is False
    assert not (tmp_path / ".promin").exists()


def test_cli_rejects_yes_and_plan_only_before_apply(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    applied = False

    def fake_apply(root: Path, plan: dict[str, object]) -> dict[str, object]:
        del root, plan
        nonlocal applied
        applied = True
        return {}

    monkeypatch.setattr(cli, "apply_plan", fake_apply)

    def guided_must_not_run(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise AssertionError("contradictory init flags reached guided init")

    monkeypatch.setattr(cli, "_guided_init", guided_must_not_run)

    with pytest.raises(ServiceError, match="--yes cannot be combined with --plan-only"):
        cli._run(_parse_guided_init(tmp_path, "--yes", "--plan-only"))
    assert applied is False
    assert not (tmp_path / ".promin").exists()


def test_cli_keeps_complete_legacy_selection_deterministic_and_applicable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    applied: list[dict[str, object]] = []

    def fake_apply(root: Path, plan: dict[str, object]) -> dict[str, object]:
        del root
        applied.append(plan)
        return {
            "record_type": "InitializationResult",
            "status": "created",
            "authority": False,
            "pass_credit": False,
            "acceptance_pass": False,
        }

    monkeypatch.setattr(cli, "apply_plan", fake_apply)

    result = cli._run(
        _parse_guided_init(
            tmp_path,
            "--documentation",
            "decline",
            "--verification",
            "decline",
            "--yes",
        )
    )

    assert result["status"] == "created"
    assert len(applied) == 1
    selection = applied[0]["init_capability_selection"]
    assert isinstance(selection, dict)
    assert selection["documentation_choice"] == "decline"
    assert selection["verification_choice"] == "decline"
    assert selection["authority_granted"] is False
    assert selection["pass_credit"] is False
    assert selection["acceptance_pass"] is False

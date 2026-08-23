from __future__ import annotations

from pathlib import Path

import pytest

import promin.init_profiles as init_profiles_module
from promin.canonical import ParseLimits, canonical_bytes, digest_value, parse_json_strict
from promin.init_profiles import (
    InitProfileError,
    export_expert_init_bundle,
    import_expert_init_bundle,
    load_init_profile,
    resolve_init_experience,
)
from promin.version import standard_version


ROOT = Path(__file__).resolve().parents[1]
BUNDLE_FILE = "expert-init.json"
ALL_LANGUAGES = (
    "c",
    "cpp",
    "csharp",
    "java",
    "kotlin",
    "scala",
    "groovy",
    "javascript",
    "typescript",
    "python",
    "build",
    "documentation",
    "static-analysis",
    "generic",
)


def _profile() -> dict[str, object]:
    return load_init_profile(ROOT / "capability_profiles" / "standard-init.json")


def _profile_selections() -> dict[str, object]:
    return {
        "c-family-semantic": {
            "documentation": {
                "mode": "custom",
                "items": ["compact-module-contract-index", "clang-doc"],
            },
            "tools": {
                "mode": "custom",
                "items": ["canonical-compilation-database", "clangd", "clang-check"],
            },
        },
        "csharp-semantic": {
            "documentation": {
                "mode": "custom",
                "items": ["public-contract-index", "docfx"],
            },
            "tools": {
                "mode": "custom",
                "items": ["dotnet-compiler", "roslyn-analyzers", "docfx"],
            },
        },
        "javascript-typescript-semantic": {
            "documentation": {
                "mode": "custom",
                "items": ["api-documentation", "typedoc"],
            },
            "tools": {
                "mode": "custom",
                "items": ["eslint", "typescript-compiler", "typedoc"],
            },
        },
        "jvm-semantic": {
            "documentation": {
                "mode": "custom",
                "items": ["api-documentation", "javadoc"],
            },
            "tools": {
                "mode": "custom",
                "items": ["javac", "checkstyle", "spotbugs"],
            },
        },
        "open-source-tooling": {
            "documentation": {
                "mode": "custom",
                "items": ["portable-documentation", "documentation-generator"],
            },
            "tools": {
                "mode": "custom",
                "items": ["build-graph-check", "static-analysis", "format-check"],
            },
        },
        "python-semantic": {
            "documentation": {
                "mode": "custom",
                "items": ["api-documentation", "sphinx"],
            },
            "tools": {
                "mode": "custom",
                "items": ["python-syntax-check", "ruff", "mypy"],
            },
        },
        "weak-host-fallback": {
            "documentation": {
                "mode": "custom",
                "items": ["portable-contract-summary"],
            },
            "tools": {
                "mode": "custom",
                "items": ["optional-tool-unavailable"],
            },
        },
    }


def _plan_inputs() -> dict[str, object]:
    return {
        "goal": "Verify an arbitrary polyglot product",
        "autonomy": "standing-reversible",
        "reporting_language": "uk",
        "profile_layers": ["baseline", "expert"],
        "brief": {
            "constraints": ["bounded concurrency", "deterministic evidence"],
            "deliverables": ["implementation", "review"],
        },
        "max_preflight_files": 100_000,
    }


def _export(
    directory: Path,
    *,
    languages=ALL_LANGUAGES,
    selections: dict[str, object] | None = None,
) -> dict[str, object]:
    return export_expert_init_bundle(
        directory,
        standard_default=_profile(),
        plan_inputs=_plan_inputs(),
        languages=languages,
        expert_selections=_profile_selections() if selections is None else selections,
        expert_source="owner",
        host_override={"analysis_profile": "standard"},
        project_override={"artifact_profile": "diagnostic"},
        cli_override={
            "analysis_profile": "diagnostic",
            "agent_slots": 12,
            "autonomy": "standing-reversible",
        },
        interactive_override={"provider_strategy": "full-scan"},
    )


def _document(directory: Path) -> dict[str, object]:
    value = parse_json_strict((directory / BUNDLE_FILE).read_bytes())
    assert isinstance(value, dict)
    return value


def _rewrite(
    directory: Path,
    mutate,
    *,
    bind_digest: bool,
    canonical: bool = True,
) -> None:
    document = _document(directory)
    mutate(document)
    if bind_digest:
        document["bundle_digest"] = digest_value(
            {key: value for key, value in document.items() if key != "bundle_digest"}
        )
    data = (
        canonical_bytes(document)
        if canonical
        else (
            __import__("json").dumps(document, ensure_ascii=False, indent=2) + "\n"
        ).encode("utf-8")
    )
    (directory / BUNDLE_FILE).write_bytes(data)


def test_expert_init_is_one_canonical_deterministic_file_for_all_languages(
    tmp_path: Path,
) -> None:
    first_directory = tmp_path / "first"
    second_directory = tmp_path / "second"

    first = _export(first_directory)
    second = _export(second_directory, languages=reversed(ALL_LANGUAGES))
    imported = import_expert_init_bundle(first_directory)

    assert first == second == imported
    assert first["record_type"] == "ExpertInit"
    assert first["bundle_file"] == BUNDLE_FILE
    assert first["standard_default"] == _profile()
    assert first["plan_inputs"] == _plan_inputs()
    assert first["languages"] == sorted(ALL_LANGUAGES)
    assert set(first["expert_selections"]) == set(_profile_selections())
    assert first["resolved_experience"] == resolve_init_experience(
        first["standard_default"],
        experience="expert",
        languages=first["languages"],
        host_override=first["host_override"],
        project_override=first["project_override"],
        cli_override=first["cli_override"],
        interactive_override=first["interactive_override"],
        expert_selections=first["expert_selections"],
        expert_source=first["expert_source"],
    )
    for claim in (
        "authority_granted",
        "pass_credit",
        "acceptance_pass",
        "product_acceptance_pass",
        "release_approved",
    ):
        assert first[claim] is False
        assert first["resolved_experience"][claim] is False
    assert first["authority_effect"] == "none"
    assert standard_version() == "1.0.0-alpha.4"

    first_files = {path.name: path.read_bytes() for path in first_directory.iterdir()}
    second_files = {path.name: path.read_bytes() for path in second_directory.iterdir()}
    assert first_files == second_files
    assert set(first_files) == {BUNDLE_FILE}
    assert canonical_bytes(parse_json_strict(first_files[BUNDLE_FILE])) == first_files[BUNDLE_FILE]
    identity = {key: value for key, value in first.items() if key != "bundle_digest"}
    assert first["bundle_digest"] == digest_value(identity)


def test_expert_init_uses_catalog_tools_for_typescript_and_all_jvm_languages(
    tmp_path: Path,
) -> None:
    document = _export(tmp_path / "bundle")
    composition = document["resolved_experience"]["language_composition"]

    assert composition["selected_profile_ids"] == sorted(_profile_selections())
    assert {"typescript", "kotlin", "scala", "groovy"} <= set(
        composition["resolved_languages"]
    )
    assert {
        "dotnet-compiler",
        "roslyn-analyzers",
        "eslint",
        "typescript-compiler",
        "javac",
        "checkstyle",
        "spotbugs",
        "python-syntax-check",
        "ruff",
        "mypy",
    } <= set(composition["selected_tools"])
    assert composition["pass_credit"] is False
    assert composition["acceptance_pass"] is False


def test_legacy_language_keyed_input_is_only_an_input_adapter(tmp_path: Path) -> None:
    legacy = {
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
    document = _export(
        tmp_path / "legacy",
        languages=("python", "java"),
        selections=legacy,
    )

    assert set(document["expert_selections"]) == {"jvm-semantic", "python-semantic"}
    assert document["expert_selections"]["jvm-semantic"]["tools"] == {
        "mode": "accept",
        "items": [],
    }
    assert document["expert_selections"]["python-semantic"]["tools"] == {
        "mode": "accept",
        "items": [],
    }
    assert all("capability_id" not in value for value in document["expert_selections"].values())


def test_expert_init_bounds_public_iterables_and_input_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed = 0

    def too_many_languages():
        nonlocal observed
        for _ in range(65):
            observed += 1
            yield "python"

    with pytest.raises(InitProfileError, match="registered maximum 64"):
        _export(tmp_path / "too-many", languages=too_many_languages())
    assert observed == 65
    assert not (tmp_path / "too-many").exists()

    directory = tmp_path / "oversized"
    directory.mkdir()
    monkeypatch.setattr(
        init_profiles_module,
        "DEFAULT_LIMITS",
        ParseLimits(
            max_bytes=128,
            max_depth=64,
            max_items=1_000,
            max_string_length=1_000,
            max_number_length=64,
        ),
    )
    (directory / BUNDLE_FILE).write_bytes(b"x" * 129)
    with pytest.raises(InitProfileError, match="bounded size"):
        import_expert_init_bundle(directory)


@pytest.mark.parametrize("change", ("missing", "extra", "wrong-name"))
def test_expert_init_requires_exact_one_file(
    tmp_path: Path,
    change: str,
) -> None:
    directory = tmp_path / change
    _export(directory)
    if change == "missing":
        (directory / BUNDLE_FILE).unlink()
    elif change == "extra":
        (directory / "owner-note.txt").write_text("keep", encoding="utf-8")
    else:
        (directory / BUNDLE_FILE).rename(directory / "manifest.json")

    with pytest.raises(InitProfileError, match="exactly expert-init.json"):
        import_expert_init_bundle(directory)


def test_expert_init_rejects_tamper_and_noncanonical_bytes(tmp_path: Path) -> None:
    digest_directory = tmp_path / "digest"
    _export(digest_directory)
    _rewrite(
        digest_directory,
        lambda value: value.__setitem__("bundle_digest", "0" * 64),
        bind_digest=False,
    )
    with pytest.raises(InitProfileError, match="digest mismatch"):
        import_expert_init_bundle(digest_directory)

    noncanonical_directory = tmp_path / "noncanonical"
    _export(noncanonical_directory)
    _rewrite(
        noncanonical_directory,
        lambda _value: None,
        bind_digest=False,
        canonical=False,
    )
    with pytest.raises(InitProfileError, match="not canonical"):
        import_expert_init_bundle(noncanonical_directory)

    stale_directory = tmp_path / "stale-derived"
    _export(stale_directory)

    def change_derived_result(value: dict[str, object]) -> None:
        value["resolved_experience"]["status"] = "changed-without-resolution"

    _rewrite(stale_directory, change_derived_result, bind_digest=True)
    with pytest.raises(InitProfileError, match="not normalized or self-consistent"):
        import_expert_init_bundle(stale_directory)


@pytest.mark.parametrize(
    "claim",
    (
        "authority_granted",
        "pass_credit",
        "acceptance_pass",
        "product_acceptance_pass",
        "release_approved",
    ),
)
def test_expert_init_rejects_false_claim_even_with_rebound_digest(
    tmp_path: Path,
    claim: str,
) -> None:
    directory = tmp_path / claim
    _export(directory)
    _rewrite(
        directory,
        lambda value: value.__setitem__(claim, True),
        bind_digest=True,
    )
    with pytest.raises(InitProfileError, match=claim):
        import_expert_init_bundle(directory)


def test_expert_init_is_create_only_and_validates_before_create(tmp_path: Path) -> None:
    existing = tmp_path / "existing"
    existing.mkdir()
    marker = existing / "owner-data.txt"
    marker.write_text("preserve\n", encoding="utf-8")

    with pytest.raises(InitProfileError, match="already exists"):
        _export(existing)
    assert marker.read_text(encoding="utf-8") == "preserve\n"
    assert not (existing / BUNDLE_FILE).exists()

    invalid = _profile_selections()
    invalid["python-semantic"]["tools"] = {
        "mode": "custom",
        "items": ["not-declared"],
    }
    destination = tmp_path / "invalid"
    with pytest.raises(InitProfileError, match="declared capabilities"):
        _export(destination, selections=invalid)
    assert not destination.exists()

    missing_parent = tmp_path / "missing" / "bundle"
    with pytest.raises(InitProfileError, match="parent must already be"):
        _export(missing_parent)
    assert not missing_parent.exists()

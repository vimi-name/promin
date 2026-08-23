from __future__ import annotations

import json
from pathlib import Path
import shutil

import pytest

import promin.language_catalog as language_catalog_module
from promin.experience import detect_technologies
from promin.language_catalog import (
    BUNDLED_LANGUAGE_PROFILES,
    LanguageCatalogError,
    compose_language_capabilities,
    languages_for_detected_technologies,
    load_bundled_language_catalog,
    load_language_catalog,
)


@pytest.mark.parametrize(
    ("technology", "languages"),
    (
        ("cpp", ("cpp",)),
        ("cmake", ("cpp",)),
        ("windows-native", ("cpp",)),
        ("visual-studio", ("cpp",)),
        ("dotnet", ("csharp",)),
        ("java", ("java",)),
        ("kotlin", ("kotlin",)),
        ("scala", ("scala",)),
        ("groovy", ("groovy",)),
        ("android", ("kotlin",)),
        ("gradle", ("groovy",)),
        ("javascript", ("javascript",)),
        ("typescript", ("typescript",)),
        ("node", ("javascript",)),
        ("react", ("javascript",)),
        ("react-native", ("javascript",)),
        ("expo", ("javascript",)),
        ("nextjs", ("javascript",)),
        ("vite", ("javascript",)),
        ("supabase", ("javascript",)),
        ("vue", ("javascript",)),
        ("svelte", ("javascript",)),
        ("express", ("javascript",)),
        ("python", ("python",)),
        ("rust", ("generic",)),
        ("go", ("generic",)),
        ("swift", ("generic",)),
        ("dart", ("generic",)),
        ("containers", ("build",)),
    ),
)
def test_every_detectable_technology_resolves_from_bundled_catalog_truth(
    technology: str, languages: tuple[str, ...]
) -> None:
    assert languages_for_detected_technologies((technology,)) == languages


def test_detected_language_identity_and_bundled_order_are_deterministic() -> None:
    technologies = ("typescript", "kotlin", "python", "scala", "groovy")

    first = languages_for_detected_technologies(technologies)
    second = languages_for_detected_technologies(reversed(technologies))

    assert first == second == ("typescript", "kotlin", "scala", "groovy", "python")
    assert languages_for_detected_technologies(("future-technology",)) == ()


def test_every_fact_emitted_by_the_ordinary_detector_has_a_catalog_language() -> None:
    paths = (
        "src/source.js",
        "src/source.ts",
        "src/source.py",
        "src/source.kt",
        "src/source.java",
        "src/source.cpp",
        "src/source.cs",
        "src/source.rs",
        "src/source.go",
        "src/source.swift",
        "src/source.dart",
        "CMakeLists.txt",
        "AndroidManifest.xml",
        "build.gradle",
        "project.sln",
        "project.vcxproj",
        "project.csproj",
        "supabase/config.toml",
        "Dockerfile",
        "package.json",
    )
    dependencies = {
        name: "1"
        for name in (
            "react",
            "react-native",
            "expo",
            "next",
            "vite",
            "@supabase/supabase-js",
            "vue",
            "svelte",
            "express",
        )
    }
    facts, _signals = detect_technologies(
        {
            "entries": [{"path": path} for path in paths],
            "manifest_samples": {
                "package.json": json.dumps({"dependencies": dependencies})
            },
            "truncated": False,
        }
    )

    emitted = tuple(str(fact["technology"]) for fact in facts)
    assert emitted
    assert all(
        languages_for_detected_technologies((technology,))
        for technology in emitted
    )


ROOT = Path(__file__).resolve().parents[1]
PROFILE_ROOT = ROOT / "language_profiles"

EXPECTED_PROFILES = {
    "c-family-semantic.json": (
        "c-family-semantic",
        "c-family",
        ("c", "cpp"),
    ),
    "csharp-semantic.json": (
        "csharp-semantic",
        "csharp",
        ("csharp",),
    ),
    "javascript-typescript-semantic.json": (
        "javascript-typescript-semantic",
        "javascript",
        ("javascript", "typescript"),
    ),
    "jvm-semantic.json": (
        "jvm-semantic",
        "java",
        ("java", "kotlin", "scala", "groovy"),
    ),
    "open-source-tooling.json": (
        "open-source-tooling",
        "tooling",
        ("build", "documentation", "static-analysis"),
    ),
    "python-semantic.json": (
        "python-semantic",
        "python",
        ("python",),
    ),
    "weak-host-fallback.json": (
        "weak-host-fallback",
        "generic",
        ("generic",),
    ),
}

EXPECTED_OSS_TOOLS = {
    "c-family-semantic": (
        ("canonical-compilation-database", "clangd", "clang-tidy"),
        ("clang-check", "include-what-you-use", "cppcheck"),
    ),
    "csharp-semantic": (
        ("dotnet-compiler", "roslyn-analyzers"),
        ("docfx",),
    ),
    "javascript-typescript-semantic": (
        ("eslint", "typescript-compiler"),
        ("typedoc",),
    ),
    "jvm-semantic": (
        ("javac", "checkstyle"),
        ("spotbugs", "javadoc"),
    ),
    "python-semantic": (
        ("python-syntax-check", "ruff"),
        ("mypy", "sphinx"),
    ),
}

EXPECTED_OSS_DOCUMENTATION = {
    "csharp-semantic": ("docfx",),
    "javascript-typescript-semantic": ("typedoc",),
    "jvm-semantic": ("javadoc",),
    "python-semantic": ("sphinx",),
}


def _copy_profiles(root: Path) -> Path:
    destination = root / "language_profiles"
    shutil.copytree(PROFILE_ROOT, destination)
    return destination


def test_bundled_catalog_exactly_binds_distribution_profiles() -> None:
    descriptors = {
        descriptor.filename: (
            descriptor.profile_id,
            descriptor.language_family,
            descriptor.languages,
        )
        for descriptor in BUNDLED_LANGUAGE_PROFILES
    }
    assert descriptors == EXPECTED_PROFILES
    assert {path.name for path in PROFILE_ROOT.glob("*.json")} == set(EXPECTED_PROFILES)

    first = load_bundled_language_catalog(PROFILE_ROOT)
    second = load_bundled_language_catalog(PROFILE_ROOT)
    assert first == second
    assert first.catalog_digest == second.catalog_digest
    assert first.source_digest == second.source_digest
    assert [profile.profile_id for profile in first.profiles] == sorted(
        profile_id for profile_id, _, _ in EXPECTED_PROFILES.values()
    )
    for profile_id, family, languages in EXPECTED_PROFILES.values():
        profile = first.profile(profile_id)
        assert profile.language_family == family
        assert profile.languages == languages


@pytest.mark.parametrize(
    ("alias", "profile_id", "family"),
    (
        ("c", "c-family-semantic", "c-family"),
        ("C++", "c-family-semantic", "c-family"),
        ("cpp", "c-family-semantic", "c-family"),
        ("C#", "csharp-semantic", "csharp"),
        ("csharp", "csharp-semantic", "csharp"),
        ("java", "jvm-semantic", "java"),
        ("kotlin", "jvm-semantic", "java"),
        ("scala", "jvm-semantic", "java"),
        ("groovy", "jvm-semantic", "java"),
        ("JS", "javascript-typescript-semantic", "javascript"),
        ("javascript", "javascript-typescript-semantic", "javascript"),
        ("TS", "javascript-typescript-semantic", "javascript"),
        ("typescript", "javascript-typescript-semantic", "javascript"),
        ("py", "python-semantic", "python"),
        ("python", "python-semantic", "python"),
        ("build", "open-source-tooling", "tooling"),
        ("documentation", "open-source-tooling", "tooling"),
        ("static-analysis", "open-source-tooling", "tooling"),
        ("generic", "weak-host-fallback", "generic"),
    ),
)
def test_bundled_catalog_preserves_public_language_aliases(
    alias: str,
    profile_id: str,
    family: str,
) -> None:
    catalog = load_bundled_language_catalog(PROFILE_ROOT)
    result = compose_language_capabilities(catalog, languages=(alias,))

    assert result["language_families"] == [family]
    assert result["selected_profile_ids"] == [profile_id]
    assert result["pass_credit"] is False
    assert result["acceptance_pass"] is False


def test_language_profiles_declare_concrete_oss_tools_without_credit() -> None:
    catalog = load_bundled_language_catalog(PROFILE_ROOT)
    for profile_id, (recommended, optional) in EXPECTED_OSS_TOOLS.items():
        profile = catalog.profile(profile_id)
        assert profile.recommended_tools == recommended
        assert profile.optional_tools == optional
    for profile_id, optional in EXPECTED_OSS_DOCUMENTATION.items():
        assert catalog.profile(profile_id).documentation_optional == optional

    result = compose_language_capabilities(
        catalog,
        languages=("C++", "C#", "java", "JS", "py"),
    )
    assert result["selected_profile_ids"] == [
        "c-family-semantic",
        "csharp-semantic",
        "javascript-typescript-semantic",
        "jvm-semantic",
        "python-semantic",
    ]
    assert result["selected_tools"] == sorted(
        tool
        for recommended, _optional in EXPECTED_OSS_TOOLS.values()
        for tool in recommended
    )
    assert "typescript-compiler" in result["selected_tools"]
    assert result["status"] == "SKIPPED"
    assert result["availability_observations"] == []
    assert result["claims"] == {
        "acceptance_pass": False,
        "pass_credit": False,
        "product_acceptance_pass": False,
        "release_approved": False,
    }
    assert result["acceptance_pass"] is False
    assert result["pass_credit"] is False
    assert result["product_acceptance_pass"] is False
    assert result["release_approved"] is False


def test_optional_tool_selection_is_profile_bounded() -> None:
    catalog = load_bundled_language_catalog(PROFILE_ROOT)
    default_result = compose_language_capabilities(catalog, languages=("typescript",))
    assert default_result["selected_tools"] == ["eslint", "typescript-compiler"]

    result = compose_language_capabilities(
        catalog,
        languages=("typescript",),
        overrides={
            "javascript-typescript-semantic": {
                "tools": {
                    "mode": "custom",
                    "items": ["typescript-compiler", "typedoc"],
                }
            }
        },
    )
    assert result["selected_tools"] == ["typedoc", "typescript-compiler"]
    assert result["pass_credit"] is False

    with pytest.raises(LanguageCatalogError, match="declared capabilities"):
        compose_language_capabilities(
            catalog,
            languages=("typescript",),
            overrides={
                "javascript-typescript-semantic": {
                    "tools": {"mode": "custom", "items": ["invented-tool"]}
                }
            },
        )

    with pytest.raises(LanguageCatalogError, match="bounded item count"):
        compose_language_capabilities(
            catalog,
            languages=("typescript",),
            overrides={
                "javascript-typescript-semantic": {
                    "tools": {
                        "mode": "custom",
                        "items": ["typescript-compiler"] * 65,
                    }
                }
            },
        )


def test_bundled_catalog_rejects_missing_extra_and_misbound_profiles(
    tmp_path: Path,
) -> None:
    missing = _copy_profiles(tmp_path / "missing")
    (missing / "jvm-semantic.json").unlink()
    with pytest.raises(LanguageCatalogError, match="filenames must be exact"):
        load_bundled_language_catalog(missing)

    extra = _copy_profiles(tmp_path / "extra")
    shutil.copy2(extra / "python-semantic.json", extra / "unknown-semantic.json")
    with pytest.raises(LanguageCatalogError, match="filenames must be exact"):
        load_bundled_language_catalog(extra)

    misbound = _copy_profiles(tmp_path / "misbound")
    jvm_path = misbound / "jvm-semantic.json"
    document = json.loads(jvm_path.read_text(encoding="utf-8"))
    document["profileId"] = "different-jvm-semantic"
    jvm_path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(LanguageCatalogError, match="identity differs"):
        load_bundled_language_catalog(misbound)


def test_catalog_rejects_invalid_schema_language_and_profile(tmp_path: Path) -> None:
    invalid_schema = _copy_profiles(tmp_path / "schema")
    profile_path = invalid_schema / "python-semantic.json"
    document = json.loads(profile_path.read_text(encoding="utf-8"))
    document["schema"] = "promin.language-capability-profile.v2"
    profile_path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(LanguageCatalogError, match="schema must be"):
        load_bundled_language_catalog(invalid_schema)

    catalog = load_bundled_language_catalog(PROFILE_ROOT)
    with pytest.raises(LanguageCatalogError, match="supported language alias"):
        compose_language_capabilities(catalog, languages=("rust",))
    with pytest.raises(LanguageCatalogError, match="unknown language profile"):
        catalog.profile("unknown-semantic")


def test_generic_catalog_loads_single_file_and_bounded_directory(tmp_path: Path) -> None:
    profile_path = tmp_path / "python-semantic.json"
    shutil.copy2(PROFILE_ROOT / profile_path.name, profile_path)
    single = load_language_catalog(profile_path)
    assert [profile.profile_id for profile in single.profiles] == ["python-semantic"]

    directory = tmp_path / "profiles"
    directory.mkdir()
    shutil.copy2(profile_path, directory / profile_path.name)
    (directory / "README.txt").write_text("not a profile\n", encoding="utf-8")
    catalog = load_language_catalog(directory)
    assert [profile.profile_id for profile in catalog.profiles] == ["python-semantic"]

    (directory / "nested").mkdir()
    with pytest.raises(LanguageCatalogError, match="nested directories"):
        load_language_catalog(directory)


def test_generic_catalog_enforces_ordinary_count_and_byte_limits(tmp_path: Path) -> None:
    crowded = tmp_path / "crowded"
    crowded.mkdir()
    for index in range(language_catalog_module._MAX_PROFILE_FILES + 1):
        (crowded / f"member-{index:02d}.txt").write_text("bounded\n", encoding="utf-8")
    with pytest.raises(LanguageCatalogError, match="bounded profile count"):
        load_language_catalog(crowded)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (language_catalog_module._MAX_PROFILE_BYTES + 1))
    with pytest.raises(LanguageCatalogError, match="bounded byte limit"):
        load_language_catalog(oversized)


@pytest.mark.parametrize(
    "source",
    (
        b'{"schema":"one","schema":"two"}\n',
        b'{"schema":NaN}\n',
        b"not-json\n",
    ),
)
def test_catalog_rejects_malformed_json(source: bytes, tmp_path: Path) -> None:
    path = tmp_path / "malformed.json"
    path.write_bytes(source)
    with pytest.raises(LanguageCatalogError):
        load_language_catalog(path)

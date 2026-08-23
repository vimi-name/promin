from __future__ import annotations

from pathlib import Path
import hashlib
import os
import shutil
import sys
import time
from dataclasses import replace

import pytest

from promin.language_catalog import load_bundled_language_catalog
from promin.language_tooling import (
    LanguageToolingError,
    plan_language_tool,
    probe_language_tool,
    run_language_tool,
    _host_path_guard_available,
)


PACKAGE_ROOT = Path(__file__).resolve().parents[1]


def load_catalog():
    return load_bundled_language_catalog(PACKAGE_ROOT / "language_profiles")


def test_plan_rejects_undeclared_tool_and_argv_injection(tmp_path: Path) -> None:
    catalog = load_catalog()
    with pytest.raises(LanguageToolingError, match="declared"):
        plan_language_tool(
            catalog,
            language_id="c-family",
            tool_id="powershell",
            action_id="static-analysis",
            root=tmp_path,
        )
    with pytest.raises(LanguageToolingError, match="argument"):
        plan_language_tool(
            catalog,
            language_id="c-family",
            tool_id="clang-tidy",
            action_id="static-analysis",
            root=tmp_path,
            arguments=(";", "del"),
        )


def test_plan_record_is_deterministic_and_claim_free(tmp_path: Path) -> None:
    first = plan_language_tool(
        load_catalog(),
        language_id="c-family",
        tool_id="clang-tidy",
        action_id="static-analysis",
        root=tmp_path,
    )
    second = plan_language_tool(
        load_catalog(),
        language_id="c-family",
        tool_id="clang-tidy",
        action_id="static-analysis",
        root=tmp_path,
    )

    assert first.to_record()["claims"]["pass_credit"] is False
    assert first.to_record() == second.to_record()


@pytest.mark.parametrize(
    ("language_id", "tool_id", "action_id", "expected_argv"),
    (
        ("c-family", "clang-tidy", "static-analysis", ("clang-tidy", "src", "--")),
        ("c-family", "clangd", "toolchain-info", ("clangd", "--version")),
        ("c-family", "clang-check", "static-analysis", ("clang-check", "src", "--")),
        ("c-family", "include-what-you-use", "static-analysis", ("include-what-you-use", "src", "--")),
        ("c-family", "cppcheck", "static-analysis", ("cppcheck", "src")),
        ("c-family", "clang-doc", "documentation", ("clang-doc", "src")),
        ("c-family", "doxygen-html-xml", "documentation", ("doxygen", "Doxyfile")),
        ("csharp", "dotnet-compiler", "toolchain-info", ("dotnet", "--info")),
        ("csharp", "roslyn-analyzers", "static-analysis", ("dotnet", "format", "analyzers", "--verify-no-changes", "--no-restore")),
        ("csharp", "docfx", "documentation", ("docfx", "docfx.json")),
        ("jvm", "javac", "toolchain-info", ("javac", "-version")),
        ("jvm", "javadoc", "documentation", ("javadoc", "src")),
        ("jvm", "checkstyle", "static-analysis", ("checkstyle", "checkstyle.xml", "src")),
        ("jvm", "spotbugs", "static-analysis", ("spotbugs", "build")),
    ),
)
def test_plan_uses_fixed_allowlisted_action_grammar(
    tmp_path: Path, language_id: str, tool_id: str, action_id: str,
    expected_argv: tuple[str, ...],
) -> None:
    catalog = load_catalog()
    plan = plan_language_tool(
        catalog,
        language_id=language_id,
        tool_id=tool_id,
        action_id=action_id,
        root=tmp_path,
    )
    assert plan.tool_id == tool_id
    assert plan.capability_id == tool_id
    assert plan.action_id == action_id
    assert plan.argv == expected_argv
    assert plan.working_directory == str(tmp_path.resolve())
    assert plan.output_roots
    assert plan.to_record() == {
        "language_id": {"jvm": "java"}.get(language_id, language_id),
        "capability_id": tool_id,
        "action_id": action_id,
        "tool_id": tool_id,
        "executable": expected_argv[0],
        "argv": list(expected_argv),
        "working_directory": str(tmp_path.resolve()),
        "output_roots": ["builds/analysis", ".promin/logs"]
        if language_id == "c-family" else ["host-local-diagnostics", "host-local-forensics"],
            "profile_digest": catalog.profile(
                {"c-family": "c-family-semantic", "csharp": "csharp-semantic", "jvm": "jvm-semantic"}
                .get(language_id, "")
            ).profile_digest,
            "required_configuration_paths": [],
            "claims": {
            "acceptance_pass": False,
            "pass_credit": False,
            "product_acceptance_pass": False,
            "release_approved": False,
        },
        "acceptance_pass": False,
        "pass_credit": False,
        "product_acceptance_pass": False,
        "release_approved": False,
    }


def test_plan_rejects_alias_inputs_and_selected_profile_missing_tool(tmp_path: Path) -> None:
    catalog = load_catalog()
    for language_id, tool_id in (("c-family", "doxygen"), ("csharp", "dotnet")):
        with pytest.raises(LanguageToolingError, match="declared"):
            plan_language_tool(
                catalog, language_id=language_id, tool_id=tool_id,
                action_id="documentation" if tool_id == "doxygen" else "toolchain-info",
                root=tmp_path,
            )
    with pytest.raises(LanguageToolingError, match="declared"):
        plan_language_tool(
            catalog, language_id="csharp", tool_id="clang-tidy",
            action_id="static-analysis", root=tmp_path,
        )


def test_plan_rejects_canonical_compilation_database_as_non_executable(tmp_path: Path) -> None:
    with pytest.raises(LanguageToolingError, match="declared"):
        plan_language_tool(
            load_catalog(),
            language_id="c-family",
            tool_id="canonical-compilation-database",
            action_id="toolchain-info",
            root=tmp_path,
        )


def test_plan_preserves_declared_argument_positions(tmp_path: Path) -> None:
    catalog = load_catalog()
    assert plan_language_tool(
        catalog, language_id="c-family", tool_id="clang-tidy",
        action_id="static-analysis", root=tmp_path,
        arguments=("src/main.cpp",),
    ).argv == ("clang-tidy", "src/main.cpp", "--")
    assert plan_language_tool(
        catalog, language_id="jvm", tool_id="checkstyle",
        action_id="static-analysis", root=tmp_path,
        arguments=("config/checkstyle.xml", "src"),
    ).argv == ("checkstyle", "config/checkstyle.xml", "src")


def test_roslyn_analyzers_rejects_project_argument(tmp_path: Path) -> None:
    with pytest.raises(LanguageToolingError, match="argument count"):
        plan_language_tool(
            load_catalog(),
            language_id="csharp",
            tool_id="roslyn-analyzers",
            action_id="static-analysis",
            root=tmp_path,
            arguments=("Project.csproj",),
        )


def test_roslyn_analyzers_missing_executable_is_unavailable_and_claim_free(tmp_path: Path) -> None:
    plan = plan_language_tool(
        load_catalog(),
        language_id="csharp",
        tool_id="roslyn-analyzers",
        action_id="static-analysis",
        root=tmp_path,
    )
    missing = tmp_path / "missing-dotnet"
    receipt = probe_language_tool(
        replace(plan, executable=str(missing), argv=(str(missing), *plan.argv[1:])),
        timeout_seconds=1,
    )
    assert receipt.status == "UNAVAILABLE"
    assert receipt.invoked is False
    assert all(value is False for value in receipt.claims.values())


def test_plan_rejects_unknown_action_and_noncanonical_argument(tmp_path: Path) -> None:
    with pytest.raises(LanguageToolingError, match="action"):
        plan_language_tool(
            load_catalog(),
            language_id="c-family",
            tool_id="clang-tidy",
            action_id="run-anything",
            root=tmp_path,
        )
    with pytest.raises(LanguageToolingError, match="argument"):
        plan_language_tool(
            load_catalog(),
            language_id="c-family",
            tool_id="clang-tidy",
            action_id="static-analysis",
            root=tmp_path,
            arguments=("../outside",),
        )


@pytest.mark.parametrize("value", ("/absolute", r"C:\absolute", r"\\server\share", ".", "a/../b"))
def test_plan_rejects_absolute_drive_unc_and_parent_paths(tmp_path: Path, value: str) -> None:
    with pytest.raises(LanguageToolingError, match="argument"):
        plan_language_tool(
            load_catalog(), language_id="c-family", tool_id="clang-tidy",
            action_id="static-analysis", root=tmp_path, arguments=(value,),
        )


@pytest.mark.parametrize("value", (";", "&", "|", ">", "<", "$", "`", "%", "^", "!"))
def test_plan_rejects_shell_metacharacters(tmp_path: Path, value: str) -> None:
    with pytest.raises(LanguageToolingError, match="argument"):
        plan_language_tool(
            load_catalog(), language_id="c-family", tool_id="clang-tidy",
            action_id="static-analysis", root=tmp_path, arguments=(value,),
        )


def test_plan_rejects_invalid_root_non_tuple_and_excess_arguments(tmp_path: Path) -> None:
    catalog = load_catalog()
    with pytest.raises(LanguageToolingError, match="existing directory"):
        plan_language_tool(catalog, language_id="c-family", tool_id="clang-tidy",
                           action_id="static-analysis", root=tmp_path / "missing")
    with pytest.raises(LanguageToolingError, match="tuple"):
        plan_language_tool(catalog, language_id="c-family", tool_id="clang-tidy",
                           action_id="static-analysis", root=tmp_path, arguments=["src"])
    with pytest.raises(LanguageToolingError, match="argument count"):
        plan_language_tool(catalog, language_id="c-family", tool_id="clang-tidy",
                           action_id="static-analysis", root=tmp_path,
                           arguments=("a", "b"))


@pytest.mark.parametrize(
    ("language_id", "tool_id", "action_id", "expected_argv", "configuration", "expected_roots"),
    (
        ("javascript", "eslint", "static-analysis", ("eslint", "--config", "eslint.config.js", "src"), "eslint.config.js", ("host-local-diagnostics", "host-local-forensics")),
        ("typescript", "typescript-compiler", "static-analysis", ("tsc", "--noEmit", "--project", "tsconfig.json"), "tsconfig.json", ("host-local-diagnostics", "host-local-forensics")),
        ("js", "typedoc", "documentation", ("typedoc", "--options", "typedoc.json", "--out", "host-local-diagnostics/typedoc"), "typedoc.json", ("host-local-diagnostics/typedoc", "host-local-forensics")),
        ("python", "python-compileall", "static-analysis", ("python", "-B", "-m", "compileall", "-q", "src"), None, ("host-local-diagnostics", "host-local-forensics")),
        ("py", "ruff", "static-analysis", ("ruff", "check", "--config", "pyproject.toml", "src"), "pyproject.toml", ("host-local-diagnostics", "host-local-forensics")),
        ("python", "mypy", "static-analysis", ("mypy", "--config-file", "pyproject.toml", "src"), "pyproject.toml", ("host-local-diagnostics", "host-local-forensics")),
        ("python", "sphinx", "documentation", ("sphinx-build", "-W", "-b", "html", "docs", "host-local-diagnostics/sphinx-html"), "docs/conf.py", ("host-local-diagnostics/sphinx-html", "host-local-forensics")),
    ),
)
def test_plan_js_typescript_python_contracts_are_configuration_bound(
    tmp_path: Path, language_id: str, tool_id: str, action_id: str,
    expected_argv: tuple[str, ...], configuration: str | None,
    expected_roots: tuple[str, ...],
) -> None:
    if configuration is not None:
        config = tmp_path / configuration
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text("# fixture\n", encoding="utf-8")
    plan = plan_language_tool(
        load_catalog(), language_id=language_id, tool_id=tool_id,
        action_id=action_id, root=tmp_path,
    )
    assert plan.language_id == ("javascript" if language_id in {"javascript", "typescript", "js"} else "python")
    assert plan.tool_id == tool_id
    assert plan.action_id == action_id
    assert plan.argv == expected_argv
    assert plan.required_configuration_paths == (() if configuration is None else (configuration,))
    assert plan.output_roots == expected_roots
    assert plan.profile_digest == load_catalog().profile(
        "javascript-typescript-semantic" if language_id in {"javascript", "typescript", "js"} else "python-semantic"
    ).profile_digest
    record = plan.to_record()
    assert record["required_configuration_paths"] == ([] if configuration is None else [configuration])
    assert all(record[key] is False for key in ("acceptance_pass", "pass_credit", "product_acceptance_pass", "release_approved"))
    assert all(value is False for value in record["claims"].values())


@pytest.mark.parametrize(
    ("language_id", "tool_id", "action_id", "configuration"),
    (
        ("javascript", "eslint", "static-analysis", "eslint.config.js"),
        ("typescript", "typescript-compiler", "static-analysis", "tsconfig.json"),
        ("javascript", "typedoc", "documentation", "typedoc.json"),
        ("python", "ruff", "static-analysis", "pyproject.toml"),
        ("python", "mypy", "static-analysis", "pyproject.toml"),
        ("python", "sphinx", "documentation", "docs/conf.py"),
    ),
)
def test_configuration_bound_tools_reject_missing_directory_and_link(
    tmp_path: Path, language_id: str, tool_id: str, action_id: str, configuration: str,
) -> None:
    catalog = load_catalog()
    with pytest.raises(LanguageToolingError, match="configuration"):
        plan_language_tool(catalog, language_id=language_id, tool_id=tool_id, action_id=action_id, root=tmp_path)
    config = tmp_path / configuration
    config.mkdir(parents=True)
    with pytest.raises(LanguageToolingError, match="configuration"):
        plan_language_tool(catalog, language_id=language_id, tool_id=tool_id, action_id=action_id, root=tmp_path)
    config.rmdir()
    target = tmp_path / "target.conf"
    target.write_text("# target\n", encoding="utf-8")
    try:
        config.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links unavailable")
    with pytest.raises(LanguageToolingError, match="configuration"):
        plan_language_tool(catalog, language_id=language_id, tool_id=tool_id, action_id=action_id, root=tmp_path)


def test_python_compileall_has_no_configuration_and_rejects_second_source_argument(tmp_path: Path) -> None:
    plan = plan_language_tool(
        load_catalog(), language_id="python", tool_id="python-compileall",
        action_id="static-analysis", root=tmp_path,
    )
    assert plan.argv == ("python", "-B", "-m", "compileall", "-q", "src")
    assert plan.required_configuration_paths == ()
    with pytest.raises(LanguageToolingError, match="argument count"):
        plan_language_tool(
            load_catalog(), language_id="python", tool_id="python-compileall",
            action_id="static-analysis", root=tmp_path,
            arguments=("src", "other"),
        )


@pytest.mark.parametrize(
    ("language_id", "tool_id", "action_id", "configuration"),
    (
        ("javascript", "eslint", "static-analysis", "eslint.config.js"),
        ("typescript", "typescript-compiler", "static-analysis", "tsconfig.json"),
        ("javascript", "typedoc", "documentation", "typedoc.json"),
        ("python", "python-compileall", "static-analysis", None),
        ("python", "ruff", "static-analysis", "pyproject.toml"),
        ("python", "mypy", "static-analysis", "pyproject.toml"),
        ("python", "sphinx", "documentation", "docs/conf.py"),
    ),
)
def test_new_contracts_reject_any_caller_argument(
    tmp_path: Path, language_id: str, tool_id: str, action_id: str,
    configuration: str | None,
) -> None:
    if configuration is not None:
        config = tmp_path / configuration
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text("# fixture\n", encoding="utf-8")
    with pytest.raises(LanguageToolingError, match="argument count"):
        plan_language_tool(
            load_catalog(), language_id=language_id, tool_id=tool_id,
            action_id=action_id, root=tmp_path, arguments=("caller-input",),
        )


def test_public_guide_closes_js_typescript_python_tooling_boundary() -> None:
    guide = (PACKAGE_ROOT / "docs" / "LANGUAGE_CAPABILITIES_UA.md").read_text(
        encoding="utf-8"
    )
    expected_rows = {
        "| JavaScript | `eslint` | `eslint` | `eslint --config eslint.config.js src` | `eslint.config.js` |",
        "| TypeScript | `typescript-compiler` | `tsc` | `tsc --noEmit --project tsconfig.json` | `tsconfig.json` |",
        "| JavaScript | `typedoc` | `typedoc` | `typedoc --options typedoc.json --out host-local-diagnostics/typedoc` | `typedoc.json` |",
        "| Python | `python-compileall` | `python` | `python -B -m compileall -q src` | none |",
        "| Python | `ruff` | `ruff` | `ruff check --config pyproject.toml src` | `pyproject.toml` |",
        "| Python | `mypy` | `mypy` | `mypy --config-file pyproject.toml src` | `pyproject.toml` |",
        "| Python | `sphinx` | `sphinx-build` | `sphinx-build -W -b html docs host-local-diagnostics/sphinx-html` | `docs/conf.py` |",
    }
    assert "| family | plan ID | executable | fixed argv | exact prerequisite |" in guide
    assert all(row in guide for row in expected_rows)
    false_claim_fields = {
        "acceptance_pass",
        "pass_credit",
        "product_acceptance_pass",
        "release_approved",
    }
    assert {field for field in false_claim_fields if f"`{field}=false`" in guide} == false_claim_fields


def _fake_tool_plan(tmp_path: Path, *, mutate_after_start: bool = False):
    script = tmp_path / "fake_tool.py"
    mutation = "\nopen(sys.executable, 'ab').write(b'\u0021')\n" if mutate_after_start else ""
    script.write_text(
        "import sys\n"
        "sys.stdout.buffer.write(bytes([102, 97, 107, 101, 45, 116, 111, 111, 108, 32, 49, 10]))\n"
        + mutation,
        encoding="utf-8",
    )
    executable = tmp_path / ("fake-python.exe" if os.name == "nt" else "fake-python")
    shutil.copy2(sys.executable, executable)
    plan = plan_language_tool(
        load_catalog(), language_id="c-family", tool_id="clang-tidy",
        action_id="static-analysis", root=tmp_path,
    )
    return replace(
        plan,
        executable=str(executable),
        argv=(str(executable), str(script)),
    ), executable


def test_probe_receipt_binds_executable_and_stream_digests(tmp_path: Path) -> None:
    plan, executable = _fake_tool_plan(tmp_path)
    receipt = probe_language_tool(plan, timeout_seconds=5)
    assert receipt.status == "AVAILABLE"
    assert receipt.executable_sha256 == hashlib.sha256(executable.read_bytes()).hexdigest()
    assert receipt.stdout_sha256 == hashlib.sha256(b"fake-tool 1\n").hexdigest()
    assert receipt.claims["pass_credit"] is False
    assert receipt.invoked is True


def test_probe_unavailable_has_no_substitute(tmp_path: Path) -> None:
    plan = plan_language_tool(
        load_catalog(), language_id="c-family", tool_id="clang-tidy",
        action_id="static-analysis", root=tmp_path,
    )
    missing = tmp_path / "missing-tool"
    missing_plan = replace(plan, executable=str(missing), argv=(str(missing),))
    receipt = probe_language_tool(missing_plan, timeout_seconds=1)
    assert receipt.status == "UNAVAILABLE"
    assert receipt.invoked is False


def test_probe_rejects_executable_drift(tmp_path: Path) -> None:
    plan, _ = _fake_tool_plan(tmp_path, mutate_after_start=True)
    assert probe_language_tool(plan, timeout_seconds=5).status == "FAILED"


def test_probe_bounds_stdout_and_hashes_stderr(tmp_path: Path) -> None:
    plan, executable = _fake_tool_plan(tmp_path)
    script = tmp_path / "streams.py"
    script.write_text("import sys\nsys.stdout.write('x' * 10000)\nsys.stderr.write('err')\n", encoding="utf-8")
    plan = replace(plan, argv=(str(executable), str(script)))
    receipt = probe_language_tool(plan, timeout_seconds=5, output_limit_bytes=32)
    assert receipt.status == "FAILED"
    assert receipt.stdout_size_bytes == 10000
    assert receipt.stdout_size_bytes > 32
    assert receipt.stderr_size_bytes == 3
    assert receipt.stderr_sha256 == hashlib.sha256(b"err").hexdigest()


def test_probe_nonzero_exit_and_argv_identity_mismatch(tmp_path: Path) -> None:
    plan, executable = _fake_tool_plan(tmp_path)
    script = tmp_path / "fail.py"
    script.write_text("import sys\nsys.exit(7)\n", encoding="utf-8")
    failed = probe_language_tool(replace(plan, argv=(str(executable), str(script))), timeout_seconds=5)
    assert failed.status == "FAILED"
    mismatch = replace(plan, argv=(sys.executable, str(script)))
    assert probe_language_tool(mismatch, timeout_seconds=5).invoked is False


def test_probe_timeout_with_executable_drift_is_failed(tmp_path: Path) -> None:
    plan, executable = _fake_tool_plan(tmp_path)
    script = tmp_path / "timeout.py"
    script.write_text(
        "import sys, time\nopen(sys.executable, 'ab').write(b'!')\ntime.sleep(10)\n",
        encoding="utf-8",
    )
    receipt = probe_language_tool(replace(plan, argv=(str(executable), str(script))), timeout_seconds=1)
    assert receipt.status == "FAILED"


def test_probe_timeout_does_not_wait_for_inherited_pipe(tmp_path: Path) -> None:
    plan, executable = _fake_tool_plan(tmp_path)
    script = tmp_path / "inherit_pipe.py"
    script.write_text(
        "import subprocess, sys, time\n"
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(3)'])\n"
        "time.sleep(10)\n",
        encoding="utf-8",
    )
    started = time.monotonic()
    receipt = probe_language_tool(
        replace(plan, argv=(str(executable), str(script))), timeout_seconds=1
    )
    elapsed = time.monotonic() - started
    assert receipt.status == "TIMED_OUT"
    assert receipt.stream_cleanup_completed is True
    assert elapsed < 5


def test_run_receipt_collects_declared_output_manifest(tmp_path: Path) -> None:
    if not _host_path_guard_available():
        pytest.skip("safe descriptor path guard unavailable")
    plan, executable = _fake_tool_plan(tmp_path)
    script = tmp_path / "write_output.py"
    script.write_text(
        "from pathlib import Path\n"
        "Path('docs/generated').mkdir(parents=True)\n"
        "Path('docs/generated/report.xml').write_bytes(b'<x/>')\n",
        encoding="utf-8",
    )
    plan = replace(
        plan,
        argv=(str(executable), str(script)),
        output_roots=("docs/generated",),
    )
    receipt = run_language_tool(plan, timeout_seconds=5)
    assert receipt.output_manifest == (
        {"path": "docs/generated/report.xml", "bytes": 4,
         "sha256": hashlib.sha256(b"<x/>").hexdigest()},
    )
    assert receipt.claims["acceptance_pass"] is False


def test_run_nonzero_exit_keeps_safe_manifest_and_false_credit(tmp_path: Path) -> None:
    if not _host_path_guard_available():
        pytest.skip("safe descriptor path guard unavailable")
    plan, executable = _fake_tool_plan(tmp_path)
    script = tmp_path / "write_then_fail.py"
    script.write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "Path('docs/generated').mkdir(parents=True)\n"
        "Path('docs/generated/report.xml').write_bytes(b'<x/>')\n"
        "sys.exit(7)\n",
        encoding="utf-8",
    )
    plan = replace(plan, argv=(str(executable), str(script)), output_roots=("docs/generated",))
    receipt = run_language_tool(plan, timeout_seconds=5)
    assert receipt.status == "FAILED"
    assert receipt.exit_code == 7
    assert receipt.output_manifest[0]["path"] == "docs/generated/report.xml"
    assert receipt.claims["acceptance_pass"] is False


def test_run_rejects_output_root_outside_project(tmp_path: Path) -> None:
    plan, _ = _fake_tool_plan(tmp_path)
    with pytest.raises(LanguageToolingError, match="output root"):
        run_language_tool(replace(plan, output_roots=("../escape",)), timeout_seconds=5)


def test_run_rejects_output_symlink(tmp_path: Path) -> None:
    if not _host_path_guard_available():
        pytest.skip("safe descriptor path guard unavailable")
    plan, executable = _fake_tool_plan(tmp_path)
    script = tmp_path / "write_link.py"
    script.write_text(
        "from pathlib import Path\n"
        "Path('docs/generated').mkdir(parents=True)\n"
        "Path('docs/generated/link').symlink_to(Path('outside.txt'))\n",
        encoding="utf-8",
    )
    (tmp_path / "outside.txt").write_bytes(b"outside")
    plan = replace(plan, argv=(str(executable), str(script)), output_roots=("docs/generated",))
    try:
        receipt = run_language_tool(plan, timeout_seconds=5)
    except OSError:
        pytest.skip("symbolic links unavailable")
    assert receipt.status == "FAILED"
    assert receipt.output_manifest == ()


def test_run_rejects_directory_replacement_during_scan(tmp_path: Path, monkeypatch) -> None:
    if not _host_path_guard_available():
        pytest.skip("safe descriptor path guard unavailable")
    plan, executable = _fake_tool_plan(tmp_path)
    script = tmp_path / "write_output.py"
    script.write_text(
        "from pathlib import Path\n"
        "Path('docs/generated').mkdir(parents=True)\n"
        "Path('docs/generated/report.xml').write_bytes(b'<x/>')\n",
        encoding="utf-8",
    )
    plan = replace(plan, argv=(str(executable), str(script)), output_roots=("docs/generated",))
    original_scandir = os.scandir
    replaced = False

    def racing_scandir(path):
        nonlocal replaced
        if Path(path).name == "generated" and not replaced:
            replaced = True
            moved = tmp_path / "docs" / "generated-original"
            Path(path).rename(moved)
            try:
                Path(path).symlink_to(tmp_path / "outside")
            except OSError:
                pytest.skip("symbolic links unavailable")
        return original_scandir(path)

    (tmp_path / "outside").mkdir()
    monkeypatch.setattr(os, "scandir", racing_scandir)
    receipt = run_language_tool(plan, timeout_seconds=5)
    assert receipt.status == "FAILED"
    assert receipt.output_manifest == ()


def test_run_fails_closed_without_host_path_guard(tmp_path: Path, monkeypatch) -> None:
    plan, executable = _fake_tool_plan(tmp_path)
    marker = tmp_path / "invoked.marker"
    script = tmp_path / "must_not_run.py"
    script.write_text(f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n", encoding="utf-8")
    plan = replace(plan, argv=(str(executable), str(script)), output_roots=("docs/generated",))
    monkeypatch.setattr("promin.language_tooling._host_path_guard_available", lambda: False)
    receipt = run_language_tool(plan, timeout_seconds=5)
    assert receipt.status == "UNAVAILABLE_HOST_PATH_GUARD"
    assert receipt.invoked is False
    assert receipt.output_manifest == ()
    assert not marker.exists()
    assert receipt.claims == {
        "acceptance_pass": False,
        "pass_credit": False,
        "product_acceptance_pass": False,
        "release_approved": False,
    }


def test_run_rejects_mutation_outside_declared_output_root(tmp_path: Path) -> None:
    if not _host_path_guard_available():
        pytest.skip("safe descriptor path guard unavailable")
    plan, executable = _fake_tool_plan(tmp_path)
    script = tmp_path / "mutate_source.py"
    script.write_text(
        "from pathlib import Path\n"
        "Path('docs/generated').mkdir(parents=True)\n"
        "Path('docs/generated/report.xml').write_bytes(b'<x/>')\n"
        "Path('source-changed.txt').write_bytes(b'changed')\n",
        encoding="utf-8",
    )
    plan = replace(plan, argv=(str(executable), str(script)), output_roots=("docs/generated",))
    receipt = run_language_tool(plan, timeout_seconds=5)
    assert receipt.status == "FAILED"
    assert receipt.failure_detail == "project_mutation_outside_declared_roots"
    assert receipt.output_manifest == ()
    assert receipt.claims["pass_credit"] is False

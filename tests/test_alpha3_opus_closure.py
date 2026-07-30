from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

import promin.portability as portability
from promin import __version__
from promin.__main__ import _parser, _run, main
from promin.audit import duplicate_name_markers
from promin.canonical import CanonicalError, require_regular_file
from promin.experience import apply_plan, detect_technologies, resolve_plan
from promin.platform_paths import windows_extended_path
from promin.portability import doctor_with_portability, host_binding, repair_project
from promin.provider_store import materialize_from_store, provider_store_root
from promin.system_check import remediation_commands, run_system_check


def _preflight(paths: list[str], *, samples: dict[str, str] | None = None) -> dict:
    return {
        "entries": [
            {"path": path, "kind": "file", "size_bytes": 1, "suffix": Path(path).suffix.casefold()}
            for path in paths
        ],
        "manifest_samples": samples or {},
        "truncated": False,
        "entry_count": len(paths),
        "bytes_read": 0,
        "max_files": 10_000,
        "max_bytes": 2 * 1024 * 1024,
        "max_depth": 2,
        "full_repository_scan": False,
        "git": {},
    }


def test_alpha3_version_and_python_projection() -> None:
    assert __version__ == "1.0.0-alpha.3"
    pyproject = Path(__file__).parents[1] / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    assert 'version = "1.0.0a3"' in text
    assert 'requires-python = ">=3.12,<3.15"' in text


def test_containment_accepts_root_alias_but_rejects_internal_link(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    target = real / "value.json"
    target.write_text("{}", encoding="utf-8")
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable")
    assert require_regular_file(alias / "value.json", root=alias) == target.resolve()

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "escape.json").write_text("{}", encoding="utf-8")
    internal = real / "internal"
    internal.symlink_to(outside, target_is_directory=True)
    with pytest.raises(CanonicalError):
        require_regular_file(alias / "internal" / "escape.json", root=alias)


def test_technology_sources_and_plan_are_bounded(tmp_path: Path) -> None:
    paths = [f"src/f{index:04d}.js" for index in range(5000)]
    facts, _signals = detect_technologies(_preflight(paths))
    javascript = next(item for item in facts if item["technology"] == "javascript")
    assert len(javascript["sources"]) == 64
    assert javascript["total_source_count"] == 5000
    assert javascript["sources_truncated"] is True

    src = tmp_path / "src"
    src.mkdir()
    for index in range(100):
        (src / f"f{index:03d}.js").write_text("x", encoding="utf-8")
    plan = resolve_plan(tmp_path, goal="Audit", max_preflight_files=256)
    assert len(json.dumps(plan, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) < 8192


def test_windows_extended_paths_are_normalized() -> None:
    assert windows_extended_path(r"C:\\very\\long\\path") == r"\\?\C:\very\long\path"
    assert windows_extended_path(r"\\server\\share\\path") == r"\\?\UNC\server\share\path"
    assert windows_extended_path(r"\\?\C:\already") == r"\\?\C:\already"


def test_host_os_does_not_change_canonical_plan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"react": "1"}}), encoding="utf-8")
    monkeypatch.setattr("promin.experience.platform.system", lambda: "Windows")
    windows = resolve_plan(tmp_path, goal="Audit")
    monkeypatch.setattr("promin.experience.platform.system", lambda: "Linux")
    linux = resolve_plan(tmp_path, goal="Audit")
    assert windows["profile_layers"] == linux["profile_layers"]
    assert windows["plan_digest"] == linux["plan_digest"]
    assert "windows-development" not in windows["profile_layers"]


def test_duplicate_markers_are_anchored() -> None:
    false = duplicate_name_markers(("bold.js", "golden.ts", "folder.py", "threshold.js"))
    assert false["total_count"] == 0
    real = duplicate_name_markers(("a.js", "a (2).js", "a.bak.js", "a_v2.js"))
    assert real["total_count"] == 3


def test_expo_workspace_is_mobile(tmp_path: Path) -> None:
    mobile = tmp_path / "mobile-app"
    mobile.mkdir()
    (mobile / "package.json").write_text(
        json.dumps({"dependencies": {"expo": "latest", "react-native": "latest", "react": "latest"}}),
        encoding="utf-8",
    )
    plan = resolve_plan(tmp_path, goal="Audit")
    unit = next(item for item in plan["workspace_map"]["units"] if item["path"] == "mobile-app")
    assert unit["kind"] == "mobile-application"
    assert "mobile-application" in unit["profile_layers"]
    assert "mobile-application" in plan["profile_layers"]


def test_failed_init_is_atomic_and_retryable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plan = resolve_plan(tmp_path, goal="Create")
    from promin.experience import ProminService

    original = ProminService.initialize
    calls = 0

    def reject_once(self, request):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("synthetic init failure")
        return original(self, request)

    monkeypatch.setattr(ProminService, "initialize", reject_once)
    with pytest.raises(RuntimeError, match="synthetic init failure"):
        apply_plan(tmp_path, plan)
    assert not (tmp_path / ".promin").exists()
    result = apply_plan(tmp_path, plan)
    assert result["status"] == "created"


def test_read_only_cli_does_not_create_control_state(tmp_path: Path) -> None:
    parser = _parser()
    review = _run(parser.parse_args(["--root", str(tmp_path), "init", "--goal", "Review"]))
    assert review["record_type"] == "GuidedInitReview"
    status = _run(parser.parse_args(["--root", str(tmp_path), "status"]))
    assert status["status"] == "not-initialized"
    audit = _run(parser.parse_args(["--root", str(tmp_path), "audit", "--max-files", "10"]))
    assert audit["record_type"] == "ProminRuntimeAudit"
    assert not (tmp_path / ".promin").exists()


def test_cli_help_and_all_remediations_are_parseable() -> None:
    parser = _parser()
    help_text = parser.format_help()
    assert "validate Core" in help_text
    assert "continue a bounded" in help_text
    assert parser.parse_args(["refresh", "--reset-derived"]).reset_derived is True
    for command in remediation_commands():
        parser.parse_args(command.split()[1:])


def test_uninitialized_messages_are_safe(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--root", str(tmp_path), "--no-telemetry", "status"]) == 0
    capsys.readouterr()
    for argv in (["validate"], ["next"], ["context", "query"]):
        assert main(["--root", str(tmp_path), "--no-telemetry", *argv]) == 2
        captured = capsys.readouterr()
        assert str(tmp_path) not in captured.err
        assert "promin init" in captured.err


def test_host_binding_tamper_is_degraded(tmp_path: Path) -> None:
    host_dir = tmp_path / ".promin" / "host"
    host_dir.mkdir(parents=True)
    value = host_binding()
    value["machine"] = "tampered"
    (host_dir / "host.json").write_text(json.dumps(value), encoding="utf-8")
    result = doctor_with_portability(tmp_path, replay=False)
    assert result["status"] == "degraded"
    assert result["host_binding_integrity"] == "invalid"
    assert result["repair_available"] is True


def test_repair_plan_matches_apply(tmp_path: Path) -> None:
    plan = resolve_plan(tmp_path, goal="Create")
    apply_plan(tmp_path, plan)
    projection = tmp_path / ".promin" / "state" / "projection"
    if projection.exists():
        shutil.rmtree(projection)
    planned = repair_project(tmp_path, apply=False)
    applied = repair_project(tmp_path, apply=True)
    assert [item["action"] for item in planned["actions"] if item.get("status") != "blocked"] == applied["performed"]


def test_clone_repair_resolves_portable_plan_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Clone repair must reuse doctor resolution rather than scanning twice."""

    plan = resolve_plan(tmp_path, goal="Create")
    apply_plan(tmp_path, plan)
    (tmp_path / ".promin" / "generated" / "resolved-plan.json").unlink()

    public_diagnosis = portability.doctor_with_portability(tmp_path, replay=False)
    assert "_resolved_plan" not in public_diagnosis

    original = portability.resolve_plan
    calls = 0

    def counted_resolve(*args: object, **kwargs: object) -> dict[str, object]:
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(portability, "resolve_plan", counted_resolve)
    repaired = portability.repair_project(tmp_path, apply=False)

    assert calls == 1
    assert not [item for item in repaired["actions"] if item.get("status") == "blocked"]


def test_system_check_exercises_bounded_init(tmp_path: Path) -> None:
    plan = resolve_plan(tmp_path, goal="Create")
    apply_plan(tmp_path, plan)
    result = run_system_check(tmp_path)
    check = next(item for item in result["checks"] if item["check_id"] == "SYS-INIT-PATH-001")
    assert check["status"] == "pass"
    assert check["evidence"]["record_type"] in {"InitializationResult", "InitResult"}


def test_shared_provider_store_reuses_blob(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "python.exe"
    source.write_bytes(b"provider")
    import hashlib
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    monkeypatch.setenv("PROMIN_PROVIDER_STORE", str(tmp_path / "store"))
    first = tmp_path / "one" / "payload.exe"
    second = tmp_path / "two" / "payload.exe"
    materialize_from_store(source, first, digest)
    materialize_from_store(source, second, digest)
    assert first.read_bytes() == second.read_bytes() == b"provider"
    first.write_bytes(b"tampered-project-receipt")
    third = tmp_path / "three" / "payload.exe"
    materialize_from_store(source, third, digest)
    assert third.read_bytes() == b"provider"


def test_latency_contracts_are_canonical() -> None:
    conformance = json.loads((Path(__file__).parents[1] / "core" / "conformance.json").read_text(encoding="utf-8"))
    records = conformance["command_latency_contracts"]
    assert any(record["command"] == "next" and record["budget_ms"] <= 2000 for record in records)
    assert any(record["command"] == "init review" and record["budget_ms"] <= 5000 for record in records)


def test_host_python_binding_uses_installed_base_executable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import promin.experience as experience
    import hashlib

    base = tmp_path / "base-python.exe"
    base.write_bytes(b"base-python")
    venv = tmp_path / "venv-python.exe"
    venv.write_bytes(b"venv-launcher-needs-pyvenv")
    monkeypatch.setattr(experience.sys, "_base_executable", str(base), raising=False)
    monkeypatch.setattr(experience.sys, "executable", str(venv))
    project = tmp_path / "project"
    project.mkdir()
    source_value, bound = experience._materialize_host_python(project)
    assert source_value == str(base)
    assert bound == base
    assert bound.read_bytes() != venv.read_bytes()
    assert not bound.is_relative_to(project)
    assert hashlib.sha256(bound.read_bytes()).hexdigest() == hashlib.sha256(base.read_bytes()).hexdigest()


def test_provider_receipt_path_is_bounded_for_deep_windows_root(tmp_path: Path) -> None:
    from promin.init import _provider_receipt_path

    deep = Path("C:/") / ("x" * 120) / ".promin" / "providers"
    binding = {
        "provider_id": "alpha-python",
        "identity": {"digest": "a" * 64, "source": "python.exe"},
    }
    receipt = _provider_receipt_path(deep, binding)
    assert len(receipt.parent.name) == 24
    assert len(str(receipt)) < 260
    assert windows_extended_path(str(receipt)).startswith("\\\\?\\")


@pytest.mark.skipif(os.name != "nt", reason="Windows junction behavior")
def test_windows_junction_root_alias_is_supported(tmp_path: Path) -> None:
    import subprocess

    real = tmp_path / "real"
    real.mkdir()
    (real / "value.json").write_text("{}", encoding="utf-8")
    alias = tmp_path / "alias"
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(alias), str(real)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip("junction creation unavailable")
    assert require_regular_file(alias / "value.json", root=alias) == (real / "value.json").resolve()


def test_shared_provider_store_recovers_from_corrupted_hardlink(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "provider.bin"
    source.write_bytes(b"trusted-provider-bytes")
    import hashlib

    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    store = tmp_path / "store"
    monkeypatch.setenv("PROMIN_PROVIDER_STORE", str(store))

    first = tmp_path / "first" / "provider.bin"
    materialize_from_store(source, first, digest)
    # Simulate a hostile/local write through a project receipt.  The shared
    # store is a cache, not authority: a subsequent materialization must repair
    # from the still-verified source rather than propagating corrupt bytes.
    os.chmod(first, 0o700)
    first.write_bytes(b"corrupt")

    repaired = tmp_path / "repaired" / "provider.bin"
    materialize_from_store(source, repaired, digest)
    assert repaired.read_bytes() == b"trusted-provider-bytes"
    assert hashlib.sha256(repaired.read_bytes()).hexdigest() == digest


# Alpha.3 closure regressions
def test_windows_extended_prefix_is_neutral_for_identity() -> None:
    from promin.platform_paths import normalize_identity_text

    plain = r"C:\\provider-store\\ab\\payload.exe"
    extended = r"\\?\C:\provider-store\ab\payload.exe"
    assert normalize_identity_text(plain) == normalize_identity_text(extended)

    unc = r"\\server\share\provider.exe"
    extended_unc = r"\\?\UNC\server\share\provider.exe"
    assert normalize_identity_text(unc) == normalize_identity_text(extended_unc)


def test_provider_store_root_resolves_default_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    physical = tmp_path / "physical-cache"
    physical.mkdir()
    alias = tmp_path / "cache-alias"
    try:
        alias.symlink_to(physical, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlink unavailable")

    monkeypatch.delenv("PROMIN_PROVIDER_STORE", raising=False)
    monkeypatch.setattr("promin.provider_store._platform", lambda: "linux")
    monkeypatch.setenv("XDG_CACHE_HOME", str(alias))

    assert provider_store_root() == (physical / "promin" / "provider-store-v1").resolve()


def test_provider_layer_has_one_path_identity_owner() -> None:
    source = (Path(__file__).parents[1] / "promin" / "init.py").read_text(
        encoding="utf-8"
    )
    assert "def _provider_path" not in source
    assert "def _configured_provider_path" not in source
    assert ".resolve(strict=True)" not in source or "resolve_identity_path" in source
    assert "os.path.abspath" not in source


def test_global_technology_source_budget_is_shared_across_all_technologies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    suffixes = ["js", "ts", "py", "kt", "java", "cpp", "cs", "rs", "go", "swift"]
    paths = [f"apps/{suffix}/nested-segment-nested-segment-nested-segment/file-{index:04d}.{suffix}" for suffix in suffixes for index in range(500)]
    preflight = _preflight(paths)
    technologies, _signals = detect_technologies(preflight)

    assert len(paths) == 5000
    assert sum(len(item["sources"]) for item in technologies) <= 64
    counts = {item["technology"]: item["total_source_count"] for item in technologies}
    assert counts["javascript"] == 500
    assert counts["typescript"] == 500
    assert counts["python"] == 500
    assert all(item["sources_truncated"] is True for item in technologies)

    monkeypatch.setattr("promin.experience.bounded_preflight", lambda *args, **kwargs: preflight)
    plan = resolve_plan(tmp_path, goal="Audit a mixed technology repository")
    encoded = json.dumps(plan, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert len(encoded) <= 8192


def test_every_latency_contract_has_an_explicit_measured_workload() -> None:
    conformance = json.loads(
        (Path(__file__).parents[1] / "core" / "conformance.json").read_text(
            encoding="utf-8"
        )
    )
    records = conformance["command_latency_contracts"]
    assert records
    for record in records:
        assert record["measurement_mode"] in {"cli_cold", "runtime_warm", "operation_incremental"}
        assert isinstance(record["max_files"], int) and record["max_files"] >= 0
        assert isinstance(record["workload_id"], str) and record["workload_id"]
        assert record["percentile"] == "p95"
        assert record["measured_runs"] > 0


def test_alpha3_version_is_canonical() -> None:
    manifest = json.loads(
        (Path(__file__).parents[1] / "core" / "promin.manifest.json").read_text(
            encoding="utf-8"
        )
    )
    assert manifest["version"] == "1.0.0-alpha.3"

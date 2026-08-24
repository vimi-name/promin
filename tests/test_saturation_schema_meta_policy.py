from __future__ import annotations

import ast
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SATURATION_SOURCE = PACKAGE_ROOT / "tools" / "promin_saturation.py"
INIT_SOURCE = PACKAGE_ROOT / "promin" / "init.py"


def _calls_in(function_name: str) -> list[ast.Call]:
    tree = ast.parse(SATURATION_SOURCE.read_text(encoding="utf-8"))
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == function_name
    )
    return [node for node in ast.walk(function) if isinstance(node, ast.Call)]


def _has_false_keyword(call: ast.Call, name: str) -> bool:
    return any(
        keyword.arg == name
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is False
        for keyword in call.keywords
    )


def test_saturation_init_reuses_candidate_schema_meta_admission() -> None:
    """The exact package gate owns schema meta-validation before a 100k run."""

    canonical_calls = _calls_in("_canonical_saturation_project_plan")
    init_calls = _calls_in("_make_saturation_init_plan")
    workspace_calls = _calls_in("_initialize_saturation_workspace")

    assert any(
        isinstance(call.func, ast.Name)
        and call.func.id == "load_contract_bundle"
        and _has_false_keyword(call, "verify_schema_meta")
        for call in canonical_calls
    )
    assert any(
        isinstance(call.func, ast.Name)
        and call.func.id == "load_contract_bundle"
        and _has_false_keyword(call, "verify_schema_meta")
        for call in init_calls
    )
    assert any(
        isinstance(call.func, ast.Name)
        and call.func.id == "make_plan"
        and _has_false_keyword(call, "verify_schema_meta")
        for call in init_calls
    )
    assert any(
        isinstance(call.func, ast.Name)
        and call.func.id == "apply_plan"
        and _has_false_keyword(call, "verify_schema_meta")
        for call in workspace_calls
    )


def test_jsonschema_receipt_hashes_the_full_distribution_without_thread_startup() -> None:
    """Weak-host init keeps the same receipt coverage without executor liveness risk."""

    tree = ast.parse(INIT_SOURCE.read_text(encoding="utf-8"))
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_jsonschema_receipt"
    )
    names = {node.id for node in ast.walk(function) if isinstance(node, ast.Name)}

    assert "ThreadPoolExecutor" not in names
    assert "_digest_verified_file" in names


def test_provider_receipt_batches_directory_durability_after_full_component_copy() -> None:
    """A staged provider receipt does not fsync the same directory per file."""

    tree = ast.parse(INIT_SOURCE.read_text(encoding="utf-8"))
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
    }
    copy_names = {
        node.id
        for node in ast.walk(functions["_copy_provider_receipt"])
        if isinstance(node, ast.Name)
    }
    materialize_names = {
        node.id
        for node in ast.walk(functions["_materialize_dependency_component"])
        if isinstance(node, ast.Name)
    }

    assert "fsync_directory" not in copy_names
    assert "fsync_directory" in materialize_names


def test_receipted_python_runtime_healthcheck_prefers_verified_host_identity() -> None:
    """Copied Python payloads are evidence, not standalone interpreter binaries."""

    tree = ast.parse(INIT_SOURCE.read_text(encoding="utf-8"))
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "verify_provider_preflight"
    )
    names = {node.id for node in ast.walk(function) if isinstance(node, ast.Name)}

    assert "healthcheck_binding" in names
    assert "source_binding" in names

    matching_calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_matching_provider_source"
    ]
    assert any(
        call.args
        and isinstance(call.args[0], ast.Name)
        and call.args[0].id == "healthcheck_binding"
        for call in matching_calls
    )


def test_saturation_provider_healthchecks_allow_a_bounded_cold_start() -> None:
    """Exact saturation must not reject a real Windows provider on a 5s cold start."""

    source = SATURATION_SOURCE.read_text(encoding="utf-8")

    assert "_SATURATION_PROVIDER_HEALTHCHECK_TIMEOUT_MS = 30_000" in source
    assert source.count(
        '"timeout_ms": _SATURATION_PROVIDER_HEALTHCHECK_TIMEOUT_MS'
    ) == 2


def test_init_preflight_does_not_rescan_just_verified_provider_receipts() -> None:
    """Receipt identity reuses the transaction's completed full verification."""

    tree = ast.parse(INIT_SOURCE.read_text(encoding="utf-8"))
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
    }
    preflight_calls = [
        node
        for node in ast.walk(functions["_preflight_init_inputs"])
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_init_input_identity"
    ]

    assert any(
        any(
            keyword.arg == "provider_receipts_verified"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in call.keywords
        )
        for call in preflight_calls
    )


def test_semantic_corpus_uses_one_bounded_verified_commit_phase() -> None:
    """Bootstrap and search corpus commands must not reopen public mutation admission."""

    tree = ast.parse(SATURATION_SOURCE.read_text(encoding="utf-8"))
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_ensure_semantic_corpus"
    )
    calls = [node for node in ast.walk(function) if isinstance(node, ast.Call)]

    assert any(
        isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "runtime"
        and call.func.attr == "begin_verified_commit_phase"
        for call in calls
    )
    assert any(
        isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "commit_phase"
        and call.func.attr == "commit"
        for call in calls
    )

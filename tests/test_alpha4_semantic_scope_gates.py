from __future__ import annotations

from promin.semantic_scope import (
    affected_semantic_scope,
    build_module_graph,
)
from promin.language_analysis import GateStatus


def test_affected_scope_is_exact_bounded_and_bound_to_compilation_database() -> None:
    graph = build_module_graph(
        {
            "src/a.cpp": ("src/b.cpp", "src/c.cpp"),
            "src/b.cpp": ("src/d.cpp",),
            "src/c.cpp": (),
            "src/d.cpp": (),
        }
    )
    scope = affected_semantic_scope(
        changed_paths=("src/a.cpp",),
        graph=graph,
        compilation_database_digest="a" * 64,
        compilation_database_sources=("src/a.cpp", "src/b.cpp", "src/c.cpp", "src/d.cpp"),
        max_depth=2,
        max_files=8,
    )

    assert scope.status is GateStatus.PASS
    assert scope.paths == ("src/a.cpp", "src/b.cpp", "src/c.cpp", "src/d.cpp")
    assert scope.truncated is False
    assert scope.compilation_database_digest == "a" * 64

    bounded = affected_semantic_scope(
        changed_paths=("src/a.cpp",),
        graph=graph,
        compilation_database_digest="a" * 64,
        compilation_database_sources=("src/a.cpp", "src/b.cpp", "src/c.cpp", "src/d.cpp"),
        max_depth=2,
        max_files=2,
    )
    assert bounded.status is GateStatus.UNAVAILABLE
    assert bounded.truncated is True
    assert bounded.paths == ("src/a.cpp", "src/b.cpp")


def test_scope_rejects_compilation_database_identity_gap() -> None:
    graph = build_module_graph({"src/a.cpp": ("src/b.cpp",), "src/b.cpp": ()})
    scope = affected_semantic_scope(
        changed_paths=("src/a.cpp",),
        graph=graph,
        compilation_database_digest="b" * 64,
        compilation_database_sources=("src/a.cpp",),
        max_depth=1,
        max_files=4,
    )

    assert scope.status is GateStatus.FAIL
    assert any("does not cover" in error for error in scope.errors)


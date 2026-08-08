from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from promin.canonical import canonical_bytes
from promin.project_package import ProjectPackageError, verify_project_package


def _write_canonical(path: Path, value: object) -> None:
    path.write_bytes(canonical_bytes(value))


def _member(source_path: str, target_path: str, member_class: str, payload: bytes) -> dict[str, object]:
    return {
        "source_path": source_path,
        "target_path": target_path,
        "member_class": member_class,
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "mode": 0o644,
    }


def _make_package(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    root = tmp_path / "portable-package"
    docs = root / "seeds" / "docs"
    extension = root / "seeds" / "extensions" / "markdown"
    docs.mkdir(parents=True)
    extension.mkdir(parents=True)
    readme_payload = b"Portable alpha4 documentation.\n"
    extension_payload = b'{"render":"strict"}\n'
    (docs / "README.md").write_bytes(readme_payload)
    (extension / "config.json").write_bytes(extension_payload)
    members = [
        _member(
            "seeds/docs/README.md",
            ".promin/docs/README.md",
            "portable-doc",
            readme_payload,
        ),
        _member(
            "seeds/extensions/markdown/config.json",
            ".promin/docs/extensions/markdown/config.json",
            "typed-extension",
            extension_payload,
        ),
    ]
    tree_rows = [
        {
            key: member[key]
            for key in (
                "source_path",
                "target_path",
                "member_class",
                "bytes",
                "sha256",
                "mode",
            )
        }
        for member in members
    ]
    base = {
        "schema": "promin.project-package.v1",
        "package_id": "portable-alpha4",
        "package_version": "1.0.0-alpha.4",
        "standard_version": "1.0.0-alpha.4",
        "default_profile": "minimal",
        "profiles": ["minimal", "standard"],
        "tracked_extension_roots": [".promin/docs"],
        "operational_roots": [
            ".promin/cache",
            ".promin/evidence",
            ".promin/init",
            ".promin/leases",
            ".promin/locks",
            ".promin/providers",
            ".promin/state",
        ],
        "state_migration_supported": False,
        "previous_progress_replay_supported": False,
    }
    content: dict[str, object] = {
        "schema": "promin.project-package-content.v1",
        "package_id": base["package_id"],
        "package_version": base["package_version"],
        "seed_surfaces": [
            {
                "surface_id": "docs",
                "surface_kind": "portable-doc",
                "source_root": "seeds/docs",
                "target_root": ".promin/docs",
            },
            {
                "surface_id": "extension-markdown",
                "surface_kind": "typed-extension",
                "source_root": "seeds/extensions/markdown",
                "target_root": ".promin/docs/extensions/markdown",
            },
        ],
        "host_integrations": [],
        "members": members,
        "tree_sha256": hashlib.sha256(canonical_bytes(tree_rows)).hexdigest(),
    }
    _write_canonical(root / "project-package.json", base)
    _write_canonical(root / "project-package-content.json", content)
    return root, content


def test_project_package_binds_exact_typed_seed_tree(tmp_path: Path) -> None:
    root, _ = _make_package(tmp_path)

    verified = verify_project_package(root)

    assert verified.package_id == "portable-alpha4"
    assert verified.member_count == 2
    assert verified.total_bytes > 0
    assert verified.tracked_extension_roots == (".promin/docs",)
    receipt = verified.receipt()
    assert receipt["state_migration_supported"] is False
    assert receipt["previous_progress_replay_supported"] is False
    assert receipt["acceptance_pass"] is False
    assert receipt["pass_credit"] is False


def test_project_package_rejects_member_payload_tampering(tmp_path: Path) -> None:
    root, _ = _make_package(tmp_path)
    (root / "seeds" / "docs" / "README.md").write_bytes(b"Changed after binding.\n")

    with pytest.raises(ProjectPackageError, match="bytes or sha256"):
        verify_project_package(root)


def test_project_package_rejects_undeclared_seed_file(tmp_path: Path) -> None:
    root, _ = _make_package(tmp_path)
    (root / "seeds" / "docs" / "unbound.md").write_bytes(b"unbound\n")

    with pytest.raises(ProjectPackageError, match="exact typed member manifest"):
        verify_project_package(root)


def test_project_package_rejects_sibling_extension_control_root(tmp_path: Path) -> None:
    root, content = _make_package(tmp_path)
    content["seed_surfaces"][1]["target_root"] = ".promin/extensions/markdown"  # type: ignore[index]
    _write_canonical(root / "project-package-content.json", content)

    with pytest.raises(ProjectPackageError, match="docs/extensions"):
        verify_project_package(root)


def test_project_package_rejects_unbound_tree_digest(tmp_path: Path) -> None:
    root, content = _make_package(tmp_path)
    content["tree_sha256"] = "0" * 64
    _write_canonical(root / "project-package-content.json", content)

    with pytest.raises(ProjectPackageError, match="tree_sha256"):
        verify_project_package(root)


def test_project_package_rejects_noncanonical_member_mode(tmp_path: Path) -> None:
    root, content = _make_package(tmp_path)
    content["members"][0]["mode"] = 0o600  # type: ignore[index]
    _write_canonical(root / "project-package-content.json", content)

    with pytest.raises(ProjectPackageError, match="canonical regular-file mode"):
        verify_project_package(root)

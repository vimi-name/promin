from __future__ import annotations

from pathlib import Path

import pytest

from promin.canonical import CanonicalError, require_regular_file
import promin.platform_paths as platform_paths


def test_regular_file_reuses_unchanged_root_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "receipts"
    root.mkdir()
    files = []
    for index in range(3):
        path = root / f"component-{index}.json"
        path.write_text("{}", encoding="utf-8")
        files.append(path)

    platform_paths._root_identity_cache.clear()
    calls = 0
    original = platform_paths.resolve_identity_path

    def counted(value: str | Path, **kwargs: object) -> Path:
        nonlocal calls
        calls += 1
        return original(value, **kwargs)

    monkeypatch.setattr(platform_paths, "resolve_identity_path", counted)
    assert [require_regular_file(path, root=root) for path in files] == [
        path.resolve() for path in files
    ]

    # Every file still receives its own resolved containment check.  The root
    # identity is the only repeated lookup removed from this operation.
    assert calls == len(files) + 1


def test_regular_file_invalidates_cached_root_after_replacement(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "receipt.json").write_text('{"origin":"first"}', encoding="utf-8")
    expected = root / "receipt.json"
    retired = tmp_path / "retired-root"

    platform_paths._root_identity_cache.clear()
    assert require_regular_file(expected, root=root).read_text(encoding="utf-8") == (
        '{"origin":"first"}'
    )
    root.rename(retired)
    root.mkdir()
    expected.write_text('{"origin":"second"}', encoding="utf-8")

    # Re-statting the lexical root on every use prevents a stale root identity
    # from authorizing a replacement at the same lexical path.
    assert require_regular_file(expected, root=root) == expected.resolve()
    assert require_regular_file(expected, root=root).read_text(
        encoding="utf-8"
    ) == '{"origin":"second"}'


def test_regular_file_cache_keeps_internal_link_rejection(tmp_path: Path) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "escape.json").write_text("{}", encoding="utf-8")
    internal = root / "internal"
    try:
        internal.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable")

    platform_paths._root_identity_cache.clear()
    with pytest.raises(CanonicalError, match="symbolic link or reparse point rejected"):
        require_regular_file(internal / "escape.json", root=root)

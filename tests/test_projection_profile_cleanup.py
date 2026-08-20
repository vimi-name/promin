from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from tools import promin_projection_profile as profile


pytestmark = pytest.mark.skipif(
    os.name != "nt",
    reason="the extended cleanup spelling is required only for Windows paths",
)


def test_profile_cleans_a_long_fixed_profile_work_root(tmp_path: Path) -> None:
    """A completed fixed-size profile cleans a long derived-index path.

    The real Windows diagnostic run completed all three selected profiles and
    wrote its report before ``TemporaryDirectory`` encountered WinError 145
    while removing an EventStore derived-index ``packages`` directory.  This
    keeps the public CLI path intact while reproducing that lifecycle boundary
    with the smallest fixed profile.
    """

    output = tmp_path / "projection-profile.json"

    assert profile.main(
        [
            "--size",
            "1000",
            "--work-root",
            str(tmp_path),
            "--output",
            str(output),
        ]
    ) == 0
    assert output.is_file()
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["status"] == "diagnostic-only"
    assert report["executed_sizes"] == [1_000]
    assert report["pass_credit"] is False
    assert not list(tmp_path.glob("promin-projection-profile-*"))

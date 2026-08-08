from __future__ import annotations

from pathlib import Path

from promin.skills import create_skill, remove_skill, request_skill, skill_catalog


def test_project_skill_lifecycle_is_portable_bounded_and_non_authoritative(tmp_path: Path) -> None:
    created = create_skill(
        tmp_path,
        name="security-review",
        description="Review a bounded change for security regressions.",
        body="# Security review\n\nInspect only the Task scope and return evidence.\n",
        capabilities=("review.security",),
        security_scope="read-only",
        portable=True,
    )
    assert created["status"] == "created"
    assert created["authority"] is False
    assert created["pass_credit"] is False

    catalog = skill_catalog(tmp_path)
    project_skills = [
        item for item in catalog["skills"]
        if item["catalog_source"] == "project-docs"
    ]
    assert [item["skill_id"] for item in project_skills] == ["security-review"]
    request = request_skill(tmp_path, requirement="security review")
    assert request["status"] == "matched"
    assert request["matching_installed_skills"][0]["skill_id"] == "security-review"

    removed = remove_skill(tmp_path, name="security-review", portable=True)
    assert removed["status"] == "removed"
    remaining = skill_catalog(tmp_path)["skills"]
    assert not any(item["catalog_source"] == "project-docs" for item in remaining)

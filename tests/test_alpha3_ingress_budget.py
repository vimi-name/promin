from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from promin.canonical import digest_value
from promin.contracts import (
    ContractError,
    compile_project_init,
    load_contract_bundle,
    validate_definition,
    validate_ingress,
    validate_plan_objects,
)


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
PRESET = PACKAGE_ROOT / "presets" / "semantic-standard.json"


def _project_init() -> tuple[object, dict[str, object]]:
    bundle = load_contract_bundle(PACKAGE_ROOT, PRESET)
    value = compile_project_init(
        {
            "record_type": "ProjectInit",
            "project_id": "ingress-budget",
            "roots": [{"path": ".", "kind": "product"}],
            "candidate_recipe": {
                "inventory_mode": "explicit",
                "include": ["src/**"],
                "exclude": [".promin/**"],
                "symlink_policy": "reject",
                "path_identity": "nfc-posix-relative",
                "collision_policy": "reject-nfc-and-casefold-collisions",
                "product_identity_excludes_control_state": True,
            },
            "preset_id": "semantic-standard",
            "operating_profile": "baseline",
        },
        bundle,
    )
    return bundle, value


def _with_source_samples(value: dict[str, object], *, technologies: int, samples: int) -> dict[str, object]:
    candidate = deepcopy(value)
    profile = candidate["resolved_profile"]
    assert isinstance(profile, dict)
    profile["detected_technologies"] = [
        {
            "technology": f"technology-{technology_index:03d}",
            "sources": [
                f"src/technology-{technology_index:03d}/file-{source_index:03d}.py"
                for source_index in range(samples)
            ],
            "total_source_count": samples,
            "sources_truncated": False,
            "source_count_complete": True,
            "confidence": 1.0,
        }
        for technology_index in range(technologies)
    ]
    profile_identity = {key: item for key, item in profile.items() if key != "profile_digest"}
    profile["profile_digest"] = digest_value(profile_identity)
    return candidate


def test_project_init_ingress_rejects_8192_source_samples() -> None:
    bundle, base = _project_init()
    assert isinstance(base, dict)
    candidate = _with_source_samples(base, technologies=128, samples=64)

    # The per-fact schema limits alone accept 128 * 64.  The aggregate Core
    # budget must still fail closed at every direct ProjectInit ingress.
    validate_definition(bundle.schema, "ProjectInit", candidate)
    with pytest.raises(ContractError, match="source sample budget exceeded: 8192>64"):
        compile_project_init(candidate, bundle)
    with pytest.raises(ContractError, match="source sample budget exceeded: 8192>64"):
        validate_ingress(bundle, candidate, operation="import")

    plans = {
        "project.json": candidate,
        "standards.json": {"record_type": "StandardsInit", "bindings": []},
        "technologies.json": {"record_type": "TechnologiesInit", "bindings": []},
        "authority.json": {
            "record_type": "AuthorityInit",
            "trust_mode": "local-owner",
            "subjects": [{"subject_id": "owner", "kind": "human", "display_name": "Owner"}],
            "roots": [
                {
                    "subject_id": "owner",
                    "capability_ceiling": ["standard.activate"],
                    "scope": [{"kind": "project", "value": "ingress-budget"}],
                }
            ],
        },
    }
    with pytest.raises(ContractError, match="source sample budget exceeded: 8192>64"):
        validate_plan_objects(plans, bundle, {"record_type": "LicensesPlan", "bindings": []})

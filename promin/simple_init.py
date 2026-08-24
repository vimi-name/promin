"""Small, deterministic initialization surface for the alpha.4 experience.

The default route deliberately resolves only a small bounded preflight and the
minimal catalog-backed capability selection.  Callers that need a different
goal, autonomy, language, profile layer, or preflight ceiling must provide an
``AdvancedInitConfiguration`` explicitly.  Project writes still go through
the canonical ``experience.apply_plan`` route.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .experience import apply_plan, bind_init_capability_selection, resolve_plan
from .init_profiles import (
    InitProfileError,
    load_init_profile,
    resolve_init_experience,
)
from .language_catalog import languages_for_detected_technologies
from .limits import PREFLIGHT_FILE_ITEMS_MAX
from .resources import bundle_root


DEFAULT_SIMPLE_PREFLIGHT_FILES = 128
_CAPABILITY_PROFILE = "capability_profiles/standard-init.json"


@dataclass(frozen=True)
class AdvancedInitConfiguration:
    """Explicit overrides for callers that need more than simple init."""

    goal: str | None = None
    autonomy: str | None = None
    language: str | None = None
    profiles: tuple[str, ...] = ()
    brief: Mapping[str, Any] | None = None
    max_preflight_files: int = DEFAULT_SIMPLE_PREFLIGHT_FILES


def _validate_configuration(
    configuration: AdvancedInitConfiguration | None,
) -> AdvancedInitConfiguration:
    if configuration is None:
        return AdvancedInitConfiguration()
    if not isinstance(configuration, AdvancedInitConfiguration):
        raise TypeError("configuration must be AdvancedInitConfiguration")
    if (
        isinstance(configuration.max_preflight_files, bool)
        or not isinstance(configuration.max_preflight_files, int)
        or not 1 <= configuration.max_preflight_files <= PREFLIGHT_FILE_ITEMS_MAX
    ):
        raise ValueError(
            "max_preflight_files must be an integer from 1 through "
            f"{PREFLIGHT_FILE_ITEMS_MAX}"
        )
    if configuration.autonomy not in {None, "ask", "standing-reversible"}:
        raise ValueError("autonomy must be ask or standing-reversible")
    if configuration.language not in {None, "auto", "uk", "en"}:
        raise ValueError("language must be auto, uk, or en")
    if configuration.goal is not None and (
        not isinstance(configuration.goal, str) or not configuration.goal.strip()
    ):
        raise ValueError("goal must be a non-empty string when provided")
    if not isinstance(configuration.profiles, tuple) or any(
        not isinstance(profile, str) or not profile for profile in configuration.profiles
    ):
        raise ValueError("profiles must be a tuple of non-empty profile IDs")
    return configuration


def _minimal_capability_selection(
    plan: Mapping[str, Any], configuration: AdvancedInitConfiguration
) -> dict[str, Any]:
    profile = load_init_profile(bundle_root() / _CAPABILITY_PROFILE)
    languages = languages_for_detected_technologies(
        str(item.get("technology", "")).casefold()
        for item in plan.get("detected_technologies", [])
        if isinstance(item, Mapping)
    )
    cli_override = (
        None
        if configuration.autonomy is None
        else {"autonomy": configuration.autonomy}
    )
    try:
        resolved = resolve_init_experience(
            profile,
            experience="minimal",
            languages=languages,
            cli_override=cli_override,
        )
    except InitProfileError as exc:
        raise ValueError(f"minimal capability selection is invalid: {exc}") from exc
    return {
        "status": "UNAVAILABLE",
        "selection_source": "cli" if cli_override is not None else "default",
        "profile_digest": resolved["profile"]["profile_digest"],
        "selection_digest": resolved["experience_digest"],
        "authority_granted": False,
        "pass_credit": False,
        "acceptance_pass": False,
    }


def build_simple_init_plan(
    project_root: Path | str,
    configuration: AdvancedInitConfiguration | None = None,
) -> dict[str, Any]:
    """Build a real minimal init plan without mutating the project root."""

    selected = _validate_configuration(configuration)
    plan = resolve_plan(
        project_root,
        goal=selected.goal,
        autonomy=selected.autonomy,
        language=selected.language,
        explicit_profiles=selected.profiles,
        brief=selected.brief,
        max_preflight_files=selected.max_preflight_files,
    )
    return bind_init_capability_selection(
        plan,
        _minimal_capability_selection(plan, selected),
    )


def apply_simple_init(
    project_root: Path | str,
    configuration: AdvancedInitConfiguration | None = None,
) -> dict[str, Any]:
    """Apply a simple plan through the canonical alpha.4 initialization path."""

    plan = build_simple_init_plan(project_root, configuration)
    result = apply_plan(project_root, plan)
    return {
        **result,
        "mode": "simple",
        "authority": False,
        "authority_granted": False,
        "pass_credit": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
        "simple_init": {
            "preflight_max_files": plan["preflight"]["max_files"],
            "capability_status": plan["init_capability_selection"]["status"],
        },
    }


__all__ = [
    "AdvancedInitConfiguration",
    "DEFAULT_SIMPLE_PREFLIGHT_FILES",
    "apply_simple_init",
    "build_simple_init_plan",
]

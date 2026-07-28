from __future__ import annotations

import fnmatch
import hashlib
import unicodedata
from collections import OrderedDict, defaultdict
from copy import deepcopy
from dataclasses import dataclass
from functools import cached_property
import threading
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping, MutableMapping, Sequence

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError

from .canonical import (
    CanonicalError,
    canonical_bytes,
    digest_file,
    digest_value,
    ensure_exact_regular_files,
    load_json_strict,
    parse_json_strict,
)


CORE_FILES = (
    "promin.manifest.json",
    "semantic-model.json",
    "authority-model.json",
    "policy-set.json",
    "contracts.schema.json",
    "conformance.json",
)
PLAN_FILES = ("project.json", "standards.json", "technologies.json", "authority.json")
INIT_FILES = PLAN_FILES + ("activation.json",)
BASE_USER_COMMANDS = ("init", "doctor", "status", "next", "validate", "continue", "audit", "refresh", "context", "skills")
OBSERVATIONAL_CONSISTENCY = "observational-best-effort"
IMMUTABLE_SNAPSHOT_CONSISTENCY = frozenset({"immutable-vcs-tree"})
SNAPSHOT_CONSISTENCY_MODES = frozenset(
    {OBSERVATIONAL_CONSISTENCY, *IMMUTABLE_SNAPSHOT_CONSISTENCY}
)


class ContractError(CanonicalError):
    """Raised when structurally valid JSON violates Promin contracts."""


def _posix_relative_text(value: str | PurePosixPath, *, label: str) -> tuple[str, str]:
    if isinstance(value, PurePosixPath):
        raw = value.as_posix()
    elif isinstance(value, str):
        raw = value
    else:
        raise ContractError(f"{label} must be a POSIX relative string")
    if not raw or len(raw) > 4096 or raw.startswith("/") or "\\" in raw:
        raise ContractError(f"{label} must be an anchored POSIX relative path")
    if len(raw) >= 2 and raw[0].isalpha() and raw[1] == ":":
        raise ContractError(f"{label} must not contain a drive-qualified path")
    parts = raw.split("/")
    if any(not part or part in {".", ".."} or "\x00" in part for part in parts):
        raise ContractError(f"{label} contains a forbidden path segment")
    normalized = unicodedata.normalize("NFC", raw)
    return raw, normalized


def _compile_posix_pattern(value: str) -> tuple[str, ...]:
    _, normalized = _posix_relative_text(value, label="candidate recipe pattern")
    parts = tuple(normalized.split("/"))
    if any("**" in part and part != "**" for part in parts):
        raise ContractError("candidate recipe ** wildcard must occupy a complete segment")
    return parts


def _pattern_matches(pattern: Sequence[str], path: Sequence[str]) -> bool:
    def closure(states: set[int]) -> set[int]:
        expanded = set(states)
        pending = list(states)
        while pending:
            index = pending.pop()
            if index < len(pattern) and pattern[index] == "**" and index + 1 not in expanded:
                expanded.add(index + 1)
                pending.append(index + 1)
        return expanded

    states = closure({0})
    for component in path:
        next_states: set[int] = set()
        for index in states:
            if index >= len(pattern):
                continue
            if pattern[index] == "**":
                next_states.add(index)
            elif fnmatch.fnmatchcase(component, pattern[index]):
                next_states.add(index + 1)
        states = closure(next_states)
        if not states:
            return False
    return len(pattern) in closure(states)


@dataclass(frozen=True)
class CompiledCandidateRecipe:
    include: tuple[tuple[str, ...], ...]
    exclude: tuple[tuple[str, ...], ...]
    symlink_policy: str
    consistency_mode: str
    snapshot_provider_id: str | None
    digest: str

    @staticmethod
    def canonical_path(value: str | PurePosixPath) -> str:
        _, normalized = _posix_relative_text(value, label="candidate path")
        return normalized

    @staticmethod
    def collision_key(value: str | PurePosixPath) -> str:
        return CompiledCandidateRecipe.canonical_path(value).casefold()

    @property
    def creditable(self) -> bool:
        return self.consistency_mode in IMMUTABLE_SNAPSHOT_CONSISTENCY

    @property
    def requires_descriptor_nofollow(self) -> bool:
        return True

    def includes(self, value: str | PurePosixPath) -> bool:
        path = tuple(self.canonical_path(value).split("/"))
        return any(_pattern_matches(pattern, path) for pattern in self.include) and not any(
            _pattern_matches(pattern, path) for pattern in self.exclude
        )

    def select(
        self,
        value: str | PurePosixPath,
        collision_index: MutableMapping[str, str],
        *,
        is_symlink: bool = False,
    ) -> str | None:
        raw, normalized = _posix_relative_text(value, label="candidate path")
        key = normalized.casefold()
        previous = collision_index.get(key)
        if previous is not None:
            raise ContractError(
                "candidate path collision after NFC/casefold normalization: "
                f"{previous!r} vs {raw!r}"
            )
        collision_index[key] = raw
        if not self.includes(normalized):
            return None
        if is_symlink and self.symlink_policy == "reject":
            raise ContractError(f"candidate symbolic link rejected: {normalized}")
        return normalized


def compile_candidate_recipe(recipe: Mapping[str, Any]) -> CompiledCandidateRecipe:
    if not isinstance(recipe, Mapping):
        raise ContractError("candidate recipe must be an object")
    allowed_keys = {
        "inventory_mode",
        "include",
        "exclude",
        "symlink_policy",
        "path_identity",
        "collision_policy",
        "product_identity_excludes_control_state",
        "snapshot_consistency",
        "snapshot_provider_id",
    }
    if set(recipe) - allowed_keys:
        raise ContractError("candidate recipe contains unsupported fields")
    if recipe.get("inventory_mode") != "explicit":
        raise ContractError("candidate recipe inventory mode must be explicit")
    if recipe.get("path_identity") != "nfc-posix-relative":
        raise ContractError("candidate recipe path identity must be nfc-posix-relative")
    if recipe.get("collision_policy") != "reject-nfc-and-casefold-collisions":
        raise ContractError("candidate recipe collision policy must fail closed")
    if recipe.get("product_identity_excludes_control_state") is not True:
        raise ContractError("candidate recipe must exclude control state from product identity")
    symlink_policy = recipe.get("symlink_policy")
    if symlink_policy not in {"reject", "hash-link-metadata"}:
        raise ContractError("candidate recipe has an unsupported symlink policy")

    include_values = recipe.get("include")
    exclude_values = recipe.get("exclude")
    if (
        not isinstance(include_values, Sequence)
        or isinstance(include_values, (str, bytes))
        or not include_values
        or not isinstance(exclude_values, Sequence)
        or isinstance(exclude_values, (str, bytes))
        or not exclude_values
        or len(include_values) > 64
        or len(exclude_values) > 128
        or not all(isinstance(item, str) for item in (*include_values, *exclude_values))
    ):
        raise ContractError("candidate recipe include/exclude must be non-empty string arrays")
    _casefold_unique(include_values, "candidate include pattern")
    _casefold_unique(exclude_values, "candidate exclude pattern")
    include = tuple(_compile_posix_pattern(item) for item in include_values)
    exclude = tuple(_compile_posix_pattern(item) for item in exclude_values)
    if (".promin", "**") not in exclude:
        raise ContractError("candidate recipe must explicitly exclude .promin/**")

    consistency_mode = recipe.get("snapshot_consistency", OBSERVATIONAL_CONSISTENCY)
    if consistency_mode not in SNAPSHOT_CONSISTENCY_MODES:
        raise ContractError("candidate recipe has an unsupported snapshot consistency mode")
    snapshot_provider_id = recipe.get("snapshot_provider_id")
    if consistency_mode in IMMUTABLE_SNAPSHOT_CONSISTENCY:
        if not isinstance(snapshot_provider_id, str) or not snapshot_provider_id.strip():
            raise ContractError("immutable candidate recipe requires snapshot_provider_id")
    elif snapshot_provider_id is not None:
        raise ContractError("observational candidate recipe must not select a snapshot provider")

    return CompiledCandidateRecipe(
        include=include,
        exclude=exclude,
        symlink_policy=symlink_policy,
        consistency_mode=consistency_mode,
        snapshot_provider_id=snapshot_provider_id,
        digest=digest_value(recipe),
    )


def validate_candidate_consistency(candidate: Mapping[str, Any]) -> None:
    mode = candidate.get("consistency_mode")
    if mode not in SNAPSHOT_CONSISTENCY_MODES:
        raise ContractError("Candidate has an unsupported consistency mode")
    if not isinstance(candidate.get("creditable"), bool):
        raise ContractError("Candidate creditable must be boolean")
    candidate_recipe_digest = candidate.get("candidate_recipe_digest")
    if (
        not isinstance(candidate_recipe_digest, str)
        or len(candidate_recipe_digest) != 64
        or any(character not in "0123456789abcdef" for character in candidate_recipe_digest)
    ):
        raise ContractError("Candidate must bind candidate_recipe_digest")
    provider_id = candidate.get("snapshot_provider_id")
    snapshot_digest = candidate.get("snapshot_digest")
    if mode in IMMUTABLE_SNAPSHOT_CONSISTENCY:
        if candidate["creditable"] is not True:
            raise ContractError("immutable snapshot Candidate must be creditable")
        if not isinstance(provider_id, str) or not provider_id.strip():
            raise ContractError("immutable snapshot Candidate must bind snapshot_provider_id")
        if (
            not isinstance(snapshot_digest, str)
            or len(snapshot_digest) != 64
            or any(character not in "0123456789abcdef" for character in snapshot_digest)
        ):
            raise ContractError("immutable snapshot Candidate must bind snapshot_digest")
    elif candidate["creditable"] is not False:
        raise ContractError("observational Candidate cannot receive credit")
    elif provider_id is not None or snapshot_digest is not None:
        raise ContractError("observational Candidate must not claim immutable snapshot identity")


def _casefold_unique(values: Iterable[str], label: str) -> None:
    materialized = list(values)
    if len(materialized) != len(set(materialized)):
        raise ContractError(f"duplicate {label}")
    folded: dict[str, str] = {}
    for value in materialized:
        key = unicodedata.normalize("NFC", value).casefold()
        previous = folded.get(key)
        if previous is not None and previous != value:
            raise ContractError(
                f"{label} collision after normalization: {previous!r} vs {value!r}"
            )
        folded[key] = value


def validator_for(schema: Mapping[str, Any], definition: str) -> Draft202012Validator:
    definitions = schema.get("$defs")
    if not isinstance(definitions, dict) or definition not in definitions:
        raise ContractError(f"unknown schema definition: {definition}")
    return Draft202012Validator(
        {"$ref": f"#/$defs/{definition}", "$defs": definitions},
        format_checker=FormatChecker(),
    )


def validate_definition(
    schema: Mapping[str, Any],
    definition: str,
    instance: Any,
    *,
    validator: Draft202012Validator | None = None,
) -> None:
    errors = sorted(
        (validator or validator_for(schema, definition)).iter_errors(instance),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        details = "; ".join(
            f"/{'/'.join(map(str, error.absolute_path))}: {error.message}"
            for error in errors[:12]
        )
        raise ContractError(f"{definition} validation failed: {details}")


def _verify_relation_vocabulary(core: Mapping[str, Any]) -> None:
    semantic = core["semantic-model.json"]
    entity_kinds = {item["kind"] for item in semantic["persistent_entities"]}
    _casefold_unique(entity_kinds, "persistent entity kind")
    relations = semantic["relations"]
    _casefold_unique((item["kind"] for item in relations), "relation kind")
    for relation in relations:
        if not set(relation["source"] + relation["target"]) <= entity_kinds:
            raise ContractError(
                f"relation {relation['kind']} references an unknown entity kind"
            )


def _verify_authority_vocabulary(core: Mapping[str, Any]) -> None:
    authority = core["authority-model.json"]
    schema = core["contracts.schema.json"]
    capabilities = {item["id"] for item in authority["capabilities"]}
    _casefold_unique(capabilities, "action capability")
    if "projection.read" not in capabilities:
        raise ContractError("projection.read capability is required for bounded retrieval")
    command_kinds = set(
        schema["$defs"]["CommandRequest"]["properties"]["command_kind"]["enum"]
    )
    rules = authority["command_capability_rules"]
    _casefold_unique((item["command_kind"] for item in rules), "command capability rule")
    if {item["command_kind"] for item in rules} != command_kinds:
        raise ContractError("command capability rules do not cover the exact command vocabulary")
    for rule in rules:
        resolved = (
            [rule["capability_id"]]
            if "capability_id" in rule
            else list(rule["capability_by_value"].values())
        )
        if not set(resolved) <= capabilities:
            raise ContractError("command rule references an unknown action capability")
    effect_rules = authority["command_effect_scope_rules"]
    _casefold_unique((item["command_kind"] for item in effect_rules), "effect-scope rule")
    if {item["command_kind"] for item in effect_rules} != command_kinds:
        raise ContractError("effect-scope rules do not cover the exact command vocabulary")
    scope_kinds = set(
        schema["$defs"]["ScopeSelector"]["properties"]["kind"]["enum"]
    )
    for rule in effect_rules:
        declared: set[str] = set()
        if rule["mode"] == "payload-id":
            declared.add(rule["kind"])
        elif rule["mode"] == "payload-multi-id":
            declared.update(target["kind"] for target in rule["targets"])
        elif rule["mode"] in {
            "payload-dynamic-id",
            "payload-dynamic-id-or-referenced-grant-scope",
        }:
            declared.update(rule["kind_map"].values())
            if rule["mode"] == "payload-dynamic-id-or-referenced-grant-scope":
                if rule.get("grant_target_type") != "Grant":
                    raise ContractError(
                        "referenced Grant effect-scope rule has an invalid target type"
                    )
        if not declared <= scope_kinds:
            raise ContractError("effect-scope rule references an unknown scope kind")
    for role, selected in authority["role_presets_non_authoritative"].items():
        _casefold_unique(selected, f"{role} role capability")
        if not set(selected) <= capabilities:
            raise ContractError(f"role preset {role} references an unknown capability")


def verify_core(
    core_dir: str | Path, *, verify_schema_meta: bool = True
) -> dict[str, Any]:
    directory = Path(core_dir)
    ensure_exact_regular_files(directory, CORE_FILES)
    core = {
        name: load_json_strict(directory / name, root=directory)
        for name in CORE_FILES
    }
    schema = core["contracts.schema.json"]
    if verify_schema_meta:
        try:
            Draft202012Validator.check_schema(schema)
        except SchemaError as exc:
            raise ContractError(f"invalid Draft 2020-12 schema: {exc.message}") from exc
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise ContractError("contracts.schema.json must declare Draft 2020-12")
    definitions = schema.get("$defs")
    if not isinstance(definitions, Mapping) or "ImplementationClosure" not in definitions:
        raise ContractError("compiled schema lacks the ImplementationClosure definition")
    record_definitions = _compiled_record_definitions(schema)
    required_definition_shapes = {
        "ContinuationTokenClaims",
        "HumanDocumentVerification",
        "InventoryProjectionRow",
        "StandardReleaseCandidateBinding",
        "StandardReleaseDecision",
        "StandardReleaseEvidenceManifest",
        "StandardReleaseTrustConfiguration",
    }
    if not required_definition_shapes <= set(definitions):
        raise ContractError("compiled schema lacks required v1 canonical record shapes")
    for definition_name in required_definition_shapes:
        record_type = (
            definitions[definition_name]
            .get("properties", {})
            .get("record_type", {})
            .get("const")
        )
        if record_type != definition_name:
            raise ContractError(
                f"compiled schema definition {definition_name!r} has the wrong record_type"
            )
    for filename, definition in (
        ("promin.manifest.json", "StandardManifest"),
        ("semantic-model.json", "SemanticModel"),
        ("authority-model.json", "AuthorityModel"),
        ("policy-set.json", "PolicySet"),
        ("conformance.json", "Conformance"),
    ):
        validate_definition(schema, definition, core[filename])

    manifest = core["promin.manifest.json"]
    if manifest["canonical_name"] != "promin" or manifest.get("aliases"):
        raise ContractError("Core identity must be lowercase promin with no aliases")
    if not str(manifest["version"]).startswith("1."):
        raise ContractError("Promin standard version must be 1.x")
    expected_components = set(CORE_FILES) - {"promin.manifest.json"}
    listed = [component["path"] for component in manifest["core_components"]]
    _casefold_unique(listed, "Core component path")
    if set(listed) != expected_components or len(listed) != len(expected_components):
        raise ContractError("manifest must bind exactly the five non-manifest Core artifacts")
    for component in manifest["core_components"]:
        if digest_file(directory / component["path"], root=directory) != component["sha256"]:
            raise ContractError(f"Core digest mismatch: {component['path']}")
    manifest_identity = dict(manifest)
    claimed_bundle_digest = manifest_identity.pop("bundle_digest")
    if digest_value(manifest_identity) != claimed_bundle_digest:
        raise ContractError("Core bundle digest does not cover the complete manifest identity")

    functions = [core[name].get("function") for name in CORE_FILES]
    if any(not isinstance(item, str) or not item.strip() for item in functions):
        raise ContractError("every Core artifact must state one non-empty function")
    _casefold_unique(functions, "Core artifact function")
    semantic = core["semantic-model.json"]
    _casefold_unique(
        (item["id"] for item in semantic["technology_capabilities"]),
        "technology capability",
    )
    policies = core["policy-set.json"]["policies"]
    _casefold_unique((item["id"] for item in policies), "policy id")
    _casefold_unique((item["validator_id"] for item in policies), "policy validator id")
    budgets = core["conformance.json"]["structural_budgets"]
    if len(semantic["persistent_entities"]) > budgets["persistent_entity_kinds_max"]:
        raise ContractError("persistent entity budget exceeded")
    if len(semantic["relations"]) > budgets["relation_kinds_max"]:
        raise ContractError("relation budget exceeded")
    _verify_relation_vocabulary(core)
    _verify_authority_vocabulary(core)
    expected_policy_validators = {
        item["validator_id"] for item in core["policy-set.json"]["policies"]
    }
    expected_acceptance = set(core["conformance.json"]["required_acceptance"])
    expected_mutations = set(core["conformance.json"]["mutation_families"])
    if set(POLICY_VALIDATORS) != expected_policy_validators:
        raise ContractError("executable policy validator coverage differs from Core owners")
    if set(ACCEPTANCE_VALIDATORS) != expected_acceptance:
        raise ContractError("executable acceptance validator coverage differs from Core owners")
    if set(MUTATION_PROBES) != expected_mutations:
        raise ContractError("executable mutation probe coverage differs from Core owners")
    return core


def verify_preset(preset_path: str | Path, core: Mapping[str, Any]) -> dict[str, Any]:
    path = Path(preset_path)
    preset = load_json_strict(path, root=path.parent)
    validate_definition(core["contracts.schema.json"], "Preset", preset)
    if not str(preset["version"]).startswith("1."):
        raise ContractError("Promin preset version must be 1.x")
    if preset["default_profile"] not in preset["profiles"]:
        raise ContractError("preset default profile is absent")
    if "optional_user_commands" in preset or "admin_commands" in preset:
        raise ContractError("preset contains removed v1 command catalogues")
    if tuple(preset["base_user_commands"]) != BASE_USER_COMMANDS:
        raise ContractError("preset must expose exactly the ten alpha base commands")
    _casefold_unique(preset["base_user_commands"], "preset base user command")
    known = {item["id"] for item in core["semantic-model.json"]["technology_capabilities"]}
    selected = preset["required_provider_capabilities"] + preset["optional_provider_capabilities"]
    _casefold_unique(selected, "preset provider capability")
    if not set(selected) <= known:
        raise ContractError("preset references an unknown provider capability")
    ceiling = core["conformance.json"]["workcard_hard_ceiling"]
    keys = {
        "max_context_bytes": "max_bytes",
        "max_entities": "max_entities",
        "max_relations": "max_relations",
        "max_fanout_per_entity": "max_fanout_per_entity",
        "top_k": "top_k",
    }
    for profile_id, profile in preset["profiles"].items():
        for profile_key, ceiling_key in keys.items():
            if profile[profile_key] > ceiling[ceiling_key]:
                raise ContractError(
                    f"profile {profile_id} exceeds Core hard ceiling {ceiling_key}"
                )
    return preset


@dataclass(frozen=True)
class ContractBundle:
    source_root: Path
    core_dir: Path
    preset_path: Path
    core: Mapping[str, Any]
    preset: Mapping[str, Any]
    schema_meta_verified: bool = True

    @property
    def schema(self) -> Mapping[str, Any]:
        return self.core["contracts.schema.json"]

    @property
    def manifest(self) -> Mapping[str, Any]:
        return self.core["promin.manifest.json"]

    @property
    def bundle_digest(self) -> str:
        return str(self.manifest["bundle_digest"])

    @property
    def preset_digest(self) -> str:
        return digest_file(self.preset_path, root=self.preset_path.parent)

    @cached_property
    def record_definitions(self) -> Mapping[str, str]:
        return _compiled_record_definitions(self.schema)

    @cached_property
    def _definition_validators(self) -> dict[str, Draft202012Validator]:
        return {}

    def definition_validator(self, definition: str) -> Draft202012Validator:
        validator = self._definition_validators.get(definition)
        if validator is None:
            validator = validator_for(self.schema, definition)
            self._definition_validators[definition] = validator
        return validator


from .conformance import acceptance_catalogue, mutation_catalogue, policy_catalogue


POLICY_VALIDATORS: Mapping[str, Callable[..., None]] = policy_catalogue()
ACCEPTANCE_VALIDATORS: Mapping[str, Callable[..., None]] = acceptance_catalogue()
MUTATION_PROBES: Mapping[str, Callable[..., None]] = mutation_catalogue()


_BUNDLE_CACHE_LIMIT = 4
_bundle_cache: "OrderedDict[tuple[Any, ...], ContractBundle]" = OrderedDict()
_bundle_cache_guard = threading.Lock()


def _bundle_cache_key(
    root: Path, core_dir: Path, preset: Path, *, verify_schema_meta: bool
) -> tuple[Any, ...]:
    """Return a content-derived key for an immutable installed contract bundle.

    Hashing the six small Core artifacts is substantially cheaper than repeatedly
    compiling/checking the 2020-12 schema and avoids retaining a new resolver
    graph for every project in a long-lived agent process.  Content digests, not
    only mtimes, ensure that an in-place edit invalidates the cache.
    """

    core_digests: list[tuple[str, str]] = []
    for name in CORE_FILES:
        path = core_dir / name
        if path.is_symlink() or not path.is_file():
            raise ContractError(f"Core artifact must be a regular file: {path}")
        core_digests.append((name, digest_file(path, root=core_dir)))
    if preset.is_symlink() or not preset.is_file():
        raise ContractError(f"preset must be a regular file: {preset}")
    return (
        str(root),
        str(core_dir),
        tuple(core_digests),
        str(preset),
        digest_file(preset, root=preset.parent),
        verify_schema_meta,
    )



def load_contract_bundle(
    bundle_root: str | Path,
    preset_path: str | Path,
    *,
    verify_schema_meta: bool = True,
) -> ContractBundle:
    root_input = Path(bundle_root)
    if root_input.is_symlink():
        raise ContractError(f"standard bundle must not be a symbolic link: {root_input}")
    root = root_input.resolve(strict=True)
    if not root.is_dir():
        raise ContractError(f"standard bundle must be a real directory: {root}")
    core_dir = root / "core" if (root / "core").is_dir() else root
    preset_input = Path(preset_path)
    if preset_input.is_symlink():
        raise ContractError(f"preset must not be a symbolic link: {preset_input}")
    selected_preset = preset_input.resolve(strict=True)
    key = _bundle_cache_key(
        root, core_dir, selected_preset, verify_schema_meta=verify_schema_meta
    )
    with _bundle_cache_guard:
        cached = _bundle_cache.get(key)
        if cached is not None:
            _bundle_cache.move_to_end(key)
            return cached
    core = verify_core(core_dir, verify_schema_meta=verify_schema_meta)
    preset = verify_preset(selected_preset, core)
    bundle = ContractBundle(
        root,
        core_dir,
        selected_preset,
        core,
        preset,
        schema_meta_verified=verify_schema_meta,
    )
    with _bundle_cache_guard:
        _bundle_cache[key] = bundle
        _bundle_cache.move_to_end(key)
        while len(_bundle_cache) > _BUNDLE_CACHE_LIMIT:
            _bundle_cache.popitem(last=False)
    return bundle


def _scope_unique(scope: Iterable[Mapping[str, Any]], label: str) -> None:
    keys = [(item["kind"], item["value"]) for item in scope]
    if len(keys) != len(set(keys)):
        raise ContractError(f"duplicate {label} scope selector")


def _default_project_intent(project: Mapping[str, Any]) -> dict[str, Any]:
    project_id = str(project.get("project_id") or "project")
    return {
        "project_mode": "existing-code",
        "goal": f"Audit, stabilize, and safely continue development of {project_id}.",
        "success_criteria": [
            "The next work item is bounded and evidence-oriented.",
            "Routine work does not require repeated user supervision.",
            "No failed result receives pass credit.",
        ],
        "constraints": [],
        "non_goals": [],
        "deliverables": [],
        "references": [],
        "work_sources": [],
        "reporting_language": "en",
        "autonomy": "safe-auto",
    }


def _default_resolved_profile(project: Mapping[str, Any]) -> dict[str, Any]:
    preset_id = str(project.get("preset_id") or "semantic-morok-tower")
    profile = {
        "revision": 1,
        "layers": [preset_id],
        "detected_technologies": [],
        "operation_profiles": [
            {
                "operation": "plan-refinement",
                "model_tier": "standard",
                "reason": "explicit expert configuration requires bounded planning",
            },
            {
                "operation": "implementation",
                "model_tier": "standard",
                "reason": "routine bounded implementation",
            },
        ],
        "resolution": [
            {
                "profile_id": preset_id,
                "reason": "explicit preset selected by expert initialization",
                "confidence": 1.0,
            }
        ],
        "authority_effect": "none",
    }
    return {**profile, "profile_digest": digest_value(profile)}


def compile_project_init(
    project: Mapping[str, Any], bundle: ContractBundle
) -> dict[str, Any]:
    """Compile concise expert input into one explicit canonical ProjectInit.

    Defaults are deterministic, visible in the returned plan, and derived only
    from the explicit project record plus the selected preset.  The installed
    canonical record is therefore strict even when the authoring input is small.
    """

    if not isinstance(project, Mapping):
        raise ContractError("project init input must be an object")
    result = deepcopy(dict(project))
    allowed_base = {
        "record_type",
        "project_id",
        "roots",
        "candidate_recipe",
        "preset_id",
        "operating_profile",
        "intent",
        "resolved_profile",
        "orchestration",
        "telemetry",
    }
    unknown = set(result) - allowed_base
    if unknown:
        raise ContractError(f"project init input has unknown fields: {sorted(unknown)}")
    if result.get("record_type") != "ProjectInit":
        raise ContractError("project init input record_type must be ProjectInit")
    if result.get("preset_id") != bundle.preset.get("preset_id"):
        raise ContractError("project init selects a different preset")

    result.setdefault("intent", _default_project_intent(result))
    result.setdefault("resolved_profile", _default_resolved_profile(result))
    result.setdefault(
        "orchestration",
        {
            "enabled": True,
            "enforcement": "required",
            "unregistered_work": "external-proposal-only",
            "model_routing": "cheapest-adequate-with-evidence-escalation",
            "host_source": "explicit-promin",
        },
    )
    result.setdefault(
        "telemetry",
        {
            "enabled": True,
            "local_only": True,
            "export_enabled": False,
            "max_log_bytes": 4 * 1024 * 1024,
            "retention_records": 5000,
            "store_full_prompts": False,
            "store_source_bodies": False,
            "store_secrets_or_pii": False,
        },
    )
    validate_definition(bundle.schema, "ProjectInit", result)
    return result


def validate_plan_objects(
    plans: Mapping[str, Any], bundle: ContractBundle, licenses: Any
) -> None:
    if set(plans) != set(PLAN_FILES):
        raise ContractError(f"init plan set must be exactly {list(PLAN_FILES)}")
    definitions = {
        "project.json": "ProjectInit",
        "standards.json": "StandardsInit",
        "technologies.json": "TechnologiesInit",
        "authority.json": "AuthorityInit",
    }
    for filename, definition in definitions.items():
        validate_definition(bundle.schema, definition, plans[filename])

    project = plans["project.json"]
    if project["preset_id"] != bundle.preset["preset_id"]:
        raise ContractError("project selects a different preset")
    if project["operating_profile"] not in bundle.preset["profiles"]:
        raise ContractError("project selects an unknown operating profile")
    recipe = project["candidate_recipe"]
    compiled_recipe = compile_candidate_recipe(recipe)
    _casefold_unique(
        (item["standard_id"] for item in plans["standards.json"]["bindings"]),
        "standard binding",
    )

    bindings = plans["technologies.json"]["bindings"]
    _casefold_unique((item["capability_id"] for item in bindings), "technology capability binding")
    _casefold_unique((item["provider_id"] for item in bindings), "technology provider binding")
    known = {item["id"] for item in bundle.core["semantic-model.json"]["technology_capabilities"]}
    if not {item["capability_id"] for item in bindings} <= known:
        raise ContractError("technology plan binds an unknown capability")
    required = set(bundle.preset["required_provider_capabilities"])
    required_bindings = {item["capability_id"] for item in bindings if item["required"]}
    if required_bindings != required:
        raise ContractError(
            f"required provider bindings mismatch: expected={sorted(required)} "
            f"actual={sorted(required_bindings)}"
        )
    if compiled_recipe.snapshot_provider_id is not None:
        snapshot_bindings = [
            item
            for item in bindings
            if item["provider_id"] == compiled_recipe.snapshot_provider_id
        ]
        if len(snapshot_bindings) != 1:
            raise ContractError("candidate snapshot provider is not exactly bound")
        if snapshot_bindings[0]["capability_id"] != "filesystem-inventory":
            raise ContractError(
                "candidate snapshot provider must implement filesystem-inventory"
            )
    validate_license_plan(licenses, bindings, bundle.schema)

    authority = plans["authority.json"]
    subject_ids = [item["subject_id"] for item in authority["subjects"]]
    _casefold_unique(subject_ids, "authority subject")
    subjects = set(subject_ids)
    roots = authority["roots"]
    _casefold_unique((item["subject_id"] for item in roots), "root authority subject")
    capabilities = {item["id"] for item in bundle.core["authority-model.json"]["capabilities"]}
    for root in roots:
        if root["subject_id"] not in subjects:
            raise ContractError("root authority references an unknown subject")
        if not set(root["capability_ceiling"]) <= capabilities:
            raise ContractError("root authority exceeds the Core capability vocabulary")
        _scope_unique(root["scope"], f"root {root['subject_id']}")
    if authority["trust_mode"] == "team-signed":
        if "signature" not in {item["capability_id"] for item in bindings}:
            raise ContractError("team-signed mode requires an explicit signature provider")
        key_ids = [item["key_id"] for item in authority["keys"]]
        _casefold_unique(key_ids, "trust key")
        selected = authority["team_policy"]["key_ids"]
        if not set(selected) <= set(key_ids) or authority["team_policy"]["threshold"] > len(set(selected)):
            raise ContractError("invalid team threshold/key selection")


def validate_license_plan(
    licenses: Any,
    provider_bindings: Iterable[Mapping[str, Any]],
    schema: Mapping[str, Any],
) -> None:
    if not isinstance(licenses, dict) or set(licenses) != {"record_type", "bindings"}:
        raise ContractError("licenses plan must contain exactly record_type and bindings")
    if licenses["record_type"] != "LicensesPlan" or not isinstance(licenses["bindings"], list):
        raise ContractError("invalid licenses plan identity")
    expected = {item["provider_id"]: item["license"] for item in provider_bindings}
    actual: dict[str, Any] = {}
    for item in licenses["bindings"]:
        if not isinstance(item, dict) or set(item) != {"provider_id", "license"}:
            raise ContractError("invalid licenses plan binding")
        provider_id = item["provider_id"]
        if not isinstance(provider_id, str) or provider_id in actual:
            raise ContractError("duplicate or invalid licenses plan provider")
        validate_definition(schema, "LicenseBinding", item["license"])
        actual[provider_id] = item["license"]
    if actual != expected:
        raise ContractError("licenses plan must exactly match technology provider bindings")
SemanticValidator = Callable[[Mapping[str, Any], ContractBundle, Mapping[str, Any]], None]


class SemanticValidatorRegistry:
    def __init__(self) -> None:
        self._validators: dict[tuple[str, str], list[SemanticValidator]] = defaultdict(list)

    def register(
        self, operation: str, record_type: str, validator: SemanticValidator
    ) -> None:
        if operation not in {"*", "command", "import", "replay", "rebuild", "export", "transient"}:
            raise ValueError(f"unsupported ingress operation: {operation}")
        if not record_type:
            raise ValueError("record_type must be non-empty")
        self._validators[(operation, record_type)].append(validator)

    def validate(
        self,
        operation: str,
        record_type: str,
        value: Mapping[str, Any],
        bundle: ContractBundle,
        context: Mapping[str, Any],
    ) -> None:
        if operation not in {"command", "import", "replay", "rebuild", "export", "transient"}:
            raise ContractError(f"unsupported ingress operation: {operation}")
        keys = (("*", "*"), ("*", record_type), (operation, "*"), (operation, record_type))
        for key in keys:
            for validator in self._validators.get(key, ()):
                validator(value, bundle, context)


def _compiled_record_definitions(schema: Mapping[str, Any]) -> dict[str, str]:
    definitions = schema.get("$defs")
    if not isinstance(definitions, Mapping):
        raise ContractError("compiled schema definitions are missing")
    records: dict[str, str] = {}
    for definition_name, definition in definitions.items():
        if not isinstance(definition_name, str) or not isinstance(definition, Mapping):
            continue
        persistence = definition.get("x-promin-persistence")
        if persistence == "derived-live-only":
            continue
        if persistence not in {
            None,
            "derived-rebuild-only",
            "export-only",
            "transient-ingress-only",
        }:
            raise ContractError(
                f"compiled schema definition {definition_name!r} has an unsupported persistence class"
            )
        properties = definition.get("properties")
        if not isinstance(properties, Mapping):
            continue
        record_type_shape = properties.get("record_type")
        if not isinstance(record_type_shape, Mapping):
            continue
        record_type = record_type_shape.get("const")
        if not isinstance(record_type, str) or not record_type:
            continue
        if "record_type" not in definition.get("required", ()):
            raise ContractError(
                f"compiled schema record definition {definition_name!r} does not require record_type"
            )
        previous = records.get(record_type)
        if previous is not None:
            raise ContractError(
                f"compiled schema maps record_type {record_type!r} to multiple definitions"
            )
        records[record_type] = definition_name
    if not records:
        raise ContractError("compiled schema contains no canonical record definitions")
    return records


def _activation_binding(
    value: Mapping[str, Any], bundle: ContractBundle, context: Mapping[str, Any]
) -> None:
    active = context.get("activation_digest")
    if active is not None and "activation_digest" in value and value["activation_digest"] != active:
        raise ContractError("record Activation binding does not match active state")


def _artifact_activation_binding(
    value: Mapping[str, Any], bundle: ContractBundle, context: Mapping[str, Any]
) -> None:
    if value.get("artifact_kind") != "evidence":
        return
    active = context.get("activation_digest")
    binding = value.get("evidence_binding")
    if active is not None and (
        not isinstance(binding, Mapping)
        or binding.get("activation_digest") != active
    ):
        raise ContractError("evidence Artifact Activation binding does not match active state")


def _candidate_consistency_binding(
    value: Mapping[str, Any], bundle: ContractBundle, context: Mapping[str, Any]
) -> None:
    validate_candidate_consistency(value)
    expected_recipe = context.get("candidate_recipe_digest")
    if expected_recipe is not None and value["candidate_recipe_digest"] != expected_recipe:
        raise ContractError("Candidate recipe binding does not match active project recipe")
    expected_mode = context.get("candidate_consistency_mode")
    if expected_mode is not None and value["consistency_mode"] != expected_mode:
        raise ContractError("Candidate consistency mode does not match inventory mode")
    expected_provider = context.get("snapshot_provider_id")
    if expected_provider is not None and value.get("snapshot_provider_id") != expected_provider:
        raise ContractError("Candidate snapshot provider does not match active provider")


def _relation_domain_range(
    value: Mapping[str, Any], bundle: ContractBundle, context: Mapping[str, Any]
) -> None:
    definitions = {
        item["kind"]: item for item in bundle.core["semantic-model.json"]["relations"]
    }
    relation = definitions[value["kind"]]
    if value["source_type"] not in relation["source"] or value["target_type"] not in relation["target"]:
        raise ContractError("relation violates its Core domain or range")


def _dependency_graph_binding(
    value: Mapping[str, Any], bundle: ContractBundle, context: Mapping[str, Any]
) -> None:
    if value.get("kind") != "DEPENDS_ON":
        return
    tasks = context.get("current_tasks")
    relations = context.get("current_relations")
    if not isinstance(tasks, (list, tuple)) or not isinstance(relations, (list, tuple)):
        raise ContractError("DEPENDS_ON validation requires current graph state")
    relation_values = [
        relation
        for relation in relations
        if relation.get("relation_id") != value["relation_id"]
    ] + [value]
    try:
        from .conformance import _dependency_state

        _dependency_state(
            bundle,
            {
                "current_tasks": tasks,
                "current_relations": relation_values,
                "current_gate_results": context.get("current_gate_results", []),
                "current_findings": context.get("current_findings", []),
            },
        )
    except Exception as exc:
        raise ContractError("DEPENDS_ON graph is cyclic or unresolved") from exc


def _task_gate_definition_binding(
    value: Mapping[str, Any], bundle: ContractBundle, context: Mapping[str, Any]
) -> None:
    gate_owner = bundle.core["policy-set.json"]["gate_run_definition_contract"]
    allowed_pairs = {
        (evidence_purpose, evidence_class)
        for evidence_purpose, evidence_classes in gate_owner[
            "evidence_class_purpose_pairs"
        ].items()
        for evidence_class in evidence_classes
    }
    owner_identity = {
        field: nested
        for field, nested in value.items()
        if field not in {"state", "gate_run_definitions"}
    }
    owner_digest = digest_value(owner_identity)
    seen_definition_ids: set[str] = set()
    seen_definition_digests: set[str] = set()
    for binding in value["gate_run_definitions"]:
        definition = binding["definition"]
        definition_digest = digest_value(definition)
        if (
            binding["definition_digest"] != definition_digest
            or definition_digest in seen_definition_digests
            or definition["definition_id"] in seen_definition_ids
            or definition["owner_kind"] != "Task"
            or definition["owner_digest"] != owner_digest
            or definition["activation_digest"] != value["activation_digest"]
            or definition["candidate_digest"] != value["candidate_digest"]
            or (
                definition["expected_evidence_purpose"],
                definition["expected_evidence_class"],
            )
            not in allowed_pairs
            or (
                definition["product_credit_required"] is True
                and (
                    definition["expected_evidence_purpose"] != "product"
                    or definition["expected_evidence_class"]
                    != "product-execution"
                )
            )
        ):
            raise ContractError("Task carries a drifted or duplicated GateRunDefinition")
        if definition["target_kind"] == "candidate":
            if definition["target_digest"] != definition["candidate_digest"]:
                raise ContractError("candidate GateRunDefinition target digest drifted")
        else:
            finding_snapshots = context.get("gate_definition_findings")
            snapshot = (
                finding_snapshots.get(definition["target_digest"])
                if isinstance(finding_snapshots, Mapping)
                else None
            )
            if not isinstance(snapshot, Mapping):
                raise ContractError(
                    "finding GateRunDefinition requires its immutable OPEN Finding snapshot"
                )
            validate_definition(bundle.schema, "Finding", snapshot)
            if (
                digest_value(snapshot) != definition["target_digest"]
                or snapshot.get("status") != "OPEN"
                or snapshot.get("candidate_digest") != definition["candidate_digest"]
            ):
                raise ContractError("finding GateRunDefinition target snapshot is invalid")
        seen_definition_ids.add(definition["definition_id"])
        seen_definition_digests.add(definition_digest)


def _inventory_projection_row_binding(
    value: Mapping[str, Any], bundle: ContractBundle, context: Mapping[str, Any]
) -> None:
    path = CompiledCandidateRecipe.canonical_path(value["path"])
    expected_id = "artifact:file:" + hashlib.sha256(path.encode("utf-8")).hexdigest()[:48]
    proxy = value["semantic_proxy"]
    payload = proxy["payload"]
    if proxy["id"] != expected_id or payload["artifact_id"] != expected_id:
        raise ContractError("InventoryProjectionRow Artifact identity differs from its path")
    if (
        payload["artifact_kind"] != "product"
        or payload["digest"] != value["digest"]
        or payload["size_bytes"] != value["size"]
    ):
        raise ContractError("InventoryProjectionRow Artifact payload differs from raw file facts")
    search_text = unicodedata.normalize("NFC", path)
    search_text_max = bundle.core["conformance.json"]["scale_contracts"][
        "inventory"
    ]["search_text_bytes_max"]
    if (
        value["search_text"] != search_text
        or len(search_text.encode("utf-8")) > search_text_max
    ):
        raise ContractError("InventoryProjectionRow search text differs from canonical path")


def _resolved_inventory_stream(
    value: Mapping[str, Any], bundle: ContractBundle, context: Mapping[str, Any]
) -> tuple[list[dict[str, Any]], bytes]:
    artifacts = context.get("inventory_stream_artifacts")
    resolved = (
        artifacts.get(value["stream_artifact_id"])
        if isinstance(artifacts, Mapping)
        else None
    )
    if (
        not isinstance(resolved, Mapping)
        or set(resolved) != {"record", "payload"}
        or not isinstance(resolved.get("record"), Mapping)
        or not isinstance(resolved.get("payload"), bytes)
    ):
        raise ContractError("inventory manifest requires exact finalized CAS stream bytes")
    record = resolved["record"]
    if (
        set(record) != {"artifact", "commit_binding"}
        or not isinstance(record.get("artifact"), Mapping)
        or not isinstance(record.get("commit_binding"), Mapping)
        or set(record["commit_binding"])
        != {"command_digest", "batch_digest", "primary_event_id", "primary_event_digest"}
    ):
        raise ContractError("inventory stream Artifact record is not finalized")
    artifact = record["artifact"]
    validate_definition(bundle.schema, "Artifact", artifact)
    payload_bytes = resolved["payload"]
    owner = bundle.core["semantic-model.json"]["design_rules"][
        "inventory_projection"
    ]
    if (
        artifact["artifact_id"] != value["stream_artifact_id"]
        or artifact["artifact_kind"] != owner["stream_artifact_kind"]
        or artifact["media_type"] != owner["stream_media_type"]
        or artifact["digest"] != hashlib.sha256(payload_bytes).hexdigest()
        or artifact["size_bytes"] != len(payload_bytes)
        or digest_value(record) != value["stream_artifact_record_digest"]
        or value["stream_digest"] != artifact["digest"]
        or value["stream_bytes"] != len(payload_bytes)
    ):
        raise ContractError("inventory stream CAS binding differs from manifest")
    rows: list[dict[str, Any]] = []
    inventory_digest = hashlib.sha256()
    previous_path: str | None = None
    offset = 0
    while offset < len(payload_bytes):
        end = payload_bytes.find(b"\n", offset)
        if end < 0:
            raise ContractError("inventory JSONL stream lacks final LF")
        line = payload_bytes[offset : end + 1]
        offset = end + 1
        parsed = parse_json_strict(line)
        if not isinstance(parsed, dict) or canonical_bytes(parsed) != line:
            raise ContractError("inventory JSONL row is not exact canonical JSON")
        validate_definition(bundle.schema, "InventoryJsonlRow", parsed)
        path = CompiledCandidateRecipe.canonical_path(parsed["path"])
        search_text = unicodedata.normalize("NFC", path)
        limit = bundle.core["conformance.json"]["scale_contracts"]["inventory"][
            "search_text_bytes_max"
        ]
        if (
            parsed["path"] != path
            or parsed["search_text"] != search_text
            or len(search_text.encode("utf-8")) > limit
            or (previous_path is not None and path <= previous_path)
        ):
            raise ContractError("inventory JSONL path/search ordering is invalid")
        previous_path = path
        inventory_digest.update(
            canonical_bytes(
                {"path": path, "digest": parsed["digest"], "size": parsed["size"]}
            )
        )
        rows.append(parsed)
    if (
        len(rows) != value["entry_count"]
        or inventory_digest.hexdigest() != value["inventory_digest"]
        or value["row_schema_digest"]
        != digest_value(bundle.schema["$defs"]["InventoryJsonlRow"])
    ):
        raise ContractError("inventory JSONL count, schema, or rolling digest differs")
    return rows, payload_bytes


def _inventory_input_manifest_binding(
    value: Mapping[str, Any], bundle: ContractBundle, context: Mapping[str, Any]
) -> None:
    candidate = context.get("inventory_candidate")
    if not isinstance(candidate, Mapping):
        raise ContractError("inventory manifest requires exact Candidate context")
    validate_definition(bundle.schema, "Candidate", candidate)
    validate_candidate_consistency(candidate)
    if (
        candidate["candidate_digest"] != value["candidate_digest"]
        or candidate["inventory_digest"] != value["inventory_digest"]
        or candidate["consistency_mode"] != value["consistency_mode"]
        or candidate["snapshot_provider_id"] != value["snapshot_provider_id"]
        or candidate["snapshot_digest"] != value["snapshot_digest"]
    ):
        raise ContractError("inventory manifest differs from Candidate")
    _resolved_inventory_stream(value, bundle, context)


def _current_inventory_binding(
    value: Mapping[str, Any], bundle: ContractBundle, context: Mapping[str, Any]
) -> None:
    manifest = context.get("inventory_input_manifest")
    rows = context.get("inventory_projection_rows")
    if not isinstance(manifest, Mapping) or not isinstance(rows, (list, tuple)):
        raise ContractError("CurrentInventory requires manifest and projection rows")
    validate_definition(bundle.schema, "InventoryInputManifest", manifest)
    source_rows, _ = _resolved_inventory_stream(manifest, bundle, context)
    for row in rows:
        validate_definition(bundle.schema, "InventoryProjectionRow", row)
        _inventory_projection_row_binding(row, bundle, context)
    raw = [(row["path"], row["digest"], row["size"], row["search_text"]) for row in source_rows]
    projected = [
        (row["path"], row["digest"], row["size"], row["search_text"])
        for row in rows
    ]
    if (
        value["manifest_digest"] != digest_value(manifest)
        or any(value[field] != manifest[field] for field in (
            "candidate_digest", "inventory_digest", "stream_digest", "stream_bytes", "entry_count"
        ))
        or value["projection_row_count"] != len(rows)
        or value["entry_count"] != len(source_rows)
        or raw != projected
    ):
        raise ContractError("CurrentInventory differs from its exact verified input")


def _bounded_workcard(
    value: Mapping[str, Any], bundle: ContractBundle, context: Mapping[str, Any]
) -> None:
    profile_id = context.get("operating_profile")
    if profile_id not in bundle.preset["profiles"]:
        raise ContractError("WorkCard validation requires the active operating profile")
    profile = bundle.preset["profiles"][profile_id]
    ceiling = bundle.core["conformance.json"]["workcard_hard_ceiling"]
    profile_keys = {
        "max_bytes": "max_context_bytes",
        "max_entities": "max_entities",
        "max_relations": "max_relations",
        "max_fanout_per_entity": "max_fanout_per_entity",
        "top_k": "top_k",
    }
    for key, selected in value["budget"].items():
        if selected > ceiling[key] or selected > profile[profile_keys[key]]:
            raise ContractError(f"WorkCard budget exceeds active ceiling: {key}")


def _research_draft_transient_binding(
    value: Mapping[str, Any], bundle: ContractBundle, context: Mapping[str, Any]
) -> None:
    from .conformance import validate_research_draft_intake

    plan = context.get("active_license_plan")
    plan_digest = context.get("active_license_plan_digest")
    receipts = context.get("source_receipts")
    evidence_receipts = context.get("evidence_receipts")
    if (
        not isinstance(plan, Mapping)
        or not isinstance(plan_digest, str)
        or not isinstance(receipts, Mapping)
        or not isinstance(evidence_receipts, Mapping)
    ):
        raise ContractError("research intake lacks verified source and license context")
    validate_research_draft_intake(
        bundle,
        value,
        active_license_plan=plan,
        active_license_plan_digest=plan_digest,
        source_receipts=receipts,
        evidence_receipts=evidence_receipts,
    )


def _projection_limits_binding(
    value: Mapping[str, Any], bundle: ContractBundle, context: Mapping[str, Any]
) -> None:
    profile_id = context.get("operating_profile")
    profiles = bundle.preset.get("profiles")
    if not isinstance(profile_id, str) or not isinstance(profiles, Mapping):
        raise ContractError("ProjectionLimits requires the active operating profile")
    profile = profiles.get(profile_id)
    if not isinstance(profile, Mapping):
        raise ContractError("ProjectionLimits selects an unknown operating profile")
    authority = bundle.core["authority-model.json"]
    conformance = bundle.core["conformance.json"]
    policies = bundle.core["policy-set.json"]
    continuation = authority["continuation_access_rule"]
    workcard_scale = conformance["scale_contracts"]["workcard"]
    result_owner = policies["derived_result_contracts"]["RetrievalPage"]
    identity = {
        "record_type": "ProjectionLimits",
        "token_version": continuation["token_version"],
        "ranking_algorithm_id": continuation["ranking_algorithm_id"],
        "traversal_algorithm_id": continuation["traversal_algorithm_id"],
        "dependency_depth_hard_max": conformance["dependency_depth_hard_max"],
        "continuation_ttl_seconds_max": continuation["ttl_seconds_max"],
        "selected_profile_id": profile_id,
        "selected_profile_digest": digest_value(profile),
        "persistent_entity_types": [
            item["kind"]
            for item in bundle.core["semantic-model.json"]["persistent_entities"]
        ],
        "default_budget": {
            "max_bytes": profile["max_context_bytes"],
            "max_entities": profile["max_entities"],
            "max_relations": profile["max_relations"],
            "max_fanout_per_entity": profile["max_fanout_per_entity"],
            "top_k": profile["top_k"],
        },
        "hard_budget": conformance["workcard_hard_ceiling"],
        "default_depth": profile["default_dependency_depth"],
        "depth_min": continuation["depth_min"],
        "depth_max": conformance["dependency_depth_hard_max"],
        "default_ttl_seconds": continuation["default_ttl_seconds"],
        "ttl_min_seconds": continuation["ttl_min_seconds"],
        "ttl_max_seconds": continuation["ttl_seconds_max"],
        "max_token_bytes": workcard_scale["continuation_token_bytes_max"],
        "max_continuation_state_bytes": workcard_scale[
            "continuation_state_bytes_max"
        ],
        "max_query_bytes": result_owner["query_bytes_max"],
        "min_result_bytes": continuation["min_result_bytes"],
        "max_resume_binding_fields": continuation["max_resume_binding_fields"],
        "max_resume_binding_key_chars": continuation[
            "max_resume_binding_key_chars"
        ],
        "max_resume_binding_value_bytes": continuation[
            "max_resume_binding_value_bytes"
        ],
        "max_resume_binding_bytes": continuation["max_resume_binding_bytes"],
        "required_resume_binding_fields": continuation[
            "required_resume_binding_fields"
        ],
    }
    expected = {**identity, "policy_digest": digest_value(identity)}
    if value != expected:
        raise ContractError("ProjectionLimits differs from its installed Core and profile")


DEFAULT_SEMANTIC_VALIDATORS = SemanticValidatorRegistry()
DEFAULT_SEMANTIC_VALIDATORS.register("*", "*", _activation_binding)
DEFAULT_SEMANTIC_VALIDATORS.register("*", "Artifact", _artifact_activation_binding)
DEFAULT_SEMANTIC_VALIDATORS.register("*", "Candidate", _candidate_consistency_binding)
DEFAULT_SEMANTIC_VALIDATORS.register("*", "Relation", _relation_domain_range)
for _operation in ("command", "import", "rebuild", "replay"):
    DEFAULT_SEMANTIC_VALIDATORS.register(
        _operation, "Relation", _dependency_graph_binding
    )
DEFAULT_SEMANTIC_VALIDATORS.register("*", "Task", _task_gate_definition_binding)
DEFAULT_SEMANTIC_VALIDATORS.register(
    "*", "InventoryProjectionRow", _inventory_projection_row_binding
)
DEFAULT_SEMANTIC_VALIDATORS.register(
    "rebuild", "InventoryInputManifest", _inventory_input_manifest_binding
)
DEFAULT_SEMANTIC_VALIDATORS.register(
    "rebuild", "CurrentInventory", _current_inventory_binding
)
DEFAULT_SEMANTIC_VALIDATORS.register("*", "WorkCard", _bounded_workcard)
DEFAULT_SEMANTIC_VALIDATORS.register(
    "rebuild", "ProjectionLimits", _projection_limits_binding
)
DEFAULT_SEMANTIC_VALIDATORS.register(
    "transient", "ResearchDraftIntake", _research_draft_transient_binding
)


def validate_ingress(
    bundle: ContractBundle,
    value: Any,
    *,
    operation: str,
    definition: str | None = None,
    context: Mapping[str, Any] | None = None,
    registry: SemanticValidatorRegistry | None = None,
) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ContractError("ingress record must be a JSON object")
    record_type = value.get("record_type")
    record_definitions = bundle.record_definitions
    if not isinstance(record_type, str):
        raise ContractError(f"unknown or missing record_type: {record_type!r}")
    definitions = bundle.schema.get("$defs")
    if not isinstance(definitions, Mapping):
        raise ContractError("compiled schema definitions are missing")
    if definition is None:
        resolved_definition = record_definitions.get(record_type)
        if resolved_definition is None:
            raise ContractError(f"unknown or missing record_type: {record_type!r}")
    else:
        resolved_definition = definition
    definition_schema = definitions.get(resolved_definition)
    if not isinstance(definition_schema, Mapping):
        raise ContractError(f"unknown schema definition: {resolved_definition!r}")
    expected_record_type = (
        definition_schema.get("properties", {})
        .get("record_type", {})
        .get("const")
    )
    if expected_record_type != record_type:
        raise ContractError("explicit schema definition conflicts with record_type")
    allowed_operations = definition_schema.get("x-promin-ingress-operations")
    if allowed_operations is not None and (
        not isinstance(allowed_operations, list)
        or operation not in allowed_operations
    ):
        raise ContractError(
            f"{record_type} is not valid at {operation!r} ingress"
        )
    validate_definition(
        bundle.schema,
        resolved_definition,
        value,
        validator=bundle.definition_validator(resolved_definition),
    )
    (registry or DEFAULT_SEMANTIC_VALIDATORS).validate(
        operation, record_type, value, bundle, context or {}
    )
    return value

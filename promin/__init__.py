"""Promin version 1 runtime contracts."""

from .canonical import (
    DEFAULT_LIMITS,
    CanonicalError,
    ParseLimits,
    canonical_bytes,
    digest_bytes,
    digest_file,
    digest_value,
    load_json_strict,
    parse_json_strict,
)
from .contracts import (
    ACCEPTANCE_VALIDATORS,
    CORE_FILES,
    INIT_FILES,
    MUTATION_PROBES,
    PLAN_FILES,
    POLICY_VALIDATORS,
    ContractBundle,
    ContractError,
    SemanticValidatorRegistry,
    load_contract_bundle,
    validate_definition,
    validate_ingress,
    verify_core,
    verify_preset,
)
from .conformance import (
    ConformanceError,
    acceptance_proof_classes,
    sanitize_research_draft_bytes,
)
from .evidence import (
    standard_distribution_status,
    validate_human_document_verification,
    validate_standard_release_candidate_binding,
    validate_standard_release_decision,
    validate_standard_release_evidence_manifest,
)
from .init import (
    ActivationContext,
    ActivationGuard,
    InitError,
    InitRequest,
    InitResult,
    initialize_project,
    verify_provider_preflight,
    verify_before_mutation,
)
from .mutation_suite import MutationRejection, MutationSuiteError, run_mutation

__all__ = [
    "ActivationContext",
    "ActivationGuard",
    "ACCEPTANCE_VALIDATORS",
    "CanonicalError",
    "ContractBundle",
    "ContractError",
    "ConformanceError",
    "CORE_FILES",
    "DEFAULT_LIMITS",
    "INIT_FILES",
    "InitError",
    "InitRequest",
    "InitResult",
    "MUTATION_PROBES",
    "MutationRejection",
    "MutationSuiteError",
    "PLAN_FILES",
    "POLICY_VALIDATORS",
    "ParseLimits",
    "SemanticValidatorRegistry",
    "canonical_bytes",
    "acceptance_proof_classes",
    "digest_bytes",
    "digest_file",
    "digest_value",
    "initialize_project",
    "load_contract_bundle",
    "load_json_strict",
    "parse_json_strict",
    "run_mutation",
    "standard_distribution_status",
    "validate_human_document_verification",
    "validate_definition",
    "validate_ingress",
    "sanitize_research_draft_bytes",
    "validate_standard_release_candidate_binding",
    "validate_standard_release_decision",
    "validate_standard_release_evidence_manifest",
    "verify_before_mutation",
    "verify_provider_preflight",
    "verify_core",
    "verify_preset",
]

from .version import standard_version

__version__ = standard_version()

#!/usr/bin/env python3
"""Generate the four promin human PDF projections from canonical owners."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from xml.sax.saxutils import escape

from reportlab import Version as REPORTLAB_VERSION
from reportlab import rl_config
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    Flowable,
    Frame,
    KeepTogether,
    LongTable,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from promin_validate import (  # noqa: E402
    CANONICAL_PACKAGE_DIRECTORIES,
    CANONICAL_PACKAGE_DIRECTORY_COUNT,
    CANONICAL_PACKAGE_FILE_COUNT,
    CANONICAL_PACKAGE_FILES,
    CANONICAL_PAYLOAD_FILES,
    GENERATED_SURFACES,
    SEMVER,
)


rl_config.invariant = 1
rl_config.useA85 = 1

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "core"
PRESET_PATH = ROOT / "presets" / "semantic-standard.json"
OUTPUT = ROOT / "human"
PAGE_WIDTH, PAGE_HEIGHT = A4
README_PATH = ROOT / "README.md"
MACHINE_README_PATH = ROOT / "MACHINE_README.md"

EXPLICIT_EMIT_PLAN_EXAMPLE = (
    "promin --root PROJECT init --standard-bundle BUNDLE --preset PRESET "
    "--project-plan PROJECT_PLAN --standards-plan STANDARDS_PLAN "
    "--technologies-plan TECHNOLOGIES_PLAN --licenses-plan LICENSES_PLAN "
    "--authority-plan AUTHORITY_PLAN --emit-plan DIRECTORY"
)

EXPLICIT_TEAM_INIT_EXAMPLE = (
    "promin --root PROJECT init --standard-bundle BUNDLE --preset PRESET "
    "--project-plan PROJECT_PLAN --standards-plan STANDARDS_PLAN "
    "--technologies-plan TECHNOLOGIES_PLAN --licenses-plan LICENSES_PLAN "
    "--authority-plan AUTHORITY_PLAN --activation-proofs ACTIVATION_PROOFS"
)

DOCUMENT_REQUIRED_TOKENS = (
    "promin",
    "1.0.0",
    "ReadyFrontier",
    "NextResult",
    "ContinueResult",
    "RetrievalPage",
    "activation.json",
    "WorkCardProjection",
    "DoctorResult",
    "OperationMetrics",
    "ResearchDraftIntake",
    "SanitizedResearchDraft",
    "SemanticExport",
    "EventStorePolicy",
    "ProviderInvocationEvidence",
    "product_acceptance_pass",
    "not_approved",
    "public_release_approved",
    "baseline",
    "balanced",
    "extended",
)

FONT_FACES = {
    "regular": "Promin",
    "bold": "Promin-Bold",
    "italic": "Promin-Italic",
    "mono": "Promin-Mono",
}

CORE_PATHS = {
    "manifest": CORE / "promin.manifest.json",
    "semantic": CORE / "semantic-model.json",
    "authority": CORE / "authority-model.json",
    "policy": CORE / "policy-set.json",
    "conformance": CORE / "conformance.json",
    "schema": CORE / "contracts.schema.json",
    "preset": PRESET_PATH,
}

OWNER = {
    "manifest": "core/promin.manifest.json",
    "semantic": "core/semantic-model.json",
    "authority": "core/authority-model.json",
    "policy": "core/policy-set.json",
    "conformance": "core/conformance.json",
    "schema": "core/contracts.schema.json",
    "preset": "presets/semantic-standard.json",
}

CURRENT_LANGUAGE = "en"

PUBLIC_COMMANDS = ("init", "doctor", "status", "next", "validate", "static-admission", "continue", "audit", "refresh", "context", "skills")

STANDARD_CANDIDATE_FIELDS = (
    "record_type",
    "standard_name",
    "version",
    "archive_sha256",
    "archive_bytes",
    "archive_member_manifest_digest",
    "package_manifest_digest",
    "checksums_digest",
    "core_bundle_digest",
    "preset_digest",
    "package_tool_digest",
    "validator_digest",
    "test_manifest_digest",
    "portable_implementation_closure_digest",
    "candidate_binding_digest",
)

STANDARD_EVIDENCE_MANIFEST_FIELDS = (
    "record_type",
    "standard_name",
    "version",
    "candidate_binding_digest",
    "entries",
    "evidence_manifest_digest",
)

STANDARD_DECISION_FIELDS = (
    "record_type",
    "decision_id",
    "standard_name",
    "version",
    "candidate_binding_digest",
    "evidence_manifest_digest",
    "outcome",
    "decider_id",
    "release_capability",
    "trust_root_id",
    "signature_provider_id",
    "key_id",
    "nonce",
    "decided_at",
    "signed_claim_digest",
    "signature",
)

UA_LABELS = {
    "Accepted root definition": "Прийняте кореневе визначення",
    "Allowed next state": "Дозволений наступний стан",
    "Authority": "Повноваження",
    "Authority status": "Статус повноважень",
    "Authorization proof": "Доказ авторизації",
    "Binding equality": "Рівність прив'язки",
    "Binding": "Прив'язка",
    "Budgets": "Бюджети",
    "Bytes": "Байти",
    "Canonical value": "Канонічне значення",
    "Capabilities": "Можливості",
    "Capability": "Можливість",
    "Capability IDs": "Ідентифікатори можливостей",
    "Capability resolution": "Визначення можливості",
    "Claim component": "Компонент твердження",
    "Command": "Команда",
    "Command kind": "Тип команди",
    "Commands": "Команди",
    "Constraint": "Обмеження",
    "Continuation field": "Поле продовження",
    "Definition": "Визначення",
    "Default depth": "Типова глибина",
    "Depth": "Глибина",
    "Derived projection": "Похідна проєкція",
    "Effect scope": "Область дії",
    "Evidence field": "Поле evidence",
    "Entities": "Сутності",
    "Entity": "Сутність",
    "Forbidden boundary": "Заборонена межа",
    "ID": "ID",
    "Installed record": "Встановлений запис",
    "Kind": "Тип",
    "Lease": "Оренда",
    "Meaning": "Значення",
    "Mode": "Режим",
    "Mutation family": "Сімейство мутацій",
    "Mutation probe ID": "ID мутаційної перевірки",
    "Name": "Назва",
    "Owner": "Власник",
    "Parallel": "Паралельність",
    "Predicate ID": "ID предиката",
    "Preset field": "Поле preset",
    "Preset provider class": "Клас провайдера preset",
    "Profile": "Профіль",
    "Property": "Властивість",
    "Purpose": "Призначення",
    "Reference benchmark": "Еталонне вимірювання",
    "Relation": "Відношення",
    "Relations": "Відношення",
    "Required": "Обов'язкове",
    "Required fields": "Обов'язкові поля",
    "Required capability": "Обов'язкова можливість",
    "Required result": "Обов'язковий результат",
    "Role preset": "Preset ролі",
    "Rule": "Правило",
    "Rules": "Правила",
    "Scale contract": "Контракт масштабування",
    "Schema": "Схема",
    "Severity": "Критичність",
    "SHA256": "SHA256",
    "Sole function": "Єдина функція",
    "Source": "Джерело",
    "Source / field": "Джерело / поле",
    "State": "Стан",
    "Statement": "Твердження",
    "Stream invariant": "Інваріант потоку",
    "Structural budget": "Структурний бюджет",
    "Structural rule": "Структурне правило",
    "StandardReleaseCandidateBinding field": "Поле StandardReleaseCandidateBinding",
    "StandardReleaseDecision field": "Поле StandardReleaseDecision",
    "StandardReleaseEvidenceManifest field": "Поле StandardReleaseEvidenceManifest",
    "HumanDocumentVerification field": "Поле HumanDocumentVerification",
    "Surface": "Поверхня команд",
    "Target": "Ціль",
    "Target rule": "Правило цілі",
    "Task": "Завдання",
    "Tier": "Рівень",
    "Trust mode": "Режим довіри",
    "Validator": "Валідатор",
    "Validator / predicate ID": "ID валідатора / предиката",
    "Validator ID": "ID валідатора",
    "Value": "Значення",
    "Value object": "Об'єкт-значення",
    "Bounded retrieval rule": "Правило обмеженого пошуку",
    "Execution truth": "Фактичне виконання",
    "Scale mode": "Режим масштабування",
    "WorkCard ceiling": "Граничні значення WorkCard",
    "command authorization Grant": "Grant авторизації команди",
    "admin": "адміністративні",
    "base": "основні",
    "derived and non-authoritative": "похідна та ненормативна",
    "composed structural definition": "складене структурне визначення",
    "exact match": "точний збіг",
    "holder Grant": "Grant утримувача",
    "no": "ні",
    "non-authoritative": "ненормативний",
    "optional": "необов'язкові",
    "required": "обов'язкові",
    "yes": "так",
}

UA_PROSE = {
    "at least one for pass, fail, or blocked": "щонайменше один для pass, fail або blocked",
    "both false for product credit": "обидва false для product credit",
    "exact candidate identity": "точна ідентичність кандидата",
    "immutable CAS content identity": "незмінна ідентичність вмісту CAS",
    "physically resolved evidence set": "фізично перевірений набір evidence",
    "resolved command capability": "визначена capability команди",
    "signed approve-or-reject claim": "підписане твердження approve або reject",
    "true only for fresh resolved passing product-execution evidence": "true лише для свіжого, вирішеного, успішного evidence класу product-execution",
    "A lease-bound command is admissible only when authorization proves the exact command capability, holder_authorization independently proves task.execute, both exact Grant claims bind the same subject, Activation and conjunctive effect scope, the referenced Lease is current and ACTIVE at issued_at, and task, generation, fence, candidate, context, and WorkCard digests match exactly.": "Команда, прив'язана до Lease, допустима лише тоді, коли authorization доводить точну capability команди, holder_authorization незалежно доводить task.execute, обидва точні твердження Grant прив'язують той самий subject, Activation і conjunctive effect scope, зазначена Lease є поточною й ACTIVE у момент issued_at, а task, generation, fence, candidate, context і digests WorkCard збігаються точно.",
    "authority.json configures root ceilings and Activation only. Root command proofs bind one command intent and may issue only the first authority.manage Grant. Every Grant proof binds claim_digest; later Grants cite an active authority.manage issuer Grant or verified team signatures.": "authority.json налаштовує лише root ceilings і Activation. Докази root command прив'язують один command intent і можуть видати лише перший Grant authority.manage. Кожний доказ Grant прив'язує claim_digest; наступні Grants посилаються на активний issuer Grant authority.manage або перевірені team signatures.",
    "Bind one immutable Core bundle, one selected preset, five explicit init plan inputs, one operating profile, and one trust mode.": "Прив'язувати один immutable Core bundle, один вибраний preset, п'ять explicit init plan inputs, один operating profile і один trust mode.",
    "Parse explicit configuration, canonicalize JSON, and run local CLI orchestration.": "Розбирати explicit configuration, канонізувати JSON і виконувати local CLI orchestration.",
    "Provide one local-writer lock, atomic replace, file sync, directory sync, and recovery primitives.": "Надавати один local-writer lock, atomic replace, file sync, directory sync і recovery primitives.",
    "Prove one subject capability within one activation, time interval, nonce, and scope.": "Доводити одну capability subject у межах однієї Activation, time interval, nonce і scope.",
    "Rebuild or verify non-authoritative projections.": "Перебудовувати або перевіряти ненормативні проєкції.",
    "A bounded generated context package for one Task.": "Обмежений згенерований пакет контексту для одного Task.",
    "A command may report a scan, healthcheck, validation, or durability action only when that action was actually executed and evidence-bound.": "Команда може повідомляти про scan, healthcheck, validation або durability action лише тоді, коли дію фактично виконано та прив'язано до доказів.",
    "A digest alone never authorizes an action.": "Сам digest ніколи не авторизує дію.",
    "A duplicate idempotency key under the same activation and subject returns the original result or a conflict.": "Повторний idempotency key у межах тієї самої Activation і subject повертає початковий результат або конфлікт.",
    "A Lease never grants validation, resolution, waiver, promotion, or release authority.": "Lease ніколи не надає повноважень на validation, resolution, waiver, promotion або release.",
    "A lease-bound command is admissible only when its subject and authorization Grant match the bounded WorkCard, the referenced Lease is current and ACTIVE at issued_at, and task, generation, fence, candidate, Activation, context, and WorkCard digests match exactly.": "Команда, прив'язана до Lease, допустима лише тоді, коли її subject та authorization Grant відповідають обмеженому WorkCard, зазначена Lease є поточною й ACTIVE у момент issued_at, а task, generation, fence, candidate, Activation, context і digest WorkCard збігаються точно.",
    "A machine-addressable invariant owned by policy-set.json.": "Машинно-адресований інваріант, власником якого є policy-set.json.",
    "A preset may configure provider needs and budgets but cannot grant action authority.": "Preset може налаштовувати потреби в провайдерах і бюджети, але не може надавати повноваження на дії.",
    "A pure decision rule.": "Чисте правило ухвалення рішення.",
    "A pure ordering or equality rule.": "Чисте правило впорядкування або рівності.",
    "A read-only request that cannot mutate authoritative state.": "Read-only запит, який не може змінювати нормативний стан.",
    "A state-changing request validated before commit.": "Запит на зміну стану, перевірений до commit.",
    "Acquire, heartbeat, close, expire, or revoke Leases.": "Отримувати, підтверджувати heartbeat, закривати, завершувати строк або відкликати Lease.",
    "Activate one digest-bound repository configuration.": "Активувати одну конфігурацію репозиторію, прив'язану до digest.",
    "Activation binds exactly project.json, standards.json, technologies.json, and authority.json.": "Activation прив'язує рівно project.json, standards.json, technologies.json і authority.json.",
    "Build adapters are optional and must not redefine the semantic model.": "Build adapters є необов'язковими й не повинні перевизначати семантичну модель.",
    "Build one disposable status, next, impact, and search projection.": "Будувати одну disposable projection для status, next, impact і search.",
    "Compute content digests and content-addressed object identities.": "Обчислювати content digests та ідентичності content-addressed objects.",
    "Coordinate temporary mutation ownership through generation, fencing, expiry, heartbeat, and close acknowledgement.": "Координувати тимчасове володіння мутацією через generation, fencing, expiry, heartbeat і підтвердження закриття.",
    "Core and selected preset inputs reject symlinks and unexpected shadow files.": "Вхідні Core і вибраний preset відхиляють symlink та неочікувані shadow files.",
    "Core bundle identity excludes replaceable presets; Activation binds the selected preset separately.": "Ідентичність Core bundle не включає замінні presets; Activation прив'язує вибраний preset окремо.",
    "Create a sanitized external package.": "Створювати очищений зовнішній пакет.",
    "Create, split, order, or block Tasks.": "Створювати, ділити, впорядковувати або блокувати Tasks.",
    "Duplicate JSON keys and path or ID collisions after NFC/casefold normalization are rejected.": "Повторні JSON keys і колізії path або ID після NFC/casefold normalization відхиляються.",
    "Effective search seed count reserves entity and relation capacity for typed closure at the requested dependency depth; top_k is a ceiling, not a mandatory fill target.": "Ефективна кількість search seeds резервує місткість сутностей і відношень для typed closure на запитаній dependency depth; top_k є межею, а не обов'язковою ціллю заповнення.",
    "Evaluate gates without promotion or release authority.": "Оцінювати gates без повноважень на promotion або release.",
    "Every authoritative record binds the exact active Core, preset, init, and profile configuration.": "Кожний нормативний запис прив'язує точну активну конфігурацію Core, preset, init і profile.",
    "Every command resolves to exactly one Core-owned capability; requested scope retains every authorization constraint and explicitly contains every command effect target.": "Кожна команда визначає рівно одну capability, власником якої є Core; requested scope зберігає кожне authorization constraint і явно містить кожну ціль впливу команди.",
    "Every committed batch binds exactly one subject, validated command digest, command intent digest, authorization digest, and idempotency key.": "Кожний committed batch прив'язує рівно один subject, validated command digest, command intent digest, authorization digest та idempotency key.",
    "Every Decision names one typed target and the decision kind, requested scope, candidate, and authority are consistent with that target.": "Кожний Decision називає одну типізовану ціль, а decision kind, requested scope, candidate і authority узгоджені з цією ціллю.",
    "Every Grant proof binds claim_digest and is either the one bootstrap root issuance, a verified team threshold, or an active authority.manage issuer Grant.": "Кожний доказ Grant прив'язує claim_digest і є або єдиним bootstrap root issuance, або перевіреним team threshold, або активним issuer Grant з authority.manage.",
    "Every mutation uses the current active Lease generation and monotonic fencing token.": "Кожна мутація використовує поточну активну generation Lease та монотонний fencing token.",
    "Every required provider identity and healthcheck succeeds before initialization is committed; a declared provider is not evidence of availability.": "Кожна обов'язкова provider identity і healthcheck успішно перевіряється до commit ініціалізації; оголошений provider не є доказом доступності.",
    "Every WorkCard stays within both Core hard ceilings and its selected profile budget.": "Кожний WorkCard залишається в межах hard ceilings Core і бюджету вибраного profile.",
    "Evidence binds candidate, policy, provider/tool, and input digests.": "Evidence прив'язує candidate, policy, provider/tool та input digests.",
    "Evidence binds Activation, candidate, policy, provider/tool, and input digests inside the immutable Artifact event payload.": "Evidence прив'язує Activation, candidate, policy, provider/tool та input digests усередині незмінного event payload Artifact.",
    "Execute cutover, rollback, and deterministic recutover.": "Виконувати cutover, rollback і deterministic recutover.",
    "Execute one Task inside its WorkCard and valid Lease.": "Виконувати один Task у межах його WorkCard і чинної Lease.",
    "Export is allowlisted, recursively bounded, symlink-safe, secret-aware, and path-sanitized.": "Export використовує allowlist, рекурсивно обмежений, безпечний щодо symlink і secrets та очищує paths.",
    "External standards and providers exist only in explicit digest-bound init records.": "Зовнішні стандарти та providers існують лише в explicit init records, прив'язаних до digest.",
    "File-level inventory and search proxies remain derived unless an independent invariant requires persistence.": "Inventory на рівні файлів і search proxies залишаються похідними, якщо незалежний інваріант не вимагає persistence.",
    "Gate pass credit is true exactly when normalized status is pass and every required gate passes.": "Gate pass credit дорівнює true лише тоді, коли normalized status є pass і кожний обов'язковий gate проходить.",
    "Identify immutable product, evidence, log, report, or diff bytes with provenance and retention metadata.": "Ідентифікувати незмінні bytes product, evidence, log, report або diff разом із provenance і retention metadata.",
    "Identify one immutable product snapshot independently from control state.": "Ідентифікувати один незмінний product snapshot незалежно від control state.",
    "Import project-specific build and dependency facts as derived projections.": "Імпортувати project-specific build і dependency facts як похідні проєкції.",
    "Init config defines root ceilings, never pre-activation runtime Grants.": "Init config визначає root ceilings, але ніколи не створює pre-activation runtime Grants.",
    "Initialization performs zero product-tree scans and creates exactly five init records.": "Ініціалізація виконує нуль product-tree scans і створює рівно п'ять init records.",
    "Issue or revoke runtime Grants within a configured root ceiling.": "Видавати або відкликати runtime Grants у межах налаштованого root ceiling.",
    "Missing, unknown, stale, downgraded, or unbound critical fields reject before mutation.": "Відсутні, невідомі, stale, downgraded або unbound critical fields спричиняють відхилення до мутації.",
    "Model strength changes decomposition, context, parallelism, and analysis depth; it never changes authority.": "Потужність моделі змінює декомпозицію, контекст, паралельність і глибину аналізу, але ніколи не змінює повноваження.",
    "multiple actors or remote transport": "кілька учасників або віддалений транспорт",
    "Must never run implicitly during initialization.": "Не повинна запускатися неявно під час ініціалізації.",
    "Must not be represented as distributed consensus.": "Не повинна подаватися як distributed consensus.",
    "Must not decide cross-record semantics or authority.": "Не повинна визначати cross-record semantics або повноваження.",
    "Must not invent policy, authority, or provider bindings.": "Не повинна вигадувати прив'язки policy, authority або provider.",
    "Mutation WorkCards require the current Lease; read-only WorkCards must not acquire or carry a mutation Lease.": "Mutation WorkCards потребують поточної Lease; read-only WorkCards не повинні отримувати або нести mutation Lease.",
    "One command batch binds the exact authorization claim and contains exactly one primary event equal to the validated command payload; auxiliary events are typed relations only and event IDs are unique.": "Один command batch прив'язує точне authorization claim і містить рівно одну primary event, рівну validated command payload; auxiliary events є лише типізованими відношеннями, а event IDs унікальні.",
    "One command produces one immutable batch under lock, compare-head, sync, atomic replace, and recovery.": "Одна команда створює один immutable batch через lock, compare-head, sync, atomic replace і recovery.",
    "One completed semantic step with explicit input, output, failure, and evidence semantics.": "Один завершений семантичний крок із явними семантиками input, output, failure і evidence.",
    "One requested inventory performs at most one full product-tree pass; all projections derive from its stream.": "Один запит inventory виконує не більше одного повного проходу product tree; усі проєкції походять із його stream.",
    "Only a valid CLOSED transition with explicit close acknowledgement releases a mutation slot.": "Лише чинний перехід до CLOSED з явним підтвердженням закриття звільняє слот мутації.",
    "Only CLOSED with a valid close_ack releases a mutation slot. EXPIRED or REVOKED requires scheduler reconciliation before slot reuse.": "Лише CLOSED із чинним close_ack звільняє слот мутації. EXPIRED або REVOKED потребує узгодження scheduler перед повторним використанням слота.",
    "Own acceptance predicates, mutation families, structural hard ceilings, scale contracts, and production-claim rules.": "Єдиний власник acceptance predicates, mutation families, structural hard ceilings, scale contracts і production-claim rules.",
    "Own action capabilities, runtime Grant semantics, trust modes, root ceilings, and separation-of-duty constraints.": "Єдиний власник action capabilities, runtime Grant semantics, trust modes, root ceilings і constraints розділення обов'язків.",
    "Own all structural, format, kind-specific payload, and strict critical-field contracts in one bundle.": "Єдиний власник усіх structural, format, kind-specific payload і strict critical-field contracts в одному bundle.",
    "Own Core bundle identity and exact digest binding for the five other Core artifacts.": "Єдиний власник ідентичності Core bundle і точного digest binding п'яти інших Core artifacts.",
    "Own executable cross-record invariants through stable validator identifiers and no duplicated budget values.": "Єдиний власник executable cross-record invariants через стабільні validator identifiers без дублювання budget values.",
    "Own the minimal persistent vocabulary, relation grammar, derived-projection boundary, and provider capability contracts.": "Єдиний власник мінімального persistent vocabulary, relation grammar, межі derived projection і provider capability contracts.",
    "Packaging alone is not a security boundary.": "Саме пакування не є security boundary.",
    "Pass, fail, and blocked gate results cite at least one immutable evidence digest; skipped results never receive pass credit.": "Gate results зі станом pass, fail або blocked посилаються щонайменше на один immutable evidence digest; skipped results ніколи не отримують pass credit.",
    "Perform an explicit one-pass product inventory and publish a digest-bound inventory stream.": "Виконувати explicit one-pass product inventory і публікувати inventory stream, прив'язаний до digest.",
    "Perform bounded recursive export inspection, allowlisting, secret classification, and symlink rejection.": "Виконувати bounded recursive export inspection, allowlisting, secret classification і відхилення symlink.",
    "Persistent graph stays within entity/relation budgets and derived file proxies stay non-authoritative.": "Persistent graph залишається в межах бюджетів entity/relation, а derived file proxies залишаються ненормативними.",
    "Projection content never becomes normative authority.": "Вміст проєкції ніколи не стає нормативним джерелом.",
    "Projection deletion and deterministic replay cannot change normative meaning.": "Видалення проєкції та deterministic replay не можуть змінити нормативне значення.",
    "Promote a validated Candidate.": "Просувати перевірений Candidate.",
    "Provider identity changes invalidate dependent evidence and projections but never silently change authority.": "Зміни provider identity роблять залежні evidence і projections нечинними, але ніколи не змінюють повноваження неявно.",
    "Publish candidate-bound evidence Artifacts.": "Публікувати evidence Artifacts, прив'язані до candidate.",
    "Ranking ties are deterministic and acceptance-critical facts are added by typed closure, not fuzzy ranking.": "Однакові ranking scores розв'язуються детерміновано, а acceptance-critical facts додаються через typed closure, не fuzzy ranking.",
    "Record an authorized acceptance, rejection, resolution, waiver, promotion, or release judgement.": "Записувати авторизоване рішення про acceptance, rejection, resolution, waiver, promotion або release.",
    "Record an observed defect or policy violation with explicit effective-blocking semantics.": "Записувати спостережений дефект або порушення policy з явною effective-blocking semantics.",
    "Record final release acceptance or rejection.": "Записувати фінальне прийняття або відхилення release.",
    "Record Findings.": "Записувати Findings.",
    "Record one execution or validation attempt against exact candidate, policy, tool, and input digests.": "Записувати одну спробу execution або validation щодо точних candidate, policy, tool та input digests.",
    "Reference package success is necessary but not sufficient. Live production credit requires all P0/P1 findings closed with candidate-bound evidence, rollback and recutover equivalence, and an authorized human release Decision.": "Успіх еталонного пакета є необхідним, але недостатнім. Live production credit потребує закриття всіх Findings P0/P1 доказами, прив'язаними до Candidate, еквівалентності rollback і recutover та авторизованого release Decision людини.",
    "Repeated initialization succeeds only when the requested canonical configuration digest exactly equals the existing Activation; otherwise it reports conflict.": "Повторна ініціалізація успішна лише тоді, коли запитаний canonical configuration digest точно дорівнює наявній Activation; інакше повертається конфлікт.",
    "Represent one schedulable unit with one acceptance predicate and bounded mutation scope.": "Представляти одну плановану одиницю з одним acceptance predicate та обмеженою mutation scope.",
    "Resolve Findings with evidence.": "Вирішувати Findings за допомогою evidence.",
    "Root command authorization signs one command intent and may issue the first authority.manage Grant only; it cannot execute ordinary project commands.": "Root command authorization підписує один command intent і може видати лише перший Grant authority.manage; вона не може виконувати звичайні команди проєкту.",
    "Select Semantic Programming plus generic decomposition, retrieval, and parallelism budgets without granting action authority.": "Вибирати Semantic Programming і загальні бюджети декомпозиції, retrieval та parallelism без надання повноважень на дії.",
    "Sign or verify activation, Grant, and Decision digests for team trust mode.": "Підписувати або перевіряти digests Activation, Grant і Decision для team trust mode.",
    "single-machine owner-controlled root authority": "root authority однієї машини під контролем власника",
    "Status, next, and WorkCard generation reject a projection whose source head or activation differs.": "Генерація status, next і WorkCard відхиляє проєкцію, source HEAD або Activation якої відрізняється.",
    "Subject, capability, conjunctive scope, interval, nonce, exact claim digest, proof chain, revocation state, and Activation all match.": "Subject, capability, conjunctive scope, interval, nonce, exact claim digest, proof chain, revocation state і Activation повністю збігаються.",
    "Task and Lease transitions are accepted only by the policy-owned state machines; generated lifecycle views cannot invent transitions.": "Переходи Task і Lease приймаються лише state machines, власником яких є policy; generated lifecycle views не можуть вигадувати переходи.",
    "Team-signature fields are never treated as valid without a configured verifier callback and threshold evaluation.": "Поля team signature ніколи не вважаються чинними без налаштованого verifier callback і threshold evaluation.",
    "The canonical identity is promin; aliases, redirects, and compatibility names are rejected.": "Канонічна ідентичність - promin; aliases, redirects і compatibility names відхиляються.",
    "The command authorization Grant and holder Grant are resolved and validated independently; they may be the same record only when the required command capability is task.execute.": "Grant авторизації команди та holder Grant визначаються й перевіряються незалежно; вони можуть бути одним записом лише тоді, коли обов'язкова capability команди є task.execute.",
    "The Core must not require a particular signer implementation.": "Core не повинен вимагати конкретної реалізації signer.",
    "Timestamps use canonical UTC seconds and issued, heartbeat, expiry, finish, and decision order is semantically checked.": "Timestamps використовують canonical UTC seconds; порядок issued, heartbeat, expiry, finish і decision перевіряється семантично.",
    "Validate the single Draft 2020-12 contract bundle with enforced formats and local references.": "Перевіряти єдиний contract bundle Draft 2020-12 з обов'язковими formats і local references.",
    "Waive Findings through an explicit Decision.": "Надавати waiver для Findings через explicit Decision.",
    "NetValue remains >0 when benefits decrease 20 percent and costs increase 20 percent": "NetValue залишається >0, коли вигоди зменшуються на 20 відсотків, а витрати зростають на 20 відсотків",
    "require current Lease and bounded WorkCard for direct mutation": "вимагати поточну Lease й обмежений WorkCard для прямої мутації",
    "require current Lease and bounded WorkCard for execution transition": "вимагати поточну Lease й обмежений WorkCard для переходу execution",
    "forbid mutation binding on non-lease command": "заборонити mutation binding для команди без Lease",
    "require current Lease generation and fence for mutation": "вимагати поточні generation і fence Lease для мутації",
    "require replay-complete immutable evidence metadata": "вимагати незмінні metadata evidence, достатні для replay",
    "product credit requires fresh resolved passing product execution evidence": "product credit потребує свіжого, вирішеного, успішного evidence виконання продукту",
    "promin composed contracts": "складені контракти promin",
}


def localized(value: Any) -> Any:
    if CURRENT_LANGUAGE != "ua":
        return value
    if isinstance(value, str):
        return UA_PROSE.get(value, UA_LABELS.get(value, value))
    if isinstance(value, list):
        return [localized(item) for item in value]
    if isinstance(value, dict):
        return {key: localized(item) for key, item in value.items()}
    return value


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_argument(value: str) -> str:
    digest = value.strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise argparse.ArgumentTypeError("expected a 64-character SHA-256 digest")
    return digest


def verify_sources(data: dict[str, dict[str, Any]]) -> None:
    manifest = data["manifest"]
    if manifest.get("canonical_name") != "promin":
        raise ValueError("manifest canonical_name must be promin")
    version = manifest.get("version")
    if not isinstance(version, str) or SEMVER.fullmatch(version) is None:
        raise ValueError("manifest version must be canonical SemVer")
    components = manifest.get("core_components")
    if not isinstance(components, list) or len(components) != 5:
        raise ValueError("manifest must bind exactly five other Core components")
    expected_paths = {
        "semantic-model.json",
        "authority-model.json",
        "policy-set.json",
        "conformance.json",
        "contracts.schema.json",
    }
    actual_paths = {item.get("path") for item in components}
    if actual_paths != expected_paths:
        raise ValueError(f"unexpected Core component set: {sorted(actual_paths)}")
    for item in components:
        component = CORE / str(item["path"])
        actual = sha256_file(component)
        if actual != item.get("sha256"):
            raise ValueError(f"Core digest mismatch for {component.name}")
    if data["schema"].get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise ValueError("contracts schema must use Draft 2020-12")
    for key in ("semantic", "authority", "policy", "conformance", "schema", "preset"):
        if data[key].get("version") != version:
            raise ValueError(f"{key} version does not match the Core manifest")

    preset = data["preset"]
    if tuple(preset.get("base_user_commands", ())) != PUBLIC_COMMANDS:
        raise ValueError("preset public command surface must match the canonical public command list")
    forbidden_keys = {
        "optional_" + "user_commands",
        "admin_" + "commands",
        "max_" + "evidence",
    }

    def walk(value: Any) -> Iterable[Any]:
        yield value
        if isinstance(value, Mapping):
            for item_key, item_value in value.items():
                yield item_key
                yield from walk(item_value)
        elif isinstance(value, list):
            for item in value:
                yield from walk(item)

    all_values = tuple(walk(data))
    forbidden_found = sorted({value for value in all_values if isinstance(value, str) and value in forbidden_keys})
    if forbidden_found:
        raise ValueError(f"removed legacy fields remain: {forbidden_found}")
    unsupported_snapshot = "immutable-filesystem-" + "snapshot"
    if any(isinstance(value, str) and unsupported_snapshot in value for value in all_values):
        raise ValueError("unsupported snapshot mode remains in canonical inputs")

    defs = data["schema"].get("$defs", {})
    required_definitions = {
        "AuthorityRuntimePolicy",
        "ContinuationTokenClaims",
        "ContinueResult",
        "CurrentInventory",
        "DoctorResult",
        "EventBatch",
        "EventStorePolicy",
        "GateEvidenceArtifactBinding",
        "GateRunDefinition",
        "HumanDocumentVerification",
        "InventoryInputManifest",
        "InventoryProjectionRow",
        "NextResult",
        "OperationMetrics",
        "ProjectionLimits",
        "ProviderInvocationEvidence",
        "ReadyFrontier",
        "ResearchDraftIntake",
        "RetrievalPage",
        "SanitizedResearchDraft",
        "SemanticExport",
        "SemanticStatePayload",
        "StandardReleaseCandidateBinding",
        "StandardReleaseDecision",
        "StandardReleaseEvidenceEntry",
        "StandardReleaseEvidenceManifest",
        "StandardReleaseTrustConfiguration",
        "WorkCard",
        "WorkCardProjection",
    }
    missing_definitions = sorted(
        name for name in required_definitions if not isinstance(defs.get(name), Mapping)
    )
    if missing_definitions:
        raise ValueError(
            "schema omits required canonical definitions: "
            + ", ".join(missing_definitions)
        )
    serialized = json.dumps(data, ensure_ascii=False, sort_keys=True)
    required_contract_tokens = (
        "untrusted-source",
        "implementation_closure_digest",
        "grant_claim_digest",
        "revocation_epoch",
        "projection.read",
        "StandardReleaseCandidateBinding",
        "StandardReleaseEvidenceManifest",
        "HumanDocumentVerification",
        "standard.distribute",
    )
    missing_tokens = [token for token in required_contract_tokens if token not in serialized]
    if missing_tokens:
        raise ValueError(f"canonical inputs omit required bindings: {missing_tokens}")

    acceptance = data["conformance"].get("required_acceptance")
    if not isinstance(acceptance, list) or len(acceptance) != 102:
        raise ValueError("promin 1.0.0 human projection requires exactly 102 acceptance predicates")
    if "dependency-graph-acyclic-and-current-ready-frontier" not in acceptance:
        raise ValueError("acceptance omits the current acyclic ReadyFrontier predicate")

    policies = data["policy"].get("policies")
    if isinstance(policies, list):
        policy_ids = {
            item.get("id")
            for item in policies
            if isinstance(item, Mapping)
        }
    else:
        policy_ids = set()
    required_policy_ids = {f"P-{index:03d}" for index in range(57, 69)}
    if not required_policy_ids.issubset(policy_ids):
        raise ValueError(
            "policy owner omits required standard invariants: "
            + ", ".join(sorted(required_policy_ids - policy_ids))
        )

    derived = data["policy"].get("derived_result_contracts")
    if not isinstance(derived, Mapping) or set(derived) != {
        "DoctorResult",
        "OperationMetrics",
        "ReadyFrontier",
        "RetrievalPage",
        "WorkCardProjection",
    }:
        raise ValueError("derived result owner must define exactly the five canonical live-only results")
    research = data["policy"].get("research_draft_sanitation")
    if not isinstance(research, Mapping) or research.get("result_record_type") != "SanitizedResearchDraft":
        raise ValueError("research draft sanitation owner is missing or inconsistent")
    semantic_export = data["policy"].get("semantic_export_contract")
    if not isinstance(semantic_export, Mapping) or semantic_export.get("output_record_type") != "SemanticStatePayload":
        raise ValueError("semantic export owner is missing or inconsistent")

    capabilities = data["semantic"].get("technology_capabilities")
    if isinstance(capabilities, list):
        protocol_ids = {
            item.get("adapter_protocol", {}).get("protocol_id")
            for item in capabilities
            if isinstance(item, Mapping)
            and isinstance(item.get("adapter_protocol"), Mapping)
        }
    else:
        protocol_ids = set()
    expected_protocol_ids = {
        "promin.build-dependency.v1",
        "promin.content-identity.v1",
        "promin.control-runtime.v1",
        "promin.export-scan.v1",
        "promin.filesystem-inventory.v1",
        "promin.local-serialization.v1",
        "promin.query-projection.v1",
        "promin.shape-validation.v1",
        "promin.signature.v1",
    }
    if protocol_ids != expected_protocol_ids:
        raise ValueError("semantic owner must define exactly the nine canonical promin protocols")

    profiles = data["preset"].get("profiles")
    if not isinstance(profiles, Mapping) or set(profiles) != {
        "baseline",
        "balanced",
        "extended",
    }:
        raise ValueError("selected preset must preserve the three canonical model profiles")


def verify_document_sources() -> None:
    documents = {
        path.name: path.read_text(encoding="utf-8")
        for path in (README_PATH, MACHINE_README_PATH)
    }
    forbidden_tokens = (
        "Agent" + "Doc",
        "PROMIN_" + "FULL",
        "--project-" + "id",
        "--source-" + "root",
        "state:" + "READY",
        "--" + "query READY",
        "version 1." + "1",
        "версія 1." + "1",
        "V" + "10",
        "V" + "5",
    )
    for name, text in documents.items():
        missing = [token for token in DOCUMENT_REQUIRED_TOKENS if token not in text]
        if missing:
            raise ValueError(f"{name} omits required standard content: {missing}")
        present_forbidden = [token for token in forbidden_tokens if token in text]
        if present_forbidden:
            raise ValueError(f"{name} contains stale identity or CLI content: {present_forbidden}")
        if EXPLICIT_EMIT_PLAN_EXAMPLE not in text:
            raise ValueError(f"{name} omits the exact explicit --emit-plan example")
        if EXPLICIT_TEAM_INIT_EXAMPLE not in text:
            raise ValueError(f"{name} omits the exact team-signed init example")

    machine = documents[MACHINE_README_PATH.name]
    if "next --subject SUBJECT --grant HOLDER_GRANT --query-grant QUERY_GRANT" not in machine:
        raise ValueError("MACHINE_README.md omits the ReadyFrontier next example")
    removed_search_form = (
        "next --subject SUBJECT --grant HOLDER_GRANT --query-grant QUERY_GRANT --"
        + "query"
    )
    if removed_search_form in machine:
        raise ValueError("MACHINE_README.md exposes the removed next search expression")


def font_bindings_from_args(args: argparse.Namespace) -> dict[str, tuple[Path, str]]:
    return {
        role: (getattr(args, f"font_{role}"), getattr(args, f"font_{role}_sha256"))
        for role in FONT_FACES
    }


def register_fonts(bindings: Mapping[str, tuple[Path, str]]) -> dict[str, dict[str, Any]]:
    if set(bindings) != set(FONT_FACES):
        raise ValueError(f"font roles must be exactly: {', '.join(FONT_FACES)}")

    verified: dict[str, tuple[bytes, str]] = {}
    for role in FONT_FACES:
        path, expected_digest = bindings[role]
        path = path.expanduser()
        if not path.is_file():
            raise FileNotFoundError(f"required {role} font is not a regular file: {path}")
        content = path.read_bytes()
        actual_digest = hashlib.sha256(content).hexdigest()
        if actual_digest != expected_digest:
            raise ValueError(
                f"{role} font digest mismatch: expected={expected_digest} actual={actual_digest}"
            )
        verified[role] = (content, actual_digest)

    evidence: dict[str, dict[str, Any]] = {}
    for role, pdf_name in FONT_FACES.items():
        content, digest = verified[role]
        pdfmetrics.registerFont(TTFont(pdf_name, io.BytesIO(content)))
        evidence[role] = {
            "bytes": len(content),
            "pdf_font_name": pdf_name,
            "sha256": digest,
        }
    pdfmetrics.registerFontFamily(
        "Promin",
        normal="Promin",
        bold="Promin-Bold",
        italic="Promin-Italic",
        boldItalic="Promin-Bold",
    )
    return evidence


def build_evidence(
    data: Mapping[str, Mapping[str, Any]],
    fonts: Mapping[str, Mapping[str, Any]],
    outputs: Sequence[Path],
    *,
    check_only: bool,
) -> dict[str, Any]:
    return {
        "record_type": "ProminHumanProjectionBuildEvidence",
        "version": 1,
        "status": "pass",
        "pass_credit": False,
        "product_acceptance_pass": False,
        "mode": "check-only" if check_only else "build",
        "generator_sha256": sha256_file(Path(__file__).resolve()),
        "reportlab_version": REPORTLAB_VERSION,
        "core_bundle_digest": data["manifest"]["bundle_digest"],
        "selected_preset_sha256": sha256_file(PRESET_PATH),
        "font_bindings": {role: dict(fonts[role]) for role in FONT_FACES},
        "outputs": [
            {
                "bytes": path.stat().st_size,
                "path": path.name,
                "sha256": sha256_file(path),
            }
            for path in outputs
        ],
    }


def write_evidence(path: Path, evidence: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def styles() -> dict[str, ParagraphStyle]:
    sample = getSampleStyleSheet()
    base = ParagraphStyle(
        "Body",
        parent=sample["BodyText"],
        fontName="Promin",
        fontSize=9.2,
        leading=12.5,
        textColor=colors.HexColor("#1F252B"),
        spaceAfter=5,
        wordWrap="CJK",
        allowWidows=0,
        allowOrphans=0,
    )
    return {
        "body": base,
        "body_compact": ParagraphStyle("BodyCompact", parent=base, fontSize=8.1, leading=10.2, spaceAfter=2),
        "small": ParagraphStyle("Small", parent=base, fontSize=7.1, leading=8.8, spaceAfter=1.5),
        "source": ParagraphStyle(
            "Source",
            parent=base,
            fontName="Promin-Italic",
            fontSize=7.2,
            leading=9,
            textColor=colors.HexColor("#59636E"),
            borderColor=colors.HexColor("#D7DCE1"),
            borderWidth=0.5,
            borderPadding=4,
            backColor=colors.HexColor("#F7F8F9"),
            spaceBefore=2,
            spaceAfter=7,
        ),
        "h1": ParagraphStyle(
            "Heading1",
            parent=base,
            fontName="Promin-Bold",
            fontSize=18,
            leading=21,
            textColor=colors.HexColor("#101820"),
            spaceBefore=12,
            spaceAfter=7,
            keepWithNext=True,
        ),
        "h2": ParagraphStyle(
            "Heading2",
            parent=base,
            fontName="Promin-Bold",
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#263746"),
            spaceBefore=9,
            spaceAfter=5,
            keepWithNext=True,
        ),
        "h3": ParagraphStyle(
            "Heading3",
            parent=base,
            fontName="Promin-Bold",
            fontSize=10.2,
            leading=13,
            textColor=colors.HexColor("#3C4A56"),
            spaceBefore=6,
            spaceAfter=3,
            keepWithNext=True,
        ),
        "cover_small": ParagraphStyle(
            "CoverSmall",
            parent=base,
            fontName="Promin",
            fontSize=11.5,
            leading=14,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#101820"),
        ),
        "cover_brand": ParagraphStyle(
            "CoverBrand",
            parent=base,
            fontName="Promin-Bold",
            fontSize=31,
            leading=36,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#101820"),
        ),
        "toc_title": ParagraphStyle(
            "TocTitle",
            parent=base,
            fontName="Promin-Bold",
            fontSize=20,
            leading=24,
            spaceAfter=12,
        ),
        "code": ParagraphStyle(
            "Code",
            parent=base,
            fontName="Promin-Mono",
            fontSize=7.3,
            leading=9.2,
            leftIndent=5,
            rightIndent=5,
            borderColor=colors.HexColor("#CDD5DC"),
            borderWidth=0.5,
            borderPadding=5,
            backColor=colors.HexColor("#F5F7F8"),
            spaceBefore=3,
            spaceAfter=7,
            wordWrap="CJK",
        ),
        "table_head": ParagraphStyle(
            "TableHead",
            parent=base,
            fontName="Promin-Bold",
            fontSize=7.1,
            leading=8.7,
            textColor=colors.white,
            spaceAfter=0,
        ),
        "table": ParagraphStyle(
            "TableCell",
            parent=base,
            fontSize=7.1,
            leading=8.8,
            spaceAfter=0,
            wordWrap="CJK",
        ),
    }


class ProminDocTemplate(BaseDocTemplate):
    def __init__(self, filename: str, *, title: str, language: str, version: str, style_map: dict[str, ParagraphStyle]):
        super().__init__(
            filename,
            pagesize=A4,
            leftMargin=18 * mm,
            rightMargin=18 * mm,
            topMargin=17 * mm,
            bottomMargin=17 * mm,
            title=title,
            author="PROMIN STANDARD",
            subject=title,
            creator="promin/tools/generate_human.py",
        )
        self.language = language
        self.version = version
        self.style_map = style_map
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id="normal")
        self.addPageTemplates(PageTemplate(id="promin", frames=[frame], onPage=self._page))

    def _page(self, canvas: Any, doc: Any) -> None:
        canvas.saveState()
        canvas.setFont("Promin", 7.2)
        canvas.setFillColor(colors.HexColor("#59636E"))
        version_text = (f"версія {self.version}" if self.language == "ua" else f"version {self.version}")
        if doc.page == 1:
            canvas.drawCentredString(PAGE_WIDTH / 2, 12 * mm, version_text)
        else:
            canvas.drawString(self.leftMargin, 10 * mm, "promin")
            canvas.drawCentredString(PAGE_WIDTH / 2, 10 * mm, version_text)
            canvas.drawRightString(PAGE_WIDTH - self.rightMargin, 10 * mm, str(doc.page))
        canvas.restoreState()

    def afterFlowable(self, flowable: Flowable) -> None:
        if not isinstance(flowable, Paragraph):
            return
        style_name = flowable.style.name
        if style_name not in {"Heading1", "Heading2", "Heading3"}:
            return
        level = {"Heading1": 0, "Heading2": 1, "Heading3": 2}[style_name]
        text = flowable.getPlainText()
        key = getattr(flowable, "_promin_anchor", None)
        if key:
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(text, key, level=level, closed=level > 0)
        self.notify("TOCEntry", (level, text, self.page, key))


def para(text: Any, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(str(localized(text))).replace("\n", "<br/>"), style)


def rich(text: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(text, style)


def anchor_id(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return normalized or "section"


def add_heading(story: list[Flowable], title: str, level: int, key: str, st: dict[str, ParagraphStyle]) -> None:
    flowable = Paragraph(f"<a name='{escape(key)}'/>{escape(title)}", st[f"h{level}"])
    flowable._promin_anchor = key  # type: ignore[attr-defined]
    story.append(flowable)


def source(story: list[Flowable], owner: str, validator: str, st: dict[str, ParagraphStyle]) -> None:
    owner_label = "Власник" if CURRENT_LANGUAGE == "ua" else "Owner"
    validator_label = "Валідатор" if CURRENT_LANGUAGE == "ua" else "Validator"
    story.append(para(f"{owner_label}: {owner} | {validator_label}: {validator}", st["source"]))


def bullet(story: list[Flowable], text: str, st: dict[str, ParagraphStyle], *, level: int = 0) -> None:
    style = ParagraphStyle(
        f"Bullet{level}",
        parent=st["body"],
        leftIndent=(5 + level * 5) * mm,
        firstLineIndent=-3.5 * mm,
        bulletIndent=(1.5 + level * 5) * mm,
        spaceAfter=2,
    )
    story.append(Paragraph(escape(str(localized(text))), style, bulletText="-"))


def cell(value: Any, st: dict[str, ParagraphStyle], *, head: bool = False) -> Paragraph:
    value = localized(value)
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(", ", ": "))
    return para(value, st["table_head" if head else "table"])


def make_table(
    headers: Sequence[str],
    rows: Iterable[Sequence[Any]],
    widths: Sequence[float],
    st: dict[str, ParagraphStyle],
    *,
    header_background: str = "#33485B",
) -> LongTable:
    converted = [[cell(value, st, head=True) for value in headers]]
    converted.extend([[cell(value, st) for value in row] for row in rows])
    table = LongTable(converted, colWidths=list(widths), repeatRows=1, hAlign=TA_LEFT, splitByRow=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(header_background)),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#C7CFD6")),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F6F8F9")]),
            ]
        )
    )
    return table


def code_block(story: list[Flowable], text: str, st: dict[str, ParagraphStyle]) -> None:
    for chunk_start in range(0, len(text.splitlines()), 28):
        lines = text.splitlines()[chunk_start : chunk_start + 28]
        story.append(Paragraph("<br/>".join(escape(line).replace(" ", "&#160;") for line in lines), st["code"]))


def cover(story: list[Flowable], st: dict[str, ParagraphStyle]) -> None:
    story.extend(
        [
            Spacer(1, 32 * mm),
            para("PROMIN STANDARD", st["cover_small"]),
            Spacer(1, 30 * mm),
            para("promin", st["cover_brand"]),
            PageBreak(),
        ]
    )


def toc(story: list[Flowable], title: str, st: dict[str, ParagraphStyle]) -> None:
    story.append(para(title, st["toc_title"]))
    contents = TableOfContents()
    contents.levelStyles = [
        ParagraphStyle("TOC1", fontName="Promin", fontSize=9.5, leading=13, leftIndent=0, firstLineIndent=0, spaceBefore=3),
        ParagraphStyle("TOC2", fontName="Promin", fontSize=8.5, leading=11, leftIndent=10, firstLineIndent=0, spaceBefore=1),
        ParagraphStyle("TOC3", fontName="Promin", fontSize=7.5, leading=9.5, leftIndent=20, firstLineIndent=0, spaceBefore=0),
    ]
    story.extend([contents, PageBreak()])


UA = {
    "toc": "Зміст",
    "main_title": "Основний стандарт",
    "appendix_title": "Додатки",
    "purpose": "Призначення і межі",
    "semantics": "Семантична модель і гранулярність",
    "init": "Ініціалізація",
    "authority": "Повноваження і контроль",
    "lifecycle": "Завдання, оренда, докази та рішення",
    "events": "Події, відтворення і цілісність",
    "retrieval": "Проєкція, пошук і продовження",
    "cli": "Команди і профілі",
    "validation": "Перевірка, міграція і перехід",
    "providers": "Межі технологій і провайдерів",
    "examples": "Робочі приклади",
}

EN = {
    "toc": "Contents",
    "main_title": "Standard",
    "appendix_title": "Appendices",
    "purpose": "Purpose and boundaries",
    "semantics": "Semantic model and granularity",
    "init": "Initialization",
    "authority": "Authority and control",
    "lifecycle": "Tasks, leases, evidence, and decisions",
    "events": "Events, replay, and integrity",
    "retrieval": "Projection, search, and continuation",
    "cli": "Commands and profiles",
    "validation": "Validation, migration, and cutover",
    "providers": "Technology and provider boundaries",
    "examples": "Working examples",
}


def main_story(data: dict[str, dict[str, Any]], language: str, st: dict[str, ParagraphStyle]) -> list[Flowable]:
    global CURRENT_LANGUAGE
    CURRENT_LANGUAGE = language
    tx = UA if language == "ua" else EN
    manifest = data["manifest"]
    sem = data["semantic"]
    auth = data["authority"]
    policy = data["policy"]
    conf = data["conformance"]
    schema = data["schema"]
    preset = data["preset"]
    policies = {item["id"]: item for item in policy["policies"]}
    defs = schema["$defs"]
    story: list[Flowable] = []
    cover(story, st)
    toc(story, tx["toc"], st)

    add_heading(story, tx["main_title"], 1, "main", st)
    if language == "ua":
        story.append(para(f"Канонічна версія стандарту: {manifest['version']}. promin визначає мінімальний, перевірюваний стандарт керування агентною роботою, де семантика, повноваження, докази та події мають однозначних власників. JSON Core є нормативним джерелом; цей текст є згенерованою робочою проєкцією тих самих фактів.", st["body"]))
    else:
        story.append(para(f"Canonical standard version: {manifest['version']}. promin defines a minimal, verifiable standard for agent work in which semantics, authority, evidence, and events have unambiguous owners. JSON Core is normative; this text is a generated operational projection of the same facts.", st["body"]))
    source(story, OWNER["manifest"], "bundle_digest + core_components", st)

    add_heading(
        story,
        "Canonical owners" if language == "en" else "Канонічні власники",
        2,
        "canonical-owners",
        st,
    )
    owner_rows = [
        (OWNER["manifest"], manifest["function"]),
        (OWNER["semantic"], sem["function"]),
        (OWNER["authority"], auth["function"]),
        (OWNER["policy"], policy["function"]),
        (OWNER["conformance"], conf["function"]),
        (OWNER["schema"], schema["function"]),
    ]
    story.append(make_table(["Core file", "Sole responsibility"], owner_rows, [57 * mm, 112 * mm], st))
    preset_boundary = (
        "The selected preset is outside Core identity. It chooses one bounded operating profile and provider needs but grants no authority. The schema is a deterministic Draft 2020-12 projection compiled from the canonical owners, never a second semantic or policy owner."
        if language == "en"
        else "Вибраний preset перебуває поза ідентичністю Core. Він обирає один обмежений operating profile і потреби провайдерів, але не надає повноважень. Схема є детермінованою проєкцією Draft 2020-12, скомпільованою з канонічних власників, а не другим власником семантики чи політики."
    )
    story.append(para(preset_boundary, st["body"]))
    source(story, OWNER["manifest"] + "; " + OWNER["preset"], "exact six-file Core + selected preset outside Core", st)

    add_heading(
        story,
        "Package contents" if language == "en" else "Склад пакета",
        2,
        "package-contents",
        st,
    )
    package_text = (
        f"The canonical tree contains exactly {CANONICAL_PACKAGE_FILE_COUNT} regular files under "
        f"{CANONICAL_PACKAGE_DIRECTORY_COUNT} declared directories. MANIFEST.json enumerates "
        f"{len(CANONICAL_PAYLOAD_FILES)} payload files; {', '.join(sorted(GENERATED_SURFACES))} are "
        "the generated integrity surfaces. Missing, additional, linked, special, or transient paths reject."
        if language == "en"
        else f"Канонічне дерево містить рівно {CANONICAL_PACKAGE_FILE_COUNT} звичайних файлів у "
        f"{CANONICAL_PACKAGE_DIRECTORY_COUNT} задекларованих директоріях. MANIFEST.json перелічує "
        f"{len(CANONICAL_PAYLOAD_FILES)} payload-файлів; {', '.join(sorted(GENERATED_SURFACES))} є "
        "згенерованими поверхнями цілісності. Відсутні, додаткові, linked, special або transient paths відхиляються."
    )
    story.append(para(package_text, st["body"]))
    package_counts: Counter[str] = Counter()
    for relative in CANONICAL_PACKAGE_FILES:
        location = relative.split("/", 1)[0] + "/" if "/" in relative else "package root"
        package_counts[location] += 1
    package_rows = sorted(
        package_counts.items(),
        key=lambda item: (item[0] != "package root", item[0].encode("utf-8")),
    )
    story.append(make_table(["Location", "Regular files"], package_rows, [120 * mm, 49 * mm], st))
    root_files = sorted(
        (relative for relative in CANONICAL_PACKAGE_FILES if "/" not in relative),
        key=lambda value: value.encode("utf-8"),
    )
    root_files_text = (
        "Root files are exactly " + ", ".join(root_files) + ". License, governance, dependency, and third-party notice closure is part of package identity."
        if language == "en"
        else "Root files: рівно " + ", ".join(root_files) + ". License, governance, dependency і third-party notice closure є частиною package identity."
    )
    story.append(para(root_files_text, st["body"]))
    source(story, "MANIFEST.json; SHA256SUMS.txt; tools/promin_validate.py", "CANONICAL_PACKAGE_FILES + CANONICAL_PACKAGE_DIRECTORIES", st)

    add_heading(story, tx["purpose"], 1, "purpose", st)
    if language == "ua":
        purpose_text = (
            "Стандарт відокремлює нормативний стан від похідних індексів і звітів, повноваження від ролей та оренди, "
            "а результат виконання від рішення про прийняття. Тип моделі може змінювати глибину аналізу, декомпозицію і паралельність, "
            "але не розширює повноваження."
        )
        non_goals = [
            "promin не є системою розподіленого консенсусу.",
            "Проєкція, пошуковий рейтинг, звіт або preset не є нормативним джерелом і не надає повноважень.",
            "Оренда не є прийняттям; виконання, перевірка, просування і фінальне рішення є різними діями.",
            "Успіх еталонного пакета не є достатнім для production credit без закриття P0/P1, parity rollback/recutover і належно авторизованого рішення.",
        ]
    else:
        purpose_text = (
            "The standard separates normative state from derived indexes and reports, authority from roles and leases, and execution "
            "results from acceptance decisions. Model tier may change analysis depth, decomposition, and parallelism, but never authority."
        )
        non_goals = [
            "promin is not a distributed-consensus system.",
            "A projection, search rank, report, or preset is neither normative authority nor an authority grant.",
            "A Lease is not acceptance; execution, validation, promotion, and final decision are distinct actions.",
            "Reference-package success is insufficient for production credit without P0/P1 closure, rollback/recutover parity, and a duly authorized Decision.",
        ]
    story.append(para(purpose_text, st["body"]))
    for item in non_goals:
        bullet(story, item, st)
    source(story, OWNER["semantic"] + "; " + OWNER["authority"] + "; " + OWNER["conformance"], "model_tier_rule + production_claim_rule", st)

    add_heading(story, tx["semantics"], 1, "semantics", st)
    if language == "ua":
        story.append(para("Семантична, публічна, compilation, runtime-dispatch і documentation гранулярності незалежні. Окремий тип або об'єкт виправданий лише незалежним інваріантом, політикою, замінністю, вимірюваним алгоритмом, межею відмови, повторним використанням або доменною значущістю.", st["body"]))
    else:
        story.append(para("Semantic, public, compilation, runtime-dispatch, and documentation granularities are independent. A separate type or object is justified only by an independent invariant, policy, replaceability, measurable algorithm, failure boundary, reuse, or domain significance.", st["body"]))
    source(story, OWNER["semantic"], "design_rules", st)

    add_heading(story, "Persistent entities" if language == "en" else "Стійкі сутності", 2, "persistent-entities", st)
    story.append(make_table(["Kind", "Purpose"], ((x["kind"], x["purpose"]) for x in sem["persistent_entities"]), [34 * mm, 135 * mm], st))
    source(story, OWNER["semantic"], "admission.entity", st)

    add_heading(story, "Relations" if language == "en" else "Відношення", 2, "relations", st)
    story.append(make_table(["Kind", "Source", "Target", "Rules"], ((x["kind"], ", ".join(x["source"]), ", ".join(x["target"]), ", ".join(x["rules"])) for x in sem["relations"]), [25 * mm, 38 * mm, 45 * mm, 61 * mm], st))
    source(story, OWNER["semantic"], "admission.relation", st)

    add_heading(story, "Derived boundary" if language == "en" else "Межа похідних даних", 2, "derived-boundary", st)
    for kind in sem["derived_projection_kinds"]:
        bullet(story, kind, st)
    story.append(para(sem["admission"]["derived_by_default"], st["body"]))
    source(story, OWNER["semantic"], "derived_projection_kinds", st)

    add_heading(
        story,
        "Inventory" if language == "en" else "Інвентаризація",
        1,
        "inventory",
        st,
    )
    inventory_text = (
        "Inventory reads the product tree once and writes an immutable manifest-verified JSONL stream of physical inventory records. Each row is normalized and folded into rolling identity and stream digests, byte and row counts; publication uses atomic replacement. Physical evidence is bucketed into the declared bucket contour, while projection rebuild verifies that descriptor while consuming the stream once and does not materialize the corpus in memory. Inventory creates no semantic Artifact, Task, READS, or PRODUCES facts; bounded semantic control records remain separately capped."
        if language == "en"
        else "Інвентаризація читає дерево продукту один раз і записує незмінний JSONL stream фізичних inventory records, перевірений manifest. Кожний рядок нормалізується та входить до rolling digests ідентичності й stream, кількості bytes і рядків; публікація використовує atomic replace. Фізичне evidence розподіляється за оголошеним bucket-контуром, а перебудова проєкції перевіряє descriptor і споживає stream один раз без матеріалізації corpus у пам'яті. Інвентаризація не створює semantic Artifact, Task, READS або PRODUCES; bounded semantic control records мають окрему граничну кількість."
    )
    story.append(para(inventory_text, st["body"]))
    inventory_row = defs["InventoryProjectionRow"]
    story.append(
        make_table(
            ["InventoryProjectionRow", "Structural rule"],
            (
                (name, summarize_schema(spec))
                for name, spec in inventory_row.get("properties", {}).items()
            ),
            [56 * mm, 113 * mm],
            st,
        )
    )
    inventory_contract = conf["scale_contracts"]["inventory"]
    story.append(
        make_table(
            ["Stream invariant", "Value"],
            (
                ("manifest_verified_jsonl", inventory_contract["manifest_verified_jsonl"]),
                ("project_tree_passes_max", inventory_contract["project_tree_passes_max"]),
                ("memory_amplification_max", inventory_contract["memory_amplification_max"]),
                ("physical_inventory_records_per_raw_file", inventory_contract["physical_inventory_records_per_raw_file"]),
                ("physical_bucket_count", inventory_contract["physical_bucket_count"]),
                ("physical_files_per_bucket", inventory_contract["physical_files_per_bucket"]),
                ("semantic_artifacts_per_raw_file", inventory_contract["semantic_artifacts_per_raw_file"]),
                ("semantic_control_record_limit", inventory_contract["semantic_control_record_limit"]),
                ("synthetic_relations_per_raw_file", inventory_contract["synthetic_relations_per_raw_file"]),
                ("synthetic_tasks_per_raw_file", inventory_contract["synthetic_tasks_per_raw_file"]),
                ("search_text_bytes_max", inventory_contract["search_text_bytes_max"]),
            ),
            [76 * mm, 93 * mm],
            st,
        )
    )
    for pid in ("P-008", "P-017", "P-043", "P-051"):
        item = policies[pid]
        bullet(story, f"{pid} {item['name']}: {localized(item['statement'])}", st)
    source(
        story,
        OWNER["semantic"] + "; " + OWNER["policy"] + "; " + OWNER["schema"],
        "InventoryProjectionRow + manifest-verified JSONL + single_scan_inventory + inventory_projection_minimality",
        st,
    )

    add_heading(story, tx["init"], 1, "initialization", st)
    if language == "ua":
        story.append(para("`promin init` приймає явно задані standard bundle, preset і рівно п'ять plan files: project.json, standards.json, technologies.json, licenses.json та authority.json. Team-signed trust додатково вимагає явний JSON array через --activation-proofs; local-owner сам утворює один root proof і відхиляє цю option. Init перевіряє Core, preset, доступність провайдерів і ліцензії до commit, встановлює незмінний стандарт за digest та атомарно записує рівно п'ять init records: ProjectInit, StandardsInit, TechnologiesInit, AuthorityInit і Activation. licenses.json є required validation input, а не шостим installed record. Успішні provider observations digest-bound у transient in-memory preflight receipt; цей receipt не є init record і ніколи не записується в `.promin/init/`. `--emit-plan` перевіряє та canonicalizes саме supplied plans поза `.promin/`, не синтезує їх із project ID або source path і відхиляє --activation-proofs; `--review-plan` перевіряє inputs без запису; `--dry-run` додає provider preflight без мутації. Кожний режим init виконує нуль проходів дерева продукту. Product repository не потребує root core/; authority є лише exact immutable copy у `.promin/standard/<digest>/`.", st["body"]))
    else:
        story.append(para("`promin init` accepts an explicit bundle, preset, and exactly five plan files: project.json, standards.json, technologies.json, licenses.json, and authority.json. Team-signed trust additionally requires an explicit JSON array through --activation-proofs; local-owner derives its one root proof and rejects that option. Init verifies Core, preset, provider health, and licenses before commit; installs an immutable digest-addressed standard; and atomically writes exactly five init records: ProjectInit, StandardsInit, TechnologiesInit, AuthorityInit, and Activation. licenses.json is a required validation input, not a sixth installed record. Successful provider observations are digest-bound in a transient in-memory preflight receipt; that receipt is not an init record and is never written under `.promin/init/`. `--emit-plan` validates and canonicalizes the supplied plans outside `.promin/`, does not synthesize them from a project ID or source path, and rejects --activation-proofs; `--review-plan` validates inputs without writes; `--dry-run` adds provider preflight without mutation. Every init mode performs zero product-tree passes. The product repository needs no root core/; authority is only the exact immutable copy under `.promin/standard/<digest>/`.", st["body"]))
    init_rows = [
        ("project.json", "ProjectInit", ", ".join(defs["ProjectInit"].get("required", []))),
        ("standards.json", "StandardsInit", ", ".join(defs["StandardsInit"].get("required", []))),
        ("technologies.json", "TechnologiesInit", ", ".join(defs["TechnologiesInit"].get("required", []))),
        ("authority.json", "AuthorityInit", ", ".join(defs["AuthorityInit"].get("required", []))),
        ("activation.json", "Activation", ", ".join(defs["Activation"].get("required", []))),
    ]
    story.append(make_table(["Installed record", "Schema", "Required fields"], init_rows, [40 * mm, 38 * mm, 91 * mm], st))
    source(story, OWNER["schema"] + "; " + OWNER["policy"], "ProjectInit/StandardsInit/TechnologiesInit/AuthorityInit/Activation + exact_init_keyset", st)
    code_block(
        story,
        ".promin/\n  standard/<core-bundle-digest>/\n    core/\n    presets/<preset-digest>.json\n  init/\n    project.json\n    standards.json\n    technologies.json\n    authority.json\n    activation.json\n  state/\n    events/batches/\n    objects/sha256/\n    projection/\n    head.json\n    locks/\n  generated/\n  cache/",
        st,
    )
    for pid in ("P-002", "P-023", "P-028", "P-030", "P-037"):
        item = policies[pid]
        bullet(story, f"{pid} {item['name']}: {localized(item['statement'])}", st)
    source(story, OWNER["policy"], "activation_binding + exact_init_keyset + exact_standard_files + config_exact_idempotency + provider_preflight", st)

    add_heading(
        story,
        "Implementation closure" if language == "en" else "Замикання реалізації",
        2,
        "implementation-closure",
        st,
    )
    closure_text = (
        "Each technologies binding names the exact promin runtime, Python interpreter, jsonschema, SQLite, and adapter components used by that capability. Activation and dependent Evidence and projection state bind the aggregate implementation_closure_digest. The runtime recomputes it before use; drift invalidates dependent current state without rewriting history."
        if language == "en"
        else "Кожна technology binding називає точні компоненти promin runtime, інтерпретатора Python, jsonschema, SQLite та adapter для відповідної capability. Activation і залежні Evidence та проєкції прив'язуються до сукупного implementation_closure_digest. Runtime обчислює його перед використанням; drift робить залежний поточний стан недійсним, не переписуючи історію."
    )
    story.append(para(closure_text, st["body"]))
    closure_rows = [
        ("TechnologiesInit.bindings[*].implementation_closure", "runtime, interpreter, components, adapters, closure_digest"),
        ("Activation.implementation_closure_digest", "aggregate current implementation identity"),
        ("EvidenceBinding.implementation_closure_digest", "implementation used to produce evidence"),
    ]
    story.append(make_table(["Binding", "Required content"], closure_rows, [79 * mm, 90 * mm], st))
    for pid in ("P-022", "P-044"):
        item = policies[pid]
        bullet(story, f"{pid} {item['name']}: {localized(item['statement'])}", st)
    source(
        story,
        OWNER["schema"] + "; " + OWNER["policy"],
        "$defs/TechnologiesInit + $defs/Activation + $defs/EvidenceBinding + implementation_closure_binding",
        st,
    )

    add_heading(story, tx["authority"], 1, "authority", st)
    story.append(para(auth["bootstrap_rule"], st["body"]))
    story.append(para(auth["model_tier_rule"], st["body"]))
    grant_summary = (
        f"Default is {auth['default']}. Maximum delegation depth is {auth['delegation_depth_max']}. Every Grant binds subject, capability, conjunctive effect scope, nonce, not-before and expiry, revocation state, exact child signed claim, issuer claim or configured team-signature boundary, and the exact Activation. Revocation Decisions and Events are resolved as immutable records; an arbitrary Decision ID is not proof."
        if language == "en"
        else f"Default - {auth['default']}. Максимальна delegation depth - {auth['delegation_depth_max']}. Кожний Grant прив'язує subject, capability, conjunctive effect scope, nonce, not-before й expiry, revocation state, exact child signed claim, issuer claim або configured team-signature boundary та exact Activation. Revocation Decisions і Events розв'язуються як immutable records; довільний Decision ID не є доказом."
    )
    story.append(para(grant_summary, st["body"]))
    source(story, OWNER["authority"], "bootstrap_rule + default + model_tier_rule", st)
    add_heading(story, "Capabilities" if language == "en" else "Можливості", 2, "capabilities", st)
    story.append(make_table(["Capability", "Purpose"], ((x["id"], x["purpose"]) for x in auth["capabilities"]), [47 * mm, 122 * mm], st))
    source(story, OWNER["authority"], "capabilities", st)
    add_heading(story, "Separation of duties" if language == "en" else "Розділення обов'язків", 2, "sod", st)
    sod_rows = []
    for item in auth["separation_of_duties"]:
        detail = item.get("statement") or json.dumps({k: v for k, v in item.items() if k not in {"id", "rule"}}, ensure_ascii=False, sort_keys=True)
        sod_rows.append((item["id"], item["rule"], detail))
    story.append(make_table(["ID", "Rule", "Constraint"], sod_rows, [20 * mm, 50 * mm, 99 * mm], st))
    story.append(para(conf["production_claim_rule"], st["body"]))
    source(story, OWNER["authority"] + "; " + OWNER["conformance"], "SOD-001..SOD-005 + signed standard-distribution decision", st)

    add_heading(story, tx["lifecycle"], 1, "lifecycle", st)
    if language == "ua":
        story.append(para("Task і Lease змінюють стан лише за policy-owned state machines. Mutation WorkCard потребує чинної Lease, а read-only WorkCard не повинен її отримувати. Lease окремо прив'язує manager і holder Grants, generation, monotonic fence, heartbeat, expiry і close acknowledgement, але ніколи не надає acceptance credit. ACTIVE і CLOSING, а також EXPIRED або REVOKED без записаного reconciliation продовжують займати capacity.", st["body"]))
    else:
        story.append(para("Task and Lease change state only through policy-owned state machines. A mutation WorkCard requires a current Lease; a read-only WorkCard must not receive one. A Lease separately binds manager and holder Grants, generation, monotonic fence, heartbeat, expiry, and close acknowledgement, but never grants acceptance credit. ACTIVE and CLOSING, and EXPIRED or REVOKED without recorded reconciliation, continue to occupy capacity.", st["body"]))
    for name in ("task", "lease"):
        rows = [(state, ", ".join(targets) if targets else "-") for state, targets in policy["state_machines"][name].items()]
        story.append(make_table([name.capitalize(), "Allowed next state"], rows, [48 * mm, 121 * mm], st))
    story.append(para(policy["state_machines"]["capacity_release"], st["body"]))
    add_heading(story, "Lifecycle command matrix" if language == "en" else "Матриця команд життєвого циклу", 2, "lifecycle-command-matrix", st)
    effect_by_command = {item["command_kind"]: item for item in auth["command_effect_scope_rules"]}
    lifecycle_kinds = {
        "task.record",
        "task.transition",
        "lease.record",
        "artifact.record",
        "run.record",
        "gate.record",
        "finding.record",
        "decision.record",
    }
    lifecycle_rows = []
    for item in auth["command_capability_rules"]:
        if item["command_kind"] not in lifecycle_kinds:
            continue
        resolution = item.get("capability_id") or json.dumps(item.get("capability_by_value", {}), ensure_ascii=False, sort_keys=True)
        effect = effect_by_command.get(item["command_kind"], {})
        lifecycle_rows.append((item["command_kind"], resolution, json.dumps(effect, ensure_ascii=False, sort_keys=True)))
    story.append(make_table(["Command", "Capability resolution", "Effect scope"], lifecycle_rows, [41 * mm, 54 * mm, 74 * mm], st))
    source(story, OWNER["authority"] + "; " + OWNER["schema"], "command_capability_rules + command_effect_scope_rules + $defs/GateResult", st)
    mutation_claim = auth.get("command_mutation_claim_rule")
    if mutation_claim:
        add_heading(story, "Lease-bound mutation claim" if language == "en" else "Прив'язка мутаційної команди до оренди", 2, "mutation-claim", st)
        story.append(para(mutation_claim["claim_rule"], st["body"]))
        if mutation_claim.get("grant_separation_rule"):
            story.append(para(mutation_claim["grant_separation_rule"], st["body"]))
            story.append(make_table(
                ["Authorization proof", "Source / field", "Required capability"],
                [
                    ("command authorization Grant", mutation_claim["command_authorization_source"], "resolved command capability"),
                    ("holder Grant", mutation_claim["holder_grant_field"], mutation_claim["holder_grant_capability"]),
                ],
                [48 * mm, 76 * mm, 45 * mm],
                st,
            ))
        story.append(make_table(
            ["Binding equality", "Required result"],
            ((equality, "exact match") for equality in mutation_claim["binding_equalities"]),
            [132 * mm, 37 * mm],
            st,
        ))
        claim_summary = (
            f"Lease-bound commands: {', '.join(mutation_claim['lease_bound_command_kinds'])}. Required Lease state: {mutation_claim['lease_required_state']}. Stale or unresolved: {mutation_claim['stale_or_unresolved']}."
            if language == "en"
            else f"Команди, прив'язані до оренди: {', '.join(mutation_claim['lease_bound_command_kinds'])}. Обов'язковий стан Lease: {mutation_claim['lease_required_state']}. Stale або unresolved: {mutation_claim['stale_or_unresolved']}."
        )
        story.append(para(claim_summary, st["body"]))
        source(story, OWNER["authority"] + "; " + OWNER["policy"], "command_mutation_claim_rule + lease_fence + command_capability_scope", st)

    artifact_def = defs["Artifact"]
    evidence_binding_def = defs["EvidenceBinding"]
    add_heading(story, "Evidence and immutable CAS" if language == "en" else "Evidence і незмінний CAS", 2, "evidence-cas", st)
    if language == "ua":
        story.append(para("Artifact ідентифікує незмінні bytes за digest у content-addressed storage. Credit завжди розв'язує точні artifact_id і digest фіналізованого Artifact record. Для artifact_kind=evidence event payload містить replay-complete metadata: точну Activation, Candidate, policy, tool, provider й input digests, outcome, evidence_purpose, evidence_class, stale, unresolved та product_credit_eligible. Клас harness-generated не змішується з product-execution і не отримує product credit.", st["body"]))
    else:
        story.append(para("Artifact identifies immutable bytes by digest in content-addressed storage. Credit always resolves the exact artifact_id and finalized Artifact-record digest. For artifact_kind=evidence, the event payload carries replay-complete metadata: exact Activation, Candidate, policy, tool, provider, and input digests plus outcome, evidence_purpose, evidence_class, stale, unresolved, and product_credit_eligible. The harness-generated class remains separate from product-execution and receives no product credit.", st["body"]))
    evidence_rows = [
        ("digest", "immutable CAS content identity"),
        ("evidence_binding", ", ".join(evidence_binding_def["required"])),
        ("outcome", ", ".join(artifact_def["properties"]["outcome"]["enum"])),
        ("evidence_class", ", ".join(artifact_def["properties"]["evidence_class"]["enum"])),
        ("evidence_purpose", "must equal the precommitted GateRunDefinition purpose"),
        ("stale / unresolved", "both false for product credit"),
        ("product_credit_eligible", "true only for fresh resolved passing product-execution evidence"),
    ]
    story.append(make_table(["Evidence field", "Rule"], evidence_rows, [54 * mm, 115 * mm], st))
    gate_definition_text = (
        "Pass, fail, and blocked gate statuses bind exact evidence against an immutable GateRunDefinition precommitted by its owning Task. Skipped requires a reason, carries no Artifact credit, and has pass_credit=false. The definition fixes evidence class and purpose, product-credit requirement, exact target kind, digest and scope, and Candidate, policy, tool, provider, and input digests before a Run or GateResult is submitted. Inline definitions, mixed classes, and payload-digest substitutes reject."
        if language == "en"
        else "Gate statuses pass, fail і blocked прив'язують точний evidence до незмінного GateRunDefinition, заздалегідь визначеного його Task-власником. Skipped потребує reason, не має Artifact credit і завжди має pass_credit=false. Definition фіксує клас і purpose evidence, вимогу product credit, точні target kind, digest і scope, а також Candidate, policy, tool, provider та input digests до подання Run або GateResult. Inline definitions, змішані класи й заміна digest payload відхиляються."
    )
    story.append(para(gate_definition_text, st["body"]))
    source(story, OWNER["schema"] + "; " + OWNER["semantic"] + "; " + OWNER["policy"], "$defs/Artifact + $defs/EvidenceBinding + $defs/GateResult + candidate_evidence_binding + credit_requires_evidence", st)
    for pid in ("P-004", "P-005", "P-013", "P-014", "P-033", "P-038", "P-039", "P-040"):
        item = policies[pid]
        bullet(story, f"{pid} {item['name']}: {localized(item['statement'])}", st)
    source(story, OWNER["policy"], "lease_fence + candidate_evidence_binding + current_outcome + effective_finding + lease_only_for_mutation + state_machine_transition + decision_target_binding + credit_requires_evidence", st)

    add_heading(story, tx["events"], 1, "events", st)
    ingress_pipeline = (
        "bounded canonical parse\n-> compiled Draft 2020-12 schema\n-> semantic policy registry\n-> Activation integrity\n-> capability and conjunctive effect-scope resolution\n-> Grant, SOD, Lease, and fence checks\n-> candidate and evidence binding\n-> bounded atomic event batch\n-> rebuildable projection"
        if language == "en"
        else "обмежений канонічний розбір\n-> скомпільована схема Draft 2020-12\n-> реєстр семантичних політик\n-> цілісність Activation\n-> визначення capability і conjunctive effect scope\n-> перевірки Grant, SOD, Lease і fence\n-> прив'язка Candidate та Evidence\n-> обмежений атомарний пакет подій\n-> відновлювана проєкція"
    )
    code_block(
        story,
        ingress_pipeline,
        st,
    )
    if language == "ua":
        story.append(para("Одна нормалізована команда з exact authorization, idempotency key та expected HEAD утворює один незмінний атомарний batch. Під cross-process writer lock runtime оновлює exact HEAD і replay-derived authority state, перевіряє встановлені bytes, авторизує та застосовує команду до копії, обчислює typed state delta, виконує file sync, atomic replace і directory sync та лише після durable append публікує live state. Batch містить рівно одну primary event, що відповідає validated command payload; event IDs унікальні. Commit має O(batch), пошук HEAD - O(1), replay - O(events).", st["body"]))
    else:
        story.append(para("One normalized command with exact authorization, idempotency key, and expected HEAD forms one immutable atomic batch. Under the cross-process writer lock, the runtime refreshes exact HEAD and replay-derived authority state, verifies installed bytes, authorizes and applies the command to a copy, computes the typed state delta, performs file sync, atomic replace, and directory sync, and publishes live state only after the durable append. The batch contains exactly one primary event equal to the validated command payload; event IDs are unique. Commit is O(batch), HEAD lookup O(1), and replay O(events).", st["body"]))
    event_commitment_rows = [
        ("previous_authority_commitment", "exact previous commitment or the Core-owned genesis value"),
        ("authority_commitment", "commitment over sequence, previous batch, event and state-binding identities"),
        ("cumulative_event_count", "previous count plus current Event count"),
        ("event_semantic_digest", "ordered append-only digest of canonical Events"),
        ("state_binding_delta", "non-empty sorted unique set/delete changes to typed authority leaves"),
        ("cumulative_state_binding_update_count", "previous update count plus current delta length"),
        ("state_binding_digest", "typed-sparse-merkle-v1 post-batch authority root"),
        ("created_at", "UTC with exact second precision"),
    ]
    story.append(make_table(["EventBatch commitment", "Required meaning"], event_commitment_rows, [63 * mm, 106 * mm], st))
    checkpoint_text = (
        "Replay verifies the complete journal prefix. EventStorePolicy is derived live-only from the installed owners with no defaults or nullable critical fields. Checkpoints, SQLite, typed graph state, and sidecars may accelerate rebuild but cannot supply a missing commitment, inject an authority leaf, or change journal meaning."
        if language == "en"
        else "Replay перевіряє повний префікс journal. EventStorePolicy є derived live-only з установлених owners без defaults або nullable critical fields. Checkpoints, SQLite, typed graph state і sidecars можуть прискорювати rebuild, але не можуть підставляти відсутній commitment, додавати authority leaf або змінювати значення journal."
    )
    story.append(para(checkpoint_text, st["body"]))
    for pid in ("P-006", "P-011", "P-015", "P-025", "P-027", "P-041"):
        item = policies[pid]
        bullet(story, f"{pid} {item['name']}: {localized(item['statement'])}", st)
    source(story, OWNER["authority"] + "; " + OWNER["policy"] + "; " + OWNER["conformance"], "EventStorePolicy + EventBatch commitments + atomic_event_commit + historical_revocation + state_command_idempotency + one_command_one_batch + strict_time + command_event_correspondence", st)

    add_heading(story, tx["retrieval"], 1, "retrieval", st)
    if language == "ua":
        story.append(para("SQLite/typed graph є одною disposable projection. `next` не виконує FTS: він обчислює live-only ReadyFrontier з поточного ациклічного графа DEPENDS_ON, вибирає перший Task у детермінованому порядку frontier і повертає immutable read-only WorkCard у NextResult.work_card. `continue` споживає opaque ReadyFrontier token і повертає ContinueResult. Обидва result envelopes містять рівно шість полів і жодних інших: record_type, status, subject_id, activation_digest, work_card і continuation, саме в цьому contract order. status=ready вимагає strict Core WorkCard, status=empty вимагає work_card=null, а continuation є non-null лише для truncated frontier page і містить лише next-page token. Task є eligible лише тоді, коли всі dependencies мають поточний COMPLETED, усі потрібні GateResults є current pass з credit, а жодний поточний OPEN Finding не блокує Task. WorkCardProjection є лише internal selected-Task materialization, не є public result envelope і не містить continuation field або token.", st["body"]))
        story.append(para("Для інших generic bounded retrieval operations точний пошук ID передує content-aware FTS; RetrievalPage є окремим generic retrieval result, а ranking не надає фактів прийняття. Широкий запит вибирає лише детермінований bounded top-k seed set. Якщо збігів більше, RetrievalPage встановлює refinement_required=true, повертає bounded hints і не відкриває pagination через невибраний corpus. Typed closure обчислюється лише для вибраних seeds, а об'єднання вибраного closure є повним у межах depth 1-12 і budgets. Неявне скорочення заборонено.", st["body"]))
    else:
        story.append(para("The SQLite/typed graph is one disposable projection. `next` does not run FTS: it computes a live-only ReadyFrontier from the current acyclic DEPENDS_ON graph, selects the first Task in deterministic frontier order, and returns an immutable read-only WorkCard in NextResult.work_card. `continue` consumes the opaque ReadyFrontier token and returns ContinueResult. Both result envelopes contain exactly six fields and no others: record_type, status, subject_id, activation_digest, work_card, and continuation, in that contract order. status=ready requires a strict Core WorkCard, status=empty requires work_card=null, and continuation is non-null only for a truncated frontier page and contains only its next-page token. A Task is eligible only when every dependency is currently COMPLETED, every required GateResult is current passing credit, and no current OPEN Finding blocks it. WorkCardProjection is internal selected-Task materialization only, is not a public result envelope, and contains no continuation field or token.", st["body"]))
        story.append(para("For other generic bounded retrieval operations, exact-ID lookup precedes content-aware FTS; RetrievalPage is the separate generic retrieval result and ranking never grants acceptance facts. A broad query selects only a deterministic bounded top-k seed set. When more matches exist, RetrievalPage sets refinement_required=true, returns bounded hints, and exposes no pagination through the unselected corpus. Typed closure is computed only for selected seeds, and their closure union is complete within depth 1-12 and the declared budgets. Silent truncation is forbidden.", st["body"]))
    continuation_text = (
        "A public scheduling continuation is an opaque authenticated ReadyFrontier next-page handle of at most 256 bytes. Its bound state is stored locally, limited to 16 KiB, and binds subject, the current projection.read Grant, scope, Activation, current ReadyFrontier, deterministic order and cursor, HEAD, projection, complete budgets, time bounds, revocation state, and implementation closure. NextResult.continuation and ContinueResult.continuation are null when the frontier page is complete. Separately, RetrievalPage owns generic retrieval continuation and exposes only stream_cursor and next_stream_cursor; removed cursor aliases reject. Its token is not ReadyFrontier scheduling continuation. WorkCardProjection contains no continuation field or token. Continuation overhead remains at most ten percent of the bounded WorkCard. Every page rechecks the Grant; a token is never an authority grant and cannot traverse unselected corpus matches."
        if language == "en"
        else "Public scheduling continuation є opaque authenticated ReadyFrontier next-page handle розміром не більше 256 bytes. Його bound state зберігається локально, обмежений 16 KiB і містить subject, чинний Grant projection.read, scope, Activation, current ReadyFrontier, детермінований порядок і cursor, HEAD, projection, повні budgets, часові межі, стан revocation й implementation closure. NextResult.continuation і ContinueResult.continuation є null, коли frontier page завершена. Окремо RetrievalPage володіє generic retrieval continuation і містить лише stream_cursor та next_stream_cursor; видалені cursor aliases відхиляються. Його token не є ReadyFrontier scheduling continuation. WorkCardProjection не містить continuation field або token. Overhead continuation не перевищує десяти відсотків bounded WorkCard. Кожна сторінка повторно перевіряє Grant; token не надає повноважень і не може переходити невибраними збігами corpus."
    )
    story.append(para(continuation_text, st["body"]))
    ceiling = conf["workcard_hard_ceiling"]
    story.append(make_table(["WorkCard ceiling", "Value"], ceiling.items(), [70 * mm, 99 * mm], st))
    continuation = defs["ContinuationTokenClaims"]
    story.append(make_table(["Continuation field", "Structural rule"], ((name, spec) for name, spec in continuation.get("properties", {}).items()), [50 * mm, 119 * mm], st))
    search_contract = conf["scale_contracts"]["workcard"]
    story.append(
        make_table(
            ["Bounded retrieval rule", "Value"],
            (
                ("broad_query_behavior", search_contract["broad_query_behavior"]),
                ("continuation_token_bytes_max", search_contract["continuation_token_bytes_max"]),
                ("continuation_state_bytes_max", search_contract["continuation_state_bytes_max"]),
                ("selected_closure_union_completeness", search_contract["selected_closure_union_completeness"]),
                ("corpus_independent_output_bound", search_contract["corpus_independent_output_bound"]),
            ),
            [68 * mm, 101 * mm],
            st,
        )
    )
    for pid in ("P-007", "P-009", "P-024", "P-026", "P-032", "P-042"):
        item = policies[pid]
        bullet(story, f"{pid} {item['name']}: {localized(item['statement'])}", st)
    source(story, OWNER["policy"] + "; " + OWNER["conformance"] + "; " + OWNER["schema"], "ReadyFrontier + NextResult + ContinueResult + WorkCard + WorkCardProjection + RetrievalPage + projection_derived + bounded_workcard + stale_projection + deterministic_retrieval + depth_aware_retrieval + $defs/ContinuationTokenClaims", st)

    add_heading(story, tx["cli"], 1, "cli", st)
    story.append(make_table(["Surface", "Commands"], [
        ("public", ", ".join(preset["base_user_commands"])),
    ], [40 * mm, 129 * mm], st))
    query_workflows = [
        ("next", "--subject SUBJECT --grant HOLDER_GRANT --query-grant QUERY_GRANT [--depth 1..12]", "holder=task.execute; query=projection.read"),
        ("continue", "TOKEN --subject SUBJECT --grant QUERY_GRANT", "query=projection.read"),
    ]
    story.append(make_table(["Command", "Arguments", "Grant capability"], query_workflows, [28 * mm, 91 * mm, 50 * mm], st))
    query_text = (
        "The two next Grants are verified independently. Next derives the current ReadyFrontier and returns its first eligible Task as NextResult.work_card; it accepts no FTS expression. Continue requires the explicit subject and current projection.read query Grant and returns ContinueResult for the next frontier page. Both exact envelopes contain only record_type, status, subject_id, activation_digest, work_card, and continuation."
        if language == "en"
        else "Два Grants для next перевіряються незалежно. Next обчислює поточний ReadyFrontier і повертає його перший eligible Task як NextResult.work_card; він не приймає FTS expression. Continue потребує явного subject і чинного query Grant з projection.read та повертає ContinueResult для наступної frontier page. Обидва exact envelopes містять лише record_type, status, subject_id, activation_digest, work_card і continuation."
    )
    story.append(para(query_text, st["body"]))
    profile_rows = []
    for name, profile in preset["profiles"].items():
        profile_rows.append((name, profile["model_tier"], profile["max_parallel_tasks"], profile["default_dependency_depth"], profile["max_context_bytes"], profile["max_entities"], profile["max_relations"], profile["top_k"]))
    story.append(make_table(["Profile", "Tier", "Parallel", "Default depth", "Bytes", "Entities", "Relations", "top_k"], profile_rows, [32 * mm, 25 * mm, 18 * mm, 14 * mm, 20 * mm, 20 * mm, 20 * mm, 20 * mm], st))
    for item in preset["forbidden_implicit_behavior"]:
        bullet(story, item, st)
    item = policies["P-052"]
    bullet(story, f"P-052 {item['name']}: {localized(item['statement'])}", st)
    source(story, OWNER["preset"] + "; " + OWNER["authority"], "base_user_commands + profiles + forbidden_implicit_behavior + model_tier_rule", st)

    add_heading(story, tx["validation"], 1, "validation", st)
    if language == "ua":
        validation_text = (
            "Однаковий суворий pipeline застосовується до command, import, replay, rebuild і export. Порожні, невідомі, null, stale, degraded, unbound або cyclic critical records відхиляються. "
            "Одноразовий інструмент поза canonical promin імпортує підтримувані Tasks, Grants і revocations, Leases, evidence Artifacts, Findings, GateResults, Decisions та continuation state через той самий ingress; generated indexes, reports і DB перебудовуються. Cutover потребує candidate-bound dual-run parity, rollback, deterministic recutover, закриття P0/P1, нуль legacy references і належно авторизованого людського Decision. До цього cutover=false і deletion=false."
        )
    else:
        validation_text = (
            "The same strict pipeline applies to command, import, replay, rebuild, and export. Empty, unknown, null, stale, degraded, unbound, or cyclic critical records are rejected. "
            "A one-time tool outside canonical promin imports supported Tasks, Grants and revocations, Leases, evidence Artifacts, Findings, GateResults, Decisions, and continuation state through the same ingress; generated indexes, reports, and databases are rebuilt. Cutover requires candidate-bound dual-run parity, rollback, deterministic recutover, P0/P1 closure, zero legacy references, and a duly authorized human Decision. Until then cutover=false and deletion=false."
        )
    story.append(para(validation_text, st["body"]))
    if language == "ua":
        story.append(para(
            "ResearchDraftIntake є bounded transient ingress. Кожне джерело прив'язується до immutable Artifact receipt, recomputed content digest, size, media type, provenance й active reviewed або source-verified license plan. Claim kinds: research_question, hypothesis, assumption, evidence_claim і blocked_claim; verification: unverified, source-bound, verified або blocked. Citation refs ідентифікують research sources, а evidence refs - незалежно resolved Artifact records. Metadata-only sources залишають усі залежні claims blocked і normative_use_allowed=false.",
            st["body"],
        ))
        story.append(para(
            "SanitizedResearchDraft містить лише eligible source-bound або independently verified factual candidates. Distribution, marketing і proof claims залишаються в excluded ledger з bounded text і digest, source/evidence refs та reasons. Result є derived live-only і не може змінювати GateResult, Decision, acceptance, pass credit, public approval або distribution state; public_release_approved залишається false.",
            st["body"],
        ))
        story.append(para(
            "SemanticExport є export-only semantic-state record, не package і не authority. Він прив'язує exact Candidate, Activation, HEAD, Core, preset, implementation closure, provider receipt, inputs та фактичні output Artifact ID і finalized record digest. Output bytes, digest, size і media type повторно обчислюються з exact CAS bytes; exported records deduplicate за digest і впорядковуються digest-ascending. Rebuild перевіряє journal та inventory inputs, виконує нуль product passes і атомарно публікує disposable projection.",
            st["body"],
        ))
    else:
        story.append(para(
            "ResearchDraftIntake is bounded transient ingress. Every source binds an immutable Artifact receipt, recomputed content digest, size, media type, provenance, and an active reviewed or source-verified license plan. Claim kinds are research_question, hypothesis, assumption, evidence_claim, and blocked_claim; verification is unverified, source-bound, verified, or blocked. Citation refs identify research sources while evidence refs identify independently resolved Artifact records. Metadata-only sources leave every dependent claim blocked and normative_use_allowed=false.",
            st["body"],
        ))
        story.append(para(
            "SanitizedResearchDraft contains only eligible source-bound or independently verified factual candidates. Distribution, marketing, and proof claims remain in an excluded ledger with bounded text and digest, source and evidence refs, and reasons. The result is derived live-only and cannot change GateResult, Decision, acceptance, pass credit, public approval, or distribution state; public_release_approved remains false.",
            st["body"],
        ))
        story.append(para(
            "SemanticExport is an export-only semantic-state record, not a package or authority source. It binds exact Candidate, Activation, HEAD, Core, preset, implementation closure, provider receipt, inputs, and actual output Artifact ID and finalized record digest. Output bytes, digest, size, and media type are recomputed from exact CAS bytes; exported records deduplicate by digest and are ordered digest-ascending. Rebuild verifies journal and inventory inputs, performs zero product passes, and atomically publishes a disposable projection.",
            st["body"],
        ))
    acceptance_groups = [conf["required_acceptance"][index : index + 13] for index in range(0, len(conf["required_acceptance"]), 13)]
    for group in acceptance_groups:
        story.append(para(", ".join(group), st["small"]))
    source(story, OWNER["policy"] + "; " + OWNER["conformance"] + "; " + OWNER["schema"], "ResearchDraftIntake + SanitizedResearchDraft + SemanticExport + SemanticStatePayload + ReadyFrontier + required_acceptance + mutation_families + Draft 2020-12 oneOf", st)

    add_heading(
        story,
        "Dependency verification" if language == "en" else "Перевірка залежностей",
        2,
        "dependency-verification",
        st,
    )
    dependency_rows = [
        ("current-environment", "check the interpreter running the command; do not create a nested environment"),
        ("offline-wheelhouse", "create a clean temporary environment; install only from the explicit wheelhouse"),
        ("online-clean", "create a clean temporary environment; install declared dependencies online"),
        ("none", "omit only the dependency smoke and grant no pass credit"),
    ]
    story.append(make_table(["Mode", "Execution truth"], dependency_rows, [48 * mm, 121 * mm], st))
    dependency_text = (
        "No-degradation executes every required test and rejects a skipped required test. It cross-binds the controller platform, CPython version, ABI and tags to the clean-venv executable and SHA-256, the base executable below its base prefix and controller-matching SHA-256, and one SQLite version across controller, validation, and installed observations. One monotonic total deadline covers setup, copies, environment creation, dependency installation, probes, validation, and tests. Every subprocess is contained as a process tree and remaining descendants are terminated after timeout or parent exit. Deadline exhaustion, output overflow, orphaned descendants, or missing progress fails without pass credit."
        if language == "en"
        else "No-degradation виконує кожний обов'язковий тест і відхиляє пропущений обов'язковий тест. Він cross-bind контролерну platform, версію CPython, ABI і tags з executable та SHA-256 чистого venv, base executable у межах base prefix та його SHA-256, що збігається з контролером, і одну версію SQLite у controller, validation та installed observations. Один monotonic total deadline охоплює setup, копіювання, створення середовища, встановлення залежностей, probes, validation і tests. Кожний subprocess ізольований як process tree, а залишкові descendants завершуються після timeout або виходу parent. Вичерпання deadline, output overflow, orphaned descendants або відсутність progress відхиляє результат без pass credit."
    )
    story.append(para(dependency_text, st["body"]))
    matrix_text = (
        "Platform and Python matrix rows are audit-level compatibility observations only. They are non-authoritative, provide no standalone pass credit, and cannot authorize distribution or product acceptance. Supplemental interpreter rows do not add EvidenceManifest roles."
        if language == "en"
        else "Рядки матриці platform і Python є лише audit-level спостереженнями сумісності. Вони не є нормативними, не надають standalone pass credit і не можуть авторизувати дистрибуцію або product acceptance. Додаткові рядки інтерпретаторів не додають ролей EvidenceManifest."
    )
    story.append(para(matrix_text, st["body"]))
    saturation_text = (
        "Each saturation iteration uses a fresh exact five-record, zero-scan control state and never reuses semantic state. The incoming baseline, every iteration control state, and the restored baseline retain byte identities. Audit output contains evidence and logs only; recoverable control state is held in a disjoint workspace-sibling operational-state root. Partial progress is uncredited, and final evidence is published only after three consecutive full zero-new iterations."
        if language == "en"
        else "Кожна saturation iteration використовує свіжий exact п'яти-record, zero-scan control state і ніколи не повторно використовує semantic state. Вхідний baseline, control state кожної iteration і відновлений baseline зберігають byte identities. Audit output містить лише evidence та logs; recoverable control state зберігається в окремому operational-state root поруч із workspace. Partial progress не отримує credit, а фінальний evidence публікується лише після трьох послідовних повних zero-new iterations."
    )
    story.append(para(saturation_text, st["body"]))
    scale_mode_rows = (
        [
            ('python -B -m pytest -q -m "not scale"', "focused conformance mode; excludes the physical scale lane"),
            ("PowerShell: $env:PROMIN_SCALE_WORKSPACE='C:\\promin-scale'; $env:PROMIN_SCALE_ARCHIVE='C:\\evidence\\promin.zip'; python -B -m pytest -q -m scale", "Windows physical 100000-file lane; workspace and exact archive are explicit"),
            ('POSIX: PROMIN_SCALE_WORKSPACE=/tmp/promin-scale PROMIN_SCALE_ARCHIVE=/tmp/evidence/promin.zip python -B -m pytest -q -m scale', "Linux physical 100000-file lane; workspace and exact archive are explicit"),
        ]
        if language == "en"
        else [
            ('python -B -m pytest -q -m "not scale"', "focused режим відповідності; фізична scale lane не виконується"),
            ("PowerShell: $env:PROMIN_SCALE_WORKSPACE='C:\\promin-scale'; $env:PROMIN_SCALE_ARCHIVE='C:\\evidence\\promin.zip'; python -B -m pytest -q -m scale", "Windows physical lane на 100000 файлів; workspace і точний архів задано явно"),
            ('POSIX: PROMIN_SCALE_WORKSPACE=/tmp/promin-scale PROMIN_SCALE_ARCHIVE=/tmp/evidence/promin.zip python -B -m pytest -q -m scale', "Linux physical lane на 100000 файлів; workspace і точний архів задано явно"),
        ]
    )
    story.append(make_table(["Scale mode", "Execution truth"], scale_mode_rows, [56 * mm, 113 * mm], st))
    source(
        story,
        "tools/promin_validate.py; tools/promin_package.py; tools/promin_no_degradation.py; tools/promin_saturation_audit.py",
        "dependency-mode dispatch + runtime cross-binding + total deadline + process-tree containment + fresh saturation control state",
        st,
    )

    add_heading(story, tx["providers"], 1, "providers", st)
    story.append(make_table(["Capability", "Task", "Forbidden boundary"], ((x["id"], x["task"], x["forbidden_boundary"]) for x in sem["technology_capabilities"]), [38 * mm, 66 * mm, 65 * mm], st))
    provider_rows = [("required", ", ".join(preset["required_provider_capabilities"]))]
    if preset.get("optional_provider_capabilities"):
        provider_rows.append(("additional", ", ".join(preset["optional_provider_capabilities"])))
    story.append(make_table(["Preset provider class", "Capability IDs"], provider_rows, [45 * mm, 124 * mm], st))
    protocol_rows = []
    for capability in sem["technology_capabilities"]:
        protocol = capability["adapter_protocol"]
        protocol_rows.append((
            capability["id"],
            protocol["protocol_id"],
            ", ".join(sorted(protocol["operation_contracts"])),
            protocol["receipt_persistence"],
        ))
    story.append(make_table(["Capability", "Protocol ID", "Operations", "Receipt"], protocol_rows, [34 * mm, 50 * mm, 57 * mm, 28 * mm], st))
    provider_evidence_text = (
        "Each operation uses its Core-owned request and response shape and installed content-addressed dependency receipt. ProviderInvocationEvidence binds the exact protocol ID, operation and operation-contract digest, provider and adapter identity, invocation kind, dependency-receipt digest, and observed outcome. Full output binds exact output_digest, output_size_bytes, and output_size_ceiling_bytes; diagnostic stdout and stderr captures are separate, bounded to 1 MiB, and carry truncation flags. Unknown bindings, reconstructed receipts, and raw provider-specific bypasses reject."
        if language == "en"
        else "Кожна operation використовує Core-owned request/response shape та встановлений content-addressed dependency receipt. ProviderInvocationEvidence прив'язує точні protocol ID, operation і operation-contract digest, provider та adapter identity, invocation kind, dependency-receipt digest і observed outcome. Повний output прив'язує exact output_digest, output_size_bytes і output_size_ceiling_bytes; diagnostic stdout/stderr captures є окремими, обмежені 1 MiB і мають truncation flags. Unknown bindings, reconstructed receipts і raw provider-specific bypasses відхиляються."
    )
    story.append(para(provider_evidence_text, st["body"]))
    source(story, OWNER["semantic"] + "; " + OWNER["preset"] + "; " + OWNER["policy"] + "; " + OWNER["schema"], "technology_capabilities.adapter_protocol + ProviderInvocationEvidence + provider_preflight + provider_substitution", st)

    add_heading(story, tx["examples"], 1, "examples", st)
    code_block(
        story,
        "promin --root <project> init --standard-bundle <promin> --preset <preset> --project-plan <plans/project.json> --standards-plan <plans/standards.json> --technologies-plan <plans/technologies.json> --licenses-plan <plans/licenses.json> --authority-plan <plans/authority.json> --emit-plan <canonical-plans>\npromin --root <project> init --standard-bundle <promin> --preset <preset> --project-plan <plans/project.json> --standards-plan <plans/standards.json> --technologies-plan <plans/technologies.json> --licenses-plan <plans/licenses.json> --authority-plan <plans/authority.json> --review-plan\npromin --root <project> init --standard-bundle <promin> --preset <preset> --project-plan <plans/project.json> --standards-plan <plans/standards.json> --technologies-plan <plans/technologies.json> --licenses-plan <plans/licenses.json> --authority-plan <plans/authority.json> --dry-run\npromin --root <project> init --standard-bundle <promin> --preset <preset> --project-plan <plans/project.json> --standards-plan <plans/standards.json> --technologies-plan <plans/technologies.json> --licenses-plan <plans/licenses.json> --authority-plan <plans/authority.json>\npromin --root <project> init --standard-bundle <promin> --preset <preset> --project-plan <plans/project.json> --standards-plan <plans/standards.json> --technologies-plan <plans/technologies.json> --licenses-plan <plans/licenses.json> --authority-plan <plans/authority.json> --activation-proofs <proofs.json>\n\npromin --root <project> doctor\npromin --root <project> status\npromin --root <project> next --subject <id> --grant <holder-grant> --query-grant <query-grant> --depth 2\npromin --root <project> validate\npromin --root <project> continue <token> --subject <id> --grant <query-grant>",
        st,
    )
    if language == "ua":
        story.append(para("Приклад не обходить ingress: кожна дія зміни стану проходить canonical parse, schema, policies, перевірку цілісності Activation, capability/scope, Grant/SOD/Lease/fence, прив'язку evidence й atomic commit. `status`, `next` та `continue` відхиляють stale projection або continuation.", st["body"]))
        story.append(para("`doctor` є єдиним aggregate live health report для exact current components core, init, providers, recovery, replay і projection. Component і rollup statuses: healthy, degraded, failed або incomplete з precedence failed, incomplete, degraded, healthy. `--no-replay` дає incomplete; missing або stale projection ніколи не healthy; provider status походить із фактичних bounded observations. Report завжди має `report_authoritative=false`, `pass_credit=false`, `product_acceptance_pass=false` і `product_public_approval=not_approved`.", st["body"]))
        story.append(para("OperationMetrics є live-only non-authoritative observation однієї команди й містить лише Core-owned duration, changed-record, event-write, projection-update, runtime-checkpoint, physical-payload-byte та bytes-per-changed-record fields. DoctorResult і OperationMetrics не збирають, не вигадують і не розподіляють token, cost, usage, goal, session, batch, workspace або per-run usage or per-run accounting.", st["body"]))
    else:
        story.append(para("The example does not bypass ingress: every state-changing action still passes canonical parse, schema, policies, Activation integrity, capability/scope, Grant/SOD/Lease/fence, evidence binding, and atomic commit. `status`, `next`, and `continue` reject a stale projection or continuation.", st["body"]))
        story.append(para("`doctor` is the one aggregate live health report for the exact current components core, init, providers, recovery, replay, and projection. Component and rollup statuses are healthy, degraded, failed, or incomplete with precedence failed, incomplete, degraded, healthy. `--no-replay` yields incomplete; a missing or stale projection is never healthy; provider status comes from actual bounded observations. The report always has `report_authoritative=false`, `pass_credit=false`, `product_acceptance_pass=false`, and `product_public_approval=not_approved`.", st["body"]))
        story.append(para("OperationMetrics is a live-only non-authoritative observation for one command and contains only Core-owned duration, changed-record, event-write, projection-update, runtime-checkpoint, physical-payload-byte, and bytes-per-changed-record fields. DoctorResult and OperationMetrics neither collect, invent, nor allocate token, cost, usage, goal, session, batch, workspace, or per-run usage or per-run accounting.", st["body"]))
    source(story, OWNER["preset"] + "; " + OWNER["policy"] + "; " + OWNER["schema"], "base_user_commands + command_capability_scope + critical record definitions", st)

    add_heading(
        story,
        "Standard candidate, evidence, and decision"
        if language == "en"
        else "Кандидат стандарту, докази й рішення",
        1,
        "standard-distribution-decision",
        st,
    )
    distribution_text = (
        "The chain is acyclic: exact candidate ZIP bytes produce StandardReleaseCandidateBinding; exact-package verification and multi-platform closure are recomputed rather than supplied as evidence roles; physically resolved results produce StandardReleaseEvidenceManifest; an active configured authority then signs one explicit approve or reject StandardReleaseDecision; distribution status is derived from that verified chain. VERSION.json describes version and package identity only. Every external JSON record is parsed from one bounded stable byte read. A digest string by itself proves neither evidence nor authority, and the decision cannot change candidate bytes."
        if language == "en"
        else "Ланцюг є ациклічним: точні bytes ZIP-кандидата утворюють StandardReleaseCandidateBinding; exact-package verification і multi-platform closure обчислюються повторно, а не приймаються як evidence roles; фізично перевірені результати утворюють StandardReleaseEvidenceManifest; після цього активне налаштоване повноваження підписує StandardReleaseDecision з явним outcome approve або reject; статус дистрибуції є похідним від перевіреного ланцюга. VERSION.json описує лише версію та ідентичність пакета. Кожний зовнішній JSON record парситься з одного bounded stable read тих самих bytes. Окремий рядок digest не доводить ані evidence, ані повноваження, а рішення не змінює bytes кандидата."
    )
    story.append(para(distribution_text, st["body"]))
    story.append(
        make_table(
            ["StandardReleaseCandidateBinding field", "Binding"],
            ((name, "exact candidate identity") for name in STANDARD_CANDIDATE_FIELDS),
            [77 * mm, 92 * mm],
            st,
        )
    )
    evidence_roles = (
        defs["StandardReleaseEvidenceEntry"]["properties"]["evidence_role"]["enum"]
    )
    story.append(
        make_table(
            ["StandardReleaseEvidenceManifest field", "Binding"],
            ((name, "physically resolved evidence set") for name in STANDARD_EVIDENCE_MANIFEST_FIELDS),
            [77 * mm, 92 * mm],
            st,
        )
    )
    story.append(
        para(
            (
                "Required evidence roles: "
                if language == "en"
                else "Обов'язкові ролі evidence: "
            )
            + ", ".join(evidence_roles),
            st["body_compact"],
        )
    )
    story.append(
        make_table(
            ["StandardReleaseDecision field", "Binding"],
            ((name, "signed approve-or-reject claim") for name in STANDARD_DECISION_FIELDS),
            [77 * mm, 92 * mm],
            st,
        )
    )
    authority_text = (
        "Decision verification requires release_capability=standard.distribute, the configured trust root and Ed25519 provider, an active matching key and decider, bounded nonce and decision time, the canonical signed-claim digest, a valid signature, and a separately supplied SHA-256 pin for the exact trust-configuration bytes. A valid signature under an unpinned caller-supplied root is only signature_valid_under_supplied_root and cannot approve. Unknown, revoked, expired, unsigned, replayed-version, unpinned, or mismatched records fail closed. Approve affects only standard distribution; product acceptance remains false, public approval remains not approved, public_release_approved remains false, and cutover and deletion remain false until their independent human decision boundary is satisfied."
        if language == "en"
        else "Перевірка Decision потребує release_capability=standard.distribute, налаштованих trust root і Ed25519 provider, активних відповідних key і decider, обмежених nonce та часу рішення, canonical signed-claim digest, чинного signature й окремо заданого SHA-256 pin точних bytes trust configuration. Чинний signature під неприкріпленим caller-supplied root має лише статус signature_valid_under_supplied_root і не може схвалити дистрибуцію. Невідомі, відкликані, прострочені, непідписані, повторно використані для іншої версії, unpinned або невідповідні записи відхиляються. Approve впливає лише на дистрибуцію стандарту; product acceptance залишається false, public approval - not approved, public_release_approved - false, а cutover і deletion залишаються false до виконання окремої межі людського рішення."
    )
    story.append(para(authority_text, st["body"]))

    add_heading(
        story,
        "Document verification" if language == "en" else "Перевірка документів",
        2,
        "human-document-verification",
        st,
    )
    document_text = (
        "HumanDocumentVerification is a typed exact-ZIP candidate-bound result. It verifies all four PDFs by exact digest, strict parse, page count, extracted-character count, blank-page and extraction diagnostics, exact regular/bold/italic/mono font digests, and deterministic rebuild. Every page is rendered to a digest-bound PNG, and visual_review_scope covers every rendered page and clipping result; a first-page check or an unspecified visual scope cannot pass. The record always keeps product_acceptance_pass=false."
        if language == "en"
        else "HumanDocumentVerification є типізованим результатом, прив'язаним до точного ZIP-кандидата. Він перевіряє всі чотири PDF за точними digest, strict parse, кількістю сторінок, кількістю вилучених символів, діагностикою порожніх сторінок і extraction, точними digest regular/bold/italic/mono fonts та deterministic rebuild. Кожна сторінка рендериться у digest-bound PNG, а visual_review_scope охоплює всі rendered pages і результати clipping; перевірка лише першої сторінки або невизначена візуальна область не може пройти. Запис завжди зберігає product_acceptance_pass=false."
    )
    story.append(para(document_text, st["body"]))
    document_definition = defs["HumanDocumentVerification"]
    story.append(
        make_table(
            ["HumanDocumentVerification field", "Structural rule"],
            (
                (name, summarize_schema(spec))
                for name, spec in document_definition.get("properties", {}).items()
            ),
            [69 * mm, 100 * mm],
            st,
        )
    )
    for pid in ("P-045", "P-054", "P-055", "P-056"):
        item = policies[pid]
        bullet(story, f"{pid} {item['name']}: {localized(item['statement'])}", st)
    source(
        story,
        OWNER["authority"] + "; " + OWNER["schema"] + "; " + OWNER["conformance"],
        "candidate binding + physical evidence resolution + configured signed approve/reject + typed PDF verification",
        st,
    )
    return story


def summarize_schema(definition: Any) -> str:
    definition = localized(definition)
    if not isinstance(definition, dict):
        return json.dumps(definition, ensure_ascii=False, sort_keys=True)
    parts: list[str] = []
    for key in ("type", "const", "enum", "format", "pattern", "minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems", "uniqueItems", "additionalProperties", "unevaluatedProperties"):
        if key in definition:
            value = definition[key]
            serialized = json.dumps(value, ensure_ascii=False, sort_keys=True)
            if isinstance(value, dict):
                serialized = "schema(keys:" + ",".join(sorted(value)) + ")"
            elif isinstance(value, list) and len(serialized) > 240:
                serialized = f"[{len(value)} items]"
            parts.append(f"{key}={serialized}")
    if "$ref" in definition:
        parts.append(f"$ref={json.dumps(definition['$ref'], ensure_ascii=False)}")
    for key in ("oneOf", "anyOf", "allOf"):
        branches = definition.get(key)
        if not isinstance(branches, list):
            continue
        branch_labels: list[str] = []
        for branch in branches:
            if not isinstance(branch, dict):
                branch_labels.append(type(branch).__name__)
            elif isinstance(branch.get("$ref"), str):
                branch_labels.append(branch["$ref"])
            elif "const" in branch:
                branch_labels.append(f"const:{json.dumps(branch['const'], ensure_ascii=False)}")
            elif isinstance(branch.get("type"), str):
                branch_labels.append(f"type:{branch['type']}")
            else:
                branch_labels.append("keys:" + ",".join(sorted(branch)))
        parts.append(f"{key}[{len(branches)}]=" + " | ".join(branch_labels))
    return "; ".join(parts) or "composed structural definition"


def appendix_story(data: dict[str, dict[str, Any]], language: str, st: dict[str, ParagraphStyle]) -> list[Flowable]:
    global CURRENT_LANGUAGE
    CURRENT_LANGUAGE = language
    tx = UA if language == "ua" else EN
    manifest = data["manifest"]
    sem = data["semantic"]
    auth = data["authority"]
    policy = data["policy"]
    conf = data["conformance"]
    schema = data["schema"]
    preset = data["preset"]
    story: list[Flowable] = []
    cover(story, st)
    toc(story, tx["toc"], st)
    add_heading(story, tx["appendix_title"], 1, "appendices", st)
    intro = (
        "Ці таблиці є повною згенерованою проєкцією канонічних власників. Кожний запис показує шлях власника та ідентифікатор виконуваного валідатора, посилання на схему, предикат або ідентифікатор мутаційної перевірки."
        if language == "ua"
        else "These tables are a complete generated projection of canonical owners. Every entry shows an owner path and an executable validator, schema reference, predicate, or mutation-probe identifier."
    )
    story.append(para(intro, st["body"]))
    source(story, OWNER["manifest"], "bundle_digest + core_components", st)

    add_heading(story, "Canonical owner trace" if language == "en" else "Трасування канонічних власників", 1, "owner-trace", st)
    owner_rows = [
        (OWNER["manifest"], manifest["function"], manifest["schema_ref"], sha256_file(CORE_PATHS["manifest"])),
        (OWNER["semantic"], sem["function"], sem["schema_ref"], sha256_file(CORE_PATHS["semantic"])),
        (OWNER["authority"], auth["function"], auth["schema_ref"], sha256_file(CORE_PATHS["authority"])),
        (OWNER["policy"], policy["function"], policy["schema_ref"], sha256_file(CORE_PATHS["policy"])),
        (OWNER["conformance"], conf["function"], conf["schema_ref"], sha256_file(CORE_PATHS["conformance"])),
        (OWNER["schema"], schema["function"], "Draft 2020-12 oneOf", sha256_file(CORE_PATHS["schema"])),
    ]
    story.append(make_table(["Owner", "Sole function", "Validator", "SHA256"], owner_rows, [40 * mm, 57 * mm, 37 * mm, 35 * mm], st))
    bundle_label = "Core bundle digest" if language == "en" else "Digest пакета Core"
    preset_label = "Selected preset outside Core identity" if language == "en" else "Вибраний preset поза ідентичністю Core"
    story.append(para(f"{bundle_label}: {manifest['bundle_digest']}", st["body"]))
    story.append(para(f"{preset_label}: {OWNER['preset']} | SHA256: {sha256_file(PRESET_PATH)}", st["body"]))
    source(story, OWNER["manifest"], "canonical_name_only + core_components + bundle_digest", st)

    schema_count = len(schema["$defs"])
    add_heading(
        story,
        f"Schema catalog - {schema_count} definitions"
        if language == "en"
        else f"Каталог схеми - {schema_count} визначень",
        1,
        "schema-catalog",
        st,
    )
    schema_intro = (
        f"Schema ID: {schema['$id']} | Dialect: {schema['$schema']} | Definitions: {len(schema['$defs'])}"
        if language == "en"
        else f"ID схеми: {schema['$id']} | Діалект: {schema['$schema']} | Визначень: {len(schema['$defs'])}"
    )
    story.append(para(schema_intro, st["body"]))
    for index, (name, definition) in enumerate(sorted(schema["$defs"].items()), 1):
        key = f"schema-{anchor_id(name)}"
        add_heading(story, f"{index}. {name}", 2, key, st)
        required = definition.get("required", []) if isinstance(definition, dict) else []
        type_label = "Type summary" if language == "en" else "Опис типу"
        required_label = "Required" if language == "en" else "Обов'язкові поля"
        story.append(para(f"{type_label}: {summarize_schema(definition)}", st["body_compact"]))
        story.append(para(f"{required_label}: {', '.join(required) if required else '-'}", st["body_compact"]))
        properties = definition.get("properties", {}) if isinstance(definition, dict) else {}
        if properties:
            prop_rows = []
            for prop_name, prop_schema in sorted(properties.items()):
                prop_rows.append((prop_name, "yes" if prop_name in required else "no", summarize_schema(prop_schema)))
            story.append(make_table(["Property", "Required", "Structural rule"], prop_rows, [46 * mm, 19 * mm, 104 * mm], st))
        raw = json.dumps(localized(definition), ensure_ascii=False, sort_keys=True, indent=2)
        code_block(story, raw, st)
        source(story, f"{OWNER['schema']}#/$defs/{name}", f"{schema['$id']}#/$defs/{name}", st)

    policy_count = len(policy["policies"])
    add_heading(
        story,
        f"Policy registry - {policy_count} policies"
        if language == "en"
        else f"Реєстр політик - {policy_count}",
        1,
        "policy-registry",
        st,
    )
    policy_rows = [(item["id"], item["severity"], item["name"], item["statement"], item["validator_id"], OWNER["policy"]) for item in policy["policies"]]
    story.append(make_table(["ID", "Severity", "Name", "Statement", "Validator ID", "Owner"], policy_rows, [16 * mm, 17 * mm, 28 * mm, 61 * mm, 25 * mm, 22 * mm], st))
    source(story, OWNER["policy"], "validator_registry_version=1", st)
    add_heading(story, "Executable validator index" if language == "en" else "Індекс виконуваних валідаторів", 2, "validator-index", st)
    for item in policy["policies"]:
        story.append(para(f"{item['id']} | {item['validator_id']} | {OWNER['policy']}", st["body_compact"]))
    source(story, OWNER["policy"], "policies[].validator_id", st)

    acceptance_count = len(conf["required_acceptance"])
    add_heading(
        story,
        f"Acceptance predicates - {acceptance_count}"
        if language == "en"
        else f"Предикати прийняття - {acceptance_count}",
        1,
        "acceptance-predicates",
        st,
    )
    acceptance_rows = [(index, item, item, OWNER["conformance"]) for index, item in enumerate(conf["required_acceptance"], 1)]
    story.append(make_table(["#", "Predicate ID", "Validator / predicate ID", "Owner"], acceptance_rows, [12 * mm, 66 * mm, 58 * mm, 33 * mm], st))
    story.append(para(conf["production_claim_rule"], st["body"]))
    source(story, OWNER["conformance"], "required_acceptance", st)

    mutation_count = len(conf["mutation_families"])
    add_heading(
        story,
        f"Mutation catalog - {mutation_count} families"
        if language == "en"
        else f"Каталог мутацій - {mutation_count} сімейств",
        1,
        "mutation-catalog",
        st,
    )
    mutation_rows = [(index, item, item, OWNER["conformance"]) for index, item in enumerate(conf["mutation_families"], 1)]
    story.append(make_table(["#", "Mutation family", "Mutation probe ID", "Owner"], mutation_rows, [12 * mm, 66 * mm, 58 * mm, 33 * mm], st))
    source(story, OWNER["conformance"], "mutation_families", st)

    add_heading(story, "State machines" if language == "en" else "Автомати станів", 1, "state-machines", st)
    for machine in ("task", "lease"):
        add_heading(story, machine.capitalize(), 2, f"state-{machine}", st)
        rows = [(state, ", ".join(targets) if targets else "-") for state, targets in policy["state_machines"][machine].items()]
        story.append(make_table(["State", "Allowed next state"], rows, [55 * mm, 114 * mm], st))
        source(story, OWNER["policy"], f"state_machines.{machine} + state_machine_transition", st)
    story.append(para(policy["state_machines"]["capacity_release"], st["body"]))
    source(story, OWNER["policy"], "state_machines.capacity_release", st)

    add_heading(story, "Capabilities and command authorization" if language == "en" else "Можливості й авторизація команд", 1, "command-authorization", st)
    story.append(make_table(["Capability", "Purpose", "Owner", "Validator"], ((x["id"], x["purpose"], OWNER["authority"], "command_capability_scope") for x in auth["capabilities"]), [37 * mm, 69 * mm, 35 * mm, 28 * mm], st))
    add_heading(story, "Command to capability resolution" if language == "en" else "Відображення команди у можливість", 2, "command-capability", st)
    command_rows = []
    for item in auth["command_capability_rules"]:
        resolution = item.get("capability_id") or json.dumps({"payload_field": item.get("payload_field"), "capability_by_value": item.get("capability_by_value")}, ensure_ascii=False, sort_keys=True)
        command_rows.append((item["command_kind"], resolution, OWNER["authority"], "command_capability_scope"))
    story.append(make_table(["Command kind", "Capability resolution", "Owner", "Validator"], command_rows, [42 * mm, 65 * mm, 34 * mm, 28 * mm], st))
    add_heading(story, "Command effect scope" if language == "en" else "Область дії команд", 2, "command-effect-scope", st)
    effect_rows = []
    for item in auth["command_effect_scope_rules"]:
        effect_rows.append((item["command_kind"], item["mode"], json.dumps({k: v for k, v in item.items() if k not in {"command_kind", "mode"}}, ensure_ascii=False, sort_keys=True), OWNER["authority"], "command_capability_scope"))
    story.append(make_table(["Command kind", "Mode", "Target rule", "Owner", "Validator"], effect_rows, [34 * mm, 30 * mm, 56 * mm, 27 * mm, 22 * mm], st))
    mutation_claim = auth.get("command_mutation_claim_rule")
    if mutation_claim:
        add_heading(story, "Lease-bound mutation claim" if language == "en" else "Прив'язка мутаційної команди до оренди", 2, "appendix-mutation-claim", st)
        story.append(para(mutation_claim["claim_rule"], st["body"]))
        claim_rows = [
            ("command_authorization_source", mutation_claim["command_authorization_source"]),
            ("grant_separation_rule", mutation_claim["grant_separation_rule"]),
            ("holder_grant_capability", mutation_claim["holder_grant_capability"]),
            ("holder_grant_field", mutation_claim["holder_grant_field"]),
            ("lease_bound_command_kinds", mutation_claim["lease_bound_command_kinds"]),
            ("lease_bound_task_transition_states", mutation_claim["lease_bound_task_transition_states"]),
            ("lease_required_state", mutation_claim["lease_required_state"]),
            ("required_command_fields", mutation_claim["required_command_fields"]),
            ("required_workcard_fields", mutation_claim["required_workcard_fields"]),
            ("stale_or_unresolved", mutation_claim["stale_or_unresolved"]),
        ]
        story.append(make_table(
            ["Claim component", "Canonical value", "Owner", "Validator"],
            ((name, value, OWNER["authority"], "lease_fence + command_capability_scope") for name, value in claim_rows),
            [47 * mm, 66 * mm, 33 * mm, 23 * mm],
            st,
        ))
        story.append(make_table(
            ["Binding equality", "Owner", "Validator"],
            ((value, OWNER["authority"], "lease_fence + command_capability_scope") for value in mutation_claim["binding_equalities"]),
            [103 * mm, 38 * mm, 28 * mm],
            st,
        ))
        code_block(story, json.dumps(localized(mutation_claim), ensure_ascii=False, sort_keys=True, indent=2), st)
        source(story, OWNER["authority"] + "; " + OWNER["policy"], "command_mutation_claim_rule + lease_fence + command_capability_scope", st)

    add_heading(story, "Replay-complete Evidence and CAS" if language == "en" else "Повні для відтворення Evidence і CAS", 2, "appendix-evidence-cas", st)
    artifact_def = schema["$defs"]["Artifact"]
    binding_def = schema["$defs"]["EvidenceBinding"]
    evidence_rows = [
        ("Artifact.required", artifact_def["required"], "Artifact"),
        ("EvidenceBinding.required", binding_def["required"], "EvidenceBinding"),
        ("outcome", artifact_def["properties"]["outcome"]["enum"], "Artifact"),
        ("evidence_class", artifact_def["properties"]["evidence_class"]["enum"], "Artifact"),
        ("product_credit_eligible", "true only for fresh resolved passing product-execution evidence", "Artifact.allOf"),
        ("GateResult.evidence_artifacts", "exact artifact_id + artifact_record_digest for pass, fail, or blocked", "GateResult.oneOf"),
    ]
    story.append(make_table(
        ["Evidence field", "Rule", "Schema"],
        evidence_rows,
        [52 * mm, 82 * mm, 35 * mm],
        st,
    ))
    source(story, OWNER["schema"] + "; " + OWNER["semantic"] + "; " + OWNER["policy"], "$defs/Artifact + $defs/EvidenceBinding + $defs/GateResult + candidate_evidence_binding + credit_requires_evidence", st)
    add_heading(story, "Separation of duties" if language == "en" else "Розділення обов'язків", 2, "appendix-sod", st)
    sod_rows = [(x["id"], x["rule"], json.dumps(localized({k: v for k, v in x.items() if k not in {"id", "rule"}}), ensure_ascii=False, sort_keys=True), OWNER["authority"], x["id"]) for x in auth["separation_of_duties"]]
    story.append(make_table(["ID", "Rule", "Constraint", "Owner", "Validator"], sod_rows, [17 * mm, 39 * mm, 65 * mm, 28 * mm, 20 * mm], st))
    source(story, OWNER["authority"], "capabilities + command_capability_rules + command_effect_scope_rules + separation_of_duties", st)

    add_heading(story, "Trust, bootstrap, and role presets" if language == "en" else "Довіра, початкова авторизація і presets ролей", 1, "trust-bootstrap", st)
    story.append(para(auth["bootstrap_rule"], st["body"]))
    story.append(make_table(["Trust mode", "Definition", "Owner", "Validator"], ((name, value, OWNER["authority"], "grant_validity") for name, value in auth["trust_modes"].items()), [34 * mm, 77 * mm, 34 * mm, 24 * mm], st))
    role_rows = [(name, ", ".join(values), "non-authoritative", OWNER["authority"]) for name, values in auth["role_presets_non_authoritative"].items()]
    story.append(make_table(["Role preset", "Capabilities", "Authority status", "Owner"], role_rows, [30 * mm, 75 * mm, 33 * mm, 31 * mm], st))
    source(story, OWNER["authority"], "bootstrap_rule + trust_modes + role_presets_non_authoritative", st)

    add_heading(story, "Semantic vocabulary" if language == "en" else "Семантичний словник", 1, "semantic-vocabulary", st)
    story.append(make_table(["Entity", "Purpose", "Owner", "Validator"], ((x["kind"], x["purpose"], OWNER["semantic"], "admission.entity") for x in sem["persistent_entities"]), [30 * mm, 76 * mm, 35 * mm, 28 * mm], st))
    story.append(make_table(["Relation", "Source", "Target", "Rules", "Validator"], ((x["kind"], ", ".join(x["source"]), ", ".join(x["target"]), ", ".join(x["rules"]), "admission.relation") for x in sem["relations"]), [24 * mm, 34 * mm, 38 * mm, 48 * mm, 25 * mm], st))
    story.append(make_table(["Value object", "Meaning", "Owner", "Validator"], ((name, value, OWNER["semantic"], "design_rules") for name, value in sem["value_objects"].items()), [34 * mm, 72 * mm, 35 * mm, 28 * mm], st))
    story.append(make_table(["Derived projection", "Authority", "Owner", "Validator"], ((name, "derived and non-authoritative", OWNER["semantic"], "derived_projection_kinds") for name in sem["derived_projection_kinds"]), [42 * mm, 49 * mm, 42 * mm, 36 * mm], st))
    source(story, OWNER["semantic"], "admission + design_rules + persistent_entities + relations + value_objects + derived_projection_kinds", st)

    add_heading(story, "Technology boundaries" if language == "en" else "Технологічні межі", 1, "technology-boundaries", st)
    story.append(make_table(["Capability", "Task", "Forbidden boundary", "Owner", "Validator"], ((x["id"], x["task"], x["forbidden_boundary"], OWNER["semantic"], "technology_capabilities") for x in sem["technology_capabilities"]), [28 * mm, 45 * mm, 49 * mm, 26 * mm, 21 * mm], st))
    source(story, OWNER["semantic"], "technology_capabilities", st)

    add_heading(story, "Conformance budgets and scale" if language == "en" else "Бюджети відповідності й масштабування", 1, "conformance-budgets", st)
    scale_summary = (
        "The physical lane uses 100,000 raw files represented by one physical inventory record per file, with bucketed evidence across 100 buckets of 1,000 files. Raw inventory creates no semantic Artifact, Task, or Relation records; semantic control state is separately bounded at 256 records. An explicit authorized harness corpus brings the projection to at least 198,999 Core-valid typed Relations as physical evidence, not per-file semantic materialization. At least 600 actual runtime queries mix exact identities, content-only and high-cardinality terms, broad bounded refinement, misses, hostile identity text, and forced continuation across depths 1-12. This bounded physical proof is not a full 1000 by 1000 execution and must not be replaced by one."
        if language == "en"
        else "Фізична перевірка використовує 100 000 raw-файлів, представлених одним physical inventory record на файл, із bucketed evidence у 100 buckets по 1 000 файлів. Raw inventory не створює semantic Artifact, Task або Relation records; semantic control state окремо обмежено 256 records. Окремий авторизований harness corpus доводить щонайменше 198 999 Core-valid типізованих Relations як фізичне evidence, а не per-file semantic materialization. Щонайменше 600 фактичних runtime-запитів поєднують exact identities, content-only і high-cardinality terms, broad bounded refinement, misses, hostile identity text та forced continuation на глибинах 1-12. Цей bounded physical proof не є повним виконанням 1000 на 1000 і не повинен ним замінюватися."
    )
    story.append(para(scale_summary, st["body"]))
    story.append(make_table(["Structural budget", "Value", "Owner", "Validator"], ((name, value, OWNER["conformance"], name) for name, value in conf["structural_budgets"].items()), [54 * mm, 28 * mm, 50 * mm, 37 * mm], st))
    story.append(make_table(["WorkCard ceiling", "Value", "Owner", "Validator"], ((name, value, OWNER["conformance"], "bounded-workcard-through-depth-twelve") for name, value in conf["workcard_hard_ceiling"].items()), [49 * mm, 25 * mm, 48 * mm, 47 * mm], st))
    story.append(make_table(["Scale contract", "Definition", "Owner", "Validator"], ((name, value, OWNER["conformance"], name) for name, value in conf["scale_contracts"].items()), [36 * mm, 69 * mm, 36 * mm, 28 * mm], st))
    story.append(make_table(["Reference benchmark", "Value", "Owner", "Validator"], ((name, value, OWNER["conformance"], "reference-benchmark") for name, value in conf["reference_benchmarks"].items()), [57 * mm, 31 * mm, 48 * mm, 33 * mm], st))
    source(story, OWNER["conformance"], "structural_budgets + workcard_hard_ceiling + scale_contracts + reference_benchmarks", st)

    add_heading(story, "Preset and profiles" if language == "en" else "Набір налаштувань і профілі", 1, "preset-profiles", st)
    story.append(para(preset["function"], st["body"]))
    profile_rows = [(name, json.dumps(value, ensure_ascii=False, sort_keys=True), OWNER["preset"], "profiles") for name, value in preset["profiles"].items()]
    story.append(make_table(["Profile", "Budgets", "Owner", "Validator"], profile_rows, [31 * mm, 81 * mm, 34 * mm, 23 * mm], st))
    preset_rows = [
        ("base_user_commands", preset["base_user_commands"]),
        ("required_provider_capabilities", preset["required_provider_capabilities"]),
        ("forbidden_implicit_behavior", preset["forbidden_implicit_behavior"]),
        ("semantic_programming", preset["semantic_programming"]),
    ]
    if preset.get("optional_provider_capabilities"):
        preset_rows.append(("additional_provider_capabilities", preset["optional_provider_capabilities"]))
    story.append(make_table(["Preset field", "Value", "Owner", "Validator"], ((name, value, OWNER["preset"], name) for name, value in preset_rows), [47 * mm, 74 * mm, 28 * mm, 20 * mm], st))
    source(story, OWNER["preset"], "Preset schema + preset field identifiers", st)

    add_heading(story, "Top-level schema ingress" if language == "en" else "Кореневий вхід схеми", 1, "schema-ingress", st)
    ingress_rows = []
    for index, ref in enumerate(schema["oneOf"], 1):
        ingress_rows.append((index, ref.get("$ref", ""), OWNER["schema"], ref.get("$ref", "")))
    story.append(make_table(["#", "Accepted root definition", "Owner", "Validator"], ingress_rows, [12 * mm, 74 * mm, 42 * mm, 41 * mm], st))
    source(story, OWNER["schema"], "oneOf + Draft 2020-12", st)
    return story


def build_pdf(path: Path, story: list[Flowable], *, title: str, language: str, version: str, st: dict[str, ParagraphStyle]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = ProminDocTemplate(str(path), title=title, language=language, version=version, style_map=st)
    doc.multiBuild(story)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    for role in FONT_FACES:
        parser.add_argument(
            f"--font-{role}",
            type=Path,
            required=True,
            metavar="PATH",
            help=f"explicit portable {role} TrueType/OpenType font input",
        )
        parser.add_argument(
            f"--font-{role}-sha256",
            type=sha256_argument,
            required=True,
            metavar="SHA256",
            help=f"expected SHA-256 for --font-{role}",
        )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="verify canonical inputs and font bindings without generating PDFs",
    )
    parser.add_argument(
        "--evidence-out",
        type=Path,
        help="optional path for deterministic JSON build evidence (also printed to stdout)",
    )
    args = parser.parse_args(argv)
    data = {key: load_json(path) for key, path in CORE_PATHS.items()}
    verify_sources(data)
    verify_document_sources()
    font_evidence = register_fonts(font_bindings_from_args(args))
    version = data["manifest"]["version"]
    outputs = [
        ("promin_main_ua.pdf", "ua", f"promin версія {version}", main_story),
        ("promin_appendices_ua.pdf", "ua", f"promin версія {version}", appendix_story),
        ("promin_main_en.pdf", "en", f"promin version {version}", main_story),
        ("promin_appendices_en.pdf", "en", f"promin version {version}", appendix_story),
    ]
    generated: list[Path] = []
    if not args.check_only:
        st = styles()
        for filename, language, title, factory in outputs:
            path = args.output / filename
            build_pdf(path, factory(data, language, st), title=title, language=language, version=version, st=st)
            generated.append(path)
    evidence = build_evidence(data, font_evidence, generated, check_only=args.check_only)
    if args.evidence_out is not None:
        write_evidence(args.evidence_out, evidence)
    print(json.dumps(evidence, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

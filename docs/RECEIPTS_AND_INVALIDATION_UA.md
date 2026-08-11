# Receipt, Merkle та admission policy

Цей документ описує alpha.4 primitives для доказу provider closure та для
допуску verification gates. Вони самі по собі не є Activation, provider
dispatch, build, runtime evidence або product acceptance.

## Межі власності записів

`promin.input_identity` є єдиним власником source selection і provider input
identity. Selection перевіряє containment, дозволені/заборонені корені,
case-collision та link/reparse до читання байтів.

`promin.provider_envelope` є єдиним власником:

- `PhysicalSeal` фізичного provider artifact;
- global driver / module envelope;
- `FullScan` і `Reuse`, а також exact `ProviderCoverageUnion`;
- `ConservativeTimestampInterval`.

`promin.provider_receipts` не має другої schema для жодного з цих понять. Він
приймає лише їхні typed records, перевіряє актуальний physical seal і додає
`TargetMerkleReceipt`: content-addressed binding на digest та canonical-byte
SHA-256 канонічних owner records. Локальний шлях artifact потрібний лише для
перевірки seal і ніколи не серіалізується в receipt.

## Byte-authoritative target closure

`scan_target_closure(selection)` приймає лише typed `SourceSelection`, а не
raw root/path list. Для кожного включеного файла він повторно перевіряє
canonical source selection після preflight, перевіряє containment перед hash,
відкидає link/junction/reparse та special file і читає точні байти через
стабільний `lstat/fstat/lstat` read-race witness.

Stat поля використовуються тільки як witness конкурентної підміни, а не як
cache authority. Кожен включений файл SHA-256-хешується при кожному capture.
Тому in-place byte substitution зі збереженими size/mtime не може лишитися
reuse hit: змінюється leaf SHA-256 і Merkle root.

`ReceiptLeaf` містить portable relative path, SHA-256 exact bytes і byte count.
Leaf та internal Merkle node мають різні domain prefixes. Closure включає
selection digest, exact selected path set, явний transient allowlist, exact
excluded path set та всі включені leaves. Transient може бути виключений лише
як явний шлях, що реально належить selected closure; порожній closure
fail-closed.

## H14: bounded Merkle reuse для великих closure

`capture_target_closure(...)` робить рівно **один physical traversal** для
одного capture. Він не запускає окремий metadata revalidation pass: для
кожного `SourceEntry` containment, preflight metadata witness і відкриття
regular file перевіряються в тому ж проході, у якому обчислюється SHA-256.
Тому зміна байта зі збереженим size/mtime на Windows не може стати cache hit.

`MerkleLeafCache` — тільки process-local bounded LRU. Ключ містить portable
path, fresh byte SHA-256 і byte count; leaf можна взяти з cache лише **після**
нового physical read та порівняння цього SHA-256. Metadata не є ключем або
authority. Cache не зберігає host path, має `max_entries` і conservative
`max_bytes`, а eviction/uncacheable leaf фіксуються лише як diagnostic
observation.

`TargetClosureLimits` за замовчуванням допускає 250 000 selected files (тобто
100k+ closure), але обмежує file count, total hashed bytes і conservative
materialized-leaf accounting. Merkle folding для already canonical leaves
використовує O(log n) intermediate hashes; сам receipt усе одно зберігає exact
leaf list, тому memory limit є fail-closed, а не прихованим скороченням scope.

`TargetClosureCapture` чесно показує `physical_traversal_passes=1`, кількість
байтово перевірених файлів, bytes, hits/misses та eviction. Це diagnostic
receipt без pass credit. `benchmark_target_closure_capture(...)` має максимум
2 warmup і 5 measured samples, приймає лише preselected real target, не
генерує/не змінює source і завжди повертає `DIAGNOSTIC_ONLY`,
`performance_acceptance=false`, `acceptance_pass=false`.

## Rebinding та lineage

`bind_target_merkle_receipt(...)` вимагає рівність між:

- `ProviderInputIdentity.input_digest`;
- `ProviderEnvelope.input_identity_digest`;
- `CoverageUnion.input_identity_digest`.

Coverage union має бути `PASS`, без missing modules, містити mode поточного
envelope і реально включати його subset/covered modules. Перед bind повторно
перевіряється фізичний artifact через canonical `ProviderEnvelope` seal.

Coverage union також містить exact sorted `contributing_envelope_digests` і
required driver roles. `TargetMerkleReceipt` rebind-ить цей contributor
lineage, не вигадуючи власну provider/coverage schema. Різниця contributor
lineage класифікується як dependency-closure change і не може бути зведена до
leaf-cache reuse.

`FullScan` формує лише root lineage. `Reuse` обов'язково містить
`parent_target_receipt_digest`; він не успадковує незафіксовані лічильники або
metadata-only стан. Lifecycle interval, якщо наданий, лишається canonical
record з `provider_envelope`; receipt лише прив'язує його digest і canonical
bytes SHA-256.

Усі receipt і closure records мають `acceptance_pass=false` та
`pass_credit=false`. Навіть успішний rebind є лише доказом цілісності inputs,
не релізним або продуктовим acceptance.

## Windows physical EventStore history seal

`promin.windows_event_history` додає вузький фізичний seal лише для Windows
history EventStore на томі **NTFS** або **ReFS**. До вже наявної повної
EventStore-перевірки він утримує immutable journal та authority files відкритими
no-write/no-delete handles, а також утримує handles обох history directories.
Seal прив'язується лише після успішної повної byte verification; він не створює
окремий metadata-only шлях довіри.

Fast validation вимагає одночасно:

- exact closure імен та кількості файлів у journal і authority directories;
- незмінні held immutable file witnesses під утримуваними handles;
- точну рівність mutable control digests для HEAD payload, authority-root
  payload і checkpoint payload, а також authority generation.

`ChangeTime` є лише witness/hint зміни, а не джерелом істини для reuse: writer
з `FILE_WRITE_ATTRIBUTES` може відновити timestamp на NTFS. Тому ChangeTime не
замінює exact filename/count closure, утримувані handles або byte verification.

Якщо том або Windows capability не підтримується, є конфліктний writer,
неможливо утримати directory/file handle, перевищено cap held files або
спостереження конфліктують, seal не дає часткового результату: використовується
звичайний повний scan / EventStore verification. POSIX-маршрут не змінюється і не
отримує Windows physical seal.

Цей механізм не є acceptance або performance claim: `acceptance_pass=false` і
`pass_credit=false` залишаються незмінними.

## Core event batch ceiling: 128

Core ceiling для одного atomic EventStore batch дорівнює **128 events** і
**128 state-binding updates**. Це дозволяє одну `Task` разом максимум зі
127 `Relation` в одному atomic batch. Спроба додати 128 Relations до однієї
Task створила б 129 events і відхиляється до commit.

Ця межа не змінює semantic workload, не скорочує scope і не дозволяє тихо
відкинути або підмінити Relations. Вона визначає лише atomic commit shape:
1 Task + 127 Relations. Ліміт не є performance claim і не надає acceptance чи
pass credit.

## Typed invalidation і gate admission

`promin.gate_admission` має чотири bounded invalidation classes:

- `BODY_ONLY`: `cheap-source` → `affected-semantic` → `dependency-reuse`;
- `IMPORT_SURFACE`: `cheap-source` → `module-graph-refresh` →
  `bounded-provider-delta`;
- `CMAKE_TOPOLOGY`: `cheap-source` → `single-configure` →
  `module-graph-refresh` → `provider-refresh`;
- `TOOLING_ONLY`: `tool-tests`.

Git HEAD сам по собі означає тільки `BODY_ONLY`; він не авторизує configure,
provider refresh або новий target receipt. `GatePhaseReceipt` містить exact
input digest, scope count, availability, status, elapsed seconds і завжди
`credit=false`. Cheap non-pass, missing receipt, unavailable tool, phase budget
або host budget fail closed і блокують усі наступні дорожчі фази.

Навіть повністю passing admission plan має лише `admission_pass=true`:
`pass_credit=false` і `acceptance_pass=false` лишаються обов'язковими.

`ReceiptInvalidationClass` уточнює причину без створення другого gate policy:

- `REUSE_VALIDATED`, `BYTE_CONTENT_CHANGED` → bounded `BODY_ONLY` plan;
- `SOURCE_TOPOLOGY_CHANGED`, `TRANSIENT_POLICY_CHANGED`, `SELECTION_DRIFT` →
  `IMPORT_SURFACE` plan;
- `DEPENDENCY_CLOSURE_CHANGED`, `PROVIDER_IDENTITY_CHANGED` →
  `CMAKE_TOPOLOGY` plan.

Це лише вибір найменш дорогого достатнього вже існуючого plan. Усі gate
receipts, benchmark і cache statistics лишаються non-crediting.

## Межа Wave 1

Поточна хвиля додає незалежні primitives та unit tests. Інтеграція з `init.py`,
`service.py`, provider store, Core schema та CLI виконується окремою хвилею.
До неї ці модулі не надають runtime/product acceptance або pass credit.

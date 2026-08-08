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

## Rebinding та lineage

`bind_target_merkle_receipt(...)` вимагає рівність між:

- `ProviderInputIdentity.input_digest`;
- `ProviderEnvelope.input_identity_digest`;
- `CoverageUnion.input_identity_digest`.

Coverage union має бути `PASS`, без missing modules, містити mode поточного
envelope і реально включати його subset/covered modules. Перед bind повторно
перевіряється фізичний artifact через canonical `ProviderEnvelope` seal.

`FullScan` формує лише root lineage. `Reuse` обов'язково містить
`parent_target_receipt_digest`; він не успадковує незафіксовані лічильники або
metadata-only стан. Lifecycle interval, якщо наданий, лишається canonical
record з `provider_envelope`; receipt лише прив'язує його digest і canonical
bytes SHA-256.

Усі receipt і closure records мають `acceptance_pass=false` та
`pass_credit=false`. Навіть успішний rebind є лише доказом цілісності inputs,
не релізним або продуктовим acceptance.

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

## Межа Wave 1

Поточна хвиля додає незалежні primitives та unit tests. Інтеграція з `init.py`,
`service.py`, provider store, Core schema та CLI виконується окремою хвилею.
До неї ці модулі не надають runtime/product acceptance або pass credit.

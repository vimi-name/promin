# C/C++ capability profile

`language_profiles/c-family-semantic.json` — це generic, декларативний
контур для C та C++. Він не містить ідентифікаторів конкретного продукту,
шляхів вихідного коду або припущень про конкретний toolchain.

## Межа доказу

Текстовий збіг, regex або простий лексичний кандидат має стан `REVIEW`.
`PROVEN` дозволений лише для факту з compiler diagnostic або повного
структурованого contract proof. `SAFE` описує перевірений профілем факт.
Жоден з цих станів не надає `pass_credit`, product acceptance або release
approval.

## Лексична і module boundary перевірка

Перед структурним C/C++ аналізом Promin створює offset-preserving маску: вона
зберігає довжину та CR/LF позиції, але виключає comments, preprocessor,
ordinary/raw strings, character literals та явно позначені embedded-language
payloads. Template parameters, local declarations, member access і qualified
namespace components є typed exclusions, а не залежностями за замовчуванням.
Неповна лексична форма — `UNAVAILABLE`/`REVIEW`, не pass.

Для uniquely owned exported type допустимі лише direct import,
explicit export-import closure або same named module. Private transitive import
не є доказом видимості.

## CompDB і зовнішні інструменти

Canonical `compile_commands.json` перевіряється до clangd або clang-tidy:
потрібні physical regular file, точна форма рядків, root-contained source
identity, driver identity, compile intent та відсутність conflicting commands
для одного source identity. Відсутній CompDB має стан `UNAVAILABLE`; Promin не
конструює fallback command line.

clangd, clang-tidy, Doxygen і clang-doc є profile-selected extension points.
Відсутність optional tool має стан `UNAVAILABLE`. HTML/XML, raw diagnostics та
per-file inventories генеруються тільки в explicit host-local diagnostic mode;
їхня наявність не є documentation credit.

## Ownership, operation roles і scope

Профіль моделює by-value, rvalue-reference, borrowed-reference, member та
result-extraction transfers. Якщо source доступний після transfer, потрібен
детермінований moved-from postcondition. Аналіз не переносить ownership proof
через scope boundary.

Raw owner має повністю задекларувати рівно одну політику: movable owner,
explicitly immobile або transactional exchange з noexcept exchange і rollback
payload. Binary boundary вимагає explicit const-correct conversion, exact size
і preservation of ownership; compatibility helper, який приховує зміну
representation, заборонений.

Command, query і value query визначаються annotation, project mapping або
profile naming rule. Самі назви не є global Standard convention. Несумісні
effect/result контракти fail-closed.

Affected semantic scope — це changed C/C++ paths плюс bounded reverse closure
canonical module graph, прив'язаний до digest canonical CompDB. Depth/file
truncation завжди явний і не дає credit. `BODY_ONLY`, `IMPORT_SURFACE`,
`CMAKE_TOPOLOGY` та `TOOLING_ONLY` — різні invalidation classes; Git HEAD сам
по собі не авторизує configure, provider refresh або receipt recapture.

## Статичний admission

Найдешевші source gates виконуються до дорожчих етапів і мають timing receipt
з input digest та scope count. Невирішений дешевий invariant блокує дорожчий
етап. Цей profile surface є pure/static: він не запускає provider, build,
runtime або product acceptance route.

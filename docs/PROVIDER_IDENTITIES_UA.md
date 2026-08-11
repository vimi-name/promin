# Ідентичності provider/configure

Цей стандарт не пов'язує авторитет provider, configure або target receipt з
одним станом Git. Для кожної операції фіксуються чотири незалежні частини:
репозиторій, tooling, dependencies і точний target. Кожна частина має власні
типізовані записи та digest; їх сукупність утворює `ProviderInputIdentity`.
Git HEAD може зберігатися лише як неавторитетне спостереження і сам по собі не
дозволяє configure, повний provider scan або повторний target receipt.

Перед будь-яким хешуванням байтів, резервуванням виходу чи платформною
операцією `SourceSelection` перевіряє POSIX-відносні шляхи, membership,
заборонені корені, regular-file mode, link/reparse точки, дублікати та
portable case-collision. Вона навмисно не читає вміст файлу. Після create-only
резервування selection перечитується та порівнюється канонічними байтами; при
дрейфі операція завершується fail-closed. Наступний content-addressed етап
зобов'язаний окремо перевірити фактичні байти.

`ProviderEnvelope` прив'язує provider до SHA-256 physical seal, повного global
driver set і точного module subset. Якщо для мови потрібен C compiler, його
роль має бути присутня у global set навіть коли вибраний subset не містить C
файлів. `FullScan` і `Reuse` є явними тегами. Жоден з них не успадковує
лічильники іншого: достатність визначається лише явним union
`covered_modules` для запитаного scope.

Для CMake File API Promin спочатку створює create-only фізичний query у
`.cmake/api/v1/query/client-promin/query.json`, а після configure вимагає
реальний index reply і кожен запитаний response JSON. Модуль не запускає CMake
та не замінює чужий query. Відсутній reply має статус `UNAVAILABLE`; зламаний
або неповний reply — `FAIL`.

Точні timestamp provider з мікросекундами конвертуються в whole-second
lifecycle interval консервативно: start округлюється вниз, completion — вгору;
вхідна точність і спосіб конвертації записуються. Naive, non-UTC, malformed або
зворотно впорядковані часи не округлюються неявно й відхиляються.

Усі ці записи мають `acceptance_pass=false` і `pass_credit=false`. Вони є
передумовами дешевих і наступних gate, а не доказом product/release acceptance.

## Великий багатомовний scope

Для великого проєкту `BoundedModuleClosure` обходить точний явний граф
залежностей у стабільному UTF-8 порядку. Всі dependency nodes мають бути
декларовані; відсутній node не трактується як leaf. Ліміти `max_modules` і
`max_edges` повертають лише `UNAVAILABLE` + `truncated=true`, тому частковий
closure не можна використати як target identity або для provider reuse.

`MultiLanguageDriverSet` окремо фіксує global drivers для C, C++, C#, Java,
JavaScript і Python. Вибраний module subset не може прибрати driver іншої
заявленої мови. Кожен `LanguageDriver` повинен посилатися на той самий exact
`ProviderDriver`, що присутній у base envelope.

`ContributorDigest` прив'язує contributor, його module IDs і physical SHA-256
seal. `ContributorProvenance` дозволяється лише для повного closure і покриває
його module IDs точно, без пропусків чи extra modules. Перед runtime reuse
`verify_contributor_artifacts` перечитує байти всіх contributor artifacts;
відновлення розміру або mtime не замінює SHA-256 перевірку.

`LargeProjectProviderEnvelope` зв'язує base `FullScan`/`Reuse` envelope,
complete module closure, contributor provenance та multi-language driver set.
`Reuse` мусить містити digest відомого parent aggregate. Детермінований
`ProviderIdentityAggregate` допускає PASS лише коли є FullScan, explicit
FullScan/Reuse union повністю покриває bounded closure, глобальні drivers
збігаються, а contributor provenance однакова. Його `ProviderReuseMetrics`
показує кількість повторно покритих modules/contributors і elapsed time, але
час не входить у aggregate digest; усі acceptance/pass поля лишаються false.

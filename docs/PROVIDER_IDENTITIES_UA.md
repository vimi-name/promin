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

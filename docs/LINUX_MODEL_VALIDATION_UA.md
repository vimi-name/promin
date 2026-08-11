# Linux model validation через Docker

`tools/promin_linux_model.py` будує і, якщо Docker локально доступний, запускає
**контейнерну модель** Linux-перевірки. Це не є доказом роботи на окремому
Linux-host і не змінює deployment scope Standard.

## Межа доказу

План містить окремі identity для Docker client/server і локально наявного image,
SHA-256 tree identity source mount, точні argv-команди та незмінні limits.
Image ніколи не завантажується: Docker отримує `--pull=never`.

До успішного `docker run` поле `container_executed` є `false`. Навіть після
`PASS` воно означає лише, що всі exact commands завершилися в Docker-контейнері:

- `actual_linux_host_validated=false`;
- `linux_standard_validated=false`;
- `acceptance_pass=false`;
- `product_acceptance_pass=false`;
- `release_eligible=false`;
- `pass_credit=false`.

Отже `PASS` не є claim про Linux host, product runtime, installability або
release. `UNAVAILABLE` (Docker відсутній, daemon недоступний або image локально
відсутній) також ніколи не стає `PASS`. `FAIL` означає identity drift, зміну
source tree, timeout або non-zero exact command.

## Ізоляція

Кожен command запускається окремо без shell через Docker argv з такими
незмінними обмеженнями:

- bind mount source у `/workspace` тільки `readonly`;
- `--read-only` для root filesystem;
- `--network=none`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`;
- non-root `65534:65534`;
- isolated `/tmp` як `tmpfs` з `noexec,nosuid`;
- exact `memory`, `cpus`, `pids` і command timeout;
- `PYTHONDONTWRITEBYTECODE=1`.

Перед запуском і після нього SHA-256 tree identity source root перевіряється
повторно. Link/reparse/special entries у mounted tree, зміна image/tool identity
або source tree зупиняють маршрут fail-closed. Результат за замовчуванням
друкується в stdout; `--output` дозволено лише поза mounted source root, тобто
host-local.

## Використання

Побудувати план без запуску контейнера:

```powershell
py -3.14 tools/promin_linux_model.py plan C:\path\to\clean-source
```

Запустити найменший безпечний proof (`["python", "--version"]`) лише за
умови, що image `python:3.14-slim` уже локально присутній:

```powershell
py -3.14 tools/promin_linux_model.py run C:\path\to\clean-source `
  --output C:\host-local\linux-model-result.json
```

Для реального command set потрібен попередньо підготовлений локальний image та
кожен argv задається як JSON-масив, без shell interpolation:

```powershell
py -3.14 tools/promin_linux_model.py run C:\path\to\clean-source `
  --image registry.example.invalid/promin-test@sha256:<digest> `
  --command-json '["python","-m","pytest","-q","tests/test_heavy_linux_model.py"]' `
  --timeout-seconds 600 --memory-bytes 1073741824 --cpus-millis 1000 `
  --pids-limit 128 --output C:\host-local\linux-model-result.json
```

Не передавайте working tree з secret-bearing або operational state як source
mount. Для Standard candidate слід створити окремий clean package/staging root.
Цей tool не додає CI lane, manifest або tracked operational evidence.

## Стани результату

| Status | Значення | Credit |
|---|---|---|
| `PASS` | усі exact commands запущено в bound Docker container і вони завершилися з `0`; це лише modeled container proof | none |
| `FAIL` | source/tool/image identity drift або command/timeout failure | none |
| `UNAVAILABLE` | Docker, daemon або local image недоступні до container run | none |

Docker model — додатковий локальний route. Linux-host runtime, deployment,
installability та acceptance потребують окремого evidence на відповідному host.

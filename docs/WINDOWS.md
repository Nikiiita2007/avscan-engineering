# Windows: сборка и запуск

Пошаговая инструкция для Windows 10/11 x64. Коротко то же самое сказано в [README.md](../README.md); подробности и ограничения прототипа в [MANUAL.md](../MANUAL.md).

## 1. Что нужно установить

- Visual Studio 2022 или 2026 с нагрузкой «Разработка классических приложений на C++» (MSVC, Windows SDK, CMake >= 3.24).
- Git.
- vcpkg: `git clone https://github.com/microsoft/vcpkg C:\tools\vcpkg`, затем `C:\tools\vcpkg\bootstrap-vcpkg.bat`.

Повторный `git clone` в `C:\tools\vcpkg` на машине, где vcpkg уже стоит, завершится ошибкой `already exists`. Это нормально: достаточно запустить `bootstrap-vcpkg.bat`.

## 2. Получить код

Новая копия:

```powershell
mkdir C:\dev -Force
cd C:\dev
git clone https://github.com/Nikiiita2007/avscan-engineering
cd C:\dev\avscan-engineering
```

Уже есть копия: обновите её.

```powershell
cd C:\dev\avscan-engineering
git status
git pull origin master
```

Не работайте в `C:\Windows\System32`. Если PowerShell открыт там, команда `git clone` создаст папку в системном каталоге (в 32-разрядном PowerShell — в `SysWOW64`), а `cd` и сборка потом её не найдут.

## 3. Собрать и проверить

```powershell
$env:VCPKG_ROOT = "C:\tools\vcpkg"
cmake --preset windows-vcpkg
cmake --build build/windows --config Release
ctest --test-dir build/windows -C Release --output-on-failure
```

Пресет `windows-vcpkg` собирает x64, подключает vcpkg и включает C API (`AV_CAPI=ON`). Ядро хоста модулей включено по умолчанию (`AV_HOST=ON`).

Ожидаемый результат `ctest`: 5 тестов и «100% tests passed».

| Тест | Что проверяет |
|---|---|
| `core_selftest` | встроенные самотесты ядра |
| `quality` | корпус файлов и карантин |
| `config_events` | разбор конфига монитора и события JSON Lines |
| `capi` | C API (`avscan_capi.dll`) |
| `host` | ядро хоста модулей и проверка манифестов из `modules/` |

Если тестов меньше пяти, вы собираете старую копию репозитория (`git pull`) либо использовали другой пресет. Удалите папку `build\windows` и повторите конфигурацию, если сомневаетесь в кэше.

## 4. Что где лежит

В `build\windows\Release`:

- `avscan.exe` — сканер файлов и каталогов;
- `avmonitor.exe` — монитор каталогов, ETW и служба;
- `avquarantine.exe` — зашифрованное хранилище улик;
- `avgui.exe` — окно ручного скана одного файла;
- `avscan_capi.dll` — C API для других модулей и языков;
- `quality_tests.exe`, `config_events_tests.exe`, `capi_test.exe`, `host_tests.exe` — тесты (запускаются через `ctest`).

База `db\signatures.db` копируется рядом с `avscan.exe`, `avmonitor.exe` и `avgui.exe`. DLL зависимостей (zlib, libarchive и др.) vcpkg обычно кладёт рядом с EXE при сборке. Если вы переносите программы на другую машину, берите всю папку `Release`, а не отдельный EXE.

## 5. Запуск

### Сканер

```powershell
cd C:\dev\avscan-engineering\build\windows\Release
.\avscan.exe --selftest
.\avscan.exe --no-cache -v "C:\Samples\file.exe"
.\avscan.exe --no-cache --json -r "C:\Samples" > report.json
```

Коды выхода: 0 — чисто, 1 — заражён, 2 — подозрительно, 3 — ошибка, 4 — неверные аргументы. Только статус `Skipped` может вернуть 0, поэтому в автоматизации смотрите статусы в JSON, а не один код выхода.

### GUI

```powershell
.\avgui.exe
```

Запускайте из папки, где есть `db\signatures.db`. Окно проверяет один выбранный файл, управления монитором и карантином в нём нет.

### Монитор

Файл конфигурации (формат и ключи в [CONFIG.md](CONFIG.md)):

```powershell
.\avmonitor.exe --config C:\AVScan\avmonitor.conf
```

Или аргументы:

```powershell
.\avmonitor.exe --watch "D:\Incoming" --exclude "D:\Incoming\Trusted" --quarantine "D:\Evidence" --threads 4
.\avmonitor.exe --watch "D:\Incoming" --events jsonl
```

`--events jsonl` печатает по одному JSON-объекту на строку: удобно для других модулей. Аргументы обрабатываются слева направо, поэтому всё после `--config` переопределяет значения из файла. Не сохраняйте журнал в наблюдаемом каталоге без `--exclude`, иначе монитор будет реагировать на собственные записи.

`--etw`, `--block-exec`, `--auto-quarantine` и установка службы требуют повышенного терминала. Эти режимы не прошли полной приёмки на Windows: сначала проверьте их на тестовой папке (MANUAL.md, раздел 10).

### Карантин

```powershell
.\avquarantine.exe store "D:\Evidence" "D:\Samples\suspect.bin"
.\avquarantine.exe list "D:\Evidence"
.\avquarantine.exe restore "D:\Evidence" <ID> "D:\Out\restored.bin"
```

Режим `store` шифрует образец, а ключ привязан к учётной записи и машине (DPAPI): восстановить запись можно только там, где она создана.

### C API и хост модулей

C API описан в [CAPI.md](CAPI.md). Ядро хоста модулей отдельного исполняемого файла не имеет: его проверяет `host_tests.exe` (или `ctest -R host`). Манифесты планируемых модулей лежат в `modules\`.

## 6. Если что-то не работает

| Симптом | Причина и решение |
|---|---|
| `destination path ... already exists` при `git clone` | папка уже есть; перейдите в неё и выполните `git pull origin master` |
| `cmake` не находит `CMakePresets.json` | вы не в папке репозитория; проверьте `pwd` |
| `ctest` показывает меньше 5 тестов | устаревший клон или другой пресет; `git pull`, затем заново сконфигурируйте |
| ошибка `VCPKG_ROOT` или toolchain | задайте `$env:VCPKG_ROOT = "C:\tools\vcpkg"` в том же окне, где запускаете `cmake` |
| `cl.exe` не найден | откройте Developer PowerShell (x64) или установите нагрузку C++ в Visual Studio |
| антивирус удаляет файлы корпуса | не отключайте защиту; тест EICAR собирает строку в памяти, поэтому корпус в репозитории не содержит её в открытом виде |
| сообщение `CMAKE_TOOLCHAIN_FILE not used` | безвредное предупреждение: vcpkg уже подключён через пресет |
| EXE не запускается: нет DLL | запускайте из папки `build\windows\Release` или скопируйте её целиком |
| ETW не стартует | нужен повышенный терминал; без него монитор каталогов продолжает работать |

## 7. Что не проверено

Сборка и `ctest` проверены на Windows 11 с MSVC. Монитор в реальной работе, ETW, служба, GUI и карантин с DPAPI проходят автоматические проверки в CI, но полную ручную приёмку по списку из MANUAL.md (раздел 10) ещё не прошли. Не используйте проект как единственную защиту системы.

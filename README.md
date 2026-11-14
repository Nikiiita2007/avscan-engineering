# AVScan Engineering

Учебный антивирусный сканер на C++20: ядро (SHA-256, Aho-Corasick, разбор PE, архивы), монитор Windows (IOCP, ETW), карантин, минимальный GUI, C API и заготовка хоста модулей.
Это прототип, а не готовая защита: база сигнатур демонстрационная, подробности и ограничения в [MANUAL.md](MANUAL.md). Пошаговая инструкция для Windows: [docs/WINDOWS.md](docs/WINDOWS.md).

## Что в репозитории

| Часть | Где | Статус |
|---|---|---|
| Ядро сканирования | `libs/core` | собирается и тестируется в CI |
| Монитор (каталоги, ETW, служба) | `libs/monitor`, `avmonitor.exe` | CI проверяет сборку и smoke-тест; полная приёмка на Windows не проведена |
| Карантин (зашифрованные улики) | `libs/quarantine`, `avquarantine.exe` | собирается и тестируется |
| GUI (ручной скан одного файла) | `libs/gui`, `avgui.exe` | собирается; ручная проверка не проведена |
| C API | `libs/capi`, `avscan_capi.dll`, [docs/CAPI.md](docs/CAPI.md) | собирается и тестируется |
| Конфиг монитора и события JSON Lines | [docs/CONFIG.md](docs/CONFIG.md) | собирается и тестируется |
| Ядро хоста модулей (JSON, манифесты, протокол, жизненный цикл) | `libs/host`, `modules/` | только библиотека и тесты |

Хост модулей пока не приложение: нет транспорта на именованных каналах, запуска процессов и окна настройки. Три манифеста в `modules/` (`antivirus`, `vuln_parser`, `net_analyzer`) описывают планируемые модули, их исполняемых файлов ещё нет.

## Сборка на Windows

Проверено: MSVC, Visual Studio 2026 / 2022. Нужны Visual Studio с нагрузкой «Разработка классических приложений на C++» (MSVC, Windows SDK, CMake), Git и [vcpkg](https://github.com/microsoft/vcpkg).

```powershell
git clone https://github.com/microsoft/vcpkg C:\tools\vcpkg
C:\tools\vcpkg\bootstrap-vcpkg.bat

mkdir C:\dev -Force
cd C:\dev
git clone https://github.com/Nikiiita2007/avscan-engineering
cd C:\dev\avscan-engineering
$env:VCPKG_ROOT = "C:\tools\vcpkg"
cmake --preset windows-vcpkg
cmake --build build/windows --config Release
ctest --test-dir build/windows -C Release --output-on-failure
```

Клонируйте в обычную папку (например, `C:\dev`), а не в `C:\Windows\System32`. Запускайте в Developer PowerShell (x64) или в обычном PowerShell, где доступны `cmake` и `cl`.

Если репозиторий уже склонирован, обновите его перед сборкой: `git pull origin master`. Иначе вы соберёте старый код.

Первая сборка собирает зависимости vcpkg (zlib, libarchive, tl-expected). Версии закреплены через `builtin-baseline` в `vcpkg.json`; при обновлении baseline пересоберите и проверьте тесты.

### Что должно получиться

В `build\windows\Release`: `avscan.exe`, `avmonitor.exe`, `avquarantine.exe`, `avgui.exe`, `avscan_capi.dll`, `capi_test.exe`, `quality_tests.exe`, `config_events_tests.exe`, `host_tests.exe`. База `db\signatures.db` копируется рядом с `avscan`, `avmonitor` и `avgui`.

`ctest` должен показать 5 тестов и «100% tests passed»: `core_selftest`, `quality`, `config_events`, `capi`, `host`. Если тестов меньше, вы собираете устаревшую копию репозитория или пресет без `AV_CAPI`.

## Запуск

```powershell
cd C:\dev\avscan-engineering\build\windows\Release
.\avscan.exe --selftest
.\avscan.exe --no-cache -v "C:\Samples\file.exe"
.\avscan.exe --no-cache --json -r "C:\Samples" > report.json
.\avgui.exe
```

Монитор можно запускать из командной строки или с файлом конфигурации:

```powershell
.\avmonitor.exe --config C:\AVScan\avmonitor.conf
.\avmonitor.exe --watch "D:\Incoming" --events jsonl
```

Формат конфига и событий: [docs/CONFIG.md](docs/CONFIG.md). ETW, `--block-exec` и `--install-service` требуют повышенных прав. Монитор и службу без необходимости не запускайте: Windows-ветки не проходили полной приёмки (MANUAL.md, раздел 10).

## Хост модулей

Код хоста лежит в `libs/host` (только заголовки), проверяется тестом `host_tests`. Что умеет ядро: строгий разбор JSON, кадры сообщений (4 байта длины и JSON, до 1 МиБ), проверка `module.json`, поиск модулей в каталоге, рукопожатие `hello`/`start`/`stop`/`ping`, шина событий с правом публикации только в собственном пространстве имён модуля.

Отключить можно опцией `-DAV_HOST=OFF`.

## Тесты и антивирус системы

Тестовая строка EICAR больше не хранится в репозитории: тест собирает её в памяти (в том числе ZIP), поэтому антивирус Windows не удаляет файлы корпуса и тесты не зависят от его настроек. Скрипт `scripts/make_corpus.py` создаёт остальные файлы корпуса.

## CI

- Linux: сборка, ASan/UBSan, libFuzzer.
- Windows (MinGW + Wine): кросс-сборка и smoke-тесты, MSI.
- Windows (MSVC + vcpkg): нативная сборка и тесты, кэш бинарных пакетов vcpkg.
- Релиз (по тегу `v*`): архивы MSVC и MinGW, MSI, `SHA256SUMS.txt`.

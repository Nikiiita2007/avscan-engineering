# AVScan Engineering

Учебный антивирусный сканер на C++20: ядро (SHA-256, Aho-Corasick, разбор PE, архивы), монитор Windows (IOCP, ETW), карантин, минимальный GUI.
Это прототип, а не готовая защита: база сигнатур демонстрационная, подробности и ограничения в [MANUAL.md](MANUAL.md).

## Сборка на Windows (проверено: MSVC, Visual Studio 2026 / 2022)

Нужны: Visual Studio с нагрузкой «Разработка классических приложений на C++» (MSVC, Windows SDK, CMake), Git и [vcpkg](https://github.com/microsoft/vcpkg).

```powershell
git clone https://github.com/microsoft/vcpkg C:\tools\vcpkg
C:\tools\vcpkg\bootstrap-vcpkg.bat

git clone https://github.com/Nikiiita2007/avscan-engineering
cd avscan-engineering
$env:VCPKG_ROOT = "C:\tools\vcpkg"
cmake --preset windows-vcpkg
cmake --build build/windows --config Release
ctest --test-dir build/windows -C Release --output-on-failure
```

Запускайте в Developer PowerShell (x64). Результат: `build\windows\Release\avscan.exe`, `avmonitor.exe`, `avquarantine.exe`, `avgui.exe`; база `db\signatures.db` копируется рядом.

Первая сборка собирает зависимости vcpkg (zlib, libarchive, tl-expected). Версии закреплены через `builtin-baseline` в `vcpkg.json`; при обновлении baseline пересоберите и проверьте тесты.

## Запуск

```powershell
cd build\windows\Release
.\avscan.exe --selftest
.\avscan.exe --no-cache -v "C:\Samples\file.exe"
.\avgui.exe
```

Монитор и службу (`--install-service`) без необходимости не запускайте: Windows-ветки не проходили полной приёмки (MANUAL.md, раздел 10).

## Тесты и антивирус системы

Тестовая строка EICAR больше не хранится в репозитории: тест собирает её в памяти (в том числе ZIP), поэтому антивирус Windows не удаляет файлы корпуса и тесты не зависят от его настроек. Скрипт `scripts/make_corpus.py` создаёт остальные файлы корпуса.

## CI

- Linux: сборка, ASan/UBSan, libFuzzer.
- Windows (MinGW + Wine): кросс-сборка и smoke-тесты, MSI.
- Windows (MSVC + vcpkg): нативная сборка и тесты, кэш бинарных пакетов vcpkg.

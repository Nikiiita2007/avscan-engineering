# AVScan Engineering 0.4 — сборка, тестирование и использование

## 1. Что поставляется и что реально проверено

Исходный проект C++20 с отдельными CMake-библиотеками core, monitor, quarantine, gui; приложениями avscan, avmonitor, avquarantine, avgui; базой сигнатур; EICAR и синтетическим тест-набором; целями libFuzzer и настройками clang-tidy, ASan, UBSan.

Архив НЕ содержит готового Windows EXE. Windows-ветки IOCP, ETW и GUI в этой среде не собирались и не запускались. CMake/vcpkg/clang-tidy/libFuzzer также не запускались: инструментов нет. Проверено GCC 15 на Linux: ядро с zlib, 11 старых самотестов, 17 новых проверок, ASan+UBSan и по 10000 мутационных входов PE/архивов. Результаты: docs/TEST_RESULTS.txt. Мутационный smoke-тест не равен coverage-guided libFuzzer и не доказывает отсутствие уязвимостей.

ВНИМАНИЕ: tests/corpus/eicar.com — настоящий 68-байтовый EICAR-тест, а eicar.zip содержит его сжатую копию. Установленный антивирус может заблокировать сам ZIP проекта, распаковку или часть тестов. Не отключайте защиту системы ради сборки; используйте согласованную тестовую среду. EICAR не запускать: сканеру нужен только файл как данные. Это не реальное вредоносное ПО. Если файл удалён защитой, повторный scripts/make_corpus.py тоже может быть заблокирован. Такой тест считается внешне заблокированным, а не успешным.

## 2. Структура

- libs/core: SHA-256, Aho–Corasick, маски/смещения/AND-условия, PE/импорты/энтропия, архивные лимиты, скоринг, отчёты, результат Result<T>, концепты.
- libs/monitor: Windows IOCP/ReadDirectoryChangesW и ETW, RAII UniqueHandle, jthread/stop_token, debounce, стабилизация, очередь и worker-пул.
- libs/quarantine: явное копирование доказательств (sample.bin и source.txt) без удаления исходника.
- libs/gui: минимальное нативное Win32-окно ручного выбора и проверки одного файла, фоновый jthread.
- apps: независимые точки входа четырёх приложений.
- tests: quality.cpp, старые selftest в apps, corpus, мутационный драйвер.
- fuzz: две LLVMFuzzerTestOneInput цели PE и archive.
- scripts: генератор корпуса, Linux offline-сборка, Windows smoke-сценарий.
- .clang-tidy, CMakePresets.json, vcpkg.json: инженерные настройки.

Граф зависимостей: core <- monitor; core <- quarantine; core+monitor <- gui. Приложения линкуются с соответствующими библиотеками. Quarantine не вызывается автоматически из монитора или GUI. GUI не является панелью управления всеми компонентами: он предоставляет только ручной скан.

## 3. Windows: основной путь через CMake и vcpkg

Требуется Visual Studio 2022 с Desktop development with C++, Windows 10/11 SDK, CMake >= 3.24, установленный vcpkg. В Developer PowerShell:

```powershell
$env:VCPKG_ROOT = "C:\tools\vcpkg"
cmake --preset windows-vcpkg
cmake --build build/windows --config Release
ctest --test-dir build/windows -C Release --output-on-failure
```

При наличии manifest mode vcpkg установит tl-expected, zlib, libarchive из vcpkg.json. Реальная библиотека подключается через find_package(tl-expected CONFIG REQUIRED) и target tl::expected. При её отсутствии обычная сборка завершается ошибкой, а не подменяет её молча. В manifest пока не закреплён registry baseline: для строгой воспроизводимости закрепите используемый commit vcpkg в собственном репозитории/CI; этот пакет не заявляет полностью воспроизводимую цепочку зависимостей.

Получатся build/windows/Release/avscan.exe, avmonitor.exe, avquarantine.exe, avgui.exe. Рядом с avscan/avmonitor/avgui копируется db/signatures.db. DLL зависимостей должны быть доступны через deployment vcpkg или PATH.

### Установщик (MSI, WiX v6)

installer/avscan.wxs — WiX v6-авторинг: 4 EXE + db/signatures.db в Program Files\AVScan, установка/остановка/удаление службы AVScanMonitor (ServiceInstall/ServiceControl), MajorUpgrade по UpgradeCode. Сборка только на Windows (WiX зависит от Windows API; на Linux `wix build` падает с WIX0389 на Directory/@Name):

```powershell
powershell -ExecutionPolicy Bypass -File installer\build-msi.ps1   # нужен dotnet SDK 8+ и build\win\*.exe
```

CI (.github/workflows/ci.yml) собирает MSI на windows-latest из артефакта кросс-сборки. MSIX не используется: требует подписи сертификатом; для подписи MSI/EXE добавьте signtool в CI. Установка службы через MSI и через `--install-service` эквивалентны (не делайте оба раза).

### CI/CD (GitHub Actions)

Три конвейера + релиз: linux (Release-сборка, ctest, ASan+UBSan, 2x60 c libFuzzer), windows (кросс-сборка MinGW со статическими zlib/libarchive, smoke-тесты под Wine, ZIP-артефакт), msi (WiX на Windows-раннере). Релиз с артефактами создаётся автоматически по тегу v*.

## 4. Linux: сборка и автономная проверка

Основная CMake-сборка с vcpkg (Ninja и CMake установите отдельно):

```bash
export VCPKG_ROOT=/opt/vcpkg
cmake -S . -B build/linux -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
  -DCMAKE_BUILD_TYPE=Debug
cmake --build build/linux
ctest --test-dir build/linux --output-on-failure
```

Если tl-expected и libarchive отсутствуют, есть явный автономный режим:

```bash
cmake --preset offline
cmake --build build/offline
ctest --test-dir build/offline --output-on-failure
```

В AV_OFFLINE=ON используется собственный минимальный Result на std::variant, НЕ настоящий tl::expected. Это только путь проверки без сети. AV_ARCHIVES=OFF отключает распаковку архивов: они не считаются полностью проверенными. На Linux GUI/IOCP/ETW не поддерживаются, соответствующие исполняемые файлы — явные platform stubs.

Без CMake, но с g++ и zlib:

```bash
sh scripts/build-offline.sh
SANITIZE=1 sh scripts/build-offline.sh
```

Этот скрипт собирает/проверяет ядро и карантин с zlib, запускает самотесты и мутационный smoke. Он не собирает Windows-монитор, не использует real tl::expected, libarchive или libFuzzer. Скрипт генерирует EICAR — учитывайте предупреждение выше. Не используйте старую команду src/*.cpp: структура и точки входа изменились.

## 5. Пользовательский запуск

### Ручное сканирование

Из корня проекта или каталога EXE с db:

```powershell
.\avscan.exe --selftest
.\avscan.exe --no-cache -v "C:\Samples\file.exe"
.\avscan.exe --no-cache --json -r "C:\Samples" > report.json
```

-v — подробный текст: какие баллы начислены/не начислены, объяснения. --json — структурированный отчёт. --no-cache нужен для полной актуальной детализации. База демонстрационная, не коммерческая база угроз.

Статусы: Clean — ничего не найдено в выполненных проверках (не гарантия безопасности); Infected — сигнатура/хэш или порог; Suspicious — эвристический порог; Error — ошибка; Skipped — пропуск/неполная проверка. Коды avscan: 0/1/2/3/4 для чисто/заражён/подозрительно/ошибка/аргументы. Унаследованное поведение: только Skipped может вернуть 0; при автоматизации дополнительно анализируйте статусы JSON, а не только exit code.

Для legacy avscan и avquarantine аргументы Windows поступают через main(char**): не-ASCII командная строка может зависеть от кодовой страницы CRT. Unicode-пути из avmonitor (wmain) и GUI преобразуются в UTF-8 явно. Полная Unicode-нормализация всего старого CLI не заявляется.

### Монитор Windows

```powershell
.\avmonitor.exe --help
.\avmonitor.exe --watch "D:\Incoming" --exclude "D:\Incoming\Trusted" `
  --quarantine "D:\Evidence" --priority "D:\Priority" --threads 4 --etw
```

ETW требует повышенных привилегий. Без --watch используются Downloads текущего пользователя и Temp, они же приоритетные. --db задаёт базу. CLI новой сборки предоставляет --watch, --exclude, --priority, --quarantine, --db, --threads, --etw; не все настройки прошлых прототипов доступны как аргументы. В MonitorOptions заданы debounce 750 мс, stable 1000 мс, maxSize 512 МиБ, queueLimit 50000; для изменения этих четырёх значений отредактируйте monitor.hpp и пересоберите.

Сначала выставляется подписка, затем первичный обход. Буфер 64 КиБ на корень, OVERLAPPED и единый IOCP. При нулевом completion/ошибке уведомлений планируется полный повторный обход. Новый каталог также вызывает обход. Запрос перевыставляется до обработки скопированных событий. Невозможность rearm завершает монитор с ошибкой. Scope-guard отменяет и дренирует pending I/O до освобождения OVERLAPPED-буферов. UniqueHandle освобождает handles.

Очередь объединяет события пути и ждёт стабилизации size+mtime; сравнение повторяется после скана. До 20 повторов для изменяющихся/нечитаемых файлов. Новый скан того же пути не идёт параллельно другому. Приоритет: ETW 3, приоритетные каталоги 2, обычные события 0, обход -1. Нет вытеснения уже запущенной задачи и нет защиты от starvation. У worker собственный Scanner без общего дискового кэша. Длительная пауза записи не доказывает её завершение; TOCTOU и подмены с сохранёнными метаданными остаются.

Системный ETW logger имеет имя AVScan-<PID>, process/image flags, TDH для полей событий, QueryFullProcessImageName для пути процесса; \Device и \SystemRoot пути модулей преобразуются в DOS-пути. Отказ ETW журналируется, каталоговый монитор продолжает работу. Потеря ETW-событий журналируется; текущая сборка НЕ восстанавливает историю краткоживущих процессов и не выполняет снимок всех уже работающих процессов. ETW callback не сканирует файл, а передаёт его очереди. Доступ к защищённым процессам и разрешение некоторых путей могут не удаться.

Ctrl+C запрашивает stop_token. Уже выполняющийся скан может задержать остановку: stop_token не прерывает текущий блокирующий скан или распаковщик. Поддерживается Ctrl+C/Break, не все варианты завершения консоли. Это обнаружение после события, не блокировка исполнения и не minifilter/EDR.

Не сохраняйте журнал в наблюдаемом каталоге без --exclude: возможна самогенерация событий. Вывод монитора — текстовая диагностика и отдельные многострочные JSON-объекты, не единый JSON и не JSONL. Исключения лексические по компонентам пути без учёта регистра; reparse points при обходе пропускаются. Это не защищённая граница против hardlinks, aliases и гонок.

### GUI

```powershell
.\avgui.exe
```

Запускайте из папки, где есть db/signatures.db. Кнопка Choose and scan file открывает выбор, запускает фоновый скан и показывает подробный отчёт. Во время скана кнопка отключена; при закрытии окно ждёт завершения текущего скана. GUI не предоставляет управление ETW/монитором/карантином. Windows-работоспособность интерфейса требует проверки.

### Карантин / evidence store

```powershell
.\avquarantine.exe "D:\Evidence" "D:\Samples\suspect.bin"   # legacy: plaintext evidence copy
.\avquarantine.exe store "D:\Evidence" "D:\Samples\suspect.bin"     # зашифрованная запись
.\avquarantine.exe list "D:\Evidence"
.\avquarantine.exe restore "D:\Evidence" <ID> "D:\Out\restored.bin"
.\avquarantine.exe remove "D:\Evidence" <ID>                # перезапись случайными данными + удаление
```

Legacy-режим только копирует данные (sample.bin + source.txt), исходник не удаляется. Новый режим store шифрует образец AES-256-CBC (CNG); ключ 32 байта генерируется на store и защищается DPAPI (store.key, per-user/machine); на sample.bin.enc накладывается protected DACL с deny-execute ACE для Everyone (allow — владелец/Administrators/SYSTEM), на каталог записи — protected DACL без deny (deny-execute на каталоге блокировал бы traversal). restore расшифровывает запись побайтово (работает только на той же машине/учётке, где создан store — ограничение DPAPI). remove перезаписывает шифротекст случайными байтами и удаляет запись. Это НЕ криптографическая граница против локального админа: владелец/админ может снять DACL и DPAPI-ключ привязан к учётной записи. Защита от подмен symlink/junction и транзакционность не реализованы.

### Монитор: реакция на события (block-exec, автокарантин)

```powershell
.\avmonitor.exe --watch "D:\Incoming" --etw --block-exec --auto-quarantine --quarantine "D:\Evidence"
```

--block-exec: при детекте Infected на ETW-событии запуска процесса монитор завершает этот процесс (OpenProcess+TerminateProcess). Это пост-фактум-терминация сразу после старта, а НЕ предварительная блокировка исполнения: настоящая pre-execution блокировка требует minifilter-драйвера и не реализована. --auto-quarantine: при Infected (любой источник) автоматически создаётся зашифрованная карантинная запись. Исходный файл при этом не удаляется и не блокируется.

### Windows-служба монитора

```powershell
# из повышенного терминала:
.\avmonitor.exe --install-service --watch "D:\Incoming" --etw --block-exec --auto-quarantine
.\avmonitor.exe --service-args "--watch D:\Incoming --etw --block-exec"
.\avmonitor.exe --remove-service
```

--install-service создаёт службу AVScanMonitor (auto start, LocalSystem, binPath=avmonitor.exe --service). Аргументы службы хранятся в HKLM\Software\AVScan\Monitor (REG_SZ "Args"), изменение — через --service-args (или реестр) с последующим перезапуском службы. Лог службы: %ProgramData%\AVScan\monitor.log. Служба устанавливается также MSI-установщиком (ServiceInstall). Без Args служба наблюдает Downloads/Temp текущих профилей. Остановка: SCM STOP (служебный stop_token), уже идущий скан может задержать остановку.

## 6. Современный C++20 и ошибки

std::filesystem — пути и обход; std::span — байтовые блоки; ByteRange/StreamHasher concepts — контракт потокового хэширования (feed используется ядром); jthread/stop_token — worker-пул, обход, ETW consumer, GUI; move-only UniqueHandle — CloseHandle в деструкторе. TRACEHANDLE не HANDLE: освобождается через ControlTrace/CloseTrace внутри Etw, не через UniqueHandle.

makeEngine возвращает Result<unique_ptr<Scanner>>; в обычной сборке Result — alias tl::expected. Ошибки открытия/синтаксиса базы передаются как значения. Старые ScanResult и часть исключений I/O сохранены: весь код НЕ переписан на expected. Scanner запрещает копирование/перемещение, чтобы не было двойного освобождения cache pointer.

Добавлена защита от uint32 переполнения e_lfanew+4 в detectType и безопасное сравнение диапазона при чтении PE. tests/corpus/regression-lfanew.bin проверяет граничный случай.

## 7. ASan и UBSan

Linux с Clang/GCC, dependencies через vcpkg:

```bash
cmake --preset linux-sanitize
cmake --build build/sanitize
ctest --test-dir build/sanitize --output-on-failure
```

Для Windows MSVC: отдельная конфигурация -DAV_ASAN=ON; UBSan MSVC не поддерживается, CMake выдаёт явную ошибку при AV_UBSAN=ON. Для диагностики UBSan используйте Linux GCC/Clang. ASan/UBSan должны присутствовать при компиляции библиотек и линковке executable; настройки CMake это делают. Санитайзеры проверяют только реально пройденные пути, а не всё приложение автоматически.

## 8. clang-tidy

Установите clang-tidy и configure с -DAV_TIDY=ON (отдельный build/tidy). Отсутствие инструмента вызывает ошибку CMake. Конфигурация в .clang-tidy: clang-analyzer, bugprone, performance и часть modernize. WarningsAsErrors не включён: это стартовый профиль аудита, не подтверждение zero-warnings. При Ninja генерируется compile_commands.json. Здесь анализатор не запускался.

## 9. libFuzzer

Для настоящего coverage-guided фаззинга нужен Linux clang++ с compiler-rt/libFuzzer. Отдельная сборка:

```bash
cmake -S . -B build/fuzz -G Ninja -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
  -DAV_FUZZ=ON -DAV_ASAN=ON -DAV_UBSAN=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build/fuzz --target fuzz_pe fuzz_archive
./build/fuzz/fuzz_pe tests/corpus -max_len=65536 -max_total_time=120 -timeout=5 -rss_limit_mb=1024
./build/fuzz/fuzz_archive tests/corpus -max_len=65536 -max_total_time=120 -timeout=5 -rss_limit_mb=1024
```

Используйте КОПИЮ корпуса, если не хотите, чтобы libFuzzer добавлял новые входы в каталог исходников. Перед фаззингом учитывайте EICAR/реакцию установленного антивируса. При желании скопируйте в отдельный корпус только synthetic-pe/regression/ZIP без EICAR.

Отдельная core_fuzz инструментирована fuzzer-no-link; normal executable не линкуется со вторым main. На fuzz executable добавлен fuzzer runtime. Цель PE напрямую вызывает detectType и parsePe; archive вызывает ограниченный сканер памяти (не более 1 МиБ на запись, 2 МиБ суммарно, depth 2, 32 записи). Для 7z/RAR нужен libarchive и соответствующие дополнительные seeds; поставленный corpus ZIP не означает проверенный 7z/RAR. Лимита CPU внутри каждого распаковщика нет — используйте -timeout и внешние ограничения процесса.

В этой среде libFuzzer не запускался. tests/mutation_driver.cpp — детерминированный мутационный smoke без обратной связи по покрытию. Он запускается offline-скриптом; выполнено 10000 входов на каждую цель под ASan+UBSan.

## 10. Приёмка Windows

1. Собрать MSVC x64, запустить ctest (антивирус может заблокировать EICAR).
2. Запустить scripts/windows-smoke.ps1 и команду монитора, которую он напечатает, в другом повышенном терминале.
3. Проверить запись частями, rename, исключённый файл, ETW process-start и image-load.
4. Отдельно нагрузить каталог до реального переполнения: 1000 файлов в smoke НЕ гарантирует потерю уведомлений. Проверить предупреждение/повторный обход.
5. Проверить недоступный каталог, исчезнувший файл, отказ ETW без прав, большой файл, Ctrl+C при скане и отсутствие оставшейся AVScan-<PID> сессии через logman query -ets.
6. Проверить GUI: выбрать файл, получить результат, закрыть во время скана.
7. Проверить evidence copy на чистом тестовом файле, сохранность исходника, исключение store из монитора.

## 11. Известные ограничения и честный статус

Не заявляется production-ready защита. База демонстрационная; ssdeep-подобный hash собственный и не гарантирует совместимость с ssdeep, TLSH отсутствует. Унаследованы ограничения ZIP64/методов сжатия, парсинга PE и неполных отчётов из кэша. Диск/процесс могут измениться между проверками. Криптографическая изоляция карантина и полноценный GUI отсутствуют. Windows/real tl::expected/CMake/vcpkg/clang-tidy/libFuzzer/libarchive в данной среде НЕ проверены. Модульные исходники и инструкции предоставлены; фактическая матрица проверки — docs/TEST_RESULTS.txt.

docs/CORE_LEGACY.md оставлен для описания старой базы и скоринга, но его команды сборки, обещание «все пункты реализованы» и утверждение о гарантированном обнаружении любого изменения файла устарели. При расхождении следуйте этому MANUAL.md.

Документация инструментов: https://clang.llvm.org/docs/AddressSanitizer.html ; https://llvm.org/docs/LibFuzzer.html ; https://vcpkg.io/en/package/tl-expected.html

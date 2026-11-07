AVScan Engineering 0.4 — сборка для Windows x64
================================================================

ЧТО НОВОГО В 0.4
----------------
- Карантин: шифрование AES-256-CBC (CNG), ключ под DPAPI, NTFS deny-execute ACL
  на зашифрованный образец, restore (расшифровка) и remove (перезапись + удаление).
- Монитор: --block-exec (терминация процесса по ETW-детекту), --auto-quarantine
  (автоматическая шифрованная карантинная запись при Infected).
- Служба Windows: avmonitor --install-service/--remove-service/--service-args,
  автозапуск (LocalSystem), лог в %ProgramData%\AVScan\monitor.log.
- MSI-установщик (WiX): installer/ в исходниках, сборка через CI или build-msi.ps1.

ФАЙЛЫ
-----
avscan.exe       — консольный сканер (CLI, JSON-отчёты)
avmonitor.exe    — монитор каталогов + ETW + block-exec + автокарантин + служба
avquarantine.exe — карантин: store/restore/remove/list (см. --help)
avgui.exe        — Win32-GUI ручного скана
db/signatures.db — демонстрационная база (обязательна рядом с EXE)

ЗАПУСК
------
  avscan.exe --selftest
  avscan.exe --no-cache -v "C:\Samples\file.exe"
  avmonitor.exe --watch "D:\Incoming" --etw --block-exec --auto-quarantine --quarantine "D:\Evidence"

  rem карантин:
  avquarantine.exe store "D:\Evidence" "D:\Samples\suspect.bin"   -> печатает ID
  avquarantine.exe list "D:\Evidence"
  avquarantine.exe restore "D:\Evidence" <ID> "D:\Out\file.bin"
  avquarantine.exe remove "D:\Evidence" <ID>

  rem служба (повышенный терминал):
  avmonitor.exe --install-service --watch "D:\Incoming" --etw --block-exec
  sc start AVScanMonitor

ВАЖНО
-----
- База сигнатур демонстрационная; это инженерный прототип, не продукт защиты.
- restore работает только на той же машине/учётке, где создан store (DPAPI).
- --block-exec завершает процесс ПОСЛЕ старта (не pre-execution блокировка;
  настоящая блокировка требует minifilter-драйвера).
- eicar.com в тестах — безопасный стандартный тест-файл, не запускайте его.
- Сборка: MinGW-w64 GCC 13, статические zlib 1.3.1 + libarchive 3.7.7, без внешних DLL.
- Проверено под Wine 10.0: самотесты, quality-тесты, EICAR (файл и внутри ZIP),
  монитор с автокарантином, полный цикл store/list/restore/remove. ETW, служба и
  GUI интерактивно требуют проверки на реальной Windows 10/11.

Исходники и CI: см. репозиторий проекта (GitHub Actions: тесты, санитайзеры,
фаззинг, кросс-сборка, MSI). Полная документация — MANUAL.md в исходниках.

# Архитектура Rust-экосистемы AVScan

## Компоненты
- `avscan-protocol` — кадры (4 байта длины little-endian + JSON, ≤ 1 MiB), конверт `Message`. Зеркалит `libs/host/protocol.hpp`.
- `avscan-manifest` — разбор и строгая валидация `module.json` (зеркалит `libs/host/manifest.hpp`).
- `orchestrator` — supervisor процессов, handshake, шина событий, CLI, HTTP/SSE/WS.
- `vuln-scanner` (id модуля `vuln_parser`), `net-analyzer`, `log-hunter` — отдельные процессы-модули.
- Антивирус остаётся на C++ и запускается оркестратором как обычный модуль.

## Протокол
hello (модуль→хост) → hello_ack → start → started → [ping/pong, event, log] → stop → stopped.
Обмен через stdin/stdout. Неизвестные поля, v != 1, пустой или слишком большой кадр — ошибка, соединение закрывается.

## Конфигурация оркестратора
JSON-файл: пути к бинарникам (`modules[].binary`), каталоги манифестов, порт API, каталог логов. Всё переопределяется через CLI/ENV.

## Отказоустойчивость
Supervisor следит за выходом процесса; при `restart.policy = on_failure` перезапускает с экспоненциальным backoff до `max_restarts`. Логи — `tracing` + JSON.

## Безопасность
Модуль не может публиковать темы вне своего id. API по умолчанию слушает 127.0.0.1. Секреты в репозиторий не попадают; для push используется `gh auth` или `GH_TOKEN`.

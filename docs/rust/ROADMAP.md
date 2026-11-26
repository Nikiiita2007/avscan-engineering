# Roadmap: Rust orchestrator и модули

- [x] Этап 0 — анализ, архитектура, roadmap, PR
- [x] Этап 1 — workspace, protocol, manifest, скелет, CI
- [x] Этап 2 — запуск процессов, handshake, supervisor
- [x] Этап 3 — vuln_scanner (крейт vuln-scanner, манифест rust/modules/vuln_scanner/module.json)
- [ ] Этап 4 — net_analyzer
- [ ] Этап 5 — log_hunter
- [ ] Этап 6 — CLI, HTTP, SSE/WS, пересылка событий модулям, интеграционные тесты
- [ ] Этап 7 — документация, примеры, финальный PR

## Принятые решения
- Порядок байт длины кадра: little-endian (как в libs/host/protocol.hpp).
- Документы Rust-части лежат в docs/rust/.
- Handshake инициирует хост (hello → hello_ack → start → started).
- Модуль `vuln_scanner` — отдельный модуль со своим манифестом в rust/modules/. Черновик `modules/vuln_parser` (разбор URL бюллетеней) не изменяется и остаётся для будущего парсера.

## Заметки
- Cargo.lock пока не закоммичен: после первой зелёной сборки добавить его в репозиторий.
- Rust CI (`rust-ci.yml`) запускается только при изменениях в `rust/**`.
- Транспорт Rust-оркестратора — stdin/stdout; named pipes для C++ антивируса — этап 6/7.
- Оркестратор пока не пересылает события шины модулям: триггер `vuln_scanner.scan` заработает после этапа 6. Сканер можно запускать вручную: `vuln-scanner scan <path>`.
- База уязвимых версий — встроенный снимок, не исчерпывающий; подтверждайте находки по бюллетеням производителей.

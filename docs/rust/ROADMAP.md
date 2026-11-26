# Roadmap: Rust orchestrator и модули

- [x] Этап 0 — анализ, архитектура, roadmap, PR
- [x] Этап 1 — workspace, protocol, manifest, скелет, CI
- [x] Этап 2 — запуск процессов, handshake, supervisor
- [x] Этап 3 — vuln_scanner (крейт vuln-scanner, манифест rust/modules/vuln_scanner/module.json)
- [x] Этап 4 — net_analyzer (крейт net-analyzer, существующий манифест modules/net_analyzer/module.json)
- [x] Этап 5 — log_hunter (крейт log-hunter, манифест rust/modules/log_hunter/module.json)
- [ ] Этап 6 — CLI, HTTP, SSE/WS, пересылка событий модулям, интеграционные тесты
- [ ] Этап 7 — документация, примеры, финальный PR

## Принятые решения
- Порядок байт длины кадра: little-endian (как в libs/host/protocol.hpp).
- Документы Rust-части лежат в docs/rust/.
- Handshake инициирует хост (hello → hello_ack → start → started).
- Модуль `vuln_scanner` — отдельный модуль со своим манифестом в rust/modules/. Черновик `modules/vuln_parser` (разбор URL бюллетеней) не изменяется и остаётся для будущего парсера.
- Модуль `net_analyzer` реализует уже существующий черновой манифест без изменений; тест сверяет модуль с реальным файлом манифеста.
- Модуль `log_hunter` — новый модуль со своим манифестом в rust/modules/log_hunter/ (в modules/ манифеста для него не было).

## Заметки
- Cargo.lock пока не закоммичен: после первой зелёной сборки добавить его в репозиторий.
- Rust CI (`rust-ci.yml`) запускается только при изменениях в `rust/**`.
- Транспорт Rust-оркестратора — stdin/stdout; named pipes для C++ антивируса — этап 6/7.
- Оркестратор пока не пересылает события шины модулям: триггер `vuln_scanner.scan` заработает после этапа 6. Сканер можно запускать вручную: `vuln-scanner scan <path>`.
- net_analyzer работает по конфигу (`pcap_paths`, `listen`): манифест подписан только на `host.shutdown`. Живой захват трафика не реализован; вместо него localhost-приём pcap-потока (`tcpdump -U -w - | nc 127.0.0.1 9099`).
- log_hunter читает файлы один раз или в режиме `follow` (опрос раз в 200 мс, переживает ротацию логов).
- Базы уязвимых версий и устаревших образов — встроенные снимки, не исчерпывающие; подтверждайте находки по бюллетеням производителей.
- Код общего runtime модуля (кадры, Out, serve) сейчас дублируется в трёх крейтах; кандидат на вынос в общий крейт на этапе 7.

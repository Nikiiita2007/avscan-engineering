# Roadmap: Rust orchestrator и модули

- [x] Этап 0 — анализ, архитектура, roadmap, PR
- [x] Этап 1 — workspace, protocol, manifest, скелет, CI
- [ ] Этап 2 — запуск процессов, handshake, supervisor
- [ ] Этап 3 — vuln_parser (крейт vuln-scanner)
- [ ] Этап 4 — net_analyzer
- [ ] Этап 5 — log_hunter
- [ ] Этап 6 — CLI, HTTP, SSE/WS, интеграционные тесты
- [ ] Этап 7 — документация, примеры, финальный PR

## Принятые решения
- Порядок байт длины кадра: little-endian (как в libs/host/protocol.hpp).
- Документы Rust-части лежат в docs/rust/.
- Id модуля: vuln_parser (из существующего манифеста).

## Заметки
- Cargo.lock пока не закоммичен: после первой зелёной сборки добавить его в репозиторий.
- Rust CI (`rust-ci.yml`) запускается только при изменениях в `rust/**`.

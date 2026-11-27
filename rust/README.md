# AVScan: Rust-оркестратор и модули

Здесь лежит Rust-часть проекта: оркестратор, который запускает модули как отдельные процессы, и три модуля анализа. C++ код антивируса не затронут; общий протокол описан в `docs/rust/COMMANDS.md`.

## Состав

| Крейт | Роль |
|---|---|
| `avscan-protocol` | кадры и сообщения (4 байта длины little-endian и JSON, до 1 MiB) |
| `avscan-manifest` | разбор и проверка `module.json` |
| `orchestrator` | бинарник `orchestrator`: супервизор модулей, шина событий, HTTP API и CLI-клиент |
| `log-hunter` | модуль `log_hunter`: логи аутентификации, команда `log.hunt` |
| `vuln-scanner` | модуль `vuln_scanner`: секреты, зависимости, Dockerfile, команда `vuln.scan_files` |
| `net-analyzer` | модуль `net_analyzer`: pcap-файлы и поток на loopback, команда `net.analyze` |

Каждый модуль также работает как обычная командная утилита без оркестратора (`log-hunter analyze <файл>`, `vuln-scanner scan <путь>`, `net-analyzer analyze <файл.pcap>`).

## Сборка и проверки

Из каталога `rust` (там же лежит `Cargo.toml` рабочего пространства; в корне репозитория его нет):

```sh
cargo build --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Бинарники получаются в `rust/target/debug`. После изменения зависимостей выполните `cargo update -w` и закоммитьте `Cargo.lock`.

## Быстрый старт

Из корня репозитория (пути в конфиге считаются от текущего каталога):

```sh
cargo build --manifest-path rust/Cargo.toml --workspace
cargo run --manifest-path rust/Cargo.toml -p avscan-orchestrator -- --config rust/examples/orchestrator.json validate
AVSCAN_TOKEN=0123456789abcdef-change-me cargo run --manifest-path rust/Cargo.toml -p avscan-orchestrator -- --config rust/examples/orchestrator.json serve
```

В другом терминале (тот же токен в `AVSCAN_TOKEN`):

```sh
cargo run --manifest-path rust/Cargo.toml -p avscan-orchestrator -- modules
cargo run --manifest-path rust/Cargo.toml -p avscan-orchestrator -- exec log_hunter log.hunt --args '{"paths":["/var/log/auth.log"]}'
cargo run --manifest-path rust/Cargo.toml -p avscan-orchestrator -- history --limit 20
```

Если бинарник `orchestrator` уже собран, вместо `cargo run ... --` можно вызывать `rust/target/debug/orchestrator` напрямую. Клиентские команды (`modules`, `start`, `stop`, `exec`, `publish`, `history`) требуют запущенного `serve`.

## Конфигурация

Пример: `rust/examples/orchestrator.json`. Поля файла `orchestrator.json`:

- `listen`: адрес HTTP API, только loopback; по умолчанию `127.0.0.1:8787`.
- `modules`: список модулей. У каждого `manifest` (путь к `module.json`), `binary` (исполняемый файл), необязательные `enabled`, `args` и `config`.
- `config` модуля: настройки, которые оркестратор передаёт модулю в сообщении `start`. Ключи оттуда заменяют одноимённые ключи `config` из манифеста. Главный случай: `command_roots`, список каталогов, внутри которых модуль читает файлы по командам и событиям.

Без `command_roots` команды `vuln_scanner` и `net_analyzer` отклоняются: у них по умолчанию нет ни одного разрешённого каталога. У `log_hunter` по умолчанию разрешён каталог файлов из `paths`. В примере указаны пути Linux; на Windows замените их на свои каталоги. Если там нет `/var/log/auth.log`, `log_hunter` сообщает об этом событием, но не падает; в примере `paths` пуст.

Манифест `net_analyzer` — черновик в `modules/net_analyzer/module.json`, который требует прав `admin`; оркестратор эти права не проверяет и не выдаёт. Если модуль нужен не всегда, поставьте ему `"enabled": false`.

## HTTP API

Всё на loopback. Подробности, коды ответов и примеры — в `docs/rust/COMMANDS.md`.

| Маршрут | Что делает |
|---|---|
| `GET /health` | жив ли сервер (единственный маршрут без токена) |
| `GET /modules` | состояние модулей, причина сбоя, `capabilities` |
| `POST /modules/{id}/start`, `/stop` | запуск и остановка одного модуля |
| `POST /modules/{id}/command` | команда модулю (имя = capability), ответ приходит после анализа до 30 с |
| `POST /events` | событие от хоста на шину |
| `GET /events` | поток событий (SSE), без повтора пропущенных |
| `GET /events/recent?limit=N` | последние до 500 событий из памяти оркестратора |

## Безопасность

- API слушает только loopback; адрес не можно назначить внешним.
- Без токена (`AVSCAN_TOKEN`, не короче 16 символов) любая локальная программа может управлять модулями. С токеном нужен заголовок `Authorization: Bearer ...` на всех маршрутах, кроме `/health`. Токен передаётся открытым текстом, что допустимо только на loopback; предпочтительнее переменная окружения, а не флаг `--token` (он виден в списке процессов).
- Запросы с чужой веб-страницы отклоняются с кодом 403: заголовок `Host` должен быть loopback-именем, а `Origin`, если он есть, — адресом самого сервера.
- Модули читают файлы по командам и событиям только внутри `command_roots`; пути разрешаются с учётом симлинков.

## Известные ограничения

- Файлы из стартового конфига модуля анализируются до начала обслуживания запросов: большой файл задержит первый ответ на `ping`.
- История событий хранится только в памяти, у событий нет временных меток.
- Живой захват трафика не реализован; `net_analyzer` читает pcap-файлы или поток на loopback.
- Пароли, токены и другие секреты в находках маскируются; встроенная база уязвимых версий неполная, находки нужно подтверждать по бюллетеням производителей.
- Оркестратор не связан с C++ антивирусом: транспорт на именованных каналах Windows не реализован.

## Документы

- `docs/rust/COMMANDS.md`: протокол команд, события, HTTP и CLI.
- `docs/rust/ARCHITECTURE.md`: архитектура.
- `docs/rust/ROADMAP.md` и `docs/rust/STAGE6.md`: план и состояние этапов.
- `docs/rust/STAGE9_UX_UI.md`, `docs/rust/VISUALIZATION.md`, `docs/rust/ui/prototype.html`: дизайн панели управления и прототип (панель не реализована).

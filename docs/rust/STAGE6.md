# Этап 6: CLI и API

Статус: управление модулями, команды, события и защита API готовы (части 6.1-6.9), этап НЕ закрыт: остались пункты из раздела «Осталось до приёмки». Формат команд и событий описан в docs/rust/COMMANDS.md.

## Готово
- CLI clap: --config (AVSCAN_CONFIG), --token (AVSCAN_TOKEN), подкоманды validate и serve --listen (AVSCAN_LISTEN).
- Клиентские подкоманды modules, start, stop и exec: работают с запущенным serve по HTTP (--api, AVSCAN_API, по умолчанию 127.0.0.1:8787), печатают JSON-ответ и возвращают ненулевой код при ответе не 2xx.
- HTTP API (только loopback):
  - GET /health, GET /modules, GET /events (SSE, live-only; lagged сообщает о потерянных событиях).
  - POST /modules/{id}/start, POST /modules/{id}/stop, POST /modules/{id}/command.
  - POST /events: публикация события от хоста (источник host).
- Управление отдельным модулем: у каждого модуля свой сигнал остановки и ограниченная очередь команд (16).
- Протокол: сообщения command и command_result, проверка capability по манифесту, не более 16 ожидающих команд на сессию.
- Доставка событий шины модулям по списку subscribes из манифеста; модуль не получает собственные события.
- Модули log_hunter (log.hunt), vuln_scanner (vuln.scan_files, событие vuln_scanner.scan) и net_analyzer (net.analyze) читают файлы по командам и событиям только внутри command_roots.
- Необязательный Bearer-токен: с токеном все маршруты, кроме GET /health, требуют заголовок Authorization.
- Защита от запросов с веб-страниц: заголовок Host должен быть loopback-именем (защита от DNS rebinding), заголовок Origin, если он есть, должен совпадать с самим сервером; иначе ответ 403. Клиенты без этих заголовков (curl, CLI) не затронуты.
- C++ хост (libs/host): ModuleHost::sendCommand и приём command_result, тесты tests/host_command_test.cpp.
- Интеграционный тест настоящего бинарника: crates/log-hunter/tests/orchestrator_e2e.rs (handshake, команда, событие на шине, отказ вне command_roots, остановка).
- JSON-логи направлены в stderr. Файловый log_dir не реализован.

## Запуск из корня репозитория
```sh
cargo run --manifest-path rust/Cargo.toml -p avscan-orchestrator -- --config orchestrator.json validate
AVSCAN_TOKEN=0123456789abcdef-change-me cargo run --manifest-path rust/Cargo.toml -p avscan-orchestrator -- --config orchestrator.json serve --listen 127.0.0.1:8787
curl -H "Authorization: Bearer $AVSCAN_TOKEN" http://127.0.0.1:8787/modules
curl -N -H "Authorization: Bearer $AVSCAN_TOKEN" http://127.0.0.1:8787/events
```

Минимальный orchestrator.json: {"listen":"127.0.0.1:8787","modules":[]}.
Пути манифестов и бинарников разрешаются относительно текущей директории.
CLI изменён: старый позиционный путь заменён флагом --config и подкомандой.

## Осталось до приёмки этапа 6
- Обновление rust/Cargo.lock: файл в репозитории устарел (в CI добавляются axum, clap, tower и другие зависимости). Нужно выполнить cargo update -w или cargo check локально и закоммитить результат.
- Модули анализируют файлы в потоке протокола: большой файл задерживает ответы на ping. Нужен отдельный рабочий поток или ограничение размера.
- Тайм-ауты записи, прерываемый handshake и тесты завершения под нагрузкой.
- Интеграционные тесты с настоящим бинарником есть только для log_hunter; для vuln_scanner и net_analyzer есть тесты на уровне протокола.
- CLI-подкоманда для POST /events (пока только curl).
- Согласование транспорта существующего C++ антивируса с его реальной точкой входа.
- Список типов сообщений в комментарии libs/host/protocol.hpp не упоминает command и command_result.
- Зелёные fmt, clippy, test, build и cargo check после последнего коммита.

SSE удовлетворяет требованию SSE или WebSocket; WebSocket не обязателен.
Этап 8 запланирован отдельно: альтернативный C++20 HTTP-сервер по учебному PDF. Дизайн панели управления (этап 9) описан в docs/rust/STAGE9_UX_UI.md.

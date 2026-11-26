# Этап 6: CLI и API

Статус: ЗАКРЫТ для Rust-части (части 6.1-6.15). Пункты, которые не вошли, перечислены в разделе «Перенесено на этап 7» и не скрыты. Формат команд и событий описан в docs/rust/COMMANDS.md.

## Готово
- CLI clap: --config (AVSCAN_CONFIG), --token (AVSCAN_TOKEN), подкоманды validate и serve --listen (AVSCAN_LISTEN).
- Клиентские подкоманды modules, start, stop, exec, publish и history: работают с запущенным serve по HTTP (--api, AVSCAN_API, по умолчанию 127.0.0.1:8787), печатают JSON-ответ и возвращают ненулевой код при ответе не 2xx.
- HTTP API (только loopback):
  - GET /health, GET /modules (состояние и capabilities), GET /events (SSE, live-only; lagged сообщает о потерянных событиях), GET /events/recent (последние 500 событий шины, самые старые первыми).
  - POST /modules/{id}/start, POST /modules/{id}/stop, POST /modules/{id}/command.
  - POST /events: публикация события от хоста (источник host).
- Управление отдельным модулем: у каждого модуля свой сигнал остановки и ограниченная очередь команд (16).
- Протокол: сообщения command и command_result, проверка capability по манифесту, не более 16 ожидающих команд на сессию.
- Доставка событий шины модулям по списку subscribes из манифеста; модуль не получает собственные события.
- Модули log_hunter (log.hunt), vuln_scanner (vuln.scan_files, событие vuln_scanner.scan) и net_analyzer (net.analyze) читают файлы по командам и событиям только внутри command_roots.
- Все три модуля выполняют анализ по команде или событию в рабочих потоках (до 4 одновременно): ping отвечается во время анализа, stop ждёт завершения идущих анализов.
- Устойчивость соединения: запись кадра ограничена тайм-аутом (5 с по умолчанию), по истечении сессия завершается ошибкой вместо зависания супервизора; запрос остановки прерывает handshake, который ещё ждёт модуль.
- Необязательный Bearer-токен: с токеном все маршруты, кроме GET /health, требуют заголовок Authorization.
- Защита от запросов с веб-страниц: заголовок Host должен быть loopback-именем (защита от DNS rebinding), заголовок Origin, если он есть, должен совпадать с самим сервером; иначе ответ 403. Клиенты без этих заголовков (curl, CLI) не затронуты.
- C++ хост (libs/host): ModuleHost::sendCommand и приём command_result, тесты tests/host_command_test.cpp; комментарий в libs/host/protocol.hpp перечисляет command и command_result.
- Интеграционные тесты с настоящими бинарниками для всех трёх модулей (crates/log-hunter, crates/vuln-scanner и crates/net-analyzer, файл tests/orchestrator_e2e.rs): handshake, команда, событие на шине, отказ вне command_roots, остановка. Для log_hunter есть нагрузочный тест: пачка из 40 команд, лишние отклоняются, принятые получают ответ, модуль продолжает работать. Для vuln_scanner проверено и событие от хоста.
- rust/Cargo.lock закоммичен; после изменения зависимостей выполняйте cargo update -w в каталоге rust и коммитьте результат.
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

## Перенесено на этап 7
- Транспорт существующего C++ антивируса: Transport на именованных каналах Windows и согласование с его реальной точкой входа. В репозитории реализации нет, а проверить её можно только на Windows.
- Комментарий со списком типов сообщений в rust/crates/avscan-protocol/src/lib.rs не упоминает command и command_result (комментарий, на поведение не влияет).
- Файлы из стартового конфига всех трёх модулей анализируются до начала обслуживания запросов, поэтому большой файл задерживает первый ответ на ping.
- Нагрузочные тесты есть только для log_hunter; для остальных модулей и для разрыва соединения на середине записи их стоит добавить.
- Общий код runtime модуля (кадры, вывод, serve, проверка путей, рабочие потоки) дублируется в трёх крейтах.

SSE удовлетворяет требованию SSE или WebSocket; WebSocket не обязателен.
Этап 8 запланирован отдельно: альтернативный C++20 HTTP-сервер по учебному PDF. Дизайн панели управления (этап 9) описан в docs/rust/STAGE9_UX_UI.md.

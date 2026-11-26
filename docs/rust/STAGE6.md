# Этап 6: CLI и API

Статус: часть 6.1, НЕ завершён. C++ код не изменяется.

## Реализуется в 6.1
- CLI clap: --config (AVSCAN_CONFIG), validate, serve --listen (AVSCAN_LISTEN).
- GET /health: состояние HTTP-сервера (не гарантия здоровья модулей).
- GET /modules: состояния supervisor, причина отказа, номер перезапуска.
- GET /events: SSE live-only, module_event; lagged сообщает о потерянных событиях медленного подписчика.
- HTTP слушает только loopback. Авторизации пока нет; локальные процессы могут читать события.
- JSON-логи направлены в stderr. Файловый log_dir пока не реализован.
- Тесты CLI и маршрутов через tower::ServiceExt.

## Запуск из корня репозитория
```sh
cargo run --manifest-path rust/Cargo.toml -p avscan-orchestrator -- --config orchestrator.json validate
cargo run --manifest-path rust/Cargo.toml -p avscan-orchestrator -- --config orchestrator.json serve --listen 127.0.0.1:8787
curl http://127.0.0.1:8787/modules
curl -N http://127.0.0.1:8787/events
```

Минимальный orchestrator.json: {"listen":"127.0.0.1:8787","modules":[]}.
Пути манифестов и бинарников пока разрешаются относительно текущей директории.
CLI изменён: старый позиционный путь заменён флагом --config и подкомандой.

## Осталось до приёмки этапа 6
- Команды scan/start/stop через CLI и HTTP.
- Доставка команд и событий подписанным модулям с ограниченными очередями.
- Интеграционные тесты запуска настоящих бинарников и доставки SSE-событий.
- Тайм-ауты записи, прерываемый handshake, тесты завершения под нагрузкой.
- Согласование транспорта существующего C++ антивируса с его реальной точкой входа.
- Обновление Cargo.lock после добавления зависимостей.
- Зелёные fmt, clippy, test, build и cargo check перед закрытием этапа.

SSE удовлетворяет требованию SSE или WebSocket; WebSocket не обязателен.
Этап 8 запланирован отдельно: альтернативный C++20 HTTP-сервер по учебному PDF.

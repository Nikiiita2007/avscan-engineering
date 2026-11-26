# Визуализация работы оркестратора и других приложений

Документ дополняет `docs/rust/STAGE9_UX_UI.md`. Диаграммы описывают реальное поведение кода (HTTP-API, сессии модулей, супервизор), а не желаемое. Интерактивная версия лежит в `docs/rust/ui/prototype.html`: скачайте файл и откройте в браузере, GitHub показывает его только как исходный код. Прототип имитирует данные и никуда не подключается.

## Кто участвует
| Участник | Что делает | Как общается с оркестратором |
|---|---|---|
| Панель в браузере (этап 9, не реализована) | Показывает состояние и находки, запускает проверки | HTTP на 127.0.0.1: GET /modules, SSE /events, POST start, stop, command, events |
| CLI `orchestrator` | modules, start, stop, exec | те же HTTP-запросы |
| curl и скрипты | любые запросы вручную | HTTP, включая POST /events |
| log_hunter, vuln_scanner, net_analyzer | Анализируют файлы, публикуют находки | процесс с протоколом на stdin и stdout: hello, start, command, event, ping, stop |
| C++ ModuleHost (libs/host) | Та же роль хоста для C++ части | sendCommand и приём command_result; HTTP-обвязки нет |
| Шина событий | Рассылает события всем подписчикам | внутри процесса оркестратора |

## Общая схема
```mermaid
flowchart LR
  subgraph clients["Клиенты на этом компьютере"]
    ui["Панель в браузере"]
    cli["CLI: modules, start, stop, exec"]
    curl["curl и скрипты"]
  end
  subgraph orch["Процесс оркестратора"]
    guard["Проверка Host и Origin, затем токен"]
    api["HTTP API 127.0.0.1"]
    sup["Супервизор: свой сигнал остановки и очередь 16 команд на модуль"]
    bus(("Шина событий"))
  end
  subgraph mods["Процессы модулей"]
    lh["log_hunter"]
    vs["vuln_scanner"]
    na["net_analyzer"]
  end
  ui --> guard
  cli --> guard
  curl --> guard
  guard --> api
  api -->|"start, stop, command"| sup
  sup -->|"stdin: hello, start, command, event, ping, stop"| lh
  sup -->|"stdin"| vs
  sup -->|"stdin"| na
  lh -->|"stdout: event, command_result, pong"| bus
  vs --> bus
  na --> bus
  api -->|"POST /events, источник host"| bus
  bus -->|"по списку subscribes"| sup
  bus -->|"SSE module_event"| api
```

## Команда модулю
Сценарий: пользователь запускает проверку лога.
```mermaid
sequenceDiagram
  autonumber
  participant C as Клиент
  participant A as HTTP API
  participant S as Сессия модуля
  participant M as log_hunter
  participant B as Шина событий
  C->>A: POST /modules/log_hunter/command, name log.hunt, args paths
  A->>A: Host, Origin, токен, очередь не полна
  A->>S: команда в очереди
  S->>S: name есть среди capabilities манифеста?
  S->>M: command, id cmd-1
  M->>M: пути внутри command_roots?
  M->>B: event log_hunter.ioc, log_hunter.log
  B-->>C: SSE module_event
  M->>S: command_result, ok true
  S->>A: результат
  A-->>C: 200 ok true
```
Если что-то из проверок не прошло, ответ приходит раньше: 403 (Host или Origin), 401 (токен), 404 (нет модуля), 409 (не запущен), 429 (очередь полна). Отказ модуля приходит как `ok: false` с текстом `error`. Если модуль не ответил за 30 секунд, клиент получает 504, а работа модуля при этом может продолжаться. Если модуль завершился, не ответив, клиент получает 502.

## Событие от хоста
Сценарий: клиент публикует `vuln_scanner.scan`.
```mermaid
sequenceDiagram
  autonumber
  participant C as Клиент
  participant A as HTTP API
  participant B as Шина событий
  participant S as Сессия vuln_scanner
  participant M as vuln_scanner
  C->>A: POST /events, topic vuln_scanner.scan, data paths
  A->>B: событие, источник host
  A-->>C: 202, receivers
  B->>S: событие
  S->>S: тема есть в subscribes? источник не сам модуль?
  S->>M: event, topic, data, source
  M->>M: пути внутри command_roots?
  alt пути разрешены
    M->>B: event vuln_scanner.report
    B-->>C: SSE module_event
  else путь вне command_roots
    M->>S: log, scan request refused
  end
```
Ответ 202 не означает, что модуль получил событие: `receivers` считает всех получателей шины, в том числе SSE-клиентов.

## Жизненный цикл модуля
```mermaid
stateDiagram-v2
  [*] --> Starting
  Starting --> Running: hello, hello_ack, start, started
  Starting --> Failed: не запустился, перезапуск запрещён или исчерпан
  Running --> Stopped: stop, ответ stopped
  Running --> Restarting: сбой, политика on_failure, попытки остались
  Running --> Failed: сбой, перезапуск запрещён или исчерпан
  Restarting --> Starting: пауза 0.5 с умноженная на 2 в степени n, не больше 30 с
  Failed --> Starting: POST start
  Stopped --> Starting: POST start
```
Политика и число попыток берутся из манифеста: у `log_hunter` и `vuln_scanner` это `on_failure` с двумя попытками, у `net_analyzer` перезапуск не разрешён.

## Что видит пользователь
| Событие внутри | Как показано в панели |
|---|---|
| Состояние модуля изменилось | Строка таблицы: значок, слово и цвет; причина сбоя под строкой |
| Модуль упал и перезапускается | Состояние «Перезапуск (попытка N)», узел на схеме мигает |
| Пришло событие находки | Строка в ленте, отсортированной по важности, затем по времени; сообщение в зоне `role=status` |
| Критическая находка или потеря связи | Сообщение в зоне `role=alert` |
| Любое сообщение между участниками | Строка в журнале и движущийся значок на схеме: круг (HTTP, SSE), квадрат (событие), ромб (команда и результат) |
| События пропущены (`lagged`) | Метка «пропущено N событий» в ленте |

## Что показывает прототип
- Сценарии: проверка модуля, имитация сбоя, остановка, запуск, событие от хоста (с отказом по пути вне `command_roots`).
- Схема повторяет реальные пути сообщений. Для пользователей, отключивших анимацию в системе (`prefers-reduced-motion`), движение заменено подсветкой.
- Всё то же самое дублируется в таблице журнала, поэтому схема не единственный источник информации.
- Данные демонстрационные: имена правил и описания находок взяты из тестов модулей, но сами находки выдуманы.

## Ограничения
- Прототип не проверялся в разных браузерах и со скринридерами; это нужно сделать до реализации.
- Реальный поток SSE нужно читать через `fetch`, потому что встроенный `EventSource` не отправляет заголовок `Authorization`; подробности в `STAGE9_UX_UI.md`.
- Для `net_analyzer` и C++ антивируса на схеме показаны только те связи, которые реализованы в коде.

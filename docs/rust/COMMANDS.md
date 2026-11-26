# Protocol: command and command_result

Status: stage 6.2 (protocol, HTTP), 6.3 (CLI client), 6.4 (path restriction), 6.5 (API token), 6.6 (`vuln_scanner`), 6.7 (`net_analyzer`), 6.8 (C++ host), 6.9 (events to modules), 6.10 (Host and Origin guard), 6.11 (capabilities in `GET /modules`), 6.12 (event history, CLI `publish` and `history`) and 6.13 (worker threads in `log_hunter` and `net_analyzer`). Both the Rust orchestrator and the C++ `ModuleHost` can send `command` and receive `command_result`.

## command (host to module)
- `type`: `command`, `id`: request id (`cmd-N`, at most 64 chars), `module`: module id.
- `payload.name`: command name. It must equal a capability declared in the module manifest, otherwise the host rejects it without contacting the module.
- `payload.args`: JSON object with command arguments (may be empty).

## command_result (module to host)
- `type`: `command_result`, `id`: the request id, `module`: module id.
- `payload.ok`: boolean. `payload.error`: optional string.
- A `command_result` with an unknown id is a protocol violation and fails the session.
- Progress and findings are published as normal `event` messages on topics the module declares, so they reach SSE.
- A module may answer later than it receives the next message: `log_hunter` and `net_analyzer` answer a valid command from a worker thread when the analysis is done, and keep answering `ping` meanwhile. The answers of different commands can arrive in any order; the `id` pairs each one with its request.

## Limits
- At most 16 commands wait for a result per session; more are rejected.
- At most 16 commands wait in the per-module queue; more give HTTP 429.
- A module may run at most 4 analyses at a time (`log_hunter`, `net_analyzer`); the next command is answered with `ok: false` and "too many analyses are running".
- Pending commands are completed with a failure if the session ends (the HTTP requester gets 502).

## Events to modules
- The Rust orchestrator sends a bus event to a module as an `event` message (payload `topic`, `data`, `source`) when the topic matches the manifest `subscribes` list. A module never receives its own events. The session subscribes when it is created, so events published during the handshake are delivered after the start. A module that reads too slowly loses events (logged).
- The host publishes events with `POST /events` (body `{"topic":"...","data":{...}}`, `data` optional and an object). Topics use lowercase letters, digits, `_` and `.` (at most 64 chars, no empty segments). The answer is 202 with the number of bus receivers (the history recorder is not counted); it does not mean that a module got the event. Events from the host have the source `host`.
- `vuln_scanner` reacts to `vuln_scanner.scan` (data `paths`) like to the command, but only inside `command_roots`; a refused request is reported as a `log` message because an event has no answer.
```sh
orchestrator publish vuln_scanner.scan --data '{"paths":["/srv/project"]}'
curl -X POST http://127.0.0.1:8787/events -H "Authorization: Bearer $AVSCAN_TOKEN" -H 'content-type: application/json' -d '{"topic":"vuln_scanner.scan","data":{"paths":["/srv/project"]}}'
```
- The C++ `ModuleHost` already forwards bus events to subscribed modules; the Rust side now matches it.

## Event history
SSE is live only, so a client that connects later would see nothing. The orchestrator therefore keeps the last 500 bus events (module events and host events) in memory. `GET /events/recent?limit=N` returns up to `N` of them, oldest first (default 100, at most 500; a non-numeric `limit` gives 400). Each item is `{topic, source, data}`; events carry no timestamps, so clients order them by position. The history is lost when the orchestrator restarts, and events that a slow recorder misses because of lag are not recovered.

## C++ host
`ModuleHost::sendCommand(name, args, callback)` in `libs/host/module_host.hpp`:
- The callback runs once with a `CommandOutcome { ok, error }`: the module's `command_result`, or a failure when the command is rejected (module not running, undeclared capability, 16 commands already waiting), the module fails or the host stops. It does not run if the host object is destroyed first, and it must not call back into the host.
- `pump()` and the internal waits process `command_result` messages; one with an unknown id fails the module.
- Tests: `tests/host_command_test.cpp` (CTest name `host_command`).

## HTTP
- `GET /health`: `{"status":"ok"}`; the only route that needs no token.
- `GET /modules`: a list of `{id, state, restart_attempt, error, capabilities}`. `state` is `starting`, `running`, `restarting`, `stopped` or `failed`; `restart_attempt` is set while restarting; `error` is the reason of a failure; `capabilities` are the names from the manifest and are the valid command names.
- `GET /events`: Server-Sent Events, live only. Event `module_event` carries `{topic, source, data}`; event `lagged` carries `{dropped}`; a keep-alive comment arrives every 15 s.
- `GET /events/recent`: the event history described above.
- `POST /modules/{id}/start`: 202; 404 unknown module; 409 already running or still stopping.
- `POST /modules/{id}/stop`: 202, does not wait for exit; 404; 409 not running.
- `POST /modules/{id}/command` with `{"name":"...","args":{}}`: 200 with `{ok,error}` when the module answers; 404; 409; 429; 502 if the module ended; 504 after 30 s.
- `POST /events`: 202; 400 for an invalid topic or non-object data.

## Requests from web pages
Every route refuses requests that a web page could send, with 403, before the token is checked:
- A `Host` header that is not `127.0.0.1`, `localhost` or `[::1]` (with any port) is a DNS rebinding attempt.
- An `Origin` header must be exactly `http://` plus the `Host` value; a different address or port, `https://` and `null` are refused. Browsers send `Origin` on cross-site requests, so a foreign page cannot call the API.
- Clients that send no `Origin`, such as curl and the CLI, are not affected. This does not replace the token: without a token every local program can still control the modules.

## Authentication
- Start the server with a token: `AVSCAN_TOKEN=<at least 16 characters> orchestrator serve` (or `--token`). Every route except `GET /health` then needs `Authorization: Bearer <token>`; otherwise the server answers 401.
- Without a token the API is open to every local process. The server logs whether authentication is on.
- The token is sent in clear text, which is acceptable only because the API binds to loopback. Do not put the token on a command line that other users can read; prefer the environment variable.
- Client commands read the same `AVSCAN_TOKEN` (or `--token`) and send it automatically.
```sh
export AVSCAN_TOKEN=0123456789abcdef-change-me
orchestrator serve --listen 127.0.0.1:8787
curl -H "Authorization: Bearer $AVSCAN_TOKEN" http://127.0.0.1:8787/modules
```

## CLI client
The client commands talk to a running `serve` over loopback (`--api`, env `AVSCAN_API`, default `127.0.0.1:8787`). They print the JSON response and exit with a non-zero code on a non-2xx status.
```sh
orchestrator modules
orchestrator stop log_hunter
orchestrator start log_hunter
orchestrator exec log_hunter log.hunt --args '{"paths":["/var/log/auth.log"]}'
orchestrator exec vuln_scanner vuln.scan_files --args '{"paths":["/srv/project"]}'
orchestrator exec net_analyzer net.analyze --args '{"pcap_paths":["/srv/pcap/capture.pcap"]}'
orchestrator publish host.ping --data '{}'
orchestrator history --limit 20
```

## Modules
| Module | Command | Argument | Result events |
|---|---|---|---|
| `log_hunter` | `log.hunt` | `paths` | `log_hunter.ioc`, `log_hunter.log` |
| `vuln_scanner` | `vuln.scan_files` | `paths` | `vuln_scanner.report` |
| `net_analyzer` | `net.analyze` | `pcap_paths` | `net_analyzer.alert`, `net_analyzer.log` |

- All three read only inside `command_roots` (module config, list of paths). Paths are resolved with symlinks before the check. Without `command_roots`: `log_hunter` uses the directories of its `paths` (default manifest: `/var/log`), `net_analyzer` the directories of its `pcap_paths`, and `vuln_scanner` its `paths`. With the default manifests of `vuln_scanner` and `net_analyzer` nothing is configured, so the command is refused until `command_roots` or the matching paths are set.
- `log_hunter` and `net_analyzer` run a command's analysis on a worker thread, so `ping` is answered while it runs; `stop` waits for the analyses that are still running, and the host kills the module if that takes longer than its stop timeout (5 s by default). `vuln_scanner` still works on the protocol thread, so a large tree delays its `ping` answers.
- The files named in a module's start config are analyzed before the module serves requests, so a large one delays the first `ping` answer in all three modules.
- The `net_analyzer` manifest is still a draft in `modules/net_analyzer/module.json` (needs the `admin` permission); the Rust crate does not modify it.

## Not done yet
- The message type list in the comment of `libs/host/protocol.hpp` and in the protocol specification does not mention `command` and `command_result` yet.
- The C++ host has no HTTP or CLI front end; `sendCommand` is a library call only.
- The API does not report each module's `command_roots`; see `docs/rust/STAGE9_UX_UI.md`.
- The three modules have no common finding format; only `rule` and `severity` are confirmed.
- `vuln_scanner` does not use worker threads yet.

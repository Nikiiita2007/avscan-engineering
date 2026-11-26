# Protocol: command and command_result

Status: stage 6.2 (protocol, HTTP), 6.3 (CLI client), 6.4 (path restriction), 6.5 (API token), 6.6 (`vuln_scanner`) and 6.7 (`net_analyzer`). The C++ host does not send or accept these messages yet; mirror them in `libs/host` before relying on them across both hosts.

## command (host to module)
- `type`: `command`, `id`: request id (`cmd-N`, at most 64 chars), `module`: module id.
- `payload.name`: command name. It must equal a capability declared in the module manifest, otherwise the host rejects it without contacting the module.
- `payload.args`: JSON object with command arguments (may be empty).

## command_result (module to host)
- `type`: `command_result`, `id`: the request id, `module`: module id.
- `payload.ok`: boolean. `payload.error`: optional string.
- A `command_result` with an unknown id is a protocol violation and fails the session.
- Progress and findings are published as normal `event` messages on topics the module declares, so they reach SSE.

## Limits
- At most 16 commands wait for a result per session; more are rejected.
- At most 16 commands wait in the per-module queue; more give HTTP 429.
- Pending commands are dropped (the requester gets 502) if the session ends.

## HTTP
- `POST /modules/{id}/start`: 202; 404 unknown module; 409 already running or still stopping.
- `POST /modules/{id}/stop`: 202, does not wait for exit; 404; 409 not running.
- `POST /modules/{id}/command` with `{"name":"...","args":{}}`: 200 with `{ok,error}` when the module answers; 404; 409; 429; 502 if the module ended; 504 after 30 s.

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
```

## Modules
| Module | Command | Argument | Result events |
|---|---|---|---|
| `log_hunter` | `log.hunt` | `paths` | `log_hunter.ioc`, `log_hunter.log` |
| `vuln_scanner` | `vuln.scan_files` | `paths` | `vuln_scanner.report` |
| `net_analyzer` | `net.analyze` | `pcap_paths` | `net_analyzer.alert`, `net_analyzer.log` |

- All three read only inside `command_roots` (module config, list of paths). Paths are resolved with symlinks before the check. Without `command_roots`: `log_hunter` uses the directories of its `paths` (default manifest: `/var/log`), `net_analyzer` the directories of its `pcap_paths`, and `vuln_scanner` its `paths`. With the default manifests of `vuln_scanner` and `net_analyzer` nothing is configured, so the command is refused until `command_roots` or the matching paths are set.
- All three work on the protocol thread, so a large file or tree delays `ping` answers.
- The `net_analyzer` manifest is still a draft in `modules/net_analyzer/module.json` (needs the `admin` permission); the Rust crate does not modify it.

## Not done yet
- Updating `libs/host` (C++) and the message list in the `avscan-protocol` docs.

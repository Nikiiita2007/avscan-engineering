# Protocol: command and command_result

Status: stage 6.2 (protocol, HTTP) and 6.3 (CLI client). The C++ host does not send or accept these messages yet; mirror them in `libs/host` before relying on them across both hosts.

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

## CLI client
The client commands talk to a running `serve` over loopback (`--api`, env `AVSCAN_API`, default `127.0.0.1:8787`). They print the JSON response and exit with a non-zero code on a non-2xx status.
```sh
orchestrator modules
orchestrator stop log_hunter
orchestrator start log_hunter
orchestrator exec log_hunter log.hunt --args '{"paths":["/var/log/auth.log"]}'
```

## Modules
- `log_hunter` answers `log.hunt` (args: `paths`). Files are analyzed on the protocol thread, so a large file delays `ping` answers.
- `net-analyzer` and `vuln-scanner` do not handle `command` yet.
- Security: the API has no authentication and `paths` is not restricted, so any local process can make the module read any file the module can read.

## Not done yet
- Updating `libs/host` (C++) and the message list in the `avscan-protocol` docs.
- `command` support in `net-analyzer` and `vuln-scanner`.
- Path allow-list or authentication for the API.

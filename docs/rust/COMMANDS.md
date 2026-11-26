# Protocol: command and command_result

Status: added in stage 6.2. The C++ host does not send or accept these messages yet; mirror them in `libs/host` before relying on them across both hosts.

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

Example:
```sh
curl -X POST http://127.0.0.1:8787/modules/log_hunter/command -H 'content-type: application/json' -d '{"name":"log.hunt","args":{"path":"/var/log/auth.log"}}'
```

## Not done yet
- CLI subcommands for start/stop/command (HTTP only for now).
- Integration tests with a real module binary.
- Updating `libs/host` (C++) and the message list in `avscan-protocol` docs.

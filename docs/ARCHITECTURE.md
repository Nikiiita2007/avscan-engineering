# Architecture: Rust orchestrator and modules

## Processes

```
 external client --HTTP/SSE--> orchestrator --frames--> antivirus (C++, existing)
                                         |-----------> vuln_scanner (Rust)
                                         |-----------> net_analyzer (Rust)
                                         '-----------> log_hunter (Rust)
```

The orchestrator starts every module as a separate process, performs the handshake, supervises it and restarts it according to the manifest policy.

## Wire protocol (compatible with `libs/host`)

- Frame: 4-byte **little-endian** payload length + UTF-8 JSON, 1..1 MiB.
- Envelope: `v` (must be 1), `type`, optional `id` (<= 64), `module` (<= 64), `payload` (object). Unknown fields are errors.
- Types: `hello`, `hello_ack`, `start`, `started`, `stop`, `stopped`, `ping`, `pong`, `event`, `log`, `error`.
- After the first framing error the connection is dropped.

## Manifest (`module.json`)

Strict validation as in `libs/host/manifest.hpp`: allowed top-level fields are `id`, `name`, `version`, `api_version`, `description`, `entry`, `capabilities`, `permissions`, `events`, `restart`, `config`. A module may publish events only under its own id namespace. Binary paths are overridden in the orchestrator config.

## Crates (`rust/`)

- `avscan-protocol`: framing, envelope, codec (tokio-util), unit tests.
- `avscan-manifest`: manifest parsing and validation.
- `orchestrator`: supervisor, event bus, CLI (clap), HTTP API with SSE, tracing JSON logs.
- `vuln_scanner`, `net_analyzer`, `log_hunter`: independent binaries.

## Cross-cutting decisions

- Tokio everywhere; `thiserror` in libraries, `anyhow` in binaries.
- All ports and paths come from config files or CLI flags.
- Restart: exponential backoff, capped by `restart.max_restarts`; every incident is logged as a structured JSON record.
- Event bus is in-memory (broadcast channel); namespace checks are enforced by the orchestrator.

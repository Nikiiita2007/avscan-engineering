# Modules over named pipes (Windows)

By default the Rust orchestrator is the host of every module: it starts the process and runs the handshake over
the module's stdin and stdout. With **pipes** the C++ host is the host instead. The orchestrator only starts the
module and relays bytes between a named pipe and the module's stdio; the frames of the protocol are not parsed.

```
C++ host (avhost, ModuleHost) <-- named pipe --> orchestrator (relay) <-- stdin/stdout --> module
```

## Orchestrator configuration

List the module as usual under `modules`, and add its id to `pipes` with a pipe name:

```json
{
  "modules": [
    { "manifest": "modules/log_hunter/module.json", "binary": "bin/log-hunter.exe" }
  ],
  "pipes": { "log_hunter": "\\\\.\\pipe\\avscan.log_hunter" }
}
```

The name must look like `\\.\pipe\<name>` (no further separators), and two modules cannot share a pipe.
`pipes` is accepted only on Windows. A pipe for an unknown or disabled module is an error, which
`orchestrator validate` reports.

## What the orchestrator does for such a module

1. Creates the pipe (a single instance, remote clients refused) and starts the module process.
2. Waits for the host to connect, then copies bytes both ways until one side closes.
3. When the host disconnects, the module sees the end of its input. A module that then exits with code 0 stays
   stopped. Any other failure follows the restart policy of its manifest.

The orchestrator does not run the handshake for these modules, so they are **not** listed by `GET /modules`,
they take no HTTP commands and their events do not reach the orchestrator's bus. The host owns the whole life
cycle.

## Trying it with avhost

Start the orchestrator (`orchestrator serve`), then run in another console:

```
avhost --pipe \\.\pipe\avscan.log_hunter --manifest modules\log_hunter\module.json --command <capability> --args "{...}"
```

`avhost` connects (retrying for 10 seconds, because the pipe appears just before the module starts), runs the
handshake, prints the module's events and logs, sends the command, waits for its result and stops the module.
Without `--command` it listens for `--seconds` seconds. Exit code 0 means success, 1 a failed command, 2 bad
arguments, 3 a connection, manifest or handshake error.

In code, use `connectPipeTransport` from `libs/host/pipe_transport.hpp` and pass the result to `ModuleHost`.

## Limits

- A write to the pipe blocks while the module does not read and the buffer is full. `ModuleHost` is
  single-threaded, so a stuck module stalls the host loop.
- After `terminate()` the pipe closes. A module that ends with code 0 is not restarted automatically.
- Anyone who can create the pipe name first can make the orchestrator fail to start the module (the orchestrator
  creates it as the first instance and reports an error), but cannot take over an existing pipe.

# log-hunter

Module `log_hunter` of the AVScan Rust ecosystem. It parses authentication logs
(`/var/log/auth.log`, `/var/log/secure`) and reports indicators of compromise (IOC).
Manifest: `rust/modules/log_hunter/module.json`.

## Recognized log lines

- `sshd`: failed and accepted logins, invalid users.
- `sudo`: repeated authentication failures, users not in sudoers.
- `su`: failed switches.
- `useradd`: new local accounts.

Timestamps in the classic `Nov 26 14:02:11` form and in ISO 8601 form are supported.
Lines without a year are mapped to a fixed reference year, so alert timestamps are only
meaningful relative to each other; the year change between December and January is handled.

## Rules (all thresholds are configurable)

| Rule | Severity | Meaning |
|---|---|---|
| `ssh-bruteforce` | high | many failed logins from one address within a window |
| `ssh-user-enumeration` | medium | many different invalid usernames from one address |
| `ssh-login-after-failures` | critical | successful login from an address that just failed several times |
| `root-password-login` | medium | direct root login with a password |
| `sudo-failures` / `su-failures` | medium | repeated failures for one local user |
| `sudo-not-in-sudoers` | medium | a user without sudo rights tried sudo |
| `account-created` | medium | a new local account was created |
| `ioc-ip` | high | activity from an address or CIDR on the configured list (`bad_ips`) |

Untrusted usernames (invalid users) are masked in alert text when `mask_secrets` is true
(default), because people sometimes type their password as a username.

## Usage

    log-hunter analyze <auth.log>...   print a JSON report, exit code 1 on a high or critical alert
    log-hunter follow <auth.log>       print one JSON alert per line while the file grows
    log-hunter                         run as an AVScan module (protocol on stdin/stdout)

Module config keys: `paths`, `follow` (poll the files for new lines, survives log rotation),
`mask_secrets`, `rules` (any field of the rules table, unknown keys are rejected).
Alerts are published as events `log_hunter.ioc`, progress as `log_hunter.log`.

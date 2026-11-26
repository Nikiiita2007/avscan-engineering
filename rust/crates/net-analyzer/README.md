# net-analyzer

Passive network analyzer for the AVScan Rust ecosystem. It implements the
existing draft manifest `modules/net_analyzer/module.json` (module id
`net_analyzer`); the manifest is not modified.

## Inputs

- **pcap files**: classic libpcap format (not pcapng), link types Ethernet, raw IP and
  Linux cooked capture. IPv4 and IPv6 with TCP or UDP.
- **localhost stream**: a TCP listener on a loopback address that accepts a pcap
  stream, for example `tcpdump -U -w - | nc 127.0.0.1 9099`. Non-loopback
  addresses are refused. Live capture itself is not done by this module.

## Rules (all thresholds are configurable)

| Rule | Severity | Meaning |
|---|---|---|
| `suspicious-port` | medium | new TCP connection or UDP datagram to a port from a configurable list |
| `port-scan` | high | one host probes many distinct TCP ports of another host within a window |
| `dns-long-name` | medium | very long DNS name or label (tunneling) |
| `dns-high-entropy` | medium | random-looking DNS label (DGA or tunneling) |
| `dns-suspicious-tld` | low | DNS name under a configured suspicious TLD |
| `dns-query-burst` | medium | many DNS queries from one host within a window |
| `dns-nxdomain-burst` | high | many NXDOMAIN answers to one host within a window |

DNS names in alerts are masked when `mask_secrets` is true (default): long first
labels keep only four characters.

## Usage

    net-analyzer analyze <file.pcap>...   print a JSON report, exit code 1 on a high alert
    net-analyzer listen 127.0.0.1:9099    print one JSON alert per line
    net-analyzer                          run as an AVScan module (protocol on stdin/stdout)

Module config keys: `mode` (only `passive`), `mask_secrets`, `pcap_paths`, `listen`,
`rules` (any field of the rules table, unknown keys are rejected).
Alerts are published as events `net_analyzer.alert`, progress as `net_analyzer.log`.

The current manifest subscribes only to `host.shutdown`, so analysis is driven by the
config (`pcap_paths`, `listen`). To trigger analysis by an event later, the manifest
would need an additional subscription.

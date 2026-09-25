# NetScanner

![Version](https://img.shields.io/badge/Version-v1.2.2-red)
![Language](https://img.shields.io/badge/Language-0.16.0-orange?logo=zig&logoSize=auto)
![OS](https://img.shields.io/badge/OS-Linux%2C%20MacOS%2C%20Windows-blue)
![License](https://img.shields.io/badge/License-GNU%20GPL--3.0-green)

Command line tool written in Zig for scanning and analyzing local
networks. The root [README](../README.md) is the short version, this
file is the full guide.

## Table of Contents

1. [Usage](#usage)
2. [Installation](#installation)
3. [Build](#build)
4. [Testing](#testing)
5. [Release builds](#release-builds)
6. [Linux test lab](#linux-test-lab)
7. [Branches](#branches)
8. [License](#license)

## Usage

```sh
ns -s <subnet> [options]                   # Find live hosts (example: 192.168.0.0/24)
ns -p <ip> <port-range> [--timeout <ms>]   # Scan one host for open ports (example: 192.168.1.1 1-1024)
ns -s|-p ... --json                        # Machine-readable output, one JSON object per line
ns --help                                 # Display help message
ns --version                              # Display version
```

### Discovery options (`ns -s`)

- `ns -s <subnet>`: Fast TCP plus ARP discovery (default).
- `--resolve`: Automatically resolves both hostnames (mDNS port 5353 + NetBIOS port 137 + Reverse DNS PTR) and hardware manufacturers (MAC extraction + OUI database lookup).
- `--hostname`: Resolves hostnames only (mDNS, NetBIOS, Reverse DNS).
- `--vendor`: Resolves MAC addresses and hardware manufacturers only.
- `--oui-file <path>`: Load an external Wireshark `manuf` or IEEE OUI database file.
- `--ping`: Uses ICMP ping sweep instead of TCP plus ARP.

When `--resolve`, `--hostname`, or `--vendor` is passed, results are formatted into an aligned table:

```text
IP               HOSTNAME                  MAC                MANUFACTURER
192.168.1.1      gateway                   00:50:56:a1:b2:c3  VMware, Inc.
192.168.1.10     nas-storage               00:11:32:11:22:33  Synology Incorporated
192.168.1.25     raspberrypi               2c:cf:67:aa:bb:cc  Raspberry Pi (Trading) Ltd
192.168.1.42     workstation               70:85:c2:44:55:66  ASRock Incorporation
192.168.1.105    smart-light               ec:b5:fa:01:02:03  Philips Lighting BV
192.168.1.140    game-console              fc:ca:40:77:88:99  Sony Interactive Entertainment Inc.
8 hosts up (1.8s)
```

When run without resolution flags, `ns -s` outputs the classic compact numerical list followed by the host count and elapsed time.

### Machine-readable output (`--json`)

Add `--json` to `-s` or `-p` for one JSON object per line on stdout
(NDJSON), for scripts and frontends such as NetScannerDesktop. Every
line has a `type`; events stream as they happen, and `summary` is
always last:

```text
{"type":"start","mode":"subnet","cidr":"192.168.1.0/24","first":"192.168.1.0","last":"192.168.1.255"}
{"type":"host","ip":"192.168.1.10","source":"tcp"}
{"type":"host","ip":"192.168.1.25","source":"arp"}
{"type":"host_detail","ip":"192.168.1.10","hostname":"nas-storage","mac":"00:11:32:11:22:33","vendor":"Synology Incorporated"}
{"type":"summary","hosts":2,"elapsed_ms":1843}
```

- `host.source` is `tcp`, `arp` or `ping` (`--ping` scans).
- `host_detail` lines appear only with `--resolve`, `--hostname` or
  `--vendor`, one per host, after the sweep. Only requested fields are
  present; unresolved ones are `null`.
- Port scans stream `{"type":"port","port":80}` and end with
  `{"type":"summary","open_ports":[22,80],"elapsed_ms":512}`.
- Input errors print `{"type":"error","message":"..."}` and exit with
  status 1. Diagnostics (warnings) stay on stderr as plain text.

In both modes, invalid input exits with status 1 and a successful scan
(even one that finds nothing) exits with 0.

## Installation

Requires [Zig](https://ziglang.org/) 0.16.0 or newer (see
`build.zig.zon`) when building from source.

Either download a prebuilt binary from
[GitHub Releases](https://github.com/Criseda/NetScanner/releases)
(v1.0.0 and later), or build from source as described below.

## Build

To build for your platform from source:

```sh
cd /path/to/repo     # Change to the project directory
zig build            # Build the project
./zig-out/bin/ns --help
```

## Testing

```sh
zig build test --summary all
```

CI runs the same two commands on Linux, macOS and Windows (see
`.github/workflows/ci.yml`).

## Release builds

Maintainers build all five release binaries with:

```sh
zig build release -Doptimize=ReleaseFast
```

Binaries land in `zig-out/releases/`, one folder per platform
(`windows`, `macos-x86_64`, `macos-arm64`, `linux-x86_64`,
`linux-arm64`).

Build releases on a Mac. `zig build` ad-hoc codesigns the macOS
binaries, and without that signature macOS 27 hides the ARP table
(no MAC addresses, manufacturers or quiet hosts). Cross-built macOS
binaries are left unsigned.

## Linux test lab

`docker/README.md` describes a virtual LAN for testing on Linux
without owning a Linux box. Windows and macOS cannot be
containerized, so those are tested on real hosts directly.

## Branches

`main` is the only long lived branch. The old `develop` branch was
merged into `main` and deleted.

## License

GNU GPL-3.0, see [LICENSE](../LICENSE).

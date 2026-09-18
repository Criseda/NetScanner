# NetScanner

![Version](https://img.shields.io/badge/Version-v1.2.0-red)
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
192.168.0.1      -                         64:fa:2b:b0:93:f1  Sagemcom Broadband SAS
192.168.0.17     DRAGONAS                  00:11:32:4f:c2:75  Synology Incorporated
192.168.0.30     LAURPI                    2c:cf:67:89:ea:27  Raspberry Pi (Trading) Ltd
192.168.0.39     Laur-PC                   9c:6b:00:42:1d:a6  ASRock Incorporation
192.168.0.153    ecb5fa31ae69              ec:b5:fa:31:ae:69  Philips Lighting BV
192.168.0.167    PS5-8ADCDF                5c:96:66:8a:dc:df  Sony Interactive Entertainment Inc.
8 hosts up (6.6s)
```

When run without resolution flags, `ns -s` outputs the classic compact numerical list followed by the host count and elapsed time.

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

## Linux test lab

`docker/README.md` describes a virtual LAN for testing on Linux
without owning a Linux box. Windows and macOS cannot be
containerized, so those are tested on real hosts directly.

## Branches

`main` is the only long lived branch. The old `develop` branch was
merged into `main` and deleted.

## License

GNU GPL-3.0, see [LICENSE](../LICENSE).

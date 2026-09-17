# NetScanner

![Version](https://img.shields.io/badge/Version-v1.0.0-red)
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
ns -s <subnet> [--ping]    # Find live hosts (example: 192.168.0.1/24)
ns -p <ip> <port-range>    # Scan one host for open ports (example: 192.168.1.1 1-1024)
ns --help                  # Display help message
ns --version               # Display version
```

`ns -s` runs fast TCP plus ARP discovery by default. The TCP sweep
finds hosts with open ports, and the ARP harvest pass catches quiet
hosts that answer ARP but drop TCP. Harvest only candidates are
verified with a targeted probe before being reported, so stale table
entries do not turn into false positives. Pass `--ping` to use one
ICMP ping per host instead.

Results stream as hosts are found, then a sorted recap lists every
host numerically followed by a one line summary such as
`12 hosts up (2.1s)`, so output is easy to scan and diff.

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

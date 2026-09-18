# NetScanner

![Version](https://img.shields.io/badge/Version-v1.1.0-red)
![Language](https://img.shields.io/badge/Language-0.16.0-orange?logo=zig&logoSize=auto)
![OS](https://img.shields.io/badge/OS-Linux%2C%20MacOS%2C%20Windows-blue)
![License](https://img.shields.io/badge/License-GNU%20GPL--3.0-green)

NetScanner finds live hosts on your local network and scans their
ports. It needs no root privileges and no extra tools, and a full
`/24` sweep usually takes about 2 seconds.

By default, discovery combines fast TCP probes with a pass over the
local ARP table, so quiet hosts that answer ARP but drop TCP still
show up. If that does not fit your network, `--ping` falls back to
one ICMP ping per host. Results stream as hosts are found, then a
sorted recap with a host count and elapsed time closes the scan.

## Install

Requires [Zig](https://ziglang.org/) 0.16.0 or newer (see
`build.zig.zon`) when building from source.

Download a prebuilt binary from
[GitHub Releases](https://github.com/Criseda/NetScanner/releases)
(v1.0.0 and later, with builds for Windows, macOS x86_64/arm64 and
Linux x86_64/arm64), or build it yourself:

```sh
zig build
./zig-out/bin/ns --help
```

## Usage

```sh
ns -s <subnet> [--ping]    # Find live hosts (example: 192.168.0.1/24)
ns -p <ip> <port-range>    # Scan one host for open ports (example: 192.168.1.1 1-1024)
ns --help                  # Display help message
ns --version               # Display version
```

`ns -s` uses fast TCP plus ARP discovery unless you pass `--ping`,
which uses ICMP instead.

## Docs

- [docs/README.md](docs/README.md) has the full guide: install options, build and
  test commands, release builds and notes on each discovery mode.
- [docker/README.md](docker/README.md) describes the Linux test lab, a virtual LAN you
  can scan without owning a Linux box.

## License

GNU GPL-3.0, see [LICENSE](LICENSE).

# NetScanner

![Version](https://img.shields.io/badge/Version-v1.2.0-red)
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
ns -s <subnet> [options]       # Find live hosts (example: 192.168.0.0/24)
ns -p <ip> <port-range>        # Scan one host for open ports (example: 192.168.1.1 1-1024)
ns --help                      # Display help message
ns --version                   # Display version
```

`ns -s` uses fast TCP plus ARP discovery by default (`--ping` uses ICMP).
Add `--resolve` (or `--hostname`, `--vendor`) to see device names and hardware manufacturers:

```sh
ns -s 192.168.0.0/24 --resolve
```

Output:
```text
IP               HOSTNAME                  MAC                MANUFACTURER
192.168.0.1      -                         64:fa:2b:b0:93:f1  Sagemcom Broadband SAS
192.168.0.17     DRAGONAS                  00:11:32:4f:c2:75  Synology Incorporated
192.168.0.30     LAURPI                    2c:cf:67:89:ea:27  Raspberry Pi (Trading) Ltd
192.168.0.39     Laur-PC                   9c:6b:00:42:1d:a6  ASRock Incorporation
192.168.0.153    ecb5fa31ae69              ec:b5:fa:31:ae:69  Philips Lighting BV
192.168.0.167    PS5-8ADCDF                5c:96:66:8a:dc:df  Sony Interactive Entertainment Inc.
```

## Docs

- [docs/README.md](docs/README.md) has the full guide: install options, build and
  test commands, release builds and notes on each discovery mode.
- [docker/README.md](docker/README.md) describes the Linux test lab, a virtual LAN you
  can scan without owning a Linux box.

## License

GNU GPL-3.0, see [LICENSE](LICENSE).

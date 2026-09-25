# Changelog

## Unreleased

- New `--json` flag for `-s` and `-p`: one JSON object per line (`start`,
  `host`, `host_detail`, `port`, `summary`, `error`) so programs can drive
  `ns` without scraping the human-readable text, which is free to keep
  changing. Hostnames and vendor names are JSON-escaped. See
  `docs/README.md`.
- Invalid input now exits with status 1 (it used to print the
  `NetScanner: ...` message and exit 0), so scripts can tell a failure
  from a scan that found nothing. A malformed subnet prints a clear
  message instead of a raw error trace.
- Redirecting output to a file (`ns -s ... > hosts.txt`) no longer
  garbles it: every line used to be written at the start of the file,
  overwriting the previous one. Pipes and terminals were not affected.

- `zig build` on macOS no longer prints "replacing existing signature" on
  every run, which made successful builds look like failures. The binary is
  now signed only when it changes, silently; codesign errors still show and
  fail the build.

## v1.2.2

MAC addresses and manufacturers work on macOS again (macOS 27 hid them):

- macOS 27 hides the kernel ARP table from third-party binaries: `arp -a`
  spawned by `ns` printed nothing, so `--vendor` / `--resolve` showed `-`
  for every MAC and manufacturer, and the ARP harvest silently found no quiet
  hosts (a /23 scan here went from 8 hosts to 37).
- `ns` now reads the table directly via `sysctl` on macOS, and `zig build`
  ad-hoc codesigns macOS binaries with the identifier
  `io.github.criseda.netscanner`, which macOS requires before it returns the
  table. No Apple developer account or privileges needed.
- macOS binaries must be built on a Mac: cross-built ones stay unsigned and
  see an empty table.
- Run `ns` directly from a shell. When another program is its parent
  (including `zig build run`), macOS still hides the table.
- An empty table now prints a warning explaining why, instead of blank
  columns with no explanation.

## v1.2.1

Hardware manufacturer identification data upgrade and binary lookup engine:

- Full Wireshark OUI database: Upgraded the embedded hardware manufacturer database from ~1,969 prefixes to the complete Wireshark / IEEE database (39,914 24-bit OUIs), resolving 100% of standard IEEE-assigned vendors worldwide (including all 1,553 Apple, 971 Samsung, 682 Intel, 1,252 Cisco, and 339 Espressif IoT prefixes previously omitted).
- Binary lookup table architecture: Pre-packs sorted 8-byte records and a deduplicated string pool into `oui.bin` directly embedded in `.rodata`, eliminating compile-time text parsing bottlenecks while maintaining sub-microsecond binary search lookup (< 20ns) with zero memory allocations and zero startup delay.
- Generator tooling: Added `scripts/generate_oui.py` for automated updates from upstream Wireshark automated data distributions.

## v1.2.0

Hostname resolution and hardware manufacturer lookup for subnet scans (`-s`), with zero extra privileges or external tools required:

- `--resolve`: Automatically resolves hostnames (via Reverse DNS PTR, RFC 6762 mDNS port 5353 queries, and RFC 1002 NetBIOS Name Service queries) and hardware manufacturers (via ARP table MAC extraction and embedded OUI lookup).
- `--hostname`: Resolves hostnames only (mDNS, NetBIOS NBNS, and Reverse DNS with domain suffix stripping).
- `--vendor`: Looks up MAC addresses and hardware manufacturer names only, with fallback to Windows `SendARP` for local interface / missing ARP entries.
- `--oui-file <path>`: Allows loading an external Wireshark `manuf` or IEEE OUI database file for custom or offline OUI lookups, with support for colon (`:`) and hyphen (`-`) delimiters and varying hex widths.
- Embedded OUI database: Bundles ~2,000 curated, balanced hardware manufacturer prefixes parsed at compile time from standard Wireshark flat format and sorted in `.rodata` for sub-microsecond binary search lookup (< 50ns per host) with zero external runtime dependencies.
- Ping-blocking host discovery: ARP harvest pass verifies candidates that drop ICMP ping via a parallel SendARP worker pool on Windows and kernel neighbor reachability evaluation (REACHABLE/DELAY states) on Linux, capturing firewalled IoT devices and network gear (GL.iNet, TP-Link, smart home gear) in milliseconds without stalling discovery sweeps.
- Terminal escape sequence filtering: Enforces printable ASCII validation on hostnames retrieved over NetBIOS and mDNS to prevent ANSI escape sequence injection.
- Redesigned usage & help formatting: Clear, structured CLI overview with categorized sections (`COMMANDS`, `SUBNET OPTIONS`, `PORT OPTIONS`, `GLOBAL FLAGS`, and `EXAMPLES`) and `-h` / `-v` shorthands.
- Output formatting: Displays an aligned tabular view (`IP`, `HOSTNAME`, `MAC`, `MANUFACTURER`) when resolution flags are used, while preserving the clean, compact numerical recap when flags are omitted.
- Fully cross-platform across Windows, Linux, and macOS without requiring root or administrator privileges.

## v1.1.0

Port scanning is faster and quieter, with no new privileges required:

- Fixed worker pools replace thread-per-port (and thread-per-IP in
  discovery): a full 65k range needs hundreds of threads instead of
  tens of thousands. A 200-port loopback scan drops from about 4.2s
  to about 0.6s on Windows.
- Port probes use a dedicated 500ms timeout while discovery keeps its
  longer Windows bound, so slow RSTs still count as host-up.
  Override it per scan with `ns -p <ip> <range> --timeout <ms>`.
- Results are sorted ascending; reversed ranges are rejected
  (`InvalidPortRange`, the CLI still accepts either order); the
  silent port-137 skip, the per-port sleep, per-port filtered stderr
  lines, and a leftover TEMP timing print are gone.
- `ipStringToBytes` rejects empty octets and `/0` CIDRs no longer
  overflow the mask computation.

## v1.0.0

First stable release: reliable no-root LAN discovery plus port
scanning on macOS, Linux and Windows.

Discovery:

- The default TCP plus ARP engine sweeps a `/24` in about 2 seconds,
  down from 494 seconds with naive ping sweeping. The TCP sweep finds
  hosts with open ports, and the ARP harvest pass catches quiet hosts
  that answer ARP but drop TCP. Harvest only candidates get a targeted
  probe before being reported, so stale table entries do not turn into
  false positives.
- The `--ping` fallback uses one ICMP ping per host for networks where
  TCP plus ARP does not fit.
- Results stream as hosts are found, then a sorted recap lists every
  host numerically with a one line summary of host count and elapsed
  time.

Scanning:

- Port scans share the TCP connect timeout, so filtered ports report
  quickly instead of stalling.
- Commands are unified under `-s` for discovery and `-p` for ports,
  with `--help` and `--version` alongside.

Platforms and toolchain:

- Ported to Zig 0.16.0.
- The Windows discovery path works natively, with a Winsock connect
  timeout, Windows `arp -a` parsing, and calmer WSA startup and
  cleanup.
- Linux is validated in the Docker lab (see `docker/README.md`),
  including an `ip neigh` fallback when `arp` is missing and per-OS
  ping wait flags.
- `develop` is merged into `main`, which is now the only long lived
  branch.
- CI builds and runs the tests on Linux, macOS and Windows.

Older history lives in the `v0.3.0` pre-release.

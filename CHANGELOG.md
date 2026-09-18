# Changelog

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

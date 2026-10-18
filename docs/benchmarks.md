# NetScanner vs nmap

How `ns` compares with nmap when neither tool has admin rights. In
that mode nmap cannot send raw packets, so both tools find open ports
the same way: a full TCP `connect()` per port. The time difference
comes from how many connects each tool keeps in flight and how long
it waits for the silent ones, not from a different kind of probe.

masscan and zmap are not compared: they need raw sockets and root,
which NetScanner rules out by design.

## Setup

- Windows 11 Pro (build 26300), Intel Core i9-12900K, wired gigabit
  Ethernet to the home router (192.168.0.1). The router *drops*
  probes to closed ports instead of refusing them, so every closed
  port costs both tools a timeout.
- `ns` v1.6.0, built with `zig build -Doptimize=ReleaseFast`. v1.7.0
  only adds `--neighbor-table=parent`; without that flag its scans
  do the same work.
- nmap 7.92, the official Windows zip (signature checked), run
  without Npcap. nmap then falls back to `connect()` mode by itself,
  as it would for any user without admin rights.
- Every (tool, run) pair of a case went into one list in random
  order, so network drift lands on both tools alike. Times are wall
  clock for the whole process. Ten runs per arm, except where noted.
  p90 is the nearest rank: the 9th of 10 sorted runs.
- Hosts and open ports were recorded for every run, not just time.

nmap gets `-n` (no reverse DNS) because `ns` does not resolve names
unless asked to (`--resolve`), and `-Pn` for port scans, because the
target is known to be up.

## Results

### Host discovery, home /24

| Command | Median | p90 | Hosts found |
|---|---|---|---|
| `ns -s 192.168.0.0/24` | 1.18 s | 1.47 s | 11-12 |
| `nmap -sn -n 192.168.0.0/24` | 22.54 s | 22.69 s | 5 |
| `nmap -sn -n -T4 192.168.0.0/24` | 22.68 s | 22.85 s | 5 |

nmap found the same 5 hosts in every run, and `ns` found all five in
every run too. `ns` also found devices nmap never saw: 3 that
answered mDNS and 2 known only from the ARP table in every run, plus
a third ARP-only host in 8 of 10 runs. Its count also includes the
scanning machine itself, which nmap does not list. Unprivileged nmap
only tries TCP ports 80 and 443 on each address, so phones, TVs and
smart-home devices that listen on neither are missed. `-T4` changed
nothing.

`ns` times fall into two groups: 0.55 s in 4 runs, and 1.1-1.6 s in
the other 6, with the same hosts found either way. The cause of the
split was not examined.

### Router, ports 1-1024

| Command | Median | p90 | Open ports found |
|---|---|---|---|
| `ns -p 192.168.0.1 1-1024` | 0.88 s | 0.90 s | 80, 443 (10/10 runs) |
| `nmap -sT -p 1-1024 -T4 -Pn -n 192.168.0.1` | 46.59 s | 47.75 s | 80, 443 (10/10); 53 in 8/10 |
| `nmap -sT -p 1-1024 -Pn -n 192.168.0.1` | 47.50 s | 53.01 s | 80, 443 (10/10); 53 in 9/10 |

**nmap finds a port `ns` misses.** The router's DNS port (TCP 53) is
open, and nmap found it in 17 of its 20 runs. `ns` found it in none of
its 10. On narrow ranges `ns` does find it (`53-53` did, `50-60` in
2 of 3 tries), and in 1 of 5 single connects to it, it answered only
the operating system's SYN retransmit, a second later. So
the router seems to drop some SYNs to port 53, more of them when
probes arrive in a burst. `ns` gives a silent port two tries, and here
both are lost. nmap keeps retransmitting to silent ports for much
longer, which finds port 53 and also explains most of its time.

### Router, ports 1-65535

| Command | Median | p90 | Open ports found |
|---|---|---|---|
| `ns -p 192.168.0.1 1-65535` | 14.90 s | 14.96 s | 80, 443 (10/10 runs) |
| `nmap -sT -p 1-65535 -T4 -Pn -n 192.168.0.1` | 48.4 min (1 run) | - | 80, 443 (53 not found this run) |

nmap ran once here: at this pace ten runs would take most of a day.

### scanme.nmap.org, ports 1-1024

| Command | Median | p90 | Open ports found |
|---|---|---|---|
| `ns -p 45.33.32.156 1-1024` | 0.75 s | 0.78 s | 22, 80 (3/3 runs) |
| `nmap -sT -p 1-1024 -T4 -Pn -n 45.33.32.156` | 85.61 s | 86.63 s | 22, 80 (3/3 runs) |

The Nmap Project explicitly allows scanning this host. It is about
150 ms away from this machine, and closed ports reach it as silence
(1022 filtered), not refusals. To keep the load on it low, each tool
ran 3 times, so the p90 here is the slowest run.

## Not measured

- **Privileged nmap** (`nmap -sn` or `-sS` as admin, with Npcap): ARP
  discovery and SYN scanning are much faster and would find the quiet
  LAN hosts. That needs admin rights, which `ns` avoids by design.
- **Linux and macOS.** Only Windows was measured. The Docker lab in
  `docker/` could give Linux numbers.
- **Newer nmap releases** (7.93 and later ship only as an installer
  that needs admin rights). Connect scans have changed little since
  7.92, but that is unverified.
- **Hosts that refuse closed ports** (send RST). Both tools finish
  far faster there, and the gap between them is likely smaller.

## Reproducing

Each case ran with this loop (PowerShell), in place of a fixed
before/after order:

```powershell
$arms = @(
  @{ name = 'ns';   exe = 'ns.exe';   args = @('-p', '192.168.0.1', '1-1024', '--json') },
  @{ name = 'nmap'; exe = 'nmap.exe'; args = @('-sT', '-p', '1-1024', '-T4', '-Pn', '-n', '-oG', '-', '192.168.0.1') }
)
$order = foreach ($a in $arms) { foreach ($i in 1..10) { $a } }
foreach ($a in ($order | Get-Random -Count $order.Count)) {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $out = & $a.exe @($a.args) 2>&1
  "{0},{1}" -f $a.name, $sw.ElapsedMilliseconds
  # ...then record the hosts or open ports found in $out
}
```

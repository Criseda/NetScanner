# Changelog

## Unreleased

- `--hostname` takes a fraction of the time it did, most of all on
  Windows (#107). There the reverse DNS lookup asks DNS only: Windows'
  getnameinfo went on, once DNS had no name, to LLMNR and NetBIOS over
  TCP/IP, and gave up on an address nobody names after about 5s. ns
  sends its own NetBIOS and mDNS queries first, so those fallbacks only
  asked the same hosts again; Linux and macOS have none of them. And on
  every OS, a host's NetBIOS and mDNS queries go out together and share
  one 200 ms wait, which ends as soon as each has its answer or was
  refused (an ICMP port unreachable, now heard on Linux and macOS too):
  one after the other, each with its own wait, they took up to 400 ms.
  Windows 11, wired, a /24 with 10 hosts, ReleaseFast, interleaved in
  one random order, 12 runs each, medians (p90): `ns -s --hostname`
  5.95s (6.14s) -> 0.81s (0.98s), DNS-only alone 1.00s (1.79s); the
  same 5 names in every run of all three. `ns -s` unchanged, 0.565s.
  macOS 27 (M3 Pro, Wi-Fi, a /23 with 30-48 hosts, 14 runs each),
  where only the shared wait applies: 1.74s (1.76s) -> 0.93s (1.01s),
  the same 8 names, each found about as often as its host was; a
  single host that answers neither query 0.42s -> 0.22s. Not measured
  on Linux.

- `ns -p` no longer holds its opening burst for the full 500 ms on a
  host that drops some of it (#106). The probes sent before the host's
  first answer had no learned wait, so each unanswered one waited 500
  ms, and since they fill the window, the scan waited with them: a
  router that drops closed ports took 0.9s for 1-1024, and a scan
  whose first SYN to port 22 was lost took 0.5s however few ports it
  covered. They already get a second try once the host turns out near,
  so now they wait the learned wait too, and until the burst has had
  no answer for that long: its answers queue, and on a host 80 ms away
  they came in over 100-126 ms, past the 121 ms learned from them. A
  far host (no answer under 100 ms) is unchanged.
  ReleaseFast, old and new interleaved in one random order, medians
  (p90), every open port found in every run unless noted:
  - Docker lab (Linux), 1-1024 (16 each): first SYN to 22 lost 0.503s
    (0.504s) -> 0.103s (0.125s); closed ports dropped 0.806s (0.870s)
    -> 0.638s (0.677s); 80 ms away (30 each) 0.275s (0.299s) -> 0.279s
    (0.311s), within noise. 1-65535 (12 each): first SYN lost 0.503s
    -> 0.159s; 5% loss and clean within noise.
  - Windows 11, wired: home router 1-1024 (12 each) 0.882s (0.891s) ->
    0.714s (0.725s), its rate-limited port 53 in 3 of 12 runs against
    0 of 12; a Raspberry Pi 1-1024 (20 each), scanme.nmap.org 1-1024
    (14 each) and loopback 1-65535 (10 each) unchanged.
  - macOS 27, M3 Pro, Wi-Fi: a smart-home device that drops closed
    ports, 1-1024 (12 each) 1.40s (2.03s) -> 1.01s (2.03s); the router
    (which refuses closed ports), three other LAN devices (12-30 each),
    scanme.nmap.org 1-1024 (30 each, three times over) and 1-8192 (8
    each, kernel CPU 2.51s -> 2.45s) unchanged.
  Sweeps (`ns -s`) keep their fixed 500 ms: one
  probe per address and no retry, so no observed signal says an
  address that has not answered yet never will.

- A scan's threads report their verdicts a batch at a time, one lock
  per batch instead of one per port (#105). Round trips are still
  measured when each answer arrives, so the learned wait and the
  window see the same times. They still take their ports one at a
  time: taking a batch and firing it back to back was faster on Linux
  but made macOS loopback scans about a fifth slower (four of six sets
  of 30-60 runs, p < 0.01 in three), where a connect to a closed local
  port is refused under the kernel's TCP locks and the loops ran into
  each other there. ReleaseFast, interleaved, medians (p90), `ns -p
  127.0.0.1 1-65535`: Linux (arm64 VM on an M3 Pro Mac, 30 each)
  0.086s (0.091s) -> 0.073s (0.079s), against 0.065s taking batches;
  macOS 27 (M3 Pro, 40 each) 0.585s (0.818s) -> 0.567s (0.774s),
  within noise; the router 1-1024 (14 each) and scanme.nmap.org 1-1024
  (30 each) unchanged. Same ports found everywhere. Not measured in this form on Windows,
  native Linux or the Docker lab; with batched takes, Windows loopback,
  router and scanme were unchanged, and WSL2 loopback went 0.099s ->
  0.077s.

- On macOS, scans spread their connects over at most 3 threads, not
  up to half the cores. A connect to a closed port on the machine
  itself is refused inside the connect call, under the kernel's TCP
  locks, so more threads only waited on each other. On an 11-core Mac
  (5 threads before), ReleaseFast, interleaved in one random order,
  medians (p90): `ns -p 127.0.0.1 1-65535` (30 runs each) 0.646s
  (1.100s) -> 0.570s (0.784s), back to v1.7.0's 0.558s (0.777s), with
  kernel CPU 2.75s -> 1.45s; in a sweep of 1-5 threads (30 each), 3
  were fastest, 0.427s against 0.594s for 5. The router's full range
  (6 each) 45.0s -> 43.9s, the same five ports every run; router
  1-1024, scanme.nmap.org 1-1024 and `ns -s` on a /23 unchanged, the
  same ports and hosts found.

- On Windows, scans spread their connects over at most 4 threads, not
  up to 8. On the one machine measured, more than four slowed the scan
  down again, with more kernel CPU. On a 24-thread i9-12900K
  (Windows 11, 8 threads before), ReleaseFast, 1-8 threads interleaved
  in one random order, medians (p90): `ns -p 127.0.0.1 1-65535` (30
  runs each) 2.86s (3.02s) -> 2.45s (2.52s), kernel CPU 10.1s -> 7.9s;
  the router's 1-1024 (10 each) 0.88s at every thread count, the same
  three ports every run. Linux keeps up to 8: on the same machine
  under WSL2, loopback kept getting faster up to 6-8 threads (0.097s,
  against 0.115s with 4).

- The per-host mDNS name lookup (`--hostname`) reads the reply with the
  same parser as the multicast listener, and the C one is gone (#91). A
  PTR answer now counts only when it is about the address asked; one
  naming another address used to be taken as the host's name. A reply
  without a matching PTR can still name the host through an address
  record pointing at it, as replies to the listener already could.

- `ns -p` retries the ports it probed before the host's first answer.
  Those probes have no learned wait yet, so they waited the full 500 ms
  once and were never retried; with the most often open ports going
  first, they are also the likeliest to be open, and one lost SYN lost
  them for good (#90). Once the host has answered quickly enough to
  count as near, each of them still unanswered gets a second try in the
  retry pass, at the learned wait. A far host (no answer faster than
  100 ms) is unchanged.
  Linux (WSL2) on loopback, 15 open ports, 1-65535, SYNs dropped with
  iptables, ReleaseFast, old (`main`) and new interleaved in one random
  order, medians (p90):
  - first SYN to port 22 dropped (6 runs each): old missed 22 in every
    run, new in none; 0.502s both.
  - 5% of SYNs dropped at random (30 each): old missed a port in 10 of
    30 runs (22, 53, 80, 443, 8443, 40000), new in none; 0.745s
    (0.789s) -> 0.733s (0.791s).
  - no drops (30 each): 0.116s (0.130s) -> 0.113s (0.127s).
  - closed ports dropped, a host whose retry pass runs anyway (three
    batches, 52 runs each): 13.70s, 13.70s, 13.69s -> 13.89s (12
    runs), 13.71s, 13.74s, with 15-19s outliers on both sides; new
    makes 102 more connects of 131k.
  Windows 11, wired, 5 s of quiet before each run:
  - scanme.nmap.org 1-1024 (8 each): 0.723s (0.745s) -> 0.721s
    (0.735s); 22 and 80 every run.
  - home router 1-1024, which drops closed ports (two batches, 10 and
    15 each): 0.883s (0.891s) -> 0.901s (0.917s), then 0.886s (0.898s)
    -> 0.889s (0.904s); 80 and 443 every run, its rate-limited 53 in
    25 of 25 runs and 24 of 25.
  macOS was not measured: the change is in the scan's own
  bookkeeping, the same on every OS, and the opening burst there is
  smaller (128 probes, not 256).
- `ns -p` on the machine's own address no longer reports ports that
  nothing listens on. A connect to one of its own addresses can get
  the target port as its source port, and the OS then completes it as
  a simultaneous open with itself (#90). `ns -p 127.0.0.1 1-65535`
  reported such phantom ports, inside the ephemeral range, on Linux
  (WSL2) in 10 of 15 runs (one port each), and on Windows 11 in 3 of
  12 (10 to 61 ports each); now in none of 15 and 12, at the same
  speed. A connect that reached its own socket now counts as closed.
  The check runs only on connects that succeed: two system calls per
  open port. macOS was not checked.
- `ns -p` tries the ports most often found open first, most likely
  first, then the rest of the range in port order. Some hosts
  rate-limit SYNs and answer only the first dozen or so of a burst; a
  home router's open DNS port 53 was lost in every scan when probed
  53rd, as port order had it, while nmap, which also tries the ports
  most often open first, found it. The ranking comes from how many
  Internet hosts Censys finds with each TCP port open
  (`scripts/port_counts.json`, the 2000 most common), not from any one
  network; only ports with a name are ranked, and common ones that
  had none get one in the overlay. Same probes, same pace. `port`
  events now come in that order; the closing table and the JSON
  summary's `open_ports` stay sorted.
  Windows 11, wired, ReleaseFast, old (`main`) and new interleaved in
  one random order, 5 s of quiet before each run, medians (p90):
  - router 1-1024 (12 runs each): 0.894s (1.064s) -> 0.897s (0.999s);
    port 53 found in 6 of 12 runs instead of 0; 80 and 443 in all.
  - router 1-100 (10 each): 0.598s (0.652s) -> 0.551s (0.645s), both
    bimodal at about 0.55 and 0.65s; 53 found in 3 of 10 instead of 0.
  - router 1-65535 (10 each): 15.00s (15.38s) -> 14.89s (15.07s); 53
    found in 9 of 10 instead of 0 (it goes out 18th).
  - scanme.nmap.org 1-1024 (4 each): 0.753s -> 0.728s, 22 and 80 every
    run. Home /24 discovery (`ns -s`, path unchanged): 1.259s -> 0.850s,
    both bimodal; 11 hosts, except 10 in new's last two runs, after
    old's last.
  The router answers 53 less often for a while after a full-range
  scan, which those runs mixed in. Without full-range runs, 20 s of
  quiet before each, the ranked order against trying the curated
  overlay ports first: 53 found on 1-100 in 8 of 10 runs against 7,
  on 1-1024 in 5 of 10 against 3, at the same speed; and /24 found 9
  hosts in every run of both old and new after the first.
  Linux and macOS were not measured: the change only reorders the
  ports a scan already tries, the same on every OS.
- `ns -p` names 102 more ports that IANA leaves unnamed. The 88 open on
  50,000+ Internet hosts are labelled from what Censys and Shodan see
  on them (mostly `HTTP alt`; also Android TV Remote, Kubelet,
  RustDesk, MikroTik API, Windows RPC dynamic ports, ...) or from
  Wikipedia's port list (CC BY-SA 4.0) where scans could not tell.
  14 less common ones are named from their documented default use
  where that is plausibly what runs there: Minecraft, FiveM, Bitcoin,
  Transmission, Deluge, TeamCity, ComfyUI, Vite, Envoy, NATS, ...

## v1.7.0

MAC addresses, manufacturers and quiet hosts for apps that run `ns`
on macOS, through a new `--neighbor-table=parent` flag. Nothing
changes without the flag: compared with v1.6.0 on macOS (Wi-Fi /24,
ReleaseFast, 10 interleaved runs each), `ns -s --json` took a median
of 0.52s either way and found as many hosts within Wi-Fi noise
(medians 38 and 37, every run 33-39). Linux and Windows were not benchmarked: the
change adds no work to their scans either.

Changes:

- `ns -s --json --neighbor-table=parent` asks the app that runs `ns`
  for the ARP table instead of reading it: `ns` prints a
  `neighbors_request` event and reads the app's `neighbors` reply on
  stdin (see "Neighbor table from the parent" in docs/README.md).
  macOS hides the table from programs started by apps that are not
  Developer ID signed, but the app itself can read it, so with this
  NetScanner for macOS gets MAC addresses, manufacturers and the quiet
  hosts of the ARP harvest. Without an answer within 2 seconds, `ns`
  reads the table itself as before. Without the flag nothing changes.

## v1.6.0

Faster scans on every OS, and more of the quiet devices found.
Compared with v1.5.0 (ReleaseFast, 10 interleaved runs each, medians;
the same hosts and open ports found unless noted):

- Windows 11 (wired home /24): `ns -s` 6.95s -> 0.61s; `ns -s --ping`
  1.98s -> 0.85s, now with the 8 real hosts every run (v1.5.0
  reported 8 to 166); `ns -p` 1-1024 on the router 2.14s -> 0.93s.
- Linux (Docker lab /24): `ns -s` 2.09s -> 0.55s; `ns -s --ping`
  1.06s -> 1.13s, as pings now go out at most 2 per millisecond; `ns
  -p` on a host that refuses closed ports, 1-1024 0.03s -> 0.04s and
  1-65535 0.08s -> 0.14s.
- macOS (Wi-Fi, a /23 with smart-home devices): `ns -s` 3.09s ->
  1.52s, finding a median of 39 hosts instead of 35.5; `ns -s --ping`
  3.47s -> 1.10s, a median of 36 hosts instead of 37 (38 in all on
  both, across a second set of runs); `ns -p` 1-1024 on the router
  1.14s -> 0.64s.

Changes:

- `ns -s` reports a quiet host at once when its ARP entry appeared
  during the scan, instead of pinging it first (#79). The table is
  read before the sweep too: an entry that was not there then was
  resolved by the sweep's own connects, so the host answered ARP
  seconds ago, which is proof enough. This matters most on macOS,
  whose table records no reachability state, so every entry used to
  get the confirming ping, and devices that answer ARP but drop ping
  were never reported. Older entries still get the ping, as before
  (#23), and so do new entries sharing a MAC with another address in
  the range (a router doing proxy ARP answers for all of them).
  Measured on macOS (Wi-Fi, a /23 with smart-home devices, 10
  interleaved runs each): with the ARP table cleared before each run,
  1.52s -> 0.52s and a median of 15 -> 18.5 hosts found (Espressif,
  Nest and Tuya devices that drop ping); with a warm table, 1.53s
  either way and the same hosts. Linux and Windows already reported
  these entries at once as reachable, and measure the same as before.

- Port scans of distant hosts are as fast as `--timeout 500` again.
  A host that never answers faster than 100 ms now gets one 500 ms
  wait per port, as before #69, instead of a shorter learned wait and
  a second try. That far away, a port that missed the learned wait was
  nearly always a slow refusal rather than a lost packet, so the second
  pass found nothing and only added time. The host's fastest answer
  decides, so a nearby router slowed down by the scan itself keeps its
  second tries. Measured on macOS against scanme.nmap.org (`1-1024`,
  ~170 ms away, 20 runs): 1.12s -> 0.87s, level with `--timeout 500`,
  same open ports. LAN scans are unchanged.

- `--ping`, and the ping that confirms quiet hosts from the ARP table
  in a default `ns -s`, now send their pings from inside `ns` instead
  of starting a `ping` process per host, still without privileges.
  Up to 512 pings wait for their answer at once, each for its own 1s,
  instead of in waves of 256 that each waited for their slowest host.
  Measured on Windows 11 (median, same machine, old and new builds
  interleaved): `--ping` on a home /24 2.5s -> 1.0s, on an empty routed
  /20 46.5s -> 8.0s, on an empty routed /16 710s -> 128s. The default
  `ns -s` is unchanged (2.0s). On macOS (Wi-Fi): `--ping` on a /23
  2.3s -> 1.1-1.3s, on an empty routed /20 18.2s -> 8.2s, with the
  same hosts found. Pings go out at most 2 per millisecond: at 16, a
  Wi-Fi /23 lost up to half its replies. On Linux, an on-link /20 sweeps in 13.5s
  instead of about 20s. Where Linux does not allow unprivileged pings
  (the user's group is outside `net.ipv4.ping_group_range`), `ns` falls
  back to the `ping` command, as before.

- Fixed: on Windows, `--ping` sometimes reported absent hosts as up.
  Windows' `ping` succeeds when the answer is "destination host
  unreachable" from the scanning machine itself, so a random handful of
  empty addresses showed up in each scan (up to 5 on a /24). Only an
  echo reply from the host itself counts now.

- `ns -s` on an attached subnet now also asks the network who is there
  over multicast: one mDNS service query and one SSDP search go out as
  the TCP sweep starts, and every device in range that answers is
  reported, with no ping needed (a fresh reply is proof). Phones,
  printers, TVs and speakers often drop TCP and ICMP yet answer these.
  Replies come back to `ns`'s own port, so the system's mDNS service
  is untouched, and the listener stops when the sweep and ARP check
  end, so it adds no wait. Routed ranges skip it. With `--hostname` /
  `--resolve`, an mDNS name heard this way replaces that host's mDNS
  query; NetBIOS still wins where it answers, so names are as before.
  **JSON change:** `host.source` can now be `mdns` or `ssdp` (text
  output tags those hosts `(mdns)` / `(ssdp)`), and a host TCP would
  have found may now arrive first by multicast. Consumers should
  accept unknown `source` values.

- Discovery (`ns -s`) reads the ARP table straight from the kernel on
  Linux (netlink) and Windows (`GetIpNetTable2`), as it already did on
  macOS, instead of running `arp -a` or `ip neigh`. Linux no longer
  needs net-tools, and `arp -a` no longer looks up a name for every
  table entry (seconds of DNS waits after each sweep). The kernel's
  own verdict on each entry is now used on both OSes: a host it
  confirmed seconds ago is reported at once (`source` `arp`), with no
  confirming ping. So a device that drops TCP and ping but answers ARP
  is now found on Linux too (only Windows found those before, through
  SendARP). Older entries are still pinged first, as before. Measured
  (median of 10, `ns -s` on a /24): Windows 11 home LAN 1.8s -> 1.1s,
  the same 10 hosts every run; Linux Docker lab 11.8s -> 1.1s, all 4
  neighbours found in every run (was 2-3). macOS is unchanged.

- Scans keep many connects in flight at once instead of one per thread
  (#67). A probe that gets no answer no longer ties up a thread for its
  whole timeout, so hosts that drop closed ports, and sweeps of empty
  ranges, scan several times faster. Port scans start with as many
  probes in flight as the old thread pool had (128 on macOS, 256
  elsewhere) and grow toward 1024 while the host answers promptly. When
  its answers slow down, the scan halves the number in flight, but
  never below where it started, because a home router sent probes
  faster than it can answer starts losing open ports. A host that was
  answering and suddenly answers nothing (an iPhone on Wi-Fi does this
  for seconds under a fast scan) gets the starting pace back, and when
  the second tries show the host lost many first ones, the ports silent
  on both get a third try at the old pace. Needs no privileges: on
  Linux and macOS, `ns` raises its own soft open-file limit as far as
  the hard limit allows. Measured
  (median of 10, interleaved with the previous build, same ports and
  hosts found):
  - Windows 11: `-p` 1-65535 on a router that drops closed ports
    55.6s -> 15.4s, on a NAS that refuses them 4.6s -> 2.9s, on
    127.0.0.1 3.0s -> 2.6s; `-s` on a /24 2.0s -> 1.5s, on an empty
    routed /20 16.5s -> 2.2s.
  - Linux (Docker): `-p` 1-65535 on a host that drops closed ports
    67.1s -> 14.4s; `-s` on an empty routed /20 16.4s -> 2.2s. Scans
    that finish in a fraction of a second anyway are slightly slower:
    1-65535 on a host that refuses closed ports 0.10s -> 0.18s, on
    127.0.0.1 0.07s -> 0.12s.
  - macOS (Apple Silicon, Wi-Fi): `-p` 1-65535 on an iPhone 19.0s ->
    15.4s, on a mesh router 50.2s -> 45.1s, on a recorder that refuses
    closed ports 20.0s -> 17.7s, on 127.0.0.1 0.58s -> 0.53s, on an
    absent host (1-2000) 8.1s -> 2.5s; scanme.nmap.org 1-1024 1.74s ->
    1.43s; `-s` on a /23 3.1s -> 1.6s, on an empty routed /20 16.2s ->
    2.6s.

- Port scans of distant hosts no longer retry closed ports that were
  merely slow to refuse. The learned wait now keeps at least 40 ms
  above the host's average round trip: on a steady link it had settled
  only a millisecond or two above it, so the slower refusals missed it
  and were tried again at the end of the scan, for nothing. Measured on
  Windows 11 against scanme.nmap.org (`1-1024`, 168 ms away): 1-6
  refused ports retried per run before, none after (the one port
  dropped on the way still is, as it should be). Same open ports;
  LAN scans are unchanged, as the 100 ms floor already left more room.
  A retried port's two tries now also share the 500 ms between them,
  even if the host slowed down in between (the second could wait the
  full 500 ms before).

- Port scans (`ns -p`) learn their connect timeout from the host's own
  answers instead of always waiting 500 ms per port: TCP's
  retransmission formula (RFC 6298) over the ports that answered,
  between 100 and 500 ms. An unanswered port gets a second try near
  the end of the scan, so neither one lost packet nor a host that
  stalls for a moment can hide it. The learned wait is used only when
  both tries fit in 500 ms, so no port waits longer than before. The
  gain is on hosts that drop closed ports instead of refusing them:
  measured on Windows 11, a full `1-65535` scan of such a router
  127.9s -> 54.6s (median of 10, same open ports found). Hosts that
  refuse closed ports already answer every probe and scan as fast as
  before (`1-10000` on a NAS: 0.7s either way). `--timeout <ms>` still
  fixes the wait, exactly as before.

- On Windows, a refused connection is now reported the moment the host
  answers, instead of about 2s later: Windows retried every refused
  connect before giving up, and `ns` now turns those retries off.
  Discovery (`ns -s`) therefore waits 500 ms per probe on Windows too,
  as on Linux and macOS (was 3000 ms), and port scans see closed ports
  at once. Measured on Windows 11, home network (median of 10 / 5 / 3
  runs, same hosts and ports found): `ns -s` on a /24 6.9s -> 1.8s, on
  an empty /24 6.2s -> 1.2s, and `ns -p` 1-10000 on a NAS that refuses
  closed ports 19.9s -> 0.7s. Hosts that drop probes instead of refusing
  them scan as before. A probe that gets no answer still waits the
  full timeout, but sends its connection request only once: with
  `--timeout` above 1000, Windows no longer resends it after 1s.

- Building from source requires Zig 0.17.0 (was 0.16.0); 0.16.0 no
  longer builds the project. Prebuilt binaries are unaffected. The
  Docker test lab installs 0.17.0 too.

## v1.5.0

Scans report their progress, to frontends and in the terminal:

- `--json` scans now report live progress, so frontends can show a real
  percentage instead of a spinner: `{"type":"progress","phase":"sweep","done":120,"total":254}`.
  Phases are `ports` (`-p`), `sweep` (`-s`, TCP or `--ping`), `arp`
  (the ping check of quiet hosts from the ARP table, after a TCP sweep)
  and `identify` (hostname resolution with `--resolve` / `--hostname`,
  which can take seconds after the sweep is done). Events go out only
  when the whole percentage changes, at most about 100 per phase.
  `done` only increases, and each phase ends with one `done == total`
  event.
  A `host` or `port` event always comes before the progress event that
  counts it. Existing events are unchanged, and text output has no
  progress lines.
- In a terminal, text scans show a live status line instead of printing
  every result as it is found, e.g. `⠹ Scanning 192.168.1.0/24… 42% ·
  7 hosts found`, then `Identifying devices… 3 of 9` during `--resolve`
  (ASCII where the terminal is not UTF-8).
  Results print once, in the closing summary, so hosts and ports are no
  longer listed twice. **Behavior change** for terminals only: piped or
  redirected output, `--json`, and terminals that cannot show the line
  (`TERM=dumb`, or a reported size of zero) still stream line by line,
  exactly as before.
- Ctrl+C on a scan in a terminal now stops it and prints what it found
  so far, marked `interrupted` (e.g. `7 hosts up (1.5s, interrupted)`),
  instead of discarding it. A second Ctrl+C quits at once. `ns` still
  exits as interrupted (SIGINT; `STATUS_CONTROL_C_EXIT` on Windows), so
  scripts see the stop. If SIGINT was ignored at startup (`nohup`), it
  stays ignored.
- The elapsed time that closes a subnet scan (and `elapsed_ms` in its
  `--json` summary) now includes hostname resolution with `--resolve` /
  `--hostname`. It used to stop when the sweep ended, so a scan that
  spent seconds naming hosts reported only part of its time.
- On macOS, a ping that gets no answer now gives up after 1s, as on
  Linux and Windows, instead of 2s. `--ping` sweeps and the check of
  quiet hosts from the ARP table finish about a second sooner.
- `--ping` sweeps hear each host the moment its ping answers, so the
  found count (status line, or `host` events with `--json`) climbs right
  away instead of waiting behind the first host that never answers.
  Ranges larger than a /24 ping in waves of 256 hosts instead of
  starting a process for every host at once.
- A port scan that finds nothing closes with its elapsed time too, like
  every other scan: `No open ports found (0.5s)`.

## v1.4.0

Port scans name the services they find:

- Every open port is named from an embedded table of about 6,000 TCP
  ports: the official IANA service registry, plus a curated overlay of
  friendly labels, categories and common unofficial uses (RDP instead of
  `ms-wbt-server`, Home Assistant on 8123). The two stay apart: the
  official IANA name is always reported next to the label, and ports
  known only from common use have none. No network lookups, no flags.
- `--json` port events gain `service`, `iana`, `description` and
  `category` (each `null` when unknown), e.g.
  `{"type":"port","port":3389,"service":"RDP","iana":"ms-wbt-server",...}`.
  Existing fields are unchanged; `summary.open_ports` is still a list of
  numbers. NetScannerDesktop shows them as columns in its Port scan table.
- Text output streams `Open port: 3389 (RDP)`, and the closing
  `Open ports: 22, 80` line is replaced by an aligned PORT / SERVICE /
  IANA / DESCRIPTION table with a count and elapsed time, like `-s`.
  **Behavior change** for scripts that scrape the text; use `--json`.
- Generator tooling: `scripts/generate_ports.py` packs the IANA registry
  and `scripts/port_overlay.txt` into `src/core/data/ports.bin`, and
  prints which ports changed since the last run for the PR description.

## v1.3.0

Machine-readable output for scripts and frontends, and reliable exit codes:

- New `--json` flag for `-s` and `-p`: one JSON object per line (`start`,
  `host`, `host_detail`, `port`, `summary`, `error`) so programs can drive
  `ns` without scraping the human-readable text, which is free to keep
  changing. Hostnames and vendor names are JSON-escaped. See
  `docs/README.md`. NetScannerDesktop uses it automatically.
- Invalid input now exits with status 1 (it used to print the
  `NetScanner: ...` message and exit 0), so scripts can tell a failure
  from a scan that found nothing. A malformed subnet prints a clear
  message instead of a raw error trace. **Behavior change** for scripts
  that relied on exit 0.
- Redirecting output to a file (`ns -s ... > hosts.txt`) no longer
  garbles it: every line used to be written at the start of the file,
  overwriting the previous one. Pipes and terminals were not affected.
- `--help` lists the new OUTPUT OPTIONS section.
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

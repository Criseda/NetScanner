# NetScanner Docker test lab

Test NetScanner on Linux without owning a Linux box. Related issue: #28.
Windows and macOS can't be containerized (Windows containers need a
Windows host, macOS containers don't exist), so those are tested on
real hosts directly (see #24 for Windows).

## Support matrix

| Environment | Status |
|---|---|
| linux/arm64 | Verified: build, 20/20 tests, discovery 4/4, port scans |
| linux/amd64 | Verified under Rosetta: build, 20/20 tests, discovery 4/4 |

## Quick start (Linux lab)

One command brings up a virtual `/24` with two neighbours (a quiet
box that answers ping and drops TCP, and a web box with port 80
open), plus a
scanner shell with the repo mounted:

```sh
docker compose -f docker/compose.yaml up -d
docker compose -f docker/compose.yaml exec scanner bash
```

Inside the scanner shell:

```sh
zig build && zig build test --summary all   # toolchain check
./zig-out/bin/ns -s 192.168.90.0/24         # expect .1, .2, .3, .4 in ~1s
./zig-out/bin/ns -s 192.168.90.0/29 --ping  # ICMP ping sweep
./zig-out/bin/ns -p 192.168.90.3 79-81      # expect port 80 open
```

Ground truth for scoring: `docker network inspect netscanner-lab_lantest`.
Tear down with `docker compose -f docker/compose.yaml down`.

To run the amd64 image instead (emulated, slower):

```sh
DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose -f docker/compose.yaml up -d
```

## Benchmark targets (lossy, filtering, far)

The quiet box and the web box never lose a packet, so behaviour that
only shows under loss (a port missed when its SYN is dropped, #90)
can't be reproduced with them. The `bench` profile adds targets that
listen on the same 15 ports (`OPEN_PORTS` in `docker/lab.env`, the
ground truth) and shape their own traffic with iptables or tc:

| Target | Address | What it does |
|---|---|---|
| `clean` | .200 | Nothing: the baseline |
| `lossy` | .201 | Drops 5% of incoming SYNs at random (`LOSS`) |
| `filtering` | .202 | Drops SYNs to every closed port, like a home router |
| `first-syn-lost` | .203 | Drops the first SYN to port 22 in every scan (#90) |
| `far` | .204 | Adds 80 ms to every round trip (`DELAY`, tc netem) |

```sh
docker compose -f docker/compose.yaml --profile bench up -d --build
```

`first-syn-lost` lets a SYN through when another reached port 22 in
the last second (`FIRST_SYN_WINDOW`), so a scan's retry gets through
and the next scan, after a longer pause, loses its first SYN again.
`far` needs `sch_netem` in the host kernel; where it is missing the
container exits with a message instead of running as a near host.

`scripts/bench.py` compares two builds on these targets the way
AGENTS.md asks of a performance change: ReleaseFast binaries, old and
new interleaved in one random order, 10+ runs each, medians and p90 of
wall and CPU time, and per run whether every open port was found. A
rank test (Mann-Whitney) and a bootstrap interval on the ratio of the
medians say whether a difference stands out from the noise. Inside
the scanner shell, building the old side from any commit:

```sh
git config --global --add safe.directory /work
mkdir -p /tmp/old-src && git archive main | tar -x -C /tmp/old-src
(cd /tmp/old-src && zig build -Doptimize=ReleaseFast -p /tmp/old)
zig build -Doptimize=ReleaseFast -p /tmp/new --cache-dir /tmp/new-cache
python3 scripts/bench.py --old /tmp/old/bin/ns --new /tmp/new/bin/ns --runs 20
```

The `--cache-dir` keeps the container's build cache apart from the
host's. By default the runner scans `1-65535` on `clean`, `lossy` and
`first-syn-lost`; `--profiles` picks others, and `filtering` and `far`
take seconds per scan over the full range, so `--ports 1-1024` (whose
ground truth is the open ports inside it) keeps them short. `--seed`
replays a run order, `--csv` keeps every run.

This covers Linux only. Windows and macOS still need real hosts.

## Manual setup (without compose)

```sh
docker build -f docker/Dockerfile.linux -t netscanner-test .
docker network create --subnet 192.168.90.0/24 nstest
docker run -d --network nstest --name nst-n1 busybox sleep 3600
docker run -d --network nstest --name nst-web busybox httpd -f -p 80
docker run --rm --network nstest --cap-add=NET_RAW \
  -v "$PWD:/work" -w /work netscanner-test ./zig-out/bin/ns -s 192.168.90.0/24
```

`ns` pings from inside the process, through an unprivileged ICMP
socket that Docker allows by default (`net.ipv4.ping_group_range`).
`--cap-add=NET_RAW` is only for the `ping` binary `ns` falls back to
when that socket is refused; without it, that binary fails with
"Operation not permitted". To exercise the fallback, block the socket:

```sh
docker run --rm --network nstest --cap-add=NET_RAW \
  --sysctl net.ipv4.ping_group_range="1 0" \
  -v "$PWD:/work" -w /work netscanner-test ./zig-out/bin/ns -s 192.168.90.0/29 --ping
```

# NetScanner Docker test lab

Test NetScanner on other operating systems without owning them.
Related issues: #24 (Windows run), #28 (Linux run).

## Support matrix

| Environment | File | Status |
|---|---|---|
| linux/arm64 | `Dockerfile.linux` | Verified: build, 20/20 tests, discovery 4/4, port scans |
| linux/amd64 | `Dockerfile.linux` (`--platform`) | Verified under Rosetta: build, 20/20 tests, discovery 4/4 |
| windows/amd64 | `Dockerfile.windows` | UNTESTED template, needs a Windows host (see below) |
| windows/arm64 | — | Omitted: no practical container base/toolchain story; see #24 |
| macOS (any) | — | No such thing as macOS containers; test on a real Mac |

## Quick start (Linux lab)

One command brings up a virtual `/24` with two neighbours — a quiet
box (answers ping, drops TCP) and a web box (port 80 open) — plus a
scanner shell with the repo mounted:

```sh
docker compose -f docker/compose.yaml up -d
docker compose -f docker/compose.yaml exec scanner bash
```

Inside the scanner shell:

```sh
zig build && zig build test --summary all   # toolchain check
./zig-out/bin/ns -s 192.168.90.0/24         # expect .1, .2, .3, .4 in ~1s
./zig-out/bin/ns -s 192.168.90.0/29 --ping  # ping fallback path
./zig-out/bin/ns -p 192.168.90.3 79-81      # expect port 80 open
```

Ground truth for scoring: `docker network inspect netscanner-lab_lantest`.
Tear down with `docker compose -f docker/compose.yaml down`.

To run the amd64 image instead (emulated, slower):

```sh
DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose -f docker/compose.yaml up -d
```

## Manual setup (without compose)

```sh
docker build -f docker/Dockerfile.linux -t netscanner-test .
docker network create --subnet 192.168.90.0/24 nstest
docker run -d --network nstest --name nst-n1 busybox sleep 3600
docker run -d --network nstest --name nst-web busybox httpd -f -p 80
docker run --rm --network nstest --cap-add=NET_RAW \
  -v "$PWD:/work" -w /work netscanner-test ./zig-out/bin/ns -s 192.168.90.0/24
```

`--cap-add=NET_RAW` is required: without it the `ping` binary the
`--ping` path shells out to fails with "Operation not permitted".

## Windows

Windows containers run only on Windows hosts (Windows 10/11 Pro+ or
Server with the Containers feature, Docker Desktop in
Windows-containers mode) — so `Dockerfile.windows` is an untested
starting point, not a verified setup. If you have such a host, the
file header lists the four validation steps; report back on #24.

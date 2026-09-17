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

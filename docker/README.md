# NetScanner Docker test lab

Run the Linux validation (#28) without a Linux box. macOS and Windows
containers don't exist, so this is Linux-only; Windows still needs a
real Windows host (see #24).

## Build the image

Zig toolchain + the network tools the scanner needs. Supports x86_64
and arm64 (picked automatically).

```sh
docker build -f docker/Dockerfile.linux -t netscanner-test .
```

## Spin up a virtual LAN

A /24 with two neighbours: a quiet box (answers ping, drops TCP)
and a web box (port 80 open). The gateway (.1) comes free.

```sh
docker network create --subnet 192.168.90.0/24 nstest
docker run -d --network nstest --name nst-n1 busybox sleep 3600
docker run -d --network nstest --name nst-web busybox httpd -f -p 80
```

## Run the validation

The repo mounts into the container, so you build and test the real code.
`--cap-add=NET_RAW` is required: without it the `ping` binary the
`--ping` path shells out to gets "Operation not permitted".

```sh
# Build + unit tests
docker run --rm --network nstest --cap-add=NET_RAW \
  -v "$PWD:/work" -w /work netscanner-test \
  bash -c "zig build && zig build test --summary all"

# Fast discovery: expect .1, .2, .3, .4 (self) in ~1s
docker run --rm --network nstest --cap-add=NET_RAW \
  -v "$PWD:/work" -w /work netscanner-test \
  ./zig-out/bin/ns -s 192.168.90.0/24

# Ping fallback (first run may miss one host; that flake is known)
docker run --rm --network nstest --cap-add=NET_RAW \
  -v "$PWD:/work" -w /work netscanner-test \
  ./zig-out/bin/ns -s 192.168.90.0/29 --ping

# Port scans: 80 open on web (.3), nothing on n1 (.2)
docker run --rm --network nstest --cap-add=NET_RAW \
  -v "$PWD:/work" -w /work netscanner-test \
  ./zig-out/bin/ns -p 192.168.90.3 79-81
```

Ground truth for scoring: `docker network inspect nstest` lists every
container IPv4 on the LAN.

## Tear down

```sh
docker rm -f nst-n1 nst-web
docker network rm nstest
```

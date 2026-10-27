#!/bin/sh
# Entry point of a benchmark target (docker/Dockerfile.target): listen
# on every port in OPEN_PORTS, then shape this container's own traffic
# the way PROFILE says, so behaviour that only shows under loss or
# filtering can be reproduced in the lab. See docker/README.md.
set -eu

: "${OPEN_PORTS:?set OPEN_PORTS (docker/lab.env)}"
PROFILE=${PROFILE:-clean}

# busybox httpd backgrounds itself; an empty root answers 404, which
# is fine: only the accepted connect matters.
mkdir -p /srv/empty
for port in $(echo "$OPEN_PORTS" | tr ',' ' '); do
  httpd -p "$port" -h /srv/empty
done

case "$PROFILE" in
  clean)
    ;;
  lossy)
    # Drop a random share of incoming SYNs, open and closed ports alike.
    iptables -A INPUT -p tcp --syn \
      -m statistic --mode random --probability "${LOSS:-0.05}" -j DROP
    ;;
  filtering)
    # Like a home router: closed ports never answer, open ones do.
    iptables -A INPUT -p tcp --syn \
      -m multiport ! --dports "$OPEN_PORTS" -j DROP
    ;;
  first-syn-lost)
    # Drop the first SYN to one open port in every scan (#90). A SYN
    # within FIRST_SYN_WINDOW seconds of the last one to that port is a
    # retry from the same scan and goes through (and keeps the window
    # open); after a quiet gap longer than the window, the next scan's
    # first SYN is dropped again. A packet counter (--mode nth) would
    # only catch the first scan after the container starts.
    port=${FIRST_SYN_PORT:-22}
    window=${FIRST_SYN_WINDOW:-1}
    iptables -A INPUT -p tcp --syn --dport "$port" \
      -m recent --name ns_first --update --seconds "$window" -j ACCEPT
    iptables -A INPUT -p tcp --syn --dport "$port" \
      -m recent --name ns_first --set -j DROP
    ;;
  far)
    # Delay everything this host sends, so each round trip takes
    # DELAY longer. Needs sch_netem in the host kernel, which some
    # lack: fail loudly rather than run as a near host.
    if ! tc qdisc add dev eth0 root netem delay "${DELAY:-80ms}"; then
      echo "target: tc netem failed; this kernel has no sch_netem" >&2
      exit 1
    fi
    ;;
  *)
    echo "target: unknown PROFILE '$PROFILE'" >&2
    exit 1
    ;;
esac

echo "target ready: profile=$PROFILE open=$OPEN_PORTS"
exec sleep infinity

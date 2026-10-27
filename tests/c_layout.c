// What the C compiler makes of the types and constants that
// src/c/c_bindings.zig declares again by hand, for c_bindings_test.zig
// to compare against Zig's view. A field added, resized or reordered on
// one side still compiles and links, then corrupts data at run time,
// possibly on one OS's ABI only; CI runs the tests on all three.
//
// Built into the test binary only (build.zig), never into ns.

#include <stddef.h>
#include <stdint.h>

#include "icmp_ping.h"
#include "multicast.h"
#include "neighbors.h"
#include "ns_socket.h"
#include "resolver.h"
#include "tcp_probe.h"

const size_t layout_ns_neighbor_size = sizeof(ns_neighbor);
const size_t layout_ns_neighbor_align = _Alignof(ns_neighbor);
const size_t layout_ns_neighbor_ip = offsetof(ns_neighbor, ip);
const size_t layout_ns_neighbor_mac = offsetof(ns_neighbor, mac);
const size_t layout_ns_neighbor_has_mac = offsetof(ns_neighbor, has_mac);
const size_t layout_ns_neighbor_state = offsetof(ns_neighbor, state);
const int layout_ns_neigh_reachable = NS_NEIGH_REACHABLE;

const size_t layout_icmp_observer_size = sizeof(icmp_ping_observer);
const size_t layout_icmp_observer_align = _Alignof(icmp_ping_observer);
const size_t layout_icmp_observer_ctx = offsetof(icmp_ping_observer, ctx);
const size_t layout_icmp_observer_pinged = offsetof(icmp_ping_observer, pinged);
const size_t layout_icmp_observer_stop_requested =
    offsetof(icmp_ping_observer, stop_requested);
const int layout_icmp_ping_done = ICMP_PING_DONE;
const int layout_icmp_ping_unavailable = ICMP_PING_UNAVAILABLE;

const int layout_tcp_probe_open = TCP_PROBE_OPEN;
const int layout_tcp_probe_refused = TCP_PROBE_REFUSED;
const int layout_tcp_probe_filtered = TCP_PROBE_FILTERED;
const int layout_tcp_probe_pending = TCP_PROBE_PENDING;
const int layout_tcp_probe_max_sockets = TCP_PROBE_MAX_SOCKETS;

const size_t layout_udp_exchange_size = sizeof(ns_udp_exchange);
const size_t layout_udp_exchange_align = _Alignof(ns_udp_exchange);
const size_t layout_udp_exchange_req = offsetof(ns_udp_exchange, req);
const size_t layout_udp_exchange_req_len = offsetof(ns_udp_exchange, req_len);
const size_t layout_udp_exchange_resp = offsetof(ns_udp_exchange, resp);
const size_t layout_udp_exchange_cap = offsetof(ns_udp_exchange, cap);
const size_t layout_udp_exchange_resp_len = offsetof(ns_udp_exchange, resp_len);
const size_t layout_udp_exchange_port = offsetof(ns_udp_exchange, port);
const int layout_ns_wait_max = NS_WAIT_MAX;

const size_t layout_mc_socket_size = sizeof(mc_socket);
const int64_t layout_mc_no_socket = MC_NO_SOCKET;

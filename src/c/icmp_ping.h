#ifndef ICMP_PING_H
#define ICMP_PING_H

#include <stddef.h>
#include <stdint.h>

// What icmp_ping_sweep returns.
typedef enum {
  ICMP_PING_DONE = 0, // The sweep ran; every host was reported.
  // In-process pinging is not allowed here (Linux: the user's group is
  // outside net.ipv4.ping_group_range). Nothing was sent or reported,
  // so the caller can fall back to ping(1).
  ICMP_PING_UNAVAILABLE = 1,
  ICMP_PING_NO_MEMORY = 2, // Nothing was sent or reported.
} icmp_ping_result;

// How the sweep reports, called on the sweeping thread only.
typedef struct {
  void *ctx;
  // Host `index` answered (1) or did not (0). Called exactly once for
  // every host the sweep got to (all of them, unless it was stopped).
  void (*pinged)(void *ctx, size_t index, int answered);
  // Nonzero once the caller wants the sweep to stop: no new echoes go
  // out, and the ones in flight are waited for (at most timeout_ms).
  int (*stop_requested)(void *ctx);
} icmp_ping_observer;

// Send one ICMP echo request to each of ips[0..count) from inside the
// process, at most max_in_flight unanswered at a time, and report which
// hosts sent back an echo reply within timeout_ms. Each ip is four
// bytes in network order (as written, 192.168.1.1 is {192,168,1,1}).
//
// No privileges needed: Windows uses IcmpSendEcho2, Linux and macOS
// unprivileged datagram ICMP sockets. Only an echo reply from the host
// itself counts; "destination unreachable" from a router never does.
icmp_ping_result icmp_ping_sweep(const uint8_t (*ips)[4], size_t count,
                                 int timeout_ms, size_t max_in_flight,
                                 const icmp_ping_observer *observer);

#endif

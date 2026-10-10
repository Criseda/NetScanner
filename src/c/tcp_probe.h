#ifndef TCP_PROBE_H
#define TCP_PROBE_H

#include <stdint.h>

// Result of one TCP connect attempt, mirroring Outcome in
// src/core/connects.zig, plus "not settled yet".
typedef enum {
  TCP_PROBE_OPEN, // Connected: the port is open.
  TCP_PROBE_REFUSED, // RST: the port is closed, but a host answered.
  TCP_PROBE_FILTERED, // Timeout or unreachable: no answer at all.
  TCP_PROBE_PENDING, // Started; wait on the socket, then finish it.
} tcp_probe_result;

// Most sockets one tcp_probe_wait call watches. MAX_IN_FLIGHT in
// src/core/connects.zig must not exceed it.
#define TCP_PROBE_MAX_SOCKETS 4096

// Windows-only: many connects in flight on one thread. Zig's std.Io
// connect leaves its timeout unimplemented (as of 0.17 it panics), and
// Winsock needs its own setup, so the three steps live here:
//
// 1. tcp_probe_start begins a non-blocking connect to ip:port (four
//    bytes, network order). It returns the verdict when the connect
//    settles at once, or TCP_PROBE_PENDING with the socket in
//    *out_sock.
// 2. tcp_probe_wait waits up to wait_ms for any of `count` pending
//    sockets to settle and sets settled[i] to 1 for each that did.
//    Returns how many settled, or -1 on failure.
// 3. tcp_probe_finish reads a pending socket's verdict and closes it.
//    Pass settled = 0 at the deadline: a connect still in flight then
//    is "no answer", never "open".
tcp_probe_result tcp_probe_start(const unsigned char ip[4], unsigned short port,
                                 int timeout_ms, uintptr_t *out_sock);
int tcp_probe_wait(const uintptr_t *socks, int count, int wait_ms,
                   unsigned char *settled);
tcp_probe_result tcp_probe_finish(uintptr_t sock, int settled);

#endif

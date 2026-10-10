#ifndef MULTICAST_H
#define MULTICAST_H

#include <stddef.h>
#include <stdint.h>

// UDP plumbing for multicast discovery (mDNS + SSDP) during `ns -s`.
// Building and parsing the packets happens in src/core/multicast.zig;
// this file only owns the sockets, because Winsock and BSD sockets
// differ in every call it needs. IPv4 addresses travel as 4 bytes in
// network order, exactly like the Zig side's [4]u8.

// An open discovery socket, or MC_NO_SOCKET. Wide enough for a Winsock
// SOCKET (a pointer-sized handle) as well as a POSIX fd.
typedef int64_t mc_socket;
#define MC_NO_SOCKET ((mc_socket)-1)

// Find this machine's address on an attached subnet that overlaps
// first..last (inclusive), skipping loopback and interfaces that are
// down. Multicast never crosses a router, so a range with no such
// interface is off-link and gets no queries. Writes the address to
// out_local and returns 0, or -1 when the range is off-link.
int mc_local_address(const unsigned char first[4], const unsigned char last[4],
                     unsigned char out_local[4]);

// A non-blocking UDP socket on an ephemeral port, sending multicast out
// of the interface that owns `local` with a TTL of 1 (link-local).
// Replies to a query sent from it come back to it by unicast.
mc_socket mc_open(const unsigned char local[4]);

// Send one datagram to ip:port. 0 on success, -1 on failure.
int mc_send(mc_socket sock, const unsigned char ip[4], unsigned short port,
            const unsigned char *buf, size_t len);

// Wait up to timeout_ms for one datagram. Returns its length (with the
// sender in out_from), 0 when nothing arrived in time (or a signal cut
// the wait short), or -1 on a socket error.
int mc_recv(mc_socket sock, int timeout_ms, unsigned char *buf, size_t cap,
            unsigned char out_from[4]);

// Cut short a wait in mc_recv on another thread: sends the socket an
// empty datagram from loopback, which mc_recv reports as "nothing yet".
// Lets a listener stop at once instead of at the end of its poll.
void mc_wake(mc_socket sock);

void mc_close(mc_socket sock);

#endif

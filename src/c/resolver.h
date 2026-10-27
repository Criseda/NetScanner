#ifndef RESOLVER_H
#define RESOLVER_H

#include <stddef.h>

/// Resolve an IPv4 address to its reverse DNS PTR hostname using standard
/// getnameinfo(). Operates without elevated privileges by querying the system's
/// configured DNS resolver.
/// Returns 0 on success with a null-terminated hostname in out_buf, -1 on failure.
int resolve_ptr(const char *ip_address, char *out_buf, size_t out_len);

/// One request of udp_exchange_all: `req` goes to the host's `port`,
/// and its reply, if any, lands in `resp`.
typedef struct {
  const unsigned char *req;
  size_t req_len;
  unsigned char *resp;
  size_t cap;
  /// Set by udp_exchange_all: the reply's length, or -1 for none.
  int resp_len;
  unsigned short port;
} ns_udp_exchange;

/// Send each of `xs` (at most NS_WAIT_MAX) to its port on `ip` (4 bytes,
/// network order) at once, and wait up to timeout_ms for their replies.
/// Returns as soon as every request has its reply or was refused (an
/// ICMP port unreachable), so a host with neither service costs a round
/// trip, not the whole wait. Used for the per-host name queries
/// (NetBIOS, unicast mDNS), whose packets src/core/resolver.zig and
/// src/core/multicast.zig build and parse.
void udp_exchange_all(const unsigned char ip[4], ns_udp_exchange *xs, int count,
                      int timeout_ms);

/// Read an entire file into a newly allocated buffer using standard C stdio.
/// Used for loading custom Wireshark or IEEE OUI databases cross-platform
/// independently of standard library filesystem shifts.
/// Caller must release the buffer using free_file_content().
char *read_file_content(const char *path, size_t *out_len);
void free_file_content(char *ptr);

/// Query Windows SendARP (iphlpapi.dll) for an IP's physical address.
/// Serves as a zero-privilege fallback on Windows to identify the local scanning
/// host's own MAC address (which never appears in its own kernel arp table) as well
/// as ping-dropping devices. Returns -1 on non-Windows platforms.
int get_mac_sendarp(const char *ip_address, unsigned char out_mac[6]);

#endif

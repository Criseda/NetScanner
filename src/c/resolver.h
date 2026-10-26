#ifndef RESOLVER_H
#define RESOLVER_H

#include <stddef.h>

/// Resolve an IPv4 address to its reverse DNS PTR hostname using standard
/// getnameinfo(). Operates without elevated privileges by querying the system's
/// configured DNS resolver.
/// Returns 0 on success with a null-terminated hostname in out_buf, -1 on failure.
int resolve_ptr(const char *ip_address, char *out_buf, size_t out_len);

/// Query NetBIOS Node Status (RFC 1002, UDP port 137) with a bounded timeout.
/// Discovers Windows workstation names, Samba file servers, and NAS appliances
/// that ignore standard DNS PTR requests.
/// Returns 0 on success with a null-terminated name in out_buf, -1 on timeout/failure.
int query_netbios(const char *ip_address, char *out_buf, size_t out_len, int timeout_ms);

/// Send one UDP datagram to ip:port (4 bytes, network order) from an
/// ephemeral port and wait up to timeout_ms for one reply from that same
/// address. Used for the per-host unicast mDNS name query, whose packets
/// src/core/multicast.zig builds and parses. Returns the reply's length
/// in resp, or -1 on timeout or failure (on Windows, also at once when
/// the host answers with an ICMP port unreachable).
int udp_exchange(const unsigned char ip[4], unsigned short port,
                 const unsigned char *req, size_t req_len, unsigned char *resp,
                 size_t cap, int timeout_ms);

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

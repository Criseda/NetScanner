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

/// Query Multicast DNS reverse PTR (RFC 6762, UDP port 5353) with a bounded timeout.
/// Sends a unicast DNS PTR request directly to the target host to discover gaming
/// consoles (PlayStation, Nintendo), Apple devices, smart TVs, and IoT bridges
/// without needing a local mDNS responder daemon.
/// Returns 0 on success with a null-terminated name in out_buf, -1 on timeout/failure.
int query_mdns(const char *ip_address, char *out_buf, size_t out_len, int timeout_ms);

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

/// Dump the macOS kernel neighbour table via sysctl(NET_RT_FLAGS, RTF_LLINFO),
/// formatted as `arp -a` rows ("? (ip) at mac on ifname [ethernet]") so the
/// shared parser handles it unchanged. Exists because macOS 27 hides this table
/// from third-party binaries: a spawned `arp -a` always comes back empty, and a
/// direct sysctl only works when the caller is codesigned with a reverse-DNS
/// identifier (build.zig does that). Returns a malloc'd buffer the caller
/// releases with free_arp_table(), or NULL on failure / non-macOS platforms.
char *dump_arp_table(size_t *out_len);
void free_arp_table(char *ptr);

#endif

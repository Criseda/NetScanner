#ifndef NEIGHBORS_H
#define NEIGHBORS_H

#include <stddef.h>

/// How sure the kernel is that a neighbor is there right now.
enum {
  /// Confirmed within the last few seconds (Linux REACHABLE/DELAY,
  /// Windows NlnsReachable/NlnsDelay): fresh proof the host is present.
  NS_NEIGH_REACHABLE = 1,
  /// Resolved at some point but not confirmed lately (stale, probing,
  /// permanent, or macOS, which keeps no such state): the host may have
  /// left since, so it still needs a confirming ping.
  NS_NEIGH_STALE = 2,
};

/// One IPv4 neighbor-table entry. Dead entries (incomplete, failed,
/// unreachable) and multicast/broadcast rows are never returned.
typedef struct {
  unsigned char ip[4];
  unsigned char mac[6];
  unsigned char has_mac;
  unsigned char state; // NS_NEIGH_*
} ns_neighbor;

/// Read the kernel's IPv4 neighbor (ARP) table natively: netlink
/// RTM_GETNEIGH on Linux, GetIpNetTable2 on Windows, the sysctl route
/// dump on macOS. No process is spawned and no text is parsed.
/// On success returns 0 and a malloc'd array the caller releases with
/// free_neighbors(); -1 on failure.
///
/// macOS 27 hides this table from third-party binaries unless the caller
/// is codesigned with a reverse-DNS identifier (build.zig does that) and
/// launched from a shell; it then reads as empty, not as a failure.
int dump_neighbors(ns_neighbor **out, size_t *out_count);
void free_neighbors(ns_neighbor *ptr);

#endif

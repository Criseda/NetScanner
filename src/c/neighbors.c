#include "neighbors.h"

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <iphlpapi.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#endif

#ifdef __linux__
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/neighbour.h>
#include <sys/time.h>
#endif

#ifdef __APPLE__
#include <net/if_dl.h>
#include <net/route.h>
#include <stdint.h>
#include <sys/sysctl.h>
#endif

// ---------------------------------------------------------------------------
// Collecting entries: one growable array, filled by each OS's reader.
// ---------------------------------------------------------------------------

typedef struct {
  ns_neighbor *items;
  size_t len;
  size_t cap;
} neighbor_list;

/// Append one entry, unless it is not a real host: multicast and limited
/// broadcast addresses, or a broadcast MAC (Windows lists each subnet's
/// broadcast address as a permanent ff-ff-ff-ff-ff-ff row). Returns -1
/// only when out of memory.
static int list_add(neighbor_list *list, const unsigned char ip[4],
                    const unsigned char *mac, size_t mac_len,
                    unsigned char state) {
  if (ip[0] >= 224 || ip[0] == 0) return 0;
  static const unsigned char broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  int has_mac = mac != NULL && mac_len == 6;
  if (has_mac && memcmp(mac, broadcast, 6) == 0) return 0;

  if (list->len == list->cap) {
    size_t cap = list->cap ? list->cap * 2 : 64;
    ns_neighbor *grown = (ns_neighbor *)realloc(list->items, cap * sizeof(ns_neighbor));
    if (!grown) return -1;
    list->items = grown;
    list->cap = cap;
  }
  ns_neighbor *entry = &list->items[list->len++];
  memset(entry, 0, sizeof(*entry));
  memcpy(entry->ip, ip, 4);
  if (has_mac) memcpy(entry->mac, mac, 6);
  entry->has_mac = (unsigned char)has_mac;
  entry->state = state;
  return 0;
}

// ---------------------------------------------------------------------------
// Linux: netlink RTM_GETNEIGH dump.
// ---------------------------------------------------------------------------

#ifdef __linux__
/// What an `ip neigh` state means here, or 0 for dead entries. DELAY is
/// the kernel waiting a few seconds before re-probing an entry it just
/// used, so it counts as reachable (as the old `ip neigh` parsing did).
/// NOARP entries belong to links without ARP (loopback, tunnels).
static unsigned char linux_state(unsigned short nud) {
  if (nud & (NUD_REACHABLE | NUD_DELAY)) return NS_NEIGH_REACHABLE;
  if (nud & (NUD_STALE | NUD_PROBE | NUD_PERMANENT)) return NS_NEIGH_STALE;
  return 0;
}

/// Add every entry of one netlink reply to `list`. Returns 1 once the
/// dump is done, 0 to keep reading, -1 on error.
static int linux_parse(neighbor_list *list, char *buf, int len) {
  for (struct nlmsghdr *nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, (unsigned)len);
       nh = NLMSG_NEXT(nh, len)) {
    if (nh->nlmsg_type == NLMSG_DONE) return 1;
    if (nh->nlmsg_type == NLMSG_ERROR) return -1;
    if (nh->nlmsg_type != RTM_NEWNEIGH) continue;

    struct ndmsg *ndm = (struct ndmsg *)NLMSG_DATA(nh);
    if (ndm->ndm_family != AF_INET) continue;
    unsigned char state = linux_state(ndm->ndm_state);
    if (!state) continue;

    const unsigned char *ip = NULL;
    const unsigned char *mac = NULL;
    size_t mac_len = 0;
    int attr_len = (int)nh->nlmsg_len - (int)NLMSG_LENGTH(sizeof(*ndm));
    for (struct rtattr *rta = (struct rtattr *)((char *)ndm + NLMSG_ALIGN(sizeof(*ndm)));
         RTA_OK(rta, attr_len); rta = RTA_NEXT(rta, attr_len)) {
      if (rta->rta_type == NDA_DST && RTA_PAYLOAD(rta) == 4) {
        ip = (const unsigned char *)RTA_DATA(rta);
      } else if (rta->rta_type == NDA_LLADDR) {
        mac = (const unsigned char *)RTA_DATA(rta);
        mac_len = RTA_PAYLOAD(rta);
      }
    }
    if (ip && list_add(list, ip, mac, mac_len, state) != 0) return -1;
  }
  return 0;
}

static int linux_dump(neighbor_list *list) {
  int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  if (fd < 0) return -1;
  // A local dump answers at once; the timeout only guards against a
  // kernel that never sends NLMSG_DONE.
  struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  struct {
    struct nlmsghdr nh;
    struct ndmsg ndm;
  } req;
  memset(&req, 0, sizeof(req));
  req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
  req.nh.nlmsg_type = RTM_GETNEIGH;
  req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.nh.nlmsg_seq = 1;
  req.ndm.ndm_family = AF_INET;
  struct sockaddr_nl kernel;
  memset(&kernel, 0, sizeof(kernel));
  kernel.nl_family = AF_NETLINK;
  if (sendto(fd, &req, req.nh.nlmsg_len, 0, (struct sockaddr *)&kernel, sizeof(kernel)) < 0) {
    close(fd);
    return -1;
  }

  // Aligned for the nlmsghdr casts; 32 KiB holds a few hundred entries
  // per read, and the loop reads until the dump says it is done.
  long buf[32768 / sizeof(long)];
  int result = 0;
  while (result == 0) {
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) {
      result = -1;
      break;
    }
    result = linux_parse(list, (char *)buf, (int)n);
  }
  close(fd);
  return result < 0 ? -1 : 0;
}
#endif

// ---------------------------------------------------------------------------
// Windows: GetIpNetTable2 (iphlpapi).
// ---------------------------------------------------------------------------

#ifdef _WIN32
static unsigned char windows_state(NL_NEIGHBOR_STATE state) {
  switch (state) {
  case NlnsReachable:
  case NlnsDelay:
    return NS_NEIGH_REACHABLE;
  case NlnsStale:
  case NlnsProbe:
  case NlnsPermanent:
    return NS_NEIGH_STALE;
  default: // NlnsUnreachable, NlnsIncomplete: nobody answered.
    return 0;
  }
}

static int windows_dump(neighbor_list *list) {
  PMIB_IPNET_TABLE2 table = NULL;
  if (GetIpNetTable2(AF_INET, &table) != NO_ERROR) return -1;
  int result = 0;
  for (ULONG i = 0; i < table->NumEntries; i++) {
    const MIB_IPNET_ROW2 *row = &table->Table[i];
    unsigned char state = windows_state(row->State);
    if (!state || row->Address.si_family != AF_INET) continue;
    const unsigned char *ip = (const unsigned char *)&row->Address.Ipv4.sin_addr;
    if (list_add(list, ip, row->PhysicalAddress, row->PhysicalAddressLength, state) != 0) {
      result = -1;
      break;
    }
  }
  FreeMibTable(table);
  return result;
}
#endif

// ---------------------------------------------------------------------------
// macOS: sysctl(NET_RT_FLAGS, RTF_LLINFO) route dump.
// ---------------------------------------------------------------------------

#ifdef __APPLE__
/// Routing-socket sockaddrs are padded to 4-byte boundaries (same rounding as
/// Apple's arp.c), so the link-layer address sits after the rounded IPv4 one.
#define ARP_SA_ROUNDUP(a) \
  ((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))

/// macOS keeps no reachability state in this dump, so every resolved
/// entry counts as stale and gets the confirming ping.
static int macos_dump(neighbor_list *list) {
  int mib[6] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO};

  // The table can grow between sizing and reading, so retry with slack.
  char *raw = NULL;
  size_t raw_len = 0;
  for (int attempt = 0; attempt < 3; attempt++) {
    size_t needed = 0;
    if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
      free(raw);
      return -1;
    }
    raw_len = needed + needed / 2 + sizeof(struct rt_msghdr);
    free(raw);
    raw = (char *)malloc(raw_len);
    if (!raw) return -1;
    if (sysctl(mib, 6, raw, &raw_len, NULL, 0) == 0) break;
    if (errno != ENOMEM || attempt == 2) {
      free(raw);
      return -1;
    }
  }

  int result = 0;
  for (char *next = raw; next < raw + raw_len;) {
    struct rt_msghdr *rtm = (struct rt_msghdr *)next;
    if (rtm->rtm_msglen == 0) break;
    next += rtm->rtm_msglen;

    struct sockaddr_in *sin = (struct sockaddr_in *)(rtm + 1);
    if (sin->sin_family != AF_INET) continue;
    struct sockaddr_dl *sdl =
        (struct sockaddr_dl *)((char *)sin + ARP_SA_ROUNDUP(sin->sin_len));
    // Unresolved entries carry no link-layer address: nobody answered.
    if (sdl->sdl_family != AF_LINK || sdl->sdl_alen != 6) continue;
    if (list_add(list, (const unsigned char *)&sin->sin_addr,
                 (const unsigned char *)LLADDR(sdl), 6, NS_NEIGH_STALE) != 0) {
      result = -1;
      break;
    }
  }
  free(raw);
  return result;
}
#endif

int dump_neighbors(ns_neighbor **out, size_t *out_count) {
  if (!out || !out_count) return -1;
  neighbor_list list = {NULL, 0, 0};
  int result;
#if defined(__linux__)
  result = linux_dump(&list);
#elif defined(_WIN32)
  result = windows_dump(&list);
#elif defined(__APPLE__)
  result = macos_dump(&list);
#else
  result = -1;
#endif
  if (result != 0) {
    free(list.items);
    return -1;
  }
  *out = list.items;
  *out_count = list.len;
  return 0;
}

void free_neighbors(ns_neighbor *ptr) {
  if (ptr) free(ptr);
}

#include "multicast.h"

#include <string.h>

#ifdef _WIN32
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <Windows.h>
#include <iphlpapi.h>
#include <stdlib.h>
#include "win_wsa.h"
// Winsock's own value (_WSAIOW(IOC_VENDOR, 12)); not every SDK names it.
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

static uint32_t to_host_order(const unsigned char ip[4]) {
  return ((uint32_t)ip[0] << 24) | ((uint32_t)ip[1] << 16) |
         ((uint32_t)ip[2] << 8) | (uint32_t)ip[3];
}

// True when the subnet `addr`/`prefix` shares an address with first..last.
// A /32 is skipped: it is a point-to-point link (a VPN, typically), where
// there is no segment for multicast to reach.
static int subnet_overlaps(uint32_t addr, unsigned prefix, uint32_t first,
                           uint32_t last) {
  if (prefix == 0 || prefix >= 32) return 0;
  uint32_t mask = 0xFFFFFFFFu << (32 - prefix);
  uint32_t net = addr & mask;
  uint32_t broadcast = net | ~mask;
  return net <= last && broadcast >= first;
}

static void from_host_order(uint32_t value, unsigned char out[4]) {
  out[0] = (unsigned char)(value >> 24);
  out[1] = (unsigned char)(value >> 16);
  out[2] = (unsigned char)(value >> 8);
  out[3] = (unsigned char)value;
}

int mc_local_address(const unsigned char first[4], const unsigned char last[4],
                     unsigned char out_local[4]) {
  if (!first || !last || !out_local) return -1;
  const uint32_t lo = to_host_order(first);
  const uint32_t hi = to_host_order(last);
#ifdef _WIN32
  win_wsa_init_once();
  // The adapter list is sized on first ask; grow and retry if it grew
  // in between (an adapter came up).
  ULONG size = 16 * 1024;
  IP_ADAPTER_ADDRESSES *adapters = NULL;
  const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                      GAA_FLAG_SKIP_DNS_SERVER;
  ULONG ret = ERROR_BUFFER_OVERFLOW;
  for (int attempt = 0; attempt < 3 && ret == ERROR_BUFFER_OVERFLOW; attempt++) {
    free(adapters);
    adapters = (IP_ADAPTER_ADDRESSES *)malloc(size);
    if (!adapters) return -1;
    ret = GetAdaptersAddresses(AF_INET, flags, NULL, adapters, &size);
  }
  if (ret != NO_ERROR) {
    free(adapters);
    return -1;
  }
  int found = -1;
  for (IP_ADAPTER_ADDRESSES *a = adapters; a && found != 0; a = a->Next) {
    if (a->OperStatus != IfOperStatusUp) continue;
    if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
    for (IP_ADAPTER_UNICAST_ADDRESS *u = a->FirstUnicastAddress; u; u = u->Next) {
      const struct sockaddr_in *sin = (const struct sockaddr_in *)u->Address.lpSockaddr;
      if (!sin || sin->sin_family != AF_INET) continue;
      const uint32_t addr = ntohl(sin->sin_addr.s_addr);
      if (subnet_overlaps(addr, u->OnLinkPrefixLength, lo, hi)) {
        from_host_order(addr, out_local);
        found = 0;
        break;
      }
    }
  }
  free(adapters);
  return found;
#else
  struct ifaddrs *list = NULL;
  if (getifaddrs(&list) != 0) return -1;
  int found = -1;
  for (struct ifaddrs *i = list; i; i = i->ifa_next) {
    if (!i->ifa_addr || !i->ifa_netmask) continue;
    if (i->ifa_addr->sa_family != AF_INET) continue;
    if (!(i->ifa_flags & IFF_UP) || (i->ifa_flags & IFF_LOOPBACK)) continue;
    const uint32_t addr = ntohl(((struct sockaddr_in *)i->ifa_addr)->sin_addr.s_addr);
    const uint32_t mask = ntohl(((struct sockaddr_in *)i->ifa_netmask)->sin_addr.s_addr);
    unsigned prefix = 0;
    for (uint32_t m = mask; m & 0x80000000u; m <<= 1) prefix++;
    if (subnet_overlaps(addr, prefix, lo, hi)) {
      from_host_order(addr, out_local);
      found = 0;
      break;
    }
  }
  freeifaddrs(list);
  return found;
#endif
}

#ifdef _WIN32
typedef SOCKET native_socket;
#define CLOSE_SOCKET closesocket
#else
typedef int native_socket;
#define CLOSE_SOCKET close
#endif

mc_socket mc_open(const unsigned char local[4]) {
  if (!local) return MC_NO_SOCKET;
#ifdef _WIN32
  win_wsa_init_once();
  SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock == INVALID_SOCKET) return MC_NO_SOCKET;
  u_long nonblocking = 1;
  ioctlsocket(sock, FIONBIO, &nonblocking);
  // Windows reports an ICMP port-unreachable for an earlier send as
  // WSAECONNRESET on the next recvfrom, which would end the listener
  // the first time a name query hits a host without mDNS. Turn that off.
  BOOL report_resets = FALSE;
  DWORD returned = 0;
  WSAIoctl(sock, SIO_UDP_CONNRESET, &report_resets, sizeof(report_resets),
           NULL, 0, &returned, NULL, NULL);
#else
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) return MC_NO_SOCKET;
  int flags = fcntl(sock, F_GETFL, 0);
  if (flags >= 0) fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif

  // Port 0: an ephemeral port. Responders then answer by unicast to it
  // (mDNS "legacy unicast", RFC 6762 section 6.7; SSDP always does),
  // so nothing competes with the system's own responder on 5353/1900.
  struct sockaddr_in bind_addr;
  memset(&bind_addr, 0, sizeof(bind_addr));
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  bind_addr.sin_port = 0;
  if (bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) != 0) {
    CLOSE_SOCKET(sock);
    return MC_NO_SOCKET;
  }

  // Leave through the interface on the scanned subnet, not whichever
  // one the default route names (a VPN or a Hyper-V switch, say).
  struct in_addr out_if;
  memcpy(&out_if.s_addr, local, 4);
  setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, (const char *)&out_if, sizeof(out_if));
  // Link-local groups never cross a router anyway; say so explicitly.
#ifdef _WIN32
  DWORD ttl = 1;
#else
  unsigned char ttl = 1;
#endif
  setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, (const char *)&ttl, sizeof(ttl));
  // SSDP devices answer `ssdp:all` with a burst (one reply per service
  // they offer); a larger buffer keeps the burst from being dropped.
  int rcvbuf = 256 * 1024;
  setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const char *)&rcvbuf, sizeof(rcvbuf));
  return (mc_socket)sock;
}

int mc_send(mc_socket sock, const unsigned char ip[4], unsigned short port,
            const unsigned char *buf, size_t len) {
  if (sock == MC_NO_SOCKET || !ip || !buf) return -1;
  struct sockaddr_in dest;
  memset(&dest, 0, sizeof(dest));
  dest.sin_family = AF_INET;
  dest.sin_port = htons(port);
  memcpy(&dest.sin_addr.s_addr, ip, 4);
  int sent = (int)sendto((native_socket)sock, (const char *)buf, (int)len, 0,
                         (struct sockaddr *)&dest, sizeof(dest));
  return sent == (int)len ? 0 : -1;
}

int mc_recv(mc_socket sock, int timeout_ms, unsigned char *buf, size_t cap,
            unsigned char out_from[4]) {
  if (sock == MC_NO_SOCKET || !buf || !out_from) return -1;
#ifdef _WIN32
  SOCKET s = (SOCKET)sock;
  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(s, &rfds);
  struct timeval tv = {
      .tv_sec = timeout_ms / 1000,
      .tv_usec = (timeout_ms % 1000) * 1000,
  };
  int ready = select(0, &rfds, NULL, NULL, &tv);
  if (ready == 0) return 0;
  if (ready < 0) return -1;
  struct sockaddr_in from;
  int from_len = sizeof(from);
  int n = recvfrom(s, (char *)buf, (int)cap, 0, (struct sockaddr *)&from, &from_len);
  if (n < 0) {
    // Raced by nothing, or a datagram larger than the buffer: neither
    // ends the listener.
    int err = WSAGetLastError();
    return (err == WSAEWOULDBLOCK || err == WSAEMSGSIZE || err == WSAECONNRESET) ? 0 : -1;
  }
#else
  int s = (int)sock;
  struct pollfd pfd = {.fd = s, .events = POLLIN, .revents = 0};
  // A signal (Ctrl+C, a terminal resize) cuts the wait short with
  // EINTR; report "nothing yet" and let the caller's loop wait again.
  int ready = poll(&pfd, 1, timeout_ms);
  if (ready == 0) return 0;
  if (ready < 0) return errno == EINTR ? 0 : -1;
  struct sockaddr_in from;
  socklen_t from_len = sizeof(from);
  ssize_t n = recvfrom(s, buf, cap, 0, (struct sockaddr *)&from, &from_len);
  if (n < 0) {
    return (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ||
            errno == ECONNREFUSED)
               ? 0
               : -1;
  }
#endif
  if (from.sin_family != AF_INET) return 0;
  memcpy(out_from, &from.sin_addr.s_addr, 4);
  return (int)n;
}

void mc_wake(mc_socket sock) {
  if (sock == MC_NO_SOCKET) return;
  struct sockaddr_in self;
  memset(&self, 0, sizeof(self));
#ifdef _WIN32
  int self_len = sizeof(self);
#else
  socklen_t self_len = sizeof(self);
#endif
  if (getsockname((native_socket)sock, (struct sockaddr *)&self, &self_len) != 0) return;
  self.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sendto((native_socket)sock, "", 0, 0, (struct sockaddr *)&self, sizeof(self));
}

void mc_close(mc_socket sock) {
  if (sock != MC_NO_SOCKET) CLOSE_SOCKET((native_socket)sock);
}

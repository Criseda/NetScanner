#include "resolver.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ns_socket.h"

#ifdef _WIN32
#include <iphlpapi.h>
#include <windns.h>
#else
#include <netdb.h>
#endif

#ifdef _WIN32
// Windows asks DNS only. Its getnameinfo goes on, once DNS has no
// name, to LLMNR and then NetBIOS over TCP/IP, and an address nobody
// names took about 5s to give up (four routers, phones and smart
// plugs on one LAN, every run): most of what `--hostname` added to a
// sweep. ns sends its own NetBIOS and mDNS queries before this one,
// so those fallbacks only asked the same hosts again, more slowly;
// getnameinfo on Linux and macOS has none of them either.
int resolve_ptr(const char *ip_address, char *out_buf, size_t out_len) {
  if (!ip_address || !out_buf || out_len == 0) return -1;
  struct in_addr addr;
  if (ns_inet_pton(ip_address, &addr) != 1) return -1;
  const unsigned char *b = (const unsigned char *)&addr.s_addr;
  char query[32];
  snprintf(query, sizeof(query), "%u.%u.%u.%u.in-addr.arpa", b[3], b[2], b[1],
           b[0]);

  PDNS_RECORDA records = NULL;
  DNS_STATUS status =
      DnsQuery_A(query, DNS_TYPE_PTR,
                 DNS_QUERY_STANDARD | DNS_QUERY_NO_NETBT | DNS_QUERY_NO_MULTICAST,
                 NULL, (PDNS_RECORD *)&records, NULL);
  if (status != 0 || !records) return -1;
  int ret = -1;
  for (PDNS_RECORDA r = records; r; r = r->pNext) {
    if (r->wType != DNS_TYPE_PTR || !r->Data.PTR.pNameHost) continue;
    snprintf(out_buf, out_len, "%s", r->Data.PTR.pNameHost);
    ret = 0;
    break;
  }
  DnsRecordListFree((PDNS_RECORD)records, DnsFreeRecordList);
  return ret;
}
#else
int resolve_ptr(const char *ip_address, char *out_buf, size_t out_len) {
  ns_socket_init();
  if (!ip_address || !out_buf || out_len == 0) return -1;

  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  if (ns_inet_pton(ip_address, &sa.sin_addr) != 1) return -1;

  int ret = getnameinfo((struct sockaddr *)&sa, sizeof(sa), out_buf,
                        (socklen_t)out_len, NULL, 0, NI_NAMEREQD);
  return (ret == 0) ? 0 : -1;
}
#endif

void udp_exchange_all(const unsigned char ip[4], ns_udp_exchange *xs, int count,
                      int timeout_ms) {
  if (!xs || count <= 0) return;
  for (int i = 0; i < count; i++) xs[i].resp_len = -1;
  if (!ip || count > NS_WAIT_MAX || timeout_ms <= 0) return;

  struct sockaddr_in dest;
  memset(&dest, 0, sizeof(dest));
  dest.sin_family = AF_INET;
  memcpy(&dest.sin_addr.s_addr, ip, 4);

  // Each request gets a socket connected to its port, so only that
  // port's reply reaches it, and an ICMP port unreachable comes back
  // as an error on it (on every OS: an unconnected socket hears of one
  // only on Windows). waiting[] holds the sockets still waiting, and
  // owner[] which request each belongs to.
  ns_socket waiting[NS_WAIT_MAX];
  int owner[NS_WAIT_MAX];
  int pending = 0;
  for (int i = 0; i < count; i++) {
    ns_socket sock = ns_udp_socket();
    if (sock == NS_NO_SOCKET) continue;
    dest.sin_port = htons(xs[i].port);
    if (connect(sock, (struct sockaddr *)&dest, sizeof(dest)) != 0 ||
        send(sock, (const char *)xs[i].req, (int)xs[i].req_len, 0) != (int)xs[i].req_len) {
      ns_close(sock);
      continue;
    }
    waiting[pending] = sock;
    owner[pending] = i;
    pending++;
  }

  long long deadline = ns_now_ms() + timeout_ms;
  while (pending > 0) {
    long long left = deadline - ns_now_ms();
    int ready[NS_WAIT_MAX];
    if (left <= 0 || ns_wait_any(waiting, pending, (int)left, ready) <= 0) break;
    // Backwards, so moving the last socket into a settled one's slot
    // never skips one.
    for (int j = pending - 1; j >= 0; j--) {
      if (!ready[j]) continue;
      ns_udp_exchange *x = &xs[owner[j]];
      int n = recv(waiting[j], (char *)x->resp, (int)x->cap, 0);
      // Nothing there after all: keep waiting. Otherwise a reply, or
      // an error (the port refused), settles this request.
      if (n < 0 && ns_would_block()) continue;
      x->resp_len = n;
      ns_close(waiting[j]);
      pending--;
      waiting[j] = waiting[pending];
      owner[j] = owner[pending];
    }
  }
  for (int j = 0; j < pending; j++) ns_close(waiting[j]);
}

char *read_file_content(const char *path, size_t *out_len) {
  if (!path || !out_len) return NULL;
  FILE *f = fopen(path, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  long size = ftell(f);
  // Cap at 64 MB to avoid unbounded memory allocation on special or corrupt files
  if (size < 0 || size > 64 * 1024 * 1024) {
    fclose(f);
    return NULL;
  }
  fseek(f, 0, SEEK_SET);
  char *buf = (char *)malloc((size_t)size + 1);
  if (!buf) {
    fclose(f);
    return NULL;
  }
  size_t read_bytes = fread(buf, 1, (size_t)size, f);
  fclose(f);
  buf[read_bytes] = '\0';
  *out_len = read_bytes;
  return buf;
}

void free_file_content(char *ptr) {
  if (ptr) free(ptr);
}

int get_mac_sendarp(const char *ip_address, unsigned char out_mac[6]) {
#ifdef _WIN32
  win_wsa_init_once();
  if (!ip_address || !out_mac) return -1;
  struct in_addr addr;
  if (InetPtonA(AF_INET, ip_address, &addr) != 1) return -1;
  ULONG mac_len = 6;
  DWORD ret = SendARP(addr.s_addr, 0, (ULONG *)out_mac, &mac_len);
  return (ret == NO_ERROR && mac_len == 6) ? 0 : -1;
#else
  (void)ip_address;
  (void)out_mac;
  return -1;
#endif
}


#include "resolver.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <iphlpapi.h>
#include "win_wsa.h"
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#endif

int resolve_ptr(const char *ip_address, char *out_buf, size_t out_len) {
#ifdef _WIN32
  win_wsa_init_once();
#endif
  if (!ip_address || !out_buf || out_len == 0) return -1;

  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
#ifdef _WIN32
  if (InetPtonA(AF_INET, ip_address, &sa.sin_addr) != 1) return -1;
#else
  if (inet_pton(AF_INET, ip_address, &sa.sin_addr) != 1) return -1;
#endif

  int ret = getnameinfo((struct sockaddr *)&sa, sizeof(sa), out_buf,
                        (socklen_t)out_len, NULL, 0, NI_NAMEREQD);
  return (ret == 0) ? 0 : -1;
}

int query_netbios(const char *ip_address, char *out_buf, size_t out_len,
                  int timeout_ms) {
  if (!ip_address || !out_buf || out_len == 0 || timeout_ms <= 0) return -1;
#ifdef _WIN32
  win_wsa_init_once();
  SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock == INVALID_SOCKET) return -1;

  u_long nonblocking = 1;
  ioctlsocket(sock, FIONBIO, &nonblocking);
#else
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) return -1;

  int flags = fcntl(sock, F_GETFL, 0);
  if (flags >= 0) fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif

  struct sockaddr_in dest;
  memset(&dest, 0, sizeof(dest));
  dest.sin_family = AF_INET;
  dest.sin_port = htons(137);
#ifdef _WIN32
  if (InetPtonA(AF_INET, ip_address, &dest.sin_addr) != 1) {
    closesocket(sock);
    return -1;
  }
#else
  if (inet_pton(AF_INET, ip_address, &dest.sin_addr) != 1) {
    close(sock);
    return -1;
  }
#endif

  // RFC 1002 Node Status Request (50 bytes)
  static const unsigned char request[50] = {
      0x13, 0x37,             // Transaction ID
      0x00, 0x00,             // Flags: Query
      0x00, 0x01,             // QDCOUNT: 1
      0x00, 0x00,             // ANCOUNT: 0
      0x00, 0x00,             // NSCOUNT: 0
      0x00, 0x00,             // ARCOUNT: 0
      0x20,                   // Length 32
      'C',  'K',              // NetBIOS wildcard '*' encoded
      'A',  'A',  'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
      'A',  'A',  'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
      'A',  'A',  'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
      0x00,                   // Terminator
      0x00, 0x21,             // Type: NBSTAT
      0x00, 0x01              // Class: IN
  };

  int sent = sendto(sock, (const char *)request, sizeof(request), 0,
                    (struct sockaddr *)&dest, sizeof(dest));
  if (sent != sizeof(request)) {
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
    return -1;
  }

#ifdef _WIN32
  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(sock, &rfds);
  struct timeval tv = {
      .tv_sec = timeout_ms / 1000,
      .tv_usec = (timeout_ms % 1000) * 1000,
  };
  if (select(0, &rfds, NULL, NULL, &tv) <= 0) {
    closesocket(sock);
    return -1;
  }
#else
  struct pollfd pfd = {.fd = sock, .events = POLLIN, .revents = 0};
  if (poll(&pfd, 1, timeout_ms) <= 0) {
    close(sock);
    return -1;
  }
#endif
  struct sockaddr_in from;
#ifdef _WIN32
  int from_len = sizeof(from);
#else
  socklen_t from_len = sizeof(from);
#endif
  unsigned char resp[1024];
  int recv_len = recvfrom(sock, (char *)resp, sizeof(resp), 0,
                          (struct sockaddr *)&from, &from_len);
#ifdef _WIN32
  closesocket(sock);
#else
  close(sock);
#endif

  // Verify the packet actually came from our target IP, ignoring any stray broadcast traffic.
  if (from.sin_addr.s_addr != dest.sin_addr.s_addr) return -1;

  if (recv_len < 57) return -1;
  if (resp[0] != 0x13 || resp[1] != 0x37) return -1;

  int num_names = (int)resp[56];
  int offset = 57;

  for (int i = 0; i < num_names; i++) {
    if (offset + 18 > recv_len) break;
    unsigned char suffix = resp[offset + 15];
    unsigned short flags =
        (unsigned short)((resp[offset + 16] << 8) | resp[offset + 17]);
    int is_group = (flags & 0x8000) != 0;

    if (!is_group && (suffix == 0x00 || suffix == 0x20)) {
      int len = 15;
      while (len > 0 && resp[offset + len - 1] == ' ') {
        len--;
      }
      if (len > 0) {
        // Enforce printable ASCII to prevent terminal escape sequence injection
        int valid = 1;
        for (int j = 0; j < len; j++) {
          unsigned char c = resp[offset + j];
          if (c < 32 || c > 126) {
            valid = 0;
            break;
          }
        }
        if (!valid) continue;

        if ((size_t)len >= out_len) len = (int)(out_len - 1);
        memcpy(out_buf, &resp[offset], len);
        out_buf[len] = '\0';
        return 0;
      }
    }
    offset += 18;
  }

  return -1;
}

static int parse_dns_name(const unsigned char *pkt, size_t pkt_len, size_t pos,
                          char *out, size_t out_len) {
  size_t out_pos = 0;
  int depth = 0;

  while (pos < pkt_len && depth < 20) {
    unsigned char len = pkt[pos];
    if (len == 0) break;
    if ((len & 0xC0) == 0xC0) {
      if (pos + 1 >= pkt_len) return -1;
      pos = ((size_t)(len & 0x3F) << 8) | (size_t)pkt[pos + 1];
      depth++;
      continue;
    }
    pos++;
    if (pos + len > pkt_len) return -1;
    if (out_pos > 0 && out_pos + 1 < out_len) {
      out[out_pos++] = '.';
    }
    for (size_t i = 0; i < len && out_pos + 1 < out_len; i++) {
      unsigned char c = pkt[pos + i];
      if (c < 32 || c > 126) return -1; // Reject control characters and ANSI escape sequences
      out[out_pos++] = (char)c;
    }
    pos += len;
    depth++;
  }
  // Reject cyclic pointer loops and empty names
  if (depth >= 20 || out_pos == 0) return -1;
  if (out_pos < out_len) {
    out[out_pos] = '\0';
  } else {
    out[out_len - 1] = '\0';
  }
  return 0;
}

static int skip_dns_name(const unsigned char *pkt, size_t pkt_len, size_t *pos) {
  int depth = 0;
  while (*pos < pkt_len && depth < 20) {
    unsigned char len = pkt[*pos];
    if (len == 0) {
      (*pos)++;
      return 0;
    }
    if ((len & 0xC0) == 0xC0) {
      if (*pos + 1 >= pkt_len) return -1;
      *pos += 2;
      return 0;
    }
    *pos += 1 + len;
    depth++;
  }
  return -1;
}

int query_mdns(const char *ip_address, char *out_buf, size_t out_len, int timeout_ms) {
  if (!ip_address || !out_buf || out_len == 0 || timeout_ms <= 0) return -1;
#ifdef _WIN32
  win_wsa_init_once();
  SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock == INVALID_SOCKET) return -1;

  u_long nonblocking = 1;
  ioctlsocket(sock, FIONBIO, &nonblocking);
#else
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) return -1;

  int flags = fcntl(sock, F_GETFL, 0);
  if (flags >= 0) fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif

  struct sockaddr_in dest;
  memset(&dest, 0, sizeof(dest));
  dest.sin_family = AF_INET;
  dest.sin_port = htons(5353);
#ifdef _WIN32
  if (InetPtonA(AF_INET, ip_address, &dest.sin_addr) != 1) {
    closesocket(sock);
    return -1;
  }
#else
  if (inet_pton(AF_INET, ip_address, &dest.sin_addr) != 1) {
    close(sock);
    return -1;
  }
#endif

  unsigned int o[4];
  if (sscanf(ip_address, "%u.%u.%u.%u", &o[0], &o[1], &o[2], &o[3]) != 4) {
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
    return -1;
  }

  unsigned char req[512];
  req[0] = 0x00; req[1] = 0x01; // ID: 1
  req[2] = 0x00; req[3] = 0x00; // Query
  req[4] = 0x00; req[5] = 0x01; // QDCOUNT: 1
  req[6] = 0x00; req[7] = 0x00; // ANCOUNT: 0
  req[8] = 0x00; req[9] = 0x00; // NSCOUNT: 0
  req[10] = 0x00; req[11] = 0x00; // ARCOUNT: 0

  size_t idx = 12;
  char num_buf[16];
  for (int i = 3; i >= 0; i--) {
    int nlen = snprintf(num_buf, sizeof(num_buf), "%u", o[i]);
    req[idx++] = (unsigned char)nlen;
    memcpy(&req[idx], num_buf, (size_t)nlen);
    idx += (size_t)nlen;
  }
  req[idx++] = 7;
  memcpy(&req[idx], "in-addr", 7);
  idx += 7;
  req[idx++] = 4;
  memcpy(&req[idx], "arpa", 4);
  idx += 4;
  req[idx++] = 0x00; // end of name

  req[idx++] = 0x00; req[idx++] = 0x0C; // QTYPE: PTR
  req[idx++] = 0x00; req[idx++] = 0x01; // QCLASS: IN

  int sent = sendto(sock, (const char *)req, (int)idx, 0,
                    (struct sockaddr *)&dest, sizeof(dest));
  if (sent != (int)idx) {
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
    return -1;
  }

#ifdef _WIN32
  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(sock, &rfds);
  struct timeval tv = {
      .tv_sec = timeout_ms / 1000,
      .tv_usec = (timeout_ms % 1000) * 1000,
  };
  if (select(0, &rfds, NULL, NULL, &tv) <= 0) {
    closesocket(sock);
    return -1;
  }
#else
  struct pollfd pfd = {.fd = sock, .events = POLLIN, .revents = 0};
  if (poll(&pfd, 1, timeout_ms) <= 0) {
    close(sock);
    return -1;
  }
#endif

  struct sockaddr_in from;
#ifdef _WIN32
  int from_len = sizeof(from);
#else
  socklen_t from_len = sizeof(from);
#endif
  unsigned char resp[1024];
  int recv_len = recvfrom(sock, (char *)resp, sizeof(resp), 0,
                          (struct sockaddr *)&from, &from_len);
#ifdef _WIN32
  closesocket(sock);
#else
  close(sock);
#endif

  // Verify the response originated from our target IP (discards rogue LAN multicast echoes).
  if (from.sin_addr.s_addr != dest.sin_addr.s_addr) return -1;

  if (recv_len < 12) return -1;
  int qdcount = (resp[4] << 8) | resp[5];
  int ancount = (resp[6] << 8) | resp[7];
  if (ancount == 0) return -1;

  size_t pos = 12;
  for (int i = 0; i < qdcount; i++) {
    if (skip_dns_name(resp, (size_t)recv_len, &pos) != 0) return -1;
    if (pos + 4 > (size_t)recv_len) return -1;
    pos += 4; // skip QTYPE + QCLASS
  }

  for (int i = 0; i < ancount; i++) {
    if (skip_dns_name(resp, (size_t)recv_len, &pos) != 0) return -1;
    if (pos + 10 > (size_t)recv_len) return -1;
    unsigned short rtype = (unsigned short)((resp[pos] << 8) | resp[pos + 1]);
    unsigned short rdlen = (unsigned short)((resp[pos + 8] << 8) | resp[pos + 9]);
    pos += 10;
    if (rtype == 0x000C) { // PTR
      return parse_dns_name(resp, (size_t)recv_len, pos, out_buf, out_len);
    }
    if (pos + rdlen > (size_t)recv_len) return -1;
    pos += rdlen;
  }

  return -1;
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


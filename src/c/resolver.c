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
#include <errno.h>
#include <time.h>
#endif

#ifndef _WIN32
/* Wait up to timeout_ms for `sock` to turn readable: 1 if it did, 0 on
 * timeout or error. A signal handler running on this thread makes poll()
 * fail with EINTR, and poll is never restarted, even under SA_RESTART.
 * ns runs two while its status line is up (Ctrl+C, and the SIGWINCH
 * redraw on a terminal resize), so retry with whatever time is left
 * instead of dropping an answer that is still on its way. */
static int wait_readable(int sock, int timeout_ms) {
  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);
  struct pollfd pfd = {.fd = sock, .events = POLLIN, .revents = 0};
  int left = timeout_ms;
  for (;;) {
    int rc = poll(&pfd, 1, left);
    if (rc > 0) return 1;
    if (rc == 0 || errno != EINTR) return 0;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000L +
                      (now.tv_nsec - start.tv_nsec) / 1000000L;
    left = timeout_ms - (int)elapsed_ms;
    if (left <= 0) return 0;
  }
}
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
  if (!wait_readable(sock, timeout_ms)) {
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

  // A failed recvfrom (-1) leaves `from` unwritten, so the length comes
  // first. Then verify the packet actually came from our target IP,
  // ignoring any stray broadcast traffic.
  if (recv_len < 57 || (size_t)from_len < sizeof(from)) return -1;
  if (from.sin_addr.s_addr != dest.sin_addr.s_addr) return -1;
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

int udp_exchange(const unsigned char ip[4], unsigned short port,
                 const unsigned char *req, size_t req_len, unsigned char *resp,
                 size_t cap, int timeout_ms) {
  if (!ip || !req || !resp || cap == 0 || timeout_ms <= 0) return -1;
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
  dest.sin_port = htons(port);
  memcpy(&dest.sin_addr.s_addr, ip, 4);

  int sent = sendto(sock, (const char *)req, (int)req_len, 0,
                    (struct sockaddr *)&dest, sizeof(dest));
  if (sent != (int)req_len) {
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
  if (!wait_readable(sock, timeout_ms)) {
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
  int recv_len = recvfrom(sock, (char *)resp, (int)cap, 0,
                          (struct sockaddr *)&from, &from_len);
#ifdef _WIN32
  closesocket(sock);
#else
  close(sock);
#endif

  // A failed recvfrom (-1) leaves `from` unwritten, so the length comes
  // first. Then verify the reply came from the host we asked (discards
  // stray LAN multicast that happened to reach this port).
  if (recv_len < 0 || (size_t)from_len < sizeof(from)) return -1;
  if (from.sin_addr.s_addr != dest.sin_addr.s_addr) return -1;
  return recv_len;
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


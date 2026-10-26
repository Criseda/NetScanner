#ifndef NS_SOCKET_H
#define NS_SOCKET_H

// The ordinary socket calls that Winsock and POSIX spell differently,
// for the UDP helpers in resolver.c and multicast.c. With the per-OS
// lines here, each helper reads as one program instead of two
// interleaved ones, and a fix to one branch (the EINTR retry in
// ns_wait_readable, say) cannot be forgotten in the other.
//
// neighbors.c, icmp_ping.c and tcp_probe.c stay per-OS on purpose: the
// APIs themselves differ there, not just their spelling.
//
// Everything here is static inline, so each including .c file gets its
// own copy and an unused helper costs nothing.

#ifdef _WIN32
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include "win_wsa.h"

typedef SOCKET ns_socket;
typedef int ns_socklen;
#define NS_NO_SOCKET INVALID_SOCKET
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

typedef int ns_socket;
typedef socklen_t ns_socklen;
#define NS_NO_SOCKET (-1)
#endif

// Get the socket library ready: Winsock's one-time startup on Windows
// (see win_wsa.h), nothing elsewhere. Every helper that makes a
// socket call without ns_udp_socket (getnameinfo, say) calls it first.
static inline void ns_socket_init(void) {
#ifdef _WIN32
  win_wsa_init_once();
#endif
}

static inline void ns_close(ns_socket sock) {
#ifdef _WIN32
  closesocket(sock);
#else
  close(sock);
#endif
}

static inline void ns_set_nonblocking(ns_socket sock) {
#ifdef _WIN32
  u_long nonblocking = 1;
  ioctlsocket(sock, FIONBIO, &nonblocking);
#else
  int flags = fcntl(sock, F_GETFL, 0);
  if (flags >= 0) fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif
}

// A non-blocking IPv4 UDP socket, or NS_NO_SOCKET.
static inline ns_socket ns_udp_socket(void) {
  ns_socket_init();
  ns_socket sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock == NS_NO_SOCKET) return NS_NO_SOCKET;
  ns_set_nonblocking(sock);
  return sock;
}

// Parse dotted-quad `text` into `out`: 1 on success, as inet_pton.
static inline int ns_inet_pton(const char *text, struct in_addr *out) {
#ifdef _WIN32
  return InetPtonA(AF_INET, text, out);
#else
  return inet_pton(AF_INET, text, out);
#endif
}

// Wait up to timeout_ms for `sock` to turn readable: 1 if it did, 0 on
// timeout, -1 on error.
//
// On POSIX, a signal handler running on this thread makes poll() fail
// with EINTR, and poll is never restarted, even under SA_RESTART. ns
// runs two while its status line is up (Ctrl+C, and the SIGWINCH
// redraw on a terminal resize), so retry with whatever time is left
// instead of dropping an answer that is still on its way.
static inline int ns_wait_readable(ns_socket sock, int timeout_ms) {
#ifdef _WIN32
  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(sock, &rfds);
  struct timeval tv = {
      .tv_sec = timeout_ms / 1000,
      .tv_usec = (timeout_ms % 1000) * 1000,
  };
  int ready = select(0, &rfds, NULL, NULL, &tv);
  return ready > 0 ? 1 : ready;
#else
  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);
  struct pollfd pfd = {.fd = sock, .events = POLLIN, .revents = 0};
  int left = timeout_ms;
  for (;;) {
    int ready = poll(&pfd, 1, left);
    if (ready > 0) return 1;
    if (ready == 0) return 0;
    if (errno != EINTR) return -1;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000L +
                      (now.tv_nsec - start.tv_nsec) / 1000000L;
    left = timeout_ms - (int)elapsed_ms;
    if (left <= 0) return 0;
  }
#endif
}

#endif

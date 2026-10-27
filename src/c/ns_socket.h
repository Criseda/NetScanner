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

// Most sockets one ns_wait_any call watches.
#define NS_WAIT_MAX 8

// Wait up to timeout_ms for any of `socks` (at most NS_WAIT_MAX) to
// turn readable, setting ready[i] to 1 for each that did and 0 for the
// rest: how many did, 0 on timeout, -1 on error. A socket with an error
// pending (a connected UDP socket that got an ICMP port unreachable,
// say) counts as readable: the next recv reports the error.
//
// On POSIX, a signal handler running on this thread makes poll() fail
// with EINTR, and poll is never restarted, even under SA_RESTART. ns
// runs two while its status line is up (Ctrl+C, and the SIGWINCH
// redraw on a terminal resize), so retry with whatever time is left
// instead of dropping an answer that is still on its way.
static inline int ns_wait_any(const ns_socket *socks, int count, int timeout_ms,
                              int *ready) {
  if (count <= 0 || count > NS_WAIT_MAX) return -1;
#ifdef _WIN32
  fd_set rfds;
  FD_ZERO(&rfds);
  for (int i = 0; i < count; i++) FD_SET(socks[i], &rfds);
  struct timeval tv = {
      .tv_sec = timeout_ms / 1000,
      .tv_usec = (timeout_ms % 1000) * 1000,
  };
  int n = select(0, &rfds, NULL, NULL, &tv);
  for (int i = 0; i < count; i++) ready[i] = n > 0 && FD_ISSET(socks[i], &rfds);
  return n;
#else
  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);
  struct pollfd pfds[NS_WAIT_MAX];
  for (int i = 0; i < count; i++) {
    pfds[i] = (struct pollfd){.fd = socks[i], .events = POLLIN, .revents = 0};
  }
  int left = timeout_ms;
  for (;;) {
    int n = poll(pfds, (nfds_t)count, left);
    for (int i = 0; i < count; i++) ready[i] = n > 0 && pfds[i].revents != 0;
    if (n >= 0) return n;
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

// Wait up to timeout_ms for `sock` to turn readable: 1 if it did, 0 on
// timeout, -1 on error.
static inline int ns_wait_readable(ns_socket sock, int timeout_ms) {
  int ready;
  int n = ns_wait_any(&sock, 1, timeout_ms, &ready);
  return n > 0 ? 1 : n;
}

// A monotonic clock in milliseconds, for deadlines.
static inline long long ns_now_ms(void) {
#ifdef _WIN32
  return (long long)GetTickCount64();
#else
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (long long)now.tv_sec * 1000LL + now.tv_nsec / 1000000L;
#endif
}

// Whether the last failed recv on a non-blocking socket just found
// nothing there yet, rather than an error.
static inline int ns_would_block(void) {
#ifdef _WIN32
  return WSAGetLastError() == WSAEWOULDBLOCK;
#else
  return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
#endif
}

#endif

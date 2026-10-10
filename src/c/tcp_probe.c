#include "tcp_probe.h"

#ifdef _WIN32

// Winsock's fd_set holds FD_SETSIZE sockets (64 by default) and may be
// resized by defining it before the headers. It is a plain array plus a
// count, so unlike POSIX there is no ceiling on the socket values.
#define FD_SETSIZE TCP_PROBE_MAX_SOCKETS
#include "win_wsa.h"

#include <stdlib.h>
#include <string.h>
#include <WS2tcpip.h>
#include <mstcpip.h>

// Map a finished connection attempt to a verdict. Only an actively
// refused connection proves "closed but present"; every other error
// (timeout, unreachable network, ...) means "no answer".
static tcp_probe_result classify(int so_error) {
  switch (so_error) {
  case 0:
    return TCP_PROBE_OPEN;
  case WSAECONNREFUSED:
  case WSAECONNRESET:
    return TCP_PROBE_REFUSED;
  default:
    return TCP_PROBE_FILTERED;
  }
}

// Make a refusal surface the moment its RST arrives. By default Windows
// treats a RST to its SYN as a reason to try again, retransmitting the
// SYN twice before reporting "refused" -- about 2s later, every time,
// which made every closed port and every refusing host cost a full
// timeout. Turning SYN retransmissions off reports the RST at once
// (measured ~0.5ms on a LAN, was ~2020ms).
// With no retransmissions, a silent target fails after one initial RTO
// (WSAETIMEDOUT) instead of after our deadline, so the RTO is set to
// that deadline: the single SYN waits exactly as long as the caller
// asked, no shorter. Best effort: if Windows rejects the option, the
// probe still works, only slower to see refusals.
static void refuse_fast(SOCKET sock, int timeout_ms) {
  TCP_INITIAL_RTO_PARAMETERS params;
  params.Rtt = (USHORT)(timeout_ms > 0xFFFE ? 0xFFFE : timeout_ms);
  params.MaxSynRetransmissions = TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS;
  DWORD returned = 0;
  WSAIoctl(sock, SIO_TCP_INITIAL_RTO, &params, sizeof(params), NULL, 0,
           &returned, NULL, NULL);
}

tcp_probe_result tcp_probe_start(const unsigned char ip[4], unsigned short port,
                                 int timeout_ms, uintptr_t *out_sock) {
  win_wsa_init_once();

  SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock == INVALID_SOCKET) {
    return TCP_PROBE_FILTERED;
  }

  // Non-blocking so a dead host cannot stall us in SYN retransmits.
  u_long nonblocking = 1;
  if (ioctlsocket(sock, FIONBIO, &nonblocking) != 0) {
    closesocket(sock);
    return TCP_PROBE_FILTERED;
  }
  refuse_fast(sock, timeout_ms);

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  memcpy(&addr.sin_addr, ip, 4);

  if (connect(sock, (const struct sockaddr *)&addr, sizeof(addr)) == 0) {
    closesocket(sock);
    return TCP_PROBE_OPEN;
  }
  const int connect_error = WSAGetLastError();
  if (connect_error != WSAEWOULDBLOCK) {
    closesocket(sock);
    return classify(connect_error);
  }
  *out_sock = (uintptr_t)sock;
  return TCP_PROBE_PENDING;
}

static int compare_sockets(const void *a, const void *b) {
  const SOCKET x = *(const SOCKET *)a;
  const SOCKET y = *(const SOCKET *)b;
  return (x > y) - (x < y);
}

// select() rather than WSAPoll: before Windows 10 2004, WSAPoll did not
// report a failed connect at all, so every refusal would have looked
// like silence until its deadline. select() has always reported it,
// through the exception set.
int tcp_probe_wait(const uintptr_t *socks, int count, int wait_ms,
                   unsigned char *settled) {
  if (count > TCP_PROBE_MAX_SOCKETS) {
    count = TCP_PROBE_MAX_SOCKETS;
  }
  if (count <= 0) {
    return 0;
  }
  memset(settled, 0, (size_t)count);

  // Two sets of up to 4096 sockets are 64KB: too much for a stack, so
  // they live on the heap.
  fd_set *writable = malloc(sizeof(fd_set));
  fd_set *failed = malloc(sizeof(fd_set));
  if (writable == NULL || failed == NULL) {
    free(writable);
    free(failed);
    return -1;
  }
  // Filled directly: FD_SET scans the set for duplicates on every
  // call, which is quadratic over thousands of sockets.
  for (int i = 0; i < count; i++) {
    writable->fd_array[i] = (SOCKET)socks[i];
    failed->fd_array[i] = (SOCKET)socks[i];
  }
  writable->fd_count = (u_int)count;
  failed->fd_count = (u_int)count;

  struct timeval wait = {
      .tv_sec = wait_ms / 1000,
      .tv_usec = (wait_ms % 1000) * 1000,
  };
  const int ready = select(0, NULL, writable, failed, &wait);
  if (ready <= 0) {
    free(writable);
    free(failed);
    return ready < 0 ? -1 : 0;
  }

  // select() leaves only the ready sockets in each set. Sort them once
  // and look each watched socket up, instead of FD_ISSET's linear scan
  // per socket.
  const size_t ready_cap = (size_t)writable->fd_count + failed->fd_count;
  SOCKET *ready_socks = malloc(sizeof(SOCKET) * ready_cap);
  if (ready_socks == NULL) {
    free(writable);
    free(failed);
    return -1;
  }
  size_t ready_count = 0;
  for (u_int i = 0; i < writable->fd_count; i++) {
    ready_socks[ready_count++] = writable->fd_array[i];
  }
  for (u_int i = 0; i < failed->fd_count; i++) {
    ready_socks[ready_count++] = failed->fd_array[i];
  }
  free(writable);
  free(failed);
  qsort(ready_socks, ready_count, sizeof(SOCKET), compare_sockets);

  int settled_count = 0;
  for (int i = 0; i < count; i++) {
    const SOCKET sock = (SOCKET)socks[i];
    if (bsearch(&sock, ready_socks, ready_count, sizeof(SOCKET),
                compare_sockets) != NULL) {
      settled[i] = 1;
      settled_count++;
    }
  }
  free(ready_socks);
  return settled_count;
}

// A signaled socket has a verdict ready; an unsignaled one may still
// carry a late refusal, so the socket itself always has the final word.
// Only a signaled success counts as open -- anything still in flight
// at the deadline is "no answer", never "open".
tcp_probe_result tcp_probe_finish(uintptr_t raw_sock, int settled) {
  const SOCKET sock = (SOCKET)raw_sock;
  int so_error = 0;
  int opt_len = sizeof(so_error);
  const int read_failed =
      getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&so_error, &opt_len) != 0;
  closesocket(sock);
  if (read_failed || (!settled && so_error == 0)) {
    return TCP_PROBE_FILTERED;
  }
  return classify(so_error);
}

#endif

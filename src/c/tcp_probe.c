#include "tcp_probe.h"

#ifdef _WIN32

#include "win_wsa.h"

#include <string.h>
#include <WS2tcpip.h>

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

tcp_probe_result tcp_probe(const char *ip_address, unsigned short port,
                           int timeout_ms) {
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

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (InetPtonA(AF_INET, ip_address, &addr.sin_addr) != 1) {
    closesocket(sock);
    return TCP_PROBE_FILTERED;
  }

  if (connect(sock, (const struct sockaddr *)&addr, sizeof(addr)) == 0) {
    closesocket(sock);
    return TCP_PROBE_OPEN;
  }
  const int connect_error = WSAGetLastError();
  if (connect_error != WSAEWOULDBLOCK) {
    closesocket(sock);
    return classify(connect_error);
  }

  // Connection in progress: wait until the socket settles, but no
  // longer than our timeout. A signaled socket has a verdict ready;
  // an unsignaled one may still carry a late refusal, so the socket
  // itself always has the final word below. Only a signaled success
  // counts as open -- anything still in flight at the deadline is "no
  // answer", never "open".
  fd_set writable;
  FD_ZERO(&writable);
  FD_SET(sock, &writable);
  fd_set exceptional;
  FD_ZERO(&exceptional);
  FD_SET(sock, &exceptional);
  struct timeval wait = {
      .tv_sec = timeout_ms / 1000,
      .tv_usec = (timeout_ms % 1000) * 1000,
  };
  const int settled =
      select(0, NULL, &writable, &exceptional, &wait) > 0;

  int so_error = 0;
  int opt_len = sizeof(so_error);
  if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&so_error, &opt_len) !=
      0) {
    closesocket(sock);
    return TCP_PROBE_FILTERED;
  }
  closesocket(sock);
  if (!settled && so_error == 0) {
    return TCP_PROBE_FILTERED;
  }
  return classify(so_error);
}

#endif

#include "icmp_ping.h"

#include <stdlib.h>
#include <string.h>

// One sweep sends at most this many echoes per millisecond (2,000 a
// second): a /24 goes out in about 128 ms, never as one burst that a
// busy Wi-Fi link or a small router queue could drop part of (#37).
// Most echoes in a sweep go to empty addresses, and each of those
// first makes the OS broadcast an ARP request, which Wi-Fi sends at
// its slowest rate. At 16 a millisecond, a Wi-Fi /23 on macOS lost
// up to half its replies, the gateway's included (2 runs of 5 found
// 21 and 27 hosts of 40); at 2 it finds what ping(1) did. Large
// ranges barely notice: MAX_PINGS_IN_FLIGHT with a 1s wait already
// holds a sweep to about 500 echoes a second once it is under way.
#define SENDS_PER_MS 2

// Echo payload: a per-sweep token, so stray replies (another program's
// pings, or an earlier sweep's late ones) never count, and the host's
// index, so a reply finds its host without a lookup. 32 bytes in all,
// the size Windows' ping(1) sends.
#define PAYLOAD_LEN 32

typedef struct {
  uint32_t token;
  uint32_t index;
  uint8_t pad[PAYLOAD_LEN - 8];
} echo_payload;

// Where each host stands. Every host is reported exactly once, on
// leaving STATE_IN_FLIGHT (or on a send that failed outright).
enum { STATE_WAITING = 0, STATE_IN_FLIGHT = 1, STATE_REPORTED = 2 };

static void report(const icmp_ping_observer *observer, uint8_t *state,
                   size_t index, int answered) {
  state[index] = STATE_REPORTED;
  observer->pinged(observer->ctx, index, answered);
}

// How many more echoes the send rate allows, `elapsed_ms` into a sweep
// that has sent `sent` so far.
static size_t send_budget(int64_t elapsed_ms, size_t sent) {
  const size_t allowed = (size_t)(elapsed_ms + 1) * SENDS_PER_MS;
  return allowed > sent ? allowed - sent : 0;
}

#ifdef _WIN32

// ---------------------------------------------------------------------------
// Windows: IcmpSendEcho2 with a completion routine (APC). Windows owns
// the socket, the echo ID and the timeout; each echo in flight only
// needs a reply buffer of its own, from a pool of max_in_flight slots.
// Completion routines run on this thread, inside the alertable waits.
// ---------------------------------------------------------------------------

#include <WinSock2.h>
#include <Windows.h>
// winternl.h defines PIO_APC_ROUTINE; the macro tells icmpapi.h so,
// and it then declares IcmpSendEcho2 with that type (not FARPROC).
#include <winternl.h>
#ifndef PIO_APC_ROUTINE_DEFINED
#define PIO_APC_ROUTINE_DEFINED
#endif
#include <iphlpapi.h>
#include <icmpapi.h>

#ifndef CREATE_WAITABLE_TIMER_HIGH_RESOLUTION
#define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 0x00000002
#endif

// Room for the reply record, the echoed payload, an ICMP error's
// 8 bytes, and the IO_STATUS_BLOCK Windows appends for an APC.
#define REPLY_SIZE                                                             \
  (sizeof(ICMP_ECHO_REPLY) + PAYLOAD_LEN + 8 + sizeof(IO_STATUS_BLOCK) + 64)

struct sweep;

typedef struct slot {
  struct sweep *sweep;
  size_t index;
  struct slot *next_free;
  // ICMP_ECHO_REPLY holds pointers, so keep it pointer-aligned.
  union {
    void *align;
    unsigned char bytes[REPLY_SIZE];
  } reply;
} slot;

typedef struct sweep {
  const uint8_t (*ips)[4];
  const icmp_ping_observer *observer;
  uint8_t *state;
  slot *free_slots;
  size_t in_flight;
} sweep;

static void release(sweep *s, slot *sl) {
  sl->next_free = s->free_slots;
  s->free_slots = sl;
  s->in_flight--;
}

// An echo reply from the host itself. Everything else -- a timeout, or
// "destination unreachable" relayed from a router -- has a status other
// than IP_SUCCESS.
static int is_answer(const sweep *s, slot *sl) {
  if (IcmpParseReplies(sl->reply.bytes, REPLY_SIZE) == 0) return 0;
  const ICMP_ECHO_REPLY *reply = (const ICMP_ECHO_REPLY *)sl->reply.bytes;
  IPAddr expected;
  memcpy(&expected, s->ips[sl->index], 4);
  return reply->Status == IP_SUCCESS && reply->Address == expected;
}

// Milliseconds on a monotonic clock. Not GetTickCount64: it moves in
// ~15.6 ms steps, and each step would release a burst of echoes.
static int64_t now_ms(void) {
  LARGE_INTEGER frequency, counter;
  QueryPerformanceFrequency(&frequency);
  QueryPerformanceCounter(&counter);
  return (int64_t)(counter.QuadPart / (frequency.QuadPart / 1000));
}

static VOID NTAPI on_reply(PVOID context, PIO_STATUS_BLOCK status,
                           ULONG reserved) {
  (void)status;
  (void)reserved;
  slot *sl = (slot *)context;
  sweep *s = sl->sweep;
  const int answered = is_answer(s, sl);
  report(s->observer, s->state, sl->index, answered);
  release(s, sl);
}

// Sleep until a completion routine ran, or `ms` passed. The default
// timer tick is ~15.6 ms, which would turn a 1 ms pacing pause into a
// burst of 250 echoes; a high-resolution timer keeps the pacing even.
static void alertable_wait(HANDLE timer, DWORD ms) {
  if (timer != NULL) {
    LARGE_INTEGER due;
    due.QuadPart = -(LONGLONG)ms * 10000; // Relative, in 100 ns units.
    if (SetWaitableTimer(timer, &due, 0, NULL, NULL, FALSE)) {
      WaitForSingleObjectEx(timer, INFINITE, TRUE);
      return;
    }
  }
  SleepEx(ms, TRUE);
}

icmp_ping_result icmp_ping_sweep(const uint8_t (*ips)[4], size_t count,
                                 int timeout_ms, size_t max_in_flight,
                                 const icmp_ping_observer *observer) {
  if (count == 0) return ICMP_PING_DONE;
  if (max_in_flight == 0) max_in_flight = 1;
  if (max_in_flight > count) max_in_flight = count;

  HANDLE icmp = IcmpCreateFile();
  if (icmp == INVALID_HANDLE_VALUE) return ICMP_PING_UNAVAILABLE;

  uint8_t *state = calloc(count, 1);
  slot *slots = calloc(max_in_flight, sizeof(slot));
  if (state == NULL || slots == NULL) {
    free(state);
    free(slots);
    IcmpCloseHandle(icmp);
    return ICMP_PING_NO_MEMORY;
  }
  sweep s = {.ips = ips, .observer = observer, .state = state};
  for (size_t i = 0; i < max_in_flight; i++) {
    slots[i].sweep = &s;
    slots[i].next_free = s.free_slots;
    s.free_slots = &slots[i];
  }
  HANDLE timer = CreateWaitableTimerExW(
      NULL, NULL, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);

  echo_payload payload;
  memset(&payload, 0, sizeof(payload));
  const int64_t started = now_ms();
  size_t next = 0;
  int stopped = 0;
  for (;;) {
    if (!stopped && observer->stop_requested(observer->ctx)) stopped = 1;
    size_t budget = send_budget(now_ms() - started, next);
    while (!stopped && next < count && s.free_slots != NULL && budget > 0) {
      slot *sl = s.free_slots;
      s.free_slots = sl->next_free;
      s.in_flight++;
      sl->index = next;
      IPAddr dest;
      memcpy(&dest, ips[next], 4);
      payload.index = (uint32_t)next;
      state[next] = STATE_IN_FLIGHT;
      next++;
      budget--;
      const DWORD rc = IcmpSendEcho2(
          icmp, NULL, on_reply, sl, dest, &payload, sizeof(payload), NULL,
          sl->reply.bytes, REPLY_SIZE, (DWORD)timeout_ms);
      if (rc == 0 && GetLastError() == ERROR_IO_PENDING) continue;
      // Finished on the spot: no completion routine will run.
      const int answered = rc != 0 && is_answer(&s, sl);
      report(observer, state, sl->index, answered);
      release(&s, sl);
    }
    if (s.in_flight == 0 && (stopped || next == count)) break;
    // More to send and room for it: wait one pacing step. Otherwise
    // only a completion can change anything.
    const int can_send = !stopped && next < count && s.free_slots != NULL;
    alertable_wait(timer, can_send ? 1 : 50);
  }

  if (timer != NULL) CloseHandle(timer);
  IcmpCloseHandle(icmp);
  free(slots);
  free(state);
  return ICMP_PING_DONE;
}

#else

// ---------------------------------------------------------------------------
// Linux and macOS: unprivileged datagram ICMP sockets, a small pool of
// them (see ECHOES_PER_SOCKET). Echoes go out paced, replies are
// matched by the token and index in their payload, and a host still
// unanswered timeout_ms after its echo left counts as down. Echoes all share one timeout and leave in index order, so they
// also expire in index order: `oldest` walks up behind them.
// ---------------------------------------------------------------------------

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define ICMP_ECHO_REPLY_TYPE 0
#define ICMP_ECHO_REQUEST_TYPE 8
#define ICMP_HEADER_LEN 8

static int64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// The Internet checksum (RFC 1071). Linux fills it in for datagram ICMP
// sockets itself; macOS does not.
static uint16_t checksum(const uint8_t *data, size_t len) {
  uint32_t sum = 0;
  for (size_t i = 0; i + 1 < len; i += 2) {
    sum += (uint32_t)(data[i] << 8 | data[i + 1]);
  }
  if (len & 1) sum += (uint32_t)data[len - 1] << 8;
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
  return (uint16_t)~sum;
}

typedef enum { SEND_OK, SEND_BUSY, SEND_FAILED } send_outcome;

static send_outcome send_echo(int sock, const uint8_t ip[4], uint16_t ident,
                              uint32_t token, size_t index) {
  uint8_t packet[ICMP_HEADER_LEN + PAYLOAD_LEN];
  memset(packet, 0, sizeof(packet));
  packet[0] = ICMP_ECHO_REQUEST_TYPE;
  // Linux replaces the identifier with the socket's own; macOS keeps it.
  packet[4] = (uint8_t)(ident >> 8);
  packet[5] = (uint8_t)ident;
  packet[6] = (uint8_t)(index >> 8);
  packet[7] = (uint8_t)index;
  echo_payload payload;
  memset(&payload, 0, sizeof(payload));
  payload.token = token;
  payload.index = (uint32_t)index;
  memcpy(packet + ICMP_HEADER_LEN, &payload, sizeof(payload));
  const uint16_t sum = checksum(packet, sizeof(packet));
  packet[2] = (uint8_t)(sum >> 8);
  packet[3] = (uint8_t)sum;

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  memcpy(&addr.sin_addr, ip, 4);
  if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&addr,
             sizeof(addr)) >= 0) {
    return SEND_OK;
  }
  // A full send buffer clears as echoes leave; try again shortly.
  if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS ||
      errno == EINTR) {
    return SEND_BUSY;
  }
  // Unreachable network, a firewall, a broadcast address: no answer.
  return SEND_FAILED;
}

// The host index an echo reply answers, or -1 for anything that is not
// an echo reply to this sweep, from the host it was sent to.
static long match_reply(const uint8_t *buf, size_t len,
                        const struct sockaddr_in *from, uint16_t ident,
                        uint32_t token, const uint8_t (*ips)[4],
                        size_t count) {
  // macOS hands over the IP header too, Linux only the ICMP message. An
  // echo reply starts with type 0, an IPv4 header with version 4.
  size_t offset = 0;
  if (len > 0 && (buf[0] >> 4) == 4) offset = (size_t)(buf[0] & 0x0F) * 4;
  if (len < offset + ICMP_HEADER_LEN + sizeof(echo_payload)) return -1;
  const uint8_t *icmp = buf + offset;
  if (icmp[0] != ICMP_ECHO_REPLY_TYPE || icmp[1] != 0) return -1;
#ifndef __linux__
  // Linux only delivers this socket's replies; macOS delivers every
  // echo reply the host receives.
  if ((uint16_t)(icmp[4] << 8 | icmp[5]) != ident) return -1;
#else
  (void)ident;
#endif
  echo_payload payload;
  memcpy(&payload, icmp + ICMP_HEADER_LEN, sizeof(payload));
  if (payload.token != token || payload.index >= count) return -1;
  if (memcmp(&from->sin_addr, ips[payload.index], 4) != 0) return -1;
  return (long)payload.index;
}

// Echoes in flight per socket. An echo to a host on the local link
// waits in the kernel's ARP queue until the host's address resolves,
// up to ~3s for a host that is not there, and Linux charges it to the
// sending socket's buffer all that time. The default buffer (208 KiB,
// and unprivileged programs cannot raise it past net.core.wmem_max)
// holds only a few hundred of them, so on a large, mostly empty local
// network one socket runs out of room (EAGAIN) and stalls; a pool of
// sockets, each with a buffer of its own, keeps the echoes flowing.
#define ECHOES_PER_SOCKET 32
#define MAX_SOCKETS 16

// How long one echo may find every socket full before its host counts
// as unanswered. The kernel frees room as ARP gives up on absent hosts
// (~3s), so this only trips on a socket that never drains.
#define BUSY_GIVE_UP_MS 5000

// One non-blocking datagram ICMP socket, or -1. Linux refuses (EACCES)
// unless the user's group is inside net.ipv4.ping_group_range.
static int open_socket(void) {
  const int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
  if (sock < 0) return -1;
  const int flags = fcntl(sock, F_GETFL, 0);
  if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
    close(sock);
    return -1;
  }
  // Best effort: the kernel caps both at its *mem_max.
  int bufsize = 1 << 20;
  setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
  setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
  return sock;
}

icmp_ping_result icmp_ping_sweep(const uint8_t (*ips)[4], size_t count,
                                 int timeout_ms, size_t max_in_flight,
                                 const icmp_ping_observer *observer) {
  if (count == 0) return ICMP_PING_DONE;
  if (max_in_flight == 0) max_in_flight = 1;

  size_t wanted = (max_in_flight + ECHOES_PER_SOCKET - 1) / ECHOES_PER_SOCKET;
  if (wanted > MAX_SOCKETS) wanted = MAX_SOCKETS;
  struct pollfd socks[MAX_SOCKETS];
  size_t nsocks = 0;
  while (nsocks < wanted) {
    const int sock = open_socket();
    if (sock < 0) break;
    socks[nsocks++] = (struct pollfd){.fd = sock, .events = POLLIN};
  }
  // Not even one: the caller falls back to ping(1). Fewer than wanted
  // (out of descriptors, say) still works, just with less room.
  if (nsocks == 0) return ICMP_PING_UNAVAILABLE;

  uint8_t *state = calloc(count, 1);
  int64_t *sent_at = malloc(count * sizeof(int64_t));
  if (state == NULL || sent_at == NULL) {
    free(state);
    free(sent_at);
    for (size_t i = 0; i < nsocks; i++) close(socks[i].fd);
    return ICMP_PING_NO_MEMORY;
  }

  const int64_t started = now_ms();
  const uint16_t ident = (uint16_t)getpid();
  struct timespec seed;
  clock_gettime(CLOCK_REALTIME, &seed);
  const uint32_t token =
      (uint32_t)seed.tv_nsec ^ ((uint32_t)getpid() << 16) ^ (uint32_t)count;

  size_t next = 0;   // The next host to send to.
  size_t oldest = 0; // Every host below this one is reported.
  size_t in_flight = 0;
  int stopped = 0;
  int64_t busy_since = -1; // When `next` first found every socket full.
  for (;;) {
    int64_t now = now_ms();
    // Hosts whose wait is over, oldest first.
    while (oldest < next) {
      if (state[oldest] == STATE_IN_FLIGHT) {
        if (now < sent_at[oldest] + timeout_ms) break;
        report(observer, state, oldest, 0);
        in_flight--;
      }
      oldest++;
    }

    if (!stopped && observer->stop_requested(observer->ctx)) stopped = 1;
    int busy = 0;
    size_t budget = send_budget(now - started, next);
    while (!stopped && next < count && in_flight < max_in_flight &&
           budget > 0) {
      // Round robin, so every socket carries an even share; a full one
      // hands the echo on to the next.
      send_outcome sent = SEND_BUSY;
      for (size_t k = 0; k < nsocks && sent == SEND_BUSY; k++) {
        sent = send_echo(socks[(next + k) % nsocks].fd, ips[next], ident,
                         token, next);
      }
      if (sent == SEND_BUSY) {
        // Never report a host down that no echo reached: wait for room.
        if (busy_since < 0) busy_since = now;
        if (now - busy_since < BUSY_GIVE_UP_MS) {
          busy = 1;
          break;
        }
      }
      busy_since = -1;
      if (sent == SEND_OK) {
        state[next] = STATE_IN_FLIGHT;
        sent_at[next] = now;
        in_flight++;
      } else {
        report(observer, state, next, 0);
      }
      next++;
      budget--;
    }
    if (in_flight == 0 && (stopped || next == count)) break;

    // Sleep until the oldest echo's wait ends, or one pacing step when
    // more can go out now.
    int wait_ms = timeout_ms;
    if (oldest < next) wait_ms = (int)(sent_at[oldest] + timeout_ms - now);
    if (!stopped && next < count && (busy || in_flight < max_in_flight)) {
      wait_ms = 1;
    }
    if (wait_ms < 0) wait_ms = 0;
    // EINTR (a signal handler ran) just goes round the loop again.
    if (poll(socks, (nfds_t)nsocks, wait_ms) <= 0) continue;

    for (size_t i = 0; i < nsocks; i++) {
      if (!(socks[i].revents & POLLIN)) continue;
      for (;;) {
        uint8_t buf[512];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        const ssize_t n = recvfrom(socks[i].fd, buf, sizeof(buf), 0,
                                   (struct sockaddr *)&from, &from_len);
        if (n < 0) {
          if (errno == EINTR) continue;
          break; // EAGAIN: drained.
        }
        // macOS gives every socket a copy of every reply; the state
        // check counts each host once.
        const long index =
            match_reply(buf, (size_t)n, &from, ident, token, ips, count);
        if (index < 0 || state[index] != STATE_IN_FLIGHT) continue;
        report(observer, state, (size_t)index, 1);
        in_flight--;
      }
    }
  }

  free(sent_at);
  free(state);
  for (size_t i = 0; i < nsocks; i++) close(socks[i].fd);
  return ICMP_PING_DONE;
}

#endif

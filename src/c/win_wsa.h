#ifndef WIN_WSA_H
#define WIN_WSA_H

// One-time Winsock setup shared by the Windows helpers in ping.c and
// tcp_probe.c. Calling WSAStartup/WSACleanup per operation is wrong
// under threads: one thread's WSACleanup can tear down Winsock while
// another thread is mid-call, failing requests at random (#24). So
// each helper starts Winsock exactly once and balances it with one
// process-exit cleanup; process exit reclaims the rest.
//
// Everything here is static, so each including .c file gets its own
// copy: two files mean two startups and two matching cleanups, which
// stays balanced because WSAStartup/WSACleanup are reference counted.

#include <Windows.h>
#include <WinSock2.h>
#include <stdlib.h>

static INIT_ONCE win_wsa_once = INIT_ONCE_STATIC_INIT;

static void win_wsa_do_cleanup(void) { WSACleanup(); }

static BOOL CALLBACK win_wsa_do_startup(PINIT_ONCE once, PVOID param,
                                        PVOID *context) {
  (void)once;
  (void)param;
  (void)context;
  WSADATA wsa_data;
  if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
    return FALSE;
  }
  atexit(win_wsa_do_cleanup);
  return TRUE;
}

// Safe to call from any thread, any number of times. When startup
// itself fails there is nothing sensible to do here; the Winsock
// call that follows will fail and its caller reports it.
static inline void win_wsa_init_once(void) {
  InitOnceExecuteOnce(&win_wsa_once, win_wsa_do_startup, NULL, NULL);
}

#endif

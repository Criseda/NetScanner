#ifndef PING_H
#define PING_H

#include <stdbool.h>

bool ping_host(const char* ip_address);

#ifdef _WIN32
#include <Windows.h>

// Winsock error of the most recent failed ping_host call.
// Zero means no failure has been recorded yet.
DWORD ping_last_error(void);
#endif

#endif
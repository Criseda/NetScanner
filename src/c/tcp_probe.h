#ifndef TCP_PROBE_H
#define TCP_PROBE_H

// Result of one TCP connect attempt, mirroring ProbeOutcome in
// src/core/scanner.zig.
typedef enum {
  TCP_PROBE_OPEN, // Connected: the port is open.
  TCP_PROBE_REFUSED, // RST: the port is closed, but a host answered.
  TCP_PROBE_FILTERED, // Timeout or unreachable: no answer at all.
} tcp_probe_result;

// Windows-only: connect to ip:port, waiting at most timeout_ms.
// Zig's std.Io connect leaves its timeout unimplemented (as of 0.17
// it panics), so this uses the classic non-blocking + select recipe
// directly.
tcp_probe_result tcp_probe(const char *ip_address, unsigned short port,
                           int timeout_ms);

#endif

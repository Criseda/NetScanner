#include "ping.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PING_TIMEOUT_MS 1000

#ifdef _WIN32
// Windows implementation
#include <Windows.h>
#include <minwindef.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <IPExport.h>
#include <icmpapi.h>

bool ping_host(const char *ip_address) {
  HANDLE hIcmp;
  char send_data[32] = "ping test";
  LPVOID reply_buffer;
  DWORD reply_size;
  IPAddr ip_addr;

  // Initialize Winsock
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
    return false;
  }

  hIcmp = IcmpCreateFile();
  if (hIcmp == INVALID_HANDLE_VALUE) {
    WSACleanup();
    return false;
  }

  // Convert IP address string to network byte order
  ip_addr = inet_addr(ip_address);
  if (ip_addr == INADDR_NONE) {
    IcmpCloseHandle(hIcmp);
    WSACleanup();
    return false;
  }

  reply_size = sizeof(ICMP_ECHO_REPLY) + sizeof(send_data);
  reply_buffer = (VOID *)malloc(reply_size);

  if (IcmpSendEcho(hIcmp, ip_addr, send_data, sizeof(send_data), NULL,
                   reply_buffer, reply_size, PING_TIMEOUT_MS) != 0) {
    free(reply_buffer);
    IcmpCloseHandle(hIcmp);
    WSACleanup();
    return true;
  } else {
    free(reply_buffer);
    IcmpCloseHandle(hIcmp);
    WSACleanup();
    return false;
  }
}

#elif defined(__APPLE__)
// macOS implementation - use system ping command
bool ping_host(const char *ip_address) {
  char cmd[256];

  // Build a command that will exit with status 0 if the host responds
  // -c 1: send one packet
  // -W 1: wait max 1 second
  // -q: quiet output
  snprintf(cmd, sizeof(cmd), "ping -c 1 -W 1 -q %s > /dev/null 2>&1",
           ip_address);

  // Execute command and check its exit status
  int result = system(cmd);

  // Return true if ping succeeded (exit status 0)
  return (result == 0);
}

#else
// Linux implementation
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

// ICMP packet checksum calculation
unsigned short in_cksum(unsigned short *addr, int len) {
  int nleft = len;
  int sum = 0;
  unsigned short *w = addr;
  unsigned short answer = 0;

  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }

  if (nleft == 1) {
    *(unsigned char *)(&answer) = *(unsigned char *)w;
    sum += answer;
  }

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  answer = ~sum;
  return answer;
}

// Simplified Linux ping implementation using raw sockets
bool ping_host(const char *ip_address) {
  // For testing non-root access, fall back to system ping
  if (geteuid() != 0) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ping -c 1 -W 1 -q %s > /dev/null 2>&1",
             ip_address);
    return system(cmd) == 0;
  }

  // Normal raw socket implementation (requires root)
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sock < 0) {
    return false;
  }

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(ip_address);

  struct timeval timeout;
  timeout.tv_sec = PING_TIMEOUT_MS / 1000;
  timeout.tv_usec = (PING_TIMEOUT_MS % 1000) * 1000;
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

  // Create ICMP packet
  char send_data[32] = "ping test";
  const size_t packet_size = sizeof(struct icmphdr) + sizeof(send_data);
  char packet[packet_size];
  struct icmphdr *icmp_header = (struct icmphdr *)packet;

  // Set up ICMP header
  icmp_header->type = ICMP_ECHO;
  icmp_header->code = 0;
  icmp_header->un.echo.id = getpid() & 0xFFFF;
  icmp_header->un.echo.sequence = 1;

  // Copy payload after the ICMP header
  memcpy(packet + sizeof(struct icmphdr), send_data, sizeof(send_data));
  icmp_header->checksum = 0;
  icmp_header->checksum = in_cksum((unsigned short *)packet, packet_size);

  // Send the packet
  if (sendto(sock, packet, packet_size, 0, (struct sockaddr *)&addr,
             sizeof(addr)) <= 0) {
    close(sock);
    return false;
  }

  // Wait for response
  char reply[1024];
  struct sockaddr_in from;
  socklen_t fromlen = sizeof(from);
  int received = recvfrom(sock, reply, sizeof(reply), 0,
                          (struct sockaddr *)&from, &fromlen);
  close(sock);

  // Simple check: did we get any reply from the target?
  return (received > 0 && from.sin_addr.s_addr == addr.sin_addr.s_addr);
}
#endif
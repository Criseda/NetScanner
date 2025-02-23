#include "../include/ping.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <minwindef.h>
#include <IPExport.h>
#include <WS2tcpip.h>
#include <WinSock2.h>
#include <Windows.h>
#include <icmpapi.h>
#include <iphlpapi.h>
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#define PING_TIMEOUT_MS 1000
#define ICMP_ECHO_REQUEST 8

bool ping_host(const char* ip_address) {
#ifdef _WIN32
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
  reply_buffer = (VOID*)malloc(reply_size);

  if (IcmpSendEcho(hIcmp, ip_addr, send_data, sizeof(send_data), NULL,
                   reply_buffer, reply_size, PING_TIMEOUT_MS) != 0) {
    free(reply_buffer);
    IcmpCloseHandle(hIcmp);
    WSACleanup();
    return true;
  } else {  // Added else block to handle IcmpSendEcho failure
    free(reply_buffer);
    IcmpCloseHandle(hIcmp);
    WSACleanup();
    return false;
  }

#else
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sock < 0) {
    return false;
  }

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(ip_address);

  // Set socket timeout
  struct timeval timeout;
  timeout.tv_sec = PING_TIMEOUT_MS / 1000;
  timeout.tv_usec = (PING_TIMEOUT_MS % 1000) * 1000;

  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

  // Prepare ICMP packet
  uint8_t packet[64];
  struct icmp* icmp_header = (struct icmp*)packet;

  icmp_header->icmp_type = ICMP_ECHO_REQUEST;
  icmp_header->icmp_code = 0;
  icmp_header->icmp_cksum = 0;
  icmp_header->icmp_id = getpid();
  icmp_header->icmp_seq = 1;

  // Send ICMP packet
  if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr*)&addr,
             sizeof(addr)) <= 0) {
    close(sock);
    return false;
  }

  // Receive response
  uint8_t reply[512];
  if (recvfrom(sock, reply, sizeof(reply), 0, NULL, NULL) <= 0) {
    close(sock);
    return false;
  }

  close(sock);
  return true;
#endif
}
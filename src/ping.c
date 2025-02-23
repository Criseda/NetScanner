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

// Add after the includes, before ping_host function
#ifndef _WIN32
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
#endif

bool ping_host(const char *ip_address) {
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
  reply_buffer = (VOID *)malloc(reply_size);

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

  struct timeval timeout;
  timeout.tv_sec = PING_TIMEOUT_MS / 1000;
  timeout.tv_usec = (PING_TIMEOUT_MS % 1000) * 1000;
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

  // Prepare ICMP packet with header and payload
  char send_data[32] = "ping test";  // payload
  const size_t packet_size = sizeof(struct icmp) + sizeof(send_data);
  char packet[packet_size];
  struct icmp *icmp_header = (struct icmp *)packet;
  icmp_header->icmp_type = ICMP_ECHO;
  icmp_header->icmp_code = 0;
  icmp_header->icmp_id = getpid() & 0xFFFF;
  icmp_header->icmp_seq = 1;
  // Copy payload after the ICMP header
  memcpy(packet + sizeof(struct icmp), send_data, sizeof(send_data));
  icmp_header->icmp_cksum = 0;
  icmp_header->icmp_cksum = in_cksum((unsigned short *)packet, packet_size);

  // Send the complete packet
  if (sendto(sock, packet, packet_size, 0, (struct sockaddr *)&addr,
             sizeof(addr)) <= 0) {
    close(sock);
    return false;
  }

  // Wait for a response (rest of the code follows unchanged)
  char reply[1024];
  struct sockaddr_in from;
  socklen_t fromlen = sizeof(from);

  int received = recvfrom(sock, reply, sizeof(reply), 0,
                          (struct sockaddr *)&from, &fromlen);

  if (received <= (int)(sizeof(struct ip) + sizeof(struct icmp))) {
    close(sock);
    return false;
  }

  // Verify the reply came from the intended host
  if (from.sin_addr.s_addr != addr.sin_addr.s_addr) {
    close(sock);
    return false;
  }

  // Skip IP header to get to ICMP header
  struct ip *ip_header = (struct ip *)reply;
  int ip_header_len = ip_header->ip_hl * 4;
  if (received < ip_header_len + (int)sizeof(struct icmp)) {
    close(sock);
    return false;
  }

  struct icmp *icmp_reply = (struct icmp *)(reply + ip_header_len);
  close(sock);

  // Validate that we received an ECHO REPLY with our ID
  return (icmp_reply->icmp_type == ICMP_ECHOREPLY &&
          icmp_reply->icmp_id == (getpid() & 0xFFFF));
#endif
}
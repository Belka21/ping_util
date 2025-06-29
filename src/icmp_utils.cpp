#include "icmp_utils.h"

#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>

#include <cstring>
#include <stdexcept>

// Вычисление контрольной суммы ICMP (RFC 1071)
unsigned short checksum(void* buffer, size_t length) {
  unsigned int sum = 0;

  if (buffer != nullptr && length != 0) {
    unsigned char* buf = (unsigned char*)buffer;

    while (length > 1) {
      unsigned short word;
      memcpy(&word, buf, sizeof(word));
      sum += word;
      buf += 2;
      length -= 2;
    }

    // если длина нечётная
    if (length == 1) {
      unsigned short word = *buf;
      sum += word;
    }

    // 32-битная сумма в 16 бит
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
  }

  return ~sum;
}

// Отправка ICMP Echo Request
void send_icmp_echo(int sockfd, const std::string& target_ip) {
  struct sockaddr_in dest_addr;
  memset(&dest_addr, 0, sizeof(dest_addr));
  dest_addr.sin_family = AF_INET;
  if (inet_pton(AF_INET, target_ip.c_str(), &dest_addr.sin_addr) != 1) {
    throw std::runtime_error("Invalid target IP address");
  }

  icmp_packet packet;
  memset(&packet, 0, sizeof(packet));

  packet.header.type = ICMP_ECHO;
  packet.header.code = 0;
  packet.header.un.echo.id = htons((uint16_t)getpid());
  packet.header.un.echo.sequence = htons(1);
  memset(packet.payload, 'A', sizeof(packet.payload));
  packet.payload[sizeof(packet.payload) - 1] = '\0';

  packet.header.checksum = checksum(&packet, sizeof(packet));

  if (sendto(sockfd, &packet, sizeof(packet), 0, (struct sockaddr*)&dest_addr,
             sizeof(dest_addr)) <= 0) {
    throw std::runtime_error("Failed to send ICMP packet");
  }
}

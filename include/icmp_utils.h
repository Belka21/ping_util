#pragma once

#include <netinet/ip_icmp.h>
#include <string>

struct icmp_packet {
    struct icmphdr header;
    char payload[64];
};

unsigned short checksum(void* buffer, size_t length);
void send_icmp_echo(int sockfd, const std::string& target_ip);

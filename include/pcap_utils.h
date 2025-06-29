#pragma once
#include <string>
#include <net/ethernet.h>
#include <pcap.h>

struct CallbackData {
    struct ether_addr target_mac;
    bool reply_received;
};

void packet_handler(u_char* user_data, const struct pcap_pkthdr* header,
                    const u_char* packet);

void get_mac_address(const std::string& interface,
                     const std::string& target_ip);

#include "pcap_utils.h"

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <pcap.h>

#include <cstring>
#include <ctime>
#include <iostream>
#include <stdexcept>

#include "network_utils.h"

// Callback-функция для обработки пакетов
void packet_handler(u_char* user_data, const struct pcap_pkthdr* header,
                    const u_char* packet) {
  if (!user_data) {
    std::cerr << "Error: user_data is nullptr (callback context missing)"
              << std::endl;
    return;
  }

  if (!header) {
    std::cerr << "Error: pcap_pkthdr is nullptr" << std::endl;
    return;
  }

  if (!packet) {
    std::cerr << "Error: packet data is nullptr" << std::endl;
    return;
  }

  CallbackData* data = reinterpret_cast<CallbackData*>(user_data);

  if (header->len < sizeof(struct ether_header) + sizeof(struct iphdr)) {
    std::cerr << "Packet too small to be IPv4" << std::endl;
    return;
  }

  // Извлекаем MAC-адрес из Ethernet-заголовка
  struct ether_header* eth_header = (struct ether_header*)packet;
  memcpy(&data->target_mac, eth_header->ether_shost, sizeof(data->target_mac));
  data->reply_received = true;
}

// Получение MAC адреса из ответа
void get_mac_address(const std::string& interface,
                     const std::string& target_ip) {
  if (!is_interface_exists(interface)) {
    throw std::runtime_error("Network interface '" + interface +
                             "' does not exist");
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 4000, errbuf);
  if (!handle) {
    throw std::runtime_error("Could not open device: " + std::string(errbuf));
  }

  // BPF-фильтр
  std::string filter = "icmp and src host " + target_ip + " and icmp[0] == 0";

  struct bpf_program fp;
  if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) ==
      -1) {
    pcap_close(handle);
    throw std::runtime_error("Could not parse filter: " +
                             std::string(pcap_geterr(handle)));
  }

  if (pcap_setfilter(handle, &fp) == -1) {
    pcap_close(handle);
    throw std::runtime_error("Could not install filter: " +
                             std::string(pcap_geterr(handle)));
  }

  // Ожидаем ответ (с таймаутом)
  CallbackData data = {};
  data.reply_received = false;

  pcap_setnonblock(handle, 1, errbuf);
  time_t start = time(nullptr);
  while (time(nullptr) - start < 10) {
    int ret = pcap_dispatch(handle, 1, packet_handler,
                            reinterpret_cast<u_char*>(&data));
    if (ret > 0) break;  // получили пакет
    if (ret == -1) {
    }  // пакета нет
  }
  pcap_close(handle);

  if (!data.reply_received) {
    throw std::runtime_error(
        "No ICMP reply received (timeout or filter mismatch)");
  }

  printf(
      "Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
      data.target_mac.ether_addr_octet[0], data.target_mac.ether_addr_octet[1],
      data.target_mac.ether_addr_octet[2], data.target_mac.ether_addr_octet[3],
      data.target_mac.ether_addr_octet[4], data.target_mac.ether_addr_octet[5]);
}

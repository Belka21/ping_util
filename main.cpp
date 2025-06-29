#include <arpa/inet.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std;

// Структура для ICMP пакета
struct icmp_packet {
  struct icmphdr header;
  char payload[64];
};

// Структура для хранения данных callback
struct CallbackData {
  ether_addr target_mac;
  bool reply_received;
};

// Функция вычисления контрольной суммы ICMP (RFC 1071)
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

    // cвёртывание 32-битной суммы в 16 бит
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
  }

  return ~sum;
}

// Проверка существования интерфейса
bool is_interface_exists(const std::string& interface) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    std::cerr << "socket() failed: " << strerror(errno) << std::endl;
    return false;
  }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);

  // Попробуем получить флаги интерфейса
  int result = ioctl(fd, SIOCGIFFLAGS, &ifr);
  if (result < 0) {
    std::cerr << "ioctl(SIOCGIFFLAGS) failed for interface '"
              << interface << "': " << strerror(errno) << " (" << errno << ")"
              << std::endl;
  } else {
    std::cout << "Interface '" << interface << "' exists with flags: 0x"
              << std::hex << ifr.ifr_flags << std::dec << std::endl;
  }

  close(fd);
  return (result >= 0);
}

// Callback-функция для обработки пакетов
void packet_handler(u_char* user_data, const struct pcap_pkthdr* header,
                    const u_char* packet) {
  if (!user_data) {
    cerr << "Error: user_data is nullptr (callback context missing)" << endl;
    return;
  }

  if (!header) {
    cerr << "Error: pcap_pkthdr is nullptr" << endl;
    return;
  }

  if (!packet) {
    cerr << "Error: packet data is nullptr" << endl;
    return;
  }

  CallbackData* data = reinterpret_cast<CallbackData*>(user_data);

  if (header->len < sizeof(struct ether_header) + sizeof(struct iphdr)) {
    cerr << "Packet too small to be IPv4" << endl;
    return;
  }

  // Извлекаем MAC-адрес из Ethernet-заголовка
  struct ether_header* eth_header = (struct ether_header*)packet;
  memcpy(&data->target_mac, eth_header->ether_shost, sizeof(data->target_mac));
  data->reply_received = true;
}

// Запрос маршрута по умолчанию
string get_default_interface() {
  ifstream route_file("/proc/net/route");
  string line;

  getline(route_file, line);

  while (getline(route_file, line)) {
    istringstream iss(line);
    string iface;
    unsigned long dest;

    iss >> iface >> hex >> dest;

    if (dest == 0) {
      return iface;
    }
  }

  throw runtime_error("Default route not found");
}

// Отправка ICMP Echo Request
void send_icmp_echo(int sockfd, const string& target_ip) {
  struct sockaddr_in dest_addr;
  memset(&dest_addr, 0, sizeof(dest_addr));
  dest_addr.sin_family = AF_INET;
  if (inet_pton(AF_INET, target_ip.c_str(), &dest_addr.sin_addr) != 1) {
    throw runtime_error("Invalid target IP address");
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
    throw runtime_error("Failed to send ICMP packet");
  }
}

// Получение MAC адреса из ответа
void get_mac_address(const string& interface, const string& target_ip) {
  if (!is_interface_exists(interface)) {
    throw runtime_error("Network interface '" + interface + "' does not exist");
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 4000, errbuf);
  if (!handle) {
    throw runtime_error("Could not open device: " + string(errbuf));
  }

  // BPF-фильтр
  string filter = "icmp and src host " + target_ip + " and icmp[0] == 0";

  struct bpf_program fp;
  if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) ==
      -1) {
    pcap_close(handle);
    throw runtime_error("Could not parse filter: " +
                        string(pcap_geterr(handle)));
  }

  if (pcap_setfilter(handle, &fp) == -1) {
    pcap_close(handle);
    throw runtime_error("Could not install filter: " +
                        string(pcap_geterr(handle)));
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
    throw runtime_error("No ICMP reply received (timeout or filter mismatch)");
  }

  printf(
      "Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
      data.target_mac.ether_addr_octet[0], data.target_mac.ether_addr_octet[1],
      data.target_mac.ether_addr_octet[2], data.target_mac.ether_addr_octet[3],
      data.target_mac.ether_addr_octet[4], data.target_mac.ether_addr_octet[5]);
}

int main(int argc, char* argv[]) {
  string interface;
  string target_ip;

  try {
    if (argc < 2 || argc > 3) {
      cerr << "Usage: " << argv[0] << " <target_ip> [interface]" << endl;
      cerr << "If interface is not specified, will use default route interface"
           << endl;
      return 1;
    }

    target_ip = argv[1];

    if (argc == 3) {
      interface = argv[2];
    } else {
      interface = get_default_interface();
      cout << "Using default interface: " << interface << endl;
    }

    if (getuid() != 0) {
      throw runtime_error("This program requires root privileges");
    }

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
      throw runtime_error("Failed to create raw socket");
    }

    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
      close(sockfd);
      throw runtime_error("Failed to set socket timeout");
    }

    send_icmp_echo(sockfd, target_ip);
    get_mac_address(interface, target_ip);

    close(sockfd);
  }
  catch(const exception& e) {
    cerr << "Error: " << e.what() << endl;
    return 1;
  }

  return 0;
}

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
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std;

// Структура для ICMP пакета
struct icmp_packet {
  struct icmphdr header;
  char payload[64];
};

// Функция вычисления контрольной суммы ICMP (RFC 1071)
unsigned short checksum(void* buffer, size_t length) {
  unsigned int sum = 0;

  if (buffer != nullptr && length != 0) {
    unsigned char* buf = (unsigned char*)buffer;
    // Обработка основной части данных (по 2 байта)
    while (length > 1) {
      unsigned short word;
      memcpy(&word, buf,
             sizeof(word));  // Безопасное копирование с любым выравниванием
      sum += word;
      buf += 2;
      length -= 2;
    }

    // Обработка оставшегося байта, если длина нечётная
    if (length == 1) {
      unsigned short word = *buf;  // Оставшийся байт дополняется нулём
      sum += word;
    }

    // Свёртывание 32-битной суммы в 16 бит
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
  }

  return ~sum;
}

// Проверка существования интерфейса
bool is_interface_exists(const string& interface) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    return false;
  }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);

  bool exists = (ioctl(fd, SIOCGIFINDEX, &ifr) >= 0);
  close(fd);
  return exists;
}

string get_default_interface() {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    throw runtime_error("Failed to create socket");
  }

  struct rtentry rt;
  memset(&rt, 0, sizeof(rt));

  // Запрашиваем маршрут по умолчанию
  if (ioctl(fd, SIOCGRTCONF, &rt) < 0) {
    close(fd);
    throw runtime_error("Failed to get default route");
  }

  close(fd);
  return string(rt.rt_dev);
}

// Отправка ICMP Echo Request
void send_icmp_echo(int sockfd, const string& target_ip) {
  struct sockaddr_in dest_addr;
  memset(&dest_addr, 0, sizeof(dest_addr));
  dest_addr.sin_family = AF_INET;
  if (inet_pton(AF_INET, target_ip.c_str(), &dest_addr.sin_addr) != 1) {
    throw runtime_error("Invalid target IP address");
  }

  // Создаем ICMP пакет
  icmp_packet packet;
  memset(&packet, 0, sizeof(packet));

  // Заполняем заголовок ICMP
  packet.header.type = ICMP_ECHO;
  packet.header.code = 0;
  packet.header.un.echo.id = htons((uint16_t)getpid());
  packet.header.un.echo.sequence = htons(1);
  memset(packet.payload, 'A', sizeof(packet.payload));
  packet.payload[sizeof(packet.payload) - 1] = '\0';

  // Вычисляем контрольную сумму
  packet.header.checksum = checksum(&packet, sizeof(packet));

  // Отправляем пакет
  if (sendto(sockfd, &packet, sizeof(packet), 0, (struct sockaddr*)&dest_addr,
             sizeof(dest_addr)) <= 0) {
    throw runtime_error("Failed to send ICMP packet");
  }
}

// Получение MAC адреса из ответа
void get_mac_address(const string& interface, const string& target_ip,
                     uint16_t expected_id, uint16_t expected_seq) {
  if (!is_interface_exists(interface)) {
    throw runtime_error("Network interface '" + interface + "' does not exist");
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
  if (!handle) {
    throw runtime_error("Could not open device: " + string(errbuf));
  }

  // Формируем BPF-фильтр с проверкой id и sequence
  char id_str[10], seq_str[10];
  snprintf(id_str, sizeof(id_str), "0x%x", ntohs(expected_id));
  snprintf(seq_str, sizeof(seq_str), "0x%x", ntohs(expected_seq));

  string filter = "icmp and src host " + target_ip +
                  " and icmp[0] == 0" +  // ICMP Echo Reply
                  " and icmp[4:2] == " + id_str +
                  " and icmp[6:2] == " + seq_str;

  struct bpf_program fp;
  if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) ==
      -1) {
    pcap_close(handle);
    throw runtime_error("Could not parse filter: " +
                        string(pcap_geterr(handle)));
  }

  if (pcap_setfilter(handle, &fp) == -1) {
    pcap_freecode(&fp);
    pcap_close(handle);
    throw runtime_error("Could not install filter: " +
                        string(pcap_geterr(handle)));
  }

  // Ожидаем ответ (с таймаутом)
  struct pcap_pkthdr header;
  const u_char* packet = pcap_next(handle, &header);
  pcap_freecode(&fp);

  if (!packet) {
    pcap_close(handle);
    throw runtime_error("No ICMP reply received (timeout or filter mismatch)");
  }

  // Проверяем, что пакет достаточно большой
  if (header.len < sizeof(struct ether_header) + sizeof(struct iphdr)) {
    pcap_close(handle);
    throw runtime_error("Packet too small to be IPv4");
  }

  // Извлекаем MAC-адрес из Ethernet-заголовка
  struct ether_header* eth_header = (struct ether_header*)packet;
  printf("Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
         eth_header->ether_dhost[0], eth_header->ether_dhost[1],
         eth_header->ether_dhost[2], eth_header->ether_dhost[3],
         eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

  pcap_close(handle);
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
    uint16_t id = htons((uint16_t)getpid());
    uint16_t seq = htons(1);
    get_mac_address(interface, target_ip, id, seq);

    close(sockfd);
  }
  catch(const exception& e) {
    cerr << "Error: " << e.what() << endl;
    return 1;
  }

  return 0;
}

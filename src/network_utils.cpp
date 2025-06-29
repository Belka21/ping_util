#include "network_utils.h"

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

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

// Запрос маршрута по умолчанию
std::string get_default_interface() {
  std::ifstream route_file("/proc/net/route");
  std::string line;

  getline(route_file, line);

  while (getline(route_file, line)) {
    std::istringstream iss(line);
    std::string iface;
    unsigned long dest;

    iss >> iface >> std::hex >> dest;

    if (dest == 0) {
      return iface;
    }
  }

  throw std::runtime_error("Default route not found");
}

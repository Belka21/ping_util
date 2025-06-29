#include <sys/ioctl.h>
#include <unistd.h>

#include <iostream>
#include <stdexcept>
#include <string>

#include "icmp_utils.h"
#include "network_utils.h"
#include "pcap_utils.h"

using namespace std;

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

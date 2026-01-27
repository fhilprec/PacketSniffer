#include <arpa/inet.h>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <unistd.h>
#include "PCAPWriter.hpp"

class PacketCapture {
public:
  PacketCapture(int port) : PacketCapture(port, "") {}

  PacketCapture(int port, std::string PcapFilename) 
      : port(port), running(false), pcap_filename(PcapFilename) {
      this->socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

      if (socket_fd < 0) {
          std::cerr << "Failed to create socket: " << strerror(errno) << "\n";
          std::cerr << "Note: Raw sockets require root privileges\n";
          throw std::runtime_error("Failed to create socket: " + std::string(strerror(errno)));
      }
      
      if (!pcap_filename.empty()) {
          pcap_writer = new PCAPWriter(pcap_filename);
      }
  }
  
  ~PacketCapture(){
    close(socket_fd);
    if (pcap_writer) {
        delete pcap_writer;
    }
  };

  void startCapture() {
    std::cout << "Packet sniffer started. Capturing packets";
    if (port > 0) {
      std::cout << " on port " << port;
    }
    std::cout << "...\n";

    std::array<char, 65536> packet_buffer;

    while (true) {
      ssize_t data_size = recvfrom(socket_fd, packet_buffer.data(),
                                   packet_buffer.size(), 0, nullptr, nullptr);

      if (data_size < 0) {
        std::cerr << "Failed to receive packet: " << strerror(errno) << "\n"
                  << "Maybe you are not running as root?\n";
        break;
      }
      process_packet(packet_buffer, data_size);
    }

    close(socket_fd);
  }
  void stopCapture();

  void printpayload(const char *payload, int len) {
    for (int i = 0; i < 64; i++) {
      if (isprint(payload[i])) {
        std::cout << payload[i];
      } else {
        std::cout << ".";
      }
    }
    std::cout << "\n" << std::endl;
  }

  void process_packet(std::array<char, 65536> &buffer, ssize_t size,
                      bool printMacAddresses = true) {

    struct ethhdr *eth = (struct ethhdr *)buffer.data();

    if (ntohs(eth->h_proto) != ETH_P_IP) {
      return;
    }

    struct iphdr *ip_header =
        (struct iphdr *)(buffer.data() + sizeof(struct ethhdr));

    struct in_addr src_addr, dest_addr;
    src_addr.s_addr = ip_header->saddr;
    dest_addr.s_addr = ip_header->daddr;

    // Filter out localhost traffic
    if ((ntohl(src_addr.s_addr) >> 24) == 127 ||
        (ntohl(dest_addr.s_addr) >> 24) == 127) {
      return;
    }

    int src_port = 0, dest_port = 0;

    if (ip_header->protocol == IPPROTO_TCP) {
      struct tcphdr *tcp =
          (struct tcphdr *)(buffer.data() + sizeof(struct ethhdr) +
                            (ip_header->ihl * 4));
      src_port = ntohs(tcp->source);
      dest_port = ntohs(tcp->dest);
    } else if (ip_header->protocol == IPPROTO_UDP) {
      struct udphdr *udp =
          (struct udphdr *)(buffer.data() + sizeof(struct ethhdr) +
                            (ip_header->ihl * 4));
      src_port = ntohs(udp->source);
      dest_port = ntohs(udp->dest);
    }

    // Filter by port if specified
    if (port > 0 && src_port != port && dest_port != port) {
      return;
    }

    std::cout << " | IP: " << inet_ntoa(src_addr) << " -> "
              << inet_ntoa(dest_addr);

    if (ip_header->protocol == IPPROTO_TCP) {
      std::cout << " | TCP " << src_port << " -> " << dest_port;
    } else if (ip_header->protocol == IPPROTO_UDP) {
      std::cout << " | UDP " << src_port << " -> " << dest_port;
    }


    if (printMacAddresses) {

      std::cout << "\nMAC: ";
      printf("%02x:%02x:%02x:%02x:%02x:%02x", eth->h_source[0],
             eth->h_source[1], eth->h_source[2], eth->h_source[3],
             eth->h_source[4], eth->h_source[5]);
      std::cout << " -> ";
      printf("%02x:%02x:%02x:%02x:%02x:%02x", eth->h_dest[0], eth->h_dest[1],
             eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
      std::cout << "\n";
    }

    std::cout << " | Size: " << size << " bytes\n";
    printpayload(buffer.data() + sizeof(struct ethhdr) + (ip_header->ihl * 4),
                 size - sizeof(struct ethhdr) - (ip_header->ihl * 4));

    if (!pcap_filename.empty()) {
        pcap_writer->writePcapPacket(buffer.data(), size);
    }
  }



private:
  int socket_fd;
  bool running;
  int port;
  std::string pcap_filename;
  PCAPWriter * pcap_writer = nullptr;
};
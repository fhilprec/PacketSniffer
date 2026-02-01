
#pragma once
#include <chrono>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

// PCAP file format structures
struct pcap_file_header {
  uint32_t magic_number;  // 0xa1b2c3d4
  uint16_t version_major; // 2
  uint16_t version_minor; // 4
  int32_t thiszone;       // GMT to local correction
  uint32_t sigfigs;       // accuracy of timestamps
  uint32_t snaplen;       // max length of captured packets
  uint32_t network;       // data link type (1 = Ethernet)
};

struct pcap_packet_header {
  uint32_t ts_sec;   // timestamp seconds
  uint32_t ts_usec;  // timestamp microseconds
  uint32_t incl_len; // number of octets of packet saved in file
  uint32_t orig_len; // actual length of packet
};

class PCAPWriter {
public:
  explicit PCAPWriter(const std::string &filename) {
    pcap_file.open(filename, std::ios::binary | std::ios::out);
    if (!pcap_file.is_open()) {
      throw std::runtime_error("Failed to open PCAP file: " + filename);
    }
    writePcapHeader();
    std::cout << "Writing packets to PCAP file: " << filename << "\n";
  }

  ~PCAPWriter() noexcept {
    if (pcap_file.is_open()) {
      pcap_file.close();
    }
  }

  // Delete copy constructor and assignment operator
  PCAPWriter(const PCAPWriter &) = delete;
  PCAPWriter &operator=(const PCAPWriter &) = delete;

  void writePcapPacket(const char *packet_data, uint32_t packet_len) {
    if (!pcap_file.is_open()) {
      return;
    }

    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
    auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(
        duration - seconds);

    pcap_packet_header pkt_header;
    pkt_header.ts_sec = static_cast<uint32_t>(seconds.count());
    pkt_header.ts_usec = static_cast<uint32_t>(microseconds.count());
    pkt_header.incl_len = packet_len;
    pkt_header.orig_len = packet_len;

    pcap_file.write(reinterpret_cast<const char *>(&pkt_header),
                    sizeof(pkt_header));
    pcap_file.write(packet_data, packet_len);
    // Removed flush() - batching will handle flushing
  }

private:
  std::ofstream pcap_file;

  void writePcapHeader() {
    pcap_file_header header;
    header.magic_number = 0xa1b2c3d4;
    header.version_major = 2;
    header.version_minor = 4;
    header.thiszone = 0;
    header.sigfigs = 0;
    header.snaplen = 65535;
    header.network = 1; // Ethernet
    pcap_file.write(reinterpret_cast<const char *>(&header), sizeof(header));
    pcap_file.flush();
  }
};

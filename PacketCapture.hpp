#include "PCAPWriter.hpp"
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
#include <thread>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>

class PacketCapture {
public:
  PacketCapture(int port) : PacketCapture(port, "") {}

  PacketCapture(int port, std::string PcapFilename)
      : port(port), running(false), pcap_filename(PcapFilename) {
    this->socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (socket_fd < 0) {
      std::cerr << "Failed to create socket: " << strerror(errno) << "\n";
      std::cerr << "Note: Raw sockets require root privileges\n";
      throw std::runtime_error("Failed to create socket: " +
                               std::string(strerror(errno)));
    }

    // Increase socket receive buffer size to 10MB
    int bufsize = 10 * 1024 * 1024;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize)) < 0) {
      std::cerr << "Warning: Failed to set socket buffer size: " << strerror(errno) << "\n";
    }

    if (!pcap_filename.empty()) {
      pcap_writer = new PCAPWriter(pcap_filename);
    }
  }

  ~PacketCapture() {
    stopCapture();
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

    running = true;

    // Start worker threads
    const int num_threads = std::thread::hardware_concurrency() > 0 ?
                            std::thread::hardware_concurrency() : 4;
    for (int i = 0; i < num_threads; ++i) {
      worker_threads.emplace_back(&PacketCapture::processWorker, this);
    }

    // Start PCAP writer thread if needed
    if (pcap_writer) {
      pcap_writer_thread = std::thread(&PacketCapture::pcapWriterWorker, this);
    }

    // Main capture loop
    std::array<char, 65536> packet_buffer;
    std::atomic<uint64_t> packet_counter{0};
    while (running) {
      ssize_t data_size = recvfrom(socket_fd, packet_buffer.data(),
                                   packet_buffer.size(), 0, nullptr, nullptr);

      if (data_size < 0) {
        if (running) {
          std::cerr << "Failed to receive packet: " << strerror(errno) << "\n"
                    << "Maybe you are not running as root?\n";
        }
        break;
      }

      // Add packet to processing queue
      {
        std::unique_lock<std::mutex> lock(queue_mutex);
        PacketData pkt;
        pkt.data.resize(data_size);
        std::memcpy(pkt.data.data(), packet_buffer.data(), data_size);
        pkt.size = data_size;
        packet_queue.push(std::move(pkt));
      }
      queue_cv.notify_one();
      
    }
  }

  void stopCapture() {
    if (!running) return;

    running = false;
    queue_cv.notify_all();
    pcap_queue_cv.notify_all();

    // Wait for worker threads
    for (auto& thread : worker_threads) {
      if (thread.joinable()) {
        thread.join();
      }
    }

    // Wait for PCAP writer thread
    if (pcap_writer_thread.joinable()) {
      pcap_writer_thread.join();
    }

    std::cout << "Capture stopped\n";
  }

  void process_packet(const char* buffer, ssize_t size) {

    const bool debug = false;
    
    if (debug) std::cout << " DEBUG : PROCESSING PACKET" << std::endl;
    
    struct ethhdr *eth = (struct ethhdr *)buffer;

    

    if (ntohs(eth->h_proto) != ETH_P_IP) {
      return;
    }

    if (debug)  std::cout << " DEBUG : WE ARE TCP IP" << std::endl;

    struct iphdr *ip_header =
        (struct iphdr *)(buffer + sizeof(struct ethhdr));

    struct in_addr src_addr, dest_addr;
    src_addr.s_addr = ip_header->saddr;
    dest_addr.s_addr = ip_header->daddr;

    // // Filter out localhost traffic
    // if ((ntohl(src_addr.s_addr) >> 24) == 127 ||
    //     (ntohl(dest_addr.s_addr) >> 24) == 127) {
    //   return;
    // }

    if (debug)  std::cout << " DEBUG : WE ARE NOT LOCALHOST" << std::endl;

    int src_port = 0, dest_port = 0;

    if (ip_header->protocol == IPPROTO_TCP) {
      struct tcphdr *tcp =
          (struct tcphdr *)(buffer + sizeof(struct ethhdr) +
                            (ip_header->ihl * 4));
      src_port = ntohs(tcp->source);
      dest_port = ntohs(tcp->dest);
    } else if (ip_header->protocol == IPPROTO_UDP) {
      struct udphdr *udp =
          (struct udphdr *)(buffer + sizeof(struct ethhdr) +
                            (ip_header->ihl * 4));
      src_port = ntohs(udp->source);
      dest_port = ntohs(udp->dest);
    }

    // Filter by port if specified
    if (port > 0 && src_port != port && dest_port != port) {
      return;
    }

    if (debug)  std::cout << " DEBUG : WE HAVE THE PROPER PORT" << std::endl;

    // Queue packet for PCAP writing if enabled
    if (pcap_writer) {
      std::unique_lock<std::mutex> lock(pcap_queue_mutex);
      PcapPacketData pkt;
      pkt.data.resize(size);
      std::memcpy(pkt.data.data(), buffer, size);
      pkt.size = size;
      pcap_packet_queue.push(std::move(pkt));
      pcap_queue_cv.notify_one();
    }
  }

private:
  struct PacketData {
    std::vector<char> data;
    ssize_t size;
  };

  struct PcapPacketData {
    std::vector<char> data;
    uint32_t size;
  };

  void processWorker() {
    while (running) {
      PacketData pkt;
      {
        std::unique_lock<std::mutex> lock(queue_mutex);
        queue_cv.wait(lock, [this] { return !packet_queue.empty() || !running; });

        if (!running && packet_queue.empty()) {
          break;
        }

        if (!packet_queue.empty()) {
          pkt = std::move(packet_queue.front());
          packet_queue.pop();
        }
      }

      if (pkt.size > 0) {
        process_packet(pkt.data.data(), pkt.size);
      }
    }
  }

  void pcapWriterWorker() {
    const int BATCH_SIZE = 1;
    std::vector<PcapPacketData> batch;
    batch.reserve(BATCH_SIZE);

    while (running || !pcap_packet_queue.empty()) {
      {
        std::unique_lock<std::mutex> lock(pcap_queue_mutex);
        pcap_queue_cv.wait_for(lock, std::chrono::milliseconds(100),
                               [this] { return !pcap_packet_queue.empty() || !running; });

        // Collect packets into batch
        while (!pcap_packet_queue.empty() && batch.size() < BATCH_SIZE) {
          batch.push_back(std::move(pcap_packet_queue.front()));
          pcap_packet_queue.pop();
        }
      }

      std::cout << "WRITTEN A BATCH OF 100 PACKETS" << '\n';

      // Write batch to file
      if (!batch.empty()) {
        for (auto& pkt : batch) {
          pcap_writer->writePcapPacket(pkt.data.data(), pkt.size);
        }
        batch.clear();
      }
    }
  }

  int socket_fd;
  std::atomic<bool> running;
  int port;
  std::string pcap_filename;
  PCAPWriter *pcap_writer = nullptr;

  // Ring buffer for packet processing
  std::queue<PacketData> packet_queue;
  std::mutex queue_mutex;
  std::condition_variable queue_cv;
  std::vector<std::thread> worker_threads;

  // PCAP writing queue
  std::queue<PcapPacketData> pcap_packet_queue;
  std::mutex pcap_queue_mutex;
  std::condition_variable pcap_queue_cv;
  std::thread pcap_writer_thread;
};
#include "PacketCapture.hpp"
#include <memory>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <thread>

int main(int argc, char *argv[]) {

  std::unique_ptr<PacketCapture> packetCapture;
  int port = 0; // 0 means capture all ports
  if (argc > 1) {
    port = std::stoi(argv[1]);
    packetCapture = std::make_unique<PacketCapture>(port);
  } else if (argc > 2) {
    std::string pcapFile = argv[2];
    packetCapture = std::make_unique<PacketCapture>(port, pcapFile);
  } else {
    throw std::runtime_error("Specifiy sufficient args");
  }

  std::thread t([pc = std::move(packetCapture)]() { pc->startCapture(); });
  
  
  
  t.join();
  return 0;
}
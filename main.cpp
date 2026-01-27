#include "PacketCapture.hpp"
#include <memory>
#include <string>
#include <sys/socket.h>

int main(int argc, char* argv[]) {
    
    std::unique_ptr<PacketCapture> packetCapture;
    int port = 0;  // 0 means capture all ports
    if (argc > 1){
        port = std::stoi(argv[1]);
        packetCapture = std::make_unique<PacketCapture>(port);
    }
    if (argc > 2){
        std::string pcapFile = argv[2];
        packetCapture = std::make_unique<PacketCapture>(port, pcapFile);
        
    }

    packetCapture->startCapture();
    return 0;
}
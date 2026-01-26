#include "PacketCapture.hpp"
#include <sys/socket.h>








int main(int argc, char* argv[]) {
    int port = 0;  // 0 means capture all ports
    if (argc > 1){
        port = std::stoi(argv[1]);
    }

    PacketCapture pc(port);
    pc.startCapture();

    return 0;
}
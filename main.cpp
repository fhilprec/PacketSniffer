#include <vector>
#include <iostream>
#include <sys/socket.h>
#include<linux/if_packet.h>
#include<net/ethernet.h>
#include <netinet/in.h>
#include <unistd.h> //for close()
#include <cerrno>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>



void printpayload(const char* payload, int len){
    for(int i =0; i < len; i++){
        if(isprint(payload[i])) {
            std::cout << payload[i];
        } else {
            std::cout << ".";
        }
    }
    std::cout << "\n" << std::endl;
}




void process_packet(std::vector<char>& buffer, ssize_t size) {


    struct ethhdr* eth = (struct ethhdr*)buffer.data();
    
    // Check if it's an IP packet
    if (ntohs(eth->h_proto) != ETH_P_IP) {
        return;  // Skip non-IP packets
    }
    
    struct iphdr* ip_header = (struct iphdr*)(buffer.data() + sizeof(struct ethhdr));
    
    struct in_addr src_addr, dest_addr;
    src_addr.s_addr = ip_header->saddr;
    dest_addr.s_addr = ip_header->daddr;
    
    // Skip loopback traffic (127.0.0.0/8)
    if ((ntohl(src_addr.s_addr) >> 24) == 127 || (ntohl(dest_addr.s_addr) >> 24) == 127) {
        return;
    }
    
    std::cout << "IP Packet: " << inet_ntoa(src_addr) << " -> " << inet_ntoa(dest_addr);
    
    // Check protocol
    if (ip_header->protocol == IPPROTO_TCP) {
        struct tcphdr* tcp = (struct tcphdr*)(buffer.data() + sizeof(struct ethhdr) + (ip_header->ihl * 4));
        std::cout << " | TCP " << ntohs(tcp->source) << " -> " << ntohs(tcp->dest);
    } 
    else if (ip_header->protocol == IPPROTO_UDP) {
        struct udphdr* udp = (struct udphdr*)(buffer.data() + sizeof(struct ethhdr) + (ip_header->ihl * 4));
        std::cout << " | UDP " << ntohs(udp->source) << " -> " << ntohs(udp->dest);
    }
    std::cout << " | Size: " << size << " bytes\n";
    printpayload(buffer.data() + sizeof(struct ethhdr) + (ip_header->ihl * 4), size - sizeof(struct ethhdr) - (ip_header->ihl * 4));
}

int main(int argc, char* argv[]) {
    
    int port = 8080;
    if (argc > 1){
        port = std::stoi(argv[1]);
    }
    
    int socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); //ETH_P_ALL to capture all incomming packets
    if (socket_fd < 0) {
        std::cerr << "Note: Raw sockets require root privileges\n";
        return 1;
    }

    std::cout << "Packet sniffer started. Capturing packets...\n";

    std::vector<char> packet_buffer(65536);

    while (true) {
        ssize_t data_size = recvfrom(socket_fd, packet_buffer.data(), packet_buffer.size(), 0, nullptr, nullptr);
        
        if (data_size < 0) {
            std::cerr << "Failed to receive packet: " <<  "\n";
            break;
        }
        process_packet(packet_buffer, data_size);
    }

    close(socket_fd);
    return 0;
}
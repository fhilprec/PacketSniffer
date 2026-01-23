class PacketCapture {
public:
    PacketCapture();
    ~PacketCapture();
    
    void startCapture();
    void stopCapture();
    
private:
    int raw_socket_fd;
    bool running;
};
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace secure_channel {

    class TcpSocket {
    public:
        TcpSocket();
        explicit TcpSocket(int fd);
        ~TcpSocket();
        TcpSocket(const TcpSocket&) = delete;
        TcpSocket& operator=(const TcpSocket&) = delete;
        TcpSocket(TcpSocket&& other) noexcept;
        TcpSocket& operator=(TcpSocket&& other) noexcept;

        void connect(const std::string& host, uint16_t port);
        void bind(uint16_t port);
        void listen(int backlog = 5);
        TcpSocket accept();
        void send_all(const uint8_t* data, size_t len);
        void recv_all(uint8_t* buffer, size_t len);
        void send_all(const std::vector<uint8_t>& data) { send_all(data.data(), data.size());}
        std::vector<uint8_t> recv_all(size_t len);
        void close();
        bool is_open() const { return fd_ != -1; }

    private:
        int fd_;
    };

    class TcpServer {
    public:
        explicit TcpServer(uint16_t port);
        TcpSocket accept();

    private:
        TcpSocket listen_socket_;
    };
} // namespace secure_channel 
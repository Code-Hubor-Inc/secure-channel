#include "secure-channel/network.hpp"
#include <stdexcept>
#include <cstring>
#include <vector>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

namespace secure_channel {

    //..TcpSocket..
    TcpSocket::TcpSocket() : fd_(-1) {}

    TcpSocket::TcpSocket(int fd) : fd_(fd) {}

    TcpSocket::~TcpSocket() {
        if (fd_ != -1) {
            ::close(fd_);
        }
    }

    TcpSocket::TcpSocket(TcpSocket&& other) noexcept : fd_(other.fd_) {
        other.fd_= -1;
    }

    TcpSocket& TcpSocket::operator=(TcpSocket&& other) noexcept {
        if (this != &other) {
            if (fd_ != -1) ::close(fd_);
            fd_= other.fd_;
            other.fd_= -1;
        }
        return *this;
    }

    // Recently added
    std::vector<uint8_t> TcpSocket::recv_all(size_t len) {
    std::vector<uint8_t> buf(len);
    recv_all(buf.data(), len);
    return buf;
}

    void TcpSocket::connect(const std::string& host, uint16_t port) {
        fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ < 0) throw std::runtime_error("Socket failed");

        struct hostent* server = gethostbyname(host.c_str());
        if (!server) throw std::runtime_error("gethostbyname() failed");

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        memcpy(&addr.sin_addr.s_addr, server->h_addr, server->h_length);
        addr.sin_port = htons(port);

        if (::connect(fd_, (struct sockaddr*)&addr,sizeof(addr)) < 0) {
            ::close(fd_);
            fd_= -1;
            throw std::runtime_error("Connect() failed");
        }
    }

    void TcpSocket::bind(uint16_t port) {
        fd_= socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ < 0) throw std::runtime_error("socket() failed");

        int opt = 1;
        if (setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            ::close(fd_);
            fd_= -1;
            throw std::runtime_error("setsockopt() failed");
        }

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons(port);

        if (::bind(fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            ::close(fd_);
            fd_= -1;
            throw std::runtime_error("bind() failed");
        }   
    }

    void TcpSocket::listen(int backlog) {
        if (::listen(fd_, backlog) < 0) {
            throw std::runtime_error("listen() failed");
        }
    }

    TcpSocket TcpSocket::accept() {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = ::accept(fd_, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            throw std::runtime_error("accept() failed");
        }
        return TcpSocket(client_fd);
    }

    void TcpSocket::send_all(const uint8_t* data, size_t len) {
        size_t sent = 0;
        while (sent < len) {
            ssize_t n = ::send(fd_, data + sent, len - sent, MSG_NOSIGNAL);
            if (n <= 0) {
                throw std::runtime_error("send() failed");
            }
            sent += n;
        }
    }

    void TcpSocket::recv_all(uint8_t* buffer, size_t len) {
        size_t received = 0;
        while (received < len) {
            ssize_t n = ::recv(fd_, buffer + received, len - received, 0);
            if (n <= 0) {
                throw std::runtime_error("recv() failed or connection closed");
            }
            received += n;
        }
    }

    void TcpSocket::close() {
        if (fd_ != -1) {
            ::close(fd_);
            fd_= -1;
        }
    }

    TcpServer::TcpServer(uint16_t port) {
        listen_socket_.bind(port);
        listen_socket_.listen();
    }

    TcpSocket TcpServer::accept() {
        return listen_socket_.accept();
    }
} // namespace secure_channel
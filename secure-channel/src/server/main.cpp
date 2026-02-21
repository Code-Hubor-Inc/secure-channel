#include "secure-channel/handshake.hpp"
#include "secure-channel/record.hpp"
#include "secure-channel/network.hpp"
#include "secure-channel/common.hpp"
#include <iostream>

int main() {
    try {
        secure_channel::CtrDrbg rng;
        secure_channel::TcpServer server(DEFAULT_PORT);
        LOG_INFO("Server listening on port " << DEFAULT_PORT);

        auto client_socket = server.accept();
        LOG_INFO("Client connected");

        auto handshake = secure_channel::Handshake::create_server(rng);
        handshake.perform(client_socket);
        LOG_INFO("Handshake complete");

        auto client_key = handshake.get_client_write_key(); // for recieving
        auto server_key = handshake.get_server_write_key(); // for sending to client
        secure_channel::RecordLayer reciever(false, client_key);
        secure_channel::RecordLayer sender(false, server_key);

        while (true) {
            // Recieve record
            auto header = client_socket.recv_all(4);
            uint32_t len = ntoh32(*reinterpret_cast<uint32_t*>(header.data()));
            auto record = client_socket.recv_all(len);
            auto plain = reciever.decrypt(record);

            std::string msg(plain.begin(), plain.end());
            std::cout << "Recieved: " << msg << std::endl;

            // echo back
            auto response = sender.encrypt(plain);
            client_socket.send_all(response);
        }
    } catch (const std::exception& e) {
        LOG_ERROR(e.what());
        return 1;
    }
    return 0;
}
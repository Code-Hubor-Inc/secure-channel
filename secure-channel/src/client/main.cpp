#include "secure-channel/handshake.hpp"
#include "secure-channel/record.hpp"
#include "secure-channel/network.hpp"
#include "secure-channel/common.hpp"
#include <iostream>
#include <string>

int main() {
    try {
        secure_channel::CtrDrbg rng;
        auto handshake = secure_channel::Handshake::create_client(rng);

        secure_channel::TcpSocket socket;
        socket.connect("127.0.0.1", DEFAULT_PORT);
        LOG_INFO("Connected complete");

        handshake.perform(socket);
        LOG_INFO("Handshake complete");

        auto client_key = handshake.get_client_write_key(); // For sending
        auto server_key = handshake.get_server_write_key(); // For recieving
        secure_channel::RecordLayer sender(true, client_key);
        secure_channel::RecordLayer recieve(true, server_key); // same keys because client uses client_write for sending and server_write for recieving

        std::string line;
        while (std::getline(std::cin, line)) {
            if (line == "quit") break;

            // encrypt and send
            std::vector<uint8_t> plain(line.begin(), line.end());
            auto record = sender.encrypt(plain);
            socket.send_all(record);

            // Recieve echo
            auto resp_record = socket.recv_all(record.size());
            auto resp_plain = recieve.decrypt(resp_record);
            std::string resp(resp_plain.begin(), resp_plain.end());
            std::cout << "Echo: " << resp << std::endl;
        }

        socket.close();
    } catch (const std::exception& e) {
        LOG_ERROR(e.what());
        return 1;
    }
    return 0;
}
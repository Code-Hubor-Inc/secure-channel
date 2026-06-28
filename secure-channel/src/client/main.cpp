#include "secure-channel/handshake.hpp"
#include "secure-channel/record.hpp"
#include "secure-channel/network.hpp"
#include "secure-channel/common.hpp"
#include "secure-channel/vault.hpp"
#include <iostream>
#include <string>
#include <sstream>

void print_help() {
    std::cout << "Commands:\n"
              << "  login <password>\n"
              << "  set <key> <value>\n"
              << "  get <key>\n"
              << "  list\n"
              << "  delete <key>\n"
              << "  logout\n"
              << "  quit\n";
}

int main() {
    try {
        secure_channel::CtrDrbg rng;
        auto handshake = secure_channel::Handshake::create_client(rng);

        secure_channel::TcpSocket socket;
        socket.connect("127.0.0.1", DEFAULT_PORT);
        LOG_INFO("Connected to server");

        handshake.perform(socket);
        LOG_INFO("Secure channel established");

        auto client_key = handshake.get_client_write_key();
        auto server_key = handshake.get_server_write_key();
        secure_channel::RecordLayer sender(true, client_key);
        secure_channel::RecordLayer receiver(true, server_key);

        secure_channel::VaultClient client(socket, receiver, sender);

        std::string line;
        print_help();
        while (std::cout << "> " && std::getline(std::cin, line)) {
            if (line == "quit") break;
            if (line.empty()) continue;

            std::stringstream ss(line);
            std::string cmd;
            ss >> cmd;

            if (cmd == "login") {
                std::string pwd;
                ss >> pwd;
                if (client.login(pwd)) {
                    std::cout << "Login successful\n";
                } else {
                    std::cout << "Login failed\n";
                }
            } else if (cmd == "set") {
                std::string key, val;
                ss >> key;
                std::getline(ss >> std::ws, val); // rest of line as value (supports spaces)
                if (client.set(key, {val.begin(), val.end()})) {
                    std::cout << "Secret stored\n";
                } else {
                    std::cout << "Failed to store secret\n";
                }
            } else if (cmd == "get") {
                std::string key;
                ss >> key;
                std::vector<uint8_t> val;
                if (client.get(key, val)) {
                    std::cout << "Value: " << std::string(val.begin(), val.end()) << "\n";
                } else {
                    std::cout << "Secret not found\n";
                }
            } else if (cmd == "list") {
                auto keys = client.list();
                std::cout << "Secrets:\n";
                for (const auto& k : keys) {
                    std::cout << "  - " << k << "\n";
                }
            } else if (cmd == "delete") {
                std::string key;
                ss >> key;
                if (client.del(key)) {
                    std::cout << "Secret deleted\n";
                } else {
                    std::cout << "Secret not found\n";
                }
            } else if (cmd == "logout") {
                client.logout();
                std::cout << "Logged out\n";
            } else {
                print_help();
            }
        }

        socket.close();
    } catch (const std::exception& e) {
        LOG_ERROR(e.what());
        return 1;
    }
    return 0;
}

#include "secure-channel/handshake.hpp"
#include "secure-channel/record.hpp"
#include "secure-channel/network.hpp"
#include "secure-channel/common.hpp"
#include "secure-channel/vault.hpp"
#include "secure-channel/crypto.hpp"
#include <cstdlib>
#include <iostream>

static std::vector<uint8_t> key_from_password(const std::string& password) {
    secure_channel::Sha256 sha;
    sha.update(reinterpret_cast<const uint8_t*>(password.data()), password.size());
    return sha.finish();
}

int main() {
    try {
        const char* env_pw = std::getenv("VAULT_PASSWORD");
        std::string password = env_pw ? env_pw : "master_key_123";
        secure_channel::Vault vault("vault.db", key_from_password(password));
        secure_channel::CtrDrbg rng;
        secure_channel::TcpServer server(DEFAULT_PORT);
        LOG_INFO("Vault Server listening on port " << DEFAULT_PORT);

        while (true) {
            try {
                auto client_socket = server.accept();
                LOG_INFO("Client connected");

                auto handshake = secure_channel::Handshake::create_server(rng);
                handshake.perform(client_socket);
                LOG_INFO("Handshake complete");

                auto client_key = handshake.get_client_write_key();
                auto server_key = handshake.get_server_write_key();
                
                secure_channel::RecordLayer receiver(false, client_key);
                secure_channel::RecordLayer sender(false, server_key);

                secure_channel::handle_vault_session(client_socket, receiver, sender, vault);
                LOG_INFO("Client disconnected");
            } catch (const std::exception& e) {
                LOG_ERROR("Client error: " << e.what());
            }
        }
    } catch (const std::exception& e) {
        LOG_ERROR("Fatal error: " << e.what());
        return 1;
    }
    return 0;
}

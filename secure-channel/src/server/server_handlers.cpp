#include "secure-channel/vault.hpp"
#include "secure-channel/record.hpp"
#include "secure-channel/network.hpp"
#include "secure-channel/common.hpp"
#include <iostream>
#include <cstring>

namespace secure_channel {

    void handle_vault_session(TcpSocket& socket, RecordLayer& receiver, RecordLayer& sender, Vault& vault) {
        bool authenticated = false;

        while (true) {
            try {
                // Receive record
                auto header = socket.recv_all(4);
                uint32_t len = ntoh32(*reinterpret_cast<uint32_t*>(header.data()));
                auto record = socket.recv_all(len);
                auto plain = receiver.decrypt(record);

                if (plain.empty()) continue;

                CommandType cmd = static_cast<CommandType>(plain[0]);
                std::vector<uint8_t> response_payload;

                if (!authenticated && cmd != CommandType::LOGIN) {
                    response_payload.push_back(static_cast<uint8_t>(CommandType::ERROR));
                    const char* msg = "Not authenticated";
                    response_payload.insert(response_payload.end(), msg, msg + strlen(msg));
                } else {
                    switch (cmd) {
                        case CommandType::LOGIN: {
                            std::string password(plain.begin() + 1, plain.end());
                            if (vault.authenticate(password)) {
                                authenticated = true;
                                response_payload.push_back(static_cast<uint8_t>(CommandType::RESPONSE));
                                const char* msg = "Login successful";
                                response_payload.insert(response_payload.end(), msg, msg + strlen(msg));
                            } else {
                                response_payload.push_back(static_cast<uint8_t>(CommandType::ERROR));
                                const char* msg = "Invalid password";
                                response_payload.insert(response_payload.end(), msg, msg + strlen(msg));
                            }
                            break;
                        }
                        case CommandType::SET: {
                            if (plain.size() < 3) break;
                            uint8_t key_len = plain[1];
                            std::string key(plain.begin() + 2, plain.begin() + 2 + key_len);
                            std::vector<uint8_t> val(plain.begin() + 2 + key_len, plain.end());
                            vault.set_secret(key, val);
                            response_payload.push_back(static_cast<uint8_t>(CommandType::RESPONSE));
                            const char* msg = "Secret stored";
                            response_payload.insert(response_payload.end(), msg, msg + strlen(msg));
                            break;
                        }
                        case CommandType::GET: {
                            std::string key(plain.begin() + 1, plain.end());
                            std::vector<uint8_t> val;
                            if (vault.get_secret(key, val)) {
                                response_payload.push_back(static_cast<uint8_t>(CommandType::RESPONSE));
                                response_payload.insert(response_payload.end(), val.begin(), val.end());
                            } else {
                                response_payload.push_back(static_cast<uint8_t>(CommandType::ERROR));
                                const char* msg = "Secret not found";
                                response_payload.insert(response_payload.end(), msg, msg + strlen(msg));
                            }
                            break;
                        }
                        case CommandType::LIST: {
                            auto keys = vault.list_secrets();
                            response_payload.push_back(static_cast<uint8_t>(CommandType::RESPONSE));
                            for (const auto& k : keys) {
                                response_payload.push_back(static_cast<uint8_t>(k.size()));
                                response_payload.insert(response_payload.end(), k.begin(), k.end());
                            }
                            break;
                        }
                        case CommandType::DELETE: {
                            std::string key(plain.begin() + 1, plain.end());
                            if (vault.delete_secret(key)) {
                                response_payload.push_back(static_cast<uint8_t>(CommandType::RESPONSE));
                                const char* msg = "Secret deleted";
                                response_payload.insert(response_payload.end(), msg, msg + strlen(msg));
                            } else {
                                response_payload.push_back(static_cast<uint8_t>(CommandType::ERROR));
                                const char* msg = "Secret not found";
                                response_payload.insert(response_payload.end(), msg, msg + strlen(msg));
                            }
                            break;
                        }
                        case CommandType::LOGOUT: {
                            authenticated = false;
                            response_payload.push_back(static_cast<uint8_t>(CommandType::RESPONSE));
                            const char* msg = "Logged out";
                            response_payload.insert(response_payload.end(), msg, msg + strlen(msg));
                            break;
                        }
                        default: {
                            response_payload.push_back(static_cast<uint8_t>(CommandType::ERROR));
                            const char* msg = "Unknown command";
                            response_payload.insert(response_payload.end(), msg, msg + strlen(msg));
                            break;
                        }
                    }
                }

                // Send encrypted response
                auto encrypted_resp = sender.encrypt(response_payload);
                socket.send_all(encrypted_resp);

            } catch (const std::runtime_error& e) {
                std::string msg = e.what();
                if (msg.find("recv() failed") != std::string::npos ||
                    msg.find("connection closed") != std::string::npos) {
                    break; // normal client disconnect
                }
                LOG_ERROR("Session error: " << msg);
                break;
            }
        }
    }

} // namespace secure_channel

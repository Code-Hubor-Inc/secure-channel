#include "secure-channel/vault.hpp"
#include "secure-channel/record.hpp"
#include "secure-channel/network.hpp"
#include "secure-channel/common.hpp"
#include <iostream>

namespace secure_channel {

    VaultClient::VaultClient(TcpSocket& socket, RecordLayer& receiver, RecordLayer& sender)
        : socket_(socket), receiver_(receiver), sender_(sender) {}

    std::vector<uint8_t> VaultClient::send_and_receive(const std::vector<uint8_t>& payload) {
        auto encrypted = sender_.encrypt(payload);
        socket_.send_all(encrypted);

        auto header = socket_.recv_all(4);
        uint32_t len = ntoh32(*reinterpret_cast<uint32_t*>(header.data()));
        auto record = socket_.recv_all(len);
        return receiver_.decrypt(record);
    }

    bool VaultClient::login(const std::string& password) {
        std::vector<uint8_t> payload;
        payload.push_back(static_cast<uint8_t>(CommandType::LOGIN));
        payload.insert(payload.end(), password.begin(), password.end());

        auto resp = send_and_receive(payload);
        if (resp.empty()) return false;
        return static_cast<CommandType>(resp[0]) == CommandType::RESPONSE;
    }

    bool VaultClient::set(const std::string& key, const std::vector<uint8_t>& value) {
        std::vector<uint8_t> payload;
        payload.push_back(static_cast<uint8_t>(CommandType::SET));
        payload.push_back(static_cast<uint8_t>(key.size()));
        payload.insert(payload.end(), key.begin(), key.end());
        payload.insert(payload.end(), value.begin(), value.end());

        auto resp = send_and_receive(payload);
        if (resp.empty()) return false;
        return static_cast<CommandType>(resp[0]) == CommandType::RESPONSE;
    }

    bool VaultClient::get(const std::string& key, std::vector<uint8_t>& out_value) {
        std::vector<uint8_t> payload;
        payload.push_back(static_cast<uint8_t>(CommandType::GET));
        payload.insert(payload.end(), key.begin(), key.end());

        auto resp = send_and_receive(payload);
        if (resp.empty() || static_cast<CommandType>(resp[0]) != CommandType::RESPONSE) return false;
        
        out_value.assign(resp.begin() + 1, resp.end());
        return true;
    }

    std::vector<std::string> VaultClient::list() {
        std::vector<uint8_t> payload;
        payload.push_back(static_cast<uint8_t>(CommandType::LIST));

        auto resp = send_and_receive(payload);
        std::vector<std::string> keys;
        if (resp.empty() || static_cast<CommandType>(resp[0]) != CommandType::RESPONSE) return keys;

        size_t offset = 1;
        while (offset < resp.size()) {
            uint8_t len = resp[offset++];
            keys.push_back(std::string(resp.begin() + offset, resp.begin() + offset + len));
            offset += len;
        }
        return keys;
    }

    bool VaultClient::del(const std::string& key) {
        std::vector<uint8_t> payload;
        payload.push_back(static_cast<uint8_t>(CommandType::DELETE));
        payload.insert(payload.end(), key.begin(), key.end());

        auto resp = send_and_receive(payload);
        if (resp.empty()) return false;
        return static_cast<CommandType>(resp[0]) == CommandType::RESPONSE;
    }

    void VaultClient::logout() {
        std::vector<uint8_t> payload;
        payload.push_back(static_cast<uint8_t>(CommandType::LOGOUT));
        send_and_receive(payload);
    }

} // namespace secure_channel

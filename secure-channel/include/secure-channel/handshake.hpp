#pragma once

#include "crypto.hpp"
#include "network.hpp"
#include <vector>
#include <memory>

namespace secure_channel {

    class Handshake {
    public:
        static Handshake create_client(CtrDrbg& rng);
        static Handshake create_server(CtrDrbg& rng);

        void perform(TcpSocket& socket);

        std::vector<uint8_t> get_client_write_key() const { return client_write_key_; }
        std::vector<uint8_t> get_server_write_key() const { return server_write_key_; }

    private:
        Handshake(bool is_server, CtrDrbg& rng);

        std::vector<uint8_t> build_hello();
        void parse_hello(const std::vector<uint8_t>& msg);
        std::vector<uint8_t> build_key_exchange();
        void parse_key_exchange(const std::vector<uint8_t>& msg);
        std::vector<uint8_t> build_finished();
        bool verify_finished(const std::vector<uint8_t>& msg);

        void derive_keys();

        bool is_server_;
        CtrDrbg& rng_;

        DhContext dh_;
        std::vector<uint8_t> client_nonce_;
        std::vector<uint8_t> server_nonce_;
        std::vector<uint8_t> shared_secret_;
        std::vector<uint8_t> client_write_key_;
        std::vector<uint8_t> server_write_key_;

        std::vector<uint8_t> handshake_log_;
        std::vector<uint8_t> our_ke_log_;  // our key exchange message (unframed)
        std::vector<uint8_t> peer_ke_log_; // peer's key exchange message (unframed)
    };
} // namespace secure_channel
#include "secure-channel/handshake.hpp"
#include "secure-channel/common.hpp"
#include <cstring>
#include <stdexcept>

namespace secure_channel {

    // Prepend a 4-byte big-endian length so the receiver knows how many bytes to read.
    static std::vector<uint8_t> frame(const std::vector<uint8_t>& msg) {
        uint32_t len = hton(static_cast<uint32_t>(msg.size()));
        std::vector<uint8_t> out(4);
        memcpy(out.data(), &len, 4);
        out.insert(out.end(), msg.begin(), msg.end());
        return out;
    }

    Handshake Handshake::create_client(CtrDrbg& rng) {
        return Handshake(false, rng);
    }

    Handshake Handshake::create_server(CtrDrbg& rng) {
        return Handshake(true, rng);
    }

    Handshake::Handshake(bool is_server, CtrDrbg& rng) 
        : is_server_(is_server), rng_(rng) {
        // Generate nonce (32 bytes)
        auto nonce = rng_.random(32);
        if (is_server_) {
            server_nonce_ = std::move(nonce);
        } else {
            client_nonce_ = std::move(nonce);
        }
    }

    void Handshake::perform(TcpSocket& socket) {
        // Simple state machine
        if (!is_server_) {
            // CLIENT PATH
            // Client: sends hello, receives server hello, send key exchange, receive finished
            
            // 1. Send client hello
            socket.send_all(build_hello());
            
            // 2. Receive server hello (get length first)
            auto hello_resp = socket.recv_all(4);
            uint32_t len = ntoh32(*reinterpret_cast<uint32_t*>(hello_resp.data()));
            auto msg = socket.recv_all(len);
            parse_hello(msg);

            // 3. Send client key exchange
            socket.send_all(build_key_exchange());

            // 4. Receive server's key exchange
            auto ke_resp_len = socket.recv_all(4);
            len = ntoh32(*reinterpret_cast<uint32_t*>(ke_resp_len.data()));
            auto ke_msg = socket.recv_all(len);
            parse_key_exchange(ke_msg);

            // Log in canonical order: server_ke (peer) then client_ke (ours)
            handshake_log_.insert(handshake_log_.end(), peer_ke_log_.begin(), peer_ke_log_.end());
            handshake_log_.insert(handshake_log_.end(), our_ke_log_.begin(),  our_ke_log_.end());

            // 5. Derive keys
            derive_keys();

            // 6. Send client finished
            socket.send_all(build_finished());

            // 7. Receive server's finished and verify
            auto fin_resp_len = socket.recv_all(4);
            len = ntoh32(*reinterpret_cast<uint32_t*>(fin_resp_len.data()));
            auto fin_msg = socket.recv_all(len);
            if (!verify_finished(fin_msg)) {
                throw std::runtime_error("Server finished verification failed");
            }
        } else {
            // SERVER PATH
            // Server: receive hello, send hello+key exchange, receive key exchange, receive finished, send finished
            
            // 1. Receive client hello
            auto hello_len_raw = socket.recv_all(4);
            uint32_t len = ntoh32(*reinterpret_cast<uint32_t*>(hello_len_raw.data()));
            auto msg = socket.recv_all(len);
            parse_hello(msg);

            // 2. Send server hello
            socket.send_all(build_hello());

            // 3. Send server key exchange
            socket.send_all(build_key_exchange());

            // 4. Receive client key exchange
            auto ke_len_raw = socket.recv_all(4);
            len = ntoh32(*reinterpret_cast<uint32_t*>(ke_len_raw.data()));
            auto ke_msg = socket.recv_all(len);
            parse_key_exchange(ke_msg);

            // Log in canonical order: server_ke (ours) then client_ke (peer)
            handshake_log_.insert(handshake_log_.end(), our_ke_log_.begin(),  our_ke_log_.end());
            handshake_log_.insert(handshake_log_.end(), peer_ke_log_.begin(), peer_ke_log_.end());

            // 5. Derive keys
            derive_keys();

            // 6. Receive client finished
            auto fin_len_raw = socket.recv_all(4);
            len = ntoh32(*reinterpret_cast<uint32_t*>(fin_len_raw.data()));
            auto fin_msg = socket.recv_all(len);
            if (!verify_finished(fin_msg)) {
                throw std::runtime_error("Client finished verification failed");
            }

            // 7. Send server finished
            socket.send_all(build_finished());
        }
    }

    std::vector<uint8_t> Handshake::build_hello() {
        // Message format: [type (1) = 0x01] [nonce (32)]
        std::vector<uint8_t> msg;
        msg.push_back(0x01); // Hello type
        if (is_server_) {
            msg.insert(msg.end(), server_nonce_.begin(), server_nonce_.end());
        } else {
            msg.insert(msg.end(), client_nonce_.begin(), client_nonce_.end());
        }

        handshake_log_.insert(handshake_log_.end(), msg.begin(), msg.end());
        return frame(msg);
    }

    void Handshake::parse_hello(const std::vector<uint8_t>& msg) {
        if (msg.empty() || msg[0] != 0x01) {
            throw std::runtime_error("Invalid hello message");
        }
        
        std::vector<uint8_t> nonce(msg.begin() + 1, msg.end());
        if (nonce.size() != 32) {
            throw std::runtime_error("Invalid nonce length");
        }
        
        if (is_server_) {
            client_nonce_ = std::move(nonce);
        } else {
            server_nonce_ = std::move(nonce);
        }
        
        // Append to handshake log for finished message verification
        handshake_log_.insert(handshake_log_.end(), msg.begin(), msg.end());
    }

    std::vector<uint8_t> Handshake::build_key_exchange() {
        dh_.make_public(rng_);
        auto pub = dh_.get_public();

        std::vector<uint8_t> msg;
        msg.push_back(0x02);
        uint16_t len = static_cast<uint16_t>(pub.size());
        msg.push_back((len >> 8) & 0xFF);
        msg.push_back(len & 0xFF);
        msg.insert(msg.end(), pub.begin(), pub.end());

        our_ke_log_ = msg; // store for ordered logging in perform()
        return frame(msg);
    }

    void Handshake::parse_key_exchange(const std::vector<uint8_t>& msg) {
        if (msg.empty() || msg[0] != 0x02)
            throw std::runtime_error("Invalid key exchange message");
        if (msg.size() < 3)
            throw std::runtime_error("Key exchange message too short");

        uint16_t len = (msg[1] << 8) | msg[2];
        if (msg.size() != 3 + static_cast<size_t>(len))
            throw std::runtime_error("Key exchange length mismatch");

        std::vector<uint8_t> peer_pub(msg.begin() + 3, msg.end());
        shared_secret_ = dh_.compute_shared(peer_pub, rng_);

        peer_ke_log_ = msg; // store for ordered logging in perform()
    }

    void Handshake::derive_keys() {
        // Derive master secret from shared secret and nonces
        // We use SHA256 with different labels to derive two distinct keys
        
        // Derive client write key
        {
            Sha256 sha;
            sha.update(shared_secret_);
            sha.update(client_nonce_);
            sha.update(server_nonce_);
            sha.update(reinterpret_cast<const uint8_t*>("client"), 6);
            client_write_key_ = sha.finish();
        }

        // Derive server write key
        {
            Sha256 sha;
            sha.update(shared_secret_);
            sha.update(client_nonce_);
            sha.update(server_nonce_);
            sha.update(reinterpret_cast<const uint8_t*>("server"), 6);
            server_write_key_ = sha.finish();
        }
    }

    std::vector<uint8_t> Handshake::build_finished() {
        // Message format: [type (1) = 0x03] [hash (32)]
        std::vector<uint8_t> msg;
        msg.push_back(0x03); // Finished type

        Sha256 sha;
        sha.update(handshake_log_);
        auto hash = sha.finish();
        msg.insert(msg.end(), hash.begin(), hash.end());

        return frame(msg);
    }

    bool Handshake::verify_finished(const std::vector<uint8_t>& msg) {
        // Verify finished message
        if (msg.empty() || msg[0] != 0x03) {
            return false;
        }
        
        if (msg.size() != 33) { // 1 byte type + 32 bytes hash
            return false;
        }
        
        // Extract the received hash
        std::vector<uint8_t> received_hash(msg.begin() + 1, msg.end());
        
        // Compute expected hash from handshake log
        Sha256 sha;
        sha.update(handshake_log_);
        auto expected_hash = sha.finish();
        
        // Compare hashes
        if (received_hash.size() != expected_hash.size()) {
            return false;
        }
        
        // Constant-time comparison to prevent timing attacks
        uint8_t diff = 0;
        for (size_t i = 0; i < received_hash.size(); i++) {
            diff |= received_hash[i] ^ expected_hash[i];
        }
        
        return diff == 0;
    }

} // namespace secure_channel
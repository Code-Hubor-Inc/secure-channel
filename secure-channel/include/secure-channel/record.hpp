#pragma once

#include "crypto.hpp"
#include <cstdint>
#include <vector>

namespace secure_channel {

    class RecordLayer {
    public:
        RecordLayer(bool is_client, const std::vector<uint8_t>& key);

        std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext);
        std::vector<uint8_t> decrypt(const std::vector<uint8_t>& record);

        private:
            bool is_client_;
            GcmContext gcm_;
            uint32_t send_seq_;
            uint32_t recv_seq_;

            static constexpr size_t NONCE_SIZE = 12;
            static constexpr size_t TAG_SIZE = 16;
            static constexpr size_t HEADER_SIZE = 4 + NONCE_SIZE; // seq + nonce
    };
} // namespace secure_channel
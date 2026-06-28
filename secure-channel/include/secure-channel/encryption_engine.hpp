#pragma once

#include "secure-channel/key_manager.hpp"
#include <vector>
#include <cstdint>

namespace secure_channel {
    
    // What encrypt() returns and decrypt() consumes.
    // ciphertext layout: [12-byte nonce][encrypted data][16-byte tag]
    struct EncryptedBlob {
        std::vector<uint8_t> ciphertext;
        WrappedKey           wrapped_dek;
    };

    class EncryptionEngine {
        public: 
            explicit EncryptionEngine(KeyManager & key_manager);

            // Encrypt plaintext. Generate a fresh DEK and random nonoce every call.
            EncryptedBlob encrypt(const std::vector<uint8_t>& plain);

            // Decrypt a blob produced by encrypt().
            std::vector<uint8_t> decrypt(const EncryptedBlob& blob);

        private:
            KeyManager& key_manager_;
            CtrDrbg     rng_;     
    };
} // namespace secure_channel
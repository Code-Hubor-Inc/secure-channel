#pragma once

#include "secure-channel/crypto.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace secure_channel {
    // A DEK wrapped  (encrypted) under a KEK.
    // Store this alongside your ciphertext - its useless without the master key.
    struct WrappedKey {
        // Layout: [12bytes nonce][32-bytes enc_dec][16-byte tag] = always 60 bytes
        std::vector<uint8_t> data;
        uint32_t version; // which KEK version was used to wrap this DEK
    };

    // Return by generated_dek() - use raw for encryption, stire wrapped the ciphertext.
    struct DekPair {
        std::vector<uint8_t> raw; // 32-byte DEK - zero it after use
        WrappedKey wrapped; // persist this in the DB alongside the ciphertext
    };

    struct KeyVersion {
        uint32_t number;
        int64_t created_unix; //second since epoch
        bool active;
    };

    class KeyManager {
        public:
            // master_key: exactly 32 bytes - the root secret (load from env or file)
            //storage_path: file where key version metadata is persisted
            KeyManager(std::vector<uint8_t> master_key, const std::string& storage_path);
            ~KeyManager();

            // Generate a fresh random DEK and return it wrapped under the active KEK.
            DekPair generate_dek();

            // Wrap an existing raw DEK under active KEK.
            WrappedKey wrap_dek(const std::vector<uint8_t>& raw_dek);

            // Unwrap a wrapped DEK - uses the version recorded in wrapped version.
            std::vector<uint8_t> unwrap_dek(const WrappedKey& wrapped);

            // Add a new active KEK version; old versions remain for unwrapping.
            void rotate();

            uint32_t active_version() const;

            void save();
            void load();

        private:
            std::vector<uint8_t> master_key_;
            std::string storage_path_;
            std::vector<KeyVersion> versions_;
            CtrDrbg rng_;
            
            // Derives a 32-byte KEK deterministically: SHA256(master_key || version)
            std::vector<uint8_t> derive_kek(uint32_t version) const;
    };
} // namespace secure_channel
#include "secure-channel/encryption_engine.hpp"
#include "secure-channel/common.hpp"
#include <algorithm>
#include <stdexcept>

namespace secure_channel {

    EncryptionEngine::EncryptionEngine(KeyManager& key_manager)
        : key_manager_(key_manager) {}

    EncryptedBlob EncryptionEngine::encrypt(const std::vector<uint8_t>& plain) {
        // Fresh DEK per secret - compromise of one ciphertext doesnt affect others.
        DekPair dek = key_manager_.generate_dek();

        auto nonce = rng_.random(NONCE_SIZE);

        GcmContext gcm;
        gcm.set_key(dek.raw);
        auto cipher_and_tag = gcm.encrypt(plain, nonce); //[data][tag]

        std::fill(dek.raw.begin(), dek.raw.end(), 0);

        EncryptedBlob blob;
        blob.ciphertext.insert(blob.ciphertext.end(), nonce.begin(), nonce.end());
        blob.ciphertext.insert(blob.ciphertext.end(), cipher_and_tag.begin(), cipher_and_tag.end());
        blob.wrapped_dek = std::move(dek.wrapped);
        return blob; 
    }
    
    std::vector<uint8_t> EncryptionEngine::decrypt(const EncryptedBlob& blob) {
        if (blob.ciphertext.size() < NONCE_SIZE + TAG_SIZE)
            throw std::runtime_error("EncryptionEngine: ciphertext too short");

        auto raw_dek = key_manager_.unwrap_dek(blob.wrapped_dek);

        std::vector<uint8_t> nonce(blob.ciphertext.begin(),
            blob.ciphertext.begin() + NONCE_SIZE);
        std::vector<uint8_t> cipher_and_tag(blob.ciphertext.begin() + NONCE_SIZE,
            blob.ciphertext.end());

        GcmContext gcm;
        gcm.set_key(raw_dek);
        auto plain = gcm.decrypt(cipher_and_tag, nonce);

        std::fill(raw_dek.begin(), raw_dek.end(), 0);
        return plain;
    } 
} // namespace secure_channel
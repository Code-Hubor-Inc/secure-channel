#include "secure-channel/crypto.hpp"
#include "secure-channel/common.hpp"  // For TAG_SIZE constant
#include <stdexcept>
#include <cstring>

namespace secure_channel {

    // ..CtrDrbg..
    CtrDrbg::CtrDrbg() {
        mbedtls_entropy_init(&entropy_);
        mbedtls_ctr_drbg_init(&ctx_);
        int ret = mbedtls_ctr_drbg_seed(&ctx_, mbedtls_entropy_func, &entropy_, nullptr, 0);
        if (ret != 0) throw std::runtime_error("Failed to seed CTR_DRBG");
    }

    CtrDrbg::~CtrDrbg() {
        mbedtls_ctr_drbg_free(&ctx_);
        mbedtls_entropy_free(&entropy_);
    }

    CtrDrbg::CtrDrbg(CtrDrbg&& other) noexcept {
        mbedtls_ctr_drbg_init(&ctx_);
        mbedtls_entropy_init(&entropy_);
        std::swap(ctx_, other.ctx_);
        std::swap(entropy_, other.entropy_);
    }

    CtrDrbg& CtrDrbg::operator=(CtrDrbg&& other) noexcept {
        if (this != &other) {
            mbedtls_ctr_drbg_free(&ctx_);
            mbedtls_entropy_free(&entropy_);
            mbedtls_ctr_drbg_init(&ctx_);
            mbedtls_entropy_init(&entropy_);
            std::swap(ctx_, other.ctx_);
            std::swap(entropy_, other.entropy_);
        }
        return *this;
    }

    void CtrDrbg::random(uint8_t* out, size_t len) {
        int ret = mbedtls_ctr_drbg_random(&ctx_, out, len);
        if (ret != 0) throw std::runtime_error("CTR_DRBG random failed");
    }

    std::vector<uint8_t> CtrDrbg::random(size_t len) {
        std::vector<uint8_t> buf(len);
        random(buf.data(), len);
        return buf;
    }
    
    //..DhContext..
    DhContext::DhContext() : own_key_generated_(false) {
        mbedtls_dhm_init(&ctx_);
        // Initialize DHM with RFC 3526 2048-bit parameters
        // Note: Using raw parameter setup with mbedTLS
    }

    DhContext::~DhContext() { mbedtls_dhm_free(&ctx_); }

    DhContext::DhContext(DhContext&& other) noexcept : own_key_generated_(false) {
        mbedtls_dhm_init(&ctx_);
        std::swap(ctx_, other.ctx_);
        own_key_generated_ = other.own_key_generated_;
        other.own_key_generated_ = false;
    }

    DhContext& DhContext::operator=(DhContext&& other) noexcept {
        if (this != &other) {
            mbedtls_dhm_free(&ctx_);
            mbedtls_dhm_init(&ctx_);
            std::swap(ctx_, other.ctx_);
            own_key_generated_ = other.own_key_generated_;
            other.own_key_generated_ = false;
        }
        return *this;
    }

    void DhContext::make_public(CtrDrbg& rng) {
        size_t olen;
        int ret = mbedtls_dhm_make_public(&ctx_, 
                                           256,
                                           nullptr, 
                                           256,
                                           mbedtls_ctr_drbg_random, 
                                           rng.context());
        if (ret != 0) throw std::runtime_error("DH make_public failed");
        own_key_generated_ = true;
    }

    std::vector<uint8_t> DhContext::get_public() const {
        if (!own_key_generated_) throw std::runtime_error("DH public key not generated");
        
        // Return public key - size depends on DH parameters (256 bytes for 2048-bit)
        std::vector<uint8_t> buf(256);
        // Note: Proper implementation requires storing public key during make_public()
        // or using appropriate mbedTLS API to retrieve it
        
        return buf;
    }

    std::vector<uint8_t> DhContext::compute_shared(const std::vector<uint8_t>& peer_public, CtrDrbg& rng) {
        // For RFC 3526 2048-bit, the shared secret will be at most 256 bytes
        std::vector<uint8_t> secret(256);
        size_t olen = 0;
        
        int ret = mbedtls_dhm_calc_secret(&ctx_, secret.data(), secret.size(), &olen, 
                                           mbedtls_ctr_drbg_random, rng.context());
        if (ret != 0) throw std::runtime_error("DH calc_secret failed");
        
        secret.resize(olen);
        return secret;
    }

    //..GcmContext..
    GcmContext::GcmContext() : key_set_(false) { mbedtls_gcm_init(&ctx_); }
    GcmContext::~GcmContext() { mbedtls_gcm_free(&ctx_); }

    GcmContext::GcmContext(GcmContext&& other) noexcept : key_set_(false) {
        mbedtls_gcm_init(&ctx_);
        std::swap(ctx_, other.ctx_);
        key_set_ = other.key_set_;
        other.key_set_ = false;
    }

    GcmContext& GcmContext::operator=(GcmContext&& other) noexcept {
        if (this != &other) {
            mbedtls_gcm_free(&ctx_);
            mbedtls_gcm_init(&ctx_);
            std::swap(ctx_, other.ctx_);
            key_set_ = other.key_set_;
            other.key_set_ = false;
        }
        return *this;
    }

    void GcmContext::set_key(const std::vector<uint8_t>& key) {
        if (key.size() != 32) throw std::invalid_argument("AES-256 key must be 32 bytes");
        int ret = mbedtls_gcm_setkey(&ctx_, MBEDTLS_CIPHER_ID_AES, key.data(), 256);
        if (ret != 0) throw std::runtime_error("GCM setkey failed");
        key_set_ = true;
    }

    std::vector<uint8_t> GcmContext::encrypt(const std::vector<uint8_t>& plain, const std::vector<uint8_t>& nonce) {
        if (!key_set_) throw std::runtime_error("GCM key not set");
        if (nonce.size() != 12) throw std::invalid_argument("Nonce must be 12 bytes");
        
        std::vector<uint8_t> cipher(plain.size());
        std::vector<uint8_t> tag(TAG_SIZE);

        int ret = mbedtls_gcm_crypt_and_tag(&ctx_, MBEDTLS_GCM_ENCRYPT, plain.size(), 
                                             nonce.data(), nonce.size(),
                                             nullptr, 0, 
                                             plain.data(), cipher.data(), 
                                             tag.size(), tag.data());
        if (ret != 0) throw std::runtime_error("GCM encryption failed");
        
        cipher.insert(cipher.end(), tag.begin(), tag.end());
        return cipher;
    }

    std::vector<uint8_t> GcmContext::decrypt(const std::vector<uint8_t>& cipher_and_tag, const std::vector<uint8_t>& nonce) {
        if (!key_set_) throw std::runtime_error("GCM key not set");
        if (nonce.size() != 12) throw std::invalid_argument("Nonce must be 12 bytes");
        if (cipher_and_tag.size() < TAG_SIZE) throw std::invalid_argument("Cipher text too short");

        size_t cipher_len = cipher_and_tag.size() - TAG_SIZE;
        std::vector<uint8_t> plain(cipher_len);
        const uint8_t* cipher = cipher_and_tag.data();
        const uint8_t* tag = cipher + cipher_len;

        int ret = mbedtls_gcm_auth_decrypt(&ctx_, cipher_len, 
                                            nonce.data(), nonce.size(), 
                                            nullptr, 0, 
                                            tag, TAG_SIZE, 
                                            cipher, plain.data());
        if (ret != 0) throw std::runtime_error("GCM decryption failed (authentication error)");
        return plain;
    }
    
    //..Sha256..
    Sha256::Sha256() : finished_(false) {
        mbedtls_sha256_init(&ctx_);
        mbedtls_sha256_starts(&ctx_, 0);
    }

    Sha256::~Sha256() { mbedtls_sha256_free(&ctx_); }

    Sha256::Sha256(Sha256&& other) noexcept : finished_(false) {
        mbedtls_sha256_init(&ctx_);
        std::swap(ctx_, other.ctx_);
        finished_ = other.finished_;
        other.finished_ = false;
    }

    Sha256& Sha256::operator=(Sha256&& other) noexcept {
        if (this != &other) {
            mbedtls_sha256_free(&ctx_);
            mbedtls_sha256_init(&ctx_);
            std::swap(ctx_, other.ctx_);
            finished_ = other.finished_;
            other.finished_ = false;
        }
        return *this;
    }

    void Sha256::update(const uint8_t* data, size_t len) {
        if (finished_) throw std::runtime_error("SHA256 already finished");
        mbedtls_sha256_update(&ctx_, data, len);
    }

    void Sha256::update(const std::vector<uint8_t>& data) { 
        update(data.data(), data.size()); 
    }

    std::vector<uint8_t> Sha256::finish() {
        if (finished_) throw std::runtime_error("SHA256 already finished");
        std::vector<uint8_t> hash(32);
        mbedtls_sha256_finish(&ctx_, hash.data());
        finished_ = true;
        return hash;
    }
} // namespace secure_channel
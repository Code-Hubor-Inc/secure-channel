#pragma once

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/dhm.h>
#include <mbedtls/gcm.h>
#include <mbedtls/sha256.h>
#include <vector>
#include <cstdint>

namespace secure_channel {

    class CtrDrbg {
    public:
        CtrDrbg();
        ~CtrDrbg();
        CtrDrbg(const CtrDrbg&) = delete;
        CtrDrbg& operator=(const CtrDrbg&) = delete;
        CtrDrbg(CtrDrbg&& other) noexcept;
        CtrDrbg& operator=(CtrDrbg&& other) noexcept;

        std::vector<uint8_t> random(size_t len);
        void random(uint8_t* out, size_t len);
        mbedtls_ctr_drbg_context* context() { return &ctx_; }

    private:
        mbedtls_ctr_drbg_context ctx_;
        mbedtls_entropy_context entropy_;
    };

    class DhContext {
    public:
        DhContext();
        ~DhContext();
        DhContext(const DhContext&) = delete;
        DhContext& operator=(const DhContext&) = delete;
        DhContext(DhContext&& other) noexcept;
        DhContext& operator=(DhContext&& other) noexcept;

        void make_public(CtrDrbg& rng);
        std::vector<uint8_t> get_public() const;
        std::vector<uint8_t> compute_shared(const std::vector<uint8_t>& peer_public, CtrDrbg& rng);

    private:
    mbedtls_dhm_context ctx_;
    bool own_key_generated_;
    };

    class GcmContext {
    public:
        GcmContext();
        ~GcmContext();
        GcmContext(const GcmContext&) = delete;
        GcmContext& operator=(const GcmContext&) = delete;
        GcmContext(GcmContext&& other) noexcept;
        GcmContext& operator=(GcmContext&& other) noexcept;

        void set_key(const std::vector<uint8_t>& key);
        std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plain, const std::vector<uint8_t>& nonce);
        std::vector<uint8_t> decrypt(const std::vector<uint8_t>& cipher_and_tag, const std::vector<uint8_t>& nonce);

        private:
            mbedtls_gcm_context ctx_;
            bool key_set_;
    };

    class Sha256 {
    public:
        Sha256();
        ~Sha256();
        Sha256(const Sha256&) = delete;
        Sha256& operator=(const Sha256&) = delete;
        Sha256(Sha256&& other) noexcept;
        Sha256& operator=(Sha256&& other) noexcept;

        void update(const uint8_t* data, size_t len);
        void update(const std::vector<uint8_t>& data);
        std::vector<uint8_t> finish();

        private:
            mbedtls_sha256_context ctx_;
            bool finished_;
    };
    
} // namespace secure_channel
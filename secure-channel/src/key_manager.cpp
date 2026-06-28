#include "secure-channel/key_manager.hpp"
#include "secure-channel/common.hpp"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <stdexcept>

namespace secure_channel {
    KeyManager::KeyManager(std::vector<uint8_t> master_key, const std::string& storage_path)
    : master_key_(std::move(master_key)), storage_path_(storage_path)
    {
        if (master_key_.size() != 32)
            throw std::invalid_argument("Master key must be exactly 32 bytes");
        load();
        if (versions_.empty()) {
            auto now = std::chrono::system_clock::now();
            int64_t ts = std::chrono::duration_cast<std::chrono::seconds>(
                 now.time_since_epoch()).count();
            versions_.push_back({1, ts, true});     
            save();
        }    
    }

    KeyManager::~KeyManager() {
        std::fill(master_key_.begin(), master_key_.end(), 0);
    }

    std::vector<uint8_t> KeyManager::derive_kek(uint32_t version ) const {
        // SHA256(master_key || version_bytes) -> deterministic 32-byte KEK
        Sha256 sha;
        sha.update(master_key_);
        uint8_t ver_bytes[4];
        ver_bytes[0] = (version >> 24) & 0xFF;
        ver_bytes[1] = (version >> 16) & 0xFF;
        ver_bytes[2] = (version >> 8) & 0xFF;
        ver_bytes[3] = (version )     & 0xFF;
        sha.update(ver_bytes, 4);
        return sha.finish();
    }

    DekPair KeyManager::generate_dek() {
        DekPair pair;
        pair.raw = rng_.random(32);
        pair.wrapped = wrap_dek(pair.raw);
        return pair;
    }

    WrappedKey KeyManager::wrap_dek(const std::vector<uint8_t>& raw_dek) {
        if (raw_dek.size() != 32)
            throw std::invalid_argument("DEK must be 32 bytes");

        uint32_t version = active_version();
        auto kek = derive_kek(version);
        auto nonce = rng_.random(12);
        
        GcmContext gcm;
        gcm.set_key(kek);
        auto enc = gcm.encrypt(raw_dek, nonce); // enc = [32-byte ciphertext][16-byte tag]

        std::fill(kek.begin(), kek.end(), 0);

        WrappedKey wk;
        wk.version = version;
        wk.data.insert(wk.data.end(), nonce.begin(), nonce.end()); // 12 bytes
        wk.data.insert(wk.data.end(), enc.begin(), enc.end()); // 48 bytes (32 + 16)
        return wk;
    }

    std::vector<uint8_t> KeyManager::unwrap_dek(const WrappedKey& wrapped) {
        // Expected layout: [12-byte nonce][32-byte enc_dek][16-byte tag] = 60 bytes
        if (wrapped.data.size() != 60)
            throw std::runtime_error("Invalid wrapped key size");
        
        auto kek = derive_kek(wrapped.version);
        
        std::vector<uint8_t> nonce(wrapped.data.begin(), wrapped.data.begin() + 12);
        std::vector<uint8_t> enc_and_tag(wrapped.data.begin() + 12, wrapped.data.end());

        GcmContext gcm;
        gcm.set_key(kek);
        auto raw_dek = gcm.decrypt(enc_and_tag, nonce);

        std::fill(kek.begin(), kek.end(), 0);
        return raw_dek;
    }

    void KeyManager::rotate() {
        for (auto& v : versions_) v.active = false;

        uint32_t next = versions_.back().number + 1;
        auto now = std::chrono::system_clock::now();
        int64_t ts = std::chrono::duration_cast<std::chrono::seconds>(
             now.time_since_epoch()).count();
        versions_.push_back({next, ts, true});
        save();
        LOG_INFO("KeyManager: rotated to KEK version " << next);     
    }

    uint32_t KeyManager::active_version() const {
        for (auto it = versions_.rbegin(); it != versions_.rend(); ++it)
            if (it->active) return it->number;
        throw std::runtime_error("No active KEK version found");   
    }

    void KeyManager::save() {
        std::ofstream ofs(storage_path_, std::ios::binary | std::ios::trunc);
        if (!ofs) throw std::runtime_error("KeyManager cannot open " + storage_path_);

        uint32_t count = static_cast<uint32_t>(versions_.size());
        ofs.write(reinterpret_cast<const char*>(&count), sizeof(count));
        for (const auto& v : versions_) {
            ofs.write(reinterpret_cast<const char*>(&v.number),       sizeof(v.number));
            ofs.write(reinterpret_cast<const char*>(&v.created_unix), sizeof(v.created_unix));
            uint8_t active = v.active ? 1 : 0;
            ofs.write(reinterpret_cast<const char*>(&active),         sizeof(active));
        }
    }

    void KeyManager::load() {
        std::ifstream ifs(storage_path_, std::ios::binary);
        if (!ifs) return;

        uint32_t count = 0;
        ifs.read(reinterpret_cast<char*>(&count), sizeof(count));
        versions_.clear();
        for (uint32_t i = 0; i < count; ++i) {
            KeyVersion v{};
            uint8_t active = 0;
            ifs.read(reinterpret_cast<char*>(&v.number),       sizeof(v.number));
            ifs.read(reinterpret_cast<char*>(&v.created_unix), sizeof(v.created_unix));
            ifs.read(reinterpret_cast<char*>(&active),         sizeof(active));
            v.active = (active != 0);
            versions_.push_back(v);
        }
    }
} // namespace secure_channel
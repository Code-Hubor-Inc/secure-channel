#include "secure-channel/vault.hpp"
#include "secure-channel/crypto.hpp"
#include "secure-channel/common.hpp"
#include <algorithm>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace secure_channel {

    static std::vector<uint8_t> derive(const std::vector<uint8_t>& base,
                                       const std::string& label) {
        Sha256 sha;
        sha.update(base);
        sha.update(reinterpret_cast<const uint8_t*>(label.data()), label.size());
        return sha.finish();
    }

    Vault::Vault(const std::string& storage_path, std::vector<uint8_t> master_key)
        : storage_path_(storage_path),
          key_manager_(master_key, storage_path + ".keys"),
          engine_(key_manager_)
    {
        auth_verifier_ = derive(master_key, "auth-verifier");
        std::fill(master_key.begin(), master_key.end(), 0);
        load();
        log_action("STARTUP", "Vault initialized");
    }

    Vault::~Vault() {
        save();
        log_action("SHUTDOWN", "Vault closed");
    }

    bool Vault::authenticate(const std::string& password) {
        Sha256 sha;
        sha.update(reinterpret_cast<const uint8_t*>(password.data()), password.size());
        auto candidate_key      = sha.finish();
        auto candidate_verifier = derive(candidate_key, "auth-verifier");

        bool success = (candidate_verifier == auth_verifier_);
        log_action("AUTH", success ? "Login successful" : "Login failed");
        return success;
    }

    void Vault::set_secret(const std::string& key, const std::vector<uint8_t>& value) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto now = std::chrono::system_clock::now();
        if (secrets_.count(key)) {
            secrets_[key].value      = value;
            secrets_[key].updated_at = now;
            log_action("SET", "Updated secret: " + key);
        } else {
            VaultEntry entry;
            entry.value      = value;
            entry.created_at = now;
            entry.updated_at = now;
            secrets_[key] = std::move(entry);
            log_action("SET", "Created secret: " + key);
        }
        save_locked();
    }

    bool Vault::get_secret(const std::string& key, std::vector<uint8_t>& out_value) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (secrets_.count(key)) {
            out_value = secrets_[key].value;
            log_action("GET", "Accessed secret: " + key);
            return true;
        }
        log_action("GET", "Failed access (not found): " + key);
        return false;
    }

    std::vector<std::string> Vault::list_secrets() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> keys;
        for (const auto& pair : secrets_)
            keys.push_back(pair.first);
        log_action("LIST", "Listed all secrets");
        return keys;
    }

    bool Vault::delete_secret(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (secrets_.erase(key)) {
            log_action("DELETE", "Deleted secret: " + key);
            save_locked();
            return true;
        }
        log_action("DELETE", "Failed delete (not found): " + key);
        return false;
    }

    // File layout:
    //   [32-byte auth_verifier]
    //   [8-byte entry count]
    //   per entry:
    //     [8-byte key_len][key bytes]
    //     [8-byte ciphertext_len][ciphertext bytes]
    //     [4-byte wrapped_dek version][60-byte wrapped_dek data]
    void Vault::save() {
        std::lock_guard<std::mutex> lock(mutex_);
        save_locked();
    }

    void Vault::save_locked() {
        std::ofstream ofs(storage_path_, std::ios::binary | std::ios::trunc);
        if (!ofs) {
            LOG_ERROR("Vault: cannot open " << storage_path_ << " for writing");
            return;
        }

        ofs.write(reinterpret_cast<const char*>(auth_verifier_.data()), 32);

        uint64_t count = secrets_.size();
        ofs.write(reinterpret_cast<const char*>(&count), sizeof(count));

        for (const auto& [key, entry] : secrets_) {
            auto blob = engine_.encrypt(entry.value);

            uint64_t key_len = key.size();
            ofs.write(reinterpret_cast<const char*>(&key_len), sizeof(key_len));
            ofs.write(key.data(), key_len);

            uint64_t ct_len = blob.ciphertext.size();
            ofs.write(reinterpret_cast<const char*>(&ct_len), sizeof(ct_len));
            ofs.write(reinterpret_cast<const char*>(blob.ciphertext.data()), ct_len);

            uint32_t ver = blob.wrapped_dek.version;
            ofs.write(reinterpret_cast<const char*>(&ver), sizeof(ver));
            ofs.write(reinterpret_cast<const char*>(blob.wrapped_dek.data.data()), 60);
        }
    }

    void Vault::load() {
        std::ifstream ifs(storage_path_, std::ios::binary);
        if (!ifs) return;

        std::vector<uint8_t> stored_verifier(32);
        if (!ifs.read(reinterpret_cast<char*>(stored_verifier.data()), 32)) return;
        auth_verifier_ = stored_verifier;

        uint64_t count = 0;
        if (!ifs.read(reinterpret_cast<char*>(&count), sizeof(count))) return;

        for (uint64_t i = 0; i < count; ++i) {
            uint64_t key_len = 0;
            if (!ifs.read(reinterpret_cast<char*>(&key_len), sizeof(key_len))) break;
            std::string key(key_len, '\0');
            if (!ifs.read(key.data(), key_len)) break;

            uint64_t ct_len = 0;
            if (!ifs.read(reinterpret_cast<char*>(&ct_len), sizeof(ct_len))) break;
            EncryptedBlob blob;
            blob.ciphertext.resize(ct_len);
            if (!ifs.read(reinterpret_cast<char*>(blob.ciphertext.data()), ct_len)) break;

            uint32_t ver = 0;
            if (!ifs.read(reinterpret_cast<char*>(&ver), sizeof(ver))) break;
            blob.wrapped_dek.version = ver;
            blob.wrapped_dek.data.resize(60);
            if (!ifs.read(reinterpret_cast<char*>(blob.wrapped_dek.data.data()), 60)) break;

            try {
                auto plain = engine_.decrypt(blob);
                auto now   = std::chrono::system_clock::now();
                VaultEntry e;
                e.value      = plain;
                e.wrapped_dek = blob.wrapped_dek;
                e.created_at = now;
                e.updated_at = now;
                secrets_[key] = std::move(e);
            } catch (const std::exception& e) {
                LOG_ERROR("Vault: failed to decrypt entry '" << key << "': " << e.what());
            }
        }
    }

    void Vault::log_action(const std::string& action, const std::string& details) {
        auto now  = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S")
           << " [" << action << "] " << details;
        write_audit_log(ss.str());
    }

    void Vault::write_audit_log(const std::string& entry) {
        std::ofstream log_file("vault_audit.log", std::ios::app);
        if (log_file) log_file << entry << "\n";
        LOG_INFO("Audit: " << entry);
    }

} // namespace secure_channel

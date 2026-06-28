#pragma once
#include "secure-channel/encryption_engine.hpp"

#include <string>
#include <vector>
#include <map>
#include <mutex>
// #include <fstream>
#include <chrono>

namespace secure_channel {

    enum class CommandType : uint8_t {
        LOGIN = 0x01,
        SET = 0x02,
        GET = 0x03,
        LIST = 0x04,
        DELETE = 0x05,
        LOGOUT = 0x06,
        RESPONSE = 0x80,
        ERROR = 0xFF
    };

    struct VaultEntry {
        std::vector<uint8_t> value; // plaintext, held in memory only.
        WrappedKey           wrapped_dek; // persisted to sidk alongside ciphertext
        std::chrono::system_clock::time_point created_at;
        std::chrono::system_clock::time_point updated_at;
    };

    class Vault {
    public:
        // master_key: exactly 32 bytes - derive it from your password before passing it
        Vault(const std::string& storage_path, std::vector<uint8_t> master_key);
        ~Vault();

        bool authenticate(const std::string& password);
        
        void set_secret(const std::string& key, const std::vector<uint8_t>& value);
        bool get_secret(const std::string& key, std::vector<uint8_t>& out_value);
        std::vector<std::string> list_secrets();
        bool delete_secret(const std::string& key);

        void save();  // public: acquires mutex
        void load();

        void log_action(const std::string& action, const std::string& details);

    private:
        std::string storage_path_;
        std::vector<uint8_t> auth_verifier_; // SHA256(master_key || "auth-verifier") stored on disk
        std::map<std::string, VaultEntry> secrets_;
        std::mutex mutex_;

        KeyManager       key_manager_;
        EncryptionEngine engine_;

        void save_locked(); // save without acquiring mutex (caller already holds it)
        void write_audit_log(const std::string& entry);
    };

    // Forward declarations
    class RecordLayer;
    class TcpSocket;

    class VaultClient {
    public:
        VaultClient(TcpSocket& socket, RecordLayer& receiver, RecordLayer& sender);

        bool login(const std::string& password);
        bool set(const std::string& key, const std::vector<uint8_t>& value);
        bool get(const std::string& key, std::vector<uint8_t>& out_value);
        std::vector<std::string> list();
        bool del(const std::string& key);
        void logout();

    private:
        TcpSocket& socket_;
        RecordLayer& receiver_;
        RecordLayer& sender_;

        std::vector<uint8_t> send_and_receive(const std::vector<uint8_t>& payload);
    };

    void handle_vault_session(TcpSocket& socket, RecordLayer& receiver, RecordLayer& sender, Vault& vault);

} // namespace secure_channel

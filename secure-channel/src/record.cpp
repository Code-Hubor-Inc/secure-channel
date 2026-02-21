#include "secure-channel/record.hpp"
#include "secure-channel/common.hpp"
#include <cstring>
#include <stdexcept>

namespace secure_channel {

RecordLayer::RecordLayer(bool is_client, const std::vector<uint8_t>& key)
    : is_client_(is_client), send_seq_(0), recv_seq_(0) {
        gcm_.set_key(key);
    }

std::vector<uint8_t> RecordLayer::encrypt(const std::vector<uint8_t>& plaintext) {
    // Build nonce: first 4 bytes are send_seq in network order, rest zero
    uint8_t nonce[NONCE_SIZE] = {0};
    uint32_t seq_net = hton(send_seq_);
    memcpy(nonce, &seq_net, 4);

    auto cipher_and_tag = gcm_.encrypt(plaintext, std::vector<uint8_t>(nonce, nonce + NONCE_SIZE));

    // construct record: [sequence number (4) | nonce (12) ciphertext+tag]
    std::vector<uint8_t> record;
    record.resize(4 + NONCE_SIZE + cipher_and_tag.size());
    memcpy(record.data(), &seq_net, 4);
    memcpy(record.data() + 4, nonce, NONCE_SIZE);
    memcpy(record.data() + 4 + NONCE_SIZE, cipher_and_tag.data(), cipher_and_tag.size());

    send_seq_++;
    return record;
}

std::vector<uint8_t> RecordLayer::decrypt(const std::vector<uint8_t>& record)
{
    if (record.size() < HEADER_SIZE + TAG_SIZE)
        throw std::runtime_error("Record too short");

    // Extract sequence number
    uint32_t seq_net;
    memcpy(&seq_net, record.data(), 4);
    uint32_t seq = ntoh32(seq_net);

    // Replay protection
    if (seq != recv_seq_)
        throw std::runtime_error("Out-of-order or replayed packet");

    // Extract nonce (first 4 bytes are the sequence number, rest zeros)
    std::vector<uint8_t> nonce(record.begin() + 4, record.begin() + 4 + NONCE_SIZE);

    // Ciphertext and tag
    std::vector<uint8_t> cipher_and_tag(record.begin() + 4 + NONCE_SIZE, record.end());

    auto plain = gcm_.decrypt(cipher_and_tag, nonce);
    recv_seq_++;
    return plain;
}

} // namespace secure-channel
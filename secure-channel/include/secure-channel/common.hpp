#pragma once

#include <cstdint>
#include <iostream>
#include <vector>
#include <stdexcept>
#include <arpa/inet.h>

#define LOG_ERROR(msg) std::cerr << "[ERROR] " << msg << std::endl
#define LOG_INFO(msg) std::cout << "[INFO] " << msg << std::endl

constexpr uint16_t DEFAULT_PORT = 4444;
constexpr size_t MAX_PAYLOAD = 1024;
constexpr size_t NONCE_SIZE = 12;
constexpr size_t TAG_SIZE = 16;

inline uint32_t hton(uint32_t host) {
    return ((host & 0xFF000000) >> 24) | ((host & 0x00FF0000) >> 8) |
            ((host & 0x0000FF00) << 8) | ((host & 0x000000FF) << 24);
}

inline uint32_t ntoh32(uint32_t net) { return htonl(net); }
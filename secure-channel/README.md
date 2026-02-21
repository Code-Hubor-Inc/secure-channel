# Secure communication Protocol (Mini TLS)

This project implements a simplified secure channel between a client and a server
Similar to the core of TLS, its feartures:

- Diffle-Hellman Key exchange(2048-bit)
- AES-256-GCM authenticated encryption
- SHA256-based key deriviation
- Replay protection via sequence numbers
- Clean RAII wrapper for mbedTLS and sockets

## Building

## Dependencies
- CMake ≥ 3.10
- mbedTLS development libraries (libmbedtls-dev on ubuntu/Debian)

### Build steps
```bash
mkdir build && cd build
cmake ..
make
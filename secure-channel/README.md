# Secure Vault over Mini TLS

This project implements a secure secret vault accessible via a simplified secure channel (Mini TLS).

## Features

- **Secure Channel**:
    - Diffie-Hellman Key exchange (2048-bit)
    - AES-256-GCM authenticated encryption for all traffic
    - SHA256-based key derivation
    - Replay protection via sequence numbers
- **Vault Operations**:
    - **Secret Storage**: Store and retrieve secrets (binary data) via `SET` and `GET`.
    - **Mutual Authentication**: Client must authenticate with a password after the secure channel is established.
    - **Encryption at Rest**: Vault data is encrypted on disk using AES-GCM with a key derived from a master password.
    - **Audit Logging**: All vault operations are logged with timestamps and status.

## Project Structure

- `include/secure-channel/`: Header files for crypto, network, record layer, and vault.
- `src/`: Implementation files.
- `src/server/`: Vault server implementation.
- `src/client/`: Vault CLI client implementation.

## Dependencies

- CMake ≥ 3.10
- mbedTLS development libraries (`libmbedtls-dev` on Ubuntu/Debian)

## Building

```bash
mkdir build && cd build
cmake ..
make
```

## Usage

### 1. Start the Server
```bash
./secure_server
```
The server will initialize a `vault.db` file (encrypted) and listen on port 4444.

### 2. Run the Client
```bash
./secure_client
```
The client will connect and establish a secure channel. You can then use the following commands:
- `login <password>`: Authenticate (default: `master_key_123`)
- `set <key> <value>`: Store a secret
- `get <key>`: Retrieve a secret
- `list`: List all secret keys
- `logout`: End the session
- `quit`: Exit the client
# Combined image: the C++ vault server/client and the Node HTTP bridge run in the
# same container, since secure_client only ever dials 127.0.0.1:4444 (no configurable
# host) — splitting them across containers would require patching the C++ networking
# code, which we deliberately avoid touching here.

FROM debian:bookworm-slim AS cpp-build

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake build-essential pkg-config libmbedtls-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src/secure-channel
COPY secure-channel/ .
RUN mkdir build && cd build && cmake -DCMAKE_BUILD_TYPE=Release .. && make -j"$(nproc)"

FROM node:20-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libmbedtls14 libmbedcrypto7 libmbedx509-1 tini bash \
    && rm -rf /var/lib/apt/lists/*

COPY --from=cpp-build /src/secure-channel/build/secure_server /usr/local/bin/secure_server
COPY --from=cpp-build /src/secure-channel/build/secure_client /usr/local/bin/secure_client

WORKDIR /app
COPY vault-api-bridge/package.json vault-api-bridge/package-lock.json ./
RUN npm ci --omit=dev
COPY vault-api-bridge/server.js vault-api-bridge/index.html vault-api-bridge/create-user.js ./
COPY vault-api-bridge/lib ./lib
COPY deploy/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENV VAULT_CLIENT_PATH=/usr/local/bin/secure_client
ENV PORT=3000

# Runs as root: Railway (and most PaaS volume mounts) mount a fresh volume
# at /data owned by root at container start, overriding any chown baked
# into the image, so a non-root user here can't reliably write to it.
RUN mkdir -p /data
WORKDIR /data

EXPOSE 3000
ENTRYPOINT ["tini", "--", "/usr/local/bin/entrypoint.sh"]

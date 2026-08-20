#!/bin/bash
# Starts the C++ vault server in the background, waits for it to accept
# connections on 127.0.0.1:4444, then execs the Node bridge in the foreground
# so it becomes PID 1's child and receives signals correctly (via tini).
set -eu

if [ -z "${VAULT_PASSWORD:-}" ]; then
    echo "WARNING: VAULT_PASSWORD is not set — falling back to the default" \
         "'master_key_123'. Set VAULT_PASSWORD before deploying anywhere reachable" \
         "from the internet." >&2
fi

secure_server &
SERVER_PID=$!

trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT INT TERM

for i in $(seq 1 50); do
    if kill -0 "$SERVER_PID" 2>/dev/null; then
        if (echo > /dev/tcp/127.0.0.1/4444) 2>/dev/null; then
            break
        fi
    else
        echo "secure_server exited during startup" >&2
        exit 1
    fi
    sleep 0.2
done

exec node /app/server.js

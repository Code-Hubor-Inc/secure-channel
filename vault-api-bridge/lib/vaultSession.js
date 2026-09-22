const { spawn } = require('child_process');

const VAULT_CLIENT_PATH = process.env.VAULT_CLIENT_PATH || '../secure-channel/build/secure_client';
const PROMPT = '> ';
const IDLE_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes

class VaultSession {
    constructor() {
        this.proc = spawn(VAULT_CLIENT_PATH);
        this.buffer = '';
        this.queue = []; // [{ resolve, reject }], one per in-flight command
        this.lastActive = Date.now();
        this.closed = false;

        this.proc.stdout.on('data', (chunk) => this._onData(chunk.toString()));
        this.proc.on('close', () => this._onClose(new Error('vault client process exited')));
        this.proc.on('error', (err) => this._onClose(err));

        // Resolves once the CLI has printed its startup banner and is waiting at "> ".
        this.ready = new Promise((resolve, reject) => this.queue.push({ resolve, reject }));
    }

    _onData(text) {
        this.buffer += text;
        if (this.buffer.endsWith(PROMPT)) {
            const output = this.buffer.slice(0, -PROMPT.length);
            this.buffer = '';
            const pending = this.queue.shift();
            if (pending) pending.resolve(output);
        }
    }

    _onClose(err) {
        this.closed = true;
        while (this.queue.length) this.queue.shift().reject(err);
    }

    // Sends one line, resolves with everything the CLI printed before the next "> " prompt.
    async send(commandLine) {
        if (this.closed) throw new Error('vault session is closed');
        this.lastActive = Date.now();
        const output = await new Promise((resolve, reject) => {
            this.queue.push({ resolve, reject });
            this.proc.stdin.write(commandLine + '\n');
        });
        return output.trim();
    }

    isIdle() {
        return Date.now() - this.lastActive > IDLE_TIMEOUT_MS;
    }

    destroy() {
        if (this.closed) return;
        this.closed = true;
        try { this.proc.stdin.end('quit\n'); } catch (_) {}
        setTimeout(() => { try { this.proc.kill(); } catch (_) {} }, 500);
    }
}

module.exports = { VaultSession, IDLE_TIMEOUT_MS };

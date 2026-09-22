const crypto = require('crypto');
const { VaultSession } = require('./vaultSession');

const sessions = new Map(); // token -> { username, vault, lastActive }

function createToken() {
    return crypto.randomBytes(32).toString('hex');
}

// `username` is only for audit logging — it is never sent to the vault.
// The bridge authenticates to the vault itself using VAULT_PASSWORD.
async function create(username) {
    const vault = new VaultSession();
    await vault.ready;
    const result = await vault.send(`login ${process.env.VAULT_PASSWORD || 'master_key_123'}`);
    if (!result.includes('Login successful')) {
        vault.destroy();
        throw new Error('bridge could not authenticate to the vault — check VAULT_PASSWORD');
    }
    const token = createToken();
    sessions.set(token, { username, vault, lastActive: Date.now() });
    return token;
}

function get(token) {
    const session = sessions.get(token);
    if (!session) return null;
    if (session.vault.isIdle()) { destroy(token); return null; }
    session.lastActive = Date.now();
    return session;
}

function destroy(token) {
    const session = sessions.get(token);
    if (!session) return;
    session.vault.destroy();
    sessions.delete(token);
}

setInterval(() => {
    for (const [token, session] of sessions) {
        if (session.vault.isIdle()) destroy(token);
    }
}, 60 * 1000).unref();

module.exports = { create, get, destroy };

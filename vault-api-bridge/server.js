const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const users = require('./lib/users');
const sessions = require('./lib/sessionStore');

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(__dirname));

// Keys must be alphanumeric + hyphens/underscores only — no spaces or shell metacharacters.
function isValidKey(key) {
    return typeof key === 'string' && /^[a-zA-Z0-9_-]+$/.test(key) && key.length <= 128;
}

// Values are sent as a single line on the vault client's stdin ("set <key> <value>\n"),
// so a newline would let a caller inject extra vault commands into the session.
function isValidValue(value) {
    return typeof value === 'string'
        && value.length > 0
        && value.length <= 4096
        && !/[\r\n]/.test(value);
}

function auditLog(username, action, detail) {
    const line = `${new Date().toISOString()} user=${username} action=${action} ${detail}\n`;
    fs.appendFile('bridge-audit.log', line, () => {}); // cwd is /data (set by WORKDIR)
}

function requireSession(req, res, next) {
    const auth = req.headers['authorization'];
    const token = auth && auth.startsWith('Bearer ') ? auth.slice(7) : null;
    const session = token && sessions.get(token);
    if (!session) return res.status(401).json({ success: false, message: 'Invalid or expired session' });
    req.token = token;
    req.vaultSession = session;
    next();
}

// POST /api/login
// Body: { "username": "...", "password": "..." }
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!(await users.verify(username, password)))
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
    try {
        const token = await sessions.create(username);
        auditLog(username, 'LOGIN', '');
        res.json({ success: true, token });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// POST /api/logout
// Headers: Authorization: Bearer <token>
app.post('/api/logout', requireSession, (req, res) => {
    sessions.destroy(req.token);
    auditLog(req.vaultSession.username, 'LOGOUT', '');
    res.json({ success: true });
});

// POST /api/secrets
// Headers: Authorization: Bearer <token>
// Body: { "key": "mykey", "value": "mysecret" }
app.post('/api/secrets', requireSession, async (req, res) => {
    const { key, value } = req.body;
    if (!isValidKey(key))
        return res.status(400).json({ success: false, message: 'Invalid key — use alphanumeric, hyphens, underscores only' });
    if (!isValidValue(value))
        return res.status(400).json({ success: false, message: 'Value is required and must be under 4096 bytes' });

    try {
        const result = await req.vaultSession.vault.send(`set ${key} ${value}`);
        auditLog(req.vaultSession.username, 'SET', `key=${key}`);
        if (result.includes('Secret stored')) {
            return res.json({ success: true, message: 'Secret stored securely' });
        }
        res.status(500).json({ success: false, message: 'Unexpected vault response' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// GET /api/secrets
// Headers: Authorization: Bearer <token>
app.get('/api/secrets', requireSession, async (req, res) => {
    try {
        const result = await req.vaultSession.vault.send('list');
        const keys = result
            .split('\n')
            .filter(line => line.trim().startsWith('-'))
            .map(line => line.trim().substring(2).trim());
        auditLog(req.vaultSession.username, 'LIST', '');
        res.json({ success: true, keys });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// GET /api/secrets/:key
// Headers: Authorization: Bearer <token>
app.get('/api/secrets/:key', requireSession, async (req, res) => {
    const { key } = req.params;
    if (!isValidKey(key))
        return res.status(400).json({ success: false, message: 'Invalid key format' });

    try {
        const result = await req.vaultSession.vault.send(`get ${key}`);
        auditLog(req.vaultSession.username, 'GET', `key=${key}`);
        const match = result.match(/Value: (.*)/);
        if (match) {
            return res.json({ success: true, key, value: match[1].trim() });
        }
        res.status(404).json({ success: false, message: 'Secret not found' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// DELETE /api/secrets/:key
// Headers: Authorization: Bearer <token>
app.delete('/api/secrets/:key', requireSession, async (req, res) => {
    const { key } = req.params;
    if (!isValidKey(key))
        return res.status(400).json({ success: false, message: 'Invalid key format' });

    try {
        const result = await req.vaultSession.vault.send(`delete ${key}`);
        auditLog(req.vaultSession.username, 'DELETE', `key=${key}`);
        if (result.includes('Secret deleted')) {
            return res.json({ success: true, message: 'Secret deleted' });
        }
        res.status(404).json({ success: false, message: 'Secret not found' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.listen(port, () => {
    console.log(`Vault API Bridge listening at http://localhost:${port}`);
    console.log('');
    console.log('Endpoints');
    console.log('  POST   /api/login             body: { username, password } -> { token }');
    console.log('  POST   /api/logout             Authorization: Bearer <token>');
    console.log('  POST   /api/secrets            Authorization: Bearer <token>  body: { key, value }');
    console.log('  GET    /api/secrets            Authorization: Bearer <token>  list all keys');
    console.log('  GET    /api/secrets/:key       Authorization: Bearer <token>  retrieve a secret');
    console.log('  DELETE /api/secrets/:key       Authorization: Bearer <token>  delete a secret');
});
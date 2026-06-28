const express = require('express');
const { spawn } = require('child_process');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');

const app = express();
const port = 3000;
const COMMAND_TIMEOUT_MS = 8000; // kill subprocess if server doesn't respond in 8s

app.use(cors());
app.use(bodyParser.json());

const VAULT_CLIENT_PATH = path.join(__dirname, '../secure-channel/build/secure_client');

// Extract password from Authorization header: "Basic base64(anything:password)"
// or plain "Bearer <password>" for simplicity in curl testing.
function getPassword(req) {
    const auth = req.headers['authorization'];
    if (!auth) return null;

    if (auth.startsWith('Basic ')) {
        const decoded = Buffer.from(auth.slice(6), 'base64').toString();
        const colon = decoded.indexOf(':');
        return colon !== -1 ? decoded.slice(colon + 1) : decoded;
    }
    if (auth.startsWith('Bearer ')) {
        return auth.slice(7);
    }
    return null;
}

// Keys must be alphanumeric + hyphens/underscores only — no spaces or shell metacharacters.
function isValidKey(key) {
    return typeof key === 'string' && /^[a-zA-Z0-9_-]+$/.test(key) && key.length <= 128;
}

function isValidValue(value) {
    return typeof value === 'string' && value.length > 0 && value.length <= 4096;
}

function runVaultCommand(password, commands) {
    return new Promise((resolve, reject) => {
        const client = spawn(VAULT_CLIENT_PATH);
        let output = '';
        let errorOutput = '';
        let timedOut = false;

        const timer = setTimeout(() => {
            timedOut = true;
            client.kill();
            reject(new Error('Vault server did not respond in time'));
        }, COMMAND_TIMEOUT_MS);

        client.stdout.on('data', (data) => { output += data.toString(); });
        client.stderr.on('data', (data) => { errorOutput += data.toString(); });

        client.on('close', (code) => {
            clearTimeout(timer);
            if (timedOut) return;
            if (code !== 0) {
                reject(new Error(`Client exited with code ${code}: ${errorOutput}`));
            } else {
                resolve(output);
            }
        });

        client.on('error', (err) => {
            clearTimeout(timer);
            reject(new Error(`Failed to spawn vault client: ${err.message}`));
        });

        client.stdin.write(`login ${password}\n`);
        commands.forEach(cmd => { client.stdin.write(cmd + '\n'); });
        client.stdin.write('quit\n');
        client.stdin.end();
    });
}

// POST /api/secrets
// Headers: Authorization: Bearer <password>  (or Basic base64(:password))
// Body: { "key": "mykey", "value": "mysecret" }
app.post('/api/secrets', async (req, res) => {
    const password = getPassword(req);
    if (!password)
        return res.status(401).json({ success: false, message: 'Authorization header required' });

    const { key, value } = req.body;
    if (!isValidKey(key))
        return res.status(400).json({ success: false, message: 'Invalid key — use alphanumeric, hyphens, underscores only' });
    if (!isValidValue(value))
        return res.status(400).json({ success: false, message: 'Value is required and must be under 4096 bytes' });

    try {
        const result = await runVaultCommand(password, [`set ${key} ${value}`]);
        if (result.includes('Login failed')) {
            return res.status(401).json({ success: false, message: 'Invalid password' });
        }
        if (result.includes('Secret stored')) {
            return res.json({ success: true, message: 'Secret stored securely' });
        }
        res.status(500).json({ success: false, message: 'Unexpected vault response' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// GET /api/secrets
// Headers: Authorization: Bearer <password>
app.get('/api/secrets', async (req, res) => {
    const password = getPassword(req);
    if (!password)
        return res.status(401).json({ success: false, message: 'Authorization header required' });

    try {
        const result = await runVaultCommand(password, ['list']);
        if (result.includes('Login failed')) {
            return res.status(401).json({ success: false, message: 'Invalid password' });
        }
        const keys = result
            .split('\n')
            .filter(line => line.trim().startsWith('-'))
            .map(line => line.trim().substring(2).trim());
        res.json({ success: true, keys });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// GET /api/secrets/:key
// Headers: Authorization: Bearer <password>
app.get('/api/secrets/:key', async (req, res) => {
    const password = getPassword(req);
    if (!password)
        return res.status(401).json({ success: false, message: 'Authorization header required' });

    const { key } = req.params;
    if (!isValidKey(key))
        return res.status(400).json({ success: false, message: 'Invalid key format' });

    try {
        const result = await runVaultCommand(password, [`get ${key}`]);
        if (result.includes('Login failed')) {
            return res.status(401).json({ success: false, message: 'Invalid password' });
        }
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
// Headers: Authorization: Bearer <password>
app.delete('/api/secrets/:key', async (req, res) => {
    const password = getPassword(req);
    if (!password)
        return res.status(401).json({ success: false, message: 'Authorization header required' });

    const { key } = req.params;
    if (!isValidKey(key))
        return res.status(400).json({ success: false, message: 'Invalid key format' });

    try {
        const result = await runVaultCommand(password, [`delete ${key}`]);
        if (result.includes('Login failed')) {
            return res.status(401).json({ success: false, message: 'Invalid password' });
        }
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
    console.log('Endpoints (all require: Authorization: Bearer <password>)');
    console.log('  POST   /api/secrets          body: { key, value }');
    console.log('  GET    /api/secrets           list all keys');
    console.log('  GET    /api/secrets/:key      retrieve a secret');
    console.log('  DELETE /api/secrets/:key      delete a secret');
});

const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

const USERS_FILE = process.env.USERS_FILE || path.join(process.cwd(), 'users.json');

function loadUsers() {
    if (!fs.existsSync(USERS_FILE)) return [];
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
}

async function verify(username, password) {
    if (typeof username !== 'string' || typeof password !== 'string') return false;
    const user = loadUsers().find(u => u.username === username);
    if (!user) return false;
    return bcrypt.compare(password, user.passwordHash);
}

module.exports = { verify, loadUsers };

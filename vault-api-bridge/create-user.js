#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

const USERS_FILE = process.env.USERS_FILE || path.join(__dirname, 'users.json');

async function main() {
    const [username, password] = process.argv.slice(2);
    if (!username || !password) {
        console.error('Usage: node create-user.js <username> <password>');
        process.exit(1);
    }
    const users = fs.existsSync(USERS_FILE) ? JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')) : [];
    if (users.some(u => u.username === username)) {
        console.error(`User "${username}" already exists`);
        process.exit(1);
    }
    users.push({ username, passwordHash: await bcrypt.hash(password, 12) });
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    console.log(`User "${username}" created.`);
}

main();
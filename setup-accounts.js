const readline = require('node:readline');
const bcrypt = require('bcryptjs');
const db = require('./database');

const accounts = [
    { username: 'owner', role: 'Owner' },
    { username: 'manager', role: 'Manager' },
    { username: 'it-support', role: 'IT Support' },
    { username: 'staff', role: 'Staf / Resepsionis' }
];

function ask(question) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    return new Promise(resolve => rl.question(question, answer => {
        rl.close();
        resolve(answer.trim());
    }));
}

function askPassword(question) {
    if (!process.stdin.isTTY || typeof process.stdin.setRawMode !== 'function') {
        return Promise.reject(new Error('Jalankan setup dari terminal interaktif agar password dapat dimasukkan secara tersembunyi.'));
    }

    return new Promise((resolve, reject) => {
        const stdin = process.stdin;
        let value = '';
        process.stdout.write(question);
        stdin.setEncoding('utf8');
        stdin.setRawMode(true);
        stdin.resume();

        const finish = (error, password) => {
            stdin.removeListener('data', onData);
            stdin.setRawMode(false);
            process.stdout.write('\n');
            if (error) reject(error);
            else resolve(password);
        };

        const onData = character => {
            if (character === '\u0003') return finish(new Error('Setup dibatalkan.'));
            if (character === '\r' || character === '\n') return finish(null, value);
            if (character === '\u007f' || character === '\b') {
                value = value.slice(0, -1);
                return;
            }
            if (character >= ' ') value += character;
        };

        stdin.on('data', onData);
    });
}

async function main() {
    if (process.stdin.isTTY !== true) {
        throw new Error('Jalankan perintah ini langsung dari terminal interaktif.');
    }

    for (const account of accounts) {
        const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(account.username);
        if (existing) {
            console.log(`Akun ${account.username} sudah ada; tidak diubah.`);
            continue;
        }

        console.log(`\nMembuat akun ${account.role} (username: ${account.username})`);
        const displayName = await ask('Nama pengguna: ');
        if (!displayName || displayName.length > 80) {
            throw new Error('Nama pengguna wajib diisi dan maksimal 80 karakter.');
        }

        const password = await askPassword('Password baru (minimal 12 karakter): ');
        const confirmation = await askPassword('Ulangi password: ');
        if (password.length < 12 || Buffer.byteLength(password, 'utf8') > 72) {
            throw new Error('Password harus minimal 12 karakter dan maksimal 72 byte UTF-8.');
        }
        if (password !== confirmation) throw new Error('Konfirmasi password tidak cocok.');

        const passwordHash = await bcrypt.hash(password, 12);
        db.prepare(`
            INSERT INTO users (username, display_name, role, password_hash)
            VALUES (?, ?, ?, ?)
        `).run(account.username, displayName, account.role, passwordHash);
        console.log(`Akun ${account.username} berhasil dibuat.`);
    }

    console.log('\nSimpan username dan password masing-masing dengan aman. Password tidak disimpan dalam teks biasa.');
}

main()
    .catch(error => {
        console.error(`Setup akun gagal: ${error.message}`);
        process.exitCode = 1;
    })
    .finally(() => db.close());

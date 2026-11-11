const crypto = require('node:crypto');
const path = require('node:path');
const express = require('express');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const db = require('./database');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const ALLOWED_ROLES = new Set(['Owner', 'Manager', 'IT Support', 'Staf / Resepsionis']);
const SETTINGS_ROLES = new Set(['Owner', 'Manager', 'IT Support']);
const ROOT = __dirname;
const DUMMY_PASSWORD_HASH = bcrypt.hashSync(crypto.randomBytes(32).toString('hex'), 12);
const DEFAULT_ROOM_SETTINGS = {
    'Family Room': { price: 1150000, includedBenefits: 'Sarapan 3 pax + Dinner 3 pax', discountPercent: 0 },
    'LakeView Room': { price: 750000, includedBenefits: 'Sarapan 2 pax + Dinner 2 pax', discountPercent: 0 },
    'PoolFront Room': { price: 900000, includedBenefits: 'Sarapan 2 pax + Dinner 2 pax', discountPercent: 0 },
    'Boutique Room': { price: 700000, includedBenefits: 'Sarapan 2 pax + Dinner 2 pax', discountPercent: 0 },
    'Standard Room': { price: 600000, includedBenefits: 'Sarapan 2 pax + Dinner 2 pax', discountPercent: 0 }
};

const roomInventory = new Map([
    ['119', { type: 'Family Room', floor: '1' }],
    ['120', { type: 'Family Room', floor: '1' }],
    ...Array.from({ length: 9 }, (_, index) => [
        String(101 + index),
        { type: 'LakeView Room', floor: '1' }
    ]),
    ...[118, 117, 116, 115, 114, 112, 111, 110].map(number => [
        String(number),
        { type: 'PoolFront Room', floor: '1' }
    ]),
    ...[205, 206, 207].map(number => [
        String(number),
        { type: 'Boutique Room', floor: '2' }
    ]),
    ...[201, 202, 203, 204].map(number => [
        String(number),
        { type: 'Standard Room', floor: '2' }
    ])
]);
const allowedStatuses = new Set(['Ready', 'Occupied', 'Dirty', 'Reserved', 'Maintenance']);

const secretRow = db.prepare('SELECT value FROM app_meta WHERE key = ?').get('session_secret');
const sessionSecret = secretRow
    ? secretRow.value
    : crypto.randomBytes(48).toString('hex');
if (!secretRow) {
    db.prepare('INSERT INTO app_meta (key, value) VALUES (?, ?)').run('session_secret', sessionSecret);
}

class SQLiteSessionStore extends session.Store {
    constructor(database) {
        super();
        this.db = database;
        this.getSession = database.prepare('SELECT sess, expires_at FROM sessions WHERE sid = ?');
        this.saveSession = database.prepare(`
            INSERT INTO sessions (sid, sess, expires_at) VALUES (?, ?, ?)
            ON CONFLICT(sid) DO UPDATE SET sess = excluded.sess, expires_at = excluded.expires_at
        `);
        this.deleteSession = database.prepare('DELETE FROM sessions WHERE sid = ?');
        this.expireSessions = database.prepare('DELETE FROM sessions WHERE expires_at <= ?');
        this.lastCleanup = 0;
    }

    get(sid, callback) {
        try {
            const row = this.getSession.get(sid);
            if (!row || row.expires_at <= Date.now()) {
                if (row) this.deleteSession.run(sid);
                return callback(null, null);
            }
            callback(null, JSON.parse(row.sess));
        } catch (error) {
            callback(error);
        }
    }

    set(sid, sessionData, callback = () => {}) {
        try {
            const expiresAt = sessionData.cookie?.expires
                ? new Date(sessionData.cookie.expires).getTime()
                : Date.now() + (sessionData.cookie?.maxAge || SESSION_TTL_MS);
            this.saveSession.run(sid, JSON.stringify(sessionData), expiresAt);
            if (Date.now() - this.lastCleanup > 60 * 60 * 1000) {
                this.expireSessions.run(Date.now());
                this.lastCleanup = Date.now();
            }
            callback(null);
        } catch (error) {
            callback(error);
        }
    }

    destroy(sid, callback = () => {}) {
        try {
            this.deleteSession.run(sid);
            callback(null);
        } catch (error) {
            callback(error);
        }
    }

    touch(sid, sessionData, callback = () => {}) {
        try {
            const expiresAt = sessionData.cookie?.expires
                ? new Date(sessionData.cookie.expires).getTime()
                : Date.now() + (sessionData.cookie?.maxAge || SESSION_TTL_MS);
            this.db.prepare('UPDATE sessions SET expires_at = ? WHERE sid = ?').run(expiresAt, sid);
            callback(null);
        } catch (error) {
            callback(error);
        }
    }
}

app.disable('x-powered-by');
app.set('trust proxy', process.env.TRUST_PROXY === '1' ? 1 : false);
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'same-origin');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Cache-Control', 'no-store');
    next();
});
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(session({
    name: 'maninjau.sid',
    secret: sessionSecret,
    store: new SQLiteSessionStore(db),
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'strict',
        secure: process.env.NODE_ENV === 'production',
        maxAge: SESSION_TTL_MS
    }
}));

const loginLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    limit: 100,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: 'Terlalu banyak percobaan login. Coba lagi beberapa saat.' }
});

function requireAuth(req, res, next) {
    const userId = req.session.user?.id;
    if (!userId) return unauthenticated(req, res);

    const user = db.prepare('SELECT id, username, display_name, role FROM users WHERE id = ?').get(userId);
    if (!user || !ALLOWED_ROLES.has(user.role)) {
        return req.session.destroy(() => unauthenticated(req, res));
    }
    req.user = user;
    next();
}

function unauthenticated(req, res) {
    if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Sesi login tidak valid.' });
    res.redirect('/login.html');
}

function requireCsrf(req, res, next) {
    const token = req.get('X-CSRF-Token');
    const expected = req.session.csrfToken;
    const tokenBuffer = Buffer.from(token || '');
    const expectedBuffer = Buffer.from(expected || '');
    if (!token || !expected || tokenBuffer.length !== expectedBuffer.length ||
        !crypto.timingSafeEqual(tokenBuffer, expectedBuffer)) {
        return res.status(403).json({ error: 'Token keamanan tidak valid. Muat ulang halaman dan coba lagi.' });
    }
    next();
}

function normalizeSettings(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
        throw new Error('Pengaturan tipe kamar tidak valid.');
    }

    return Object.fromEntries(Object.entries(DEFAULT_ROOM_SETTINGS).map(([type, defaults]) => {
        const setting = input[type] || {};
        const price = Number(setting.price);
        const discountPercent = Number(setting.discountPercent);
        const includedBenefits = setting.includedBenefits;
        if (!Number.isSafeInteger(price) || price < 0 ||
            !Number.isFinite(discountPercent) || discountPercent < 0 || discountPercent > 100 ||
            typeof includedBenefits !== 'string' || !includedBenefits.trim() || includedBenefits.length > 160) {
            throw new Error(`Pengaturan harga, diskon, atau benefit untuk ${type} tidak valid.`);
        }
        return [type, { price, discountPercent, includedBenefits: includedBenefits.trim() }];
    }));
}

function normalizeRoomState(input) {
    if (!input || typeof input !== 'object' || !Array.isArray(input.rooms) ||
        input.rooms.length !== roomInventory.size || !Array.isArray(input.maintenanceTickets)) {
        throw new Error('Format data aplikasi tidak valid.');
    }

    const settings = normalizeSettings(input.roomSettings);
    const submittedRooms = new Map();
    for (const room of input.rooms) {
        const number = String(room.number);
        if (!roomInventory.has(number) || submittedRooms.has(number)) {
            throw new Error('Daftar nomor kamar tidak valid atau memiliki duplikat.');
        }
        submittedRooms.set(number, room);
    }

    const rooms = Array.from(roomInventory, ([number, metadata]) => {
        const room = submittedRooms.get(number);
        if (!room || !allowedStatuses.has(room.status)) throw new Error(`Data kamar ${number} tidak lengkap.`);
        const setting = settings[metadata.type];
        const normalized = {
            id: Number(number),
            number,
            type: metadata.type,
            floor: metadata.floor,
            price: setting.price,
            includedBenefits: setting.includedBenefits,
            status: room.status,
            features: typeof room.features === 'string' ? room.features.slice(0, 300) : '',
            guestName: typeof room.guestName === 'string' ? room.guestName.slice(0, 120) : '',
            phone: typeof room.phone === 'string' ? room.phone.slice(0, 40) : '',
            checkInDate: typeof room.checkInDate === 'string' ? room.checkInDate.slice(0, 10) : '',
            checkOutDate: typeof room.checkOutDate === 'string' ? room.checkOutDate.slice(0, 10) : '',
            addOns: Array.isArray(room.addOns)
                ? room.addOns.filter(value => typeof value === 'string').slice(0, 20).map(value => value.slice(0, 80))
                : [],
            cleaner: typeof room.cleaner === 'string' ? room.cleaner.slice(0, 100) : ''
        };
        for (const key of ['bookingNightlyRate', 'bookingTotal', 'bookingNights', 'bookingDiscountPercent']) {
            if (Number.isSafeInteger(room[key]) && room[key] >= 0) normalized[key] = room[key];
            else if (key === 'bookingDiscountPercent' && Number.isFinite(room[key]) && room[key] >= 0 && room[key] <= 100) {
                normalized[key] = room[key];
            }
        }
        return normalized;
    });

    const maintenanceTickets = input.maintenanceTickets.slice(0, 500).map(ticket => {
        const roomNumber = String(ticket.roomNumber || '');
        if (!roomInventory.has(roomNumber)) throw new Error('Tiket perbaikan mengacu ke nomor kamar yang tidak valid.');
        return {
            id: Number.isSafeInteger(ticket.id) ? ticket.id : Date.now(),
            roomId: Number(roomNumber),
            roomNumber,
            description: typeof ticket.description === 'string' ? ticket.description.slice(0, 1000) : '',
            priority: ['Tinggi', 'Sedang', 'Rendah'].includes(ticket.priority) ? ticket.priority : 'Sedang',
            technician: typeof ticket.technician === 'string' ? ticket.technician.slice(0, 120) : '',
            status: typeof ticket.status === 'string' ? ticket.status.slice(0, 40) : 'Open',
            time: typeof ticket.time === 'string' ? ticket.time.slice(0, 10) : ''
        };
    });

    return { rooms, maintenanceTickets, roomSettings: settings };
}

app.get('/login.html', (req, res) => {
    if (req.session.user) return res.redirect('/');
    res.sendFile(path.join(ROOT, 'login.html'));
});

app.post('/api/auth/login', loginLimiter, async (req, res, next) => {
    try {
        const credentials = req.body || {};
        const username = typeof credentials.username === 'string' ? credentials.username.trim() : '';
        const password = typeof credentials.password === 'string' ? credentials.password : '';
        const user = db.prepare(`
            SELECT id, username, display_name, role, password_hash
            FROM users WHERE username = ? COLLATE NOCASE
        `).get(username);

        const passwordValid = user
            ? await bcrypt.compare(password, user.password_hash)
            : await bcrypt.compare(password, DUMMY_PASSWORD_HASH);
        if (!user || !passwordValid || !ALLOWED_ROLES.has(user.role)) {
            return res.status(401).json({ error: 'Username atau password tidak sesuai.' });
        }

        req.session.regenerate(error => {
            if (error) return next(error);
            req.session.user = { id: user.id };
            req.session.csrfToken = crypto.randomBytes(32).toString('hex');
            req.session.save(saveError => {
                if (saveError) return next(saveError);
                res.json({ ok: true });
            });
        });
    } catch (error) {
        next(error);
    }
});

app.get('/api/auth/me', requireAuth, (req, res) => {
    res.json({
        user: {
            username: req.user.username,
            displayName: req.user.display_name,
            role: req.user.role
        },
        csrfToken: req.session.csrfToken
    });
});

app.post('/api/auth/logout', requireAuth, requireCsrf, (req, res, next) => {
    req.session.destroy(error => {
        if (error) return next(error);
        res.clearCookie('maninjau.sid', {
            httpOnly: true,
            sameSite: 'strict',
            secure: process.env.NODE_ENV === 'production'
        });
        res.status(204).end();
    });
});

app.get('/api/state', requireAuth, (req, res) => {
    const row = db.prepare('SELECT state_json, revision FROM app_state WHERE id = 1').get();
    if (!row) return res.json(null);
    res.json({ state: JSON.parse(row.state_json), revision: row.revision });
});

app.put('/api/state', requireAuth, requireCsrf, (req, res) => {
    try {
        const savedStateRow = db.prepare('SELECT state_json FROM app_state WHERE id = 1').get();
        const currentSettings = savedStateRow
            ? JSON.parse(savedStateRow.state_json).roomSettings
            : DEFAULT_ROOM_SETTINGS;
        const stateInput = SETTINGS_ROLES.has(req.user.role)
            ? req.body
            : { ...req.body, roomSettings: currentSettings };
        const normalizedState = normalizeRoomState(stateInput);
        const expectedRevision = req.body.revision;
        if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0) {
            return res.status(400).json({ error: 'Versi data tidak valid.' });
        }

        const saveTransaction = db.transaction(() => {
            if (expectedRevision === 0) {
                return db.prepare(`
                    INSERT INTO app_state (id, state_json, revision, updated_at)
                    VALUES (1, ?, 1, CURRENT_TIMESTAMP)
                    ON CONFLICT(id) DO NOTHING
                `).run(JSON.stringify(normalizedState));
            }
            return db.prepare(`
                UPDATE app_state SET state_json = ?, revision = revision + 1, updated_at = CURRENT_TIMESTAMP
                WHERE id = 1 AND revision = ?
            `).run(JSON.stringify(normalizedState), expectedRevision);
        });
        const result = saveTransaction();
        if (result.changes !== 1) {
            return res.status(409).json({ error: 'Data telah diperbarui oleh pengguna lain.' });
        }
        res.json({ ok: true, revision: expectedRevision + 1 });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

function sendApp(req, res) {
    res.sendFile(path.join(ROOT, 'Index.html'));
}

app.get('/', requireAuth, sendApp);
app.get('/Index.html', requireAuth, sendApp);
app.get('/logo', (req, res) => {
    res.sendFile(path.join(ROOT, 'LOGO HMI.png'));
});
app.use('/api', (req, res) => res.status(404).json({ error: 'Endpoint tidak ditemukan.' }));
app.use((req, res) => {
    if (!req.session.user) return res.redirect('/login.html');
    res.status(404).send('Halaman tidak ditemukan.');
});

app.use((error, req, res, next) => {
    console.error('Request failed:', error);
    if (res.headersSent) return next(error);
    res.status(500).json({ error: 'Terjadi kesalahan server.' });
});

const server = app.listen(PORT, HOST, () => {
    console.log(`Hotel Maninjau Indah PMS berjalan di http://${HOST}:${PORT}`);
    console.log('Akun Owner, Manager, IT Support, dan Staf/Resepsionis dapat login.');
});

function shutdown() {
    server.close(() => {
        db.close();
        process.exit(0);
    });
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

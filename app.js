const express = require('express');
const crypto = require('crypto');
const app = express();

app.set('trust proxy', true);
app.disable('x-powered-by');

// ============================================
// 🛡️ BẢO MẬT: chống DDoS / flood / quét / nhúng iframe
// ============================================
const SEC = {
    GLOBAL_PER_MIN: 150,          // tổng request / IP / phút
    API_PER_MIN: 90,              // tổng /api/* / IP / phút
    BUCKETS: {                    // giới hạn riêng từng API / IP / phút
        '/api/start-task': 10,
        '/api/continue-task': 15,
        '/api/step-callback': 20,
        '/api/check-key': 60,
        '/api/task-status': 45,
        '/api/site-status': 25,
        '/api/verify-admin': 20,
        '/api/health': 15
    },
    LOGIN_PER_MIN: 8,             // thử mật khẩu admin / IP / phút
    LASTHOP_PER_MIN: 1500,        // chặn flood giả X-Forwarded-For (tính theo proxy gần nhất)
    BAN_VIOLATIONS: 25,           // vi phạm >= 25 lần / phút -> ban
    BAN_MS: 15 * 60 * 1000,       // thời gian ban IP
    MAX_INFLIGHT: 500,            // số request xử lý đồng thời tối đa (người thường)
    MAX_BODY_PUBLIC: 1024 * 1024, // body tối đa 1MB cho người thường
    MAX_TRACKED: 100000           // chống phình RAM
};
const secHits = new Map();
const secBans = new Map();
const secViol = new Map();
let secInflight = 0;

function secHit(key, limit) {
    const now = Date.now();
    let h = secHits.get(key);
    if (!h || h.reset <= now) { h = { n: 0, reset: now + 60000 }; secHits.set(key, h); }
    h.n++;
    return h.n > limit;
}
function secViolation(ip) {
    const now = Date.now();
    let v = secViol.get(ip);
    if (!v || v.reset <= now) { v = { n: 0, reset: now + 60000 }; secViol.set(ip, v); }
    v.n++;
    if (v.n >= SEC.BAN_VIOLATIONS) { secBans.set(ip, now + SEC.BAN_MS); secViol.delete(ip); }
}
setInterval(() => {
    const now = Date.now();
    for (const [k, h] of secHits) if (h.reset <= now) secHits.delete(k);
    for (const [k, v] of secViol) if (v.reset <= now) secViol.delete(k);
    for (const [k, u] of secBans) if (u <= now) secBans.delete(k);
    if (secHits.size > SEC.MAX_TRACKED) secHits.clear();
}, 30000).unref();

app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "frame-ancestors 'none'");
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    if (req.path.startsWith('/api/') || req.path.startsWith('/amin/')) res.setHeader('Cache-Control', 'no-store');

    if (!['GET', 'POST', 'HEAD', 'OPTIONS'].includes(req.method)) return res.status(405).end();

    const ip = getClientIP(req) || 'unknown';
    const until = secBans.get(ip);
    if (until && until > Date.now()) {
        res.setHeader('Retry-After', String(Math.ceil((until - Date.now()) / 1000)));
        return res.status(429).type('text/plain').send('Too many requests');
    }

    // Admin đã đăng nhập: không bị giới hạn
    if (isAdminSession(req)) return next();

    if (secInflight >= SEC.MAX_INFLIGHT) {
        res.setHeader('Retry-After', '5');
        return res.status(503).type('text/plain').send('Server busy');
    }
    secInflight++;
    let counted = true;
    const dec = () => { if (counted) { counted = false; secInflight--; } };
    res.on('finish', dec);
    res.on('close', dec);

    const cl = parseInt(req.headers['content-length'] || '0', 10);
    if (cl > SEC.MAX_BODY_PUBLIC) return res.status(413).json({ ok: false, reason: 'too_large' });

    const path = req.path;
    const xff = req.headers['x-forwarded-for'];
    const lastHop = xff ? String(xff).split(',').pop().trim() : ((req.socket && req.socket.remoteAddress) || '');
    let over = secHit('G|' + ip, SEC.GLOBAL_PER_MIN) || secHit('H|' + lastHop, SEC.LASTHOP_PER_MIN);
    if (!over) {
        if (ADMIN_LOGIN_ENABLED && req.method === 'POST' && path === '/' + ADMIN_PATH) {
            over = secHit('L|' + ip, SEC.LOGIN_PER_MIN);
        } else if (path.startsWith('/api/')) {
            const lim = SEC.BUCKETS[path];
            over = lim ? secHit('B|' + path + '|' + ip, lim) : false;
            if (!over) over = secHit('A|' + ip, SEC.API_PER_MIN);
        }
    }
    if (over) {
        secViolation(ip);
        res.setHeader('Retry-After', '30');
        return res.status(429).json({ ok: false, reason: 'rate_limited' });
    }
    next();
});

// Body parser: người thường 1MB, admin đã đăng nhập 20MB
const jsonSmall = express.json({ limit: '1mb' });
const jsonBig = express.json({ limit: '20mb' });
const urlSmall = express.urlencoded({ extended: true, limit: '1mb' });
const urlBig = express.urlencoded({ extended: true, limit: '20mb' });
app.use((req, res, next) => (isAdminSession(req) ? jsonBig : jsonSmall)(req, res, next));
app.use((req, res, next) => (isAdminSession(req) ? urlBig : urlSmall)(req, res, next));

// ============================================
// CONFIG
// ============================================
const ADMIN_SERIAL_B64 = 'UjlKTjYwS0VQS0o=';
const SERVER_URL = process.env.SERVER_URL || 'https://key-netsuper-api.onrender.com';

// ⭐ ADMIN: vào bằng TRANG BÍ MẬT + mật khẩu (không dùng IP nữa)
//   Đặt 2 biến môi trường trên Render:
//     ADMIN_PATH     = đường dẫn bí mật, vd: x7k2-q9m4-panel  (chỉ gồm a-z A-Z 0-9 _ -, tối thiểu 8 ký tự)
//     ADMIN_PASSWORD = mật khẩu admin (nên dài >= 12 ký tự)
//   Truy cập: https://<domain>/<ADMIN_PATH>  -> nhập mật khẩu -> vào /amin/thichlendo
//   Nếu thiếu 1 trong 2 biến thì trang bí mật bị TẮT (không ai vào được).
const ADMIN_PATH = String(process.env.ADMIN_PATH || '').trim().replace(/^\/+|\/+$/g, '');
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || '');
const ADMIN_SESSION_SECRET = String(process.env.ADMIN_SESSION_SECRET || ADMIN_PASSWORD);
const ADMIN_SESSION_HOURS = 12;
const ADMIN_COOKIE = 'ns_adm';
const ADMIN_LOGIN_ENABLED = /^[A-Za-z0-9_-]{8,}$/.test(ADMIN_PATH) && ADMIN_PASSWORD.length >= 8;
if (!ADMIN_LOGIN_ENABLED) console.error('⚠️ Thiếu/sai ADMIN_PATH hoặc ADMIN_PASSWORD -> trang admin bí mật đang TẮT');

// Chuẩn hoá IP: chữ thường, bỏ tiền tố ::ffff: (IPv4-mapped) — dùng cho whitelist IP
function normIP(ip) {
    return String(ip || '').trim().toLowerCase().replace(/^::ffff:/, '');
}
function getAdminSerial() {
    try { return Buffer.from(ADMIN_SERIAL_B64, 'base64').toString('utf8'); }
    catch (e) { return ''; }
}
const ADMIN_SERIALS = [getAdminSerial()];

const UPSTASH_URL = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
if (!UPSTASH_URL || !UPSTASH_TOKEN) console.error('❌ Thiếu UPSTASH env');

const LINK4M_API_KEY = '6a61ce8626fd3a13155f6529';
const LINK4M_API_URL = 'https://link4m.co/api-shorten/v2';
const TRAFFICVN_API_KEY = 'b19399e1906b7bad23ed21c078a1edf7';
const TRAFFICVN_API_URL = 'https://trafficvn.com/apidevelop';
// Link999 (token được che bằng base64, có thể ghi đè bằng env LINK999_API_KEY)
const LINK999_API_KEY_B64 = 'ZDRmMGMyNzliZjVkMDFjOGM2M2QxMjdhOTQ5ZmVhNzcyODhiMzg2OA==';
const LINK999_API_KEY = process.env.LINK999_API_KEY || Buffer.from(LINK999_API_KEY_B64, 'base64').toString('utf8');
const LINK999_API_URL = 'https://link999.app/st';
const LINK999_TYPE = String(process.env.LINK999_TYPE || '5');   // 5 = Google Search 4 Step

// ⭐ User get key = LUÔN 1 DEVICE cho mọi mức
const DURATION_CONFIG = {
    '3h':  { hours: 3,  devices: 1,  steps: ['link4m'] },
    '6h':  { hours: 6,  devices: 1,  steps: ['link4m', 'trafficvn'] },
    '8h':  { hours: 8,  devices: 1,  steps: ['link4m', 'trafficvn', 'trafficvn'] },
    '12h': { hours: 12, devices: 1,  steps: ['link4m', 'trafficvn', 'trafficvn', 'trafficvn'] },
    '24h': { hours: 24, devices: 1,  steps: ['link4m', 'trafficvn', 'trafficvn', 'trafficvn', 'trafficvn'] }
};

// ⭐ Gói key VIP (mua) — hiển thị ở tab NetSuperVip trong Get Key, chưa có cổng thanh toán -> luôn "đang bảo trì" cho user thường
const VIP_PACKAGES = {
    '1d':   { label: 'Key 1 ngày',    price: 10000,  hours: 24,      permanent: false },
    '7d':   { label: 'Key 7 ngày',    price: 50000,  hours: 24 * 7,  permanent: false },
    '30d':  { label: 'Key 30 ngày',   price: 199000, hours: 24 * 30, permanent: false },
    'perm': { label: 'Key Vĩnh viễn', price: 500000, hours: 0,       permanent: true  }
};

const MIN_LINK4M_MS = 80 * 1000;
const MIN_TRAFFICVN_MS = 90 * 1000;
const MIN_LINK999_MS = (Number(process.env.LINK999_MIN_SECONDS) || 90) * 1000;
const VALID_REFERERS = ['link4m.co','www.link4m.co','link4m.com','www.link4m.com','trafficvn.com','www.trafficvn.com','link999.app','www.link999.app'];
const BAD_UA_PATTERNS = ['curl','wget','python','okhttp','postman','insomnia','axios','node-fetch','go-http-client','java/','libwww','httpie','powershell','headlesschrome','phantomjs','selenium','puppeteer','playwright'];
const RATE_LIMIT_WINDOW = 60 * 60 * 1000;
const RATE_LIMIT_MAX = 5;
const MAX_BULK = 10000;
const PERMANENT_TTL_SEC = 10 * 365 * 24 * 3600;
const PERMANENT_EXPIRE_AT = () => Date.now() + PERMANENT_TTL_SEC * 1000;

// ⭐ Giới hạn số lần lấy key (public get-key flow) cho mỗi IP — vĩnh viễn, không reset
const IP_GETKEY_LIMIT = 2;

// ⭐ Số bước tối đa cho phép cấu hình theo từng mốc thời gian (chống spam quá nhiều bước)
const DURATION_MAX_STEPS = { '3h': 1, '6h': 2, '8h': 3, '12h': 4, '24h': 5 };
const DURATION_HOURS = { '3h': 3, '6h': 6, '8h': 8, '12h': 12, '24h': 24 };

function defaultAppDurations() {
    return {
        '3h':  { hidden: false, maintenance: false, steps: ['link4m'] },
        '6h':  { hidden: false, maintenance: false, steps: ['link4m', 'trafficvn'] },
        '8h':  { hidden: false, maintenance: false, steps: ['link4m', 'trafficvn', 'trafficvn'] },
        '12h': { hidden: false, maintenance: false, steps: ['link4m', 'trafficvn', 'trafficvn', 'trafficvn'] },
        '24h': { hidden: false, maintenance: false, steps: ['link4m', 'trafficvn', 'trafficvn', 'trafficvn', 'trafficvn'] }
    };
}
function defaultAppsConfig() {
    return {
        netsuper:    { label: 'NetSuper',    prefix: 'NetSuper',    tailStyle: 'alnum12',  durations: defaultAppDurations() },
        netsupervip: { label: 'NetSuperVip', prefix: 'NetSuperVip', tailStyle: 'special9', durations: defaultAppDurations() }
    };
}

// ============================================
// REDIS
// ============================================
async function redis(...args) {
    if (!UPSTASH_URL || !UPSTASH_TOKEN) return null;
    try {
        const r = await fetch(UPSTASH_URL, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${UPSTASH_TOKEN}`, 'Content-Type': 'application/json' },
            body: JSON.stringify(args)
        });
        const j = await r.json();
        if (j.error) { console.error('Redis err:', j.error); return null; }
        return j.result;
    } catch (e) { console.error('Redis err:', e.message); return null; }
}

async function redisPipeline(commands) {
    if (!UPSTASH_URL || !UPSTASH_TOKEN) return null;
    try {
        const r = await fetch(`${UPSTASH_URL}/pipeline`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${UPSTASH_TOKEN}`, 'Content-Type': 'application/json' },
            body: JSON.stringify(commands)
        });
        const j = await r.json();
        if (Array.isArray(j)) j.forEach((it, i) => { if (it && it.error) console.error(`[P${i}]`, it.error); });
        else if (j.error) console.error('[Pipeline]', j.error);
        return j;
    } catch (e) { console.error('Pipeline err:', e.message); return null; }
}

async function saveKeyToRedis(key, expireAt, maxDevices = 0, isVip = false) {
    const ttl = Math.max(1, Math.ceil((expireAt - Date.now()) / 1000));
    const value = JSON.stringify({
        hwids: [],
        maxDevices: Number(maxDevices) || 0,
        createdAt: Date.now(),
        vip: !!isVip
    });
    return await redisPipeline([
        ['SET', `ns:key:${key}`, value, 'EX', String(ttl)],
        ['HSET', 'ns:meta', key, String(expireAt)]
    ]);
}

async function saveManyKeysToRedis(keysList, expireAt, maxDevices = 0, isVip = false) {
    const ttl = Math.max(1, Math.ceil((expireAt - Date.now()) / 1000));
    const value = JSON.stringify({
        hwids: [],
        maxDevices: Number(maxDevices) || 0,
        createdAt: Date.now(),
        vip: !!isVip
    });
    const batchSize = 100;
    for (let i = 0; i < keysList.length; i += batchSize) {
        const batch = keysList.slice(i, i + batchSize);
        const cmds = [];
        for (const k of batch) {
            cmds.push(['SET', `ns:key:${k}`, value, 'EX', String(ttl)]);
            cmds.push(['HSET', 'ns:meta', k, String(expireAt)]);
        }
        await redisPipeline(cmds);
    }
    return keysList.length;
}

async function getKeyFromRedis(key) {
    const value = await redis('GET', `ns:key:${key}`);
    if (!value) return null;
    try { return JSON.parse(value); } catch (e) { return {}; }
}

async function saveKeyEntry(key, entry) {
    const ttl = await redis('TTL', `ns:key:${key}`);
    if (ttl && ttl > 0) {
        await redis('SET', `ns:key:${key}`, JSON.stringify(entry), 'EX', String(ttl));
        return true;
    }
    return false;
}

async function deleteKeyFromRedis(key) {
    return await redisPipeline([
        ['DEL', `ns:key:${key}`],
        ['HDEL', 'ns:meta', key]
    ]);
}

async function listKeysFromRedis() {
    const now = Date.now();
    const meta = await redis('HGETALL', 'ns:meta');
    if (!meta || !Array.isArray(meta) || meta.length === 0) return [];
    const result = [], expired = [];
    for (let i = 0; i < meta.length; i += 2) {
        const key = meta[i];
        const expireAt = parseInt(meta[i + 1], 10);
        if (!key || isNaN(expireAt)) continue;
        if (expireAt > now) result.push({ key, expireAt });
        else expired.push(key);
    }
    if (expired.length) await redisPipeline(expired.map(k => ['HDEL', 'ns:meta', k]));
    return result;
}

// ============================================
// STORAGE
// ============================================
const tasks = new Map();
const bypassLog = [];
const ipBlacklist = new Map();
const ipTaskLog = new Map();

// ============================================
// SITE CONFIG (status: online / maintenance / off) + IP WHITELIST
// ============================================
let siteConfigCache = {
    status: 'online',
    maintMsg: 'Website đang được bảo trì. Vui lòng quay lại sau ít phút.',
    offMsg: 'Website hiện đang tạm ngưng hoạt động.'
};
let whitelistCache = new Set();

async function loadSiteConfig() {
    const raw = await redis('GET', 'ns:site:config');
    if (raw) {
        try { siteConfigCache = { ...siteConfigCache, ...JSON.parse(raw) }; }
        catch (e) {}
    }
}
async function saveSiteConfig(patch) {
    siteConfigCache = { ...siteConfigCache, ...patch };
    await redis('SET', 'ns:site:config', JSON.stringify(siteConfigCache));
    return siteConfigCache;
}
async function loadWhitelist() {
    const members = await redis('SMEMBERS', 'ns:site:whitelist');
    if (Array.isArray(members)) whitelistCache = new Set(members);
}
async function addWhitelistIP(ip) {
    whitelistCache.add(ip);
    await redis('SADD', 'ns:site:whitelist', ip);
}
async function removeWhitelistIP(ip) {
    whitelistCache.delete(ip);
    await redis('SREM', 'ns:site:whitelist', ip);
}
function isWhitelistedIP(ip) { return whitelistCache.has(ip); }
// Load persisted config/whitelist once Redis is reachable
loadSiteConfig();
loadWhitelist();

// ============================================
// APPS CONFIG (NetSuper / NetSuperVip — durations: hidden / maintenance / steps)
// ============================================
let appsConfigCache = defaultAppsConfig();

async function loadAppsConfig() {
    const raw = await redis('GET', 'ns:appsconfig');
    if (raw) {
        try {
            const parsed = JSON.parse(raw);
            // merge shallowly so any newly-added apps/durations still have defaults
            const merged = defaultAppsConfig();
            for (const appId of Object.keys(merged)) {
                if (parsed[appId]) {
                    if (parsed[appId].label) merged[appId].label = parsed[appId].label;
                    if (parsed[appId].prefix && sanitizeKeyPrefix(parsed[appId].prefix)) merged[appId].prefix = sanitizeKeyPrefix(parsed[appId].prefix);
                    if (parsed[appId].tailStyle === 'alnum12' || parsed[appId].tailStyle === 'special9') merged[appId].tailStyle = parsed[appId].tailStyle;
                    for (const dur of Object.keys(merged[appId].durations)) {
                        if (parsed[appId].durations && parsed[appId].durations[dur]) {
                            merged[appId].durations[dur] = { ...merged[appId].durations[dur], ...parsed[appId].durations[dur] };
                        }
                    }
                }
            }
            appsConfigCache = merged;
        } catch (e) {}
    }
}
async function saveAppsConfig() {
    await redis('SET', 'ns:appsconfig', JSON.stringify(appsConfigCache));
}
function sanitizeSteps(steps, duration) {
    const max = DURATION_MAX_STEPS[duration] || 5;
    if (!Array.isArray(steps)) return null;
    const clean = steps.filter(s => s === 'link4m' || s === 'trafficvn' || s === 'link999');
    if (clean.length < 1 || clean.length > max) return null;
    return clean;
}
loadAppsConfig();

// ============================================
// PER-IP GET-KEY COUNTER (vĩnh viễn, không reset)
// ============================================
async function getIpGetKeyCount(ip) {
    const v = await redis('HGET', 'ns:ip:getkeycount', ip);
    return parseInt(v, 10) || 0;
}
async function incrIpGetKeyCount(ip) {
    return await redis('HINCRBY', 'ns:ip:getkeycount', ip, 1);
}

// ============================================
// ANTI-REPLAY: dùng lại link/log cũ để né bước
// ============================================
const usedStepNonces = new Map(); // nonce -> timestamp, dùng để chặn tái sử dụng link cũ
function rememberNonce(n) {
    usedStepNonces.set(n, Date.now());
    if (usedStepNonces.size > 20000) {
        const cutoff = Date.now() - 24 * 3600 * 1000;
        for (const [k, t] of usedStepNonces) if (t < cutoff) usedStepNonces.delete(k);
    }
}
function isNonceUsed(n) { return usedStepNonces.has(n); }

// ============================================
// HELPERS
// ============================================
function vnTime(d) {
    const t = new Date(d.getTime() + 7 * 3600 * 1000);
    const p = n => String(n).padStart(2, '0');
    return `${p(t.getUTCHours())}:${p(t.getUTCMinutes())}:${p(t.getUTCSeconds())} ${p(t.getUTCDate())}/${t.getUTCMonth()+1}/${t.getUTCFullYear()}`;
}
function getClientIP(req) {
    const fwd = req.headers['x-forwarded-for'];
    if (fwd) return String(fwd).split(',')[0].trim();
    return req.ip || '';
}
// ---- Gắn callback với đúng trình duyệt đã bấm "Tiếp tục" (chống copy link từ log / chia sẻ link) ----
function bindCookieName(token) { return 'ns_b_' + String(token || '').replace(/[^a-zA-Z0-9]/g, '').slice(0, 12); }
function setBindCookie(req, res, token, secret) {
    const secure = req.secure || String(req.headers['x-forwarded-proto'] || '').includes('https');
    res.setHeader('Set-Cookie', `${bindCookieName(token)}=${secret}; Path=/api/step-callback; HttpOnly; SameSite=Lax; Max-Age=1800${secure ? '; Secure' : ''}`);
}

// ---- Phiên admin: cookie ký HMAC (HttpOnly, SameSite=Strict) ----
function parseCookies(req) {
    const out = {};
    String(req.headers.cookie || '').split(';').forEach(part => {
        const i = part.indexOf('=');
        if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
    });
    return out;
}
function signSession(exp) {
    return crypto.createHmac('sha256', ADMIN_SESSION_SECRET).update('adm.' + exp).digest('hex');
}
function makeAdminToken() {
    const exp = Date.now() + ADMIN_SESSION_HOURS * 3600 * 1000;
    return exp + '.' + signSession(exp);
}
function safeEqualStr(a, b) {
    const ha = crypto.createHash('sha256').update(String(a)).digest();
    const hb = crypto.createHash('sha256').update(String(b)).digest();
    return crypto.timingSafeEqual(ha, hb);
}
function isAdminSession(req) {
    if (!ADMIN_LOGIN_ENABLED) return false;
    const tok = parseCookies(req)[ADMIN_COOKIE];
    if (!tok) return false;
    const [exp, sig] = tok.split('.');
    if (!exp || !sig || !/^\d+$/.test(exp) || Number(exp) < Date.now()) return false;
    return safeEqualStr(sig, signSession(exp));
}
// Dùng cho start-task: admin đã đăng nhập hoặc IP trong whitelist (do admin thêm trong panel) được bỏ qua giới hạn
function isAdminIP(req) {
    const ip = getClientIP(req);
    return isAdminSession(req) || isWhitelistedIP(ip) || isWhitelistedIP(normIP(ip));
}
// Quyền quản trị thật sự: chỉ phiên đăng nhập bí mật (hoặc serial của app). Whitelist IP KHÔNG có quyền admin.
function isAdmin(req) {
    const serial = (req.body && req.body.serial) || req.query.serial;
    return isAdminSession(req) || !!(serial && ADMIN_SERIALS.includes(String(serial).trim()));
}
function genToken() { return crypto.randomBytes(16).toString('hex'); }

// ⭐ Bộ ký tự cho key: thường (alnum) và VIP (alnum + ký tự đặc biệt, KHÔNG có dấu "-")
const KEY_CHARSET_ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const KEY_CHARSET_SPECIAL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*_=+?';
function makeRandomBlock(len, charset) {
    let s = '';
    for (let i = 0; i < len; i++) s += charset[Math.floor(Math.random() * charset.length)];
    return s;
}
// Kiểu đuôi cho romdo key (dùng ở panel RANDOM GENERATE của admin):
// 'alnum12'  -> 12 ký tự hoa/thường/số
// 'special9' -> 9 ký tự hoa/thường/số + ký tự đặc biệt (không có "-")
const KEY_TAIL_STYLES = {
    alnum12:  () => makeRandomBlock(12, KEY_CHARSET_ALNUM),
    special9: () => makeRandomBlock(9,  KEY_CHARSET_SPECIAL)
};
function genKeyTail(style) {
    const build = KEY_TAIL_STYLES[style] || KEY_TAIL_STYLES.special9;
    return build();
}
// Chỉ giữ A-Z a-z 0-9 cho phần chữ đầu tuỳ chỉnh — không cho phép dấu "-" để
// đảm bảo key VIP luôn chỉ có đúng 1 dấu "-" duy nhất.
function sanitizeKeyPrefix(p) {
    if (!p) return null;
    const clean = String(p).replace(/[^A-Za-z0-9]/g, '').slice(0, 24);
    return clean || null;
}
// Key thường mặc định (public get-key, quick-create, bulk-create) — GIỮ NGUYÊN format cũ
function genKey(prefix) {
    return `${sanitizeKeyPrefix(prefix) || 'NetSuper'}-${makeRandomBlock(11, KEY_CHARSET_ALNUM)}-${makeRandomBlock(10, KEY_CHARSET_ALNUM)}`;
}
// Key VIP: PREFIX-đuôi (1 dấu "-" duy nhất), đuôi mặc định mix hoa/thường/số/ký tự đặc biệt
function genVipKey(prefix, style) {
    return `${sanitizeKeyPrefix(prefix) || 'NetSuperVip'}-${genKeyTail(style || 'special9')}`;
}
// Key thường nhưng chữ đầu tuỳ chỉnh (dùng ở panel RANDOM GENERATE) — vẫn 1 dấu "-", đuôi chọn style
function genCustomKey(prefix, style) {
    return `${sanitizeKeyPrefix(prefix) || 'NetSuper'}-${genKeyTail(style || 'alnum12')}`;
}
function isRefererValid(referer) {
    if (!referer) return false;
    try { return VALID_REFERERS.includes(new URL(referer).hostname.toLowerCase()); }
    catch (e) { return false; }
}
function isIPRateLimited(ip) {
    const now = Date.now();
    const log = ipTaskLog.get(ip) || [];
    return log.filter(t => now - t < RATE_LIMIT_WINDOW).length >= RATE_LIMIT_MAX;
}
function logIPTask(ip) {
    const log = ipTaskLog.get(ip) || [];
    log.push(Date.now());
    if (log.length > 100) log.shift();
    ipTaskLog.set(ip, log);
}
function markIPBlacklisted(ip) {
    const entry = ipBlacklist.get(ip) || { count: 0, until: 0 };
    entry.count++;
    if (entry.count >= 3) entry.until = Date.now() + 24 * 3600 * 1000;
    ipBlacklist.set(ip, entry);
}
function isIPBlacklisted(ip) {
    const entry = ipBlacklist.get(ip);
    if (!entry) return false;
    if (entry.until > Date.now()) return true;
    if (entry.until > 0 && entry.until <= Date.now()) ipBlacklist.delete(ip);
    return false;
}
function detectBypass(req, task, stepType) {
    const reasons = [];
    const currentIP = getClientIP(req);
    const currentUA = req.headers['user-agent'] || '';
    const currentReferer = req.headers['referer'] || req.headers['referrer'] || '';
    const elapsed = Date.now() - task.stepStartedAt;
    let minTime = stepType === 'link4m' ? MIN_LINK4M_MS : (stepType === 'link999' ? MIN_LINK999_MS : MIN_TRAFFICVN_MS);
    if (elapsed < minTime) reasons.push(`Thời gian quá ngắn (${Math.round(elapsed/1000)}s < ${Math.round(minTime/1000)}s)`);
    if (currentIP !== task.stepIP) reasons.push('IP thay đổi');
    const uaLower = currentUA.toLowerCase();
    if (!currentUA) reasons.push('Thiếu User-Agent');
    else {
        for (const bad of BAD_UA_PATTERNS) if (uaLower.includes(bad)) { reasons.push(`UA bị chặn (${bad})`); break; }
        if (!uaLower.includes('mozilla') && !uaLower.includes('chrome') && !uaLower.includes('safari') && !uaLower.includes('firefox')) reasons.push('UA không phải browser');
    }
    if (!currentReferer) reasons.push('Thiếu Referer');
    else if (!isRefererValid(currentReferer)) reasons.push('Referer không hợp lệ');
    const cbKey = `${task.duration}-${task.currentStep}`;
    if (task.callbackHistory && task.callbackHistory.includes(cbKey)) reasons.push('Replay detected');
    return {
        bypass: reasons.length > 0,
        reasons,
        details: { elapsed: Math.round(elapsed/1000)+'s', ip: currentIP, ua: currentUA.substring(0,100) }
    };
}
function stepsForHours(h) {
    if (h >= 24) return ['link4m','trafficvn','trafficvn','trafficvn','trafficvn'];
    if (h >= 12) return ['link4m','trafficvn','trafficvn','trafficvn'];
    if (h >= 8)  return ['link4m','trafficvn','trafficvn'];
    if (h >= 6)  return ['link4m','trafficvn'];
    return ['link4m'];
}
async function genShortLink(type, cb) {
    try {
        if (type === 'link4m') {
            const params = new URLSearchParams({ api: LINK4M_API_KEY, url: cb, format: 'json' });
            const r = await fetch(`${LINK4M_API_URL}?${params}`);
            const j = await r.json();
            if (j.status === 'success' && j.shortenedUrl) return j.shortenedUrl;
        } else if (type === 'link999') {
            // Link999: /st?api=TOKEN&url=DEST&type=N  -> server redirect sang link rút gọn.
            // Gọi từ server và đọc header Location để KHÔNG lộ token cho người dùng.
            const params = new URLSearchParams({ api: LINK999_API_KEY, url: cb, type: LINK999_TYPE });
            const r = await fetch(`${LINK999_API_URL}?${params}`, {
                redirect: 'manual',
                headers: { 'User-Agent': 'Mozilla/5.0 (compatible; NetSuperKeyServer/1.0)' }
            });
            const loc = r.headers.get('location');
            if (loc && /^https?:\/\//i.test(loc)) return loc;
            const ct = String(r.headers.get('content-type') || '');
            if (ct.includes('json')) {
                const j = await r.json();
                const u = j.shortenedUrl || j.short_url || j.url || null;
                if (u && /^https?:\/\//i.test(u)) return u;
            }
            console.error('genShortLink link999: không lấy được link, status', r.status);
        } else {
            const params = new URLSearchParams({ api: TRAFFICVN_API_KEY, url: cb, fallback_url: cb });
            const r = await fetch(`${TRAFFICVN_API_URL}?${params}`);
            const j = await r.json();
            return j.shortenedUrl || j.short_url || j.url || null;
        }
    } catch (e) { console.error('genShortLink err:', e.message); }
    return null;
}
function calcExpire(t) {
    if (t.permanent) return { expireAt: PERMANENT_EXPIRE_AT(), isPermanent: true };
    const years   = Number(t.years)   || 0;
    const months  = Number(t.months)  || 0;
    const days    = Number(t.days)    || 0;
    const hours   = Number(t.hours)   || 0;
    const minutes = Number(t.minutes) || 0;
    const seconds = Number(t.seconds) || 0;
    const ms = years*365*24*3600*1000 + months*30*24*3600*1000 + days*24*3600*1000 +
               hours*3600*1000 + minutes*60*1000 + seconds*1000;
    if (ms <= 0) return null;
    return { expireAt: Date.now() + ms, isPermanent: false };
}
function totalHoursOf(t) {
    if (t.permanent) return 87600;
    return (Number(t.years)||0)*365*24 + (Number(t.months)||0)*30*24 + (Number(t.days)||0)*24 +
           (Number(t.hours)||0) + (Number(t.minutes)||0)/60 + (Number(t.seconds)||0)/3600;
}

// ============================================
// API: check-key
// ============================================
app.get('/api/check-key', async (req, res) => {
    const key = req.query.key;
    const hwid = String(req.query.hwid || req.query.device_id || '').trim();
    if (!key) return res.json({ p: JSON.stringify({ ok: 0 }), s: 'x' });

    const entry = await getKeyFromRedis(key);
    if (!entry) return res.json({ p: JSON.stringify({ ok: 0 }), s: 'x' });

    if (!Array.isArray(entry.hwids)) entry.hwids = entry.hwid ? [entry.hwid] : [];
    const maxDevices = Number(entry.maxDevices) || 0;

    if (hwid) {
        if (entry.hwids.includes(hwid)) {
            // known device — OK
        } else if (maxDevices === 0 || entry.hwids.length < maxDevices) {
            entry.hwids.push(hwid);
            await saveKeyEntry(key, entry);
        } else {
            return res.json({
                p: JSON.stringify({ ok: 0, reason: 'device_limit', max: maxDevices, used: entry.hwids.length }),
                s: 'x'
            });
        }
    }

    const ttl = await redis('TTL', `ns:key:${key}`);
    const exp = (ttl && ttl > 0)
        ? Math.floor((Date.now() + ttl * 1000) / 1000)
        : Math.floor(Date.now() / 1000) + 3600;
    return res.json({ p: JSON.stringify({ ok: 1, exp, maxDevices, devices: entry.hwids.length }), s: 'x' });
});

// ============================================
// API: start-task
// ============================================
app.post('/api/start-task', async (req, res) => {
    const clientIP = getClientIP(req);
    const admin = isAdminIP(req);
    if (isIPBlacklisted(clientIP) && !admin) return res.status(429).json({ ok:false, reason:'IP blocked' });
    if (isIPRateLimited(clientIP) && !admin) return res.status(429).json({ ok:false, reason:'Rate limited' });
    if (siteConfigCache.status !== 'online' && !admin) return res.status(423).json({ ok:false, message:'site_unavailable' });

    const { duration } = req.body;
    const appId = (req.body.app === 'netsupervip') ? 'netsupervip' : 'netsuper';
    const appCfg = appsConfigCache[appId];
    const durCfg = appCfg && appCfg.durations[duration];
    if (!durCfg) return res.status(400).json({ ok: false, message: 'bad_duration' });
    if (!admin && durCfg.hidden) return res.status(400).json({ ok: false, message: 'duration_hidden' });
    if (!admin && durCfg.maintenance) return res.status(423).json({ ok: false, message: 'duration_maintenance' });

    if (!admin) {
        const used = await getIpGetKeyCount(clientIP);
        if (used >= IP_GETKEY_LIMIT) return res.status(429).json({ ok: false, message: 'ip_limit', limit: IP_GETKEY_LIMIT, used });
    }

    const token = genToken();
    tasks.set(token, {
        duration, app: appId,
        steps: durCfg.steps.slice(),
        hours: DURATION_HOURS[duration],
        maxDevices: 1,        // ⭐ LUÔN = 1
        currentStep: 0, completedSteps: 0, totalSteps: durCfg.steps.length,
        done: false, key: null, keyExpire: null,
        createdAt: Date.now(),
        clientIP, clientUA: req.headers['user-agent'] || '',
        isAdmin: admin,
        stepStartedAt: 0, stepIP: '', stepUA: '', stepNonce: null,
        bypassed: false, bypassReason: null, callbackHistory: []
    });
    logIPTask(clientIP);
    setTimeout(() => tasks.delete(token), 30 * 60 * 1000);

    return res.json({ ok: true, token, duration, app: appId, totalSteps: durCfg.steps.length, maxDevices: 1, taskUrl: `${SERVER_URL}/task?token=${token}` });
});

// ============================================
// API: task-status
// ============================================
app.get('/api/task-status', (req, res) => {
    const task = tasks.get(req.query.token);
    if (!task) return res.status(404).json({ ok: false });
    return res.json({
        ok: true, duration: task.duration, app: task.app, progress: task.completedSteps, total: task.totalSteps,
        currentStep: task.currentStep, steps: task.steps, done: task.done,
        key: task.done ? task.key : null, keyExpire: task.keyExpire, hours: task.hours,
        maxDevices: task.maxDevices || 0,
        bypassed: task.bypassed, bypassReason: task.bypassReason, isAdmin: task.isAdmin
    });
});

// ============================================
// API: continue-task
// ============================================
app.get('/api/continue-task', async (req, res) => {
    const task = tasks.get(req.query.token);
    if (!task) return res.status(403).json({ ok: false });
    if (task.done) return res.json({ ok: true, done: true, key: task.key });
    if (task.bypassed) return res.json({ ok: false, message: 'bypassed' });
    const step = task.currentStep;
    if (step >= task.steps.length) return res.json({ ok: false });
    const type = task.steps[step];
    const nonce = genToken();
    task.stepNonce = nonce;
    task.bindSecret = genToken();
    setBindCookie(req, res, req.query.token, task.bindSecret);
    const cb = `${SERVER_URL}/api/step-callback?token=${req.query.token}&step=${step}&n=${nonce}&r=${Date.now()}`;
    task.stepStartedAt = Date.now();
    task.stepIP = getClientIP(req);
    task.stepUA = req.headers['user-agent'] || '';
    const url = await genShortLink(type, cb);
    if (!url) return res.json({ ok: false, message: 'link_error' });
    return res.json({ ok: true, url, step, total: task.totalSteps, type });
});

// ============================================
// API: step-callback
// ============================================
app.get('/api/step-callback', async (req, res) => {
    const { token, step, n } = req.query;
    const task = tasks.get(token);
    if (!task) return res.status(403).send('invalid');
    const stepNum = parseInt(step, 10);
    if (stepNum !== task.currentStep) return res.redirect(`${SERVER_URL}/task?token=${token}`);

    const cbKey = `${task.duration}-${stepNum}`;
    const type = task.steps[stepNum];

    if (!task.isAdmin) {
        // Chống trick: link/callback dùng log/lịch sử cũ để né bước
        const nonceInvalid = !n || n !== task.stepNonce || isNonceUsed(n);
        const replaySeen = task.callbackHistory.includes(cbKey);
        const check = detectBypass(req, task, type);
        const bypassReasons = check.reasons.slice();
        const bindCk = parseCookies(req)[bindCookieName(token)];
        const bindBad = !task.bindSecret || !bindCk || !safeEqualStr(bindCk, task.bindSecret);
        if (bindBad) bypassReasons.push('Trình duyệt không khớp phiên (link bị copy / lấy từ log)');
        if (nonceInvalid) bypassReasons.push('Link không hợp lệ hoặc đã được dùng trước đó (log/replay)');
        if (replaySeen) bypassReasons.push('Replay detected');
        if (bindBad || nonceInvalid || replaySeen || check.bypass) {
            task.bypassed = true;
            task.bypassReason = `Bypass ${type}. ${bypassReasons.join(' | ')}`;
            markIPBlacklisted(getClientIP(req));
            bypassLog.unshift({ time: vnTime(new Date()), ip: check.details.ip, ua: check.details.ua, duration: task.duration, step: stepNum+1, total: task.totalSteps, type, reasons: bypassReasons, elapsed: check.details.elapsed });
            if (bypassLog.length > 100) bypassLog.pop();
            return res.redirect(`${SERVER_URL}/task?token=${token}`);
        }
        rememberNonce(n);
    }
    if (!task.callbackHistory.includes(cbKey)) task.callbackHistory.push(cbKey);

    task.completedSteps++;
    task.currentStep++;
    task.stepStartedAt = 0; task.stepIP = ''; task.stepUA = ''; task.stepNonce = null;

    if (task.completedSteps >= task.totalSteps) {
        if (!task.isAdmin) {
            const used = await getIpGetKeyCount(task.clientIP);
            if (used >= IP_GETKEY_LIMIT) {
                task.bypassed = true;
                task.bypassReason = 'Đã đạt giới hạn số lần lấy key cho IP này';
                return res.redirect(`${SERVER_URL}/task?token=${token}`);
            }
        }
        const isVipApp = task.app === 'netsupervip';
        const appCfg = appsConfigCache[task.app] || appsConfigCache.netsuper;
        const key = isVipApp
            ? genVipKey(appCfg.prefix || 'NetSuperVip', appCfg.tailStyle || 'special9')
            : genKey(appCfg.prefix || 'NetSuper');
        const expireAt = Date.now() + task.hours * 3600 * 1000;
        await saveKeyToRedis(key, expireAt, task.maxDevices || 0, isVipApp);
        task.key = key;
        task.keyExpire = vnTime(new Date(expireAt));
        task.done = true;
        if (!task.isAdmin) await incrIpGetKeyCount(task.clientIP);
    }

    res.redirect(`${SERVER_URL}/task?token=${token}`);
});

// ============================================
// ADMIN APIs
// ============================================
app.post('/api/verify-admin', (req, res) => res.json({ isAdmin: isAdmin(req) }));

// ---- Site status (public read) ----
app.get('/api/site-status', (req, res) => {
    const admin = isAdmin(req);
    const payload = {
        ok: true,
        status: siteConfigCache.status,
        message: siteConfigCache.status === 'maintenance' ? siteConfigCache.maintMsg
               : siteConfigCache.status === 'off' ? siteConfigCache.offMsg : '',
        isAdmin: admin
    };
    if (admin) { payload.maintMsg = siteConfigCache.maintMsg; payload.offMsg = siteConfigCache.offMsg; }
    res.json(payload);
});

// ---- Site status (admin write) ----
app.post('/api/site-status', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    const { status, maintMsg, offMsg } = req.body;
    const patch = {};
    if (status && ['online', 'maintenance', 'off'].includes(status)) patch.status = status;
    if (typeof maintMsg === 'string') patch.maintMsg = maintMsg;
    if (typeof offMsg === 'string') patch.offMsg = offMsg;
    const cfg = await saveSiteConfig(patch);
    return res.json({ ok: true, config: cfg });
});

// ---- IP whitelist (admin) ----
app.post('/api/whitelist-add', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    const ip = String(req.body.ip || '').trim();
    if (!ip) return res.json({ ok: false, message: 'no_ip' });
    await addWhitelistIP(ip);
    return res.json({ ok: true, ip });
});
app.post('/api/whitelist-remove', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    const ip = String(req.body.ip || '').trim();
    if (!ip) return res.json({ ok: false, message: 'no_ip' });
    await removeWhitelistIP(ip);
    return res.json({ ok: true, ip });
});
app.post('/api/whitelist-list', (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    return res.json({ ok: true, ips: Array.from(whitelistCache), yourIp: getClientIP(req) });
});

// ---- Apps config (public read: dùng để render trang Get Key) ----
app.get('/api/apps-config', (req, res) => {
    const admin = isAdmin(req);
    const out = {};
    for (const appId of Object.keys(appsConfigCache)) {
        const a = appsConfigCache[appId];
        out[appId] = { label: a.label, durations: {} };
        if (admin) { out[appId].prefix = a.prefix; out[appId].tailStyle = a.tailStyle; }
        for (const dur of Object.keys(a.durations)) {
            const d = a.durations[dur];
            // Người dùng thường không cần thấy các key đang ẩn (trừ admin, để còn quản lý)
            if (!admin && d.hidden) continue;
            out[appId].durations[dur] = {
                hidden: d.hidden, maintenance: d.maintenance,
                steps: d.steps, totalSteps: d.steps.length,
                hours: DURATION_HOURS[dur], maxSteps: DURATION_MAX_STEPS[dur]
            };
        }
    }
    res.json({ ok: true, apps: out, isAdmin: admin });
});

// ---- Apps config (admin write) ----
app.post('/api/apps-config', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    const { app: appId, duration, hidden, maintenance, steps } = req.body;
    if (!appsConfigCache[appId] || !appsConfigCache[appId].durations[duration]) {
        return res.json({ ok: false, message: 'bad_app_or_duration' });
    }
    const durCfg = appsConfigCache[appId].durations[duration];
    if (typeof hidden === 'boolean') durCfg.hidden = hidden;
    if (typeof maintenance === 'boolean') durCfg.maintenance = maintenance;
    if (steps !== undefined) {
        const clean = sanitizeSteps(steps, duration);
        if (!clean) return res.json({ ok: false, message: 'bad_steps', maxSteps: DURATION_MAX_STEPS[duration] });
        durCfg.steps = clean;
    }
    await saveAppsConfig();
    return res.json({ ok: true, app: appId, duration, config: durCfg });
});

// ---- Đổi chữ đầu (prefix) + kiểu đuôi cho get key (admin) ----
app.post('/api/apps-prefix', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    const { app: appId, prefix, tailStyle } = req.body;
    if (!appsConfigCache[appId]) return res.json({ ok: false, message: 'bad_app' });
    const clean = sanitizeKeyPrefix(prefix);
    if (!clean) return res.json({ ok: false, message: 'bad_prefix' });
    appsConfigCache[appId].prefix = clean;
    if (tailStyle === 'alnum12' || tailStyle === 'special9') appsConfigCache[appId].tailStyle = tailStyle;
    await saveAppsConfig();
    return res.json({ ok: true, app: appId, prefix: clean, tailStyle: appsConfigCache[appId].tailStyle });
});

// ---- IP get-key usage (public, để hiển thị số lượt còn lại) ----
app.get('/api/ip-getkey-status', async (req, res) => {
    const admin = isAdmin(req);
    const used = admin ? 0 : await getIpGetKeyCount(getClientIP(req));
    res.json({ ok: true, used, limit: IP_GETKEY_LIMIT, unlimited: admin });
});

app.post('/api/create-key', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    const { content, time, maxDevices } = req.body;
    if (!content) return res.json({ ok: false, message: 'no_content' });

    const calc = calcExpire(time || {});
    if (!calc) return res.json({ ok: false, message: 'bad_time' });

    const maxDev = Math.max(0, Number(maxDevices) || 0);
    const isVip = !!req.body.vip;
    await saveKeyToRedis(content, calc.expireAt, maxDev, isVip);

    const totalHours = totalHoursOf(time || {});
    const steps = stepsForHours(totalHours);

    return res.json({
        ok: true, key: content, expireAt: calc.expireAt,
        expire: calc.isPermanent ? 'VĨNH VIỄN' : vnTime(new Date(calc.expireAt)),
        isPermanent: calc.isPermanent, maxDevices: maxDev, vip: isVip, steps
    });
});

app.post('/api/quick-create', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    const { duration, maxDevices } = req.body;
    const config = DURATION_CONFIG[duration];
    if (!config) return res.json({ ok: false });

    const maxDev = Math.max(0, Number(maxDevices) || 0);
    const key = genKey();
    const expireAt = Date.now() + config.hours * 3600 * 1000;
    await saveKeyToRedis(key, expireAt, maxDev);

    return res.json({
        ok: true, key, duration, hours: config.hours,
        expireAt, expire: vnTime(new Date(expireAt)),
        maxDevices: maxDev, steps: config.steps
    });
});

app.post('/api/bulk-create', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    const { count, time, mode, duration, maxDevices } = req.body;

    let n = parseInt(count, 10) || 1;
    if (n < 1) n = 1;
    if (n > MAX_BULK) n = MAX_BULK;

    const maxDev = Math.max(0, Number(maxDevices) || 0);
    let calc, steps, label;

    if (mode === 'preset') {
        const config = DURATION_CONFIG[duration];
        if (!config) return res.json({ ok: false, message: 'bad_duration' });
        calc = { expireAt: Date.now() + config.hours * 3600 * 1000, isPermanent: false };
        steps = config.steps;
        label = duration.toUpperCase();
    } else {
        calc = calcExpire(time || {});
        if (!calc) return res.json({ ok: false, message: 'bad_time' });
        const totalHours = totalHoursOf(time || {});
        steps = stepsForHours(totalHours);
        label = calc.isPermanent ? 'VĨNH VIỄN' : totalHours.toFixed(1) + 'h';
    }

    const keysList = [];
    for (let i = 0; i < n; i++) keysList.push(genKey());

    await saveManyKeysToRedis(keysList, calc.expireAt, maxDev);

    return res.json({
        ok: true, count: n, label, expireAt: calc.expireAt,
        expire: calc.isPermanent ? 'VĨNH VIỄN' : vnTime(new Date(calc.expireAt)),
        isPermanent: calc.isPermanent, maxDevices: maxDev,
        keys: keysList, steps
    });
});

app.post('/api/delete-key', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    await deleteKeyFromRedis(req.body.key);
    return res.json({ ok: true });
});

// ⭐ Reset key (cả key thường lẫn VIP): xoá hết hwids, giữ nguyên hạn còn lại -> key trắng, chưa ai đăng nhập.
app.post('/api/reset-key', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    const key = req.body.key;
    if (!key) return res.json({ ok: false, message: 'no_key' });
    const entry = await getKeyFromRedis(key);
    if (!entry) return res.json({ ok: false, message: 'key_not_found' });
    entry.hwids = [];
    delete entry.hwid;
    const saved = await saveKeyEntry(key, entry);
    if (!saved) return res.json({ ok: false, message: 'save_failed' });
    return res.json({ ok: true });
});

// ⭐ Sửa 1 key: cộng/trừ giờ hạn, đặt số thiết bị tối đa, gỡ 1 thiết bị, đổi loại VIP/thường
app.post('/api/key-update', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    const { key, addHours, setMaxDevices, removeHwid, setVip } = req.body;
    if (!key) return res.json({ ok: false, message: 'no_key' });
    const entry = await getKeyFromRedis(key);
    if (!entry) return res.json({ ok: false, message: 'key_not_found' });
    if (!Array.isArray(entry.hwids)) entry.hwids = entry.hwid ? [entry.hwid] : [];
    delete entry.hwid;

    if (setMaxDevices !== undefined && setMaxDevices !== null && setMaxDevices !== '') {
        entry.maxDevices = Math.max(0, Math.min(1000, parseInt(setMaxDevices, 10) || 0));
    }
    if (removeHwid) entry.hwids = entry.hwids.filter(h => h !== removeHwid);
    if (typeof setVip === 'boolean') entry.vip = setVip;

    let ttl = await redis('TTL', `ns:key:${key}`);
    if (!ttl || ttl <= 0) return res.json({ ok: false, message: 'expired' });
    const add = Number(addHours) || 0;
    if (add) {
        ttl = Math.max(60, ttl + Math.round(add * 3600));
        ttl = Math.min(ttl, PERMANENT_TTL_SEC);
    }
    await redisPipeline([
        ['SET', `ns:key:${key}`, JSON.stringify(entry), 'EX', String(ttl)],
        ['HSET', 'ns:meta', key, String(Date.now() + ttl * 1000)]
    ]);
    return res.json({
        ok: true, key, expireAt: Date.now() + ttl * 1000,
        maxDevices: Number(entry.maxDevices) || 0, devices: entry.hwids.length, vip: !!entry.vip
    });
});

// ⭐ Xoá / reset hàng loạt
app.post('/api/keys-bulk', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    const { action } = req.body;
    const keys = Array.isArray(req.body.keys) ? req.body.keys.map(String).slice(0, 5000) : [];
    if (!keys.length) return res.json({ ok: false, message: 'no_keys' });
    if (action === 'delete') {
        for (let i = 0; i < keys.length; i += 100) {
            const cmds = [];
            keys.slice(i, i + 100).forEach(k => { cmds.push(['DEL', `ns:key:${k}`]); cmds.push(['HDEL', 'ns:meta', k]); });
            await redisPipeline(cmds);
        }
        return res.json({ ok: true, action, count: keys.length });
    }
    if (action === 'reset') {
        let done = 0;
        for (let i = 0; i < keys.length; i += 100) {
            const chunk = keys.slice(i, i + 100);
            const got = await redisPipeline(chunk.map(k => ['GET', `ns:key:${k}`]));
            const ttls = await redisPipeline(chunk.map(k => ['TTL', `ns:key:${k}`]));
            const cmds = [];
            chunk.forEach((k, idx) => {
                const raw = got && got[idx] && got[idx].result;
                const ttl = ttls && ttls[idx] && ttls[idx].result;
                if (!raw || !ttl || ttl <= 0) return;
                let e = {};
                try { e = JSON.parse(raw); } catch (err) {}
                e.hwids = []; delete e.hwid;
                cmds.push(['SET', `ns:key:${k}`, JSON.stringify(e), 'EX', String(ttl)]);
                done++;
            });
            if (cmds.length) await redisPipeline(cmds);
        }
        return res.json({ ok: true, action, count: done });
    }
    return res.json({ ok: false, message: 'bad_action' });
});

// ⭐ RANDOM GENERATE: romdo key thường hoặc VIP, chữ đầu tuỳ chỉnh, đuôi chọn 1 trong 2 style
// style 'alnum12'  -> 12 ký tự hoa/thường/số
// style 'special9' -> 9 ký tự hoa/thường/số + ký tự đặc biệt (không dấu "-")
app.post('/api/random-create', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    const { count, mode, duration, maxDevices, prefix, style, vip } = req.body;

    let n = parseInt(count, 10) || 1;
    if (n < 1) n = 1;
    if (n > MAX_BULK) n = MAX_BULK;

    const isVip = !!vip;
    const maxDev = Math.max(0, Number(maxDevices) || 0);
    const cleanPrefix = sanitizeKeyPrefix(prefix) || (isVip ? 'NetSuperVip' : 'NetSuper');
    const tailStyle = style === 'alnum12' ? 'alnum12' : 'special9';

    let calc, label;
    if (mode === 'preset') {
        const config = DURATION_CONFIG[duration];
        if (!config) return res.json({ ok: false, message: 'bad_duration' });
        calc = { expireAt: Date.now() + config.hours * 3600 * 1000, isPermanent: false };
        label = duration.toUpperCase();
    } else {
        calc = calcExpire(req.body.time || {});
        if (!calc) return res.json({ ok: false, message: 'bad_time' });
        const totalHours = totalHoursOf(req.body.time || {});
        label = calc.isPermanent ? 'VĨNH VIỄN' : totalHours.toFixed(1) + 'h';
    }

    const keysList = [];
    const seen = new Set();
    while (keysList.length < n) {
        const k = `${cleanPrefix}-${genKeyTail(tailStyle)}`;
        if (seen.has(k)) continue;
        seen.add(k);
        keysList.push(k);
    }
    await saveManyKeysToRedis(keysList, calc.expireAt, maxDev, isVip);

    return res.json({
        ok: true, count: n, label, expireAt: calc.expireAt,
        expire: calc.isPermanent ? 'VĨNH VIỄN' : vnTime(new Date(calc.expireAt)),
        isPermanent: calc.isPermanent, maxDevices: maxDev, vip: isVip,
        prefix: cleanPrefix, style: tailStyle, keys: keysList
    });
});

// ⭐ VIP packages — public: mua key VIP (1 ngày/7 ngày/30 ngày/vĩnh viễn). Cổng thanh toán
// chưa triển khai -> luôn trả "đang bảo trì" cho user thường (admin dùng /api/vip-admin-create bên dưới).
app.get('/api/vip-packages', (req, res) => {
    const packages = Object.entries(VIP_PACKAGES).map(([id, p]) => ({ id, label: p.label, price: p.price, permanent: p.permanent }));
    return res.json({ ok: true, packages });
});
app.post('/api/vip-buy', (req, res) => {
    const pkg = VIP_PACKAGES[req.body.package];
    if (!pkg) return res.json({ ok: false, message: 'bad_package' });
    return res.status(423).json({ ok: false, message: 'package_maintenance', label: pkg.label });
});

// ⭐ Admin tạo key VIP miễn phí theo gói (không cần mua) — chữ đầu tuỳ chỉnh, đuôi chọn style
app.post('/api/vip-admin-create', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    const { package: pkgId, count, prefix, style, maxDevices } = req.body;
    const pkg = VIP_PACKAGES[pkgId];
    if (!pkg) return res.json({ ok: false, message: 'bad_package' });

    let n = parseInt(count, 10) || 1;
    if (n < 1) n = 1;
    if (n > MAX_BULK) n = MAX_BULK;

    const maxDev = Math.max(0, Number(maxDevices) || 0);
    const cleanPrefix = sanitizeKeyPrefix(prefix) || 'NetSuperVip';
    const tailStyle = style === 'alnum12' ? 'alnum12' : 'special9';
    const expireAt = pkg.permanent ? PERMANENT_EXPIRE_AT() : Date.now() + pkg.hours * 3600 * 1000;

    const keysList = [];
    const seen = new Set();
    while (keysList.length < n) {
        const k = `${cleanPrefix}-${genKeyTail(tailStyle)}`;
        if (seen.has(k)) continue;
        seen.add(k);
        keysList.push(k);
    }
    await saveManyKeysToRedis(keysList, expireAt, maxDev, true);

    return res.json({
        ok: true, count: n, package: pkgId, label: pkg.label,
        expireAt, expire: pkg.permanent ? 'VĨNH VIỄN' : vnTime(new Date(expireAt)),
        isPermanent: pkg.permanent, maxDevices: maxDev, vip: true,
        prefix: cleanPrefix, style: tailStyle, keys: keysList
    });
});

app.post('/api/list-keys', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    const list = await listKeysFromRedis();
    const entries = new Array(list.length).fill(null);
    for (let i = 0; i < list.length; i += 200) {
        const chunk = list.slice(i, i + 200);
        const got = await redisPipeline(chunk.map(v => ['GET', `ns:key:${v.key}`]));
        chunk.forEach((v, idx) => {
            const raw = got && got[idx] && got[idx].result;
            if (raw) { try { entries[i + idx] = JSON.parse(raw); } catch (e) { entries[i + idx] = {}; } }
        });
    }
    const out = [];
    list.forEach((v, idx) => {
        const entry = entries[idx];
        if (!entry) return; // key đã hết hạn/bị xoá trong Redis nhưng meta còn sót
        const hw = Array.isArray(entry.hwids) ? entry.hwids : (entry.hwid ? [entry.hwid] : []);
        out.push({
            key: v.key,
            expireAt: v.expireAt,
            expire: (v.expireAt - Date.now() > PERMANENT_TTL_SEC * 1000 - 86400000)
                ? 'VĨNH VIỄN' : vnTime(new Date(v.expireAt)),
            maxDevices: Number(entry.maxDevices) || 0,
            devices: hw.length,
            hwids: hw.slice(0, 20),
            createdAt: entry.createdAt || 0,
            vip: !!entry.vip
        });
    });
    return res.json({ ok: true, keys: out, serverTime: Date.now() });
});

app.post('/api/bypass-log', (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    return res.json({ ok: true, logs: bypassLog.slice(0, 50) });
});

app.get('/api/health', async (req, res) => {
    const ping = await redis('PING');
    res.json({ ok: true, redis: ping === 'PONG' });
});

// ============================================
// ROUTES
// ============================================
function serveMainOrMaintenance(req, res) {
    if (siteConfigCache.status !== 'online' && !isAdmin(req)) {
        const msg = siteConfigCache.status === 'off' ? siteConfigCache.offMsg : siteConfigCache.maintMsg;
        return res.send(renderMaintenancePage(siteConfigCache.status, msg));
    }
    return res.send(MAIN_HTML);
}
app.get('/', serveMainOrMaintenance);
app.get('/getkey', serveMainOrMaintenance);
// Hidden admin entrance — always reaches the full page (with admin panel JS-gated) regardless of site status
function notFound(res) { return res.status(404).type('text/plain').send('Cannot GET ' + 'page'); }
app.get('/amin/thichlendo', (req, res) => {
    if (!isAdminSession(req)) return notFound(res);
    res.set('Cache-Control', 'no-store'); res.send(MAIN_HTML);
});
app.get('/amin/keys', (req, res) => {
    if (!isAdminSession(req)) return notFound(res);
    res.set('Cache-Control', 'no-store'); res.send(KEYS_HTML);
});

// ---- Trang đăng nhập bí mật của admin ----
const adminLoginFails = new Map(); // ip -> { count, until }
function adminLoginPage(msg) {
    return `<!DOCTYPE html><html lang="vi"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>.</title>
<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0b1020;font-family:system-ui,sans-serif;color:#e5e7eb}
form{background:#111936;border:1px solid #243056;border-radius:14px;padding:26px;width:min(92vw,340px)}
input{width:100%;box-sizing:border-box;padding:12px;border-radius:10px;border:1px solid #2b3a6b;background:#0b1020;color:#fff;font-size:15px;margin:12px 0}
button{width:100%;padding:12px;border:0;border-radius:10px;background:linear-gradient(135deg,#22d3ee,#8b5cf6);color:#fff;font-weight:700;font-size:15px}
.e{color:#f87171;font-size:13px;min-height:16px}</style></head><body>
<form method="POST" autocomplete="off"><div style="font-weight:700;font-size:17px">Admin</div>
<input type="password" name="password" placeholder="Mật khẩu" autofocus required><div class="e">${msg || ''}</div><button type="submit">Vào</button></form></body></html>`;
}
if (ADMIN_LOGIN_ENABLED) {
    app.get('/' + ADMIN_PATH, (req, res) => {
        res.set('Cache-Control', 'no-store');
        if (isAdminSession(req)) return res.redirect('/amin/thichlendo');
        res.send(adminLoginPage(''));
    });
    app.post('/' + ADMIN_PATH, (req, res) => {
        res.set('Cache-Control', 'no-store');
        const ip = getClientIP(req);
        const f = adminLoginFails.get(ip) || { count: 0, until: 0 };
        if (f.until > Date.now()) return res.status(429).send(adminLoginPage('Thử sai quá nhiều, đợi 15 phút.'));
        const pw = String((req.body && req.body.password) || '');
        if (!safeEqualStr(pw, ADMIN_PASSWORD)) {
            f.count++;
            if (f.count >= 5) { f.until = Date.now() + 15 * 60 * 1000; f.count = 0; }
            adminLoginFails.set(ip, f);
            return res.status(401).send(adminLoginPage('Sai mật khẩu.'));
        }
        adminLoginFails.delete(ip);
        const secure = req.secure || String(req.headers['x-forwarded-proto'] || '').includes('https');
        res.setHeader('Set-Cookie', `${ADMIN_COOKIE}=${encodeURIComponent(makeAdminToken())}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${ADMIN_SESSION_HOURS * 3600}${secure ? '; Secure' : ''}`);
        return res.redirect('/amin/thichlendo');
    });
    app.post('/api/admin-logout', (req, res) => {
        res.setHeader('Set-Cookie', `${ADMIN_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`);
        res.json({ ok: true });
    });
}
app.get('/task', (req, res) => res.send(renderTaskPage(req.query.token || '')));

// ============================================
// THEME (giao diện dùng chung)
// ============================================
const THEME_HEAD = `<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0' y1='0' x2='1' y2='1'%3E%3Cstop offset='0' stop-color='%2322d3ee'/%3E%3Cstop offset='.5' stop-color='%238b5cf6'/%3E%3Cstop offset='1' stop-color='%23e879f9'/%3E%3C/linearGradient%3E%3C/defs%3E%3Cpath d='M32 4 56 24 32 60 8 24Z' fill='url(%23g)'/%3E%3Cpath d='M8 24h48L32 60Z' fill='%23000' fill-opacity='.18'/%3E%3C/svg%3E">
<meta name="theme-color" content="#060612">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Be+Vietnam+Pro:wght@400;500;600;700&family=Bricolage+Grotesque:opsz,wght@12..96,600..800&family=JetBrains+Mono:wght@500;600&display=swap" rel="stylesheet">`;

const THEME_BG = `<div class="bg" aria-hidden="true">
<span class="orb orb-1"></span>
<span class="orb orb-2"></span>
<span class="orb orb-3"></span>
<span class="orb orb-4"></span>
<span class="grid-lines"></span>
<span class="stars"></span>
<span class="vignette"></span>
</div>`;

const THEME_LOGO = `<svg viewBox="0 0 64 64" width="22" height="22" aria-hidden="true">
<defs>
<linearGradient id="bm" x1="0" y1="0" x2="1" y2="1">
<stop offset="0" stop-color="#22d3ee"/>
<stop offset=".5" stop-color="#8b5cf6"/>
<stop offset="1" stop-color="#e879f9"/>
</linearGradient>
</defs>
<path d="M32 4 56 24 32 60 8 24Z" fill="url(#bm)"/>
<path d="M8 24h48L32 60Z" fill="#000" fill-opacity=".2"/>
<path d="M8 24 20 24 32 4ZM56 24 44 24 32 4Z" fill="#fff" fill-opacity=".22"/>
</svg>`;

const THEME_CSS = `
/* ---------- TOKENS ---------- */
:root{
  --ink-950:#060612;
  --ink-900:#0a0a1f;
  --ink-800:#111129;
  --ink-700:#1a1a3a;
  --glass:rgba(15,15,40,.62);
  --glass-strong:rgba(22,22,56,.82);
  --field:rgba(255,255,255,.045);
  --line:rgba(255,255,255,.09);
  --line-strong:rgba(255,255,255,.17);
  --text:#f2f2fc;
  --text-dim:#aeb0d0;
  --text-faint:#71739a;
  --cyan:#22d3ee;
  --violet:#8b5cf6;
  --indigo:#6366f1;
  --fuchsia:#e879f9;
  --amber:#fbbf24;
  --emerald:#34d399;
  --rose:#fb7185;
  --grad-brand:linear-gradient(110deg,#22d3ee 0%,#8b5cf6 36%,#e879f9 66%,#fbbf24 100%);
  --grad-primary:linear-gradient(115deg,#6366f1 0%,#8b5cf6 45%,#e879f9 100%);
  --grad-success:linear-gradient(115deg,#10b981 0%,#22d3ee 100%);
  --grad-warm:linear-gradient(115deg,#fbbf24 0%,#fb7185 100%);
  --grad-danger:linear-gradient(115deg,#f43f5e 0%,#fb7185 100%);
  --radius-xl:26px;
  --radius-lg:20px;
  --radius-md:14px;
  --radius-sm:11px;
  --font-display:'Bricolage Grotesque','Be Vietnam Pro',system-ui,sans-serif;
  --font-body:'Be Vietnam Pro',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
  --font-mono:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  --ease:cubic-bezier(.2,.8,.2,1);
}

/* ---------- RESET ---------- */
*{box-sizing:border-box;margin:0;padding:0}
html{color-scheme:dark;-webkit-text-size-adjust:100%;scroll-behavior:smooth}
body{
  font-family:var(--font-body);
  font-size:14px;
  line-height:1.55;
  color:var(--text);
  background:var(--ink-950);
  min-height:100vh;
  overflow-x:hidden;
  -webkit-font-smoothing:antialiased;
  -moz-osx-font-smoothing:grayscale;
}
::selection{background:rgba(139,92,246,.6);color:#fff}
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(255,255,255,.14);border-radius:8px}
::-webkit-scrollbar-thumb:hover{background:rgba(255,255,255,.28)}

/* ---------- BACKGROUND ---------- */
.bg{
  position:fixed;
  inset:0;
  z-index:0;
  overflow:hidden;
  pointer-events:none;
  background:
    radial-gradient(1200px 700px at 50% -10%,rgba(99,102,241,.16),transparent 65%),
    var(--ink-950);
}
.orb{
  position:absolute;
  border-radius:50%;
  filter:blur(90px);
  opacity:.55;
  will-change:transform;
}
.orb-1{
  width:560px;height:560px;left:-180px;top:-200px;
  background:radial-gradient(circle at 35% 35%,#7c3aed,transparent 70%);
  animation:float-a 24s ease-in-out infinite;
}
.orb-2{
  width:520px;height:520px;right:-190px;top:4%;
  background:radial-gradient(circle at 60% 40%,#06b6d4,transparent 70%);
  opacity:.42;
  animation:float-b 28s ease-in-out infinite;
}
.orb-3{
  width:600px;height:600px;left:6%;bottom:-300px;
  background:radial-gradient(circle at 50% 50%,#db2777,transparent 70%);
  opacity:.38;
  animation:float-c 30s ease-in-out infinite;
}
.orb-4{
  width:420px;height:420px;right:6%;bottom:-160px;
  background:radial-gradient(circle at 50% 50%,#f59e0b,transparent 70%);
  opacity:.26;
  animation:float-a 34s ease-in-out infinite reverse;
}
.grid-lines{
  position:absolute;
  inset:0;
  background-image:
    linear-gradient(rgba(255,255,255,.04) 1px,transparent 1px),
    linear-gradient(90deg,rgba(255,255,255,.04) 1px,transparent 1px);
  background-size:46px 46px;
  -webkit-mask-image:radial-gradient(ellipse at 50% 28%,#000 8%,transparent 68%);
  mask-image:radial-gradient(ellipse at 50% 28%,#000 8%,transparent 68%);
}
.stars{
  position:absolute;
  inset:0;
  background-image:
    radial-gradient(1.4px 1.4px at 12% 22%,#fff,transparent),
    radial-gradient(1.2px 1.2px at 28% 64%,#c7d2fe,transparent),
    radial-gradient(1.6px 1.6px at 44% 12%,#fff,transparent),
    radial-gradient(1.2px 1.2px at 58% 78%,#f5d0fe,transparent),
    radial-gradient(1.5px 1.5px at 73% 30%,#fff,transparent),
    radial-gradient(1.2px 1.2px at 86% 58%,#a5f3fc,transparent),
    radial-gradient(1.4px 1.4px at 92% 14%,#fff,transparent),
    radial-gradient(1.2px 1.2px at 6% 82%,#fde68a,transparent),
    radial-gradient(1.3px 1.3px at 37% 90%,#fff,transparent),
    radial-gradient(1.1px 1.1px at 66% 48%,#e9d5ff,transparent);
  opacity:.7;
  animation:twinkle 7s ease-in-out infinite;
}
.vignette{
  position:absolute;
  inset:0;
  background:radial-gradient(ellipse at 50% 40%,transparent 45%,rgba(3,3,12,.72) 100%);
}

/* ---------- TOP BAR ---------- */
.topbar{
  position:relative;
  z-index:2;
  max-width:1120px;
  margin:0 auto;
  padding:18px 20px 0;
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:12px;
}
.brand{
  display:inline-flex;
  align-items:center;
  gap:10px;
  text-decoration:none;
}
.brand-mark{
  width:40px;
  height:40px;
  border-radius:13px;
  display:grid;
  place-items:center;
  background:linear-gradient(145deg,rgba(255,255,255,.11),rgba(255,255,255,.03));
  border:1px solid var(--line-strong);
  box-shadow:0 0 26px rgba(139,92,246,.4),inset 0 1px 0 rgba(255,255,255,.18);
}
.brand-name{
  font-family:var(--font-display);
  font-weight:800;
  font-size:17px;
  letter-spacing:.2px;
  background:var(--grad-brand);
  background-size:200% 100%;
  -webkit-background-clip:text;
  background-clip:text;
  color:transparent;
  animation:gradient-shift 9s linear infinite;
}
.pill{
  display:inline-flex;
  align-items:center;
  gap:7px;
  padding:7px 13px;
  border-radius:999px;
  font-size:11.5px;
  font-weight:600;
  color:var(--text-dim);
  background:var(--glass);
  border:1px solid var(--line);
  backdrop-filter:blur(12px);
  -webkit-backdrop-filter:blur(12px);
}
.pill i{
  width:7px;
  height:7px;
  border-radius:50%;
  background:var(--emerald);
  box-shadow:0 0 10px var(--emerald);
  display:inline-block;
}

/* ---------- GLASS CARD ---------- */
.card{
  --mx:50%;
  --my:0%;
  position:relative;
  padding:24px;
  border-radius:var(--radius-xl);
  background:
    radial-gradient(420px circle at var(--mx) var(--my),rgba(139,92,246,.13),transparent 60%),
    linear-gradient(180deg,rgba(255,255,255,.055),rgba(255,255,255,.018)),
    var(--glass);
  backdrop-filter:blur(22px) saturate(150%);
  -webkit-backdrop-filter:blur(22px) saturate(150%);
  box-shadow:0 34px 70px -34px rgba(0,0,0,.9),0 0 0 1px rgba(255,255,255,.02) inset;
}
.card::before{
  content:'';
  position:absolute;
  inset:0;
  padding:1px;
  border-radius:inherit;
  background:linear-gradient(140deg,rgba(139,92,246,.75),rgba(34,211,238,.28) 38%,rgba(255,255,255,.06) 60%,rgba(232,121,249,.6));
  -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);
  -webkit-mask-composite:xor;
  mask:linear-gradient(#000 0 0) content-box exclude,linear-gradient(#000 0 0);
  mask-composite:exclude;
  pointer-events:none;
}
.card-head{
  display:flex;
  align-items:center;
  gap:14px;
  margin-bottom:18px;
}
.card-icon{
  flex:0 0 auto;
  width:46px;
  height:46px;
  border-radius:15px;
  display:grid;
  place-items:center;
  color:#fff;
  background:var(--grad-primary);
  box-shadow:0 12px 28px -10px rgba(139,92,246,.85),inset 0 1px 0 rgba(255,255,255,.3);
}
.card-icon.green{background:var(--grad-success);box-shadow:0 12px 28px -10px rgba(16,185,129,.8),inset 0 1px 0 rgba(255,255,255,.3)}
.card-icon.warm{background:var(--grad-warm);box-shadow:0 12px 28px -10px rgba(251,113,133,.8),inset 0 1px 0 rgba(255,255,255,.3)}
.card h2{
  font-family:var(--font-display);
  font-size:19px;
  font-weight:700;
  letter-spacing:.1px;
  color:var(--text);
  line-height:1.2;
}
.card-sub{
  margin-top:3px;
  font-size:12.5px;
  color:var(--text-faint);
}

/* ---------- BUTTONS ---------- */
button{
  position:relative;
  overflow:hidden;
  width:100%;
  margin-top:10px;
  padding:15px 18px;
  border:0;
  border-radius:var(--radius-sm);
  font-family:var(--font-display);
  font-size:14px;
  font-weight:700;
  letter-spacing:.3px;
  color:#fff;
  cursor:pointer;
  background:var(--grad-primary);
  background-size:170% 100%;
  box-shadow:0 14px 32px -12px rgba(139,92,246,.85),inset 0 1px 0 rgba(255,255,255,.28);
  transition:transform .22s var(--ease),box-shadow .22s var(--ease),background-position .55s var(--ease),filter .2s ease,border-color .2s ease,background-color .2s ease;
  -webkit-tap-highlight-color:transparent;
}
button::after{
  content:'';
  position:absolute;
  top:0;
  bottom:0;
  left:0;
  width:46%;
  background:linear-gradient(100deg,transparent,rgba(255,255,255,.34),transparent);
  transform:translateX(-140%) skewX(-18deg);
  transition:transform .7s var(--ease);
  pointer-events:none;
}
button:hover{
  transform:translateY(-2px);
  background-position:100% 0;
  box-shadow:0 20px 40px -14px rgba(139,92,246,.95),inset 0 1px 0 rgba(255,255,255,.34);
}
button:hover::after{transform:translateX(320%) skewX(-18deg)}
button:active{transform:translateY(0) scale(.985);filter:brightness(.94)}
button:disabled{
  cursor:not-allowed;
  color:var(--text-faint);
  background:rgba(255,255,255,.06);
  box-shadow:none;
  transform:none;
  filter:none;
}
button:disabled::after{display:none}
button:focus-visible,input:focus-visible{outline:2px solid var(--cyan);outline-offset:3px}
.btn-purple{background:var(--grad-primary);background-size:170% 100%}
.btn-green{
  background:var(--grad-success);
  background-size:170% 100%;
  color:#032a22;
  box-shadow:0 14px 32px -12px rgba(16,185,129,.8),inset 0 1px 0 rgba(255,255,255,.35);
}
.btn-green:hover{box-shadow:0 20px 40px -14px rgba(16,185,129,.95),inset 0 1px 0 rgba(255,255,255,.4)}
.ripple{
  position:absolute;
  border-radius:50%;
  background:rgba(255,255,255,.4);
  transform:scale(0);
  animation:ripple .65s ease-out forwards;
  pointer-events:none;
}

/* ---------- BADGES ---------- */
.status-badge{
  display:inline-flex;
  align-items:center;
  gap:6px;
  padding:6px 12px;
  border-radius:999px;
  font-family:var(--font-mono);
  font-size:10.5px;
  font-weight:600;
  letter-spacing:.4px;
  backdrop-filter:blur(12px);
  -webkit-backdrop-filter:blur(12px);
}
.status-online{
  color:var(--emerald);
  background:rgba(52,211,153,.12);
  border:1px solid rgba(52,211,153,.38);
  box-shadow:0 0 22px -6px rgba(52,211,153,.6);
}
.status-offline{
  color:var(--rose);
  background:rgba(251,113,133,.12);
  border:1px solid rgba(251,113,133,.38);
  box-shadow:0 0 22px -6px rgba(251,113,133,.6);
}

/* ---------- SERVER STATUS DOT (blinking) ---------- */
.status-dot{
  display:inline-flex;
  align-items:center;
  gap:7px;
  padding:6px 13px;
  border-radius:999px;
  font-family:var(--font-mono);
  font-size:10.5px;
  font-weight:700;
  letter-spacing:.5px;
  backdrop-filter:blur(12px);
  -webkit-backdrop-filter:blur(12px);
  transition:background .25s var(--ease),border-color .25s var(--ease),color .25s var(--ease);
}
.status-dot i{
  width:8px;height:8px;border-radius:50%;flex:none;
  animation:dot-blink 1.4s ease-in-out infinite;
}
.status-dot.online{
  color:var(--emerald);
  background:rgba(52,211,153,.12);
  border:1px solid rgba(52,211,153,.4);
}
.status-dot.online i{background:var(--emerald);box-shadow:0 0 10px 2px rgba(52,211,153,.8)}
.status-dot.maintenance{
  color:var(--rose);
  background:rgba(251,113,133,.12);
  border:1px solid rgba(251,113,133,.4);
}
.status-dot.maintenance i{background:var(--rose);box-shadow:0 0 10px 2px rgba(251,113,133,.85)}
@keyframes dot-blink{
  0%,100%{opacity:1;transform:scale(1)}
  50%{opacity:.25;transform:scale(.7)}
}

/* ---------- FOOTER ---------- */
.hint{
  position:relative;
  z-index:1;
  margin-top:34px;
  text-align:center;
  font-size:12px;
  font-weight:500;
  letter-spacing:.4px;
  color:var(--text-faint);
}
.hint b{
  font-family:var(--font-display);
  font-weight:800;
  background:var(--grad-brand);
  background-size:200% 100%;
  -webkit-background-clip:text;
  background-clip:text;
  color:transparent;
  animation:gradient-shift 9s linear infinite;
}

/* ---------- KEYFRAMES ---------- */
@keyframes float-a{0%,100%{transform:translate3d(0,0,0)}50%{transform:translate3d(70px,50px,0)}}
@keyframes float-b{0%,100%{transform:translate3d(0,0,0)}50%{transform:translate3d(-80px,60px,0)}}
@keyframes float-c{0%,100%{transform:translate3d(0,0,0)}50%{transform:translate3d(60px,-70px,0)}}
@keyframes twinkle{0%,100%{opacity:.35}50%{opacity:.85}}
@keyframes gradient-shift{0%{background-position:0% 50%}100%{background-position:200% 50%}}
@keyframes rise{from{opacity:0;transform:translateY(18px)}to{opacity:1;transform:none}}
@keyframes bob{0%,100%{transform:translateY(0) rotate(-1.2deg)}50%{transform:translateY(-9px) rotate(.6deg)}}
@keyframes ripple{to{transform:scale(1);opacity:0}}
@keyframes toast-in{from{opacity:0;transform:translate(-50%,-14px) scale(.96)}to{opacity:1;transform:translate(-50%,0) scale(1)}}
@keyframes pop-in{0%{opacity:0;transform:scale(.92) translateY(10px)}60%{transform:scale(1.02)}100%{opacity:1;transform:none}}
@keyframes glow-pulse{0%,100%{box-shadow:0 0 34px -8px rgba(52,211,153,.5)}50%{box-shadow:0 0 56px -4px rgba(52,211,153,.8)}}

@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{
    animation-duration:.001ms !important;
    animation-iteration-count:1 !important;
    transition-duration:.001ms !important;
    scroll-behavior:auto !important;
  }
}
`;

const THEME_JS = `<script>
(function () {
  try {
    document.addEventListener('pointermove', function (e) {
      var t = e.target;
      var c = t && t.closest ? t.closest('.card') : null;
      if (!c) return;
      var r = c.getBoundingClientRect();
      c.style.setProperty('--mx', (e.clientX - r.left) + 'px');
      c.style.setProperty('--my', (e.clientY - r.top) + 'px');
    }, { passive: true });

    document.addEventListener('pointerdown', function (e) {
      var t = e.target;
      var b = t && t.closest ? t.closest('button') : null;
      if (!b || b.disabled) return;
      var r = b.getBoundingClientRect();
      var s = Math.max(r.width, r.height) * 1.6;
      var d = document.createElement('span');
      d.className = 'ripple';
      d.style.width = s + 'px';
      d.style.height = s + 'px';
      d.style.left = (e.clientX - r.left - s / 2) + 'px';
      d.style.top = (e.clientY - r.top - s / 2) + 'px';
      b.appendChild(d);
      setTimeout(function () { if (d.parentNode) d.parentNode.removeChild(d); }, 700);
    }, { passive: true });
  } catch (err) {}
})();
</script>`;

// ============================================
// HTML MAIN
// ============================================
const MAIN_CSS = `
/* ---------- LAYOUT ---------- */
.wrap{
  position:relative;
  z-index:1;
  max-width:560px;
  margin:0 auto;
  padding:26px 18px 48px;
}
body:has(#adminPanel[style*="block"]) .wrap{max-width:1120px}
.layout{
  display:grid;
  grid-template-columns:minmax(0,1fr);
  gap:22px;
}
@media (min-width:1000px){
  body:has(#adminPanel[style*="block"]) .layout{
    grid-template-columns:minmax(0,430px) minmax(0,1fr);
    align-items:start;
  }
  body:has(#adminPanel[style*="block"]) .get-card{
    position:sticky;
    top:22px;
  }
}

/* ---------- HERO ---------- */
.hero{
  text-align:center;
  padding:16px 0 34px;
  animation:rise .8s var(--ease) both;
}
.hero h1{
  font-family:var(--font-display);
  font-weight:800;
  font-size:clamp(50px,13vw,92px);
  line-height:.98;
  letter-spacing:-2px;
  background:var(--grad-brand);
  background-size:220% 100%;
  -webkit-background-clip:text;
  background-clip:text;
  color:transparent;
  animation:gradient-shift 10s linear infinite;
  filter:drop-shadow(0 10px 44px rgba(139,92,246,.5));
}
.tagline{
  margin:16px auto 0;
  max-width:440px;
  font-size:15px;
  font-weight:500;
  color:var(--text-dim);
}

/* ---------- KEY TICKET (hero visual) ---------- */
.ticket-wrap{
  margin:34px auto 0;
  max-width:430px;
  filter:drop-shadow(0 30px 46px rgba(124,58,237,.46));
  animation:bob 8s ease-in-out infinite;
}
.ticket{
  position:relative;
  display:flex;
  align-items:stretch;
  border-radius:22px;
  background:
    linear-gradient(135deg,rgba(139,92,246,.42),rgba(34,211,238,.16) 46%,rgba(232,121,249,.36)),
    var(--glass-strong);
  -webkit-mask:
    radial-gradient(circle 12px at 0 50%,transparent 98%,#000) left/51% 100% no-repeat,
    radial-gradient(circle 12px at 100% 50%,transparent 98%,#000) right/51% 100% no-repeat;
  mask:
    radial-gradient(circle 12px at 0 50%,transparent 98%,#000) left/51% 100% no-repeat,
    radial-gradient(circle 12px at 100% 50%,transparent 98%,#000) right/51% 100% no-repeat;
}
.ticket::before{
  content:'';
  position:absolute;
  inset:0;
  background:linear-gradient(115deg,transparent 30%,rgba(255,255,255,.14) 48%,transparent 64%);
  pointer-events:none;
}
.ticket-main{
  flex:1;
  min-width:0;
  padding:20px 16px 20px 24px;
  text-align:left;
}
.ticket-label{
  font-size:11.5px;
  font-weight:600;
  color:var(--text-dim);
  letter-spacing:.3px;
}
.ticket-code{
  margin-top:9px;
  font-family:var(--font-mono);
  font-size:clamp(10px,2.9vw,13px);
  font-weight:600;
  color:#fff;
  white-space:nowrap;
  overflow:hidden;
}
.ticket-code em{
  font-style:normal;
  color:var(--fuchsia);
  text-shadow:0 0 14px rgba(232,121,249,.8);
}
.ticket-meta{
  display:block;
  margin-top:12px;
  font-size:11.5px;
  color:var(--text-faint);
}
.ticket-stub{
  flex:0 0 78px;
  display:grid;
  place-items:center;
  padding:14px 10px;
  border-left:2px dashed rgba(255,255,255,.22);
}
.ticket-stub span{
  width:44px;
  height:44px;
  border-radius:50%;
  display:grid;
  place-items:center;
  color:#fff;
  background:var(--grad-brand);
  box-shadow:0 0 28px rgba(139,92,246,.7),inset 0 1px 0 rgba(255,255,255,.4);
}

/* ---------- PERKS ---------- */
.perks{
  list-style:none;
  display:flex;
  flex-wrap:wrap;
  justify-content:center;
  gap:8px;
  margin-top:28px;
}
.perks li{
  display:inline-flex;
  align-items:center;
  gap:8px;
  padding:8px 14px;
  border-radius:999px;
  font-size:12.5px;
  font-weight:500;
  color:var(--text-dim);
  background:var(--glass);
  border:1px solid var(--line);
  backdrop-filter:blur(10px);
  -webkit-backdrop-filter:blur(10px);
}
.perks li i{
  width:7px;
  height:7px;
  border-radius:50%;
  display:inline-block;
  background:var(--cyan);
  box-shadow:0 0 10px var(--cyan);
}
.perks li:nth-child(2) i{background:var(--fuchsia);box-shadow:0 0 10px var(--fuchsia)}
.perks li:nth-child(3) i{background:var(--amber);box-shadow:0 0 10px var(--amber)}

/* ---------- GET KEY CARD ---------- */
.get-card{animation:rise .8s var(--ease) .12s both}
.get-card #getKeyBtn{
  margin-top:2px;
  padding:19px 18px;
  font-size:15px;
  letter-spacing:.8px;
}
#durationMenu{
  display:none;
  grid-template-columns:1fr 1fr;
  gap:10px;
  margin-top:4px;
}
#durationMenu button{
  --c1:#22d3ee;
  --c2:#6366f1;
  --glow:rgba(34,211,238,.5);
  margin:0;
  padding:22px 10px 18px;
  display:flex;
  flex-direction:column;
  align-items:center;
  gap:9px;
  border-radius:var(--radius-md);
  color:var(--text);
  background:
    linear-gradient(160deg,rgba(255,255,255,.08),rgba(255,255,255,.02)),
    var(--ink-800);
  background-size:100% 100%;
  border:1px solid var(--line);
  box-shadow:0 18px 32px -20px rgba(0,0,0,.95),inset 0 1px 0 rgba(255,255,255,.08);
}
#durationMenu button::before{
  content:'';
  position:absolute;
  left:16px;
  right:16px;
  top:0;
  height:3px;
  border-radius:0 0 6px 6px;
  background:linear-gradient(90deg,var(--c1),var(--c2));
}
#durationMenu button b{
  font-family:var(--font-display);
  font-size:34px;
  font-weight:800;
  line-height:1;
  letter-spacing:-.5px;
  background:linear-gradient(120deg,var(--c1),var(--c2));
  -webkit-background-clip:text;
  background-clip:text;
  color:transparent;
}
#durationMenu button span{
  padding:3px 10px;
  border-radius:999px;
  font-family:var(--font-body);
  font-size:11px;
  font-weight:500;
  letter-spacing:0;
  color:var(--text-dim);
  background:rgba(255,255,255,.07);
}
#durationMenu button:hover{
  transform:translateY(-4px);
  border-color:var(--line-strong);
  background-position:0 0;
  box-shadow:0 24px 42px -18px var(--glow),inset 0 1px 0 rgba(255,255,255,.12);
}
#durationMenu button:nth-child(2){--c1:#a78bfa;--c2:#e879f9;--glow:rgba(167,139,250,.55)}
#durationMenu button:nth-child(3){--c1:#e879f9;--c2:#fb7185;--glow:rgba(232,121,249,.55)}
#durationMenu button:nth-child(4){--c1:#fbbf24;--c2:#fb7185;--glow:rgba(251,191,36,.5)}
#durationMenu button:nth-child(5){
  --c1:#34d399;
  --c2:#22d3ee;
  --glow:rgba(52,211,153,.55);
  grid-column:span 2;
  flex-direction:row;
  justify-content:center;
  gap:16px;
  padding:20px 10px 18px;
}
#getKeyStatus{
  margin-top:14px;
  padding:11px 14px;
  border-radius:12px;
  text-align:center;
  font-size:12.5px;
  font-weight:500;
  color:var(--text-dim);
  background:var(--field);
  border:1px solid var(--line);
}

/* ---------- ADMIN PANEL ---------- */
#adminPanel{
  display:none;
  animation:rise .7s var(--ease) both;
}
.card-head .tag{
  margin-left:auto;
  padding:5px 11px;
  border-radius:999px;
  font-size:10.5px;
  font-weight:700;
  letter-spacing:1px;
  color:#fde68a;
  background:rgba(251,191,36,.12);
  border:1px solid rgba(251,191,36,.38);
}
label{
  display:block;
  margin:18px 0 8px;
  font-size:12px;
  font-weight:600;
  letter-spacing:.2px;
  color:var(--text-dim);
}
input{
  width:100%;
  padding:13px 15px;
  border-radius:var(--radius-sm);
  font-family:var(--font-body);
  font-size:14px;
  color:var(--text);
  background:var(--field);
  border:1px solid var(--line);
  transition:border-color .2s ease,background .2s ease,box-shadow .2s ease;
}
input::placeholder{color:var(--text-faint)}
input:hover{border-color:var(--line-strong)}
input:focus{
  outline:none;
  border-color:rgba(139,92,246,.85);
  background:rgba(139,92,246,.08);
  box-shadow:0 0 0 4px rgba(139,92,246,.2);
}
input[type="number"]{
  font-family:var(--font-mono);
  font-weight:600;
  -moz-appearance:textfield;
}
input[type="number"]::-webkit-outer-spin-button,
input[type="number"]::-webkit-inner-spin-button{-webkit-appearance:none;margin:0}
#content{font-family:var(--font-mono);font-weight:600;letter-spacing:.3px}

/* segmented tabs */
.tab-bar{
  display:flex;
  gap:4px;
  margin:0 0 14px;
  padding:4px;
  border-radius:14px;
  background:rgba(0,0,0,.3);
  border:1px solid var(--line);
}
.tab-bar button{
  flex:1;
  margin:0;
  padding:11px 8px;
  border-radius:10px;
  font-size:12px;
  letter-spacing:.6px;
  color:var(--text-faint);
  background:transparent;
  box-shadow:none;
}
.tab-bar button::after{display:none}
.tab-bar button:hover{
  transform:none;
  color:var(--text);
  background:rgba(255,255,255,.06);
  box-shadow:none;
}
.tab-bar button.active,
.tab-bar button.active:hover{
  color:#fff;
  background:var(--grad-primary);
  box-shadow:0 10px 22px -10px rgba(139,92,246,.95),inset 0 1px 0 rgba(255,255,255,.3);
}

/* time inputs */
.time-grid{
  display:grid;
  grid-template-columns:repeat(3,1fr);
  gap:8px;
}
.unit{position:relative}
.unit input{
  padding:20px 8px 9px;
  text-align:center;
  font-size:17px;
}
.unit span{
  position:absolute;
  left:0;
  right:0;
  top:7px;
  text-align:center;
  font-size:10px;
  font-weight:600;
  letter-spacing:.5px;
  color:var(--text-faint);
  pointer-events:none;
}
.unit:focus-within span{color:#c4b5fd}

/* permanent switch */
.permanent-box{
  position:relative;
  display:flex;
  align-items:center;
  gap:14px;
  margin-top:12px;
  padding:14px 16px;
  border-radius:var(--radius-md);
  cursor:pointer;
  user-select:none;
  -webkit-user-select:none;
  background:linear-gradient(120deg,rgba(251,113,133,.11),rgba(251,191,36,.06));
  border:1px solid rgba(251,113,133,.32);
  transition:border-color .2s ease,background .2s ease;
}
.permanent-box:hover{border-color:rgba(251,113,133,.62)}
.permanent-box input[type="checkbox"]{
  position:absolute;
  width:1px;
  height:1px;
  padding:0;
  border:0;
  opacity:0;
  pointer-events:none;
}
.permanent-box .switch{
  position:relative;
  flex:0 0 auto;
  width:46px;
  height:26px;
  border-radius:999px;
  background:rgba(255,255,255,.12);
  border:1px solid var(--line-strong);
  transition:background .25s ease,box-shadow .25s ease,border-color .25s ease;
}
.permanent-box .switch::after{
  content:'';
  position:absolute;
  top:2px;
  left:2px;
  width:20px;
  height:20px;
  border-radius:50%;
  background:#fff;
  box-shadow:0 2px 8px rgba(0,0,0,.45);
  transition:transform .3s var(--ease);
}
.permanent-box input:checked + .switch{
  background:var(--grad-warm);
  border-color:transparent;
  box-shadow:0 0 24px -4px rgba(251,113,133,.9);
}
.permanent-box input:checked + .switch::after{transform:translateX(20px)}
.perm-text{display:flex;flex-direction:column;gap:1px}
.perm-text b{font-size:13px;font-weight:700;color:#ffc0ca}
.perm-text small{font-size:11.5px;color:var(--text-faint)}

/* device limit */
.device-box{
  margin-top:14px;
  padding:15px;
  border-radius:var(--radius-md);
  background:linear-gradient(140deg,rgba(99,102,241,.13),rgba(139,92,246,.05));
  border:1px solid rgba(139,92,246,.32);
}
.device-box label{margin:0 0 10px;color:#d4ceff}
.device-radio{display:flex;gap:8px}
.device-radio button{
  flex:1;
  margin:0;
  padding:12px 8px;
  border-radius:10px;
  font-size:12px;
  letter-spacing:.6px;
  color:var(--text-faint);
  background:rgba(0,0,0,.3);
  border:1px solid var(--line);
  box-shadow:none;
}
.device-radio button::after{display:none}
.device-radio button:hover{
  transform:none;
  color:var(--text);
  background:rgba(255,255,255,.07);
  box-shadow:none;
}
.device-radio button.active,
.device-radio button.active:hover{
  color:#fff;
  background:rgba(139,92,246,.3);
  border-color:rgba(167,139,250,.95);
  box-shadow:0 0 0 3px rgba(139,92,246,.2);
}
#devCustomInput,
#bDevCustomInput,
#bpDevCustomInput{margin-top:10px}

/* preset grid */
.quick-grid{
  display:grid;
  grid-template-columns:repeat(2,1fr);
  gap:10px;
  margin-top:8px;
}
.quick-grid button{
  margin:0;
  padding:17px 10px;
  display:flex;
  flex-direction:column;
  align-items:center;
  gap:4px;
  color:var(--text);
  background:
    linear-gradient(160deg,rgba(255,255,255,.08),rgba(255,255,255,.02)),
    var(--ink-800);
  background-size:100% 100%;
  border:1px solid var(--line);
  box-shadow:0 16px 28px -20px rgba(0,0,0,.95),inset 0 1px 0 rgba(255,255,255,.08);
}
.quick-grid button b{
  font-family:var(--font-display);
  font-size:24px;
  font-weight:800;
  line-height:1.1;
  background:var(--grad-success);
  -webkit-background-clip:text;
  background-clip:text;
  color:transparent;
}
.quick-grid button span{
  font-family:var(--font-body);
  font-size:11px;
  font-weight:500;
  letter-spacing:0;
  color:var(--text-faint);
}
.quick-grid button.wide{grid-column:span 2}
.quick-grid button:hover{
  transform:translateY(-3px);
  background-position:0 0;
  border-color:rgba(52,211,153,.6);
  box-shadow:0 22px 38px -18px rgba(16,185,129,.75),inset 0 1px 0 rgba(255,255,255,.12);
}
.picked{
  margin-top:10px;
  text-align:center;
  font-size:12px;
  font-weight:600;
  color:var(--emerald);
  min-height:18px;
}

/* divider */
.section-title{
  display:flex;
  align-items:center;
  gap:14px;
  margin:34px 0 2px;
  font-family:var(--font-display);
  font-size:13px;
  font-weight:700;
  letter-spacing:1.6px;
  text-transform:uppercase;
  color:var(--text-dim);
}
.section-title::before,
.section-title::after{
  content:'';
  flex:1;
  height:1px;
  background:linear-gradient(90deg,transparent,var(--line-strong),transparent);
}

/* toast */
#msg{
  position:fixed;
  left:50%;
  top:18px;
  z-index:100;
  display:none;
  width:max-content;
  max-width:min(92vw,460px);
  padding:13px 20px;
  border-radius:16px;
  text-align:center;
  font-size:13px;
  font-weight:600;
  backdrop-filter:blur(16px) saturate(160%);
  -webkit-backdrop-filter:blur(16px) saturate(160%);
  box-shadow:0 24px 54px -18px rgba(0,0,0,.85);
  animation:toast-in .4s var(--ease) both;
}
#msg.ok{
  color:#a7f3d0;
  background:rgba(6,78,59,.72);
  border:1px solid rgba(52,211,153,.55);
}
#msg.err{
  color:#fecdd3;
  background:rgba(136,19,55,.72);
  border:1px solid rgba(251,113,133,.55);
}

/* result */
.result-box{
  display:none;
  margin-top:20px;
  padding:18px;
  border-radius:var(--radius-lg);
  background:linear-gradient(150deg,rgba(52,211,153,.13),rgba(34,211,238,.05));
  border:1px solid rgba(52,211,153,.42);
  box-shadow:0 0 46px -14px rgba(52,211,153,.6);
  animation:pop-in .55s var(--ease) both;
}
.result-box h3{
  margin-bottom:12px;
  font-family:var(--font-display);
  font-size:15px;
  font-weight:700;
  color:var(--emerald);
}
.result-key{
  padding:14px;
  margin-bottom:10px;
  border-radius:12px;
  text-align:center;
  font-family:var(--font-mono);
  font-size:13.5px;
  font-weight:600;
  color:#d1fae5;
  word-break:break-all;
  background:rgba(0,0,0,.36);
  border:1px dashed rgba(52,211,153,.5);
}
.result-keys-list{
  max-height:220px;
  overflow-y:auto;
  margin-bottom:10px;
  padding:12px;
  border-radius:12px;
  font-family:var(--font-mono);
  font-size:11.5px;
  line-height:1.7;
  color:#ddd6fe;
  white-space:pre-line;
  word-break:break-all;
  background:rgba(0,0,0,.36);
  border:1px solid var(--line);
}

/* keys table */
.table-scroll{
  margin-top:24px;
  padding:6px 10px 10px;
  overflow-x:auto;
  border-radius:var(--radius-md);
  background:rgba(0,0,0,.24);
  border:1px solid var(--line);
}
table{
  width:100%;
  min-width:540px;
  border-collapse:separate;
  border-spacing:0 6px;
  font-size:12.5px;
}
th{
  padding:9px 10px;
  text-align:left;
  font-size:10.5px;
  font-weight:700;
  letter-spacing:1.1px;
  text-transform:uppercase;
  color:var(--text-faint);
}
td{
  padding:11px 10px;
  text-align:left;
  vertical-align:middle;
  background:rgba(255,255,255,.04);
  transition:background .2s ease;
}
tbody tr:hover td{background:rgba(255,255,255,.08)}
td:first-child{border-radius:11px 0 0 11px}
td:last-child{border-radius:0 11px 11px 0;text-align:right}
td.k{
  font-family:var(--font-mono);
  font-size:11.5px;
  font-weight:600;
  color:#ddd6fe;
  word-break:break-all;
}
td.r{
  font-family:var(--font-mono);
  font-size:11.5px;
  font-weight:600;
  color:var(--emerald);
}
td.dev{
  font-family:var(--font-mono);
  font-size:11.5px;
  font-weight:600;
  color:#c4b5fd;
}
#tbl td[colspan]{
  padding:28px 10px;
  text-align:center;
  border-radius:11px;
  color:var(--text-faint) !important;
}
.del{
  width:auto;
  margin:0;
  padding:7px 12px;
  border-radius:9px;
  font-size:11px;
  letter-spacing:0;
  color:var(--rose);
  background:rgba(251,113,133,.12);
  border:1px solid rgba(251,113,133,.36);
  box-shadow:none;
}
.del::after{display:none}
.del:hover{
  transform:none;
  color:#fff;
  background:var(--grad-danger);
  box-shadow:0 10px 22px -10px rgba(244,63,94,.9);
}

/* ---------- HOW IT WORKS ---------- */
.how{
  margin-top:40px;
  animation:rise .8s var(--ease) .26s both;
}
.how-title{
  margin-bottom:16px;
  text-align:center;
  font-family:var(--font-display);
  font-size:13px;
  font-weight:700;
  letter-spacing:1.6px;
  text-transform:uppercase;
  color:var(--text-faint);
}
.how-grid{
  display:grid;
  grid-template-columns:minmax(0,1fr);
  gap:12px;
  max-width:560px;
  margin:0 auto;
}
.how-item{
  display:flex;
  align-items:flex-start;
  gap:16px;
  padding:18px;
  border-radius:var(--radius-lg);
  background:var(--glass);
  border:1px solid var(--line);
  backdrop-filter:blur(16px);
  -webkit-backdrop-filter:blur(16px);
}
.how-num{
  flex:0 0 auto;
  width:38px;
  height:38px;
  border-radius:12px;
  display:grid;
  place-items:center;
  font-family:var(--font-display);
  font-size:16px;
  font-weight:800;
  color:#fff;
  background:var(--grad-primary);
  box-shadow:0 12px 24px -10px rgba(139,92,246,.85),inset 0 1px 0 rgba(255,255,255,.3);
}
.how-item:nth-child(2) .how-num{background:var(--grad-warm);box-shadow:0 12px 24px -10px rgba(251,113,133,.85),inset 0 1px 0 rgba(255,255,255,.3)}
.how-item:nth-child(3) .how-num{background:var(--grad-success);color:#032a22;box-shadow:0 12px 24px -10px rgba(16,185,129,.85),inset 0 1px 0 rgba(255,255,255,.35)}
.how-item h4{
  margin-bottom:3px;
  font-family:var(--font-display);
  font-size:15.5px;
  font-weight:700;
  color:var(--text);
}
.how-item p{
  font-size:12.5px;
  color:var(--text-faint);
}

/* ---------- RESPONSIVE ---------- */
@media (max-width:420px){
  .card{padding:19px;border-radius:22px}
  .card-icon{width:42px;height:42px;border-radius:13px}
  .card h2{font-size:17px}
  .ticket-main{padding:18px 12px 18px 20px}
  #durationMenu button b{font-size:30px}
  .topbar{padding:14px 16px 0}
}
`;


// ============================================
// 🌐 ĐA NGÔN NGỮ (14 ngôn ngữ phổ biến) + HƯỚNG DẪN + CHỐNG XEM LOG
// ============================================
const LANG_LIST = [["vi", "Tiếng Việt"], ["en", "English"], ["zh", "中文"], ["es", "Español"], ["hi", "हिन्दी"], ["ar", "العربية"], ["pt", "Português"], ["ru", "Русский"], ["id", "Bahasa Indonesia"], ["ja", "日本語"], ["fr", "Français"], ["ko", "한국어"], ["th", "ไทย"], ["de", "Deutsch"]];
const I18N_ALL = {
  "vi": {"tagline": "Cổng lấy key cao cấp — nhanh, an toàn, minh bạch", "ticketMeta": "1 thiết bị · Hiệu lực 3 – 24 giờ", "perk1": "1 thiết bị cho mỗi key", "perk2": "Hiệu lực 3 – 24 giờ", "perk3": "Nhận key sau khi xong nhiệm vụ", "getKeyTitle": "Get Key", "getKeySub": "Chọn thời lượng và hoàn thành nhiệm vụ để nhận key", "loading": "Đang tải...", "steps": "bước", "maintenanceShort": "Bảo trì", "noDurations": "Hiện chưa có mốc thời gian nào khả dụng", "starting": "Đang bắt đầu...", "opening": "Đang mở liên kết...", "error": "Lỗi", "ipLimitReached": "IP của bạn đã đạt giới hạn {limit} lần lấy key", "durationMaintenance": "Mốc thời gian này đang bảo trì", "durationUnavailable": "Mốc thời gian này hiện không khả dụng", "siteUnavailable": "Website đang bảo trì / tạm ngưng", "ipLimitNote": "Bạn đã dùng {used}/{limit} lượt lấy key", "ipLimitAdmin": "Tài khoản admin — không giới hạn lượt lấy key", "howBtn": "Hướng dẫn", "guideTitle": "Cách lấy key", "g1": "Chọn thời lượng key (3–24 giờ) ở mục Get Key.", "g2": "Bấm Bắt đầu rồi hoàn thành lần lượt từng bước vượt link. Chờ đủ thời gian đếm ngược ở mỗi trang.", "g3": "Sau mỗi link rút gọn bạn sẽ quay lại trang nhiệm vụ — bấm Tiếp tục để sang bước kế.", "g4": "Xong tất cả các bước để hiện key, rồi bấm COPY KEY.", "g5": "Dán key vào ứng dụng. Mỗi key chỉ dùng cho 1 thiết bị.", "guideWarn": "Không dùng VPN, công cụ bypass hoặc đổi mạng giữa chừng, nếu không IP sẽ bị chặn.", "guideDontShow": "Không hiện lại trong 2 ngày", "guideClose": "Đóng", "guideOk": "Đã hiểu", "taskTitle": "ĐANG XỬ LÝ NHIỆM VỤ", "taskSub": "Hoàn thành lần lượt từng bước bên dưới", "home": "← Trang chủ", "duration": "Thời lượng", "device": "thiết bị", "step": "Bước", "continueStep": "TIẾP TỤC BƯỚC {n} →", "copyKey": "COPY KEY", "copied": "✓ ĐÃ COPY!", "expire": "Hết hạn", "completed": "Đã xong {a}/{b}", "netErr": "Lỗi mạng", "invalidTask": "Nhiệm vụ không hợp lệ", "noToken": "Thiếu token", "backHome": "← VỀ TRANG CHỦ", "maintTitle": "Đang bảo trì", "offTitle": "Website tạm ngưng", "devtools": "Trang này không cho phép công cụ nhà phát triển."},
  "en": {"tagline": "Premium key gateway — fast, safe, transparent", "ticketMeta": "1 device · Valid 3 – 24 hours", "perk1": "1 device per key", "perk2": "Valid 3 – 24 hours", "perk3": "Key revealed after finishing tasks", "getKeyTitle": "Get Key", "getKeySub": "Pick a duration and finish the tasks to get your key", "loading": "Loading...", "steps": "steps", "maintenanceShort": "Maintenance", "noDurations": "No durations available right now", "starting": "Starting...", "opening": "Opening link...", "error": "Error", "ipLimitReached": "Your IP already reached the {limit}-key limit", "durationMaintenance": "This duration is under maintenance", "durationUnavailable": "This duration is not available right now", "siteUnavailable": "Site is under maintenance / offline", "ipLimitNote": "You have used {used}/{limit} key requests", "ipLimitAdmin": "Admin account — unlimited key requests", "howBtn": "How to use", "guideTitle": "How to get a key", "g1": "Pick a key duration (3–24 hours) in the Get Key section.", "g2": "Tap Start, then finish each link step in order. Wait the full countdown on every page.", "g3": "After each short link you return to the task page — tap Continue for the next step.", "g4": "Finish all steps to reveal your key, then tap COPY KEY.", "g5": "Paste the key into the app. One key works on 1 device only.", "guideWarn": "Do not use a VPN, bypass tools or switch network mid-task, or your IP will be blocked.", "guideDontShow": "Do not show again for 2 days", "guideClose": "Close", "guideOk": "Got it", "taskTitle": "PROCESSING TASK", "taskSub": "Complete each step below in order", "home": "← Home", "duration": "Duration", "device": "device", "step": "Step", "continueStep": "CONTINUE STEP {n} →", "copyKey": "COPY KEY", "copied": "✓ COPIED!", "expire": "Expires", "completed": "Completed {a}/{b}", "netErr": "Network error", "invalidTask": "Invalid task", "noToken": "Missing token", "backHome": "← BACK TO HOME", "maintTitle": "Under maintenance", "offTitle": "Website paused", "devtools": "Developer tools are not allowed on this page."},
  "zh": {"tagline": "高级密钥门户——快速、安全、透明", "ticketMeta": "1 台设备 · 有效期 3 – 24 小时", "perk1": "每个密钥限 1 台设备", "perk2": "有效期 3 – 24 小时", "perk3": "完成任务后获取密钥", "getKeyTitle": "获取密钥", "getKeySub": "选择时长并完成任务以获取密钥", "loading": "加载中...", "steps": "步", "maintenanceShort": "维护中", "noDurations": "暂无可用时长", "starting": "正在开始...", "opening": "正在打开链接...", "error": "错误", "ipLimitReached": "您的 IP 已达到 {limit} 次取密钥上限", "durationMaintenance": "此时长正在维护", "durationUnavailable": "此时长暂不可用", "siteUnavailable": "网站维护中 / 已暂停", "ipLimitNote": "您已使用 {used}/{limit} 次取密钥机会", "ipLimitAdmin": "管理员账户——取密钥次数不限", "howBtn": "使用说明", "guideTitle": "如何获取密钥", "g1": "在“获取密钥”区域选择密钥时长（3–24 小时）。", "g2": "点击开始，然后按顺序完成每个链接步骤。每个页面都要等待完整倒计时。", "g3": "每个短链接结束后会返回任务页面——点击继续进入下一步。", "g4": "完成所有步骤后显示密钥，然后点击复制密钥。", "g5": "将密钥粘贴到应用中。每个密钥仅限 1 台设备使用。", "guideWarn": "请勿使用 VPN、绕过工具或在任务中途切换网络，否则 IP 将被封禁。", "guideDontShow": "2 天内不再显示", "guideClose": "关闭", "guideOk": "知道了", "taskTitle": "正在处理任务", "taskSub": "请按顺序完成下面的每一步", "home": "← 首页", "duration": "时长", "device": "台设备", "step": "步骤", "continueStep": "继续第 {n} 步 →", "copyKey": "复制密钥", "copied": "✓ 已复制！", "expire": "到期时间", "completed": "已完成 {a}/{b}", "netErr": "网络错误", "invalidTask": "无效任务", "noToken": "缺少令牌", "backHome": "← 返回首页", "maintTitle": "维护中", "offTitle": "网站已暂停", "devtools": "此页面不允许使用开发者工具。"},
  "es": {"tagline": "Portal de claves premium: rápido, seguro y transparente", "ticketMeta": "1 dispositivo · Válido 3 – 24 horas", "perk1": "1 dispositivo por clave", "perk2": "Válido 3 – 24 horas", "perk3": "La clave se muestra al terminar las tareas", "getKeyTitle": "Obtener clave", "getKeySub": "Elige una duración y completa las tareas para obtener tu clave", "loading": "Cargando...", "steps": "pasos", "maintenanceShort": "Mantenimiento", "noDurations": "No hay duraciones disponibles ahora", "starting": "Iniciando...", "opening": "Abriendo enlace...", "error": "Error", "ipLimitReached": "Tu IP ya alcanzó el límite de {limit} claves", "durationMaintenance": "Esta duración está en mantenimiento", "durationUnavailable": "Esta duración no está disponible ahora", "siteUnavailable": "El sitio está en mantenimiento / fuera de línea", "ipLimitNote": "Has usado {used}/{limit} solicitudes de clave", "ipLimitAdmin": "Cuenta de administrador: solicitudes ilimitadas", "howBtn": "Cómo usar", "guideTitle": "Cómo obtener una clave", "g1": "Elige la duración de la clave (3–24 horas) en la sección Obtener clave.", "g2": "Pulsa Iniciar y completa cada paso de enlace en orden. Espera toda la cuenta atrás en cada página.", "g3": "Tras cada enlace corto volverás a la página de tareas: pulsa Continuar para el siguiente paso.", "g4": "Completa todos los pasos para ver tu clave y pulsa COPIAR CLAVE.", "g5": "Pega la clave en la aplicación. Cada clave funciona en 1 solo dispositivo.", "guideWarn": "No uses VPN ni herramientas de bypass ni cambies de red durante la tarea, o bloquearemos tu IP.", "guideDontShow": "No mostrar de nuevo durante 2 días", "guideClose": "Cerrar", "guideOk": "Entendido", "taskTitle": "PROCESANDO TAREA", "taskSub": "Completa cada paso de abajo en orden", "home": "← Inicio", "duration": "Duración", "device": "dispositivo", "step": "Paso", "continueStep": "CONTINUAR PASO {n} →", "copyKey": "COPIAR CLAVE", "copied": "✓ ¡COPIADO!", "expire": "Caduca", "completed": "Completado {a}/{b}", "netErr": "Error de red", "invalidTask": "Tarea no válida", "noToken": "Falta el token", "backHome": "← VOLVER AL INICIO", "maintTitle": "En mantenimiento", "offTitle": "Sitio web en pausa", "devtools": "Las herramientas de desarrollo no están permitidas en esta página."},
  "hi": {"tagline": "प्रीमियम की गेटवे — तेज़, सुरक्षित, पारदर्शी", "ticketMeta": "1 डिवाइस · 3 – 24 घंटे मान्य", "perk1": "हर की पर 1 डिवाइस", "perk2": "3 – 24 घंटे मान्य", "perk3": "टास्क पूरे होने के बाद की मिलेगी", "getKeyTitle": "की प्राप्त करें", "getKeySub": "अवधि चुनें और की पाने के लिए टास्क पूरे करें", "loading": "लोड हो रहा है...", "steps": "चरण", "maintenanceShort": "मेंटेनेंस", "noDurations": "अभी कोई अवधि उपलब्ध नहीं है", "starting": "शुरू हो रहा है...", "opening": "लिंक खुल रहा है...", "error": "त्रुटि", "ipLimitReached": "आपका IP {limit} की की सीमा तक पहुँच चुका है", "durationMaintenance": "यह अवधि मेंटेनेंस में है", "durationUnavailable": "यह अवधि अभी उपलब्ध नहीं है", "siteUnavailable": "साइट मेंटेनेंस में है / बंद है", "ipLimitNote": "आपने {used}/{limit} की अनुरोध उपयोग किए हैं", "ipLimitAdmin": "एडमिन खाता — की अनुरोध असीमित", "howBtn": "उपयोग कैसे करें", "guideTitle": "की कैसे पाएँ", "g1": "की प्राप्त करें सेक्शन में की की अवधि (3–24 घंटे) चुनें।", "g2": "शुरू करें दबाएँ, फिर हर लिंक चरण क्रम से पूरा करें। हर पेज पर पूरा काउंटडाउन रुकें।", "g3": "हर शॉर्ट लिंक के बाद आप टास्क पेज पर लौटेंगे — अगले चरण के लिए जारी रखें दबाएँ।", "g4": "सभी चरण पूरे करने पर की दिखेगी, फिर की कॉपी करें दबाएँ।", "g5": "की को ऐप में पेस्ट करें। एक की केवल 1 डिवाइस पर चलती है।", "guideWarn": "VPN या बायपास टूल का उपयोग न करें और टास्क के बीच नेटवर्क न बदलें, वरना आपका IP ब्लॉक हो जाएगा।", "guideDontShow": "2 दिन तक दोबारा न दिखाएँ", "guideClose": "बंद करें", "guideOk": "समझ गया", "taskTitle": "टास्क प्रोसेस हो रहा है", "taskSub": "नीचे दिए हर चरण को क्रम से पूरा करें", "home": "← होम", "duration": "अवधि", "device": "डिवाइस", "step": "चरण", "continueStep": "चरण {n} जारी रखें →", "copyKey": "की कॉपी करें", "copied": "✓ कॉपी हो गया!", "expire": "समाप्ति", "completed": "{a}/{b} पूरे", "netErr": "नेटवर्क त्रुटि", "invalidTask": "अमान्य टास्क", "noToken": "टोकन नहीं मिला", "backHome": "← होम पर जाएँ", "maintTitle": "मेंटेनेंस जारी है", "offTitle": "वेबसाइट अस्थायी रूप से बंद", "devtools": "इस पेज पर डेवलपर टूल की अनुमति नहीं है।"},
  "ar": {"tagline": "بوابة مفاتيح مميزة — سريعة وآمنة وشفافة", "ticketMeta": "جهاز واحد · صالح من 3 إلى 24 ساعة", "perk1": "جهاز واحد لكل مفتاح", "perk2": "صالح من 3 إلى 24 ساعة", "perk3": "يظهر المفتاح بعد إنهاء المهام", "getKeyTitle": "احصل على مفتاح", "getKeySub": "اختر المدة وأكمل المهام للحصول على مفتاحك", "loading": "جارٍ التحميل...", "steps": "خطوات", "maintenanceShort": "صيانة", "noDurations": "لا توجد مدد متاحة حاليًا", "starting": "جارٍ البدء...", "opening": "جارٍ فتح الرابط...", "error": "خطأ", "ipLimitReached": "وصل عنوان IP الخاص بك إلى حد {limit} مفاتيح", "durationMaintenance": "هذه المدة قيد الصيانة", "durationUnavailable": "هذه المدة غير متاحة حاليًا", "siteUnavailable": "الموقع قيد الصيانة / متوقف", "ipLimitNote": "استخدمت {used}/{limit} من طلبات المفاتيح", "ipLimitAdmin": "حساب المشرف — طلبات مفاتيح غير محدودة", "howBtn": "طريقة الاستخدام", "guideTitle": "كيف تحصل على مفتاح", "g1": "اختر مدة المفتاح (3–24 ساعة) من قسم الحصول على مفتاح.", "g2": "اضغط ابدأ ثم أكمل كل خطوة رابط بالترتيب. انتظر العد التنازلي كاملًا في كل صفحة.", "g3": "بعد كل رابط مختصر ستعود إلى صفحة المهام — اضغط متابعة للخطوة التالية.", "g4": "أكمل جميع الخطوات ليظهر المفتاح ثم اضغط نسخ المفتاح.", "g5": "الصق المفتاح في التطبيق. كل مفتاح يعمل على جهاز واحد فقط.", "guideWarn": "لا تستخدم VPN أو أدوات التجاوز ولا تغيّر الشبكة أثناء المهمة وإلا سيتم حظر عنوان IP الخاص بك.", "guideDontShow": "عدم الإظهار مجددًا لمدة يومين", "guideClose": "إغلاق", "guideOk": "فهمت", "taskTitle": "جارٍ معالجة المهمة", "taskSub": "أكمل كل خطوة أدناه بالترتيب", "home": "→ الرئيسية", "duration": "المدة", "device": "جهاز", "step": "الخطوة", "continueStep": "متابعة الخطوة {n} ←", "copyKey": "نسخ المفتاح", "copied": "✓ تم النسخ!", "expire": "ينتهي في", "completed": "اكتمل {a}/{b}", "netErr": "خطأ في الشبكة", "invalidTask": "مهمة غير صالحة", "noToken": "الرمز مفقود", "backHome": "→ العودة إلى الرئيسية", "maintTitle": "قيد الصيانة", "offTitle": "الموقع متوقف مؤقتًا", "devtools": "أدوات المطور غير مسموح بها في هذه الصفحة."},
  "pt": {"tagline": "Portal de chaves premium — rápido, seguro e transparente", "ticketMeta": "1 dispositivo · Válida por 3 – 24 horas", "perk1": "1 dispositivo por chave", "perk2": "Válida por 3 – 24 horas", "perk3": "A chave aparece após concluir as tarefas", "getKeyTitle": "Obter chave", "getKeySub": "Escolha a duração e conclua as tarefas para obter sua chave", "loading": "Carregando...", "steps": "etapas", "maintenanceShort": "Manutenção", "noDurations": "Nenhuma duração disponível no momento", "starting": "Iniciando...", "opening": "Abrindo link...", "error": "Erro", "ipLimitReached": "Seu IP já atingiu o limite de {limit} chaves", "durationMaintenance": "Esta duração está em manutenção", "durationUnavailable": "Esta duração não está disponível agora", "siteUnavailable": "Site em manutenção / fora do ar", "ipLimitNote": "Você usou {used}/{limit} solicitações de chave", "ipLimitAdmin": "Conta de administrador — solicitações ilimitadas", "howBtn": "Como usar", "guideTitle": "Como obter uma chave", "g1": "Escolha a duração da chave (3–24 horas) na seção Obter chave.", "g2": "Toque em Iniciar e conclua cada etapa de link em ordem. Aguarde toda a contagem regressiva em cada página.", "g3": "Após cada link curto você volta à página de tarefas — toque em Continuar para a próxima etapa.", "g4": "Conclua todas as etapas para revelar a chave e toque em COPIAR CHAVE.", "g5": "Cole a chave no aplicativo. Cada chave funciona em apenas 1 dispositivo.", "guideWarn": "Não use VPN, ferramentas de bypass nem troque de rede durante a tarefa, ou seu IP será bloqueado.", "guideDontShow": "Não mostrar novamente por 2 dias", "guideClose": "Fechar", "guideOk": "Entendi", "taskTitle": "PROCESSANDO TAREFA", "taskSub": "Conclua cada etapa abaixo em ordem", "home": "← Início", "duration": "Duração", "device": "dispositivo", "step": "Etapa", "continueStep": "CONTINUAR ETAPA {n} →", "copyKey": "COPIAR CHAVE", "copied": "✓ COPIADO!", "expire": "Expira em", "completed": "Concluído {a}/{b}", "netErr": "Erro de rede", "invalidTask": "Tarefa inválida", "noToken": "Token ausente", "backHome": "← VOLTAR AO INÍCIO", "maintTitle": "Em manutenção", "offTitle": "Site pausado", "devtools": "Ferramentas de desenvolvedor não são permitidas nesta página."},
  "ru": {"tagline": "Премиум-портал ключей — быстро, безопасно, прозрачно", "ticketMeta": "1 устройство · Действует 3 – 24 часа", "perk1": "1 устройство на ключ", "perk2": "Действует 3 – 24 часа", "perk3": "Ключ показывается после выполнения заданий", "getKeyTitle": "Получить ключ", "getKeySub": "Выберите срок и выполните задания, чтобы получить ключ", "loading": "Загрузка...", "steps": "шагов", "maintenanceShort": "Тех. работы", "noDurations": "Сейчас нет доступных сроков", "starting": "Запуск...", "opening": "Открываем ссылку...", "error": "Ошибка", "ipLimitReached": "Ваш IP достиг лимита в {limit} ключей", "durationMaintenance": "Этот срок на техническом обслуживании", "durationUnavailable": "Этот срок сейчас недоступен", "siteUnavailable": "Сайт на техобслуживании / отключён", "ipLimitNote": "Вы использовали {used}/{limit} запросов ключа", "ipLimitAdmin": "Аккаунт администратора — запросы без ограничений", "howBtn": "Как пользоваться", "guideTitle": "Как получить ключ", "g1": "Выберите срок действия ключа (3–24 часа) в разделе «Получить ключ».", "g2": "Нажмите «Старт» и по порядку пройдите каждый шаг со ссылкой. На каждой странице дождитесь конца обратного отсчёта.", "g3": "После каждой короткой ссылки вы вернётесь на страницу заданий — нажмите «Продолжить» для следующего шага.", "g4": "Пройдите все шаги, чтобы появился ключ, и нажмите «Копировать ключ».", "g5": "Вставьте ключ в приложение. Один ключ работает только на 1 устройстве.", "guideWarn": "Не используйте VPN, средства обхода и не меняйте сеть во время задания, иначе ваш IP будет заблокирован.", "guideDontShow": "Не показывать 2 дня", "guideClose": "Закрыть", "guideOk": "Понятно", "taskTitle": "ОБРАБОТКА ЗАДАНИЯ", "taskSub": "Выполняйте шаги ниже по порядку", "home": "← Главная", "duration": "Срок", "device": "устройство", "step": "Шаг", "continueStep": "ПРОДОЛЖИТЬ ШАГ {n} →", "copyKey": "КОПИРОВАТЬ КЛЮЧ", "copied": "✓ СКОПИРОВАНО!", "expire": "Истекает", "completed": "Выполнено {a}/{b}", "netErr": "Ошибка сети", "invalidTask": "Неверное задание", "noToken": "Нет токена", "backHome": "← НА ГЛАВНУЮ", "maintTitle": "Технические работы", "offTitle": "Сайт временно отключён", "devtools": "Инструменты разработчика на этой странице запрещены."},
  "id": {"tagline": "Gerbang kunci premium — cepat, aman, transparan", "ticketMeta": "1 perangkat · Berlaku 3 – 24 jam", "perk1": "1 perangkat per kunci", "perk2": "Berlaku 3 – 24 jam", "perk3": "Kunci muncul setelah tugas selesai", "getKeyTitle": "Dapatkan Kunci", "getKeySub": "Pilih durasi dan selesaikan tugas untuk mendapatkan kunci", "loading": "Memuat...", "steps": "langkah", "maintenanceShort": "Pemeliharaan", "noDurations": "Belum ada durasi yang tersedia", "starting": "Memulai...", "opening": "Membuka tautan...", "error": "Kesalahan", "ipLimitReached": "IP Anda sudah mencapai batas {limit} kunci", "durationMaintenance": "Durasi ini sedang dalam pemeliharaan", "durationUnavailable": "Durasi ini sedang tidak tersedia", "siteUnavailable": "Situs sedang dalam pemeliharaan / offline", "ipLimitNote": "Anda telah memakai {used}/{limit} permintaan kunci", "ipLimitAdmin": "Akun admin — permintaan kunci tanpa batas", "howBtn": "Cara pakai", "guideTitle": "Cara mendapatkan kunci", "g1": "Pilih durasi kunci (3–24 jam) di bagian Dapatkan Kunci.", "g2": "Ketuk Mulai lalu selesaikan setiap langkah tautan secara berurutan. Tunggu hitung mundur penuh di tiap halaman.", "g3": "Setelah tiap tautan pendek, Anda kembali ke halaman tugas — ketuk Lanjutkan untuk langkah berikutnya.", "g4": "Selesaikan semua langkah agar kunci muncul, lalu ketuk SALIN KUNCI.", "g5": "Tempel kunci di aplikasi. Satu kunci hanya untuk 1 perangkat.", "guideWarn": "Jangan pakai VPN, alat bypass, atau ganti jaringan di tengah tugas, atau IP Anda akan diblokir.", "guideDontShow": "Jangan tampilkan lagi selama 2 hari", "guideClose": "Tutup", "guideOk": "Mengerti", "taskTitle": "MEMPROSES TUGAS", "taskSub": "Selesaikan setiap langkah di bawah secara berurutan", "home": "← Beranda", "duration": "Durasi", "device": "perangkat", "step": "Langkah", "continueStep": "LANJUTKAN LANGKAH {n} →", "copyKey": "SALIN KUNCI", "copied": "✓ TERSALIN!", "expire": "Berakhir", "completed": "Selesai {a}/{b}", "netErr": "Kesalahan jaringan", "invalidTask": "Tugas tidak valid", "noToken": "Token tidak ada", "backHome": "← KEMBALI KE BERANDA", "maintTitle": "Sedang pemeliharaan", "offTitle": "Situs dijeda", "devtools": "Alat pengembang tidak diizinkan di halaman ini."},
  "ja": {"tagline": "プレミアムキーゲートウェイ — 高速・安全・透明", "ticketMeta": "1台のデバイス · 有効期間 3〜24時間", "perk1": "キー1つにつき1台のデバイス", "perk2": "有効期間 3〜24時間", "perk3": "タスク完了後にキーを表示", "getKeyTitle": "キーを取得", "getKeySub": "期間を選んでタスクを完了するとキーを取得できます", "loading": "読み込み中...", "steps": "ステップ", "maintenanceShort": "メンテナンス", "noDurations": "現在利用できる期間はありません", "starting": "開始中...", "opening": "リンクを開いています...", "error": "エラー", "ipLimitReached": "お使いのIPはキー{limit}回の上限に達しました", "durationMaintenance": "この期間はメンテナンス中です", "durationUnavailable": "この期間は現在利用できません", "siteUnavailable": "サイトはメンテナンス中 / 停止中です", "ipLimitNote": "キー取得 {used}/{limit} 回を使用しました", "ipLimitAdmin": "管理者アカウント — キー取得は無制限", "howBtn": "使い方", "guideTitle": "キーの取得方法", "g1": "「キーを取得」で有効期間（3〜24時間）を選びます。", "g2": "開始をタップし、各リンクのステップを順番に完了します。各ページでカウントダウンが終わるまで待ってください。", "g3": "短縮リンクのあとタスクページに戻ります。「続行」をタップして次のステップへ進みます。", "g4": "すべてのステップを完了するとキーが表示されます。「キーをコピー」をタップしてください。", "g5": "キーをアプリに貼り付けます。1つのキーは1台のデバイスでのみ使えます。", "guideWarn": "VPN・バイパスツールの使用や、タスク中のネットワーク切り替えはしないでください。IPがブロックされます。", "guideDontShow": "2日間表示しない", "guideClose": "閉じる", "guideOk": "了解", "taskTitle": "タスク処理中", "taskSub": "下のステップを順番に完了してください", "home": "← ホーム", "duration": "期間", "device": "台", "step": "ステップ", "continueStep": "ステップ{n}を続行 →", "copyKey": "キーをコピー", "copied": "✓ コピーしました！", "expire": "有効期限", "completed": "{a}/{b} 完了", "netErr": "ネットワークエラー", "invalidTask": "無効なタスクです", "noToken": "トークンがありません", "backHome": "← ホームに戻る", "maintTitle": "メンテナンス中", "offTitle": "サイト一時停止中", "devtools": "このページでは開発者ツールは使用できません。"},
  "fr": {"tagline": "Portail de clés premium — rapide, sûr, transparent", "ticketMeta": "1 appareil · Valable 3 – 24 heures", "perk1": "1 appareil par clé", "perk2": "Valable 3 – 24 heures", "perk3": "La clé s’affiche après les tâches", "getKeyTitle": "Obtenir une clé", "getKeySub": "Choisissez une durée et terminez les tâches pour obtenir votre clé", "loading": "Chargement...", "steps": "étapes", "maintenanceShort": "Maintenance", "noDurations": "Aucune durée disponible pour le moment", "starting": "Démarrage...", "opening": "Ouverture du lien...", "error": "Erreur", "ipLimitReached": "Votre IP a atteint la limite de {limit} clés", "durationMaintenance": "Cette durée est en maintenance", "durationUnavailable": "Cette durée n’est pas disponible actuellement", "siteUnavailable": "Site en maintenance / hors ligne", "ipLimitNote": "Vous avez utilisé {used}/{limit} demandes de clé", "ipLimitAdmin": "Compte admin — demandes de clé illimitées", "howBtn": "Mode d’emploi", "guideTitle": "Comment obtenir une clé", "g1": "Choisissez la durée de la clé (3–24 heures) dans la section Obtenir une clé.", "g2": "Appuyez sur Démarrer puis terminez chaque étape de lien dans l’ordre. Attendez tout le compte à rebours sur chaque page.", "g3": "Après chaque lien court, vous revenez à la page des tâches — appuyez sur Continuer pour l’étape suivante.", "g4": "Terminez toutes les étapes pour afficher la clé, puis appuyez sur COPIER LA CLÉ.", "g5": "Collez la clé dans l’application. Une clé ne fonctionne que sur 1 appareil.", "guideWarn": "N’utilisez pas de VPN ni d’outil de contournement et ne changez pas de réseau pendant la tâche, sinon votre IP sera bloquée.", "guideDontShow": "Ne plus afficher pendant 2 jours", "guideClose": "Fermer", "guideOk": "Compris", "taskTitle": "TRAITEMENT DE LA TÂCHE", "taskSub": "Terminez chaque étape ci-dessous dans l’ordre", "home": "← Accueil", "duration": "Durée", "device": "appareil", "step": "Étape", "continueStep": "CONTINUER L’ÉTAPE {n} →", "copyKey": "COPIER LA CLÉ", "copied": "✓ COPIÉ !", "expire": "Expire le", "completed": "Terminé {a}/{b}", "netErr": "Erreur réseau", "invalidTask": "Tâche invalide", "noToken": "Jeton manquant", "backHome": "← RETOUR À L’ACCUEIL", "maintTitle": "En maintenance", "offTitle": "Site suspendu", "devtools": "Les outils de développement sont interdits sur cette page."},
  "ko": {"tagline": "프리미엄 키 게이트웨이 — 빠르고 안전하며 투명하게", "ticketMeta": "기기 1대 · 유효 3 – 24시간", "perk1": "키당 기기 1대", "perk2": "유효 3 – 24시간", "perk3": "작업 완료 후 키 표시", "getKeyTitle": "키 받기", "getKeySub": "기간을 선택하고 작업을 완료하여 키를 받으세요", "loading": "불러오는 중...", "steps": "단계", "maintenanceShort": "점검 중", "noDurations": "현재 사용 가능한 기간이 없습니다", "starting": "시작 중...", "opening": "링크 여는 중...", "error": "오류", "ipLimitReached": "내 IP가 키 {limit}회 제한에 도달했습니다", "durationMaintenance": "이 기간은 점검 중입니다", "durationUnavailable": "이 기간은 현재 사용할 수 없습니다", "siteUnavailable": "사이트 점검 중 / 일시 중단", "ipLimitNote": "키 요청 {used}/{limit}회 사용했습니다", "ipLimitAdmin": "관리자 계정 — 키 요청 무제한", "howBtn": "사용 방법", "guideTitle": "키 받는 방법", "g1": "키 받기 섹션에서 키 기간(3–24시간)을 선택하세요.", "g2": "시작을 누르고 각 링크 단계를 순서대로 완료하세요. 각 페이지에서 카운트다운이 끝날 때까지 기다리세요.", "g3": "단축 링크 후 작업 페이지로 돌아옵니다. 계속을 눌러 다음 단계로 가세요.", "g4": "모든 단계를 마치면 키가 표시됩니다. 키 복사를 누르세요.", "g5": "키를 앱에 붙여넣으세요. 키 하나는 기기 1대에서만 작동합니다.", "guideWarn": "VPN, 우회 도구를 사용하거나 작업 중 네트워크를 바꾸지 마세요. IP가 차단됩니다.", "guideDontShow": "2일 동안 다시 표시하지 않기", "guideClose": "닫기", "guideOk": "확인", "taskTitle": "작업 처리 중", "taskSub": "아래 단계를 순서대로 완료하세요", "home": "← 홈", "duration": "기간", "device": "대", "step": "단계", "continueStep": "{n}단계 계속 →", "copyKey": "키 복사", "copied": "✓ 복사됨!", "expire": "만료", "completed": "{a}/{b} 완료", "netErr": "네트워크 오류", "invalidTask": "잘못된 작업", "noToken": "토큰 없음", "backHome": "← 홈으로", "maintTitle": "점검 중", "offTitle": "사이트 일시 중단", "devtools": "이 페이지에서는 개발자 도구를 사용할 수 없습니다."},
  "th": {"tagline": "ประตูรับคีย์พรีเมียม — เร็ว ปลอดภัย โปร่งใส", "ticketMeta": "1 อุปกรณ์ · ใช้ได้ 3 – 24 ชั่วโมง", "perk1": "1 อุปกรณ์ต่อ 1 คีย์", "perk2": "ใช้ได้ 3 – 24 ชั่วโมง", "perk3": "รับคีย์หลังทำภารกิจเสร็จ", "getKeyTitle": "รับคีย์", "getKeySub": "เลือกระยะเวลาและทำภารกิจให้เสร็จเพื่อรับคีย์", "loading": "กำลังโหลด...", "steps": "ขั้นตอน", "maintenanceShort": "ปิดปรับปรุง", "noDurations": "ขณะนี้ยังไม่มีระยะเวลาที่ใช้งานได้", "starting": "กำลังเริ่ม...", "opening": "กำลังเปิดลิงก์...", "error": "ข้อผิดพลาด", "ipLimitReached": "IP ของคุณถึงขีดจำกัด {limit} คีย์แล้ว", "durationMaintenance": "ระยะเวลานี้อยู่ระหว่างปรับปรุง", "durationUnavailable": "ระยะเวลานี้ยังไม่พร้อมใช้งาน", "siteUnavailable": "เว็บไซต์อยู่ระหว่างปรับปรุง / ปิดให้บริการ", "ipLimitNote": "คุณใช้สิทธิ์รับคีย์ไปแล้ว {used}/{limit} ครั้ง", "ipLimitAdmin": "บัญชีผู้ดูแล — รับคีย์ได้ไม่จำกัด", "howBtn": "วิธีใช้", "guideTitle": "วิธีรับคีย์", "g1": "เลือกระยะเวลาของคีย์ (3–24 ชั่วโมง) ในส่วนรับคีย์", "g2": "กดเริ่ม แล้วทำแต่ละขั้นตอนของลิงก์ตามลำดับ รอนับถอยหลังให้ครบในทุกหน้า", "g3": "หลังลิงก์สั้นแต่ละอัน คุณจะกลับมาที่หน้าภารกิจ — กดดำเนินการต่อเพื่อไปขั้นตอนถัดไป", "g4": "ทำทุกขั้นตอนให้เสร็จเพื่อแสดงคีย์ แล้วกดคัดลอกคีย์", "g5": "วางคีย์ในแอป หนึ่งคีย์ใช้ได้กับ 1 อุปกรณ์เท่านั้น", "guideWarn": "ห้ามใช้ VPN เครื่องมือบายพาส หรือเปลี่ยนเครือข่ายระหว่างทำภารกิจ มิฉะนั้น IP ของคุณจะถูกบล็อก", "guideDontShow": "ไม่แสดงอีกเป็นเวลา 2 วัน", "guideClose": "ปิด", "guideOk": "เข้าใจแล้ว", "taskTitle": "กำลังประมวลผลภารกิจ", "taskSub": "ทำแต่ละขั้นตอนด้านล่างตามลำดับ", "home": "← หน้าแรก", "duration": "ระยะเวลา", "device": "อุปกรณ์", "step": "ขั้นตอน", "continueStep": "ทำขั้นตอนที่ {n} ต่อ →", "copyKey": "คัดลอกคีย์", "copied": "✓ คัดลอกแล้ว!", "expire": "หมดอายุ", "completed": "เสร็จแล้ว {a}/{b}", "netErr": "เครือข่ายขัดข้อง", "invalidTask": "ภารกิจไม่ถูกต้อง", "noToken": "ไม่พบโทเคน", "backHome": "← กลับหน้าแรก", "maintTitle": "กำลังปิดปรับปรุง", "offTitle": "เว็บไซต์ปิดชั่วคราว", "devtools": "หน้านี้ไม่อนุญาตให้ใช้เครื่องมือนักพัฒนา"},
  "de": {"tagline": "Premium-Key-Portal — schnell, sicher, transparent", "ticketMeta": "1 Gerät · 3 – 24 Stunden gültig", "perk1": "1 Gerät pro Key", "perk2": "3 – 24 Stunden gültig", "perk3": "Key wird nach den Aufgaben angezeigt", "getKeyTitle": "Key holen", "getKeySub": "Wähle eine Dauer und schließe die Aufgaben ab, um deinen Key zu erhalten", "loading": "Lädt...", "steps": "Schritte", "maintenanceShort": "Wartung", "noDurations": "Derzeit keine Laufzeiten verfügbar", "starting": "Startet...", "opening": "Link wird geöffnet...", "error": "Fehler", "ipLimitReached": "Deine IP hat das Limit von {limit} Keys erreicht", "durationMaintenance": "Diese Laufzeit ist in Wartung", "durationUnavailable": "Diese Laufzeit ist derzeit nicht verfügbar", "siteUnavailable": "Website in Wartung / offline", "ipLimitNote": "Du hast {used}/{limit} Key-Anfragen genutzt", "ipLimitAdmin": "Admin-Konto — unbegrenzte Key-Anfragen", "howBtn": "Anleitung", "guideTitle": "So erhältst du einen Key", "g1": "Wähle die Key-Dauer (3–24 Stunden) im Bereich Key holen.", "g2": "Tippe auf Start und schließe jeden Link-Schritt der Reihe nach ab. Warte auf jeder Seite den ganzen Countdown ab.", "g3": "Nach jedem Kurzlink kehrst du zur Aufgabenseite zurück — tippe auf Weiter für den nächsten Schritt.", "g4": "Schließe alle Schritte ab, damit der Key erscheint, und tippe auf KEY KOPIEREN.", "g5": "Füge den Key in die App ein. Ein Key funktioniert nur auf 1 Gerät.", "guideWarn": "Nutze kein VPN, keine Bypass-Tools und wechsle während der Aufgabe nicht das Netzwerk, sonst wird deine IP gesperrt.", "guideDontShow": "2 Tage lang nicht mehr anzeigen", "guideClose": "Schließen", "guideOk": "Verstanden", "taskTitle": "AUFGABE WIRD VERARBEITET", "taskSub": "Schließe jeden Schritt unten der Reihe nach ab", "home": "← Startseite", "duration": "Dauer", "device": "Gerät", "step": "Schritt", "continueStep": "SCHRITT {n} FORTSETZEN →", "copyKey": "KEY KOPIEREN", "copied": "✓ KOPIERT!", "expire": "Läuft ab", "completed": "{a}/{b} abgeschlossen", "netErr": "Netzwerkfehler", "invalidTask": "Ungültige Aufgabe", "noToken": "Token fehlt", "backHome": "← ZUR STARTSEITE", "maintTitle": "Wartungsarbeiten", "offTitle": "Website pausiert", "devtools": "Entwicklertools sind auf dieser Seite nicht erlaubt."}
};
const I18N_TASK = {
  "vi": {"maintenanceShort": "Bảo trì", "loading": "Đang tải...", "taskTitle": "ĐANG XỬ LÝ NHIỆM VỤ", "taskSub": "Hoàn thành lần lượt từng bước bên dưới", "home": "← Trang chủ", "duration": "Thời lượng", "device": "thiết bị", "step": "Bước", "continueStep": "TIẾP TỤC BƯỚC {n} →", "copyKey": "COPY KEY", "copied": "✓ ĐÃ COPY!", "expire": "Hết hạn", "completed": "Đã xong {a}/{b}", "netErr": "Lỗi mạng", "invalidTask": "Nhiệm vụ không hợp lệ", "noToken": "Thiếu token", "backHome": "← VỀ TRANG CHỦ", "devtools": "Trang này không cho phép công cụ nhà phát triển.", "error": "Lỗi"},
  "en": {"maintenanceShort": "Maintenance", "loading": "Loading...", "taskTitle": "PROCESSING TASK", "taskSub": "Complete each step below in order", "home": "← Home", "duration": "Duration", "device": "device", "step": "Step", "continueStep": "CONTINUE STEP {n} →", "copyKey": "COPY KEY", "copied": "✓ COPIED!", "expire": "Expires", "completed": "Completed {a}/{b}", "netErr": "Network error", "invalidTask": "Invalid task", "noToken": "Missing token", "backHome": "← BACK TO HOME", "devtools": "Developer tools are not allowed on this page.", "error": "Error"},
  "zh": {"maintenanceShort": "维护中", "loading": "加载中...", "taskTitle": "正在处理任务", "taskSub": "请按顺序完成下面的每一步", "home": "← 首页", "duration": "时长", "device": "台设备", "step": "步骤", "continueStep": "继续第 {n} 步 →", "copyKey": "复制密钥", "copied": "✓ 已复制！", "expire": "到期时间", "completed": "已完成 {a}/{b}", "netErr": "网络错误", "invalidTask": "无效任务", "noToken": "缺少令牌", "backHome": "← 返回首页", "devtools": "此页面不允许使用开发者工具。", "error": "错误"},
  "es": {"maintenanceShort": "Mantenimiento", "loading": "Cargando...", "taskTitle": "PROCESANDO TAREA", "taskSub": "Completa cada paso de abajo en orden", "home": "← Inicio", "duration": "Duración", "device": "dispositivo", "step": "Paso", "continueStep": "CONTINUAR PASO {n} →", "copyKey": "COPIAR CLAVE", "copied": "✓ ¡COPIADO!", "expire": "Caduca", "completed": "Completado {a}/{b}", "netErr": "Error de red", "invalidTask": "Tarea no válida", "noToken": "Falta el token", "backHome": "← VOLVER AL INICIO", "devtools": "Las herramientas de desarrollo no están permitidas en esta página.", "error": "Error"},
  "hi": {"maintenanceShort": "मेंटेनेंस", "loading": "लोड हो रहा है...", "taskTitle": "टास्क प्रोसेस हो रहा है", "taskSub": "नीचे दिए हर चरण को क्रम से पूरा करें", "home": "← होम", "duration": "अवधि", "device": "डिवाइस", "step": "चरण", "continueStep": "चरण {n} जारी रखें →", "copyKey": "की कॉपी करें", "copied": "✓ कॉपी हो गया!", "expire": "समाप्ति", "completed": "{a}/{b} पूरे", "netErr": "नेटवर्क त्रुटि", "invalidTask": "अमान्य टास्क", "noToken": "टोकन नहीं मिला", "backHome": "← होम पर जाएँ", "devtools": "इस पेज पर डेवलपर टूल की अनुमति नहीं है।", "error": "त्रुटि"},
  "ar": {"maintenanceShort": "صيانة", "loading": "جارٍ التحميل...", "taskTitle": "جارٍ معالجة المهمة", "taskSub": "أكمل كل خطوة أدناه بالترتيب", "home": "→ الرئيسية", "duration": "المدة", "device": "جهاز", "step": "الخطوة", "continueStep": "متابعة الخطوة {n} ←", "copyKey": "نسخ المفتاح", "copied": "✓ تم النسخ!", "expire": "ينتهي في", "completed": "اكتمل {a}/{b}", "netErr": "خطأ في الشبكة", "invalidTask": "مهمة غير صالحة", "noToken": "الرمز مفقود", "backHome": "→ العودة إلى الرئيسية", "devtools": "أدوات المطور غير مسموح بها في هذه الصفحة.", "error": "خطأ"},
  "pt": {"maintenanceShort": "Manutenção", "loading": "Carregando...", "taskTitle": "PROCESSANDO TAREFA", "taskSub": "Conclua cada etapa abaixo em ordem", "home": "← Início", "duration": "Duração", "device": "dispositivo", "step": "Etapa", "continueStep": "CONTINUAR ETAPA {n} →", "copyKey": "COPIAR CHAVE", "copied": "✓ COPIADO!", "expire": "Expira em", "completed": "Concluído {a}/{b}", "netErr": "Erro de rede", "invalidTask": "Tarefa inválida", "noToken": "Token ausente", "backHome": "← VOLTAR AO INÍCIO", "devtools": "Ferramentas de desenvolvedor não são permitidas nesta página.", "error": "Erro"},
  "ru": {"maintenanceShort": "Тех. работы", "loading": "Загрузка...", "taskTitle": "ОБРАБОТКА ЗАДАНИЯ", "taskSub": "Выполняйте шаги ниже по порядку", "home": "← Главная", "duration": "Срок", "device": "устройство", "step": "Шаг", "continueStep": "ПРОДОЛЖИТЬ ШАГ {n} →", "copyKey": "КОПИРОВАТЬ КЛЮЧ", "copied": "✓ СКОПИРОВАНО!", "expire": "Истекает", "completed": "Выполнено {a}/{b}", "netErr": "Ошибка сети", "invalidTask": "Неверное задание", "noToken": "Нет токена", "backHome": "← НА ГЛАВНУЮ", "devtools": "Инструменты разработчика на этой странице запрещены.", "error": "Ошибка"},
  "id": {"maintenanceShort": "Pemeliharaan", "loading": "Memuat...", "taskTitle": "MEMPROSES TUGAS", "taskSub": "Selesaikan setiap langkah di bawah secara berurutan", "home": "← Beranda", "duration": "Durasi", "device": "perangkat", "step": "Langkah", "continueStep": "LANJUTKAN LANGKAH {n} →", "copyKey": "SALIN KUNCI", "copied": "✓ TERSALIN!", "expire": "Berakhir", "completed": "Selesai {a}/{b}", "netErr": "Kesalahan jaringan", "invalidTask": "Tugas tidak valid", "noToken": "Token tidak ada", "backHome": "← KEMBALI KE BERANDA", "devtools": "Alat pengembang tidak diizinkan di halaman ini.", "error": "Kesalahan"},
  "ja": {"maintenanceShort": "メンテナンス", "loading": "読み込み中...", "taskTitle": "タスク処理中", "taskSub": "下のステップを順番に完了してください", "home": "← ホーム", "duration": "期間", "device": "台", "step": "ステップ", "continueStep": "ステップ{n}を続行 →", "copyKey": "キーをコピー", "copied": "✓ コピーしました！", "expire": "有効期限", "completed": "{a}/{b} 完了", "netErr": "ネットワークエラー", "invalidTask": "無効なタスクです", "noToken": "トークンがありません", "backHome": "← ホームに戻る", "devtools": "このページでは開発者ツールは使用できません。", "error": "エラー"},
  "fr": {"maintenanceShort": "Maintenance", "loading": "Chargement...", "taskTitle": "TRAITEMENT DE LA TÂCHE", "taskSub": "Terminez chaque étape ci-dessous dans l’ordre", "home": "← Accueil", "duration": "Durée", "device": "appareil", "step": "Étape", "continueStep": "CONTINUER L’ÉTAPE {n} →", "copyKey": "COPIER LA CLÉ", "copied": "✓ COPIÉ !", "expire": "Expire le", "completed": "Terminé {a}/{b}", "netErr": "Erreur réseau", "invalidTask": "Tâche invalide", "noToken": "Jeton manquant", "backHome": "← RETOUR À L’ACCUEIL", "devtools": "Les outils de développement sont interdits sur cette page.", "error": "Erreur"},
  "ko": {"maintenanceShort": "점검 중", "loading": "불러오는 중...", "taskTitle": "작업 처리 중", "taskSub": "아래 단계를 순서대로 완료하세요", "home": "← 홈", "duration": "기간", "device": "대", "step": "단계", "continueStep": "{n}단계 계속 →", "copyKey": "키 복사", "copied": "✓ 복사됨!", "expire": "만료", "completed": "{a}/{b} 완료", "netErr": "네트워크 오류", "invalidTask": "잘못된 작업", "noToken": "토큰 없음", "backHome": "← 홈으로", "devtools": "이 페이지에서는 개발자 도구를 사용할 수 없습니다.", "error": "오류"},
  "th": {"maintenanceShort": "ปิดปรับปรุง", "loading": "กำลังโหลด...", "taskTitle": "กำลังประมวลผลภารกิจ", "taskSub": "ทำแต่ละขั้นตอนด้านล่างตามลำดับ", "home": "← หน้าแรก", "duration": "ระยะเวลา", "device": "อุปกรณ์", "step": "ขั้นตอน", "continueStep": "ทำขั้นตอนที่ {n} ต่อ →", "copyKey": "คัดลอกคีย์", "copied": "✓ คัดลอกแล้ว!", "expire": "หมดอายุ", "completed": "เสร็จแล้ว {a}/{b}", "netErr": "เครือข่ายขัดข้อง", "invalidTask": "ภารกิจไม่ถูกต้อง", "noToken": "ไม่พบโทเคน", "backHome": "← กลับหน้าแรก", "devtools": "หน้านี้ไม่อนุญาตให้ใช้เครื่องมือนักพัฒนา", "error": "ข้อผิดพลาด"},
  "de": {"maintenanceShort": "Wartung", "loading": "Lädt...", "taskTitle": "AUFGABE WIRD VERARBEITET", "taskSub": "Schließe jeden Schritt unten der Reihe nach ab", "home": "← Startseite", "duration": "Dauer", "device": "Gerät", "step": "Schritt", "continueStep": "SCHRITT {n} FORTSETZEN →", "copyKey": "KEY KOPIEREN", "copied": "✓ KOPIERT!", "expire": "Läuft ab", "completed": "{a}/{b} abgeschlossen", "netErr": "Netzwerkfehler", "invalidTask": "Ungültige Aufgabe", "noToken": "Token fehlt", "backHome": "← ZUR STARTSEITE", "devtools": "Entwicklertools sind auf dieser Seite nicht erlaubt.", "error": "Fehler"}
};
const I18N_MAINT = {
  "vi": {"maintTitle": "Đang bảo trì", "offTitle": "Website tạm ngưng", "maintenanceShort": "Bảo trì"},
  "en": {"maintTitle": "Under maintenance", "offTitle": "Website paused", "maintenanceShort": "Maintenance"},
  "zh": {"maintTitle": "维护中", "offTitle": "网站已暂停", "maintenanceShort": "维护中"},
  "es": {"maintTitle": "En mantenimiento", "offTitle": "Sitio web en pausa", "maintenanceShort": "Mantenimiento"},
  "hi": {"maintTitle": "मेंटेनेंस जारी है", "offTitle": "वेबसाइट अस्थायी रूप से बंद", "maintenanceShort": "मेंटेनेंस"},
  "ar": {"maintTitle": "قيد الصيانة", "offTitle": "الموقع متوقف مؤقتًا", "maintenanceShort": "صيانة"},
  "pt": {"maintTitle": "Em manutenção", "offTitle": "Site pausado", "maintenanceShort": "Manutenção"},
  "ru": {"maintTitle": "Технические работы", "offTitle": "Сайт временно отключён", "maintenanceShort": "Тех. работы"},
  "id": {"maintTitle": "Sedang pemeliharaan", "offTitle": "Situs dijeda", "maintenanceShort": "Pemeliharaan"},
  "ja": {"maintTitle": "メンテナンス中", "offTitle": "サイト一時停止中", "maintenanceShort": "メンテナンス"},
  "fr": {"maintTitle": "En maintenance", "offTitle": "Site suspendu", "maintenanceShort": "Maintenance"},
  "ko": {"maintTitle": "점검 중", "offTitle": "사이트 일시 중단", "maintenanceShort": "점검 중"},
  "th": {"maintTitle": "กำลังปิดปรับปรุง", "offTitle": "เว็บไซต์ปิดชั่วคราว", "maintenanceShort": "ปิดปรับปรุง"},
  "de": {"maintTitle": "Wartungsarbeiten", "offTitle": "Website pausiert", "maintenanceShort": "Wartung"}
};

// Nhận diện ngôn ngữ: lưu trước đó -> ngôn ngữ trình duyệt -> English
const NS_DETECT_JS = `function nsDetectLang(){try{var s=localStorage.getItem('ns_lang');if(s&&I18N[s])return s}catch(e){}var l=navigator.languages||[navigator.language||'vi'];for(var i=0;i<l.length;i++){var p=String(l[i]).toLowerCase().slice(0,2);if(I18N[p])return p}return 'en'}`;

// Popup hướng dẫn: có ô tích "không hiện lại 2 ngày" + nút đóng
const GUIDE_CSS = `<style>
.g-ov{position:fixed;inset:0;z-index:9998;background:rgba(3,6,18,.72);-webkit-backdrop-filter:blur(4px);backdrop-filter:blur(4px);display:none;align-items:center;justify-content:center;padding:16px}
.g-box{position:relative;width:min(100%,440px);max-height:88vh;overflow:auto;background:#0f1530;border:1px solid rgba(255,255,255,.14);border-radius:18px;padding:22px 20px 18px;color:#e5e7eb;box-shadow:0 20px 60px rgba(0,0,0,.55)}
.g-box h3{margin:0 36px 12px 0;font-size:18px}
.g-x{position:absolute;top:10px;right:10px;width:34px;height:34px;border-radius:50%;border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.06);color:#fff;font-size:16px;cursor:pointer}
.g-list{margin:0 0 12px;padding-left:20px;font-size:14px;line-height:1.55}
.g-list li{margin:6px 0}
.g-warn{font-size:13px;line-height:1.5;background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.35);color:#fecaca;border-radius:10px;padding:9px 11px;margin-bottom:12px}
.g-chk{display:flex;align-items:center;gap:9px;font-size:13.5px;margin:4px 0 14px;cursor:pointer}
.g-chk input{width:18px;height:18px;accent-color:#8b5cf6;flex:none}
.g-act{display:flex;gap:10px}
.g-btn{flex:1;padding:11px;border:0;border-radius:11px;font-weight:700;font-size:14px;cursor:pointer;color:#fff;background:linear-gradient(135deg,#22d3ee,#8b5cf6)}
.g-btn.ghost{background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.16)}
[dir=rtl] .g-x{right:auto;left:10px}
[dir=rtl] .g-box h3{margin:0 0 12px 36px}
[dir=rtl] .g-list{padding-left:0;padding-right:20px}
#langSel option{color:#111;background:#fff}
html:not(.adm) body{-webkit-user-select:none;user-select:none;-webkit-touch-callout:none}
html:not(.adm) input,html:not(.adm) textarea,html:not(.adm) #keyBox{-webkit-user-select:text;user-select:text}
img{-webkit-user-drag:none}
</style>`;

const GUIDE_HTML = GUIDE_CSS + `
<div id="guideOv" class="g-ov" role="dialog" aria-modal="true" onclick="if(event.target===this)closeGuide()">
<div class="g-box">
<button class="g-x" type="button" onclick="closeGuide()" aria-label="Close">&#10005;</button>
<h3 data-i18n="guideTitle">Cách lấy key</h3>
<ol class="g-list">
<li data-i18n="g1"></li><li data-i18n="g2"></li><li data-i18n="g3"></li><li data-i18n="g4"></li><li data-i18n="g5"></li>
</ol>
<div class="g-warn" data-i18n="guideWarn"></div>
<label class="g-chk"><input type="checkbox" id="guideChk"><span data-i18n="guideDontShow">Không hiện lại trong 2 ngày</span></label>
<div class="g-act">
<button class="g-btn ghost" type="button" onclick="closeGuide()" data-i18n="guideClose">Đóng</button>
<button class="g-btn" type="button" onclick="closeGuide()" data-i18n="guideOk">Đã hiểu</button>
</div>
</div>
</div>`;

const GUIDE_JS = `
function nsHideGuide(){var o=document.getElementById('guideOv');if(o)o.style.display='none'}
function openGuide(){var o=document.getElementById('guideOv');if(!o)return;var c=document.getElementById('guideChk');if(c)c.checked=false;o.style.display='flex'}
function closeGuide(){var c=document.getElementById('guideChk');if(c&&c.checked){try{localStorage.setItem('ns_guide_until',String(Date.now()+48*3600*1000))}catch(e){}}nsHideGuide()}
document.addEventListener('keydown',function(e){if(e.key==='Escape')closeGuide()});
(function(){var u=0;try{u=Number(localStorage.getItem('ns_guide_until')||0)}catch(e){}if(Date.now()>=u){setTimeout(function(){var o=document.getElementById('guideOv');if(o&&!window.__NS_ADMIN)o.style.display='flex'},350)}})();
`;

// Chống xem log / DevTools (chỉ là lớp cản trở phía trình duyệt; chặn thật nằm ở server)
const PROTECT_JS = `
window.__NS_ADMIN=false;
function nsSetAdmin(v){window.__NS_ADMIN=!!v;try{document.documentElement.classList.toggle('adm',!!v)}catch(e){}}
(function(){
var touch=('ontouchstart' in window)||(navigator.maxTouchPoints>0);
function adm(){return window.__NS_ADMIN===true}
try{if(window.top!==window.self){window.top.location=window.self.location}}catch(e){}
document.addEventListener('contextmenu',function(e){if(!adm())e.preventDefault()});
document.addEventListener('dragstart',function(e){if(!adm())e.preventDefault()});
document.addEventListener('keydown',function(e){
 if(adm())return;
 var k=String(e.key||'').toLowerCase(),c=e.ctrlKey||e.metaKey;
 var bad=(e.key==='F12')||(c&&e.shiftKey&&(k==='i'||k==='j'||k==='c'||k==='k'))||(c&&(k==='u'||k==='s'))||(e.metaKey&&e.altKey&&(k==='i'||k==='j'||k==='u'||k==='c'));
 if(bad){e.preventDefault();e.stopPropagation()}
},true);
try{if(!adm()){var nop=function(){};['log','info','warn','error','debug','table','dir','trace'].forEach(function(m){try{console[m]=nop}catch(x){}})}}catch(e){}
var ov=null;
function lockScreen(on){
 if(on&&!ov){ov=document.createElement('div');ov.style.cssText='position:fixed;inset:0;z-index:2147483647;background:#050816;color:#e5e7eb;display:flex;align-items:center;justify-content:center;text-align:center;padding:24px;font:600 16px system-ui,sans-serif';ov.textContent=(typeof t==='function'?t('devtools'):'Developer tools are not allowed.');document.body.appendChild(ov)}
 else if(!on&&ov){ov.parentNode&&ov.parentNode.removeChild(ov);ov=null}
}
if(!touch){setInterval(function(){
 if(adm()){lockScreen(false);return}
 var open=(window.outerWidth-window.innerWidth>160)||(window.outerHeight-window.innerHeight>160);
 lockScreen(open)
},800)}
})();
`;

const MAIN_HTML = `<!DOCTYPE html>
<html lang="vi"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetSuper · Get Key</title>
${THEME_HEAD}
<style>${THEME_CSS}${MAIN_CSS}</style>
</head><body>
${THEME_BG}
<div id="msg" role="status" aria-live="polite"></div>
${GUIDE_HTML}
<script>${PROTECT_JS}${GUIDE_JS}</script>

<header class="topbar">
<a class="brand" href="/">
<span class="brand-mark">${THEME_LOGO}</span>
<span class="brand-name">ThichLenDo</span>
</a>
<span style="display:flex;gap:8px;align-items:center">
<span style="display:flex;gap:8px;align-items:center">
<span id="statusDot" class="status-dot online"><i></i>ONLINE</span>
<span id="redisBadge"></span>
<button class="pill" type="button" onclick="openGuide()" aria-label="Guide" title="Guide" style="cursor:pointer;font-weight:800">?</button>
<select id="langSel" class="pill" onchange="setLang(this.value)" aria-label="Language" style="cursor:pointer;background:transparent;color:inherit;max-width:104px"></select>
</span>
</header>

<main class="wrap">

<section class="hero">
<h1>NetSuper</h1>
<p class="tagline" data-i18n="tagline">Cổng lấy key cao cấp — nhanh, an toàn, minh bạch</p>

<div class="ticket-wrap" aria-hidden="true">
<div class="ticket">
<div class="ticket-main">
<span class="ticket-label">Access key</span>
<div class="ticket-code">NetSuper-<em>•••••••••••</em>-<em>••••••••••</em></div>
<span class="ticket-meta" data-i18n="ticketMeta">1 thiết bị · Hiệu lực 3 – 24 giờ</span>
</div>
<div class="ticket-stub">
<span>
<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="15" r="4"/><path d="M10.8 12.2 20 3M17 6l3 3M14.5 8.5l2 2"/></svg>
</span>
</div>
</div>
</div>

<ul class="perks">
<li><i></i><span data-i18n="perk1">1 thiết bị cho mỗi key</span></li>
<li><i></i><span data-i18n="perk2">Hiệu lực 3 – 24 giờ</span></li>
<li><i></i><span data-i18n="perk3">Nhận key sau khi xong nhiệm vụ</span></li>
</ul>
</section>

<div class="layout">

<div class="card get-card">
<div class="card-head">
<span class="card-icon">
<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="15" r="4"/><path d="M10.8 12.2 20 3M17 6l3 3M14.5 8.5l2 2"/></svg>
</span>
<div>
<h2 data-i18n="getKeyTitle">Get Key</h2>
<p class="card-sub" data-i18n="getKeySub">Chọn thời lượng và hoàn thành nhiệm vụ để nhận key</p>
</div>
</div>

<div class="tab-bar" id="appTabs">
<button id="tabApp-netsuper" class="active" onclick="switchApp('netsuper')">NetSuper</button>
<button id="tabApp-netsupervip" onclick="switchApp('netsupervip')">NetSuperVip</button>
</div>

<div id="appDurationBox"><p class="card-sub" data-i18n="loading">Đang tải...</p></div>
<div id="ipLimitNote" class="card-sub" style="margin-top:8px"></div>
<div id="getKeyStatus" style="display:none"></div>
</div>

<div class="card" id="adminPanel">

<div class="card-head">
<span class="card-icon warm">
<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 4 6v6c0 4.5 3.2 7.8 8 9 4.8-1.2 8-4.5 8-9V6z"/><path d="m9 12 2 2 4-4"/></svg>
</span>
<div>
<h2>Admin Panel</h2>
<p class="card-sub">Tạo, theo dõi và xoá key</p>
</div>
<span class="tag">ADMIN</span>
</div>

<div class="section-title">QUẢN LÝ SERVER</div>
<div class="device-radio" style="margin-bottom:10px">
<button id="siteStatusOnline" class="active" onclick="setSiteStatus('online')">🟢 ONLINE</button>
<button id="siteStatusMaint" onclick="setSiteStatus('maintenance')">🟡 BẢO TRÌ</button>
<button id="siteStatusOff" onclick="setSiteStatus('off')">🔴 TẮT WEB</button>
</div>
<label>Nội dung khi Bảo trì</label>
<textarea id="maintMsgInput" rows="2" style="width:100%;resize:vertical;font-family:var(--font-body);padding:11px 13px;border-radius:var(--radius-md);background:var(--field);border:1px solid var(--line);color:var(--text)"></textarea>
<label style="margin-top:10px;display:block">Nội dung khi Tắt web</label>
<textarea id="offMsgInput" rows="2" style="width:100%;resize:vertical;font-family:var(--font-body);padding:11px 13px;border-radius:var(--radius-md);background:var(--field);border:1px solid var(--line);color:var(--text)"></textarea>
<button class="btn-purple" style="margin-top:10px" onclick="saveSiteMessages()">LƯU NỘI DUNG</button>
<p class="card-sub" style="margin-top:8px">Get Key và Admin luôn truy cập bình thường dù bảo trì / tắt web. Người dùng thường sẽ thấy trang thông báo tương ứng.</p>

<div class="section-title">IP WHITELIST (quyền admin)</div>
<div style="display:flex;gap:8px">
<input id="whitelistIpInput" placeholder="VD: 203.0.113.5" style="flex:1">
<button class="btn-green" style="margin-top:0" onclick="addWhitelistIp()">THÊM</button>
</div>
<div id="whitelistList" style="margin-top:10px"></div>

<div class="section-title">GET KEY THEO APP (NetSuper / NetSuperVip)</div>
<div class="tab-bar" style="margin-bottom:10px">
<button id="tabAdminApp-netsuper" class="active" onclick="switchAdminApp('netsuper')">NetSuper</button>
<button id="tabAdminApp-netsupervip" onclick="switchAdminApp('netsupervip')">NetSuperVip</button>
</div>
<div id="adminAppPrefixBox" style="padding:12px;margin-top:6px;border-radius:12px;background:var(--field);border:1px solid var(--line)"></div>
<div id="adminAppDurations"></div>

<label>Key Content</label>
<input id="content" placeholder="VIP-ABC">

<label>Time</label>
<div class="tab-bar">
<button id="tabManual" class="active" onclick="switchTab('manual')">TÙY CHỈNH</button>
<button id="tabPreset" onclick="switchTab('preset')">PRESET</button>
</div>

<div id="manualTime">
<div class="time-grid">
<div class="unit"><input id="tYear" type="number" placeholder="Năm" value="0" min="0"><span>NĂM</span></div>
<div class="unit"><input id="tMonth" type="number" placeholder="Tháng" value="0" min="0"><span>THÁNG</span></div>
<div class="unit"><input id="tDay" type="number" placeholder="Ngày" value="0" min="0"><span>NGÀY</span></div>
</div>
<div class="time-grid" style="margin-top:8px">
<div class="unit"><input id="tHour" type="number" placeholder="Giờ" value="0" min="0"><span>GIỜ</span></div>
<div class="unit"><input id="tMin" type="number" placeholder="Phút" value="0" min="0"><span>PHÚT</span></div>
<div class="unit"><input id="tSec" type="number" placeholder="Giây" value="0" min="0"><span>GIÂY</span></div>
</div>
<div class="permanent-box" onclick="togglePermanent()">
<input type="checkbox" id="permanentChk">
<span class="switch"></span>
<span class="perm-text"><b>🔒 VĨNH VIỄN</b><small>không hết hạn</small></span>
</div>
</div>

<div id="presetTime" style="display:none">
<div class="quick-grid">
<button onclick="pickPreset('3h')"><b>3H</b></button>
<button onclick="pickPreset('6h')"><b>6H</b></button>
<button onclick="pickPreset('8h')"><b>8H</b></button>
<button onclick="pickPreset('12h')"><b>12H</b></button>
<button class="wide" onclick="pickPreset('24h')"><b>24H</b></button>
</div>
<div id="presetPickedLabel" class="picked"></div>
</div>

<div class="device-box">
<label>📱 Giới hạn thiết bị</label>
<div class="device-radio">
<button id="devUnlimited" class="active" onclick="setDeviceMode('unlimited')">VÔ HẠN</button>
<button id="devCustom" onclick="setDeviceMode('custom')">TÙY CHỈNH</button>
</div>
<div id="devCustomInput" style="display:none">
<input id="maxDevices" type="number" value="1" min="1" placeholder="Số thiết bị">
</div>
</div>

<button class="btn-green" onclick="createKey()">CREATE KEY</button>

<div class="section-title">BULK CREATE</div>
<label>Số lượng key</label>
<input id="bulkCount" type="number" value="10" min="1" max="10000">

<div style="margin-top:14px">
<div class="tab-bar">
<button id="tabBulkManual" class="active" onclick="switchBulkTab('manual')">TÙY CHỈNH</button>
<button id="tabBulkPreset" onclick="switchBulkTab('preset')">PRESET</button>
</div>
</div>

<div id="bulkManualTime">
<div class="time-grid">
<div class="unit"><input id="bYear" type="number" placeholder="Năm" value="0" min="0"><span>NĂM</span></div>
<div class="unit"><input id="bMonth" type="number" placeholder="Tháng" value="0" min="0"><span>THÁNG</span></div>
<div class="unit"><input id="bDay" type="number" placeholder="Ngày" value="0" min="0"><span>NGÀY</span></div>
</div>
<div class="time-grid" style="margin-top:8px">
<div class="unit"><input id="bHour" type="number" placeholder="Giờ" value="0" min="0"><span>GIỜ</span></div>
<div class="unit"><input id="bMin" type="number" placeholder="Phút" value="0" min="0"><span>PHÚT</span></div>
<div class="unit"><input id="bSec" type="number" placeholder="Giây" value="0" min="0"><span>GIÂY</span></div>
</div>
<div class="permanent-box" onclick="toggleBulkPermanent()">
<input type="checkbox" id="bulkPermanentChk">
<span class="switch"></span>
<span class="perm-text"><b>🔒 VĨNH VIỄN</b><small>không hết hạn</small></span>
</div>

<div class="device-box">
<label>📱 Giới hạn thiết bị</label>
<div class="device-radio">
<button id="bDevUnlimited" class="active" onclick="setBulkDeviceMode('unlimited')">VÔ HẠN</button>
<button id="bDevCustom" onclick="setBulkDeviceMode('custom')">TÙY CHỈNH</button>
</div>
<div id="bDevCustomInput" style="display:none">
<input id="bulkMaxDevices" type="number" value="1" min="1" placeholder="Số thiết bị">
</div>
</div>

<button class="btn-green" style="margin-top:12px" onclick="bulkCreateCustom()">⚡ TẠO HÀNG LOẠT</button>
</div>

<div id="bulkPresetTime" style="display:none">
<div class="device-box">
<label>📱 Giới hạn thiết bị</label>
<div class="device-radio">
<button id="bpDevUnlimited" class="active" onclick="setBulkPresetDeviceMode('unlimited')">VÔ HẠN</button>
<button id="bpDevCustom" onclick="setBulkPresetDeviceMode('custom')">TÙY CHỈNH</button>
</div>
<div id="bpDevCustomInput" style="display:none">
<input id="bulkPresetMaxDevices" type="number" value="1" min="1" placeholder="Số thiết bị">
</div>
</div>
<div class="quick-grid">
<button onclick="bulkCreatePreset('3h')"><b>3H</b><span>tạo hàng loạt</span></button>
<button onclick="bulkCreatePreset('6h')"><b>6H</b><span>tạo hàng loạt</span></button>
<button onclick="bulkCreatePreset('8h')"><b>8H</b><span>tạo hàng loạt</span></button>
<button onclick="bulkCreatePreset('12h')"><b>12H</b><span>tạo hàng loạt</span></button>
<button class="wide" onclick="bulkCreatePreset('24h')"><b>24H</b><span>tạo hàng loạt</span></button>
</div>
</div>

<div id="resultBox" class="result-box">
<h3>✅ Key Created</h3>
<div class="result-key" id="resultKey"></div>
<div id="resultKeysList" class="result-keys-list" style="display:none"></div>
<button class="btn-purple" style="margin-top:10px" onclick="copyAllResult()">📋 COPY ALL</button>
</div>

<a class="btn-purple" href="/amin/keys" style="display:block;text-align:center;text-decoration:none;margin-top:14px;padding:14px">🔑 MỞ TRANG QUẢN LÝ KEY (VIP / THƯỜNG · XOÁ · RESET · SỬA)</a>
</div>

</div>

<section class="how">
<div class="how-title">Cách hoạt động</div>
<div class="how-grid">
<div class="how-item">
<span class="how-num">1</span>
<div><h4>Chọn thời lượng</h4><p>3, 6, 8, 12 hoặc 24 giờ — thời lượng càng dài, số bước càng nhiều.</p></div>
</div>
<div class="how-item">
<span class="how-num">2</span>
<div><h4>Hoàn thành nhiệm vụ</h4><p>Mở từng liên kết và ở lại đủ thời gian yêu cầu trước khi sang bước tiếp theo.</p></div>
</div>
<div class="how-item">
<span class="how-num">3</span>
<div><h4>Nhận và sao chép key</h4><p>Key hiện ra ngay khi xong bước cuối, bấm một lần để sao chép.</p></div>
</div>
</div>
</section>

<div class="hint">✦ Crafted by <b>ThichLenDo</b> · v3.4 ✦</div>
</main>

<script>
// ---------- I18N (14 ngôn ngữ) ----------
const I18N = ${JSON.stringify(I18N_ALL)};
const LANG_LIST = ${JSON.stringify(LANG_LIST)};
const RTL_LANGS = ['ar'];
${NS_DETECT_JS}
let currentLang = nsDetectLang();
function t(key) { return (I18N[currentLang] && I18N[currentLang][key]) || (I18N.vi[key] || key); }
function applyLang() {
  document.documentElement.lang = currentLang;
  document.documentElement.dir = RTL_LANGS.indexOf(currentLang) > -1 ? 'rtl' : 'ltr';
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const v = t(el.getAttribute('data-i18n'));
    if (v) el.textContent = v;
  });
  const sel = document.getElementById('langSel');
  if (sel) sel.value = currentLang;
  renderAppDurations();
}
function setLang(l) {
  if (!I18N[l]) return;
  currentLang = l;
  try { localStorage.setItem('ns_lang', l); } catch (e) {}
  applyLang();
}
(function () {
  const sel = document.getElementById('langSel');
  if (!sel) return;
  LANG_LIST.forEach(p => { const o = document.createElement('option'); o.value = p[0]; o.textContent = p[1]; sel.appendChild(o); });
  sel.value = currentLang;
})();

let keysData = [];
let lastResult = null;
let currentTab = 'manual';
let currentBulkTab = 'manual';
let presetDuration = '';
let deviceMode = 'unlimited';
let bulkDeviceMode = 'unlimited';
let bulkPresetDeviceMode = 'unlimited';
let currentGetKeyApp = 'netsuper';
let appsConfigData = null;
const MAX_SHOW_KEYS = 20;
applyLang();

(async () => {
  try {
    const r = await fetch('/api/health');
    const j = await r.json();
    const badge = document.getElementById('redisBadge');
    badge.innerHTML = j.redis ? '<span class="status-badge status-online">● REDIS</span>' : '<span class="status-badge status-offline">● OFFLINE</span>';
  } catch (e) {}
})();

async function refreshStatusDot() {
  try {
    const r = await fetch('/api/site-status');
    const j = await r.json();
    const dot = document.getElementById('statusDot');
    if (!dot) return;
    if (j.status === 'online') {
      dot.className = 'status-dot online';
      dot.innerHTML = '<i></i>ONLINE';
    } else {
      dot.className = 'status-dot maintenance';
      dot.innerHTML = '<i></i>' + (j.status === 'off' ? 'OFF' : t('maintenanceShort').toUpperCase());
    }
  } catch (e) {}
}
refreshStatusDot();
setInterval(refreshStatusDot, 15000);

let clientIsAdmin = false;
(async () => {
  const r = await fetch('/api/verify-admin', {method:'POST'});
  const j = await r.json();
  clientIsAdmin = !!j.isAdmin;
  nsSetAdmin(!!j.isAdmin);
  if (j.isAdmin) {
    nsHideGuide();
    document.getElementById('adminPanel').style.display = 'block';
    await loadSiteConfigForAdmin();
    await syncWhitelist();
    await syncAdminAppConfig();
  }
  renderAppDurations(); // re-render tab NetSuperVip đúng theo quyền admin/user thường
})();

async function loadSiteConfigForAdmin() {
  try {
    const r = await fetch('/api/site-status');
    const j = await r.json();
    setSiteStatusButtons(j.status);
    document.getElementById('maintMsgInput').value = j.maintMsg || '';
    document.getElementById('offMsgInput').value = j.offMsg || '';
  } catch (e) {}
}
function setSiteStatusButtons(status) {
  document.getElementById('siteStatusOnline').classList.toggle('active', status === 'online');
  document.getElementById('siteStatusMaint').classList.toggle('active', status === 'maintenance');
  document.getElementById('siteStatusOff').classList.toggle('active', status === 'off');
}
async function setSiteStatus(status) {
  setSiteStatusButtons(status);
  const r = await fetch('/api/site-status', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({status})});
  const j = await r.json();
  if (j.ok) { showMsg('Đã cập nhật trạng thái server: ' + status.toUpperCase(), true); refreshStatusDot(); }
  else showMsg('Lỗi cập nhật trạng thái', false);
}
async function saveSiteMessages() {
  const maintMsg = document.getElementById('maintMsgInput').value;
  const offMsg = document.getElementById('offMsgInput').value;
  const r = await fetch('/api/site-status', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({maintMsg, offMsg})});
  const j = await r.json();
  showMsg(j.ok ? 'Đã lưu nội dung thông báo' : 'Lỗi lưu nội dung', !!j.ok);
}
async function syncWhitelist() {
  try {
    const r = await fetch('/api/whitelist-list', {method:'POST'});
    const j = await r.json();
    if (!j.ok) return;
    renderWhitelist(j.ips, j.yourIp);
  } catch (e) {}
}
function renderWhitelist(ips, yourIp) {
  const box = document.getElementById('whitelistList');
  if (!ips.length) { box.innerHTML = '<p class="card-sub">Chưa có IP nào trong whitelist</p>'; return; }
  box.innerHTML = '';
  ips.forEach(ip => {
    const row = document.createElement('div');
    row.style.cssText = 'display:flex;align-items:center;justify-content:space-between;gap:8px;padding:8px 12px;margin-top:6px;border-radius:10px;background:var(--field);border:1px solid var(--line);font-family:var(--font-mono);font-size:12.5px';
    row.innerHTML = '<span>' + ip + (ip === yourIp ? ' <span style="color:var(--emerald)">(bạn)</span>' : '') + '</span>';
    const btn = document.createElement('button');
    btn.className = 'del'; btn.textContent = 'X';
    btn.onclick = async () => {
      await fetch('/api/whitelist-remove', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})});
      syncWhitelist();
    };
    row.appendChild(btn);
    box.appendChild(row);
  });
}
async function addWhitelistIp() {
  const input = document.getElementById('whitelistIpInput');
  const ip = input.value.trim();
  if (!ip) return;
  const r = await fetch('/api/whitelist-add', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})});
  const j = await r.json();
  if (j.ok) { input.value = ''; showMsg('Đã thêm IP admin: ' + ip, true); syncWhitelist(); }
  else showMsg('Lỗi thêm IP', false);
}

// ---------- ADMIN: GET KEY THEO APP (hidden / maintenance / thứ tự & số bước link) ----------
let adminAppConfigCache = null;
let currentAdminApp = 'netsuper';
const DURATION_ORDER = ['3h','6h','8h','12h','24h'];
function switchAdminApp(appId) {
  currentAdminApp = appId;
  document.getElementById('tabAdminApp-netsuper').classList.toggle('active', appId === 'netsuper');
  document.getElementById('tabAdminApp-netsupervip').classList.toggle('active', appId === 'netsupervip');
  renderAdminAppDurations();
}
async function syncAdminAppConfig() {
  try {
    const r = await fetch('/api/apps-config');
    const j = await r.json();
    if (!j.ok) return;
    adminAppConfigCache = j.apps;
    renderAdminAppDurations();
  } catch (e) {}
}
function renderAdminAppPrefix() {
  const pb = document.getElementById('adminAppPrefixBox');
  if (!pb || !adminAppConfigCache || !adminAppConfigCache[currentAdminApp]) return;
  const c = adminAppConfigCache[currentAdminApp];
  const isVip = currentAdminApp === 'netsupervip';
  pb.innerHTML =
    '<b style="font-size:12px">CHỮ ĐẦU KEY KHI GET KEY (' + c.label + ')</b>' +
    '<input id="appPrefixInput" value="' + (c.prefix || '') + '" maxlength="24" placeholder="' + (isVip ? 'NetSuperVip' : 'NetSuper') + '" style="margin-top:8px">' +
    (isVip
      ? '<select id="appTailStyleSel" style="margin-top:8px"><option value="special9"' + (c.tailStyle === 'special9' ? ' selected' : '') + '>Kiểu 2: hoa+thường+số+ký tự đặc biệt (9 ký tự)</option><option value="alnum12"' + (c.tailStyle === 'alnum12' ? ' selected' : '') + '>Kiểu 1: hoa+thường+số (12 ký tự)</option></select>'
      : '<p class="card-sub" style="margin-top:6px">Key thường giữ format 2 khối: ChữĐầu-XXXXXXXXXXX-XXXXXXXXXX</p>') +
    '<button class="btn-purple" style="margin-top:8px" onclick="saveAppPrefix()">💾 LƯU CHỮ ĐẦU</button>';
}
async function saveAppPrefix() {
  const prefix = document.getElementById('appPrefixInput').value.trim();
  const sel = document.getElementById('appTailStyleSel');
  const body = {app: currentAdminApp, prefix};
  if (sel) body.tailStyle = sel.value;
  const r = await fetch('/api/apps-prefix', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const j = await r.json();
  if (j.ok) { showMsg('Đã lưu chữ đầu: ' + j.prefix, true); syncAdminAppConfig(); }
  else showMsg('FAIL: ' + (j.message || 'lỗi') + ' (chỉ dùng chữ/số, không dấu -)', false);
}
function renderAdminAppDurations() {
  renderAdminAppPrefix();
  const box = document.getElementById('adminAppDurations');
  if (!box || !adminAppConfigCache) return;
  const durations = adminAppConfigCache[currentAdminApp].durations;
  box.innerHTML = '';
  DURATION_ORDER.forEach(dur => {
    const d = durations[dur];
    const maxSteps = d.maxSteps;
    const row = document.createElement('div');
    row.style.cssText = 'padding:12px;margin-top:10px;border-radius:12px;background:var(--field);border:1px solid var(--line)';

    const head = document.createElement('div');
    head.style.cssText = 'display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap';
    head.innerHTML = '<b style="font-family:var(--font-mono)">' + dur.toUpperCase() + '</b>';

    const toggles = document.createElement('div');
    toggles.style.cssText = 'display:flex;gap:14px;font-size:12px;color:var(--text-dim)';
    toggles.innerHTML =
      '<label style="display:flex;align-items:center;gap:5px;cursor:pointer"><input type="checkbox" id="hid-' + currentAdminApp + '-' + dur + '" ' + (d.hidden ? 'checked' : '') + '> Ẩn</label>' +
      '<label style="display:flex;align-items:center;gap:5px;cursor:pointer"><input type="checkbox" id="maint-' + currentAdminApp + '-' + dur + '" ' + (d.maintenance ? 'checked' : '') + '> Bảo trì</label>';
    head.appendChild(toggles);
    row.appendChild(head);

    const stepsWrap = document.createElement('div');
    stepsWrap.style.cssText = 'display:flex;gap:6px;flex-wrap:wrap;margin-top:10px';
    stepsWrap.id = 'steps-' + currentAdminApp + '-' + dur;
    for (let i = 0; i < maxSteps; i++) {
      const sel = document.createElement('select');
      sel.dataset.slot = i;
      sel.style.cssText = 'padding:7px 8px;border-radius:8px;background:var(--ink-800);border:1px solid var(--line);color:var(--text);font-size:12px';
      const cur = d.steps[i] || '';
      ['', 'link4m', 'trafficvn', 'link999'].forEach(opt => {
        const o = document.createElement('option');
        o.value = opt; o.textContent = opt === '' ? '— (không dùng)' : opt;
        if (opt === cur) o.selected = true;
        sel.appendChild(o);
      });
      stepsWrap.appendChild(sel);
    }
    row.appendChild(stepsWrap);
    row.innerHTML += '<p class="card-sub" style="margin-top:6px">Tối đa ' + maxSteps + ' bước · thứ tự trái → phải · để trống để rút ngắn</p>';

    const saveBtn = document.createElement('button');
    saveBtn.className = 'btn-purple';
    saveBtn.style.cssText = 'margin-top:8px;padding:9px 14px;font-size:12.5px';
    saveBtn.textContent = 'LƯU ' + dur.toUpperCase();
    saveBtn.onclick = () => saveAdminAppDuration(dur, stepsWrap);
    row.appendChild(saveBtn);

    box.appendChild(row);
  });
}
async function saveAdminAppDuration(dur, stepsWrap) {
  const hidden = document.getElementById('hid-' + currentAdminApp + '-' + dur).checked;
  const maintenance = document.getElementById('maint-' + currentAdminApp + '-' + dur).checked;
  const steps = Array.from(stepsWrap.querySelectorAll('select')).map(s => s.value).filter(v => v);
  if (!steps.length) { showMsg('Cần ít nhất 1 bước', false); return; }
  const r = await fetch('/api/apps-config', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({app: currentAdminApp, duration: dur, hidden, maintenance, steps})});
  const j = await r.json();
  if (j.ok) { showMsg('Đã lưu ' + dur.toUpperCase() + ' (' + currentAdminApp + ')', true); syncAdminAppConfig(); loadAppDurations(); }
  else showMsg('Lỗi lưu: ' + (j.message || ''), false);
}

function formatCountdown(ms) {
  if (ms <= 0) return '00s';
  const s = Math.floor(ms/1000);
  if (s > 365*24*3600*9) return '∞';
  const h = Math.floor(s/3600), m = Math.floor((s%3600)/60), sec = s%60;
  const pad = n => String(n).padStart(2,'0');
  if (h >= 24) { const d = Math.floor(h/24), hh = h%24; return d+'d '+pad(hh)+'h'; }
  if (h > 0) return pad(h)+'h'+pad(m)+'m'+pad(sec)+'s';
  if (m > 0) return pad(m)+'m'+pad(sec)+'s';
  return pad(sec)+'s';
}
function updateCountdowns() {
  const now = Date.now();
  const tb = document.querySelector('#tbl tbody');
  if (!tb) return;
  tb.querySelectorAll('tr[data-key]').forEach(row => {
    const key = row.getAttribute('data-key');
    const entry = keysData.find(k => k.key === key);
    if (!entry) return;
    const remain = entry.expireAt - now;
    const cell = row.querySelector('.r');
    if (remain <= 0) { row.remove(); keysData = keysData.filter(k => k.key !== key); return; }
    cell.textContent = formatCountdown(remain);
  });
}
async function syncKeys() {
  try {
    const r = await fetch('/api/list-keys', {method:'POST'});
    const j = await r.json();
    if (!j.ok) return;
    keysData = j.keys;
    renderKeysTable(keysData);
  } catch (e) {}
}
function renderKeysTable(list) {
  const tb = document.querySelector('#tbl tbody');
  if (!tb) return;
  if (!list.length) { tb.innerHTML = '<tr><td colspan="5" style="color:#444;text-align:center">empty</td></tr>'; return; }
  tb.innerHTML = '';
  const now = Date.now();
  list.forEach(k => {
    const remain = k.expireAt - now;
    if (remain <= 0) return;
    const tr = document.createElement('tr');
    tr.setAttribute('data-key', k.key);
    const dev = (Number(k.maxDevices)||0) === 0 ? (k.devices||0) + '/∞' : (k.devices||0) + '/' + k.maxDevices;
    const vipTag = k.vip ? ' <span style="font-size:9px;padding:1px 5px;border-radius:6px;background:rgba(168,85,247,.25);color:#c4b5fd">VIP</span>' : '';
    tr.innerHTML = '<td class="k">'+k.key+vipTag+'</td><td class="r">'+formatCountdown(remain)+'</td><td class="dev">'+dev+'</td><td style="font-size:11px;color:#8791a6">'+k.expire+'</td>';
    const td = document.createElement('td');
    td.style.cssText = 'display:flex;gap:6px';
    if (k.vip) {
      const rb = document.createElement('button');
      rb.className = 'btn-purple'; rb.textContent = 'RESET';
      rb.style.cssText = 'padding:5px 9px;font-size:11px;margin-top:0';
      rb.onclick = async () => {
        rb.disabled = true;
        const r = await fetch('/api/reset-key', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:k.key})});
        const j = await r.json();
        rb.disabled = false;
        if (j.ok) { k.devices = 0; renderKeysTable(keysData); showMsg('✅ Đã reset key VIP', true); }
        else showMsg('FAIL reset: ' + (j.message||''), false);
      };
      td.appendChild(rb);
    }
    const b = document.createElement('button');
    b.className = 'del'; b.textContent = 'X';
    b.onclick = async () => {
      await fetch('/api/delete-key', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:k.key})});
      keysData = keysData.filter(x => x.key !== k.key);
      renderKeysTable(keysData);
    };
    td.appendChild(b); tr.appendChild(td); tb.appendChild(tr);
  });
}
async function loadAppDurations() {
  try {
    const r = await fetch('/api/apps-config');
    const j = await r.json();
    if (!j.ok) return;
    appsConfigData = j.apps;
    renderAppDurations();
  } catch (e) {}
  try {
    const r2 = await fetch('/api/ip-getkey-status');
    const j2 = await r2.json();
    const note = document.getElementById('ipLimitNote');
    if (j2.ok && note) {
      note.textContent = j2.unlimited
        ? t('ipLimitAdmin')
        : t('ipLimitNote').replace('{used}', j2.used).replace('{limit}', j2.limit);
    }
  } catch (e) {}
}
function switchApp(appId) {
  currentGetKeyApp = appId;
  document.getElementById('tabApp-netsuper').classList.toggle('active', appId === 'netsuper');
  document.getElementById('tabApp-netsupervip').classList.toggle('active', appId === 'netsupervip');
  renderAppDurations();
}
const VIP_PACKAGES_CLIENT = {
  '1d':   { label: 'Key 1 ngày',    price: 10000 },
  '7d':   { label: 'Key 7 ngày',    price: 50000 },
  '30d':  { label: 'Key 30 ngày',   price: 199000 },
  'perm': { label: 'Key Vĩnh viễn', price: 500000 }
};
function fmtVnd(n) { return n.toLocaleString('vi-VN') + 'đ'; }
function renderVipPackages() {
  const box = document.getElementById('appDurationBox');
  box.innerHTML = '';
  const grid = document.createElement('div');
  grid.style.display = 'grid';
  grid.style.gap = '8px';
  Object.entries(VIP_PACKAGES_CLIENT).forEach(([id, p]) => {
    const btn = document.createElement('button');
    btn.innerHTML = '<b>' + p.label + '</b><span>' + fmtVnd(p.price) + '</span>';
    btn.onclick = () => vipBuyClick(id, p.label);
    grid.appendChild(btn);
  });
  box.appendChild(grid);
  if (clientIsAdmin) {
    const admBox = document.createElement('div');
    admBox.style.cssText = 'margin-top:14px;padding:12px;border-radius:10px;border:1px solid var(--line);background:var(--field)';
    admBox.innerHTML =
      '<p class="card-sub" style="margin-bottom:8px">⭐ ADMIN — tạo key VIP miễn phí theo gói (không cần mua)</p>' +
      '<label>Chữ đầu (prefix)</label><input id="vipAdminPrefix" value="NetSuperVip" style="margin-bottom:8px">' +
      '<label>Kiểu đuôi</label>' +
      '<div class="tab-bar" style="margin-bottom:8px">' +
        '<button id="vipStyleSpecial" class="active" onclick="setVipAdminStyle(\\'special9\\')">Kiểu 2: hoa+thường+số+ký tự đặc biệt</button>' +
        '<button id="vipStyleAlnum" onclick="setVipAdminStyle(\\'alnum12\\')">Kiểu 1: hoa+thường+số</button>' +
      '</div>' +
      '<label>Số lượng</label><input id="vipAdminCount" type="number" value="1" min="1" style="margin-bottom:8px">';
    box.appendChild(admBox);
  }
}
let vipAdminStyle = 'special9';
function setVipAdminStyle(s) {
  vipAdminStyle = s;
  document.getElementById('vipStyleSpecial').classList.toggle('active', s === 'special9');
  document.getElementById('vipStyleAlnum').classList.toggle('active', s === 'alnum12');
}
async function vipBuyClick(pkgId, label) {
  const status = document.getElementById('getKeyStatus');
  status.style.display = 'block'; status.style.color = '#888'; status.textContent = t('starting');
  if (clientIsAdmin) {
    const prefix = document.getElementById('vipAdminPrefix').value.trim() || 'NetSuperVip';
    const count = parseInt(document.getElementById('vipAdminCount').value, 10) || 1;
    const r = await fetch('/api/vip-admin-create', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({package: pkgId, count, prefix, style: vipAdminStyle})});
    const j = await r.json();
    if (!j.ok) { status.style.color='#ef4444'; status.textContent = t('error') + ': ' + (j.message||''); return; }
    status.style.color = '#10b981';
    status.textContent = j.count > 1 ? ('✅ ' + j.count + ' key VIP [' + j.label + ']: ' + j.keys.slice(0,3).join(', ') + (j.count>3?' ...':'') ) : ('✅ Key VIP: ' + j.keys[0]);
    try { await navigator.clipboard.writeText(j.keys.join('\\n')); } catch (e) {}
    j.keys.forEach(k => keysData.push({ key: k, expireAt: j.expireAt, expire: j.expire, maxDevices: j.maxDevices, devices: 0, vip: true }));
    renderKeysTable(keysData);
    return;
  }
  const r = await fetch('/api/vip-buy', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({package: pkgId})});
  const j = await r.json();
  status.style.color = '#f59e0b';
  status.textContent = '🛠️ ' + (label || '') + ' — ' + t('durationMaintenance');
}
function renderAppDurations() {
  const box = document.getElementById('appDurationBox');
  if (!box) return;
  if (currentGetKeyApp === 'netsupervip') { renderVipPackages(); return; }
  if (!appsConfigData || !appsConfigData[currentGetKeyApp]) { box.innerHTML = '<p class="card-sub">' + t('loading') + '</p>'; return; }
  const durations = appsConfigData[currentGetKeyApp].durations;
  const order = ['3h','6h','8h','12h','24h'];
  box.innerHTML = '';
  const grid = document.createElement('div');
  grid.id = 'durationMenu';
  grid.style.display = 'grid';
  let any = false;
  order.forEach(dur => {
    const d = durations[dur];
    if (!d) return; // ẩn -> không hiện
    any = true;
    const btn = document.createElement('button');
    if (d.maintenance) {
      btn.disabled = true;
      btn.style.opacity = '.5';
      btn.style.cursor = 'not-allowed';
      btn.innerHTML = '<b>' + dur.toUpperCase() + '</b><span>' + t('maintenanceShort') + '</span>';
    } else {
      btn.onclick = () => startTask(dur);
      btn.innerHTML = '<b>' + dur.toUpperCase() + '</b><span>' + d.totalSteps + ' ' + t('steps') + '</span>';
    }
    grid.appendChild(btn);
  });
  if (!any) { box.innerHTML = '<p class="card-sub">' + t('noDurations') + '</p>'; return; }
  box.appendChild(grid);
}
async function startTask(duration) {
  const status = document.getElementById('getKeyStatus');
  status.style.display = 'block'; status.textContent = t('starting'); status.style.color = '#888';
  const r = await fetch('/api/start-task', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({duration, app: currentGetKeyApp})});
  const j = await r.json();
  if (!j.ok) {
    let msg = j.message || j.reason || 'error';
    if (msg === 'ip_limit') msg = t('ipLimitReached').replace('{limit}', j.limit);
    else if (msg === 'duration_maintenance') msg = t('durationMaintenance');
    else if (msg === 'duration_hidden' || msg === 'bad_duration') msg = t('durationUnavailable');
    else if (msg === 'site_unavailable') msg = t('siteUnavailable');
    status.textContent = t('error') + ': ' + msg; status.style.color='#ef4444'; return;
  }
  status.textContent = t('opening'); status.style.color = '#10b981';
  location.href = j.taskUrl;
}
loadAppDurations();

function switchTab(t) {
  currentTab = t;
  document.getElementById('tabManual').classList.toggle('active', t === 'manual');
  document.getElementById('tabPreset').classList.toggle('active', t === 'preset');
  document.getElementById('manualTime').style.display = t === 'manual' ? 'block' : 'none';
  document.getElementById('presetTime').style.display = t === 'preset' ? 'block' : 'none';
}
function switchBulkTab(t) {
  currentBulkTab = t;
  document.getElementById('tabBulkManual').classList.toggle('active', t === 'manual');
  document.getElementById('tabBulkPreset').classList.toggle('active', t === 'preset');
  document.getElementById('bulkManualTime').style.display = t === 'manual' ? 'block' : 'none';
  document.getElementById('bulkPresetTime').style.display = t === 'preset' ? 'block' : 'none';
}
function pickPreset(d) {
  presetDuration = d;
  document.getElementById('presetPickedLabel').textContent = 'Đã chọn: ' + d.toUpperCase();
}
function togglePermanent() { document.getElementById('permanentChk').checked = !document.getElementById('permanentChk').checked; }
function toggleBulkPermanent() { document.getElementById('bulkPermanentChk').checked = !document.getElementById('bulkPermanentChk').checked; }
function setDeviceMode(m) {
  deviceMode = m;
  document.getElementById('devUnlimited').classList.toggle('active', m === 'unlimited');
  document.getElementById('devCustom').classList.toggle('active', m === 'custom');
  document.getElementById('devCustomInput').style.display = m === 'custom' ? 'block' : 'none';
}
function setBulkDeviceMode(m) {
  bulkDeviceMode = m;
  document.getElementById('bDevUnlimited').classList.toggle('active', m === 'unlimited');
  document.getElementById('bDevCustom').classList.toggle('active', m === 'custom');
  document.getElementById('bDevCustomInput').style.display = m === 'custom' ? 'block' : 'none';
}
function setBulkPresetDeviceMode(m) {
  bulkPresetDeviceMode = m;
  document.getElementById('bpDevUnlimited').classList.toggle('active', m === 'unlimited');
  document.getElementById('bpDevCustom').classList.toggle('active', m === 'custom');
  document.getElementById('bpDevCustomInput').style.display = m === 'custom' ? 'block' : 'none';
}
function getTimeObj(prefix) {
  return {
    years:   document.getElementById(prefix+'Year').value || 0,
    months:  document.getElementById(prefix+'Month').value || 0,
    days:    document.getElementById(prefix+'Day').value || 0,
    hours:   document.getElementById(prefix+'Hour').value || 0,
    minutes: document.getElementById(prefix+'Min').value || 0,
    seconds: document.getElementById(prefix+'Sec').value || 0,
    permanent: document.getElementById(prefix === 't' ? 'permanentChk' : 'bulkPermanentChk').checked
  };
}
function getMaxDevices(mode, inputId) {
  if (mode === 'unlimited') return 0;
  const v = parseInt(document.getElementById(inputId).value, 10) || 1;
  return Math.max(1, v);
}
function showMsg(t, ok) {
  const m = document.getElementById('msg');
  m.textContent = t; m.className = ok ? 'ok' : 'err';
  m.style.display = 'block';
  setTimeout(() => m.style.display = 'none', 4000);
}
function showResult(data) {
  lastResult = data;
  document.getElementById('resultBox').style.display = 'block';
  const keyBox = document.getElementById('resultKey');
  const listBox = document.getElementById('resultKeysList');
  const devInfo = (Number(data.maxDevices)||0) === 0 ? '📱 Vô hạn' : '📱 ' + data.maxDevices + ' thiết bị';
  const devTag = ' — ' + devInfo;
  if (data.keys && data.keys.length > 1) {
    keyBox.textContent = '✅ ' + data.keys.length + ' KEYS ' + (data.label ? '[' + data.label + ']' : '') + devTag;
    const show = data.keys.slice(0, MAX_SHOW_KEYS);
    let txt = show.join('\\n');
    if (data.keys.length > MAX_SHOW_KEYS) txt += '\\n\\n... và ' + (data.keys.length - MAX_SHOW_KEYS) + ' keys nữa (bấm COPY ALL)';
    listBox.textContent = txt;
    listBox.style.display = 'block';
  } else {
    keyBox.textContent = (data.key || (data.keys && data.keys[0])) + devTag;
    listBox.style.display = 'none';
  }
}
async function createKey() {
  const content = document.getElementById('content').value.trim();
  if (!content) return showMsg('NO CONTENT', false);
  let timeObj;
  if (currentTab === 'manual') timeObj = getTimeObj('t');
  else {
    if (!presetDuration) return showMsg('Chọn preset duration', false);
    const cfg = {'3h':3,'6h':6,'8h':8,'12h':12,'24h':24}[presetDuration];
    timeObj = { hours: cfg, permanent: false, years:0,months:0,days:0,minutes:0,seconds:0 };
  }
  if (!timeObj.permanent) {
    const total = Number(timeObj.years||0)+Number(timeObj.months||0)+Number(timeObj.days||0)+Number(timeObj.hours||0)+Number(timeObj.minutes||0)+Number(timeObj.seconds||0);
    if (total <= 0) return showMsg('Chọn thời gian', false);
  }
  const maxDevices = getMaxDevices(deviceMode, 'maxDevices');
  showMsg('Creating...', true);
  const r = await fetch('/api/create-key', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({content, time: timeObj, maxDevices})});
  const j = await r.json();
  if (j.ok) {
    showMsg('✅ OK', true);
    showResult({ key: j.key, keys: [j.key], label: j.isPermanent ? 'VĨNH VIỄN' : '', expire: j.expire, maxDevices: j.maxDevices });
    keysData.push({ key: j.key, expireAt: j.expireAt, expire: j.expire, maxDevices: j.maxDevices, devices: 0 });
    renderKeysTable(keysData);
  } else showMsg('FAIL: ' + (j.message||''), false);
}
async function bulkCreateCustom() {
  const count = parseInt(document.getElementById('bulkCount').value, 10) || 1;
  if (count < 1 || count > 10000) return showMsg('1-10000', false);
  const timeObj = getTimeObj('b');
  if (!timeObj.permanent) {
    const total = Number(timeObj.years||0)+Number(timeObj.months||0)+Number(timeObj.days||0)+Number(timeObj.hours||0)+Number(timeObj.minutes||0)+Number(timeObj.seconds||0);
    if (total <= 0) return showMsg('Chọn thời gian', false);
  }
  const maxDevices = getMaxDevices(bulkDeviceMode, 'bulkMaxDevices');
  showMsg('Đang tạo ' + count + ' key...', true);
  const r = await fetch('/api/bulk-create', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({count, time: timeObj, mode: 'custom', maxDevices})});
  const j = await r.json();
  if (j.ok) {
    showMsg('✅ Đã tạo ' + j.count + ' key', true);
    showResult({ keys: j.keys, label: j.label, expire: j.expire, count: j.count, maxDevices: j.maxDevices });
    j.keys.forEach(k => keysData.push({ key: k, expireAt: j.expireAt, expire: j.expire, maxDevices: j.maxDevices, devices: 0 }));
    renderKeysTable(keysData);
    try { await navigator.clipboard.writeText(j.keys.join('\\n')); } catch (e) {}
  } else showMsg('FAIL: ' + (j.message||''), false);
}
async function bulkCreatePreset(duration) {
  const count = parseInt(document.getElementById('bulkCount').value, 10) || 1;
  if (count < 1 || count > 10000) return showMsg('1-10000', false);
  const maxDevices = getMaxDevices(bulkPresetDeviceMode, 'bulkPresetMaxDevices');
  showMsg('Đang tạo ' + count + ' key ' + duration.toUpperCase() + '...', true);
  const r = await fetch('/api/bulk-create', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({count, mode: 'preset', duration, maxDevices})});
  const j = await r.json();
  if (j.ok) {
    showMsg('✅ ' + j.count + ' key ' + duration.toUpperCase(), true);
    showResult({ keys: j.keys, label: j.label, expire: j.expire, count: j.count, maxDevices: j.maxDevices });
    j.keys.forEach(k => keysData.push({ key: k, expireAt: j.expireAt, expire: j.expire, maxDevices: j.maxDevices, devices: 0 }));
    renderKeysTable(keysData);
    try { await navigator.clipboard.writeText(j.keys.join('\\n')); } catch (e) {}
  } else showMsg('FAIL: ' + (j.message||''), false);
}
function copyAllResult() {
  if (!lastResult) return;
  const devInfo = (Number(lastResult.maxDevices)||0) === 0 ? '📱 Vô hạn' : '📱 ' + lastResult.maxDevices + ' thiết bị';
  let txt = '';
  if (lastResult.keys && lastResult.keys.length > 1) {
    txt = '🔑 ' + lastResult.keys.length + ' KEYS ' + (lastResult.label ? '[' + lastResult.label + ']' : '') + '\\n';
    txt += '⏱️ Expire: ' + lastResult.expire + '\\n' + devInfo + '\\n\\n' + lastResult.keys.join('\\n');
  } else {
    txt = '🔑 KEY: ' + (lastResult.key || lastResult.keys[0]) + '\\n⏱️ Expire: ' + lastResult.expire + '\\n' + devInfo + '\\n';
  }
  navigator.clipboard.writeText(txt).then(() => showMsg('✅ Copied!', true));
}
</script>
${THEME_JS}
</body></html>`;

// ============================================
// HTML TASK
// ============================================
const TASK_CSS = `
body{display:flex;flex-direction:column}
.topbar{width:100%}
.task-wrap{
  position:relative;
  z-index:1;
  flex:1;
  width:100%;
  max-width:500px;
  margin:0 auto;
  padding:28px 16px 40px;
  display:flex;
  flex-direction:column;
  justify-content:center;
}
a.pill{
  text-decoration:none;
  transition:color .2s ease,border-color .2s ease,transform .2s var(--ease);
}
a.pill:hover{
  color:var(--text);
  border-color:var(--line-strong);
  transform:translateX(-2px);
}

/* ---------- TASK CARD ---------- */
.task-card{
  padding:26px;
  animation:rise .8s var(--ease) both;
}
.task-head{
  display:flex;
  align-items:center;
  gap:14px;
  margin-bottom:20px;
}
.task-head h1{
  font-family:var(--font-display);
  font-size:21px;
  font-weight:800;
  line-height:1.15;
  letter-spacing:.8px;
  background:var(--grad-brand);
  background-size:200% 100%;
  -webkit-background-clip:text;
  background-clip:text;
  color:transparent;
  animation:gradient-shift 9s linear infinite;
}
.sub{
  display:flex;
  flex-wrap:wrap;
  align-items:center;
  justify-content:center;
  gap:8px;
  margin-bottom:18px;
  padding:12px 14px;
  border-radius:14px;
  text-align:center;
  font-size:12.5px;
  font-weight:500;
  color:var(--text-dim);
  background:var(--field);
  border:1px solid var(--line);
}
.duration-badge{
  display:inline-block;
  padding:4px 13px;
  border-radius:999px;
  font-family:var(--font-display);
  font-size:12px;
  font-weight:800;
  letter-spacing:.6px;
  color:#fff;
  background:var(--grad-primary);
  box-shadow:0 8px 18px -8px rgba(139,92,246,.9),inset 0 1px 0 rgba(255,255,255,.3);
}

/* ---------- STEPPER ---------- */
.progress{
  display:flex;
  flex-direction:column;
  gap:10px;
  margin:0 0 8px;
}
.step-row{
  position:relative;
  display:flex;
  align-items:center;
  padding:12px 14px;
  border-radius:15px;
  font-size:13px;
  font-weight:500;
  color:var(--text-dim);
  background:rgba(255,255,255,.035);
  border:1px solid var(--line);
}
.step-row:not(:last-child)::after{
  content:'';
  position:absolute;
  left:28px;
  top:100%;
  width:2px;
  height:10px;
  background:var(--line-strong);
}
.step-icon{
  flex:0 0 auto;
  width:30px;
  height:30px;
  margin-right:13px;
  border-radius:50%;
  display:grid;
  place-items:center;
  font-size:13px;
  font-weight:700;
  font-variant-emoji:text;
  color:var(--text-faint);
  background:rgba(255,255,255,.06);
  border:1px solid var(--line-strong);
}
.step-row.pending{color:var(--text-faint)}
.step-row.done{
  color:#a7f3d0;
  background:linear-gradient(120deg,rgba(52,211,153,.12),rgba(34,211,238,.04));
  border-color:rgba(52,211,153,.38);
}
.step-row.done:not(:last-child)::after{background:var(--emerald)}
.step-row.done .step-icon{
  color:#032a22;
  background:var(--grad-success);
  border-color:transparent;
  box-shadow:0 0 18px -2px rgba(52,211,153,.8);
}
.step-row.current{
  color:var(--text);
  background:linear-gradient(120deg,rgba(139,92,246,.2),rgba(232,121,249,.07));
  border-color:rgba(167,139,250,.65);
  box-shadow:0 0 0 3px rgba(139,92,246,.14),0 18px 34px -20px rgba(139,92,246,.9);
}
.step-row.current .step-icon{
  padding-left:2px;
  color:#fff;
  background:var(--grad-primary);
  border-color:transparent;
  box-shadow:0 0 0 4px rgba(139,92,246,.26),0 0 22px rgba(139,92,246,.8);
}

/* ---------- ACTIONS ---------- */
#actions button{margin-top:16px;padding:17px 18px;font-size:14.5px}
.copybtn{
  background:var(--grad-success);
  background-size:170% 100%;
  color:#032a22;
  box-shadow:0 14px 32px -12px rgba(16,185,129,.85),inset 0 1px 0 rgba(255,255,255,.35);
}
.copybtn:hover{box-shadow:0 20px 40px -14px rgba(16,185,129,.95),inset 0 1px 0 rgba(255,255,255,.4)}
.homebtn{
  background:var(--grad-primary);
  background-size:170% 100%;
}
#keyBox{
  position:relative;
  margin:8px 0 2px;
  padding:26px 16px 22px;
  border-radius:20px;
  text-align:center;
  font-family:var(--font-mono);
  font-size:clamp(14px,4.2vw,18px);
  font-weight:600;
  line-height:1.5;
  word-break:break-all;
  color:#d1fae5;
  text-shadow:0 0 18px rgba(52,211,153,.6);
  background:linear-gradient(150deg,rgba(52,211,153,.17),rgba(34,211,238,.06));
  border:1px solid rgba(52,211,153,.55);
  animation:pop-in .6s var(--ease) both,glow-pulse 3.2s ease-in-out .6s infinite;
}
#keyBox::before{
  content:'Key của bạn';
  display:block;
  margin-bottom:10px;
  font-family:var(--font-body);
  font-size:11.5px;
  font-weight:600;
  letter-spacing:.4px;
  color:var(--text-dim);
  text-shadow:none;
}
.bypass-box{
  margin:4px 0 2px;
  padding:24px 18px;
  border-radius:20px;
  text-align:center;
  background:linear-gradient(150deg,rgba(244,63,94,.17),rgba(251,113,133,.05));
  border:1px solid rgba(251,113,133,.52);
  box-shadow:0 0 48px -14px rgba(244,63,94,.65);
  animation:pop-in .5s var(--ease) both;
}
.bypass-box h3{
  margin-bottom:10px;
  font-family:var(--font-display);
  font-size:17px;
  font-weight:800;
  letter-spacing:.5px;
  color:var(--rose);
}
.bypass-box p{
  font-size:13px;
  line-height:1.7;
  color:#fecdd3;
  word-break:break-word;
}
.status{
  margin-top:18px;
  text-align:center;
  font-size:12.5px;
  font-weight:500;
  color:var(--text-dim);
}

@media (max-width:420px){
  .task-card{padding:20px}
  .task-head h1{font-size:18px}
  .topbar{padding:14px 16px 0}
}
`;

const MAINTENANCE_CSS = `
.maint-wrap{max-width:520px;margin:0 auto;padding:60px 20px 40px;position:relative;z-index:1}
.maint-card{
  padding:38px 28px;
  border-radius:var(--radius-xl);
  background:var(--glass-strong);
  border:1px solid var(--line-strong);
  backdrop-filter:blur(20px);
  text-align:center;
}
.maint-icon{
  width:64px;height:64px;margin:0 auto 18px;
  display:flex;align-items:center;justify-content:center;
  border-radius:50%;
}
.maint-icon.maintenance{background:linear-gradient(135deg,rgba(251,191,36,.22),rgba(251,113,133,.12));color:var(--amber)}
.maint-icon.off{background:linear-gradient(135deg,rgba(244,63,94,.22),rgba(251,113,133,.12));color:var(--rose)}
.maint-card h1{font-family:var(--font-display);font-size:22px;margin-bottom:10px}
.maint-card p{color:var(--text-dim);font-size:14px;line-height:1.7;white-space:pre-wrap}
`;

function renderMaintenancePage(status, message) {
    const isOff = status === 'off';
    const title = isOff ? 'Website tạm ngưng' : 'Đang bảo trì';
    return `<!DOCTYPE html>
<html lang="vi"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetSuper · ${title}</title>
${THEME_HEAD}
<style>${THEME_CSS}${MAINTENANCE_CSS}</style>
</head><body>
${THEME_BG}
<header class="topbar">
<a class="brand" href="/">
<span class="brand-mark">${THEME_LOGO}</span>
<span class="brand-name">ThichLenDo</span>
</a>
<span id="statusDot" class="status-dot ${isOff ? 'maintenance' : 'maintenance'}"><i></i><span id="dotTxt" data-off="${isOff ? 1 : 0}">${isOff ? 'OFF' : 'BẢO TRÌ'}</span></span>
</header>
<main class="maint-wrap">
<div class="card maint-card">
<div class="maint-icon ${isOff ? 'off' : 'maintenance'}">
<svg viewBox="0 0 24 24" width="30" height="30" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94z"/></svg>
</div>
<h1 data-i18n="${isOff ? 'offTitle' : 'maintTitle'}">${title}</h1>
<p>${message.replace(/</g,'&lt;')}</p>
</div>
<div class="hint foot-credit" style="margin-top:22px">✦ Crafted by <b>ThichLenDo</b> ✦</div>
</main>
<script>
const I18N = ${JSON.stringify(I18N_MAINT)};
${NS_DETECT_JS}
(function(){var L=nsDetectLang();var d=I18N[L]||I18N.vi;var h=document.querySelector('[data-i18n]');
if(h&&d[h.getAttribute('data-i18n')])h.textContent=d[h.getAttribute('data-i18n')];
var dt=document.getElementById('dotTxt');if(dt&&dt.getAttribute('data-off')!=='1')dt.textContent=d.maintenanceShort.toUpperCase();
document.documentElement.lang=L;document.documentElement.dir=(L==='ar'?'rtl':'ltr')})();
</script>
</body></html>`;
}

function renderTaskPage(token) {
    return `<!DOCTYPE html>
<html lang="vi"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetSuper · Task</title>
${THEME_HEAD}
<style>${THEME_CSS}${TASK_CSS}</style>
${GUIDE_CSS}
</head><body>
${THEME_BG}

<header class="topbar">
<a class="brand" href="/">
<span class="brand-mark">${THEME_LOGO}</span>
<span class="brand-name">ThichLenDo</span>
</a>
<span style="display:flex;gap:8px;align-items:center">
<span id="statusDot" class="status-dot online"><i></i>ONLINE</span>
<select id="langSel" class="pill" onchange="setLang(this.value)" aria-label="Language" style="cursor:pointer;background:transparent;color:inherit;max-width:104px"></select>
<a class="pill" href="/" data-i18n="home">← Trang chủ</a>
</span>
</header>

<main class="task-wrap">
<div class="card task-card">
<div class="task-head">
<span class="card-icon">
<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 6h11M9 12h11M9 18h11"/><path d="m3.5 6 1.2 1.2L7 4.8M3.5 12l1.2 1.2L7 10.8M3.5 18l1.2 1.2L7 16.8"/></svg>
</span>
<div>
<h1 data-i18n="taskTitle">PROCESSING TASK</h1>
<p class="card-sub" data-i18n="taskSub">Hoàn thành lần lượt từng bước bên dưới</p>
</div>
</div>
<div class="sub" id="sub" data-i18n="loading">Loading...</div>
<div class="progress" id="progress"></div>
<div id="actions"></div>
<div class="status" id="status"></div>
</div>
<div class="hint foot-credit">✦ Crafted by <b>ThichLenDo</b> ✦</div>
</main>
<script>
const token = ${JSON.stringify(token)};
const I18N = ${JSON.stringify(I18N_TASK)};
const LANG_LIST = ${JSON.stringify(LANG_LIST)};
const RTL_LANGS = ['ar'];
${NS_DETECT_JS}
let currentLang = nsDetectLang();
function t(k) { return (I18N[currentLang] && I18N[currentLang][k]) || (I18N.vi[k] || k); }
function applyLang() {
  document.documentElement.lang = currentLang;
  document.documentElement.dir = RTL_LANGS.indexOf(currentLang) > -1 ? 'rtl' : 'ltr';
  document.querySelectorAll('[data-i18n]').forEach(el => { const v = t(el.getAttribute('data-i18n')); if (v) el.textContent = v; });
  const sel = document.getElementById('langSel'); if (sel) sel.value = currentLang;
}
function setLang(l) {
  if (!I18N[l]) return;
  currentLang = l;
  try { localStorage.setItem('ns_lang', l); } catch (e) {}
  applyLang();
  if (token) refresh();
}
(function () {
  const sel = document.getElementById('langSel');
  if (!sel) return;
  LANG_LIST.forEach(p => { const o = document.createElement('option'); o.value = p[0]; o.textContent = p[1]; sel.appendChild(o); });
  sel.value = currentLang;
})();
applyLang();
let polling = null;
async function refresh() {
  if (!token) return showError(t('noToken'));
  const r = await fetch('/api/task-status?token=' + token);
  const j = await r.json();
  if (!j.ok) return showError(t('invalidTask'));
  if (j.bypassed) {
    document.getElementById('sub').innerHTML = '';
    document.getElementById('progress').innerHTML = '';
    const acts = document.getElementById('actions');
    acts.innerHTML = '<div class="bypass-box"><h3>⛔ BYPASS DETECTED</h3><p>' + j.bypassReason + '</p></div>';
    const homeBtn = document.createElement('button');
    homeBtn.className = 'homebtn'; homeBtn.textContent = t('backHome');
    homeBtn.onclick = () => location.href = '/';
    acts.appendChild(homeBtn);
    if (polling) clearInterval(polling);
    return;
  }
  const devTag = j.maxDevices > 0 ? ' · ' + j.maxDevices + ' ' + t('device') : '';
  document.getElementById('sub').innerHTML = t('duration') + ': <span class="duration-badge">' + j.duration.toUpperCase() + '</span>' + devTag + (j.isAdmin ? ' [ADMIN]' : '');
  const prog = document.getElementById('progress');
  prog.innerHTML = '';
  j.steps.forEach((type, i) => {
    const row = document.createElement('div');
    let cls = 'pending', icon = '○';
    if (i < j.completedSteps) { cls='done'; icon='✓'; }
    else if (i === j.currentStep) { cls='current'; icon='▶'; }
    row.className = 'step-row ' + cls;
    const label = type === 'link4m' ? 'Link4M (80s)' : (type === 'link999' ? 'Link999 (90s)' : 'TrafficVN (90s)');
    row.innerHTML = '<span class="step-icon">' + icon + '</span> ' + t('step') + ' ' + (i+1) + '/' + j.total + ' — ' + label;
    prog.appendChild(row);
  });
  const acts = document.getElementById('actions');
  acts.innerHTML = '';
  if (j.done) {
    const kb = document.createElement('div'); kb.id = 'keyBox'; kb.textContent = j.key;
    acts.appendChild(kb);
    const btn = document.createElement('button');
    btn.className = 'copybtn'; btn.textContent = t('copyKey');
    btn.onclick = () => { navigator.clipboard.writeText(j.key); btn.textContent=t('copied'); setTimeout(()=>btn.textContent=t('copyKey'),2000); };
    acts.appendChild(btn);
    document.getElementById('status').textContent = t('expire') + ': ' + j.keyExpire;
    if (polling) clearInterval(polling);
    return;
  }
  const btn = document.createElement('button');
  btn.textContent = t('continueStep').replace('{n}', j.currentStep + 1);
  btn.onclick = () => continueTask(btn);
  acts.appendChild(btn);
  document.getElementById('status').textContent = t('completed').replace('{a}', j.completedSteps).replace('{b}', j.total);
}
async function continueTask(btn) {
  btn.disabled = true; btn.textContent = t('loading');
  try {
    const r = await fetch('/api/continue-task?token=' + token);
    const j = await r.json();
    if (j.done) return refresh();
    if (!j.ok) { btn.textContent=t('error'); btn.disabled=false; setTimeout(refresh,2000); return; }
    location.href = j.url;
  } catch (e) { btn.textContent = t('netErr'); btn.disabled = false; }
}
function showError(m) {
  document.getElementById('sub').innerHTML = '<span style="color:#ef4444">' + m + '</span>';
  document.getElementById('progress').innerHTML = '';
  document.getElementById('actions').innerHTML = '';
  document.getElementById('status').textContent = '';
}
async function refreshStatusDot() {
  try {
    const r = await fetch('/api/site-status');
    const j = await r.json();
    const dot = document.getElementById('statusDot');
    if (!dot) return;
    if (j.status === 'online') { dot.className = 'status-dot online'; dot.innerHTML = '<i></i>ONLINE'; }
    else { dot.className = 'status-dot maintenance'; dot.innerHTML = '<i></i>' + (j.status === 'off' ? 'OFF' : t('maintenanceShort').toUpperCase()); }
  } catch (e) {}
}
refreshStatusDot();
setInterval(refreshStatusDot, 15000);
refresh();
polling = setInterval(refresh, 3000);
</script>
<script>${PROTECT_JS}</script>
${THEME_JS}
</body></html>`;
}

// ============================================
const PORT = process.env.PORT || 3000;
// ============================================
// TRANG QUẢN LÝ KEY (admin) — /amin/keys
// ============================================
const KEYS_HTML = `<!DOCTYPE html>
<html lang="vi"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Quản lý key</title>
<style>
:root{--bg:#0b0d14;--card:#141826;--line:#252b3d;--txt:#e7eaf3;--dim:#8791a6;--acc:#8b5cf6;--ok:#10b981;--bad:#ef4444;--warn:#f59e0b;--vip:#c4b5fd}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.4 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:12px 12px 90px}
.wrap{max-width:760px;margin:0 auto}
a.back{color:var(--dim);text-decoration:none;font-size:13px}
h1{font-size:18px;margin:8px 0 12px}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:12px}
.st{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:10px;text-align:center}
.st b{display:block;font-size:18px}
.st span{font-size:11px;color:var(--dim)}
input,select,button{font:inherit;color:var(--txt)}
input[type=text],input[type=number],select{width:100%;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px;outline:none}
.row{display:flex;gap:8px;margin-bottom:8px}
.row>*{flex:1}
.chips{display:flex;gap:6px;margin-bottom:8px;flex-wrap:wrap}
.chip{padding:7px 12px;border-radius:999px;border:1px solid var(--line);background:var(--card);cursor:pointer;font-size:13px}
.chip.on{background:var(--acc);border-color:var(--acc)}
.bulk{position:fixed;left:0;right:0;bottom:0;background:#10142200;backdrop-filter:blur(10px);background:rgba(16,20,34,.96);border-top:1px solid var(--line);padding:10px 12px;display:flex;gap:6px;align-items:center;flex-wrap:wrap;z-index:5}
.bulk .cnt{font-size:12px;color:var(--dim);margin-right:auto}
.btn{border:1px solid var(--line);background:var(--card);border-radius:9px;padding:8px 11px;cursor:pointer;font-size:12px}
.btn.p{background:var(--acc);border-color:var(--acc)}
.btn.d{background:rgba(239,68,68,.15);border-color:rgba(239,68,68,.5);color:#fca5a5}
.btn.w{background:rgba(245,158,11,.15);border-color:rgba(245,158,11,.5);color:#fcd34d}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:10px;margin-bottom:8px}
.card.flash{border-color:var(--ok);box-shadow:0 0 0 1px var(--ok)}
.top{display:flex;gap:8px;align-items:flex-start}
.top input[type=checkbox]{margin-top:3px;width:18px;height:18px;flex:none}
.key{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;word-break:break-all;cursor:pointer;flex:1}
.tag{font-size:10px;padding:2px 7px;border-radius:7px;margin-left:6px;vertical-align:middle;white-space:nowrap}
.tag.v{background:rgba(168,85,247,.25);color:var(--vip)}
.tag.n{background:rgba(148,163,184,.18);color:#cbd5e1}
.tag.new{background:rgba(16,185,129,.2);color:#6ee7b7}
.meta{display:flex;gap:12px;flex-wrap:wrap;font-size:12px;color:var(--dim);margin:6px 0 8px 26px}
.meta b{color:var(--txt)}
.meta .full{color:var(--bad)}
.act{display:flex;gap:6px;flex-wrap:wrap;margin-left:26px}
.det{margin:10px 0 0 26px;padding:10px;border-radius:10px;background:#0d1120;border:1px solid var(--line)}
.det label{font-size:11px;color:var(--dim);display:block;margin:6px 0 4px}
.hw{display:flex;gap:6px;align-items:center;justify-content:space-between;font-family:ui-monospace,Menlo,monospace;font-size:11px;padding:5px 0;border-bottom:1px solid var(--line);word-break:break-all}
.pager{display:flex;gap:8px;align-items:center;justify-content:center;margin:12px 0;color:var(--dim);font-size:13px}
.empty{text-align:center;color:var(--dim);padding:30px 0}
#toast{position:fixed;top:12px;left:50%;transform:translateX(-50%);background:#1c2236;border:1px solid var(--line);padding:9px 14px;border-radius:10px;font-size:13px;z-index:20;display:none;max-width:90%}
#deny{display:none;text-align:center;margin-top:60px;color:var(--bad)}
</style></head><body>
<div class="wrap">
<a class="back" href="/amin/thichlendo">← Về trang chính</a>
<h1>🔑 Quản lý key toàn server</h1>
<div id="deny">Không có quyền truy cập trang này.</div>
<div id="main" style="display:none">
<div class="stats" id="stats"></div>
<input type="text" id="q" placeholder="Tìm key...">
<div class="chips" style="margin-top:8px" id="typeChips"></div>
<div class="row">
<select id="statusSel">
<option value="all">Mọi trạng thái</option>
<option value="used">Đã có người nhập</option>
<option value="unused">Chưa ai nhập (key trắng)</option>
<option value="full">Đã đầy thiết bị</option>
<option value="soon">Sắp hết hạn (dưới 1 giờ)</option>
</select>
<select id="sortSel">
<option value="remain_desc">Còn lâu nhất</option>
<option value="remain_asc">Sắp hết hạn</option>
<option value="new">Mới tạo</option>
<option value="dev">Nhiều thiết bị nhất</option>
</select>
</div>
<div id="list"></div>
<div class="pager" id="pager"></div>
</div>
</div>
<div class="bulk" id="bulk" style="display:none">
<span class="cnt" id="selCnt"></span>
<button class="btn" id="bAll">Chọn tất cả (đã lọc)</button>
<button class="btn" id="bCopy">Copy</button>
<button class="btn" id="bTxt">Tải .txt</button>
<button class="btn w" id="bReset">Reset</button>
<button class="btn d" id="bDel">Xoá</button>
</div>
<div id="toast"></div>
<script>
var all=[],filtered=[],sel={},page=0,PER=40,clock=0;
var typeF='all',prevDev={},flashUntil={},openKey={};
function $(id){return document.getElementById(id)}
function toast(m,ok){var t=$('toast');t.textContent=m;t.style.color=ok===false?'#fca5a5':'#e7eaf3';t.style.display='block';clearTimeout(toast.h);toast.h=setTimeout(function(){t.style.display='none'},2600)}
function api(path,body){return fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})}).then(function(r){return r.json()})}
function nowMs(){return Date.now()+clock}
function pad(n){return n<10?'0'+n:''+n}
function fmt(ms){
  if(ms<=0)return 'hết hạn';
  var s=Math.floor(ms/1000),h=Math.floor(s/3600),m=Math.floor((s%3600)/60),c=s%60;
  if(h>=24){return Math.floor(h/24)+'d '+pad(h%24)+'h'}
  if(h>0)return pad(h)+'h'+pad(m)+'m'+pad(c)+'s';
  if(m>0)return pad(m)+'m'+pad(c)+'s';
  return pad(c)+'s';
}
function copyText(t){
  if(navigator.clipboard&&navigator.clipboard.writeText){return navigator.clipboard.writeText(t)}
  var a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();
  try{document.execCommand('copy')}catch(e){}
  document.body.removeChild(a);return Promise.resolve();
}
function selKeys(){return Object.keys(sel).filter(function(k){return sel[k]})}
function load(first){
  return api('/api/list-keys').then(function(j){
    if(!j.ok){if(first){$('deny').style.display='block'}return}
    $('main').style.display='block';
    clock=j.serverTime-Date.now();
    var t=Date.now();
    j.keys.forEach(function(k){
      if(prevDev[k.key]!==undefined&&k.devices>prevDev[k.key]){flashUntil[k.key]=t+30000}
      prevDev[k.key]=k.devices;
    });
    all=j.keys;
    var alive={};all.forEach(function(k){alive[k.key]=1});
    Object.keys(sel).forEach(function(k){if(!alive[k])delete sel[k]});
    apply();
  }).catch(function(){if(first){$('deny').style.display='block'}});
}
function apply(){
  var q=$('q').value.trim().toLowerCase(),st=$('statusSel').value,so=$('sortSel').value,n=nowMs();
  filtered=all.filter(function(k){
    if(k.expireAt<=n)return false;
    if(typeF==='vip'&&!k.vip)return false;
    if(typeF==='normal'&&k.vip)return false;
    if(q&&k.key.toLowerCase().indexOf(q)<0)return false;
    if(st==='used'&&k.devices<=0)return false;
    if(st==='unused'&&k.devices>0)return false;
    if(st==='full'&&!(k.maxDevices>0&&k.devices>=k.maxDevices))return false;
    if(st==='soon'&&!(k.expireAt-n<3600000))return false;
    return true;
  });
  filtered.sort(function(a,b){
    if(so==='remain_asc')return a.expireAt-b.expireAt;
    if(so==='new')return (b.createdAt||0)-(a.createdAt||0);
    if(so==='dev')return b.devices-a.devices;
    return b.expireAt-a.expireAt;
  });
  var pages=Math.max(1,Math.ceil(filtered.length/PER));
  if(page>=pages)page=pages-1;
  renderStats();renderChips();renderList();renderPager(pages);renderBulk();
}
function renderStats(){
  var vip=0,used=0,dev=0;
  all.forEach(function(k){if(k.vip)vip++;if(k.devices>0)used++;dev+=k.devices});
  var d=[['Tổng',all.length],['VIP',vip],['Thường',all.length-vip],['Đã dùng',used],['Chưa dùng',all.length-used],['Thiết bị',dev]];
  $('stats').innerHTML='';
  d.forEach(function(x){var e=document.createElement('div');e.className='st';var b=document.createElement('b');b.textContent=x[1];var s=document.createElement('span');s.textContent=x[0];e.appendChild(b);e.appendChild(s);$('stats').appendChild(e)});
}
function renderChips(){
  var box=$('typeChips');box.innerHTML='';
  [['all','Tất cả'],['vip','VIP'],['normal','Thường']].forEach(function(x){
    var c=document.createElement('div');c.className='chip'+(typeF===x[0]?' on':'');c.textContent=x[1];
    c.onclick=function(){typeF=x[0];page=0;apply()};box.appendChild(c);
  });
}
function mk(tag,cls,txt){var e=document.createElement(tag);if(cls)e.className=cls;if(txt!==undefined)e.textContent=txt;return e}
function btn(txt,cls,fn){var b=mk('button','btn '+(cls||''),txt);b.onclick=fn;return b}
function renderList(){
  var box=$('list');box.innerHTML='';
  if(!filtered.length){box.appendChild(mk('div','empty','Không có key nào'));return}
  var n=nowMs(),slice=filtered.slice(page*PER,page*PER+PER);
  slice.forEach(function(k){
    var card=mk('div','card'+(flashUntil[k.key]>Date.now()?' flash':''));
    card.setAttribute('data-key',k.key);
    var top=mk('div','top');
    var cb=document.createElement('input');cb.type='checkbox';cb.checked=!!sel[k.key];
    cb.onchange=function(){if(cb.checked)sel[k.key]=1;else delete sel[k.key];renderBulk()};
    var kd=mk('div','key',k.key);kd.title='Bấm để copy';
    kd.onclick=function(){copyText(k.key).then(function(){toast('Đã copy key')})};
    kd.appendChild(mk('span','tag '+(k.vip?'v':'n'),k.vip?'VIP':'THƯỜNG'));
    if(flashUntil[k.key]>Date.now())kd.appendChild(mk('span','tag new','vừa có người nhập'));
    top.appendChild(cb);top.appendChild(kd);card.appendChild(top);
    var meta=mk('div','meta');
    var r=mk('span');r.appendChild(document.createTextNode('Còn '));var rb=mk('b',null,fmt(k.expireAt-n));rb.className='rem';rb.setAttribute('data-exp',k.expireAt);r.appendChild(rb);meta.appendChild(r);
    var full=k.maxDevices>0&&k.devices>=k.maxDevices;
    var dv=mk('span');dv.appendChild(document.createTextNode('Thiết bị '));var db=mk('b',full?'full':null,k.devices+'/'+(k.maxDevices>0?k.maxDevices:'∞'));dv.appendChild(db);meta.appendChild(dv);
    meta.appendChild(mk('span',null,'Hết hạn: '+k.expire));
    card.appendChild(meta);
    var act=mk('div','act');
    act.appendChild(btn('Reset','w',function(){doReset([k.key])}));
    act.appendChild(btn('Xoá','d',function(){doDelete([k.key])}));
    act.appendChild(btn(openKey[k.key]?'Đóng':'⚙ Sửa','',function(){openKey[k.key]=!openKey[k.key];renderList()}));
    card.appendChild(act);
    if(openKey[k.key])card.appendChild(detail(k));
    box.appendChild(card);
  });
}
function detail(k){
  var d=mk('div','det');
  d.appendChild(mk('label',null,'Thiết bị đã nhập ('+k.devices+')'));
  if(!k.hwids||!k.hwids.length){d.appendChild(mk('div',null,'Chưa có thiết bị nào'))}
  else k.hwids.forEach(function(h){
    var r=mk('div','hw');r.appendChild(mk('span',null,h));
    r.appendChild(btn('Gỡ','d',function(){upd(k,{removeHwid:h},'Đã gỡ thiết bị')}));d.appendChild(r);
  });
  d.appendChild(mk('label',null,'Cộng thêm giờ hạn (số âm để trừ)'));
  var h=document.createElement('input');h.type='number';h.value='0';d.appendChild(h);
  d.appendChild(mk('label',null,'Số thiết bị tối đa (0 = không giới hạn)'));
  var m=document.createElement('input');m.type='number';m.min='0';m.value=k.maxDevices||0;d.appendChild(m);
  var row=mk('div','act');row.style.margin='10px 0 0';
  row.appendChild(btn('Lưu','p',function(){
    var body={};
    if(Number(h.value)!==0)body.addHours=Number(h.value);
    body.setMaxDevices=Number(m.value)||0;
    upd(k,body,'Đã lưu');
  }));
  row.appendChild(btn('+1 thiết bị','',function(){upd(k,{setMaxDevices:(k.maxDevices>0?k.maxDevices:k.devices)+1},'Đã cộng 1 thiết bị')}));
  row.appendChild(btn(k.vip?'Chuyển thành THƯỜNG':'Chuyển thành VIP','',function(){upd(k,{setVip:!k.vip},'Đã đổi loại key')}));
  d.appendChild(row);
  return d;
}
function upd(k,body,msg){
  body.key=k.key;
  api('/api/key-update',body).then(function(j){
    if(!j.ok){toast('Lỗi: '+(j.message||''),false);return}
    toast(msg);load(false);
  });
}
function doReset(keys){
  if(!confirm('Reset '+keys.length+' key? Toàn bộ thiết bị đã nhập sẽ bị gỡ, key về trạng thái trắng.'))return;
  var p=keys.length===1?api('/api/reset-key',{key:keys[0]}):api('/api/keys-bulk',{action:'reset',keys:keys});
  p.then(function(j){if(j.ok){toast('Đã reset '+(j.count||1)+' key');load(false)}else toast('Lỗi reset: '+(j.message||''),false)});
}
function doDelete(keys){
  if(!confirm('Xoá '+keys.length+' key? Không thể hoàn tác.'))return;
  var p=keys.length===1?api('/api/delete-key',{key:keys[0]}):api('/api/keys-bulk',{action:'delete',keys:keys});
  p.then(function(j){
    if(j.ok){keys.forEach(function(k){delete sel[k]});all=all.filter(function(x){return keys.indexOf(x.key)<0});toast('Đã xoá '+(j.count||keys.length)+' key');apply()}
    else toast('Lỗi xoá',false);
  });
}
function renderPager(pages){
  var p=$('pager');p.innerHTML='';
  if(pages<=1){p.appendChild(mk('span',null,filtered.length+' key'));return}
  var a=btn('‹ Trước','',function(){if(page>0){page--;renderList();renderPager(pages);window.scrollTo(0,0)}});
  var b=btn('Sau ›','',function(){if(page<pages-1){page++;renderList();renderPager(pages);window.scrollTo(0,0)}});
  p.appendChild(a);p.appendChild(mk('span',null,'Trang '+(page+1)+'/'+pages+' · '+filtered.length+' key'));p.appendChild(b);
}
function renderBulk(){
  var n=selKeys().length;
  $('bulk').style.display=(n>0||filtered.length)?'flex':'none';
  $('selCnt').textContent='Đã chọn '+n;
}
$('bAll').onclick=function(){
  var allSel=filtered.length&&filtered.every(function(k){return sel[k.key]});
  filtered.forEach(function(k){if(allSel)delete sel[k.key];else sel[k.key]=1});
  renderList();renderBulk();
};
function needSel(){var k=selKeys();if(!k.length){toast('Chưa chọn key nào',false);return null}return k}
$('bCopy').onclick=function(){var k=needSel();if(k)copyText(k.join(String.fromCharCode(10))).then(function(){toast('Đã copy '+k.length+' key')})};
$('bTxt').onclick=function(){
  var k=selKeys();if(!k.length)k=filtered.map(function(x){return x.key});
  if(!k.length){toast('Không có key',false);return}
  var blob=new Blob([k.join(String.fromCharCode(10))],{type:'text/plain'});
  var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='keys.txt';document.body.appendChild(a);a.click();document.body.removeChild(a);
};
$('bReset').onclick=function(){var k=needSel();if(k)doReset(k)};
$('bDel').onclick=function(){var k=needSel();if(k)doDelete(k)};
$('q').oninput=function(){page=0;apply()};
$('statusSel').onchange=function(){page=0;apply()};
$('sortSel').onchange=function(){page=0;apply()};
setInterval(function(){
  var n=nowMs(),expired=false;
  var els=document.querySelectorAll('.rem');
  for(var i=0;i<els.length;i++){
    var ms=Number(els[i].getAttribute('data-exp'))-n;
    els[i].textContent=fmt(ms);
    if(ms<=0)expired=true;
  }
  if(expired)apply();
},1000);
setInterval(function(){load(false)},15000);
load(true);
</script>
</body></html>
`;

// Bắt lỗi chung (body quá lớn, JSON hỏng...) — không lộ stack
app.use((err, req, res, next) => {
    const code = (err && err.status) || 400;
    if (res.headersSent) return next(err);
    res.status(code).json({ ok: false });
});

const server = app.listen(PORT, () => console.log('✅ NetSuper running on port ' + PORT));
// Chống Slowloris / giữ kết nối treo
server.headersTimeout = 15000;
server.requestTimeout = 30000;
server.keepAliveTimeout = 5000;
server.timeout = 40000;
server.maxHeadersCount = 60;

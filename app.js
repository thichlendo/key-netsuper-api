const express = require('express');
const crypto = require('crypto');
const app = express();

app.set('trust proxy', true);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============================================
// CONFIG
// ============================================
const ADMIN_IPS = ['171.237.204.101'];
const ADMIN_SERIALS = ['R9JN60KEPKJ'];
const SERVER_URL = process.env.SERVER_URL || 'https://key-netsuper-api.onrender.com';

const UPSTASH_URL = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

if (!UPSTASH_URL || !UPSTASH_TOKEN) {
    console.error('❌ Thiếu UPSTASH env');
}

const LINK4M_API_KEY = '6a61ce8626fd3a13155f6529';
const LINK4M_API_URL = 'https://link4m.co/api-shorten/v2';
const TRAFFICVN_API_KEY = 'b19399e1906b7bad23ed21c078a1edf7';
const TRAFFICVN_API_URL = 'https://trafficvn.com/apidevelop';

const DURATION_CONFIG = {
    '3h':  { hours: 3,  steps: ['link4m'] },
    '6h':  { hours: 6,  steps: ['link4m', 'trafficvn'] },
    '8h':  { hours: 8,  steps: ['link4m', 'trafficvn', 'trafficvn'] },
    '12h': { hours: 12, steps: ['link4m', 'trafficvn', 'trafficvn', 'trafficvn'] },
    '24h': { hours: 24, steps: ['link4m', 'trafficvn', 'trafficvn', 'trafficvn', 'trafficvn'] }
};

const MIN_LINK4M_MS = 80 * 1000;
const MIN_TRAFFICVN_MS = 90 * 1000;
const VALID_REFERERS = ['link4m.co','www.link4m.co','link4m.com','www.link4m.com','trafficvn.com','www.trafficvn.com'];
const BAD_UA_PATTERNS = ['curl','wget','python','okhttp','postman','insomnia','axios','node-fetch','go-http-client','java/','libwww','httpie','powershell','headlesschrome','phantomjs','selenium','puppeteer','playwright'];
const RATE_LIMIT_WINDOW = 60 * 60 * 1000;
const RATE_LIMIT_MAX = 5;

// ============================================
// REDIS — Hash (Upstash free cho phép)
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
        if (j.error) { console.error('Redis error:', j.error); return null; }
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
        if (Array.isArray(j)) {
            j.forEach((item, idx) => {
                if (item && item.error) console.error(`[Pipeline ${idx}]`, item.error);
            });
        } else if (j.error) {
            console.error('[Pipeline]', j.error);
        }
        return j;
    } catch (e) { console.error('Pipeline err:', e.message); return null; }
}

async function saveKeyToRedis(key, expireAt, hwid = '') {
    const ttl = Math.max(1, Math.ceil((expireAt - Date.now()) / 1000));
    console.log(`[SAVE] key=${key} ttl=${ttl}s expireAt=${new Date(expireAt).toISOString()}`);
    const value = JSON.stringify({ hwid, createdAt: Date.now() });
    const result = await redisPipeline([
        ['SET', `ns:key:${key}`, value, 'EX', String(ttl)],
        ['HSET', 'ns:meta', key, String(expireAt)]
    ]);
    const check = await redis('GET', `ns:key:${key}`);
    console.log(`[VERIFY] ${key} => ${check ? 'OK' : 'MISSING'}`);
    return result;
}

async function getKeyFromRedis(key) {
    const value = await redis('GET', `ns:key:${key}`);
    if (!value) return null;
    try { return JSON.parse(value); } catch (e) { return {}; }
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
function isAdminIP(req) { return ADMIN_IPS.includes(getClientIP(req)); }
function isAdmin(req) {
    const ip = getClientIP(req);
    const serial = (req.body && req.body.serial) || req.query.serial;
    return isAdminIP(req) || (serial && ADMIN_SERIALS.includes(String(serial).trim()));
}
function genToken() { return crypto.randomBytes(16).toString('hex'); }
function genKey() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const block = () => { let s=''; for(let i=0;i<4;i++) s+=chars[Math.floor(Math.random()*chars.length)]; return s; };
    return `NETSUPER-${block()}-${block()}-${block()}`;
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

    let minTime = stepType === 'link4m' ? MIN_LINK4M_MS : MIN_TRAFFICVN_MS;
    if (elapsed < minTime) {
        reasons.push(`Thời gian quá ngắn (${Math.round(elapsed/1000)}s < ${Math.round(minTime/1000)}s)`);
    }
    if (currentIP !== task.stepIP) reasons.push(`IP thay đổi`);
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

// Xác định steps dựa trên tổng giờ
function stepsForHours(h) {
    if (h >= 24) return ['link4m','trafficvn','trafficvn','trafficvn','trafficvn'];
    if (h >= 12) return ['link4m','trafficvn','trafficvn','trafficvn'];
    if (h >= 8)  return ['link4m','trafficvn','trafficvn'];
    if (h >= 6)  return ['link4m','trafficvn'];
    return ['link4m'];
}

// Generate link rút gọn cho 1 step
async function genShortLink(type, cb) {
    try {
        if (type === 'link4m') {
            const params = new URLSearchParams({ api: LINK4M_API_KEY, url: cb, format: 'json' });
            const r = await fetch(`${LINK4M_API_URL}?${params}`);
            const j = await r.json();
            if (j.status === 'success' && j.shortenedUrl) return j.shortenedUrl;
        } else {
            const params = new URLSearchParams({ api: TRAFFICVN_API_KEY, url: cb, fallback_url: cb });
            const r = await fetch(`${TRAFFICVN_API_URL}?${params}`);
            const j = await r.json();
            return j.shortenedUrl || j.short_url || j.url || null;
        }
    } catch (e) { console.error('genShortLink err:', e.message); }
    return null;
}

// Tạo task + generate tất cả link
async function createTaskWithLinks(steps, hours, presetKey, duration) {
    const token = genToken();
    const task = {
        duration: duration || 'custom',
        steps: steps.slice(),
        hours,
        currentStep: 0,
        completedSteps: 0,
        totalSteps: steps.length,
        done: false,
        key: presetKey || null,
        keyExpire: null,
        presetKey: presetKey || null,
        createdAt: Date.now(),
        isAdmin: true,
        stepStartedAt: 0, stepIP: '', stepUA: '',
        bypassed: false, bypassReason: null,
        callbackHistory: []
    };
    tasks.set(token, task);
    setTimeout(() => tasks.delete(token), 30 * 60 * 1000);

    const links = [];
    for (let i = 0; i < steps.length; i++) {
        const cb = `${SERVER_URL}/api/step-callback?token=${token}&step=${i}&r=${Date.now()}-${i}`;
        const url = await genShortLink(steps[i], cb);
        links.push({ step: i, type: steps[i], url: url || cb });
    }

    return { token, links };
}

// ============================================
// API: check-key
// ============================================
app.get('/api/check-key', async (req, res) => {
    const key = req.query.key;
    const hwid = req.query.hwid || '';
    if (!key) return res.json({ p: JSON.stringify({ ok: 0 }), s: 'x' });
    const entry = await getKeyFromRedis(key);
    if (!entry) return res.json({ p: JSON.stringify({ ok: 0 }), s: 'x' });
    if (!entry.hwid) {
        entry.hwid = hwid;
        const ttl = await redis('TTL', `ns:key:${key}`);
        if (ttl && ttl > 0) await redis('SET', `ns:key:${key}`, JSON.stringify(entry), 'EX', String(ttl));
    } else if (entry.hwid !== hwid && hwid) {
        return res.json({ p: JSON.stringify({ ok: 0 }), s: 'x' });
    }
    const ttl = await redis('TTL', `ns:key:${key}`);
    const exp = (ttl && ttl > 0) ? Math.floor((Date.now() + ttl * 1000) / 1000) : Math.floor(Date.now()/1000) + 3600;
    return res.json({ p: JSON.stringify({ ok: 1, exp }), s: 'x' });
});

// ============================================
// API: start-task (user)
// ============================================
app.post('/api/start-task', (req, res) => {
    const clientIP = getClientIP(req);
    if (isIPBlacklisted(clientIP) && !isAdminIP(req)) return res.status(429).json({ ok:false, reason:'IP blocked' });
    if (isIPRateLimited(clientIP) && !isAdminIP(req)) return res.status(429).json({ ok:false, reason:'Rate limited' });

    const { duration } = req.body;
    const config = DURATION_CONFIG[duration];
    if (!config) return res.status(400).json({ ok: false, message: 'bad_duration' });

    const token = genToken();
    tasks.set(token, {
        duration, steps: config.steps.slice(), hours: config.hours,
        currentStep: 0, completedSteps: 0, totalSteps: config.steps.length,
        done: false, key: null, keyExpire: null, presetKey: null,
        createdAt: Date.now(),
        clientIP, clientUA: req.headers['user-agent'] || '',
        isAdmin: isAdminIP(req),
        stepStartedAt: 0, stepIP: '', stepUA: '',
        bypassed: false, bypassReason: null, callbackHistory: []
    });
    logIPTask(clientIP);
    setTimeout(() => tasks.delete(token), 30 * 60 * 1000);

    return res.json({ ok: true, token, duration, totalSteps: config.steps.length, taskUrl: `${SERVER_URL}/task?token=${token}` });
});

// ============================================
// API: task-status
// ============================================
app.get('/api/task-status', (req, res) => {
    const task = tasks.get(req.query.token);
    if (!task) return res.status(404).json({ ok: false });
    return res.json({
        ok: true, duration: task.duration, progress: task.completedSteps, total: task.totalSteps,
        currentStep: task.currentStep, steps: task.steps, done: task.done,
        key: task.done ? task.key : null, keyExpire: task.keyExpire, hours: task.hours,
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
    const cb = `${SERVER_URL}/api/step-callback?token=${req.query.token}&step=${step}&r=${Date.now()}`;
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
    const { token, step } = req.query;
    const task = tasks.get(token);
    if (!task) return res.status(403).send('invalid');
    const stepNum = parseInt(step, 10);
    if (stepNum !== task.currentStep) return res.redirect(`${SERVER_URL}/task?token=${token}`);

    const cbKey = `${task.duration}-${stepNum}`;
    if (!task.callbackHistory.includes(cbKey)) task.callbackHistory.push(cbKey);
    const type = task.steps[stepNum];

    if (!task.isAdmin) {
        const check = detectBypass(req, task, type);
        if (check.bypass) {
            task.bypassed = true;
            task.bypassReason = `Bypass ${type}. ${check.reasons.join(' | ')}`;
            markIPBlacklisted(getClientIP(req));
            bypassLog.unshift({ time: vnTime(new Date()), ip: check.details.ip, ua: check.details.ua, duration: task.duration, step: stepNum+1, total: task.totalSteps, type, reasons: check.reasons, elapsed: check.details.elapsed });
            if (bypassLog.length > 100) bypassLog.pop();
            return res.redirect(`${SERVER_URL}/task?token=${token}`);
        }
    }

    task.completedSteps++;
    task.currentStep++;
    task.stepStartedAt = 0; task.stepIP = ''; task.stepUA = '';

    if (task.completedSteps >= task.totalSteps) {
        if (task.presetKey) {
            // Key đã tạo sẵn từ admin
            task.key = task.presetKey;
            const ttl = await redis('TTL', `ns:key:${task.presetKey}`);
            task.keyExpire = (ttl && ttl > 0) ? vnTime(new Date(Date.now() + ttl * 1000)) : 'N/A';
        } else {
            const key = genKey();
            const expireAt = Date.now() + task.hours * 3600 * 1000;
            await saveKeyToRedis(key, expireAt);
            task.key = key;
            task.keyExpire = vnTime(new Date(expireAt));
        }
        task.done = true;
    }

    res.redirect(`${SERVER_URL}/task?token=${token}`);
});

// ============================================
// ADMIN APIs
// ============================================
app.post('/api/verify-admin', (req, res) => {
    return res.json({ isAdmin: isAdmin(req), ip: getClientIP(req) });
});

app.post('/api/create-key', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    const { content, hours, minutes, seconds } = req.body;
    if (!content) return res.json({ ok: false });

    const ms = (Number(hours)||0)*3600000 + (Number(minutes)||0)*60000 + (Number(seconds)||0)*1000;
    if (ms <= 0) return res.json({ ok: false });

    const expireAt = Date.now() + ms;
    await saveKeyToRedis(content, expireAt);

    // Tạo task + link rút gọn
    const totalHours = ms / 3600000;
    const steps = stepsForHours(totalHours);
    const { links } = await createTaskWithLinks(steps, totalHours, content, 'custom');

    return res.json({
        ok: true,
        key: content,
        expireAt,
        expire: vnTime(new Date(expireAt)),
        links
    });
});

app.post('/api/quick-create', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    const { duration } = req.body;
    const config = DURATION_CONFIG[duration];
    if (!config) return res.json({ ok: false });

    const key = genKey();
    const durationMs = config.hours * 3600 * 1000;
    const expireAt = Date.now() + durationMs;
    await saveKeyToRedis(key, expireAt);

    const { links } = await createTaskWithLinks(config.steps, config.hours, key, duration);

    return res.json({
        ok: true,
        key,
        duration,
        hours: config.hours,
        expireAt,
        expire: vnTime(new Date(expireAt)),
        links
    });
});

app.post('/api/delete-key', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    await deleteKeyFromRedis(req.body.key);
    return res.json({ ok: true });
});

app.post('/api/list-keys', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    const list = await listKeysFromRedis();
    const out = list.map(v => ({ key: v.key, expireAt: v.expireAt, expire: vnTime(new Date(v.expireAt)), hwid: 'free' }));
    return res.json({ ok: true, keys: out });
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
app.get('/', (req, res) => res.send(MAIN_HTML));
app.get('/task', (req, res) => res.send(renderTaskPage(req.query.token || '')));

// ============================================
// HTML MAIN
// ============================================
const MAIN_HTML = `<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NETSUPER</title>
<link href="https://fonts.googleapis.com/css2?family=Sora:wght@600;700;800&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@500;600&display=swap" rel="stylesheet">
<style>
:root{--bg:#0a0d14;--bg-2:#11141d;--border:rgba(255,255,255,.08);--gold:#e3b65a;--gold-soft:#f4d998;--emerald:#2fd9a8;--violet:#8a7cff;--red:#ff5d6c;--text:#eef0f5;--text-dim:#8791a6;--text-faint:#525c72;}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',sans-serif;color:var(--text);min-height:100vh;padding:20px;background:radial-gradient(900px 480px at 50% -8%,rgba(227,182,90,.10),transparent 60%),radial-gradient(700px 400px at 100% 100%,rgba(138,124,255,.06),transparent 60%),var(--bg)}
.wrap{max-width:440px;margin:0 auto;padding-top:34px}
h1{font-family:'Sora',sans-serif;font-weight:800;font-size:27px;text-align:center;background:linear-gradient(135deg,var(--gold-soft),var(--gold) 55%,#b8862f);-webkit-background-clip:text;background-clip:text;color:transparent}
.tagline{text-align:center;color:var(--text-faint);font-size:12px;margin:6px 0 22px}
.card{background:linear-gradient(180deg,rgba(255,255,255,.035),rgba(255,255,255,.015));border:1px solid var(--border);border-radius:18px;padding:20px;margin-bottom:14px;box-shadow:0 20px 40px -22px rgba(0,0,0,.7)}
.card h2{font-family:'Sora',sans-serif;font-size:12.5px;color:var(--text-dim);letter-spacing:.4px;margin-bottom:14px;display:flex;align-items:center;gap:8px}
.card h2::before{content:'';width:6px;height:6px;border-radius:50%;background:var(--gold);box-shadow:0 0 8px var(--gold)}
button{width:100%;padding:15px;border:none;border-radius:12px;cursor:pointer;font-family:'Sora',sans-serif;font-weight:700;font-size:14px;background:linear-gradient(135deg,var(--gold-soft),var(--gold));color:#1a1204;transition:transform .15s ease,opacity .15s ease;margin-top:8px}
button:hover{transform:translateY(-1px)}
button:active{transform:translateY(0);opacity:.85}
button:disabled{background:#232838;color:var(--text-faint);cursor:not-allowed;transform:none}
.btn-purple{background:linear-gradient(135deg,#a89bff,var(--violet));color:#fff}
.btn-green{background:linear-gradient(135deg,#5eead4,var(--emerald));color:#04231b}
label{display:block;font-size:11px;color:var(--text-faint);margin:12px 0 6px}
input{width:100%;padding:12px 14px;background:var(--bg-2);border:1px solid var(--border);border-radius:10px;color:var(--text);font-size:13px;font-family:'Inter',sans-serif}
input:focus{outline:none;border-color:var(--gold);box-shadow:0 0 0 3px rgba(227,182,90,.15)}
.row{display:flex;gap:8px;margin-top:8px}
.row input{flex:1}
table{width:100%;font-size:12px;border-collapse:collapse;margin-top:10px}
th,td{padding:9px 6px;text-align:left;border-bottom:1px solid var(--border)}
th{color:var(--text-faint);font-size:10px;text-transform:uppercase}
td.k{color:var(--gold-soft);font-family:'JetBrains Mono',monospace;font-size:11px;word-break:break-all}
td.r{color:var(--emerald);font-family:'JetBrains Mono',monospace}
.del{background:rgba(255,93,108,.12);color:var(--red);border:1px solid rgba(255,93,108,.3);padding:5px 10px;border-radius:8px;cursor:pointer;width:auto;font-size:11px}
#msg{text-align:center;padding:10px;border-radius:10px;margin-top:10px;font-size:12px;display:none}
.ok{background:rgba(47,217,168,.12);color:var(--emerald);border:1px solid rgba(47,217,168,.25)}
.err{background:rgba(255,93,108,.12);color:var(--red);border:1px solid rgba(255,93,108,.25)}
#adminPanel{display:none}
#durationMenu{display:none;grid-template-columns:1fr 1fr;gap:8px;margin-top:12px}
#durationMenu button{padding:18px 10px;font-size:15px;background:var(--bg-2);color:var(--text);border:1px solid var(--border)}
#durationMenu button b{color:var(--gold-soft);display:block;font-size:19px}
#durationMenu button span{font-size:10.5px;color:var(--text-faint);display:block;margin-top:3px}
.quick-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px}
.quick-grid button{padding:14px 10px;font-size:14px;background:var(--bg-2);color:var(--text);border:1px solid var(--border);margin-top:0}
.quick-grid button b{color:var(--emerald);display:block;font-size:16px}
.quick-grid button span{font-size:10px;color:var(--text-faint);display:block;margin-top:2px}
.quick-grid button.wide{grid-column:span 2}
.section-title{font-family:'Sora',sans-serif;font-size:11px;color:var(--text-faint);letter-spacing:.6px;text-transform:uppercase;margin:18px 0 8px;display:flex;align-items:center;gap:8px}
.section-title::before,.section-title::after{content:'';flex:1;height:1px;background:var(--border)}
.result-box{background:rgba(47,217,168,.06);border:1px solid rgba(47,217,168,.3);border-radius:14px;padding:14px;margin-top:12px;display:none}
.result-box h3{color:var(--emerald);font-family:'Sora',sans-serif;font-size:13px;margin-bottom:10px}
.result-key{font-family:'JetBrains Mono',monospace;font-size:14px;color:var(--gold-soft);background:rgba(0,0,0,.3);padding:10px;border-radius:8px;margin-bottom:10px;word-break:break-all;text-align:center;font-weight:600}
.link-item{padding:10px;background:rgba(0,0,0,.3);border-radius:8px;margin-bottom:6px;font-size:12px}
.link-item .step-label{color:var(--text-faint);font-size:10px;text-transform:uppercase;margin-bottom:4px}
.link-item .step-url{color:#c7bfff;word-break:break-all;font-family:'JetBrains Mono',monospace;font-size:11px}
.link-item .step-type{display:inline-block;padding:2px 6px;border-radius:4px;font-size:9px;font-weight:600;margin-left:6px}
.type-link4m{background:rgba(138,124,255,.2);color:#c7bfff}
.type-trafficvn{background:rgba(255,183,90,.2);color:#ffb75a}
.hint{color:var(--text-faint);font-size:11px;text-align:center;margin-top:26px}
.status-badge{display:inline-flex;align-items:center;gap:5px;font-size:10px;padding:3px 8px;border-radius:10px;margin-left:8px}
.status-online{background:rgba(47,217,168,.15);color:var(--emerald);border:1px solid rgba(47,217,168,.3)}
.status-offline{background:rgba(255,93,108,.15);color:var(--red);border:1px solid rgba(255,93,108,.3)}
</style>
</head><body>
<div class="wrap">
<h1>NETSUPER</h1>
<div class="tagline">Cổng lấy key cao cấp — nhanh, an toàn, minh bạch<span id="redisBadge"></span></div>

<div class="card">
<h2>Get Key</h2>
<button class="btn-purple" onclick="toggleMenu()" id="getKeyBtn">GET KEY</button>
<div id="durationMenu">
<button onclick="startTask('3h')"><b>3H</b><span>1 link</span></button>
<button onclick="startTask('6h')"><b>6H</b><span>2 link</span></button>
<button onclick="startTask('8h')"><b>8H</b><span>3 link</span></button>
<button onclick="startTask('12h')"><b>12H</b><span>4 link</span></button>
<button onclick="startTask('24h')" style="grid-column:span 2"><b>24H</b><span>5 link</span></button>
</div>
<div id="getKeyStatus" style="display:none;text-align:center;margin-top:12px;color:#888;font-size:12px"></div>
</div>

<div class="card" id="adminPanel">
<h2>Admin Panel</h2>
<label>Key Content</label>
<input id="content" placeholder="VIP-ABC">
<label>Duration</label>
<div class="row">
<input id="h" type="number" placeholder="h" value="0">
<input id="m" type="number" placeholder="m" value="0">
<input id="s" type="number" placeholder="s" value="0">
</div>
<button class="btn-green" onclick="createKey()">CREATE KEY + GET LINKS</button>

<div class="section-title">QUICK CREATE</div>
<div class="quick-grid">
<button onclick="quickCreate('3h')"><b>3H</b><span>1 click</span></button>
<button onclick="quickCreate('6h')"><b>6H</b><span>1 click</span></button>
<button onclick="quickCreate('8h')"><b>8H</b><span>1 click</span></button>
<button onclick="quickCreate('12h')"><b>12H</b><span>1 click</span></button>
<button class="wide" onclick="quickCreate('24h')"><b>24H</b><span>1 click</span></button>
</div>

<div id="msg"></div>

<div id="resultBox" class="result-box">
<h3>✅ Key Created</h3>
<div class="result-key" id="resultKey"></div>
<div id="resultLinks"></div>
<button class="btn-purple" style="margin-top:10px" onclick="copyAllResult()">📋 COPY ALL</button>
</div>

<table id="tbl"><thead><tr><th>KEY</th><th>REMAIN</th><th>EXPIRE</th><th></th></tr></thead><tbody></tbody></table>
</div>

<div class="hint">✦ Crafted by ThichLenDo · v2.3 ✦</div>
</div>

<script>
let keysData = [];
let lastResult = null;

(async () => {
  try {
    const r = await fetch('/api/health');
    const j = await r.json();
    const badge = document.getElementById('redisBadge');
    badge.innerHTML = j.redis
      ? '<span class="status-badge status-online">● REDIS</span>'
      : '<span class="status-badge status-offline">● OFFLINE</span>';
  } catch (e) {}
})();

(async () => {
  const r = await fetch('/api/verify-admin', {method:'POST'});
  const j = await r.json();
  if (j.isAdmin) {
    document.getElementById('adminPanel').style.display = 'block';
    await syncKeys();
    setInterval(updateCountdowns, 1000);
    setInterval(syncKeys, 30000);
  }
})();

function formatCountdown(ms) {
  if (ms <= 0) return '00s';
  const s = Math.floor(ms/1000), h = Math.floor(s/3600), m = Math.floor((s%3600)/60), sec = s%60;
  const pad = n => String(n).padStart(2,'0');
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
  if (!list.length) { tb.innerHTML = '<tr><td colspan="4" style="color:#444;text-align:center">empty</td></tr>'; return; }
  tb.innerHTML = '';
  const now = Date.now();
  list.forEach(k => {
    const remain = k.expireAt - now;
    if (remain <= 0) return;
    const tr = document.createElement('tr');
    tr.setAttribute('data-key', k.key);
    tr.innerHTML = '<td class="k">'+k.key+'</td><td class="r">'+formatCountdown(remain)+'</td><td style="font-size:11px;color:#8791a6">'+k.expire+'</td>';
    const td = document.createElement('td');
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
function toggleMenu() {
  const m = document.getElementById('durationMenu');
  const btn = document.getElementById('getKeyBtn');
  if (m.style.display === 'grid') { m.style.display='none'; btn.style.display='block'; }
  else { m.style.display='grid'; btn.style.display='none'; }
}
async function startTask(duration) {
  const status = document.getElementById('getKeyStatus');
  status.style.display = 'block'; status.textContent = 'Starting...'; status.style.color = '#888';
  const r = await fetch('/api/start-task', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({duration})});
  const j = await r.json();
  if (!j.ok) { status.textContent = 'Error: ' + (j.reason || j.message); status.style.color='#ef4444'; return; }
  status.textContent = 'Opening...'; status.style.color = '#10b981';
  location.href = j.taskUrl;
}
function showMsg(t, ok) {
  const m = document.getElementById('msg');
  m.textContent = t; m.className = ok ? 'ok' : 'err';
  m.style.display = 'block';
  setTimeout(() => m.style.display = 'none', 3500);
}
function showResult(key, expire, links) {
  lastResult = { key, expire, links };
  document.getElementById('resultBox').style.display = 'block';
  document.getElementById('resultKey').textContent = key;
  const box = document.getElementById('resultLinks');
  box.innerHTML = '';
  if (links && links.length) {
    links.forEach((lnk, i) => {
      const div = document.createElement('div');
      div.className = 'link-item';
      const typeLabel = lnk.type === 'link4m' ? 'LINK4M' : 'TRAFFICVN';
      const typeCls = lnk.type === 'link4m' ? 'type-link4m' : 'type-trafficvn';
      div.innerHTML = '<div class="step-label">Step '+(i+1)+'/'+links.length+' <span class="step-type '+typeCls+'">'+typeLabel+'</span></div><div class="step-url">'+lnk.url+'</div>';
      box.appendChild(div);
    });
  } else {
    box.innerHTML = '<div style="color:#666;font-size:11px;text-align:center">No link needed</div>';
  }
}
async function createKey() {
  const content = document.getElementById('content').value.trim();
  const hours = document.getElementById('h').value || 0;
  const minutes = document.getElementById('m').value || 0;
  const seconds = document.getElementById('s').value || 0;
  if (!content) return showMsg('NO CONTENT', false);
  showMsg('Creating key + links...', true);
  const r = await fetch('/api/create-key', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({content, hours, minutes, seconds})});
  const j = await r.json();
  if (j.ok) {
    showMsg('✅ OK', true);
    showResult(j.key, j.expire, j.links || []);
    keysData.push({ key: j.key, expireAt: j.expireAt, expire: j.expire });
    renderKeysTable(keysData);
  } else showMsg('FAIL', false);
}
async function quickCreate(duration) {
  showMsg('Creating ' + duration.toUpperCase() + ' key + links...', true);
  const r = await fetch('/api/quick-create', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({duration})});
  const j = await r.json();
  if (j.ok) {
    showMsg('✅ ' + j.key, true);
    showResult(j.key, j.expire, j.links || []);
    keysData.push({ key: j.key, expireAt: j.expireAt, expire: j.expire });
    renderKeysTable(keysData);
    try { await navigator.clipboard.writeText(j.key); } catch (e) {}
  } else showMsg('FAIL: ' + (j.message || 'unknown'), false);
}
function copyAllResult() {
  if (!lastResult) return;
  let txt = '🔑 KEY: ' + lastResult.key + '\\n';
  txt += '⏱️ Expire: ' + lastResult.expire + '\\n\\n';
  if (lastResult.links && lastResult.links.length) {
    txt += '📋 STEPS:\\n';
    lastResult.links.forEach((lnk, i) => {
      txt += (i+1) + '. [' + lnk.type.toUpperCase() + '] ' + lnk.url + '\\n';
    });
  }
  navigator.clipboard.writeText(txt).then(() => showMsg('✅ Copied!', true));
}
</script>
</body></html>`;

// ============================================
// HTML TASK
// ============================================
function renderTaskPage(token) {
    return `<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Task</title>
<link href="https://fonts.googleapis.com/css2?family=Sora:wght@600;700;800&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@500;600&display=swap" rel="stylesheet">
<style>
:root{--bg:#0a0d14;--bg-2:#11141d;--border:rgba(255,255,255,.08);--gold:#e3b65a;--gold-soft:#f4d998;--emerald:#2fd9a8;--violet:#8a7cff;--red:#ff5d6c;--text:#eef0f5;--text-dim:#8791a6;--text-faint:#525c72;}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',sans-serif;color:var(--text);min-height:100vh;padding:20px;display:flex;align-items:center;justify-content:center;background:radial-gradient(900px 480px at 50% -8%,rgba(227,182,90,.10),transparent 60%),var(--bg)}
.card{background:linear-gradient(180deg,rgba(255,255,255,.035),rgba(255,255,255,.015));border:1px solid var(--border);border-radius:20px;padding:26px;max-width:440px;width:100%}
h1{font-family:'Sora',sans-serif;font-weight:800;font-size:19px;text-align:center;background:linear-gradient(135deg,var(--gold-soft),var(--gold) 55%,#b8862f);-webkit-background-clip:text;background-clip:text;color:transparent;margin-bottom:14px}
.sub{text-align:center;color:var(--text-faint);font-size:12px;margin-bottom:18px}
.progress{margin:20px 0}
.step-row{display:flex;align-items:center;margin:9px 0;padding:12px 14px;border-radius:12px;background:var(--bg-2);font-size:13px;border:1px solid var(--border)}
.step-row.done{color:var(--emerald);border-color:rgba(47,217,168,.3);background:rgba(47,217,168,.06)}
.step-row.current{color:var(--gold-soft);border-color:rgba(227,182,90,.35);background:rgba(227,182,90,.07)}
.step-row.pending{color:var(--text-faint)}
.step-icon{width:22px;margin-right:10px;text-align:center}
button{width:100%;padding:16px;border:none;border-radius:12px;cursor:pointer;margin-top:14px;font-family:'Sora',sans-serif;font-weight:700;font-size:14px;background:linear-gradient(135deg,var(--gold-soft),var(--gold));color:#1a1204}
button:disabled{background:#232838;color:var(--text-faint);cursor:not-allowed}
#keyBox{background:linear-gradient(180deg,rgba(227,182,90,.09),rgba(227,182,90,.02));border:1px solid rgba(227,182,90,.4);border-radius:14px;padding:22px;font-family:'JetBrains Mono',monospace;font-size:16px;color:var(--gold-soft);margin:20px 0;word-break:break-all;text-align:center;font-weight:600}
.copybtn{background:linear-gradient(135deg,#5eead4,var(--emerald));color:#04231b}
.status{text-align:center;color:var(--text-dim);font-size:12px;margin-top:14px}
.duration-badge{display:inline-block;background:rgba(138,124,255,.15);color:#c7bfff;padding:4px 12px;border-radius:20px;font-size:11px;font-weight:600;border:1px solid rgba(138,124,255,.3)}
.bypass-box{background:rgba(255,93,108,.08);border:1px solid rgba(255,93,108,.35);border-radius:16px;padding:22px;margin:20px 0;text-align:center}
.bypass-box h3{font-family:'Sora',sans-serif;font-size:15px;margin-bottom:10px;color:var(--red)}
.bypass-box p{font-size:12.5px;color:#ffb3ba;line-height:1.6;word-break:break-word}
.homebtn{background:linear-gradient(135deg,#a89bff,var(--violet));color:#fff}
.foot-credit{color:var(--text-faint);font-size:10.5px;text-align:center;margin-top:18px}
</style>
</head><body>
<div class="card">
<h1>PROCESSING TASK</h1>
<div class="sub" id="sub">Loading...</div>
<div class="progress" id="progress"></div>
<div id="actions"></div>
<div class="status" id="status"></div>
<div class="foot-credit">✦ ThichLenDo ✦</div>
</div>
<script>
const token = ${JSON.stringify(token)};
let polling = null;
async function refresh() {
  if (!token) return showError('No token');
  const r = await fetch('/api/task-status?token=' + token);
  const j = await r.json();
  if (!j.ok) return showError('Invalid task');
  if (j.bypassed) {
    document.getElementById('sub').innerHTML = '';
    document.getElementById('progress').innerHTML = '';
    const acts = document.getElementById('actions');
    acts.innerHTML = '<div class="bypass-box"><h3>⛔ BYPASS DETECTED</h3><p>' + j.bypassReason + '</p></div>';
    const homeBtn = document.createElement('button');
    homeBtn.className = 'homebtn'; homeBtn.textContent = '← VỀ TRANG CHỦ';
    homeBtn.onclick = () => location.href = '/';
    acts.appendChild(homeBtn);
    if (polling) clearInterval(polling);
    return;
  }
  document.getElementById('sub').innerHTML = 'Duration: <span class="duration-badge">' + j.duration.toUpperCase() + '</span>' + (j.isAdmin ? ' [ADMIN]' : '');
  const prog = document.getElementById('progress');
  prog.innerHTML = '';
  j.steps.forEach((type, i) => {
    const row = document.createElement('div');
    let cls = 'pending', icon = '○';
    if (i < j.completedSteps) { cls='done'; icon='✓'; }
    else if (i === j.currentStep) { cls='current'; icon='▶'; }
    row.className = 'step-row ' + cls;
    const label = type === 'link4m' ? 'Link4M (80s)' : 'TrafficVN (90s)';
    row.innerHTML = '<span class="step-icon">' + icon + '</span> Step ' + (i+1) + '/' + j.total + ' — ' + label;
    prog.appendChild(row);
  });
  const acts = document.getElementById('actions');
  acts.innerHTML = '';
  if (j.done) {
    const kb = document.createElement('div'); kb.id = 'keyBox'; kb.textContent = j.key;
    acts.appendChild(kb);
    const btn = document.createElement('button');
    btn.className = 'copybtn'; btn.textContent = 'COPY KEY';
    btn.onclick = () => { navigator.clipboard.writeText(j.key); btn.textContent='✓ COPIED!'; setTimeout(()=>btn.textContent='COPY KEY',2000); };
    acts.appendChild(btn);
    document.getElementById('status').textContent = 'Expire: ' + j.keyExpire;
    if (polling) clearInterval(polling);
    return;
  }
  const btn = document.createElement('button');
  btn.textContent = 'CONTINUE STEP ' + (j.currentStep + 1) + ' →';
  btn.onclick = () => continueTask(btn);
  acts.appendChild(btn);
  document.getElementById('status').textContent = 'Completed ' + j.completedSteps + '/' + j.total;
}
async function continueTask(btn) {
  btn.disabled = true; btn.textContent = 'Loading...';
  try {
    const r = await fetch('/api/continue-task?token=' + token);
    const j = await r.json();
    if (j.done) return refresh();
    if (!j.ok) { btn.textContent='Error'; btn.disabled=false; setTimeout(refresh,2000); return; }
    location.href = j.url;
  } catch (e) { btn.textContent = 'Network error'; btn.disabled = false; }
}
function showError(t) {
  document.getElementById('sub').innerHTML = '<span style="color:#ef4444">' + t + '</span>';
  document.getElementById('progress').innerHTML = '';
  document.getElementById('actions').innerHTML = '';
  document.getElementById('status').textContent = '';
}
refresh();
polling = setInterval(refresh, 3000);
</script>
</body></html>`;
}

// ============================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('✅ Server running on port ' + PORT));

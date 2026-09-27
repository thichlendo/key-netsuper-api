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

// ⭐ Upstash Redis
const UPSTASH_URL = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

if (!UPSTASH_URL || !UPSTASH_TOKEN) {
    console.error('❌ Thiếu UPSTASH_REDIS_REST_URL hoặc UPSTASH_REDIS_REST_TOKEN');
}

// Link4M
const LINK4M_API_KEY = '6a61ce8626fd3a13155f6529';
const LINK4M_API_URL = 'https://link4m.co/api-shorten/v2';

// TrafficVN
const TRAFFICVN_API_KEY = 'b19399e1906b7bad23ed21c078a1edf7';
const TRAFFICVN_API_URL = 'https://trafficvn.com/apidevelop';

// Duration config
const DURATION_CONFIG = {
    '3h':  { hours: 3,  steps: ['link4m'] },
    '6h':  { hours: 6,  steps: ['link4m', 'trafficvn'] },
    '8h':  { hours: 8,  steps: ['link4m', 'trafficvn', 'trafficvn'] },
    '12h': { hours: 12, steps: ['link4m', 'trafficvn', 'trafficvn', 'trafficvn'] },
    '24h': { hours: 24, steps: ['link4m', 'trafficvn', 'trafficvn', 'trafficvn', 'trafficvn'] }
};

// Anti-bypass
const MIN_LINK4M_MS = 80 * 1000;
const MIN_TRAFFICVN_MS = 90 * 1000;
const VALID_REFERERS = [
    'link4m.co', 'www.link4m.co', 'link4m.com', 'www.link4m.com',
    'trafficvn.com', 'www.trafficvn.com'
];
const BAD_UA_PATTERNS = [
    'curl', 'wget', 'python', 'python-requests', 'python-urllib',
    'okhttp', 'postman', 'insomnia', 'axios', 'node-fetch',
    'go-http-client', 'java/', 'libwww', 'httpie', 'powershell',
    'headlesschrome', 'phantomjs', 'selenium', 'puppeteer', 'playwright'
];
const RATE_LIMIT_WINDOW = 60 * 60 * 1000;
const RATE_LIMIT_MAX = 5;

// ============================================
// UPSTASH REDIS HELPERS
// ============================================
async function redis(...args) {
    if (!UPSTASH_URL || !UPSTASH_TOKEN) return null;
    try {
        const r = await fetch(UPSTASH_URL, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${UPSTASH_TOKEN}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(args)
        });
        const j = await r.json();
        if (j.error) {
            console.error('Redis error:', j.error);
            return null;
        }
        return j.result;
    } catch (e) {
        console.error('Redis fetch error:', e.message);
        return null;
    }
}

async function redisPipeline(commands) {
    if (!UPSTASH_URL || !UPSTASH_TOKEN) return null;
    try {
        const r = await fetch(`${UPSTASH_URL}/pipeline`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${UPSTASH_TOKEN}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(commands)
        });
        const j = await r.json();
        return j;
    } catch (e) {
        console.error('Redis pipeline error:', e.message);
        return null;
    }
}

// 💾 Lưu key vào Redis với TTL tự động
async function saveKeyToRedis(key, expireAt, hwid = '') {
    const ttl = Math.max(1, Math.ceil((expireAt - Date.now()) / 1000));
    const value = JSON.stringify({ hwid, createdAt: Date.now() });
    return await redisPipeline([
        ['SET', `ns:key:${key}`, value, 'EX', String(ttl)],
        ['ZADD', 'ns:keys', String(expireAt), key]
    ]);
}

async function getKeyFromRedis(key) {
    const value = await redis('GET', `ns:key:${key}`);
    if (!value) return null;
    try {
        return JSON.parse(value);
    } catch (e) {
        return {};
    }
}

async function deleteKeyFromRedis(key) {
    return await redisPipeline([
        ['DEL', `ns:key:${key}`],
        ['ZREM', 'ns:keys', key]
    ]);
}

async function listKeysFromRedis() {
    const now = Date.now();

    // 1) Clean expired
    await redis('ZREMRANGEBYSCORE', 'ns:keys', '-inf', `(${now}`);

    // 2) Get valid keys
    const raw = await redis('ZRANGEBYSCORE', 'ns:keys', `(${now}`, '+inf', 'WITHSCORES');
    if (!raw || !Array.isArray(raw) || raw.length === 0) return [];

    const keys = [];
    const scores = [];
    for (let i = 0; i < raw.length; i += 2) {
        keys.push(raw[i]);
        scores.push(parseInt(raw[i + 1], 10));
    }

    // 3) Batch GET values
    const commands = keys.map(k => ['GET', `ns:key:${k}`]);
    const values = await redisPipeline(commands);

    return keys.map((key, i) => {
        let hwid = 'free';
        try {
            const v = values && values[i] ? values[i].result : null;
            const parsed = JSON.parse(v || '{}');
            hwid = parsed.hwid || 'free';
        } catch (e) {}
        return { key, expireAt: scores[i], hwid };
    });
}

// ============================================
// STORAGE IN RAM (tạm thời — không cần persist)
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

function isAdminIP(req) {
    return ADMIN_IPS.includes(getClientIP(req));
}

function isAdmin(req) {
    const ip = getClientIP(req);
    const serial = (req.body && req.body.serial) || req.query.serial;
    return isAdminIP(req) || (serial && ADMIN_SERIALS.includes(String(serial).trim()));
}

function genToken() {
    return crypto.randomBytes(16).toString('hex');
}

function genKey() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const block = () => {
        let s = '';
        for (let i = 0; i < 4; i++) s += chars[Math.floor(Math.random() * chars.length)];
        return s;
    };
    return `NETSUPER-${block()}-${block()}-${block()}`;
}

function isRefererValid(referer) {
    if (!referer) return false;
    try {
        const url = new URL(referer);
        const host = url.hostname.toLowerCase();
        return VALID_REFERERS.includes(host);
    } catch (e) {
        return false;
    }
}

function isIPRateLimited(ip) {
    const now = Date.now();
    const log = ipTaskLog.get(ip) || [];
    const recent = log.filter(t => now - t < RATE_LIMIT_WINDOW);
    return recent.length >= RATE_LIMIT_MAX;
}

function logIPTask(ip) {
    const now = Date.now();
    const log = ipTaskLog.get(ip) || [];
    log.push(now);
    if (log.length > 100) log.shift();
    ipTaskLog.set(ip, log);
}

function markIPBlacklisted(ip) {
    const entry = ipBlacklist.get(ip) || { count: 0, until: 0 };
    entry.count++;
    if (entry.count >= 3) {
        entry.until = Date.now() + 24 * 3600 * 1000;
    }
    ipBlacklist.set(ip, entry);
}

function isIPBlacklisted(ip) {
    const entry = ipBlacklist.get(ip);
    if (!entry) return false;
    if (entry.until > Date.now()) return true;
    if (entry.until > 0 && entry.until <= Date.now()) {
        ipBlacklist.delete(ip);
    }
    return false;
}

// ============================================
// ANTI-BYPASS DETECTOR
// ============================================
function detectBypass(req, task, stepType) {
    const reasons = [];
    const currentIP = getClientIP(req);
    const currentUA = req.headers['user-agent'] || '';
    const currentReferer = req.headers['referer'] || req.headers['referrer'] || '';
    const elapsed = Date.now() - task.stepStartedAt;

    let minTime = 0;
    if (stepType === 'link4m') minTime = MIN_LINK4M_MS;
    else if (stepType === 'trafficvn') minTime = MIN_TRAFFICVN_MS;

    if (elapsed < minTime) {
        const required = Math.round(minTime / 1000);
        const actual = Math.round(elapsed / 1000);
        reasons.push(`Thời gian quá ngắn (${actual}s < ${required}s)`);
    }

    if (currentIP !== task.stepIP) {
        reasons.push(`IP thay đổi (${task.stepIP} → ${currentIP})`);
    }

    const uaLower = currentUA.toLowerCase();
    if (!currentUA) {
        reasons.push('Thiếu User-Agent');
    } else {
        for (const bad of BAD_UA_PATTERNS) {
            if (uaLower.includes(bad)) {
                reasons.push(`User-Agent bị chặn (${bad})`);
                break;
            }
        }
        if (!uaLower.includes('mozilla') && !uaLower.includes('chrome') && !uaLower.includes('safari') && !uaLower.includes('firefox')) {
            reasons.push('User-Agent không phải trình duyệt');
        }
    }

    if (!currentReferer) {
        reasons.push('Thiếu Referer (không qua link)');
    } else if (!isRefererValid(currentReferer)) {
        reasons.push(`Referer không hợp lệ (${currentReferer.substring(0, 60)})`);
    }

    const callbackKey = `${task.duration}-${task.currentStep}`;
    if (task.callbackHistory && task.callbackHistory.includes(callbackKey)) {
        reasons.push('Token đã được dùng (replay detected)');
    }

    return {
        bypass: reasons.length > 0,
        reasons: reasons,
        details: {
            elapsed: Math.round(elapsed / 1000) + 's',
            ip: currentIP,
            expectedIP: task.stepIP,
            ua: currentUA.substring(0, 100)
        }
    };
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

    // HWID bind
    if (!entry.hwid) {
        entry.hwid = hwid;
        const ttl = await redis('TTL', `ns:key:${key}`);
        if (ttl && ttl > 0) {
            await redis('SET', `ns:key:${key}`, JSON.stringify(entry), 'EX', String(ttl));
        }
    } else if (entry.hwid !== hwid && hwid) {
        return res.json({ p: JSON.stringify({ ok: 0 }), s: 'x' });
    }

    const score = await redis('ZSCORE', 'ns:keys', key);
    const exp = score
        ? Math.floor(parseInt(score, 10) / 1000)
        : Math.floor(Date.now() / 1000) + 3600;

    return res.json({ p: JSON.stringify({ ok: 1, exp }), s: 'x' });
});

// ============================================
// API: start-task
// ============================================
app.post('/api/start-task', (req, res) => {
    const clientIP = getClientIP(req);

    if (isIPBlacklisted(clientIP) && !isAdminIP(req)) {
        return res.status(429).json({
            ok: false,
            message: 'ip_blocked',
            reason: 'IP đã bị chặn do bypass nhiều lần'
        });
    }

    if (isIPRateLimited(clientIP) && !isAdminIP(req)) {
        return res.status(429).json({
            ok: false,
            message: 'rate_limited',
            reason: 'Quá nhiều task. Chờ 1 giờ.'
        });
    }

    const { duration } = req.body;
    const config = DURATION_CONFIG[duration];
    if (!config) return res.status(400).json({ ok: false, message: 'bad_duration' });

    const token = genToken();
    const userAgent = req.headers['user-agent'] || '';

    tasks.set(token, {
        duration,
        steps: config.steps.slice(),
        hours: config.hours,
        currentStep: 0,
        completedSteps: 0,
        totalSteps: config.steps.length,
        done: false,
        key: null,
        keyExpire: null,
        createdAt: Date.now(),
        clientIP: clientIP,
        clientUA: userAgent,
        isAdmin: isAdminIP(req),
        stepStartedAt: 0,
        stepIP: '',
        stepUA: '',
        bypassed: false,
        bypassReason: null,
        callbackHistory: []
    });

    logIPTask(clientIP);
    setTimeout(() => tasks.delete(token), 30 * 60 * 1000);

    return res.json({
        ok: true,
        token,
        duration,
        totalSteps: config.steps.length,
        taskUrl: `${SERVER_URL}/task?token=${token}`
    });
});

// ============================================
// API: task-status
// ============================================
app.get('/api/task-status', (req, res) => {
    const { token } = req.query;
    const task = tasks.get(token);
    if (!task) return res.status(404).json({ ok: false });

    return res.json({
        ok: true,
        duration: task.duration,
        progress: task.completedSteps,
        total: task.totalSteps,
        currentStep: task.currentStep,
        steps: task.steps,
        done: task.done,
        key: task.done ? task.key : null,
        keyExpire: task.keyExpire,
        hours: task.hours,
        bypassed: task.bypassed,
        bypassReason: task.bypassReason,
        isAdmin: task.isAdmin
    });
});

// ============================================
// API: continue-task
// ============================================
app.get('/api/continue-task', async (req, res) => {
    const { token } = req.query;
    const task = tasks.get(token);
    if (!task) return res.status(403).json({ ok: false, message: 'invalid' });
    if (task.done) return res.json({ ok: true, done: true, key: task.key });
    if (task.bypassed) return res.json({ ok: false, message: 'bypassed' });

    const step = task.currentStep;
    if (step >= task.steps.length) return res.json({ ok: false, message: 'all_steps_done' });

    const type = task.steps[step];
    const cb = `${SERVER_URL}/api/step-callback?token=${token}&step=${step}&r=${Date.now()}`;

    task.stepStartedAt = Date.now();
    task.stepIP = getClientIP(req);
    task.stepUA = req.headers['user-agent'] || '';

    try {
        let shortUrl = null;
        let raw = null;

        if (type === 'link4m') {
            const params = new URLSearchParams({
                api: LINK4M_API_KEY,
                url: cb,
                format: 'json'
            });
            const r = await fetch(`${LINK4M_API_URL}?${params.toString()}`);
            raw = await r.json();

            if (raw.status === 'success' && raw.shortenedUrl) {
                shortUrl = raw.shortenedUrl;
            } else {
                return res.json({ ok: false, message: 'link4m_error', raw });
            }

        } else if (type === 'trafficvn') {
            const params = new URLSearchParams({
                api: TRAFFICVN_API_KEY,
                url: cb,
                fallback_url: cb
            });
            const r = await fetch(`${TRAFFICVN_API_URL}?${params.toString()}`);
            raw = await r.json();

            shortUrl = raw.shortenedUrl || raw.short_url || raw.url;

            if (!shortUrl) {
                return res.json({ ok: false, message: 'trafficvn_error', raw });
            }

        } else {
            return res.json({ ok: false, message: 'unknown_step_type' });
        }

        return res.json({
            ok: true,
            url: shortUrl,
            step,
            total: task.totalSteps,
            type
        });

    } catch (e) {
        return res.json({ ok: false, message: 'network_error', error: String(e) });
    }
});

// ============================================
// API: step-callback
// ============================================
app.get('/api/step-callback', async (req, res) => {
    const { token, step } = req.query;
    const task = tasks.get(token);
    if (!task) return res.status(403).send('invalid');

    const stepNum = parseInt(step, 10);
    if (stepNum !== task.currentStep) {
        return res.redirect(`${SERVER_URL}/task?token=${token}`);
    }

    const cbKey = `${task.duration}-${stepNum}`;
    if (!task.callbackHistory.includes(cbKey)) {
        task.callbackHistory.push(cbKey);
    }

    const type = task.steps[stepNum];

    if (!task.isAdmin) {
        const check = detectBypass(req, task, type);

        if (check.bypass) {
            task.bypassed = true;
            const label = type === 'link4m' ? 'Link4M' : 'TrafficVN';
            task.bypassReason = `Bypass link ${label}. Chi tiết: ${check.reasons.join(' | ')}`;

            markIPBlacklisted(getClientIP(req));

            bypassLog.unshift({
                time: vnTime(new Date()),
                ip: check.details.ip,
                ua: check.details.ua,
                duration: task.duration,
                step: stepNum + 1,
                total: task.totalSteps,
                type,
                reasons: check.reasons,
                elapsed: check.details.elapsed
            });
            if (bypassLog.length > 100) bypassLog.pop();

            return res.redirect(`${SERVER_URL}/task?token=${token}`);
        }
    }

    task.completedSteps++;
    task.currentStep++;
    task.stepStartedAt = 0;
    task.stepIP = '';
    task.stepUA = '';

    if (task.completedSteps >= task.totalSteps) {
        const key = genKey();
        const duration = task.hours * 3600 * 1000;
        const expireAt = Date.now() + duration;

        // ⭐ Lưu vào Redis (không mất khi deploy)
        await saveKeyToRedis(key, expireAt);

        task.key = key;
        task.keyExpire = vnTime(new Date(expireAt));
        task.done = true;
    }

    res.redirect(`${SERVER_URL}/task?token=${token}`);
});

// ============================================
// API: verify-admin
// ============================================
app.post('/api/verify-admin', (req, res) => {
    return res.json({ isAdmin: isAdmin(req), ip: getClientIP(req) });
});

// ============================================
// API ADMIN
// ============================================
app.post('/api/create-key', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    const { content, hours, minutes, seconds } = req.body;
    if (!content) return res.json({ ok: false });

    const ms = (Number(hours)||0)*3600000 + (Number(minutes)||0)*60000 + (Number(seconds)||0)*1000;
    if (ms <= 0) return res.json({ ok: false });

    const expireAt = Date.now() + ms;
    await saveKeyToRedis(content, expireAt);

    return res.json({
        ok: true,
        key: content,
        expireAt: expireAt,
        expire: vnTime(new Date(expireAt))
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
    const out = list.map(v => ({
        key: v.key,
        expireAt: v.expireAt,
        expire: vnTime(new Date(v.expireAt)),
        hwid: v.hwid || 'free'
    }));
    return res.json({ ok: true, keys: out });
});

app.post('/api/bypass-log', (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    return res.json({ ok: true, logs: bypassLog.slice(0, 50) });
});

app.post('/api/blacklist', (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    const out = [];
    for (const [ip, entry] of ipBlacklist) {
        out.push({
            ip,
            count: entry.count,
            blocked: entry.until > Date.now(),
            until: entry.until > 0 ? vnTime(new Date(entry.until)) : '-'
        });
    }
    return res.json({ ok: true, list: out });
});

app.post('/api/unblock-ip', (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    ipBlacklist.delete(req.body.ip);
    return res.json({ ok: true });
});

// Health check
app.get('/api/health', async (req, res) => {
    const ping = await redis('PING');
    res.json({ ok: true, redis: ping === 'PONG' });
});

// ============================================
// ROUTES
// ============================================
app.get('/', (req, res) => res.send(MAIN_HTML));

app.get('/task', (req, res) => {
    const token = req.query.token || '';
    res.send(renderTaskPage(token));
});

// ============================================
// HTML: MAIN PAGE
// ============================================
const MAIN_HTML = `<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NETSUPER</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ctext y='.9em' font-size='90'%3E%F0%9F%92%8E%3C/text%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Sora:wght@600;700;800&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@500;600&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#0a0d14; --bg-2:#11141d; --border:rgba(255,255,255,.08);
  --gold:#e3b65a; --gold-soft:#f4d998; --emerald:#2fd9a8; --violet:#8a7cff; --red:#ff5d6c;
  --text:#eef0f5; --text-dim:#8791a6; --text-faint:#525c72;
}
*{box-sizing:border-box;margin:0;padding:0}
body{
  font-family:'Inter',sans-serif;color:var(--text);min-height:100vh;padding:20px;
  background:
    radial-gradient(900px 480px at 50% -8%, rgba(227,182,90,.10), transparent 60%),
    radial-gradient(700px 400px at 100% 100%, rgba(138,124,255,.06), transparent 60%),
    var(--bg);
}
.wrap{max-width:440px;margin:0 auto;padding-top:34px}
h1{
  font-family:'Sora',sans-serif;font-weight:800;font-size:27px;text-align:center;letter-spacing:.3px;
  background:linear-gradient(135deg,var(--gold-soft),var(--gold) 55%,#b8862f);
  -webkit-background-clip:text;background-clip:text;color:transparent;
}
.tagline{text-align:center;color:var(--text-faint);font-size:12px;margin:6px 0 22px;font-weight:500}
.card{
  background:linear-gradient(180deg,rgba(255,255,255,.035),rgba(255,255,255,.015));
  border:1px solid var(--border);border-radius:18px;padding:20px;margin-bottom:14px;
  box-shadow:0 20px 40px -22px rgba(0,0,0,.7);
  animation:rise .5s cubic-bezier(.16,1,.3,1) both;
}
@keyframes rise{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
.card h2{
  font-family:'Sora',sans-serif;font-size:12.5px;font-weight:600;color:var(--text-dim);
  letter-spacing:.4px;margin-bottom:14px;display:flex;align-items:center;gap:8px;
}
.card h2::before{content:'';width:6px;height:6px;border-radius:50%;background:var(--gold);box-shadow:0 0 8px var(--gold)}
button{
  width:100%;padding:15px;border:none;border-radius:12px;cursor:pointer;
  font-family:'Sora',sans-serif;font-weight:700;font-size:14px;
  background:linear-gradient(135deg,var(--gold-soft),var(--gold));color:#1a1204;
  box-shadow:0 10px 24px -10px rgba(227,182,90,.55);
  transition:transform .15s ease,opacity .15s ease;
}
button:hover{transform:translateY(-1px)}
button:active{transform:translateY(0);opacity:.85}
button:disabled{background:#232838;color:var(--text-faint);box-shadow:none;cursor:not-allowed;transform:none}
.btn-purple{background:linear-gradient(135deg,#a89bff,var(--violet));color:#fff;box-shadow:0 10px 24px -10px rgba(138,124,255,.5)}
.btn-green{background:linear-gradient(135deg,#5eead4,var(--emerald));color:#04231b;box-shadow:0 10px 24px -10px rgba(47,217,168,.5)}
label{display:block;font-size:11px;color:var(--text-faint);margin:12px 0 6px;font-weight:500}
input{
  width:100%;padding:12px 14px;background:var(--bg-2);border:1px solid var(--border);
  border-radius:10px;color:var(--text);font-family:'Inter',sans-serif;font-size:13px;
  transition:border-color .15s ease,box-shadow .15s ease;
}
input:focus{outline:none;border-color:var(--gold);box-shadow:0 0 0 3px rgba(227,182,90,.15)}
.row{display:flex;gap:8px;margin-top:8px}
.row input{flex:1}
table{width:100%;font-size:12px;border-collapse:collapse;margin-top:10px}
th,td{padding:9px 6px;text-align:left;border-bottom:1px solid var(--border)}
th{color:var(--text-faint);font-weight:600;font-size:10px;letter-spacing:.3px}
td.k{color:var(--gold-soft);font-family:'JetBrains Mono',monospace;font-size:11px;word-break:break-all}
td.r{color:var(--emerald);font-family:'JetBrains Mono',monospace;font-variant-numeric:tabular-nums}
.del{background:rgba(255,93,108,.12);color:var(--red);border:1px solid rgba(255,93,108,.3);padding:5px 10px;border-radius:8px;cursor:pointer;width:auto;font-size:11px;margin:0}
.del:hover{background:rgba(255,93,108,.2)}
#msg{text-align:center;padding:10px;border-radius:10px;margin-top:10px;font-size:12px;display:none;font-weight:500}
.ok{background:rgba(47,217,168,.12);color:var(--emerald);border:1px solid rgba(47,217,168,.25)}
.err{background:rgba(255,93,108,.12);color:var(--red);border:1px solid rgba(255,93,108,.25)}
#adminPanel{display:none}
#durationMenu{display:none;grid-template-columns:1fr 1fr;gap:8px;margin-top:12px}
#durationMenu button{padding:18px 10px;font-size:15px;background:var(--bg-2);color:var(--text);border:1px solid var(--border);box-shadow:none}
#durationMenu button:hover{border-color:var(--gold);background:rgba(227,182,90,.06)}
#durationMenu button b{font-family:'Sora',sans-serif;color:var(--gold-soft);display:block;font-size:19px}
#durationMenu button span{font-size:10.5px;color:var(--text-faint);display:block;margin-top:3px}
.hint{color:var(--text-faint);font-size:11px;text-align:center;margin-top:26px;letter-spacing:.3px}
.log-item{background:var(--bg-2);border:1px solid var(--border);border-radius:10px;padding:10px;margin:6px 0;font-size:11px;font-family:'JetBrains Mono',monospace}
.log-item .bad{color:var(--red);font-weight:600}
.log-item .meta{color:var(--text-faint);margin-top:4px;font-size:10px}
.row-expiring{animation:fadeOut 1s ease forwards}
@keyframes fadeOut{to{opacity:0;transform:translateX(-10px)}}
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
<button class="btn-green" onclick="createKey()">CREATE KEY</button>
<div id="msg"></div>
<table id="tbl"><thead><tr><th>KEY</th><th>REMAIN</th><th>EXPIRE</th><th></th></tr></thead><tbody></tbody></table>
</div>

<div class="card" id="bypassLogPanel" style="display:none">
<h2>Bypass Log</h2>
<div id="bypassLogList"></div>
</div>

<div class="hint">✦ Crafted by ThichLenDo · v2.0 (Redis) ✦</div>
</div>

<script>
let keysData = [];
let countdownTimer = null;
let syncTimer = null;

// Health check
(async () => {
  try {
    const r = await fetch('/api/health');
    const j = await r.json();
    const badge = document.getElementById('redisBadge');
    if (j.redis) {
      badge.innerHTML = '<span class="status-badge status-online">● REDIS</span>';
    } else {
      badge.innerHTML = '<span class="status-badge status-offline">● OFFLINE</span>';
    }
  } catch (e) {}
})();

// Verify admin
(async () => {
  const r = await fetch('/api/verify-admin', {method:'POST'});
  const j = await r.json();
  if (j.isAdmin) {
    document.getElementById('adminPanel').style.display = 'block';
    document.getElementById('bypassLogPanel').style.display = 'block';
    await syncKeys();
    loadBypassLog();
    countdownTimer = setInterval(updateCountdowns, 1000);
    syncTimer = setInterval(syncKeys, 30000);
    setInterval(loadBypassLog, 15000);
  }
})();

function formatCountdown(ms) {
  if (ms <= 0) return '00s';
  const totalSec = Math.floor(ms / 1000);
  const h = Math.floor(totalSec / 3600);
  const m = Math.floor((totalSec % 3600) / 60);
  const s = totalSec % 60;
  const pad = n => String(n).padStart(2, '0');
  if (h > 0) return pad(h) + 'h' + pad(m) + 'm' + pad(s) + 's';
  if (m > 0) return pad(m) + 'm' + pad(s) + 's';
  return pad(s) + 's';
}

function updateCountdowns() {
  const now = Date.now();
  const tb = document.querySelector('#tbl tbody');
  if (!tb) return;

  const rows = tb.querySelectorAll('tr[data-key]');
  rows.forEach(row => {
    const key = row.getAttribute('data-key');
    const entry = keysData.find(k => k.key === key);
    if (!entry) return;

    const remain = entry.expireAt - now;
    const remainCell = row.querySelector('.r');

    if (remain <= 0) {
      if (!row.classList.contains('row-expiring')) {
        row.classList.add('row-expiring');
        remainCell.textContent = '00s';
        setTimeout(() => {
          row.remove();
          keysData = keysData.filter(k => k.key !== key);
          if (keysData.length === 0) renderKeysTable([]);
        }, 1000);
      }
      return;
    }

    remainCell.textContent = formatCountdown(remain);
  });
}

async function syncKeys() {
  try {
    const r = await fetch('/api/list-keys', {method:'POST'});
    const j = await r.json();
    if (!j.ok) return;
    keysData = j.keys;
    renderKeysTable(keysData);
  } catch (e) {
    console.error('sync error', e);
  }
}

function renderKeysTable(list) {
  const tb = document.querySelector('#tbl tbody');
  if (!tb) return;

  if (!list.length) {
    tb.innerHTML = '<tr><td colspan="4" style="color:#444;text-align:center">empty</td></tr>';
    return;
  }

  tb.innerHTML = '';
  const now = Date.now();

  list.forEach(k => {
    const remain = k.expireAt - now;
    if (remain <= 0) return;

    const tr = document.createElement('tr');
    tr.setAttribute('data-key', k.key);

    const tdKey = document.createElement('td');
    tdKey.className = 'k';
    tdKey.textContent = k.key;

    const tdRemain = document.createElement('td');
    tdRemain.className = 'r';
    tdRemain.textContent = formatCountdown(remain);

    const tdExpire = document.createElement('td');
    tdExpire.style.fontSize = '11px';
    tdExpire.style.color = '#8791a6';
    tdExpire.textContent = k.expire;

    const tdDel = document.createElement('td');
    const btn = document.createElement('button');
    btn.className = 'del';
    btn.textContent = 'X';
    btn.onclick = async () => {
      await fetch('/api/delete-key', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({key: k.key})
      });
      keysData = keysData.filter(x => x.key !== k.key);
      renderKeysTable(keysData);
    };
    tdDel.appendChild(btn);

    tr.appendChild(tdKey);
    tr.appendChild(tdRemain);
    tr.appendChild(tdExpire);
    tr.appendChild(tdDel);
    tb.appendChild(tr);
  });
}

function toggleMenu() {
  const m = document.getElementById('durationMenu');
  const btn = document.getElementById('getKeyBtn');
  if (m.style.display === 'grid') {
    m.style.display = 'none';
    btn.style.display = 'block';
  } else {
    m.style.display = 'grid';
    btn.style.display = 'none';
  }
}

async function startTask(duration) {
  const status = document.getElementById('getKeyStatus');
  status.style.display = 'block';
  status.textContent = 'Starting...';
  status.style.color = '#888';

  const r = await fetch('/api/start-task', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({duration})
  });
  const j = await r.json();

  if (!j.ok) {
    status.textContent = 'Error: ' + (j.reason || j.message || 'unknown');
    status.style.color = '#ef4444';
    return;
  }

  status.textContent = 'Opening ' + duration + ' task (' + j.totalSteps + ' steps)...';
  status.style.color = '#10b981';

  location.href = j.taskUrl;
}

function showMsg(t, ok) {
  const m = document.getElementById('msg');
  m.textContent = t;
  m.className = ok ? 'ok' : 'err';
  m.style.display = 'block';
  setTimeout(() => m.style.display = 'none', 2500);
}

async function createKey() {
  const content = document.getElementById('content').value.trim();
  const hours = document.getElementById('h').value || 0;
  const minutes = document.getElementById('m').value || 0;
  const seconds = document.getElementById('s').value || 0;
  if (!content) return showMsg('NO CONTENT', false);

  const r = await fetch('/api/create-key', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({content, hours, minutes, seconds})
  });
  const j = await r.json();
  if (j.ok) {
    showMsg('OK ' + j.key, true);
    keysData.push({
      key: j.key,
      expireAt: j.expireAt,
      expire: j.expire
    });
    renderKeysTable(keysData);
  } else {
    showMsg('FAIL', false);
  }
}

async function loadBypassLog() {
  try {
    const r = await fetch('/api/bypass-log', {method:'POST'});
    const j = await r.json();
    const box = document.getElementById('bypassLogList');
    if (!j.ok || !j.logs.length) {
      box.innerHTML = '<div style="color:#444;text-align:center;font-size:11px">No bypass yet</div>';
      return;
    }
    box.innerHTML = j.logs.map(log => {
      return '<div class="log-item">' +
        '<div class="bad">⛔ IP: ' + log.ip + '</div>' +
        '<div>' + log.duration.toUpperCase() + ' · Step ' + log.step + '/' + log.total + ' · ' + log.type + '</div>' +
        '<div>' + log.reasons.join('<br>') + '</div>' +
        '<div class="meta">' + log.time + ' · ' + log.elapsed + '</div>' +
        '</div>';
    }).join('');
  } catch (e) {}
}
</script>
</body></html>`;

// ============================================
// HTML: TASK PAGE
// ============================================
function renderTaskPage(token) {
    return `<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Task</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ctext y='.9em' font-size='90'%3E%F0%9F%92%8E%3C/text%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Sora:wght@600;700;800&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@500;600&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#0a0d14; --bg-2:#11141d; --border:rgba(255,255,255,.08);
  --gold:#e3b65a; --gold-soft:#f4d998; --emerald:#2fd9a8; --violet:#8a7cff; --red:#ff5d6c;
  --text:#eef0f5; --text-dim:#8791a6; --text-faint:#525c72;
}
*{box-sizing:border-box;margin:0;padding:0}
body{
  font-family:'Inter',sans-serif;color:var(--text);min-height:100vh;padding:20px;
  display:flex;align-items:center;justify-content:center;
  background:
    radial-gradient(900px 480px at 50% -8%, rgba(227,182,90,.10), transparent 60%),
    radial-gradient(700px 400px at 100% 100%, rgba(138,124,255,.06), transparent 60%),
    var(--bg);
}
.card{
  background:linear-gradient(180deg,rgba(255,255,255,.035),rgba(255,255,255,.015));
  border:1px solid var(--border);border-radius:20px;padding:26px;max-width:440px;width:100%;
  box-shadow:0 20px 40px -22px rgba(0,0,0,.7);
  animation:rise .5s cubic-bezier(.16,1,.3,1) both;
}
@keyframes rise{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
h1{
  font-family:'Sora',sans-serif;font-weight:800;font-size:19px;text-align:center;letter-spacing:.3px;
  background:linear-gradient(135deg,var(--gold-soft),var(--gold) 55%,#b8862f);
  -webkit-background-clip:text;background-clip:text;color:transparent;margin-bottom:14px;
}
.sub{text-align:center;color:var(--text-faint);font-size:12px;margin-bottom:18px}
.progress{margin:20px 0}
.step-row{
  display:flex;align-items:center;margin:9px 0;padding:12px 14px;border-radius:12px;
  background:var(--bg-2);font-size:13px;border:1px solid var(--border);transition:all .2s ease;
}
.step-row.done{color:var(--emerald);border-color:rgba(47,217,168,.3);background:rgba(47,217,168,.06)}
.step-row.current{color:var(--gold-soft);border-color:rgba(227,182,90,.35);background:rgba(227,182,90,.07)}
.step-row.pending{color:var(--text-faint)}
.step-icon{width:22px;margin-right:10px;text-align:center}
button{
  width:100%;padding:16px;border:none;border-radius:12px;cursor:pointer;margin-top:14px;
  font-family:'Sora',sans-serif;font-weight:700;font-size:14px;
  background:linear-gradient(135deg,var(--gold-soft),var(--gold));color:#1a1204;
  box-shadow:0 10px 24px -10px rgba(227,182,90,.55);
  transition:transform .15s ease,opacity .15s ease;
}
button:hover{transform:translateY(-1px)}
button:active{transform:translateY(0);opacity:.85}
button:disabled{background:#232838;color:var(--text-faint);box-shadow:none;cursor:not-allowed;transform:none}
#keyBox{
  background:linear-gradient(180deg,rgba(227,182,90,.09),rgba(227,182,90,.02));
  border:1px solid rgba(227,182,90,.4);border-radius:14px;padding:22px;
  font-family:'JetBrains Mono',monospace;font-size:16px;color:var(--gold-soft);
  margin:20px 0;word-break:break-all;text-align:center;font-weight:600;
  box-shadow:0 0 30px -10px rgba(227,182,90,.35);
}
.copybtn{background:linear-gradient(135deg,#5eead4,var(--emerald));color:#04231b;box-shadow:0 10px 24px -10px rgba(47,217,168,.5)}
.status{text-align:center;color:var(--text-dim);font-size:12px;margin-top:14px}
.duration-badge{display:inline-block;background:rgba(138,124,255,.15);color:#c7bfff;padding:4px 12px;border-radius:20px;font-size:11px;font-weight:600;border:1px solid rgba(138,124,255,.3)}
.err{color:var(--red)}
.bypass-box{background:rgba(255,93,108,.08);border:1px solid rgba(255,93,108,.35);border-radius:16px;padding:22px;margin:20px 0;text-align:center}
.bypass-box h3{font-family:'Sora',sans-serif;font-size:15px;margin-bottom:10px;color:var(--red)}
.bypass-box p{font-size:12.5px;color:#ffb3ba;line-height:1.6;word-break:break-word}
.homebtn{background:linear-gradient(135deg,#a89bff,var(--violet));color:#fff;box-shadow:0 10px 24px -10px rgba(138,124,255,.5)}
.foot-credit{color:var(--text-faint);font-size:10.5px;text-align:center;margin-top:18px;letter-spacing:.3px}
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
    acts.innerHTML = '';

    const box = document.createElement('div');
    box.className = 'bypass-box';
    box.innerHTML = '<h3>⛔ BYPASS DETECTED</h3><p>' + j.bypassReason + '</p>';
    acts.appendChild(box);

    const homeBtn = document.createElement('button');
    homeBtn.className = 'homebtn';
    homeBtn.textContent = '← VỀ TRANG CHỦ GET KEY LẠI';
    homeBtn.onclick = () => location.href = '/';
    acts.appendChild(homeBtn);

    document.getElementById('status').textContent = 'Xin cảm ơn.';
    if (polling) clearInterval(polling);
    return;
  }

  document.getElementById('sub').innerHTML =
    'Duration: <span class="duration-badge">' + j.duration.toUpperCase() + '</span>' +
    (j.isAdmin ? ' <span style="color:#fbbf24">[ADMIN]</span>' : '');

  const prog = document.getElementById('progress');
  prog.innerHTML = '';
  j.steps.forEach((type, i) => {
    const row = document.createElement('div');
    let cls = 'pending';
    let icon = '○';
    if (i < j.completedSteps) { cls = 'done'; icon = '✓'; }
    else if (i === j.currentStep) { cls = 'current'; icon = '▶'; }
    row.className = 'step-row ' + cls;
    const label = type === 'link4m' ? 'Link4M (80s)' : 'TrafficVN (90s)';
    row.innerHTML = '<span class="step-icon">' + icon + '</span> Step ' + (i+1) + '/' + j.total + ' — ' + label;
    prog.appendChild(row);
  });

  const acts = document.getElementById('actions');
  acts.innerHTML = '';

  if (j.done) {
    const keyBox = document.createElement('div');
    keyBox.id = 'keyBox';
    keyBox.textContent = j.key;
    acts.appendChild(keyBox);

    const btn = document.createElement('button');
    btn.className = 'copybtn';
    btn.textContent = 'COPY KEY';
    btn.onclick = () => {
      navigator.clipboard.writeText(j.key);
      btn.textContent = '✓ COPIED!';
      setTimeout(() => btn.textContent = 'COPY KEY', 2000);
    };
    acts.appendChild(btn);

    const homeBtn = document.createElement('button');
    homeBtn.className = 'homebtn';
    homeBtn.textContent = '← VỀ TRANG CHỦ';
    homeBtn.onclick = () => location.href = '/';
    acts.appendChild(homeBtn);

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
  btn.disabled = true;
  btn.textContent = 'Loading link...';

  try {
    const r = await fetch('/api/continue-task?token=' + token);
    const j = await r.json();

    if (j.done) return refresh();
    if (!j.ok) {
      btn.textContent = 'Error: ' + (j.message || 'unknown');
      btn.disabled = false;
      setTimeout(refresh, 2000);
      return;
    }

    btn.textContent = 'Redirecting...';
    location.href = j.url;
  } catch (e) {
    btn.textContent = 'Network error';
    btn.disabled = false;
  }
}

function showError(t) {
  document.getElementById('sub').innerHTML = '<span class="err">' + t + '</span>';
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

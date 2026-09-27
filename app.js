const express = require('express');
const crypto = require('crypto');
const app = express();

// ⚠️ QUAN TRỌNG: Bật trust proxy để đọc đúng IP thật
// Render.com dùng proxy → nếu không bật, req.ip sẽ trả IP của load balancer
app.set('trust proxy', true);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============================================
// CONFIG
// ============================================
const ADMIN_IPS = [
    '171.237.204.101',    // IP nhà admin
    // '14.225.xx.xx',    // thêm IP khác nếu muốn
];

const LINK4M_API_KEY = '6a61ce8626fd3a13155f6529';
const LINK4M_API_URL = 'https://link4m.co/api-shorten/v2';
const SERVER_URL = process.env.SERVER_URL || 'https://key-netsuper-api.onrender.com';

// In-memory
const keys = new Map();
const pending = new Map();

// ============================================
// HELPERS
// ============================================
function getClientIP(req) {
    // Render đặt IP thật ở header x-forwarded-for
    const fwd = req.headers['x-forwarded-for'];
    if (fwd) {
        // Có thể có nhiều IP: "client, proxy1, proxy2"
        return String(fwd).split(',')[0].trim();
    }
    return req.ip || req.connection?.remoteAddress || '';
}

function isAdminIP(ip) {
    return ADMIN_IPS.includes(String(ip).trim());
}

function vnTime(d) {
    const t = new Date(d.getTime() + 7 * 3600 * 1000);
    const p = n => String(n).padStart(2, '0');
    return `${p(t.getUTCHours())}:${p(t.getUTCMinutes())}:${p(t.getUTCSeconds())} ${p(t.getUTCDate())}/${t.getUTCMonth()+1}/${t.getUTCFullYear()}`;
}

function remain(ms) {
    if (ms <= 0) return 'expired';
    const s = Math.floor(ms / 1000);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    if (h > 0) return `${h}h${m}m${sec}s`;
    if (m > 0) return `${m}m${sec}s`;
    return `${sec}s`;
}

function genToken() {
    return crypto.randomBytes(16).toString('hex');
}

// ============================================
// API: check-key
// ============================================
app.get('/api/check-key', (req, res) => {
    const key = req.query.key;
    if (!key) return res.status(400).json({ status: false });
    const e = keys.get(key);
    if (!e) return res.json({ status: false, message: 'invalid' });
    if (Date.now() > e.expire) { keys.delete(key); return res.json({ status: false, message: 'expired' }); }
    return res.json({ status: true });
});

// ============================================
// API: verify-admin (check IP)
// ============================================
app.post('/api/verify-admin', (req, res) => {
    const ip = getClientIP(req);
    return res.json({ isAdmin: isAdminIP(ip), ip: ip });
});

// ============================================
// API: create-key (admin only)
// ============================================
app.post('/api/create-key', (req, res) => {
    const ip = getClientIP(req);
    if (!isAdminIP(ip)) return res.status(403).json({ ok: false });

    const { content, hours, minutes, seconds } = req.body;
    if (!content) return res.json({ ok: false, message: 'no_content' });

    const ms = (Number(hours)||0)*3600000 + (Number(minutes)||0)*60000 + (Number(seconds)||0)*1000;
    if (ms <= 0) return res.json({ ok: false, message: 'bad_duration' });

    keys.set(content, { expire: Date.now() + ms, createdAt: Date.now() });
    return res.json({ ok: true, key: content, expire: vnTime(new Date(Date.now() + ms)) });
});

// ============================================
// API: delete-key (admin only)
// ============================================
app.post('/api/delete-key', (req, res) => {
    const ip = getClientIP(req);
    if (!isAdminIP(ip)) return res.status(403).json({ ok: false });
    keys.delete(req.body.key);
    return res.json({ ok: true });
});

// ============================================
// API: list-keys (admin only)
// ============================================
app.post('/api/list-keys', (req, res) => {
    const ip = getClientIP(req);
    if (!isAdminIP(ip)) return res.status(403).json({ ok: false });

    const out = [];
    const now = Date.now();
    for (const [k, v] of keys) {
        const r = v.expire - now;
        if (r <= 0) { keys.delete(k); continue; }
        out.push({ key: k, remaining: remain(r), expire: vnTime(new Date(v.expire)) });
    }
    return res.json({ ok: true, keys: out });
});

// ============================================
// API: request-token
// ============================================
app.post('/api/request-token', (req, res) => {
    const token = genToken();
    pending.set(token, { createdAt: Date.now(), verified: false });
    setTimeout(() => pending.delete(token), 10 * 60 * 1000);
    return res.json({ ok: true, token });
});

// ============================================
// API: get-link4m
// ============================================
app.post('/api/get-link4m', async (req, res) => {
    const { token } = req.body;
    if (!token || !pending.has(token)) return res.status(403).json({ ok: false });

    const cb = `${SERVER_URL}/api/link4m-callback?token=${token}`;
    try {
        const params = new URLSearchParams({ api: LINK4M_API_KEY, url: cb, format: 'json' });
        const r = await fetch(`${LINK4M_API_URL}?${params.toString()}`);
        const j = await r.json();
        if (j.status !== 'success' || !j.shortenedUrl) return res.json({ ok: false, raw: j });
        return res.json({ ok: true, url: j.shortenedUrl });
    } catch (e) {
        return res.json({ ok: false, message: String(e) });
    }
});

// ============================================
// API: link4m-callback
// ============================================
app.get('/api/link4m-callback', (req, res) => {
    const { token } = req.query;
    if (!token || !pending.has(token)) return res.status(403).send('forbidden');
    pending.get(token).verified = true;
    res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>OK</title>
<style>body{font-family:monospace;background:#0a0a0a;color:#10b981;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;text-align:center;flex-direction:column}
h1{font-size:20px}p{color:#666;font-size:13px;margin-top:12px}a{color:#00f2fe;margin-top:20px;text-decoration:none;padding:12px 24px;border:1px solid #00f2fe;border-radius:8px}</style>
</head><body>
<h1>VERIFIED</h1>
<p>Get your key now</p>
<a href="/get-key?token=${token}">GET KEY</a>
</body></html>`);
});

// ============================================
// API: get-key
// ============================================
app.post('/api/get-key', (req, res) => {
    const { token } = req.body;
    if (!token || !pending.has(token)) return res.status(403).json({ ok: false });
    const p = pending.get(token);
    if (!p.verified) return res.status(403).json({ ok: false, message: 'not_verified' });
    pending.delete(token);

    const key = crypto.randomBytes(8).toString('hex').toUpperCase();
    const duration = 24 * 3600 * 1000;
    keys.set(key, { expire: Date.now() + duration, createdAt: Date.now() });
    return res.json({ ok: true, key, expire: vnTime(new Date(Date.now() + duration)) });
});

// ============================================
// ROUTE: /get-key
// ============================================
app.get('/get-key', (req, res) => {
    res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Get Key</title>
<style>body{font-family:monospace;background:#0a0a0a;color:#fff;padding:20px;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#141414;border:1px solid #222;border-radius:16px;padding:24px;max-width:400px;width:100%;text-align:center}
h1{color:#00f2fe;font-size:16px;margin:0 0 16px}
#key{background:#0a0a0a;border:1px solid #333;border-radius:8px;padding:16px;font-size:16px;color:#10b981;word-break:break-all;margin:16px 0}
button{background:#00f2fe;color:#000;border:none;padding:12px 24px;border-radius:8px;font-weight:700;cursor:pointer;width:100%}
.err{color:#ef4444}</style>
</head><body>
<div class="card">
<h1>YOUR KEY</h1>
<div id="key">loading...</div>
<button onclick="copyKey()">COPY</button>
</div>
<script>
const token = new URLSearchParams(location.search).get('token');
async function load() {
  const r = await fetch('/api/get-key', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token})});
  const j = await r.json();
  if (j.ok) document.getElementById('key').textContent = j.key;
  else document.getElementById('key').innerHTML = '<span class="err">ERROR</span>';
}
function copyKey() {
  navigator.clipboard.writeText(document.getElementById('key').textContent);
  alert('Copied!');
}
load();
</script>
</body></html>`);
});

// ============================================
// ROUTE: / (main)
// ============================================
app.get('/', (req, res) => {
    res.send(MAIN_HTML);
});

// ============================================
// MAIN HTML
// ============================================
const MAIN_HTML = `<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NETSUPER</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:monospace;background:#0a0a0a;color:#e0e0e0;min-height:100vh;padding:16px}
.wrap{max-width:460px;margin:0 auto;padding-top:40px}
h1{font-size:20px;text-align:center;color:#00f2fe;margin-bottom:24px}
.card{background:#141414;border:1px solid #222;border-radius:12px;padding:16px;margin-bottom:12px}
.card h2{font-size:13px;color:#8b5cf6;margin-bottom:12px;text-transform:uppercase}
button{width:100%;padding:14px;background:#00f2fe;border:none;border-radius:8px;color:#000;font-weight:700;font-family:monospace;font-size:14px;cursor:pointer}
button:active{opacity:.7}
.btn-purple{background:#8b5cf6;color:#fff}
label{display:block;font-size:11px;color:#666;margin:8px 0 4px;text-transform:uppercase}
input{width:100%;padding:10px;background:#0a0a0a;border:1px solid #333;border-radius:8px;color:#fff;font-family:monospace;font-size:13px}
input:focus{outline:none;border-color:#00f2fe}
.row{display:flex;gap:8px;margin-top:8px}
.row input{flex:1}
table{width:100%;font-size:11px;border-collapse:collapse;margin-top:8px}
th,td{padding:6px 4px;text-align:left;border-bottom:1px solid #222}
th{color:#555;font-weight:400;font-size:10px}
td.k{color:#fbbf24}
td.r{color:#10b981}
.del{background:#ef4444;color:#fff;border:none;padding:4px 8px;border-radius:6px;cursor:pointer;width:auto;font-size:11px;margin:0}
#msg{text-align:center;padding:8px;border-radius:8px;margin-top:8px;font-size:12px;display:none}
.ok{background:#10b98122;color:#10b981}
.err{background:#ef444422;color:#ef4444}
#adminPanel{display:none}
.hint{color:#444;font-size:11px;text-align:center;margin-top:20px}
</style>
</head><body>
<div class="wrap">
<h1>NETSUPER</h1>

<div class="card">
<h2>Get Key</h2>
<button class="btn-purple" onclick="getKey()">GET KEY</button>
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
<button onclick="createKey()">CREATE KEY</button>
<div id="msg"></div>
<table id="tbl"><thead><tr><th>KEY</th><th>REMAIN</th><th>EXPIRE</th><th></th></tr></thead><tbody></tbody></table>
</div>

<div class="hint">v1.0</div>
</div>

<script>
// ===== VERIFY ADMIN BY IP =====
async function verifyAdmin() {
  const r = await fetch('/api/verify-admin', {method:'POST'});
  const j = await r.json();
  if (j.isAdmin) {
    document.getElementById('adminPanel').style.display = 'block';
    loadKeys();
    setInterval(loadKeys, 5000);
  }
}
verifyAdmin();

// ===== GET KEY =====
async function getKey() {
  const r1 = await fetch('/api/request-token', {method:'POST'});
  const j1 = await r1.json();
  if (!j1.ok) return alert('Error');

  const r2 = await fetch('/api/get-link4m', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({token: j1.token})
  });
  const j2 = await r2.json();
  if (!j2.ok) return alert('Link4M error: ' + JSON.stringify(j2));

  location.href = j2.url;
}

// ===== ADMIN =====
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
  if (j.ok) { showMsg('OK ' + j.key, true); loadKeys(); }
  else showMsg('FAIL', false);
}

async function loadKeys() {
  const r = await fetch('/api/list-keys', {method:'POST'});
  const j = await r.json();
  const tb = document.querySelector('#tbl tbody');
  tb.innerHTML = '';
  if (!j.ok || !j.keys.length) {
    tb.innerHTML = '<tr><td colspan="4" style="color:#444;text-align:center">empty</td></tr>';
    return;
  }
  j.keys.forEach(k => {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td class="k">' + k.key + '</td><td class="r">' + k.remaining + '</td><td>' + k.expire + '</td>';
    const td = document.createElement('td');
    const b = document.createElement('button');
    b.className = 'del'; b.textContent = 'X';
    b.onclick = async () => {
      await fetch('/api/delete-key', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({key: k.key})
      });
      loadKeys();
    };
    td.appendChild(b); tr.appendChild(td);
    tb.appendChild(tr);
  });
}
</script>
</body></html>`;

// ============================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('ok port ' + PORT));

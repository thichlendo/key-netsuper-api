const express = require('express');
const crypto = require('crypto');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============================================
// CONFIG
// ============================================
const ADMIN_SERIALS = ['R9JN60KEPKJ'];

// App token - CHANGE THIS before deploy
const APP_TOKEN = 'NS_9f8a3b2c1d4e5f6a7b8c9d0e1f2a3b4c';

// Link4M API
const LINK4M_API_KEY = '6a61ce8626fd3a13155f6529';
const LINK4M_API_URL = 'https://link4m.co/api-shorten/v2';

// Your server URL (Render auto-injects, or hardcode)
const SERVER_URL = process.env.SERVER_URL || 'https://key-netsuper-api.onrender.com';

// In-memory storage
const keys = new Map();      // key -> { expire, createdAt }
const pending = new Map();   // token -> { createdAt, verified, ip }

// ============================================
// HELPERS
// ============================================
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

function isAdmin(req) {
    const s = req.headers['x-device-serial'] || req.query.serial || (req.body && req.body.serial);
    return s && ADMIN_SERIALS.includes(String(s).trim());
}

function isApp(req) {
    return req.headers['x-app-token'] === APP_TOKEN;
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
// API: request-token
// App gọi để xin token trước khi vượt Link4M
// ============================================
app.post('/api/request-token', (req, res) => {
    if (!isApp(req)) return res.status(403).json({ ok: false });

    const token = genToken();
    pending.set(token, {
        createdAt: Date.now(),
        verified: false,
        ip: req.ip
    });

    // auto-expire pending after 10min
    setTimeout(() => pending.delete(token), 10 * 60 * 1000);

    return res.json({ ok: true, token });
});

// ============================================
// API: get-link4m
// App gửi token → server gọi Link4M API tạo short link
// Redirect về /api/link4m-callback?token=xxx
// ============================================
app.post('/api/get-link4m', async (req, res) => {
    if (!isApp(req)) return res.status(403).json({ ok: false });

    const { token } = req.body;
    if (!token || !pending.has(token)) {
        return res.status(403).json({ ok: false, message: 'invalid_token' });
    }

    // URL sau khi user vượt Link4M sẽ redirect về đây
    const callbackUrl = `${SERVER_URL}/api/link4m-callback?token=${token}`;

    try {
        const params = new URLSearchParams({
            api: LINK4M_API_KEY,
            url: callbackUrl,
            format: 'json'
        });

        const r = await fetch(`${LINK4M_API_URL}?${params.toString()}`);
        const j = await r.json();

        if (j.status !== 'success' || !j.shortenedUrl) {
            return res.json({ ok: false, message: 'link4m_error', raw: j });
        }

        return res.json({ ok: true, url: j.shortenedUrl });

    } catch (err) {
        return res.json({ ok: false, message: 'network_error', error: String(err) });
    }
});

// ============================================
// API: link4m-callback
// Link4M gọi về đây SAU KHI user vượt link
// ============================================
app.get('/api/link4m-callback', (req, res) => {
    const { token } = req.query;
    if (!token || !pending.has(token)) {
        return res.status(403).send('forbidden');
    }

    const p = pending.get(token);
    p.verified = true;
    p.verifiedAt = Date.now();

    // Trang HTML đơn giản báo user có thể quay lại app
    res.send(`<!DOCTYPE html><html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OK</title>
<style>body{font-family:monospace;background:#0a0a0a;color:#10b981;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;text-align:center}
.b{font-size:14px}p{color:#666;font-size:12px;margin-top:8px}</style>
</head><body>
<div>
<div class="b">VERIFIED</div>
<p>Return to app to get key</p>
</div>
</body></html>`);
});

// ============================================
// API: get-key
// App gọi sau khi user đã vượt Link4M (token.verified = true)
// ============================================
app.post('/api/get-key', (req, res) => {
    if (!isApp(req)) return res.status(403).json({ ok: false });

    const { token } = req.body;
    if (!token || !pending.has(token)) {
        return res.status(403).json({ ok: false, message: 'invalid_token' });
    }

    const p = pending.get(token);
    if (!p.verified) {
        return res.status(403).json({ ok: false, message: 'not_verified' });
    }

    // One-time use
    pending.delete(token);

    const key = crypto.randomBytes(8).toString('hex').toUpperCase();
    const duration = 24 * 3600 * 1000;
    keys.set(key, {
        expire: Date.now() + duration,
        createdAt: Date.now()
    });

    return res.json({
        ok: true,
        key,
        expire: vnTime(new Date(Date.now() + duration))
    });
});

// ============================================
// API: check-token-status
// App polling kiểm tra user đã vượt Link4M chưa
// ============================================
app.post('/api/check-token', (req, res) => {
    if (!isApp(req)) return res.status(403).json({ ok: false });

    const { token } = req.body;
    if (!token || !pending.has(token)) {
        return res.status(403).json({ ok: false, message: 'invalid_token' });
    }

    const p = pending.get(token);
    return res.json({ ok: true, verified: !!p.verified });
});

// ============================================
// API ADMIN
// ============================================
app.post('/api/create-key', (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    const { content, hours, minutes, seconds } = req.body;
    if (!content) return res.json({ ok: false });

    const ms = (Number(hours)||0)*3600000 + (Number(minutes)||0)*60000 + (Number(seconds)||0)*1000;
    if (ms <= 0) return res.json({ ok: false });

    keys.set(content, {
        expire: Date.now() + ms,
        createdAt: Date.now()
    });
    return res.json({ ok: true, key: content, expire: vnTime(new Date(Date.now() + ms)) });
});

app.post('/api/delete-key', (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    keys.delete(req.body.key);
    return res.json({ ok: true });
});

app.get('/api/list-keys', (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    const out = [];
    const now = Date.now();
    for (const [k, v] of keys) {
        const r = v.expire - now;
        if (r <= 0) { keys.delete(k); continue; }
        out.push({
            key: k,
            remaining: remain(r),
            expire: vnTime(new Date(v.expire))
        });
    }
    return res.json({ ok: true, keys: out });
});

// ============================================
// ROUTES
// ============================================
app.get('/', (req, res) => res.status(404).send(''));

app.get('/admin', (req, res) => {
    if (!isAdmin(req)) return res.status(404).send('');
    res.send(ADMIN_HTML);
});

// ============================================
// ADMIN HTML
// ============================================
const ADMIN_HTML = `<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:monospace;background:#0a0a0a;color:#e0e0e0;min-height:100vh;padding:16px}
.wrap{max-width:460px;margin:0 auto}
h1{font-size:18px;text-align:center;margin:20px 0;color:#00f2fe}
.card{background:#141414;border:1px solid #222;border-radius:12px;padding:16px;margin-bottom:12px}
.card h2{font-size:13px;color:#8b5cf6;margin-bottom:12px;text-transform:uppercase}
label{display:block;font-size:11px;color:#666;margin:8px 0 4px;text-transform:uppercase}
input{width:100%;padding:10px;background:#0a0a0a;border:1px solid #333;border-radius:8px;color:#fff;font-family:monospace;font-size:13px}
input:focus{outline:none;border-color:#00f2fe}
.row{display:flex;gap:8px;margin-top:8px}
.row input{flex:1}
button{width:100%;padding:12px;background:#00f2fe;border:none;border-radius:8px;color:#000;font-weight:700;font-family:monospace;font-size:13px;cursor:pointer;margin-top:12px}
button:active{opacity:.7}
table{width:100%;font-size:11px;border-collapse:collapse;margin-top:8px}
th,td{padding:6px 4px;text-align:left;border-bottom:1px solid #222}
th{color:#555;font-weight:400;font-size:10px}
td.k{color:#fbbf24}
td.r{color:#10b981}
.del{background:#ef4444;color:#fff;border:none;padding:4px 8px;border-radius:6px;cursor:pointer;width:auto;font-size:11px;margin:0}
#msg{text-align:center;padding:8px;border-radius:8px;margin-top:8px;font-size:12px;display:none}
.ok{background:#10b98122;color:#10b981}
.err{background:#ef444422;color:#ef4444}
</style>
</head><body>
<div class="wrap">
<h1>ADMIN</h1>
<div class="card">
<h2>Create</h2>
<label>Key</label>
<input id="content" placeholder="VIP-ABC">
<label>Duration</label>
<div class="row">
<input id="h" type="number" placeholder="h" value="0">
<input id="m" type="number" placeholder="m" value="0">
<input id="s" type="number" placeholder="s" value="0">
</div>
<button onclick="createKey()">CREATE</button>
<div id="msg"></div>
</div>
<div class="card">
<h2>Keys</h2>
<table id="tbl"><thead><tr><th>KEY</th><th>REMAIN</th><th>EXPIRE</th><th></th></tr></thead><tbody></tbody></table>
</div>
</div>
<script>
const serial = new URLSearchParams(location.search).get('serial') || '';
function showMsg(t, ok) {
  const m = document.getElementById('msg');
  m.textContent = t; m.className = ok ? 'ok' : 'err';
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
    headers: {'Content-Type': 'application/json', 'X-Device-Serial': serial},
    body: JSON.stringify({content, hours, minutes, seconds})
  });
  const j = await r.json();
  if (j.ok) { showMsg('OK ' + j.key, true); load(); }
  else showMsg('FAIL', false);
}
async function load() {
  const r = await fetch('/api/list-keys', {headers: {'X-Device-Serial': serial}});
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
        headers: {'Content-Type': 'application/json', 'X-Device-Serial': serial},
        body: JSON.stringify({key: k.key})
      });
      load();
    };
    td.appendChild(b); tr.appendChild(td);
    tb.appendChild(tr);
  });
}
load();
setInterval(load, 5000);
</script>
</body></html>`;

// ============================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Server on ' + PORT));

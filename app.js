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

// Link4M
const LINK4M_API_KEY = '6a61ce8626fd3a13155f6529';
const LINK4M_API_URL = 'https://link4m.co/api-shorten/v2';

// TrafficVN
const TRAFFICVN_API_KEY = 'b19399e1906b7bad23ed21c078a1edf7';
const TRAFFICVN_API_URL = 'https://trafficvn.com/apidevelop';

// Duration config — kèm thời gian tối thiểu mỗi link
const DURATION_CONFIG = {
    '3h':  { hours: 3,  steps: ['link4m'] },
    '6h':  { hours: 6,  steps: ['link4m', 'trafficvn'] },
    '8h':  { hours: 8,  steps: ['link4m', 'trafficvn', 'trafficvn'] },
    '12h': { hours: 12, steps: ['link4m', 'trafficvn', 'trafficvn', 'trafficvn'] },
    '24h': { hours: 24, steps: ['link4m', 'trafficvn', 'trafficvn', 'trafficvn', 'trafficvn'] }
};

// ⏱️ Thời gian tối thiểu mỗi link (ms)
const MIN_LINK4M_MS = 80 * 1000;      // 80 giây
const MIN_TRAFFICVN_MS = 90 * 1000;   // 90 giây

// Storage
const keys = new Map();
const tasks = new Map();

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

// 🎲 Format key: NETSUPER-XXXX-XXXX-XXXX
function genKey() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const block = () => {
        let s = '';
        for (let i = 0; i < 4; i++) s += chars[Math.floor(Math.random() * chars.length)];
        return s;
    };
    return `NETSUPER-${block()}-${block()}-${block()}`;
}

// ============================================
// API: /api/check-key
// ============================================
app.get('/api/check-key', (req, res) => {
    const key = req.query.key;
    const hwid = req.query.hwid || '';

    if (!key) return res.json({ p: JSON.stringify({ ok: 0 }), s: 'x' });

    const entry = keys.get(key);
    if (!entry) return res.json({ p: JSON.stringify({ ok: 0 }), s: 'x' });

    if (Date.now() > entry.expire) {
        keys.delete(key);
        return res.json({ p: JSON.stringify({ ok: 0 }), s: 'x' });
    }

    if (!entry.hwid) {
        entry.hwid = hwid;
    } else if (entry.hwid !== hwid && hwid) {
        return res.json({ p: JSON.stringify({ ok: 0 }), s: 'x' });
    }

    const exp = Math.floor(entry.expire / 1000);
    return res.json({ p: JSON.stringify({ ok: 1, exp }), s: 'x' });
});

// ============================================
// API: start-task
// ============================================
app.post('/api/start-task', (req, res) => {
    const { duration } = req.body;
    const config = DURATION_CONFIG[duration];
    if (!config) return res.status(400).json({ ok: false, message: 'bad_duration' });

    const token = genToken();
    const clientIP = getClientIP(req);

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
        // Anti-bypass
        clientIP: clientIP,
        isAdmin: isAdminIP(req),
        stepStartedAt: 0,
        bypassed: false,
        bypassReason: null
    });

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

    // 📌 Ghi lại thời điểm bắt đầu step
    task.stepStartedAt = Date.now();

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
// API: step-callback — có anti-bypass
// ============================================
app.get('/api/step-callback', (req, res) => {
    const { token, step } = req.query;
    const task = tasks.get(token);
    if (!task) return res.status(403).send('invalid');

    const stepNum = parseInt(step, 10);
    if (stepNum !== task.currentStep) {
        return res.redirect(`${SERVER_URL}/task?token=${token}`);
    }

    // ⏱️ Kiểm tra thời gian
    const elapsed = Date.now() - task.stepStartedAt;
    const type = task.steps[stepNum];

    // ⚠️ Bỏ qua check nếu là ADMIN
    if (!task.isAdmin) {
        let minTime = 0;
        if (type === 'link4m') minTime = MIN_LINK4M_MS;
        else if (type === 'trafficvn') minTime = MIN_TRAFFICVN_MS;

        if (elapsed < minTime) {
            // 🚫 BYPASS DETECTED
            task.bypassed = true;
            const label = type === 'link4m' ? 'Link4M' : 'TrafficVN';
            const required = Math.round(minTime / 1000);
            const actual = Math.round(elapsed / 1000);
            task.bypassReason = `Bạn đã bypass link ${label}! Yêu cầu tối thiểu ${required}s nhưng chỉ mất ${actual}s.`;
            return res.redirect(`${SERVER_URL}/task?token=${token}`);
        }
    }

    // ✅ Hợp lệ
    task.completedSteps++;
    task.currentStep++;

    if (task.completedSteps >= task.totalSteps) {
        const key = genKey();
        const duration = task.hours * 3600 * 1000;
        const expire = Date.now() + duration;

        keys.set(key, {
            expire,
            hwid: '',
            createdAt: Date.now()
        });

        task.key = key;
        task.keyExpire = vnTime(new Date(expire));
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
app.post('/api/create-key', (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    const { content, hours, minutes, seconds } = req.body;
    if (!content) return res.json({ ok: false });

    const ms = (Number(hours)||0)*3600000 + (Number(minutes)||0)*60000 + (Number(seconds)||0)*1000;
    if (ms <= 0) return res.json({ ok: false });

    keys.set(content, {
        expire: Date.now() + ms,
        hwid: '',
        createdAt: Date.now()
    });
    return res.json({ ok: true, key: content, expire: vnTime(new Date(Date.now() + ms)) });
});

app.post('/api/delete-key', (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    keys.delete(req.body.key);
    return res.json({ ok: true });
});

app.post('/api/list-keys', (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });

    const out = [];
    const now = Date.now();
    for (const [k, v] of keys) {
        const r = v.expire - now;
        if (r <= 0) { keys.delete(k); continue; }
        out.push({
            key: k,
            remaining: remain(r),
            expire: vnTime(new Date(v.expire)),
            hwid: v.hwid || 'free'
        });
    }
    return res.json({ ok: true, keys: out });
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
  transition:transform .15s ease,opacity .15s ease,box-shadow .15s ease;
}
button:hover{transform:translateY(-1px)}
button:active{transform:translateY(0);opacity:.85}
button:disabled{background:#232838;color:var(--text-faint);box-shadow:none;cursor:not-allowed;transform:none}
button:focus-visible{outline:2px solid var(--gold-soft);outline-offset:2px}
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
td.k{color:var(--gold-soft);font-family:'JetBrains Mono',monospace;font-size:11px}
td.r{color:var(--emerald);font-family:'JetBrains Mono',monospace}
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
</style>
</head><body>
<div class="wrap">
<h1>NETSUPER</h1>
<div class="tagline">Cổng lấy key cao cấp — nhanh, an toàn, minh bạch</div>

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

<div class="hint">✦ Crafted by ThichLenDo · v1.1 ✦</div>
</div>

<script>
(async () => {
  const r = await fetch('/api/verify-admin', {method:'POST'});
  const j = await r.json();
  if (j.isAdmin) {
    document.getElementById('adminPanel').style.display = 'block';
    loadKeys();
    setInterval(loadKeys, 5000);
  }
})();

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

  const r = await fetch('/api/start-task', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({duration})
  });
  const j = await r.json();

  if (!j.ok) {
    status.textContent = 'Error: ' + (j.message || 'unknown');
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
.bypass-box p{font-size:12.5px;color:#ffb3ba;line-height:1.6}
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

  // Nếu bị bypass → hiện thông báo
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
app.listen(PORT, () => console.log('Server running on port ' + PORT));

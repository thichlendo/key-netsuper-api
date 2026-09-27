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
const TRAFFICVN_API_URL = 'https://trafficvn.com/api';
const TRAFFICVN_FALLBACK = 'https://www.google.com';

// Duration config — mỗi mức có list step tương ứng
const DURATION_CONFIG = {
    '3h':  { hours: 3,  steps: ['link4m'] },
    '6h':  { hours: 6,  steps: ['link4m', 'trafficvn'] },
    '8h':  { hours: 8,  steps: ['link4m', 'trafficvn', 'trafficvn'] },
    '12h': { hours: 12, steps: ['link4m', 'trafficvn', 'trafficvn', 'trafficvn'] },
    '24h': { hours: 24, steps: ['link4m', 'trafficvn', 'trafficvn', 'trafficvn', 'trafficvn'] }
};

// Storage
const keys = new Map();     // key -> { expire, hwid, createdAt }
const tasks = new Map();    // token -> { duration, steps, currentStep, done, key, ... }

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

function isAdmin(req) {
    const ip = getClientIP(req);
    const serial = req.body?.serial || req.query?.serial;
    return ADMIN_IPS.includes(ip) || (serial && ADMIN_SERIALS.includes(String(serial).trim()));
}

function genToken() {
    return crypto.randomBytes(16).toString('hex');
}

function genKey() {
    return 'NS-' + crypto.randomBytes(6).toString('hex').toUpperCase();
}

// ============================================
// ⭐ API: /api/check-key — app gọi để verify key
// Trả về format: { p: "<json>", s: "x" }
// ============================================
app.get('/api/check-key', (req, res) => {
    const key = req.query.key;
    const hwid = req.query.hwid || '';

    if (!key) {
        return res.json({ p: JSON.stringify({ ok: 0 }), s: 'x' });
    }

    const entry = keys.get(key);
    if (!entry) {
        return res.json({ p: JSON.stringify({ ok: 0 }), s: 'x' });
    }

    if (Date.now() > entry.expire) {
        keys.delete(key);
        return res.json({ p: JSON.stringify({ ok: 0 }), s: 'x' });
    }

    // Nếu muốn HWID bind
    if (!entry.hwid) {
        entry.hwid = hwid;
    } else if (entry.hwid !== hwid) {
        return res.json({ p: JSON.stringify({ ok: 0 }), s: 'x' });
    }

    const exp = Math.floor(entry.expire / 1000);
    return res.json({ p: JSON.stringify({ ok: 1, exp }), s: 'x' });
});

// ============================================
// API: start-task — app gọi để bắt đầu flow get key
// ============================================
app.post('/api/start-task', (req, res) => {
    const { duration } = req.body;
    const config = DURATION_CONFIG[duration];
    if (!config) return res.status(400).json({ ok: false, message: 'bad_duration' });

    const token = genToken();
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
        createdAt: Date.now()
    });

    // auto-expire sau 30 phút
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
// API: task-status — check tiến độ
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
        hours: task.hours
    });
});

// ============================================
// API: continue-task — tạo link cho step hiện tại
// ============================================
app.get('/api/continue-task', async (req, res) => {
    const { token } = req.query;
    const task = tasks.get(token);
    if (!task) return res.status(403).json({ ok: false, message: 'invalid' });
    if (task.done) return res.json({ ok: true, done: true, key: task.key });

    const step = task.currentStep;
    if (step >= task.steps.length) return res.json({ ok: false, message: 'all_steps_done' });

    const type = task.steps[step];
    const cb = `${SERVER_URL}/api/step-callback?token=${token}&step=${step}`;

    try {
        let shortUrl = null;

        if (type === 'link4m') {
            const params = new URLSearchParams({
                api: LINK4M_API_KEY,
                url: cb,
                format: 'json'
            });
            const r = await fetch(`${LINK4M_API_URL}?${params.toString()}`);
            const j = await r.json();
            if (j.status === 'success' && j.shortenedUrl) {
                shortUrl = j.shortenedUrl;
            } else {
                return res.json({ ok: false, message: 'link4m_error', raw: j });
            }

        } else if (type === 'trafficvn') {
            const params = new URLSearchParams({
                api: TRAFFICVN_API_KEY,
                url: cb,
                fallback_url: TRAFFICVN_FALLBACK
            });
            const r = await fetch(`${TRAFFICVN_API_URL}?${params.toString()}`);
            const j = await r.json();
            // TrafficVN có thể trả format khác, thử nhiều key
            shortUrl = j.shortenedUrl || j.short_url || j.shortened || j.url || j.data?.shortenedUrl;
            if (!shortUrl) {
                return res.json({ ok: false, message: 'trafficvn_error', raw: j });
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
// API: step-callback — Link4M/TrafficVN gọi về
// ============================================
app.get('/api/step-callback', (req, res) => {
    const { token, step } = req.query;
    const task = tasks.get(token);
    if (!task) return res.status(403).send('invalid');

    const stepNum = parseInt(step, 10);
    if (stepNum !== task.currentStep) {
        // Đã hoặc sai step → quay về task page
        return res.redirect(`${SERVER_URL}/task?token=${token}`);
    }

    task.completedSteps++;
    task.currentStep++;

    if (task.completedSteps >= task.totalSteps) {
        // ✅ Hoàn thành tất cả step → sinh key
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

        return res.redirect(`${SERVER_URL}/task?token=${token}`);
    }

    // Còn step tiếp theo → về task page
    res.redirect(`${SERVER_URL}/task?token=${token}`);
});

// ============================================
// API: verify-admin (cho web)
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
// ROUTE: / — trang chủ
// ============================================
app.get('/', (req, res) => res.send(MAIN_HTML));

// ============================================
// ROUTE: /task — trang xử lý các bước
// ============================================
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
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:monospace;background:#0a0a0a;color:#e0e0e0;min-height:100vh;padding:16px}
.wrap{max-width:460px;margin:0 auto;padding-top:30px}
h1{font-size:20px;text-align:center;color:#00f2fe;margin-bottom:20px}
.card{background:#141414;border:1px solid #222;border-radius:12px;padding:16px;margin-bottom:12px}
.card h2{font-size:13px;color:#8b5cf6;margin-bottom:12px;text-transform:uppercase;letter-spacing:1px}
button{width:100%;padding:14px;background:#00f2fe;border:none;border-radius:8px;color:#000;font-weight:700;font-family:monospace;font-size:14px;cursor:pointer}
button:active{opacity:.7}
.btn-purple{background:#8b5cf6;color:#fff}
.btn-green{background:#10b981;color:#fff}
.btn-small{padding:10px;font-size:12px}
label{display:block;font-size:11px;color:#666;margin:8px 0 4px;text-transform:uppercase}
input{width:100%;padding:10px;background:#0a0a0a;border:1px solid #333;border-radius:8px;color:#fff;font-family:monospace;font-size:13px}
input:focus{outline:none;border-color:#00f2fe}
.row{display:flex;gap:8px;margin-top:8px}
.row input{flex:1}
table{width:100%;font-size:11px;border-collapse:collapse;margin-top:8px}
th,td{padding:6px 4px;text-align:left;border-bottom:1px solid #222}
th{color:#555;font-weight:400;font-size:10px;text-transform:uppercase}
td.k{color:#fbbf24}
td.r{color:#10b981}
.del{background:#ef4444;color:#fff;border:none;padding:4px 8px;border-radius:6px;cursor:pointer;width:auto;font-size:11px;margin:0}
#msg{text-align:center;padding:8px;border-radius:8px;margin-top:8px;font-size:12px;display:none}
.ok{background:#10b98122;color:#10b981}
.err{background:#ef444422;color:#ef4444}
#adminPanel{display:none}
#durationMenu{display:none;grid-template-columns:1fr 1fr;gap:8px;margin-top:12px}
#durationMenu button{padding:16px;font-size:15px;background:#1e1e2e;color:#fff;border:1px solid #333}
#durationMenu button:hover{border-color:#00f2fe;background:#252540}
#durationMenu button b{color:#00f2fe;display:block;font-size:18px}
#durationMenu button span{font-size:10px;color:#666;display:block;margin-top:2px}
.hint{color:#333;font-size:10px;text-align:center;margin-top:20px}
</style>
</head><body>
<div class="wrap">
<h1>NETSUPER</h1>

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

<div class="hint">v1.0</div>
</div>

<script>
// ===== ADMIN VERIFY =====
(async () => {
  const r = await fetch('/api/verify-admin', {method:'POST'});
  const j = await r.json();
  if (j.isAdmin) {
    document.getElementById('adminPanel').style.display = 'block';
    loadKeys();
    setInterval(loadKeys, 5000);
  }
})();

// ===== DURATION MENU =====
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

// ===== START TASK =====
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

  // Mở trang task
  location.href = j.taskUrl;
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
// HTML: TASK PAGE
// ============================================
function renderTaskPage(token) {
    return `<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Task</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:monospace;background:#0a0a0a;color:#e0e0e0;min-height:100vh;padding:16px;display:flex;align-items:center;justify-content:center}
.card{background:#141414;border:1px solid #222;border-radius:16px;padding:24px;max-width:440px;width:100%}
h1{font-size:18px;text-align:center;color:#00f2fe;margin-bottom:16px}
.sub{text-align:center;color:#666;font-size:12px;margin-bottom:16px}
.progress{margin:20px 0}
.step-row{display:flex;align-items:center;margin:10px 0;padding:10px;border-radius:8px;background:#0a0a0a;font-size:13px}
.step-row.done{color:#10b981;border-left:3px solid #10b981}
.step-row.current{color:#fbbf24;border-left:3px solid #fbbf24;background:#1a1a0a}
.step-row.pending{color:#444;border-left:3px solid #222}
.step-icon{width:20px;margin-right:10px}
button{width:100%;padding:16px;background:#00f2fe;border:none;border-radius:8px;color:#000;font-weight:700;font-family:monospace;font-size:14px;cursor:pointer;margin-top:16px}
button:active{opacity:.7}
button:disabled{background:#333;color:#555;cursor:not-allowed}
#keyBox{background:#0a0a0a;border:2px solid #10b981;border-radius:8px;padding:20px;font-size:18px;color:#10b981;margin:20px 0;word-break:break-all;text-align:center;font-weight:700}
.copybtn{background:#10b981;color:#fff}
.status{text-align:center;color:#888;font-size:12px;margin-top:12px}
.duration-badge{display:inline-block;background:#8b5cf644;color:#c4b5fd;padding:4px 10px;border-radius:6px;font-size:11px}
</style>
</head><body>
<div class="card">
<h1>PROCESSING TASK</h1>
<div class="sub" id="sub">Loading...</div>
<div class="progress" id="progress"></div>
<div id="actions"></div>
<div class="status" id="status"></div>
</div>

<script>
const token = ${JSON.stringify(token)};
let polling = null;

async function refresh() {
  if (!token) return showError('No token');
  const r = await fetch('/api/task-status?token=' + token);
  const j = await r.json();
  if (!j.ok) return showError('Invalid task');

  document.getElementById('sub').innerHTML =
    'Duration: <span class="duration-badge">' + j.duration.toUpperCase() + '</span>';

  // Render steps
  const prog = document.getElementById('progress');
  prog.innerHTML = '';
  j.steps.forEach((type, i) => {
    const row = document.createElement('div');
    let cls = 'pending';
    let icon = '○';
    if (i < j.completedSteps) { cls = 'done'; icon = '✓'; }
    else if (i === j.currentStep) { cls = 'current'; icon = '▶'; }
    row.className = 'step-row ' + cls;
    const label = type === 'link4m' ? 'Link4M' : 'TrafficVN';
    row.innerHTML = '<span class="step-icon">' + icon + '</span> Step ' + (i+1) + '/' + j.total + ' — ' + label;
    prog.appendChild(row);
  });

  // Actions
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

    const doneBtn = document.createElement('button');
    doneBtn.textContent = 'DONE — BACK TO APP';
    doneBtn.style.background = '#8b5cf6';
    doneBtn.style.color = '#fff';
    doneBtn.onclick = () => {
      window.close();
      // hoặc history.back()
    };
    acts.appendChild(doneBtn);

    document.getElementById('status').textContent = 'Expire: ' + j.keyExpire;
    if (polling) clearInterval(polling);
    return;
  }

  // Nút continue
  const btn = document.createElement('button');
  btn.textContent = 'CONTINUE STEP ' + (j.currentStep + 1) + ' →';
  btn.onclick = () => continueTask(btn);
  acts.appendChild(btn);

  document.getElementById('status').textContent = 'Completed ' + j.completedSteps + '/' + j.total;
}

async function continueTask(btn) {
  btn.disabled = true;
  btn.textContent = 'Loading link...';

  const r = await fetch('/api/continue-task?token=' + token);
  const j = await r.json();

  if (j.done) return refresh();
  if (!j.ok) {
    btn.textContent = 'Error: ' + (j.message || 'unknown');
    btn.disabled = false;
    return;
  }

  btn.textContent = 'Redirecting...';
  location.href = j.url;
}

function showError(t) {
  document.getElementById('sub').textContent = t;
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
app.listen(PORT, () => console.log('ok port ' + PORT));

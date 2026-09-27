const express = require('express');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============================================
// CẤU HÌNH
// ============================================
const ADMIN_SERIALS = [
    'R9JN60KEPKJ',      // máy của bạn
    // 'ABC123XYZ',     // thêm máy khác nếu muốn
];

// Database tạm trong RAM (thay bằng MongoDB/Redis nếu muốn vĩnh viễn)
const keys = new Map(); // key -> { expire, content, createdAt }

// ============================================
// TIMEZONE HELPER — UTC+7 Việt Nam
// ============================================
function toVNTime(date) {
    return new Date(date.getTime() + 7 * 60 * 60 * 1000);
}

function formatVN(date) {
    const d = toVNTime(date);
    const pad = n => String(n).padStart(2, '0');
    return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} ` +
           `${pad(d.getUTCDate())}/${d.getUTCMonth() + 1}/${d.getUTCFullYear()}`;
}

function formatRemaining(ms) {
    if (ms <= 0) return 'Hết hạn';
    const s = Math.floor(ms / 1000);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    if (h > 0) return `${h}h ${m}m ${sec}s`;
    if (m > 0) return `${m}m ${sec}s`;
    return `${sec}s`;
}

// ============================================
// AUTH MIDDLEWARE — check serial
// ============================================
function isAdmin(req) {
    const serial = req.headers['x-device-serial'] 
                || req.query.serial 
                || (req.body && req.body.serial);
    return serial && ADMIN_SERIALS.includes(String(serial).trim());
}

// ============================================
// ROUTE: /api/check-key
// ============================================
app.get('/api/check-key', (req, res) => {
    const key = req.query.key;
    if (!key) {
        return res.status(400).json({ status: false, message: 'Thiếu key' });
    }
    const entry = keys.get(key);
    if (!entry) {
        return res.json({ status: false, message: 'Key không tồn tại' });
    }
    if (Date.now() > entry.expire) {
        keys.delete(key);
        return res.json({ status: false, message: 'Key đã hết hạn' });
    }
    return res.json({ status: true, message: 'OK', content: entry.content });
});

// ============================================
// ROUTE: / (trang chủ)
// ============================================
app.get('/', (req, res) => {
    const admin = isAdmin(req);
    res.send(renderHomePage(admin));
});

// ============================================
// ROUTE: /admin (chỉ cần serial đúng)
// ============================================
app.get('/admin', (req, res) => {
    if (!isAdmin(req)) {
        return res.status(404).send('Not Found');
    }
    res.send(renderAdminPage());
});

// ============================================
// API ADMIN: Tạo key
// ============================================
app.post('/api/create-key', (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });

    const { content, hours, minutes, seconds } = req.body;
    if (!content) return res.json({ ok: false, message: 'Thiếu nội dung' });

    const totalMs = (Number(hours) || 0) * 3600 * 1000
                  + (Number(minutes) || 0) * 60 * 1000
                  + (Number(seconds) || 0) * 1000;

    if (totalMs <= 0) return res.json({ ok: false, message: 'Thời hạn phải > 0' });

    const key = content;
    keys.set(key, {
        content: content,
        expire: Date.now() + totalMs,
        createdAt: Date.now(),
    });

    return res.json({ ok: true, key, expire: formatVN(new Date(Date.now() + totalMs)) });
});

// ============================================
// API ADMIN: Xóa key
// ============================================
app.post('/api/delete-key', (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    const { key } = req.body;
    keys.delete(key);
    return res.json({ ok: true });
});

// ============================================
// API ADMIN: Danh sách key
// ============================================
app.get('/api/list-keys', (req, res) => {
    if (!isAdmin(req)) return res.status(403).json({ ok: false });
    const list = [];
    const now = Date.now();
    for (const [k, v] of keys.entries()) {
        const remain = v.expire - now;
        if (remain <= 0) { keys.delete(k); continue; }
        list.push({
            key: k,
            content: v.content,
            remaining: formatRemaining(remain),
            expire: formatVN(new Date(v.expire)),
        });
    }
    return res.json({ ok: true, keys: list });
});

// ============================================
// HTML: Trang chủ cho user thường
// ============================================
function renderHomePage(admin) {
    return `<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NETSUPER API</title>
<style>
  body{margin:0;font-family:system-ui;background:linear-gradient(135deg,#1a1040,#0d0720);color:#fff;min-height:100vh;padding:20px;display:flex;align-items:center;justify-content:center}
  .card{max-width:400px;width:100%;background:rgba(30,20,60,0.7);border:1px solid rgba(139,92,246,0.3);border-radius:20px;padding:30px;text-align:center}
  h1{background:linear-gradient(90deg,#00F2FE,#8B5CF6);-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-size:26px;margin:0 0 16px}
  p{color:#94A3B8;font-size:14px;margin:8px 0}
  .status{padding:12px;background:rgba(16,185,129,0.15);border:1px solid rgba(16,185,129,0.4);border-radius:12px;color:#10B981;font-weight:600;margin-top:20px}
</style>
</head><body>
<div class="card">
  <h1>🚀 NETSUPER API</h1>
  <p>Hệ thống đang hoạt động</p>
  <div class="status">✅ ONLINE</div>
  <p style="margin-top:24px;font-size:12px;color:#64748B">Vui lòng mở app để lấy key</p>
</div>
</body></html>`;
}

// ============================================
// HTML: Admin panel (chỉ hiện khi serial đúng)
// ============================================
function renderAdminPage() {
    return `<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ADMIN PANEL</title>
<style>
  *{box-sizing:border-box}
  body{margin:0;font-family:system-ui;background:linear-gradient(135deg,#1a1040,#0d0720);color:#fff;min-height:100vh;padding:16px}
  .wrap{max-width:480px;margin:0 auto}
  h1{background:linear-gradient(90deg,#00F2FE,#8B5CF6);-webkit-background-clip:text;-webkit-text-fill-color:transparent;text-align:center;font-size:24px;margin:20px 0}
  .card{background:rgba(30,20,60,0.7);border:1px solid rgba(139,92,246,0.3);border-radius:20px;padding:20px;margin-bottom:16px}
  .card h2{color:#00F2FE;font-size:16px;margin:0 0 16px}
  label{display:block;color:#94A3B8;font-size:13px;margin:10px 0 6px}
  input{width:100%;padding:12px;background:rgba(10,5,25,0.6);border:1px solid rgba(139,92,246,0.4);border-radius:10px;color:#fff;font-size:14px}
  input:focus{outline:none;border-color:#00F2FE}
  .row{display:flex;gap:10px;margin-top:10px}
  .row input{flex:1}
  button{width:100%;padding:14px;background:linear-gradient(90deg,#00F2FE,#8B5CF6);border:none;border-radius:12px;color:#fff;font-weight:700;font-size:15px;cursor:pointer;margin-top:16px}
  button:active{transform:scale(0.98)}
  table{width:100%;font-size:12px;border-collapse:collapse;margin-top:10px}
  th,td{padding:8px 4px;text-align:left;border-bottom:1px solid rgba(139,92,246,0.2)}
  th{color:#94A3B8;font-weight:500}
  td.k{color:#FBBF24;font-weight:600}
  td.r{color:#10B981}
  .del{background:#EF4444;color:#fff;border:none;padding:6px 10px;border-radius:8px;cursor:pointer;width:auto}
  #msg{text-align:center;padding:10px;border-radius:10px;margin-top:10px;font-size:13px;display:none}
  .ok{background:rgba(16,185,129,0.2);color:#10B981}
  .err{background:rgba(239,68,68,0.2);color:#EF4444}
</style>
</head><body>
<div class="wrap">
  <h1>👑 ADMIN PANEL</h1>

  <div class="card">
    <h2>➕ TẠO KEY MỚI</h2>
    <label>🔑 Nội dung key (chữ gì cũng được)</label>
    <input id="content" placeholder="VD: VIP-ABC, Hello123, TEST-KEY">
    <label>⏱️ Thời hạn</label>
    <div class="row">
      <input id="h" type="number" placeholder="Giờ" value="0">
      <input id="m" type="number" placeholder="Phút" value="0">
      <input id="s" type="number" placeholder="Giây" value="0">
    </div>
    <button onclick="createKey()">⚡ TẠO KEY</button>
    <div id="msg"></div>
  </div>

  <div class="card">
    <h2>📋 DANH SÁCH KEY</h2>
    <table id="tbl"><thead><tr><th>KEY</th><th>CÒN LẠI</th><th>HẾT HẠN</th><th></th></tr></thead><tbody></tbody></table>
  </div>
</div>

<script>
  const serial = new URLSearchParams(location.search).get('serial') || '';

  function showMsg(text, ok) {
    const m = document.getElementById('msg');
    m.textContent = text;
    m.className = ok ? 'ok' : 'err';
    m.style.display = 'block';
    setTimeout(() => m.style.display = 'none', 3000);
  }

  async function createKey() {
    const content = document.getElementById('content').value.trim();
    const hours = document.getElementById('h').value || 0;
    const minutes = document.getElementById('m').value || 0;
    const seconds = document.getElementById('s').value || 0;
    if (!content) return showMsg('Nhập nội dung key!', false);
    const r = await fetch('/api/create-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Device-Serial': serial },
      body: JSON.stringify({ content, hours, minutes, seconds })
    });
    const j = await r.json();
    if (j.ok) { showMsg('✅ Đã tạo key: ' + j.key, true); loadKeys(); }
    else showMsg('❌ ' + (j.message || 'Lỗi'), false);
  }

  async function loadKeys() {
    const r = await fetch('/api/list-keys', { headers: { 'X-Device-Serial': serial } });
    const j = await r.json();
    const tb = document.querySelector('#tbl tbody');
    tb.innerHTML = '';
    if (!j.ok || !j.keys.length) {
      tb.innerHTML = '<tr><td colspan="4" style="text-align:center;color:#64748B">Chưa có key</td></tr>';
      return;
    }
    j.keys.forEach(k => {
      const tr = document.createElement('tr');
      tr.innerHTML = '<td class="k">' + k.key + '</td><td class="r">' + k.remaining + '</td><td>' + k.expire + '</td>';
      const td = document.createElement('td');
      const btn = document.createElement('button');
      btn.className = 'del';
      btn.textContent = '🗑';
      btn.onclick = async () => {
        await fetch('/api/delete-key', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Device-Serial': serial },
          body: JSON.stringify({ key: k.key })
        });
        loadKeys();
      };
      td.appendChild(btn);
      tr.appendChild(td);
      tb.appendChild(tr);
    });
  }

  loadKeys();
  setInterval(loadKeys, 5000);
</script>
</body></html>`;
}

// ============================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Server running on port ' + PORT));

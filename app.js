// ============================================================
//  NETSUPER SERVER - app.js (v2)
//  - Admin vào bằng IP HOẶC secret key
//  - User vượt Link4M → server TỰ SINH KEY random
// ============================================================

const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('trust proxy', true);

// ============================================================
//  CẤU HÌNH
// ============================================================
const LINK4M_API = "6a61ce8626fd3a13155f6529";

// IP được coi là admin (LAN + localhost)
const ADMIN_IPS = (process.env.ADMIN_IP || "192.168.1.17,127.0.0.1,::1")
  .split(',').map(s => s.trim()).filter(Boolean);

// 🔑 SECRET để vào admin bất chấp IP (dùng khi deploy Render)
const ADMIN_SECRET = process.env.ADMIN_SECRET || "NETSUPER2024";

// Thời hạn mặc định cho key tự sinh (giây) - 24h
const AUTO_KEY_DURATION = parseInt(process.env.AUTO_KEY_DURATION) || 86400;

const KEYS_FILE   = path.join(__dirname, "dynamic-keys.json");
const TOKENS_FILE = path.join(__dirname, "tokens.json");

// ============================================================
//  STORAGE
// ============================================================
let dynamicKeys  = {};
let pendingTokens = {};

try { dynamicKeys   = JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8')); } catch {}
try { pendingTokens = JSON.parse(fs.readFileSync(TOKENS_FILE, 'utf8')); } catch {}

const saveKeys   = () => fs.writeFileSync(KEYS_FILE, JSON.stringify(dynamicKeys, null, 2));
const saveTokens = () => fs.writeFileSync(TOKENS_FILE, JSON.stringify(pendingTokens, null, 2));

// ============================================================
//  HELPERS
// ============================================================
function getClientIp(req) {
  let ip = '';
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) ip = fwd.split(',')[0].trim();
  if (!ip) ip = req.socket?.remoteAddress || req.ip || '';
  // Bỏ prefix IPv6-mapped
  if (ip.startsWith('::ffff:')) ip = ip.substring(7);
  // Chuẩn hóa localhost IPv6
  if (ip === '::1') ip = '127.0.0.1';
  return ip;
}

function isAdmin(req) {
  // Cách 1: khớp IP
  const ip = getClientIp(req);
  if (ADMIN_IPS.includes(ip)) return true;
  // Cách 2: khớp secret (dùng khi deploy Render)
  const secret = req.query.secret || req.body?.secret;
  if (secret && secret === ADMIN_SECRET) return true;
  return false;
}

function randomToken(len = 24) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let s = '';
  for (let i = 0; i < len; i++) s += chars[Math.floor(Math.random() * chars.length)];
  return s;
}

function randomKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const block = () => {
    let s = '';
    for (let i = 0; i < 4; i++) s += chars[Math.floor(Math.random() * chars.length)];
    return s;
  };
  return `NETSUPER-${block()}-${block()}-${block()}`;
}

function generateUniqueKey() {
  let k;
  do { k = randomKey(); } while (dynamicKeys[k]);
  return k;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function formatDuration(seconds) {
  seconds = Math.max(0, Math.floor(seconds));
  if (seconds === 0) return '0s';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  const p = [];
  if (h > 0) p.push(h + 'h');
  if (m > 0) p.push(m + 'm');
  if (s > 0 || p.length === 0) p.push(s + 's');
  return p.join(' ');
}

function cleanupExpired() {
  const now = Date.now();
  let changed = false;
  for (const k in dynamicKeys) {
    if (dynamicKeys[k].expireAt < now) { delete dynamicKeys[k]; changed = true; }
  }
  if (changed) saveKeys();

  changed = false;
  for (const t in pendingTokens) {
    if (now - pendingTokens[t].createdAt > 3600_000) { delete pendingTokens[t]; changed = true; }
  }
  if (changed) saveTokens();
}

setInterval(cleanupExpired, 5 * 60 * 1000);

// ============================================================
//  CSS
// ============================================================
const CSS = `
* { margin:0; padding:0; box-sizing:border-box; font-family:'Segoe UI',Arial,sans-serif; }
body { min-height:100vh; display:flex; align-items:center; justify-content:center;
  background:linear-gradient(135deg,#0f0c29,#302b63,#24243e); padding:20px; color:#fff; }
.box { background:rgba(255,255,255,.06); border:1px solid rgba(255,255,255,.12);
  backdrop-filter:blur(10px); border-radius:18px; padding:24px;
  max-width:700px; width:100%; box-shadow:0 20px 60px rgba(0,0,0,.5); }
h1 { font-size:20px; text-align:center; margin-bottom:6px;
  background:linear-gradient(90deg,#00e5ff,#a855f7);
  -webkit-background-clip:text; -webkit-text-fill-color:transparent; }
.sub { font-size:12px; text-align:center; color:#9ca3af; margin-bottom:18px; }
label { display:block; font-weight:600; font-size:13px; margin-bottom:6px; color:#cbd5e1; }
input { width:100%; padding:12px 14px; border:2px solid rgba(255,255,255,.15);
  border-radius:10px; font-size:14px; outline:none;
  background:rgba(0,0,0,.3); color:#fff; transition:.2s; font-family:monospace; }
input:focus { border-color:#00e5ff; box-shadow:0 0 0 3px rgba(0,229,255,.2); }
.field { margin-bottom:12px; }
button.main { width:100%; padding:13px; margin-top:8px; border:none; border-radius:10px;
  background:linear-gradient(135deg,#00e5ff,#a855f7); color:#fff;
  font-size:15px; font-weight:700; cursor:pointer; transition:.2s; }
button.main:hover { transform:translateY(-2px); box-shadow:0 8px 25px rgba(0,229,255,.4); }
.key-display { text-align:center; padding:26px 12px; margin:16px 0;
  background:linear-gradient(135deg,rgba(0,229,255,.12),rgba(168,85,247,.12));
  border:1px solid rgba(0,229,255,.35); border-radius:12px; }
.key-label { font-size:11px; color:#00e5ff; letter-spacing:2px; font-weight:700; }
.key-value { font-family:'Courier New',monospace; font-size:24px; font-weight:900;
  margin-top:10px; letter-spacing:1.5px;
  background:linear-gradient(90deg,#00e5ff,#a855f7,#00e5ff);
  background-size:200% auto;
  -webkit-background-clip:text; -webkit-text-fill-color:transparent;
  animation:shine 3s linear infinite; word-break:break-all; }
@keyframes shine { to { background-position:200% center; } }
.info { font-size:11px; color:#9ca3af; margin-top:6px; line-height:1.5; }
.tag { display:inline-block; padding:3px 8px; border-radius:6px;
  background:rgba(0,229,255,.15); color:#00e5ff; font-size:11px; font-weight:700; margin:2px; }
.badge-ok { background:rgba(34,197,94,.2); color:#4ade80; }
.badge-err { background:rgba(239,68,68,.2); color:#f87171; }
table { width:100%; border-collapse:collapse; margin-top:10px; font-size:12px; }
th, td { padding:8px 6px; text-align:left; border-bottom:1px solid rgba(255,255,255,.08); }
th { color:#9ca3af; font-weight:700; font-size:11px; letter-spacing:.5px; }
td code { font-family:monospace; color:#fbbf24; word-break:break-all; }
.del { background:rgba(239,68,68,.2); color:#f87171; border:none;
  padding:6px 10px; border-radius:6px; cursor:pointer; font-size:12px; }
.del:hover { background:#ef4444; color:#fff; }
.row3 { display:grid; grid-template-columns:1fr 1fr 1fr; gap:8px; }
.section-title { font-size:13px; color:#cbd5e1; font-weight:700; margin:20px 0 6px;
  display:flex; justify-content:space-between; align-items:center; }
.section-title span { font-size:11px; color:#9ca3af; font-weight:400; }
.btn-big { font-size:18px !important; padding:20px !important; letter-spacing:1px; }
.error-page { text-align:center; padding:30px 20px; }
.error-page h2 { font-size:22px; color:#f87171; margin-bottom:12px; }
.error-page p { color:#9ca3af; font-size:14px; line-height:1.7; }
.debug { background:rgba(251,191,36,.1); border:1px solid rgba(251,191,36,.3);
  border-radius:8px; padding:10px; margin-top:14px; font-size:11px; color:#fbbf24; }
.debug code { color:#fff; background:rgba(0,0,0,.3); padding:2px 6px; border-radius:4px; }
`;

// ============================================================
//  ROUTE / : ADMIN → /admin  |  USER → trang GET KEY
// ============================================================
app.get('/', (req, res) => {
  if (isAdmin(req)) return res.redirect('/admin' + (req.query.secret ? '?secret=' + req.query.secret : ''));

  const ip = getClientIp(req);

  res.send(`<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GET KEY - NETSUPER</title>
<style>${CSS}</style>
</head>
<body>
<div class="box">
  <h1>🔑 GET KEY MIỄN PHÍ</h1>
  <p class="sub">Nhận key bảo mật chỉ với vài bước</p>

  <div style="background:rgba(0,0,0,.3);padding:14px;border-radius:10px;margin-bottom:16px;">
    <div style="font-size:13px;color:#cbd5e1;line-height:1.9;">
      <div>1️⃣ Nhấn nút <b style="color:#00e5ff">LẤY KEY NGAY</b></div>
      <div>2️⃣ Vượt qua <b style="color:#a855f7">Link4M</b></div>
      <div>3️⃣ Nhận <b style="color:#fbbf24">key tự động</b> ngay sau đó</div>
    </div>
  </div>

  <a href="/get-key" style="text-decoration:none;">
    <button class="main btn-big">🚀 LẤY KEY NGAY</button>
  </a>

  <div class="debug">
    🔍 IP của bạn: <code>${escapeHtml(ip)}</code><br>
    💡 Nếu bạn là admin, vào: <code>/admin?secret=NETSUPER2024</code>
  </div>
</div>
</body>
</html>`);
});

// ============================================================
//  ROUTE /admin
// ============================================================
app.get('/admin', (req, res) => {
  if (!isAdmin(req)) {
    return res.status(403).send(`<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>403</title><style>${CSS}</style></head><body>
<div class="box"><div class="error-page">
<h2>⛔ 403 - Không có quyền</h2>
<p>IP của bạn: <code>${escapeHtml(getClientIp(req))}</code><br><br>
Nếu là admin, thêm <code>?secret=NETSUPER2024</code> vào URL.</p>
<a href="/" style="text-decoration:none;"><button class="main" style="margin-top:20px;">← Về trang chủ</button></a>
</div></div></body></html>`);
  }

  cleanupExpired();

  const now = Date.now();
  const list = Object.entries(dynamicKeys).sort((a,b) => a[1].expireAt - b[1].expireAt);
  const secretQS = req.query.secret ? '?secret=' + encodeURIComponent(req.query.secret) : '';

  const rows = list.length === 0
    ? `<tr><td colspan="4" style="text-align:center;color:#9ca3af;padding:20px;">Chưa có key nào</td></tr>`
    : list.map(([k, v]) => {
        const remain = Math.max(0, Math.floor((v.expireAt - now) / 1000));
        return `<tr>
          <td><code>${escapeHtml(k)}</code></td>
          <td><span class="tag ${remain > 0 ? 'badge-ok' : 'badge-err'}">${remain > 0 ? formatDuration(remain) : 'Hết hạn'}</span></td>
          <td style="font-size:11px;color:#9ca3af;">${new Date(v.expireAt).toLocaleString('vi-VN')}</td>
          <td style="text-align:right;">
            <form method="POST" action="/admin/delete${secretQS}" style="display:inline;" onsubmit="return confirm('Xóa key này?');">
              <input type="hidden" name="key" value="${escapeHtml(k)}">
              ${req.query.secret ? `<input type="hidden" name="secret" value="${escapeHtml(req.query.secret)}">` : ''}
              <button class="del" type="submit">🗑️</button>
            </form>
          </td>
        </tr>`;
      }).join('');

  res.send(`<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ADMIN - NETSUPER</title>
<style>${CSS}</style>
</head>
<body>
<div class="box" style="max-width:780px;">
  <h1>👑 ADMIN PANEL</h1>
  <p class="sub">IP: <code style="color:#fbbf24">${escapeHtml(getClientIp(req))}</code></p>

  <div style="background:rgba(0,0,0,.3);padding:16px;border-radius:12px;">
    <div style="font-size:14px;font-weight:700;margin-bottom:12px;color:#00e5ff;">➕ TẠO KEY MỚI</div>
    <form method="POST" action="/admin/create${secretQS}">
      <div class="field">
        <label>🔑 Nội dung key (chữ gì cũng được)</label>
        <input name="key" placeholder="VD: VIP-ABC, Hello123, TEST-KEY" required>
      </div>
      <div class="field">
        <label>⏱️ Thời hạn</label>
        <div class="row3">
          <input type="number" name="h" min="0" value="0" placeholder="Giờ">
          <input type="number" name="m" min="0" value="0" placeholder="Phút">
          <input type="number" name="s" min="0" value="0" placeholder="Giây">
        </div>
      </div>
      <button class="main" type="submit">⚡ TẠO KEY</button>
    </form>
  </div>

  <div class="section-title">
    <span>📋 DANH SÁCH KEY (${list.length})</span>
    <span>Auto-key: ${formatDuration(AUTO_KEY_DURATION)}</span>
  </div>
  <div style="max-height:340px;overflow:auto;">
    <table>
      <thead><tr><th>KEY</th><th>CÒN LẠI</th><th>HẾT HẠN</th><th></th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>

  <div class="info" style="text-align:center;margin-top:16px;">
    💡 User vượt Link4M xong → server TỰ SINH KEY random (thời hạn ${formatDuration(AUTO_KEY_DURATION)})
  </div>
</div>
</body>
</html>`);
});

app.post('/admin/create', (req, res) => {
  if (!isAdmin(req)) return res.status(403).send('403');
  const secretQS = req.query.secret ? '?secret=' + encodeURIComponent(req.query.secret) : '';

  const key = (req.body.key || '').trim();
  if (!key) return res.redirect('/admin' + secretQS);

  const h = parseInt(req.body.h) || 0;
  const m = parseInt(req.body.m) || 0;
  const s = parseInt(req.body.s) || 0;
  const durationMs = (h * 3600 + m * 60 + s) * 1000;

  if (durationMs <= 0) return res.redirect('/admin' + secretQS);

  dynamicKeys[key] = {
    expireAt: Date.now() + durationMs,
    createdAt: Date.now(),
    duration: `${h}h${m}m${s}s`,
    auto: false
  };
  saveKeys();
  res.redirect('/admin' + secretQS);
});

app.post('/admin/delete', (req, res) => {
  if (!isAdmin(req)) return res.status(403).send('403');
  const secretQS = req.query.secret ? '?secret=' + encodeURIComponent(req.query.secret) : '';
  const key = req.body.key;
  if (key && dynamicKeys[key]) { delete dynamicKeys[key]; saveKeys(); }
  res.redirect('/admin' + secretQS);
});

// ============================================================
//  GET /get-key : SINH TOKEN + REDIRECT SANG LINK4M
// ============================================================
app.get('/get-key', (req, res) => {
  const token = randomToken();
  pendingTokens[token] = { createdAt: Date.now(), ip: getClientIp(req) };
  saveTokens();

  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  const callbackUrl = `${proto}://${host}/callback?token=${token}`;

  const link4mUrl = `https://link4m.co/st?api=${LINK4M_API}&url=${encodeURIComponent(callbackUrl)}`;
  console.log('🔄 Redirect user → Link4M. Callback:', callbackUrl);
  res.redirect(link4mUrl);
});

// ============================================================
//  GET /callback : SAU KHI VƯỢT LINK4M → TỰ SINH KEY
// ============================================================
app.get('/callback', (req, res) => {
  const token = req.query.token;

  if (!token || !pendingTokens[token]) {
    return res.status(400).send(`<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Lỗi</title><style>${CSS}</style></head><body><div class="box">
<div class="error-page">
<h2>❌ Token không hợp lệ</h2>
<p>Token đã hết hạn hoặc đã được sử dụng.<br>Vui lòng quay lại và lấy key mới.</p>
<a href="/" style="text-decoration:none;"><button class="main" style="margin-top:20px;">← Về trang chủ</button></a>
</div></div></body></html>`);
  }

  delete pendingTokens[token];
  saveTokens();
  cleanupExpired();

  // 🔥 TỰ SINH KEY RANDOM MỚI (không cần admin tạo trước)
  const newKey = generateUniqueKey();
  dynamicKeys[newKey] = {
    expireAt: Date.now() + AUTO_KEY_DURATION * 1000,
    createdAt: Date.now(),
    duration: formatDuration(AUTO_KEY_DURATION),
    auto: true,
    fromIp: getClientIp(req)
  };
  saveKeys();

  console.log(`✅ Đã tạo key tự động: ${newKey}`);

  res.send(`<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Key của bạn</title>
<style>${CSS}</style>
</head>
<body>
<div class="box">
  <h1>🎉 NHẬN KEY THÀNH CÔNG</h1>
  <p class="sub">Key được tạo tự động cho bạn</p>

  <div class="key-display">
    <div class="key-label">KEY CỦA BẠN</div>
    <div class="key-value" id="keyVal">${escapeHtml(newKey)}</div>
  </div>

  <div style="text-align:center;margin-bottom:14px;">
    <span class="tag badge-ok">⏱️ Hiệu lực: ${formatDuration(AUTO_KEY_DURATION)}</span>
  </div>

  <button class="main" id="copyBtn">📋 SAO CHÉP KEY</button>

  <a href="/" style="text-decoration:none;">
    <button class="main" style="background:rgba(255,255,255,.1);margin-top:8px;">🔄 LẤY KEY KHÁC</button>
  </a>
</div>

<script>
document.getElementById('copyBtn').onclick = function(e) {
  var k = document.getElementById('keyVal').textContent;
  navigator.clipboard.writeText(k).then(function() {
    var b = e.target, old = b.textContent;
    b.textContent = '✅ ĐÃ COPY!';
    setTimeout(function(){ b.textContent = old; }, 1500);
  }).catch(function(){ alert('Không copy được!'); });
};
</script>
</body>
</html>`);
});

// ============================================================
//  API CHECK KEY
// ============================================================
app.get('/api/check-key', (req, res) => {
  const key = req.query.key;
  if (!key) return res.status(400).json({ status: false, message: 'Thiếu key!' });

  cleanupExpired();

  if (dynamicKeys[key]) {
    const remain = Math.max(0, Math.floor((dynamicKeys[key].expireAt - Date.now()) / 1000));
    if (remain > 0) {
      return res.json({
        status: true,
        message: 'Key hợp lệ!',
        data: {
          key,
          expire_at: new Date(dynamicKeys[key].expireAt).toISOString(),
          remain_seconds: remain,
          remain_text: formatDuration(remain),
          auto: dynamicKeys[key].auto || false
        }
      });
    }
    delete dynamicKeys[key];
    saveKeys();
  }

  res.json({ status: false, message: 'Key không tồn tại hoặc đã hết hạn!' });
});

// ============================================================
//  KHỞI ĐỘNG
// ============================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log('🚀 Server chạy ở port ' + PORT);
  console.log('👑 Admin IPs: ' + ADMIN_IPS.join(', '));
  console.log('🔑 Admin secret: ' + ADMIN_SECRET);
  console.log('🌐 User:  http://localhost:' + PORT + '/');
  console.log('👑 Admin: http://localhost:' + PORT + '/admin?secret=' + ADMIN_SECRET);
  console.log('⏱️  Key tự sinh có hiệu lực: ' + formatDuration(AUTO_KEY_DURATION));
});

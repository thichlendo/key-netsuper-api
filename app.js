// ============================================================
//  NETSUPER SERVER - app.js
//  Admin (theo IP) tạo key + User vượt Link4M nhận key
// ============================================================

const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('trust proxy', true); // Để lấy IP đúng sau proxy (Render/Cloudflare)

// ============================================================
//  CẤU HÌNH
// ============================================================
const LINK4M_API = "6a61ce8626fd3a13155f6529";

// Danh sách IP được coi là ADMIN (cách nhau dấu phẩy)
// 192.168.1.17 = IP LAN theo yêu cầu
// 127.0.0.1 và ::1 để test local
const ADMIN_IPS = (process.env.ADMIN_IP || "192.168.1.17,127.0.0.1,::1")
  .split(',').map(s => s.trim()).filter(Boolean);

// File lưu key động + token
const KEYS_FILE   = path.join(__dirname, "dynamic-keys.json");
const TOKENS_FILE = path.join(__dirname, "tokens.json");

// ============================================================
//  LƯU TRỮ (JSON file, không cần database)
// ============================================================
let dynamicKeys  = {}; // { "KEY": { expireAt, createdAt, duration } }
let pendingTokens = {}; // { "token": { createdAt } }

try { dynamicKeys   = JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8')); } catch {}
try { pendingTokens = JSON.parse(fs.readFileSync(TOKENS_FILE, 'utf8')); } catch {}

const saveKeys   = () => fs.writeFileSync(KEYS_FILE, JSON.stringify(dynamicKeys, null, 2));
const saveTokens = () => fs.writeFileSync(TOKENS_FILE, JSON.stringify(pendingTokens, null, 2));

// ============================================================
//  HELPERS
// ============================================================
function getClientIp(req) {
  let ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
        || req.socket?.remoteAddress
        || req.ip
        || '';
  if (ip.startsWith('::ffff:')) ip = ip.substring(7);
  return ip;
}

function isAdmin(req) {
  return ADMIN_IPS.includes(getClientIp(req));
}

function randomToken(len = 24) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let s = '';
  for (let i = 0; i < len; i++) s += chars[Math.floor(Math.random() * chars.length)];
  return s;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function formatDuration(seconds) {
  if (seconds <= 0) return '0s';
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

// Chạy cleanup mỗi 5 phút
setInterval(cleanupExpired, 5 * 60 * 1000);

// ============================================================
//  CSS DÙNG CHUNG
// ============================================================
const CSS = `
* { margin:0; padding:0; box-sizing:border-box; font-family:'Segoe UI',Arial,sans-serif; }
body { min-height:100vh; display:flex; align-items:center; justify-content:center;
  background:linear-gradient(135deg,#0f0c29,#302b63,#24243e); padding:20px; color:#fff; }
.box { background:rgba(255,255,255,.06); border:1px solid rgba(255,255,255,.12);
  backdrop-filter:blur(10px); border-radius:18px; padding:24px;
  max-width:680px; width:100%; box-shadow:0 20px 60px rgba(0,0,0,.5); }
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
button.ghost { background:rgba(255,255,255,.1); color:#fff; padding:12px 16px; border:none;
  border-radius:10px; font-weight:700; cursor:pointer; font-size:14px; }
button.ghost:hover { background:#00e5ff; color:#000; }
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
.badge-warn { background:rgba(251,191,36,.2); color:#fbbf24; }
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
`;

// ============================================================
//  ROUTE / : ADMIN → /admin  |  USER → trang GET KEY
// ============================================================
app.get('/', (req, res) => {
  if (isAdmin(req)) return res.redirect('/admin');

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
      <div>3️⃣ Quay về nhận <b style="color:#fbbf24">key</b> tự động</div>
    </div>
  </div>

  <a href="/get-key" style="text-decoration:none;">
    <button class="main btn-big">🚀 LẤY KEY NGAY</button>
  </a>

  <div class="info" style="text-align:center;margin-top:16px;">
    ⚡ Key miễn phí • Không cần đăng ký • Nhận ngay sau khi vượt
  </div>
</div>
</body>
</html>`);
});

// ============================================================
//  ROUTE /admin : CHỈ ADMIN (theo IP)
// ============================================================
app.get('/admin', (req, res) => {
  if (!isAdmin(req)) {
    return res.status(403).send(`<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>403</title><style>${CSS}</style></head><body>
<div class="box"><div class="error-page">
<h2>⛔ 403 - Không có quyền</h2>
<p>Trang này chỉ dành cho admin.<br>IP của bạn: <code>${escapeHtml(getClientIp(req))}</code></p>
<a href="/" style="text-decoration:none;"><button class="main" style="margin-top:20px;">← Về trang chủ</button></a>
</div></div></body></html>`);
  }

  cleanupExpired();

  const now = Date.now();
  const list = Object.entries(dynamicKeys).sort((a,b) => a[1].expireAt - b[1].expireAt);

  const rows = list.length === 0
    ? `<tr><td colspan="4" style="text-align:center;color:#9ca3af;padding:20px;">Chưa có key nào</td></tr>`
    : list.map(([k, v]) => {
        const remain = Math.max(0, Math.floor((v.expireAt - now) / 1000));
        const isExpired = remain <= 0;
        return `<tr>
          <td><code>${escapeHtml(k)}</code></td>
          <td><span class="tag ${isExpired ? 'badge-err' : 'badge-ok'}">${isExpired ? 'Hết hạn' : formatDuration(remain)}</span></td>
          <td style="font-size:11px;color:#9ca3af;">${new Date(v.expireAt).toLocaleString('vi-VN')}</td>
          <td style="text-align:right;">
            <form method="POST" action="/admin/delete" style="display:inline;" onsubmit="return confirm('Xóa key này?');">
              <input type="hidden" name="key" value="${escapeHtml(k)}">
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
<div class="box" style="max-width:760px;">
  <h1>👑 ADMIN PANEL</h1>
  <p class="sub">Chào admin <code style="color:#fbbf24">${escapeHtml(getClientIp(req))}</code></p>

  <!-- FORM TẠO KEY -->
  <div style="background:rgba(0,0,0,.3);padding:16px;border-radius:12px;">
    <div style="font-size:14px;font-weight:700;margin-bottom:12px;color:#00e5ff;">➕ TẠO KEY MỚI</div>
    <form method="POST" action="/admin/create">
      <div class="field">
        <label>🔑 Nội dung key (chữ gì cũng được)</label>
        <input name="key" placeholder="VD: VIP-ABC-123 hoặc HelloWorld123" required>
      </div>
      <div class="field">
        <label>⏱️ Thời hạn</label>
        <div class="row3">
          <input type="number" name="h" min="0" value="0" placeholder="Giờ">
          <input type="number" name="m" min="0" value="0" placeholder="Phút">
          <input type="number" name="s" min="0" value="0" placeholder="Giây">
        </div>
        <div class="info">💡 Nhập số vào ô tương ứng — có thể để 0 nếu không dùng</div>
      </div>
      <button class="main" type="submit">⚡ TẠO KEY</button>
    </form>
  </div>

  <!-- DANH SÁCH KEY -->
  <div class="section-title">
    <span style="font-size:14px;color:#cbd5e1;font-weight:700;">📋 DANH SÁCH KEY</span>
    <span>${list.length} key đang hoạt động</span>
  </div>
  <div style="max-height:340px;overflow:auto;">
    <table>
      <thead><tr><th>KEY</th><th>CÒN LẠI</th><th>HẾT HẠN</th><th></th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>

  <div class="info" style="text-align:center;margin-top:16px;">
    🌐 User vào web sẽ thấy nút GET KEY → vượt Link4M → nhận 1 key ngẫu nhiên
  </div>
</div>
</body>
</html>`);
});

// ============================================================
//  POST /admin/create : TẠO KEY
// ============================================================
app.post('/admin/create', (req, res) => {
  if (!isAdmin(req)) return res.status(403).send('403');

  let key = (req.body.key || '').trim();
  if (!key) return res.redirect('/admin?err=empty');

  const h = parseInt(req.body.h) || 0;
  const m = parseInt(req.body.m) || 0;
  const s = parseInt(req.body.s) || 0;
  const durationMs = (h * 3600 + m * 60 + s) * 1000;

  if (durationMs <= 0) return res.redirect('/admin?err=duration');

  dynamicKeys[key] = {
    expireAt: Date.now() + durationMs,
    createdAt: Date.now(),
    duration: `${h}h${m}m${s}s`
  };
  saveKeys();
  res.redirect('/admin?ok=created');
});

// ============================================================
//  POST /admin/delete : XÓA KEY
// ============================================================
app.post('/admin/delete', (req, res) => {
  if (!isAdmin(req)) return res.status(403).send('403');
  const key = req.body.key;
  if (key && dynamicKeys[key]) {
    delete dynamicKeys[key];
    saveKeys();
  }
  res.redirect('/admin');
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
  res.redirect(link4mUrl);
});

// ============================================================
//  GET /callback : SAU KHI VƯỢT LINK4M → NHẬN KEY
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

  const keys = Object.keys(dynamicKeys);
  if (keys.length === 0) {
    return res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Hết key</title><style>${CSS}</style></head><body><div class="box">
<div class="error-page">
<h2>😢 Hết key rồi!</h2>
<p>Hiện chưa có key nào trong hệ thống.<br>Vui lòng quay lại sau.</p>
<a href="/" style="text-decoration:none;"><button class="main" style="margin-top:20px;">← Về trang chủ</button></a>
</div></div></body></html>`);
  }

  // Chọn 1 key ngẫu nhiên
  const chosen = keys[Math.floor(Math.random() * keys.length)];
  const info = dynamicKeys[chosen];
  const remaining = Math.max(0, Math.floor((info.expireAt - Date.now()) / 1000));

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
  <p class="sub">Sao chép key bên dưới để sử dụng</p>

  <div class="key-display">
    <div class="key-label">KEY CỦA BẠN</div>
    <div class="key-value" id="keyVal">${escapeHtml(chosen)}</div>
  </div>

  <div style="text-align:center;margin-bottom:14px;">
    <span class="tag badge-ok">⏱️ Còn lại: ${formatDuration(remaining)}</span>
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
//  API CHECK KEY (dùng cho app/tool khác)
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
          remain_text: formatDuration(remain)
        }
      });
    }
    delete dynamicKeys[key];
    saveKeys();
  }

  res.json({ status: false, message: 'Key không tồn tại hoặc đã hết hạn!' });
});

// API danh sách key (cho admin xem)
app.get('/api/keys', (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ status: false });
  cleanupExpired();
  res.json(Object.keys(dynamicKeys));
});

// ============================================================
//  KHỞI ĐỘNG
// ============================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('🚀 Server running on port ' + PORT);
  console.log('👑 Admin IPs: ' + ADMIN_IPS.join(', '));
  console.log('🌐 User: http://localhost:' + PORT + '/');
  console.log('👑 Admin: http://localhost:' + PORT + '/admin');
});

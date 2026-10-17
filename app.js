const http = require('http');
const https = require('https');
const url = require('url');

// =========================================================================
// CẤU HÌNH CỦA BẠN
// =========================================================================
const PORT = 3000;
const SITETOP_API_TOKEN = 'cAOeedGlhCojd3ACNJtnAUI5';

// Để Server tự động đọc được con số "Hoàn thành: 1" từ trang quản lý SiteTop,
// bạn dán Cookie đăng nhập trang sitetop.net của bạn vào đây (F12 -> Application -> Cookies)
let SITETOP_COOKIE = ''; 

// Lưu trữ các phiên test trong bộ nhớ
const testSessions = new Map();

// Hàm gọi API SiteTop tạo link rút gọn mới
function createSiteTopLink(destinationUrl) {
  return new Promise((resolve, reject) => {
    const apiUrl = `https://sitetop.net/api?api=${SITETOP_API_TOKEN}&url=${encodeURIComponent(destinationUrl)}`;
    https.get(apiUrl, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error('Phản hồi từ SiteTop không phải JSON: ' + data));
        }
      });
    }).on('error', reject);
  });
}

// Hàm chui vào trang https://sitetop.net/user/ để soi con số "Hoàn thành" của mã link
function checkSiteTopViewCount(slug, cookieStr) {
  return new Promise((resolve) => {
    if (!cookieStr) {
      return resolve({ scraped: false, views: null, note: 'Chưa nhập Cookie SiteTop nên chỉ kiểm tra qua Thời gian & Referer' });
    }

    const options = {
      hostname: 'sitetop.net',
      path: `/user/?search=${slug}`,
      method: 'GET',
      headers: {
        'Cookie': cookieStr,
        'User-Agent': 'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/128.0.0.0 Mobile Safari/537.36'
      }
    };

    const req = https.request(options, (res) => {
      let html = '';
      res.on('data', chunk => html += chunk);
      res.on('end', () => {
        // Tìm vị trí mã slug (ví dụ: 8jxd3c) trong HTML và đọc số nằm sau chữ "Hoàn thành"
        const slugIndex = html.indexOf(slug);
        if (slugIndex === -1) {
          return resolve({ scraped: true, views: 0, note: 'Không tìm thấy mã link hoặc Cookie hết hạn' });
        }
        const snippet = html.substring(slugIndex, slugIndex + 1500);
        const match = snippet.match(/Hoàn thành[\s\S]*?>\s*(\d+)\s*</i) || snippet.match(/Hoàn thành[^0-9]*([0-9]+)/i);
        const views = match ? parseInt(match[1], 10) : 0;
        resolve({ scraped: true, views, note: `Đọc trực tiếp từ SiteTop: Hoàn thành = ${views}` });
      });
    });

    req.on('error', () => resolve({ scraped: false, views: 0, note: 'Lỗi kết nối tới SiteTop' }));
    req.end();
  });
}

// Khởi tạo Web Server Test
const server = http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;

  // 1. TRANG GIAO DIỆN TEST CHÍNH
  if (pathname === '/' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`
<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Bộ Test Check View Thực Tế — SiteTop Anti-Bypass</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen p-4 sm:p-8 font-sans">
  <div class="max-w-2xl mx-auto space-y-6">
    
    <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl">
      <h1 class="text-xl font-black text-teal-400">🧪 PHÒNG THÍ NGHIỆM TEST CHECK VIEW SITETOP</h1>
      <p class="text-xs text-slate-400 mt-1">
        Kiểm tra thực tế: Vượt thật trên SiteTop vs. Bấm thẳng vào Link Đích (Bypass).
      </p>

      <!-- Ô nhập Cookie tùy chọn -->
      <div class="mt-4 pt-4 border-t border-slate-800 space-y-2 text-xs">
        <label class="font-bold text-amber-400 block">Cookie phiên đăng nhập SiteTop.net (Tùy chọn để Bot tự đọc cột "Hoàn thành"):</label>
        <input id="cookie-input" type="text" placeholder="Dán Cookie từ F12 (VD: PHPSESSID=xxxx...) hoặc bỏ trống để test bằng Callback" class="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2.5 text-slate-200 font-mono" />
      </div>

      <button onclick="createNewTestLink()" id="btn-create" class="mt-4 w-full bg-teal-500 hover:bg-teal-400 text-slate-950 font-black py-3.5 rounded-xl text-sm transition shadow-lg">
        ⚡ BƯỚC 1: GỌI API TẠO LINK RÚT GỌN SITETOP MỚI ĐỂ TEST
      </button>
    </div>

    <!-- Khu vực hiển thị Link vừa tạo -->
    <div id="test-arena" class="hidden bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-5 shadow-xl">
      <div class="flex items-center justify-between border-b border-slate-800 pb-3">
        <span class="text-xs font-bold uppercase text-slate-400">Phiên Test: <b id="session-id-txt" class="text-white font-mono">---</b></span>
        <span class="text-xs font-mono bg-amber-500/20 text-amber-300 px-3 py-1 rounded-full">Đã trôi qua: <b id="timer-txt">0</b>s</span>
      </div>

      <div class="space-y-3 text-xs">
        <!-- Lựa chọn A: Vượt thật -->
        <div class="p-4 bg-emerald-950/30 border border-emerald-500/40 rounded-xl space-y-2">
          <div class="font-extrabold text-emerald-400 text-sm">CÁCH A: VƯỢT LINK THẬT TRÊN SITETOP (HỢP LỆ)</div>
          <p class="text-slate-300">Bấm vào link rút gọn bên dưới, làm đủ nhiệm vụ trên SiteTop (mất khoảng 70s - 80s). Khi xong, SiteTop sẽ tự chuyển hướng bạn về Link Đích và ghi nhận <b>Hoàn thành = 1</b>.</p>
          <div class="font-mono font-bold text-teal-300 bg-slate-950 p-2.5 rounded border border-slate-800 break-all" id="short-url-txt">https://sitetop.net/...</div>
          <a id="short-url-btn" href="#" target="_blank" class="inline-block bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-black px-4 py-2 rounded-lg">
            👉 Mở Link Rút Gọn Để Vượt Thật ↗
          </a>
        </div>

        <!-- Lựa chọn B: Gian lận mở thẳng link đích -->
        <div class="p-4 bg-rose-950/30 border border-rose-500/40 rounded-xl space-y-2">
          <div class="font-extrabold text-rose-400 text-sm">CÁCH B: GIAN LẬN — BẤM THẲNG VÀO LINK ĐÍCH (KHÔNG VƯỢT)</div>
          <p class="text-slate-300">Giả sử kẻ gian lấy được Link Đích và bấm vào luôn mà không qua SiteTop. Hãy bấm thử để xem hệ thống phát hiện và chặn lại như thế nào:</p>
          <div class="font-mono text-slate-400 bg-slate-950 p-2.5 rounded border border-slate-800 break-all" id="dest-url-txt">http://localhost:3000/callback?...</div>
          <a id="dest-url-btn" href="#" target="_blank" class="inline-block bg-rose-600 hover:bg-rose-500 text-white font-bold px-4 py-2 rounded-lg">
            🚫 Thử Gian Lận: Mở Thẳng Link Đích ↗
          </a>
        </div>
      </div>

      <!-- Bước xác thực 5 giây -->
      <div class="pt-4 border-t border-slate-800 space-y-3 text-center">
        <div class="text-xs font-bold text-slate-300">SAU KHI THỬ CÁCH A HOẶC CÁCH B, BẤM NÚT DƯỚI ĐÂY ĐỂ XOAY 5 GIÂY CHECK VIEW:</div>
        <button onclick="verifyTestSession()" id="btn-verify" class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-black py-3.5 rounded-xl text-sm transition shadow-lg">
          🔍 BƯỚC 2: XOAY 5 GIÂY KIỂM TRA XEM ĐƯỢC TÍNH VIEW KHÔNG
        </button>

        <div id="spinner-box" class="hidden p-4 bg-slate-950 border border-indigo-500/40 rounded-xl text-xs text-indigo-300 font-bold">
          ⏳ Đang xoay 5 giây đối soát dữ liệu với SiteTop... (<span id="spin-sec">5</span>s)
        </div>

        <div id="result-box" class="hidden p-4 rounded-xl text-xs text-left font-mono space-y-1"></div>
      </div>
    </div>

  </div>

  <script>
    let currentSessionId = null;
    let elapsedInterval = null;
    let seconds = 0;

    async function createNewTestLink() {
      const btn = document.getElementById('btn-create');
      const cookie = document.getElementById('cookie-input').value.trim();
      btn.disabled = true;
      btn.innerText = 'Đang gọi API SiteTop tạo link...';

      const res = await fetch('/api/create-test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cookie })
      });
      const data = await res.json();
      btn.disabled = false;
      btn.innerText = '⚡ TẠO LẠI LINK TEST MỚI';

      if (!data.success) {
        return alert('Lỗi tạo link: ' + data.message);
      }

      currentSessionId = data.sessionId;
      document.getElementById('session-id-txt').innerText = data.sessionId + ' (Mã: ' + data.slug + ')';
      document.getElementById('short-url-txt').innerText = data.shortUrl;
      document.getElementById('short-url-btn').href = data.shortUrl;
      document.getElementById('dest-url-txt').innerText = data.destinationUrl;
      document.getElementById('dest-url-btn').href = data.destinationUrl;
      document.getElementById('test-arena').classList.remove('hidden');
      document.getElementById('result-box').classList.add('hidden');

      seconds = 0;
      clearInterval(elapsedInterval);
      elapsedInterval = setInterval(() => {
        seconds++;
        document.getElementById('timer-txt').innerText = seconds;
      }, 1000);
    }

    function verifyTestSession() {
      if (!currentSessionId) return;
      const spinner = document.getElementById('spinner-box');
      const resBox = document.getElementById('result-box');
      const spinSec = document.getElementById('spin-sec');

      spinner.classList.remove('hidden');
      resBox.classList.add('hidden');
      let left = 5;
      spinSec.innerText = left;

      const t = setInterval(() => {
        left--;
        spinSec.innerText = left;
        if (left <= 0) clearInterval(t);
      }, 1000);

      setTimeout(async () => {
        const res = await fetch('/api/verify-test?sessionId=' + currentSessionId);
        const data = await res.json();
        spinner.classList.add('hidden');
        resBox.classList.remove('hidden');

        if (data.valid) {
          resBox.className = 'p-4 rounded-xl text-xs text-left font-mono space-y-1.5 bg-emerald-950 border-2 border-emerald-500 text-emerald-300';
          resBox.innerHTML = '<b>✓ KẾT QUẢ: ĐƯỢC TÍNH 1 VIEW HỢP LỆ (+250đ)!</b><br/>' +
            '• Mã Link SiteTop: ' + data.slug + '<br/>' +
            '• Thời gian hoàn thành: ' + data.duration + ' giây (Đạt chuẩn >= 65s)<br/>' +
            '• Trạng thái Callback: Đã đi qua trang đích<br/>' +
            '• Kết quả soi SiteTop: ' + data.siteTopNote;
        } else {
          resBox.className = 'p-4 rounded-xl text-xs text-left font-mono space-y-1.5 bg-rose-950 border-2 border-rose-500 text-rose-300';
          resBox.innerHTML = '<b>✕ KẾT QUẢ: BỊ CHẶN — KHÔNG ĐƯỢC TÍNH VIEW (0đ)!</b><br/>' +
            '• Lý do chặn: <b>' + data.reason + '</b><br/>' +
            '• Thời gian thực hiện: ' + data.duration + ' giây<br/>' +
            '• Kết quả soi SiteTop: ' + data.siteTopNote;
        }
      }, 5000);
    }
  </script>
</body>
</html>
    `);
    return;
  }

  // 2. API TẠO LINK TEST MỚI BẰNG TOKEN CỦA BẠN
  if (pathname === '/api/create-test' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const { cookie } = JSON.parse(body || '{}');
        if (cookie) SITETOP_COOKIE = cookie;

        const sessionId = 'SES_' + Math.random().toString(36).substring(2, 9).toUpperCase();
        // Link đích phải thuộc domain đã được duyệt nguồn trên SiteTop của bạn
        const destinationUrl = `https://key-netsuper-api.onrender.com/api/step-callback?session=${sessionId}`;

        const stRes = await createSiteTopLink(destinationUrl);
        if (stRes.status !== 'success') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ success: false, message: stRes.message || 'Không tạo được link trên SiteTop' }));
        }

        const shortUrl = stRes.shortenedUrl;
        const slug = shortUrl.split('/').pop();

        testSessions.set(sessionId, {
          sessionId,
          slug,
          shortUrl,
          destinationUrl: `http://localhost:${PORT}/callback?session=${sessionId}`,
          createdAt: Date.now(),
          callbackHitTime: null,
          refererHeader: ''
        });

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: true,
          sessionId,
          slug,
          shortUrl,
          destinationUrl: `http://localhost:${PORT}/callback?session=${sessionId}`
        }));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, message: err.message }));
      }
    });
    return;
  }

  // 3. ENDPOINT LINK ĐÍCH (CALLBACK KHI VƯỢT XONG HOẶC KHI BẤM THẲNG)
  if (pathname === '/callback' && req.method === 'GET') {
    const sessionId = parsedUrl.query.session;
    const session = testSessions.get(sessionId);

    if (session) {
      session.callbackHitTime = Date.now();
      session.refererHeader = req.headers['referer'] || 'Trực tiếp (Không có Referer từ SiteTop)';
    }

    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`
      <body style="background:#0f172a;color:#fff;font-family:sans-serif;text-align:center;padding-top:80px;">
        <h2>Đã chạm tới Link Đích!</h2>
        <p>Bây giờ hãy quay lại tab Phòng Thí Nghiệm và bấm <b>"Bước 2: Xoay 5 Giây Kiểm Tra"</b> để xem bạn có được tính view hay bị phát hiện Bypass.</p>
      </body>
    `);
    return;
  }

  // 4. API ĐỐI SOÁT 5 GIÂY (PHÁN QUYẾT CÓ TÍNH VIEW HAY KHÔNG)
  if (pathname === '/api/verify-test' && req.method === 'GET') {
    const sessionId = parsedUrl.query.sessionId;
    const session = testSessions.get(sessionId);

    if (!session) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ valid: false, reason: 'Không tìm thấy phiên!' }));
    }

    const now = Date.now();
    const duration = Math.floor(((session.callbackHitTime || now) - session.createdAt) / 1000);

    // Chui vào SiteTop kiểm tra số "Hoàn thành"
    const stCheck = await checkSiteTopViewCount(session.slug, SITETOP_COOKIE);

    // QUY TẮC PHÁN QUYẾT CHỐNG GIAN LẬN:
    // TH1: Chưa hề chạm tới Link Đích
    if (!session.callbackHitTime) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        valid: false,
        slug: session.slug,
        duration,
        siteTopNote: stCheck.note,
        reason: 'Bạn chưa vượt xong link (Chưa chạm tới trang đích)!'
      }));
    }

    // TH2: Có Cookie SiteTop và SiteTop báo Hoàn thành = 0 (Dù có bấm thẳng vào link đích)
    if (stCheck.scraped && stCheck.views === 0) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        valid: false,
        slug: session.slug,
        duration,
        siteTopNote: stCheck.note,
        reason: 'BẠN ĐÃ DÙNG THẲNG LINK ĐÍCH MÀ KHÔNG VƯỢT! (Trên SiteTop cột Hoàn thành vẫn = 0)'
      }));
    }

    // TH3: Thời gian từ lúc tạo link đến lúc vào link đích dưới 65 giây (Bấm thẳng vào link đích hoặc Bypass)
    if (duration < 65) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        valid: false,
        slug: session.slug,
        duration,
        siteTopNote: stCheck.note,
        reason: `PHÁT HIỆN BẤM THẲNG LINK ĐÍCH / BYPASS! Thời gian quá nhanh (${duration}s < 70s chuẩn).`
      }));
    }

    // HỢP LỆ
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      valid: true,
      slug: session.slug,
      duration,
      siteTopNote: stCheck.note
    }));
  }
});

server.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(`Server Test đang chạy tại: http://localhost:${PORT}`);
  console.log(`Mở trình duyệt vào địa chỉ trên để bắt đầu test!`);
  console.log(`====================================================`);
});

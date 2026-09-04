const express = require('express');
const { Pool } = require('pg');

const app = express();
const port = process.env.PORT || 3000;

// Cấu hình kết nối PostgreSQL qua biến môi trường DATABASE_URL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // Bắt buộc khi kết nối Render Postgres
  }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Endpoint kiểm tra Key
// App Android có thể gửi qua GET: /api/check-key?key=NETSUPER-XXXX-XXXX
// Hoặc qua POST: { "key": "NETSUPER-XXXX-XXXX" }
app.all('/api/check-key', async (req, res) => {
  const userKey = req.query.key || req.body.key;

  if (!userKey) {
    return res.status(400).json({ status: false, message: 'Vui lòng cung cấp key!' });
  }

  try {
    // Truy vấn key trong bảng keys
    const queryText = 'SELECT * FROM keys WHERE key_code = $1';
    const result = await pool.query(queryText, [userKey]);

    if (result.rows.length === 0) {
      return res.status(404).json({ status: false, message: 'Key không tồn tại!' });
    }

    const keyData = result.rows[0];

    // Kiểm tra thời hạn key (nếu expire_at không null)
    if (keyData.expire_at) {
      const now = new Date();
      const expireDate = new Date(keyData.expire_at);

      if (now > expireDate) {
        return res.status(403).json({ status: false, message: 'Key đã hết hạn sử dụng!' });
      }
    }

    // Key hợp lệ
    return res.status(200).json({
      status: true,
      message: 'Xác thực thành công!',
      data: {
        key: keyData.key_code,
        expire_at: keyData.expire_at || 'Vĩnh viễn'
      }
    });

  } catch (error) {
    console.error('Lỗi Database:', error);
    return res.status(500).json({ status: false, message: 'Lỗi máy chủ kết nối Database!' });
  }
});

// Endpoint mặc định kiểm tra server sống hay chết
app.get('/', (req, res) => {
  res.send('Key Verification Server is Running!');
});

app.listen(port, () => {
  console.log(`Server đang chạy trên port ${port}`);
});

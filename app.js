const express = require('express');
const { Pool } = require('pg');

const app = express();
app.use(express.json());

// Cấu hình kết nối PostgreSQL với SSL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// ===== KHỞI TẠO DATABASE =====
const initDb = async () => {
  try {
    const client = await pool.connect();
    
    // Tạo bảng keys với cột key_value (không dùng từ khóa "key")
    await client.query(`
      CREATE TABLE IF NOT EXISTS keys (
        id SERIAL PRIMARY KEY,
        key_value VARCHAR(255) UNIQUE NOT NULL,
        expire_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Thêm key mặc định nếu chưa có
    await client.query(`
      INSERT INTO keys (key_value, expire_at) 
      VALUES ('0969696969', '2099-12-31 23:59:59')
      ON CONFLICT (key_value) DO NOTHING;
    `);

    client.release();
    console.log('✅ Database initialized successfully!');
  } catch (err) {
    console.error('❌ Database init error:', err.message);
  }
};
initDb();

// ===== TRANG CHỦ =====
app.get('/', (req, res) => {
  res.send('Key Verification Server is Running!');
});

// ===== ENDPOINT KIỂM TRA KEY =====
app.all('/api/check-key', async (req, res) => {
  try {
    // Lấy key từ query string hoặc body
    const key = req.query.key || req.body.key;

    if (!key) {
      return res.status(400).json({
        status: false,
        message: 'Vui lòng cung cấp key!'
      });
    }

    const client = await pool.connect();
    
    // Truy vấn với cột key_value (đã sửa)
    const result = await client.query('SELECT * FROM keys WHERE key_value = $1', [key]);
    client.release();

    if (result.rows.length === 0) {
      return res.json({
        status: false,
        message: 'Key không tồn tại!'
      });
    }

    const keyData = result.rows[0];
    const now = new Date();

    // Kiểm tra hết hạn
    if (keyData.expire_at && new Date(keyData.expire_at) < now) {
      return res.json({
        status: false,
        message: 'Key đã hết hạn sử dụng!'
      });
    }

    // Thành công
    return res.json({
      status: true,
      message: 'Xác thực thành công!',
      data: {
        key: keyData.key_value,
        expire_at: keyData.expire_at
      }
    });

  } catch (error) {
    console.error('❌ Database error:', error);
    return res.status(500).json({
      status: false,
      message: 'Lỗi máy chủ kết nối Database!',
      error: error.message
    });
  }
});

// ===== ENDPOINT THÊM KEY MỚI (tùy chọn) =====
app.post('/api/add-key', async (req, res) => {
  try {
    const { key, expire_at } = req.body;
    
    if (!key) {
      return res.status(400).json({
        status: false,
        message: 'Vui lòng cung cấp key!'
      });
    }

    const client = await pool.connect();
    await client.query(
      'INSERT INTO keys (key_value, expire_at) VALUES ($1, $2) ON CONFLICT (key_value) DO NOTHING',
      [key, expire_at || '2099-12-31 23:59:59']
    );
    client.release();

    res.json({
      status: true,
      message: 'Key đã được thêm thành công!'
    });
  } catch (error) {
    res.status(500).json({
      status: false,
      message: error.message
    });
  }
});

// ===== CHẠY SERVER =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server is running on port ${PORT}`);
});

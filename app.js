const express = require('express');
const { Pool } = require('pg');

const app = express();
app.use(express.json());

// Cấu hình kết nối PostgreSQL với SSL hợp lệ cho Render
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Tự động khởi tạo bảng 'keys' nếu chưa tồn tại
const initDb = async () => {
  try {
    const client = await pool.connect();
    await client.query(`
      CREATE TABLE IF NOT EXISTS keys (
        id SERIAL PRIMARY KEY,
        "key" VARCHAR(255) UNIQUE NOT NULL,
        expire_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    client.release();
    console.log('Khởi tạo cấu trúc Database thành công!');
  } catch (err) {
    console.error('Lỗi khởi tạo Database:', err.message);
  }
};
initDb();

// Trang chủ
app.get('/', (req, res) => {
  res.send('Key Verification Server is Running!');
});

// Endpoint kiểm tra Key
app.all('/api/check-key', async (req, res) => {
  try {
    const key = req.query.key || req.body.key;

    if (!key) {
      return res.status(400).json({
        status: false,
        message: 'Vui lòng cung cấp key!'
      });
    }

    const client = await pool.connect();
    // Bọc "key" trong ngoặc kép để PostgreSQL nhận diện là tên cột
    const result = await client.query('SELECT * FROM keys WHERE "key" = $1', [key]);
    client.release();

    if (result.rows.length === 0) {
      return res.json({
        status: false,
        message: 'Key không tồn tại!'
      });
    }

    const keyData = result.rows[0];
    const now = new Date();

    if (keyData.expire_at && new Date(keyData.expire_at) < now) {
      return res.json({
        status: false,
        message: 'Key đã hết hạn sử dụng!'
      });
    }

    return res.json({
      status: true,
      message: 'Xác thực thành công!',
      data: {
        key: keyData.key,
        expire_at: keyData.expire_at
      }
    });

  } catch (error) {
    console.error('Database connection error:', error);
    return res.status(500).json({
      status: false,
      message: 'Lỗi máy chủ kết nối Database!',
      error: error.message
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

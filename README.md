# 🚀 Key Verification API (Netsuper)

API kiểm tra và xác thực License Key kết nối với cơ sở dữ liệu PostgreSQL, được triển khai trên [Render](https://render.com).

## 📌 Tính năng chính
* Xác thực key từ ứng dụng Android.
* Kiểm tra thời hạn truy cập (Key 24h, Key vĩnh viễn...).
* Tích hợp cơ sở dữ liệu PostgreSQL.

## 🌐 Endpoint API

### Check Key Status
* **Method:** `GET` / `POST`
* **URL:** `https://<your-render-url>/api/check-key?key=YOUR_KEY`

**Response Mẫu (Thành công):**
```json
{
  "status": true,
  "message": "Xác thực thành công!",
  "data": {
    "key": "NETSUPER-XXXX-XXXX",
    "expire_at": "2026-12-31T23:59:59.000Z"
  }
}

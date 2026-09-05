const express = require('express');
const app = express();
app.use(express.json());

// Import danh sách key từ file keys.js
const validKeys = require('./keys.js');

// Hàm kiểm tra key có tiền tố NETSUPER không
function isNetSuperKey(key) {
    return key && key.startsWith('NETSUPER-');
}

// Hàm lấy thời gian hết hạn
function getExpiryTime(key) {
    // Mặc định 24 giờ
    let hours = 24;
    
    // Nếu key là NETSUPER và có thể set 48 giờ (có thể thêm logic riêng)
    // Ví dụ: nếu key kết thúc bằng "-48H" thì set 48 giờ
    if (isNetSuperKey(key) && key.endsWith('-48H')) {
        hours = 48;
    }
    
    const now = new Date();
    now.setHours(now.getHours() + hours);
    return now.toISOString();
}

// ===== TRANG CHỦ =====
app.get('/', (req, res) => {
    res.send('Key Verification Server is Running!');
});

// ===== ENDPOINT KIỂM TRA KEY =====
app.get('/api/check-key', (req, res) => {
    const key = req.query.key || req.body.key;

    if (!key) {
        return res.status(400).json({
            status: false,
            message: 'Vui lòng cung cấp key!'
        });
    }

    // Kiểm tra key có trong danh sách không
    if (validKeys.includes(key)) {
        // Lấy thời gian hết hạn
        const expireAt = getExpiryTime(key);
        
        return res.json({
            status: true,
            message: 'Xác thực thành công!',
            data: {
                key: key,
                expire_at: expireAt,
                note: isNetSuperKey(key) ? 'Key NETSUPER - thời hạn 24/48 giờ' : 'Key thường - không giới hạn'
            }
        });
    } else {
        return res.json({
            status: false,
            message: 'Key không tồn tại!'
        });
    }
});

// ===== CHẠY SERVER =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server is running on port ${PORT}`);
});

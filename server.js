const express = require("express");
const helmet = require("helmet"); 
const cors = require("cors"); 
const bcrypt = require("bcryptjs"); 
const jwt = require("jsonwebtoken"); 
const rateLimit = require("express-rate-limit");
const http = require("http"); // مطلوب للـ Socket.io
const { Server } = require("socket.io"); // إضافة Socket.io للسرعة الفائقة
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } }); // إعداد الـ Socket

app.set('trust proxy', 1); 
app.use(helmet());
app.use(cors()); 
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "super_secret_jwt_key_9988"; 

const appLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100,
    message: { error: "طلبات كثيرة جداً، يرجى المحاولة لاحقاً" }
});

let users = []; 

// --- جزء استقبال بيانات الساعة (الـ Gateway) ---
// يتم استدعاء هذا المسار من تطبيق الهاتف فور استلامه بيانات من الساعة
app.post("/api/watch/data", (req, res) => {
    const { heartRate, steps, battery, macAddress } = req.body;

    // التحقق البسيط من البيانات
    if (!macAddress) return res.status(400).json({ message: "MAC address required" });

    // إرسال البيانات فوراً لكل الشاشات المفتوحة (الداشبورد)
    // هذا هو الجزء الذي يحقق سرعة البرق
    io.emit("live-watch-data", {
        macAddress,
        heartRate,
        steps,
        battery,
        timestamp: new Date().getTime()
    });

    res.status(200).json({ status: "received" });
});

// 1. مسار تسجيل حساب جديد
app.post("/api/auth/register", appLimiter, async (req, res) => {
    const { name, email, phone, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "الإيميل والباسورد مطلوبين!" });

    const cleanEmail = email.toLowerCase().trim();
    if (users.find(u => u.email === cleanEmail)) return res.status(400).json({ message: "هذا الحساب مسجل بالفعل!" });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    users.push({ id: users.length + 1, name, email: cleanEmail, phone, password: hashedPassword, provider: "email" });
    res.status(201).json({ message: "تم تسجيل الحساب بنجاح!" });
});

// 2. مسار تسجيل الدخول
app.post("/api/auth/login", appLimiter, async (req, res) => {
    const { email, password } = req.body;
    const cleanEmail = email.toLowerCase().trim();
    const user = users.find(u => u.email === cleanEmail);
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: "الإيميل أو كلمة المرور غير صحيحة!" });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.status(200).json({ token, user: { name: user.name, email: user.email } });
});

// إعداد الـ Socket للاتصالات الحية
io.on("connection", (socket) => {
    console.log("Client connected to Dashboard: ", socket.id);
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Professional Server running with Real-time Socket on port ${PORT}`);
});
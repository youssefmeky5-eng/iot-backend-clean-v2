const express = require("express");
const helmet = require("helmet"); 
const cors = require("cors"); 
const bcrypt = require("bcryptjs"); 
const jwt = require("jsonwebtoken"); 
const rateLimit = require("express-rate-limit");
const http = require("http"); // إضافة للتحكم في الـ Socket
const { Server } = require("socket.io"); // إضافة المكتبة
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

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

// 1. مسار تسجيل حساب جديد
app.post("/api/auth/register", appLimiter, async (req, res) => {
    const { name, email, phone, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "الإيميل والباسورد مطلوبين!" });
    const cleanEmail = email.toLowerCase().trim();
    const userExists = users.find(u => u.email === cleanEmail);
    if (userExists) return res.status(400).json({ message: "هذا الحساب مسجل بالفعل!" });
    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        users.push({ id: users.length + 1, name, email: cleanEmail, phone, password: hashedPassword, provider: "email" });
        res.status(201).json({ message: "تم تسجيل الحساب بنجاح!" });
    } catch (error) { res.status(500).json({ message: "حدث خطأ أثناء تشفير البيانات" }); }
});

// 2. مسار تسجيل الدخول
app.post("/api/auth/login", appLimiter, async (req, res) => {
    const { email, password } = req.body;
    const cleanEmail = email.toLowerCase().trim();
    const user = users.find(u => u.email === cleanEmail);
    if (!user || user.provider !== "email") return res.status(401).json({ message: "الإيميل أو كلمة المرور غير صحيحة!" });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: "الإيميل أو كلمة المرور غير صحيحة!" });
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.status(200).json({ message: "تم تسجيل الدخول بنجاح!", token, user: { name: user.name, email: user.email, phone: user.phone } });
});

// --- الجزء المضاف: نظام استقبال بيانات الساعة والاتصالات ---
app.post("/api/watch/data", (req, res) => {
    const { heartRate, steps, battery, macAddress } = req.body;
    io.emit("live-watch-data", { macAddress, heartRate, steps, battery, timestamp: Date.now() });
    res.status(200).json({ status: "received" });
});

io.on("connection", (socket) => {
    // تسجيل المستخدم للاتصال
    socket.on("register", (userId) => { socket.join(userId); });

    // نظام الاتصال بين المستخدمين
    socket.on("call-user", (data) => {
        socket.to(data.targetUserId).emit("incoming-call", { from: socket.id, callerName: data.callerName, signalData: data.signalData });
    });

    socket.on("accept-call", (data) => {
        socket.to(data.to).emit("call-accepted", data.signal);
    });

    socket.on("reject-call", (data) => {
        socket.to(data.to).emit("call-rejected");
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Professional Server is running on port ${PORT}`);
});
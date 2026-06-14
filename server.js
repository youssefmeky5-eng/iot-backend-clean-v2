const express = require("express");
const helmet = require("helmet"); 
const cors = require("cors"); 
const bcrypt = require("bcryptjs"); 
const jwt = require("jsonwebtoken"); 
const rateLimit = require("express-rate-limit");
require('dotenv').config();

const app = express();

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

    if (!email || !password) {
        return res.status(400).json({ message: "الإيميل والباسورد مطلوبين!" });
    }

    const cleanEmail = email.toLowerCase().trim();
    const userExists = users.find(u => u.email === cleanEmail);
    if (userExists) {
        return res.status(400).json({ message: "هذا الحساب مسجل بالفعل!" });
    }

    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = {
            id: users.length + 1,
            name,
            email: cleanEmail,
            phone,
            password: hashedPassword,
            provider: "email"
        };

        users.push(newUser);
        console.log(`🆕 مستخدم جديد سجل: ${cleanEmail}`);
        res.status(201).json({ message: "تم تسجيل الحساب بنجاح!" });
    } catch (error) {
        res.status(500).json({ message: "حدث خطأ أثناء تشفير البيانات" });
    }
});

// 2. مسار تسجيل الدخول
app.post("/api/auth/login", appLimiter, async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) return res.status(400).json({ message: "الإيميل والباسورد مطلوبين!" });
    
    const cleanEmail = email.toLowerCase().trim();
    const user = users.find(u => u.email === cleanEmail);
    
    if (!user || user.provider !== "email") {
        return res.status(401).json({ message: "الإيميل أو كلمة المرور غير صحيحة!" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(401).json({ message: "الإيميل أو كلمة المرور غير صحيحة!" });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    res.status(200).json({
        message: "تم تسجيل الدخول بنجاح!",
        token,
        user: { name: user.name, email: user.email, phone: user.phone }
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Professional Server is running on port ${PORT}`);
});
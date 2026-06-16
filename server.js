const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const http = require("http");
const { Server } = require("socket.io");
require("dotenv").config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.set("trust proxy", 1);
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

/* ================= AUTH ================= */

app.post("/api/auth/register", appLimiter, async (req, res) => {
  const { name, email, phone, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ message: "الإيميل والباسورد مطلوبين!" });

  const cleanEmail = email.toLowerCase().trim();
  const userExists = users.find(u => u.email === cleanEmail);

  if (userExists)
    return res.status(400).json({ message: "هذا الحساب مسجل بالفعل!" });

  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  users.push({
    id: String(users.length + 1),
    name,
    email: cleanEmail,
    phone,
    password: hashedPassword,
    provider: "email"
  });

  res.status(201).json({ message: "تم تسجيل الحساب بنجاح!" });
});

app.post("/api/auth/login", appLimiter, async (req, res) => {
  const { email, password } = req.body;

  const cleanEmail = email.toLowerCase().trim();
  const user = users.find(u => u.email === cleanEmail);

  if (!user || user.provider !== "email")
    return res.status(401).json({ message: "بيانات غير صحيحة" });

  const match = await bcrypt.compare(password, user.password);

  if (!match)
    return res.status(401).json({ message: "بيانات غير صحيحة" });

  const token = jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.json({
    message: "تم تسجيل الدخول",
    token,
    user: { id: user.id, name: user.name }
  });
});

/* ================= SOCKET.IO ================= */

io.on("connection", (socket) => {
  console.log("User connected:", socket.id);

  // تسجيل المستخدم
  socket.on("register", (userId) => {
    socket.join(userId);
    socket.userId = userId;
  });

  /* ================= CALL SYSTEM ================= */

  socket.on("call-user", (data) => {
    io.to(data.targetUserId).emit("incoming-call", {
      from: data.from,
      callerName: data.callerName,
      type: data.type
    });
  });

  socket.on("accept-call", (data) => {
    io.to(data.to).emit("call-accepted", {
      from: socket.id
    });
  });

  socket.on("reject-call", (data) => {
    io.to(data.to).emit("call-rejected");
  });

  /* ================= WEBRTC SIGNALING ================= */

  // 📡 Offer
  socket.on("offer", (data) => {
    io.to(data.to).emit("offer", {
      from: socket.id,
      sdp: data.sdp
    });
  });

  // 📡 Answer
  socket.on("answer", (data) => {
    io.to(data.to).emit("answer", {
      from: socket.id,
      sdp: data.sdp
    });
  });

  // 📡 ICE Candidates
  socket.on("ice-candidate", (data) => {
    io.to(data.to).emit("ice-candidate", {
      from: socket.id,
      candidate: data.candidate
    });
  });

  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id);
  });
});

/* ================= SERVER ================= */

const PORT = process.env.PORT || 3000;

server.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 WebRTC Server running on port ${PORT}`);
});
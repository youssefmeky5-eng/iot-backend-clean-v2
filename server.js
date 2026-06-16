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

const io = new Server(server, {
  cors: {
    origin: "*",
  },
});

app.set("trust proxy", 1);
app.use(helmet());
app.use(cors());
app.use(express.json());

const JWT_SECRET =
  process.env.JWT_SECRET || "super_secret_jwt_key_9988";

const appLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    error: "طلبات كثيرة جداً، يرجى المحاولة لاحقاً",
  },
});

let users = [];

/* ================= ONLINE USERS ================= */

const onlineUsers = new Map();
// userId -> socket.id

/* ================= AUTH ================= */

app.post("/api/auth/register", appLimiter, async (req, res) => {
  const { name, email, phone, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      message: "الإيميل والباسورد مطلوبين!",
    });
  }

  const cleanEmail = email.toLowerCase().trim();

  const userExists = users.find(
    (u) => u.email === cleanEmail
  );

  if (userExists) {
    return res.status(400).json({
      message: "هذا الحساب مسجل بالفعل!",
    });
  }

  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  users.push({
    id: String(users.length + 1),
    name,
    email: cleanEmail,
    phone,
    password: hashedPassword,
    provider: "email",
  });

  res.status(201).json({
    message: "تم تسجيل الحساب بنجاح!",
  });
});

app.post("/api/auth/login", appLimiter, async (req, res) => {
  const { email, password } = req.body;

  const cleanEmail = email.toLowerCase().trim();

  const user = users.find(
    (u) => u.email === cleanEmail
  );

  if (!user || user.provider !== "email") {
    return res.status(401).json({
      message: "بيانات غير صحيحة",
    });
  }

  const match = await bcrypt.compare(
    password,
    user.password
  );

  if (!match) {
    return res.status(401).json({
      message: "بيانات غير صحيحة",
    });
  }

  const token = jwt.sign(
    {
      id: user.id,
      email: user.email,
    },
    JWT_SECRET,
    {
      expiresIn: "7d",
    }
  );

  res.json({
    message: "تم تسجيل الدخول",
    token,
    user: {
      id: user.id,
      name: user.name,
    },
  });
});

/* ================= ESP HTTP API ================= */

// استقبال بيانات ESP عبر HTTP
app.post("/api/watch-data", (req, res) => {
  const data = req.body;

  console.log("📡 HTTP Watch Data:", data);

  // إرسال البيانات لكل التطبيقات المتصلة
  io.emit("watch-data", data);

  res.json({
    success: true,
    message: "Data received",
  });
});

// إرسال أوامر للـ ESP عبر HTTP
app.post("/api/esp-command", (req, res) => {
  const data = req.body;

  console.log("📤 HTTP ESP Command:", data);

  io.emit("esp-command", data);

  res.json({
    success: true,
    message: "Command sent",
  });
});

/* ================= SOCKET.IO ================= */

io.on("connection", (socket) => {
  console.log("✅ User connected:", socket.id);

  /* ================= REGISTER ================= */

  socket.on("register", (userId) => {
    if (!userId) return;

    socket.join(userId);
    socket.userId = userId;

    onlineUsers.set(userId, socket.id);

    console.log("👤 Registered user:", userId);
  });

  /* ================= ESP REGISTER ================= */

  socket.on("register-esp", (espId) => {
    socket.espId = espId;

    console.log("⌚ ESP Registered:", espId);
  });

  /* ================= CALL SYSTEM ================= */

  socket.on("call-user", (data) => {
    const targetSocketId = onlineUsers.get(
      data.targetUserId
    );

    if (targetSocketId) {
      io.to(targetSocketId).emit("incoming-call", {
        from: data.from,
        callerName: data.callerName,
        type: data.type,
      });
    }
  });

  socket.on("accept-call", (data) => {
    const targetSocketId = onlineUsers.get(data.to);

    if (targetSocketId) {
      io.to(targetSocketId).emit("call-accepted", {
        from: socket.userId,
      });
    }
  });

  socket.on("reject-call", (data) => {
    const targetSocketId = onlineUsers.get(data.to);

    if (targetSocketId) {
      io.to(targetSocketId).emit("call-rejected");
    }
  });

  /* ================= WEBRTC SIGNALING ================= */

  socket.on("offer", (data) => {
    const targetSocketId = onlineUsers.get(data.to);

    if (targetSocketId) {
      io.to(targetSocketId).emit("offer", {
        from: socket.userId,
        sdp: data.sdp,
      });
    }
  });

  socket.on("answer", (data) => {
    const targetSocketId = onlineUsers.get(data.to);

    if (targetSocketId) {
      io.to(targetSocketId).emit("answer", {
        from: socket.userId,
        sdp: data.sdp,
      });
    }
  });

  socket.on("ice-candidate", (data) => {
    const targetSocketId = onlineUsers.get(data.to);

    if (targetSocketId) {
      io.to(targetSocketId).emit("ice-candidate", {
        from: socket.userId,
        candidate: data.candidate,
      });
    }
  });

  /* ================= WATCH DATA ================= */

  socket.on("watch-data", (data) => {
    console.log("📡 Watch Data:", data);

    // إرسال لصاحب الحساب
    if (data.userId) {
      const targetSocketId = onlineUsers.get(
        data.userId
      );

      if (targetSocketId) {
        io.to(targetSocketId).emit(
          "watch-data",
          data
        );
      }
    }

    // بث البيانات لباقي التطبيقات
    socket.broadcast.emit("watch-data", data);
  });

  /* ================= ESP COMMAND ================= */

  socket.on("esp-command", (data) => {
    console.log("📤 ESP Command:", data);

    io.emit("esp-command", data);
  });

  /* ================= DISCONNECT ================= */

  socket.on("disconnect", () => {
    console.log("❌ User disconnected:", socket.id);

    if (socket.userId) {
      onlineUsers.delete(socket.userId);
    }
  });
});

/* ================= HEALTH CHECK ================= */

app.get("/", (req, res) => {
  res.json({
    status: "ok",
    server: "IoT + WebRTC Backend",
    onlineUsers: onlineUsers.size,
  });
});

/* ================= SERVER ================= */

const PORT = process.env.PORT || 3000;

server.listen(PORT, "0.0.0.0", () => {
  console.log(
    `🚀 WebRTC + IoT Server running on port ${PORT}`
  );
});
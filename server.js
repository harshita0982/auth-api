const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use("/uploads", express.static("uploads"));

// ================= DB =================
mongoose.connect(process.env.MONGO_URI)
.then(() => console.log("DB Connected"))
.catch(err => console.log(err));

// ================= MODEL =================
const User = mongoose.model("User", new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  profileImage: String
}));

// ================= AUTH MIDDLEWARE =================
const auth = (req, res, next) => {
  const token = req.header("Authorization");
  if (!token) return res.status(401).json({ msg: "No token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded.id;
    next();
  } catch {
    res.status(401).json({ msg: "Invalid token" });
  }
};

// ================= MULTER =================
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname)
});
const upload = multer({ storage });

// ================= AUTH APIs =================

// 1. Register
app.post("/api/auth/register", async (req, res) => {
  const { name, email, password } = req.body;

  const exist = await User.findOne({ email });
  if (exist) return res.status(400).json({ msg: "User exists" });

  const hashed = await bcrypt.hash(password, 10);
  const user = new User({ name, email, password: hashed });

  await user.save();
  res.json({ msg: "Registered" });
});

// 2. Login
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ msg: "Invalid credentials" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ msg: "Invalid credentials" });

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    expiresIn: "1d"
  });

  res.json({ token });
});

// 3. Get Profile (Protected)
app.get("/api/auth/me", auth, async (req, res) => {
  const user = await User.findById(req.user).select("-password");
  res.json(user);
});

// ================= USER APIs =================

// 4. Get All Users
app.get("/api/users", async (req, res) => {
  const users = await User.find().select("-password");
  res.json(users);
});

// 5. Get User by ID
app.get("/api/users/:id", async (req, res) => {
  const user = await User.findById(req.params.id).select("-password");
  res.json(user);
});

// 6. Update User
app.put("/api/users/:id", async (req, res) => {
  const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
  res.json(user);
});

// 7. Delete User
app.delete("/api/users/:id", async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  res.json({ msg: "User deleted" });
});

// 8. Upload Profile Image
app.post("/api/users/upload-profile", upload.single("profile"), async (req, res) => {
  const user = await User.findByIdAndUpdate(
    req.body.userId,
    { profileImage: req.file.path },
    { new: true }
  );
  res.json(user);
});

// ================= SERVER =================
app.listen(5000, () => console.log("Server running on port 5000"));

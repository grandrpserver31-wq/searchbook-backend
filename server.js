require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();

app.use(cors({ origin: '*', credentials: false, methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], allowedHeaders: ['Content-Type', 'x-username', 'x-admin-user'] }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

const MONGO_URI = process.env.MONGO_URI;
const PORT = process.env.PORT || 5000;

if (!MONGO_URI) { console.error("❌ ERROR: MONGO_URI not set!"); process.exit(1); }

mongoose.connect(MONGO_URI)
    .then(() => console.log("✅ MongoDB Connected!"))
    .catch(err => console.error("❌ DB Error:", err.message));

function errRes(res, message, code = 500) { return res.status(code).json({ success: false, message: String(message) }); }
function okRes(res, data = {}) { return res.json(Object.assign({ success: true }, data)); }

const activeUsers = {};
app.use((req, res, next) => {
    const username = req.headers['x-username'];
    if (username) activeUsers[username] = Date.now();
    next();
});

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true },
    fullName: { type: String, default: "" },
    bio: { type: String, default: "" },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

const PostSchema = new mongoose.Schema({
    username: { type: String, required: true },
    content: { type: String, default: "" },
    createdAt: { type: Date, default: Date.now }
});
const Post = mongoose.model('Post', PostSchema);

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return errRes(res, "User not found!", 400);
        const isMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isMatch) return errRes(res, "Invalid password!", 400);
        activeUsers[user.username] = Date.now();
        res.json({ success: true, username: user.username, email: user.email, fullName: user.fullName });
    } catch (e) { errRes(res, e.message); }
});

app.get('/api/active-users', (req, res) => {
    const now = Date.now();
    const list = Object.keys(activeUsers).filter(u => now - activeUsers[u] < 2 * 60 * 1000);
    res.json({ success: true, count: list.length, users: list });
});

app.get('/api/posts', async (req, res) => {
    try {
        const posts = await Post.find().sort({ createdAt: -1 }).limit(50);
        res.json(posts);
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/posts', async (req, res) => {
    try {
        const { username, content } = req.body;
        const np = new Post({ username, content });
        await np.save();
        res.status(201).json({ success: true, message: "Post created!" });
    } catch (e) { errRes(res, e.message); }
});

app.get('/api/admin/users', async (req, res) => {
    try {
        const users = await User.find().select('username email createdAt');
        res.json({ success: true, users });
    } catch (e) { errRes(res, e.message); }
});

app.use((req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

app.listen(PORT, () => {
    console.log(`✅ SearchBook running on port ${PORT}`);
});

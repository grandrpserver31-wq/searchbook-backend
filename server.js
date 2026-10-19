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

let speakeasy = null, QRCode = null;
try {
    speakeasy = require('speakeasy');
    QRCode = require('qrcode');
} catch (e) {}

mongoose.connect(MONGO_URI)
    .then(() => console.log("✅ MongoDB Connected!"))
    .catch(err => console.error("❌ DB Error:", err.message));

function errRes(res, message, code = 500) { return res.status(code).json({ success: false, message: String(message) }); }
function okRes(res, data = {}) { return res.json(Object.assign({ success: true }, data)); }

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true },
    fullName: { type: String, default: "" },
    twoFAEnabled: { type: Boolean, default: false },
    twoFASecret: { type: String, default: "" },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

const PostSchema = new mongoose.Schema({
    username: { type: String, required: true },
    content: { type: String, default: "" },
    createdAt: { type: Date, default: Date.now }
});
const Post = mongoose.model('Post', PostSchema);

app.post('/api/signup', async (req, res) => {
    try {
        const { username, email, password, fullName } = req.body;
        if (!username || !email || !password) return errRes(res, "All fields required", 400);
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);
        const newUser = new User({ username, email, fullName: fullName || username, passwordHash });
        await newUser.save();
        res.status(201).json({ success: true, message: "Account created!" });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return errRes(res, "User not found!", 400);
        const isMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isMatch) return errRes(res, "Invalid password!", 400);
        res.json({ success: true, username: user.username, email: user.email, fullName: user.fullName });
    } catch (e) { errRes(res, e.message); }
});

app.get('/api/user/:email', async (req, res) => {
    try {
        const u = await User.findOne({ email: req.params.email });
        if (!u) return errRes(res, "User not found", 404);
        res.json({ success: true, user: { username: u.username, email: u.email, fullName: u.fullName, twoFAEnabled: u.twoFAEnabled } });
    } catch (e) { errRes(res, e.message); }
});

app.put('/api/user/change-password', async (req, res) => {
    try {
        const { email, oldPassword, newPassword } = req.body;
        const u = await User.findOne({ email });
        if (!u) return errRes(res, "User not found", 404);
        const m = await bcrypt.compare(oldPassword, u.passwordHash);
        if (!m) return errRes(res, "Incorrect current password", 400);
        const salt = await bcrypt.genSalt(10);
        u.passwordHash = await bcrypt.hash(newPassword, salt);
        await u.save();
        okRes(res, { message: "Password updated successfully!" });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/2fa/setup', async (req, res) => {
    try {
        if (!speakeasy || !QRCode) return errRes(res, "2FA module unavailable", 500);
        const { email } = req.body;
        const u = await User.findOne({ email });
        if (!u) return errRes(res, "User not found", 404);
        const secret = speakeasy.generateSecret({ name: `Searchbook (${u.username})`, length: 20 });
        u.twoFASecret = secret.base32;
        await u.save();
        const qrCode = await QRCode.toDataURL(secret.otpauth_url);
        res.json({ success: true, secret: secret.base32, qrCode });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/2fa/verify', async (req, res) => {
    try {
        if (!speakeasy) return errRes(res, "2FA unavailable", 500);
        const { email, code } = req.body;
        const u = await User.findOne({ email });
        if (!u || !u.twoFASecret) return errRes(res, "Setup 2FA first", 400);
        const verified = speakeasy.totp.verify({ secret: u.twoFASecret, encoding: 'base32', token: code, window: 1 });
        if (!verified) return errRes(res, "Invalid 2FA code", 400);
        u.twoFAEnabled = true;
        await u.save();
        okRes(res, { message: "2FA enabled!" });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/2fa/disable', async (req, res) => {
    try {
        if (!speakeasy) return errRes(res, "2FA unavailable", 500);
        const { email, code } = req.body;
        const u = await User.findOne({ email });
        if (!u || !u.twoFAEnabled) return errRes(res, "2FA already off", 400);
        const verified = speakeasy.totp.verify({ secret: u.twoFASecret, encoding: 'base32', token: code, window: 1 });
        if (!verified) return errRes(res, "Invalid 2FA code", 400);
        u.twoFAEnabled = false;
        u.twoFASecret = "";
        await u.save();
        okRes(res, { message: "2FA disabled!" });
    } catch (e) { errRes(res, e.message); }
});

app.get('/api/admin/users', async (req, res) => {
    try {
        const users = await User.find().select('username email twoFAEnabled createdAt');
        res.json({ success: true, users });
    } catch (e) { errRes(res, e.message); }
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

app.use((req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

app.listen(PORT, () => {
    console.log(`✅ SearchBook running on port ${PORT}`);
});

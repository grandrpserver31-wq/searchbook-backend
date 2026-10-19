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
    following: { type: [String], default: [] },
    twoFAEnabled: { type: Boolean, default: false },
    twoFASecret: { type: String, default: "" },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

const PostSchema = new mongoose.Schema({
    username: { type: String, required: true },
    content: { type: String, default: "" },
    likes: { type: [String], default: [] },
    comments: { type: Array, default: [] },
    shares: { type: Number, default: 0 },
    views: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
});
const Post = mongoose.model('Post', PostSchema);

const ComplaintSchema = new mongoose.Schema({
    username: { type: String, required: true },
    subject: { type: String, required: true },
    message: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});
const Complaint = mongoose.model('Complaint', ComplaintSchema);

// SIGNUP
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

// LOGIN WITH 2FA SUPPORT
app.post('/api/login', async (req, res) => {
    try {
        const { email, password, twoFACode } = req.body;
        const user = await User.findOne({ email });
        if (!user) return errRes(res, "User not found!", 400);
        
        if (user.twoFAEnabled) {
            if (!twoFACode) return res.json({ success: false, requires2FA: true });
            const verified = speakeasy.totp.verify({ secret: user.twoFASecret, encoding: 'base32', token: twoFACode, window: 1 });
            if (!verified) return errRes(res, "Invalid 2FA code!", 400);
        } else {
            const isMatch = await bcrypt.compare(password, user.passwordHash);
            if (!isMatch) return errRes(res, "Invalid password!", 400);
        }
        
        res.json({ success: true, username: user.username, email: user.email, fullName: user.fullName });
    } catch (e) { errRes(res, e.message); }
});

// USER PROFILE
app.get('/api/user/:email', async (req, res) => {
    try {
        const u = await User.findOne({ email: req.params.email });
        if (!u) return errRes(res, "User not found", 404);
        res.json({ success: true, user: { username: u.username, email: u.email, fullName: u.fullName, twoFAEnabled: u.twoFAEnabled } });
    } catch (e) { errRes(res, e.message); }
});

// CHANGE PASSWORD
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

// 2FA SETUP & VERIFY
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

// AI SMART FEED ALGORITHM
app.get('/api/feed/:username', async (req, res) => {
    try {
        const username = req.params.username;
        const user = await User.findOne({ username });
        const following = user ? user.following : [];
        const posts = await Post.find().limit(100).lean();
        const now = Date.now();
        
        posts.forEach(p => {
            const ageHours = (now - new Date(p.createdAt).getTime()) / (1000 * 60 * 60);
            const isFriend = following.includes(p.username) ? 20 : 0;
            const engagementScore = ((p.likes?.length || 0) * 3) + ((p.comments?.length || 0) * 4) + ((p.shares || 0) * 5);
            const timeDecay = Math.max(0, 72 - ageHours) * 1.5;
            p.feedScore = isFriend + engagementScore + timeDecay;
        });

        posts.sort((a, b) => b.feedScore - a.feedScore);
        res.json(posts);
    } catch (e) { errRes(res, e.message); }
});

// CREATE POST
app.post('/api/posts', async (req, res) => {
    try {
        const { username, content } = req.body;
        const np = new Post({ username, content });
        await np.save();
        res.status(201).json({ success: true, message: "Post created!" });
    } catch (e) { errRes(res, e.message); }
});

// COMPLAINT SUBMIT
app.post('/api/complaint/submit', async (req, res) => {
    try {
        const { username, subject, message } = req.body;
        const c = new Complaint({ username, subject, message });
        await c.save();
        okRes(res, { message: "Complaint sent!" });
    } catch (e) { errRes(res, e.message); }
});

// ADMIN API
app.get('/api/admin/users', async (req, res) => {
    try {
        const users = await User.find().select('username email twoFAEnabled createdAt');
        res.json({ success: true, users });
    } catch (e) { errRes(res, e.message); }
});

app.use((req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

app.listen(PORT, () => {
    console.log(`✅ SearchBook Server running on port ${PORT}`);
});

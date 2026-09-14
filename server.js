require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

const app = express();
app.use(express.static(__dirname));
app.use(express.json({ limit: '50mb' }));
app.use(cors());

const MONGO_URI = process.env.MONGO_URI;

// ============ ADMIN SCHEMA (MongoDB) ============
const AdminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});
const Admin = mongoose.model('Admin', AdminSchema);
// ================================================

app.get('/server.js', (req, res) => res.status(403).send('Forbidden'));
app.get('/.env', (req, res) => res.status(403).send('Forbidden'));

mongoose.connect(MONGO_URI)
    .then(() => console.log("SearchBook MongoDB Connected!"))
    .catch(err => console.error("DB Error:", err));

const activeUsers = {};
app.use((req, res, next) => {
    const username = req.headers['x-username'];
    if (username) activeUsers[username] = Date.now();
    next();
});

setInterval(() => {
    const now = Date.now();
    for (const u in activeUsers) {
        if (now - activeUsers[u] > 2 * 60 * 1000) delete activeUsers[u];
    }
}, 60000);

const otpStore = {};

app.post('/api/send-otp', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ success: false, message: "Email dorkar!" });
        const otp = Math.floor(100000 + Math.random() * 900000);
        otpStore[email] = { otp, expiresAt: Date.now() + 60 * 1000 };
        setTimeout(() => {
            if (otpStore[email] && Date.now() >= otpStore[email].expiresAt) delete otpStore[email];
        }, 61000);
        console.log(`OTP for ${email}: ${otp}`);
        res.json({ success: true, message: "OTP generated", otp });
    } catch (error) { res.status(500).json({ success: false, message: "OTP failed" }); }
});

app.post('/api/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;
        const stored = otpStore[email];
        if (!stored) return res.status(400).json({ success: false, message: "OTP expire" });
        if (Date.now() > stored.expiresAt) { delete otpStore[email]; return res.status(400).json({ success: false, message: "OTP expire" }); }
        if (stored.otp != otp) return res.status(400).json({ success: false, message: "Bhul OTP" });
        delete otpStore[email];
        res.json({ success: true, message: "OTP verified" });
    } catch (error) { res.status(500).json({ success: false, message: "Verify failed" }); }
});

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true },
    fullName: { type: String, default: "" },
    bio: { type: String, default: "" },
    profilePic: { type: String, default: "" },
    followers: { type: [String], default: [] },
    following: { type: [String], default: [] },
    bookmarks: { type: [String], default: [] },
    theme: { type: String, default: "light" },
    twoFASecret: { type: String, default: "" },
    twoFAEnabled: { type: Boolean, default: false },
    isBlocked: { type: Boolean, default: false },
    isMuted: { type: Boolean, default: false },
    isSuspended: { type: Boolean, default: false },
    suspendedUntil: { type: Date, default: null },
    warnings: { type: Number, default: 0 },
    strikes: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

const PostSchema = new mongoose.Schema({
    username: { type: String, required: true },
    content: { type: String, default: "" },
    media: { type: String, default: "" },
    mediaType: { type: String, default: "text" },
    likes: { type: [String], default: [] },
    reactions: { type: Object, default: {} },
    comments: { type: Array, default: [] },
    shares: { type: Number, default: 0 },
    views: { type: Number, default: 0 },
    poll: { type: Object, default: null },
    createdAt: { type: Date, default: Date.now }
});
const Post = mongoose.model('Post', PostSchema);

const StorySchema = new mongoose.Schema({
    username: { type: String, required: true },
    media: { type: String, required: true },
    mediaType: { type: String, default: "image" },
    text: { type: String, default: "" },
    expiresAt: { type: Date, required: true },
    createdAt: { type: Date, default: Date.now }
});
const Story = mongoose.model('Story', StorySchema);

const RoomSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },
    members: { type: [String], required: true },
    lastMessage: { type: String, default: "" },
    lastTime: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now }
});
const Room = mongoose.model('Room', RoomSchema);

const MessageSchema = new mongoose.Schema({
    roomId: { type: String, required: true },
    sender: { type: String, required: true },
    text: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', MessageSchema);

const ComplaintSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, default: "" },
    subject: { type: String, required: true },
    message: { type: String, required: true },
    status: { type: String, default: "pending" },
    adminNote: { type: String, default: "" },
    createdAt: { type: Date, default: Date.now }
});
const Complaint = mongoose.model('Complaint', ComplaintSchema);

// ============ AUTH ============
app.post('/api/signup', async (req, res) => {
    try {
        const { username, email, password, fullName } = req.body;
        if (!username || !email || !password) return res.status(400).json({ success: false, message: "Sob field din" });
        const existing = await User.findOne({ $or: [{ email }, { username }] });
        if (existing) return res.status(400).json({ success: false, message: "Email/username ache" });
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newUser = new User({ username, email, fullName: fullName || username, passwordHash: hashedPassword });
        await newUser.save();
        res.status(201).json({ success: true, message: "Account created!" });
    } catch (err) { res.status(500).json({ success: false, message: "Signup failed" }); }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password, twoFACode } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ success: false, message: "User nai!" });

        if (user.isBlocked) return res.status(403).json({ success: false, message: "Apnar account block kora hoyeche." });
        if (user.isSuspended && user.suspendedUntil && user.suspendedUntil > new Date()) {
            return res.status(403).json({ success: false, message: `Account suspended till ${user.suspendedUntil.toLocaleDateString()}` });
        }

        const isMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isMatch) return res.status(400).json({ success: false, message: "Bhul password!" });

        if (user.twoFAEnabled && user.twoFASecret) {
            if (!twoFACode) {
                return res.status(200).json({ success: false, requires2FA: true, message: "2FA code din" });
            }
            const verified = speakeasy.totp.verify({
                secret: user.twoFASecret,
                encoding: 'base32',
                token: twoFACode,
                window: 1
            });
            if (!verified) {
                return res.status(400).json({ success: false, requires2FA: true, message: "Bhul 2FA code!" });
            }
        }

        activeUsers[user.username] = Date.now();
        res.json({ success: true, username: user.username, email: user.email, fullName: user.fullName, theme: user.theme || "light" });
    } catch (err) { res.status(500).json({ success: false, message: "Login failed" }); }
});

// ============ FORGOT PASSWORD ============
app.post('/api/forgot/check-email', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ success: false, message: "Email din" });
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ success: false, message: "Ei email diye kono account nai" });

        if (user.twoFAEnabled && user.twoFASecret) {
            return res.json({ success: true, needs2FA: true, message: "2FA code din age" });
        }

        const otp = Math.floor(100000 + Math.random() * 900000);
        otpStore[email] = { otp, expiresAt: Date.now() + 60 * 1000 };
        setTimeout(() => {
            if (otpStore[email] && Date.now() >= otpStore[email].expiresAt) delete otpStore[email];
        }, 61000);
        res.json({ success: true, needs2FA: false, otp: otp, message: "OTP পাঠানো হয়েছে" });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/forgot/verify-2fa', async (req, res) => {
    try {
        const { email, twoFACode } = req.body;
        if (!email || !twoFACode) return res.status(400).json({ success: false, message: "Sob field din" });
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ success: false, message: "User nai" });

        const verified = speakeasy.totp.verify({
            secret: user.twoFASecret,
            encoding: 'base32',
            token: twoFACode,
            window: 1
        });
        if (!verified) return res.status(400).json({ success: false, message: "Bhul 2FA code!" });

        const otp = Math.floor(100000 + Math.random() * 900000);
        otpStore[email] = { otp, expiresAt: Date.now() + 60 * 1000 };
        setTimeout(() => {
            if (otpStore[email] && Date.now() >= otpStore[email].expiresAt) delete otpStore[email];
        }, 61000);
        res.json({ success: true, otp: otp, message: "2FA verified, OTP পাঠানো হয়েছে" });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/forgot/reset-password', async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;
        if (!email || !otp || !newPassword) return res.status(400).json({ success: false, message: "Sob field din" });
        if (newPassword.length < 6) return res.status(400).json({ success: false, message: "Password min 6 char" });

        const stored = otpStore[email];
        if (!stored) return res.status(400).json({ success: false, message: "OTP expire" });
        if (Date.now() > stored.expiresAt) { delete otpStore[email]; return res.status(400).json({ success: false, message: "OTP expire" }); }
        if (stored.otp != otp) return res.status(400).json({ success: false, message: "Bhul OTP" });

        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ success: false, message: "User nai" });

        const salt = await bcrypt.genSalt(10);
        user.passwordHash = await bcrypt.hash(newPassword, salt);
        await user.save();
        delete otpStore[email];
        res.json({ success: true, message: "Password reset successful! Ekhon login korun." });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

// ============ 2FA APIs ============
app.post('/api/2fa/setup', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ success: false, message: "User nai" });
        const secret = speakeasy.generateSecret({
            name: `Searchbook (${user.username})`,
            issuer: 'Searchbook'
        });
        user.twoFASecret = secret.base32;
        await user.save();
        const qrCodeDataURL = await QRCode.toDataURL(secret.otpauth_url);
        res.json({ success: true, qrCode: qrCodeDataURL, secret: secret.base32 });
    } catch (e) { res.status(500).json({ success: false, message: "2FA setup failed" }); }
});

app.post('/api/2fa/verify', async (req, res) => {
    try {
        const { email, code } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ success: false, message: "User nai" });
        if (!user.twoFASecret) return res.status(400).json({ success: false, message: "Age setup korun" });
        const verified = speakeasy.totp.verify({
            secret: user.twoFASecret,
            encoding: 'base32',
            token: code,
            window: 1
        });
        if (!verified) return res.status(400).json({ success: false, message: "Bhul code!" });
        user.twoFAEnabled = true;
        await user.save();
        res.json({ success: true, message: "2FA enabled!" });
    } catch (e) { res.status(500).json({ success: false, message: "Verify failed" }); }
});

app.post('/api/2fa/disable', async (req, res) => {
    try {
        const { email, code } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ success: false, message: "User nai" });
        const verified = speakeasy.totp.verify({
            secret: user.twoFASecret,
            encoding: 'base32',
            token: code,
            window: 1
        });
        if (!verified) return res.status(400).json({ success: false, message: "Bhul code!" });
        user.twoFAEnabled = false;
        user.twoFASecret = "";
        await user.save();
        res.json({ success: true, message: "2FA disabled!" });
    } catch (e) { res.status(500).json({ success: false, message: "Disable failed" }); }
});

// ============ COMPLAINT APIs ============
app.post('/api/complaint/submit', async (req, res) => {
    try {
        const { username, email, subject, message } = req.body;
        if (!username || !subject || !message) {
            return res.status(400).json({ success: false, message: "Subject and message required" });
        }
        const complaint = new Complaint({ username, email: email || "", subject, message });
        await complaint.save();
        res.json({ success: true, message: "Complaint submitted! Admin shiggiri dekhe action nibe." });
    } catch (e) { res.status(500).json({ success: false, message: "Complaint failed" }); }
});

// ============ ADMIN APIs ============
async function requireAdmin(req, res, next) {
    try {
        const adminUser = req.headers['x-admin-user'];
        if (!adminUser) return res.status(403).json({ success: false, message: "Admin access required" });
        const admin = await Admin.findOne({ username: adminUser });
        if (!admin) return res.status(403).json({ success: false, message: "Admin access required" });
        next();
    } catch (e) {
        res.status(500).json({ success: false, message: "Admin check failed" });
    }
}

app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const admin = await Admin.findOne({ username });
        if (!admin) {
            return res.status(401).json({ success: false, message: "Bhul admin username" });
        }
        const isMatch = await bcrypt.compare(password, admin.passwordHash);
        if (!isMatch) {
            return res.status(401).json({ success: false, message: "Bhul admin password" });
        }
        res.json({ success: true, message: "Admin login successful", adminUser: admin.username });
    } catch (e) {
        res.status(500).json({ success: false, message: "Admin login failed" });
    }
});

app.post('/api/admin/change-password', requireAdmin, async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;
        const adminUser = req.headers['x-admin-user'];
        if (!oldPassword || !newPassword) return res.status(400).json({ success: false, message: "Dui password din" });
        if (newPassword.length < 4) return res.status(400).json({ success: false, message: "Password min 4 char" });
        const admin = await Admin.findOne({ username: adminUser });
        if (!admin) return res.status(404).json({ success: false, message: "Admin nai" });
        const isMatch = await bcrypt.compare(oldPassword, admin.passwordHash);
        if (!isMatch) return res.status(400).json({ success: false, message: "Purono password bhul" });
        const salt = await bcrypt.genSalt(10);
        admin.passwordHash = await bcrypt.hash(newPassword, salt);
        await admin.save();
        res.json({ success: true, message: "Admin password changed!" });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
    try {
        const now = Date.now();
        const users = await User.find().select('-passwordHash -twoFASecret').lean();
        const list = users.map(u => ({
            ...u,
            isActive: !!(activeUsers[u.username] && (now - activeUsers[u.username] < 2 * 60 * 1000)),
            lastActive: activeUsers[u.username] || null
        }));
        list.sort((a, b) => {
            if (a.isActive && !b.isActive) return -1;
            if (!a.isActive && b.isActive) return 1;
            return new Date(b.createdAt) - new Date(a.createdAt);
        });
        res.json({ success: true, users: list, activeCount: list.filter(u => u.isActive).length, totalCount: list.length });
    } catch (e) {
        res.status(500).json({ success: false, message: "Failed to load users" });
    }
});

app.get('/api/admin/complaints', requireAdmin, async (req, res) => {
    try {
        const complaints = await Complaint.find().sort({ createdAt: -1 }).lean();
        res.json({ success: true, complaints });
    } catch (e) {
        res.status(500).json({ success: false, message: "Failed to load complaints" });
    }
});

app.post('/api/admin/complaint/resolve', requireAdmin, async (req, res) => {
    try {
        const { complaintId, adminNote } = req.body;
        const c = await Complaint.findById(complaintId);
        if (!c) return res.status(404).json({ success: false, message: "Complaint nai" });
        c.status = "resolved";
        c.adminNote = adminNote || "Resolved by admin";
        await c.save();
        res.json({ success: true, message: "Complaint resolved" });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/admin/complaint/delete', requireAdmin, async (req, res) => {
    try {
        const { complaintId } = req.body;
        await Complaint.findByIdAndDelete(complaintId);
        res.json({ success: true, message: "Complaint deleted" });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/admin/user/block', requireAdmin, async (req, res) => {
    try {
        const { username, block } = req.body;
        const u = await User.findOne({ username });
        if (!u) return res.status(404).json({ success: false, message: "User nai" });
        u.isBlocked = !!block;
        if (block) { u.isSuspended = false; u.isMuted = false; }
        await u.save();
        if (block) delete activeUsers[username];
        res.json({ success: true, message: block ? "User blocked" : "User unblocked", isBlocked: u.isBlocked });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/admin/user/mute', requireAdmin, async (req, res) => {
    try {
        const { username, mute } = req.body;
        const u = await User.findOne({ username });
        if (!u) return res.status(404).json({ success: false, message: "User nai" });
        u.isMuted = !!mute;
        await u.save();
        res.json({ success: true, message: mute ? "User muted" : "User unmuted", isMuted: u.isMuted });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/admin/user/warn', requireAdmin, async (req, res) => {
    try {
        const { username } = req.body;
        const u = await User.findOne({ username });
        if (!u) return res.status(404).json({ success: false, message: "User nai" });
        u.warnings = (u.warnings || 0) + 1;
        await u.save();
        res.json({ success: true, message: `Warning sent (${u.warnings} total)`, warnings: u.warnings });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/admin/user/strike', requireAdmin, async (req, res) => {
    try {
        const { username } = req.body;
        const u = await User.findOne({ username });
        if (!u) return res.status(404).json({ success: false, message: "User nai" });
        u.strikes = (u.strikes || 0) + 1;
        if (u.strikes >= 3) {
            u.isSuspended = true;
            u.suspendedUntil = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
            delete activeUsers[username];
        }
        await u.save();
        res.json({ success: true, message: `Strike added (${u.strikes} total)`, strikes: u.strikes, autoSuspended: u.strikes >= 3 });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/admin/user/suspend', requireAdmin, async (req, res) => {
    try {
        const { username, suspend, days } = req.body;
        const u = await User.findOne({ username });
        if (!u) return res.status(404).json({ success: false, message: "User nai" });
        u.isSuspended = !!suspend;
        if (suspend) {
            u.isBlocked = false;
            u.suspendedUntil = new Date(Date.now() + (days || 7) * 24 * 60 * 60 * 1000);
        } else {
            u.suspendedUntil = null;
        }
        await u.save();
        if (suspend) delete activeUsers[username];
        res.json({ success: true, message: suspend ? `User suspended for ${days || 7} days` : "User unsuspended", isSuspended: u.isSuspended });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/admin/user/reset-2fa', requireAdmin, async (req, res) => {
    try {
        const { username } = req.body;
        const u = await User.findOne({ username });
        if (!u) return res.status(404).json({ success: false, message: "User nai" });
        u.twoFAEnabled = false;
        u.twoFASecret = "";
        await u.save();
        res.json({ success: true, message: "2FA reset done" });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/admin/user/delete', requireAdmin, async (req, res) => {
    try {
        const { username } = req.body;
        const u = await User.findOne({ username });
        if (!u) return res.status(404).json({ success: false, message: "User nai" });
        await Post.deleteMany({ username });
        await Story.deleteMany({ username });
        await Complaint.deleteMany({ username });
        const rooms = await Room.find({ members: username });
        for (const r of rooms) {
            await Message.deleteMany({ roomId: r._id.toString() });
        }
        await Room.deleteMany({ members: username });
        await User.deleteOne({ username });
        delete activeUsers[username];
        res.json({ success: true, message: "User deleted completely" });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/admin/post/delete', requireAdmin, async (req, res) => {
    try {
        const { postId } = req.body;
        await Post.findByIdAndDelete(postId);
        res.json({ success: true, message: "Post deleted" });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.get('/api/admin/posts', requireAdmin, async (req, res) => {
    try {
        const posts = await Post.find().sort({ createdAt: -1 }).limit(200).lean();
        res.json({ success: true, posts });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

// ============ USER APIs ============
app.post('/api/logout', (req, res) => {
    const { username } = req.body;
    if (username) delete activeUsers[username];
    res.json({ success: true });
});

app.post('/api/heartbeat', (req, res) => {
    const { username } = req.body;
    if (username) activeUsers[username] = Date.now();
    res.json({ success: true });
});

app.get('/api/active-users', (req, res) => {
    const now = Date.now();
    const list = Object.keys(activeUsers).filter(u => now - activeUsers[u] < 2 * 60 * 1000);
    res.json({ success: true, count: list.length, users: list });
});

app.get('/api/user/:email', async (req, res) => {
    try {
        const u = await User.findOne({ email: req.params.email });
        if (!u) return res.status(404).json({ success: false, message: "User nai" });
        const now = Date.now();
        const isActive = activeUsers[u.username] && (now - activeUsers[u.username] < 2 * 60 * 1000);
        res.json({ success: true, user: {
            username: u.username, email: u.email, fullName: u.fullName || u.username,
            bio: u.bio || "", profilePic: u.profilePic || "",
            followers: u.followers || [], following: u.following || [],
            bookmarks: u.bookmarks || [], theme: u.theme || "light",
            twoFAEnabled: u.twoFAEnabled || false,
            isActive: !!isActive, createdAt: u.createdAt
        }});
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.get('/api/user/username/:username', async (req, res) => {
    try {
        const u = await User.findOne({ username: req.params.username });
        if (!u) return res.status(404).json({ success: false, message: "User nai" });
        const now = Date.now();
        const isActive = activeUsers[u.username] && (now - activeUsers[u.username] < 2 * 60 * 1000);
        res.json({ success: true, user: {
            username: u.username, fullName: u.fullName || u.username,
            bio: u.bio || "", profilePic: u.profilePic || "",
            followers: u.followers || [], following: u.following || [],
            isActive: !!isActive, createdAt: u.createdAt
        }});
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.get('/api/search/users/:query', async (req, res) => {
    try {
        const q = req.params.query;
        const users = await User.find({ $or: [
            { username: { $regex: q, $options: 'i' } },
            { fullName: { $regex: q, $options: 'i' } }
        ]}).limit(20).select('username fullName profilePic bio');
        const now = Date.now();
        const list = users.map(u => ({
            username: u.username, fullName: u.fullName,
            profilePic: u.profilePic, bio: u.bio,
            isActive: !!(activeUsers[u.username] && (now - activeUsers[u.username] < 2 * 60 * 1000))
        }));
        res.json({ success: true, users: list });
    } catch (e) { res.status(500).json({ success: false, message: "Search failed" }); }
});

app.put('/api/user/profile', async (req, res) => {
    try {
        const { email, profilePic, bio, fullName } = req.body;
        const u = await User.findOne({ email });
        if (!u) return res.status(404).json({ success: false, message: "User nai" });
        if (profilePic !== undefined) u.profilePic = profilePic;
        if (bio !== undefined) u.bio = bio;
        if (fullName !== undefined) u.fullName = fullName;
        await u.save();
        res.json({ success: true, message: "Profile updated!" });
    } catch (e) { res.status(500).json({ success: false, message: "Update failed" }); }
});

app.put('/api/user/change-password', async (req, res) => {
    try {
        const { email, oldPassword, newPassword, twoFACode } = req.body;
        const u = await User.findOne({ email });
        if (!u) return res.status(404).json({ success: false, message: "User nai" });
        const m = await bcrypt.compare(oldPassword, u.passwordHash);
        if (!m) return res.status(400).json({ success: false, message: "Purono password bhul" });

        if (u.twoFAEnabled && u.twoFASecret) {
            if (!twoFACode) {
                return res.status(200).json({ success: false, requires2FA: true, message: "2FA code din" });
            }
            const verified = speakeasy.totp.verify({
                secret: u.twoFASecret,
                encoding: 'base32',
                token: twoFACode,
                window: 1
            });
            if (!verified) {
                return res.status(400).json({ success: false, requires2FA: true, message: "Bhul 2FA code!" });
            }
        }

        if (newPassword.length < 6) return res.status(400).json({ success: false, message: "Min 6 char" });
        const salt = await bcrypt.genSalt(10);
        u.passwordHash = await bcrypt.hash(newPassword, salt);
        await u.save();
        res.json({ success: true, message: "Password changed!" });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.put('/api/user/theme', async (req, res) => {
    try {
        const { email, theme } = req.body;
        await User.updateOne({ email }, { theme });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/user/bookmark', async (req, res) => {
    try {
        const { email, postId } = req.body;
        const u = await User.findOne({ email });
        if (!u) return res.status(404).json({ success: false, message: "User nai" });
        const idx = u.bookmarks.indexOf(postId);
        if (idx === -1) u.bookmarks.push(postId);
        else u.bookmarks.splice(idx, 1);
        await u.save();
        res.json({ success: true, bookmarks: u.bookmarks });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.get('/api/user/bookmarks/:email', async (req, res) => {
    try {
        const u = await User.findOne({ email: req.params.email });
        if (!u) return res.status(404).json({ success: false, message: "User nai" });
        const posts = await Post.find({ _id: { $in: u.bookmarks } });
        res.json({ success: true, posts });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/user/follow', async (req, res) => {
    try {
        const { follower, following } = req.body;
        if (follower === following) return res.status(400).json({ success: false, message: "Nijer ke follow korte parben na" });
        await User.updateOne({ username: follower }, { $addToSet: { following } });
        await User.updateOne({ username: following }, { $addToSet: { followers: follower } });
        res.json({ success: true, message: "Followed!" });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/user/unfollow', async (req, res) => {
    try {
        const { follower, following } = req.body;
        await User.updateOne({ username: follower }, { $pull: { following } });
        await User.updateOne({ username: following }, { $pull: { followers: follower } });
        res.json({ success: true, message: "Unfollowed!" });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

// ============ POST APIs ============
app.post('/api/posts', async (req, res) => {
    try {
        const { username, content, media, mediaType, poll } = req.body;
        const u = await User.findOne({ username });
        if (u && u.isMuted) {
            return res.status(403).json({ success: false, message: "Apnar account mute kora hoyeche. Post korte parben na." });
        }
        const post = new Post({ username, content, media, mediaType, poll });
        await post.save();
        res.json({ success: true, message: "Post created!", post });
    } catch (e) { res.status(500).json({ success: false, message: "Failed to create post" }); }
});

app.get('/api/posts', async (req, res) => {
    try {
        const posts = await Post.find().sort({ createdAt: -1 }).limit(100);
        res.json({ success: true, posts });
    } catch (e) { res.status(500).json({ success: false, message: "Failed to load posts" }); }
});

app.get('/api/posts/user/:username', async (req, res) => {
    try {
        const posts = await Post.find({ username: req.params.username }).sort({ createdAt: -1 });
        res.json({ success: true, posts });
    } catch (e) { res.status(500).json({ success: false, message: "Failed to load user posts" }); }
});

app.post('/api/posts/like', async (req, res) => {
    try {
        const { postId, username } = req.body;
        const post = await Post.findById(postId);
        if (!post) return res.status(404).json({ success: false, message: "Post nai" });
        const idx = post.likes.indexOf(username);
        if (idx === -1) post.likes.push(username);
        else post.likes.splice(idx, 1);
        await post.save();
        res.json({ success: true, likes: post.likes });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/posts/comment', async (req, res) => {
    try {
        const { postId, username, text } = req.body;
        const post = await Post.findById(postId);
        if (!post) return res.status(404).json({ success: false, message: "Post nai" });
        const comment = { username, text, createdAt: new Date() };
        post.comments.push(comment);
        await post.save();
        res.json({ success: true, comments: post.comments });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.delete('/api/posts/:id', async (req, res) => {
    try {
        await Post.findByIdAndDelete(req.params.id);
        res.json({ success: true, message: "Post deleted" });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

// ============ STORY APIs ============
app.post('/api/stories', async (req, res) => {
    try {
        const { username, media, mediaType, text } = req.body;
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
        const story = new Story({ username, media, mediaType, text, expiresAt });
        await story.save();
        res.json({ success: true, story });
    } catch (e) { res.status(500).json({ success: false, message: "Story create failed" }); }
});

app.get('/api/stories', async (req, res) => {
    try {
        const stories = await Story.find({ expiresAt: { $gt: new Date() } }).sort({ createdAt: -1 });
        res.json({ success: true, stories });
    } catch (e) { res.status(500).json({ success: false, message: "Failed to load stories" }); }
});

// ============ CHAT APIs ============
app.post('/api/chat/room', async (req, res) => {
    try {
        const { name, members } = req.body;
        let room = await Room.findOne({ name });
        if (!room) {
            room = new Room({ name, members });
            await room.save();
        }
        res.json({ success: true, room });
    } catch (e) { res.status(500).json({ success: false, message: "Room create failed" }); }
});

app.get('/api/chat/messages/:roomId', async (req, res) => {
    try {
        const messages = await Message.find({ roomId: req.params.roomId }).sort({ createdAt: 1 });
        res.json({ success: true, messages });
    } catch (e) { res.status(500).json({ success: false, message: "Failed to load messages" }); }
});

app.post('/api/chat/message', async (req, res) => {
    try {
        const { roomId, sender, text } = req.body;
        const msg = new Message({ roomId, sender, text });
        await msg.save();
        await Room.findByIdAndUpdate(roomId, { lastMessage: text, lastTime: new Date() });
        res.json({ success: true, message: msg });
    } catch (e) { res.status(500).json({ success: false, message: "Failed to send message" }); }
});

// ============ SERVER LISTEN ============
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`SearchBook Server running on port ${PORT}`);
});

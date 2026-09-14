require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();

// ============ CORS ============
app.use(cors({
    origin: '*',
    credentials: false,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'x-username', 'x-admin-user']
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ============ ENV VARIABLES ============
// ⚠️ শুধু MONGO_URI .env এ থাকবে
// Admin credentials MongoDB তে hashed থাকে
const MONGO_URI = process.env.MONGO_URI;
const PORT = process.env.PORT || 5000;

if (!MONGO_URI) {
    console.error("❌ ERROR: MONGO_URI not set!");
    process.exit(1);
}

// ============ OPTIONAL MODULES ============
let speakeasy = null, QRCode = null;
try {
    speakeasy = require('speakeasy');
    QRCode = require('qrcode');
    console.log("✅ 2FA modules loaded");
} catch (e) {
    console.warn("⚠️ 2FA modules missing: npm install speakeasy qrcode");
}

// ============ MONGODB ============
mongoose.connect(MONGO_URI)
    .then(() => console.log("✅ MongoDB Connected!"))
    .catch(err => console.error("❌ DB Error:", err.message));

// ============ HELPERS ============
function errRes(res, message, code = 500) {
    return res.status(code).json({ success: false, message: String(message) });
}
function okRes(res, data = {}) {
    return res.json(Object.assign({ success: true }, data));
}

// ============ ACTIVE USERS ============
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

// ============ SCHEMAS ============
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
    twoFAEnabled: { type: Boolean, default: false },
    twoFASecret: { type: String, default: "" },
    isBlocked: { type: Boolean, default: false },
    isSuspended: { type: Boolean, default: false },
    isMuted: { type: Boolean, default: false },
    isFlagged: { type: Boolean, default: false },
    suspendedUntil: { type: Date, default: null },
    warnings: { type: Number, default: 0 },
    strikes: { type: Number, default: 0 },
    lastActive: { type: Date, default: Date.now },
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

// ==================================================================
// ✅ ADMIN SCHEMA — MongoDB তে bcrypt hashed password
// ⚠️ Code এ কোনো admin credentials নেই
// ==================================================================
const AdminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true },
    fullName: { type: String, default: "Administrator" },
    lastLogin: { type: Date, default: null },
    loginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date, default: null },
    createdAt: { type: Date, default: Date.now }
});
const Admin = mongoose.model('Admin', AdminSchema);

// ============ OTP ============
app.post('/api/send-otp', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return errRes(res, "Email dorkar!", 400);
        const otp = Math.floor(100000 + Math.random() * 900000);
        otpStore[email] = { otp, expiresAt: Date.now() + 60000 };
        setTimeout(() => { if (otpStore[email] && Date.now() >= otpStore[email].expiresAt) delete otpStore[email]; }, 61000);
        console.log(`OTP for ${email}: ${otp}`);
        res.json({ success: true, message: "OTP generated", otp });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;
        const stored = otpStore[email];
        if (!stored) return errRes(res, "OTP expire", 400);
        if (Date.now() > stored.expiresAt) { delete otpStore[email]; return errRes(res, "OTP expire", 400); }
        if (stored.otp != otp) return errRes(res, "Bhul OTP", 400);
        delete otpStore[email];
        okRes(res, { message: "OTP verified" });
    } catch (e) { errRes(res, e.message); }
});

// ============ SIGNUP ============
app.post('/api/signup', async (req, res) => {
    try {
        const { username, email, password, fullName } = req.body;
        if (!username || !email || !password) return errRes(res, "Sob field din", 400);
        if (password.length < 6) return errRes(res, "Password min 6 char", 400);
        const existing = await User.findOne({ $or: [{ email }, { username }] });
        if (existing) return errRes(res, "Email/username ache", 400);
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);
        const newUser = new User({ username, email, fullName: fullName || username, passwordHash });
        await newUser.save();
        res.status(201).json({ success: true, message: "Account created!" });
    } catch (e) { errRes(res, e.message); }
});

// ============ LOGIN ============
app.post('/api/login', async (req, res) => {
    try {
        const { email, password, twoFACode } = req.body;
        if (!email || !password) return errRes(res, "Email + password din", 400);
        const user = await User.findOne({ email });
        if (!user) return errRes(res, "User nai!", 400);
        if (user.isBlocked) return errRes(res, "Account block!", 403);
        if (user.isSuspended && user.suspendedUntil && user.suspendedUntil > new Date()) {
            return errRes(res, "Account suspended!", 403);
        }
        const isMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isMatch) return errRes(res, "Bhul password!", 400);
        if (user.twoFAEnabled) {
            if (!speakeasy) return errRes(res, "2FA unavailable", 500);
            if (!twoFACode) return res.json({ success: false, requires2FA: true });
            const verified = speakeasy.totp.verify({ secret: user.twoFASecret, encoding: 'base32', token: twoFACode, window: 1 });
            if (!verified) return errRes(res, "Bhul 2FA code!", 400);
        }
        activeUsers[user.username] = Date.now();
        user.lastActive = new Date();
        await user.save();
        res.json({ success: true, username: user.username, email: user.email, fullName: user.fullName, theme: user.theme || "light" });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/logout', (req, res) => {
    try {
        const { username } = req.body;
        if (username) delete activeUsers[username];
        okRes(res);
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/heartbeat', async (req, res) => {
    try {
        const { username } = req.body;
        if (username) {
            activeUsers[username] = Date.now();
            try { await User.updateOne({ username }, { lastActive: new Date() }); } catch (e) {}
        }
        okRes(res);
    } catch (e) { errRes(res, e.message); }
});

app.get('/api/active-users', (req, res) => {
    try {
        const now = Date.now();
        const list = Object.keys(activeUsers).filter(u => now - activeUsers[u] < 2 * 60 * 1000);
        res.json({ success: true, count: list.length, users: list });
    } catch (e) { errRes(res, e.message); }
});

// ============ USER ============
app.get('/api/user/:email', async (req, res) => {
    try {
        const u = await User.findOne({ email: req.params.email });
        if (!u) return errRes(res, "User nai", 404);
        const now = Date.now();
        const isActive = activeUsers[u.username] && (now - activeUsers[u.username] < 2 * 60 * 1000);
        res.json({ success: true, user: {
            username: u.username, email: u.email, fullName: u.fullName || u.username,
            bio: u.bio || "", profilePic: u.profilePic || "",
            followers: u.followers || [], following: u.following || [],
            bookmarks: u.bookmarks || [], theme: u.theme || "light",
            twoFAEnabled: u.twoFAEnabled || false, isActive: !!isActive, createdAt: u.createdAt
        }});
    } catch (e) { errRes(res, e.message); }
});

app.get('/api/user/username/:username', async (req, res) => {
    try {
        const u = await User.findOne({ username: req.params.username });
        if (!u) return errRes(res, "User nai", 404);
        const now = Date.now();
        const isActive = activeUsers[u.username] && (now - activeUsers[u.username] < 2 * 60 * 1000);
        res.json({ success: true, user: {
            username: u.username, fullName: u.fullName || u.username,
            bio: u.bio || "", profilePic: u.profilePic || "",
            followers: u.followers || [], following: u.following || [],
            isActive: !!isActive, createdAt: u.createdAt
        }});
    } catch (e) { errRes(res, e.message); }
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
            username: u.username, fullName: u.fullName, profilePic: u.profilePic, bio: u.bio,
            isActive: !!(activeUsers[u.username] && (now - activeUsers[u.username] < 2 * 60 * 1000))
        }));
        res.json({ success: true, users: list });
    } catch (e) { errRes(res, e.message); }
});

app.put('/api/user/profile', async (req, res) => {
    try {
        const { email, profilePic, bio, fullName } = req.body;
        const u = await User.findOne({ email });
        if (!u) return errRes(res, "User nai", 404);
        if (profilePic !== undefined) u.profilePic = profilePic;
        if (bio !== undefined) u.bio = bio;
        if (fullName !== undefined) u.fullName = fullName;
        await u.save();
        okRes(res, { message: "Profile updated!" });
    } catch (e) { errRes(res, e.message); }
});

app.put('/api/user/change-password', async (req, res) => {
    try {
        const { email, oldPassword, newPassword } = req.body;
        const u = await User.findOne({ email });
        if (!u) return errRes(res, "User nai", 404);
        const m = await bcrypt.compare(oldPassword, u.passwordHash);
        if (!m) return errRes(res, "Purono password bhul", 400);
        if (newPassword.length < 6) return errRes(res, "Min 6 char", 400);
        const salt = await bcrypt.genSalt(10);
        u.passwordHash = await bcrypt.hash(newPassword, salt);
        await u.save();
        okRes(res, { message: "Password changed!" });
    } catch (e) { errRes(res, e.message); }
});

app.put('/api/user/theme', async (req, res) => {
    try {
        const { email, theme } = req.body;
        await User.updateOne({ email }, { theme });
        okRes(res);
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/user/bookmark', async (req, res) => {
    try {
        const { email, postId } = req.body;
        const u = await User.findOne({ email });
        if (!u) return errRes(res, "User nai", 404);
        const idx = u.bookmarks.indexOf(postId);
        if (idx === -1) u.bookmarks.push(postId);
        else u.bookmarks.splice(idx, 1);
        await u.save();
        res.json({ success: true, bookmarks: u.bookmarks });
    } catch (e) { errRes(res, e.message); }
});

app.get('/api/user/bookmarks/:email', async (req, res) => {
    try {
        const u = await User.findOne({ email: req.params.email });
        if (!u) return errRes(res, "User nai", 404);
        const posts = await Post.find({ _id: { $in: u.bookmarks } });
        res.json({ success: true, posts });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/user/follow', async (req, res) => {
    try {
        const { follower, following } = req.body;
        if (follower === following) return errRes(res, "Nijer ke follow kora jabe na", 400);
        await User.updateOne({ username: follower }, { $addToSet: { following } });
        await User.updateOne({ username: following }, { $addToSet: { followers: follower } });
        okRes(res, { message: "Followed!" });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/user/unfollow', async (req, res) => {
    try {
        const { follower, following } = req.body;
        await User.updateOne({ username: follower }, { $pull: { following } });
        await User.updateOne({ username: following }, { $pull: { followers: follower } });
        okRes(res, { message: "Unfollowed!" });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/user/delete-self', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return errRes(res, "Email + password din", 400);
        const user = await User.findOne({ email });
        if (!user) return errRes(res, "User nai", 404);
        const match = await bcrypt.compare(password, user.passwordHash);
        if (!match) return errRes(res, "Password bhul!", 400);
        const username = user.username;
        await Post.deleteMany({ username });
        await Story.deleteMany({ username });
        await Message.deleteMany({ sender: username });
        await Room.deleteMany({ members: username });
        await Complaint.deleteMany({ username });
        await User.updateMany({ followers: username }, { $pull: { followers: username } });
        await User.updateMany({ following: username }, { $pull: { following: username } });
        await User.deleteOne({ email });
        delete activeUsers[username];
        okRes(res, { message: "Account deleted." });
    } catch (e) { errRes(res, e.message); }
});

// ============ POSTS ============
app.post('/api/posts/delete-own', async (req, res) => {
    try {
        const { postId, username } = req.body;
        const post = await Post.findById(postId);
        if (!post) return errRes(res, "Post nai", 404);
        if (post.username !== username) return errRes(res, "Ei post apnar na!", 403);
        await Post.deleteOne({ _id: postId });
        okRes(res, { message: "Post deleted!" });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/posts', async (req, res) => {
    try {
        const { username, content, media, mediaType, poll } = req.body;
        const u = await User.findOne({ username });
        if (u && u.isMuted) return errRes(res, "Apni mute achen", 403);
        const np = new Post({ username, content: content || "", media: media || "", mediaType: mediaType || "text", poll: poll || null });
        await np.save();
        res.status(201).json({ success: true, message: "Post created!" });
    } catch (e) { errRes(res, e.message); }
});

app.get('/api/feed/:username', async (req, res) => {
    try {
        const currentUsername = req.params.username;
        const currentUser = await User.findOne({ username: currentUsername });
        if (!currentUser) return errRes(res, "User nai", 404);
        const following = currentUser.following || [];
        const posts = await Post.find().limit(200).lean();
        const now = Date.now();
        const myLikes = [], myComments = [];
        posts.forEach(p => {
            if (p.likes && p.likes.includes(currentUsername)) myLikes.push(p.username);
            if (p.comments) p.comments.forEach(c => { if (c.username === currentUsername) myComments.push(p.username); });
        });
        posts.forEach(p => {
            const age = (now - new Date(p.createdAt).getTime()) / 3600000;
            const interestMatch = (myLikes.filter(u => u === p.username).length * 2) + (myComments.filter(u => u === p.username).length * 3);
            const isFriend = following.includes(p.username) ? 1 : 0;
            const trendingScore = ((p.likes?.length || 0) * 2) + ((p.comments?.length || 0) * 3) + ((p.shares || 0) * 4) + ((p.views || 0) * 0.3) + (Object.values(p.reactions || {}).reduce((s, arr) => s + (arr?.length || 0), 0) * 2);
            const recencyScore = Math.max(0, 48 - age) * 3;
            p.feedScore = (interestMatch * 4) + (isFriend * 3 * 100) + (trendingScore * 2) + recencyScore;
        });
        posts.sort((a, b) => b.feedScore - a.feedScore);
        res.json(posts.slice(0, 50));
    } catch (e) { errRes(res, e.message); }
});

app.get('/api/posts', async (req, res) => {
    try {
        const posts = await Post.find().limit(100).lean();
        const now = Date.now();
        posts.forEach(p => {
            const age = (now - new Date(p.createdAt).getTime()) / 3600000;
            const likeScore = (p.likes?.length || 0) * 3;
            const commentScore = (p.comments?.length || 0) * 4;
            const shareScore = (p.shares || 0) * 5;
            const viewScore = (p.views || 0) * 0.5;
            const reactionScore = Object.values(p.reactions || {}).reduce((s, arr) => s + (arr?.length || 0), 0) * 3;
            const timeScore = Math.max(0, 24 - age) * 2;
            p.score = likeScore + commentScore + shareScore + viewScore + reactionScore + timeScore;
        });
        posts.sort((a, b) => b.score - a.score);
        res.json(posts.slice(0, 50));
    } catch (e) { errRes(res, e.message); }
});

app.get('/api/posts/user/:username', async (req, res) => {
    try {
        const posts = await Post.find({ username: req.params.username }).sort({ createdAt: -1 });
        res.json(posts);
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/posts/like', async (req, res) => {
    try {
        const { postId, username } = req.body;
        const p = await Post.findById(postId);
        if (!p) return errRes(res, "Post nai", 404);
        const idx = p.likes.indexOf(username);
        if (idx === -1) p.likes.push(username); else p.likes.splice(idx, 1);
        await p.save();
        res.json({ success: true, likes: p.likes.length });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/posts/reaction', async (req, res) => {
    try {
        const { postId, username, reaction } = req.body;
        const p = await Post.findById(postId);
        if (!p) return errRes(res, "Post nai", 404);
        if (!p.reactions) p.reactions = {};
        if (!p.reactions[reaction]) p.reactions[reaction] = [];
        Object.keys(p.reactions).forEach(k => {
            const idx = p.reactions[k].indexOf(username);
            if (idx !== -1 && k !== reaction) p.reactions[k].splice(idx, 1);
        });
        const idx = p.reactions[reaction].indexOf(username);
        if (idx === -1) p.reactions[reaction].push(username);
        else p.reactions[reaction].splice(idx, 1);
        p.markModified('reactions');
        await p.save();
        res.json({ success: true, reactions: p.reactions });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/posts/comment', async (req, res) => {
    try {
        const { postId, username, text } = req.body;
        const p = await Post.findById(postId);
        if (!p) return errRes(res, "Post nai", 404);
        p.comments.push({ username, text, createdAt: new Date() });
        await p.save();
        res.json({ success: true, comments: p.comments });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/posts/share', async (req, res) => {
    try {
        const { postId } = req.body;
        const p = await Post.findById(postId);
        if (!p) return errRes(res, "Post nai", 404);
        p.shares = (p.shares || 0) + 1;
        await p.save();
        res.json({ success: true, shares: p.shares });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/posts/view', async (req, res) => {
    try {
        const { postId } = req.body;
        await Post.findByIdAndUpdate(postId, { $inc: { views: 1 } });
        okRes(res);
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/posts/vote', async (req, res) => {
    try {
        const { postId, username, optionIndex } = req.body;
        const p = await Post.findById(postId);
        if (!p || !p.poll) return errRes(res, "Poll nai", 404);
        let alreadyVoted = false;
        p.poll.options.forEach((opt, i) => {
            const idx = opt.votes.indexOf(username);
            if (idx !== -1) { opt.votes.splice(idx, 1); if (i === optionIndex) alreadyVoted = true; }
        });
        if (!alreadyVoted) p.poll.options[optionIndex].votes.push(username);
        p.markModified('poll');
        await p.save();
        res.json({ success: true, poll: p.poll });
    } catch (e) { errRes(res, e.message); }
});

// ============ STORIES ============
app.post('/api/stories', async (req, res) => {
    try {
        const { username, media, mediaType, text } = req.body;
        if (!media) return errRes(res, "Media dorkar", 400);
        const ns = new Story({ username, media, mediaType: mediaType || "image", text: text || "", expiresAt: new Date(Date.now() + 24*60*60*1000) });
        await ns.save();
        res.status(201).json({ success: true, message: "Story created!" });
    } catch (e) { errRes(res, e.message); }
});

app.get('/api/stories', async (req, res) => {
    try {
        await Story.deleteMany({ expiresAt: { $lt: new Date() } });
        const stories = await Story.find({ expiresAt: { $gt: new Date() } }).sort({ createdAt: -1 });
        const grouped = {};
        stories.forEach(s => {
            if (!grouped[s.username]) grouped[s.username] = [];
            grouped[s.username].push(s);
        });
        res.json({ success: true, stories: grouped });
    } catch (e) { errRes(res, e.message); }
});

// ============ CHAT ============
app.post('/api/chat/room', async (req, res) => {
    try {
        const { user1, user2 } = req.body;
        const roomName = [user1, user2].sort().join('_');
        let room = await Room.findOne({ name: roomName });
        if (!room) { room = new Room({ name: roomName, members: [user1, user2] }); await room.save(); }
        res.json({ success: true, room });
    } catch (e) { errRes(res, e.message); }
});

app.get('/api/chat/rooms/:username', async (req, res) => {
    try {
        const rooms = await Room.find({ members: req.params.username }).sort({ lastTime: -1 });
        res.json({ success: true, rooms });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/chat/message', async (req, res) => {
    try {
        const { roomId, sender, text } = req.body;
        const m = new Message({ roomId, sender, text });
        await m.save();
        await Room.findByIdAndUpdate(roomId, { lastMessage: text.substring(0, 50), lastTime: new Date() });
        res.json({ success: true, message: m });
    } catch (e) { errRes(res, e.message); }
});

app.get('/api/chat/messages/:roomId', async (req, res) => {
    try {
        const msgs = await Message.find({ roomId: req.params.roomId }).sort({ createdAt: 1 }).limit(200);
        res.json({ success: true, messages: msgs });
    } catch (e) { errRes(res, e.message); }
});

// ============ ALGORITHMS ============
app.get('/api/recommend/:username', async (req, res) => {
    try {
        const myUsername = req.params.username;
        const me = await User.findOne({ username: myUsername });
        if (!me) return errRes(res, "User nai", 404);
        const myFollowing = me.following || [];
        const allUsers = await User.find({ username: { $ne: myUsername } }).limit(200);
        const now = Date.now();
        const recommendations = [];
        for (const other of allUsers) {
            if (myFollowing.includes(other.username)) continue;
            const otherFollowers = other.followers || [];
            const mutualFollowers = otherFollowers.filter(f => myFollowing.includes(f));
            const mutualScore = mutualFollowers.length * 3;
            const otherIsActive = !!(activeUsers[other.username] && (now - activeUsers[other.username] < 2 * 60 * 1000));
            const iAmActive = !!(activeUsers[myUsername] && (now - activeUsers[myUsername] < 2 * 60 * 1000));
            const activityMatch = (otherIsActive === iAmActive) ? 2 : 0;
            const activityLevel = Math.min(5, otherFollowers.length / 10);
            const ratioPenalty = ((other.following || []).length > otherFollowers.length * 3) ? -2 : 0;
            const totalScore = mutualScore + activityMatch + activityLevel + ratioPenalty;
            if (totalScore > 0) {
                let reason = [];
                if (mutualFollowers.length > 0) reason.push(mutualFollowers.length + " mutual");
                if (otherIsActive && iAmActive) reason.push("Both active");
                if (otherFollowers.length > 20) reason.push("Popular");
                if (reason.length === 0) reason.push("Suggested");
                recommendations.push({
                    username: other.username, fullName: other.fullName, profilePic: other.profilePic,
                    isActive: otherIsActive, score: Math.round(totalScore * 10) / 10, reason: reason.join(" · ")
                });
            }
        }
        recommendations.sort((a, b) => b.score - a.score);
        res.json({ success: true, recommendations: recommendations.slice(0, 15) });
    } catch (e) { errRes(res, e.message); }
});

app.get('/api/notifications/:username', async (req, res) => {
    try {
        const myUsername = req.params.username;
        const me = await User.findOne({ username: myUsername });
        if (!me) return errRes(res, "User nai", 404);
        const myFollowing = me.following || [];
        const now = Date.now();
        const notifications = [];
        const recentPosts = await Post.find({ username: { $in: myFollowing } }).sort({ createdAt: -1 }).limit(20);
        recentPosts.forEach(p => {
            const ageHours = (now - new Date(p.createdAt).getTime()) / 3600000;
            const priority = 9 + ((p.likes?.length || 0) * 0.2);
            if (priority >= 8) {
                notifications.push({
                    icon: "📝", text: p.username + " posted: " + (p.content || "").substring(0, 60),
                    timeAgo: Math.round(ageHours) + "h ago",
                    priorityScore: Math.round(priority * 10) / 10,
                    priority: priority >= 12 ? "high" : priority >= 9 ? "medium" : "low"
                });
            }
        });
        (me.followers || []).slice(-5).forEach(f => {
            notifications.push({ icon: "👤", text: f + " started following you", timeAgo: "Recently", priorityScore: 10.5, priority: "high" });
        });
        notifications.sort((a, b) => b.priorityScore - a.priorityScore);
        res.json({ success: true, notifications: notifications.slice(0, 20) });
    } catch (e) { errRes(res, e.message); }
});

async function detectFakeScore(user) {
    let score = 0;
    const reasons = [];
    if (!user.profilePic || user.profilePic.length < 50) { score += 1; reasons.push("No pic"); }
    const postCount = await Post.countDocuments({ username: user.username });
    if (postCount === 0) { score += 2; reasons.push("No posts"); }
    const followingCount = (user.following || []).length;
    const followerCount = (user.followers || []).length;
    if (followingCount > 50 && followerCount < 5) { score += 3; reasons.push("Follows many"); }
    if (!user.bio || user.bio.length < 3) { score += 1; reasons.push("Empty bio"); }
    return { score, reasons, isFake: score >= 5 };
}

// ============ COMPLAINT ============
app.post('/api/complaint/submit', async (req, res) => {
    try {
        const { username, email, subject, message } = req.body;
        if (!username || !subject || !message) return errRes(res, "Sob field din", 400);
        const c = new Complaint({ username, email: email || "", subject, message });
        await c.save();
        okRes(res, { message: "Complaint submitted." });
    } catch (e) { errRes(res, e.message); }
});

// ==================================================================
// ✅ ADMIN AUTH — MongoDB bcrypt hashed password
// ⚠️ Code এ কোনো admin credentials hardcoded নেই
// ==================================================================
async function verifyAdmin(req) {
    const header = req.headers['x-admin-user'];
    if (!header) return null;
    const admin = await Admin.findOne({ username: header });
    return admin || null;
}

app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return errRes(res, "Username + password din", 400);

        const admin = await Admin.findOne({ username });
        if (!admin) return errRes(res, "Bhul credentials", 401);

        // Check if locked
        if (admin.lockUntil && admin.lockUntil > new Date()) {
            return errRes(res, "Account locked. Try again later.", 429);
        }

        const isMatch = await bcrypt.compare(password, admin.passwordHash);
        if (!isMatch) {
            admin.loginAttempts = (admin.loginAttempts || 0) + 1;
            if (admin.loginAttempts >= 5) {
                admin.lockUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 min lock
                admin.loginAttempts = 0;
                await admin.save();
                return errRes(res, "Too many attempts. Locked for 15 minutes.", 429);
            }
            await admin.save();
            return errRes(res, "Bhul credentials", 401);
        }

        // Success
        admin.loginAttempts = 0;
        admin.lockUntil = null;
        admin.lastLogin = new Date();
        await admin.save();

        res.json({ success: true, adminUser: admin.username });
    } catch (e) { errRes(res, e.message); }
});

app.get('/api/admin/users', async (req, res) => {
    try {
        const admin = await verifyAdmin(req);
        if (!admin) return errRes(res, "Unauthorized", 401);
        const users = await User.find().sort({ createdAt: -1 });
        const now = Date.now();
        const list = [];
        let flaggedCount = 0;
        for (const u of users) {
            const fake = await detectFakeScore(u);
            if (fake.isFake) flaggedCount++;
            list.push({
                username: u.username, email: u.email, fullName: u.fullName || "",
                isActive: !!(activeUsers[u.username] && (now - activeUsers[u.username] < 2 * 60 * 1000)),
                isBlocked: !!u.isBlocked,
                isSuspended: !!(u.isSuspended && u.suspendedUntil && u.suspendedUntil > new Date()),
                isMuted: !!u.isMuted, isFlagged: fake.isFake,
                suspendedUntil: u.suspendedUntil, warnings: u.warnings || 0,
                strikes: u.strikes || 0, twoFAEnabled: u.twoFAEnabled || false,
                lastActive: u.lastActive || u.createdAt, createdAt: u.createdAt
            });
        }
        res.json({ success: true, users: list, totalCount: list.length, activeCount: list.filter(u => u.isActive).length, flaggedCount });
    } catch (e) { errRes(res, e.message); }
});

app.get('/api/admin/flagged-users', async (req, res) => {
    try {
        const admin = await verifyAdmin(req);
        if (!admin) return errRes(res, "Unauthorized", 401);
        const users = await User.find();
        const flagged = [];
        for (const u of users) {
            const fake = await detectFakeScore(u);
            if (fake.isFake) flagged.push({ username: u.username, fakeScore: fake.score, reasons: fake.reasons });
        }
        flagged.sort((a, b) => b.fakeScore - a.fakeScore);
        res.json({ success: true, users: flagged });
    } catch (e) { errRes(res, e.message); }
});

app.get('/api/admin/user/analysis/:username', async (req, res) => {
    try {
        const admin = await verifyAdmin(req);
        if (!admin) return errRes(res, "Unauthorized", 401);
        const username = req.params.username;
        const user = await User.findOne({ username });
        if (!user) return errRes(res, "User not found", 404);
        const posts = await Post.find({ username });
        const stories = await Story.find({ username });
        const messages = await Message.find({ sender: username });
        let totalLikesReceived = 0, totalCommentsReceived = 0, totalViews = 0;
        posts.forEach(p => {
            totalLikesReceived += (p.likes || []).length;
            totalCommentsReceived += (p.comments || []).length;
            totalViews += (p.views || 0);
        });
        const stats = {
            totalPosts: posts.length, totalLikesReceived, totalCommentsReceived, totalViews,
            totalStories: stories.length, totalMessages: messages.length,
            totalFollowers: (user.followers || []).length, totalFollowing: (user.following || []).length
        };
        const fake = await detectFakeScore(user);
        res.json({
            success: true,
            user: { username: user.username, email: user.email, fullName: user.fullName, bio: user.bio,
                profilePic: user.profilePic, isBlocked: user.isBlocked, isSuspended: user.isSuspended,
                isMuted: user.isMuted, isFlagged: fake.isFake, fakeScore: fake.score,
                suspendedUntil: user.suspendedUntil, warnings: user.warnings || 0,
                strikes: user.strikes || 0, twoFAEnabled: user.twoFAEnabled || false,
                theme: user.theme || "light", lastActive: user.lastActive || user.createdAt, createdAt: user.createdAt },
            stats, recentPosts: posts.slice(0, 5).map(p => ({ _id: p._id, content: p.content, likes: p.likes || [], comments: p.comments || [], views: p.views || 0, createdAt: p.createdAt }))
        });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/admin/user/block', async (req, res) => {
    try {
        const admin = await verifyAdmin(req);
        if (!admin) return errRes(res, "Unauthorized", 401);
        const { username, block } = req.body;
        await User.updateOne({ username }, { isBlocked: block });
        if (block) delete activeUsers[username];
        okRes(res, { message: block ? "User blocked!" : "User unblocked!" });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/admin/user/mute', async (req, res) => {
    try {
        const admin = await verifyAdmin(req);
        if (!admin) return errRes(res, "Unauthorized", 401);
        const { username, mute } = req.body;
        await User.updateOne({ username }, { isMuted: mute });
        okRes(res, { message: mute ? "User muted!" : "User unmuted!" });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/admin/user/warn', async (req, res) => {
    try {
        const admin = await verifyAdmin(req);
        if (!admin) return errRes(res, "Unauthorized", 401);
        const { username } = req.body;
        const u = await User.findOneAndUpdate({ username }, { $inc: { warnings: 1 } }, { new: true });
        okRes(res, { message: `Warning #${u.warnings} added` });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/admin/user/strike', async (req, res) => {
    try {
        const admin = await verifyAdmin(req);
        if (!admin) return errRes(res, "Unauthorized", 401);
        const { username } = req.body;
        const u = await User.findOneAndUpdate({ username }, { $inc: { strikes: 1 } }, { new: true });
        if (u.strikes >= 3) {
            u.isSuspended = true;
            u.suspendedUntil = new Date(Date.now() + 7*24*60*60*1000);
            await u.save();
            okRes(res, { message: `${username} auto-suspended 7 days!` });
        } else {
            okRes(res, { message: `Strike #${u.strikes} added` });
        }
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/admin/user/suspend', async (req, res) => {
    try {
        const admin = await verifyAdmin(req);
        if (!admin) return errRes(res, "Unauthorized", 401);
        const { username, suspend, days } = req.body;
        if (suspend) {
            const until = new Date(Date.now() + (days || 7) * 24*60*60*1000);
            await User.updateOne({ username }, { isSuspended: true, suspendedUntil: until });
            delete activeUsers[username];
            okRes(res, { message: `${username} suspended` });
        } else {
            await User.updateOne({ username }, { isSuspended: false, suspendedUntil: null });
            okRes(res, { message: `${username} unsuspended` });
        }
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/admin/user/reset-2fa', async (req, res) => {
    try {
        const admin = await verifyAdmin(req);
        if (!admin) return errRes(res, "Unauthorized", 401);
        const { username } = req.body;
        await User.updateOne({ username }, { twoFAEnabled: false, twoFASecret: "" });
        okRes(res, { message: `2FA reset` });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/admin/user/delete', async (req, res) => {
    try {
        const admin = await verifyAdmin(req);
        if (!admin) return errRes(res, "Unauthorized", 401);
        const { username } = req.body;
        await Post.deleteMany({ username });
        await Story.deleteMany({ username });
        await Message.deleteMany({ sender: username });
        await Room.deleteMany({ members: username });
        await Complaint.deleteMany({ username });
        await User.updateMany({ followers: username }, { $pull: { followers: username } });
        await User.updateMany({ following: username }, { $pull: { following: username } });
        await User.deleteOne({ username });
        delete activeUsers[username];
        okRes(res, { message: `${username} deleted` });
    } catch (e) { errRes(res, e.message); }
});

app.get('/api/admin/complaints', async (req, res) => {
    try {
        const admin = await verifyAdmin(req);
        if (!admin) return errRes(res, "Unauthorized", 401);
        const complaints = await Complaint.find().sort({ createdAt: -1 });
        res.json({ success: true, complaints });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/admin/complaint/resolve', async (req, res) => {
    try {
        const admin = await verifyAdmin(req);
        if (!admin) return errRes(res, "Unauthorized", 401);
        const { complaintId, adminNote } = req.body;
        await Complaint.updateOne({ _id: complaintId }, { status: "resolved", adminNote: adminNote || "" });
        okRes(res, { message: "Complaint resolved!" });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/admin/complaint/delete', async (req, res) => {
    try {
        const admin = await verifyAdmin(req);
        if (!admin) return errRes(res, "Unauthorized", 401);
        const { complaintId } = req.body;
        await Complaint.deleteOne({ _id: complaintId });
        okRes(res, { message: "Complaint deleted!" });
    } catch (e) { errRes(res, e.message); }
});

app.get('/api/admin/posts', async (req, res) => {
    try {
        const admin = await verifyAdmin(req);
        if (!admin) return errRes(res, "Unauthorized", 401);
        const posts = await Post.find().sort({ createdAt: -1 }).limit(100);
        res.json({ success: true, posts });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/admin/post/delete', async (req, res) => {
    try {
        const admin = await verifyAdmin(req);
        if (!admin) return errRes(res, "Unauthorized", 401);
        const { postId } = req.body;
        await Post.deleteOne({ _id: postId });
        okRes(res, { message: "Post deleted!" });
    } catch (e) { errRes(res, e.message); }
});

// ============ 2FA ============
app.post('/api/2fa/setup', async (req, res) => {
    try {
        if (!speakeasy || !QRCode) return errRes(res, "2FA not available", 500);
        const { email } = req.body;
        const u = await User.findOne({ email });
        if (!u) return errRes(res, "User nai", 404);
        const secret = speakeasy.generateSecret({ name: `Searchbook (${u.username})`, length: 20 });
        u.twoFASecret = secret.base32;
        await u.save();
        const qrCode = await QRCode.toDataURL(secret.otpauth_url);
        res.json({ success: true, secret: secret.base32, qrCode });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/2fa/verify', async (req, res) => {
    try {
        if (!speakeasy) return errRes(res, "2FA not available", 500);
        const { email, code } = req.body;
        const u = await User.findOne({ email });
        if (!u || !u.twoFASecret) return errRes(res, "Setup age korun", 400);
        const verified = speakeasy.totp.verify({ secret: u.twoFASecret, encoding: 'base32', token: code, window: 1 });
        if (!verified) return errRes(res, "Bhul code!", 400);
        u.twoFAEnabled = true;
        await u.save();
        okRes(res, { message: "2FA enabled!" });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/2fa/disable', async (req, res) => {
    try {
        if (!speakeasy) return errRes(res, "2FA not available", 500);
        const { email, code } = req.body;
        const u = await User.findOne({ email });
        if (!u || !u.twoFAEnabled) return errRes(res, "2FA off", 400);
        const verified = speakeasy.totp.verify({ secret: u.twoFASecret, encoding: 'base32', token: code, window: 1 });
        if (!verified) return errRes(res, "Bhul code!", 400);
        u.twoFAEnabled = false;
        u.twoFASecret = "";
        await u.save();
        okRes(res, { message: "2FA disabled!" });
    } catch (e) { errRes(res, e.message); }
});

// ============ FORGOT ============
app.post('/api/forgot/check-email', async (req, res) => {
    try {
        const { email } = req.body;
        const u = await User.findOne({ email });
        if (!u) return errRes(res, "Account nai", 404);
        if (u.twoFAEnabled) return res.json({ success: true, needs2FA: true });
        const otp = Math.floor(100000 + Math.random() * 900000);
        otpStore[email] = { otp, expiresAt: Date.now() + 60000 };
        setTimeout(() => { if (otpStore[email] && Date.now() >= otpStore[email].expiresAt) delete otpStore[email]; }, 61000);
        res.json({ success: true, needs2FA: false, otp });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/forgot/verify-2fa', async (req, res) => {
    try {
        if (!speakeasy) return errRes(res, "2FA not available", 500);
        const { email, twoFACode } = req.body;
        const u = await User.findOne({ email });
        if (!u || !u.twoFAEnabled) return errRes(res, "2FA off", 400);
        const verified = speakeasy.totp.verify({ secret: u.twoFASecret, encoding: 'base32', token: twoFACode, window: 1 });
        if (!verified) return errRes(res, "Bhul 2FA code!", 400);
        const otp = Math.floor(100000 + Math.random() * 900000);
        otpStore[email] = { otp, expiresAt: Date.now() + 60000 };
        res.json({ success: true, otp });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/forgot/reset-password', async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;
        const stored = otpStore[email];
        if (!stored) return errRes(res, "OTP expire", 400);
        if (Date.now() > stored.expiresAt) { delete otpStore[email]; return errRes(res, "OTP expire", 400); }
        if (stored.otp != otp) return errRes(res, "Bhul OTP", 400);
        if (!newPassword || newPassword.length < 6) return errRes(res, "Min 6 char", 400);
        const u = await User.findOne({ email });
        if (!u) return errRes(res, "User nai", 404);
        const salt = await bcrypt.genSalt(10);
        u.passwordHash = await bcrypt.hash(newPassword, salt);
        await u.save();
        delete otpStore[email];
        okRes(res, { message: "Password reset successful!" });
    } catch (e) { errRes(res, e.message); }
});

// ============ CATCH-ALL ============
app.use('/api', (req, res) => {
    res.status(404).json({ success: false, message: "API not found: " + req.originalUrl });
});

app.use((req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ============ START ============
app.listen(PORT, () => {
    console.log("═══════════════════════════════════");
    console.log(`✅ SearchBook running on port ${PORT}`);
    console.log(`🌐 URL: http://localhost:${PORT}`);
    console.log("═══════════════════════════════════");
});

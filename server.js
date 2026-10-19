Require('dotenv').config();
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

// Community Chat Schema
const CommunityMessageSchema = new mongoose.Schema({
    sender: { type: String, required: true },
    text: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});
const CommunityMessage = mongoose.model('CommunityMessage', CommunityMessageSchema);

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

// ============ 30-SECOND OTP ============
app.post('/api/send-otp', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return errRes(res, "Email required!", 400);
        const otp = Math.floor(100000 + Math.random() * 900000);
        otpStore[email] = { otp, expiresAt: Date.now() + 30000 }; // 30 seconds expiration
        setTimeout(() => { if (otpStore[email] && Date.now() >= otpStore[email].expiresAt) delete otpStore[email]; }, 31000);
        res.json({ success: true, message: "OTP generated", otp });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;
        const stored = otpStore[email];
        if (!stored) return errRes(res, "OTP expired", 400);
        if (Date.now() > stored.expiresAt) { delete otpStore[email]; return errRes(res, "OTP expired", 400); }
        if (stored.otp != otp) return errRes(res, "Invalid OTP", 400);
        delete otpStore[email];
        okRes(res, { message: "OTP verified" });
    } catch (e) { errRes(res, e.message); }
});

// ============ SIGNUP ============
app.post('/api/signup', async (req, res) => {
    try {
        const { username, email, password, fullName } = req.body;
        if (!username || !email || !password) return errRes(res, "All fields required", 400);
        if (password.length < 6) return errRes(res, "Password must be min 6 chars", 400);
        const existing = await User.findOne({ $or: [{ email }, { username }] });
        if (existing) return errRes(res, "Email or username already exists", 400);
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
        if (!email || !password) return errRes(res, "Email + password required", 400);
        const user = await User.findOne({ email });
        if (!user) return errRes(res, "User not found!", 400);
        if (user.isBlocked) return errRes(res, "Account blocked!", 403);
        if (user.isSuspended && user.suspendedUntil && user.suspendedUntil > new Date()) {
            return errRes(res, "Account suspended!", 403);
        }
        const isMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isMatch) return errRes(res, "Invalid password!", 400);
        if (user.twoFAEnabled) {
            if (!speakeasy) return errRes(res, "2FA unavailable", 500);
            if (!twoFACode) return res.json({ success: false, requires2FA: true });
            const verified = speakeasy.totp.verify({ secret: user.twoFASecret, encoding: 'base32', token: twoFACode, window: 1 });
            if (!verified) return errRes(res, "Invalid 2FA code!", 400);
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

// ============ USER ROUTES ============
app.get('/api/user/:email', async (req, res) => {
    try {
        const u = await User.findOne({ email: req.params.email });
        if (!u) return errRes(res, "User not found", 404);
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
        if (!u) return errRes(res, "User not found", 404);
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
        if (!u) return errRes(res, "User not found", 404);
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
        if (!u) return errRes(res, "User not found", 404);
        const m = await bcrypt.compare(oldPassword, u.passwordHash);
        if (!m) return errRes(res, "Incorrect old password", 400);
        if (newPassword.length < 6) return errRes(res, "Min 6 chars required", 400);
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
        if (!u) return errRes(res, "User not found", 404);
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
        if (!u) return errRes(res, "User not found", 404);
        const posts = await Post.find({ _id: { $in: u.bookmarks } });
        res.json({ success: true, posts });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/user/follow', async (req, res) => {
    try {
        const { follower, following } = req.body;
        if (follower === following) return errRes(res, "Cannot follow yourself", 400);
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
        const user = await User.findOne({ email });
        if (!user) return errRes(res, "User not found", 404);
        const match = await bcrypt.compare(password, user.passwordHash);
        if (!match) return errRes(res, "Incorrect password!", 400);
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

// ============ SMART AI ALGORITHM & POSTS ============
app.post('/api/posts/delete-own', async (req, res) => {
    try {
        const { postId, username } = req.body;
        const post = await Post.findById(postId);
        if (!post) return errRes(res, "Post not found", 404);
        if (post.username !== username) return errRes(res, "Unauthorized", 403);
        await Post.deleteOne({ _id: postId });
        okRes(res, { message: "Post deleted!" });
    } catch (e) { errRes(res, e.message); }
});

// In-code AI content moderation (Anti-toxic / Ad-blocker / Safety shield)
function isToxicOrInappropriate(content) {
    if (!content) return false;
    const lower = content.toLowerCase();
    const badWords = ["badword1", "badword2", "hate", "kill", "suicide", "nsfw", "porn", "xxx"]; // configurable toxic keywords
    for (let word of badWords) {
        if (lower.includes(word)) return true;
    }
    return false;
}

app.post('/api/posts', async (req, res) => {
    try {
        const { username, content, media, mediaType, poll } = req.body;
        const u = await User.findOne({ username });
        if (u && u.isMuted) return errRes(res, "You are muted by admin", 403);
        
        // AI moderation check
        if (isToxicOrInappropriate(content)) {
            return errRes(res, "Post flagged by AI moderation: Inappropriate or toxic content detected.", 400);
        }

        const np = new Post({ username, content: content || "", media: media || "", mediaType: mediaType || "text", poll: poll || null });
        await np.save();
        res.status(201).json({ success: true, message: "Post created!" });
    } catch (e) { errRes(res, e.message); }
});

// AI Smart Feed Ranking Algorithm Engine
app.get('/api/feed/:username', async (req, res) => {
    try {
        const currentUsername = req.params.username;
        const currentUser = await User.findOne({ username: currentUsername });
        if (!currentUser) return errRes(res, "User not found", 404);
        const following = currentUser.following || [];
        const posts = await Post.find().limit(200).lean();
        const now = Date.now();
        
        posts.forEach(p => {
            const ageHours = (now - new Date(p.createdAt).getTime()) / 3600000;
            const isFriend = following.includes(p.username) ? 20 : 0;
            const mediaBoost = p.media ? 15 : 0; // Video & Image boost
            const pollBoost = p.poll ? 10 : 0;
            const trendingScore = ((p.likes?.length || 0) * 3) + ((p.comments?.length || 0) * 4) + ((p.shares || 0) * 5) + ((p.views || 0) * 0.2) + (Object.values(p.reactions || {}).reduce((s, arr) => s + (arr?.length || 0), 0) * 3);
            const recencyDecay = Math.max(0, 72 - ageHours) * 1.5;
            
            p.feedScore = isFriend + mediaBoost + pollBoost + trendingScore + recencyDecay;
        });
        posts.sort((a, b) => b.feedScore - a.feedScore);
        res.json(posts.slice(0, 50));
    } catch (e) { errRes(res, e.message); }
});

app.get('/api/posts', async (req, res) => {
    try {
        const posts = await Post.find().limit(100).sort({ createdAt: -1 }).lean();
        res.json(posts);
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
        if (!p) return errRes(res, "Post not found", 404);
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
        if (!p) return errRes(res, "Post not found", 404);
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
        if (isToxicOrInappropriate(text)) return errRes(res, "Comment blocked by AI filter.", 400);
        const p = await Post.findById(postId);
        if (!p) return errRes(res, "Post not found", 404);
        p.comments.push({ username, text, createdAt: new Date() });
        await p.save();
        res.json({ success: true, comments: p.comments });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/posts/share', async (req, res) => {
    try {
        const { postId } = req.body;
        const p = await Post.findById(postId);
        if (!p) return errRes(res, "Post not found", 404);
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
        if (!p || !p.poll) return errRes(res, "Poll not found", 404);
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
        if (!media) return errRes(res, "Media required", 400);
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

// ============ PRIVATE & COMMUNITY CHAT ============
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
        if (isToxicOrInappropriate(text)) return errRes(res, "Message blocked by AI filter.", 400);
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

// Community Chatroom endpoints
app.get('/api/community/messages', async (req, res) => {
    try {
        const messages = await CommunityMessage.find().sort({ createdAt: 1 }).limit(100);
        res.json({ success: true, messages });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/community/message', async (req, res) => {
    try {
        const { sender, text } = req.body;
        if (!sender || !text) return errRes(res, "Sender and text required", 400);
        if (isToxicOrInappropriate(text)) return errRes(res, "Message blocked by AI filter.", 400);
        const msg = new CommunityMessage({ sender, text });
        await msg.save();
        res.json({ success: true, message: msg });
    } catch (e) { errRes(res, e.message); }
});

// ============ RECOMMENDATIONS & NOTIFICATIONS ============
app.get('/api/recommend/:username', async (req, res) => {
    try {
        const myUsername = req.params.username;
        const me = await User.findOne({ username: myUsername });
        if (!me) return errRes(res, "User not found", 404);
        const myFollowing = me.following || [];
        const allUsers = await User.find({ username: { $ne: myUsername } }).limit(200);
        const recommendations = [];
        for (const other of allUsers) {
            if (myFollowing.includes(other.username)) continue;
            const mutualFollowers = (other.followers || []).filter(f => myFollowing.includes(f));
            recommendations.push({
                username: other.username, fullName: other.fullName, profilePic: other.profilePic,
                score: mutualFollowers.length + 1, reason: mutualFollowers.length > 0 ? mutualFollowers.length + " mutual" : "Suggested"
            });
        }
        recommendations.sort((a, b) => b.score - a.score);
        res.json({ success: true, recommendations: recommendations.slice(0, 10) });
    } catch (e) { errRes(res, e.message); }
});

// ============ COMPLAINTS ============
app.post('/api/complaint/submit', async (req, res) => {
    try {
        const { username, email, subject, message } = req.body;
        if (!username || !subject || !message) return errRes(res, "All fields required", 400);
        const c = new Complaint({ username, email: email || "", subject, message });
        await c.save();
        okRes(res, { message: "Complaint submitted successfully." });
    } catch (e) { errRes(res, e.message); }
});

// ============ 2FA & FORGOT PASSWORD ============
app.post('/api/2fa/setup', async (req, res) => {
    try {
        if (!speakeasy || !QRCode) return errRes(res, "2FA not available", 500);
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
        if (!speakeasy) return errRes(res, "2FA not available", 500);
        const { email, code } = req.body;
        const u = await User.findOne({ email });
        if (!u || !u.twoFASecret) return errRes(res, "Setup 2FA first", 400);
        const verified = speakeasy.totp.verify({ secret: u.twoFASecret, encoding: 'base32', token: code, window: 1 });
        if (!verified) return errRes(res, "Invalid code!", 400);
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
        if (!u || !u.twoFAEnabled) return errRes(res, "2FA already off", 400);
        const verified = speakeasy.totp.verify({ secret: u.twoFASecret, encoding: 'base32', token: code, window: 1 });
        if (!verified) return errRes(res, "Invalid code!", 400);
        u.twoFAEnabled = false;
        u.twoFASecret = "";
        await u.save();
        okRes(res, { message: "2FA disabled!" });
    } catch (e) { errRes(res, e.message); }
});

// 2FA-Locked Password Reset Flow
app.post('/api/forgot/check-email', async (req, res) => {
    try {
        const { email } = req.body;
        const u = await User.findOne({ email });
        if (!u) return errRes(res, "Account not found", 404);
        if (u.twoFAEnabled) return res.json({ success: true, needs2FA: true });
        const otp = Math.floor(100000 + Math.random() * 900000);
        otpStore[email] = { otp, expiresAt: Date.now() + 30000 };
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
        if (!verified) return errRes(res, "Invalid 2FA code!", 400);
        const otp = Math.floor(100000 + Math.random() * 900000);
        otpStore[email] = { otp, expiresAt: Date.now() + 30000 };
        res.json({ success: true, otp });
    } catch (e) { errRes(res, e.message); }
});

app.post('/api/forgot/reset-password', async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;
        const stored = otpStore[email];
        if (!stored || Date.now() > stored.expiresAt || stored.otp != otp) {
            return errRes(res, "OTP expired or invalid", 400);
        }
        if (!newPassword || newPassword.length < 6) return errRes(res, "Min 6 chars required", 400);
        const u = await User.findOne({ email });
        if (!u) return errRes(res, "User not found", 404);
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

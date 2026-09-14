require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.static(__dirname));
app.use(express.json({ limit: '50mb' }));
app.use(cors());

// MongoDB URI .env file থেকে আসবে — GitHub এ দেখা যাবে না
const MONGO_URI = process.env.MONGO_URI;

// Sensitive files block (safety)
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

// ===== USER SCHEMA (নতুন field সহ) =====
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

// ===== COMPLAINT SCHEMA =====
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
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ success: false, message: "User nai!" });

        if (user.isBlocked) return res.status(403).json({ success: false, message: "Apnar account block kora hoyeche!" });
        if (user.isSuspended && user.suspendedUntil && user.suspendedUntil > new Date()) {
            return res.status(403).json({ success: false, message: "Account suspended until " + user.suspendedUntil.toLocaleDateString() });
        }

        const isMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isMatch) return res.status(400).json({ success: false, message: "Bhul password!" });

        activeUsers[user.username] = Date.now();
        user.lastActive = new Date();
        await user.save();
        res.json({ success: true, username: user.username, email: user.email, fullName: user.fullName, theme: user.theme || "light" });
    } catch (err) { res.status(500).json({ success: false, message: "Login failed" }); }
});

app.post('/api/logout', (req, res) => {
    const { username } = req.body;
    if (username) delete activeUsers[username];
    res.json({ success: true });
});

app.post('/api/heartbeat', async (req, res) => {
    const { username } = req.body;
    if (username) {
        activeUsers[username] = Date.now();
        try { await User.updateOne({ username }, { lastActive: new Date() }); } catch (e) {}
    }
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
        const { email, oldPassword, newPassword } = req.body;
        const u = await User.findOne({ email });
        if (!u) return res.status(404).json({ success: false, message: "User nai" });
        const m = await bcrypt.compare(oldPassword, u.passwordHash);
        if (!m) return res.status(400).json({ success: false, message: "Purono password bhul" });
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

// ==================================================================
// ✅ NEW #1: USER নিজের Account Delete করার API
// ==================================================================
app.post('/api/user/delete-self', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ success: false, message: "Email + password din" });
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ success: false, message: "User nai" });
        const match = await bcrypt.compare(password, user.passwordHash);
        if (!match) return res.status(400).json({ success: false, message: "Password bhul!" });
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
        console.log(`🗑️ Account self-deleted: ${username} (${email})`);
        res.json({ success: true, message: "Account permanently deleted. Sob data muche geche." });
    } catch (e) {
        console.error("Delete account error:", e);
        res.status(500).json({ success: false, message: "Delete failed: " + e.message });
    }
});

// ==================================================================
// ✅ NEW #2: নিজের Post Delete করার API
// ==================================================================
app.post('/api/posts/delete-own', async (req, res) => {
    try {
        const { postId, username } = req.body;
        if (!postId || !username) return res.status(400).json({ success: false, message: "postId + username din" });
        const post = await Post.findById(postId);
        if (!post) return res.status(404).json({ success: false, message: "Post nai" });
        if (post.username !== username) return res.status(403).json({ success: false, message: "Ei post apnar na!" });
        await Post.deleteOne({ _id: postId });
        console.log(`🗑️ Post deleted: ${postId} by ${username}`);
        res.json({ success: true, message: "Post deleted!" });
    } catch (e) { res.status(500).json({ success: false, message: "Delete failed: " + e.message }); }
});

app.post('/api/posts', async (req, res) => {
    try {
        const { username, content, media, mediaType, poll } = req.body;
        const u = await User.findOne({ username });
        if (u && u.isMuted) return res.status(403).json({ success: false, message: "Apni mute kora achen, post korte parben na" });
        const np = new Post({ username, content: content || "", media: media || "", mediaType: mediaType || "text", poll: poll || null });
        await np.save();
        res.status(201).json({ success: true, message: "Post created!" });
    } catch (e) { res.status(500).json({ success: false, message: "Post failed" }); }
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
    } catch (e) { res.status(500).json({ success: false, message: "Load failed" }); }
});

app.get('/api/posts/user/:username', async (req, res) => {
    try {
        const posts = await Post.find({ username: req.params.username }).sort({ createdAt: -1 });
        res.json(posts);
    } catch (e) { res.status(500).json({ success: false, message: "Load failed" }); }
});

app.post('/api/posts/like', async (req, res) => {
    try {
        const { postId, username } = req.body;
        const p = await Post.findById(postId);
        if (!p) return res.status(404).json({ success: false, message: "Post nai" });
        const idx = p.likes.indexOf(username);
        if (idx === -1) p.likes.push(username); else p.likes.splice(idx, 1);
        await p.save();
        res.json({ success: true, likes: p.likes.length });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/posts/reaction', async (req, res) => {
    try {
        const { postId, username, reaction } = req.body;
        const p = await Post.findById(postId);
        if (!p) return res.status(404).json({ success: false, message: "Post nai" });
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
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/posts/comment', async (req, res) => {
    try {
        const { postId, username, text } = req.body;
        const p = await Post.findById(postId);
        if (!p) return res.status(404).json({ success: false, message: "Post nai" });
        p.comments.push({ username, text, createdAt: new Date() });
        await p.save();
        res.json({ success: true, comments: p.comments });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/posts/share', async (req, res) => {
    try {
        const { postId } = req.body;
        const p = await Post.findById(postId);
        if (!p) return res.status(404).json({ success: false, message: "Post nai" });
        p.shares = (p.shares || 0) + 1;
        await p.save();
        res.json({ success: true, shares: p.shares });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/posts/view', async (req, res) => {
    try {
        const { postId } = req.body;
        await Post.findByIdAndUpdate(postId, { $inc: { views: 1 } });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/posts/vote', async (req, res) => {
    try {
        const { postId, username, optionIndex } = req.body;
        const p = await Post.findById(postId);
        if (!p || !p.poll) return res.status(404).json({ success: false, message: "Poll nai" });
        let alreadyVoted = false;
        p.poll.options.forEach((opt, i) => {
            const idx = opt.votes.indexOf(username);
            if (idx !== -1) {
                opt.votes.splice(idx, 1);
                if (i === optionIndex) alreadyVoted = true;
            }
        });
        if (!alreadyVoted) p.poll.options[optionIndex].votes.push(username);
        p.markModified('poll');
        await p.save();
        res.json({ success: true, poll: p.poll });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/stories', async (req, res) => {
    try {
        const { username, media, mediaType, text } = req.body;
        if (!media) return res.status(400).json({ success: false, message: "Media dorkar" });
        const ns = new Story({ username, media, mediaType: mediaType || "image", text: text || "", expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) });
        await ns.save();
        res.status(201).json({ success: true, message: "Story created!" });
    } catch (e) { res.status(500).json({ success: false, message: "Story failed" }); }
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
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/chat/room', async (req, res) => {
    try {
        const { user1, user2 } = req.body;
        const roomName = [user1, user2].sort().join('_');
        let room = await Room.findOne({ name: roomName });
        if (!room) {
            room = new Room({ name: roomName, members: [user1, user2] });
            await room.save();
        }
        res.json({ success: true, room });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.get('/api/chat/rooms/:username', async (req, res) => {
    try {
        const rooms = await Room.find({ members: req.params.username }).sort({ lastTime: -1 });
        res.json({ success: true, rooms });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/chat/message', async (req, res) => {
    try {
        const { roomId, sender, text } = req.body;
        const m = new Message({ roomId, sender, text });
        await m.save();
        await Room.findByIdAndUpdate(roomId, { lastMessage: text.substring(0, 50), lastTime: new Date() });
        res.json({ success: true, message: m });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.get('/api/chat/messages/:roomId', async (req, res) => {
    try {
        const msgs = await Message.find({ roomId: req.params.roomId }).sort({ createdAt: 1 }).limit(200);
        res.json({ success: true, messages: msgs });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

// ==================== COMPLAINT SYSTEM ====================
app.post('/api/complaint/submit', async (req, res) => {
    try {
        const { username, email, subject, message } = req.body;
        if (!username || !subject || !message) return res.status(400).json({ success: false, message: "Sob field din" });
        const c = new Complaint({ username, email: email || "", subject, message });
        await c.save();
        console.log(`📢 Complaint from ${username}: ${subject}`);
        res.json({ success: true, message: "Complaint submitted. Admin shiggiri dekhe nebe." });
    } catch (e) { res.status(500).json({ success: false, message: "Failed: " + e.message }); }
});

// ==================== ADMIN PANEL APIS ====================
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";

function isAdmin(req) {
    return req.headers['x-admin-user'] === ADMIN_USERNAME;
}

app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        res.json({ success: true, adminUser: ADMIN_USERNAME });
    } else {
        res.status(401).json({ success: false, message: "Bhul credentials" });
    }
});

app.get('/api/admin/users', async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(401).json({ success: false, message: "Unauthorized" });
        const users = await User.find().sort({ createdAt: -1 });
        const now = Date.now();
        const list = users.map(u => ({
            username: u.username,
            email: u.email,
            fullName: u.fullName || "",
            isActive: !!(activeUsers[u.username] && (now - activeUsers[u.username] < 2 * 60 * 1000)),
            isBlocked: !!u.isBlocked,
            isSuspended: !!(u.isSuspended && u.suspendedUntil && u.suspendedUntil > new Date()),
            isMuted: !!u.isMuted,
            suspendedUntil: u.suspendedUntil,
            warnings: u.warnings || 0,
            strikes: u.strikes || 0,
            twoFAEnabled: u.twoFAEnabled || false,
            lastActive: u.lastActive || u.createdAt,
            createdAt: u.createdAt
        }));
        const activeCount = list.filter(u => u.isActive).length;
        res.json({ success: true, users: list, totalCount: list.length, activeCount });
    } catch (e) { res.status(500).json({ success: false, message: "Failed: " + e.message }); }
});

// ==================================================================
// ✅ NEW #3: ADMIN USER DATA ANALYSIS
// ==================================================================
app.get('/api/admin/user/analysis/:username', async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(401).json({ success: false, message: "Unauthorized" });
        const username = req.params.username;
        const user = await User.findOne({ username });
        if (!user) return res.status(404).json({ success: false, message: "User not found" });
        const posts = await Post.find({ username });
        const stories = await Story.find({ username });
        const messages = await Message.find({ sender: username });
        let totalLikesReceived = 0;
        let totalCommentsReceived = 0;
        let totalViews = 0;
        let totalReactionsReceived = 0;
        posts.forEach(p => {
            totalLikesReceived += (p.likes || []).length;
            totalCommentsReceived += (p.comments || []).length;
            totalViews += (p.views || 0);
            totalReactionsReceived += Object.values(p.reactions || {}).reduce((s, arr) => s + (arr?.length || 0), 0);
        });
        const stats = {
            totalPosts: posts.length,
            totalLikesReceived,
            totalCommentsReceived,
            totalViews,
            totalReactionsReceived,
            totalStories: stories.length,
            totalMessages: messages.length,
            totalFollowers: (user.followers || []).length,
            totalFollowing: (user.following || []).length
        };
        const recentPosts = posts
            .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
            .slice(0, 5)
            .map(p => ({
                _id: p._id,
                content: p.content,
                likes: p.likes || [],
                comments: p.comments || [],
                views: p.views || 0,
                createdAt: p.createdAt
            }));
        res.json({
            success: true,
            user: {
                username: user.username,
                email: user.email,
                fullName: user.fullName,
                bio: user.bio,
                profilePic: user.profilePic,
                isBlocked: user.isBlocked,
                isSuspended: user.isSuspended,
                isMuted: user.isMuted,
                suspendedUntil: user.suspendedUntil,
                warnings: user.warnings || 0,
                strikes: user.strikes || 0,
                twoFAEnabled: user.twoFAEnabled || false,
                theme: user.theme || "light",
                lastActive: user.lastActive || user.createdAt,
                createdAt: user.createdAt
            },
            stats,
            recentPosts
        });
    } catch (e) { res.status(500).json({ success: false, message: "Failed: " + e.message }); }
});

app.post('/api/admin/user/block', async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(401).json({ success: false, message: "Unauthorized" });
        const { username, block } = req.body;
        await User.updateOne({ username }, { isBlocked: block });
        if (block) delete activeUsers[username];
        res.json({ success: true, message: block ? "User blocked!" : "User unblocked!" });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/admin/user/mute', async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(401).json({ success: false, message: "Unauthorized" });
        const { username, mute } = req.body;
        await User.updateOne({ username }, { isMuted: mute });
        res.json({ success: true, message: mute ? "User muted!" : "User unmuted!" });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/admin/user/warn', async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(401).json({ success: false, message: "Unauthorized" });
        const { username } = req.body;
        const u = await User.findOneAndUpdate({ username }, { $inc: { warnings: 1 } }, { new: true });
        res.json({ success: true, message: `Warning #${u.warnings} added to ${username}` });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/admin/user/strike', async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(401).json({ success: false, message: "Unauthorized" });
        const { username } = req.body;
        const u = await User.findOneAndUpdate({ username }, { $inc: { strikes: 1 } }, { new: true });
        if (u.strikes >= 3) {
            const until = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
            u.isSuspended = true;
            u.suspendedUntil = until;
            await u.save();
            res.json({ success: true, message: `⚠️ ${username} auto-suspended 7 days (3 strikes)!` });
        } else {
            res.json({ success: true, message: `Strike #${u.strikes} added to ${username}` });
        }
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/admin/user/suspend', async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(401).json({ success: false, message: "Unauthorized" });
        const { username, suspend, days } = req.body;
        if (suspend) {
            const until = new Date(Date.now() + (days || 7) * 24 * 60 * 60 * 1000);
            await User.updateOne({ username }, { isSuspended: true, suspendedUntil: until });
            delete activeUsers[username];
            res.json({ success: true, message: `${username} suspended ${days || 7} days` });
        } else {
            await User.updateOne({ username }, { isSuspended: false, suspendedUntil: null });
            res.json({ success: true, message: `${username} unsuspended` });
        }
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/admin/user/reset-2fa', async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(401).json({ success: false, message: "Unauthorized" });
        const { username } = req.body;
        await User.updateOne({ username }, { twoFAEnabled: false, twoFASecret: "" });
        res.json({ success: true, message: `2FA reset for ${username}` });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/admin/user/delete', async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(401).json({ success: false, message: "Unauthorized" });
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
        res.json({ success: true, message: `${username} and all data deleted` });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.get('/api/admin/complaints', async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(401).json({ success: false, message: "Unauthorized" });
        const complaints = await Complaint.find().sort({ createdAt: -1 });
        res.json({ success: true, complaints });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/admin/complaint/resolve', async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(401).json({ success: false, message: "Unauthorized" });
        const { complaintId, adminNote } = req.body;
        await Complaint.updateOne({ _id: complaintId }, { status: "resolved", adminNote: adminNote || "" });
        res.json({ success: true, message: "Complaint resolved!" });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/admin/complaint/delete', async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(401).json({ success: false, message: "Unauthorized" });
        const { complaintId } = req.body;
        await Complaint.deleteOne({ _id: complaintId });
        res.json({ success: true, message: "Complaint deleted!" });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.get('/api/admin/posts', async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(401).json({ success: false, message: "Unauthorized" });
        const posts = await Post.find().sort({ createdAt: -1 }).limit(100);
        res.json({ success: true, posts });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

app.post('/api/admin/post/delete', async (req, res) => {
    try {
        if (!isAdmin(req)) return res.status(401).json({ success: false, message: "Unauthorized" });
        const { postId } = req.body;
        await Post.deleteOne({ _id: postId });
        res.json({ success: true, message: "Post deleted!" });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

// ==================== 2FA SYSTEM ====================
app.post('/api/2fa/setup', async (req, res) => {
    try {
        const { email } = req.body;
        const u = await User.findOne({ email });
        if (!u) return res.status(404).json({ success: false, message: "User nai" });
        const speakeasy = require('speakeasy');
        const QRCode = require('qrcode');
        const secret = speakeasy.generateSecret({ name: `Searchbook (${u.username})`, length: 20 });
        u.twoFASecret = secret.base32;
        await u.save();
        const qrCode = await QRCode.toDataURL(secret.otpauth_url);
        res.json({ success: true, secret: secret.base32, qrCode });
    } catch (e) { res.status(500).json({ success: false, message: "Failed: " + e.message }); }
});

app.post('/api/2fa/verify', async (req, res) => {
    try {
        const { email, code } = req.body;
        const u = await User.findOne({ email });
        if (!u) return res.status(404).json({ success: false, message: "User nai" });
        if (!u.twoFASecret) return res.status(400).json({ success: false, message: "Setup korte hobe age" });
        const speakeasy = require('speakeasy');
        const verified = speakeasy.totp.verify({ secret: u.twoFASecret, encoding: 'base32', token: code, window: 1 });
        if (!verified) return res.status(400).json({ success: false, message: "Bhul code!" });
        u.twoFAEnabled = true;
        await u.save();
        res.json({ success: true, message: "2FA enabled!" });
    } catch (e) { res.status(500).json({ success: false, message: "Failed: " + e.message }); }
});

app.post('/api/2fa/disable', async (req, res) => {
    try {
        const { email, code } = req.body;
        const u = await User.findOne({ email });
        if (!u) return res.status(404).json({ success: false, message: "User nai" });
        if (!u.twoFAEnabled) return res.status(400).json({ success: false, message: "2FA already off" });
        const speakeasy = require('speakeasy');
        const verified = speakeasy.totp.verify({ secret: u.twoFASecret, encoding: 'base32', token: code, window: 1 });
        if (!verified) return res.status(400).json({ success: false, message: "Bhul code!" });
        u.twoFAEnabled = false;
        u.twoFASecret = "";
        await u.save();
        res.json({ success: true, message: "2FA disabled!" });
    } catch (e) { res.status(500).json({ success: false, message: "Failed: " + e.message }); }
});

// ==================== FORGOT PASSWORD ====================
app.post('/api/forgot/check-email', async (req, res) => {
    try {
        const { email } = req.body;
        const u = await User.findOne({ email });
        if (!u) return res.status(404).json({ success: false, message: "Ei email e kono account nai" });
        if (u.twoFAEnabled) return res.json({ success: true, needs2FA: true, message: "2FA code din" });
        const otp = Math.floor(100000 + Math.random() * 900000);
        otpStore[email] = { otp, expiresAt: Date.now() + 60 * 1000 };
        setTimeout(() => { if (otpStore[email] && Date.now() >= otpStore[email].expiresAt) delete otpStore[email]; }, 61000);
        console.log(`Forgot OTP for ${email}: ${otp}`);
        res.json({ success: true, needs2FA: false, otp });
    } catch (e) { res.status(500).json({ success: false, message: "Failed: " + e.message }); }
});

app.post('/api/forgot/verify-2fa', async (req, res) => {
    try {
        const { email, twoFACode } = req.body;
        const u = await User.findOne({ email });
        if (!u) return res.status(404).json({ success: false, message: "User nai" });
        if (!u.twoFAEnabled) return res.status(400).json({ success: false, message: "2FA off" });
        const speakeasy = require('speakeasy');
        const verified = speakeasy.totp.verify({ secret: u.twoFASecret, encoding: 'base32', token: twoFACode, window: 1 });
        if (!verified) return res.status(400).json({ success: false, message: "Bhul 2FA code!" });
        const otp = Math.floor(100000 + Math.random() * 900000);
        otpStore[email] = { otp, expiresAt: Date.now() + 60 * 1000 };
        setTimeout(() => { if (otpStore[email] && Date.now() >= otpStore[email].expiresAt) delete otpStore[email]; }, 61000);
        res.json({ success: true, otp });
    } catch (e) { res.status(500).json({ success: false, message: "Failed: " + e.message }); }
});

app.post('/api/forgot/reset-password', async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;
        const stored = otpStore[email];
        if (!stored) return res.status(400).json({ success: false, message: "OTP expire" });
        if (Date.now() > stored.expiresAt) { delete otpStore[email]; return res.status(400).json({ success: false, message: "OTP expire" }); }
        if (stored.otp != otp) return res.status(400).json({ success: false, message: "Bhul OTP" });
        if (!newPassword || newPassword.length < 6) return res.status(400).json({ success: false, message: "Min 6 char" });
        const u = await User.findOne({ email });
        if (!u) return res.status(404).json({ success: false, message: "User nai" });
        const salt = await bcrypt.genSalt(10);
        u.passwordHash = await bcrypt.hash(newPassword, salt);
        await u.save();
        delete otpStore[email];
        res.json({ success: true, message: "Password reset successful!" });
    } catch (e) { res.status(500).json({ success: false, message: "Failed: " + e.message }); }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`SearchBook running on port ${PORT}`));

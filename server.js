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

// ============ OTP Store ============
const otpStore = {};
// Reset password store
const resetStore = {};

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
    twoFASecret: { type: String, default: "" },
    twoFAEnabled: { type: Boolean, default: false },
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
// Step 1: Check email + check if 2FA enabled
app.post('/api/forgot/check-email', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ success: false, message: "Email din" });
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ success: false, message: "Ei email diye kono account nai" });
        
        // If 2FA enabled, needs 2FA verification first
        if (user.twoFAEnabled && user.twoFASecret) {
            return res.json({ success: true, needs2FA: true, message: "2FA code din age" });
        }
        
        // Send OTP
        const otp = Math.floor(100000 + Math.random() * 900000);
        otpStore[email] = { otp, expiresAt: Date.now() + 60 * 1000 };
        setTimeout(() => {
            if (otpStore[email] && Date.now() >= otpStore[email].expiresAt) delete otpStore[email];
        }, 61000);
        console.log(`Reset OTP for ${email}: ${otp}`);
        res.json({ success: true, needs2FA: false, otp: otp, message: "OTP পাঠানো হয়েছে" });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

// Step 2: Verify 2FA and send OTP
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
        
        // Send OTP after 2FA verified
        const otp = Math.floor(100000 + Math.random() * 900000);
        otpStore[email] = { otp, expiresAt: Date.now() + 60 * 1000 };
        setTimeout(() => {
            if (otpStore[email] && Date.now() >= otpStore[email].expiresAt) delete otpStore[email];
        }, 61000);
        console.log(`Reset OTP for ${email}: ${otp}`);
        res.json({ success: true, otp: otp, message: "2FA verified, OTP পাঠানো হয়েছে" });
    } catch (e) { res.status(500).json({ success: false, message: "Failed" }); }
});

// Step 3: Reset password with OTP
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

app.post('/api/posts', async (req, res) => {
    try {
        const { username, content, media, mediaType, poll } = req.body;
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

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`SearchBook running on port ${PORT}`));

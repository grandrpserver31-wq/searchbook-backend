require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

const MONGO_URI = process.env.MONGO_URI;
const PORT = process.env.PORT || 5000;

let speakeasy = null, QRCode = null;
try {
    speakeasy = require('speakeasy');
    QRCode = require('qrcode');
} catch (e) {}

mongoose.connect(MONGO_URI).then(() => console.log("✅ DB Connected")).catch(e => console.error(e));

// AI Security Bot / Toxicity Filter Words List
const toxicKeywords = ["badword1", "badword2", "terrorist", "hackingscript", "spamattack", "abuse"];
function isToxicContent(text) {
    if (!text) return false;
    const lower = text.toLowerCase();
    return toxicKeywords.some(word => lower.includes(word));
}

// Strong Password Validation Helper
function isStrongPassword(pass) {
    if (!pass) return false;
    const minLength = pass.length >= 8;
    const hasUpper = /[A-Z]/.test(pass);
    const hasLower = /[a-z]/.test(pass);
    const hasNumber = /[0-9]/.test(pass);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(pass);
    return minLength && hasUpper && hasLower && hasNumber && hasSpecial;
}

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true },
    fullName: { type: String, default: "" },
    friends: { type: [String], default: [] },
    friendRequestsSent: { type: [String], default: [] },
    friendRequestsReceived: { type: [String], default: [] },
    twoFAEnabled: { type: Boolean, default: false },
    twoFASecret: { type: String, default: "" }
});
const User = mongoose.model('User', UserSchema);

const PostSchema = new mongoose.Schema({
    username: { type: String, required: true },
    content: { type: String, default: "" },
    imageUrl: { type: String, default: "" },
    likes: { type: [String], default: [] },
    loves: { type: [String], default: [] },
    fires: { type: [String], default: [] },
    comments: { type: Array, default: [] },
    createdAt: { type: Date, default: Date.now }
});
const Post = mongoose.model('Post', PostSchema);

const CommunityMessageSchema = new mongoose.Schema({
    username: { type: String, required: true },
    text: { type: String, default: "" },
    imageUrl: { type: String, default: "" },
    createdAt: { type: Date, default: Date.now }
});
const CommunityMessage = mongoose.model('CommunityMessage', CommunityMessageSchema);

const PrivateMessageSchema = new mongoose.Schema({
    sender: { type: String, required: true },
    receiver: { type: String, required: true },
    text: { type: String, default: "" },
    createdAt: { type: Date, default: Date.now }
});
const PrivateMessage = mongoose.model('PrivateMessage', PrivateMessageSchema);

app.post('/api/signup', async (req, res) => {
    try {
        const { username, email, password, fullName } = req.body;
        if (!isStrongPassword(password)) {
            return res.status(400).json({ success: false, message: "Password must be at least 8 chars long with upper, lower, number, and special chars." });
        }
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);
        const newUser = new User({ username, email, fullName, passwordHash });
        await newUser.save();
        res.json({ success: true });
    } catch (e) { res.status(400).json({ success: false, message: e.message }); }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password, twoFACode } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ success: false, message: "User not found" });

        if (user.twoFAEnabled) {
            if (!twoFACode) return res.json({ success: false, requires2FA: true });
            const verified = speakeasy.totp.verify({ secret: user.twoFASecret, encoding: 'base32', token: twoFACode, window: 1 });
            if (!verified) return res.status(400).json({ success: false, message: "Invalid 2FA code" });
        } else {
            const isMatch = await bcrypt.compare(password, user.passwordHash);
            if (!isMatch) return res.status(400).json({ success: false, message: "Invalid password" });
        }

        res.json({ success: true, username: user.username, email: user.email, fullName: user.fullName });
    } catch (e) { res.status(400).json({ success: false, message: e.message }); }
});

app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    if (username === (process.env.ADMIN_USER || "riyad") && password === (process.env.ADMIN_PASS || "riyad1234")) {
        return res.json({ success: true });
    }
    res.status(401).json({ success: false });
});

app.get('/api/admin/users', async (req, res) => {
    const users = await User.find().select('username email twoFAEnabled createdAt');
    res.json({ success: true, users });
});

// Friend Request & Acceptance System
app.get('/api/friend-status', async (req, res) => {
    const { user1, user2 } = req.query;
    const u1 = await User.findOne({ username: user1 });
    if (!u1) return res.json({ status: "none" });
    if (u1.friends.includes(user2)) return res.json({ status: "friends" });
    if (u1.friendRequestsSent.includes(user2)) return res.json({ status: "pending_sent" });
    if (u1.friendRequestsReceived.includes(user2)) return res.json({ status: "pending_received" });
    res.json({ status: "none" });
});

app.post('/api/friend-request', async (req, res) => {
    const { sender, receiver } = req.body;
    const uSender = await User.findOne({ username: sender });
    const uReceiver = await User.findOne({ username: receiver });
    if (uSender && uReceiver && !uSender.friends.includes(receiver)) {
        if (!uSender.friendRequestsSent.includes(receiver)) uSender.friendRequestsSent.push(receiver);
        if (!uReceiver.friendRequestsReceived.includes(sender)) uReceiver.friendRequestsReceived.push(sender);
        await uSender.save();
        await uReceiver.save();
    }
    res.json({ success: true });
});

app.post('/api/friend-accept', async (req, res) => {
    const { user, friend } = req.body;
    const u = await User.findOne({ username: user });
    const f = await User.findOne({ username: friend });
    if (u && f) {
        u.friendRequestsReceived = u.friendRequestsReceived.filter(x => x !== friend);
        f.friendRequestsSent = f.friendRequestsSent.filter(x => x !== user);
        if (!u.friends.includes(friend)) u.friends.push(friend);
        if (!f.friends.includes(user)) f.friends.push(user);
        await u.save();
        await f.save();
    }
    res.json({ success: true });
});

app.get('/api/friends/:username', async (req, res) => {
    const u = await User.findOne({ username: req.params.username });
    if (!u) return res.json({ success: false, friends: [] });
    res.json({ success: true, friends: u.friends });
});

// 1-to-1 Secure Private Chat (Only sender and receiver can view)
app.get('/api/private-messages', async (req, res) => {
    const { user1, user2 } = req.query;
    const messages = await PrivateMessage.find({
        $or: [
            { sender: user1, receiver: user2 },
            { sender: user2, receiver: user1 }
        ]
    }).sort({ createdAt: 1 });
    res.json({ success: true, messages });
});

app.post('/api/private-messages', async (req, res) => {
    const { sender, receiver, text } = req.body;
    const u = await User.findOne({ username: sender });
    if (!u || !u.friends.includes(receiver)) {
        return res.status(403).json({ success: false, message: "You must be accepted friends to chat privately!" });
    }
    if (isToxicContent(text)) {
        return res.status(400).json({ success: false, message: "Message blocked by AI Security Bot." });
    }
    const pm = new PrivateMessage({ sender, receiver, text });
    await pm.save();
    res.json({ success: true });
});

// Community Chatroom API
app.get('/api/community-messages', async (req, res) => {
    const messages = await CommunityMessage.find().sort({ createdAt: 1 }).limit(100);
    res.json({ success: true, messages });
});

app.post('/api/community-messages', async (req, res) => {
    const { username, text, imageUrl } = req.body;
    if (isToxicContent(text)) {
        return res.status(400).json({ success: false, message: "Community message blocked by AI Security Bot." });
    }
    const cm = new CommunityMessage({ username, text, imageUrl });
    await cm.save();
    res.json({ success: true });
});

// AI Algorithm Feed
app.get('/api/feed/:username', async (req, res) => {
    try {
        const username = req.params.username;
        const user = await User.findOne({ username });
        const friends = user ? user.friends : [];
        const posts = await Post.find().sort({ createdAt: -1 }).limit(100).lean();
        const now = Date.now();

        posts.forEach(p => {
            const ageHours = (now - new Date(p.createdAt).getTime()) / (1000 * 60 * 60);
            const isFriend = friends.includes(p.username) ? 20 : 0;
            const engagement = ((p.likes?.length || 0) * 3) + ((p.comments?.length || 0) * 4);
            const decay = Math.max(0, 72 - ageHours) * 1.5;
            p.feedScore = isFriend + engagement + decay;
        });

        posts.sort((a, b) => b.feedScore - a.feedScore);
        res.json(posts);
    } catch (e) { res.json([]); }
});

app.post('/api/posts', async (req, res) => {
    try {
        const { username, content, imageUrl } = req.body;
        if (isToxicContent(content)) {
            return res.status(400).json({ success: false, message: "⚠️ Post rejected by AI Security Bot: Contains toxic or prohibited content!" });
        }
        const np = new Post({ username, content, imageUrl });
        await np.save();
        res.json({ success: true });
    } catch (e) { res.status(400).json({ success: false, message: e.message }); }
});

app.post('/api/posts/:id/react', async (req, res) => {
    const { username, type } = req.body;
    const post = await Post.findById(req.params.id);
    if (post) {
        if (type === 'like' && !post.likes.includes(username)) post.likes.push(username);
        if (type === 'love' && !post.loves.includes(username)) post.loves.push(username);
        if (type === 'fire' && !post.fires.includes(username)) post.fires.push(username);
        await post.save();
    }
    res.json({ success: true });
});

app.post('/api/posts/:id/comment', async (req, res) => {
    const { username, text } = req.body;
    if (isToxicContent(text)) return res.status(400).json({ success: false, message: "Comment blocked by AI Filter." });
    const post = await Post.findById(req.params.id);
    if (post) {
        post.comments.push({ username, text, createdAt: new Date() });
        await post.save();
    }
    res.json({ success: true });
});

app.post('/api/posts/:id/share', async (req, res) => {
    const { username } = req.body;
    const post = await Post.findById(req.params.id);
    if (post) {
        const sharedPost = new Post({ username, content: `🔁 Shared from @${post.username}: "${post.content}"`, imageUrl: post.imageUrl });
        await sharedPost.save();
    }
    res.json({ success: true });
});

app.get('/api/user-posts/:username', async (req, res) => {
    const posts = await Post.find({ username: req.params.username }).sort({ createdAt: -1 });
    res.json(posts);
});

app.get('/api/user/:email', async (req, res) => {
    const u = await User.findOne({ email: req.params.email });
    if (!u) return res.status(404).json({ success: false });
    res.json({ success: true, user: { username: u.username, email: u.email, twoFAEnabled: u.twoFAEnabled } });
});

app.post('/api/2fa/setup', async (req, res) => {
    if (!speakeasy || !QRCode) return res.status(500).json({ success: false });
    const u = await User.findOne({ email: req.body.email });
    const secret = speakeasy.generateSecret({ name: `Searchbook (${u.username})` });
    u.twoFASecret = secret.base32;
    await u.save();
    const qrCode = await QRCode.toDataURL(secret.otpauth_url);
    res.json({ success: true, qrCode });
});

app.post('/api/2fa/verify', async (req, res) => {
    const u = await User.findOne({ email: req.body.email });
    const verified = speakeasy.totp.verify({ secret: u.twoFASecret, encoding: 'base32', token: req.body.code, window: 1 });
    if (!verified) return res.status(400).json({ success: false });
    u.twoFAEnabled = true;
    await u.save();
    res.json({ success: true });
});

app.put('/api/user/change-password', async (req, res) => {
    const { email, oldPassword, newPassword } = req.body;
    if (!isStrongPassword(newPassword)) {
        return res.status(400).json({ success: false, message: "New password must be strong." });
    }
    const u = await User.findOne({ email });
    const m = await bcrypt.compare(oldPassword, u.passwordHash);
    if (!m) return res.status(400).json({ success: false, message: "Incorrect current password" });
    const salt = await bcrypt.genSalt(10);
    u.passwordHash = await bcrypt.hash(newPassword, salt);
    await u.save();
    res.json({ success: true });
});

app.use((req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

app.listen(PORT, () => console.log(`Server running on ${PORT}`));

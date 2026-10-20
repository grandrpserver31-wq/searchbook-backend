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

const toxicKeywords = [
    "badword1", "badword2", "terrorist", "hackingscript", "spamattack", "abuse",
    "sex", "fuck", "porn", "nude", "naked", "xxx", "adult", "violence", "suicide",
    "kill", "murder", "blood", "rape", "hate", "scam"
];

function isToxicContent(text) {
    if (!text) return false;
    const lower = text.toLowerCase();
    return toxicKeywords.some(word => lower.includes(word));
}

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
    twoFASecret: { type: String, default: "" },
    lastActive: { type: Date, default: Date.now },
    strikes: { type: Number, default: 0 },
    banUntil: { type: Date, default: null },
    isPermanentBanned: { type: Boolean, default: false },
    lastIp: { type: String, default: "" }
});
const User = mongoose.model('User', UserSchema);

const BannedIPSchema = new mongoose.Schema({
    ip: { type: String, required: true, unique: true },
    createdAt: { type: Date, default: Date.now }
});
const BannedIP = mongoose.model('BannedIP', BannedIPSchema);

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

const ReportSchema = new mongoose.Schema({
    postId: { type: String, required: true },
    author: { type: String, required: true },
    reporter: { type: String, required: true },
    reason: { type: String, required: true },
    status: { type: String, default: "pending" },
    createdAt: { type: Date, default: Date.now }
});
const Report = mongoose.model('Report', ReportSchema);

const ComplaintSchema = new mongoose.Schema({
    username: { type: String, required: true },
    message: { type: String, required: true },
    status: { type: String, default: "pending" },
    createdAt: { type: Date, default: Date.now }
});
const Complaint = mongoose.model('Complaint', ComplaintSchema);

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

// Auto-check expiration of ban/mute
async function checkUserStatus(user) {
    if (user.banUntil && user.banUntil <= new Date()) {
        user.banUntil = null;
        if (user.strikes === 2 || user.strikes === 3) {
            user.strikes = 0; // Reset strikes after period completion
        }
        await user.save();
    }
}

app.post('/api/ping', async (req, res) => {
    const { username } = req.body;
    if (username) {
        const u = await User.findOne({ username });
        if (u) {
            await checkUserStatus(u);
            u.lastActive = new Date();
            await u.save();
        }
    }
    res.json({ success: true });
});

app.get('/api/active-users', async (req, res) => {
    try {
        const threshold = new Date(Date.now() - 45000);
        const activeUsers = await User.find({ lastActive: { $gte: threshold } }).select('username');
        res.json({ success: true, users: activeUsers.map(u => u.username) });
    } catch (e) { res.json({ success: false, users: [] }); }
});

app.post('/api/signup', async (req, res) => {
    try {
        const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || "unknown";
        const checkIpBan = await BannedIP.findOne({ ip: clientIp });
        if (checkIpBan) {
            return res.status(403).json({ success: false, message: "Registration blocked. Your IP address has been permanently banned." });
        }

        const { username, email, password, fullName } = req.body;
        if (!isStrongPassword(password)) {
            return res.status(400).json({ success: false, message: "Password must be strong." });
        }
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);
        const newUser = new User({ username, email, fullName, passwordHash, lastIp: clientIp });
        await newUser.save();
        res.json({ success: true });
    } catch (e) { res.status(400).json({ success: false, message: e.message }); }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password, twoFACode } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ success: false, message: "User not found" });

        await checkUserStatus(user);

        if (user.isPermanentBanned) {
            return res.json({ success: false, banned: true, message: "Your account is permanently banned. You cannot access Searchbook." });
        }

        if (user.banUntil && user.banUntil > new Date() && user.strikes >= 3) {
            const daysLeft = Math.ceil((user.banUntil - new Date()) / (1000 * 60 * 60 * 24));
            return res.json({ success: false, banned: true, message: `Your account is suspended for ${daysLeft} days.` });
        }

        if (user.twoFAEnabled) {
            if (!twoFACode) return res.json({ success: false, requires2FA: true });
            const verified = speakeasy.totp.verify({ secret: user.twoFASecret, encoding: 'base32', token: twoFACode, window: 1 });
            if (!verified) return res.status(400).json({ success: false, message: "Invalid 2FA code" });
        } else {
            const isMatch = await bcrypt.compare(password, user.passwordHash);
            if (!isMatch) return res.status(400).json({ success: false, message: "Invalid password" });
        }

        user.lastActive = new Date();
        user.lastIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || "";
        await user.save();
        res.json({ success: true, username: user.username, email: user.email, fullName: user.fullName });
    } catch (e) { res.status(400).json({ success: false, message: e.message }); }
});

// Admin Login Route
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const AdminModel = mongoose.connection.collection('admins');
        const adminUser = await AdminModel.findOne({ username: username });
        
        if (!adminUser) {
            return res.status(401).json({ success: false, message: "Invalid admin username" });
        }

        let storedHash = adminUser.passwordHash;
        if (storedHash && (storedHash.startsWith('$2y$') || storedHash.startsWith('$2a$'))) {
            storedHash = '$2b$' + storedHash.substring(4);
        }

        const isMatch = await bcrypt.compare(password, storedHash);
        if (!isMatch) {
            return res.status(401).json({ success: false, message: "Invalid admin password" });
        }

        await AdminModel.updateOne({ username: username }, { $set: { lastLogin: new Date() } });
        res.json({ success: true, message: "Admin login successful" });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

app.get('/api/admin/users', async (req, res) => {
    const users = await User.find().select('username email twoFAEnabled strikes banUntil isPermanentBanned createdAt');
    res.json({ success: true, users });
});

app.get('/api/admin/reports', async (req, res) => {
    const reports = await Report.find({ status: "pending" }).sort({ createdAt: -1 });
    res.json({ success: true, reports: reports.map(r => ({ reportId: r._id, postId: r.postId, author: r.author, reporter: r.reporter, reason: r.reason })) });
});

app.get('/api/admin/complaints', async (req, res) => {
    const complaints = await Complaint.find({ status: "pending" }).sort({ createdAt: -1 });
    res.json({ success: true, complaints });
});

app.post('/api/admin/resolve-complaint', async (req, res) => {
    const { complaintId } = req.body;
    await Complaint.findByIdAndUpdate(complaintId, { status: "resolved" });
    res.json({ success: true });
});

app.post('/api/admin/issue-strike', async (req, res) => {
    const { username, reportId } = req.body;
    const author = await User.findOne({ username });
    if (author) {
        author.strikes = (author.strikes || 0) + 1;
        
        if (author.strikes === 2) {
            author.banUntil = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days mute for posts/community
        } else if (author.strikes === 3) {
            author.banUntil = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days full ban
        } else if (author.strikes >= 4) {
            author.isPermanentBanned = true;
            if (author.lastIp) {
                await BannedIP.updateOne({ ip: author.lastIp }, { ip: author.lastIp }, { upsert: true });
            }
        }
        await author.save();
    }
    if (reportId) {
        await Report.findByIdAndUpdate(reportId, { status: "resolved" });
    }
    res.json({ success: true });
});

app.post('/api/admin/dismiss-report', async (req, res) => {
    const { reportId } = req.body;
    await Report.findByIdAndUpdate(reportId, { status: "dismissed" });
    res.json({ success: true });
});

app.post('/api/admin/reset-strike', async (req, res) => {
    const { username } = req.body;
    const u = await User.findOneAndUpdate({ username }, { strikes: 0, banUntil: null, isPermanentBanned: false });
    if (u && u.lastIp) {
        await BannedIP.deleteOne({ ip: u.lastIp });
    }
    res.json({ success: true });
});

// User account deletion
app.delete('/api/user/delete', async (req, res) => {
    const { email, password } = req.body;
    const u = await User.findOne({ email });
    if (!u) return res.status(404).json({ success: false, message: "User not found" });
    const isMatch = await bcrypt.compare(password, u.passwordHash);
    if (!isMatch) return res.status(400).json({ success: false, message: "Incorrect password" });
    await User.deleteOne({ email });
    await Post.deleteMany({ username: u.username });
    res.json({ success: true });
});

// Complaints submission with username & password verification
app.post('/api/complaints', async (req, res) => {
    const { username, password, message } = req.body;
    const u = await User.findOne({ username });
    if (!u) return res.status(400).json({ success: false, message: "Invalid username" });
    const isMatch = await bcrypt.compare(password, u.passwordHash);
    if (!isMatch) return res.status(400).json({ success: false, message: "Invalid password" });

    const comp = new Complaint({ username, message });
    await comp.save();
    res.json({ success: true });
});

app.post('/api/report-post', async (req, res) => {
    const { postId, reporter, reason } = req.body;
    const post = await Post.findById(postId);
    if (post) {
        const newReport = new Report({ postId, author: post.username, reporter, reason });
        await newReport.save();
    }
    res.json({ success: true });
});

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
    if (u) await checkUserStatus(u);
    if (u && (u.isPermanentBanned || (u.banUntil && u.banUntil > new Date() && u.strikes >= 3))) {
        return res.status(403).json({ success: false, message: "Your account is banned." });
    }
    if (!u || !u.friends.includes(receiver)) {
        return res.status(403).json({ success: false, message: "You must be accepted friends to chat privately!" });
    }
    if (isToxicContent(text)) {
        return res.status(400).json({ success: false, message: "⚠️ Message blocked by AI Safety Bot!" });
    }
    const pm = new PrivateMessage({ sender, receiver, text });
    await pm.save();
    res.json({ success: true });
});

app.get('/api/community-messages', async (req, res) => {
    const messages = await CommunityMessage.find().sort({ createdAt: 1 }).limit(100);
    res.json({ success: true, messages });
});

app.post('/api/community-messages', async (req, res) => {
    const { username, text, imageUrl } = req.body;
    const u = await User.findOne({ username });
    if (u) await checkUserStatus(u);
    if (u && (u.isPermanentBanned || (u.banUntil && u.banUntil > new Date()))) {
        return res.status(403).json({ success: false, message: "Account is muted or banned." });
    }
    if (isToxicContent(text)) {
        return res.status(400).json({ success: false, message: "⚠️ Message blocked by AI Safety Bot!" });
    }
    const cm = new CommunityMessage({ username, text, imageUrl });
    await cm.save();
    res.json({ success: true });
});

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
        const u = await User.findOne({ username });
        if (u) await checkUserStatus(u);
        if (u && (u.isPermanentBanned || (u.banUntil && u.banUntil > new Date()))) {
            return res.status(403).json({ success: false, message: "Account is muted or banned. Cannot post." });
        }
        if (isToxicContent(content)) {
            return res.status(400).json({ success: false, message: "⚠️ Post rejected by AI Safety Bot!" });
        }
        const np = new Post({ username, content, imageUrl });
        await np.save();
        res.json({ success: true });
    } catch (e) { res.status(400).json({ success: false, message: e.message }); }
});

app.delete('/api/posts/:id', async (req, res) => {
    try {
        const { username } = req.body;
        const post = await Post.findById(req.params.id);
        if (!post) return res.status(404).json({ success: false, message: "Post not found" });
        if (post.username !== username) return res.status(403).json({ success: false, message: "Unauthorized" });
        await Post.findByIdAndDelete(req.params.id);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
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
    if (isToxicContent(text)) return res.status(400).json({ success: false, message: "⚠️ Comment blocked by AI Safety Bot!" });
    const post = await Post.findById(req.params.id);
    if (post) {
        post.comments.push({ username, text, createdAt: new Date() });
        await post.save();
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

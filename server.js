const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.static(__dirname));
app.use(express.json({ limit: '50mb' }));
app.use(cors());

const MONGO_URI = "mongodb+srv://grandrpserver31_db_user:Tx8SpBrESEEbb0wr@cluster0.rstum6r.mongodb.net/searchbookDB?appName=Cluster00";

mongoose.connect(MONGO_URI)
    .then(() => console.log("SearchBook MongoDB Connected!"))
    .catch(err => console.error("DB Error:", err));

// ==========================================
// ACTIVE USERS TRACKER (memory te)
// ==========================================
const activeUsers = {}; // { username: lastActiveTimestamp }

// Protti request e active update
app.use((req, res, next) => {
    const username = req.headers['x-username'];
    if (username) {
        activeUsers[username] = Date.now();
    }
    next();
});

// Auto cleanup — 2 minute por inactive
setInterval(() => {
    const now = Date.now();
    for (const u in activeUsers) {
        if (now - activeUsers[u] > 2 * 60 * 1000) { // 2 min
            delete activeUsers[u];
        }
    }
}, 60000);

// ==========================================
// OTP Store
// ==========================================
const otpStore = {};

app.post('/api/send-otp', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ success: false, message: "Email dorkar!" });

        const otp = Math.floor(100000 + Math.random() * 900000);
        otpStore[email] = { otp, expiresAt: Date.now() + 60 * 1000 };

        setTimeout(() => {
            if (otpStore[email] && Date.now() >= otpStore[email].expiresAt) {
                delete otpStore[email];
            }
        }, 61000);

        res.json({ success: true, message: "OTP generated", otp });
    } catch (error) {
        res.status(500).json({ success: false, message: "OTP failed" });
    }
});

app.post('/api/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;
        const stored = otpStore[email];

        if (!stored) return res.status(400).json({ success: false, message: "OTP expire" });
        if (Date.now() > stored.expiresAt) {
            delete otpStore[email];
            return res.status(400).json({ success: false, message: "OTP expire" });
        }
        if (stored.otp != otp) return res.status(400).json({ success: false, message: "Bhul OTP" });

        delete otpStore[email];
        res.json({ success: true, message: "OTP verified" });
    } catch (error) {
        res.status(500).json({ success: false, message: "Verify failed" });
    }
});

// ==========================================
// SCHEMAS
// ==========================================
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true },
    fullName: { type: String, default: "" },
    bio: { type: String, default: "" },
    profilePic: { type: String, default: "" },
    followers: { type: [String], default: [] },
    following: { type: [String], default: [] },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

const PostSchema = new mongoose.Schema({
    username: { type: String, required: true },
    content: { type: String, default: "" },
    media: { type: String, default: "" },
    mediaType: { type: String, default: "text" },
    likes: { type: [String], default: [] },
    comments: { type: Array, default: [] },
    shares: { type: Number, default: 0 },
    views: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
});
const Post = mongoose.model('Post', PostSchema);

// ==========================================
// CHAT SCHEMAS
// ==========================================
const RoomSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },  // Dui user er username sorted + '_'
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

// ==========================================
// AUTH APIs
// ==========================================
app.post('/api/signup', async (req, res) => {
    try {
        const { username, email, password, fullName } = req.body;
        if (!username || !email || !password) return res.status(400).json({ success: false, message: "Sob field din" });

        const existing = await User.findOne({ $or: [{ email }, { username }] });
        if (existing) return res.status(400).json({ success: false, message: "Email/username ache" });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({
            username, email,
            fullName: fullName || username,
            passwordHash: hashedPassword
        });

        await newUser.save();
        res.status(201).json({ success: true, message: "Account created!" });
    } catch (err) {
        res.status(500).json({ success: false, message: "Signup failed" });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ success: false, message: "User nai!" });

        const isMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isMatch) return res.status(400).json({ success: false, message: "Bhul password!" });

        // Active mark korun
        activeUsers[user.username] = Date.now();

        res.json({
            success: true,
            username: user.username,
            email: user.email,
            fullName: user.fullName
        });
    } catch (err) {
        res.status(500).json({ success: false, message: "Login failed" });
    }
});

// Logout — active theke bad
app.post('/api/logout', (req, res) => {
    const { username } = req.body;
    if (username) delete activeUsers[username];
    res.json({ success: true });
});

// Heartbeat — user active ache bole janay
app.post('/api/heartbeat', (req, res) => {
    const { username } = req.body;
    if (username) activeUsers[username] = Date.now();
    res.json({ success: true });
});

// ==========================================
// ACTIVE USER APIs
// ==========================================
app.get('/api/active-users', (req, res) => {
    const now = Date.now();
    const activeList = Object.keys(activeUsers).filter(u => now - activeUsers[u] < 2 * 60 * 1000);
    res.json({ success: true, count: activeList.length, users: activeList });
});

// ==========================================
// USER APIs
// ==========================================
app.get('/api/user/:email', async (req, res) => {
    try {
        const user = await User.findOne({ email: req.params.email });
        if (!user) return res.status(404).json({ success: false, message: "User nai" });

        const now = Date.now();
        const isActive = activeUsers[user.username] && (now - activeUsers[user.username] < 2 * 60 * 1000);

        res.json({
            success: true,
            user: {
                username: user.username,
                email: user.email,
                fullName: user.fullName || user.username,
                bio: user.bio || "",
                profilePic: user.profilePic || "",
                followers: user.followers || [],
                following: user.following || [],
                isActive: !!isActive,
                createdAt: user.createdAt
            }
        });
    } catch (err) {
        res.status(500).json({ success: false, message: "Failed" });
    }
});

app.get('/api/user/username/:username', async (req, res) => {
    try {
        const user = await User.findOne({ username: req.params.username });
        if (!user) return res.status(404).json({ success: false, message: "User nai" });

        const now = Date.now();
        const isActive = activeUsers[user.username] && (now - activeUsers[user.username] < 2 * 60 * 1000);

        res.json({
            success: true,
            user: {
                username: user.username,
                fullName: user.fullName || user.username,
                bio: user.bio || "",
                profilePic: user.profilePic || "",
                followers: user.followers || [],
                following: user.following || [],
                isActive: !!isActive,
                createdAt: user.createdAt
            }
        });
    } catch (err) {
        res.status(500).json({ success: false, message: "Failed" });
    }
});

// Search users (active status shoho)
app.get('/api/search/users/:query', async (req, res) => {
    try {
        const query = req.params.query;
        const users = await User.find({
            $or: [
                { username: { $regex: query, $options: 'i' } },
                { fullName: { $regex: query, $options: 'i' } }
            ]
        }).limit(20).select('username fullName profilePic bio');

        const now = Date.now();
        const usersWithStatus = users.map(u => ({
            username: u.username,
            fullName: u.fullName,
            profilePic: u.profilePic,
            bio: u.bio,
            isActive: !!(activeUsers[u.username] && (now - activeUsers[u.username] < 2 * 60 * 1000))
        }));

        res.json({ success: true, users: usersWithStatus });
    } catch (err) {
        res.status(500).json({ success: false, message: "Search failed" });
    }
});

app.put('/api/user/profile', async (req, res) => {
    try {
        const { email, profilePic, bio, fullName } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ success: false, message: "User nai" });

        if (profilePic !== undefined) user.profilePic = profilePic;
        if (bio !== undefined) user.bio = bio;
        if (fullName !== undefined) user.fullName = fullName;

        await user.save();
        res.json({ success: true, message: "Profile updated!" });
    } catch (err) {
        res.status(500).json({ success: false, message: "Update failed" });
    }
});

app.put('/api/user/change-password', async (req, res) => {
    try {
        const { email, oldPassword, newPassword } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ success: false, message: "User nai" });

        const isMatch = await bcrypt.compare(oldPassword, user.passwordHash);
        if (!isMatch) return res.status(400).json({ success: false, message: "Purono password bhul" });

        if (newPassword.length < 6) return res.status(400).json({ success: false, message: "Min 6 char" });

        const salt = await bcrypt.genSalt(10);
        user.passwordHash = await bcrypt.hash(newPassword, salt);

        await user.save();
        res.json({ success: true, message: "Password changed!" });
    } catch (err) {
        res.status(500).json({ success: false, message: "Failed" });
    }
});

app.post('/api/user/follow', async (req, res) => {
    try {
        const { follower, following } = req.body;
        if (follower === following) return res.status(400).json({ success: false, message: "Nijer ke follow korte parben na" });

        await User.updateOne({ username: follower }, { $addToSet: { following } });
        await User.updateOne({ username: following }, { $addToSet: { followers: follower } });

        res.json({ success: true, message: "Followed!" });
    } catch (err) {
        res.status(500).json({ success: false, message: "Failed" });
    }
});

app.post('/api/user/unfollow', async (req, res) => {
    try {
        const { follower, following } = req.body;
        await User.updateOne({ username: follower }, { $pull: { following } });
        await User.updateOne({ username: following }, { $pull: { followers: follower } });
        res.json({ success: true, message: "Unfollowed!" });
    } catch (err) {
        res.status(500).json({ success: false, message: "Failed" });
    }
});

// ==========================================
// POST APIs (Algorithm)
// ==========================================
app.post('/api/posts', async (req, res) => {
    try {
        const { username, content, media, mediaType } = req.body;
        const newPost = new Post({
            username,
            content: content || "",
            media: media || "",
            mediaType: mediaType || "text"
        });
        await newPost.save();
        res.status(201).json({ success: true, message: "Post created!" });
    } catch (err) {
        res.status(500).json({ success: false, message: "Post failed" });
    }
});

app.get('/api/posts', async (req, res) => {
    try {
        const posts = await Post.find().limit(100).lean();
        const now = Date.now();
        posts.forEach(p => {
            const ageInHours = (now - new Date(p.createdAt).getTime()) / (1000 * 60 * 60);
            const likeScore = (p.likes?.length || 0) * 3;
            const commentScore = (p.comments?.length || 0) * 4;
            const shareScore = (p.shares || 0) * 5;
            const viewScore = (p.views || 0) * 0.5;
            const timeScore = Math.max(0, 24 - ageInHours) * 2;
            p.score = likeScore + commentScore + shareScore + viewScore + timeScore;
        });
        posts.sort((a, b) => b.score - a.score);
        res.json(posts.slice(0, 50));
    } catch (err) {
        res.status(500).json({ success: false, message: "Load failed" });
    }
});

app.get('/api/posts/user/:username', async (req, res) => {
    try {
        const posts = await Post.find({ username: req.params.username }).sort({ createdAt: -1 });
        res.json(posts);
    } catch (err) {
        res.status(500).json({ success: false, message: "Load failed" });
    }
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
        res.json({ success: true, likes: post.likes.length });
    } catch (err) {
        res.status(500).json({ success: false, message: "Failed" });
    }
});

app.post('/api/posts/comment', async (req, res) => {
    try {
        const { postId, username, text } = req.body;
        const post = await Post.findById(postId);
        if (!post) return res.status(404).json({ success: false, message: "Post nai" });

        post.comments.push({ username, text, createdAt: new Date() });
        await post.save();
        res.json({ success: true, comments: post.comments });
    } catch (err) {
        res.status(500).json({ success: false, message: "Failed" });
    }
});

app.post('/api/posts/share', async (req, res) => {
    try {
        const { postId } = req.body;
        const post = await Post.findById(postId);
        if (!post) return res.status(404).json({ success: false, message: "Post nai" });

        post.shares = (post.shares || 0) + 1;
        await post.save();
        res.json({ success: true, shares: post.shares });
    } catch (err) {
        res.status(500).json({ success: false, message: "Failed" });
    }
});

app.post('/api/posts/view', async (req, res) => {
    try {
        const { postId } = req.body;
        await Post.findByIdAndUpdate(postId, { $inc: { views: 1 } });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: "Failed" });
    }
});

// ==========================================
// CHAT APIs
// ==========================================

// Room create ba get
app.post('/api/chat/room', async (req, res) => {
    try {
        const { user1, user2 } = req.body;
        if (!user1 || !user2) return res.status(400).json({ success: false, message: "Dui user din" });

        // Room name — username sorted (jate same room hoy)
        const roomName = [user1, user2].sort().join('_');

        let room = await Room.findOne({ name: roomName });
        if (!room) {
            room = new Room({
                name: roomName,
                members: [user1, user2]
            });
            await room.save();
        }

        res.json({ success: true, room });
    } catch (err) {
        res.status(500).json({ success: false, message: "Room create failed" });
    }
});

// User er sob chat room
app.get('/api/chat/rooms/:username', async (req, res) => {
    try {
        const rooms = await Room.find({ members: req.params.username })
            .sort({ lastTime: -1 });
        res.json({ success: true, rooms });
    } catch (err) {
        res.status(500).json({ success: false, message: "Load failed" });
    }
});

// Message send
app.post('/api/chat/message', async (req, res) => {
    try {
        const { roomId, sender, text } = req.body;
        if (!roomId || !sender || !text) return res.status(400).json({ success: false, message: "Sob field din" });

        const msg = new Message({ roomId, sender, text });
        await msg.save();

        // Room er last message update
        await Room.findByIdAndUpdate(roomId, {
            lastMessage: text.substring(0, 50),
            lastTime: new Date()
        });

        res.json({ success: true, message: msg });
    } catch (err) {
        res.status(500).json({ success: false, message: "Send failed" });
    }
});

// Message load
app.get('/api/chat/messages/:roomId', async (req, res) => {
    try {
        const msgs = await Message.find({ roomId: req.params.roomId })
            .sort({ createdAt: 1 })
            .limit(200);
        res.json({ success: true, messages: msgs });
    } catch (err) {
        res.status(500).json({ success: false, message: "Load failed" });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`SearchBook running on port ${PORT}`));

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.json());
app.use(cors());

// SearchBook Cloud Database Link
const MONGO_URI = "mongodb+srv://searchbookuser:searchbook123@cluster0.rstum6r.mongodb.net/searchbookDB?appName=Cluster0";

mongoose.connect(MONGO_URI)
    .then(() => console.log("SearchBook MongoDB Atlas Connected Successfully!"))
    .catch(err => console.error("Database Connection Error:", err));

// 1. User Schema
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

// 2. Post Schema
const PostSchema = new mongoose.Schema({
    username: { type: String, required: true },
    content: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});
const Post = mongoose.model('Post', PostSchema);

// --- API Routes ---
app.post('/api/signup', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({ username, email, passwordHash: hashedPassword });
        await newUser.save();
        res.status(201).json({ success: true, message: "SearchBook-এ অ্যাকাউন্ট তৈরি সফল হয়েছে!" });
    } catch (err) {
        res.status(500).json({ success: false, message: "অ্যাকাউন্ট তৈরি করা যায়নি।" });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ success: false, message: "ইউজার পাওয়া যায়নি!" });

        const isMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isMatch) return res.status(400).json({ success: false, message: "ভুল পাসওয়ার্ড!" });

        res.json({ success: true, message: "লগইন সফল হয়েছে!", username: user.username });
    } catch (err) {
        res.status(500).json({ success: false, message: "লগইন করা যায়নি।" });
    }
});

app.post('/api/posts', async (req, res) => {
    try {
        const { username, content } = req.body;
        const newPost = new Post({ username, content });
        await newPost.save();
        res.status(201).json({ success: true, message: "পোস্ট পাবলিক হয়েছে!" });
    } catch (err) {
        res.status(500).json({ success: false, message: "পোস্ট করা যায়নি।" });
    }
});

app.get('/api/posts', async (req, res) => {
    try {
        const posts = await Post.find().sort({ createdAt: -1 });
        res.json(posts);
    } catch (err) {
        res.status(500).json({ success: false, message: "পোস্ট লোড করা যায়নি।" });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`SearchBook Backend running on port ${PORT}`));
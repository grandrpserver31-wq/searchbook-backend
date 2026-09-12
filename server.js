const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.static(__dirname));
app.use(express.json());
app.use(cors());

const MONGO_URI = "mongodb+srv://grandrpserver31_db_user:Tx8SpBrESEEbb0wr@cluster0.rstum6r.mongodb.net/searchbookDB?appName=Cluster00";

mongoose.connect(MONGO_URI)
    .then(() => console.log("SearchBook MongoDB Atlas Connected Successfully!"))
    .catch(err => console.error("Database Connection Error:", err));

// ==========================================
// OTP STORE (1 minute expire)
// ==========================================
const otpStore = {};

// ==========================================
// SEND OTP API (Email pathabe na, shudhu generate korbe)
// ==========================================
app.post('/api/send-otp', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ success: false, message: "Email dorkar!" });
        }

        // 6 digit OTP generate
        const otp = Math.floor(100000 + Math.random() * 900000);

        // Server memory te save (1 minute expire)
        otpStore[email] = {
            otp: otp,
            expiresAt: Date.now() + 60 * 1000
        };

        console.log(`OTP generated for ${email}: ${otp} (expires in 1 min)`);

        // 1 minute por auto delete
        setTimeout(() => {
            if (otpStore[email] && Date.now() >= otpStore[email].expiresAt) {
                delete otpStore[email];
                console.log(`OTP expired & deleted for ${email}`);
            }
        }, 61 * 1000);

        // OTP ta response e pathacchi (browser e dekhacche)
        res.status(200).json({
            success: true,
            message: "OTP generated successfully",
            otp: otp  // <-- Browser e dekhacche (1 min expire)
        });

    } catch (error) {
        console.error("OTP generate failed:", error.message);
        res.status(500).json({ success: false, message: "OTP generate korte problem hoyeche" });
    }
});

// ==========================================
// VERIFY OTP API
// ==========================================
app.post('/api/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;

        const stored = otpStore[email];

        if (!stored) {
            return res.status(400).json({ success: false, message: "OTP expire hoye geche. Abar pathan." });
        }

        if (Date.now() > stored.expiresAt) {
            delete otpStore[email];
            return res.status(400).json({ success: false, message: "OTP expire hoye geche. Abar pathan." });
        }

        if (stored.otp != otp) {
            return res.status(400).json({ success: false, message: "Bhul OTP!" });
        }

        // OTP thik — muche fellun
        delete otpStore[email];
        res.status(200).json({ success: true, message: "OTP verified successfully!" });

    } catch (error) {
        res.status(500).json({ success: false, message: "OTP verify korte problem hoyeche" });
    }
});

// ==========================================
// SCHEMAS
// ==========================================
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

const PostSchema = new mongoose.Schema({
    username: { type: String, required: true },
    content: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});
const Post = mongoose.model('Post', PostSchema);

// ==========================================
// SIGNUP API
// ==========================================
app.post('/api/signup', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ success: false, message: "Sob field puron korun" });
        }

        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.status(400).json({ success: false, message: "Ei email/username age theke ache" });
        }

        // Password hash korun (hacker dekhbe na)
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({
            username,
            email,
            passwordHash: hashedPassword
        });

        await newUser.save();
        res.status(201).json({ success: true, message: "Account created successfully!" });

    } catch (err) {
        res.status(500).json({ success: false, message: "Account create korte problem hoyeche" });
    }
});

// ==========================================
// LOGIN API
// ==========================================
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ success: false, message: "ইউজার পাওয়া যায়নি!" });

        const isMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isMatch) return res.status(400).json({ success: false, message: "ভুল পাসওয়ার্ড!" });

        res.json({ success: true, message: "লগইন সফল হয়েছে!", username: user.username });
    } catch (err) {
        res.status(500).json({ success: false, message: "লগইন করা যায়নি।" });
    }
});

// ==========================================
// POSTS API
// ==========================================
app.post('/api/posts', async (req, res) => {
    try {
        const { username, content } = req.body;
        const newPost = new Post({ username, content });
        await newPost.save();
        res.status(201).json({ success: true, message: "পোস্ট পাবলিক হয়েছে!" });
    } catch (err) {
        res.status(500).json({ success: false, message: "পোস্ট করা যায়নি।" });
    }
});

app.get('/api/posts', async (req, res) => {
    try {
        const posts = await Post.find().sort({ createdAt: -1 });
        res.json(posts);
    } catch (err) {
        res.status(500).json({ success: false, message: "পোস্ট লোড করা যায়নি।" });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`SearchBook Backend running on port ${PORT}`));
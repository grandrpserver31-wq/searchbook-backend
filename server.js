const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.static(__dirname));
app.use(express.json());
app.use(cors());

// SearchBook Cloud Database Link
const MONGO_URI = "mongodb+srv://grandrpserver31_db_user:Tx8SpBrESEEbb0wr@cluster0.rstum6r.mongodb.net/searchbookDB?appName=Cluster00";

mongoose.connect(MONGO_URI)
    .then(() => console.log("SearchBook MongoDB Atlas Connected Successfully!"))
    .catch(err => console.error("Database Connection Error:", err));

// ==========================================
// NODEMAILER SETUP (Gmail - Port 465 SSL)
// ==========================================
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS
    }
});

// Verify transporter on startup
transporter.verify((error, success) => {
    if (error) {
        console.error("Nodemailer verification FAILED:", error.message);
    } else {
        console.log("Nodemailer is ready to send emails!");
    }
});

// ==========================================
// OTP SEND API
// ==========================================
app.post('/api/send-otp', async (req, res) => {
    try {
        const { email, name } = req.body;

        if (!email) {
            return res.status(400).json({ success: false, message: "Email dorkar!" });
        }

        const otp = Math.floor(100000 + Math.random() * 900000);

        const mailOptions = {
            from: `"Searchbook" <${process.env.GMAIL_USER}>`,
            to: email,
            subject: 'Your Searchbook Verification Code',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 500px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
                    <h2 style="color: #1877f2; text-align: center;">Searchbook</h2>
                    <p>Hi ${name || 'User'},</p>
                    <p>Your verification code is:</p>
                    <h1 style="color: #1877f2; letter-spacing: 8px; text-align: center;">${otp}</h1>
                    <p>Please enter this code to complete your registration.</p>
                    <p style="color: #666; font-size: 12px;">If you didn't request this, ignore this email.</p>
                    <p>Thank you,<br>Searchbook Team</p>
                </div>
            `
        };

        await transporter.sendMail(mailOptions);
        console.log(`OTP sent to ${email}: ${otp}`);

        res.status(200).json({
            success: true,
            message: "OTP sent successfully to " + email,
            otp: otp
        });

    } catch (error) {
        console.error("Email sending failed:", error.message);
        res.status(500).json({
            success: false,
            message: "Failed to send OTP",
            error: error.message
        });
    }
});

// ==========================================
// USER SCHEMA
// ==========================================
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

// ==========================================
// POST SCHEMA
// ==========================================
const PostSchema = new mongoose.Schema({
    username: { type: String, required: true },
    content: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});
const Post = mongoose.model('Post', PostSchema);

// ==========================================
// API ROUTES
// ==========================================
app.post('/api/signup', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({ username, email, passwordHash: hashedPassword });
        await newUser.save();
        res.status(201).json({ success: true, message: "SearchBook-এ অ্যাকাউন্ট তৈরি সফল হয়েছে!" });
    } catch (err) {
        res.status(500).json({ success: false, message: "অ্যাকাউন্ট তৈরি করা যায়নি।" });
    }
});

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

// ==========================================
// SERVER START
// ==========================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`SearchBook Backend running on port ${PORT}`));
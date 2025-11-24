import express from 'express';
import http from 'http';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import { Server } from 'socket.io';
import { nanoid } from 'nanoid';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import path from 'path';
import { fileURLToPath } from 'url';
import cors from 'cors';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

// --- CORS FIX FOR MOBILE ---
app.use(cors({
    origin: '*', // Development ke liye sab allow kar rahe hain
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
}));

const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*" } // Socket ke liye bhi CORS allow kiya
});
const JWT_SECRET = 'your-very-secret-key-12345';

// --- DATABASE CONNECTION ---
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB Connected!'))
  .catch(err => console.error('❌ DB Error:', err));

// --- SCHEMAS ---
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    displayName: { type: String, default: "" },
    avatarUrl: { type: String, default: "" },
    status: { type: String, default: "Offline" },
    lastSeen: { type: Number, default: 0 },
    wappyId: { type: String, unique: true, sparse: true }, 
    isIdHidden: { type: Boolean, default: false }, 
    friends: [{ type: String }], 
    friendRequests: [{
        senderEmail: String, senderId: String,
        avatarUrl: String, displayName: String,
        timestamp: { type: Number, default: Date.now }
    }],
    settings: {
        privacy: { 
            lastSeen: { type: String, default: 'Contacts' }, 
            profilePhoto: { type: String, default: 'Everyone' }, 
            onlineStatus: { type: Boolean, default: true }, 
            readReceipts: { type: Boolean, default: true } 
        },
        notifications: { 
            message: { type: Boolean, default: true }, 
            group: { type: Boolean, default: true }, 
            sound: { type: Boolean, default: true } 
        }
    }
});
const User = mongoose.model('User', userSchema);

const messageSchema = new mongoose.Schema({
    messageId: { type: String, default: nanoid },
    senderEmail: String, text: String, timestamp: Number, status: String,
    receiverEmail: String, receiverGroupId: String
});
const Message = mongoose.model('Message', messageSchema);

const contactSchema = new mongoose.Schema({
    ownerEmail: String, friendEmail: String, nickname: String, isBlocked: {type: Boolean, default: false}
});
const Contact = mongoose.model('Contact', contactSchema);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(process.cwd(), 'public')));
// --- MIDDLEWARE ---
const protectRoute = (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({message: "Not authorized"});
  try { const decoded = jwt.verify(token, JWT_SECRET); req.user = decoded; next(); } 
  catch (error) { res.status(401).json({message: "Invalid token"}); }
};

// --- AUTH ROUTES ---

// 🆕 REGISTER ROUTE (New Feature Added)
app.post('/api/native/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        // Check if user exists
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ message: 'User already exists' });

        // Hash Password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create User
        const newUser = new User({
            email,
            password: hashedPassword,
            displayName: email.split('@')[0] // Default name email ka pehla hissa
        });
        await newUser.save();

        // Generate Token
        const token = jwt.sign({ email: newUser.email }, JWT_SECRET);
        res.status(201).json({ message: 'User created successfully', token, user: newUser });
    } catch (error) {
        res.status(500).json({ message: 'Server error during registration' });
    }
});

// LOGIN ROUTE
app.post('/api/native/login', async (req, res) => {
  try {
      const { email, password } = req.body;
      const user = await User.findOne({ email });
      if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ message: 'Invalid credentials' });
      
      const token = jwt.sign({ email: user.email }, JWT_SECRET);
      res.json({ message: 'Success', token, user });
  } catch (e) { res.status(500).json({ message: "Server Error" }); }
});
// Get Profile
app.get('/api/me', protectRoute, async (req, res) => {
  try {
      let user = await User.findOne({ email: req.user.email }).select('-password');
      res.json(user);
  } catch (e) { res.status(500).json({ message: "Error fetching profile" }); }
});

// Check ID Availability
app.post('/api/check-id', async (req, res) => {
    const { wappyId } = req.body;
    const regex = /^[a-z0-9_]{4,16}$/;
    if (!regex.test(wappyId)) return res.json({ available: false, reason: 'format' });
    const user = await User.findOne({ wappyId: '@' + wappyId });
    if (user) return res.json({ available: false, reason: 'taken' });
    res.json({ available: true });
});

// Update Settings
app.post('/api/update-settings', protectRoute, async (req, res) => {
    try {
        const { type, data } = req.body;
        const user = await User.findOne({ email: req.user.email });
        
        if (type === 'privacy') {
            if (data.wappyId) user.wappyId = data.wappyId;
            if (data.displayName) user.displayName = data.displayName;
            if (data.isIdHidden !== undefined) user.isIdHidden = data.isIdHidden;
            if(user.settings.privacy) user.settings.privacy = { ...user.settings.privacy, ...data };
        } else if (type === 'notifications') {
            user.settings.notifications = { ...user.settings.notifications, ...data };
        }
        await user.save();
        res.json({ message: "Updated", settings: user.settings });
    } catch (e) { res.status(500).json({ message: "Error" }); }
});

// Search User
app.get('/api/search-user', protectRoute, async (req, res) => {
    const { query } = req.query;
    const user = await User.findOne({ wappyId: query, isIdHidden: false }).select('email displayName wappyId avatarUrl');
    if (!user) return res.status(404).json({ message: "User not found or hidden" });
    res.json(user);
});

// Send Request
app.post('/api/send-request', protectRoute, async (req, res) => {
    const { targetEmail } = req.body;
    const sender = await User.findOne({ email: req.user.email });
    const target = await User.findOne({ email: targetEmail });
    if (!target) return res.status(404).json({ message: "User not found" });
    
    const exists = target.friendRequests.find(r => r.senderEmail === sender.email);
    if (exists || target.friends.includes(sender.email)) return res.status(400).json({ message: "Request already sent or friends" });

    target.friendRequests.push({
        senderEmail: sender.email, senderId: sender.wappyId,
        avatarUrl: sender.avatarUrl, displayName: sender.displayName
    });
    await target.save();
    res.json({ message: "Request Sent! 🍉" });
});

// Handle Request
app.post('/api/handle-request', protectRoute, async (req, res) => {
    const { senderEmail, action } = req.body; 
    const me = await User.findOne({ email: req.user.email });
    const sender = await User.findOne({ email: senderEmail });
    me.friendRequests = me.friendRequests.filter(r => r.senderEmail !== senderEmail);
    if (action === 'accept') {
        if (!me.friends.includes(senderEmail)) me.friends.push(senderEmail);
        if (!sender.friends.includes(me.email)) sender.friends.push(me.email);
        await sender.save();
        const newContact = new Contact({ ownerEmail: me.email, friendEmail: senderEmail, nickname: sender.displayName });
        await newContact.save();
    }
    await me.save();
    res.json({ message: action === 'accept' ? "Friend Added! 💚" : "Removed" });
});
// Chat List
app.get('/api/chats', protectRoute, async (req, res) => {
    try { const myEmail = req.user.email; 
        const allMessages = await Message.find({ $and: [ { $or: [ { senderEmail: myEmail }, { receiverEmail: myEmail } ]} ]}).sort({ timestamp: -1 }).lean(); 
        const conversations = new Map();
        allMessages.forEach(msg => {
            let convoId = msg.senderEmail === myEmail ? msg.receiverEmail : msg.senderEmail;
            if (!conversations.has(convoId)) { conversations.set(convoId, { id: convoId, text: msg.text, timestamp: msg.timestamp }); }
        });
        const chatList = Array.from(conversations.values());
        let detailedChatList = await Promise.all(chatList.map(async (chat) => {
            const contact = await Contact.findOne({ ownerEmail: myEmail, friendEmail: chat.id }).lean();
            const friendUser = await User.findOne({ email: chat.id }).lean();
            if (!friendUser) return null;
            return { ...chat, nickname: contact ? contact.nickname : friendUser.displayName, avatarUrl: friendUser.avatarUrl };
        }));
        res.json(detailedChatList.filter(Boolean));
    } catch (error) { res.status(500).json({ message: 'Server error' }); }
});

// Contacts List
app.get('/api/contacts', protectRoute, async (req, res) => {
    try {
        const myContacts = await Contact.find({ ownerEmail: req.user.email }).lean();
        const detailedContacts = await Promise.all(myContacts.map(async (contact) => {
            const friendUser = await User.findOne({ email: contact.friendEmail }).lean();
            if (!friendUser) return null;
            return { ...contact, status: friendUser.status, avatarUrl: friendUser.avatarUrl };
        }));
        res.json(detailedContacts.filter(Boolean));
    } catch (error) { res.status(500).json({ message: 'Server error' }); }
});

// Messages
app.get('/api/messages/:id', protectRoute, async (req, res) => {
    const myEmail = req.user.email; const id = req.params.id;
    const messages = await Message.find({ $or: [ { senderEmail: myEmail, receiverEmail: id }, { senderEmail: id, receiverEmail: myEmail } ] }).sort({ timestamp: -1 }).limit(50).lean();
    res.json({ messages: messages });
});

// Delete Account
app.delete('/api/delete-account', protectRoute, async (req, res) => {
    try { await User.deleteOne({ email: req.user.email }); res.json({ message: "Account deleted successfully" }); } catch (e) { res.status(500).json({ message: "Error deleting account" }); }
});

// --- SOCKET.IO (REAL-TIME FIX FOR MOBILE) ---
io.use((socket, next) => {
    // Mobile apps "auth" object bhejte hain, Web cookies bhejta hai. Dono check karenge.
    const token = socket.handshake.auth?.token || 
                  socket.handshake.headers.authorization?.split(" ")[1] ||
                  socket.handshake.headers.cookie?.split('token=')[1];

    if (!token) return next(new Error("Authentication error"));
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        socket.userEmail = decoded.email; // Socket object me user save kar liya
        next();
    } catch (err) {
        next(new Error("Authentication error"));
    }
});

io.on('connection', (socket) => {
    console.log(`⚡ User Connected: ${socket.userEmail}`);
    socket.join(socket.userEmail); // Apne email ke room me join karo

    socket.on('send message', async (data) => {
        const { receiverId, text } = data;
        const senderEmail = socket.userEmail; // Ab hume pakka pata hai sender kaun hai

        const newMsg = new Message({ 
            senderEmail,
            receiverEmail: receiverId, text, timestamp: Date.now(), status: 'sent' 
        });
        await newMsg.save();

        // Real-time bhej do
        io.to(receiverId).emit('new message', { ...data, senderEmail, status: 'received', timestamp: Date.now() });
    });
});

server.listen(PORT, () => console.log(`🍉 Wappy Server Running on Port ${PORT}`));

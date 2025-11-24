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

// --- CORS SETUP ---
app.use(cors({
    origin: '*', 
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
}));

const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*" } 
});
const JWT_SECRET = 'your-very-secret-key-12345';

// --- DATABASE CONNECTION ---
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB Connected!'))
  .catch(err => console.error('❌ DB Error:', err));

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
// --- USER SCHEMA ---
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
    
    // Pending Requests
    friendRequests: [{
        senderEmail: String,
        senderId: String,
        avatarUrl: String,
        displayName: String,
        timestamp: { type: Number, default: Date.now }
    }],

    // Ignored Requests (24h Cooldown)
    ignoredRequests: [{
        email: String,
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

// --- 🔥 UPDATED CONTACT SCHEMA ---
const contactSchema = new mongoose.Schema({
    ownerEmail: String, 
    friendEmail: String, 
    nickname: String, 
    isBlocked: { type: Boolean, default: false },
    
    // 👇 Naya Signature Logic
    signature: { type: String, default: 'Friends' } 
});
const Contact = mongoose.model('Contact', contactSchema);
// --- AUTH ROUTES ---

// Register
app.post('/api/native/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ message: 'User already exists' });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({
            email, password: hashedPassword, displayName: email.split('@')[0]
        });
        await newUser.save();

        const token = jwt.sign({ email: newUser.email }, JWT_SECRET);
        res.status(201).json({ message: 'User created successfully', token, user: newUser });
    } catch (error) { res.status(500).json({ message: 'Server error during registration' }); }
});

// Login
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

// Update Settings
app.post('/api/update-settings', protectRoute, async (req, res) => {
    try {
        const { type, data } = req.body;
        const user = await User.findOne({ email: req.user.email });
        
        if (type === 'privacy') {
            if (data.wappyId) user.wappyId = data.wappyId;
            if (data.displayName) user.displayName = data.displayName;
            if(user.settings.privacy) user.settings.privacy = { ...user.settings.privacy, ...data };
        } 
        await user.save();
        res.json({ message: "Updated", settings: user.settings });
    } catch (e) { res.status(500).json({ message: "Error" }); }
});
// --- FRIEND REQUEST SYSTEM ---

// Send Request (With 24h Ignored Check)
app.post('/api/send-request', protectRoute, async (req, res) => {
    const { targetEmail } = req.body;
    const sender = await User.findOne({ email: req.user.email });
    const target = await User.findOne({ email: targetEmail });

    if (!target) return res.status(404).json({ message: "User not found" });
    if (target.friends.includes(sender.email)) return res.status(400).json({ message: "Already connected!" });

    const exists = target.friendRequests.find(r => r.senderEmail === sender.email);
    if (exists) return res.status(400).json({ message: "Request already sent ✔" });

    // 24h Ignore Check
    const ignoredEntry = target.ignoredRequests.find(r => r.email === sender.email);
    if (ignoredEntry) {
        const timeDiff = Date.now() - ignoredEntry.timestamp;
        const hoursLeft = 24 - (timeDiff / (1000 * 60 * 60));
        if (timeDiff < 24 * 60 * 60 * 1000) {
            return res.status(400).json({ message: `Request ignored. Try again in ${Math.ceil(hoursLeft)} hours.` });
        } else {
            target.ignoredRequests = target.ignoredRequests.filter(r => r.email !== sender.email);
        }
    }

    // Add Request
    target.friendRequests.push({
        senderEmail: sender.email, senderId: sender.wappyId,
        avatarUrl: sender.avatarUrl, displayName: sender.displayName
    });
    await target.save();

    // Notify Target User via Socket
    io.to(targetEmail).emit('new request', { 
        senderName: sender.displayName, 
        senderId: sender.wappyId 
    });

    res.json({ message: "Request Sent ✔" });
});

// 🔥 HANDLE REQUEST (UPDATED WITH SIGNATURE)
app.post('/api/handle-request', protectRoute, async (req, res) => {
    const { senderEmail, action, signature } = req.body; // <-- Signature receive kiya
    const me = await User.findOne({ email: req.user.email });
    const sender = await User.findOne({ email: senderEmail });

    me.friendRequests = me.friendRequests.filter(r => r.senderEmail !== senderEmail);

    if (action === 'accept') {
        if (!me.friends.includes(senderEmail)) me.friends.push(senderEmail);
        if (!sender.friends.includes(me.email)) sender.friends.push(me.email);
        await sender.save();

        // 🔥 Save Signature
        const chosenSig = signature || 'Friends';

        const c1 = new Contact({ ownerEmail: me.email, friendEmail: senderEmail, nickname: sender.displayName, signature: chosenSig });
        await c1.save();
        const c2 = new Contact({ ownerEmail: senderEmail, friendEmail: me.email, nickname: me.displayName, signature: chosenSig });
        await c2.save();

        await me.save();
        
        // Notify Sender
        io.to(senderEmail).emit('request accepted', { 
            accepterName: me.displayName, 
            signature: chosenSig 
        });

        res.json({ message: "Connected 🤝", status: 'accepted' });

    } else if (action === 'ignore') {
        me.ignoredRequests.push({ email: senderEmail, timestamp: Date.now() });
        await me.save();
        res.json({ message: "Request Ignored", status: 'ignored' });
    }
});
// --- DATA ROUTES ---

// Chat List (Returns Signature)
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
            return { 
                ...chat, 
                nickname: contact ? contact.nickname : friendUser.displayName, 
                avatarUrl: friendUser.avatarUrl,
                signature: contact ? contact.signature : 'Friends' // 🔥 Signature Sent
            };
        }));
        res.json(detailedChatList.filter(Boolean));
    } catch (error) { res.status(500).json({ message: 'Server error' }); }
});

// Contacts List (Returns Signature)
app.get('/api/contacts', protectRoute, async (req, res) => {
    try {
        const myContacts = await Contact.find({ ownerEmail: req.user.email }).lean();
        const detailedContacts = await Promise.all(myContacts.map(async (contact) => {
            const friendUser = await User.findOne({ email: contact.friendEmail }).lean();
            if (!friendUser) return null;
            return { 
                ...contact, 
                status: friendUser.status, 
                avatarUrl: friendUser.avatarUrl,
                signature: contact.signature // 🔥 Signature Sent
            };
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

// --- SOCKET ---
io.use((socket, next) => {
    const token = socket.handshake.auth?.token || 
                  socket.handshake.headers.authorization?.split(" ")[1] ||
                  socket.handshake.headers.cookie?.split('token=')[1];

    if (!token) return next(new Error("Authentication error"));
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        socket.userEmail = decoded.email; 
        next();
    } catch (err) { next(new Error("Authentication error")); }
});

io.on('connection', (socket) => {
    socket.join(socket.userEmail);
    socket.on('join room', (room) => socket.join(room));

    socket.on('send message', async (data) => {
        const { receiverId, text } = data;
        const senderEmail = socket.userEmail;
        const newMsg = new Message({ 
            senderEmail, receiverEmail: receiverId, text, timestamp: Date.now(), status: 'sent' 
        });
        await newMsg.save();
        io.to(receiverId).emit('new message', { ...data, senderEmail, status: 'received', timestamp: Date.now() });
    });

    socket.on('friend typing', () => { /* Typing logic */ });
});

server.listen(PORT, () => console.log(`🍉 Wappy Server Running on Port ${PORT}`));

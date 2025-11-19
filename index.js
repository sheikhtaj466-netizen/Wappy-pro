// index.js (FINAL - NAYA FRIEND REQUEST SYSTEM - Part 1)
import express from 'express';
import http from 'http';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import { Server } from 'socket.io';
import { nanoid } from 'nanoid';
import dotenv from 'dotenv';
import sgMail from '@sendgrid/mail'; // SendGrid Email
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import rateLimit from 'express-rate-limit';
import mongoose from 'mongoose'; // MongoDB
import { v2 as cloudinary } from 'cloudinary'; // NAYA: Cloudinary
import { CloudinaryStorage } from 'multer-storage-cloudinary'; // NAYA: Cloudinary
import { error } from 'console';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

// === NAYA: SendGrid API Key Setup ===
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// === NAYA: Cloudinary Config ===
cloudinary.config({ 
  cloud_name: process.env.CLOUD_NAME, 
  api_key: process.env.CLOUDINARY_API_KEY, 
  api_secret: process.env.CLOUDINARY_API_SECRET 
});

const app = express();

// === NAYA: RENDER PORT FIX ===
const PORT = process.env.PORT || 3000;

// === NAYA: RENDER PROXY FIX ===
app.set('trust proxy', 1);

// === NAYA: Server aur IO definition (FIXED) ===
const server = http.createServer(app);
const io = new Server(server); // 'io' ab sahi se defined hai

const JWT_SECRET = 'your-very-secret-key-12345';
const JWT_RESET_SECRET = 'your-password-reset-key-67890';
const connectedUsers = new Map();

// === NAYA: Cloudinary Storage Engine (FIXED) ===
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'wappy_avatars', 
    format: async (req, file) => 'png', 
    public_id: (req, file) => {
      const id = req.body.groupId || req.user.email;
      return id;
    }
  },
});
// === END NAYA STORAGE ===

const upload = multer({ storage: storage });
const MESSAGES_PER_PAGE = 20;

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 10, 
    message: "Too many login attempts from this IP, please try again after 15 minutes",
    standardHeaders: true, 
    legacyHeaders: false, 
});

// === NAYA: MongoDB Database Connection ===
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('[Wappy DB] MongoDB connected successfully!'))
  .catch(err => console.error('[Wappy DB] MongoDB connection error:', err));

// === Mongoose Models (Schemas) ===
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, index: true },
    password: { type: String, required: true },
    displayName: { type: String, default: "" },
    avatarUrl: { type: String, default: "" },
    status: { type: String, default: "Offline" },
    lastSeen: { type: Number, default: 0 },
    
    // === NAYA: Mood Feature ===
    currentMood: { 
        type: String, 
        enum: ['default', 'happy', 'sad', 'angry', 'love', 'cool'], 
        default: 'default' 
    },
    // === END NAYA ===

    privacy: {
        lastSeen: { type: String, default: "everyone" },
        avatar: { type: String, default: "everyone" }
    }
});
const User = mongoose.model('User', userSchema);

const contactSchema = new mongoose.Schema({
    ownerEmail: { type: String, required: true, index: true },
    friendEmail: { type: String, required: true, index: true },
    nickname: { type: String, required: true },
    isBlocked: { type: Boolean, default: false },
    isPinned: { type: Boolean, default: false }
});
const Contact = mongoose.model('Contact', contactSchema);

const groupMemberSchema = new mongoose.Schema({
    email: String,
    role: { type: String, enum: ['admin', 'member'], default: 'member' }
}, { _id: false });
const groupSchema = new mongoose.Schema({
    groupId: { type: String, required: true, unique: true, default: nanoid },
    groupName: String,
    groupAvatar: { type: String, default: "" },
    creatorEmail: String,
    members: [groupMemberSchema]
});
const Group = mongoose.model('Group', groupSchema);

const replySchema = new mongoose.Schema({
    messageId: String,
    text: String,
    senderName: String
}, { _id: false });
const messageSchema = new mongoose.Schema({
    messageId: { type: String, required: true, unique: true, default: nanoid },
    senderEmail: { type: String, required: true, index: true },
    senderName: { type: String, required: true },
    receiverEmail: { type: String, index: true },
    receiverGroupId: { type: String, index: true },
    text: String,
    timestamp: { type: Number, index: true },
    status: String,
    isDeleted: { type: Boolean, default: false },
    deletedBy: [String],
    replyTo: { type: replySchema, default: null },
    isStarred: { type: Boolean, default: false },
    
    // === Truth Mode Feature ===
    isTruthMode: { type: Boolean, default: false },
    
    // === NAYA: Puzzle Message Feature ===
    isPuzzle: { type: Boolean, default: false } 
});

const Message = mongoose.model('Message', messageSchema);
// === NAYA: KADAM 1 - Friend Request Model ===
const friendRequestSchema = new mongoose.Schema({
    requesterEmail: { type: String, required: true, index: true },
    receiverEmail: { type: String, required: true, index: true },
    status: { 
        type: String, 
        enum: ['pending', 'accepted', 'declined', 'cancelled'], 
        default: 'pending' 
    }
}, {
    timestamps: true 
});
// Unique constraint
friendRequestSchema.index({ requesterEmail: 1, receiverEmail: 1, status: 'pending' }, { 
    unique: true, 
    partialFilterExpression: { status: 'pending' } 
});
const FriendRequest = mongoose.model('FriendRequest', friendRequestSchema);
// === END KADAM 1 ===


// === Middleware & ProtectRoute ===
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// === NAYA: ULTRA-ADVANCED STATIC PATH FIX ===
const publicPath = path.join(process.cwd(), 'public');
app.use(express.static(publicPath));
console.log(`[Wappy Server] Serving static files from: ${publicPath}`);
// === END FIX ===

const protectRoute = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) { return res.redirect('/login.html'); }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; 
    next();
  } catch (error) {
    return res.redirect('/login.html');
  }
};

io.use(async (socket, next) => {
  try {
    const token = socket.handshake.headers.cookie?.split('; ').find(row => row.startsWith('token='))?.split('=')[1];
    if (!token) { return next(new Error('Authentication error')); }
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findOne({ email: decoded.email }).lean(); 
    if (!user) { return next(new Error('User not found')); }
    socket.user = user;
    next();
  } catch (err) {
    next(new Error('Authentication error'));
  }
});

const getRoomName = (email1, email2) => [email1, email2].sort().join('-');

// === HTTP Routes ===
app.get('/', protectRoute, (req, res) => { res.redirect('/chats.html'); });
app.get('/home.html', protectRoute, async (req, res) => {
  const user = await User.findOne({ email: req.user.email }).lean();
  if (!user || !user.displayName || user.displayName === "") { return res.redirect('/set-name.html'); }
  res.sendFile(path.join(publicPath, 'home.html')); 
});
app.get('/chats.html', protectRoute, async (req, res) => {
  const user = await User.findOne({ email: req.user.email }).lean();
  if (!user || !user.displayName || user.displayName === "") { return res.redirect('/set-name.html'); }
  res.sendFile(path.join(publicPath, 'chats.html'));
});
app.get('/chat.html', protectRoute, (req, res) => {
  res.sendFile(path.join(publicPath, 'chat.html'));
});
app.get('/profile.html', protectRoute, (req, res) => {
  res.sendFile(path.join(publicPath, 'profile.html'));
});
app.get('/create-group.html', protectRoute, (req, res) => {
  res.sendFile(path.join(publicPath, 'create-group.html'));
});

app.get('/api/me', protectRoute, async (req, res) => {
  const user = await User.findOne({ email: req.user.email }).select('-password').lean();
  res.json(user);
});

async function canSeeInfo(requesterEmail, targetUser) {
    const isContact = await Contact.findOne({ ownerEmail: targetUser.email, friendEmail: requesterEmail });
    let canSeeAvatar = false;
    if (targetUser.privacy.avatar === 'everyone') { canSeeAvatar = true; } 
    else if (targetUser.privacy.avatar === 'contacts' && isContact) { canSeeAvatar = true; }
    let canSeeLastSeen = false;
    if (targetUser.privacy.lastSeen === 'everyone') { canSeeLastSeen = true; } 
    else if (targetUser.privacy.lastSeen === 'contacts' && isContact) { canSeeLastSeen = true; }
    return { canSeeAvatar, canSeeLastSeen };
}
// index.js (FINAL - NAYA FRIEND REQUEST SYSTEM - Part 2)
// === NAYA: User Info Route (Mood ke saath) ===
app.get('/api/userinfo/:email', protectRoute, async (req, res) => {
  try {
    const friendEmail = req.params.email;
    const ownerEmail = req.user.email;
    
    const contact = await Contact.findOne({ ownerEmail: ownerEmail, friendEmail: friendEmail }).lean();
    const friendUser = await User.findOne({ email: friendEmail }).lean();
    
    if (contact && friendUser) {
      const { canSeeAvatar, canSeeLastSeen } = await canSeeInfo(ownerEmail, friendUser);
      
      res.json({ 
        email: contact.friendEmail, 
        displayName: contact.nickname,
        status: canSeeLastSeen ? friendUser.status : 'Offline',
        lastSeen: canSeeLastSeen ? friendUser.lastSeen : 0,
        avatarUrl: canSeeAvatar ? friendUser.avatarUrl : '',
        isBlocked: contact.isBlocked,
        // NAYA: Mood data bhejo (agar nahi hai toh 'default')
        currentMood: friendUser.currentMood || 'default' 
      });
    } else { 
        res.status(404).json({ message: 'Contact not found' }); 
    }
  } catch (error) { 
      res.status(500).json({ message: 'Server error' }); 
  }
});

app.get('/api/groupinfo/:groupId', protectRoute, async (req, res) => {
    try {
        const groupId = req.params.groupId;
        const group = await Group.findOne({ groupId: groupId }).lean();
        if (!group) { return res.status(404).json({ message: "Group not found" }); }
        const isMember = group.members.some(m => m.email === req.user.email);
        if (!isMember) { return res.status(403).json({ message: "You are not a member of this group" }); }
        const detailedMembers = await Promise.all(group.members.map(async (member) => {
            const user = await User.findOne({ email: member.email }).select('displayName').lean();
            return { email: member.email, role: member.role,
                displayName: (user && user.displayName) ? user.displayName : member.email.split('@')[0]
            };
        }));
        res.json({ ...group, members: detailedMembers });
    } catch (error) { res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/messages/:id', protectRoute, async (req, res) => {
  const myEmail = req.user.email;
  const id = req.params.id;
  const cursor = req.query.cursor ? parseInt(req.query.cursor) : Date.now();
  const query = { $and: [ { timestamp: { $lt: cursor } }, { deletedBy: { $nin: [myEmail] } },
      { $or: [ { senderEmail: myEmail, receiverEmail: id }, { senderEmail: id, receiverEmail: myEmail }, { receiverGroupId: id } ]}
  ]};
  try {
      const messages = await Message.find(query).sort({ timestamp: -1 }).limit(MESSAGES_PER_PAGE).lean();
      const nextCursor = messages.length === MESSAGES_PER_PAGE ? messages[messages.length - 1].timestamp : null;
      res.json({ messages: messages.reverse(), nextCursor: nextCursor });
  } catch (error) { console.error("[Wappy Error] Error fetching messages:", error); res.status(500).json({ message: "Server error" }); }
});

app.get('/api/contacts', protectRoute, async (req, res) => {
  try {
    const ownerEmail = req.user.email;
    const searchQuery = req.query.q || '';
    let query = { ownerEmail: ownerEmail };
    if (searchQuery) { query.nickname = { $regex: searchQuery, $options: 'i' }; }
    const myContacts = await Contact.find(query).lean();
    const detailedContacts = await Promise.all(myContacts.map(async (contact) => {
      const friendUser = await User.findOne({ email: contact.friendEmail }).lean();
      if (!friendUser) return null;
      const { canSeeAvatar, canSeeLastSeen } = await canSeeInfo(ownerEmail, friendUser);
      return { ...contact, status: canSeeLastSeen ? friendUser.status : 'Offline', lastSeen: canSeeLastSeen ? friendUser.lastSeen : 0, avatarUrl: canSeeAvatar ? friendUser.avatarUrl : '' };
    }));
    const finalContacts = detailedContacts.filter(Boolean);
    finalContacts.sort((a, b) => {
      if (a.isPinned && !b.isPinned) return -1;
      if (!a.isPinned && b.isPinned) return 1;
      return a.nickname.localeCompare(b.nickname);
    });
    res.json(finalContacts);
  } catch (error) { console.error('[Wappy Error] Get contacts error:', error); res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/chats', protectRoute, async (req, res) => {
    try {
        const myEmail = req.user.email;
        const searchQuery = req.query.q || '';
        const allMessages = await Message.find({ $and: [ { deletedBy: { $nin: [myEmail] } },
                { $or: [ { senderEmail: myEmail }, { receiverEmail: myEmail },
                    { receiverGroupId: { $in: (await Group.find({ 'members.email': myEmail }).select('groupId').lean()).map(g => g.groupId) } }
                ]}
            ]}).sort({ timestamp: -1 }).lean(); 
        const conversations = new Map();
        allMessages.forEach(msg => {
            let convoId = ''; let isGroup = false;
            if (msg.receiverGroupId) { convoId = msg.receiverGroupId; isGroup = true; } 
            else { convoId = msg.senderEmail === myEmail ? msg.receiverEmail : msg.senderEmail; }
            if (!conversations.has(convoId)) {
                conversations.set(convoId, { id: convoId, isGroup: isGroup, text: msg.isDeleted ? "This message was deleted" : msg.text, timestamp: msg.timestamp, senderEmail: msg.senderEmail, status: msg.status });
            }
        });
        const chatList = Array.from(conversations.values());
        let detailedChatList = await Promise.all(chatList.map(async (chat) => {
            if (chat.isGroup) {
                const group = await Group.findOne({ groupId: chat.id }).lean();
                if (!group) return null;
                return { ...chat, nickname: group.groupName, avatarUrl: group.groupAvatar || '', isPinned: false };
            } else {
                const contact = await Contact.findOne({ ownerEmail: myEmail, friendEmail: chat.id }).lean();
                const friendUser = await User.findOne({ email: chat.id }).lean();
                if (!contact || !friendUser) return null;
                const { canSeeAvatar } = await canSeeInfo(myEmail, friendUser);
                return { ...chat, nickname: contact.nickname, avatarUrl: canSeeAvatar ? friendUser.avatarUrl : '', isPinned: contact.isPinned };
            }
        }));
        detailedChatList = detailedChatList.filter(Boolean);
        if (searchQuery) { detailedChatList = detailedChatList.filter(c => c.nickname.toLowerCase().includes(searchQuery.toLowerCase())); }
        detailedChatList.sort((a, b) => {
            if (a.isPinned && !b.isPinned) return -1;
            if (!a.isPinned && b.isPinned) return 1;
            return b.timestamp - a.timestamp;
        });
        res.json(detailedChatList);
    } catch (error) { console.error('[Wappy Error] Get chats error:', error); res.status(500).json({ message: 'Server error' }); }
});

app.post('/api/upload-avatar', protectRoute, upload.single('avatar'), async (req, res, next) => { 
  try {
    if (!req.file) { return res.status(400).send('No file uploaded.'); }
    const avatarUrl = req.file.path; 
    await User.updateOne({ email: req.user.email }, { $set: { avatarUrl: avatarUrl } });
    console.log(`[Wappy] Avatar updated for ${req.user.email}: ${avatarUrl}`);
    res.redirect('/profile.html');
  } catch (error) { 
    console.error('[Wappy Error] Avatar upload error:', error);
    next(error); 
  }
});

app.post('/api/toggle-block', protectRoute, async (req, res) => {
  try {
    const { friendEmail } = req.body;
    const ownerEmail = req.user.email;
    const contact = await Contact.findOne({ ownerEmail: ownerEmail, friendEmail: friendEmail });
    if (contact) {
      contact.isBlocked = !contact.isBlocked; await contact.save();
      const status = contact.isBlocked ? 'blocked' : 'unblocked';
      console.log(`[Wappy] User ${ownerEmail} ${status} ${friendEmail}`);
      res.json({ message: `User ${status}`, isBlocked: contact.isBlocked });
    } else { res.status(404).send('Contact not found'); }
  } catch (error) { console.error('[Wappy Error] Toggle block error:', error); res.status(500).send('Server error'); }
});

app.post('/api/toggle-pin', protectRoute, async (req, res) => {
  try {
    const { friendEmail } = req.body;
    const ownerEmail = req.user.email;
    const contact = await Contact.findOne({ ownerEmail: ownerEmail, friendEmail: friendEmail });
    if (contact) {
      contact.isPinned = !contact.isPinned; await contact.save();
      const status = contact.isPinned ? 'pinned' : 'unpinned';
      console.log(`[Wappy] User ${ownerEmail} ${status} chat with ${friendEmail}`);
      res.json({ message: `Chat ${status}`, isPinned: contact.isPinned });
    } else { res.status(404).send('Contact not found'); }
  } catch (error) { console.error('[Wappy Error] Toggle pin error:', error); res.status(500).send('Server error'); }
});

app.post('/api/update-privacy', protectRoute, async (req, res) => {
    try {
        const { lastSeen, avatar } = req.body;
        const myEmail = req.user.email;
        const validOptions = ["everyone", "contacts", "nobody"];
        if (!validOptions.includes(lastSeen) || !validOptions.includes(avatar)) { return res.status(400).json({ message: "Invalid options" }); }
        await User.updateOne( { email: myEmail }, { $set: { 'privacy.lastSeen': lastSeen, 'privacy.avatar': avatar } });
        console.log(`[Wappy] Privacy updated for ${myEmail}`);
        res.json({ message: "Privacy settings updated" });
    } catch (error) { console.error('[Wappy Error] Update privacy error:', error); res.status(500).json({ message: "Server error" }); }
});
// === NAYA: Update Mood Route ===
app.post('/api/update-mood', protectRoute, async (req, res, next) => {
    try {
        const { mood } = req.body;
        const myEmail = req.user.email;
        
        // Allowed moods check karo
        const validMoods = ['default', 'happy', 'sad', 'angry', 'love', 'cool'];
        if (!validMoods.includes(mood)) {
            return res.status(400).json({ message: "Invalid mood selected" });
        }
        
        // Database update karo
        await User.updateOne({ email: myEmail }, { $set: { currentMood: mood } });
        
        console.log(`[Wappy] Mood updated for ${myEmail}: ${mood}`);
        res.json({ message: "Mood updated successfully", mood: mood });
        
    } catch (error) {
        console.error('[Wappy Error] Update mood error:', error);
        next(error);
    }
});

app.post('/api/create-group', protectRoute, async (req, res) => {
    try {
        let { groupName, members } = req.body;
        const creatorEmail = req.user.email;
        if (!groupName || !members || members.length === 0) { return res.status(400).json({ message: "Group name and members are required." }); }
        const memberObjects = members.map(email => ({ email: email, role: "member" }));
        memberObjects.push({ email: creatorEmail, role: "admin" });
        const newGroup = new Group({ groupId: nanoid(), groupName: groupName, groupAvatar: "", creatorEmail: creatorEmail, members: memberObjects });
        await newGroup.save();
        console.log(`[Wappy] New group created: ${groupName} by ${creatorEmail}`);
        res.status(201).json({ message: "Group created!", group: newGroup });
    } catch (error) { console.error('[Wappy Error] Create group error:', error); res.status(500).json({ message: "Server error" }); }
});

app.post('/api/toggle-star', protectRoute, async (req, res) => {
    try {
        const { messageId } = req.body;
        const myEmail = req.user.email;
        const message = await Message.findOne({ messageId: messageId });
        if (!message) { return res.status(404).json({ message: "Message not found" }); }
        let isMyChat = false;
        if (message.receiverGroupId){
            const group = await Group.findOne({ groupId: message.receiverGroupId }).lean();
            isMyChat = group && group.members.some(m => m.email === myEmail);
        } else { isMyChat = (message.senderEmail === myEmail) || (message.receiverEmail === myEmail); }
        if (!isMyChat) { return res.status(403).json({ message: "Not authorized" }); }
        message.isStarred = !message.isStarred; await message.save();
        const status = message.isStarred ? 'starred' : 'unstarred';
        console.log(`[Wappy] Message ${messageId} ${status} by ${myEmail}`);
        let roomName = message.receiverGroupId ? message.receiverGroupId : getRoomName(message.senderEmail, message.receiverEmail);
        io.to(roomName).emit('message starred', { messageId: message.messageId, isStarred: message.isStarred });
        res.json({ message: `Message ${status}`, isStarred: message.isStarred });
    } catch (error) { console.error('[Wappy Error] Star message error:', error); res.status(500).json({ message: "Server error" }); }
});

// === Authentication Routes (SendGrid Waala Fix) ===
app.post('/register', async (req, res, next) => { 
  try {
    const { email, password } = req.body;
    console.log(`[Wappy Register] Checking if user exists: ${email}`);
    let existingUser = await User.findOne({ email: email }).lean();
    if (existingUser) { 
      console.log(`[Wappy Register] Failed: User already exists: ${email}`);
      return res.status(400).send('User already exists'); 
    }
    console.log(`[Wappy Register] Hashing password for ${email}`);
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const newUser = new User({ email: email, password: hashedPassword, displayName: email.split('@')[0] });
    console.log(`[Wappy Register] Saving new user ${email} to database...`);
    await newUser.save();
    console.log(`[Wappy Register] NEW USER REGISTERED: ${email}`);
    try {
      console.log(`[Wappy Register] Sending welcome email to ${email} via SendGrid...`);
      const msg = {
        to: email, from: process.env.EMAIL_USER, subject: 'Welcome to Wappy! 🍉',
        text: `Welcome, ${email}! Thank you for joining Wappy. You can now login and start chatting with your friends.`,
        html: `<div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: auto; border: 1px solid #ddd; border-radius: 8px; overflow: hidden;"><div style="background-color: #22c55e; color: white; padding: 20px; text-align: center;"><h1 style="margin: 0; font-size: 28px;">Welcome to Wappy! 🍉</h1></div><div style="padding: 30px;"><p style="font-size: 18px;">Hello ${email},</p><p>Thank you for joining Wappy. We're excited to have you on board!</p><p>You can now log in and start chatting with your friends and family.</p><a href="https://wappy-pro.onrender.com/login.html" style="background-color: #22c55e; color: white; padding: 12px 25px; text-decoration: none; border-radius: 5px; display: inline-block; margin-top: 20px; font-weight: bold;">Login to Your Account</a><p style="margin-top: 30px; font-size: 14px; color: #777;">If you did not sign up for this account, you can safely ignore this email.</p><hr style="border: 0; border-top: 1px solid #eee; margin-top: 20px;"><p style="font-size: 12px; color: #999; text-align: center;">&copy; ${new Date().getFullYear()} Wappy. All rights reserved.</p></div></div>`
      };
      await sgMail.send(msg);
      console.log(`[Wappy Register] Welcome email sent to: ${email}`);
    } catch (emailError) { 
      console.error(`--- SENDGRID EMAIL FAILED but user was registered ---`);
      if (emailError.response) { console.error(emailError.response.body); } else { console.error(emailError); }
      console.error(`--- END SENDGRID ERROR ---`);
    }
    res.redirect('/login.html');
  } catch (error) { 
    next(error); 
  }
});

app.post('/login', loginLimiter, async (req, res, next) => { 
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email: email }).lean();
    if (!user) { return res.status(400).send('Invalid email or password'); }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) { return res.status(400).send('Invalid email or password'); }
         // NAYA: 30 Din ki expiry
    const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    
    res.cookie('token', token, { 
        httpOnly: true, 
        // 30 Din * 24 Ghante * 60 Min * 60 Sec * 1000 ms
        maxAge: 30 * 24 * 60 * 60 * 1000, 
        secure: true, 
        sameSite: 'Lax' // 'Strict' ko 'Lax' kiya taaki WebView mein problem na ho
    });
    console.log(`[Wappy] USER LOGGED IN: ${email}`);
    res.redirect('/chats.html');
  } catch (error) { 
    next(error); 
  }
});

app.post('/set-name', protectRoute, async (req, res, next) => { 
  try {
    const { displayName } = req.body;
    await User.updateOne({ email: req.user.email }, { $set: { displayName: displayName } });
    console.log(`[Wappy] DISPLAY NAME SET for ${req.user.email}: ${displayName}`);
    res.redirect('/chats.html');
  } catch (error) { 
    next(error); 
  }
});

// === NAYA: KADAM 2 - "Send Friend Request" Route (Facebook Jaisa) ===
// (Ye 'Mutual Add' waale code ko replace kar raha hai)
app.post('/add-friend', protectRoute, async (req, res, next) => { 
  try {
    // Nickname ki zaroorat nahi, woh accept par set hoga
    const { friendEmail } = req.body; 
    const requesterEmail = req.user.email;

    // 1. Basic Checks
    if (friendEmail === requesterEmail) { return res.status(400).json({message: "You cannot send a request to yourself."}); }
    const friendUser = await User.findOne({ email: friendEmail }).lean();
    if (!friendUser) { return res.status(404).json({message: "User with this email does not exist."}); }

    // 2. Check ki pehle se dost toh nahi hain
    const alreadyFriend = await Contact.findOne({ ownerEmail: requesterEmail, friendEmail: friendEmail }).lean();
    if (alreadyFriend) { return res.status(400).json({message: "You are already friends with this user."}); }

    // 3. Check ki pehle se PENDING request toh nahi hai (A -> B ya B -> A)
    const existingRequest = await FriendRequest.findOne({
      $or: [
        { requesterEmail: requesterEmail, receiverEmail: friendEmail, status: 'pending' },
        { requesterEmail: friendEmail, receiverEmail: requesterEmail, status: 'pending' }
      ]
    });

    if (existingRequest) {
      if (existingRequest.requesterEmail === friendEmail) {
        return res.status(400).json({message: "This user has already sent you a request. Check your notifications."});
      } else {
        return res.status(400).json({message: "You have already sent a request to this user."});
      }
    }

    // 4. Nayi request banao
    const newRequest = new FriendRequest({
      requesterEmail: requesterEmail,
      receiverEmail: friendEmail,
      status: 'pending'
    });
    await newRequest.save();
    
    console.log(`[Wappy] NEW FRIEND REQUEST: ${requesterEmail} -> ${friendEmail}`);
    
    // 5. NAYA: User B ko real-time notification bhejo (agar woh online hai)
    const friendSocketId = connectedUsers.get(friendEmail);
    if (friendSocketId) {
      const requesterUser = await User.findOne({ email: requesterEmail }).select('displayName avatarUrl').lean();
      io.to(friendSocketId).emit('new_friend_request', {
          _id: newRequest._id, // Request ki ID
          requesterEmail: requesterEmail,
          displayName: requesterUser.displayName || requesterEmail.split('@')[0],
          avatarUrl: requesterUser.avatarUrl
      });
    }
    
    // NAYA: Redirect ke bajaaye JSON response bhejo
    res.status(200).json({ message: "Friend request sent!" });

  } catch (error) { 
    if (error.code === 11000) { // Duplicate key error
      return res.status(400).json({message: "You have already sent a request to this user."});
    }
    next(error); 
  }
});

// === NAYA: KADAM 3 - Friend Request Management Routes ===

// 1. User ki saari PENDING requests fetch karna
app.get('/api/friend-requests', protectRoute, async (req, res, next) => {
  try {
    const myEmail = req.user.email;
    const requests = await FriendRequest.find({ 
      receiverEmail: myEmail, 
      status: 'pending' 
    }).lean();
    
    const detailedRequests = await Promise.all(requests.map(async (request) => {
      const user = await User.findOne({ email: request.requesterEmail }).select('displayName avatarUrl').lean();
      return {
        _id: request._id, // Request ki ID
        requesterEmail: request.requesterEmail,
        displayName: user ? (user.displayName || request.requesterEmail.split('@')[0]) : request.requesterEmail.split('@')[0],
        avatarUrl: user ? user.avatarUrl : ''
      };
    }));
    
    res.status(200).json(detailedRequests);
  } catch (error) {
    next(error);
  }
});

// 2. Request ko "ACCEPT" karna
app.post('/api/friend-requests/accept', protectRoute, async (req, res, next) => {
  try {
    const { requestId } = req.body; 
    const myEmail = req.user.email; // Main (User B)

    const request = await FriendRequest.findOne({ 
      _id: requestId, 
      receiverEmail: myEmail, 
      status: 'pending' 
    });

    if (!request) {
      return res.status(404).json({message: "Request not found or already handled."});
    }
    
    const requesterEmail = request.requesterEmail; // User A

    const meUser = await User.findOne({ email: myEmail }).lean();
    const requesterUser = await User.findOne({ email: requesterEmail }).lean();

    if (!requesterUser) {
        return res.status(404).json({message: "Requester user not found."});
    }

    // 3. Mutual contacts banao
    const newContactForMe = new Contact({
      ownerEmail: myEmail,
      friendEmail: requesterEmail,
      nickname: requesterUser.displayName || requesterEmail.split('@')[0]
    });
    
    const newContactForRequester = new Contact({
      ownerEmail: requesterEmail,
      friendEmail: myEmail,
      nickname: meUser.displayName || myEmail.split('@')[0]
    });

    // 4. Request ko 'accepted' mark karo aur dono contacts save karo
    request.status = 'accepted';
    
    await Promise.all([
      request.save(),
      newContactForMe.save(),
      newContactForRequester.save()
    ]);
    
    console.log(`[Wappy] FRIEND REQUEST ACCEPTED: ${requesterEmail} <-> ${myEmail}`);

    // 5. NAYA: User A (Requester) ko notification bhejo ki request accept ho gayi
    const requesterSocketId = connectedUsers.get(requesterEmail);
    if (requesterSocketId) {
        const { canSeeAvatar, canSeeLastSeen } = await canSeeInfo(requesterEmail, meUser);
        const contactDataForA = {
            ...newContactForRequester.toObject(),
            status: canSeeLastSeen ? meUser.status : 'Offline', 
            lastSeen: canSeeLastSeen ? meUser.lastSeen : 0,
            avatarUrl: canSeeAvatar ? meUser.avatarUrl : '' 
        };
        io.to(requesterSocketId).emit('request_accepted', contactDataForA);
    }

    res.status(200).json({ message: "Friend request accepted!" });

  } catch (error) {
    next(error);
  }
});

// 3. Request ko "DECLINE" karna
app.post('/api/friend-requests/decline', protectRoute, async (req, res, next) => {
  try {
    const { requestId } = req.body;
    const myEmail = req.user.email;

    const result = await FriendRequest.updateOne({
      _id: requestId,
      receiverEmail: myEmail,
      status: 'pending'
    }, {
      status: 'declined'
    });

    if (result.modifiedCount === 0) {
      return res.status(404).json({message: "Request not found or already handled."});
    }
    
    console.log(`[Wappy] FRIEND REQUEST DECLINED: by ${myEmail}`);
    res.status(200).json({ message: "Friend request declined." });

  } catch (error) {
    next(error);
  }
});
// === END KADAM 3 ===


app.get('/logout', (req, res) => {
  res.cookie('token', '', { maxAge: 1 });
  res.redirect('/login.html');
});

app.post('/forgot-password', async (req, res, next) => { 
  try {
    const { email } = req.body;
    const user = await User.findOne({ email: email }).lean();
    if (!user) {
      console.log(`[Wappy Forgot] Password reset attempt for non-existent user: ${email}`);
      return res.send("If this email is registered, you will receive a reset link.");
    }
        // NAYA: 30 Din ki expiry
    const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    const resetUrl = `https://wappy-pro.onrender.com/reset-password.html?token=${resetToken}`;
    console.log(`[Wappy Forgot] Password reset link (SendGrid) sending to: ${email}`);
    const msg = {
      to: email, from: process.env.EMAIL_USER, subject: "Your Wappy Password Reset Link",
      text: `Hello ${user.displayName || user.email}, Click the link below to reset your password. This link is valid for 10 minutes only. ${resetUrl}`,
      html: `<div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: auto; border: 1px solid #ddd; border-radius: 8px; overflow: hidden;"><div style="background-color: #f4b400; color: white; padding: 20px; text-align: center;"><h1 style="margin: 0; font-size: 28px;">Password Reset Request</h1></div><div style="padding: 30px;"><p style="font-size: 18px;">Hello ${user.displayName || user.email},</p><p>We received a request to reset your password for your Wappy account. You can reset your password by clicking the button below.</p><p><strong>This link is valid for 10 minutes only.</strong></p><a href="${resetUrl}" style="background-color: #f4b400; color: white; padding: 12px 25px; text-decoration: none; border-radius: 5px; display: inline-block; margin-top: 20px; font-weight: bold;">Reset Your Password</a><p style="margin-top: 30px; font-size: 14px; color: #777;">If you did not request this, please ignore this email. Your password will not be changed.</p></div></div>`
    };
    await sgMail.send(msg);
    console.log(`[Wappy Forgot] Password reset link sent to: ${email}`);
    res.send("Password reset link has been sent to your email.");
  } catch (error) { 
    next(error);
  }
});

app.post('/reset-password', async (req, res, next) => {
  try {
    const { token } = req.query;
    const { password } = req.body;
    if (!token) { return res.status(400).send('Invalid token'); }
    let decoded;
    try { decoded = jwt.verify(token, JWT_RESET_SECRET); } 
    catch (err) { return res.status(400).send('Invalid or expired token. Please try again.'); }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    await User.updateOne({ email: decoded.email }, { $set: { password: hashedPassword } });
    console.log(`[Wappy] Password reset SUCCESS for: ${decoded.email}`);
    res.redirect('/login.html');
  } catch (error) { 
    next(error); 
  }
});
// index.js (FINAL - NAYA FRIEND REQUEST SYSTEM - Part 3)
// === Socket.io Logic ===
io.on('connection', async (socket) => {
  const userEmail = socket.user.email;
  console.log(`[Wappy Socket] User connected: ${userEmail}`);
  connectedUsers.set(userEmail, socket.id);
  
  await User.updateOne({ email: userEmail }, { $set: { status: 'Online' } });
  
  const myContacts = await Contact.find({ ownerEmail: userEmail }).lean();
  const myFriends = await Contact.find({ friendEmail: userEmail }).lean();
  
  for (const friend of myFriends) {
    const friendSocketId = connectedUsers.get(friend.ownerEmail);
    if (friendSocketId) { io.to(friendSocketId).emit('friend status', { email: userEmail, status: 'Online' }); }
  }
  for (const contact of myContacts) {
      const friendSocketId = connectedUsers.get(contact.friendEmail);
      if(friendSocketId) {
          const friendUser = await User.findOne({ email: contact.friendEmail }).lean();
          if(friendUser) {
              const { canSeeLastSeen } = await canSeeInfo(userEmail, friendUser);
              if(canSeeLastSeen) { socket.emit('friend status', { email: contact.friendEmail, status: 'Online' }); }
          }
      }
  }

  socket.on('join room', async (roomId) => {
    let roomName = roomId;
    if (roomId.includes('@')) { roomName = getRoomName(userEmail, roomId); }
    socket.join(roomName);
    console.log(`[Wappy Socket] ${userEmail} joined room: ${roomName}`);
    const myGroups = await Group.find({ 'members.email': userEmail }).lean();
    myGroups.forEach(group => {
        socket.join(group.groupId);
        console.log(`[Wappy Socket] ${userEmail} auto-joined group room: ${group.groupId}`);
    });
  });
  // === NAYA: 'send message' (Puzzle Type ke saath) ===
  socket.on('send message', async (data) => {
    // KADAM 1: 'puzzleType' ko data se nikalo (default 'none')
    const { receiverId, text, tempId, replyTo, isTruthMode = false, puzzleType = 'none' } = data; 
    
    if (!text || text.trim() === "") { return; }
    const trimmedText = text.trim();
    const senderEmail = userEmail;
    const senderUser = await User.findOne({ email: senderEmail }).select('displayName').lean();
    const senderName = (senderUser && senderUser.displayName) ? senderUser.displayName : senderEmail.split('@')[0];

    const messageData = {
      messageId: nanoid(), 
      senderEmail, 
      senderName: senderName,
      receiverEmail: null, 
      receiverGroupId: null, 
      text: trimmedText,
      timestamp: Date.now(), 
      status: 'sent', 
      isDeleted: false,
      deletedBy: [], 
      replyTo: replyTo || null, 
      isStarred: false, 
      tempId: tempId,
      isTruthMode: isTruthMode,
      // KADAM 2: Puzzle type database mein save karo
      puzzleType: puzzleType 
    };
    
    let roomName = receiverId;
    let socketsToNotify = [];

    if (receiverId.includes('@')) {
        messageData.receiverEmail = receiverId;
        roomName = getRoomName(senderEmail, receiverId);
        const receiverContact = await Contact.findOne({ ownerEmail: receiverId, friendEmail: senderEmail }).lean();
        if (receiverContact && receiverContact.isBlocked) { return; }
        const senderContact = await Contact.findOne({ ownerEmail: senderEmail, friendEmail: receiverId }).lean();
        if (senderContact && senderContact.isBlocked) { return socket.emit('send error', { message: 'You have blocked this user. Unblock them to send a message.' }); }
        
        const receiverSocketId = connectedUsers.get(receiverId);
        if (receiverSocketId) { messageData.status = 'delivered'; socketsToNotify.push(receiverSocketId); }
        socketsToNotify.push(connectedUsers.get(senderEmail));
    } else {
        messageData.receiverGroupId = receiverId;
        const group = await Group.findOne({ groupId: receiverId }).lean();
        if (!group) return; 
        group.members.forEach(member => {
            const memberSocketId = connectedUsers.get(member.email);
            if (memberSocketId) { socketsToNotify.push(memberSocketId); }
        });
        messageData.status = 'delivered';
    }
    
    const newMessage = new Message(messageData);
    await newMessage.save();
    
    io.to(roomName).emit('new message', messageData);
    
    socketsToNotify.forEach(socketId => {
        if(socketId) io.to(socketId).emit('chat list update');
    });
    console.log(`[Wappy Socket] Message sent: ${trimmedText} (Truth:${isTruthMode}, Puzzle:${puzzleType})`);
  });

// === NAYA: 'delete message' (Truth Mode check ke saath) ===
socket.on('delete message', async (data) => {
    try {
      const { messageId } = data;
      const message = await Message.findOne({ messageId: messageId });
      
      // Check karo ki message hai ya nahi
      if (!message) {
        return socket.emit('send error', { message: 'Message not found.' });
      }
      
      // Check karo ki message bhej ne waala hi delete kar raha hai
      if (message.senderEmail !== userEmail) {
        return socket.emit('send error', { message: 'You can only delete your own messages.' });
      }
      
      // === NAYA: TRUTH MODE CHECK ===
      // Agar message Truth Mode mein tha, toh delete mat karo
      if (message.isTruthMode) {
        console.log(`[Wappy] DENIED delete for Truth Mode message: ${messageId}`);
        return socket.emit('send error', { message: 'This is a Truth Message and cannot be deleted.' });
      }
      // === END NAYA CHECK ===

      // Agar normal message hai, toh delete kar do
      message.text = "This message was deleted"; 
      message.isDeleted = true; 
      message.replyTo = null; // Reply bhi hata do
      await message.save();
      
      let roomName = '';
      if (message.receiverGroupId) { roomName = message.receiverGroupId; } 
      else { roomName = getRoomName(message.senderEmail, message.receiverEmail); }
      
      io.to(roomName).emit('message deleted', { messageId: messageId, text: message.text });
      io.to(roomName).emit('chat list update');
      
    } catch (error) { 
        console.error('[Wappy Error] Delete message error:', error); 
        socket.emit('send error', { message: 'Server error while deleting.' });
    }
  });

  socket.on('delete message', async (data) => {
    try {
      const { messageId } = data;
      const message = await Message.findOne({ messageId: messageId });
      if (message && message.senderEmail === userEmail) {
        message.text = "This message was deleted"; message.isDeleted = true; message.replyTo = null;
        await message.save();
        let roomName = '';
        if (message.receiverGroupId) { roomName = message.receiverGroupId; } 
        else { roomName = getRoomName(message.senderEmail, message.receiverEmail); }
        io.to(roomName).emit('message deleted', { messageId: messageId, text: message.text });
        io.to(roomName).emit('chat list update');
      }
    } catch (error) { console.error('[Wappy Error] Delete message error:', error); }
  });

  socket.on('delete for me', async (data) => {
    try {
      const { messageId } = data;
      const update = { $push: { deletedBy: userEmail } };
      await Message.updateOne({ messageId: messageId }, update);
      socket.emit('message removed', { messageId: messageId });
      socket.emit('chat list update');
    } catch (error) { console.error('[Wappy Error] Delete for me error:', error); }
  });

  socket.on('mark messages seen', async (data) => {
    const { chatId } = data;
    const myEmail = socket.user.email;
    try {
        const query = { status: { $ne: 'seen' }, senderEmail: { $ne: myEmail }, $or: [ { receiverEmail: myEmail, senderEmail: chatId }, { receiverGroupId: chatId } ] };
        const update = { $set: { status: 'seen' } };
        const result = await Message.updateMany(query, update);
        if (result.modifiedCount > 0) {
            console.log(`[Wappy Socket] Messages in chat ${chatId} marked as SEEN by ${myEmail}`);
            const updatedMessages = await Message.find({ ...query, status: 'seen' }).select('messageId status').lean();
            if (chatId.includes('@')) {
                const friendSocketId = connectedUsers.get(chatId);
                if (friendSocketId) { io.to(friendSocketId).emit('messages updated', updatedMessages); io.to(friendSocketId).emit('chat list update'); }
            } else {
                const group = await Group.findOne({ groupId: chatId }).lean();
                if (group) {
                    group.members.forEach(member => {
                        if (member.email !== myEmail) {
                            const memberSocketId = connectedUsers.get(member.email);
                            if (memberSocketId) { io.to(memberSocketId).emit('messages updated', updatedMessages); }
                        }
                    });
                }
            }
        }
    } catch (error) { console.error('[Wappy Error] Mark messages seen error:', error); }
  });

  socket.on('start typing', (data) => {
    const { chatId } = data;
    let roomName = chatId.includes('@') ? getRoomName(userEmail, chatId) : chatId;
    socket.to(roomName).emit('friend typing', { email: userEmail, chatId: chatId });
  });

  socket.on('stop typing', (data) => {
    const { chatId } = data;
    let roomName = chatId.includes('@') ? getRoomName(userEmail, chatId) : chatId;
    socket.to(roomName).emit('friend stopped typing', { email: userEmail, chatId: chatId });
  });

  socket.on('disconnect', async () => {
    console.log(`[Wappy Socket] User disconnected: ${userEmail}`);
    connectedUsers.delete(userEmail);
    const lastSeenTime = Date.now();
    await User.updateOne({ email: userEmail }, { $set: { status: 'Offline', lastSeen: lastSeenTime } });
    const friends = await Contact.find({ friendEmail: userEmail }).lean();
    for (const friend of friends) {
      const friendSocketId = connectedUsers.get(friend.ownerEmail);
      if (friendSocketId) { io.to(friendSocketId).emit('friend status', { email: userEmail, status: 'Offline', lastSeen: lastSeenTime }); }
    }
  });
});

// === NAYA: PROFESSIONAL ERROR HANDLING ===
// 404 Handler (File Not Found) - Ye hamesha baaki routes ke BAAD aana chahiye
app.use((req, res, next) => {
  const error = new Error(`Not Found - ${req.originalUrl}`);
  console.error(`[Wappy 404 Error] Path not found: ${req.originalUrl}`);
  res.status(404);
  next(error); // Error ko neeche global handler par bhejo
});

// Global Error Handler (500 Server Error)
app.use((err, req, res, next) => {
  const statusCode = res.statusCode === 200 ? 500 : res.statusCode; 
  res.status(statusCode);
  console.error('!!!!!!!!!!!!!!!!! GLOBAL ERROR CAUGHT !!!!!!!!!!!!!!!!!');
  console.error(`Error: ${err.message}`);
  console.error(`Stack: ${err.stack}`); // Poora technical error
  console.error('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!');
  res.json({
    message: err.message,
    stack: process.env.NODE_ENV === 'production' ? '🥞' : err.stack, 
  });
});
// === END ERROR HANDLING ===

// === Server ko Start Karna ===
async function startServer() {
  server.listen(PORT, () => {
    console.log('----------------------------------------------------');
    console.log(`🍉 Wappy server is UP and running!`);
    console.log(`📈 Listening on PORT: ${PORT}`);
    console.log(`🖥️ Local:   http://localhost:${PORT}`);
    console.log('----------------------------------------------------');
  });
}

startServer();

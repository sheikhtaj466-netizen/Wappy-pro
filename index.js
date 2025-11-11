// index.js (Kadam 35 - MongoDB FINAL - Part 1)
import express from 'express';
import http from 'http';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import { Server } from 'socket.io';
import { nanoid } from 'nanoid';
import dotenv from 'dotenv';
import sgMail from '@sendgrid/mail';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import rateLimit from 'express-rate-limit';
import mongoose from 'mongoose'; // MongoDB

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();
sgMail.setApiKey(process.env.SENDGRID_API_KEY);
const app = express();

// === RENDER PROXY FIX ===
// Ye line Render par 'express-rate-limit' ke 'X-Forwarded-For' error ko fix karti hai
app.set('trust proxy', 1);
// === END FIX ===

const server = http.createServer(app);
const io = new Server(server);
const PORT = 3000;
const JWT_SECRET = 'your-very-secret-key-12345';
const JWT_RESET_SECRET = 'your-password-reset-key-67890';
const connectedUsers = new Map();
const storage = multer.diskStorage({
  destination: 'public/uploads/avatars/',
  filename: function (req, file, cb) {
    const id = req.body.groupId || req.user.email;
    const extension = path.extname(file.originalname);
    cb(null, id + extension);
  }
});
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
  .then(() => console.log('MongoDB connected successfully!'))
  .catch(err => console.error('MongoDB connection error:', err));

// === NAYA: Mongoose Models (Schemas) ===

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, index: true },
    password: { type: String, required: true },
    displayName: { type: String, default: "" },
    avatarUrl: { type: String, default: "" },
    status: { type: String, default: "Offline" },
    lastSeen: { type: Number, default: 0 },
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
    isStarred: { type: Boolean, default: false } // Kadam 35
});
const Message = mongoose.model('Message', messageSchema);


// (Middleware & ProtectRoute)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const protectRoute = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) { return res.redirect('/login.html'); }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { email: "..." }
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
    const user = await User.findOne({ email: decoded.email }).lean(); // .lean() faster read-only
    if (!user) { return next(new Error('User not found')); }
    socket.user = user;
    next();
  } catch (err) {
    next(new Error('Authentication error'));
  }
});

const getRoomName = (email1, email2) => [email1, email2].sort().join('-');

// === HTTP Routes (Updated for MongoDB) ===

app.get('/', protectRoute, (req, res) => { res.redirect('/chats.html'); });
app.get('/home.html', protectRoute, async (req, res) => {
  const user = await User.findOne({ email: req.user.email }).lean();
  if (!user || !user.displayName || user.displayName === "") { return res.redirect('/set-name.html'); }
  res.sendFile(path.join(__dirname, 'public', 'home.html'));
});
app.get('/chats.html', protectRoute, async (req, res) => {
  const user = await User.findOne({ email: req.user.email }).lean();
  if (!user || !user.displayName || user.displayName === "") { return res.redirect('/set-name.html'); }
  res.sendFile(path.join(__dirname, 'public', 'chats.html'));
});
app.get('/chat.html', protectRoute, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'chat.html'));
});
app.get('/profile.html', protectRoute, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});
app.get('/create-group.html', protectRoute, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'create-group.html'));
});

app.get('/api/me', protectRoute, async (req, res) => {
  const user = await User.findOne({ email: req.user.email }).select('-password').lean();
  res.json(user);
});

async function canSeeInfo(requesterEmail, targetUser) {
    const isContact = await Contact.findOne({ ownerEmail: targetUser.email, friendEmail: requesterEmail });
    let canSeeAvatar = false;
    if (targetUser.privacy.avatar === 'everyone') {
        canSeeAvatar = true;
    } else if (targetUser.privacy.avatar === 'contacts' && isContact) {
        canSeeAvatar = true;
    }
    let canSeeLastSeen = false;
    if (targetUser.privacy.lastSeen === 'everyone') {
        canSeeLastSeen = true;
    } else if (targetUser.privacy.lastSeen === 'contacts' && isContact) {
        canSeeLastSeen = true;
    }
    return { canSeeAvatar, canSeeLastSeen };
}

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
        isBlocked: contact.isBlocked
      });
    } else { res.status(404).json({ message: 'Contact not found' }); }
  } catch (error) { res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/groupinfo/:groupId', protectRoute, async (req, res) => {
    try {
        const groupId = req.params.groupId;
        const group = await Group.findOne({ groupId: groupId }).lean();
        
        if (!group) {
            return res.status(404).json({ message: "Group not found" });
        }
        
        const isMember = group.members.some(m => m.email === req.user.email);
        if (!isMember) {
            return res.status(403).json({ message: "You are not a member of this group" });
        }
        
        // Member details ko populate karo
        const detailedMembers = await Promise.all(group.members.map(async (member) => {
            const user = await User.findOne({ email: member.email }).select('displayName').lean();
            return {
                email: member.email,
                role: member.role,
                displayName: (user && user.displayName) ? user.displayName : member.email.split('@')[0]
            };
        }));
        
        res.json({ ...group, members: detailedMembers });
        
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/messages/:id', protectRoute, async (req, res) => {
  const myEmail = req.user.email;
  const id = req.params.id;
  const cursor = req.query.cursor ? parseInt(req.query.cursor) : Date.now();
  
  const query = {
      $and: [
          { timestamp: { $lt: cursor } },
          { deletedBy: { $nin: [myEmail] } },
          { $or: [
              // 1-to-1 chats
              { senderEmail: myEmail, receiverEmail: id },
              { senderEmail: id, receiverEmail: myEmail },
              // Group chats
              { receiverGroupId: id }
          ]}
      ]
  };

  try {
      const messages = await Message.find(query)
          .sort({ timestamp: -1 }) // Naye se puraana
          .limit(MESSAGES_PER_PAGE)
          .lean();
      
      const nextCursor = messages.length === MESSAGES_PER_PAGE ? messages[messages.length - 1].timestamp : null;
      
      res.json({ messages: messages.reverse(), nextCursor: nextCursor }); // Waapas puraane se naya bhejo
  } catch (error) {
      console.error("Error fetching messages:", error);
      res.status(500).json({ message: "Server error" });
  }
});

app.get('/api/contacts', protectRoute, async (req, res) => {
  try {
    const ownerEmail = req.user.email;
    const searchQuery = req.query.q || '';
    
    let query = { ownerEmail: ownerEmail };
    if (searchQuery) {
        query.nickname = { $regex: searchQuery, $options: 'i' }; // 'i' = case-insensitive
    }
    
    const myContacts = await Contact.find(query).lean();
    
    const detailedContacts = await Promise.all(myContacts.map(async (contact) => {
      const friendUser = await User.findOne({ email: contact.friendEmail }).lean();
      if (!friendUser) return null;
      const { canSeeAvatar, canSeeLastSeen } = await canSeeInfo(ownerEmail, friendUser);
      return { 
        ...contact, 
        status: canSeeLastSeen ? friendUser.status : 'Offline', 
        lastSeen: canSeeLastSeen ? friendUser.lastSeen : 0,
        avatarUrl: canSeeAvatar ? friendUser.avatarUrl : '' 
      };
    }));
    
    const finalContacts = detailedContacts.filter(Boolean);

    finalContacts.sort((a, b) => {
      if (a.isPinned && !b.isPinned) return -1;
      if (!a.isPinned && b.isPinned) return 1;
      return a.nickname.localeCompare(b.nickname);
    });
    
    res.json(finalContacts);
  } catch (error) { console.error('Get contacts error:', error); res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/chats', protectRoute, async (req, res) => {
    try {
        const myEmail = req.user.email;
        const searchQuery = req.query.q || '';
        
        // 1. Find all messages involving the user
        const allMessages = await Message.find({
            $and: [
                { deletedBy: { $nin: [myEmail] } },
                { $or: [
                    { senderEmail: myEmail },
                    { receiverEmail: myEmail },
                    { receiverGroupId: { $in: (await Group.find({ 'members.email': myEmail }).select('groupId').lean()).map(g => g.groupId) } }
                ]}
            ]
        }).sort({ timestamp: -1 }).lean(); // Sort by new to old to easily find the last one

        const conversations = new Map();
        allMessages.forEach(msg => {
            let convoId = '';
            let isGroup = false;

            if (msg.receiverGroupId) {
                convoId = msg.receiverGroupId;
                isGroup = true;
            } else {
                convoId = msg.senderEmail === myEmail ? msg.receiverEmail : msg.senderEmail;
            }
            
            if (!conversations.has(convoId)) { // Since they are sorted, the first one we find is the last message
                conversations.set(convoId, {
                    id: convoId,
                    isGroup: isGroup,
                    text: msg.isDeleted ? "This message was deleted" : msg.text,
                    timestamp: msg.timestamp,
                    senderEmail: msg.senderEmail,
                    status: msg.status
                });
            }
        });

        const chatList = Array.from(conversations.values());
        
        let detailedChatList = await Promise.all(chatList.map(async (chat) => {
            if (chat.isGroup) {
                const group = await Group.findOne({ groupId: chat.id }).lean();
                if (!group) return null;
                return {
                    ...chat,
                    nickname: group.groupName,
                    avatarUrl: group.groupAvatar || '',
                    isPinned: false // (Group pinning abhi nahi)
                };
            } else {
                const contact = await Contact.findOne({ ownerEmail: myEmail, friendEmail: chat.id }).lean();
                const friendUser = await User.findOne({ email: chat.id }).lean();
                if (!contact || !friendUser) return null;
                const { canSeeAvatar } = await canSeeInfo(myEmail, friendUser);
                return {
                    ...chat,
                    nickname: contact.nickname,
                    avatarUrl: canSeeAvatar ? friendUser.avatarUrl : '',
                    isPinned: contact.isPinned
                };
            }
        }));
        
        detailedChatList = detailedChatList.filter(Boolean);

        if (searchQuery) {
            detailedChatList = detailedChatList.filter(c => 
                c.nickname.toLowerCase().includes(searchQuery.toLowerCase())
            );
        }

        detailedChatList.sort((a, b) => {
            if (a.isPinned && !b.isPinned) return -1;
            if (!a.isPinned && b.isPinned) return 1;
            return b.timestamp - a.timestamp;
        });

        res.json(detailedChatList);

    } catch (error) {
        console.error('Get chats error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});
// index.js (Kadam C.3 - MongoDB Update - Part 2)
// [NOTE: Aapke original code mein '/api/chats' route do baar tha, maine ek remove kar diya hai]
// [Aapka doosra '/api/chats' route yahan se shuru hota tha, woh duplicate tha]

app.post('/api/upload-avatar', protectRoute, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) { return res.status(400).send('No file uploaded.'); }
    const avatarUrl = `/uploads/avatars/${req.file.filename}`;
    
    await User.updateOne({ email: req.user.email }, { $set: { avatarUrl: avatarUrl } });
    
    console.log(`Avatar updated for ${req.user.email}: ${avatarUrl}`);
    res.redirect('/profile.html');
  } catch (error) { console.error('Avatar upload error:', error); res.status(500).send('Server error'); }
});
app.post('/api/toggle-block', protectRoute, async (req, res) => {
  try {
    const { friendEmail } = req.body;
    const ownerEmail = req.user.email;
    
    const contact = await Contact.findOne({ ownerEmail: ownerEmail, friendEmail: friendEmail });
    if (contact) {
      contact.isBlocked = !contact.isBlocked; 
      await contact.save();
      const status = contact.isBlocked ? 'blocked' : 'unblocked';
      console.log(`User ${ownerEmail} ${status} ${friendEmail}`);
      res.json({ message: `User ${status}`, isBlocked: contact.isBlocked });
    } else {
      res.status(404).send('Contact not found');
    }
  } catch (error) {
    console.error('Toggle block error:', error);
    res.status(500).send('Server error');
  }
});
app.post('/api/toggle-pin', protectRoute, async (req, res) => {
  try {
    const { friendEmail } = req.body;
    const ownerEmail = req.user.email;
    const contact = await Contact.findOne({ ownerEmail: ownerEmail, friendEmail: friendEmail });
    if (contact) {
      contact.isPinned = !contact.isPinned; 
      await contact.save();
      const status = contact.isPinned ? 'pinned' : 'unpinned';
      console.log(`User ${ownerEmail} ${status} chat with ${friendEmail}`);
      res.json({ message: `Chat ${status}`, isPinned: contact.isPinned });
    } else {
      res.status(404).send('Contact not found');
    }
  } catch (error) {
    console.error('Toggle pin error:', error);
    res.status(500).send('Server error');
  }
});
app.post('/api/update-privacy', protectRoute, async (req, res) => {
    try {
        const { lastSeen, avatar } = req.body;
        const myEmail = req.user.email;
        const validOptions = ["everyone", "contacts", "nobody"];
        if (!validOptions.includes(lastSeen) || !validOptions.includes(avatar)) {
            return res.status(400).json({ message: "Invalid options" });
        }
        
        await User.updateOne(
            { email: myEmail }, 
            { $set: { 'privacy.lastSeen': lastSeen, 'privacy.avatar': avatar } }
        );
        
        console.log(`Privacy updated for ${myEmail}`);
        res.json({ message: "Privacy settings updated" });
    } catch (error) {
        console.error('Update privacy error:', error);
        res.status(500).json({ message: "Server error" });
    }
});
app.post('/api/create-group', protectRoute, async (req, res) => {
    try {
        let { groupName, members } = req.body;
        const creatorEmail = req.user.email;

        if (!groupName || !members || members.length === 0) {
            return res.status(400).json({ message: "Group name and members are required." });
        }
        
        const memberObjects = members.map(email => ({
            email: email,
            role: "member"
        }));
        memberObjects.push({ email: creatorEmail, role: "admin" });
        
        const newGroup = new Group({
            groupId: nanoid(),
            groupName: groupName,
            groupAvatar: "",
            creatorEmail: creatorEmail,
            members: memberObjects
        });
        
        await newGroup.save();
        
        console.log(`New group created: ${groupName} by ${creatorEmail}`);
        res.status(201).json({ message: "Group created!", group: newGroup });

    } catch (error) {
        console.error('Create group error:', error);
        res.status(500).json({ message: "Server error" });
    }
});

app.post('/api/toggle-star', protectRoute, async (req, res) => {
    try {
        const { messageId } = req.body;
        const myEmail = req.user.email;

        const message = await Message.findOne({ messageId: messageId });

        if (!message) {
            return res.status(404).json({ message: "Message not found" });
        }
        
        let isMyChat = false;
        if (message.receiverGroupId) {
            const group = await Group.findOne({ groupId: message.receiverGroupId }).lean();
            isMyChat = group && group.members.some(m => m.email === myEmail);
        } else {
            isMyChat = (message.senderEmail === myEmail) || (message.receiverEmail === myEmail);
        }

        if (!isMyChat) {
            return res.status(403).json({ message: "Not authorized" });
        }

        message.isStarred = !message.isStarred;
        await message.save();
        
        const status = message.isStarred ? 'starred' : 'unstarred';
        console.log(`Message ${messageId} ${status} by ${myEmail}`);
        
        let roomName = message.receiverGroupId 
            ? message.receiverGroupId 
            : getRoomName(message.senderEmail, message.receiverEmail);
            
        io.to(roomName).emit('message starred', { 
            messageId: message.messageId, 
            isStarred: message.isStarred 
        });
        
        res.json({ message: `Message ${status}`, isStarred: message.isStarred });

    } catch (error) {
        console.error('Star message error:', error);
        res.status(500).json({ message: "Server error" });
    }
});

// === Authentication Routes (Updated for MongoDB) ===
// === Authentication Routes (Updated for MongoDB) ===
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Check 1: Kya user pehle se hai?
    console.log(`Register attempt: Checking if user exists: ${email}`);
    let existingUser = await User.findOne({ email: email }).lean();
    if (existingUser) { 
      console.log(`Register failed: User already exists: ${email}`);
      return res.status(400).send('User already exists'); 
    }
    
    // Check 2: Password hashing
    console.log(`Register attempt: Hashing password for ${email}`);
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Check 3: Naya user object banana
    const newUser = new User({ 
      email: email, 
      password: hashedPassword,
      displayName: email.split('@')[0] // Default display name
    });
    
    // Check 4: Database mein save karna (YAHAN ERROR HO SAKTA HAI)
    console.log(`Register attempt: Saving new user ${email} to database...`);
    await newUser.save();
    console.log(`NEW USER REGISTERED: ${email}`);
    
    // Check 5: Welcome email bhejna (YA YAHAN ERROR HO SAKTA HAI)
        // Check 5: Welcome email bhejna (with SendGrid)
    try {
      console.log(`Register attempt: Sending welcome email to ${email} via SendGrid...`);
      
      const msg = {
        to: email, // Naye user ka email
        from: process.env.EMAIL_USER, // Aapka SendGrid par verified email
        subject: 'Welcome to Wappy! 🍉',
        text: `Welcome, ${email}! Thank you for joining Wappy. You can now login and start chatting with your friends.`, // Ye unke liye jinko HTML nahi dikhta
        
        // Ye hai Professional HTML Email
        html: `
          <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: auto; border: 1px solid #ddd; border-radius: 8px; overflow: hidden;">
            <div style="background-color: #22c55e; color: white; padding: 20px; text-align: center;">
              <h1 style="margin: 0; font-size: 28px;">Welcome to Wappy! 🍉</h1>
            </div>
            <div style="padding: 30px;">
              <p style="font-size: 18px;">Hello ${email},</p>
              <p>Thank you for joining Wappy. We're excited to have you on board!</p>
              <p>You can now log in and start chatting with your friends and family.</p>
              <a href="https://wappy.onrender.com/login.html" style="background-color: #22c55e; color: white; padding: 12px 25px; text-decoration: none; border-radius: 5px; display: inline-block; margin-top: 20px; font-weight: bold;">
                Login to Your Account
              </a>
              <p style="margin-top: 30px; font-size: 14px; color: #777;">
                If you did not sign up for this account, you can safely ignore this email.
              </p>
              <hr style="border: 0; border-top: 1px solid #eee; margin-top: 20px;">
              <p style="font-size: 12px; color: #999; text-align: center;">&copy; ${new Date().getFullYear()} Wappy. All rights reserved.</p>
            </div>
          </div>
        `
      };
      
      await sgMail.send(msg);
      console.log(`Welcome email sent to: ${email}`);
      
    } catch (emailError) { 
      // Agar SendGrid fail ho (bohot kam hota hai)
      console.error(`--- SENDGRID EMAIL FAILED but user was registered ---`);
      if (emailError.response) {
        console.error(emailError.response.body); // SendGrid ke asli error
      } else {
        console.error(emailError);
      }
      console.error(`--- END SENDGRID ERROR ---`);
    }
    
    res.redirect('/login.html');

  } catch (error) { 
    // YEH HAI ASAL FIX
    // Agar upar kahin bhi (DB save, bcrypt) error aaye, toh yahan log hoga
    console.error('!!!!!!!!!!!!!!!!! REGISTER FAILED !!!!!!!!!!!!!!!!!');
    console.error('An error occurred in the POST /register route:');
    console.error(error); // Error ko terminal mein print karo
    console.error('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!');
    res.status(500).send('Server error. Check terminal logs.'); 
  }
});
app.post('/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email: email }).lean();
    if (!user) { 
      return res.status(400).send('Invalid email or password'); 
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) { 
      return res.status(400).send('Invalid email or password'); 
    }
    const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true, maxAge: 60 * 60 * 1000 });
    console.log(`USER LOGGED IN: ${email}`);
    res.redirect('/chats.html');
  } catch (error) { res.status(500).send('Server error'); }
});

app.post('/set-name', protectRoute, async (req, res) => {
  try {
    const { displayName } = req.body;
    await User.updateOne({ email: req.user.email }, { $set: { displayName: displayName } });
    console.log(`DISPLAY NAME SET for ${req.user.email}: ${displayName}`);
    res.redirect('/chats.html');
  } catch (error) { res.status(500).send('Server error'); }
});

app.post('/add-friend', protectRoute, async (req, res) => {
  try {
    const { friendEmail, nickname } = req.body;
    const ownerEmail = req.user.email;
    if (friendEmail === ownerEmail) { return res.status(400).send("You cannot add yourself."); }
    
    const friendExists = await User.findOne({ email: friendEmail }).lean();
    if (!friendExists) { return res.status(404).send("User with this email does not exist."); }
    
    const alreadyFriend = await Contact.findOne({ ownerEmail: ownerEmail, friendEmail: friendEmail }).lean();
    if (alreadyFriend) { return res.status(400).send("This user is already in your contacts."); }
    
    const newContact = new Contact({ 
      ownerEmail: ownerEmail, 
      friendEmail: friendEmail, 
      nickname: nickname || friendExists.displayName || friendEmail.split('@')[0]
    });
    await newContact.save();
    
    console.log(`NEW FRIEND added for ${ownerEmail}: ${friendEmail}`);
    res.redirect('/home.html');
  } catch (error) { console.error('Add friend error:', error); res.status(500).send('Server error'); }
});

app.get('/logout', (req, res) => {
  res.cookie('token', '', { maxAge: 1 });
  res.redirect('/login.html');
});

app.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email: email }).lean();
    if (!user) {
      console.log(`Password reset attempt for non-existent user: ${email}`);
      return res.send("If this email is registered, you will receive a reset link.");
    }
    const resetToken = jwt.sign({ email: user.email }, JWT_RESET_SECRET, { expiresIn: '10m' });
    const resetUrl = `http://localhost:3000/reset-password.html?token=${resetToken}`;
    await transporter.sendMail({
      from: `"Wappy Support" <${process.env.EMAIL_USER}>`,
      to: user.email,
      subject: "Your Wappy Password Reset Link",
      html: `<p>Hello ${user.displayName || user.email},</p><p>Click the link below to reset your password. This link is valid for 10 minutes only.</p><a href="${resetUrl}" style="padding: 10px 20px; background-color: #22c55e; color: white; text-decoration: none; border-radius: 5px;">Reset Your Password</a><p>If you did not request this, please ignore this email.</p>`
    });
    console.log(`Password reset link sent to: ${email}`);
    res.send("Password reset link has been sent to your email.");
  } catch (error) { console.error('Forgot password error:', error); res.status(500).send('Server error'); }
});

app.post('/reset-password', async (req, res) => {
  try {
    const { token } = req.query;
    const { password } = req.body;
    if (!token) { return res.status(400).send('Invalid token'); }
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_RESET_SECRET);
    } catch (err) {
      return res.status(400).send('Invalid or expired token. Please try again.');
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    await User.updateOne({ email: decoded.email }, { $set: { password: hashedPassword } });
    
    console.log(`Password reset SUCCESS for: ${decoded.email}`);
    res.redirect('/login.html');
  } catch (error) { console.error('Reset password error:', error); res.status(500).send('Server error'); }
});
// index.js (Kadam C.3 - MongoDB Update - Part 3)
io.on('connection', async (socket) => {
  const userEmail = socket.user.email;
  console.log(`User connected (1-to-1): ${userEmail}`);
  connectedUsers.set(userEmail, socket.id);
  
  await User.updateOne({ email: userEmail }, { $set: { status: 'Online' } });
  
  // NAYA: Socket ko bhi batao ki dost online hai (Chats page ke liye)
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
              if(canSeeLastSeen) {
                  socket.emit('friend status', { email: contact.friendEmail, status: 'Online' });
              }
          }
      }
  }


  // (getRoomName function ab global hai)

  // === NAYA: join room (Updated) ===
  socket.on('join room', async (roomId) => {
    let roomName = roomId;
    if (roomId.includes('@')) {
        roomName = getRoomName(userEmail, roomId);
    }
    
    socket.join(roomName);
    console.log(`${userEmail} joined room: ${roomName}`);
    
    // NAYA: Group ke saare rooms (sockets) ko join karo
    const myGroups = await Group.find({ 'members.email': userEmail }).lean();
    myGroups.forEach(group => {
        socket.join(group.groupId);
        console.log(`${userEmail} auto-joined group room: ${group.groupId}`);
    });
  });

  // === NAYA: send message (Updated) ===
  socket.on('send message', async (data) => {
    
    const { receiverId, text, tempId, replyTo } = data; 
    
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
      tempId: tempId
    };
    
    let roomName = receiverId;
    let socketsToNotify = [];

    if (receiverId.includes('@')) {
        // === 1-to-1 Chat Logic ===
        messageData.receiverEmail = receiverId;
        roomName = getRoomName(senderEmail, receiverId);

        const receiverContact = await Contact.findOne({ ownerEmail: receiverId, friendEmail: senderEmail }).lean();
        if (receiverContact && receiverContact.isBlocked) { return; }
        const senderContact = await Contact.findOne({ ownerEmail: senderEmail, friendEmail: receiverId }).lean();
        if (senderContact && senderContact.isBlocked) {
          return socket.emit('send error', { message: 'You have blocked this user. Unblock them to send a message.' });
        }
        
        const receiverSocketId = connectedUsers.get(receiverId);
        if (receiverSocketId) {
            messageData.status = 'delivered';
            socketsToNotify.push(receiverSocketId);
        }
        socketsToNotify.push(connectedUsers.get(senderEmail));
        
    } else {
        // === Group Chat Logic ===
        messageData.receiverGroupId = receiverId;
        const group = await Group.findOne({ groupId: receiverId }).lean();
        if (!group) return; 
        
        group.members.forEach(member => {
            const memberSocketId = connectedUsers.get(member.email);
            if (memberSocketId) {
                socketsToNotify.push(memberSocketId);
            }
        });
        messageData.status = 'delivered';
    }

    const newMessage = new Message(messageData);
    await newMessage.save();
    
    io.to(roomName).emit('new message', messageData);
    
    socketsToNotify.forEach(socketId => {
        if(socketId) io.to(socketId).emit('chat list update');
    });
    
    console.log(`Message sent to room ${roomName}: ${trimmedText}`);
  });
  
  socket.on('delete message', async (data) => {
    try {
      const { messageId } = data;
      const message = await Message.findOne({ messageId: messageId });
      
      if (message && message.senderEmail === userEmail) {
        message.text = "This message was deleted";
        message.isDeleted = true;
        message.replyTo = null;
        await message.save();
        
        let roomName = '';
        if (message.receiverGroupId) {
            roomName = message.receiverGroupId;
        } else {
            roomName = getRoomName(message.senderEmail, message.receiverEmail);
        }
        
        io.to(roomName).emit('message deleted', { messageId: messageId, text: message.text });
        io.to(roomName).emit('chat list update');
      }
    } catch (error) { console.error('Delete message error:', error); }
  });

  socket.on('delete for me', async (data) => {
    try {
      const { messageId } = data;
      // 'Delete for me' sirf user ke local state mein hota hai, lekin hume DB mein track karna hai
      const update = { $push: { deletedBy: userEmail } };
      await Message.updateOne({ messageId: messageId }, update);

      socket.emit('message removed', { messageId: messageId });
      socket.emit('chat list update');
    } catch (error) {
      console.error('Delete for me error:', error);
    }
  });

  socket.on('mark messages seen', async (data) => {
    const { chatId } = data;
    const myEmail = socket.user.email;

    try {
        const query = {
            status: { $ne: 'seen' },
            senderEmail: { $ne: myEmail },
            $or: [
                { receiverEmail: myEmail, senderEmail: chatId },
                { receiverGroupId: chatId }
            ]
        };
        
        const update = { $set: { status: 'seen' } };
        const result = await Message.updateMany(query, update);

        if (result.modifiedCount > 0) {
            console.log(`Messages in chat ${chatId} marked as SEEN by ${myEmail}`);
            
            const updatedMessages = await Message.find({
                ...query,
                status: 'seen' // Find the ones we just updated
            }).select('messageId status').lean();

            if (chatId.includes('@')) {
                const friendSocketId = connectedUsers.get(chatId);
                if (friendSocketId) {
                    io.to(friendSocketId).emit('messages updated', updatedMessages);
                    io.to(friendSocketId).emit('chat list update');
                }
            } else {
                const group = await Group.findOne({ groupId: chatId }).lean();
                if (group) {
                    group.members.forEach(member => {
                        if (member.email !== myEmail) {
                            const memberSocketId = connectedUsers.get(member.email);
                            if (memberSocketId) {
                                io.to(memberSocketId).emit('messages updated', updatedMessages);
                            }
                        }
                    });
                }
            }
        }
    } catch (error) {
        console.error('Mark messages seen error:', error);
    }
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
    console.log(`User disconnected (1-to-1): ${userEmail}`);
    connectedUsers.delete(userEmail);
    const lastSeenTime = Date.now();
    
    await User.updateOne({ email: userEmail }, { $set: { status: 'Offline', lastSeen: lastSeenTime } });
    
    const friends = await Contact.find({ friendEmail: userEmail }).lean();
    for (const friend of friends) {
      const friendSocketId = connectedUsers.get(friend.ownerEmail);
      if (friendSocketId) {
        io.to(friendSocketId).emit('friend status', { email: userEmail, status: 'Offline', lastSeen: lastSeenTime });
      }
    }
  });
});

// === Server ko Start Karna ===
async function startServer() {
  // initializeDatabase() ki zaroorat nahi, MongoDB models khud handle karte hain
  server.listen(PORT, () => {
    console.log(`🍉 Wappy server http://localhost:${PORT} par chal raha hai`);
  });
}

startServer();

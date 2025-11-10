// index.js (Kadam 35.4 - Star FIX - Part 1)
import express from 'express';
import http from 'http';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import db from './db.js';
import { Server } from 'socket.io';
import { nanoid } from 'nanoid';
import dotenv from 'dotenv';
import nodemailer from 'nodemailer';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import rateLimit from 'express-rate-limit';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();
const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = 3000;
const JWT_SECRET = 'your-very-secret-key-12345';
const JWT_RESET_SECRET = 'your-password-reset-key-67890';
const connectedUsers = new Map();
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});
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

async function initializeDatabase() {
  await db.read();
  let needsUpdate = false;
  if (!db.data.users) { db.data.users = []; needsUpdate = true; }
  if (!db.data.contacts) { db.data.contacts = []; needsUpdate = true; }
  if (!db.data.messages) { db.data.messages = []; needsUpdate = true; }
  if (!db.data.groups) { db.data.groups = []; needsUpdate = true; }

  db.data.users.forEach(user => {
    if (user.status === undefined) { user.status = 'Offline'; needsUpdate = true; }
    if (user.lastSeen === undefined) { user.lastSeen = 0; needsUpdate = true; }
    if (user.avatarUrl === undefined) { user.avatarUrl = ''; needsUpdate = true; }
    if (user.privacy === undefined) {
      user.privacy = { lastSeen: "everyone", avatar: "everyone" };
      needsUpdate = true;
    }
  });
  db.data.messages.forEach(msg => {
    if (msg.isDeleted === undefined) { msg.isDeleted = false; needsUpdate = true; }
    if (msg.deletedBy === undefined) { msg.deletedBy = []; needsUpdate = true; }
    if (msg.receiverGroupId === undefined) { msg.receiverGroupId = null; needsUpdate = true; }
    if (msg.senderName === undefined) { msg.senderName = ''; needsUpdate = true; }
    if (msg.replyTo === undefined) { msg.replyTo = null; needsUpdate = true; }
    if (msg.isStarred === undefined) { msg.isStarred = false; needsUpdate = true; }
  });
  db.data.contacts.forEach(contact => {
    if (contact.isBlocked === undefined) { contact.isBlocked = false; needsUpdate = true; }
    if (contact.isPinned === undefined) {
      contact.isPinned = false;
      needsUpdate = true;
    }
  });
  if (needsUpdate) {
    console.log('Database structure ko fix kiya ja raha (Kadam 35)...');
    await db.write();
    console.log('Database fix ho gaya!');
  }
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

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
    await db.read();
    const user = db.data.users.find(u => u.email === decoded.email);
    if (!user) { return next(new Error('User not found')); }
    socket.user = user;
    next();
  } catch (err) {
    next(new Error('Authentication error'));
  }
});

// === NAYA FIX: getRoomName ko yahan (global) define kiya ===
const getRoomName = (email1, email2) => [email1, email2].sort().join('-');

app.get('/', protectRoute, (req, res) => { res.redirect('/chats.html'); });
app.get('/home.html', protectRoute, async (req, res) => {
  await db.read();
  const user = db.data.users.find(u => u.email === req.user.email);
  if (!user.displayName || user.displayName === "") { return res.redirect('/set-name.html'); }
  res.sendFile(path.join(__dirname, 'public', 'home.html'));
});
app.get('/chats.html', protectRoute, async (req, res) => {
  await db.read();
  const user = db.data.users.find(u => u.email === req.user.email);
  if (!user.displayName || user.displayName === "") { return res.redirect('/set-name.html'); }
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
  await db.read();
  const user = db.data.users.find(u => u.email === req.user.email);
  res.json({ email: user.email, displayName: user.displayName, avatarUrl: user.avatarUrl, privacy: user.privacy });
});
function canSeeInfo(requesterEmail, targetUser) {
    const isContact = db.data.contacts.some(
        c => c.ownerEmail === targetUser.email && c.friendEmail === requesterEmail
    );
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
    await db.read();
    const friendEmail = req.params.email;
    const ownerEmail = req.user.email;
    const contact = db.data.contacts.find(c => c.ownerEmail === ownerEmail && c.friendEmail === friendEmail);
    const friendUser = db.data.users.find(u => u.email === friendEmail);
    if (contact && friendUser) {
      const { canSeeAvatar, canSeeLastSeen } = canSeeInfo(ownerEmail, friendUser);
      res.json({ email: contact.friendEmail, displayName: contact.nickname, status: canSeeLastSeen ? friendUser.status : 'Offline', lastSeen: canSeeLastSeen ? friendUser.lastSeen : 0, avatarUrl: canSeeAvatar ? friendUser.avatarUrl : '', isBlocked: contact.isBlocked });
    } else { res.status(404).json({ message: 'Contact not found' }); }
  } catch (error) { res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/groupinfo/:groupId', protectRoute, async (req, res) => {
    try {
        await db.read();
        const groupId = req.params.groupId;
        const group = db.data.groups.find(g => g.groupId === groupId);
        
        if (!group) {
            return res.status(404).json({ message: "Group not found" });
        }
        
        const isMember = group.members.some(m => m.email === req.user.email);
        if (!isMember) {
            return res.status(403).json({ message: "You are not a member of this group" });
        }
        
        const detailedMembers = group.members.map(member => {
            const user = db.data.users.find(u => u.email === member.email);
            return {
                email: member.email,
                role: member.role,
                displayName: (user && user.displayName) ? user.displayName : member.email.split('@')[0]
            };
        });
        
        res.json({ ...group, members: detailedMembers });
        
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/messages/:id', protectRoute, async (req, res) => {
  const myEmail = req.user.email;
  const id = req.params.id;
  const cursor = req.query.cursor ? parseInt(req.query.cursor) : Date.now();
  await db.read();
  
  const allMessages = db.data.messages.filter(msg => {
    if (msg.deletedBy.includes(myEmail)) { return false; }
    const isGroupChat = msg.receiverGroupId === id;
    const isPrivateChat = (msg.senderEmail === myEmail && msg.receiverEmail === id) ||
                         (msg.senderEmail === id && msg.receiverEmail === myEmail);
    return isGroupChat || isPrivateChat;
  });

  allMessages.sort((a, b) => b.timestamp - a.timestamp);
  const startIndex = allMessages.findIndex(msg => msg.timestamp < cursor);
  if (startIndex === -1 && cursor !== Date.now()) {
    return res.json({ messages: [], nextCursor: null });
  }
  const start = (startIndex === -1) ? 0 : startIndex;
  const end = start + MESSAGES_PER_PAGE;
  
  const messages = allMessages.slice(start, end).map(msg => {
      let senderName = msg.senderName;
      if (!senderName) {
          const sender = db.data.users.find(u => u.email === msg.senderEmail);
          senderName = (sender && sender.displayName) ? sender.displayName : msg.senderEmail.split('@')[0];
      }
      return { ...msg, senderName: senderName };
  });
  
  const nextCursor = messages.length === MESSAGES_PER_PAGE ? messages[messages.length - 1].timestamp : null;
  messages.reverse();
  res.json({ messages, nextCursor });
});

app.get('/api/contacts', protectRoute, async (req, res) => {
  try {
    const ownerEmail = req.user.email;
    const searchQuery = req.query.q || '';
    await db.read();
    let myContacts = db.data.contacts.filter(c => c.ownerEmail === ownerEmail);
    if (searchQuery) {
        myContacts = myContacts.filter(c => 
            c.nickname.toLowerCase().includes(searchQuery.toLowerCase())
        );
    }
    const detailedContacts = myContacts.map(contact => {
      const friendUser = db.data.users.find(u => u.email === contact.friendEmail);
      if (!friendUser) return null;
      const { canSeeAvatar, canSeeLastSeen } = canSeeInfo(ownerEmail, friendUser);
      return { ...contact, status: canSeeLastSeen ? friendUser.status : 'Offline', lastSeen: canSeeLastSeen ? friendUser.lastSeen : 0, avatarUrl: canSeeAvatar ? friendUser.avatarUrl : '' };
    }).filter(Boolean);
    detailedContacts.sort((a, b) => {
      if (a.isPinned && !b.isPinned) return -1;
      if (!a.isPinned && b.isPinned) return 1;
      return a.nickname.localeCompare(b.nickname);
    });
    res.json(detailedContacts);
  } catch (error) { console.error('Get contacts error:', error); res.status(500).json({ message: 'Server error' }); }
});
// index.js (Kadam 35.4 - Star FIX - Part 2)
app.get('/api/chats', protectRoute, async (req, res) => {
    try {
        const myEmail = req.user.email;
        const searchQuery = req.query.q || '';
        await db.read();

        const allMessages = db.data.messages.filter(msg => 
            (msg.senderEmail === myEmail || msg.receiverEmail === myEmail || 
             (msg.receiverGroupId && db.data.groups.find(g => g.groupId === msg.receiverGroupId)?.members.some(m => m.email === myEmail))) &&
            !msg.deletedBy.includes(myEmail)
        );
        
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
            
            if (!conversations.has(convoId) || msg.timestamp > conversations.get(convoId).timestamp) {
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
        
        let detailedChatList = chatList.map(chat => {
            if (chat.isGroup) {
                const group = db.data.groups.find(g => g.groupId === chat.id);
                if (!group) return null;
                return {
                    ...chat,
                    nickname: group.groupName,
                    avatarUrl: group.groupAvatar || '',
                    isPinned: false // (Group pinning abhi nahi)
                };
            } else {
                const contact = db.data.contacts.find(c => c.ownerEmail === myEmail && c.friendEmail === chat.id);
                const friendUser = db.data.users.find(u => u.email === chat.id);
                if (!contact || !friendUser) return null;
                const { canSeeAvatar } = canSeeInfo(myEmail, friendUser);
                return {
                    ...chat,
                    nickname: contact.nickname,
                    avatarUrl: canSeeAvatar ? friendUser.avatarUrl : '',
                    isPinned: contact.isPinned
                };
            }
        }).filter(Boolean);

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
app.post('/api/upload-avatar', protectRoute, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) { return res.status(400).send('No file uploaded.'); }
    const avatarUrl = `/uploads/avatars/${req.file.filename}`;
    await db.read();
    const user = db.data.users.find(u => u.email === req.user.email);
    if (user) {
      user.avatarUrl = avatarUrl;
      await db.write();
      console.log(`Avatar updated for ${req.user.email}: ${avatarUrl}`);
      res.redirect('/profile.html');
    } else { res.status(404).send('User not found'); }
  } catch (error) { console.error('Avatar upload error:', error); res.status(500).send('Server error'); }
});
app.post('/api/toggle-block', protectRoute, async (req, res) => {
  try {
    const { friendEmail } = req.body;
    const ownerEmail = req.user.email;
    await db.read();
    const contact = db.data.contacts.find(c => c.ownerEmail === ownerEmail && c.friendEmail === friendEmail);
    if (contact) {
      contact.isBlocked = !contact.isBlocked; 
      await db.write();
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
    await db.read();
    const contact = db.data.contacts.find(
      c => c.ownerEmail === ownerEmail && c.friendEmail === friendEmail
    );
    if (contact) {
      contact.isPinned = !contact.isPinned; 
      await db.write();
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
        await db.read();
        const user = db.data.users.find(u => u.email === myEmail);
        if (user) {
            user.privacy.lastSeen = lastSeen;
            user.privacy.avatar = avatar;
            await db.write();
            console.log(`Privacy updated for ${myEmail}`);
            res.json({ message: "Privacy settings updated" });
        } else {
            res.status(404).json({ message: "User not found" });
        }
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
        
        await db.read();
        
        const memberObjects = members.map(email => ({
            email: email,
            role: "member"
        }));
        
        memberObjects.push({ email: creatorEmail, role: "admin" });
        
        const newGroup = {
            groupId: nanoid(),
            groupName: groupName,
            groupAvatar: "",
            creatorEmail: creatorEmail,
            members: memberObjects
        };
        
        db.data.groups.push(newGroup);
        await db.write();
        
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

        await db.read();
        const message = db.data.messages.find(m => m.messageId === messageId);

        if (!message) {
            return res.status(404).json({ message: "Message not found" });
        }
        
        const isMyChat = (message.senderEmail === myEmail) || 
                         (message.receiverEmail === myEmail) ||
                         (message.receiverGroupId && db.data.groups.find(g => g.groupId === message.receiverGroupId)?.members.some(m => m.email === myEmail));

        if (!isMyChat) {
            return res.status(403).json({ message: "Not authorized" });
        }

        message.isStarred = !message.isStarred;
        await db.write();
        
        const status = message.isStarred ? 'starred' : 'unstarred';
        console.log(`Message ${messageId} ${status} by ${myEmail}`);
        
        // YEH HAI FIX: getRoomName ab global hai
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


app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    await db.read();
    const existingUser = db.data.users.find(user => user.email === email);
    if (existingUser) { return res.status(400).send('User already exists'); }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const newUser = { 
      email: email, 
      password: hashedPassword, 
      displayName: "", 
      status: "Offline", 
      lastSeen: 0, 
      avatarUrl: "",
      deletedBy: [],
      privacy: { lastSeen: "everyone", avatar: "everyone" }
    };
    db.data.users.push(newUser);
    await db.write();
    console.log(`NEW USER REGISTERED: ${email}`);
    try {
      await transporter.sendMail({
        from: `"Wappy Support" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: "Welcome to Wappy! 🍉",
        html: `<h1>Welcome, ${email}!</h1><p>Thank you for joining Wappy. You can now login and start chatting with your friends.</p>`
      });
      console.log(`Welcome email sent to: ${email}`);
    } catch (emailError) { console.error(`Failed to send welcome email to ${email}:`, emailError); }
    res.redirect('/login.html');
  } catch (error) { res.status(500).send('Server error'); }
});
app.post('/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    await db.read();
    const user = db.data.users.find(user => user.email === email);
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
    await db.read();
    const user = db.data.users.find(u => u.email === req.user.email);
    if (user) {
      user.displayName = displayName;
      await db.write();
      console.log(`DISPLAY NAME SET for ${req.user.email}: ${displayName}`);
      res.redirect('/chats.html');
    } else { res.status(404).send('User not found'); }
  } catch (error) { res.status(500).send('Server error'); }
});
app.post('/add-friend', protectRoute, async (req, res) => {
  try {
    const { friendEmail, nickname } = req.body;
    const ownerEmail = req.user.email;
    if (friendEmail === ownerEmail) { return res.status(400).send("You cannot add yourself."); }
    await db.read();
    const friendExists = db.data.users.find(u => u.email === friendEmail);
    if (!friendExists) { return res.status(404).send("User with this email does not exist."); }
    const alreadyFriend = db.data.contacts.find(c => c.ownerEmail === ownerEmail && c.friendEmail === friendEmail);
    if (alreadyFriend) { return res.status(400).send("This user is already in your contacts."); }
    db.data.contacts.push({ 
      ownerEmail: ownerEmail, 
      friendEmail: friendEmail, 
      nickname: nickname || friendExists.displayName, 
      isBlocked: false,
      isPinned: false
    });
    await db.write();
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
    await db.read();
    const user = db.data.users.find(u => u.email === email);
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
    await db.read();
    const user = db.data.users.find(u => u.email === decoded.email);
    if (!user) { return res.status(404).send('User not found'); }
    user.password = hashedPassword;
    await db.write();
    console.log(`Password reset SUCCESS for: ${decoded.email}`);
    res.redirect('/login.html');
  } catch (error) { console.error('Reset password error:', error); res.status(500).send('Server error'); }
});
// index.js (Kadam 35.4 - Star FIX - Part 3)
io.on('connection', async (socket) => {
  const userEmail = socket.user.email;
  console.log(`User connected (1-to-1): ${userEmail}`);
  connectedUsers.set(userEmail, socket.id);
  
  await db.read();
  const user = db.data.users.find(u => u.email === userEmail);
  if (user) { user.status = 'Online'; await db.write(); }
  
  const myContacts = db.data.contacts.filter(c => c.ownerEmail === userEmail);
  const myFriends = db.data.contacts.filter(c => c.friendEmail === userEmail);
  
  for (const friend of myFriends) {
    const friendSocketId = connectedUsers.get(friend.ownerEmail);
    if (friendSocketId) { io.to(friendSocketId).emit('friend status', { email: userEmail, status: 'Online' }); }
  }
  for (const contact of myContacts) {
      const friendSocketId = connectedUsers.get(contact.friendEmail);
      if(friendSocketId) {
          await db.read();
          const friendUser = db.data.users.find(u => u.email === contact.friendEmail);
          if(friendUser) {
              const { canSeeLastSeen } = canSeeInfo(userEmail, friendUser);
              if(canSeeLastSeen) {
                  socket.emit('friend status', { email: contact.friendEmail, status: 'Online' });
              }
          }
      }
  }

  // (getRoomName function ab global hai, yahan se hata diya gaya)

  socket.on('join room', (roomId) => {
    let roomName = roomId;
    if (roomId.includes('@')) {
        roomName = getRoomName(userEmail, roomId);
    }
    socket.join(roomName);
    console.log(`${userEmail} joined room: ${roomName}`);
    db.data.groups.forEach(group => {
        if (group.members.some(m => m.email === userEmail)) {
            socket.join(group.groupId);
            console.log(`${userEmail} auto-joined group room: ${group.groupId}`);
        }
    });
  });

  socket.on('send message', async (data) => {
    await db.read(); 
    
    const { receiverId, text, tempId, replyTo } = data; 
    
    if (!text || text.trim() === "") { return; }
    const trimmedText = text.trim();
    const senderEmail = userEmail;
    
    const senderUser = db.data.users.find(u => u.email === senderEmail);
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
      isStarred: false, // NAYA
      tempId: tempId
    };
    
    let roomName = receiverId;
    let socketsToNotify = [];

    if (receiverId.includes('@')) {
        // 1-to-1 Chat
        messageData.receiverEmail = receiverId;
        roomName = getRoomName(senderEmail, receiverId);

        const receiverContact = db.data.contacts.find(c => c.ownerEmail === receiverId && c.friendEmail === senderEmail);
        if (receiverContact && receiverContact.isBlocked) { return; }
        const senderContact = db.data.contacts.find(c => c.ownerEmail === senderEmail && c.friendEmail === receiverId);
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
        // Group Chat
        messageData.receiverGroupId = receiverId;
        const group = db.data.groups.find(g => g.groupId === receiverId);
        if (!group) return; 
        
        group.members.forEach(member => {
            const memberSocketId = connectedUsers.get(member.email);
            if (memberSocketId) {
                socketsToNotify.push(memberSocketId);
            }
        });
        messageData.status = 'delivered';
    }

    db.data.messages.push(messageData);
    await db.write();
    
    io.to(roomName).emit('new message', messageData);
    
    socketsToNotify.forEach(socketId => {
        if(socketId) io.to(socketId).emit('chat list update');
    });
    
    console.log(`Message sent to room ${roomName}: ${trimmedText}`);
  });
  
  socket.on('delete message', async (data) => {
    try {
      await db.read();
      const { messageId } = data;
      const message = db.data.messages.find(m => m.messageId === messageId);
      if (message && message.senderEmail === userEmail) {
        message.text = "This message was deleted";
        message.isDeleted = true;
        message.replyTo = null;
        await db.write();
        
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
      await db.read();
      const { messageId } = data;
      const message = db.data.messages.find(m => m.messageId === messageId);
      if (message && !message.deletedBy.includes(userEmail)) {
        message.deletedBy.push(userEmail);
        await db.write();
        socket.emit('message removed', { messageId: messageId });
        socket.emit('chat list update');
      }
    } catch (error) {
      console.error('Delete for me error:', error);
    }
  });

  socket.on('mark messages seen', async (data) => {
    await db.read();
    const { chatId } = data;
    const myEmail = socket.user.email;
    let messagesUpdated = false;
    const messagesToUpdate = [];
    
    db.data.messages.forEach(msg => {
        const isThisChat = (msg.receiverEmail === myEmail && msg.senderEmail === chatId) || (msg.receiverGroupId === chatId && msg.senderEmail !== myEmail);
        
        if (isThisChat && msg.status !== 'seen') {
            msg.status = 'seen';
            messagesUpdated = true;
            messagesToUpdate.push({ messageId: msg.messageId, status: 'seen' });
        }
    });
    
    if (messagesUpdated) {
      await db.write();
      console.log(`Messages in chat ${chatId} marked as SEEN by ${myEmail}`);
      
      if (chatId.includes('@')) {
          const friendSocketId = connectedUsers.get(chatId);
          if (friendSocketId) {
            io.to(friendSocketId).emit('messages updated', messagesToUpdate);
            io.to(friendSocketId).emit('chat list update');
          }
      } 
      else {
          const group = db.data.groups.find(g => g.groupId === chatId);
          if(group) {
              group.members.forEach(member => {
                  if(member.email !== myEmail) {
                      const memberSocketId = connectedUsers.get(member.email);
                      if(memberSocketId) {
                          io.to(memberSocketId).emit('messages updated', messagesToUpdate);
                      }
                  }
              });
          }
      }
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
    await db.read();
    const user = db.data.users.find(u => u.email === userEmail);
    if (user) {
      user.status = 'Offline';
      user.lastSeen = lastSeenTime;
      await db.write();
    }
    const friends = db.data.contacts.filter(c => c.friendEmail === userEmail);
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
  await initializeDatabase();
  server.listen(PORT, () => {
    console.log(`🍉 Wappy server http://localhost:${PORT} par chal raha hai`);
  });
}

startServer();

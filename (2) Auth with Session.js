// models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
  // No refreshTokens array needed; sessions are stored in a separate collection
});

module.exports = mongoose.model('User', userSchema);

/*-----------------------------------------------------------------------------*/

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const cors = require('cors');
const authRoutes = require('./routes/auth');

const app = express();
const isProd = process.env.NODE_ENV === 'production';

// Trust proxy if deploying behind Nginx, Render, Heroku, or AWS ALB
if (isProd) app.set('trust proxy', 1);

app.use(express.json());
app.use(cors({
  origin: 'http://localhost:5173', // Your frontend URL
  credentials: true // Required to accept and send session cookies
}));

app.use(session({
  name: 'sid', // Custom cookie name instead of default 'connect.sid'
  secret: process.env.SESSION_SECRET,
  resave: false, // Don't save session if unmodified
  saveUninitialized: false, // Don't create empty sessions for unauthenticated visitors
  store: MongoStore.create({
    mongoUrl: process.env.MONGO_URI,
    collectionName: 'sessions',
    ttl: 7 * 24 * 60 * 60 // Session expires in 7 days (in seconds)
  }),
  cookie: {
    httpOnly: true,
    secure: isProd,
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days (in milliseconds)
  }
}));

app.use('/auth', authRoutes);

mongoose.connect(process.env.MONGO_URI).then(() => {
  app.listen(5000, () => console.log('Server running on port 5000'));
});

/*-----------------------------------------------------------------------------*/

const requireAuth = (req, res, next) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ message: 'Unauthorized: Please log in' });
  }
  next();
};

module.exports = requireAuth;

/*-----------------------------------------------------------------------------*/

const express = require('express');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const requireAuth = require('../middleware/auth');

const router = express.Router();

// 1. REGISTER
router.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = await User.create({ email, password: hashedPassword });

    // Create session immediately after registration
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ message: 'Session creation failed' });

      req.session.userId = user._id;
      res.status(201).json({ message: 'Registered successfully', userId: user._id });
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// 2. LOGIN
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Regenerate session ID on login to prevent session fixation attacks
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ message: 'Login failed' });

      req.session.userId = user._id;
      res.json({ message: 'Logged in successfully', userId: user._id });
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// 3. LOGOUT
router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ message: 'Could not log out' });
    }

    // Clear the session cookie from the browser
    res.clearCookie('sid');
    res.json({ message: 'Logged out successfully' });
  });
});

// 4. PROTECTED ROUTE EXAMPLE
router.get('/profile', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ user });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;

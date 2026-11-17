// models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  // Array allows multi-device login; use a single String for single-session only
  refreshTokens: [{ type: String }] 
});

module.exports = mongoose.model('User', userSchema);

/*-----------------------------------------------------------------------------*/

const jwt = require('jsonwebtoken');

const generateTokens = (userId) => {
  const accessToken = jwt.sign(
    { userId },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: '15m' }
  );

  const refreshToken = jwt.sign(
    { userId },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: '7d' }
  );

  return { accessToken, refreshToken };
};

const setTokenCookies = (res, accessToken, refreshToken) => {
  const isProd = process.env.NODE_ENV === 'production';

  res.cookie('accessToken', accessToken, {
    httpOnly: true,
    secure: isProd,
    sameSite: 'strict',
    maxAge: 15 * 60 * 1000 // 15 minutes
  });

  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: isProd,
    sameSite: 'strict',
    path: '/auth/refresh', // Restricts cookie to only be sent to the refresh route
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  });
};

module.exports = { generateTokens, setTokenCookies };

/*-----------------------------------------------------------------------------*/

const jwt = require('jsonwebtoken');

const requireAuth = (req, res, next) => {
  const token = req.cookies.accessToken;

  if (!token) {
    return res.status(401).json({ message: 'Unauthorized: No access token' });
  }

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    req.user = { id: decoded.userId };
    next();
  } catch (err) {
    // Frontend interceptor listens for 401/403 to trigger /auth/refresh
    return res.status(401).json({ message: 'Access token expired or invalid' });
  }
};

module.exports = requireAuth;

/*-----------------------------------------------------------------------------*/

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { generateTokens, setTokenCookies } = require('../utils/tokens');
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

    const { accessToken, refreshToken } = generateTokens(user._id);
    user.refreshTokens.push(refreshToken);
    await user.save();

    setTokenCookies(res, accessToken, refreshToken);
    res.status(201).json({ message: 'Registered successfully', userId: user._id });
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

    const { accessToken, refreshToken } = generateTokens(user._id);

    // Save new refresh token in DB
    user.refreshTokens.push(refreshToken);
    await user.save();

    setTokenCookies(res, accessToken, refreshToken);
    res.json({ message: 'Logged in successfully', userId: user._id });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// 3. REFRESH TOKEN (With Rotation & Reuse Detection)
router.post('/refresh', async (req, res) => {
  const incomingRefreshToken = req.cookies.refreshToken;

  if (!incomingRefreshToken) {
    return res.status(401).json({ message: 'No refresh token provided' });
  }

  try {
    const decoded = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);
    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(403).json({ message: 'User not found' });
    }

    // Reuse Detection: Token is valid JWT, but already used/removed from DB
    if (!user.refreshTokens.includes(incomingRefreshToken)) {
      // Possible token theft: wipe all active sessions for security
      user.refreshTokens = [];
      await user.save();
      return res.status(403).json({ message: 'Refresh token reuse detected. Please log in again.' });
    }

    // Rotate Tokens: Remove old refresh token and issue a fresh pair
    const { accessToken, refreshToken: newRefreshToken } = generateTokens(user._id);
    user.refreshTokens = user.refreshTokens.filter((t) => t !== incomingRefreshToken);
    user.refreshTokens.push(newRefreshToken);
    await user.save();

    setTokenCookies(res, accessToken, newRefreshToken);
    res.json({ message: 'Tokens refreshed' });
  } catch (err) {
    return res.status(403).json({ message: 'Invalid or expired refresh token' });
  }
});

// 4. LOGOUT
router.post('/logout', async (req, res) => {
  const incomingRefreshToken = req.cookies.refreshToken;

  try {
    if (incomingRefreshToken) {
      const decoded = jwt.decode(incomingRefreshToken);
      if (decoded?.userId) {
        // Remove only the current device's refresh token from DB
        await User.findByIdAndUpdate(decoded.userId, {
          $pull: { refreshTokens: incomingRefreshToken }
        });
      }
    }
  } finally {
    // Clear both cookies regardless of DB state
    const isProd = process.env.NODE_ENV === 'production';
    res.clearCookie('accessToken', { httpOnly: true, secure: isProd, sameSite: 'strict' });
    res.clearCookie('refreshToken', { httpOnly: true, secure: isProd, sameSite: 'strict', path: '/auth/refresh' });
    res.json({ message: 'Logged out successfully' });
  }
});

// 5. PROTECTED ROUTE EXAMPLE
router.get('/profile', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password -refreshTokens');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ user });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;

/*-----------------------------------------------------------------------------*/


require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const authRoutes = require('./routes/auth');

const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: 'http://localhost:5173', // Your frontend URL
  credentials: true // Required to accept and send cookies cross-origin
}));

app.use('/auth', authRoutes);

mongoose.connect(process.env.MONGO_URI).then(() => {
  app.listen(5000, () => console.log('Server running on port 5000'));
});

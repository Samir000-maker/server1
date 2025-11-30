/* server.js
   Fixed: Added trust proxy configuration for reverse proxy environments (Render, Heroku, etc.)
   Single-file Express + Mongoose server (no .env).
   Server listens on port 5000 (all workers).
*/

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const cluster = require('cluster');
const os = require('os');

const numCPUs = os.cpus().length || 1;
const processId = process.pid;

// ---------- CONFIGURATION ----------
const MONGODB_URI = 'mongodb+srv://samir_:fitara@cluster0.cmatn6k.mongodb.net/your_app_db?retryWrites=true&w=majority'; // <-- replace if needed
const WORKER_COUNT = Math.max(1, numCPUs - 1);


const FOLLOWING_SLOT_CAPACITY = 250; // Changed from 2 to 6


// conservative per-worker pool to avoid exploding connections
const MONGO_OPTIONS = {
  maxPoolSize: 20,
  minPoolSize: 2,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
  family: 4,
  autoIndex: false
};



// Add this validation utility after the imports
const validate = {
    userId: (id) => id && typeof id === 'string' && id.trim().length > 0 && id.trim().length <= 100,
    sanitize: (input) => typeof input === 'string' ? input.trim() : input
};

// Add logging utility
const log = (level, msg, ...args) => {
    const timestamp = new Date().toISOString();
    console[level](`[${timestamp}] ${level.toUpperCase()}: ${msg}`, ...args);
};


// Updated User schema - remove the following field since we'll use separate collection
// Updated User schema with interests field
const userSchema = new mongoose.Schema({
  uid: { type: String, required: true, unique: true, index: true },
  username: { type: String, required: true, unique: true, trim: true, minlength: 3, maxlength: 30, index: true },
  name: { type: String, required: true, trim: true, maxlength: 100 },
  interests: { type: [String], default: [] }, // NEW: Array of interests
  postCount: { type: Number, default: 0, min: 0 },
  followers: { type: Number, default: 0, min: 0 },
  accountCreationTimestamp: { type: Date, default: Date.now, index: true },
  profilePictureUrl: { type: String, default: null },
  isActive: { type: Boolean, default: true, index: true },
  lastLoginTimestamp: { type: Date, default: Date.now }
}, { timestamps: true, collection: 'users' });

// Create Following schema to match your Firestore structure
const followingSchema = new mongoose.Schema({
  _id: { type: String }, // This will be "currentUserId_N"
  userId: { type: String, required: true }, // The user who is doing the following
  index: { type: Number, required: true },
  followingCount: { type: Number, default: 0, max: 2 },
  followingList: [{
    userId: { type: String, required: true } // The user being followed
  }]
}, { collection: 'following' });

const Following = mongoose.models.Following || mongoose.model('Following', followingSchema);


// will be set to true/false after we connect
let canUseTransactions = false;

// ---------- CLUSTER ----------
if (cluster.isPrimary) {
  console.log(`Primary ${processId} - starting ${WORKER_COUNT} workers`);

  for (let i = 0; i < WORKER_COUNT; i++) cluster.fork();

  cluster.on('exit', (worker, code, signal) => {
    console.error(`Worker ${worker.process.pid} exited (code=${code} signal=${signal}). Restarting in 1s`);
    setTimeout(() => cluster.fork(), 1000);
  });

  const primaryGracefulShutdown = () => {
    console.log('Primary received shutdown signal. Disconnecting workers...');
    for (const id in cluster.workers) {
      try { cluster.workers[id].disconnect(); } catch (e) { /* ignore */ }
    }
    setTimeout(() => process.exit(0), 3000);
  };
  process.on('SIGINT', primaryGracefulShutdown);
  process.on('SIGTERM', primaryGracefulShutdown);

} else {
  // ---------------- WORKER PROCESS ----------------
  const app = express();
  const PORT = 5000; // <- all workers listen on port 5000

  // ========== FIX: Enable trust proxy for reverse proxy environments ==========
  // CRITICAL: This must be set BEFORE rate limiters are configured
  // For Render, Heroku, AWS ELB, and similar platforms with a single reverse proxy
  // Set to 1 to trust the first proxy (the platform's load balancer/proxy)
  app.set('trust proxy', 1);
  console.log(`Worker ${processId} - trust proxy enabled for reverse proxy environment`);
  // ============================================================================

  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"],
      }
    }
  }));
  app.use(compression());

  const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests from this IP, please try again later.' }
  });
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 50,
    message: { error: 'Too many authentication attempts, please try again later.' }
  });

  app.use(globalLimiter);
  app.use('/api/auth', authLimiter);

app.use(cors());

  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // ---------- CONNECT & DETECT TRANSACTION SUPPORT ----------
  const connectWithRetry = async (retries = 6, delayMs = 1000) => {
    for (let attempt = 1; attempt <= retries; attempt++) {
      try {
        await mongoose.connect(MONGODB_URI, MONGO_OPTIONS);
        console.log(`Worker ${processId} connected to MongoDB on attempt ${attempt}`);
        return;
      } catch (err) {
        const isLast = attempt === retries;
        console.error(`Worker ${processId} MongoDB connect attempt ${attempt} failed: ${err.message}`);
        if (isLast) throw err;
        await new Promise(res => setTimeout(res, delayMs * Math.pow(2, attempt - 1)));
      }
    }
  };

  const detectTransactionSupport = async () => {
    try {
      const admin = mongoose.connection.db.admin();
      // try 'hello' (newer); fallback to 'ismaster'
      let info;
      try {
        info = await admin.command({ hello: 1 });
      } catch (e) {
        info = await admin.command({ ismaster: 1 });
      }

      // mongos has msg === 'isdbgrid', replica set has setName, and logicalSessionTimeoutMinutes
      const isMongos = info && info.msg === 'isdbgrid';
      const isReplicaSet = !!(info && info.setName);
      const sessionsSupported = typeof (info && info.logicalSessionTimeoutMinutes) === 'number';

      const supported = (isMongos || isReplicaSet) && sessionsSupported;
      console.log(`Worker ${processId} transaction support detection:`, {
        isMongos, isReplicaSet, sessionsSupported, supported
      });
      return supported;
    } catch (err) {
      console.warn(`Worker ${processId} could not detect transaction support, assuming false.`, err.message);
      return false;
    }
  };

  (async () => {
    try {
      await connectWithRetry();
      // after connected, detect whether transactions can be used
      canUseTransactions = await detectTransactionSupport();
    } catch (err) {
      console.error('Worker failed to connect to MongoDB after retries. Exiting worker.');
      process.exit(1);
    }
  })();

  mongoose.connection.on('error', (err) => {
    console.error('MongoDB connection error (worker):', err);
  });
  mongoose.connection.on('disconnected', () => {
    console.warn('MongoDB disconnected (worker).');
  });


  userSchema.index({ uid: 1, isActive: 1 });
  userSchema.index({ username: 1, isActive: 1 });
  userSchema.index({ accountCreationTimestamp: -1 });

  const User = mongoose.models.User || mongoose.model('User', userSchema);

  // ---------- VALIDATION ----------
  const validateUserInput = (req, res, next) => {
    try {
      const { uid, username, name } = req.body;
      if (!uid || typeof uid !== 'string' || uid.trim().length === 0) {
        return res.status(400).json({ success: false, error: 'Invalid or missing UID' });
      }
      if (!username || typeof username !== 'string' || username.trim().length < 3 || username.trim().length > 30) {
        return res.status(400).json({ success: false, error: 'Username must be between 3 and 30 characters' });
      }
      if (!name || typeof name !== 'string' || name.trim().length === 0 || name.trim().length > 100) {
        return res.status(400).json({ success: false, error: 'Name is required and must be less than 100 characters' });
      }

      const sanitizedUsername = username.trim().replace(/[^a-zA-Z0-9_-]/g, '');
      if (sanitizedUsername !== username.trim()) {
        return res.status(400).json({ success: false, error: 'Username can only contain letters, numbers, underscores, and dashes' });
      }

      req.body.username = sanitizedUsername;
      req.body.name = name.trim();
      req.body.uid = uid.trim();

      next();
    } catch (err) {
      next(err);
    }
  };

app.get("/health", (req, res) => {
  res.status(200).send("OK");
});


// Alternative simple health check (if you prefer minimal response)
app.get('/ping', (req, res) => {
  res.status(200).send('pong');
});






// Get user's following list
app.get('/api/users/:uid/following', async (req, res) => {
  try {
    const { uid } = req.params;
    
    if (!validate.userId(uid)) {
      return res.status(400).json({ success: false, error: 'Invalid UID' });
    }

    const followingDocs = await Following.find({ userId: uid })
      .select('followingList')
      .lean();
    
    const followingIds = [];
    followingDocs.forEach(doc => {
      if (doc.followingList && Array.isArray(doc.followingList)) {
        doc.followingList.forEach(item => {
          if (item.userId) followingIds.push(item.userId);
        });
      }
    });

    res.status(200).json({ 
      success: true, 
      following: followingIds,
      count: followingIds.length
    });
  } catch (err) {
    console.error('Get following error:', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});





// Add these to your MongoDB server (server.js)

// Get user posts
// Add this endpoint to your server.js file after your existing routes

// Get user posts from user_slots collection
app.get('/api/posts/user/:uid', async (req, res) => {
  try {
    const { uid } = req.params;
    
    if (!validate.userId(uid)) {
      return res.status(400).json({ success: false, error: 'Invalid UID' });
    }

    const cleanUserId = validate.sanitize(uid);
    
    // Since you don't have direct posts collection, return empty for now
    // Or implement logic to fetch from your actual posts storage
    log('info', `Fetched user posts for userId=${cleanUserId}`);

    res.status(200).json({ 
      success: true, 
      posts: [], // Empty for now - implement your posts fetching logic
      totalPosts: 0,
      userId: cleanUserId
    });

  } catch (err) {
    console.error('Get user posts error:', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Follow user
// Follow user
app.post('/api/users/:uid/follow', async (req, res) => {
  try {
    const targetUserId = req.params.uid;
    const { currentUserId } = req.body;
    
    if (!targetUserId || !currentUserId) {
      return res.status(400).json({ success: false, error: 'Missing user IDs' });
    }

    if (targetUserId === currentUserId) {
      return res.status(400).json({ success: false, error: 'Cannot follow yourself' });
    }

    console.log(`[FOLLOW] User ${currentUserId} attempting to follow ${targetUserId}, slotCapacity=${FOLLOWING_SLOT_CAPACITY}`);

    // Check if target user exists
    const targetUser = await User.findOne({ uid: targetUserId });
    if (!targetUser) {
      return res.status(404).json({ success: false, error: 'Target user not found' });
    }

    // Check if already following
    const existingFollow = await Following.findOne({
      userId: currentUserId,
      'followingList.userId': targetUserId
    });

    if (existingFollow) {
      console.log(`[FOLLOW-DUPLICATE] User ${currentUserId} already following ${targetUserId}`);
      return res.status(409).json({ success: false, error: 'Already following this user' });
    }

    // Find a following document with space (followingCount < FOLLOWING_SLOT_CAPACITY)
    let followingDoc = await Following.findOne({
      userId: currentUserId,
      followingCount: { $lt: FOLLOWING_SLOT_CAPACITY }
    }).sort({ index: 1 });

    if (!followingDoc) {
      // Create new following document
      const maxIndexDoc = await Following.findOne({ userId: currentUserId })
        .sort({ index: -1 })
        .limit(1);
      
      const newIndex = maxIndexDoc ? maxIndexDoc.index + 1 : 1;
      const newDocId = `${currentUserId}_${newIndex}`;

      console.log(`[FOLLOW] Creating new following slot ${newIndex} for user ${currentUserId}`);

      followingDoc = new Following({
        _id: newDocId,
        userId: currentUserId,
        index: newIndex,
        followingCount: 0,
        followingList: []
      });
    } else {
      console.log(`[FOLLOW] Using existing slot ${followingDoc.index}, current count=${followingDoc.followingCount}`);
    }

    // Add to following list
    followingDoc.followingList.push({ userId: targetUserId });
    followingDoc.followingCount = followingDoc.followingList.length;
    await followingDoc.save();

    // Increment target user's follower count
    await User.updateOne(
      { uid: targetUserId },
      { $inc: { followers: 1 } }
    );

    console.log(`[FOLLOW-SUCCESS] User ${currentUserId} now following ${targetUserId}, new count=${followingDoc.followingCount}`);

    res.status(200).json({ success: true, message: 'Followed successfully', slotCapacity: FOLLOWING_SLOT_CAPACITY });
  } catch (err) {
    console.error('[FOLLOW-ERROR]', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Unfollow user
// Unfollow user - change from req.body to req.query
// Unfollow user - Fix the MongoDB update conflict
app.delete('/api/users/:uid/unfollow', async (req, res) => {
  try {
    const targetUserId = req.params.uid;
    const { currentUserId } = req.query;
    
    if (!targetUserId || !currentUserId) {
      return res.status(400).json({ success: false, error: 'Missing user IDs' });
    }

    // Find the following document that contains this user
    const followingDoc = await Following.findOne({
      userId: currentUserId,
      'followingList.userId': targetUserId
    });

    if (!followingDoc) {
      return res.status(409).json({ success: false, error: 'Not following this user' });
    }

    // Remove from following list
    followingDoc.followingList = followingDoc.followingList.filter(
      item => item.userId !== targetUserId
    );
    followingDoc.followingCount = followingDoc.followingList.length;

    if (followingDoc.followingCount === 0) {
      await Following.deleteOne({ _id: followingDoc._id });
    } else {
      await followingDoc.save();
    }

    // Fix: Use a simple decrement and handle negative values separately
    const userUpdateResult = await User.updateOne(
      { uid: targetUserId, followers: { $gt: 0 } }, // Only update if followers > 0
      { $inc: { followers: -1 } }
    );

    // If no document was updated (followers was already 0), just continue
    if (userUpdateResult.matchedCount === 0) {
      // User either doesn't exist or followers is already 0
      console.log(`User ${targetUserId} not found or followers already at 0`);
    }

    res.status(200).json({ success: true, message: 'Unfollowed successfully' });
  } catch (err) {
    console.error('Unfollow user error:', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Check follow status
app.get('/api/users/:uid/follow-status', async (req, res) => {
  try {
    const targetUserId = req.params.uid;
    const { currentUserId } = req.query;
    
    if (!targetUserId || !currentUserId) {
      return res.status(400).json({ success: false, error: 'Missing user IDs' });
    }

    // Check if current user is following target user
    const isFollowing = await Following.findOne({
      userId: currentUserId,
      'followingList.userId': targetUserId
    });

    res.status(200).json({ 
      success: true, 
      isFollowing: !!isFollowing 
    });
  } catch (err) {
    console.error('Check follow status error:', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Update post
app.patch('/api/posts/:postId', async (req, res) => {
  try {
    const { postId } = req.params;
    const { caption, description } = req.body;
    
    if (!postId) {
      return res.status(400).json({ success: false, error: 'Missing post ID' });
    }

    // For now just return success since you don't have posts collection
    // Replace this with actual post update when you have posts collection
    res.status(200).json({ 
      success: true, 
      message: 'Post updated successfully' 
    });
  } catch (err) {
    console.error('Update post error:', err);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});







// SIGNUP: uses transactions only when supported; otherwise falls back to non-transactional path
app.post('/api/auth/signup', validateUserInput, async (req, res) => {
  const { uid, username, name, interests } = req.body;

  // Validate and sanitize interests
  let userInterests = [];
  if (Array.isArray(interests)) {
    userInterests = interests.filter(interest => 
      typeof interest === 'string' && interest.trim().length > 0
    ).map(interest => interest.trim());
  }

  // Log received data
  console.log(`Signup request received - UID: ${uid}, Username: ${username}, Interests: [${userInterests.join(', ')}]`);

  if (canUseTransactions) {
    // transactional path
    let session;
    try {
      session = await mongoose.startSession();
      await session.withTransaction(async () => {
        const existingUserByUid = await User.findOne({ uid }).session(session);
        if (existingUserByUid) throw new Error('User with this UID already exists');

        const existingUserByUsername = await User.findOne({ username: { $regex: new RegExp(`^${username}$`, 'i') } }).session(session);
        if (existingUserByUsername) throw new Error('Username is already taken');

        const newUser = new User({
          uid, 
          username, 
          name,
          interests: userInterests,
          postCount: 0, 
          followers: 0, 
          accountCreationTimestamp: new Date(), 
          isActive: true, 
          lastLoginTimestamp: new Date()
        });

        const savedUser = await newUser.save({ session });

        console.log(`User created successfully - UID: ${savedUser.uid}, Interests: [${(savedUser.interests || []).join(', ')}], Count: ${(savedUser.interests || []).length}`);

        res.status(201).json({
          success: true,
          message: 'User created successfully',
          user: {
            uid: savedUser.uid,
            username: savedUser.username,
            name: savedUser.name,
            interests: savedUser.interests || [],
            postCount: savedUser.postCount,
            followers: savedUser.followers,
            accountCreationTimestamp: savedUser.accountCreationTimestamp
          }
        });
      });
    } catch (error) {
      console.error('Signup error (transactional):', error);
      if (error.message === 'User with this UID already exists') {
        return res.status(409).json({ success: false, error: 'User already exists' });
      }
      if (error.message === 'Username is already taken') {
        return res.status(409).json({ success: false, error: 'Username is already taken' });
      }
      if (error && error.code === 11000) {
        return res.status(409).json({ success: false, error: 'Duplicate key conflict' });
      }
      return res.status(500).json({ success: false, error: 'Internal server error during signup' });
    } finally {
      if (session) await session.endSession();
    }

  } else {
    // fallback non-transactional path (safe on standalone)
    try {
      // quick checks to return friendly errors
      const existingUserByUid = await User.findOne({ uid }).lean();
      if (existingUserByUid) {
        return res.status(409).json({ success: false, error: 'User already exists' });
      }

      const existingUserByUsername = await User.findOne({ username: { $regex: new RegExp(`^${username}$`, 'i') } }).lean();
      if (existingUserByUsername) {
        return res.status(409).json({ success: false, error: 'Username is already taken' });
      }

      const newUser = new User({
        uid, 
        username, 
        name,
        interests: userInterests,
        postCount: 0, 
        followers: 0, 
        accountCreationTimestamp: new Date(), 
        isActive: true, 
        lastLoginTimestamp: new Date()
      });

      const savedUser = await newUser.save();

      console.log(`User created successfully - UID: ${savedUser.uid}, Username: ${savedUser.username}, Interests: [${(savedUser.interests || []).join(', ')}], Count: ${(savedUser.interests || []).length}`);

      res.status(201).json({
        success: true,
        message: 'User created successfully',
        user: {
          uid: savedUser.uid,
          username: savedUser.username,
          name: savedUser.name,
          interests: savedUser.interests || [],
          postCount: savedUser.postCount,
          followers: savedUser.followers,
          accountCreationTimestamp: savedUser.accountCreationTimestamp
        }
      });
    } catch (error) {
      console.error('Signup error (non-transactional):', error);
      console.error('Error stack:', error.stack);
      // Handle duplicate-key from unique indexes (race)
      if (error && error.code === 11000) {
        // determine which key likely conflicted
        const key = error.keyValue ? Object.keys(error.keyValue)[0] : null;
        if (key === 'uid') return res.status(409).json({ success: false, error: 'User already exists' });
        if (key === 'username') return res.status(409).json({ success: false, error: 'Username is already taken' });
        return res.status(409).json({ success: false, error: 'Duplicate key conflict' });
      }
      return res.status(500).json({ success: false, error: 'Internal server error during signup' });
    }
  }
});

  app.get('/api/users/:uid', async (req, res) => {
    try {
      const uid = String(req.params.uid || '').trim();
      if (!uid) return res.status(400).json({ success: false, error: 'Invalid UID' });

      const user = await User.findOne({ uid, isActive: true }).select('-_id -__v');
      if (!user) return res.status(404).json({ success: false, error: 'User not found' });

      res.status(200).json({ success: true, user });
    } catch (err) {
      console.error('Get user error:', err);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  });

  app.patch('/api/users/:uid/profile-picture', async (req, res) => {
    try {
      const { uid } = req.params;
      const { profilePictureUrl } = req.body;
      if (!uid || !String(uid).trim()) return res.status(400).json({ success: false, error: 'Invalid UID' });
      if (!profilePictureUrl || typeof profilePictureUrl !== 'string') return res.status(400).json({ success: false, error: 'Invalid profile picture URL' });

      const updatedUser = await User.findOneAndUpdate(
        { uid, isActive: true },
        { profilePictureUrl, lastLoginTimestamp: new Date() },
        { new: true, select: '-_id -__v' }
      );

      if (!updatedUser) return res.status(404).json({ success: false, error: 'User not found' });
      res.status(200).json({ success: true, message: 'Profile picture updated successfully', user: updatedUser });
    } catch (err) {
      console.error('Update profile picture error:', err);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  });

  app.get('/api/check-username/:username', async (req, res) => {
    try {
      const username = String(req.params.username || '').trim();
      if (!username || username.length < 3 || username.length > 30) {
        return res.status(400).json({ success: false, error: 'Username must be between 3 and 30 characters' });
      }
      const existingUser = await User.findOne({
        username: { $regex: new RegExp(`^${username}$`, 'i') },
        isActive: true
      }).select('username');

      res.status(200).json({ success: true, available: !existingUser });
    } catch (err) {
      console.error('Check username error:', err);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  });

  // 404 handler - do not pass '*' to path-to-regexp
  app.use((req, res) => {
    res.status(404).json({ success: false, error: 'Endpoint not found' });
  });

  // global error handler
  app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    if (!res.headersSent) {
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  });



app.get('/api/users/search/query', async (req, res) => {
  try {
    const { q } = req.query;

    console.log(`[SEARCH] Request received. Raw Query: "${q}"`);

    if (!q || typeof q !== 'string' || q.trim().length === 0) {
      console.warn('[SEARCH] Validation failed: Query parameter missing or empty');
      return res.status(400).json({ success: false, error: 'Query parameter required' });
    }

    const searchQuery = q.trim();
    // Escape special regex characters to prevent errors
    const escapedQuery = searchQuery.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

    console.log(`[SEARCH] Processing query: "${searchQuery}" (Escaped: "${escapedQuery}")`);

    const users = await User.aggregate([
      {
        $match: {
          username: { $regex: escapedQuery, $options: 'i' }, // Uses the username index
          isActive: true
        }
      },
      {
        $addFields: {
          // Score 2: Exact match (case-insensitive)
          isExact: { 
            $cond: [{ $eq: [{ $toLower: "$username" }, searchQuery.toLowerCase()] }, 1, 0] 
          },
          // Score 1: Starts with query
          isStartsWith: { 
            $cond: [{ $regexMatch: { input: "$username", regex: new RegExp(`^${escapedQuery}`, 'i') } }, 1, 0] 
          }
        }
      },
      {
        // Sort: Exact match first, then "starts with", then follower count (popularity), then alphabetical
        $sort: { 
          isExact: -1, 
          isStartsWith: -1, 
          followers: -1,
          username: 1 
        }
      },
      { $limit: 10 }, // HARD LIMIT: Never read more than 10 documents into memory
      {
        $project: {
          _id: 0,
          uid: 1,
          username: 1,
          name: 1,
          profilePictureUrl: 1,
          followers: 1 // Optional: return followers if you want to show "X followers"
        }
      }
    ]);

    console.log(`[SEARCH] Success. Found ${users.length} results for "${searchQuery}"`);
    
    // Optional: Log the actual usernames found to verify order
    if (users.length > 0) {
        const foundUsernames = users.map(u => u.username).join(', ');
        console.log(`[SEARCH] Results: [${foundUsernames}]`);
    }

    res.status(200).json({ success: true, users });

  } catch (err) {
    console.error('[SEARCH] Critical Error:', err);
    console.error('[SEARCH] Stack Trace:', err.stack);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});
   

   

  // ---------- SERVER START & SHUTDOWN ----------
  const server = app.listen(PORT, () => {
    console.log(`Worker ${processId} listening on port ${PORT}`);
  });

  server.timeout = 30000;
  server.keepAliveTimeout = 5000;
  server.headersTimeout = 6000;

  const shutdown = async (sig) => {
    console.log(`Worker ${processId} received ${sig} - closing server and mongoose connection`);
    try {
      server.close(() => {
        console.log(`Worker ${processId} HTTP server closed`);
      });
      await mongoose.connection.close(true);
      console.log(`Worker ${processId} mongoose connection closed`);
    } catch (err) {
      console.error(`Worker ${processId} error during shutdown:`, err);
    } finally {
      process.exit(0);
    }
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  process.on('uncaughtException', (err) => {
    console.error('uncaughtException, exiting worker:', err);
    setTimeout(() => process.exit(1), 100);
  });
  process.on('unhandledRejection', (reason) => {
    console.error('unhandledRejection, exiting worker:', reason);
    setTimeout(() => process.exit(1), 100);
  });
}

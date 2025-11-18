const express = require('express');
const multer = require('multer');
const axios = require('axios');
const FormData = require('form-data');
const admin = require('firebase-admin');

const app = express();

// Initialize Firebase Admin
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n')
    })
  });
}

const db = admin.firestore();

// CORS Middleware - MUST be before all routes
app.use((req, res, next) => {
  const allowedOrigins = [
    'https://crypto-talks.web.app',
    'https://crypto-talks.firebaseapp.com',
    'http://localhost:3000',
    'http://localhost:5000'
  ];
  
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  }
  
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  next();
});

app.use(express.json());

// Configure multer for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  }
});

// Middleware to verify Firebase auth token
async function verifyAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const token = authHeader.split('Bearer ')[1];
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error('Auth error:', error);
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

// Middleware to check if user is admin
async function verifyAdmin(req, res, next) {
  try {
    const userDoc = await db.collection('users').doc(req.user.uid).get();
    if (!userDoc.exists || userDoc.data().role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden - Admin only' });
    }
    next();
  } catch (error) {
    console.error('Admin verification error:', error);
    return res.status(403).json({ error: 'Forbidden' });
  }
}

// NEW: Get Firebase config endpoint (only public keys)
app.get('/api/firebase-config', (req, res) => {
  res.json({
    apiKey: process.env.FIREBASE_API_KEY,
    authDomain: process.env.FIREBASE_AUTH_DOMAIN,
    projectId: process.env.FIREBASE_PROJECT_ID,
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
    messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
    appId: process.env.FIREBASE_APP_ID,
    measurementId: process.env.FIREBASE_MEASUREMENT_ID
  });
});

// Upload endpoint
app.post('/api/upload', verifyAuth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const formData = new FormData();
    formData.append('file', req.file.buffer, {
      filename: req.file.originalname,
      contentType: req.file.mimetype
    });

    const response = await axios.post(
      'https://api.pinata.cloud/pinning/pinFileToIPFS',
      formData,
      {
        headers: {
          ...formData.getHeaders(),
          'Authorization': `Bearer ${process.env.PINATA_JWT}`
        },
        maxBodyLength: Infinity
      }
    );

    const cid = response.data.IpfsHash;
    const url = `https://gateway.pinata.cloud/ipfs/${cid}`;

    res.json({ cid, url });
  } catch (error) {
    console.error('Upload error:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Upload failed', 
      details: error.response?.data?.error || error.message 
    });
  }
});

// Create post endpoint
app.post('/api/posts', verifyAuth, verifyAdmin, async (req, res) => {
  try {
    const { title, subtitle, category, content, imageCID, links } = req.body;

    if (!title || !category || !content || !imageCID) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const postData = {
      title,
      subtitle: subtitle || '',
      category,
      content,
      imageCID,
      links: links || [],
      authorId: req.user.uid,
      likes: 0,
      likedBy: [],
      views: 0,
      authenticatedViews: 0,
      unauthenticatedViews: 0,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    };

    const docRef = await db.collection('posts').add(postData);

    res.json({ 
      success: true, 
      postId: docRef.id,
      message: 'Post created successfully'
    });
  } catch (error) {
    console.error('Post creation error:', error);
    res.status(500).json({ error: 'Failed to create post' });
  }
});

// Update post endpoint
app.put('/api/posts/:postId', verifyAuth, verifyAdmin, async (req, res) => {
  try {
    const { postId } = req.params;
    const { title, subtitle, category, content, imageCID, links } = req.body;

    const postRef = db.collection('posts').doc(postId);
    const postDoc = await postRef.get();

    if (!postDoc.exists) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const updateData = {
      title,
      subtitle: subtitle || '',
      category,
      content,
      links: links || [],
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    };

    if (imageCID) {
      updateData.imageCID = imageCID;
    }

    await postRef.update(updateData);

    res.json({ 
      success: true, 
      message: 'Post updated successfully'
    });
  } catch (error) {
    console.error('Post update error:', error);
    res.status(500).json({ error: 'Failed to update post' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Export for Vercel
module.exports = app;
// ==================== SECURE BACKEND SETUP ====================
// backend/api/index.js (for Vercel serverless functions)

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const FormData = require('form-data');
const fetch = require('node-fetch');
const admin = require('firebase-admin');

const app = express();

// ==================== FIREBASE ADMIN SDK INITIALIZATION ====================
// Credentials come from Vercel environment variables (no dotenv needed)

const serviceAccount = {
    type: process.env.FIREBASE_TYPE,
    project_id: process.env.FIREBASE_PROJECT_ID,
    private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
    private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
    client_email: process.env.FIREBASE_CLIENT_EMAIL,
    client_id: process.env.FIREBASE_CLIENT_ID,
    auth_uri: process.env.FIREBASE_AUTH_URI,
    token_uri: process.env.FIREBASE_TOKEN_URI,
    auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_CERT_URL,
    client_x509_cert_url: process.env.FIREBASE_CLIENT_CERT_URL,
};

// Verify all required credentials exist
const requiredFields = ['project_id', 'private_key', 'client_email'];
const missingFields = requiredFields.filter(field => !serviceAccount[field]);

if (missingFields.length > 0) {
    throw new Error(`Missing Firebase credentials: ${missingFields.join(', ')}`);
}

// Initialize Firebase Admin SDK
if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        projectId: process.env.FIREBASE_PROJECT_ID,
    });
}

const db = admin.firestore();
const auth = admin.auth();

// ==================== MIDDLEWARE ====================

// CORS Configuration - Vercel production ready
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS?.split(',') || [
    'https://crypto-talks.firebaseapp.com',
    'https://crypto-talks-p3jz.vercel.app',
];

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || ALLOWED_ORIGINS.includes(origin)) {
            callback(null, true);
        } else {
            console.warn(`CORS rejected: ${origin}`);
            callback(new Error('CORS not allowed'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 86400,
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// Configure multer for memory storage (Vercel serverless)
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowedMimes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
        if (allowedMimes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only images allowed.'));
        }
    }
});

// ==================== RATE LIMITING (In-Memory) ====================
// For production, use Redis or Vercel KV
const rateLimit = new Map();

const rateLimitMiddleware = (req, res, next) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.ip;
    const now = Date.now();
    const windowMs = 60 * 1000; // 1 minute
    const maxRequests = 50; // 50 requests per minute

    if (!rateLimit.has(ip)) {
        rateLimit.set(ip, { count: 0, resetTime: now + windowMs });
    }

    const limit = rateLimit.get(ip);

    if (now > limit.resetTime) {
        limit.count = 0;
        limit.resetTime = now + windowMs;
    }

    limit.count++;

    // Clean up old entries
    if (rateLimit.size > 10000) {
        for (const [key, val] of rateLimit.entries()) {
            if (now > val.resetTime + 60000) {
                rateLimit.delete(key);
            }
        }
    }

    if (limit.count > maxRequests) {
        return res.status(429).json({
            error: 'Too many requests. Please try again in 1 minute.'
        });
    }

    res.set('X-RateLimit-Remaining', Math.max(0, maxRequests - limit.count));
    next();
};

app.use(rateLimitMiddleware);

// ==================== AUTHENTICATION MIDDLEWARE ====================

const verifyToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.split('Bearer ')[1];

    if (!token) {
        return res.status(401).json({ error: 'No authorization token provided' });
    }

    try {
        const decodedToken = await auth.verifyIdToken(token);
        req.user = decodedToken;
        next();
    } catch (error) {
        console.error('Token verification failed:', error.message);
        res.status(401).json({ error: 'Invalid or expired token' });
    }
};

// ==================== HEALTH CHECK ====================

app.get('/', (req, res) => {
    res.json({
        message: 'Crypto Talks Secure API',
        status: 'healthy',
        timestamp: new Date().toISOString(),
        environment: 'production'
    });
});

app.get('/api', (req, res) => {
    res.json({
        message: 'Crypto Talks Secure API',
        version: '1.0.0',
        endpoints: [
            'POST /api/upload',
            'POST /api/posts',
            'PUT /api/posts/:postId',
            'DELETE /api/posts/:postId',
            'GET /api/user/profile'
        ]
    });
});

// ==================== FILE UPLOAD ENDPOINT ====================

app.post('/api/upload', verifyToken, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file provided' });
        }

        if (!process.env.PINATA_JWT) {
            console.error('PINATA_JWT not configured');
            return res.status(500).json({ error: 'Upload service misconfigured' });
        }

        // Create FormData for Pinata
        const formData = new FormData();
        formData.append('file', req.file.buffer, {
            filename: req.file.originalname,
            contentType: req.file.mimetype
        });

        // Add metadata
        const metadata = JSON.stringify({
            name: req.file.originalname,
            keyvalues: {
                uploadedBy: req.user.uid,
                timestamp: new Date().toISOString(),
                size: req.file.size
            }
        });
        formData.append('pinataMetadata', metadata);

        // Upload to Pinata
        const response = await fetch('https://api.pinata.cloud/pinning/pinFileToIPFS', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${process.env.PINATA_JWT}`
            },
            body: formData,
            timeout: 30000
        });

        if (!response.ok) {
            const errorText = await response.text();
            console.error(`Pinata error: ${response.statusText}`, errorText);
            throw new Error(`Pinata error: ${response.statusText}`);
        }

        const result = await response.json();

        if (!result.IpfsHash) {
            throw new Error('No IpfsHash in Pinata response');
        }

        return res.status(200).json({
            success: true,
            cid: result.IpfsHash,
            url: `https://gateway.pinata.cloud/ipfs/${result.IpfsHash}`,
            size: result.PinSize,
            uploadedAt: new Date().toISOString()
        });

    } catch (error) {
        console.error('Upload error:', error.message);
        res.status(500).json({
            success: false,
            error: 'Failed to upload file'
        });
    }
});

// ==================== POST MANAGEMENT ====================

app.post('/api/posts', verifyToken, async (req, res) => {
    try {
        const { title, content, category, imageCID, links = [], subtitle = '' } = req.body;

        // Validate inputs
        if (!title || !content || !category || !imageCID) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        if (title.length > 200 || title.length < 5) {
            return res.status(400).json({ error: 'Title must be 5-200 characters' });
        }

        if (content.length > 50000 || content.length < 10) {
            return res.status(400).json({ error: 'Content must be 10-50000 characters' });
        }

        // Verify user is admin
        const userDoc = await db.collection('users').doc(req.user.uid).get();
        if (!userDoc.exists || userDoc.data()?.role !== 'admin') {
            return res.status(403).json({ error: 'Admin access required' });
        }

        // Validate links
        if (Array.isArray(links)) {
            for (const link of links) {
                if (!link.url || !isValidUrl(link.url)) {
                    return res.status(400).json({ error: 'Invalid URL in links' });
                }
            }
        }

        // Create post
        const postRef = await db.collection('posts').add({
            title: title.trim(),
            subtitle: subtitle.trim(),
            content,
            category,
            imageCID,
            links,
            authorId: req.user.uid,
            likes: 0,
            likedBy: [],
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
            status: 'published'
        });

        res.status(201).json({
            success: true,
            postId: postRef.id,
            message: 'Post created successfully'
        });

    } catch (error) {
        console.error('Error creating post:', error.message);
        res.status(500).json({ error: 'Failed to create post' });
    }
});

app.put('/api/posts/:postId', verifyToken, async (req, res) => {
    try {
        const { postId } = req.params;
        const { title, content, category, imageCID, links, subtitle } = req.body;

        // Get post
        const postDoc = await db.collection('posts').doc(postId).get();
        if (!postDoc.exists) {
            return res.status(404).json({ error: 'Post not found' });
        }

        const post = postDoc.data();

        // Verify authorization
        const userDoc = await db.collection('users').doc(req.user.uid).get();
        const isAdmin = userDoc.data()?.role === 'admin';
        const isAuthor = post.authorId === req.user.uid;

        if (!isAdmin && !isAuthor) {
            return res.status(403).json({ error: 'Not authorized to update this post' });
        }

        // Validate inputs
        if (title && (title.length > 200 || title.length < 5)) {
            return res.status(400).json({ error: 'Title must be 5-200 characters' });
        }

        if (content && content.length > 50000) {
            return res.status(400).json({ error: 'Content too long' });
        }

        // Update post
        const updateData = {};
        if (title) updateData.title = title.trim();
        if (subtitle !== undefined) updateData.subtitle = subtitle.trim();
        if (content) updateData.content = content;
        if (category) updateData.category = category;
        if (imageCID) updateData.imageCID = imageCID;
        if (links) updateData.links = links;

        updateData.updatedAt = admin.firestore.FieldValue.serverTimestamp();

        await db.collection('posts').doc(postId).update(updateData);

        res.json({ success: true, message: 'Post updated successfully' });

    } catch (error) {
        console.error('Error updating post:', error.message);
        res.status(500).json({ error: 'Failed to update post' });
    }
});

app.delete('/api/posts/:postId', verifyToken, async (req, res) => {
    try {
        const { postId } = req.params;

        const postDoc = await db.collection('posts').doc(postId).get();
        if (!postDoc.exists) {
            return res.status(404).json({ error: 'Post not found' });
        }

        const post = postDoc.data();

        // Verify authorization
        const userDoc = await db.collection('users').doc(req.user.uid).get();
        const isAdmin = userDoc.data()?.role === 'admin';
        const isAuthor = post.authorId === req.user.uid;

        if (!isAdmin && !isAuthor) {
            return res.status(403).json({ error: 'Not authorized' });
        }

        // Delete associated comments in batch
        const comments = await db
            .collection('comments')
            .where('postId', '==', postId)
            .get();

        const batch = db.batch();
        comments.forEach((doc) => batch.delete(doc.ref));
        batch.delete(db.collection('posts').doc(postId));

        await batch.commit();

        res.json({ success: true, message: 'Post deleted successfully' });

    } catch (error) {
        console.error('Error deleting post:', error.message);
        res.status(500).json({ error: 'Failed to delete post' });
    }
});

// ==================== USER ENDPOINTS ====================

app.get('/api/user/profile', verifyToken, async (req, res) => {
    try {
        const userDoc = await db.collection('users').doc(req.user.uid).get();

        if (!userDoc.exists) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({
            uid: req.user.uid,
            ...userDoc.data()
        });

    } catch (error) {
        console.error('Error fetching profile:', error.message);
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
});

// ==================== UTILITY FUNCTIONS ====================

function isValidUrl(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

// ==================== ERROR HANDLING ====================

app.use((err, req, res, next) => {
    console.error('Error:', err);

    if (err.message === 'CORS not allowed') {
        return res.status(403).json({ error: 'CORS policy violation' });
    }

    if (err.message.includes('Invalid file type')) {
        return res.status(400).json({ error: 'Only image files allowed (JPEG, PNG, WebP, GIF)' });
    }

    if (err.message.includes('File too large')) {
        return res.status(413).json({ error: 'File exceeds 10MB limit' });
    }

    res.status(500).json({
        error: 'Internal server error'
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// ==================== EXPORT FOR VERCEL ====================
module.exports = app;
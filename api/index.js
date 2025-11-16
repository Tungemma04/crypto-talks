// api/index.js
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const FormData = require('form-data');
const fetch = require('node-fetch');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Configure multer for memory storage
const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({ 
    message: 'Crypto Talks API is running!',
    endpoints: {
      upload: '/api/upload (POST)'
    }
  });
});

// Health check endpoint (alias)
app.get('/api', (req, res) => {
  res.json({ 
    message: 'Crypto Talks API is running!',
    endpoints: {
      upload: '/api/upload (POST)'
    }
  });
});

// Upload endpoint
app.post('/api/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file provided' });
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
        uploadedBy: 'CryptoTalks',
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
      body: formData
    });

    const result = await response.json();

    if (result.IpfsHash) {
      return res.status(200).json({
        success: true,
        cid: result.IpfsHash,
        url: `https://gateway.pinata.cloud/ipfs/${result.IpfsHash}`,
        size: result.PinSize
      });
    }

    throw new Error('Upload failed: ' + JSON.stringify(result));
  } catch (error) {
    console.error('Upload error:', error);
    return res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Export for Vercel serverless functions
module.exports = app;
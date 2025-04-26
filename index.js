// index.js - Complete Binance API proxy server
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const cors = require('cors');
const dotenv = require('dotenv');
const morgan = require('morgan');
const fs = require('fs');
const path = require('path');
const rateLimit = require('express-rate-limit');

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const API_SECRET = process.env.API_SECRET || 'your_default_secret_key';

// Create logs directory if it doesn't exist
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir);
}

// Create a write stream for access logs
const accessLogStream = fs.createWriteStream(
  path.join(logsDir, 'access.log'), 
  { flags: 'a' }
);

// Middleware
app.use(express.json());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? 
    process.env.ALLOWED_ORIGINS.split(',') : 
    '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(morgan('combined', { stream: accessLogStream }));

// Rate limiting middleware
const apiLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW) || 60000, // 1 minute
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later' }
});

// Apply rate limiting to all routes
app.use(apiLimiter);

// API keys storage - in production, use a secure database
// Format: { userId: { key: "api_key", secret: "api_secret", createdAt: timestamp } }
const API_KEYS = {};

// Encrypt function for sensitive data
function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', 
    Buffer.from(API_SECRET.padEnd(32).slice(0, 32)), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return `${iv.toString('hex')}:${encrypted}`;
}

// Decrypt function for sensitive data
function decrypt(encryptedText) {
  const parts = encryptedText.split(':');
  if (parts.length !== 2) throw new Error('Invalid encrypted data format');
  
  const iv = Buffer.from(parts[0], 'hex');
  const encrypted = parts[1];
  const decipher = crypto.createDecipheriv('aes-256-cbc', 
    Buffer.from(API_SECRET.padEnd(32).slice(0, 32)), iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Register API keys endpoint
app.post('/api/register-key', async (req, res) => {
  try {
    const { userId, apiKey, apiSecret } = req.body;
    console.log(apiKey, apiSecret);
    if (!userId || !apiKey || !apiSecret) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    // Log registration attempt
    console.log(`API key registration attempt for userId: ${userId}`);
    
    // Test the API key before storing it
    try {
      // Generate parameters for Binance API test request
      const timestamp = Date.now();
      const queryString = `timestamp=${timestamp}`;
      
      // Generate signature
      const signature = crypto
        .createHmac("sha256", apiSecret)
        .update(queryString)
        .digest("hex");
      
      // URL with signature
      const url = `https://api.binance.com/api/v3/account?${queryString}&signature=${signature}`;
      
      // Make test request
      const response = await axios({
        method: 'GET',
        url: url,
        headers: {
          'X-MBX-APIKEY': apiKey,
          'User-Agent': 'Mozilla/5.0 ProxyServer/1.0',
          'Accept': 'application/json'
        },
        timeout: 10000
      });
      
      // If we get here, API key is valid
      console.log(`API key test successful for userId: ${userId}`);
    } catch (error) {
      console.error(`API key test failed for userId: ${userId}:`, error);
      
      // Handle specific error types
      if (axios.isAxiosError(error)) {
        const status = error.response?.status;
        const data = error.response?.data;
        
        if (status === 401) {
          return res.status(401).json({ error: 'Invalid API key' });
        } else if (status === 403) {
          return res.status(403).json({ error: 'Insufficient permissions for API key' });
        } else if (data?.msg) {
          return res.status(status || 400).json({ error: data.msg });
        }
      }
      
      return res.status(400).json({ error: 'Failed to validate API key' });
    }
    
    // Store API key (encrypted in a real production environment)
    API_KEYS[userId] = {
      key: apiKey,
      secret: apiSecret,
      createdAt: new Date().toISOString()
    };
    
    console.log(`API key registered successfully for userId: ${userId}`);
    
    return res.status(200).json({
      success: true,
      message: 'API key registered successfully',
      userId,
      createdAt: API_KEYS[userId].createdAt
    });
  } catch (error) {
    console.error('Error registering API key:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Get registered API keys (limited info, no secrets)
app.get('/api/user/:userId/key-status', (req, res) => {
  const { userId } = req.params;
  
  if (!userId) {
    return res.status(400).json({ error: 'Missing user ID' });
  }
  
  // Check if user has registered an API key
  const keyInfo = API_KEYS[userId];
  if (!keyInfo) {
    return res.status(404).json({ registered: false });
  }
  
  // Return limited info (never expose the actual API key or secret)
  return res.json({
    registered: true,
    createdAt: keyInfo.createdAt
  });
});

// Delete API key
app.delete('/api/user/:userId/key', (req, res) => {
  const { userId } = req.params;
  
  if (!userId) {
    return res.status(400).json({ error: 'Missing user ID' });
  }
  
  // Check if user exists
  if (!API_KEYS[userId]) {
    return res.status(404).json({ error: 'API key not found' });
  }
  
  // Delete the API key
  delete API_KEYS[userId];
  console.log(`Deleted API key for user ${userId}`);
  
  return res.json({ success: true });
});

// Main proxy endpoint for Binance API
app.post('/api/proxy/binance', async (req, res) => {
  try {
    const { userId, endpoint, method = 'GET', params = {} } = req.body;
    
    // Validate request
    if (!userId || !endpoint) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    // Get API credentials for the user
    const credentials = API_KEYS[userId];
    if (!credentials) {
      return res.status(404).json({ error: 'API key not found for user' });
    }
    
    console.log(`Processing request for user ${userId}: ${method} ${endpoint}`);
    
    // Add timestamp for signature
    const timestamp = Date.now();
    const requestParams = {
      ...params,
      timestamp
    };
    
    // Create query string
    const queryString = Object.entries(requestParams)
      .map(([key, value]) => `${key}=${encodeURIComponent(String(value))}`)
      .join('&');
    
    // Generate signature
    const signature = crypto
      .createHmac('sha256', credentials.secret)
      .update(queryString)
      .digest('hex');
    
    // Full URL with signature
    const url = `https://api.binance.com${endpoint}?${queryString}&signature=${signature}`;
    
    // Make the request
    const response = await axios({
      method,
      url,
      headers: {
        'X-MBX-APIKEY': credentials.key,
        'User-Agent': 'Mozilla/5.0 ProxyServer/1.0',
        'Accept': 'application/json'
      },
      timeout: 10000,
      validateStatus: () => true // Process any status code
    });
    
    // Log successful requests
    if (response.status >= 200 && response.status < 300) {
      console.log(`Request successful: ${method} ${endpoint} - Status: ${response.status} ${response}`);
    } else {
      console.warn(`Request failed: ${method} ${endpoint} - Status: ${response.status} ${response}`);
      if (response.data) {
        console.warn('Error response:', JSON.stringify(response.data).substring(0, 200));
      }
    }
    
    // Return the response data and status
    return res.status(response.status).json({
      success: response.status >= 200 && response.status < 300,
      statusCode: response.status,
      data: response.data
    });
    
  } catch (error) {
    console.error('Proxy error:', error.message);
    
    if (axios.isAxiosError(error)) {
      // Return the error response directly
      return res.status(error.response?.status || 500).json({
        success: false,
        statusCode: error.response?.status || 500,
        error: error.response?.data || error.message,
        message: 'API request failed'
      });
    }
    
    return res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Server info endpoint
app.get('/info', (req, res) => {
  res.json({
    name: 'Binance API Proxy Server',
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    timestamp: new Date().toISOString()
  });
});

// Handle 404
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error', message: err.message });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Binance proxy server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Started at: ${new Date().toISOString()}`);
});
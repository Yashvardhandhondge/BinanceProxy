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
const API_SECRET = process.env.API_SECRET || 'yash';

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

// Function to fetch all symbol prices for USDC conversion
async function fetchAllPrices() {
  try {
    const response = await axios({
      method: 'GET',
      url: 'https://api.binance.com/api/v3/ticker/price',
      headers: {
        'User-Agent': 'Mozilla/5.0 ProxyServer/1.0',
        'Accept': 'application/json'
      }
    });
    
    // Create a price map for quick lookups
    const priceMap = {};
    response.data.forEach(item => {
      priceMap[item.symbol] = parseFloat(item.price);
    });
    
    console.log(`Fetched prices for ${Object.keys(priceMap).length} symbols`);
    return priceMap;
  } catch (error) {
    console.error('Error fetching prices:', error.message);
    return {};
  }
}

// Function to calculate USDC value of assets
function calculateAssetValues(balances, priceMap) {
  const result = [];
  let totalUsdcValue = 0;
  
  balances.forEach(asset => {
    const free = parseFloat(asset.free);
    const locked = parseFloat(asset.locked);
    const total = free + locked;
    
    // Skip assets with zero balance
    if (total <= 0) return;
    
    // Try different pairs to get USDC value
    let usdcValue = 0;
    let conversionPath = '';
    
    if (asset.asset === 'USDC') {
      usdcValue = total;
      conversionPath = 'Direct';
    } else if (priceMap[`${asset.asset}USDC`]) {
      usdcValue = total * priceMap[`${asset.asset}USDC`];
      conversionPath = `${asset.asset}USDC`;
    } else if (priceMap[`USDC${asset.asset}`]) {
      usdcValue = total / priceMap[`USDC${asset.asset}`];
      conversionPath = `USDC${asset.asset} (inverse)`;
    } else if (priceMap[`${asset.asset}USDT`]) {
      // Assume 1 USDT ≈ 1 USDC for approximate valuation
      usdcValue = total * priceMap[`${asset.asset}USDT`];
      conversionPath = `${asset.asset}USDT (as proxy)`;
    } else if (priceMap[`${asset.asset}BTC`] && priceMap['BTCUSDC']) {
      usdcValue = total * priceMap[`${asset.asset}BTC`] * priceMap['BTCUSDC'];
      conversionPath = `${asset.asset}BTC → BTCUSDC`;
    } else {
      conversionPath = 'No conversion path';
    }
    
    totalUsdcValue += usdcValue;
    
    result.push({
      asset: asset.asset,
      free,
      locked,
      total,
      usdcValue: usdcValue.toFixed(2),
      conversionPath
    });
  });
  
  // Sort by USDC value (descending)
  result.sort((a, b) => parseFloat(b.usdcValue) - parseFloat(a.usdcValue));
  
  return {
    assets: result,
    totalUsdcValue: totalUsdcValue.toFixed(2)
  };
}

// Function to fetch Funding wallet balance
async function fetchFundingWallet(apiKey, apiSecret) {
  try {
    const timestamp = Date.now();
    const queryString = `timestamp=${timestamp}`;
    
    const signature = crypto
      .createHmac('sha256', apiSecret)
      .update(queryString)
      .digest('hex');
    
    const url = `https://api.binance.com/sapi/v1/asset/get-funding-asset?${queryString}&signature=${signature}`;
    
    const response = await axios({
      method: 'POST',
      url: url,
      headers: {
        'X-MBX-APIKEY': apiKey,
        'User-Agent': 'Mozilla/5.0 ProxyServer/1.0',
        'Accept': 'application/json'
      },
      timeout: 10000
    });
    
    console.log(`Fetched funding wallet with ${response.data.length} assets`);
    
    // Transform to match standard balance format
    return response.data.map(item => ({
      asset: item.asset,
      free: item.free,
      locked: item.locked || '0',
      freeze: item.freeze || '0',
      withdrawing: item.withdrawing || '0',
      btcValuation: item.btcValuation,
      walletType: 'FUNDING'
    }));
  } catch (error) {
    console.error('Error fetching funding wallet:', error.message);
    return [];
  }
}

// Function to fetch all wallet balances (Spot, Funding, etc.)
async function fetchAllWalletBalances(credentials) {
  try {
    const results = {
      SPOT: [],
      FUNDING: [],
      OTHER: [] // For any future wallet types
    };
    
    // 1. Fetch Spot wallet (main account)
    const timestamp = Date.now();
    const queryString = `timestamp=${timestamp}`;
    
    const signature = crypto
      .createHmac('sha256', credentials.secret)
      .update(queryString)
      .digest('hex');
    
    const spotUrl = `https://api.binance.com/api/v3/account?${queryString}&signature=${signature}`;
    
    const spotResponse = await axios({
      method: 'GET',
      url: spotUrl,
      headers: {
        'X-MBX-APIKEY': credentials.key,
        'User-Agent': 'Mozilla/5.0 ProxyServer/1.0',
        'Accept': 'application/json'
      },
      timeout: 10000
    });
    
    // Get all non-zero balances from spot account
    const nonZeroSpotBalances = spotResponse.data.balances
      .filter(asset => parseFloat(asset.free) > 0 || parseFloat(asset.locked) > 0)
      .map(asset => ({...asset, walletType: 'SPOT'}));
    
    results.SPOT = nonZeroSpotBalances;
    
    // 2. Fetch Funding wallet
    const fundingBalances = await fetchFundingWallet(credentials.key, credentials.secret);
    results.FUNDING = fundingBalances;
    
    // 3. Try to fetch cross-margin account (if needed)
    try {
      const marginTimestamp = Date.now();
      const marginQueryString = `timestamp=${marginTimestamp}`;
      
      const marginSignature = crypto
        .createHmac('sha256', credentials.secret)
        .update(marginQueryString)
        .digest('hex');
      
      const marginUrl = `https://api.binance.com/sapi/v1/margin/account?${marginQueryString}&signature=${marginSignature}`;
      
      const marginResponse = await axios({
        method: 'GET',
        url: marginUrl,
        headers: {
          'X-MBX-APIKEY': credentials.key,
          'User-Agent': 'Mozilla/5.0 ProxyServer/1.0',
          'Accept': 'application/json'
        },
        timeout: 10000
      });
      
      // Process margin balances if needed
      if (marginResponse.data.userAssets) {
        const nonZeroMarginBalances = marginResponse.data.userAssets
          .filter(asset => parseFloat(asset.free) > 0 || parseFloat(asset.locked) > 0)
          .map(asset => ({...asset, walletType: 'MARGIN'}));
        
        results.OTHER = [...results.OTHER, ...nonZeroMarginBalances];
        console.log(`Fetched margin account with ${nonZeroMarginBalances.length} assets`);
      }
    } catch (marginError) {
      // Margin account might not be enabled, so we'll just log and continue
      console.log('Note: Could not fetch margin account (possibly not enabled)');
    }
    
    return results;
  } catch (error) {
    console.error('Error fetching wallets:', error.message);
    throw error;
  }
}

// Function to prepare combined wallet data with USDC values
async function prepareWalletData(credentials) {
  // Fetch all wallet balances
  const wallets = await fetchAllWalletBalances(credentials);
  
  // Fetch current prices for conversion
  console.log("Fetching current market prices for USDC conversion...");
  const priceMap = await fetchAllPrices();
  
  // Process each wallet type
  const processedWallets = {};
  let totalUsdcValue = 0;
  
  for (const [walletType, balances] of Object.entries(wallets)) {
    if (balances.length > 0) {
      const walletValues = calculateAssetValues(balances, priceMap);
      processedWallets[walletType] = walletValues;
      totalUsdcValue += parseFloat(walletValues.totalUsdcValue);
      
      console.log(`===== ${walletType} WALLET (${walletValues.totalUsdcValue} USDC) =====`);
      walletValues.assets.forEach(asset => {
        console.log(
          `${asset.asset}: ${asset.total} (≈ ${asset.usdcValue} USDC) [${asset.conversionPath}]`
        );
      });
    }
  }
  
  return {
    timestamp: new Date().toISOString(),
    totalUsdcValue: totalUsdcValue.toFixed(2),
    wallets: processedWallets
  };
}

// Main proxy endpoint for Binance API
app.post('/api/proxy/binance', async (req, res) => {
  try {
    const { userId, endpoint, method = 'GET', params = {} } = req.body;
    
    // Get API credentials for the user
    const credentials = API_KEYS[userId];
    if (!credentials) {
      return res.status(404).json({ error: 'API key not found for user' });
    }
    
    console.log(`Processing ${method} request to ${endpoint} for user ${userId}`);
    
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
    
    console.log(`Making request to: ${endpoint} [Request ID: ${timestamp}]`);
    
    // Make the request to Binance
    const response = await axios({
      method,
      url,
      headers: {
        'X-MBX-APIKEY': credentials.key,
        'User-Agent': 'Mozilla/5.0 ProxyServer/1.0',
        'Accept': 'application/json'
      },
      timeout: 10000
    });
    
    console.log(`Received ${response.status} response for ${endpoint} [Request ID: ${timestamp}]`);
    
    // Special handling for account endpoint to extract and log balances
    if (endpoint === '/api/v3/account') {
      console.log(`===== ACCOUNT INFORMATION FOR USER ${userId} =====`);
      console.log(`Account type: ${response.data.accountType}`);
      console.log(`Can trade: ${response.data.canTrade}`);
      console.log(`Can withdraw: ${response.data.canWithdraw}`);
      console.log(`Can deposit: ${response.data.canDeposit}`);
      
      // Get all balances with non-zero amounts
      const nonZeroBalances = response.data.balances.filter(
        asset => parseFloat(asset.free) > 0 || parseFloat(asset.locked) > 0
      );
      
      console.log(`Found ${nonZeroBalances.length} assets with non-zero balance`);
      
      // Fetch current prices for conversion
      console.log("Fetching current market prices for USDC conversion...");
      const priceMap = await fetchAllPrices();
      
      // Calculate and log USDC values
      const assetValues = calculateAssetValues(nonZeroBalances, priceMap);
      
      console.log(`===== BALANCE SUMMARY (Total: ${assetValues.totalUsdcValue} USDC) =====`);
      assetValues.assets.forEach(asset => {
        console.log(
          `${asset.asset}: ${asset.total} (≈ ${asset.usdcValue} USDC) [${asset.conversionPath}]`
        );
      });
      
      // Add the calculated values to the response
      response.data.calculatedBalances = {
        timestamp: new Date().toISOString(),
        totalUsdcValue: assetValues.totalUsdcValue,
        assets: assetValues.assets
      };
      
      // Log to a separate balance log file
      try {
        const balanceLog = {
          userId,
          timestamp: new Date().toISOString(),
          totalUsdcValue: assetValues.totalUsdcValue,
          assets: assetValues.assets
        };
        
        fs.appendFileSync(
          path.join(logsDir, 'balance_logs.json'),
          JSON.stringify(balanceLog) + '\n'
        );
      } catch (logError) {
        console.error('Error writing to balance log:', logError);
      }
    }
    
    // Return the response data directly without modification
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

// New endpoint to directly get all wallet balances
app.get('/api/user/:userId/all-balances', async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Get API credentials for the user
    const credentials = API_KEYS[userId];
    if (!credentials) {
      return res.status(404).json({ error: 'API key not found for user' });
    }
    
    console.log(`Fetching all wallet balances for user ${userId}`);
    
    // Get comprehensive wallet data
    const walletData = await prepareWalletData(credentials);
    
    // Log summary
    console.log(`===== SUMMARY FOR USER ${userId} =====`);
    console.log(`Total across all wallets: ${walletData.totalUsdcValue} USDC`);
    for (const walletType of Object.keys(walletData.wallets)) {
      console.log(`${walletType}: ${walletData.wallets[walletType].totalUsdcValue} USDC`);
    }
    
    // Log to a separate balance log file
    try {
      const balanceLog = {
        userId,
        timestamp: walletData.timestamp,
        totalUsdcValue: walletData.totalUsdcValue,
        wallets: walletData.wallets
      };
      
      fs.appendFileSync(
        path.join(logsDir, 'all_wallets_logs.json'),
        JSON.stringify(balanceLog) + '\n'
      );
    } catch (logError) {
      console.error('Error writing to wallet log:', logError);
    }
    
    // Return formatted balance information
    return res.json({
      success: true,
      ...walletData
    });
  } catch (error) {
    console.error('Balance fetch error:', error.message);
    
    if (axios.isAxiosError(error)) {
      return res.status(error.response?.status || 500).json({
        success: false,
        error: error.response?.data || error.message
      });
    }
    
    return res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message
    });
  }
});

// Update the existing balance endpoint to use the new comprehensive function
app.get('/api/user/:userId/balance', async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Get API credentials for the user
    const credentials = API_KEYS[userId];
    if (!credentials) {
      return res.status(404).json({ error: 'API key not found for user' });
    }
    
    console.log(`Fetching balance for user ${userId} (all wallets)`);
    
    // Get comprehensive wallet data
    const walletData = await prepareWalletData(credentials);
    
    // Return formatted balance information
    return res.json({
      success: true,
      timestamp: walletData.timestamp,
      totalUsdcValue: walletData.totalUsdcValue,
      wallets: walletData.wallets
    });
  } catch (error) {
    console.error('Balance fetch error:', error.message);
    
    if (axios.isAxiosError(error)) {
      return res.status(error.response?.status || 500).json({
        success: false,
        error: error.response?.data || error.message
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
require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');
const xss = require('xss-clean');
const compression = require('compression');
const cookieParser = require('cookie-parser');

const app = express();

// =====================
// ENVIRONMENT VALIDATION
// =====================
const requiredEnvVars = [
  'JWT_SECRET', 
  'EMAIL_USER', 
  'EMAIL_PASS'
];

const missingVars = requiredEnvVars.filter(v => !process.env[v]);
if (missingVars.length > 0) {
  console.error('❌ Missing required environment variables:', missingVars.join(', '));
  console.error('💡 Please check your .env file');
  process.exit(1);
}

// ================
// SECURITY MIDDLEWARE
// ================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false
}));

app.use(compression());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(cookieParser());
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// =============
// CORS CONFIG - FIXED
// =============
const allowedOrigins = process.env.NODE_ENV === 'production' ? [
  'https://banddcleaning.com.au',
  'https://www.banddcleaning.com.au',
  'https://admin.banddcleaning.com.au'
] : [
  'http://localhost:3000',
  'http://localhost:3001',
  'http://localhost:5500',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:5500'
];

app.use(cors({
  origin: (origin, callback) => {
    console.log(`🔍 Request origin: ${origin}`);
    
    // Allow requests with no origin in development only
    if (!origin && process.env.NODE_ENV === 'development') {
      console.log('✅ Allowing null origin in development');
      return callback(null, true);
    }
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      console.log(`✅ CORS allowed for origin: ${origin}`);
      callback(null, true);
    } else {
      console.log(`❌ CORS blocked request from: ${origin}`);
      callback(new Error('Not allowed by CORS policy'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With'
  ],
  exposedHeaders: [],
  maxAge: 300
}));

// ================
// RATE LIMITING - COMPLETELY FIXED
// ================
const createRateLimiter = (options = {}) => {
  return rateLimit({
    windowMs: options.windowMs || 15 * 60 * 1000, // 15 minutes
    max: options.max || (process.env.NODE_ENV === 'production' ? 100 : 500),
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    skip: (req) => {
      return req.path === '/health' && 
             (req.ip === '127.0.0.1' || req.ip === '::1');
    },
    handler: (req, res) => {
      console.warn(`⚠️ Rate limit exceeded: ${req.ip} on ${req.method} ${req.path}`);
      res.status(429).json({
        error: 'Too many requests',
        message: 'Please try again later.',
        retryAfter: Math.ceil((options.windowMs || 15 * 60 * 1000) / 1000)
      });
    }
    // NO onLimitReached - this was causing the deprecation warning
  });
};

// Apply rate limiting
const generalLimiter = createRateLimiter();
const authLimiter = createRateLimiter({ 
  windowMs: 15 * 60 * 1000,
  max: 5 
});
const quoteLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000,
  max: 10
});

app.use(generalLimiter);
app.use('/api/auth/', authLimiter);
app.use('/api/quotes/', quoteLimiter);

// =================
// EMAIL CONFIG - FIXED TIMING
// =================
let emailTransporter = null;
let emailStatus = 'initializing';

const initializeEmail = () => {
  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      },
      tls: {
        rejectUnauthorized: false
      }
    });

    // Verify email connection
    transporter.verify((error, success) => {
      if (error) {
        console.warn('⚠️ Email server connection failed:', error.message);
        emailTransporter = null;
        emailStatus = 'failed';
      } else {
        emailTransporter = transporter;
        emailStatus = 'ready';
        console.log('✅ Email server ready');
      }
    });
  } catch (error) {
    console.warn('⚠️ Email configuration error:', error.message);
    emailTransporter = null;
    emailStatus = 'error';
  }
};

// Initialize email
initializeEmail();

// ================
// JWT UTILITIES
// ================
const createToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: '1h',
    algorithm: 'HS256',
    issuer: 'banddcleaning-api',
    audience: 'banddcleaning-web',
    jwtid: uuidv4()
  });
};

const verifyToken = (token) => {
  return jwt.verify(token, process.env.JWT_SECRET, {
    algorithms: ['HS256'],
    issuer: 'banddcleaning-api',
    audience: 'banddcleaning-web'
  });
};

// ================
// AUTH MIDDLEWARE
// ================
const authenticate = (req, res, next) => {
  console.log('🔐 Authentication check for:', req.path);
  
  const token = req.cookies?.token;
  console.log('Cookies:', req.cookies);
  console.log('Authorization header:', req.headers.authorization);
  console.log('Token found:', token ? 'Yes' : 'No');
  
  if (!token) {
    console.log('❌ No token provided');
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    console.log('🔍 Verifying token...');
    const decoded = verifyToken(token);
    console.log('✅ Token decoded successfully:', decoded);
    
    req.user = {
      id: decoded.id,
      role: decoded.role,
      sessionId: decoded.jti
    };
    
    console.log('✅ User authenticated:', req.user);
    next();
  } catch (err) {
    console.warn(`⚠️ JWT Error: ${err.message}`);
    res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// ================
// STATIC FILES
// ================
app.use(express.static(path.join(__dirname, 'public')));

// ================
// API ROUTES
// ================

// Admin login endpoint
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    console.log('Login attempt for:', email);
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    
    const adminPath = path.join(__dirname, 'admin.json');
    if (!fs.existsSync(adminPath)) {
      return res.status(500).json({ error: 'Admin configuration not found' });
    }
    
    const adminData = JSON.parse(fs.readFileSync(adminPath, 'utf8'));
    console.log('Admin email from file:', adminData.email);
    
    if (email.toLowerCase() !== adminData.email.toLowerCase()) {
      console.log('Email does not match');
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    console.log('Checking password against hash');
    const isValidPassword = await bcrypt.compare(password, adminData.passwordHash);
    console.log('Password valid:', isValidPassword);
    
    if (!isValidPassword) {
      console.log('Invalid password');
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = createToken({
      id: adminData.email,
      role: 'admin'
    });
    
    console.log('Token created successfully');
    
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 3600000
    });
    
    adminData.lastLogin = new Date().toISOString();
    fs.writeFileSync(adminPath, JSON.stringify(adminData, null, 2));
    
    console.log('Login successful for:', email);
    res.json({
      success: true,
      message: 'Login successful'
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Logout endpoint
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true, message: 'Logged out successfully' });
});

// Quote submission endpoint
app.post('/api/quotes', async (req, res) => {
  try {
    const { name, email, phone, serviceType, message, preferredDate } = req.body;
    
    if (!name || !email || !phone || !serviceType) {
      return res.status(400).json({ 
        error: 'Missing required fields: name, email, phone, serviceType' 
      });
    }

    const quote = {
      id: uuidv4(),
      name: name.trim(),
      email: email.trim().toLowerCase(),
      phone: phone.trim(),
      serviceType,
      message: message?.trim() || '',
      preferredDate: preferredDate || null,
      submittedAt: new Date().toISOString(),
      status: 'new'
    };

    // Save quote to file
    const quotesPath = path.join(__dirname, 'quotes.json');
    let quotes = [];
    
    if (fs.existsSync(quotesPath)) {
      quotes = JSON.parse(fs.readFileSync(quotesPath, 'utf8'));
    }
    
    quotes.push(quote);
    fs.writeFileSync(quotesPath, JSON.stringify(quotes, null, 2));

    // Send email if configured
    if (emailTransporter) {
      try {
        await emailTransporter.sendMail({
          from: process.env.EMAIL_USER,
          to: process.env.EMAIL_RECEIVER || process.env.EMAIL_USER,
          subject: `New Quote Request - ${serviceType}`,
          html: `
            <h2>New Quote Request</h2>
            <p><strong>Name:</strong> ${quote.name}</p>
            <p><strong>Email:</strong> ${quote.email}</p>
            <p><strong>Phone:</strong> ${quote.phone}</p>
            <p><strong>Service:</strong> ${quote.serviceType}</p>
            <p><strong>Preferred Date:</strong> ${quote.preferredDate || 'Not specified'}</p>
            <p><strong>Message:</strong><br>${quote.message || 'No additional message'}</p>
          `
        });
        console.log('✅ Quote email sent successfully');
      } catch (emailError) {
        console.warn('⚠️ Failed to send quote email:', emailError.message);
      }
    }

    res.json({
      success: true,
      message: 'Quote request submitted successfully',
      quoteId: quote.id
    });

  } catch (error) {
    console.error('Quote submission error:', error);
    res.status(500).json({ error: 'Failed to submit quote request' });
  }
});

// Admin routes
app.get('/api/admin/quotes', authenticate, (req, res) => {
  try {
    const quotesPath = path.join(__dirname, 'quotes.json');
    let quotes = [];
    
    if (fs.existsSync(quotesPath)) {
      quotes = JSON.parse(fs.readFileSync(quotesPath, 'utf8'));
    }
    
    res.json({ quotes });
  } catch (error) {
    console.error('Error fetching quotes:', error);
    res.status(500).json({ error: 'Failed to fetch quotes' });
  }
});

// ================
// STATIC ROUTES
// ================
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/admin', authenticate, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// ================
// SERVER STARTUP - FIXED EMAIL STATUS
// ================
const PORT = process.env.PORT || 3000;
const rateLimitMax = process.env.NODE_ENV === 'production' ? 100 : 500;

const server = app.listen(PORT, () => {
  console.log(`🚀 Server running in ${process.env.NODE_ENV || 'development'} mode on port ${PORT}`);
  
  console.log('🔒 Security Features Active:');
  console.log(`- CORS: ${allowedOrigins.join(', ')}`);
  console.log(`- Rate Limiting: ${rateLimitMax} req/15min`);
  console.log(`- JWT: HS256 with 1h expiration`);
  console.log(`- HTTPS Headers: ${process.env.NODE_ENV === 'production' ? 'Production' : 'Development'}`);
  
  // Don't show email status immediately - it's still initializing
  console.log('📧 Email: Initializing...');
});

// Graceful shutdown
const gracefulShutdown = (signal) => {
  console.log(`${signal} received, shutting down gracefully`);
  
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
  
  setTimeout(() => {
    console.error('Forced shutdown');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err.message);
  process.exit(1);
});

process.on('unhandledRejection', (err) => {
  console.error('Unhandled Rejection:', err.message);
  process.exit(1);
});

module.exports = app;
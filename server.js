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

// Database imports
const { initializeDatabase, Quote, Admin } = require('./models/database');
const QuoteService = require('./services/quoteService');
const { createCorsMiddleware, corsSecurityMiddleware } = require('./middleware/corsMiddleware');

const app = express();

// =====================
// DATABASE INITIALIZATION
// =====================
let dbInitialized = false;

// Initialize database on startup
initializeDatabase()
  .then(() => {
    dbInitialized = true;
    console.log('🗄️ Database ready');
  })
  .catch((error) => {
    console.error('❌ Database initialization failed:', error.message);
    process.exit(1);
  });

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
// SECURITY MIDDLEWARE - MORE PERMISSIVE CSP FOR DEVELOPMENT
// ================
app.use(helmet({
  contentSecurityPolicy: process.env.NODE_ENV === 'production' ? {
    // Strict CSP for production
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      scriptSrcAttr: ["'none'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  } : {
    // Permissive CSP for development
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      scriptSrcElem: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
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

// ================
// CORS CONFIGURATION - COMPLETE SECURITY
// ================
const allowedOrigins = process.env.NODE_ENV === 'production' ? [
  'https://banddcleaning.com.au',
  'https://www.banddcleaning.com.au',
  'https://admin.banddcleaning.com.au',
  'https://banddcleaning-com-au.onrender.com'
] : [
  'http://localhost:3000',
  'http://localhost:3001',
  'http://localhost:5500',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:5500',
  // Add production domains to dev for testing
  'https://banddcleaning.com.au',
  'https://www.banddcleaning.com.au',
  'https://admin.banddcleaning.com.au',
  'https://banddcleaning-com-au.onrender.com'
];

console.log('🔒 CORS Allowed Origins:', allowedOrigins);

// CORS middleware with STRICT security
app.use(cors({
  origin: (origin, callback) => {
    console.log('🔍 CORS Check - Origin:', origin || 'null');

    // Allow requests with no origin ONLY in development
    if (!origin) {
      if (process.env.NODE_ENV === 'development') {
        console.log('✅ CORS: Allowing null origin in development');
        return callback(null, true);
      } else {
        console.log('❌ CORS: Blocking null origin in production');
        return callback(new Error('Origin required in production'), false);
      }
    }

    // Check if origin is in allowed list
    if (allowedOrigins.includes(origin)) {
      console.log('✅ CORS: Origin allowed -', origin);
      return callback(null, true);
    }

    // BLOCK unauthorized origins - THIS WAS MISSING!
    console.warn('🚨 CORS: BLOCKED malicious origin -', origin);
    return callback(new Error(`CORS policy: Origin ${origin} not allowed`), false);
  },
  
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  maxAge: 300
}));

// Additional CORS security middleware
app.use((req, res, next) => {
  const origin = req.get('Origin');
  
  // Log all cross-origin requests for monitoring
  if (origin && !allowedOrigins.includes(origin)) {
    console.warn('🚨 SECURITY ALERT: Blocked cross-origin request');
    console.warn('  Origin:', origin);
    console.warn('  IP:', req.ip);
    console.warn('  Path:', req.path);
    console.warn('  Method:', req.method);
    console.warn('  User-Agent:', req.get('User-Agent'));
    console.warn('  Timestamp:', new Date().toISOString());
  }
  
  next();
});

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
// API ROUTES - UPDATED FOR DATABASE
// ================

// Admin login endpoint - updated for database
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    console.log('Login attempt for:', email);
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    
    // Find admin in database
    const admin = await Admin.findOne({ 
      where: { 
        email: email.toLowerCase(),
        is_active: true 
      } 
    });
    
    if (!admin) {
      console.log('Admin not found');
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if account is locked
    if (admin.locked_until && admin.locked_until > new Date()) {
      return res.status(423).json({ error: 'Account temporarily locked' });
    }
    
    console.log('Checking password against hash');
    const isValidPassword = await bcrypt.compare(password, admin.password_hash);
    
    if (!isValidPassword) {
      // Increment login attempts
      await admin.update({
        login_attempts: admin.login_attempts + 1,
        locked_until: admin.login_attempts >= 4 ? 
          new Date(Date.now() + 15 * 60 * 1000) : null // Lock for 15 minutes after 5 attempts
      });
      
      console.log('Invalid password');
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = createToken({
      id: admin.id,
      email: admin.email,
      role: admin.role
    });
    
    // Update login info
    await admin.update({
      last_login: new Date(),
      login_attempts: 0,
      locked_until: null
    });
    
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 3600000
    });
    
    console.log('Login successful for:', email);
    res.json({
      success: true,
      message: 'Login successful',
      user: {
        id: admin.id,
        email: admin.email,
        name: admin.name,
        role: admin.role
      }
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

// Quote submission endpoint - updated for database
app.post('/api/quotes', async (req, res) => {
  try {
    const { name, email, phone, serviceType, message, preferredDate } = req.body;
    
    if (!name || !email || !phone || !serviceType) {
      return res.status(400).json({ 
        error: 'Missing required fields: name, email, phone, serviceType' 
      });
    }

    // Create quote using database service
    const quote = await QuoteService.createQuote({
      name,
      email,
      phone,
      serviceType,
      message,
      preferredDate
    }, {
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Send email notification
    if (emailTransporter) {
      try {
        await emailTransporter.sendMail({
          from: process.env.EMAIL_USER,
          to: process.env.EMAIL_RECEIVER || process.env.EMAIL_USER,
          subject: `New Quote Request - ${serviceType}`,
          html: `
            <h2>🧹 New Quote Request</h2>
            <p><strong>Quote ID:</strong> ${quote.id}</p>
            <p><strong>Name:</strong> ${quote.name}</p>
            <p><strong>Email:</strong> ${quote.email}</p>
            <p><strong>Phone:</strong> ${quote.phone}</p>
            <p><strong>Service:</strong> ${quote.service_type}</p>
            <p><strong>Preferred Date:</strong> ${quote.preferred_date || 'Not specified'}</p>
            <p><strong>Message:</strong><br>${quote.message || 'No additional message'}</p>
            <p><strong>Submitted:</strong> ${quote.created_at}</p>
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

// Admin routes - updated for database
app.get('/api/admin/quotes', authenticate, async (req, res) => {
  try {
    const {
      page = 1,
      limit = 50,
      status,
      serviceType,
      search,
      startDate,
      endDate,
      sortBy,
      sortOrder
    } = req.query;

    const result = await QuoteService.getQuotes({
      page: parseInt(page),
      limit: parseInt(limit),
      status,
      serviceType,
      search,
      startDate,
      endDate,
      sortBy,
      sortOrder
    });

    res.json(result);
  } catch (error) {
    console.error('Error fetching quotes:', error);
    res.status(500).json({ error: 'Failed to fetch quotes' });
  }
});

// Get single quote
app.get('/api/admin/quotes/:id', authenticate, async (req, res) => {
  try {
    const quote = await QuoteService.getQuoteById(req.params.id);
    res.json({ quote });
  } catch (error) {
    console.error('Error fetching quote:', error);
    res.status(404).json({ error: error.message });
  }
});

// Update quote
app.put('/api/admin/quotes/:id', authenticate, async (req, res) => {
  try {
    const { status, quote_amount, notes } = req.body;
    
    const updates = {};
    if (status) updates.status = status;
    if (quote_amount !== undefined) updates.quote_amount = quote_amount;
    if (notes !== undefined) updates.notes = notes;

    const quote = await QuoteService.updateQuote(req.params.id, updates);
    res.json({ success: true, quote });
  } catch (error) {
    console.error('Error updating quote:', error);
    res.status(400).json({ error: error.message });
  }
});

// Delete quote
app.delete('/api/admin/quotes/:id', authenticate, async (req, res) => {
  try {
    await QuoteService.deleteQuote(req.params.id);
    res.json({ success: true, message: 'Quote deleted successfully' });
  } catch (error) {
    console.error('Error deleting quote:', error);
    res.status(400).json({ error: error.message });
  }
});

// Get quote statistics
app.get('/api/admin/stats', authenticate, async (req, res) => {
  try {
    const stats = await QuoteService.getQuoteStats();
    res.json(stats);
  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({ error: 'Failed to fetch statistics' });
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
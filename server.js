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

const { initializeDatabase, Quote, Admin } = require('./models/database');
const QuoteService = require('./services/quoteService');
const { createCorsMiddleware, corsSecurityMiddleware } = require('./middleware/corsMiddleware');

const app = express();

// =====================
// SECURITY CONFIGURATION
// =====================
// Strict security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdnjs.cloudflare.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      'style-src-elem': ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      connectSrc: ["'self'", "https://*.banddcleaning.com.au", "https://*.onrender.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'self'", "https://www.google.com"],
      upgradeInsecureRequests: [],
    },
  },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: true,
  crossOriginResourcePolicy: { policy: "same-site" },
  dnsPrefetchControl: true,
  frameguard: { action: "deny" },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  ieNoOpen: true,
  noSniff: true,
  originAgentCluster: true,
  permittedCrossDomainPolicies: { permittedPolicies: "none" },
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  xssFilter: true,
}));

// Basic security middleware
app.use(compression());
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// CORS configuration - strict production settings
app.use(createCorsMiddleware());
app.use(corsSecurityMiddleware);

// Form submission endpoint
app.post('/api/submit', async (req, res) => {
  try {
    const { name, email, phone, serviceType, preferredDate, frequency, address, message } = req.body;
    
    // Basic validation
    if (!name || !email || !serviceType || !message) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Create quote record
    const quote = new Quote({
      name,
      email,
      phone,
      serviceType,
      preferredDate,
      frequency,
      address,
      message,
      status: 'pending',
      createdAt: new Date()
    });

    // Save to database
    await quote.save();

    // Send email notification
    const emailService = new QuoteService();
    await emailService.sendQuoteNotification(quote);

    res.status(200).json({ 
      message: 'Quote request received successfully! We will contact you within 24 hours.',
      quoteId: quote._id 
    });
  } catch (error) {
    console.error('Quote submission error:', error);
    res.status(500).json({ 
      error: 'An error occurred while processing your request. Please try again later.' 
    });
  }
});

// =====================
// DATABASE INITIALIZATION
// =====================
let dbInitialized = false;

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
  'EMAIL_PASS',
  'CRYPTO_PEPPER',
  'DEFAULT_ADMIN_EMAIL'
];

const optionalEnvVars = {
  'NODE_ENV': 'development',
  'PORT': '3000',
  'EMAIL_RECEIVER': process.env.EMAIL_USER,
  'DB_LOGGING': 'false'
};

Object.entries(optionalEnvVars).forEach(([key, defaultValue]) => {
  if (!process.env[key]) {
    process.env[key] = defaultValue;
  }
});

const missingVars = requiredEnvVars.filter(v => !process.env[v]);
if (missingVars.length > 0) {
  console.error('❌ Missing required environment variables:', missingVars.join(', '));
  console.error('💡 Please check your .env file');
  process.exit(1);
}

// =====================
// SECURITY MIDDLEWARE
// ================
app.use(helmet({
  contentSecurityPolicy: process.env.NODE_ENV === 'production' ? {
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
// CORS CONFIGURATION
// ================
const corsMiddleware = createCorsMiddleware();
app.use(corsMiddleware);
app.use(corsSecurityMiddleware);

const isProduction = process.env.NODE_ENV === 'production';
const corsConfig = require('./config/corsConfig');
const currentConfig = isProduction ? corsConfig.production : corsConfig.development;

console.log('🔒 CORS Configuration loaded:');
console.log('🔒 Environment:', isProduction ? 'production' : 'development');
console.log('🔒 Allowed Origins:', JSON.stringify(currentConfig.origins));
console.log('🔒 Credentials allowed:', currentConfig.credentials);
console.log('🔒 Methods allowed:', currentConfig.methods);


app.use((req, res, next) => {
  const origin = req.get('Origin');
  
  
  if (origin) {
    console.log('� Cross-Origin Request:');
    console.log('  Origin:', origin);
    console.log('  Path:', req.path);
    console.log('  Method:', req.method);
    console.log('  Timestamp:', new Date().toISOString());
    
    
    if (!allowedOrigins.includes(origin)) {
      console.warn('⚠️ Note: This origin would normally be blocked');
    }
  }
  
  next();
});

// ================
// RATE LIMITING
// ================
const createRateLimiter = (options = {}) => {
  return rateLimit({
    windowMs: options.windowMs || 15 * 60 * 1000,
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
// EMAIL CONFIG
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

// Admin Authentication Middleware
const authenticateAdmin = async (req, res, next) => {
  try {
    // Check for token in cookie first (preferred method)
    let token = req.cookies.jwt;
    
    // Fallback to Authorization header if no cookie
    if (!token) {
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
      }
    }
    
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Find admin by ID
    const admin = await Admin.findByPk(decoded.adminId);
    if (!admin || !admin.is_active) {
      return res.status(401).json({ error: 'Invalid token or inactive admin' });
    }

    req.admin = admin;
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(401).json({ error: 'Invalid token' });
  }
};

// ================
// CORS Debug Route
// ================
app.get('/api/debug/cors', (req, res) => {
  const isProduction = process.env.NODE_ENV === 'production';
  
  if (isProduction && !req.headers['x-debug-mode']) {
    return res.status(403).json({ error: 'Debug endpoints are disabled in production' });
  }
  
  const config = isProduction ? corsConfig.production : corsConfig.development;
  
  res.json({
    environment: process.env.NODE_ENV || 'development',
    requestOrigin: req.get('Origin') || 'No origin header',
    isAllowed: !req.get('Origin') || config.origins.includes(req.get('Origin')),
    corsConfig: {
      origins: config.origins,
      credentials: config.credentials,
      methods: config.methods,
      allowedHeaders: config.allowedHeaders,
      exposedHeaders: config.exposedHeaders,
      maxAge: config.maxAge
    },
    headers: {
      requestHeaders: req.headers
    }
  });
});

// ================
// STATIC FILES
// ================
app.use(express.static(path.join(__dirname, 'public')));

// Force favicon serving (fixed: single handler, correct fallback base64 and encoding)
app.get('/favicon.ico', (req, res) => {
  const faviconPath = path.join(__dirname, 'public', 'favicon.ico');

  console.log('🔍 Favicon requested');
  console.log('📁 Looking for:', faviconPath);
  console.log('📁 File exists:', fs.existsSync(faviconPath));

  if (fs.existsSync(faviconPath)) {
    console.log('✅ Serving favicon file');
    res.setHeader('Content-Type', 'image/x-icon');
    res.setHeader('Cache-Control', 'public, max-age=86400');
    return res.sendFile(faviconPath);
  }

  console.log('❌ Favicon not found, serving fallback');

  // Small 16x16 transparent PNG fallback (base64), properly decoded
  const fallbackBase64 = 'iVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAYAAAAfSC3RAAAACXBIWXMAAAsTAAALEwEAmpwYAAAAB3RJTUUH5QMLCxU3y0f0WwAAAB1pVFh0Q29tbWVudAAAAAAAQ3JlYXRlZCB3aXRoIEdJTVBkLmUHAAAAF0lEQVQoz2NgGAXUBwYGBgYGJgEAADgAAf6xB0kAAAAASUVORK5CYII=';

  const fallbackIcon = Buffer.from(fallbackBase64, 'base64');
  res.setHeader('Content-Type', 'image/png');   // PNG mime for this base64
  res.setHeader('Cache-Control', 'public, max-age=86400');
  return res.end(fallbackIcon);
});

// Debug route to check what files exist (remove after testing)
app.get('/debug/files', (req, res) => {
  const publicPath = path.join(__dirname, 'public');
  try {
    const files = fs.readdirSync(publicPath);
    const faviconPath = path.join(publicPath, 'favicon.ico');
    const faviconStats = fs.existsSync(faviconPath) ? fs.statSync(faviconPath) : null;
    
    res.json({
      publicPath,
      files,
      faviconExists: fs.existsSync(faviconPath),
      faviconSize: faviconStats ? faviconStats.size : 0,
      __dirname,
      nodeEnv: process.env.NODE_ENV
    });
  } catch (error) {
    res.json({
      error: error.message,
      publicPath,
      __dirname
    });
  }
});

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
    
    res.cookie('jwt', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
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
  res.clearCookie('jwt', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
    path: '/'
  });
  res.json({ message: 'Logged out successfully' });
});

// Quote submission endpoint - updated for database
app.post('/api/quotes', async (req, res) => {
  try {
    const { name, email, phone, serviceType, message, preferredDate } = req.body;
    
    console.log('📝 Quote submission received:', { name, email, phone, serviceType });
    
    // Validation
    if (!name || !email || !serviceType) {
      return res.status(400).json({ 
        error: 'Missing required fields: name, email, serviceType',
        received: { name: !!name, email: !!email, serviceType: !!serviceType }
      });
    }

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    // Create quote with correct field mapping
    const quote = await Quote.create({
      id: require('uuid').v4(),
      name: name.trim(),
      email: email.trim().toLowerCase(),
      phone: phone?.trim() || '',
      service_type: serviceType, // ← Fix the field mapping
      message: message?.trim() || '',
      preferred_date: preferredDate ? new Date(preferredDate) : null,
      status: 'new',
      ip_address: req.ip,
      user_agent: req.get('User-Agent')
    });

    console.log('✅ Quote created successfully:', quote.id);

    // Send email notification
    if (emailTransporter) {
      try {
        await emailTransporter.sendMail({
          from: `"${process.env.EMAIL_FROM_NAME}" <${process.env.EMAIL_USER}>`,
          to: process.env.EMAIL_RECEIVER,
          subject: `🧹 New Quote Request - ${serviceType}`,
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <h2 style="color: #8B5CF6;">🧹 New Quote Request</h2>
              <div style="background: #f8f9fa; padding: 20px; border-radius: 8px;">
                <p><strong>Quote ID:</strong> ${quote.id}</p>
                <p><strong>Name:</strong> ${quote.name}</p>
                <p><strong>Email:</strong> <a href="mailto:${quote.email}">${quote.email}</a></p>
                <p><strong>Phone:</strong> <a href="tel:${quote.phone}">${quote.phone}</a></p>
                <p><strong>Service:</strong> ${serviceType}</p>
                <p><strong>Preferred Date:</strong> ${quote.preferred_date ? new Date(quote.preferred_date).toLocaleDateString() : 'Not specified'}</p>
                ${quote.message ? `<p><strong>Message:</strong><br>${quote.message}</p>` : ''}
                <p><strong>Submitted:</strong> ${new Date().toLocaleString()}</p>
                <p><strong>IP Address:</strong> ${req.ip}</p>
              </div>
            </div>
          `
        });
        console.log('✅ Quote notification email sent');
      } catch (emailError) {
        console.warn('⚠️ Email notification failed:', emailError.message);
      }
    }

    res.json({
      success: true,
      message: 'Quote request submitted successfully! We\'ll get back to you within 24 hours.',
      quoteId: quote.id
    });

  } catch (error) {
    console.error('❌ Quote submission error:', error);
    res.status(500).json({ 
      error: 'Failed to submit quote request. Please try again.',
      details: undefined
    });
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

// Admin login endpoint - updated for database
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    console.log('🔐 Admin login attempt:', email);
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find admin by email
    const admin = await Admin.findOne({ 
      where: { 
        email: email.toLowerCase().trim(),
        is_active: true 
      } 
    });

    if (!admin) {
      console.log('❌ Admin not found:', email);
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, admin.password_hash);
    if (!isValidPassword) {
      console.log('❌ Invalid password for admin:', email);
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        adminId: admin.id,
        email: admin.email,
        role: admin.role 
      },
      process.env.JWT_SECRET,
      { 
        expiresIn: process.env.JWT_EXPIRES_IN || '1h',
        issuer: process.env.JWT_ISSUER,
        audience: process.env.JWT_AUDIENCE
      }
    );

    console.log('✅ Admin login successful:', email);

    // Set JWT in HTTP-only cookie
    res.cookie('jwt', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
      maxAge: 3600000,
      path: '/'
    });    res.json({
      success: true,
      admin: {
        id: admin.id,
        email: admin.email,
        name: admin.name,
        role: admin.role
      }
    });

  } catch (error) {
    console.error('❌ Admin login error:', error);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

// Get All Quotes (Admin Only)
app.get('/api/admin/quotes', authenticateAdmin, async (req, res) => {
  try {
    console.log('📋 Admin fetching quotes:', req.admin.email);
    
    const quotes = await Quote.findAll({
      order: [['created_at', 'DESC']],
      limit: 100 // Limit for performance
    });

    console.log(`✅ Retrieved ${quotes.length} quotes`);

    res.json({
      success: true,
      quotes: quotes,
      count: quotes.length
    });

  } catch (error) {
    console.error('❌ Error fetching quotes:', error);
    res.status(500).json({ error: 'Failed to fetch quotes' });
  }
});

// Update Quote Status (Admin Only)
app.put('/api/admin/quotes/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    
    console.log('📝 Updating quote status:', id, 'to', status);
    
    if (!status) {
      return res.status(400).json({ error: 'Status is required' });
    }

    const validStatuses = ['new', 'contacted', 'quoted', 'completed', 'cancelled'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const quote = await Quote.findByPk(id);
    if (!quote) {
      return res.status(404).json({ error: 'Quote not found' });
    }

    await quote.update({ status });
    
    console.log('✅ Quote status updated successfully');

    res.json({
      success: true,
      quote: quote
    });

  } catch (error) {
    console.error('❌ Error updating quote status:', error);
    res.status(500).json({ error: 'Failed to update quote status' });
  }
});

// Delete Quote (Admin Only)
app.delete('/api/admin/quotes/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    console.log('🗑️ Deleting quote:', id);
    
    const quote = await Quote.findByPk(id);
    if (!quote) {
      return res.status(404).json({ error: 'Quote not found' });
    }

    await quote.destroy();
    
    console.log('✅ Quote deleted successfully');

    res.json({
      success: true,
      message: 'Quote deleted successfully'
    });

  } catch (error) {
    console.error('❌ Error deleting quote:', error);
    res.status(500).json({ error: 'Failed to delete quote' });
  }
});

// Admin Dashboard Stats
app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
  try {
    console.log('📊 Admin fetching stats:', req.admin.email);
    
    const totalQuotes = await Quote.count();
    const newQuotes = await Quote.count({ where: { status: 'new' } });
    const contactedQuotes = await Quote.count({ where: { status: 'contacted' } });
    const completedQuotes = await Quote.count({ where: { status: 'completed' } });
    
    // Get quotes from last 7 days
    const weekAgo = new Date();
    weekAgo.setDate(weekAgo.getDate() - 7);
    
    const recentQuotes = await Quote.count({
      where: {
        created_at: {
          [require('sequelize').Op.gte]: weekAgo
        }
      }
    });

    res.json({
      success: true,
      stats: {
        totalQuotes,
        newQuotes,
        contactedQuotes,
        completedQuotes,
        recentQuotes
      }
    });

  } catch (error) {
    console.error('❌ Error fetching stats:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// Test Admin Endpoint
app.get('/api/admin/test', authenticateAdmin, (req, res) => {
  res.json({
    success: true,
    message: 'Admin authentication working',
    admin: {
      id: req.admin.id,
      email: req.admin.email,
      name: req.admin.name
    }
  });
});

// Auth status endpoint
app.get('/api/auth/status', (req, res) => {
  try {
    const token = req.cookies.jwt;
    
    if (!token) {
      return res.status(401).json({ authenticated: false });
    }
    
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(401).json({ authenticated: false });
      }
      
      res.json({ 
        authenticated: true,
        user: {
          id: decoded.adminId,
          email: decoded.email,
          role: decoded.role
        }
      });
    });
  } catch (error) {
    console.error('Auth status error:', error);
    res.status(500).json({ error: 'Failed to check authentication status' });
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
// SERVER STARTUP
// ================
const PORT = process.env.PORT || 3000;
const rateLimitMax = process.env.NODE_ENV === 'production' ? 100 : 500;

const server = app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  
  console.log('🔒 Security Features Active:');
  console.log(`- CORS: ${corsConfig.production.origins.join(', ')}`);
  console.log(`- Rate Limiting: ${rateLimitMax} req/15min`);
  console.log(`- JWT: HS256 with 1h expiration`);
  console.log(`- HTTPS Headers: Production`);
  
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
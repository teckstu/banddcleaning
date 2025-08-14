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
  'EMAIL_PASS', 
  'PORT',
  'NODE_ENV'
];

const missingVars = requiredEnvVars.filter(v => !process.env[v]);
if (missingVars.length > 0) {
  console.error('❌ Missing required environment variables:', missingVars.join(', '));
  process.exit(1);
}

// ================
// SECURITY MIDDLEWARE
// ================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'cdn.jsdelivr.net'],
      styleSrc: ["'self'", "'unsafe-inline'", 'cdn.jsdelivr.net', 'fonts.googleapis.com'],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", 'fonts.gstatic.com'],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      formAction: ["'self'"],
      upgradeInsecureRequests: []
    }
  },
  crossOriginEmbedderPolicy: false,
  hsts: {
    maxAge: 63072000,
    includeSubDomains: true,
    preload: true
  }
}));

app.use(mongoSanitize());
app.use(xss());
app.use(hpp());
app.use(compression());
app.use(cookieParser());

// =============
// CORS CONFIG
// =============
const allowedOrigins = process.env.NODE_ENV === 'production' ? [
  'https://banddcleaning.com.au',
  'https://www.banddcleaning.com.au',
  'https://admin.banddcleaning.com.au'
] : [
  'http://localhost:3000',
  'http://localhost:3001',
  'http://localhost:5500'
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn(`🚨 CORS blocked request from: ${origin}`);
      callback(new Error('Not allowed by CORS policy'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'X-Forwarded-Proto'
  ],
  exposedHeaders: ['Authorization'],
  maxAge: 86400
}));

// ================
// RATE LIMITING
// ================
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: process.env.RATE_LIMIT_MAX || (process.env.NODE_ENV === 'production' ? 100 : 500),
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  skip: (req) => {
    return req.path === '/health' || 
           req.ip === '127.0.0.1' ||
           (process.env.TRUSTED_IPS && 
            process.env.TRUSTED_IPS.split(',').includes(req.ip));
  },
  handler: (req, res) => {
    res.status(429).json({
      error: 'Too many requests',
      message: `Please try again after ${Math.ceil(res.get('Retry-After'))} seconds`,
      limits: {
        max: this.max,
        window: '15 minutes'
      }
    });
  },
  onLimitReached: (req) => {
    console.warn(`Rate limit reached for IP: ${req.ip} on ${req.path}`);
  }
});
app.use('/api/', apiLimiter);

// ================
// BODY PARSING
// ================
app.use(express.json({
  limit: '10kb',
  verify: (req, res, buf, encoding) => {
    try {
      JSON.parse(buf.toString());
    } catch (e) {
      throw new Error('Invalid JSON payload');
    }
  }
}));

app.use(express.urlencoded({
  extended: true,
  limit: '10kb',
  parameterLimit: 10
}));

// ================
// COOKIE SECURITY
// ================
app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  }
  next();
});

// ================
// EMAIL CONFIG
// ================
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.EMAIL_PORT) || 587,
  secure: process.env.EMAIL_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  tls: {
    ciphers: 'TLS_AES_256_GCM_SHA384',
    minVersion: 'TLSv1.3',
    rejectUnauthorized: true
  },
  pool: true,
  maxConnections: 5,
  maxMessages: 100
});

transporter.verify()
  .then(() => console.log('✅ Email server ready'))
  .catch(err => console.error('❌ Email config error:', err));

// ================
// JWT CONFIGURATION
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
  const token = req.cookies?.token || 
                req.headers['authorization']?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const decoded = verifyToken(token);
    req.user = {
      id: decoded.id,
      role: decoded.role,
      sessionId: decoded.jti
    };
    next();
  } catch (err) {
    console.warn(`⚠️ JWT Error: ${err.message}`);
    res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// ================
// STATIC FILE SERVING
// ================
const staticPath = path.join(__dirname, 'public');
app.use(express.static(staticPath, {
  maxAge: process.env.NODE_ENV === 'production' ? '1y' : '0',
  etag: true,
  lastModified: true,
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    }
    res.setHeader('X-Content-Type-Options', 'nosniff');
  }
}));

// Serve login and admin pages
app.get('/login', (req, res) => {
  res.sendFile(path.join(staticPath, 'login.html'));
});

app.get('/admin', authenticate, (req, res) => {
  res.sendFile(path.join(staticPath, 'admin.html'));
});

// ================
// API ROUTES
// ================
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV,
    uptime: Math.floor(process.uptime())
  });
});

app.get('/api/admin', authenticate, (req, res) => {
  res.json({ 
    status: 'success',
    data: {
      user: req.user
    }
  });
});

// ================
// CLIENT-SIDE ROUTING
// ================
app.get('*', (req, res) => {
  res.sendFile(path.join(staticPath, 'index.html'));
});

// ================
// ERROR HANDLING
// ================
app.use((err, req, res, next) => {
  console.error('🔥 Error:', err.stack);
  
  const statusCode = err.statusCode || 500;
  const message = process.env.NODE_ENV === 'development' 
    ? err.message 
    : 'An unexpected error occurred';
  
  res.status(statusCode).json({
    error: true,
    message,
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

// ================
// SERVER STARTUP
// ================
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`🚀 Server running in ${process.env.NODE_ENV} mode on port ${PORT}`);
  console.log('🔒 Security Features Active:');
  console.log(`- CORS: ${allowedOrigins.join(', ')}`);
  console.log(`- Rate Limiting: ${apiLimiter.max} req/15min`);
  console.log(`- JWT: HS256 with 1h expiration`);
  console.log(`- HTTPS Headers: ${process.env.NODE_ENV === 'production' ? 'Enabled' : 'Development'}`);
});

process.on('unhandledRejection', (err) => {
  console.error('Unhandled Rejection:', err);
  server.close(() => process.exit(1));
});

process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    console.log('Process terminated');
  });
});
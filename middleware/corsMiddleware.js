const cors = require('cors');
const corsConfig = require('../config/corsConfig');

// Enhanced CORS middleware with security logging
const createCorsMiddleware = () => {
  // Parse allowed origins from environment variables
  const allowedOrigins = process.env.CORS_ALLOWED_ORIGINS_PROD ? 
    process.env.CORS_ALLOWED_ORIGINS_PROD.split(',') : 
    corsConfig.production.origins;
    
  const config = { 
    ...corsConfig.production, 
    origins: allowedOrigins 
  };
  
  return cors({
    origin: (origin, callback) => {
      // Handle requests with no origin (like mobile apps, REST tools, etc)
      if (!origin) {
        console.log('🔍 CORS: Browser direct request allowed');
        return callback(null, true);
      }

      // Check against allowed origins
      const isAllowed = config.origins.includes(origin);
      
      console.log(`🔍 CORS Request received:
        - Origin: ${origin}
        - Allowed: ${isAllowed ? 'Yes' : 'No'}
        - Available Origins: ${config.origins.join(', ')}`);
      
      if (isAllowed) {
        console.log('✅ CORS: Request allowed from authorized domain');
        return callback(null, true);
      }
      
      console.warn('❌ CORS: Request blocked - unauthorized origin');
      return callback(new Error('CORS policy: Origin not allowed'), false);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    exposedHeaders: ['Content-Range', 'X-Content-Range'],
    maxAge: parseInt(process.env.CORS_MAX_AGE || '86400'),
    credentials: config.credentials,
    methods: config.methods,
    allowedHeaders: config.allowedHeaders,
    exposedHeaders: config.exposedHeaders,
    maxAge: config.maxAge,
    preflightContinue: false,
    optionsSuccessStatus: 200
  });
};

// CORS security middleware
const corsSecurityMiddleware = (req, res, next) => {
  const origin = req.get('Origin');
  const referer = req.get('Referer');
  const userAgent = req.get('User-Agent');
  
  // Security checks
  if (process.env.NODE_ENV === 'production') {
    // Check for suspicious patterns
    const suspiciousPatterns = [
      /localhost/i,
      /127\.0\.0\.1/i,
      /192\.168\./i,
      /10\./i,
      /file:\/\//i
    ];
    
    if (origin && suspiciousPatterns.some(pattern => pattern.test(origin))) {
      console.error(`🚨 SECURITY: Suspicious origin detected: ${origin}`);
      return res.status(403).json({ error: 'Forbidden origin' });
    }
    
    // Check for missing User-Agent (potential bot/script)
    if (!userAgent && req.method !== 'OPTIONS') {
      console.warn(`⚠️ SECURITY: Request without User-Agent from ${req.ip}`);
    }
  }
  
  next();
};

module.exports = {
  createCorsMiddleware,
  corsSecurityMiddleware
};
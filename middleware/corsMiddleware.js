const cors = require('cors');
const corsConfig = require('../config/corsConfig');

// Enhanced CORS middleware with security logging
const createCorsMiddleware = () => {
  const isProduction = process.env.NODE_ENV === 'production';
  const config = isProduction ? corsConfig.production : corsConfig.development;
  
  return cors({
    origin: (origin, callback) => {
      console.log(`🔍 CORS Request from origin: ${origin || 'null'}`);
      
      // Allow requests with no origin (mobile apps, curl, Postman)
      if (!origin) {
        console.log('🔍 CORS: Allowing null origin request');
        return callback(null, true);
      }
      
      // Check if origin is in allowed list
      if (config.origins.includes(origin)) {
        console.log(`✅ CORS: Allowed origin: ${origin}`);
        return callback(null, true);
      }
      
      // Security logging for blocked requests
      console.warn(`❌ CORS: Blocked origin: ${origin}`);
      console.warn(`🔍 CORS: Request origin "${origin}" is not in the allowed list:`);
      console.warn('🔍 CORS Allowed origins:', JSON.stringify(config.origins));
      
      // In production, strict security
      if (isProduction) {
        return callback(new Error(`CORS policy: Origin ${origin} not allowed`), false);
      }
      
      // In development, allow for easier testing
      console.warn('⚠️ CORS: Allowing in development mode only');
      return callback(null, true);
    },
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
const corsConfig = {
  // Production CORS configuration
  production: {
    origins: [
      // Primary domain
      'https://banddcleaning.com.au',
      'https://www.banddcleaning.com.au',
      
      // Admin subdomain (if separate)
      'https://admin.banddcleaning.com.au',
      
      // Mobile app domains (if applicable)
      'https://app.banddcleaning.com.au',
      
      // CDN domains (if using)
      'https://cdn.banddcleaning.com.au',
      
      // Render.com domains - all possible variations
      'https://banddcleaning-com-au.onrender.com',
      'https://www.banddcleaning-com-au.onrender.com',
      'https://banddcleaning.onrender.com',
      'https://bd-cleaning.onrender.com',
      'https://bd-cleaning-com-au.onrender.com',
      'https://b-d-cleaning.onrender.com',
      'https://bandd-cleaning.onrender.com',
      'https://bandd-cleaning-com-au.onrender.com',
      'https://banddcleaning-admin.onrender.com',
      'https://bd-cleaning-admin.onrender.com',
      'https://banddadmin.onrender.com',
      
      // If your domain is just banddcleaning without .com.au
      'https://banddcleaning.com',
      'https://www.banddcleaning.com',
      'https://admin.banddcleaning.com',
    ],
    
    credentials: true,
    
    methods: [
      'GET',
      'POST',
      'PUT',
      'DELETE',
      'OPTIONS'
    ],
    
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Requested-With',
      'Accept',
      'Origin',
      'Cache-Control',
      'X-CSRF-Token'
    ],
    
    exposedHeaders: [
      'X-Total-Count',
      'X-Page-Count'
    ],
    
    maxAge: 86400, // 24 hours cache for preflight
    
    optionsSuccessStatus: 200
  },
  
  // Development CORS configuration
  development: {
    origins: [
      'http://localhost:3000',
      'http://localhost:3001',
      'http://localhost:5500',
      'http://127.0.0.1:3000',
      'http://127.0.0.1:5500',
      'http://localhost:8080', // Webpack dev server
      'http://localhost:4200'  // Angular dev server
    ],
    
    credentials: true,
    
    methods: [
      'GET',
      'POST',
      'PUT',
      'DELETE',
      'OPTIONS',
      'PATCH'
    ],
    
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Requested-With',
      'Accept',
      'Origin',
      'Cache-Control',
      'X-CSRF-Token',
      'X-Debug-Mode'
    ],
    
    maxAge: 300, // 5 minutes cache
    
    optionsSuccessStatus: 200
  }
};

module.exports = corsConfig;
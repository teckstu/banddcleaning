#!/usr/bin/env node

/**
 * Render Deployment Configuration Validator
 * Run this script to validate your environment variables before deployment
 */

const path = require('path');
const fs = require('fs');

console.log('🔍 B&D Cleaning - Render Deployment Validator');
console.log('='.repeat(50));

// Load environment variables
require('dotenv').config();

const requiredVars = [
  'JWT_SECRET',
  'EMAIL_USER',
  'EMAIL_PASS',
  'CRYPTO_PEPPER',
  'DEFAULT_ADMIN_EMAIL'
];

const recommendedVars = [
  'EMAIL_RECEIVER',
  'DEFAULT_ADMIN_PASSWORD'
];

const optionalVars = [
  'CORS_ADDITIONAL_ORIGINS',
  'PORT',
  'NODE_ENV'
];

console.log('\n📋 Required Environment Variables:');
let missingRequired = [];
requiredVars.forEach(varName => {
  const value = process.env[varName];
  if (!value) {
    console.log(`❌ ${varName}: NOT SET`);
    missingRequired.push(varName);
  } else if (value.includes('your-') || value.includes('change-this') || value.includes('example')) {
    console.log(`⚠️  ${varName}: PLACEHOLDER VALUE (${value.substring(0, 20)}...)`);
  } else {
    console.log(`✅ ${varName}: SET (${value.length} characters)`);
  }
});

console.log('\n📋 Recommended Environment Variables:');
recommendedVars.forEach(varName => {
  const value = process.env[varName];
  if (!value) {
    console.log(`⚠️  ${varName}: NOT SET`);
  } else if (value.includes('your-') || value.includes('change-this') || value.includes('example')) {
    console.log(`⚠️  ${varName}: PLACEHOLDER VALUE`);
  } else {
    console.log(`✅ ${varName}: SET`);
  }
});

console.log('\n📋 Optional Environment Variables:');
optionalVars.forEach(varName => {
  const value = process.env[varName];
  if (value) {
    console.log(`✅ ${varName}: ${value}`);
  } else {
    console.log(`ℹ️  ${varName}: Not set (will use default)`);
  }
});

console.log('\n🔒 Security Validation:');

// JWT Secret validation
const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret) {
  console.log('❌ JWT_SECRET: Missing');
} else if (jwtSecret.length < 32) {
  console.log('⚠️  JWT_SECRET: Too short (should be 32+ characters)');
} else if (jwtSecret.includes('secret') || jwtSecret.includes('key')) {
  console.log('⚠️  JWT_SECRET: Contains common words (use random string)');
} else {
  console.log('✅ JWT_SECRET: Strong');
}

// CRYPTO_PEPPER validation
const pepper = process.env.CRYPTO_PEPPER;
if (!pepper) {
  console.log('❌ CRYPTO_PEPPER: Missing');
} else if (pepper.length < 16) {
  console.log('⚠️  CRYPTO_PEPPER: Too short (should be 16+ characters)');
} else {
  console.log('✅ CRYPTO_PEPPER: Good');
}

// Email validation
const emailUser = process.env.EMAIL_USER;
if (emailUser && emailUser.includes('@gmail.com')) {
  console.log('✅ EMAIL: Gmail configured');
  if (!process.env.EMAIL_PASS) {
    console.log('⚠️  EMAIL_PASS: Missing (need Gmail App Password)');
  } else if (process.env.EMAIL_PASS.includes('password')) {
    console.log('⚠️  EMAIL_PASS: Placeholder value (need real App Password)');
  } else {
    console.log('✅ EMAIL_PASS: Set');
  }
}

console.log('\n🌐 CORS Configuration:');
const nodeEnv = process.env.NODE_ENV || 'development';
const additionalOrigins = process.env.CORS_ADDITIONAL_ORIGINS;

console.log(`📍 Environment: ${nodeEnv}`);

if (nodeEnv === 'production') {
  console.log('✅ Production CORS includes Render URLs:');
  console.log('   - https://banddcleaning-com-au.onrender.com');
  console.log('   - https://banddcleaning.onrender.com');
  
  if (additionalOrigins) {
    console.log('✅ Additional origins configured:');
    additionalOrigins.split(',').forEach(origin => {
      console.log(`   - ${origin.trim()}`);
    });
  } else {
    console.log('ℹ️  No additional CORS origins (add CORS_ADDITIONAL_ORIGINS if needed)');
  }
} else {
  console.log('ℹ️  Development mode - localhost origins enabled');
}

console.log('\n📝 Summary:');
if (missingRequired.length > 0) {
  console.log(`❌ ${missingRequired.length} required variables missing: ${missingRequired.join(', ')}`);
  console.log('🚫 Deployment will FAIL');
} else {
  console.log('✅ All required variables present');
  console.log('🚀 Ready for deployment!');
}

console.log('\n💡 Next Steps:');
console.log('1. Set all required environment variables in Render dashboard');
console.log('2. Use strong, unique values (not the examples)');
console.log('3. Test deployment with health check: /health');
console.log('4. Login at /login and change default admin password');

console.log('\n📚 For detailed setup instructions, see RENDER_DEPLOYMENT.md');
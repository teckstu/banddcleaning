#!/usr/bin/env node

const bcrypt = require('bcryptjs');
const fs = require('fs');
const readline = require('readline');

// Colors for terminal output
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  bright: '\x1b[1m'
};

function log(message, color = colors.reset) {
  console.log(color + message + colors.reset);
}

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function question(prompt) {
  return new Promise((resolve) => {
    rl.question(prompt, resolve);
  });
}

function validateEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

function validatePassword(password) {
  const minLength = 8;
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasNumber = /\d/.test(password);
  const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);

  return {
    valid: password.length >= minLength && hasUpper && hasLower && hasNumber && hasSpecial,
    length: password.length >= minLength,
    upper: hasUpper,
    lower: hasLower,
    number: hasNumber,
    special: hasSpecial
  };
}

async function createAdmin() {
  console.clear();
  log('╔══════════════════════════════════════════════════════════════╗', colors.cyan);
  log('║                    B&D Cleaning Co                          ║', colors.cyan);
  log('║                  Admin Manager v1.0                         ║', colors.cyan);
  log('╚══════════════════════════════════════════════════════════════╝', colors.cyan);
  console.log('');

  log('📝 Creating New Admin Account', colors.bright + colors.green);
  log('─'.repeat(50), colors.green);
  console.log('');

  let email, password;

  // Get email
  while (true) {
    email = await question('Enter admin email: ');
    if (validateEmail(email)) {
      break;
    }
    log('❌ Invalid email format. Please try again.', colors.red);
  }

  // Get password
  while (true) {
    password = await question('Enter admin password: ');
    const validation = validatePassword(password);
    
    if (validation.valid) {
      break;
    }
    
    log('❌ Password must meet these requirements:', colors.red);
    log(`${validation.length ? '✓' : '✗'} At least 8 characters`, validation.length ? colors.green : colors.red);
    log(`${validation.upper ? '✓' : '✗'} At least one uppercase letter`, validation.upper ? colors.green : colors.red);
    log(`${validation.lower ? '✓' : '✗'} At least one lowercase letter`, validation.lower ? colors.green : colors.red);
    log(`${validation.number ? '✓' : '✗'} At least one number`, validation.number ? colors.green : colors.red);
    log(`${validation.special ? '✓' : '✗'} At least one special character`, validation.special ? colors.green : colors.red);
    console.log('');
  }

  // Confirm password
  const confirmPassword = await question('Confirm password: ');
  if (password !== confirmPassword) {
    log('❌ Passwords do not match!', colors.red);
    rl.close();
    return;
  }

  // Create admin
  try {
    const hash = await bcrypt.hash(password, 12);
    const admin = {
      email: email.trim().toLowerCase(),
      passwordHash: hash,
      createdAt: new Date().toISOString(),
      lastLogin: null,
      role: 'admin'
    };

    fs.writeFileSync('admin.json', JSON.stringify(admin, null, 2));
    
    console.log('');
    log('✅ Admin account created successfully!', colors.green);
    log(`📧 Email: ${admin.email}`, colors.cyan);
    log('🔒 Password: [hidden for security]', colors.cyan);
    log(`📁 Saved to: ${process.cwd()}/admin.json`, colors.yellow);
    console.log('');
    log('🚀 You can now start your server with: npm start', colors.blue);
    log('🌐 Then login at: http://localhost:3000/login', colors.blue);
    
  } catch (error) {
    log('❌ Error creating admin account: ' + error.message, colors.red);
  }

  rl.close();
}

async function viewAdmin() {
  console.clear();
  log('👁️  Current Admin Information', colors.bright + colors.blue);
  log('─'.repeat(50), colors.blue);
  console.log('');

  if (!fs.existsSync('admin.json')) {
    log('❌ No admin account found.', colors.red);
    log('💡 Run this script to create one!', colors.yellow);
    rl.close();
    return;
  }

  const adminData = JSON.parse(fs.readFileSync('admin.json', 'utf8'));
  
  log(`📧 Email: ${adminData.email}`, colors.cyan);
  log(`📅 Created: ${new Date(adminData.createdAt).toLocaleString()}`, colors.cyan);
  log(`🕒 Last Login: ${adminData.lastLogin ? new Date(adminData.lastLogin).toLocaleString() : 'Never'}`, colors.cyan);

  rl.close();
}

async function main() {
  try {
    console.log('');
    log('Choose an option:', colors.bright);
    log('1. Create new admin account', colors.green);
    log('2. View current admin info', colors.blue);
    console.log('');
    
    const choice = await question('Enter your choice (1 or 2): ');

    switch (choice) {
      case '1':
        await createAdmin();
        break;
      case '2':
        await viewAdmin();
        break;
      default:
        log('❌ Invalid choice. Creating new admin...', colors.yellow);
        await createAdmin();
    }
  } catch (error) {
    log('❌ Error: ' + error.message, colors.red);
    rl.close();
  }
}

main();
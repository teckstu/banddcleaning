#!/usr/bin/env node

const bcrypt = require('bcryptjs');
const fs = require('fs');
const readline = require('readline');

// Simple version for testing
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

console.log('🔧 B&D Cleaning Admin Manager');
console.log('==============================');

rl.question('Enter admin email: ', (email) => {
  rl.question('Enter admin password: ', (password) => {
    
    bcrypt.hash(password, 12).then(hash => {
      const admin = {
        email: email.trim().toLowerCase(),
        passwordHash: hash,
        createdAt: new Date().toISOString(),
        lastLogin: null
      };
      
      fs.writeFileSync('admin.json', JSON.stringify(admin, null, 2));
      console.log('✅ Admin created successfully!');
      console.log('Email:', admin.email);
      console.log('Password: [saved securely]');
      rl.close();
    });
  });
});

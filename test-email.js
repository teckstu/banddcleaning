require('dotenv').config();
const nodemailer = require('nodemailer');

async function testEmailConfig() {
  console.log('🧪 Testing Email Configuration...');
  console.log('=====================================');
  
  // Check environment variables
  console.log('Environment Variables:');
  console.log('EMAIL_HOST:', process.env.EMAIL_HOST || 'NOT SET');
  console.log('EMAIL_PORT:', process.env.EMAIL_PORT || 'NOT SET');
  console.log('EMAIL_SECURE:', process.env.EMAIL_SECURE || 'NOT SET');
  console.log('EMAIL_USER:', process.env.EMAIL_USER || 'NOT SET');
  console.log('EMAIL_PASS:', process.env.EMAIL_PASS ? '[HIDDEN]' : 'NOT SET');
  console.log('');

  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.error('❌ Missing EMAIL_USER or EMAIL_PASS');
    return;
  }

  try {
    // CORRECT METHOD: createTransport (not createTransporter)
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

    console.log('📧 Testing connection...');
    
    // Test connection
    await transporter.verify();
    console.log('✅ Email server connection successful!');

    // Send test email
    console.log('📤 Sending test email...');
    
    const testEmail = {
      from: process.env.EMAIL_USER,
      to: process.env.EMAIL_RECEIVER || process.env.EMAIL_USER,
      subject: 'B&D Cleaning - Email Test ✅',
      html: `
        <h2>🎉 Email Configuration Test</h2>
        <p>This is a test email from your B&D Cleaning application.</p>
        <p><strong>⏰ Time:</strong> ${new Date().toLocaleString()}</p>
        <p><strong>✅ Status:</strong> Email system working correctly!</p>
      `
    };

    const result = await transporter.sendMail(testEmail);
    console.log('✅ Test email sent successfully!');
    console.log('📬 Message ID:', result.messageId);

  } catch (error) {
    console.error('❌ Email test failed:', error.message);
  }
}

testEmailConfig();
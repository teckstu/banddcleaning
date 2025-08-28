// test-email.js
require('dotenv').config();
const nodemailer = require('nodemailer');
const QuoteService = require('./services/quoteService');

(async () => {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    },
    tls: { rejectUnauthorized: false }
  });

  try {
    await transporter.verify();
    console.log('✅ Email transporter ready');
  } catch (err) {
    console.error('❌ Email transporter failed:', err);
    process.exit(1);
  }


  // Dummy quote data
  const quote = {
    id: 123,
    name: 'Test User',
    email: 'testuser@example.com',
    phone: '0412345678',
    service_type: 'test_service',
    preferred_date: new Date(),
    message: 'This is a test quote submission.'
  };

  // Override receiver for this test
  process.env.EMAIL_RECEIVER = 'tested.2375@gmail.com';

  try {
    await QuoteService.sendQuoteNotification(quote, transporter);
    console.log('✅ Test email sent successfully');
  } catch (err) {
    console.error('❌ Failed to send test email:', err);
  }
})();

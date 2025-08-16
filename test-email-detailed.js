// Create this test file:

const nodemailer = require('nodemailer');
require('dotenv').config();

async function testEmailConfiguration() {
    console.log('🧪 Testing Email Configuration...\n');
    
    // Check environment variables
    console.log('📧 Email Environment Variables:');
    console.log('EMAIL_HOST:', process.env.EMAIL_HOST);
    console.log('EMAIL_PORT:', process.env.EMAIL_PORT);
    console.log('EMAIL_USER:', process.env.EMAIL_USER);
    console.log('EMAIL_PASS:', process.env.EMAIL_PASS ? '✅ Set' : '❌ Missing');
    console.log('EMAIL_RECEIVER:', process.env.EMAIL_RECEIVER);
    console.log('');

    try {
        // Create transporter
        const transporter = nodemailer.createTransport({
            host: process.env.EMAIL_HOST,
            port: parseInt(process.env.EMAIL_PORT),
            secure: process.env.EMAIL_SECURE === 'true',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            }
        });

        // Verify connection
        console.log('🔗 Testing SMTP connection...');
        await transporter.verify();
        console.log('✅ SMTP connection successful\n');

        // Send test email
        console.log('📤 Sending test email...');
        const testEmail = await transporter.sendMail({
            from: `"${process.env.EMAIL_FROM_NAME}" <${process.env.EMAIL_USER}>`,
            to: process.env.EMAIL_RECEIVER,
            subject: '🧪 B&D Cleaning - Email Test',
            html: `
                <h2>Email Configuration Test</h2>
                <p>This is a test email from your B&D Cleaning website.</p>
                <p><strong>Time:</strong> ${new Date().toLocaleString()}</p>
                <p><strong>Status:</strong> ✅ Email system working correctly!</p>
            `
        });

        console.log('✅ Test email sent successfully!');
        console.log('Message ID:', testEmail.messageId);
        
    } catch (error) {
        console.error('❌ Email test failed:', error.message);
        
        if (error.message.includes('Authentication failed')) {
            console.log('\n💡 Troubleshooting:');
            console.log('1. Make sure you\'re using a Gmail App Password, not your regular password');
            console.log('2. Enable 2FA on your Gmail account');
            console.log('3. Generate a new App Password: Google Account → Security → App passwords');
        }
    }
}

testEmailConfiguration();
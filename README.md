# B&D Cleaning Co - Admin Dashboard

A professional cleaning service management system with admin dashboard and quote request functionality.

## Features

- 📧 Quote request system with email notifications
- 👨‍💼 Admin dashboard for managing quotes
- 🔒 Secure authentication with JWT
- 📱 Responsive design
- 🌐 CORS-enabled for deployment flexibility

## Quick Start

### Development

1. **Clone and Install**
   ```bash
   git clone <repository-url>
   cd banddcleaning
   npm install
   ```

2. **Setup Environment**
   ```bash
   cp .env.example .env
   # Edit .env with your actual values
   ```

3. **Run Application**
   ```bash
   npm start
   # Visit http://localhost:3000
   ```

4. **Create Admin Account**
   ```bash
   npm run admin
   ```

### Production Deployment (Render.com)

🚀 **Fixed CORS Issue**: Updated Render URL configuration to properly support deployment.

1. **Quick Deploy**
   - See detailed instructions in [RENDER_DEPLOYMENT.md](./RENDER_DEPLOYMENT.md)
   - Use the validation script: `npm run validate-deployment`

2. **Key Fixes Applied**
   - ✅ Fixed typo in Render URL (was missing 'd' in 'banddcleaning')
   - ✅ Added multiple Render URL patterns for flexibility
   - ✅ Added environment variable support for custom domains
   - ✅ Created comprehensive deployment guide

## Environment Variables

### Required
- `JWT_SECRET` - Secure JWT signing key
- `EMAIL_USER` - Gmail account for notifications
- `EMAIL_PASS` - Gmail app password
- `CRYPTO_PEPPER` - Additional security salt
- `DEFAULT_ADMIN_EMAIL` - Initial admin account email

### Optional
- `CORS_ADDITIONAL_ORIGINS` - Custom domains for CORS (comma-separated)
- `PORT` - Server port (default: 3000)
- `NODE_ENV` - Environment mode

## Supported Deployment URLs

The application automatically supports these Render.com URL patterns:
- `https://banddcleaning-com-au.onrender.com`
- `https://banddcleaning.onrender.com` 
- `https://bandd-cleaning.onrender.com`

For custom URLs, use the `CORS_ADDITIONAL_ORIGINS` environment variable.

## Scripts

- `npm start` - Start the server
- `npm run dev` - Start with auto-reload
- `npm run admin` - Create/manage admin accounts
- `npm run validate-deployment` - Validate deployment configuration
- `npm run security-check` - Run security audit

## Troubleshooting

### CORS Errors
If your render site can't access the API:
1. Check the deployment URL matches the supported patterns above
2. Add your custom URL to `CORS_ADDITIONAL_ORIGINS` environment variable
3. Ensure `NODE_ENV=production` is set in Render

### Email Issues
- Use Gmail App Password, not regular password
- Enable 2-factor authentication on Gmail account

## Security

- ✅ CORS protection
- ✅ Rate limiting
- ✅ Input validation and sanitization
- ✅ XSS protection
- ✅ SQL injection protection
- ✅ JWT authentication

## Support

For deployment issues, run the validation script:
```bash
npm run validate-deployment
```

Check the deployment guide: [RENDER_DEPLOYMENT.md](./RENDER_DEPLOYMENT.md)

---

© 2024 B&D Cleaning Co. All rights reserved.
# Render.com Deployment Guide for B&D Cleaning

## Quick Setup

1. **Fork/Connect Repository**
   - Connect your GitHub repository to Render.com
   - Select "Web Service" as the service type

2. **Environment Variables**
   Copy these required environment variables to your Render service:

   ```
   NODE_ENV=production
   PORT=10000
   
   # Security (GENERATE SECURE VALUES!)
   JWT_SECRET=your-super-secure-jwt-secret-here
   CRYPTO_PEPPER=your-super-secure-pepper-here
   
   # Database
   DB_TYPE=sqlite
   DB_PATH=./database.sqlite
   DB_LOGGING=false
   
   # Email Configuration
   EMAIL_SERVICE=gmail
   EMAIL_USER=your-email@gmail.com
   EMAIL_PASS=your-app-password
   EMAIL_RECEIVER=your-email@gmail.com
   
   # Business Settings
   DEFAULT_ADMIN_EMAIL=admin@banddcleaning.com.au
   DEFAULT_ADMIN_PASSWORD=change-this-secure-password
   
   # Optional: Add your custom Render URL if different from default
   # CORS_ADDITIONAL_ORIGINS=https://your-custom-render-url.onrender.com
   ```

3. **Build & Deploy Settings**
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Node Version**: 18 or higher

## Supported URLs

The application automatically supports these Render URL patterns:
- `https://banddcleaning-com-au.onrender.com`
- `https://www.banddcleaning-com-au.onrender.com`
- `https://banddcleaning.onrender.com`
- `https://bandd-cleaning.onrender.com`

If your Render URL is different, add it via the `CORS_ADDITIONAL_ORIGINS` environment variable.

## Important Security Notes

⚠️ **NEVER use the example values in production!**

1. Generate a secure JWT_SECRET (64+ characters)
2. Generate a secure CRYPTO_PEPPER (32+ characters)
3. Use a real email account with app password
4. Change the default admin password immediately after first login

## Email Setup

For Gmail:
1. Enable 2-factor authentication
2. Generate an "App Password" (not your regular password)
3. Use the app password in `EMAIL_PASS`

## Admin Access

After deployment:
1. Visit `https://your-app.onrender.com/login`
2. Login with `DEFAULT_ADMIN_EMAIL` and `DEFAULT_ADMIN_PASSWORD`
3. **Immediately change the password** in the admin panel

## Troubleshooting

### CORS Errors
- Check that your domain is in the allowed origins list
- Add custom domains via `CORS_ADDITIONAL_ORIGINS` environment variable

### Database Issues
- Render's filesystem is ephemeral - database resets on restart
- For persistent data, consider upgrading to a PostgreSQL addon

### Email Not Working
- Verify Gmail app password is correct
- Check if 2FA is enabled on your Gmail account
- Test email configuration locally first

## Monitoring

Access these endpoints to check service health:
- `https://your-app.onrender.com/health` - Health check
- `https://your-app.onrender.com/debug/files` - File system debug (remove in production)

---

**Need help?** Check the Render logs for detailed error messages.
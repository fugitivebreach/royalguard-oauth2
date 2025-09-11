# Arrow Industries OAuth Verification System

A secure OAuth2 verification system that links Discord and ROBLOX accounts for server verification purposes.

## Features

- **Discord OAuth2 Integration**: Secure Discord login with user profile access
- **ROBLOX OAuth2 Integration**: ROBLOX account verification with profile data
- **Modern UI**: All-black theme with rounded elements and smooth animations
- **Legal Compliance**: Full Terms of Service and Privacy Policy with USC law citations
- **Database Integration**: MongoDB storage for verification records
- **Reverification Detection**: Tracks if users have previously verified
- **Railway Deployment Ready**: Configured for easy Railway hosting

## Setup

1. **Environment Variables**
   Copy `.env.example` to `.env` and configure:
   ```
   DISCORD_CLIENT_ID=your_discord_client_id
   DISCORD_CLIENT_SECRET=your_discord_client_secret
   DISCORD_REDIRECT_URI=https://your-domain.com/auth/discord/callback
   
   ROBLOX_CLIENT_ID=your_roblox_client_id
   ROBLOX_CLIENT_SECRET=your_roblox_client_secret
   ROBLOX_REDIRECT_URI=https://your-domain.com/auth/roblox/callback
   
   MONGO_URI=mongodb://localhost:27017/royalguard
   SECRET_KEY=your_secret_key_here
   ```

2. **Discord OAuth2 Application**
   - Go to https://discord.com/developers/applications
   - Create a new application
   - Go to OAuth2 → General
   - Add redirect URI: `https://your-domain.com/auth/discord/callback`
   - Copy Client ID and Client Secret

3. **ROBLOX OAuth2 Application**
   - Go to https://create.roblox.com/credentials
   - Create a new OAuth2 application
   - Set redirect URI: `https://your-domain.com/auth/roblox/callback`
   - Request scopes: `openid`, `profile`
   - Copy Client ID and Client Secret

4. **MongoDB Database**
   - Set up MongoDB instance (local or cloud)
   - Database: `royalguard`
   - Collection: `oauth_verifications`

## Deployment

### Railway Deployment

1. Connect your GitHub repository to Railway
2. Set environment variables in Railway dashboard
3. Deploy automatically with the included `Procfile`

### Local Development

```bash
pip install -r requirements.txt
python app.py
```

## API Endpoints

- `GET /` - Main landing page with Discord login
- `GET /auth/discord` - Initiate Discord OAuth2 flow
- `GET /auth/discord/callback` - Discord OAuth2 callback
- `GET /auth/roblox` - Initiate ROBLOX OAuth2 flow
- `GET /auth/roblox/callback` - ROBLOX OAuth2 callback
- `GET /terms` - Terms of Service page
- `GET /privacy` - Privacy Policy page

## Database Schema

```javascript
{
  _id: ObjectId,
  discord_id: String,
  discord_username: String,
  discord_discriminator: String,
  discord_global_name: String,
  discord_avatar: String,
  roblox_id: String,
  roblox_username: String,
  roblox_name: String,
  roblox_avatar_url: String,
  verified_at: Date,
  is_reverify: Boolean
}
```

## Security Features

- CSRF protection with state parameters
- Secure session management
- Input validation and sanitization
- Rate limiting ready
- HTTPS enforcement in production

## Legal Compliance

- GDPR Article 6, 13, 15-22 compliance
- CCPA § 1798.100-130 compliance
- COPPA 15 U.S.C. § 6501-6502 compliance
- Communications Decency Act 47 U.S.C. § 230
- Federal Records Act 44 U.S.C. § 3101

## License

© 2025 Arrow Industries. All Rights Reserved.

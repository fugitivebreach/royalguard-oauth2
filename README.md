# Royal Guard OAuth2 Verification Server

Railway-hosted OAuth2 verification system for Discord and Roblox integration.

## Features

- **One-time verification links** (2-minute expiry)
- **Dual OAuth2 flow** (Roblox → Discord)
- **Minimalistic UI** with black background and #363636 styling
- **API endpoints** for bot integration
- **Session management** with automatic cleanup

## Deployment to Railway

1. **Create a new Railway project**
   ```bash
   railway login
   railway init
   ```

2. **Set environment variables in Railway dashboard:**
   - `SECRET_KEY` - Random secret key for Flask sessions
   - `ROBLOX_CLIENT_ID` - Your Roblox OAuth2 client ID
   - `ROBLOX_CLIENT_SECRET` - Your Roblox OAuth2 client secret
   - `REDIRECT_URI` - Your Railway app URL (e.g., `https://your-app.railway.app`)

3. **Deploy:**
   ```bash
   railway up
   ```

## OAuth2 Setup

### Roblox OAuth2
1. Go to https://create.roblox.com/credentials
2. Create new OAuth2 app
3. Set redirect URI: `https://your-app.railway.app/auth/roblox/callback`
4. Copy Client ID and Secret

## API Endpoints

### Create Verification Link
```http
POST /api/create
Content-Type: application/json

{
  "discord_username": "User#1234",
  "discord_id": "123456789012345678"
}
```

**Response:**
```json
{
  "success": true,
  "verification_url": "https://your-app.railway.app/verify/abc123...",
  "session_id": "abc123...",
  "expires_in": 120
}
```

### Check Verification Status
```http
GET /api/check/{session_id}
```

**Response (Completed):**
```json
{
  "verified": true,
  "data": {
    "discord_id": "123456789012345678",
    "discord_username": "User#1234",
    "roblox_id": "987654321",
    "roblox_username": "RobloxUser",
    "completed_at": 1704470400
  }
}
```

## Bot Integration Example

```python
import aiohttp

async def create_verification_link(discord_user):
    async with aiohttp.ClientSession() as session:
        async with session.post(
            'https://your-app.railway.app/api/create',
            json={
                'discord_username': str(discord_user),
                'discord_id': str(discord_user.id)
            }
        ) as resp:
            data = await resp.json()
            return data['verification_url']

async def check_verification(session_id):
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f'https://your-app.railway.app/api/check/{session_id}'
        ) as resp:
            return await resp.json()
```

## File Structure

```
oauth_server/
├── app.py                  # Main Flask application
├── requirements.txt        # Python dependencies
├── Procfile               # Railway deployment config
├── railway.json           # Railway build config
├── .env.example           # Environment variables template
├── templates/
│   ├── index.html         # Landing page
│   ├── redirect.html      # 5-second redirect page
│   ├── success.html       # Verification complete page
│   └── error.html         # Error page
└── static/
    └── RoyalGuardLogo.png # Logo image (add this file)

```

## Static Files

**Required:** Place `RoyalGuardLogo.png` in the `static/` folder before deploying.

## Flow

1. Bot calls `/api/create` with Discord user info (already known)
2. User clicks verification link
3. User authenticates with Roblox OAuth2
4. Verification complete - displays Roblox profile with Discord info
5. Bot polls `/api/check/{session_id}` to get results

## Security

- One-time use links (marked as used after first access)
- 2-minute expiration on all sessions
- Automatic cleanup of expired sessions
- State parameter validation

## Local Development

```bash
cd oauth_server
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your credentials
python app.py
```

Visit `http://localhost:5000`

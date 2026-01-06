# Railway Environment Variables Setup

## Required Environment Variables

Set these in your Railway project dashboard under **Variables**:

### 1. SECRET_KEY
```
Generate a random secret key for Flask sessions
```
**Value:** Use a random string generator or run:
```python
import secrets
print(secrets.token_hex(32))
```

### 2. ROBLOX_CLIENT_ID
```
3209320449011790222
```

### 3. ROBLOX_CLIENT_SECRET
```
RBX-6bN1nNmZ3Earua-29XjNW_K9jMffq4qotpwGzMCBWLtLbV25hWe7Ljv2szoD7Jor
```

### 4. REDIRECT_URI
```
https://arrowsbritisharmy-oauth.up.railway.app
```

### 5. PORT (Optional)
```
5000
```
Railway will auto-assign a port, but you can specify if needed.

---

## Roblox OAuth2 Configuration

### Required Redirect URI in Roblox Developer Portal

Go to: https://create.roblox.com/credentials

**Add this redirect URI to your OAuth2 app:**
```
https://arrowsbritisharmy-oauth.up.railway.app/auth/roblox/callback
```

**Scopes Required:**
- `openid`
- `profile`

---

## Deployment Checklist

- [ ] Set all environment variables in Railway dashboard
- [ ] Add redirect URI to Roblox OAuth2 app
- [ ] Place `RoyalGuardLogo.png` in `static/` folder
- [ ] Deploy to Railway
- [ ] Test verification flow with Discord bot

---

## Testing

After deployment, test the API:

```bash
# Test API endpoint
curl -X POST https://arrowsbritisharmy-oauth.up.railway.app/api/create \
  -H "Content-Type: application/json" \
  -d '{"discord_username":"TestUser#1234","discord_id":"123456789"}'
```

Should return:
```json
{
  "success": true,
  "verification_url": "https://arrowsbritisharmy-oauth.up.railway.app/verify/...",
  "session_id": "...",
  "expires_in": 120
}
```

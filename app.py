from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import requests
import os
from urllib.parse import urlencode
import secrets
import asyncio
from datetime import datetime
from decouple import config

app = Flask(__name__)
app.secret_key = config('SECRET_KEY', default=secrets.token_hex(32))

# Configuration with error handling
try:
    DISCORD_CLIENT_ID = config('DISCORD_CLIENT_ID')
    DISCORD_CLIENT_SECRET = config('DISCORD_CLIENT_SECRET')
    DISCORD_REDIRECT_URI = config('DISCORD_REDIRECT_URI', default='http://localhost:5000/auth/discord/callback')
    
    ROBLOX_CLIENT_ID = config('ROBLOX_CLIENT_ID', default='')
    ROBLOX_CLIENT_SECRET = config('ROBLOX_CLIENT_SECRET', default='')
    ROBLOX_REDIRECT_URI = config('ROBLOX_REDIRECT_URI', default='http://localhost:5000/auth/roblox/callback')
    
    MONGO_URI = config('MONGO_URI', default='mongodb://localhost:27017/royalguard')
    
    print(f"Configuration loaded successfully")
    print(f"Discord Client ID: {'Set' if DISCORD_CLIENT_ID else 'Missing'}")
    print(f"ROBLOX Client ID: {'Set' if ROBLOX_CLIENT_ID else 'Missing'}")
    print(f"MongoDB URI: {'Set' if MONGO_URI else 'Missing'}")
    
except Exception as e:
    print(f"Configuration error: {e}")
    # Set defaults to prevent crashes
    DISCORD_CLIENT_ID = ''
    DISCORD_CLIENT_SECRET = ''
    DISCORD_REDIRECT_URI = 'http://localhost:5000/auth/discord/callback'
    ROBLOX_CLIENT_ID = ''
    ROBLOX_CLIENT_SECRET = ''
    ROBLOX_REDIRECT_URI = 'http://localhost:5000/auth/roblox/callback'
    MONGO_URI = 'mongodb://localhost:27017/royalguard'

# MongoDB setup - Initialize lazily to avoid startup issues
verified_users_collection = None

def get_db_collection():
    global verified_users_collection
    if verified_users_collection is None:
        try:
            import motor.motor_asyncio
            client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
            db = client['royalguard']
            verified_users_collection = db['verifiedusers']
        except Exception as e:
            print(f"MongoDB connection error: {e}")
            # Continue without MongoDB for now
            pass
    return verified_users_collection

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/auth/discord')
def discord_auth():
    # Generate state for security
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    
    params = {
        'client_id': DISCORD_CLIENT_ID,
        'redirect_uri': DISCORD_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'identify',
        'state': state
    }
    
    discord_auth_url = f"https://discord.com/api/oauth2/authorize?{urlencode(params)}"
    return redirect(discord_auth_url)

@app.route('/auth/discord/callback')
def discord_callback():
    print(f"Discord callback received with code: {request.args.get('code')[:10]}...")
    
    # Check if Discord credentials are available
    if not DISCORD_CLIENT_ID or not DISCORD_CLIENT_SECRET:
        return render_template('error.html', error="Discord OAuth not configured")
    
    # Verify state parameter
    if request.args.get('state') != session.get('oauth_state'):
        return render_template('error.html', error="Invalid state parameter")
    
    code = request.args.get('code')
    if not code:
        return render_template('error.html', error="No authorization code received")
    
    # Exchange code for access token
    token_data = {
        'client_id': DISCORD_CLIENT_ID,
        'client_secret': DISCORD_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': DISCORD_REDIRECT_URI
    }
    
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    token_response = requests.post('https://discord.com/api/oauth2/token', data=token_data, headers=headers)
    
    if token_response.status_code != 200:
        return render_template('error.html', error="Failed to get Discord access token")
    
    token_json = token_response.json()
    access_token = token_json.get('access_token')
    
    # Get user info
    user_headers = {'Authorization': f'Bearer {access_token}'}
    user_response = requests.get('https://discord.com/api/users/@me', headers=user_headers)
    
    if user_response.status_code != 200:
        return render_template('error.html', error="Failed to get Discord user info")
    
    user_data = user_response.json()
    
    # Store Discord data in session (no database verification without ROBLOX)
    session['discord_user'] = {
        'id': user_data['id'],
        'username': user_data['username'],
        'discriminator': user_data.get('discriminator', '0'),
        'avatar': user_data.get('avatar'),
        'global_name': user_data.get('global_name')
    }
    
    return render_template('discord_success.html', user=user_data)

@app.route('/auth/roblox')
def roblox_auth():
    if 'discord_user' not in session:
        return redirect(url_for('index'))
    
    # Check if ROBLOX OAuth is available
    if not ROBLOX_CLIENT_ID or not ROBLOX_CLIENT_SECRET:
        return render_template('error.html', error="ROBLOX OAuth2 is temporarily unavailable - pending approval from ROBLOX")
    
    # Generate state for security
    state = secrets.token_urlsafe(32)
    session['roblox_state'] = state
    
    params = {
        'client_id': ROBLOX_CLIENT_ID,
        'redirect_uri': ROBLOX_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'openid profile',
        'state': state
    }
    
    roblox_auth_url = f"https://apis.roblox.com/oauth/v1/authorize?{urlencode(params)}"
    return redirect(roblox_auth_url)

@app.route('/auth/roblox/callback')
def roblox_callback():
    # Verify state parameter
    if request.args.get('state') != session.get('roblox_state'):
        return render_template('verification_result.html', success=False, error="Invalid state parameter")
    
    code = request.args.get('code')
    if not code:
        return render_template('verification_result.html', success=False, error="No authorization code received")
    
    # Exchange code for access token
    token_data = {
        'client_id': ROBLOX_CLIENT_ID,
        'client_secret': ROBLOX_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': ROBLOX_REDIRECT_URI
    }
    
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    token_response = requests.post('https://apis.roblox.com/oauth/v1/token', data=token_data, headers=headers)
    
    if token_response.status_code != 200:
        return render_template('verification_result.html', success=False, error="Failed to get ROBLOX access token")
    
    token_json = token_response.json()
    access_token = token_json.get('access_token')
    
    # Get user info
    user_headers = {'Authorization': f'Bearer {access_token}'}
    user_response = requests.get('https://apis.roblox.com/oauth/v1/userinfo', headers=user_headers)
    
    if user_response.status_code != 200:
        return render_template('verification_result.html', success=False, error="Failed to get ROBLOX user info")
    
    roblox_data = user_response.json()
    discord_user = session.get('discord_user')
    
    if not discord_user:
        return render_template('verification_result.html', success=False, error="Discord session expired")
    
    # Get ROBLOX user data via API
    roblox_id = roblox_data.get('sub')
    roblox_username = roblox_data.get('preferred_username')
    
    # Get additional ROBLOX user info
    roblox_user_response = requests.get(f'https://users.roblox.com/v1/users/{roblox_id}')
    roblox_user_info = {}
    if roblox_user_response.status_code == 200:
        roblox_user_info = roblox_user_response.json()
    
    # Get ROBLOX avatar headshot
    avatar_response = requests.get(f'https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds={roblox_id}&size=150x150&format=Png&isCircular=true')
    avatar_url = None
    
    if avatar_response.status_code == 200:
        avatar_data = avatar_response.json()
        if avatar_data.get('data') and len(avatar_data['data']) > 0:
            avatar_url = avatar_data['data'][0].get('imageUrl')
    
    # Get group memberships for additional verification
    group_memberships = []
    groups_response = requests.get(f'https://groups.roblox.com/v2/users/{roblox_id}/groups?limit=100')
    if groups_response.status_code == 200:
        groups_data = groups_response.json()
        group_memberships = groups_data.get('data', [])
    
    # Check if user was previously verified (reverification)
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        collection = get_db_collection()
        if collection is None:
            # Skip database operations if MongoDB is not available
            is_reverify = False
            banned = False
            suspended = False
        else:
            existing_verification = loop.run_until_complete(
                collection.find_one({
                    '$or': [
                        {'_id': int(discord_user['id'])},
                        {'roblox': int(roblox_id)}
                    ]
                })
            )
        
            is_reverify = existing_verification is not None
            
            # Check for banned/suspended status from existing records
            banned = False
            suspended = False
            if existing_verification:
                banned = existing_verification.get('banned', False)
                suspended = existing_verification.get('suspended', False)
            else:
                # Check all records with this ROBLOX ID for banned/suspended status
                all_records = loop.run_until_complete(
                    collection.find({'roblox': int(roblox_id)}).to_list(None)
                )
                if all_records:
                    banned = any(record.get('banned', False) for record in all_records)
                    suspended = any(record.get('suspended', False) for record in all_records)
            
            # Store verification data using bot's schema
            verification_data = {
                '_id': int(discord_user['id']),
                'roblox': int(roblox_id),
                'banned': banned,
                'suspended': suspended,
            }
            
            # Upsert verification record
            loop.run_until_complete(
                collection.replace_one(
                    {'_id': int(discord_user['id'])},
                    verification_data,
                    upsert=True
                )
            )
        
        loop.close()
        
    except Exception as e:
        return render_template('verification_result.html', success=False, error="Database error occurred")
    
    # Prepare data for template
    result_data = {
        'discord_user': discord_user,
        'roblox_data': {
            'id': roblox_id,
            'username': roblox_username,
            'display_name': roblox_user_info.get('displayName', roblox_username),
            'description': roblox_user_info.get('description', ''),
            'created': roblox_user_info.get('created', ''),
            'avatar_url': avatar_url
        },
        'is_reverify': is_reverify,
        'banned': banned,
        'suspended': suspended,
        'group_memberships': group_memberships[:5]  # Show top 5 groups
    }
    
    return render_template('verification_result.html', success=True, data=result_data)

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/health')
def health_check():
    return {'status': 'healthy', 'message': 'OAuth verification service is running'}

@app.route('/test')
def test_route():
    return "Railway app is working! Routes are accessible."

# Remove deprecated before_first_request - use startup logging instead
print("Flask app initialized successfully!")
print(f"Available routes: {[rule.rule for rule in app.url_map.iter_rules()]}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"Starting Flask app on port {port}")
    print(f"Available routes: {[rule.rule for rule in app.url_map.iter_rules()]}")
    app.run(debug=False, host='0.0.0.0', port=port)

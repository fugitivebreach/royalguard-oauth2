from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import requests
import os
from urllib.parse import urlencode
import secrets
from datetime import datetime
from decouple import config
import pymongo
from pymongo import MongoClient
import logging
import asyncio
import aiohttp
import json

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
    
    # Discord logging configuration
    DISCORD_BOT_TOKEN = config('DISCORD_BOT_TOKEN', default='')
    VERIFICATION_LOG_CHANNEL_ID = config('VERIFICATION_LOG_CHANNEL_ID', default='1414357206039662706')
    
    # IP Info API configuration
    IPINFO_API_TOKEN = config('IPINFO_API_TOKEN', default='')
    
    logger.info("Configuration loaded successfully")
    logger.info(f"Discord Client ID: {'Set' if DISCORD_CLIENT_ID else 'Missing'}")
    logger.info(f"ROBLOX Client ID: {'Set' if ROBLOX_CLIENT_ID else 'Missing'}")
    logger.info(f"MongoDB URI: {'Set' if MONGO_URI else 'Missing'}")
    logger.info(f"Discord Bot Token: {'Set' if DISCORD_BOT_TOKEN else 'Missing'}")
    logger.info(f"IPInfo API Token: {'Set' if IPINFO_API_TOKEN else 'Missing'}")
    
except Exception as e:
    logger.error(f"Configuration error: {e}")
    # Set defaults to prevent crashes
    DISCORD_CLIENT_ID = ''
    DISCORD_CLIENT_SECRET = ''
    DISCORD_REDIRECT_URI = 'http://localhost:5000/auth/discord/callback'
    ROBLOX_CLIENT_ID = ''
    ROBLOX_CLIENT_SECRET = ''
    ROBLOX_REDIRECT_URI = 'http://localhost:5000/auth/roblox/callback'
    MONGO_URI = 'mongodb://localhost:27017/royalguard'
    DISCORD_BOT_TOKEN = ''
    VERIFICATION_LOG_CHANNEL_ID = '1414357206039662706'
    IPINFO_API_TOKEN = ''

# MongoDB setup - Use synchronous pymongo for Flask compatibility
mongo_client = None
verified_users_collection = None

def get_db_collection():
    global mongo_client, verified_users_collection
    if verified_users_collection is None:
        try:
            mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
            # Test the connection
            mongo_client.admin.command('ping')
            db = mongo_client['royalguard']
            verified_users_collection = db['verifiedusers']
            logger.info("MongoDB connection established successfully")
        except Exception as e:
            logger.error(f"MongoDB connection error: {e}")
            verified_users_collection = None
    return verified_users_collection

def close_db_connection():
    global mongo_client
    if mongo_client:
        mongo_client.close()
        logger.info("MongoDB connection closed")

async def get_ip_info(ip_address):
    """Get IP information using ipinfo.io API"""
    try:
        if IPINFO_API_TOKEN:
            url = f"https://ipinfo.io/{ip_address}/json?token={IPINFO_API_TOKEN}"
        else:
            url = f"https://ipinfo.io/{ip_address}/json"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'ip': data.get('ip', ip_address),
                        'hostname': data.get('hostname', 'N/A'),
                        'city': data.get('city', 'N/A'),
                        'region': data.get('region', 'N/A'),
                        'country': data.get('country', 'N/A'),
                        'loc': data.get('loc', 'N/A'),
                        'org': data.get('org', 'N/A'),
                        'postal': data.get('postal', 'N/A'),
                        'timezone': data.get('timezone', 'N/A')
                    }
    except Exception as e:
        logger.error(f"Error getting IP info: {e}")
    
    return {
        'ip': ip_address,
        'hostname': 'N/A',
        'city': 'N/A',
        'region': 'N/A',
        'country': 'N/A',
        'loc': 'N/A',
        'org': 'N/A',
        'postal': 'N/A',
        'timezone': 'N/A'
    }

def get_client_ip():
    """Get the real client IP address"""
    # Check for forwarded headers first
    if request.headers.get('X-Forwarded-For'):
        # Get the first IP in the chain (original client)
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    elif request.headers.get('CF-Connecting-IP'):  # Cloudflare
        return request.headers.get('CF-Connecting-IP')
    else:
        return request.remote_addr

async def send_verification_log(discord_user, roblox_data, ip_info, is_reverify=False):
    """Send verification log to Discord channel"""
    try:
        if not DISCORD_BOT_TOKEN or not VERIFICATION_LOG_CHANNEL_ID:
            logger.warning("Discord logging not configured - skipping log")
            return
        
        # Parse location data
        location_parts = ip_info.get('loc', 'N/A').split(',') if ip_info.get('loc') != 'N/A' else ['N/A', 'N/A']
        latitude = location_parts[0] if len(location_parts) > 0 else 'N/A'
        longitude = location_parts[1] if len(location_parts) > 1 else 'N/A'
        
        # Create embed data
        embed_data = {
            "title": "Arrow Verification Logs",
            "description": f"Viewing verification log for <@{discord_user['id']}>",
            "color": 0x2E4F8E,  # discord.Color.blue() equivalent
            "fields": [
                {
                    "name": "Verification Information",
                    "value": (
                        f"Discord: <@{discord_user['id']}> | {discord_user['id']} | {discord_user['username']}\n"
                        f"ROBLOX: {roblox_data.get('username', 'N/A')} | {roblox_data.get('id', 'N/A')} | "
                        f"https://www.roblox.com/users/{roblox_data.get('id', '0')}/profile\n"
                        f"Method: OAuth2"
                    ),
                    "inline": False
                },
                {
                    "name": "Data",
                    "value": (
                        f"Association: {ip_info.get('org', 'N/A')}\n"
                        f"Country Code: {ip_info.get('country', 'N/A')}\n"
                        f"Internet Service Provider: {ip_info.get('org', 'N/A')}\n"
                        f"Latitude: {latitude}\n"
                        f"Longitude: {longitude}\n"
                        f"Region Name: {ip_info.get('region', 'N/A')}\n"
                        f"IP: {ip_info.get('ip', 'N/A')}"
                    ),
                    "inline": False
                }
            ],
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Add author field
        if discord_user.get('avatar'):
            avatar_url = f"https://cdn.discordapp.com/avatars/{discord_user['id']}/{discord_user['avatar']}.png"
        else:
            avatar_url = f"https://cdn.discordapp.com/embed/avatars/{int(discord_user['id']) % 5}.png"
        
        embed_data["author"] = {
            "name": discord_user.get('global_name') or discord_user['username'],
            "icon_url": avatar_url
        }
        
        # Send to Discord using bot token
        headers = {
            'Authorization': f'Bot {DISCORD_BOT_TOKEN}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            'embeds': [embed_data]
        }
        
        async with aiohttp.ClientSession() as session:
            url = f"https://discord.com/api/v10/channels/{VERIFICATION_LOG_CHANNEL_ID}/messages"
            async with session.post(url, headers=headers, json=payload) as response:
                if response.status == 200:
                    logger.info(f"Successfully sent verification log for Discord ID {discord_user['id']}")
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to send Discord log: {response.status} - {error_text}")
                    
    except Exception as e:
        logger.error(f"Error sending verification log: {e}")

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
        return render_template('error.html', error="ROBLOX OAuth2 credentials not configured. Please contact an administrator.")
    
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
        collection = get_db_collection()
        if collection is None:
            # Skip database operations if MongoDB is not available
            logger.warning("MongoDB not available, skipping database operations")
            is_reverify = False
            banned = False
            suspended = False
        else:
            # Convert IDs to integers for database queries
            discord_id = int(discord_user['id'])
            roblox_id_int = int(roblox_id)
            
            # Check for existing verification
            existing_verification = collection.find_one({
                '$or': [
                    {'_id': discord_id},
                    {'roblox': roblox_id_int}
                ]
            })
            
            is_reverify = existing_verification is not None
            
            # Check for banned/suspended status from existing records
            banned = False
            suspended = False
            if existing_verification:
                banned = existing_verification.get('banned', False)
                suspended = existing_verification.get('suspended', False)
                logger.info(f"Found existing verification for Discord ID {discord_id}")
            else:
                # Check all records with this ROBLOX ID for banned/suspended status
                all_records = list(collection.find({'roblox': roblox_id_int}))
                if all_records:
                    banned = any(record.get('banned', False) for record in all_records)
                    suspended = any(record.get('suspended', False) for record in all_records)
                    logger.info(f"Found {len(all_records)} existing records for ROBLOX ID {roblox_id_int}")
            
            # Store verification data using bot's schema
            verification_data = {
                '_id': discord_id,
                'roblox': roblox_id_int,
                'banned': banned,
                'suspended': suspended
            }
            
            # Upsert verification record
            result = collection.replace_one(
                {'_id': discord_id},
                verification_data,
                upsert=True
            )
            
            if result.upserted_id:
                logger.info(f"Created new verification record for Discord ID {discord_id}")
            else:
                logger.info(f"Updated existing verification record for Discord ID {discord_id}")
        
    except pymongo.errors.PyMongoError as e:
        logger.error(f"MongoDB error during verification: {e}")
        return render_template('verification_result.html', success=False, error=f"Database error: {str(e)}")
    except ValueError as e:
        logger.error(f"Data conversion error: {e}")
        return render_template('verification_result.html', success=False, error="Invalid user ID format")
    except Exception as e:
        logger.error(f"Unexpected error during verification: {e}")
        return render_template('verification_result.html', success=False, error="An unexpected error occurred during verification")
    
    # Get client IP and IP information for logging
    client_ip = get_client_ip()
    
    # Get IP information asynchronously
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        ip_info = loop.run_until_complete(get_ip_info(client_ip))
        
        # Send verification log to Discord
        roblox_log_data = {
            'id': roblox_id,
            'username': roblox_username
        }
        loop.run_until_complete(send_verification_log(discord_user, roblox_log_data, ip_info, is_reverify))
        loop.close()
        
        logger.info(f"Verification logged for Discord ID {discord_user['id']} with IP {client_ip}")
    except Exception as e:
        logger.error(f"Error during IP collection or logging: {e}")
    
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
    health_status = {
        'status': 'healthy',
        'message': 'OAuth verification service is running',
        'database': 'disconnected',
        'timestamp': datetime.utcnow().isoformat()
    }
    
    # Test database connection
    try:
        collection = get_db_collection()
        if collection is not None:
            # Test with a simple ping
            collection.database.client.admin.command('ping')
            health_status['database'] = 'connected'
            
            # Get collection stats
            stats = collection.database.command('collStats', 'verifiedusers')
            health_status['database_stats'] = {
                'document_count': stats.get('count', 0),
                'size_bytes': stats.get('size', 0)
            }
    except Exception as e:
        health_status['database'] = f'error: {str(e)}'
        logger.error(f"Health check database error: {e}")
    
    return jsonify(health_status)

@app.route('/test')
def test_route():
    return "Railway app is working! Routes are accessible."

# Add cleanup handler for graceful shutdown
import atexit
atexit.register(close_db_connection)

# Remove deprecated before_first_request - use startup logging instead
logger.info("Flask app initialized successfully!")
logger.info(f"Available routes: {[rule.rule for rule in app.url_map.iter_rules()]}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"Starting Flask app on port {port}")
    logger.info(f"Available routes: {[rule.rule for rule in app.url_map.iter_rules()]}")
    app.run(debug=False, host='0.0.0.0', port=port)

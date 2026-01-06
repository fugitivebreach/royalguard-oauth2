"""
Royal Guard OAuth2 Verification Server
Railway Deployment
"""

from flask import Flask, render_template, request, redirect, session, jsonify
import requests
import secrets
import time
import os
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# OAuth2 Configuration (set these in Railway environment variables)
ROBLOX_CLIENT_ID = os.environ.get('ROBLOX_CLIENT_ID')
ROBLOX_CLIENT_SECRET = os.environ.get('ROBLOX_CLIENT_SECRET')
REDIRECT_URI = os.environ.get('REDIRECT_URI', 'http://localhost:5000')

# In-memory storage for verification sessions (use Redis/DB in production)
verification_sessions = {}
completed_verifications = {}

def cleanup_expired_sessions():
    """Remove expired sessions"""
    current_time = time.time()
    expired = [k for k, v in verification_sessions.items() if v['expires_at'] < current_time]
    for key in expired:
        del verification_sessions[key]

@app.route('/')
def home():
    """Landing page"""
    return render_template('index.html')

@app.route('/api/create', methods=['POST'])
def create_verification():
    """API endpoint to create a one-time verification link"""
    try:
        data = request.json
        discord_username = data.get('discord_username')
        discord_id = data.get('discord_id')
        
        if not discord_username or not discord_id:
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Generate unique session ID
        session_id = secrets.token_urlsafe(32)
        
        # Store session (expires in 2 minutes)
        verification_sessions[session_id] = {
            'discord_username': discord_username,
            'discord_id': discord_id,
            'time_unix': int(time.time()),
            'expires_at': time.time() + 120,  # 2 minutes
            'used': False
        }
        
        # Cleanup old sessions
        cleanup_expired_sessions()
        
        verification_url = f"{REDIRECT_URI}/verify/{session_id}"
        
        return jsonify({
            'success': True,
            'verification_url': verification_url,
            'session_id': session_id,
            'expires_in': 120
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/verify/<session_id>')
def start_verification(session_id):
    """Start verification process"""
    cleanup_expired_sessions()
    
    # Check if session exists and is valid
    if session_id not in verification_sessions:
        return render_template('error.html', message="Verification link expired or invalid")
    
    session_data = verification_sessions[session_id]
    
    # Check if already used
    if session_data['used']:
        return render_template('error.html', message="Verification link already used")
    
    # Check if expired
    if session_data['expires_at'] < time.time():
        del verification_sessions[session_id]
        return render_template('error.html', message="Verification link expired")
    
    # Mark as used
    verification_sessions[session_id]['used'] = True
    
    # Store session ID in Flask session
    session['verification_session'] = session_id
    
    # Redirect to Roblox OAuth
    roblox_auth_url = f"https://apis.roblox.com/oauth/v1/authorize?client_id={ROBLOX_CLIENT_ID}&redirect_uri={REDIRECT_URI}/auth/roblox/callback&scope=openid%20profile&response_type=code&state={session_id}"
    
    return redirect(roblox_auth_url)

@app.route('/auth/roblox/callback')
def roblox_callback():
    """Handle Roblox OAuth callback"""
    code = request.args.get('code')
    state = request.args.get('state')
    
    if not code or not state:
        return render_template('error.html', message="Invalid callback from Roblox")
    
    # Verify state matches session
    if state not in verification_sessions:
        return render_template('error.html', message="Invalid verification session")
    
    try:
        # Get user IP address
        user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ',' in user_ip:
            user_ip = user_ip.split(',')[0].strip()
        
        # Get geolocation data from IP
        geo_data = {}
        try:
            geo_response = requests.get(f'http://ip-api.com/json/{user_ip}?fields=status,country,countryCode,region,lat,lon,isp,query')
            if geo_response.status_code == 200:
                geo_json = geo_response.json()
                if geo_json.get('status') == 'success':
                    geo_data = {
                        'ip': geo_json.get('query', user_ip),
                        'country': geo_json.get('country', 'Unknown'),
                        'country_code': geo_json.get('countryCode', 'Unknown'),
                        'region': geo_json.get('region', 'Unknown'),
                        'latitude': geo_json.get('lat', 0.0),
                        'longitude': geo_json.get('lon', 0.0),
                        'isp': geo_json.get('isp', 'Unknown')
                    }
                else:
                    geo_data = {
                        'ip': user_ip,
                        'country': 'Unknown',
                        'country_code': 'Unknown',
                        'region': 'Unknown',
                        'latitude': 0.0,
                        'longitude': 0.0,
                        'isp': 'Unknown'
                    }
        except Exception as geo_error:
            print(f"[GEOLOCATION] Error fetching geo data: {geo_error}")
            geo_data = {
                'ip': user_ip,
                'country': 'Unknown',
                'country_code': 'Unknown',
                'region': 'Unknown',
                'latitude': 0.0,
                'longitude': 0.0,
                'isp': 'Unknown'
            }
        
        # Exchange code for access token
        token_response = requests.post('https://apis.roblox.com/oauth/v1/token', data={
            'client_id': ROBLOX_CLIENT_ID,
            'client_secret': ROBLOX_CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'code': code
        })
        
        if token_response.status_code != 200:
            return render_template('error.html', message="Failed to authenticate with Roblox")
        
        token_data = token_response.json()
        access_token = token_data['access_token']
        
        # Get user info
        user_response = requests.get('https://apis.roblox.com/oauth/v1/userinfo', headers={
            'Authorization': f'Bearer {access_token}'
        })
        
        if user_response.status_code != 200:
            return render_template('error.html', message="Failed to get Roblox user info")
        
        roblox_user = user_response.json()
        
        # Store Roblox data and geolocation in session
        verification_sessions[state]['roblox_id'] = roblox_user['sub']
        verification_sessions[state]['roblox_username'] = roblox_user['preferred_username']
        verification_sessions[state]['roblox_profile_url'] = roblox_user['profile']
        verification_sessions[state]['verified'] = True
        verification_sessions[state]['geolocation'] = geo_data
        
        # Move to completed verifications
        completed_verifications[state] = verification_sessions[state].copy()
        completed_verifications[state]['completed_at'] = int(time.time())
        
        # Show success page
        return render_template('success.html', data=completed_verifications[state])
    
    except Exception as e:
        return render_template('error.html', message=f"Error during Roblox authentication: {str(e)}")

@app.route('/api/check/<session_id>')
def check_verification(session_id):
    """API endpoint to check verification status"""
    if session_id in completed_verifications:
        return jsonify({
            'verified': True,
            'data': completed_verifications[session_id]
        }), 200
    elif session_id in verification_sessions:
        return jsonify({
            'verified': False,
            'status': 'pending'
        }), 200
    else:
        return jsonify({
            'verified': False,
            'status': 'not_found'
        }), 404

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

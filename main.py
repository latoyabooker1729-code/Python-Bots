import json
from uuid import uuid4
import requests
import logging
import asyncio
import threading
import hashlib
import hmac
import base64
import time
from flask import Flask, jsonify
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes, ConversationHandler
from telegram.error import TelegramError
import os
from datetime import datetime

# Initialize Flask app for health checks
app = Flask(__name__)

# Bot token
TOKEN = "8522048948:AAH4DVdoM63rhxmiqRtpl_z2O0Lk6w7L3uo"
PORT = int(os.environ.get('PORT', 5000))

# Enable logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Global variable to track bot status
bot_status = {
    "started": False,
    "last_poll": None,
    "last_reset_request": None,
    "last_login_attempt": None,
    "total_requests": 0,
    "successful_requests": 0,
    "failed_requests": 0,
    "login_attempts": 0,
    "successful_logins": 0,
    "failed_logins": 0
}

# States for login conversation
USERNAME, PASSWORD = range(2)

def generate_device_id(username):
    """Generate a consistent device ID based on username"""
    seed = f"android-{username}"
    md5 = hashlib.md5(seed.encode()).hexdigest()
    return md5[:16]

def generate_signature(data):
    """Generate Instagram signature (simplified version)"""
    # Note: This is a simplified version. Instagram's actual signature is more complex
    key = b'7d891af0aadc89a7eaa2e9e5c3f7a8c9'
    h = hmac.new(key, data.encode(), hashlib.sha256)
    return base64.b64encode(h.digest()).decode()

def instagram_login(username, password):
    """
    Attempt to login to Instagram with username and password
    Returns: (success, message, session_data)
    """
    try:
        # Generate device ID
        device_id = generate_device_id(username)
        
        # Generate a phone ID
        phone_id = str(uuid4())
        
        # Generate a GUID
        guid = str(uuid4())
        
        # Current timestamp
        ts = int(time.time())
        
        # Headers for login
        headers = {
            'User-Agent': 'Instagram 309.0.0.31.113 Android (25/7.1.2; 450dpi; 2048x2048; Google; Pixel; sailfish; en_US; 545986883)',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Accept-Language': 'en-US',
            'X-IG-App-ID': '567067343352427',
            'X-IG-Capabilities': '3brTv10=',
            'X-IG-Connection-Type': 'WIFI',
            'X-IG-Device-ID': device_id,
            'X-IG-Device-Locale': 'en_US',
            'X-IG-Mapped-Locale': 'en_US',
            'X-FB-HTTP-Engine': 'Liger',
            'Accept-Encoding': 'gzip, deflate',
            'Host': 'i.instagram.com',
            'Connection': 'close',
        }
        
        # Login payload
        login_data = {
            'jazoest': '22523',
            'country_codes': '[{"country_code":"1","source":"default"}]',
            'phone_id': phone_id,
            'enc_password': f'#PWD_INSTAGRAM_BROWSER:0:{ts}:{password}',
            'username': username,
            'adid': str(uuid4()),
            'guid': guid,
            'device_id': device_id,
            'google_tokens': '[]',
            'login_attempt_count': '0',
        }
        
        # Create signature
        sig_data = json.dumps(login_data, separators=(',', ':'))
        signature = generate_signature(sig_data)
        
        # Add signature to data
        signed_body = f'signed_body={signature}.{sig_data}&ig_sig_key_version=4'
        
        # Send login request
        response = requests.post(
            'https://i.instagram.com/api/v1/accounts/login/',
            headers=headers,
            data=signed_body,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            
            if result.get('status') == 'ok' and result.get('logged_in_user'):
                user_id = result['logged_in_user']['pk']
                username = result['logged_in_user']['username']
                full_name = result['logged_in_user']['full_name']
                
                # Extract session cookies
                session_data = {
                    'user_id': user_id,
                    'username': username,
                    'full_name': full_name,
                    'device_id': device_id,
                    'session_id': response.cookies.get('sessionid'),
                    'csrftoken': response.cookies.get('csrftoken'),
                    'headers': headers
                }
                
                return True, f"✅ Login successful!\n\n👤 Username: {username}\n🆔 User ID: {user_id}\n📛 Full Name: {full_name}", session_data
            else:
                error_msg = result.get('message', 'Unknown error')
                if 'checkpoint' in error_msg.lower():
                    return False, "❌ Login failed: Account checkpoint required. Please check your email/phone.", None
                elif 'password' in error_msg.lower():
                    return False, "❌ Login failed: Incorrect password.", None
                else:
                    return False, f"❌ Login failed: {error_msg}", None
        else:
            error_msg = response.text
            try:
                error_json = response.json()
                error_msg = error_json.get('message', error_msg)
            except:
                pass
            
            return False, f"❌ Login failed (HTTP {response.status_code}): {error_msg}", None
            
    except requests.exceptions.Timeout:
        return False, "❌ Login failed: Request timeout. Try again later.", None
    except requests.exceptions.ConnectionError:
        return False, "❌ Login failed: Connection error. Check your internet.", None
    except Exception as e:
        return False, f"❌ Login failed: {str(e)}", None

def send_instagram_password_reset(query: str):
    """
    Send Instagram password reset request
    """
    headers = {
        'User-Agent': 'Instagram 311.0.0.32.118 Android (25/7.1.2; 450dpi; 2048x2048; Google; Pixel; sailfish; en_US; 545986883)',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'accept-language': 'en-US',
        'ig-intended-user-id': '0',
        'priority': 'u=3',
        'x-bloks-is-layout-rtl': 'false',
        'x-bloks-is-prism-enabled': 'true',
        'x-bloks-prism-button-version': '0',
        'x-bloks-version-id': '',
        'x-fb-client-ip': 'True',
        'x-fb-connection-type': 'WIFI',
        'x-fb-friendly-name': 'IgApi: accounts/send_recovery_flow_email/',
        'x-fb-request-analytics-tags': '{}',
        'x-fb-server-cluster': 'True',
        'x-ig-android-id': 'android-' + uuid4().hex[:16],
        'x-ig-app-id': '567067343352427',
        'x-ig-app-locale': 'en_US',
        'x-ig-bandwidth-speed-kbps': '652.000',
        'x-ig-bandwidth-totalbytes-b': '494530',
        'x-ig-bandwidth-totaltime-ms': '906',
        'x-ig-client-endpoint': 'user_password_recovery',
        'x-ig-capabilities': '3brTv10=',
        'x-ig-connection-type': 'WIFI',
        'x-ig-device-id': 'android-' + uuid4().hex[:16],
        'x-ig-device-locale': 'en_US',
        'x-ig-family-device-id': str(uuid4()),
        'x-ig-mapped-locale': 'en_US',
        'x-ig-nav-chain': '',
        'x-ig-timezone-offset': '19800',
        'x-ig-www-claim': '0',
        'x-mid': '',
        'x-pigeon-rawclienttime': '',
        'x-pigeon-session-id': '',
        'x-tigon-is-retry': 'False',
        'x-fb-http-engine': 'MNS',
        'x-fb-rmd': '',
        'x-fb-session-id': '',
        'x-fb-session-private': '',
    }
    
    data = {
        "adid": str(uuid4()),
        "guid": str(uuid4()),
        "device_id": "android-5b7ed0786fa2ec6f",
        "query": query,
        "waterfall_id": "6f838327-b51f-4bc1-89a2-32d5c8667ba7"
    }
    
    try:
        r = requests.post(
            'https://i-fallback.instagram.com/api/v1/accounts/send_recovery_flow_email/',
            headers=headers,
            data=data,
        )
        
        j = r.json()
        y = j.get('email', 'N/A')
        e = j.get('error_type', 'Unknown')
        
        if r.status_code == 200:
            return True, f"Password reset successfully sent to: {y}"
        else:
            return False, f"Failed to send password reset link. Error: {e}"
            
    except Exception as ex:
        return False, f"Request failed: {str(ex)}"

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send a welcome message when the command /start is issued."""
    welcome_text = """
🤖 Instagram Password Reset Bot

I can help you with Instagram account management:

🔐 **Password Reset:**
• Send any username or email to get password reset link

🔓 **Login Check:**
• Use /login to check if credentials are valid

📊 **Bot Status:**
• Use /status to see bot statistics

How to use:
1. For reset: Just send a username or email
2. For login: Use /login command

⚠️ Note: This bot uses Instagram's official APIs.
"""
    await update.message.reply_text(welcome_text)

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send a help message"""
    help_text = """
📋 Available Commands:

/start - Start the bot
/help - Show this help message
/login - Check Instagram login credentials
/status - Show bot statistics and uptime
/cancel - Cancel current operation

🔐 Login Usage:
1. Type /login
2. Enter username when asked
3. Enter password when asked
4. Get login result

📨 Reset Usage:
Just send any Instagram username or email

⚠️ Privacy:
• I don't store any credentials
• Login attempts are not saved
• All data is processed in memory only
"""
    await update.message.reply_text(help_text)

async def login_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start the login conversation"""
    await update.message.reply_text(
        "🔐 *Instagram Login Check*\n\n"
        "Please enter the Instagram username:\n"
        "(Type /cancel to stop)",
        parse_mode='Markdown'
    )
    return USERNAME

async def login_username(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Store username and ask for password"""
    username = update.message.text.strip()
    
    # Basic validation
    if len(username) < 3:
        await update.message.reply_text(
            "❌ Username is too short. Please enter a valid Instagram username:"
        )
        return USERNAME
    
    context.user_data['login_username'] = username
    
    await update.message.reply_text(
        f"👤 Username: {username}\n\n"
        "Now please enter the password:\n"
        "(Type /cancel to stop)\n\n"
        "⚠️ Your password will be sent to Instagram's servers for authentication."
    )
    return PASSWORD

async def login_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Process login with username and password"""
    password = update.message.text.strip()
    username = context.user_data.get('login_username', '')
    
    if len(password) < 6:
        await update.message.reply_text(
            "❌ Password is too short. Please enter the password again:"
        )
        return PASSWORD
    
    # Update stats
    bot_status["login_attempts"] += 1
    bot_status["last_login_attempt"] = datetime.now()
    
    # Send processing message
    processing_msg = await update.message.reply_text(
        f"🔄 Attempting to login as: {username}\n\n"
        "Checking credentials with Instagram..."
    )
    
    # Attempt login
    success, message, session_data = instagram_login(username, password)
    
    # Update counters
    if success:
        bot_status["successful_logins"] += 1
    else:
        bot_status["failed_logins"] += 1
    
    # Clear stored data for security
    if 'login_username' in context.user_data:
        del context.user_data['login_username']
    
    # Send result
    await update.message.reply_text(message)
    
    # Delete processing message
    try:
        await processing_msg.delete()
    except:
        pass
    
    return ConversationHandler.END

async def login_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Cancel the login conversation"""
    await update.message.reply_text(
        "❌ Login process cancelled.\n"
        "No credentials were stored.",
        reply_markup=None
    )
    
    # Clear stored data
    if 'login_username' in context.user_data:
        del context.user_data['login_username']
    
    return ConversationHandler.END

async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show bot status and statistics"""
    uptime = "Unknown"
    if bot_status["started"] and bot_status["last_poll"]:
        uptime_seconds = (datetime.now() - bot_status["started"]).total_seconds()
        days = uptime_seconds // 86400
        hours = (uptime_seconds % 86400) // 3600
        minutes = (uptime_seconds % 3600) // 60
        uptime = f"{int(days)}d {int(hours)}h {int(minutes)}m"
    
    last_reset = bot_status["last_reset_request"].strftime("%Y-%m-%d %H:%M:%S") if bot_status["last_reset_request"] else "None"
    last_login = bot_status["last_login_attempt"].strftime("%Y-%m-%d %H:%M:%S") if bot_status["last_login_attempt"] else "None"
    
    status_text = f"""
📊 Bot Statistics:

✅ Status: Running
⏰ Uptime: {uptime}
🔄 Last Poll: {bot_status["last_poll"].strftime("%Y-%m-%d %H:%M:%S") if bot_status["last_poll"] else "Never"}
📨 Last Reset Request: {last_reset}
🔐 Last Login Attempt: {last_login}

📈 Password Reset Stats:
• Total Requests: {bot_status["total_requests"]}
• Successful: {bot_status["successful_requests"]}
• Failed: {bot_status["failed_requests"]}
• Success Rate: {bot_status["successful_requests"]/bot_status["total_requests"]*100 if bot_status["total_requests"] > 0 else 0:.1f}%

🔓 Login Stats:
• Total Attempts: {bot_status["login_attempts"]}
• Successful: {bot_status["successful_logins"]}
• Failed: {bot_status["failed_logins"]}
• Success Rate: {bot_status["successful_logins"]/bot_status["login_attempts"]*100 if bot_status["login_attempts"] > 0 else 0:.1f}%

🏓 Health Check: https://your-koyeb-app.koyeb.app/health
"""
    await update.message.reply_text(status_text)

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle incoming messages - treat them as usernames/emails for password reset"""
    user_input = update.message.text.strip()
    
    # Check if message is a command
    if user_input.startswith('/'):
        return
    
    # Update last request time
    bot_status["last_reset_request"] = datetime.now()
    bot_status["total_requests"] += 1
    
    # Send processing message
    processing_msg = await update.message.reply_text(
        f"🔄 Processing: {user_input}\n\nSending password reset request..."
    )
    
    # Send password reset request
    success, result = send_instagram_password_reset(user_input)
    
    # Update counters
    if success:
        bot_status["successful_requests"] += 1
    else:
        bot_status["failed_requests"] += 1
    
    # Format the result message
    if success:
        result_text = f"""
✅ Password Reset Sent!

Input: {user_input}
Result: {result}

The password reset link has been sent to the associated email address.
"""
    else:
        result_text = f"""
❌ Failed to Send Reset

Input: {user_input}
Error: {result}

Possible reasons:
• Invalid username/email
• Account doesn't exist
• Instagram API error

Try again with a different username/email.
"""
    
    # Send result
    await update.message.reply_text(result_text)
    
    # Delete processing message
    try:
        await processing_msg.delete()
    except:
        pass

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Log Errors caused by Updates."""
    logger.warning('Update "%s" caused error "%s"', update, context.error)

@app.route('/')
def home():
    """Home page with bot info"""
    return jsonify({
        "status": "running",
        "service": "Instagram Password Reset & Login Bot",
        "version": "2.0",
        "features": ["password_reset", "login_check"],
        "endpoints": {
            "/": "This page",
            "/health": "Health check endpoint",
            "/stats": "Bot statistics"
        }
    })

@app.route('/health')
def health_check():
    """Health check endpoint for uptime monitoring"""
    bot_status["last_poll"] = datetime.now()
    
    if bot_status["started"]:
        uptime_seconds = (datetime.now() - bot_status["started"]).total_seconds()
        return jsonify({
            "status": "healthy",
            "bot_running": True,
            "uptime_seconds": uptime_seconds,
            "last_poll": bot_status["last_poll"].isoformat(),
            "features_active": {
                "password_reset": True,
                "login_check": True
            },
            "timestamp": datetime.now().isoformat()
        }), 200
    else:
        return jsonify({
            "status": "starting",
            "bot_running": False,
            "timestamp": datetime.now().isoformat()
        }), 503

@app.route('/stats')
def stats():
    """Bot statistics endpoint"""
    return jsonify({
        "total_requests": bot_status["total_requests"],
        "successful_requests": bot_status["successful_requests"],
        "failed_requests": bot_status["failed_requests"],
        "login_attempts": bot_status["login_attempts"],
        "successful_logins": bot_status["successful_logins"],
        "failed_logins": bot_status["failed_logins"],
        "last_reset_request": bot_status["last_reset_request"].isoformat() if bot_status["last_reset_request"] else None,
        "last_login_attempt": bot_status["last_login_attempt"].isoformat() if bot_status["last_login_attempt"] else None,
        "started_at": bot_status["started"].isoformat() if bot_status["started"] else None,
        "last_poll": bot_status["last_poll"].isoformat() if bot_status["last_poll"] else None
    })

async def run_bot():
    """Run the Telegram bot"""
    # Create the Application
    application = Application.builder().token(TOKEN).build()

    # Create login conversation handler
    login_handler = ConversationHandler(
        entry_points=[CommandHandler('login', login_start)],
        states={
            USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, login_username)],
            PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, login_password)],
        },
        fallbacks=[CommandHandler('cancel', login_cancel)],
    )

    # Add command handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("status", status_command))
    application.add_handler(login_handler)
    
    # Add message handler - handle all text messages as username/email inputs
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    # Add error handler
    application.add_error_handler(error_handler)

    # Start the Bot
    print("🤖 Instagram Password Reset & Login Bot is starting...")
    print("📱 Send /start to begin")
    print(f"🏓 Health check: http://localhost:{PORT}/health")
    print("🔐 Login feature: /login")
    
    bot_status["started"] = datetime.now()
    
    # Start polling with more frequent updates to prevent sleep
    await application.initialize()
    await application.start()
    await application.updater.start_polling(
        poll_interval=1.0,  # More frequent polling
        timeout=10,
        drop_pending_updates=True,
        allowed_updates=Update.ALL_TYPES
    )

    # Keep the bot running
    await application.updater.idle()

def run_flask():
    """Run Flask web server"""
    app.run(host='0.0.0.0', port=PORT)

def main():
    """Start both Flask server and Telegram bot"""
    print("🚀 Starting Instagram Password Reset & Login Bot with 24/7 hosting...")
    
    # Start Flask in a separate thread
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    
    # Run Telegram bot in main thread
    asyncio.run(run_bot())

if __name__ == '__main__':
    main()

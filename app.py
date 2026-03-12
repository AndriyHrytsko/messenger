from gevent import monkey
# Патчимо всі блокувальні модулі (socket, threading тощо), але не торкаємось ssl,
# щоб запобігти рекурсії всередині urllib3/requests → Twilio :contentReference[oaicite:2]{index=2}:contentReference[oaicite:3]{index=3}
monkey.patch_all()

import os
import re
import random
import sqlite3
import smtplib
import time
import logging
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify
)
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from bleach import clean
from flask_talisman import Talisman


from database_functions import DatabaseManager
from twilio.rest import Client



load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "default_secret_key")

# ————— безпечні налаштування кукі —————
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax"
)
# ————— логування безпеки —————
logging.basicConfig(
    filename='security.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)


# ————— CORS —————
CORS(app, resources={r"/*": {"origins": "*"}})

# ————— WebSocket —————
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='gevent')

# Використання Flask-Talisman для HSTS та CSP
csp = {
    "default-src": ["'self'"],
    "script-src":  ["'self'", "https://cdnjs.cloudflare.com"],
    "style-src":   ["'self'", "https://fonts.googleapis.com", "'unsafe-inline'"],
    "font-src":    ["'self'", "https://fonts.gstatic.com"],
    "img-src":     ["'self'", "data:"],
    "connect-src": ["'self'", "ws://127.0.0.1:5050", "wss://127.0.0.1:5050"]
}
Talisman(
    app,
    content_security_policy=csp,
    content_security_policy_nonce_in=["script-src"],
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    session_cookie_secure=True,
    session_cookie_http_only=True,
    session_cookie_samesite="Lax"
)

# Дані Twilio з .env
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER")

db_manager = DatabaseManager()
online_users = set()

def send_sms(to, message):
    """ Відправка SMS через Twilio """
    print(f"[DEBUG] Phone raw = '{to}' (length={len(to) if to else 0})")
    if not to or not to.startswith("+"):
        print("Номер телефону не вказано або має невірний формат.")
        return False
    client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    try:
        msg = client.messages.create(
            body=message,
            from_=TWILIO_PHONE_NUMBER,
            to=to
        )
        print(f"✅ SMS sent: {msg.sid}")
        return True
    except Exception as e:
        print(f"Error sending SMS: {e}")
        return False

def send_email(recipient, subject, message):
    """ Надсилання листа (для відновлення пароля тощо) """
    sender_email = os.getenv("EMAIL_USER")
    sender_password = os.getenv("EMAIL_PASS")
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        msg = f"Subject: {subject}\n\n{message}"
        server.sendmail(sender_email, recipient, msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

@app.route('/')
def index():
    return redirect(url_for('login'))

@limiter.limit("5 per 15 minutes")
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = clean(request.form.get('username',''), strip=True)
        password = request.form.get('password','')
        user = db_manager.get_user_by_username(username)

        # якщо заблокований
        if user and user.get('lockout_until'):
            until = datetime.fromisoformat(user['lockout_until'])
            if datetime.utcnow() < until:
                logging.warning(f"Blocked login attempt for {username}")
                flash("Обліковий запис заблоковано. Спробуйте пізніше.", "danger")
                return redirect(url_for('login'))

        # перевірка пароля
        if not user or not check_password_hash(user['password'], password):
            logging.info(f"Failed login for {username}")
            if user:
                db_manager.increment_failed_logins(user['id'])
                if user.get('failed_logins',0) + 1 >= 5:
                    lock_until = datetime.utcnow() + timedelta(minutes=15)
                    db_manager.set_lockout(user['id'], lock_until.isoformat())
                    logging.warning(f"User {username} locked until {lock_until}")
            flash("Невірний логін або пароль.", "danger")
            return redirect(url_for('login'))

        # успішний логін
        db_manager.reset_failed_logins(user['id'])
        logging.info(f"Successful login for {username}")

        # 2FA-флоу
        if user.get('two_factor_enabled',0) == 1:
            session['pending_2fa'] = {'username':username,'user_id':user['id']}
            code = str(random.randint(100000,999999))
            session['2fa_code'] = code
            send_sms(user['phone'], f"Ваш код: {code}")
            return redirect(url_for('two_factor'))

        session['user'] = username
        session['user_id'] = user['id']
        return redirect(url_for('messenger'))

    return render_template('login.html')

@app.route('/two_factor', methods=['GET', 'POST'])
def two_factor():

    if 'pending_2fa' not in session or '2fa_code' not in session:
        flash("Двофакторна автентифікація не активована.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        code = clean(request.form.get('code', ''), strip=True)
        if code == session.get('2fa_code'):
            pending = session.pop('pending_2fa')
            session['user'] = pending['username']
            session['user_id'] = pending['user_id']
            session.pop('2fa_code')
            flash("Login successful!", "success")
            return redirect(url_for('messenger'))
        else:
            flash("Невірний код. Спробуйте ще раз.", "danger")
    return render_template('two_factor.html')

@app.route('/resend_two_factor', methods=['POST'])
def resend_two_factor():
    if 'pending_2fa' not in session:
        return jsonify({"error": "Session expired, please login again."}), 400
    username = session['pending_2fa']['username']
    user = db_manager.get_user_by_username(username)
    if not user:
        return jsonify({"error": "User not found."}), 400
    code = str(random.randint(100000, 999999))
    session['2fa_code'] = code
    if send_sms(user.get('phone'), f"Ваш код підтвердження: {code}"):
        return jsonify({"message": "Code resent successfully."}), 200
    else:
        return jsonify({"error": "Failed to resend code."}), 500

@socketio.on('join')
def handle_join(data):
    room = data.get('room')
    if room:
        join_room(room)
@app.route('/register', methods=['GET', 'POST'])
def register():
    """ Реєстрація користувача """
    if request.method == 'GET':
        return render_template('register.html')

    username = clean(request.form.get('username', ''), strip=True)
    email = clean(request.form.get('email', ''), strip=True)
    phone = clean(request.form.get('phone', ''), strip=True)
    password = clean(request.form.get('password', ''), strip=True)
    confirm_password = request.form.get('confirm_password', '').strip()

    if len(username) < 3:
        flash(("error", "Username must be at least 3 characters long."))
        return redirect(url_for('register'))
    if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
        flash(("error", "Invalid email format."))
        return redirect(url_for('register'))
    if not re.match(r'^\+?\d{7,15}$', phone):
        flash(("error", "Номер телефону має бути від 7 до 15 цифр, можна з + на початку."))
        return redirect(url_for('register'))
    if not re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).{8,}$', password):
        flash(("error", "Password must be at least 8 characters long and contain uppercase, lowercase, and a number."))
        return redirect(url_for('register'))
    if password != confirm_password:
        flash(("error", "Passwords do not match."))
        return redirect(url_for('register'))

    if db_manager.user_exists(username) or db_manager.user_exists(email) or db_manager.user_exists(phone):
        flash(("error", "User with this username, email, or phone already exists."))
        return redirect(url_for('register'))

    success, message = db_manager.register_user(username, email, phone, password)
    if success:
        flash(("success", "Registration successful! Please log in."))
        return redirect(url_for('login'))
    else:
        flash(("error", message))
        return redirect(url_for('register'))

@app.route('/messenger')
def messenger():
    """ Головна сторінка чату """
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('messenger.html', username=session['user'])

@app.route('/profile', methods=['GET'])
def profile():
    """ Сторінка профілю """
    if 'user' not in session:
        return redirect(url_for('login'))
    user_data = db_manager.get_user_by_username(session['user'])
    if not user_data:
        flash("User not found", "danger")
        return redirect(url_for('messenger'))
    return render_template('profile.html', user=user_data)

@app.route('/update_profile', methods=['POST'])
def update_profile():
    """ Оновлення профілю користувача """
    if 'user' not in session:
        return redirect(url_for('login'))
    username = clean(request.form.get('username', ''), strip=True)
    email = clean(request.form.get('email', ''), strip=True)
    phone = clean(request.form.get('phone', ''), strip=True)
    db_manager.update_user_profile(session['user'], username, email, phone)
    session['user'] = username
    flash("Profile updated successfully!", "success")
    return redirect(url_for('profile'))

# Маршрути для увімкнення / вимкнення 2FA

@app.route('/enable_two_factor', methods=['GET', 'POST'])
def enable_two_factor():
    """ Увімкнення 2FA. Відправляє SMS з кодом для підтвердження. """
    if 'user' not in session:
        return redirect(url_for('login'))
    user = db_manager.get_user_by_username(session['user'])
    if user.get('two_factor_enabled'):
        flash("Двофакторна автентифікація вже увімкнена.", "info")
        return redirect(url_for('disable_two_factor'))
    if request.method == 'POST':
        code = str(random.randint(100000, 999999))
        session['enable_2fa_code'] = code
        if not send_sms(user.get('phone'), f"Ваш код для увімкнення 2FA: {code}"):
            flash("Не вдалося відправити SMS. Перевірте номер телефону.", "danger")
            return redirect(url_for('profile'))
        return redirect(url_for('confirm_enable_two_factor'))
    return render_template('enable_two_factor.html')

@app.route('/confirm_enable_two_factor', methods=['GET', 'POST'])
def confirm_enable_two_factor():
    """ Підтвердження 2FA шляхом введення коду """
    if 'user' not in session or 'enable_2fa_code' not in session:
        flash("Двофакторна автентифікація не активована.", "danger")
        return redirect(url_for('profile'))
    if request.method == 'POST':
        code = clean(request.form.get('code', ''), strip=True)
        if code == session.get('enable_2fa_code'):
            db_manager.set_two_factor_enabled(session['user'], True)
            session.pop('enable_2fa_code')
            flash("Двофакторна автентифікація увімкнена!", "success")
            return redirect(url_for('profile'))
        else:
            flash("Невірний код. Спробуйте ще раз.", "danger")
    return render_template('confirm_enable_two_factor.html')

@app.route('/disable_two_factor', methods=['GET', 'POST'])
def disable_two_factor():
    """ Вимкнення 2FA """
    if 'user' not in session:
        return redirect(url_for('login'))
    user = db_manager.get_user_by_username(session['user'])
    if not user.get('two_factor_enabled'):
        flash("Двофакторна автентифікація вже вимкнена.", "info")
        return redirect(url_for('profile'))
    if request.method == 'POST':
        db_manager.set_two_factor_enabled(session['user'], False)
        flash("Двофакторна автентифікація вимкнена.", "success")
        return redirect(url_for('profile'))
    return render_template('disable_two_factor.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """ Відновлення пароля: надсилання коду на email """
    if request.method == 'POST':
        username = clean(request.form.get('username', ''), strip=True)
        email = clean(request.form.get('email', ''), strip=True)
        user = db_manager.get_user_by_username_and_email(username, email)
        if not user:
            flash("No user found with the provided credentials.", "error")
            return redirect(url_for('forgot_password'))
        verification_code = random.randint(100000, 999999)
        db_manager.store_verification_code(user['id'], verification_code)
        if send_email(email, "Password Reset Code", f"Your verification code is: {verification_code}"):
            flash("A verification code has been sent to your email.", "success")
            session['reset_user_id'] = user['id']
            return redirect(url_for('verify_code'))
        else:
            flash("Failed to send verification email. Try again later.", "error")
    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    """ Скидання пароля після введення вірного коду """
    if 'reset_user_id' not in session:
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        password = clean(request.form.get('password', ''), strip=True)
        confirm_password = clean(request.form.get('confirm_password', ''), strip=True)
        if not password or not confirm_password:
            flash("Both fields are required.", "error")
            return redirect(url_for('reset_password'))
        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for('reset_password'))
        db_manager.update_password(session['reset_user_id'], password)
        flash("Password reset successfully. You can now login.", "success")
        session.pop('reset_user_id', None)
        return redirect(url_for('login'))
    return render_template('reset_password.html')

@app.route('/verify_code', methods=['GET', 'POST'])
def verify_code():
    """ Форма введення коду для відновлення пароля """
    if 'reset_user_id' not in session:
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        code = clean(request.form.get('code', ''), strip=True)
        if db_manager.verify_code(session['reset_user_id'], code):
            return redirect(url_for('reset_password'))
        else:
            flash("Invalid or expired verification code.", "error")
    return render_template('verify_code.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))

# Нові маршрути для роботи з публічними ключами

import json

@app.route('/api/public_key', methods=['POST'])
def save_public_key():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json()
    pub = data.get("public_key")
    if not pub:
        return jsonify({"error": "Missing public key"}), 400

    # конвертуємо dict у JSON-рядок перед збереженням
    pub_json = json.dumps(pub)
    app.logger.info(f"[save_public_key] user_id={session['user_id']} pub={pub_json}")
    db_manager.set_public_key(session["user_id"], pub_json)
    return jsonify({"message": "Public key saved"}), 200

@app.route('/api/public_key/<username>', methods=['GET'])
def get_public_key(username):
    # 1) Отримуємо збережений JWK (рядок) з БД
    pub_json_str = db_manager.get_public_key(username)
    if not pub_json_str:
        return jsonify({"status": "error", "message": "Користувача не знайдено"}), 404

    # 2) Парсимо рядок у Python-об’єкт
    try:
        pub_jwk = json.loads(pub_json_str)
    except json.JSONDecodeError:
        return jsonify({"status": "error", "message": "Невірний формат ключа"}), 500

    # 3) Віддаємо клієнту як об’єкт у полі data.public_key
    return jsonify({
        "status": "ok",
        "data": {
            "public_key": pub_jwk
        }
    }), 200

# API-шляхи для чату

@app.route('/api/add_contact', methods=['POST'])
def api_add_contact():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json()
    contact_username = clean(data.get("username", ""), strip=True)
    if not contact_username:
        return jsonify({"error": "Invalid data"}), 400
    result = db_manager.add_contact(session["user_id"], contact_username)
    if result == "Contact successfully added":
        return jsonify({"message": result}), 200
    else:
        return jsonify({"error": result}), 400

@app.route('/api/contacts', methods=['GET'])
def api_get_contacts():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    contacts = db_manager.get_contacts(session['user'])
    return jsonify({'contacts': contacts})

@app.route("/api/messages")
def api_get_messages():
    if 'user_id' not in session:
        return jsonify(error="Unauthorized"), 401

    contact = clean(request.args.get('contact',''), strip=True)
    user_id = session['user_id']
    contact_id = db_manager.get_user_id(contact)
    if not db_manager.is_contact(user_id, contact_id):
        return jsonify(error="Forbidden"), 403

    history = db_manager.get_chat_history(session['user'], contact)
    return jsonify(messages=history)



@app.route('/api/mark_as_read', methods=['POST'])
def api_mark_as_read():
    data = request.json
    sender = data.get("sender")
    receiver = session.get("user")
    if not sender or not receiver:
        return jsonify({"error": "Missing sender or receiver"}), 400
    db_manager.mark_messages_as_read(sender, receiver)
    return jsonify({"success": True})

@app.route("/api/send_message", methods=["POST"])
@limiter.limit("30 per minute")
def api_send_message():
    if 'user_id' not in session:
        return jsonify(error="Unauthorized"), 401

    data = request.get_json()
    receiver = clean(data.get('receiver', ''), strip=True)
    if not receiver:
        return jsonify(error="Receiver required"), 400

    sender = session['user']
    sender_id = session['user_id']
    receiver_id = db_manager.get_user_id(receiver)
    if not receiver_id:
        return jsonify(error="Receiver not found"), 404

    # Підготовка полів для тексту
    content_for_sender = data['content_for_sender']
    iv_for_sender = data['iv_for_sender']
    content_for_receiver = data['content_for_receiver']
    iv_for_receiver = data['iv_for_receiver']

    # Нові поля для медіа (або None)
    media_type = data.get('media_type')
    media_content_for_sender = data.get('media_content_for_sender')
    iv_media_for_sender = data.get('iv_media_for_sender')
    media_content_for_receiver = data.get('media_content_for_receiver')
    iv_media_for_receiver = data.get('iv_media_for_receiver')
    reply_to = data.get('reply_to')

    # Збереження в БД
    db_manager.send_message(
        sender=sender,
        receiver=receiver,
        content_for_sender=content_for_sender,
        iv_for_sender=iv_for_sender,
        content_for_receiver=content_for_receiver,
        iv_for_receiver=iv_for_receiver,
        media_type=media_type,
        media_content_for_sender=media_content_for_sender,
        iv_media_for_sender=iv_media_for_sender,
        media_content_for_receiver=media_content_for_receiver,
        iv_media_for_receiver=iv_media_for_receiver,
        reply_to=reply_to
    )

    # Реальна-тайм емісія через SocketIO
    room = "_".join(sorted([sender, receiver]))
    socketio.emit('new_message', {
        'sender': sender,
        'receiver': receiver,
        'content': content_for_receiver,
        'iv': iv_for_receiver,
        'media_type': media_type,
        'media_content': media_content_for_receiver,
        'iv_media': iv_media_for_receiver,
        'reply_to': reply_to,
        'timestamp': datetime.utcnow().isoformat()
    }, room=room)

    return jsonify(status="ok"), 200



@socketio.on('connect')
def handle_connect():
    if 'user' in session:
        username = session['user']
        online_users.add(username)
        emit('user_online', {'username': username}, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if 'user' in session:
        username = session['user']
        if username in online_users:
            online_users.remove(username)
            emit('user_offline', {'username': username}, broadcast=True)

if __name__ == '__main__':
    url = "https://127.0.0.1:5050"
    print(f"\n🚀  Your secure chat is running at {url}/\n")
    # запускаємо через SocketIO з перезавантажувачем
    socketio.run(
        app,
        host="0.0.0.0",
        port=5050,
        debug=True,
        certfile="127.0.0.1+1.pem",
        keyfile="127.0.0.1+1-key.pem"
    )



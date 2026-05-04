from gevent import monkey
monkey.patch_all()

import re
import secrets
import smtplib
import logging
from datetime import datetime, timedelta
import hashlib
from flask_wtf.csrf import CSRFProtect
from email.mime.text import MIMEText

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify
)
from flask_socketio import SocketIO, emit, join_room
from werkzeug.security import check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from bleach import clean
from flask_talisman import Talisman


from database_functions import DatabaseManager
from twilio.rest import Client

import hvac



vault_client = hvac.Client(url='http://127.0.0.1:8200', token='hvs.wjjbuQWdG4tBAszWiJP2xbRu')

vault_secrets = vault_client.secrets.kv.v2.read_secret_version(path='messenger')['data']['data']

app = Flask(__name__)

secret_key = vault_secrets.get("SECRET_KEY")
if not secret_key:
    raise ValueError("КРИТИЧНА ПОМИЛКА: SECRET_KEY не знайдено у Vault!")
app.secret_key = secret_key

TWILIO_ACCOUNT_SID = vault_secrets.get("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = vault_secrets.get("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = vault_secrets.get("TWILIO_PHONE_NUMBER")

csrf = CSRFProtect(app)
# ————— безпечні налаштування кукі —————
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=10 * 1024 * 1024
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


# ————— WebSocket —————
ALLOWED_ORIGINS = [
    "https://127.0.0.1:5050",
    "https://localhost:5050"
]
socketio = SocketIO(app, cors_allowed_origins=ALLOWED_ORIGINS, async_mode='gevent')

# Використання Flask-Talisman для HSTS та CSP
csp = {
    "default-src": ["'self'"],
    "script-src":  ["'self'", "https://cdnjs.cloudflare.com", "https://cdn.tailwindcss.com"],
    "style-src":   ["'self'", "https://fonts.googleapis.com", "'unsafe-inline'"],
    "font-src":    ["'self'", "https://fonts.gstatic.com"],
    "img-src":     ["'self'", "data:", "blob:"],
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


db_manager = DatabaseManager()
online_users = set()


@app.before_request
def check_valid_session():
    """Перевіряє, чи не була сесія інвалідована (наприклад, через зміну пароля)"""
    if request.endpoint and 'static' in request.endpoint:
        return

    if 'user_id' in session:
        db_token = db_manager.get_session_token(session['user_id'])
        session_token = session.get('session_token')

        if db_token and session_token:
            # Хешуємо токен з браузера, щоб порівняти з тим, що лежить у базі
            hashed_cookie_token = hashlib.sha256(session_token.encode()).hexdigest()
            if hashed_cookie_token != db_token:
                session.clear()
                flash("Ваша сесія закінчилася або пароль було змінено. Увійдіть знову.", "danger")
                return redirect(url_for('login'))
        elif db_token and not session_token:
            # Якщо в базі токен є, а в браузері чомусь немає
            session.clear()
            return redirect(url_for('login'))


def send_sms(to, message):

    if not to or not to.startswith("+"):
        print("Номер телефону не вказано або має невірний формат.")
        return False

    try:
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        msg = client.messages.create(
            body=message,
            from_=TWILIO_PHONE_NUMBER,
            to=to
        )
        return True
    except Exception as e:
        print(f"⚠️ Помилка Twilio (але Dev Mode пускає далі): {e}")
        return True  # Робимо вигляд, що все ОК, щоб можна було тестувати 2FA локально


def send_email(recipient, subject, message):

    sender_email = vault_secrets.get("EMAIL_USER")
    sender_password = vault_secrets.get("EMAIL_PASS")

    try:
        # Загортаємо лист у UTF-8 формат
        msg = MIMEText(message, 'plain', 'utf-8')
        msg['Subject'] = subject
        msg['From'] = sender_email
        msg['To'] = recipient

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)  # Відправляємо правильний MIME-об'єкт
        server.quit()
        return True
    except Exception as e:
        print(f"⚠️ Помилка SMTP (але Dev Mode пускає далі): {e}")
        return True  # Dev Mode

@app.route('/')
def index():
    return redirect(url_for('login'))


@limiter.limit("5 per 15 minutes")
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Те, що ввів юзер (може бути нік, пошта або телефон)
        input_identifier = clean(request.form.get('username', ''), strip=True).replace('\n', '').replace('\r', '')
        password = request.form.get('password', '')

        user = db_manager.get_user_for_login(input_identifier)

        # якщо заблокований
        if user and user.get('lockout_until'):
            until = datetime.fromisoformat(user['lockout_until'])
            if datetime.utcnow() < until:
                logging.warning(f"Blocked login attempt for {input_identifier}")
                flash("Обліковий запис заблоковано. Спробуйте пізніше.", "danger")
                return redirect(url_for('login'))

        # перевірка пароля
        if not user or not check_password_hash(user['password'], password):
            logging.info(f"Failed login for {input_identifier}")
            if user:
                db_manager.increment_failed_logins(user['id'])
                if user.get('failed_logins', 0) + 1 >= 5:
                    lock_until = datetime.utcnow() + timedelta(minutes=15)
                    db_manager.set_lockout(user['id'], lock_until.isoformat())
                    logging.warning(f"User {input_identifier} locked until {lock_until}")
            flash("❌ Невірне ім'я користувача, Email, телефон або пароль.", "danger")
            return redirect(url_for('login'))

        # успішний логін
        db_manager.reset_failed_logins(user['id'])
        logging.info(f"Successful login for {user['username']}")

        # 2FA-флоу
        if user.get('two_factor_enabled', 0) == 1:
            session['pending_2fa'] = {'username': user['username'], 'user_id': user['id']}
            code = str(secrets.SystemRandom().randint(100000, 999999))
            session['2fa_code'] = code
            send_sms(user['phone'], f"Ваш код: {code}")
            return redirect(url_for('two_factor'))

        # ВАЖЛИВО: Зберігаємо справжній нікнейм з БД, а не те, що ввів юзер!
        session['user'] = user['username']
        session['user_id'] = user['id']

        # Завжди генеруємо нову сесію при вході
        token = db_manager.rotate_session_token(user['id'])
        session['session_token'] = token

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
            # Завжди генеруємо нову сесію
            token = db_manager.rotate_session_token(pending['user_id'])
            session['session_token'] = token
            session.pop('2fa_code')
            flash("Login successful!", "success")
            return redirect(url_for('messenger'))
        else:
            flash("Невірний код. Спробуйте ще раз.", "danger")
    return render_template('two_factor.html')

@app.route('/resend_two_factor', methods=['POST'])
@limiter.limit("3 per hour")
def resend_two_factor():
    if 'pending_2fa' not in session:
        return jsonify({"error": "Session expired, please login again."}), 400
    username = session['pending_2fa']['username']
    user = db_manager.get_user_by_username(username)
    if not user:
        return jsonify({"error": "User not found."}), 400
    code = str(secrets.SystemRandom().randint(100000, 999999))
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
@socketio.on('join_group')
def handle_join_group(data):
    """Дозволяє користувачу підключитися до кімнати групи для Real-Time повідомлень"""
    if 'user' in session:
        group_id = data.get('group_id')
        # Перевіряємо, чи має юзер доступ до цієї групи
        if db_manager.get_group_key(group_id, session['user']):
            join_room(f"group_{group_id}")

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
        flash("Username must be at least 3 characters long.", "danger")
        return redirect(url_for('register'))
    if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
        flash("Invalid email format.", "danger")
        return redirect(url_for('register'))
    if not re.match(r'^\+?\d{7,15}$', phone):
        flash("Номер телефону має бути від 7 до 15 цифр, можна з + на початку.", "danger")
        return redirect(url_for('register'))
    if not re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).{8,}$', password):
        flash("Password must be at least 8 characters long and contain uppercase, lowercase, and a number.", "danger")
        return redirect(url_for('register'))
    if password != confirm_password:
        flash("Passwords do not match.", "danger")
        return redirect(url_for('register'))

    if db_manager.user_exists(username) or db_manager.user_exists(email) or db_manager.user_exists(phone):
        flash("User with this username, email, or phone already exists.", "danger")
        return redirect(url_for('register'))

    success, message = db_manager.register_user(username, email, phone, password)
    if success:
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))
    else:
        flash(message, "danger")
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
@limiter.limit("3 per hour")
def enable_two_factor():
    """ Увімкнення 2FA. Відправляє SMS з кодом для підтвердження. """
    if 'user' not in session:
        return redirect(url_for('login'))
    user = db_manager.get_user_by_username(session['user'])
    if user.get('two_factor_enabled'):
        flash("Двофакторна автентифікація вже увімкнена.", "info")
        return redirect(url_for('disable_two_factor'))
    if request.method == 'POST':
        code = str(secrets.SystemRandom().randint(100000, 999999))
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
@limiter.limit("3 per hour")
def forgot_password():
    """ Відновлення пароля: надсилання коду на email """
    if request.method == 'POST':
        username = clean(request.form.get('username', ''), strip=True)
        email = clean(request.form.get('email', ''), strip=True)

        user = db_manager.get_user_by_username_and_email(username, email)

        # 1. Встановлюємо універсальний прапорець для всіх запитів
        session['reset_initiated'] = True

        if user:
            verification_code = secrets.SystemRandom().randint(100000, 999999)
            db_manager.store_verification_code(user['id'], verification_code)

            # УКРАЇНСЬКИЙ текст листа
            send_email(email, "Відновлення пароля", f"Ваш код підтвердження: {verification_code}")

            # 2. Зберігаємо ID тільки якщо користувач існує
            session['reset_user_id'] = user['id']

        # УКРАЇНСЬКИЙ текст повідомлення на сайті (категорія success зробить його красивим зеленим/синім)
        flash("Якщо акаунт із такими даними існує, код підтвердження було надіслано на email.", "success")
        return redirect(url_for('verify_code'))

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
            flash("Всі поля обов'язкові.", "danger")
            return redirect(url_for('reset_password'))

        if password != confirm_password:
            flash("Паролі не співпадають.", "danger")
            return redirect(url_for('reset_password'))

        # ДОДАНО: Перевірка складності пароля (як при реєстрації)
        if not re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).{8,}$', password):
            flash("Пароль має містити щонайменше 8 символів, велику і малу літери та цифру.", "danger")
            return redirect(url_for('reset_password'))

        # ДОДАНО: Перевірка, чи пароль не є старим
        success, msg = db_manager.update_password(session['reset_user_id'], password)
        if not success:
            flash(msg, "danger")
            return redirect(url_for('reset_password'))

        db_manager.rotate_session_token(session['reset_user_id'])
        flash("Пароль успішно скинуто. Тепер ви можете увійти.", "success")
        session.pop('reset_user_id', None)
        return redirect(url_for('login'))

    return render_template('reset_password.html')


@app.route('/verify_code', methods=['GET', 'POST'])
def verify_code():
    """ Форма введення коду для відновлення пароля """
    # 1. Перевіряємо загальний прапорець замість reset_user_id
    if 'reset_initiated' not in session:
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        code = clean(request.form.get('code', ''), strip=True)

        # 2. Отримуємо ID користувача (може бути None, якщо email був фейковим)
        user_id = session.get('reset_user_id')

        # 3. Перевіряємо код тільки якщо user_id існує
        if user_id and db_manager.verify_code(user_id, code):
            return redirect(url_for('reset_password'))
        else:
            flash("Invalid or expired verification code.", "danger")

    return render_template('verify_code.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))

# Нові маршрути для Multi-Device ключів
import json


@app.route('/api/public_key', methods=['POST'])
def save_public_key():
    if 'user_id' not in session or 'session_token' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400

    pub = data.get("public_key")
    if not pub or not isinstance(pub, dict):
        return jsonify({"error": "Missing or invalid public key format"}), 400

    pub_json = json.dumps(pub)
    if len(pub_json) > 2048:
        return jsonify({"error": "Payload Too Large"}), 413

    # ДОДАНО: Зберігаємо ключ, прив'язаний до конкретної сесії!
    # Хешуємо токен браузера, бо в базі він лежить у вигляді хешу (захист сесій)
    session_hash = hashlib.sha256(session['session_token'].encode()).hexdigest()

    db_manager.set_device_public_key(session["user_id"], session_hash, pub_json)
    return jsonify({"message": "Device public key saved"}), 200


@app.route('/api/public_key/<username>', methods=['GET'])
def get_public_key(username):
    # ДОДАНО: Тепер ми дістаємо МАСИВ ключів (з усіх пристроїв юзера)
    keys_json_list = db_manager.get_user_device_keys(username)

    if not keys_json_list:
        return jsonify({"status": "error", "message": "Користувача або ключів не знайдено"}), 404

    parsed_keys = []
    for pub_str in keys_json_list:
        try:
            parsed_keys.append(json.loads(pub_str))
        except json.JSONDecodeError:
            continue

    # Віддаємо клієнту масив публічних ключів
    return jsonify({
        "status": "ok",
        "data": {
            "public_keys": parsed_keys
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

    if contact_username.lower() == session['user'].lower():
        return jsonify({"error": "Ви не можете додати самого себе"}), 400

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

    contact = clean(request.args.get('contact', ''), strip=True)

    # Отримуємо параметри пагінації з безпечними дефолтними значеннями
    try:
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))
    except ValueError:
        limit = 50
        offset = 0

    user_id = session['user_id']
    contact_id = db_manager.get_user_id(contact)
    if not db_manager.is_contact(user_id, contact_id):
        return jsonify(error="Forbidden"), 403

    history = db_manager.get_chat_history(session['user'], contact, limit, offset)
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
    }, room=receiver)

    return jsonify(status="ok"), 200


@app.route('/api/user/<username>/info', methods=['GET'])
def api_get_user_info(username):
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    info = db_manager.get_user_public_info(username)
    if info:
        return jsonify(info), 200
    return jsonify({"error": "User not found"}), 404


@app.route('/api/groups/<int:group_id>/members', methods=['GET'])
def api_get_group_members(group_id):
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    # Перевіряємо, чи має юзер доступ до групи
    if not db_manager.get_group_key(group_id, session['user']):
        return jsonify({"error": "Forbidden"}), 403

    members = db_manager.get_group_members_list(group_id)
    return jsonify({"members": members}), 200

# ==========================================
# === API ДЛЯ ГРУПОВИХ ЧАТІВ ===============
# ==========================================

@app.route('/api/groups/create', methods=['POST'])
def api_create_group():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    group_name = clean(data.get('name', ''), strip=True)
    members_data = data.get('members', [])  # Формат: [{'username': '...', 'encrypted_key': '...'}, ...]

    if not group_name or not members_data:
        return jsonify({"error": "Invalid data"}), 400

    # Додаємо самого творця в список учасників групи
    success, result = db_manager.create_group(group_name, session['user'], members_data)
    if success:
        return jsonify({"message": "Group created", "group_id": result}), 200
    else:
        return jsonify({"error": result}), 400


@app.route('/api/groups', methods=['GET'])
def api_get_groups():
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    groups = db_manager.get_user_groups(session['user'])
    return jsonify({"groups": groups}), 200


@app.route('/api/groups/<int:group_id>/key', methods=['GET'])
def api_get_group_key(group_id):
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    enc_key = db_manager.get_group_key(group_id, session['user'])
    if enc_key:
        return jsonify({"encrypted_key": enc_key}), 200
    return jsonify({"error": "Key not found or access denied"}), 404


@app.route('/api/groups/messages', methods=['GET'])
def api_get_group_messages():
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        group_id = int(request.args.get('group_id', 0))
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))
    except ValueError:
        return jsonify({"error": "Invalid parameters"}), 400

    # Перевірка доступу (чи є юзер в цій групі)
    if not db_manager.get_group_key(group_id, session['user']):
        return jsonify({"error": "Forbidden"}), 403

    messages = db_manager.get_group_messages(group_id, limit, offset)
    return jsonify({"messages": messages}), 200


@app.route('/api/groups/send', methods=['POST'])
@limiter.limit("30 per minute")
def api_send_group_message():
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    group_id = data.get('group_id')
    content = data.get('content')
    iv = data.get('iv')

    if not group_id or not content or not iv:
        return jsonify({"error": "Invalid data"}), 400

    # Перевірка доступу
    if not db_manager.get_group_key(group_id, session['user']):
        return jsonify({"error": "Forbidden"}), 403

    db_manager.save_group_message(
        group_id=group_id,
        sender_username=session['user'],
        content=content,
        iv=iv,
        media_type=data.get('media_type'),
        media_content=data.get('media_content'),
        iv_media=data.get('iv_media')
    )

    # Розсилка повідомлення через Socket.IO в спеціальну "кімнату групи"
    room_name = f"group_{group_id}"
    socketio.emit('new_group_message', {
        'group_id': group_id,
        'sender': session['user'],
        'content': content,
        'iv': iv,
        'media_type': data.get('media_type'),
        'media_content': data.get('media_content'),
        'iv_media': data.get('iv_media'),
        'timestamp': datetime.utcnow().isoformat()
    }, room=room_name)

    return jsonify({"status": "ok"}), 200

@socketio.on('connect')
def handle_connect():
    if 'user' in session:
        username = session['user']
        join_room(username)
        online_users.add(username)
        emit('user_online', {'username': username}, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if 'user' in session:
        username = session['user']
        if username in online_users:
            online_users.remove(username)
            emit('user_offline', {'username': username}, broadcast=True)


# Маршрути для видалення
@app.route('/api/remove_contact', methods=['POST'])
def api_remove_contact():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    contact_username = clean(data.get("username", ""), strip=True)

    success, msg = db_manager.remove_contact(session['user_id'], contact_username)
    if success:
        return jsonify({"message": msg}), 200
    return jsonify({"error": msg}), 400


@app.route('/api/groups/leave', methods=['POST'])
def api_leave_group():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    group_id = data.get('group_id')

    success, msg = db_manager.leave_group(session['user_id'], group_id)
    if success:
        return jsonify({"message": msg}), 200
    return jsonify({"error": msg}), 400

if __name__ == '__main__':
    url = "https://127.0.0.1:5050"
    print(f"\n🚀  Your secure chat is running at {url}/\n")
    # запускаємо через SocketIO з перезавантажувачем
    socketio.run(
        app,
        host="0.0.0.0",
        port=5050,
        debug=False,
        certfile="127.0.0.1+1.pem",
        keyfile="127.0.0.1+1-key.pem"
    )



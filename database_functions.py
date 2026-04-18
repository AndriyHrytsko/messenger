import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import time
import os
from cryptography.fernet import Fernet
import hashlib
import hmac
class DatabaseManager:
    def __init__(self, db_path="messenger.db"):
        self.db_path = db_path

        # Ініціалізація шифрування
        pii_key = os.getenv("PII_KEY")
        if not pii_key:
            raise ValueError("PII_KEY не знайдено в .env!")
        self.cipher = Fernet(pii_key)
        self.secret_salt = os.getenv("SECRET_KEY", "fallback_salt").encode()

    # --- УТИЛІТИ ДЛЯ PII ---
    def encrypt_pii(self, data):
        """Шифрує дані для зберігання в БД"""
        if not data: return None
        return self.cipher.encrypt(data.encode()).decode()

    def decrypt_pii(self, token):
        """Розшифровує дані для відображення юзеру"""
        if not token: return None
        try:
            return self.cipher.decrypt(token.encode()).decode()
        except Exception:
            return token  # Fallback для старих незашифрованих даних

    def hash_pii(self, data):
        """Створює незворотний HMAC-хеш для пошуку в БД"""
        if not data: return None
        return hmac.new(self.secret_salt, data.lower().strip().encode(), hashlib.sha256).hexdigest()


    def clear_messages(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM messages")
            conn.commit()

    def connect(self):
        return sqlite3.connect(self.db_path)

    def get_username(self, user_id):
        with self.connect() as conn:
            cursor = conn.cursor()
            result = cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
            return result[0] if result else None

    def register_user(self, username, email, phone, password):
        hashed_password = generate_password_hash(password)

        # Шифруємо та хешуємо
        enc_email = self.encrypt_pii(email)
        enc_phone = self.encrypt_pii(phone)
        hash_email = self.hash_pii(email)
        hash_phone = self.hash_pii(phone)

        try:
            with self.connect() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO users (username, email, phone, password, email_hash, phone_hash)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (username, enc_email, enc_phone, hashed_password, hash_email, hash_phone))
                conn.commit()
                return True, "User registered successfully."
        except sqlite3.IntegrityError:
            return False, "User already exists."

    def increment_failed_logins(self, user_id):
        with self.connect() as conn:
            conn.execute(
                "UPDATE users SET failed_logins = failed_logins + 1 WHERE id = ?",
                (user_id,)
            )
            conn.commit()

    def reset_failed_logins(self, user_id):
        with self.connect() as conn:
            conn.execute(
                "UPDATE users SET failed_logins = 0, lockout_until = NULL WHERE id = ?",
                (user_id,)
            )
            conn.commit()

    def set_lockout(self, user_id, until_dt):
        with self.connect() as conn:
            conn.execute(
                "UPDATE users SET lockout_until = ? WHERE id = ?",
                (until_dt, user_id)
            )
            conn.commit()

    def is_contact(self, user_id, contact_id):
        with self.connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT 1 FROM contacts WHERE user_id=? AND contact_id=?",
                (user_id, contact_id)
            )
            return cur.fetchone() is not None

    def mark_messages_as_read(self, sender_username, receiver_username):
        sender_id = self.get_user_id(sender_username)
        receiver_id = self.get_user_id(receiver_username)
        if sender_id is None or receiver_id is None:
            return
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE messages 
                SET status = 'read'
                WHERE sender_id = ? AND receiver_id = ? AND status != 'read'
            """, (sender_id, receiver_id))
            conn.commit()

    def get_user_by_username(self, username):
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, password, phone, two_factor_enabled, public_key FROM users WHERE username = ?",
                (username,)
            )
            user = cursor.fetchone()
            if user:
                return {
                    "id": user[0],
                    "username": user[1],
                    "password": user[2],
                    "phone": self.decrypt_pii(user[3]),  # ⬅️ Розшифровуємо телефон
                    "two_factor_enabled": user[4],
                    "public_key": user[5]
                }
            return None

    def get_user_by_username_and_email(self, username, email):
        email_hash = self.hash_pii(email)
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, email FROM users WHERE username = ? AND email_hash = ?",
                           (username, email_hash))
            user = cursor.fetchone()
            if user:
                return {"id": user[0], "username": user[1], "email": self.decrypt_pii(user[2])}
            return None

    def set_two_factor_enabled(self, username, enabled):
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET two_factor_enabled = ? WHERE username = ?",
                           (1 if enabled else 0, username))
            conn.commit()

    def user_exists(self, username_or_email_or_phone):
        # Робимо хеш припущення, що користувач ввів email або телефон
        pii_hash = self.hash_pii(username_or_email_or_phone)

        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id FROM users
                WHERE username = ? OR email_hash = ? OR phone_hash = ?
            ''', (username_or_email_or_phone, pii_hash, pii_hash))
            return cursor.fetchone() is not None

    def get_all_users(self, exclude_user):
        user_id = self.get_user_id(exclude_user)
        if user_id is None:
            return []
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT u.username FROM contacts
                JOIN users u ON contacts.contact_id = u.id
                WHERE contacts.user_id = ?
            ''', (user_id,))
            return [{'username': row[0]} for row in cursor.fetchall()]

    def get_chat_history(self, user1, user2, limit=50, offset=0):
        """
        Повертає список повідомлень між user1 та user2,
        з використанням пагінації (limit та offset).
        """
        u1 = self.get_user_id(user1)
        u2 = self.get_user_id(user2)
        if u1 is None or u2 is None:
            return []

        with self.connect() as conn:
            c = conn.cursor()
            # Зверни увагу на ORDER BY m.timestamp DESC LIMIT ? OFFSET ?
            c.execute("""
                SELECT 
                  m.id, m.sender_id, m.receiver_id,
                  m.content_for_sender, m.iv_for_sender,
                  m.content_for_receiver, m.iv_for_receiver,
                  m.media_type, m.media_content_for_sender, m.iv_media_for_sender,
                  m.media_content_for_receiver, m.iv_media_for_receiver,
                  m.reply_to, m.status, m.timestamp,
                  u1.username AS sender_username, u2.username AS receiver_username
                FROM messages m
                JOIN users u1 ON m.sender_id   = u1.id
                JOIN users u2 ON m.receiver_id = u2.id
                WHERE (m.sender_id   = ? AND m.receiver_id   = ?)
                   OR (m.sender_id   = ? AND m.receiver_id   = ?)
                ORDER BY m.timestamp DESC
                LIMIT ? OFFSET ?
            """, (u1, u2, u2, u1, limit, offset))
            rows = c.fetchall()

        messages = []
        for row in rows:
            messages.append({
                "id": row[0],
                "sender_id": row[1],
                "receiver_id": row[2],
                "content_for_sender": row[3],
                "iv_for_sender": row[4],
                "content_for_receiver": row[5],
                "iv_for_receiver": row[6],
                "media_type": row[7],
                "media_content_for_sender": row[8],
                "iv_media_for_sender": row[9],
                "media_content_for_receiver": row[10],
                "iv_media_for_receiver": row[11],
                "reply_to": row[12],
                "status": row[13],
                "timestamp": row[14],
                "sender_username": row[15],
                "receiver_username": row[16],
            })

        # Перевертаємо, щоб старіші повідомлення були зверху (як звикли користувачі)
        messages.reverse()
        return messages

    def send_message(self, sender, receiver,
                     content_for_sender, iv_for_sender,
                     content_for_receiver, iv_for_receiver,
                     media_type=None,
                     media_content_for_sender=None, iv_media_for_sender=None,
                     media_content_for_receiver=None, iv_media_for_receiver=None,
                     reply_to=None):
        sid = self.get_user_id(sender)
        rid = self.get_user_id(receiver)
        if sid is None or rid is None:
            return "User not found"

        with self.connect() as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO messages (
                    sender_id, receiver_id,
                    content_for_sender, iv_for_sender,
                    content_for_receiver, iv_for_receiver,
                    media_type,
                    media_content_for_sender, iv_media_for_sender,
                    media_content_for_receiver, iv_media_for_receiver,
                    reply_to,
                    status, timestamp
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'sent', datetime('now'))
            """, (
                sid, rid,
                content_for_sender, iv_for_sender,
                content_for_receiver, iv_for_receiver,
                media_type,
                media_content_for_sender, iv_media_for_sender,
                media_content_for_receiver, iv_media_for_receiver,
                reply_to
            ))
            conn.commit()
        return "OK"

    def get_user_id(self, username):
        # Видаляємо зайві пробіли та використовуємо нечутливе до регістру порівняння
        username = username.strip()
        with self.connect() as conn:
            cursor = conn.cursor()
            result = cursor.execute(
                "SELECT id FROM users WHERE TRIM(username) = TRIM(?) COLLATE NOCASE",
                (username,)
            ).fetchone()
            print(f"🔍 get_user_id('{username}') -> {result}")
            return result[0] if result else None

    def add_contact(self, user_id, contact_username):
        contact_username = contact_username.strip()  # Видаляємо зайві пробіли
        contact_id = self.get_user_id(contact_username)
        print(
            f"🧐 Перевіряємо користувача: user_id={user_id}, contact_username={contact_username}, contact_id={contact_id}")
        if user_id is None:
            print("❌ User does not exist")
            return "User does not exist"
        if contact_id is None:
            print("❌ Contact user does not exist")
            return "Contact user does not exist"
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM contacts WHERE user_id = ? AND contact_id = ?", (user_id, contact_id))
            existing_contact = cursor.fetchone()
            print("🔍 Існуючий контакт у БД:", existing_contact)
            if existing_contact:
                print("⚠️ Contact already exists")
                return "Contact already exists"

            print(f"✅ Додаємо контакт: user_id={user_id}, contact_id={contact_id}")
            # 1. Додаємо Олега до твого списку (без помилок, якщо він вже є)
            cursor.execute("INSERT OR IGNORE INTO contacts (user_id, contact_id) VALUES (?, ?)", (user_id, contact_id))
            # 2. Додаємо тебе до списку Олега (взаємно)
            cursor.execute("INSERT OR IGNORE INTO contacts (user_id, contact_id) VALUES (?, ?)", (contact_id, user_id))
            conn.commit()
            print("✅ Contact успішно додано (взаємно)")
            return "Contact successfully added"

    def get_user_data(self, username):
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username, email, phone FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            if user:
                # ⬅️ Розшифровуємо email та телефон перед тим, як повернути
                return (user[0], self.decrypt_pii(user[1]), self.decrypt_pii(user[2]))
            return None

    def update_user_profile(self, current_username, new_username, email, phone):
        enc_email = self.encrypt_pii(email)
        enc_phone = self.encrypt_pii(phone)
        hash_email = self.hash_pii(email)
        hash_phone = self.hash_pii(phone)

        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users 
                SET username = ?, email = ?, phone = ?, email_hash = ?, phone_hash = ?
                WHERE username = ?
            """, (new_username, enc_email, enc_phone, hash_email, hash_phone, current_username))
            conn.commit()

    def get_contacts(self, username):
        user_id = self.get_user_id(username)
        if user_id is None:
            print("Користувач не знайдений у базі")
            return []
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT u.username FROM contacts
                JOIN users u ON contacts.contact_id = u.id
                WHERE contacts.user_id = ?
            """, (user_id,))
            contacts = cursor.fetchall()
        print(f"📋 Контакти для {username}: {[c[0] for c in contacts]}")
        return [contact[0] for contact in contacts]

    def store_verification_code(self, user_id, code):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        timestamp = int(time.time())

        # ХЕШУЄМО КОД (зберігаємо його в такому ж нечитабельному вигляді, як і паролі)
        hashed_code = generate_password_hash(str(code))

        cursor.execute("INSERT INTO verification_codes (user_id, code, created_at) VALUES (?, ?, ?)",
                       (user_id, hashed_code, timestamp))
        conn.commit()
        conn.close()

    def verify_code(self, user_id, code):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        time_threshold = int(time.time()) - (15 * 60)

        cursor.execute(
            """
            SELECT id, code FROM verification_codes
            WHERE user_id = ? AND used = 0 AND created_at >= ?
            ORDER BY created_at DESC
            """,
            (user_id, time_threshold)
        )
        rows = cursor.fetchall()

        # Перевіряємо кожен знайдений хеш
        for row in rows:
            code_id = row[0]
            hashed_code = row[1]

            # ПОРІВНЮЄМО ХЕШ з введеним кодом
            if check_password_hash(hashed_code, str(code)):
                cursor.execute(
                    "UPDATE verification_codes SET used = 1 WHERE id = ?",
                    (code_id,)
                )
                conn.commit()
                conn.close()
                return True

        conn.close()
        return False

    def update_password(self, user_id, new_password):
        hashed_password = generate_password_hash(new_password)
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, user_id))
            conn.commit()

    def get_user_by_id(self, user_id):
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username, email, phone FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            if user:
                # ⬅️ Аналогічно розшифровуємо дані
                return (user[0], self.decrypt_pii(user[1]), self.decrypt_pii(user[2]))
            return None

    def get_session_token(self, user_id):
        """Отримує поточний токен сесії користувача з БД"""
        with self.connect() as conn:
            row = conn.execute("SELECT session_token FROM users WHERE id = ?", (user_id,)).fetchone()
            return row[0] if row else None

    def rotate_session_token(self, user_id):
        """Генерує новий токен, віддає клієнту оригінал, а в БД ховає SHA-256 хеш"""
        import secrets
        import hashlib

        raw_token = secrets.token_hex(16)  # Цей піде в cookie юзера
        hashed_token = hashlib.sha256(raw_token.encode()).hexdigest()  # Цей піде в базу

        with self.connect() as conn:
            conn.execute("UPDATE users SET session_token = ? WHERE id = ?", (hashed_token, user_id))
            conn.commit()

        return raw_token  # Віддаємо чистий, щоб app.py зберіг його в сесію
# ---------- ключі ----------------------------------------------------
    def get_public_key(self, username):
        with self.connect() as conn:
            row = conn.execute("SELECT public_key FROM users WHERE username=?", (username,)).fetchone()
            return row[0] if row and row[0] else None

    def set_public_key(self, user_id, pubkey_json):
        with self.connect() as conn:
            conn.execute("UPDATE users SET public_key=? WHERE id=?", (pubkey_json, user_id))
            conn.commit()

    # ==========================================
    # === ГРУПОВІ ЧАТИ (GROUP KEY E2E) =========
    # ==========================================

    def create_group(self, group_name, creator_username, members_data):
        """
        Створює групу та зберігає зашифрований AES-ключ для кожного учасника.
        members_data: список словників [{'username': 'user1', 'encrypted_key': '...'}, ...]
        """
        creator_id = self.get_user_id(creator_username)
        if not creator_id:
            return False, "Creator not found"

        with self.connect() as conn:
            c = conn.cursor()
            # 1. Створюємо саму групу
            c.execute("INSERT INTO groups (name, creator_id) VALUES (?, ?)", (group_name, creator_id))
            group_id = c.lastrowid

            # 2. Додаємо учасників та їхні персонально зашифровані ключі
            for member in members_data:
                u_id = self.get_user_id(member['username'])
                if u_id:
                    c.execute("""
                        INSERT INTO group_members (group_id, user_id, encrypted_group_key)
                        VALUES (?, ?, ?)
                    """, (group_id, u_id, member['encrypted_key']))
            conn.commit()
            return True, group_id

    def get_user_groups(self, username):
        """Отримує список груп, у яких бере участь користувач (із зазначенням творця)"""
        u_id = self.get_user_id(username)
        if not u_id: return []

        with self.connect() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT g.id, g.name, u.username
                FROM groups g
                JOIN users u ON g.creator_id = u.id
                JOIN group_members gm ON g.id = gm.group_id
                WHERE gm.user_id = ?
            """, (u_id,))
            return [{"id": row[0], "name": row[1], "creator": row[2]} for row in c.fetchall()]

    def get_group_key(self, group_id, username):
        """Отримує зашифрований AES-ключ групи для конкретного юзера"""
        u_id = self.get_user_id(username)
        with self.connect() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT encrypted_group_key 
                FROM group_members 
                WHERE group_id = ? AND user_id = ?
            """, (group_id, u_id))
            row = c.fetchone()
            return row[0] if row else None

    def save_group_message(self, group_id, sender_username, content, iv, media_type=None, media_content=None,
                           iv_media=None):
        """Зберігає повідомлення, зашифроване ключем групи (лише 1 шифротекст для всіх!)"""
        s_id = self.get_user_id(sender_username)
        with self.connect() as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO group_messages 
                (group_id, sender_id, content, iv, media_type, media_content, iv_media)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (group_id, s_id, content, iv, media_type, media_content, iv_media))
            conn.commit()
            return True

    def get_group_messages(self, group_id, limit=50, offset=0):
        """Отримує історію переписки в групі"""
        with self.connect() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT gm.id, gm.sender_id, u.username, gm.content, gm.iv, 
                       gm.media_type, gm.media_content, gm.iv_media, gm.timestamp
                FROM group_messages gm
                JOIN users u ON gm.sender_id = u.id
                WHERE gm.group_id = ?
                ORDER BY gm.timestamp DESC
                LIMIT ? OFFSET ?
            """, (group_id, limit, offset))
            rows = c.fetchall()

        messages = []
        for row in rows:
            messages.append({
                "id": row[0],
                "sender_id": row[1],
                "sender_username": row[2],
                "content": row[3],
                "iv": row[4],
                "media_type": row[5],
                "media_content": row[6],
                "iv_media": row[7],
                "timestamp": row[8]
            })
        messages.reverse()
        return messages
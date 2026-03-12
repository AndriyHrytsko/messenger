import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import time

class DatabaseManager:
    def __init__(self, db_path="messenger.db"):
        self.db_path = db_path

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
        try:
            with self.connect() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO users (username, email, phone, password)
                    VALUES (?, ?, ?, ?)
                ''', (username, email, phone, hashed_password))
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
                    "phone": user[3],
                    "two_factor_enabled": user[4],
                    "public_key": user[5]  # ➡️ ВАЖЛИВО: добавити!
                }
            return None

    def get_user_by_username_and_email(self, username, email):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email FROM users WHERE username = ? AND email = ?", (username, email))
        user = cursor.fetchone()
        conn.close()
        if user:
            return {"id": user[0], "username": user[1], "email": user[2]}
        return None

    def set_two_factor_enabled(self, username, enabled):
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET two_factor_enabled = ? WHERE username = ?",
                           (1 if enabled else 0, username))
            conn.commit()

    def login_user(self, username_or_email_or_phone, password):
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, password FROM users
                WHERE username = ? OR email = ? OR phone = ?
            ''', (username_or_email_or_phone, username_or_email_or_phone, username_or_email_or_phone))
            user = cursor.fetchone()
            if user and check_password_hash(user[1], password):
                return True, {"id": user[0], "username": username_or_email_or_phone}
            else:
                return False, "Invalid username/email/phone or password."

    def user_exists(self, username_or_email_or_phone):
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id FROM users
                WHERE username = ? OR email = ? OR phone = ?
            ''', (username_or_email_or_phone, username_or_email_or_phone, username_or_email_or_phone))
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

    def get_chat_history(self, user1, user2):
        """
        Повертає список повідомлень між user1 та user2,
        включно з полями для тексту і медіа.
        """
        u1 = self.get_user_id(user1)
        u2 = self.get_user_id(user2)
        if u1 is None or u2 is None:
            return []

        with self.connect() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT 
                  m.id,
                  m.sender_id,
                  m.receiver_id,
                  m.content_for_sender,
                  m.iv_for_sender,
                  m.content_for_receiver,
                  m.iv_for_receiver,
                  m.media_type,
                  m.media_content_for_sender,
                  m.iv_media_for_sender,
                  m.media_content_for_receiver,
                  m.iv_media_for_receiver,
                  m.reply_to,
                  m.status,
                  m.timestamp,
                  u1.username AS sender_username,
                  u2.username AS receiver_username
                FROM messages m
                JOIN users u1 ON m.sender_id   = u1.id
                JOIN users u2 ON m.receiver_id = u2.id
                WHERE (m.sender_id   = ? AND m.receiver_id   = ?)
                   OR (m.sender_id   = ? AND m.receiver_id   = ?)
                ORDER BY m.timestamp ASC
            """, (u1, u2, u2, u1))
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
            cursor.execute("INSERT INTO contacts (user_id, contact_id) VALUES (?, ?)", (user_id, contact_id))
            conn.commit()
            print("✅ Contact успішно додано")
            return "Contact successfully added"

    def get_user_data(self, username):
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username, email, phone FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            return user if user else None

    def update_user_profile(self, current_username, new_username, email, phone):
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users 
                SET username = ?, email = ?, phone = ? 
                WHERE username = ?
            """, (new_username, email, phone, current_username))
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
        cursor.execute("INSERT INTO verification_codes (user_id, code, created_at) VALUES (?, ?, ?)",
                       (user_id, code, timestamp))
        conn.commit()
        conn.close()

    def verify_code(self, user_id, code):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id FROM verification_codes
            WHERE user_id = ? AND code = ? AND used = 0
              AND created_at >= strftime('%s','now','-15 minutes')
            ORDER BY created_at DESC LIMIT 1
            """,
            (user_id, code)
        )
        result = cursor.fetchone()
        if result:
            cursor.execute(
                "UPDATE verification_codes SET used = 1 WHERE id = ?",
                (result[0],)
            )
            conn.commit()
        conn.close()
        return bool(result)

    def update_password(self, user_id, new_password):
        hashed_password = generate_password_hash(new_password)
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, user_id))
            conn.commit()

    def get_user_phone(self, username):
        with self.connect() as conn:
            cursor = conn.cursor()
            result = cursor.execute("SELECT phone FROM users WHERE username = ?", (username,)).fetchone()
            return result[0] if result else None

    def get_user_by_id(self, user_id):
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username, email, phone FROM users WHERE id = ?", (user_id,))
            return cursor.fetchone()

    def update_user(self, user_id, username, email, phone):
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET username=?, email=?, phone=? WHERE id=?",
                           (username, email, phone, user_id))
            conn.commit()


# ---------- ключі ----------------------------------------------------
    def get_public_key(self, username):
        with self.connect() as conn:
            row = conn.execute("SELECT public_key FROM users WHERE username=?", (username,)).fetchone()
            return row[0] if row and row[0] else None

    def set_public_key(self, user_id, pubkey_json):
        with self.connect() as conn:
            conn.execute("UPDATE users SET public_key=? WHERE id=?", (pubkey_json, user_id))
            conn.commit()


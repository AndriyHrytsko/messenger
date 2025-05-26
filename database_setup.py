import sqlite3

def create_tables(db_name="messenger.db"):
    with sqlite3.connect(db_name) as conn:
        cur = conn.cursor()

        # --- USERS ----------------------------------------------------------
        cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE,
                        phone TEXT UNIQUE,
                        password TEXT NOT NULL,
                        two_factor_enabled INTEGER DEFAULT 0,
                        public_key TEXT
                    )
                """)
        # якщо колонок ще немає — додаємо
        try:
            cur.execute("ALTER TABLE users ADD COLUMN failed_logins INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass
        try:
            cur.execute("ALTER TABLE users ADD COLUMN lockout_until DATETIME")
        except sqlite3.OperationalError:
            pass

        # --- MESSAGES -------------------------------------------------------
        cur.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id   INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                content_for_sender TEXT,  -- ciphertext для відправника
                iv_for_sender      TEXT,  -- IV для розшифрування для себе
                content_for_receiver TEXT, -- ciphertext для одержувача
                iv_for_receiver      TEXT, -- IV для розшифрування для друга
                -- Поля для медіа
                media_type TEXT,                    -- MIME-тип, напр. 'image/png' або 'application/pdf'
                media_content_for_sender TEXT,      -- base64 зашифровані дані для відправника
                iv_media_for_sender TEXT,
                media_content_for_receiver TEXT,    -- base64 зашифровані дані для отримувача
                iv_media_for_receiver TEXT,
                reply_to    INTEGER,
                status      TEXT DEFAULT 'sent',
                timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id)   REFERENCES users (id),
                FOREIGN KEY (receiver_id) REFERENCES users (id),
                FOREIGN KEY (reply_to)    REFERENCES messages (id)
            )
        """)

        # --- CONTACTS -------------------------------------------------------
        cur.execute("""
            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                contact_id INTEGER NOT NULL,
                UNIQUE (user_id, contact_id),
                FOREIGN KEY (user_id)    REFERENCES users (id),
                FOREIGN KEY (contact_id) REFERENCES users (id)
            )
        """)

        # --- VERIFICATION CODES ------------------------------------------------
        cur.execute("""
            CREATE TABLE IF NOT EXISTS verification_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                code       TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                used       INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        conn.commit()

if __name__ == "__main__":
    create_tables()
    print("✅ База даних готова")

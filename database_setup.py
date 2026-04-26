import sqlite3

def create_tables(db_name="messenger.db"):
    with sqlite3.connect(db_name) as conn:
        cur = conn.cursor()

        # --- DEVICE KEYS (Мульти-девайс ключі) ---
        cur.execute("""
                    CREATE TABLE IF NOT EXISTS device_keys (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        session_token TEXT NOT NULL UNIQUE,
                        public_key TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                    )
                """)

        # --- USERS (Оновлена, чиста таблиця з усіма колонками) ---
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE,
                phone TEXT UNIQUE,
                password TEXT NOT NULL,
                two_factor_enabled INTEGER DEFAULT 0,
                public_key TEXT,
                failed_logins INTEGER DEFAULT 0,
                lockout_until DATETIME,
                session_token TEXT,
                email_hash TEXT UNIQUE,
                phone_hash TEXT UNIQUE
            )
        """)

        # --- MESSAGES ---
        cur.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id   INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                content_for_sender TEXT,
                iv_for_sender      TEXT,
                content_for_receiver TEXT,
                iv_for_receiver      TEXT,
                media_type           TEXT,
                media_content_for_sender TEXT,
                iv_media_for_sender  TEXT,
                media_content_for_receiver TEXT,
                iv_media_for_receiver TEXT,
                reply_to    INTEGER,
                status      TEXT DEFAULT 'sent',
                timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id)   REFERENCES users (id),
                FOREIGN KEY (receiver_id) REFERENCES users (id),
                FOREIGN KEY (reply_to)    REFERENCES messages (id)
            )
        """)

        # --- CONTACTS ---
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

        # --- VERIFICATION CODES ---
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

        # --- GROUPS ---
        cur.execute("""
            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                creator_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (creator_id) REFERENCES users (id)
            )
        """)

        # --- GROUP MEMBERS ---
        cur.execute("""
            CREATE TABLE IF NOT EXISTS group_members (
                group_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                encrypted_group_key TEXT NOT NULL,
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (group_id, user_id),
                FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        """)

        # --- GROUP MESSAGES ---
        cur.execute("""
            CREATE TABLE IF NOT EXISTS group_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER NOT NULL,
                sender_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                iv TEXT NOT NULL,
                media_type TEXT,
                media_content TEXT,
                iv_media TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE CASCADE,
                FOREIGN KEY (sender_id) REFERENCES users (id) ON DELETE CASCADE
            )
        """)

        # --- ІНДЕКСИ ---
        cur.execute("CREATE INDEX IF NOT EXISTS idx_group_messages_group ON group_messages(group_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)")

        conn.commit()

if __name__ == "__main__":
    create_tables()
    print("База даних готова та оновлена")
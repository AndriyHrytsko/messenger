import sqlite3

conn = sqlite3.connect("messenger.db")
cursor = conn.cursor()

cursor.execute("SELECT id, sender_id, receiver_id FROM messages")
rows = cursor.fetchall()

broken = []

for row in rows:
    message_id, sender_id, receiver_id = row
    cursor.execute("SELECT username FROM users WHERE id = ?", (sender_id,))
    sender = cursor.fetchone()
    cursor.execute("SELECT username FROM users WHERE id = ?", (receiver_id,))
    receiver = cursor.fetchone()
    if not sender or not receiver:
        broken.append((message_id, sender_id, receiver_id))

if broken:
    print("🚨 Знайдено биті повідомлення:")
    for msg in broken:
        print(f"ID повідомлення: {msg[0]}, sender_id: {msg[1]}, receiver_id: {msg[2]}")
else:
    print("✅ Всі повідомлення мають валідних користувачів!")

conn.close()

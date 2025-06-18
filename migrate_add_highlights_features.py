import sqlite3

conn = sqlite3.connect('web.db')
cursor = conn.cursor()

try:
    cursor.execute("ALTER TABLE products ADD COLUMN highlights TEXT")
    print("Added 'highlights' column.")
except sqlite3.OperationalError as e:
    print("'highlights' column may already exist:", e)

try:
    cursor.execute("ALTER TABLE products ADD COLUMN features TEXT")
    print("Added 'features' column.")
except sqlite3.OperationalError as e:
    print("'features' column may already exist:", e)

conn.commit()
conn.close()
print("Migration complete.") 
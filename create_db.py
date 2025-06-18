import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect('web.db')
cursor = conn.cursor()

# Create users table
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0,
    reset_token TEXT UNIQUE,
    reset_token_expiry TIMESTAMP
)
''')

# Create products table
cursor.execute('''
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    price REAL NOT NULL,
    image_path TEXT,
    category TEXT,
    brand TEXT,
    stock INTEGER DEFAULT 0,
    highlights TEXT,
    features TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

# Insert a sample user (username: testuser, password: testpass) as admin
username = 'testuser'
password = generate_password_hash('testpass')
cursor.execute('INSERT OR IGNORE INTO users (username, password, is_admin) VALUES (?, ?, ?)', (username, password, 1))

conn.commit()
conn.close()

import sqlite3

def update_database():
    conn = sqlite3.connect('web.db')
    cursor = conn.cursor()

    # Add is_admin column to users table if it doesn't exist
    cursor.execute("""
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name='users'
    """)
    if cursor.fetchone():
        # Check if is_admin column exists
        cursor.execute("PRAGMA table_info(users)")
        columns = cursor.fetchall()
        if not any(column[1] == 'is_admin' for column in columns):
            cursor.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
            print("Added is_admin column to users table")
    
    # Make the first user an admin if there are any users
    cursor.execute("SELECT id FROM users ORDER BY id LIMIT 1")
    first_user = cursor.fetchone()
    if first_user:
        cursor.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (first_user[0],))
        print("Made the first user an admin")

    conn.commit()
    conn.close()
    print("Database update complete!")

if __name__ == "__main__":
    update_database() 
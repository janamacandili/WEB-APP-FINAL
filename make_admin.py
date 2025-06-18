import sqlite3

def make_user_admin(username):
    conn = sqlite3.connect('web.db')
    cursor = conn.cursor()
    
    # Check if user exists
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if user:
        # Update user to be admin
        cursor.execute("UPDATE users SET is_admin = 1 WHERE username = ?", (username,))
        conn.commit()
        print(f"Successfully made {username} an admin!")
    else:
        print(f"User {username} not found in the database.")
    
    conn.close()

if __name__ == "__main__":
    make_user_admin("Popeyeee") 
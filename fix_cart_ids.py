import sqlite3

def sync_cart_with_users():
    """
    Synchronize cart IDs with user IDs while maintaining data integrity
    """
    conn = sqlite3.connect('web.db')
    cursor = conn.cursor()
    
    try:
        # Enable foreign keys
        cursor.execute("PRAGMA foreign_keys = ON")
        
        # Create a temporary table with the structure we want
        cursor.execute('''
            CREATE TABLE cart_temp (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
            )
        ''')
        
        # Get all cart items ordered by user_id
        cursor.execute('''
            SELECT user_id, product_id, quantity, created_at 
            FROM cart 
            ORDER BY user_id
        ''')
        cart_items = cursor.fetchall()
        
        # Insert into temp table with new sequential IDs
        for item in cart_items:
            user_id, product_id, quantity, created_at = item
            cursor.execute('''
                INSERT INTO cart_temp (user_id, product_id, quantity, created_at)
                VALUES (?, ?, ?, ?)
            ''', (user_id, product_id, quantity, created_at))
        
        # Drop the original cart table
        cursor.execute('DROP TABLE cart')
        
        # Rename temp table to cart
        cursor.execute('ALTER TABLE cart_temp RENAME TO cart')
        
        # Update the IDs to match user_ids where possible
        cursor.execute('''
            UPDATE cart
            SET id = user_id
            WHERE id IN (
                SELECT c.id
                FROM cart c
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM cart c2
                    WHERE c2.id = c.user_id
                    AND c2.id != c.id
                )
            )
        ''')
        
        # Commit the changes
        conn.commit()
        print("Successfully synchronized cart IDs with user IDs where possible!")
        
        # Print the updated cart table info
        cursor.execute('SELECT * FROM cart ORDER BY id')
        rows = cursor.fetchall()
        print(f"\nUpdated cart table:")
        print(f"Total rows: {len(rows)}")
        print("Current rows:")
        for row in rows:
            print(row)
            
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == '__main__':
    sync_cart_with_users() 
import sqlite3

def rename_cart_columns():
    """
    Rename cart table columns to be more descriptive and clear
    """
    conn = sqlite3.connect('web.db')
    cursor = conn.cursor()
    
    try:
        # Temporarily disable foreign key constraints
        cursor.execute("PRAGMA foreign_keys = OFF")
        
        # Drop temporary table if it exists
        cursor.execute("DROP TABLE IF EXISTS cart_temp")
        
        # Create a temporary table with the new column names
        cursor.execute('''
            CREATE TABLE cart_temp (
                cart_item_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
            )
        ''')
        
        # Copy data from old table to new table
        cursor.execute('''
            INSERT INTO cart_temp (cart_item_id, user_id, product_id, quantity, created_at)
            SELECT id, user_id, product_id, quantity, created_at
            FROM cart
        ''')
        
        # Drop the original table
        cursor.execute('DROP TABLE cart')
        
        # Rename the new table to cart
        cursor.execute('ALTER TABLE cart_temp RENAME TO cart')
        
        # Re-enable foreign key constraints
        cursor.execute("PRAGMA foreign_keys = ON")
        
        # Commit the changes
        conn.commit()
        print("Successfully renamed cart table columns!")
        
        # Print the updated cart table info
        cursor.execute('SELECT * FROM cart ORDER BY cart_item_id')
        rows = cursor.fetchall()
        print(f"\nUpdated cart table structure:")
        print("Cart_Item_ID | User_ID | Product_ID | Quantity | Created_At")
        print("-" * 70)
        for row in rows:
            print(f"{row[0]:11d} | {row[1]:7d} | {row[2]:9d} | {row[3]:8d} | {row[4]}")
            
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == '__main__':
    rename_cart_columns() 
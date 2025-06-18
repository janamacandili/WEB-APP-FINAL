import sqlite3

def fix_table_ids(cursor, table_name, columns):
    """
    Fix IDs for a given table by creating a temp table and reordering the data.
    columns should be a list of tuples: [(name, type, constraints), ...]
    """
    # Create column definitions string
    columns_str = ', '.join([f"{col[0]} {col[1]} {col[2]}" for col in columns])
    
    try:
        # Create a temporary table
        cursor.execute(f'''
            CREATE TABLE {table_name}_temp (
                {columns_str}
            )
        ''')
        
        # Get column names for INSERT
        insert_columns = [col[0] for col in columns if col[0] != 'id']
        columns_to_insert = ', '.join(insert_columns)
        
        # Copy data from original table to temp table
        cursor.execute(f'''
            INSERT INTO {table_name}_temp ({columns_to_insert})
            SELECT {columns_to_insert} FROM {table_name}
            ORDER BY id
        ''')
        
        # Drop the original table
        cursor.execute(f'DROP TABLE {table_name}')
        
        # Rename temp table to original name
        cursor.execute(f'ALTER TABLE {table_name}_temp RENAME TO {table_name}')
        
        print(f"Successfully fixed IDs in {table_name} table!")
        
        # Print the updated table info
        cursor.execute(f'SELECT * FROM {table_name} ORDER BY id')
        rows = cursor.fetchall()
        print(f"\nUpdated {table_name} table:")
        print(f"Total rows: {len(rows)}")
        print("First few rows:")
        for row in rows[:5]:
            print(row)
            
    except sqlite3.Error as e:
        print(f"An error occurred with {table_name}: {e}")
        raise

def fix_all_ids():
    """Fix IDs in all tables that need sequential IDs"""
    conn = sqlite3.connect('web.db')
    cursor = conn.cursor()
    
    try:
        # Define table structures
        users_columns = [
            ('id', 'INTEGER', 'PRIMARY KEY AUTOINCREMENT'),
            ('username', 'TEXT', 'UNIQUE NOT NULL'),
            ('password', 'TEXT', 'NOT NULL'),
            ('is_admin', 'INTEGER', 'DEFAULT 0')
        ]
        
        products_columns = [
            ('id', 'INTEGER', 'PRIMARY KEY AUTOINCREMENT'),
            ('name', 'TEXT', 'NOT NULL'),
            ('description', 'TEXT', ''),
            ('price', 'REAL', 'NOT NULL'),
            ('image_path', 'TEXT', ''),
            ('category', 'TEXT', ''),
            ('brand', 'TEXT', ''),
            ('stock', 'INTEGER', 'DEFAULT 0'),
            ('created_at', 'TIMESTAMP', 'DEFAULT CURRENT_TIMESTAMP')
        ]
        
        cart_columns = [
            ('id', 'INTEGER', 'PRIMARY KEY AUTOINCREMENT'),
            ('user_id', 'INTEGER', 'NOT NULL'),
            ('product_id', 'INTEGER', 'NOT NULL'),
            ('quantity', 'INTEGER', 'NOT NULL DEFAULT 1'),
            ('created_at', 'TIMESTAMP', 'DEFAULT CURRENT_TIMESTAMP')
        ]
        
        # Fix IDs in each table
        fix_table_ids(cursor, 'users', users_columns)
        fix_table_ids(cursor, 'products', products_columns)
        fix_table_ids(cursor, 'cart', cart_columns)
        
        # Commit all changes
        conn.commit()
        print("\nAll tables have been fixed successfully!")
        
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
        conn.rollback()
    finally:
        conn.close()

def fix_users_only():
    """Fix IDs in the users table only (legacy support)"""
    conn = sqlite3.connect('web.db')
    cursor = conn.cursor()
    
    try:
        users_columns = [
            ('id', 'INTEGER', 'PRIMARY KEY AUTOINCREMENT'),
            ('username', 'TEXT', 'UNIQUE NOT NULL'),
            ('password', 'TEXT', 'NOT NULL'),
            ('is_admin', 'INTEGER', 'DEFAULT 0')
        ]
        
        fix_table_ids(cursor, 'users', users_columns)
        conn.commit()
        
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == '__main__':
    # By default, fix all tables
    fix_all_ids()
    
    # To fix only users table, uncomment the following line and comment out fix_all_ids()
    # fix_users_only() 
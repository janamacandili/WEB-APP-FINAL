import sqlite3

def fix_image_paths():
    conn = sqlite3.connect('web.db')
    cursor = conn.cursor()
    
    # Get all products
    cursor.execute("SELECT id, image_path FROM products")
    products = cursor.fetchall()
    
    for product in products:
        product_id = product[0]
        old_path = product[1]
        
        if old_path:  # Only process if there is a path
            # Convert backslashes to forward slashes and get the part after 'static/'
            new_path = old_path.replace('\\', '/').split('static/')[-1]
            if new_path.startswith('/'):
                new_path = new_path[1:]
            
            # Update the path in the database
            cursor.execute("""
                UPDATE products 
                SET image_path = ?
                WHERE id = ?
            """, (new_path, product_id))
            print(f"Updated path for product {product_id}:")
            print(f"Old path: {old_path}")
            print(f"New path: {new_path}")
            print("--------------------")
    
    conn.commit()
    conn.close()
    print("Database update complete!")

if __name__ == "__main__":
    fix_image_paths() 
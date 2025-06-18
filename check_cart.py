import sqlite3

def check_cart():
    conn = sqlite3.connect('web.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM cart ORDER BY cart_item_id')
    rows = cursor.fetchall()
    
    print("Current cart table contents:")
    print("Cart_Item_ID | User_ID | Product_ID | Quantity | Created_At")
    print("-" * 70)
    
    for row in rows:
        print(f"{row[0]:11d} | {row[1]:7d} | {row[2]:9d} | {row[3]:8d} | {row[4]}")
    
    conn.close()

if __name__ == '__main__':
    check_cart() 
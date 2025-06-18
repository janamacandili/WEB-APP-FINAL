import sqlite3

def check_products():
    conn = sqlite3.connect('web.db')
    cursor = conn.cursor()
    
    # Get all products
    cursor.execute("SELECT * FROM products")
    products = cursor.fetchall()
    
    print("\nProducts in database:")
    print("--------------------")
    for product in products:
        print(f"ID: {product[0]}")
        print(f"Name: {product[1]}")
        print(f"Description: {product[2]}")
        print(f"Price: {product[3]}")
        print(f"Image Path: {product[4]}")
        print(f"Category: {product[5]}")
        print(f"Stock: {product[6]}")
        print("--------------------")
    
    conn.close()

if __name__ == "__main__":
    check_products() 
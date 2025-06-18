from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3
import os
from functools import wraps
import secrets
from datetime import datetime
from urllib.parse import unquote
import re
from flask import Blueprint

app = Flask(__name__)  # Flask will automatically look for templates/ and static/ directories
app.secret_key = secrets.token_hex(16)  # Generate a secure random key
app.config['PERMANENT_SESSION_LIFETIME'] = 86400  # Session lifetime in seconds (24 hours)
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in first.', 'error')
            return redirect(url_for('login'))
        
        # Check if user is admin
        conn = sqlite3.connect('web.db')
        cursor = conn.cursor()
        cursor.execute("SELECT is_admin FROM users WHERE username = ?", (session['username'],))
        user = cursor.fetchone()
        conn.close()

        if not user or not user[0]:
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'error': 'You need to log in first to continue with your purchase'}), 401
            flash('You need to log in first to continue with your purchase', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_db():
    conn = sqlite3.connect('web.db')
    conn.execute("PRAGMA foreign_keys = ON")  # Enable foreign key support
    return conn

# Initialize cart table
def init_cart_table():
    conn = get_db()
    cursor = conn.cursor()
    
    # Create users table if it doesn't exist (with ON DELETE CASCADE)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    
    # Add reset_token and reset_token_expiry columns if they don't exist
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN reset_token TEXT UNIQUE")
    except sqlite3.OperationalError:
        pass  # Column already exists
        
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN reset_token_expiry TIMESTAMP")
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Create products table if it doesn't exist
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
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            highlights TEXT,
            features TEXT
        )
    ''')
    
    # Create cart table with proper foreign key constraints
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cart (
            cart_item_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
        )
    ''')
    
    # Create orders table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            total_amount REAL NOT NULL,
            status TEXT DEFAULT 'pending',
            shipping_address TEXT NOT NULL,
            contact_number TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    
    # Create order items table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            price REAL NOT NULL,
            FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
            FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize tables on startup
with app.app_context():
    init_cart_table()

# --- Routes for rendering templates ---
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/brands')
def brands():
    return render_template('brands.html')

@app.route('/brands/<brand>')
def products_by_brand(brand):
    # Connect to database
    conn = sqlite3.connect('web.db')
    cursor = conn.cursor()
    
    # Get category filter from query parameters if it exists
    category = request.args.get('category', None)
    if category:
        # URL decode the category name
        category = unquote(category)
    
    # Get page number from query parameters, default to 1
    page = request.args.get('page', 1, type=int)
    per_page = 9  # Number of products per page
    
    try:
        # Build the query based on whether a category filter exists
        if category:
            # Get total number of products for this brand and category
            cursor.execute("SELECT COUNT(*) FROM products WHERE brand = ? AND category = ?", (brand, category))
            total_products = cursor.fetchone()[0]
            
            # Calculate total pages
            total_pages = (total_products + per_page - 1) // per_page if total_products > 0 else 1
            
            # Ensure page number is within valid range
            page = max(1, min(page, total_pages))
            
            # Calculate offset for SQL query
            offset = (page - 1) * per_page
            
            # Get products for current page with both brand and category filters
            cursor.execute("""
                SELECT * FROM products 
                WHERE brand = ? AND category = ? 
                ORDER BY created_at DESC LIMIT ? OFFSET ?
            """, (brand, category, per_page, offset))
        else:
            # Get total number of products for this brand
            cursor.execute("SELECT COUNT(*) FROM products WHERE brand = ?", (brand,))
            total_products = cursor.fetchone()[0]
            
            # Calculate total pages
            total_pages = (total_products + per_page - 1) // per_page if total_products > 0 else 1
            
            # Ensure page number is within valid range
            page = max(1, min(page, total_pages))
            
            # Calculate offset for SQL query
            offset = (page - 1) * per_page
            
            # Get products for current page with only brand filter
            cursor.execute("""
                SELECT * FROM products 
                WHERE brand = ? 
                ORDER BY created_at DESC LIMIT ? OFFSET ?
            """, (brand, per_page, offset))
        
        products = cursor.fetchall()
        
        return render_template('products.html', 
                             products=products, 
                             selected_brand=brand,
                             selected_category=category,
                             current_page=page,
                             total_pages=total_pages)
                             
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        flash('An error occurred while fetching products.', 'error')
        return redirect(url_for('products'))
    finally:
        conn.close()

@app.route('/category/<category>')
def products_by_category(category):
    # URL decode the category name
    category = unquote(category)
    
    # Connect to database
    conn = sqlite3.connect('web.db')
    cursor = conn.cursor()
    
    # Get brand filter from query parameters if it exists
    brand = request.args.get('brand', None)
    
    # Get page number from query parameters, default to 1
    page = request.args.get('page', 1, type=int)
    per_page = 9  # Number of products per page
    
    try:
        # Build the query based on whether a brand filter exists
        if brand:
            # Get total number of products for this category and brand
            cursor.execute("SELECT COUNT(*) FROM products WHERE category = ? AND brand = ?", (category, brand))
            total_products = cursor.fetchone()[0]
            
            # Calculate total pages
            total_pages = (total_products + per_page - 1) // per_page if total_products > 0 else 1
            
            # Ensure page number is within valid range
            page = max(1, min(page, total_pages))
            
            # Calculate offset for SQL query
            offset = (page - 1) * per_page
            
            # Get products for current page with both category and brand filters
            cursor.execute("""
                SELECT * FROM products 
                WHERE category = ? AND brand = ? 
                ORDER BY created_at DESC LIMIT ? OFFSET ?
            """, (category, brand, per_page, offset))
        else:
            # Get total number of products for this category
            cursor.execute("SELECT COUNT(*) FROM products WHERE category = ?", (category,))
            total_products = cursor.fetchone()[0]
            
            # Calculate total pages
            total_pages = (total_products + per_page - 1) // per_page if total_products > 0 else 1
            
            # Ensure page number is within valid range
            page = max(1, min(page, total_pages))
            
            # Calculate offset for SQL query
            offset = (page - 1) * per_page
            
            # Get products for current page with only category filter
            cursor.execute("""
                SELECT * FROM products 
                WHERE category = ? 
                ORDER BY created_at DESC LIMIT ? OFFSET ?
            """, (category, per_page, offset))
        
        products = cursor.fetchall()
        
        return render_template('products.html', 
                             products=products, 
                             selected_category=category,
                             selected_brand=brand,
                             current_page=page,
                             total_pages=total_pages)
                             
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        flash('An error occurred while fetching products.', 'error')
        return redirect(url_for('products'))
    finally:
        conn.close()

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Redirect to home if user is already logged in
    if 'username' in session:
        flash('You are already logged in!', 'info')
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('web.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session.permanent = True
            session['username'] = username
            session['user_id'] = user[0]
            session['is_admin'] = bool(user[3]) if len(user) > 3 else False
            flash('Successfully logged in!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password. Please try again.', 'error')

    return render_template('login.html')

def validate_password(password):
    """
    Validate that the password meets all requirements:
    - At least 8 characters
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one number
    """
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    return True

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # Redirect to home if user is already logged in
    if 'username' in session:
        flash('You are already logged in! Please logout first to create a new account.', 'info')
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('signup'))

        if not validate_password(password):
            flash('Password must be at least 8 characters long and contain uppercase, lowercase, and numbers.', 'error')
            return redirect(url_for('signup'))

        # Hash the password before saving
        hashed_password = generate_password_hash(password)

        try:
            conn = sqlite3.connect('web.db')
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            conn.close()
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Please choose a different username.', 'error')
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

@app.route('/products')
def products():
    # Connect to database
    conn = sqlite3.connect('web.db')
    cursor = conn.cursor()
    
    # Get page number from query parameters, default to 1
    page = request.args.get('page', 1, type=int)
    per_page = 9  # Number of products per page
    
    # Get total number of products
    cursor.execute("SELECT COUNT(*) FROM products")
    total_products = cursor.fetchone()[0]
    
    # Calculate total pages
    total_pages = (total_products + per_page - 1) // per_page
    
    # Ensure page number is within valid range
    page = max(1, min(page, total_pages))
    
    # Calculate offset for SQL query
    offset = (page - 1) * per_page
    
    # Get products for current page
    cursor.execute("SELECT * FROM products ORDER BY created_at DESC LIMIT ? OFFSET ?", 
                  (per_page, offset))
    products = cursor.fetchall()
    conn.close()
    
    return render_template('products.html', 
                         products=products, 
                         current_page=page,
                         total_pages=total_pages)

@app.route('/product/<int:product_id>')
def product_details(product_id):
    # Connect to database
    conn = sqlite3.connect('web.db')
    cursor = conn.cursor()
    
    # Get the specific product
    cursor.execute("SELECT * FROM products WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    conn.close()
    
    if product is None:
        flash('Product not found.', 'error')
        return redirect(url_for('products'))
    
    return render_template('product_details.html', product=product)

@app.route('/admin/add-product', methods=['GET', 'POST'])
@admin_required
def add_product():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = request.form['price']
        image_path = request.form['image_path']
        highlights = request.form['highlights']
        features = request.form['features']
        
        # Clean up the image path
        # Remove any absolute path components and 'static/' prefix
        image_path = image_path.replace('\\', '/').strip()  # Replace backslashes and remove whitespace
        
        # Remove 'static/' prefix if present
        if image_path.startswith('static/'):
            image_path = image_path[7:]  # Remove 'static/' from the beginning
        
        # Remove leading slash if present
        if image_path.startswith('/'):
            image_path = image_path[1:]
            
        # Verify if the image exists in the static directory
        full_path = os.path.join('static', image_path)
        if not os.path.exists(full_path):
            flash(f'Error: Image file not found at {full_path}. Please check the path and try again.', 'error')
            return redirect(url_for('add_product'))
        
        category = request.form['category']
        brand = request.form['brand']
        stock = request.form['stock']

        try:
            conn = sqlite3.connect('web.db')
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO products (name, description, price, image_path, category, brand, stock, highlights, features)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (name, description, price, image_path, category, brand, stock, highlights, features))
            conn.commit()
            conn.close()

            flash('Product added successfully!', 'success')
            return redirect(url_for('admin_products'))
        except sqlite3.Error as e:
            flash(f'Database error: {str(e)}', 'error')
            return redirect(url_for('add_product'))

    return render_template('add_product.html')

@app.route('/admin/products')
@admin_required
def admin_products():
    conn = sqlite3.connect('web.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products ORDER BY created_at DESC")
    products = cursor.fetchall()
    conn.close()
    return render_template('admin_products.html', products=products)

@app.route('/delete_product/<int:product_id>', methods=['POST'])
@admin_required
def delete_product(product_id):
    conn = sqlite3.connect('web.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM products WHERE id = ?", (product_id,))
    conn.commit()
    conn.close()
    
    flash('Product deleted successfully!', 'success')
    return redirect(url_for('admin_products'))

@app.route('/update_stock/<int:product_id>', methods=['POST'])
@admin_required
def update_stock(product_id):
    try:
        new_stock = int(request.form['stock'])
        if new_stock < 0:
            raise ValueError("Stock cannot be negative")
            
        conn = sqlite3.connect('web.db')
        cursor = conn.cursor()
        cursor.execute("UPDATE products SET stock = ? WHERE id = ?", (new_stock, product_id))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'new_stock': new_stock})
    except (ValueError, TypeError) as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': 'Database error occurred'}), 500

@app.route('/update_guitar_category')
@admin_required
def update_guitar_category():
    conn = sqlite3.connect('web.db')
    cursor = conn.cursor()
    
    # Update all products with category "Guitars" to "Guitars & Accessories"
    cursor.execute("UPDATE products SET category = 'Guitars & Accessories' WHERE category = 'Guitars'")
    conn.commit()
    
    # Get the number of updated rows
    updated_rows = cursor.rowcount
    conn.close()
    
    flash(f'Successfully updated {updated_rows} products to new category name.', 'success')
    return redirect(url_for('admin_products'))

def get_cart_count():
    if 'user_id' not in session:
        return 0
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT SUM(quantity) FROM cart 
        WHERE user_id = ?
    """, (session['user_id'],))
    count = cursor.fetchone()[0]
    conn.close()
    
    return count or 0

app.jinja_env.globals.update(get_cart_count=get_cart_count)

@app.route('/add-to-cart', methods=['POST'])
@login_required
def add_to_cart():
    product_id = request.form.get('product_id')
    quantity = int(request.form.get('quantity', 1))
    
    if not product_id:
        return jsonify({'error': 'Product ID is required'}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Check if product exists and has enough stock
    cursor.execute("SELECT stock FROM products WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    
    if not product:
        conn.close()
        return jsonify({'error': 'Product not found'}), 404
    
    if product[0] < quantity:
        conn.close()
        return jsonify({'error': 'Not enough stock available'}), 400
    
    # Check if product already in cart
    cursor.execute("""
        SELECT cart_item_id, quantity FROM cart 
        WHERE user_id = ? AND product_id = ?
    """, (session['user_id'], product_id))
    cart_item = cursor.fetchone()
    
    try:
        if cart_item:
            # Update quantity if product already in cart
            new_quantity = cart_item[1] + quantity
            if new_quantity > product[0]:
                conn.close()
                return jsonify({'error': 'Not enough stock available'}), 400
                
            cursor.execute("""
                UPDATE cart 
                SET quantity = ?
                WHERE cart_item_id = ?
            """, (new_quantity, cart_item[0]))
        else:
            # Add new cart item
            cursor.execute("""
                INSERT INTO cart (user_id, product_id, quantity)
                VALUES (?, ?, ?)
            """, (session['user_id'], product_id, quantity))
        
        conn.commit()
        conn.close()
        return jsonify({'message': 'Product added to cart successfully'}), 200
        
    except sqlite3.Error as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

@app.route('/cart')
@login_required
def view_cart():
    conn = get_db()
    cursor = conn.cursor()
    
    # Get cart items with product details
    cursor.execute("""
        SELECT p.id, p.name, p.price, p.image_path, c.quantity, p.stock
        FROM cart c
        JOIN products p ON c.product_id = p.id
        WHERE c.user_id = ?
    """, (session['user_id'],))
    
    cart_items = cursor.fetchall()
    conn.close()
    
    total = sum(item[2] * item[4] for item in cart_items)  # price * quantity
    
    return render_template('cart.html', cart_items=cart_items, total=total)

@app.route('/update-cart', methods=['POST'])
@login_required
def update_cart():
    product_id = request.form.get('product_id')
    quantity = int(request.form.get('quantity', 0))
    
    if not product_id:
        return jsonify({'error': 'Product ID is required'}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        if quantity <= 0:
            # Remove item from cart
            cursor.execute("""
                DELETE FROM cart 
                WHERE user_id = ? AND product_id = ?
            """, (session['user_id'], product_id))
        else:
            # Check stock availability
            cursor.execute("SELECT stock FROM products WHERE id = ?", (product_id,))
            available_stock = cursor.fetchone()[0]
            
            if quantity > available_stock:
                conn.close()
                return jsonify({'error': 'Not enough stock available'}), 400
            
            # Update quantity
            cursor.execute("""
                UPDATE cart 
                SET quantity = ?
                WHERE user_id = ? AND product_id = ?
            """, (quantity, session['user_id'], product_id))
        
        conn.commit()
        conn.close()
        return jsonify({'message': 'Cart updated successfully'}), 200
        
    except sqlite3.Error as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    if request.method == 'POST':
        # Get form data
        shipping_address = request.form.get('shipping_address')
        contact_number = request.form.get('contact_number')
        
        if not shipping_address or not contact_number:
            flash('Please fill in all required fields.', 'error')
            return redirect(url_for('checkout'))
        
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            # Get cart items
            cursor.execute("""
                SELECT p.id, p.name, p.price, c.quantity, p.stock
                FROM cart c
                JOIN products p ON c.product_id = p.id
                WHERE c.user_id = ?
            """, (session['user_id'],))
            
            cart_items = cursor.fetchall()
            
            if not cart_items:
                flash('Your cart is empty.', 'error')
                return redirect(url_for('cart'))
            
            # Calculate total
            total_amount = sum(item[2] * item[3] for item in cart_items)
            
            # Check stock availability
            for item in cart_items:
                if item[3] > item[4]:  # if quantity > stock
                    flash(f'Sorry, {item[1]} is out of stock.', 'error')
                    return redirect(url_for('cart'))
            
            # Create order
            cursor.execute("""
                INSERT INTO orders (user_id, total_amount, shipping_address, contact_number)
                VALUES (?, ?, ?, ?)
            """, (session['user_id'], total_amount, shipping_address, contact_number))
            
            order_id = cursor.lastrowid
            
            # Create order items and update stock
            for item in cart_items:
                product_id, _, price, quantity, _ = item
                
                # Add to order items
                cursor.execute("""
                    INSERT INTO order_items (order_id, product_id, quantity, price)
                    VALUES (?, ?, ?, ?)
                """, (order_id, product_id, quantity, price))
                
                # Update stock
                cursor.execute("""
                    UPDATE products
                    SET stock = stock - ?
                    WHERE id = ?
                """, (quantity, product_id))
            
            # Clear cart
            cursor.execute("DELETE FROM cart WHERE user_id = ?", (session['user_id'],))
            
            conn.commit()
            flash('Order placed successfully!', 'success')
            return redirect(url_for('order_confirmation', order_id=order_id))
            
        except sqlite3.Error as e:
            conn.rollback()
            flash('An error occurred while processing your order. Please try again.', 'error')
            return redirect(url_for('checkout'))
        finally:
            conn.close()
    
    # GET request - show checkout form
    conn = get_db()
    cursor = conn.cursor()
    
    # Get cart items for display
    cursor.execute("""
        SELECT p.id, p.name, p.price, p.image_path, c.quantity
        FROM cart c
        JOIN products p ON c.product_id = p.id
        WHERE c.user_id = ?
    """, (session['user_id'],))
    
    cart_items = cursor.fetchall()
    total = sum(item[2] * item[4] for item in cart_items)
    
    conn.close()
    
    if not cart_items:
        flash('Your cart is empty.', 'error')
        return redirect(url_for('cart'))
    
    return render_template('checkout.html', cart_items=cart_items, total=total)

@app.route('/order-confirmation/<int:order_id>')
@login_required
def order_confirmation(order_id):
    conn = get_db()
    cursor = conn.cursor()
    
    # Get order details
    cursor.execute("""
        SELECT o.id, o.total_amount, o.status, o.shipping_address, o.contact_number, o.created_at
        FROM orders o
        WHERE o.id = ? AND o.user_id = ?
    """, (order_id, session['user_id']))
    
    order = cursor.fetchone()
    
    if not order:
        flash('Order not found.', 'error')
        return redirect(url_for('home'))
    
    # Convert order tuple to list so we can modify it
    order = list(order)
    # Convert the date string to a datetime object
    order[5] = datetime.strptime(order[5], '%Y-%m-%d %H:%M:%S')
    
    # Get order items
    cursor.execute("""
        SELECT p.name, oi.quantity, oi.price
        FROM order_items oi
        JOIN products p ON oi.product_id = p.id
        WHERE oi.order_id = ?
    """, (order_id,))
    
    order_items = cursor.fetchall()
    conn.close()
    
    return render_template('order_confirmation.html', order=order, order_items=order_items)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_new_password')
        
        # Validate passwords match
        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('forgot_password'))
            
        # Validate password requirements
        if len(new_password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return redirect(url_for('forgot_password'))
        if not re.search(r'[A-Z]', new_password):
            flash('Password must contain at least one uppercase letter.', 'error')
            return redirect(url_for('forgot_password'))
        if not re.search(r'[a-z]', new_password):
            flash('Password must contain at least one lowercase letter.', 'error')
            return redirect(url_for('forgot_password'))
        if not re.search(r'\d', new_password):
            flash('Password must contain at least one number.', 'error')
            return redirect(url_for('forgot_password'))
        
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            # Check if user exists
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            
            if user:
                # Update password
                hashed_password = generate_password_hash(new_password)
                cursor.execute("""
                    UPDATE users 
                    SET password = ?
                    WHERE username = ?
                """, (hashed_password, username))
                conn.commit()
                flash('Your password has been reset successfully. Please log in with your new password.', 'success')
                return redirect(url_for('login'))
            else:
                # Don't reveal if user exists or not for security
                flash('If an account exists with this username, the password will be reset.', 'info')
                return redirect(url_for('forgot_password'))
                
        except sqlite3.Error as e:
            conn.rollback()
            flash('An error occurred while resetting your password. Please try again.', 'error')
            return redirect(url_for('forgot_password'))
        finally:
            conn.close()
            
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = get_db()
    cursor = conn.cursor()
    
    # Check if token exists and is valid
    cursor.execute("""
        SELECT id FROM users 
        WHERE reset_token = ? 
        AND reset_token_expiry > datetime('now')
    """, (token,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        flash('Invalid or expired reset link. Please try again.', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('reset_password', token=token))
        
        # Update password and clear reset token
        hashed_password = generate_password_hash(password)
        cursor.execute("""
            UPDATE users 
            SET password = ?, reset_token = NULL, reset_token_expiry = NULL 
            WHERE reset_token = ?
        """, (hashed_password, token))
        conn.commit()
        conn.close()
        
        flash('Your password has been reset successfully. Please log in with your new password.', 'success')
        return redirect(url_for('login'))
    
    conn.close()
    return render_template('reset_password.html')

@app.route('/search')
def search():
    # Get the search query from URL parameters
    query = request.args.get('q', '')
    
    if not query:
        return redirect(url_for('products'))
    
    # Connect to database
    conn = sqlite3.connect('web.db')
    cursor = conn.cursor()
    
    # Search in product names and descriptions
    cursor.execute("""
        SELECT * FROM products 
        WHERE name LIKE ? OR description LIKE ? OR category LIKE ? OR brand LIKE ?
        ORDER BY created_at DESC
    """, (f'%{query}%', f'%{query}%', f'%{query}%', f'%{query}%'))
    
    products = cursor.fetchall()
    conn.close()
    
    return render_template('products.html', 
                         products=products,
                         search_query=query)

@app.route('/search-suggestions')
def search_suggestions():
    query = request.args.get('q', '').strip()
    
    if not query or len(query) < 2:
        return jsonify([])
    
    # Connect to database
    conn = sqlite3.connect('web.db')
    cursor = conn.cursor()
    
    # Search in product names, descriptions, categories, and brands
    cursor.execute("""
        SELECT id, name, price, image_path, category, brand 
        FROM products 
        WHERE name LIKE ? OR description LIKE ? OR category LIKE ? OR brand LIKE ?
        LIMIT 5
    """, (f'%{query}%', f'%{query}%', f'%{query}%', f'%{query}%'))
    
    products = cursor.fetchall()
    conn.close()
    
    # Format results
    suggestions = [{
        'id': product[0],
        'name': product[1],
        'price': float(product[2]),
        'image': product[3],
        'category': product[4],
        'brand': product[5]
    } for product in products]
    
    return jsonify(suggestions)

@app.route('/buy-now', methods=['POST'])
@login_required
def buy_now():
    product_id = request.form.get('product_id')
    quantity = int(request.form.get('quantity', 1))
    
    if not product_id:
        return jsonify({'error': 'Product ID is required'}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Check if product exists and has enough stock
        cursor.execute("SELECT id, name, price, stock, image_path FROM products WHERE id = ?", (product_id,))
        product = cursor.fetchone()
        
        if not product:
            conn.close()
            return jsonify({'error': 'Product not found'}), 404
        
        if product[3] < quantity:
            conn.close()
            return jsonify({'error': 'Not enough stock available'}), 400

        # Store buy-now item in session
        buy_now_item = {
            'product_id': product[0],
            'name': product[1],
            'price': product[2],
            'quantity': quantity,
            'image_path': product[4]
        }
        session['buy_now_item'] = buy_now_item
        
        conn.close()
        return jsonify({
            'message': 'Proceeding to checkout',
            'redirect_url': url_for('buy_now_checkout')
        }), 200
        
    except sqlite3.Error as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

@app.route('/buy-now-checkout', methods=['GET', 'POST'])
@login_required
def buy_now_checkout():
    if 'buy_now_item' not in session:
        flash('No product selected for purchase.', 'error')
        return redirect(url_for('products'))
    
    buy_now_item = session['buy_now_item']
    
    if request.method == 'POST':
        # Get form data
        shipping_address = request.form.get('shipping_address')
        contact_number = request.form.get('contact_number')
        
        if not shipping_address or not contact_number:
            flash('Please fill in all required fields.', 'error')
            return redirect(url_for('buy_now_checkout'))
        
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            # Check stock availability again
            cursor.execute("SELECT stock FROM products WHERE id = ?", (buy_now_item['product_id'],))
            available_stock = cursor.fetchone()[0]
            
            if available_stock < buy_now_item['quantity']:
                flash('Sorry, the product is out of stock.', 'error')
                return redirect(url_for('products'))
            
            # Calculate total
            total_amount = buy_now_item['price'] * buy_now_item['quantity']
            
            # Create order
            cursor.execute("""
                INSERT INTO orders (user_id, total_amount, shipping_address, contact_number)
                VALUES (?, ?, ?, ?)
            """, (session['user_id'], total_amount, shipping_address, contact_number))
            
            order_id = cursor.lastrowid
            
            # Create order item
            cursor.execute("""
                INSERT INTO order_items (order_id, product_id, quantity, price)
                VALUES (?, ?, ?, ?)
            """, (order_id, buy_now_item['product_id'], buy_now_item['quantity'], buy_now_item['price']))
            
            # Update stock
            cursor.execute("""
                UPDATE products
                SET stock = stock - ?
                WHERE id = ?
            """, (buy_now_item['quantity'], buy_now_item['product_id']))
            
            conn.commit()
            
            # Clear buy-now item from session
            session.pop('buy_now_item', None)
            
            flash('Order placed successfully!', 'success')
            return redirect(url_for('order_confirmation', order_id=order_id))
            
        except sqlite3.Error as e:
            conn.rollback()
            flash('An error occurred while processing your order. Please try again.', 'error')
            return redirect(url_for('buy_now_checkout'))
        finally:
            conn.close()
    
    # GET request - show checkout form
    return render_template('buy_now_checkout.html', item=buy_now_item)

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/routes')
def list_routes():
    import urllib
    output = []
    for rule in app.url_map.iter_rules():
        methods = ','.join(rule.methods)
        line = urllib.parse.unquote(f"{rule.endpoint}: {rule} [{methods}]")
        output.append(line)
    return "<br>".join(sorted(output))

admin = Blueprint('admin', __name__, url_prefix='/admin')

@admin.route('/add/products')
def add_products():
    return render_template('add_products.html')

app.register_blueprint(admin)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)

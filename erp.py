from flask import Flask, request, jsonify, session, make_response, render_template
from flask_cors import CORS
import sqlite3
import hashlib
import secrets
from functools import wraps
import os
from datetime import timedelta

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY') or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    DATABASE='construction_erp.db',
    JSONIFY_PRETTYPRINT_REGULAR=True
)

# Enable CORS with correct settings
CORS(app, supports_credentials=True, origins=["http://localhost:3000", "http://127.0.0.1:3000"])

# Simple Database Helper
def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        db = get_db()
        try:
            cursor = db.cursor()
            # Drop tables if they exist
            cursor.executescript('''
                DROP TABLE IF EXISTS sales;
                DROP TABLE IF EXISTS transfers;
                DROP TABLE IF EXISTS products;
                DROP TABLE IF EXISTS users;
            ''')

            # Create tables
            cursor.execute('''
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    role TEXT NOT NULL,
                    last_login TIMESTAMP,
                    failed_attempts INTEGER DEFAULT 0,
                    account_locked BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cursor.execute('''
                CREATE TABLE products (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    brand TEXT NOT NULL,
                    category TEXT NOT NULL,
                    warehouse_stock INTEGER DEFAULT 0,
                    showroom_stock INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cursor.execute('''
                CREATE TABLE transfers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    product_id INTEGER NOT NULL,
                    product_name TEXT NOT NULL,
                    from_location TEXT NOT NULL,
                    to_location TEXT NOT NULL,
                    quantity INTEGER NOT NULL,
                    status TEXT DEFAULT 'completed',
                    transfer_date DATE DEFAULT CURRENT_DATE,
                    created_by TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (product_id) REFERENCES products (id) ON DELETE CASCADE
                )
            ''')
            cursor.execute('''
                CREATE TABLE sales (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    product_id INTEGER NOT NULL,
                    product_name TEXT NOT NULL,
                    location TEXT NOT NULL,
                    quantity INTEGER NOT NULL,
                    sale_date DATE DEFAULT CURRENT_DATE,
                    sold_by TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (product_id) REFERENCES products (id) ON DELETE CASCADE
                )
            ''')

            # Insert default user
            def create_user(username, password, role):
                salt = secrets.token_hex(16)
                password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
                return (username, password_hash, salt, role)

            users = [
                create_user('admin', 'admin123', 'admin'),
                create_user('sales', 'sales123', 'sales')
            ]
            cursor.executemany('INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)', users)

            sample_products = [
                ('Concrete Waterproofing', 'Dr.Fixit', 'Waterproofing', 150, 25),
                ('Tile Adhesive', 'Pidilite', 'Adhesives', 200, 40),
                ('Wall Putty', 'Asian Paints', 'Putty', 300, 50),
                ('Crack Filler', 'Dr.Fixit', 'Repair', 80, 15),
                ('Wood Adhesive', 'Pidilite', 'Adhesives', 120, 30)
            ]
            cursor.executemany('INSERT INTO products (name, brand, category, warehouse_stock, showroom_stock) VALUES (?, ?, ?, ?, ?)', sample_products)

            db.commit()
        except Exception as e:
            db.rollback()
            raise e
        finally:
            db.close()

# Security Helpers
def verify_password(stored_hash, salt, provided_password):
    new_hash = hashlib.pbkdf2_hmac('sha256', provided_password.encode(), salt.encode(), 100000).hex()
    return secrets.compare_digest(stored_hash, new_hash)

def login_required(roles=None):
    def decorator(f):
        @wraps(f)
        def wrapped_function(*args, **kwargs):
            if 'user_id' not in session:
                return jsonify({'error': 'Authentication required'}), 401
            if roles and session.get('role') not in roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return wrapped_function
    return decorator

@app.route('/')
def home():
    return render_template("login.html")

@app.route('/dashboard')
def dashboard():
    return render_template("index.html")

@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        return _build_cors_preflight_response()
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')

    if not username or not password or not role:
        return _corsify_response(jsonify({'error': 'All fields are required'})), 400

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ? AND role = ?', (username, role)).fetchone()

    if not user or user['account_locked']:
        return _corsify_response(jsonify({'error': 'Invalid credentials or account locked'})), 401

    if not verify_password(user['password_hash'], user['salt'], password):
        db.execute('UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?', (user['id'],))
        db.commit()
        return _corsify_response(jsonify({'error': 'Invalid credentials'})), 401

    db.execute('UPDATE users SET failed_attempts = 0, last_login = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
    db.commit()
    session.clear()
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['role'] = user['role']
    session.permanent = True

    return _corsify_response(jsonify({
        'success': True,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'role': user['role']
        }
    }))

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/api/dashboard-stats')
@login_required()
def dashboard_stats():
    db = get_db()
    stats = db.execute('''
        SELECT 
            (SELECT SUM(warehouse_stock) FROM products) as warehouse_total,
            (SELECT SUM(showroom_stock) FROM products) as showroom_total,
            (SELECT COUNT(*) FROM transfers WHERE transfer_date >= date('now', '-30 days')) as monthly_transfers,
            (SELECT COUNT(*) FROM sales WHERE sale_date >= date('now', '-30 days')) as monthly_sales
    ''').fetchone()

    recent_transfers = db.execute('''
        SELECT t.*, p.brand FROM transfers t 
        JOIN products p ON t.product_id = p.id 
        ORDER BY t.created_at DESC LIMIT 5
    ''').fetchall()

    return jsonify({
        'warehouse_stock': stats['warehouse_total'] or 0,
        'showroom_stock': stats['showroom_total'] or 0,
        'monthly_imports': stats['monthly_transfers'],
        'total_sales': stats['monthly_sales'],
        'recent_transfers': [dict(row) for row in recent_transfers]
    })

@app.route('/api/products')
@login_required()
def get_products():
    db = get_db()
    products = db.execute('SELECT * FROM products').fetchall()
    return jsonify([dict(p) for p in products])

@app.route('/api/products/<int:product_id>/sell', methods=['POST'])
@login_required()
def sell_product(product_id):
    data = request.get_json()
    quantity = int(data.get('quantity'))
    location = data.get('location')

    db = get_db()
    product = db.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
    if not product:
        return jsonify({'error': 'Product not found'}), 404

    stock_col = 'warehouse_stock' if location == 'warehouse' else 'showroom_stock'
    current_stock = product[stock_col]

    if quantity > current_stock:
        return jsonify({'error': 'Not enough stock'}), 400

    db.execute(f'UPDATE products SET {stock_col} = {stock_col} - ? WHERE id = ?', (quantity, product_id))
    db.execute('INSERT INTO sales (product_id, product_name, location, quantity, sold_by) VALUES (?, ?, ?, ?, ?)',
               (product_id, product['name'], location, quantity, session['username']))
    db.commit()
    return jsonify({'success': True})

@app.route('/api/transfers', methods=['POST'])
@login_required()
def create_transfer():
    data = request.get_json()
    product_id = data.get('product_id')
    quantity = data.get('quantity')
    from_loc = data.get('from_location')
    to_loc = data.get('to_location')

    db = get_db()
    product = db.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
    if not product:
        return jsonify({'error': 'Product not found'}), 404

    from_col = from_loc + '_stock'
    to_col = to_loc + '_stock'

    current_stock = product[from_col]
    if quantity > current_stock:
        return jsonify({'error': 'Not enough stock'}), 400

    db.execute(f'UPDATE products SET {from_col} = {from_col} - ?, {to_col} = {to_col} + ? WHERE id = ?',
               (quantity, quantity, product_id))
    db.execute('INSERT INTO transfers (product_id, product_name, from_location, to_location, quantity, created_by) VALUES (?, ?, ?, ?, ?, ?)',
               (product_id, product['name'], from_loc, to_loc, quantity, session['username']))
    db.commit()
    return jsonify({'success': True})

def _build_cors_preflight_response():
    response = make_response()
    response.headers.add("Access-Control-Allow-Origin", "http://localhost:3000")
    response.headers.add("Access-Control-Allow-Headers", "*")
    response.headers.add("Access-Control-Allow-Methods", "*")
    response.headers.add("Access-Control-Allow-Credentials", "true")
    return response

def _corsify_response(response, status_code=200):
    response.headers.add("Access-Control-Allow-Origin", "http://localhost:3000")
    response.headers.add("Access-Control-Allow-Credentials", "true")
    return response

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
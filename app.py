from flask import Flask, render_template, request, redirect, session, url_for, flash
import sqlite3
import bleach
import os

from user import register_user, login_user

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database connection
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Create 'Reviews' table
def create_reviews_table():
    with get_db_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL
            );
        ''')
        conn.commit()

# Secure user database connection
def get_secure_db_connection():
    conn = sqlite3.connect('user_auth.db')
    conn.row_factory = sqlite3.Row
    return conn

def create_secure_database():
    with get_secure_db_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                secret_key TEXT
            );
        ''')
        conn.commit()

@app.route('/')
def index():
    with get_db_connection() as conn:
        reviews = conn.execute('SELECT * FROM reviews').fetchall()
    return render_template('index.html', reviews=reviews)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        totp_code = request.form['totp']

        # Attempt to log in the user
        message, success = login_user(email, password, totp_code)
        if success:
            session['user_email'] = email
            flash('Login successful!', 'success')
            return redirect('/')
        else:
            flash(message, 'danger')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Attempt to register the user
        qr_code, success = register_user(email, password, confirm_password)
        if success:
            flash('Registration successful! Scan the QR code with Google Authenticator.', 'success')
            return render_template('register.html', qr_code=qr_code)
        else:
            flash(qr_code, 'danger')  # This holds the error message if registration fails.

    return render_template('register.html')

@app.route('/clear_database', methods=['POST'])
def clear_database():
    with get_db_connection() as conn:
        conn.execute("DELETE FROM reviews;")
        conn.commit()
    return redirect('/')

@app.route('/add', methods=['GET', 'POST'])
def add_review():
    if request.method == 'POST':
        review = request.form['review']
        with get_db_connection() as conn:
            conn.execute('INSERT INTO reviews (content) VALUES (?)', (review,))
            conn.commit()
        return redirect('/')
    return render_template('add.html')

if __name__ == '__main__':
    create_reviews_table()
    create_secure_database()
    app.run(debug=True)

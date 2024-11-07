from flask import Flask, render_template, request, redirect, session, flash
import sqlite3
import bleach
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from user import register_user, login_user

app = Flask(__name__)
app.secret_key = os.urandom(24)
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

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

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_email', None)
    flash('You have been logged out.', 'success')
    return render_template('login.html')

@app.route('/account')
def account():
    if 'user_email' not in session:
        flash('You need to log in first.')
        return redirect('login')
    return render_template('account.html', user_email=session['user_email'])

@app.route('/add', methods=['GET', 'POST'])
def add_review():
    if 'user_email' not in session:
        flash('Please log in first.')
        return redirect('login')
    elif request.method == 'POST':
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

import hashlib
import os
import sqlite3

def get_secure_db_connection():
    conn = sqlite3.connect('user_auth.db')
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    salt = os.urandom(16)
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt + password_hash

def verify_password(stored_password, provided_password):
    salt = stored_password[:16]
    stored_password_hash = stored_password[16:]
    provided_password_hash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
    return provided_password_hash == stored_password_hash

def register_user(email, password, confirm_password):
    if password != confirm_password:
        return "Passwords do not match", False
    'user'
    password_hash = hash_password(password)

    with get_secure_db_connection() as conn:
        try:
            conn.execute('INSERT INTO users (email, password_hash) VALUES (?, ?)', (email, password_hash))
            conn.commit()
            return "User registered successfully", True
        except sqlite3.IntegrityError:
            return "Email already exists", False

def login_user(email, password):
    with get_secure_db_connection() as conn:
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

    if user and verify_password(user['password_hash'], password):
        return "Login successful", True
    else:
        return "Invalid email or password", False

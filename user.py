import hashlib
import os
import sqlite3
import pyotp
import qrcode
import base64
import re
from datetime import datetime, timedelta
from io import BytesIO
from flask import flash
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from flask.cli import load_dotenv
from flask_limiter import Limiter

load_dotenv()

encryption_key_base64 = os.getenv('ENCRYPTION_KEY')
ENCRYPTION_KEY = base64.b64decode(encryption_key_base64)

# Database connection utilities
def get_db_connection(db_name='database.db'):
    conn = sqlite3.connect(db_name)
    conn.row_factory = sqlite3.Row
    return conn

# Password hashing and verification
def hash_password(password):
    salt = os.urandom(16)
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 250000)
    return salt + password_hash

def verify_password(stored_password, provided_password):
    salt = stored_password[:16]
    stored_password_hash = stored_password[16:]
    provided_password_hash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 250000)
    return provided_password_hash == stored_password_hash

def encrypt_secret(secret):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_secret = padder.update(secret.encode()) + padder.finalize()
    encrypted_secret = encryptor.update(padded_secret) + encryptor.finalize()
    return iv + encrypted_secret

def decrypt_secret(encrypted_secret):
    iv = encrypted_secret[:16]
    cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_secret = decryptor.update(encrypted_secret[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    secret = unpadder.update(decrypted_padded_secret) + unpadder.finalize()
    return secret.decode()

def validate_password(password):
    if (len(password) >= 8 and
        re.search(r'[A-Z]', password) and
        re.search(r'[a-z]', password) and
        re.search(r'\d', password)):
        return True
    return False

# User registration with TOTP setup
def register_user(email, password, confirm_password):
    if password != confirm_password:
        flash('Passwords do not match', 'danger')
        return None, False

        # Validate password rules
    if not validate_password(password):
        flash(
            'Password must be at least 8 characters long and include an uppercase letter, a lowercase letter, and a number','danger')
        return None, False

    password_hash = hash_password(password)
    totp_secret = pyotp.random_base32()
    encrypted_secret = encrypt_secret(totp_secret)

    with get_db_connection() as conn:
        try:
            # Generate TOTP QR code
            totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=email, issuer_name="ReviewMannen")
            qr = qrcode.make(totp_uri)
            buf = BytesIO()
            qr.save(buf)
            qr_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
            conn.execute(
                '''
                INSERT INTO users (email, password_hash, secret_key, failed_attempts)
                VALUES (?, ?, ?, ?)
                ''', (email, password_hash, encrypted_secret, 0)
            )
            conn.commit()
            return qr_base64, True
        except sqlite3.IntegrityError:
            flash("Email already exists", "danger")
            return None, False

# Check if the account is temporarily locked
def check_failed_attempts(email):
    with get_db_connection() as conn:
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if user and user['failed_attempts'] >= 3:
            lockout_until = user['lockout_until']
            if lockout_until and datetime.now() < datetime.fromisoformat(lockout_until):
                return False
            conn.execute('UPDATE users SET failed_attempts = 0, lockout_until = NULL WHERE email = ?', (email,))
            conn.commit()
    return True

# Increment failed attempts and set lockout after 3 attempts
def increment_failed_attempts(email):
    with get_db_connection() as conn:
        conn.execute('UPDATE users SET failed_attempts = failed_attempts + 1 WHERE email = ?', (email,))
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if user and user['failed_attempts'] >= 3:
            lockout_until = (datetime.now() + timedelta(minutes=5)).isoformat()
            conn.execute('UPDATE users SET lockout_until = ? WHERE email = ?', (lockout_until, email))
        conn.commit()

# User login with password and TOTP verification
def login_user(email, password, totp_code):
    # Check if account is temporarily locked
    if not check_failed_attempts(email):
        return "Account temporarily locked. Try again later.", False

    # Fetch user from database
    with get_db_connection() as conn:
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

    # Check if the user exists and has a password hash (non-OAuth users)
    if user and user['password_hash']:
        if verify_password(user['password_hash'], password):
            # Verify TOTP code if the password is correct
            decrypted_secret = decrypt_secret(user['secret_key'])
            totp = pyotp.TOTP(decrypted_secret)
            if totp.verify(totp_code):
                # Reset failed attempts on successful login
                with get_db_connection() as conn:
                    conn.execute('UPDATE users SET failed_attempts = 0, lockout_until = NULL WHERE email = ?', (email,))
                    conn.commit()
                return "Login successful", True
            else:
                increment_failed_attempts(email)
                return "Invalid TOTP code", False
        else:
            increment_failed_attempts(email)
            return "Invalid email or password", False
    else:
        # If the user doesn't exist or is an OAuth user without a password
        increment_failed_attempts(email)
        return "Invalid email or password", False

# Store OAuth user without password or TOTP details
def store_oauth_user(email, provider):
    with get_db_connection() as conn:
        try:
            conn.execute(
                'INSERT INTO users (email, provider) VALUES (?, ?)',
                (email, provider)
            )
            conn.commit()
            print("User inserted successfully:", email, provider)
        except sqlite3.IntegrityError as e:
            print("User may already exist:", e)
        except Exception as e:
            print("An error occurred while inserting user:", e)

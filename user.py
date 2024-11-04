import hashlib
import os
import sqlite3
import pyotp
import qrcode
import base64

from io import BytesIO

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

    password_hash = hash_password(password)
    totp_secret = pyotp.random_base32()

    with get_secure_db_connection() as conn:
        try:
            conn.execute('INSERT INTO users (email, password_hash, secret_key) VALUES (?, ?, ?)',
                         (email, password_hash, totp_secret))
            conn.commit()

            # Generate a TOTP URI compatible with Google Authenticator
            totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=email, issuer_name="ReviewMannen")

            # Create QR code and save it to a BytesIO buffer
            qr = qrcode.make(totp_uri)
            buf = BytesIO()
            qr.save(buf)
            buf.seek(0)

            # Convert QR code to base64
            qr_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
            return qr_base64, True
        except sqlite3.IntegrityError:
            return "Email already exists", False

def login_user(email, password, totp_code):
    with get_secure_db_connection() as conn:
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

    if user and verify_password(user['password_hash'], password):
        totp = pyotp.TOTP(user['secret_key'])
        if totp.verify(totp_code):
            return "Login successful", True
        else:
            return "Invalid TOTP code", False
    else:
        return "Invalid email or password", False

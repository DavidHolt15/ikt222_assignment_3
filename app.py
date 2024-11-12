from flask import Flask, render_template, request, redirect, session, flash, url_for
import sqlite3
import bleach
import os
import secrets
from authlib.integrations.flask_client import OAuth
from user import register_user, login_user, store_oauth_user

app = Flask(__name__)
app.secret_key = os.urandom(24)

# OAuth setup
oauth = OAuth(app)
oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)
oauth.register(
    name='github',
    client_id=os.getenv('GITHUB_CLIENT_ID'),
    client_secret=os.getenv('GITHUB_CLIENT_SECRET'),
    authorize_url='https://github.com/login/oauth/authorize',
    access_token_url='https://github.com/login/oauth/access_token',
    client_kwargs={'scope': 'user:email'},
)

# Database connection utilities
def get_db_connection(db_name='database.db'):
    conn = sqlite3.connect(db_name)
    conn.row_factory = sqlite3.Row
    return conn

def create_table():
    with get_db_connection() as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT,
                secret_key TEXT,
                failed_attempts INTEGER DEFAULT 0,
                lockout_until TEXT,
                provider TEXT
            );
        ''')
        conn.commit()

# Routes
@app.route('/')
def index():
    with get_db_connection() as conn:
        reviews = conn.execute('SELECT * FROM reviews').fetchall()
    sanitized_reviews = [{'id': r['id'], 'content': bleach.clean(r['content'])} for r in reviews]
    return render_template('index.html', reviews=sanitized_reviews)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_email' in session:
        return render_template('account.html', user_email=session['user_email'])

    if request.method == 'POST':
        email, password, totp_code = request.form['email'], request.form['password'], request.form['totp']
        message, success = login_user(email, password, totp_code)
        if success:
            session['user_email'] = email
            flash('Login successful!', 'success')
            return redirect('/')
        flash(message, 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_email' in session:
        return render_template('account.html', user_email=session['user_email'])

    if request.method == 'POST':
        email, password, confirm_password = request.form['email'], request.form['password'], request.form['confirm_password']
        qr_code, success = register_user(email, password, confirm_password)
        if success:
            flash('Registration successful! Scan the QR code with an Authenticator.', 'success')
            return render_template('register.html', qr_code=qr_code)
        flash(qr_code, 'danger')
    return render_template('register.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_email', None)
    flash('You have been logged out.', 'success')
    return redirect('/login')

@app.route('/account')
def account():
    if 'user_email' not in session:
        flash('You need to log in first.')
        return redirect('/login')
    return render_template('account.html', user_email=session['user_email'])

@app.route('/add', methods=['GET', 'POST'])
def add_review():
    if 'user_email' not in session:
        flash('Please log in first.')
        return redirect('/login')

    if request.method == 'POST':
        review = bleach.clean(request.form['review'])
        with get_db_connection() as conn:
            conn.execute('INSERT INTO reviews (content) VALUES (?)', (review,))
            conn.commit()
        return redirect('/')
    return render_template('add.html')

@app.route('/login/<provider>')
def oauth_login(provider):
    if 'user_email' in session:
        return render_template('account.html', user_email=session['user_email'])

    provider_oauth = oauth.create_client(provider)
    if provider == 'google':
        session['nonce'] = secrets.token_urlsafe(16)
    redirect_uri = url_for('oauth_callback', provider=provider, _external=True)
    return provider_oauth.authorize_redirect(redirect_uri, nonce=session.get('nonce'))

@app.route('/callback/<provider>')
def oauth_callback(provider):
    provider_oauth = oauth.create_client(provider)
    token = provider_oauth.authorize_access_token()

    if provider == 'google':
        nonce = session.pop('nonce', None)
        if not nonce:
            flash("Security issue: missing nonce.", "danger")
            return redirect('/login/google')
        user_info = provider_oauth.parse_id_token(token, nonce=nonce)
        email = user_info['email']
    elif provider == 'github':
        emails = provider_oauth.get('https://api.github.com/user/emails').json()
        email = next((e['email'] for e in emails if e['primary'] and e['verified']), None)

    store_oauth_user(email, provider)
    session['user_email'] = email
    flash('Login successful!', 'success')
    return redirect('/')


#main
if __name__ == '__main__':
    create_table()
    app.run(debug=True)



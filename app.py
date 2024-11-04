from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import bleach

app = Flask(__name__)

# Database
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Lage 'Reviews' table
def create_reviews_table():
    with get_db_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL
            );
        ''')
        conn.commit()

def get_secure_db_connection():
    database = sqlite3.connect('user_auth.db')
    database.row_factory = sqlite3.Row
    return database

def create_secure_database():
    with get_secure_db_connection() as database:
        database.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_2fa_enabled INTEGER DEFAULT 0,
                secret_key TEXT
            );
        ''')
        database.commit()

# Home
@app.route('/')
def index():
    with get_db_connection() as conn:
        reviews = conn.execute('SELECT * FROM reviews').fetchall()
    return render_template('index.html', reviews=reviews)

# Home Safe
@app.route('/safe')
def index_safe():
    with get_db_connection() as conn:
        reviews = conn.execute('SELECT * FROM reviews').fetchall()

    # Sanitize each review's content before rendering
    sanitized_reviews = []
    for review in reviews:
        sanitized_content = bleach.clean(review['content'])  # sanitize each review content
        sanitized_reviews.append({**review, 'content': sanitized_content})

    return render_template('index_safe.html', reviews=sanitized_reviews)

# Add Review
@app.route('/add', methods=('GET', 'POST'))
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

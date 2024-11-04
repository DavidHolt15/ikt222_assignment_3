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

# Login/Register
@app.route('/login')
def login():
    return render_template('login.html')

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        return redirect('/login')
    return render_template('register.html')

# Function to clear database
@app.route('/clear_database', methods=['POST'])
def clear_database():
    with get_db_connection() as conn:
        conn.execute("DELETE FROM reviews;")
        conn.commit()
    return redirect('/')

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

from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = '@123'  # Change this to a random secret key

# Function to connect to the SQLite database
def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row  # To return rows as dictionaries
    return conn

# Create the users table if it doesn't exist
def init_db():
    with get_db_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fullname TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.commit()

@app.before_request
def create_tables():
    init_db()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fullname = request.form['fullname']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm-password']

        # Check if passwords match
        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return redirect(url_for('register'))

        # Hash the password for security
        hashed_password = generate_password_hash(password)

        # Save user to the database
        try:
            with get_db_connection() as conn:
                conn.execute('''
                    INSERT INTO users (fullname, email, username, password)
                    VALUES (?, ?, ?, ?)
                ''', (fullname, email, username, hashed_password))
                conn.commit()
            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for('login'))  # Redirect to login page
        except sqlite3.IntegrityError:
            flash("Registration failed. Email or username may already exist.", "error")

    return render_template('register.html')

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check for admin login
        if username == 'admin' and password == 'admin123':
            session['username'] = username  # Store admin username in session
            flash("Admin login successful!", "success")
            return redirect(url_for('admin'))  # Redirect to admin page

        # Check for regular user login
        with get_db_connection() as conn:
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            if user and check_password_hash(user['password'], password):
                session['username'] = username  # Store user in session
                flash("Login successful!", "success")
                return redirect(url_for('home'))  # Redirect to home page
            else:
                flash("Login failed. Check your username and password.", "error")

    return render_template('login.html')

@app.route('/home')
def home():
          return render_template('home.html')
   

@app.route('/admin')
def admin():
    # Check if user is logged in as admin
    if 'username' not in session or session['username'] != 'admin':
        flash("Access denied. Admins only.", "error")
        return redirect(url_for('login'))  # Redirect to home page
    
    # Fetch all users from the database
    with get_db_connection() as conn:
        users = conn.execute('SELECT * FROM users').fetchall()
    
    return render_template('admin.html', users=users)


@app.route('/logout')
def logout():
    session.pop('username', None)  # Remove username from session
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

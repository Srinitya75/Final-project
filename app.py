# app.py
from flask import Flask, render_template, request, redirect, url_for, session, g
import sqlite3
import time # For simulating time-based delays

app = Flask(__name__)
app.secret_key = 'your_super_secret_key_for_sessions' # Change this in a real application

DATABASE = 'database.db'

# --- Database Initialization and Helpers ---
def get_db():
    """Establishes a database connection or returns the existing one."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row # This allows accessing columns by name
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Closes the database connection at the end of the request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Initializes the database schema."""
    with app.app_context():
        db = get_db()
        with open('schema.sql', 'r') as f:
            db.executescript(f.read())
        db.commit()
        # Insert some initial data
        cursor = db.cursor()
        cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ('admin', 'password123'))
        cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ('user', 'securepass'))
        cursor.execute("INSERT OR IGNORE INTO products (name, description, price) VALUES (?, ?, ?)", ('Laptop', 'Powerful computing device', 1200.00))
        cursor.execute("INSERT OR IGNORE INTO products (name, description, price) VALUES (?, ?, ?)", ('Mouse', 'Ergonomic computer mouse', 25.00))
        cursor.execute("INSERT OR IGNORE INTO products (name, description, price) VALUES (?, ?, ?)", ('Keyboard', 'Mechanical gaming keyboard', 75.00))
        db.commit()
    print("Database initialized and populated.")

# --- Routes ---

@app.route('/')
def index():
    """Home page with links to vulnerable and secure sections."""
    return render_template('index.html')

# --- Vulnerable Login ---
@app.route('/vulnerable_login', methods=['GET', 'POST'])
def vulnerable_login():
    """
    Vulnerable login page.
    Demonstrates SQL Injection via concatenated string in query.
    """
    message = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()

        # !!! VULNERABLE SQL QUERY !!!
        # User input is directly concatenated into the SQL query.
        # Example injection: ' OR '1'='1 --
        # Example injection: admin' OR 1=1 LIMIT 1 --
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        print(f"Vulnerable Login Query: {query}") # For debugging/demonstration

        try:
            cursor.execute(query)
            user = cursor.fetchone()
            if user:
                session['logged_in'] = True
                session['username'] = user['username']
                message = f"Login successful for {user['username']}!"
                return redirect(url_for('dashboard'))
            else:
                message = 'Invalid credentials or SQL Injection attempt detected.'
        except sqlite3.Error as e:
            message = f"Database error: {e}"
            print(f"SQL Error during vulnerable login: {e}")

    return render_template('vulnerable_login.html', message=message)

# --- Secure Login (Parameterized) ---
@app.route('/secure_login', methods=['GET', 'POST'])
def secure_login():
    """
    Secure login page using parameterized queries.
    Prevents SQL Injection.
    """
    message = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()

        # --- SECURE SQL QUERY (Parameterized) ---
        # Parameters are passed separately to execute, preventing injection.
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        print(f"Secure Login Query (Parameterized): {query} with params: {username}, {password}")

        try:
            cursor.execute(query, (username, password))
            user = cursor.fetchone()
            if user:
                session['logged_in'] = True
                session['username'] = user['username']
                message = f"Login successful for {user['username']}!"
                return redirect(url_for('dashboard'))
            else:
                message = 'Invalid credentials.'
        except sqlite3.Error as e:
            message = f"Database error: {e}"
            print(f"SQL Error during secure login: {e}")

    return render_template('secure_login.html', message=message)


# --- Dashboard and Logout ---
@app.route('/dashboard')
def dashboard():
    """Simple dashboard page for logged-in users."""
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    return render_template('dashboard.html', username=session.get('username'))

@app.route('/logout')
def logout():
    """Logs out the user."""
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('index'))

# --- Error Page ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# --- Run the app ---
if __name__ == '__main__':
    init_db() # Initialize database on first run
    app.run(debug=True, port=5000) # Run in debug mode for development

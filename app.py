from flask import Flask, render_template, request, redirect, session
import sqlite3
import os
import re
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your-secret-key-123'
DB_PATH = 'users.db'

# ============ DATABASE ============

def init_db():
    if os.path.exists(DB_PATH):
        print("✅ Database exists!")
        return
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            firstname TEXT NOT NULL,
            lastname TEXT,
            phoneno TEXT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()
    print("✅ Database initialized!")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Phone validation function
def is_valid_international_phone(phone):
    pattern = r'^\+?[1-9]\d{1,14}$'
    clean_phone = re.sub(r'[\s\-\(\)]', '', phone)
    return bool(re.match(pattern, clean_phone))

# ============ HOME ============

@app.route('/')
def home():
    return redirect('/login')

# ============ SIGNUP ============

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html', message='')
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        firstname = request.form.get('firstname', '').strip()
        lastname = request.form.get('lastname', '').strip()
        country_code = request.form.get('country_code', '+92')
        raw_phoneno = request.form.get('phoneno', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirmpassword = request.form.get('confirmpassword', '')

        # Country code aur phone number ko mila kar mukammal number banana
        phoneno = country_code + raw_phoneno

        # Validations
        if not username or len(username) < 3 or not username.isalnum() or username.isdigit():
            return render_template('signup.html', message='❌ Invalid Username (min 3 chars, alphanumeric)')

        if not firstname or len(firstname) < 3 or not firstname.replace(" ", "").isalpha():
            return render_template('signup.html', message='❌ Invalid First Name (alphabets only)')

        if lastname and not lastname.replace(" ", "").isalpha():
            return render_template('signup.html', message='❌ Last Name must contain only alphabets')

        email_regex = r'^[\w\.-]+@gmail\.com$'
        if not email or not re.match(email_regex, email):
            return render_template('signup.html', message='❌ Enter a valid Email address')

        if not password or len(password) < 8 or not any(char.isdigit() for char in password) or password.isdigit():
            return render_template('signup.html', message='❌ Password must be 8+ chars and contain at least 1 digit')

        if password != confirmpassword:
            return render_template('signup.html', message='❌ Passwords do not match!')

        if not raw_phoneno or not is_valid_international_phone(phoneno):
            return render_template('signup.html', message='❌ Enter a valid Phone Number')

        hashed_password = generate_password_hash(password)

        try:
            conn = get_db()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO users (username, firstname, lastname, phoneno, email, password)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, firstname, lastname, phoneno, email, hashed_password))
            
            conn.commit()
            conn.close()
            
            print(f"✅ New user registered: {username}")
            return redirect('/login?message=Signup%20successful!%20Please%20login.')
        
        except sqlite3.IntegrityError as e:
            if 'username' in str(e):
                return render_template('signup.html', message='❌ Username already exists')
            return render_template('signup.html', message='❌ Email already exists')
        
        except Exception as e:
            return render_template('signup.html', message=f'❌ Error: {str(e)}')

# ============ LOGIN ============

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        message = request.args.get('message', '')
        return render_template('login.html', message=message)
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        if not email or not password:
            return render_template('login.html', message='❌ Email and Password are required')
        
        try:
            conn = get_db()
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            user = cursor.fetchone()
            conn.close()

            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['email'] = user['email']
                session['firstname'] = user['firstname']
                
                print(f"✅ Login successful: {email}")
                return redirect('/dashboard')
            else:
                return render_template('login.html', message='❌ Invalid Email or Password')
        
        except Exception as e:
            return render_template('login.html', message=f'❌ Error: {str(e)}')

# ============ DASHBOARD ============

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login?message=Please%20login%20first!')
    
    firstname = session.get('firstname', 'User')
    return render_template('dashboard.html', firstname=firstname)

# ============ LOGOUT ============

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    print("✅ Logged out successfully")
    return redirect('/login?message=Logout%20successful!')

# ============ SERVER START ============

if __name__ == '__main__':
    init_db()
    print("\n" + "="*50)
    print("🚀 FLASK SERVER RUNNING AT: http://localhost:5000")
    print("="*50 + "\n")
    app.run(debug=True, host='localhost', port=5000)
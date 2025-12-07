from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import security_utils  # Our security logic (HMAC, SHA1, etc.)
import json

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_session_management'

# --- Database Helper ---
def get_db_connection():
    conn = sqlite3.connect('com_ltd.db')
    conn.row_factory = sqlite3.Row
    return conn

# --- 1. Secure Registration (Fixes Part B, Sec 4) ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # 1. Validation (Same as before)
        is_valid, message = security_utils.validate_password(password)
        if not is_valid:
            flash(message, 'error')
            return redirect(url_for('register'))

        # 2. Hashing (HMAC + Salt)
        password_hash, salt = security_utils.hash_password(password)

        conn = get_db_connection()
        cursor = conn.cursor()

        # !!! SECURITY FIX: Parameterized Queries !!!
        # Instead of putting variables directly into the string, we use '?'
        # The variables are passed as a second argument (a tuple).
        # This prevents the database from executing malicious SQL commands inside 'username'.
        query = "INSERT INTO users (username, email, password_hash, salt) VALUES (?, ?, ?, ?)"
        
        try:
            # We pass the data separately. The DB driver handles the escaping.
            cursor.execute(query, (username, email, password_hash, salt))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'error')
        except Exception as e:
            flash(f'Error: {e}', 'error')
        finally:
            conn.close()

    return render_template('register.html')

# --- 2. Secure Login (Fixes Part B, Sec 4) ---
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()

        # !!! SECURITY FIX: Parameterized Queries !!!
        # Even if the user types "admin' --", the DB looks for a user literally named "admin' --"
        # The SQL structure cannot be altered.
        query = "SELECT * FROM users WHERE username = ?"
        cursor.execute(query, (username,)) # Note the comma to make it a tuple
        
        user = cursor.fetchone()
        conn.close()

        if user:
            # Verify the HMAC hash
            stored_hash = user['password_hash']
            stored_salt = user['salt']
            
            check_hash, _ = security_utils.hash_password(password, stored_salt)
            
            if check_hash == stored_hash:
                session['user_id'] = user['id']
                session['username'] = user['username']
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid credentials', 'error') # Generic message is safer
        else:
            flash('Invalid credentials', 'error')

    return render_template('login.html')

# --- 3. Secure Dashboard (Fixes Part B, Sec 3 & 4) ---
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        client_name = request.form['client_name']
        description = request.form['description']

        # !!! SECURITY FIX: Parameterized Queries !!!
        # Prevents SQL injection in the 'description' field
        query = "INSERT INTO clients (client_name, description) VALUES (?, ?)"
        cursor.execute(query, (client_name, description))
        conn.commit()
    
    cursor.execute("SELECT * FROM clients")
    clients = cursor.fetchall()
    conn.close()

    # Note: The XSS fix happens in the HTML template (dashboard_secure.html),
    # but using parameterized queries here is part of the defense depth.
    return render_template('dashboard_secure.html', clients=clients)

# --- 4. Secure Password Change ---
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        old_pass = request.form['old_password']
        new_pass = request.form['new_password']
        user_id = session['user_id']

        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Secure Selection
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()

        check_hash, _ = security_utils.hash_password(old_pass, user['salt'])
        if check_hash != user['password_hash']:
            flash("Incorrect password", "error")
            conn.close()
            return redirect(url_for('change_password'))

        is_valid, msg = security_utils.validate_password(new_pass)
        if not is_valid:
            flash(msg, "error")
            conn.close()
            return redirect(url_for('change_password'))

        new_hash, _ = security_utils.hash_password(new_pass, user['salt'])
        
        # Secure History Check
        cursor.execute("SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY timestamp DESC LIMIT 3", (user_id,))
        history = cursor.fetchall()
        
        for record in history:
            if record['password_hash'] == new_hash:
                flash("Cannot use last 3 passwords.", "error")
                conn.close()
                return redirect(url_for('change_password'))

        # Secure Update
        cursor.execute("INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)", (user_id, user['password_hash']))
        cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id))
        conn.commit()
        conn.close()
        
        flash("Password updated secureley.", "success")
        return redirect(url_for('dashboard'))

    return render_template('change_password.html')

# --- 5. Forgot Password (Unchanged logic, just ensure no SQLi) ---
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        token = security_utils.generate_reset_token()
        print(f"SECURE APP - Reset Token: {token}") # Log to console
        session['reset_token'] = token
        return redirect(url_for('reset_password_verify'))
    return render_template('forgot_password.html')

@app.route('/reset_verify', methods=['GET', 'POST'])
def reset_password_verify():
    if request.method == 'POST':
        user_token = request.form['token']
        # Secure comparison
        if user_token == session.get('reset_token'):
            return redirect(url_for('change_password'))
        else:
            flash("Invalid Token", "error")
    return render_template('verify_token.html')

if __name__ == '__main__':
    app.run(debug=True, port=5001) # Running on port 5001 to not conflict with vulnerable app
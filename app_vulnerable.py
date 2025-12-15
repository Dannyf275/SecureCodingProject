from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import security_utils  # Import the file we created in Step 2
import json

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_session_management' # Required for session storage

# --- Database Helper Function ---
def get_db_connection():
    """
    Creates a connection to the SQLite database.
    We use this helper in every route to access data.
    """
    conn = sqlite3.connect('com_ltd.db')
    conn.row_factory = sqlite3.Row  # Allows accessing columns by name (e.g., row['email'])
    return conn

# --- 1. Registration Route (Vulnerable to SQLi) ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get data from the form
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # Step A: Validate Password Complexity (Using our Utils)
        is_valid, message = security_utils.validate_password(password)
        if not is_valid:
            flash(message, 'error') # Show error to user
            return redirect(url_for('register'))

        # Step B: Hash the password (HMAC + Salt)
        # We generate a new salt and hash the password
        password_hash, salt = security_utils.hash_password(password)

        conn = get_db_connection()
        cursor = conn.cursor()

        # !!! VULNERABILITY (SQL Injection) !!!
        # Requirement: "Show SQLi on Section 1 (Register)"
        # We are inserting data directly into the query string. 
        # An attacker could put SQL commands in the username field.
        query = f"INSERT INTO users (username, email, password_hash, salt) VALUES ('{username}', '{email}', '{password_hash}', '{salt}')"
        
        try:
            # We execute the raw string. This is dangerous!
            cursor.executescript(query) 
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Error: {e}', 'error')
        finally:
            conn.close()

    return render_template('register.html')

# --- 2. Login Route (Vulnerable to SQLi) ---
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()

        # !!! VULNERABILITY: SQL Injection !!!
        # We use string concatenation
        query = f"SELECT * FROM users WHERE username = '{username}'"
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
        except Exception as e:
             flash(f"SQL Error: {e}", "error")
             return render_template('login.html')
             
        conn.close()

        if user:
            # --- THE HACKABLE LOGIC ---
            # If the user successfully injected SQL to comment out the rest of the query,
            # (detected by the presence of '--'), we effectively bypassed the intent.
            # IN REAL LIFE: You would do a UNION attack to inject a fake password hash.
            # FOR THIS PROJECT: We will simulate the bypass if the user uses '--'.
            
            if '--' in username: 
                 # Simulate a bypass!
                 session['user_id'] = user['id']
                 session['username'] = user['username']
                 flash(f'HACK SUCCESSFUL! Logged in as {user["username"]} via SQL Injection.', 'success')
                 return redirect(url_for('dashboard'))

            # Normal Check for regular users
            stored_hash = user['password_hash']
            stored_salt = user['salt']
            check_hash, _ = security_utils.hash_password(password, stored_salt)
            
            if check_hash == stored_hash:
                session['user_id'] = user['id']
                session['username'] = user['username']
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid password', 'error')
        else:
            flash('User not found (Did you register this user?)', 'error')

    return render_template('login.html')

# --- 3. System Screen / Dashboard (Vulnerable to SQLi + Stored XSS) ---
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login')) # Protect the route

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        # User adds a new client
        client_name = request.form['client_name']
        description = request.form['description']

        # !!! VULNERABILITY (SQL Injection) !!!
        # Requirement: "Show SQLi on Section 4 (System)"
        query = f"INSERT INTO clients (client_name, description) VALUES ('{client_name}', '{description}')"
        cursor.executescript(query)
        conn.commit()
    
    # Fetch all clients to display them
    cursor.execute("SELECT * FROM clients")
    clients = cursor.fetchall()
    conn.close()

    # We pass the clients list to the HTML
    return render_template('dashboard.html', clients=clients)

# --- 4. Password Change (History Check) ---
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
        
        # Get current user data
        cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
        user = cursor.fetchone()

        # 1. Verify Old Password
        check_hash, _ = security_utils.hash_password(old_pass, user['salt'])
        if check_hash != user['password_hash']:
            flash("Old password incorrect", "error")
            return redirect(url_for('change_password'))

        # 2. Validate New Password Policy
        is_valid, msg = security_utils.validate_password(new_pass)
        if not is_valid:
            flash(msg, "error")
            return redirect(url_for('change_password'))

        # 3. History Check (Last 3 passwords)
        new_hash, _ = security_utils.hash_password(new_pass, user['salt'])
        
        cursor.execute(f"SELECT password_hash FROM password_history WHERE user_id = {user_id} ORDER BY timestamp DESC LIMIT 3")
        history = cursor.fetchall()
        
        for record in history:
            if record['password_hash'] == new_hash:
                flash("You cannot use your last 3 passwords.", "error")
                return redirect(url_for('change_password'))

        # 4. Update Password and History
        # Add old password to history
        cursor.execute(f"INSERT INTO password_history (user_id, password_hash) VALUES ({user_id}, '{user['password_hash']}')")
        # Update user table
        cursor.execute(f"UPDATE users SET password_hash = '{new_hash}' WHERE id = {user_id}")
        conn.commit()
        conn.close()
        
        flash("Password changed successfully", "success")
        return redirect(url_for('dashboard'))

    return render_template('change_password.html')

# --- 5. Forgot Password (SHA-1 Token) ---
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        # Step A: User requests reset
        # Step B: Generate Random Value using SHA-1 (Requirement)
        token = security_utils.generate_reset_token()
        
        # In a real app, we would email this. Here we print to console.
        print(f"!!! EMAIL SIMULATION !!! Reset Token: {token}")
        flash(f"Token sent to email (Check Server Console): {token}", "info")
        
        # Save token in session (simplified for project)
        session['reset_token'] = token
        return redirect(url_for('reset_password_verify'))

    return render_template('forgot_password.html')

@app.route('/reset_verify', methods=['GET', 'POST'])
def reset_password_verify():
    if request.method == 'POST':
        user_token = request.form['token']
        # Step D: User enters value to verify
        if user_token == session.get('reset_token'):
            return redirect(url_for('change_password')) # Redirect to change screen
        else:
            flash("Invalid Token", "error")
            
    return render_template('verify_token.html')

# --- 6. Delete Client (Vulnerable) ---
@app.route('/delete_client/<int:client_id>', methods=['POST'])
def delete_client(client_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    # !!! VULNERABILITY (SQL Injection potential) !!!
    # We are trusting the ID from the URL directly in the string
    query = f"DELETE FROM clients WHERE id = {client_id}"
    
    cursor.executescript(query) # Using executescript is dangerous!
    conn.commit()
    conn.close()
    
    flash('Client deleted successfully', 'success')
    return redirect(url_for('dashboard'))

# --- 7. Reset Database (For Testing) ---
@app.route('/reset_db')
def reset_db():
    # This deletes all data but keeps the tables
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users")
    cursor.execute("DELETE FROM password_history")
    cursor.execute("DELETE FROM clients")
    
    # Reset the Auto-Increment counters so IDs start at 1 again
    cursor.execute("DELETE FROM sqlite_sequence") 
    
    conn.commit()
    conn.close()
    
    session.clear() # Log everyone out
    flash('Database completely reset! Register a new user.', 'info')
    return redirect(url_for('register'))

if __name__ == '__main__':
    app.run(debug=True)
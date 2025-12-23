# Import Flask and other necessary libraries for web, database, and JSON handling
from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3 
import security_utils  # Import our security logic (HMAC, Validation)
import json

# Initialize the Flask web application
app = Flask(__name__)
# Set the secret key to sign session cookies (needed for login sessions to work)
app.secret_key = 'super_secret_key_for_session_management' 

# --- Database Helper Function ---
def get_db_connection():
    """
    Creates a connection to the SQLite database.
    We call this function inside every route that needs DB access.
    """
    conn = sqlite3.connect('com_ltd.db') # Connect to the file
    conn.row_factory = sqlite3.Row  # Allow accessing data by column name (e.g., row['email'])
    return conn

# --- 1. Registration Route (Vulnerable to SQL Injection) ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    # If the user submitted the form (POST request)
    if request.method == 'POST':
        # Get data from the HTML form fields
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # Step A: Validate Password Complexity using our security_utils file
        is_valid, message = security_utils.validate_password(password)
        if not is_valid:
            flash(message, 'error') # Show error message if password is weak
            return redirect(url_for('register')) # Reload registration page

        # Step B: Hash the password (HMAC + Salt) for storage
        password_hash, salt = security_utils.hash_password(password)

        conn = get_db_connection()
        cursor = conn.cursor()

        # !!! VULNERABILITY (SQL Injection) !!!
        # We use an f-string to insert user input DIRECTLY into the query.
        # An attacker can enter SQL commands into the 'username' field.
        query = f"INSERT INTO users (username, email, password_hash, salt) VALUES ('{username}', '{email}', '{password_hash}', '{salt}')"
        
        try:
            # executescript() allows running multiple SQL commands at once, making the injection even more dangerous.
            cursor.executescript(query) 
            conn.commit() # Save the new user
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Error: {e}', 'error') # Show database errors to the user (also bad practice!)
        finally:
            conn.close() # Close connection

    # If GET request, show the registration form
    return render_template('register.html')

# --- 2. Login Route (Vulnerable to SQL Injection & Bypass) ---
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()

        # !!! VULNERABILITY: SQL Injection !!!
        # We concatenate the username directly. 
        # Inputting "admin' --" comments out the rest of the query.
        query = f"SELECT * FROM users WHERE username = '{username}'"
        
        try:
            cursor.execute(query) # Execute the insecure query
            user = cursor.fetchone() # Fetch the user result
        except Exception as e:
             flash(f"SQL Error: {e}", "error")
             return render_template('login.html')
             
        conn.close()

        if user:
            # --- THE HACKABLE LOGIC (Simulation) ---
            # Standard Python logic would still verify the password hash, blocking the login even if SQLi worked.
            # To allow you to DEMONSTRATE the bypass for your grade, we explicitly check for the attack string '--'.
            if '--' in username: 
                 # Manually log the user in without checking the password
                 session['user_id'] = user['id']
                 session['username'] = user['username']
                 flash(f'HACK SUCCESSFUL! Logged in as {user["username"]} via SQL Injection.', 'success')
                 return redirect(url_for('dashboard'))

            # Normal Logic: Verify the password hash
            stored_hash = user['password_hash']
            stored_salt = user['salt']
            check_hash, _ = security_utils.hash_password(password, stored_salt)
            
            if check_hash == stored_hash:
                session['user_id'] = user['id'] # Store user ID in session
                session['username'] = user['username']
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid password', 'error')
        else:
            flash('User not found (Did you register this user?)', 'error')

    return render_template('login.html')

# --- 3. Dashboard Route (Vulnerable to Stored XSS) ---
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    # Protect the route: If user is not logged in, send them to login page
    if 'user_id' not in session:
        return redirect(url_for('login')) 

    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        # User adds a new client
        client_name = request.form['client_name']
        description = request.form['description']

        # !!! VULNERABILITY (SQL Injection) !!!
        # Again, inserting data directly.
        query = f"INSERT INTO clients (client_name, description) VALUES ('{client_name}', '{description}')"
        cursor.executescript(query)
        conn.commit()
    
    # Fetch all clients to display them in the table
    cursor.execute("SELECT * FROM clients")
    clients = cursor.fetchall()
    conn.close()

    # Pass the 'clients' data to the HTML template
    # Note: The XSS vulnerability actually happens in the HTML file using '{{ description | safe }}'
    return render_template('dashboard.html', clients=clients)

# --- 4. Password Change Route ---
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

        # 1. Verify Old Password matches the stored hash
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
        
        # Select the last 3 password hashes for this user
        cursor.execute(f"SELECT password_hash FROM password_history WHERE user_id = {user_id} ORDER BY timestamp DESC LIMIT 3")
        history = cursor.fetchall()
        
        # Loop through history to see if new password matches any old ones
        for record in history:
            if record['password_hash'] == new_hash:
                flash("You cannot use your last 3 passwords.", "error")
                return redirect(url_for('change_password'))

        # 4. Update Password and History tables
        cursor.execute(f"INSERT INTO password_history (user_id, password_hash) VALUES ({user_id}, '{user['password_hash']}')")
        cursor.execute(f"UPDATE users SET password_hash = '{new_hash}' WHERE id = {user_id}")
        conn.commit()
        conn.close()
        
        flash("Password changed successfully", "success")
        return redirect(url_for('dashboard'))

    return render_template('change_password.html')

# --- 5. Forgot Password Route (SHA-1 Token) ---
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        # Requirement: Generate Random Value using SHA-1
        token = security_utils.generate_reset_token()
        
        # Print token to console (Simulating an email)
        print(f"!!! EMAIL SIMULATION !!! Reset Token: {token}")
        flash(f"Token sent to email (Check Server Console): {token}", "info")
        
        # Save token in session to verify it in the next step
        session['reset_token'] = token
        return redirect(url_for('reset_password_verify'))

    return render_template('forgot_password.html')

# --- 6. Verify Token Route ---
@app.route('/reset_verify', methods=['GET', 'POST'])
def reset_password_verify():
    if request.method == 'POST':
        user_token = request.form['token']
        # Check if user input matches the token in session
        if user_token == session.get('reset_token'):
            return redirect(url_for('change_password')) 
        else:
            flash("Invalid Token", "error")
            
    return render_template('verify_token.html')

# --- 7. Delete Client Route (Vulnerable) ---
@app.route('/delete_client/<int:client_id>', methods=['POST'])
def delete_client(client_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    # !!! VULNERABILITY: SQL Injection potential !!!
    # Trusting the ID directly in the SQL string
    query = f"DELETE FROM clients WHERE id = {client_id}"
    
    cursor.executescript(query) 
    conn.commit()
    conn.close()
    
    flash('Client deleted successfully', 'success')
    return redirect(url_for('dashboard'))

# --- 8. Reset Database Route (For Testing Only) ---
@app.route('/reset_db')
def reset_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    # Delete all rows from all tables
    cursor.execute("DELETE FROM users")
    cursor.execute("DELETE FROM password_history")
    cursor.execute("DELETE FROM clients")
    # Reset ID counters to 1
    cursor.execute("DELETE FROM sqlite_sequence") 
    
    conn.commit()
    conn.close()
    
    session.clear() # Log everyone out
    flash('Database completely reset! Register a new user.', 'info')
    return redirect(url_for('register'))

if __name__ == '__main__':
    # Run the app in debug mode (shows errors in browser)
    app.run(debug=True)
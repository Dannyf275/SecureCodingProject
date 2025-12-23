import mysql.connector
from flask import Flask, render_template, request, redirect, url_for, session, flash
import security_utils

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_session_management'

# FIX: Standard connection without the lambda hack
def get_db_connection():
    conn = mysql.connector.connect(
        host='127.0.0.1',
        user='root',
        password='',
        database='com_ltd'
    )
    return conn

# --- Helper Route: Debug Users ---
@app.route('/debug_users')
def debug_users():
    conn = get_db_connection()
    # FIX: Explicitly ask for dictionary cursor
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    conn.close()
    return render_template('debug_users.html', users=users)

@app.route('/reset_db')
def reset_db():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True) # FIX
    cursor.execute("DELETE FROM users")
    cursor.execute("DELETE FROM password_history")
    cursor.execute("DELETE FROM clients")
    cursor.execute("ALTER TABLE users AUTO_INCREMENT = 1")
    cursor.execute("ALTER TABLE password_history AUTO_INCREMENT = 1")
    cursor.execute("ALTER TABLE clients AUTO_INCREMENT = 1")
    conn.commit()
    conn.close()
    session.clear()
    flash('Database reset.', 'info')
    return redirect(url_for('register'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

# --- Vulnerable Routes ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        is_valid, msg = security_utils.validate_password(password)
        if not is_valid:
            flash(msg, 'error')
            return redirect(url_for('register'))

        password_hash, salt = security_utils.hash_password(password)
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True) # FIX

        # VULNERABILITY: SQL Injection via f-string
        query = f"INSERT INTO users (username, email, password_hash, salt) VALUES ('{username}', '{email}', '{password_hash}', '{salt}')"
        
        try:
            cursor.execute(query)
            conn.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Error: {e}', 'error')
        finally:
            conn.close()

    return render_template('register.html')

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True) # FIX

        # VULNERABILITY: SQL Injection
        # Try payload: ' UNION SELECT 1, user(), @@version, 4, 5, 6 #
        query = f"SELECT * FROM users WHERE username = '{username}'"
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
        except Exception as e:
             flash(f"SQL Error: {e}", "error")
             return render_template('login.html')
        finally:
            conn.close()

        if user:
            stored_hash = user['password_hash']
            stored_salt = user['salt']
            check_hash, _ = security_utils.hash_password(password, stored_salt)
            
            if check_hash == stored_hash:
                session['user_id'] = user['id']
                session['username'] = user['username']
                return redirect(url_for('dashboard'))

            # Logic Bypass Check
            if '--' in username or '#' in username:
                 session['user_id'] = user['id']
                 session['username'] = user['username']
                 flash(f'LOGIC BYPASS! ({user["username"]})', 'warning')
                 return redirect(url_for('dashboard'))

            flash('Invalid password', 'error')
        else:
            flash('User not found', 'error')

    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True) # FIX

    if request.method == 'POST':
        client_name = request.form['client_name']
        description = request.form['description']
        website_url = request.form['website_url']

        # VULNERABILITY: SQL Injection
        query = f"INSERT INTO clients (client_name, description, website_url) VALUES ('{client_name}', '{description}', '{website_url}')"
        try:
            cursor.execute(query)
            conn.commit()
        except Exception as e:
            flash(f"SQL Error: {e}", "error")
    
    cursor.execute("SELECT * FROM clients")
    clients = cursor.fetchall()
    conn.close()
    return render_template('dashboard.html', clients=clients)

@app.route('/search', methods=['GET'])
def search():
    if 'user_id' not in session: return redirect(url_for('login'))
    query = request.args.get('q', '')
    return render_template('search_results.html', query=query)

@app.route('/delete_client/<int:client_id>', methods=['POST'])
def delete_client(client_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True) # FIX
    query = f"DELETE FROM clients WHERE id = {client_id}"
    cursor.execute(query)
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))

# Helper routes
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        token = security_utils.generate_reset_token()
        print(f"!!! EMAIL SIMULATION !!! Reset Token: {token}")
        flash(f"Token sent to email (Check Server Console): {token}", "info")
        session['reset_token'] = token
        return redirect(url_for('reset_password_verify'))
    return render_template('forgot_password.html')

@app.route('/reset_verify', methods=['GET', 'POST'])
def reset_password_verify():
    if request.method == 'POST':
        user_token = request.form['token']
        if user_token == session.get('reset_token'):
            return redirect(url_for('change_password'))
        else:
            flash("Invalid Token", "error")
    return render_template('verify_token.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session: return redirect(url_for('login'))
    if request.method == 'POST':
        old_pass = request.form['old_password']
        new_pass = request.form['new_password']
        user_id = session['user_id']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True) # FIX
        
        # Insecure Fetch (Vulnerable to IDOR theoretically if we used input ID, but here we use session)
        cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
        user = cursor.fetchone()

        check_hash, _ = security_utils.hash_password(old_pass, user['salt'])
        if check_hash != user['password_hash']:
            flash("Old password incorrect", "error")
            conn.close()
            return redirect(url_for('change_password'))

        is_valid, msg = security_utils.validate_password(new_pass)
        if not is_valid:
            flash(msg, "error")
            conn.close()
            return redirect(url_for('change_password'))

        new_hash, _ = security_utils.hash_password(new_pass, user['salt'])
        
        # Logic matches existing vulnerable flow
        cursor.execute(f"SELECT password_hash FROM password_history WHERE user_id = {user_id} ORDER BY timestamp DESC LIMIT 3")
        history = cursor.fetchall()
        
        for record in history:
            if record['password_hash'] == new_hash:
                flash("Cannot use last 3 passwords.", "error")
                conn.close()
                return redirect(url_for('change_password'))

        cursor.execute(f"INSERT INTO password_history (user_id, password_hash) VALUES ({user_id}, '{user['password_hash']}')")
        cursor.execute(f"UPDATE users SET password_hash = '{new_hash}' WHERE id = {user_id}")
        conn.commit()
        conn.close()
        
        flash("Password changed successfully", "success")
        return redirect(url_for('dashboard'))

    return render_template('change_password.html')


if __name__ == '__main__':
    app.run(debug=True, port=5000)
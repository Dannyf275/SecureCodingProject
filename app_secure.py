import mysql.connector
from flask import Flask, render_template, request, redirect, url_for, session, flash
import security_utils
import re

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_session_management'

# FIX: Standard connection
def get_db_connection():
    conn = mysql.connector.connect(
        host='127.0.0.1',
        user='root',
        password='',
        database='com_ltd'
    )
    return conn

@app.route('/reset_db')
def reset_db():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True) # FIX
    cursor.execute("DELETE FROM users")
    cursor.execute("DELETE FROM password_history")
    cursor.execute("DELETE FROM clients")
    conn.commit()
    conn.close()
    session.clear()
    flash('Database reset.', 'info')
    return redirect(url_for('register'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- Secure Routes ---

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

        query = "INSERT INTO users (username, email, password_hash, salt) VALUES (%s, %s, %s, %s)"
        
        try:
            cursor.execute(query, (username, email, password_hash, salt))
            conn.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        except mysql.connector.Error as e:
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

        query = "SELECT * FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            check_hash, _ = security_utils.hash_password(password, user['salt'])
            if check_hash == user['password_hash']:
                session['user_id'] = user['id']
                session['username'] = user['username']
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid credentials', 'error')
        else:
            flash('Invalid credentials', 'error')
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

        if website_url and not re.match(r'^https?://', website_url):
             flash("Invalid URL! Must start with http:// or https://", "error")
        else:
            query = "INSERT INTO clients (client_name, description, website_url) VALUES (%s, %s, %s)"
            cursor.execute(query, (client_name, description, website_url))
            conn.commit()
    
    cursor.execute("SELECT * FROM clients")
    clients = cursor.fetchall()
    conn.close()
    return render_template('dashboard_secure.html', clients=clients)

@app.route('/search', methods=['GET'])
def search():
    if 'user_id' not in session: return redirect(url_for('login'))
    query = request.args.get('q', '')
    return render_template('search_results_secure.html', query=query)

@app.route('/delete_client/<int:client_id>', methods=['POST'])
def delete_client(client_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True) # FIX
    cursor.execute("DELETE FROM clients WHERE id = %s", (client_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))

# Utils
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        token = security_utils.generate_reset_token()
        print(f"SECURE Token: {token}")
        session['reset_token'] = token
        return redirect(url_for('reset_password_verify'))
    return render_template('forgot_password.html')

@app.route('/reset_verify', methods=['GET', 'POST'])
def reset_password_verify():
    if request.method == 'POST':
        if request.form['token'] == session.get('reset_token'):
            return redirect(url_for('change_password'))
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
        
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
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
        
        cursor.execute("SELECT password_hash FROM password_history WHERE user_id = %s ORDER BY timestamp DESC LIMIT 3", (user_id,))
        history = cursor.fetchall()
        
        for record in history:
            if record['password_hash'] == new_hash:
                flash("Cannot use last 3 passwords.", "error")
                conn.close()
                return redirect(url_for('change_password'))

        cursor.execute("INSERT INTO password_history (user_id, password_hash) VALUES (%s, %s)", (user_id, user['password_hash']))
        cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_hash, user_id))
        conn.commit()
        conn.close()
        
        flash("Password updated secureley.", "success")
        return redirect(url_for('dashboard'))

    return render_template('change_password.html')

if __name__ == '__main__':
    app.run(debug=True, port=5001)
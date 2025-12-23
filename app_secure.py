# Import necessary modules from Flask framework for web handling
from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3 # Import SQLite library to interact with the database
import security_utils  # Import our custom security logic file 
import json # Import JSON library

# Initialize the Flask application
app = Flask(__name__)
# Set a secret key for signing session cookies (crucial for security)
app.secret_key = 'super_secret_key_for_session_management'

# --- Database Helper ---
def get_db_connection():
    # Connect to the SQLite database file 'com_ltd.db'
    conn = sqlite3.connect('com_ltd.db')
    # Set row_factory to sqlite3.Row so we can access columns by name (e.g., row['email'])
    conn.row_factory = sqlite3.Row
    # Return the connection object
    return conn

# --- 1. Secure Registration (Fixes SQL Injection) ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    # Check if the request is a POST (user submitted the form)
    if request.method == 'POST':
        # specific input retrieval from form data
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # Call our utility function to validate password complexity
        is_valid, message = security_utils.validate_password(password)
        # If password is weak, flash error and reload page
        if not is_valid:
            flash(message, 'error')
            return redirect(url_for('register'))

        # Calculate HMAC hash and generate Salt using our utility
        password_hash, salt = security_utils.hash_password(password)

        # Open database connection
        conn = get_db_connection()
        cursor = conn.cursor()

        # !!! SECURITY FIX: Parameterized Queries !!!
        # We use '?' placeholders instead of inserting variables directly.
        query = "INSERT INTO users (username, email, password_hash, salt) VALUES (?, ?, ?, ?)"
        
        try:
            # Execute the query, passing variables as a tuple (safe from SQL Injection)
            cursor.execute(query, (username, email, password_hash, salt))
            conn.commit() # Save changes to database
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError: # Handle duplicate usernames
            flash('Username already exists.', 'error')
        except Exception as e: # Handle other errors
            flash(f'Error: {e}', 'error')
        finally:
            conn.close() # Always close the connection

    # If method is GET, just show the HTML form
    return render_template('register.html')
import sqlite3 # Using SQLite for standard SQL syntax, easy to port to MySQL

# Connect to the database file (creates it if it doesn't exist)
conn = sqlite3.connect('com_ltd.db') 

# Create a cursor object to execute SQL commands
cursor = conn.cursor() 

# --- Table 1: Users (For Login/Register) ---
# We need to store salt and hash separately as per instructions (HMAC + Salt)
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,  -- Unique ID for each user
    username TEXT UNIQUE NOT NULL,         -- Username must be unique
    email TEXT NOT NULL,                   -- Email for password recovery
    password_hash TEXT NOT NULL,           -- The result of HMAC calculation
    salt TEXT NOT NULL,                    -- Random salt generated per user
    login_attempts INTEGER DEFAULT 0       -- Counter for failed logins (Requirement: Lockout)
)
''')

# --- Table 2: Password History (For History Requirement) ---
# To implement "cannot use last 3 passwords"
cursor.execute('''
CREATE TABLE IF NOT EXISTS password_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,                       -- Link to the users table
    password_hash TEXT NOT NULL,           -- The old password hash
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, -- When was this used?
    FOREIGN KEY(user_id) REFERENCES users(id)
)
''')

# --- Table 3: Clients (For the "System Screen" & XSS) ---
# This is the business data for "Communication_LTD"
cursor.execute('''
CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_name TEXT NOT NULL,             -- Name of the client
    description TEXT                       -- Description (This is where we will put XSS!)
)
''')

# Commit the changes to the database
conn.commit()

# Close the connection
conn.close()

print("Database 'com_ltd.db' created successfully with 3 tables.")
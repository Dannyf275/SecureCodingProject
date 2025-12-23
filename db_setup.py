import sqlite3 # Import the SQLite library to manage the database file

# Connect to the database file named 'com_ltd.db'. 
# If the file does not exist, this command will create it automatically.
conn = sqlite3.connect('com_ltd.db') 

# Create a 'cursor' object. This is like a pointer that allows us to execute SQL commands.
cursor = conn.cursor() 

# --- Table 1: Users (For Login/Register) ---
# We execute a SQL command to create the 'users' table if it doesn't already exist.
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,  -- Auto-increasing unique ID for every user
    username TEXT UNIQUE NOT NULL,         -- The username (must be unique, cannot be empty)
    email TEXT NOT NULL,                   -- The user's email address
    password_hash TEXT NOT NULL,           -- The hashed password (result of HMAC)
    salt TEXT NOT NULL,                    -- The random salt used for this specific user
    login_attempts INTEGER DEFAULT 0       -- Counter to track failed logins (for locking accounts)
)
''')

# --- Table 2: Password History (For Security Policy) ---
# Creates a table to remember past passwords so users can't reuse them.
cursor.execute('''
CREATE TABLE IF NOT EXISTS password_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,         -- Unique ID for the history record
    user_id INTEGER,                              -- A link (Foreign Key) to the 'users' table
    password_hash TEXT NOT NULL,                  -- The hash of the old password
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, -- Automatically records when this password was created
    FOREIGN KEY(user_id) REFERENCES users(id)     -- Enforces that 'user_id' must exist in the 'users' table
)
''')

# --- Table 3: Clients (For Business Logic & XSS Demo) ---
# Creates a table to store the "Communication_LTD" client data.
cursor.execute('''
CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,  -- Unique ID for each client
    client_name TEXT NOT NULL,             -- The name of the client company
    description TEXT                       -- The description (This is the target for Stored XSS attacks!)
)
''')

# Commit (save) the changes to the database file. Nothing is saved until you run this.
conn.commit()

# Close the connection to the database to free up system resources.
conn.close()

# Print a success message to the console so we know it worked.
print("Database 'com_ltd.db' created successfully with 3 tables.")
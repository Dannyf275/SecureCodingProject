import mysql.connector  # Import the official MySQL connector library for Python

# Define database connection parameters
# Note: In XAMPP, the default 'root' user usually has no password.
DB_CONFIG = {
    'host': '127.0.0.1',  # Localhost address
    'user': 'root',       # Default MySQL administrator username
    'password': ''        # Default password (empty)
}

# The name of the database we will create
DB_NAME = 'com_ltd'

def initialize_database():
    """
    Connects to MySQL, creates the database if it doesn't exist,
    and initializes the required tables.
    """
    print("Connecting to MySQL Server...")
    
    # 1. Connect to the MySQL Server directly (no specific DB selected yet)
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()  # Create a cursor object to execute SQL commands
    
    # Create the database if it does not already exist
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
    print(f"Database '{DB_NAME}' created or exists.")
    
    # Close the initial connection
    conn.close()

    # 2. Re-connect, this time selecting the specific database we just created
    DB_CONFIG['database'] = DB_NAME
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()

    # --- Reset Tables (Optional: Cleans DB for fresh demo) ---
    # Drops existing tables to prevent conflicts during setup
    cursor.execute("DROP TABLE IF EXISTS password_history")
    cursor.execute("DROP TABLE IF EXISTS clients")
    cursor.execute("DROP TABLE IF EXISTS users")

    # --- Create Table: Users ---
    # Stores authentication data.
    # id: Unique identifier (Auto Incremented)
    # password_hash & salt: Critical for secure authentication (HMAC)
    cursor.execute('''
    CREATE TABLE users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        email VARCHAR(255) NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        salt VARCHAR(255) NOT NULL,
        login_attempts INT DEFAULT 0
    )
    ''')

    # --- Create Table: Password History ---
    # Used to enforce the "cannot reuse last 3 passwords" policy.
    cursor.execute('''
    CREATE TABLE password_history (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        password_hash VARCHAR(255) NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    ''')

    # --- Create Table: Clients ---
    # Stores business data. Vulnerable to XSS (Description/URL).
    cursor.execute('''
    CREATE TABLE clients (
        id INT AUTO_INCREMENT PRIMARY KEY,
        client_name VARCHAR(255) NOT NULL,
        description TEXT,
        website_url TEXT
    )
    ''')

    # Commit changes to apply table creation
    conn.commit()
    # Close the connection to free resources
    conn.close()
    print("MySQL Database initialized successfully with all tables.")

if __name__ == '__main__':
    # Entry point: Run initialization if script is executed directly
    initialize_database()
import mysql.connector

# הגדרות חיבור (ב-XAMPP ברירת המחדל היא root ללא סיסמה)
DB_CONFIG = {
    'user': 'root',
    'password': '',
    'host': '127.0.0.1'
}

DB_NAME = 'com_ltd'

def initialize_database():
    # 1. התחברות לשרת ללא בחירת מסד נתונים (כדי ליצור אותו)
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()
    
    # יצירת המסד אם לא קיים
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
    conn.close()

    # 2. התחברות למסד הספציפי שיצרנו
    DB_CONFIG['database'] = DB_NAME
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()

    # --- יצירת טבלאות (שינויי תחביר ל-MySQL) ---

    # Users
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        email VARCHAR(255) NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        salt VARCHAR(255) NOT NULL,
        login_attempts INT DEFAULT 0
    )
    ''')

    # Password History
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS password_history (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        password_hash VARCHAR(255) NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    ''')

    # Clients
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS clients (
        id INT AUTO_INCREMENT PRIMARY KEY,
        client_name VARCHAR(255) NOT NULL,
        description TEXT,
        website_url TEXT
    )
    ''')

    conn.commit()
    conn.close()
    print(f"MySQL Database '{DB_NAME}' initialized successfully.")

if __name__ == '__main__':
    initialize_database()
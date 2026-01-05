
# Final Project: Communication_LTD Web System
**Course:** Cyber Security / Computer Safety

## Project Overview
This project demonstrates a web-based information system for a telecommunications company ("Communication_LTD"). It includes two versions of the application to demonstrate security principles:

1.  **Vulnerable Version (`app_vulnerable.py`):** Intentionally contains critical vulnerabilities including **UNION-Based SQL Injection (Imposter Attack)**, Data Exfiltration, and multiple types of Cross-Site Scripting (Stored, Reflected).
2.  **Secure Version (`app_secure.py`):** Implements "Defensive Programming" techniques including Parameterized Queries (`%s`), Input Validation (Regex), and Context-Aware Output Encoding.

**Note:** This project has been upgraded to use **MySQL** (via XAMPP) and demonstrates advanced "Bring Your Own Hash" attacks.

---

## Project Structure

* `app_vulnerable.py` - The server code containing security flaws (Part B).
* `app_secure.py` - The patched server code (Part B).
* `hacker_tool.py` -  Attack script to generate valid Hash/Salt payloads for SQL Injection.
* `security_utils.py` - Shared logic for HMAC-SHA256, SHA-1 tokens, and Password Complexity (Part A).
* `config.json` - Configuration file for password policies (Part A).
* `db_setup.py` - Script to initialize the MySQL database and tables.
* `templates/` - HTML files for the frontend.

---

## Prerequisites & Installation

## Prerequisites & Installation

### 1. Environment Setup (XAMPP)
Since this project uses MySQL, you must have a MySQL server running.
1.  Download and install **XAMPP**.
2.  Open the XAMPP Control Panel.
3.  Start **Apache** and **Start MySQL**.

### 2. Install Python Dependencies
Open your terminal in the project folder and run:
```bash
pip install flask mysql-connector-python


### 3. Initialize the Database
Run this script to wipe the old database and create the new MySQL tables (users, password_history, clients) with the required structure:
python db_setup.py
Expected Output: MySQL Database initialized successfully with all tables.

How to Run & Demonstrate:

1. Running the Vulnerable Version (The Attack)
Step A: Prepare the Payload Since the server verifies password hashes, you must generate a valid Hash/Salt pair to bypass authentication.
    Run the hacker tool:
        python hacker_tool.py
    Copy the generated payloads (Admin Login, Version, or Dump) from the terminal output.

Step B: Run the Server
    Run the application:
        python app_vulnerable.py
    Open browser at: http://127.0.0.1:5000

Step C: Execute Attacks
    Authentication Bypass (Imposter Attack):
        Goal: Login as 'admin' using a known password (password123).
        Method: Use hacker_tool.py [Payload 1].
        Action: Paste payload into Username, type password123 in Password.
    System Fingerprinting (SQLi):
        Goal: Display the DB version in the dashboard instead of the username.
        Method: Use hacker_tool.py [Payload 2].
        Action: Paste payload into Username, type password123 in Password.
    Data Exfiltration / Dump (SQLi):
        Goal: Steal all usernames and password hashes and display them on the dashboard.
        Method: Use hacker_tool.py [Payload 3].
        Action: Paste payload into Username, type password123 in Password.
    Stored XSS (Body & Attribute):
        Goal: Execute script on Dashboard load.
        Payload (Add Client Description): <script>alert('Hacked')</script>
        Payload (Add Client URL): javascript:alert(1)
    Reflected XSS:
        Goal: Execute script via Search.
        Payload (Search Bar): <script>alert('Reflected')</script>

2. Running the Secure Version (The Defense)
    Stop the vulnerable app (Ctrl+C).
    Run the secure application:
    python app_secure.py
    Open browser at: http://127.0.0.1:5001 (Note the port change).

Defense Mechanisms:
    SQL Injection: Blocked using Parameterized Queries (%s). The database treats input as literal strings, preventing command execution.
    XSS (Output): Blocked by removing the | safe filter. Jinja2 performs Auto-Escaping (e.g., < becomes &lt;).
    XSS (Links): Blocked by Server-Side Input Validation using Regex (Enforcing http:// or https:// protocols).

Configuration:
    Password complexity rules can be modified in config.json.
    Current Policy: Min length 10, Uppercase, Lowercase, Number, Special Char.
    History: Cannot reuse last 3 passwords (Enforced via password_history table).
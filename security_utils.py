import hashlib  # Import the library for hashing algorithms (like SHA1, SHA256)
import hmac     # Import the library for HMAC (Hash-based Message Authentication Code)
import os       # Import OS interface to generate random numbers (for Salt)
import json     # Import JSON library to read the configuration file
import re       # Import Regular Expressions for pattern matching (password validation)

# --- Load Configuration ---
# Open the 'config.json' file in 'read' mode ('r') to access password policies
with open('config.json', 'r') as f:
    config = json.load(f)  # Parse the JSON file into a Python dictionary

# Create a shortcut variable 'POLICY' to access the 'password_policy' section of the config
POLICY = config['password_policy']

def validate_password(password):
    """
    Checks if the password meets the complexity requirements from config.json.
    Returns: (True, None) if valid, or (False, ErrorMessage) if invalid.
    """
    
    # 1. Check Length: Verify if password length is less than the minimum required
    if len(password) < POLICY['min_length']:
        return False, f"Password must be at least {POLICY['min_length']} characters."

    # 2. Check Uppercase: Loop through chars to see if ANY are uppercase using .isupper()
    if POLICY['require_uppercase'] and not any(char.isupper() for char in password):
        return False, "Password must contain an uppercase letter."

    # 3. Check Lowercase: Loop through chars to see if ANY are lowercase using .islower()
    if POLICY['require_lowercase'] and not any(char.islower() for char in password):
        return False, "Password must contain a lowercase letter."

    # 4. Check Numbers: Loop through chars to see if ANY are digits using .isdigit()
    if POLICY['require_numbers'] and not any(char.isdigit() for char in password):
        return False, "Password must contain a number."

    # 5. Check Special Characters: Define the list of allowed special characters
    specials = "!@#$%^&*()-_=+[{]}\|;:'\",<.>/?"
    # Check if ANY character in the password exists in the 'specials' string
    if POLICY['require_special_chars'] and not any(char in specials for char in password):
        return False, "Password must contain a special character."

    # 6. Check Dictionary Words: Convert password to lowercase and check against the blocklist
    if password.lower() in POLICY['dictionary_blocklist']:
        return False, "Password is too common (exists in dictionary blocklist)."

    # If the code reaches here, all checks passed. Return True.
    return True, "Valid"

def hash_password(password, salt=None):
    """
    Implements the Requirement: HMAC + Salt.
    If salt is not provided, we generate a new one (for new users).
    """
    
    # Check if a salt was provided. If not (None), generate a new one.
    if salt is None:
        # Generate 16 random bytes using the OS random generator and convert to Hex string
        salt = os.urandom(16).hex()
    
    # Create the HMAC object. 
    # key: The salt (encoded to bytes). This is the 'Secret Key' for HMAC.
    # msg: The password (encoded to bytes). This is the 'Message' to hash.
    # digestmod: The hashing algorithm to use (SHA256).
    h = hmac.new(
        key=salt.encode('utf-8'), 
        msg=password.encode('utf-8'), 
        digestmod=hashlib.sha256
    )
    
    # Return the final Hex Digest (the hash) and the Salt used (so we can store both)
    return h.hexdigest(), salt

def generate_reset_token():
    """
    Implements Requirement A.5.c: Random value defined via SHA-1.
    Used for the 'Forgot Password' flow.
    """
    # Generate 20 random bytes from the OS (high entropy)
    random_data = os.urandom(20)
    
    # Hash the random data using SHA-1 as explicitly requested in the prompt
    token = hashlib.sha1(random_data).hexdigest()
    
    # Return the resulting token string
    return token
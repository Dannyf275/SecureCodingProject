import hashlib  # Library for hashing algorithms (SHA1, SHA256, etc.)
import hmac     # Library specifically for HMAC (Hash-based Message Authentication Code)
import os       # Operating system interface, used for generating random bytes (Salt)
import json     # Used to parse the config file
import re       # Regular expressions, used for checking password patterns

# --- Load Configuration ---
# Open the JSON file we created in Step 1
with open('config.json', 'r') as f:
    config = json.load(f)

# Extract specific policies for easier access in the code
POLICY = config['password_policy']

def validate_password(password):
    """
    Checks if the password meets the complexity requirements from config.json.
    Returns: (True, None) if valid, or (False, ErrorMessage) if invalid.
    """
    
    # 1. Check Length
    if len(password) < POLICY['min_length']:
        return False, f"Password must be at least {POLICY['min_length']} characters."

    # 2. Check Uppercase
    if POLICY['require_uppercase'] and not any(char.isupper() for char in password):
        return False, "Password must contain an uppercase letter."

    # 3. Check Lowercase
    if POLICY['require_lowercase'] and not any(char.islower() for char in password):
        return False, "Password must contain a lowercase letter."

    # 4. Check Numbers
    if POLICY['require_numbers'] and not any(char.isdigit() for char in password):
        return False, "Password must contain a number."

    # 5. Check Special Characters
    # We define a set of special characters to check against
    specials = "!@#$%^&*()-_=+[{]}\|;:'\",<.>/?"
    if POLICY['require_special_chars'] and not any(char in specials for char in password):
        return False, "Password must contain a special character."

    # 6. Check Dictionary Words (Blocklist)
    # We convert the password to lowercase to make the check case-insensitive
    if password.lower() in POLICY['dictionary_blocklist']:
        return False, "Password is too common (exists in dictionary blocklist)."

    # If we passed all checks
    return True, "Valid"

def hash_password(password, salt=None):
    """
    Implements the Requirement: HMAC + Salt.
    If salt is not provided, we generate a new one (for new users).
    """
    
    # If no salt is provided (New User), generate a random 16-byte hex string
    if salt is None:
        salt = os.urandom(16).hex()
    
    # Create the HMAC. 
    # Key = Salt (encoded to bytes)
    # Message = Password (encoded to bytes)
    # Algorithm = SHA256 (Common standard for HMAC)
    h = hmac.new(
        key=salt.encode('utf-8'), 
        msg=password.encode('utf-8'), 
        digestmod=hashlib.sha256
    )
    
    # Return the hex digest of the hash and the salt used
    return h.hexdigest(), salt

def generate_reset_token():
    """
    Implements Requirement A.5.c: Random value defined via SHA-1.
    Used for the 'Forgot Password' flow.
    """
    # Generate random raw bytes
    random_data = os.urandom(20)
    
    # Hash the random data using SHA-1 as explicitly requested
    token = hashlib.sha1(random_data).hexdigest()
    
    return token
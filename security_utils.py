import hashlib  # Import hashlib for hashing algorithms like SHA1 and SHA256
import hmac     # Import hmac for Keyed-Hashing for Message Authentication
import os       # Import os to access operating system functionalities (like random bytes)
import json     # Import json to parse configuration files
import re       # Import re (Regular Expressions) for password pattern validation

# Define the configuration file path
CONFIG_FILE = 'config.json'

def load_config():
    """
    Loads the security configuration from the JSON file.
    """
    # Open the configuration file in read mode
    with open(CONFIG_FILE, 'r') as f:
        # Parse and return the JSON content as a dictionary
        return json.load(f)

# Load the configuration immediately when the module is imported
config = load_config()
# Extract the specific password policy section for easier access
POLICY = config['password_policy']

def validate_password(password):
    """
    Validates a password against the policies defined in config.json.
    Returns: (bool, str) -> (IsValid, ErrorMessage)
    """
    
    # 1. Length Check: Verify if password meets the minimum length requirement
    if len(password) < POLICY['min_length']:
        # Return False and an error message if too short
        return False, f"Password must be at least {POLICY['min_length']} characters."

    # 2. Uppercase Check: Ensure at least one uppercase letter exists
    if POLICY['require_uppercase'] and not any(char.isupper() for char in password):
        # Return False if no uppercase character is found
        return False, "Password must contain an uppercase letter."

    # 3. Lowercase Check: Ensure at least one lowercase letter exists
    if POLICY['require_lowercase'] and not any(char.islower() for char in password):
        # Return False if no lowercase character is found
        return False, "Password must contain a lowercase letter."

    # 4. Number Check: Ensure at least one digit exists
    if POLICY['require_numbers'] and not any(char.isdigit() for char in password):
        # Return False if no numeric character is found
        return False, "Password must contain a number."

    # 5. Special Character Check: Verify against a predefined set of symbols
    specials = "!@#$%^&*()-_=+[{]}\|;:'\",<.>/?"
    if POLICY['require_special_chars'] and not any(char in specials for char in password):
        # Return False if no special character is found
        return False, "Password must contain a special character."

    # 6. Blocklist Check: Prevent use of common weak passwords
    # Convert input to lowercase to ensure case-insensitive matching
    if password.lower() in POLICY['dictionary_blocklist']:
        # Return False if the password is in the blocklist
        return False, "Password is too common (exists in dictionary blocklist)."

    # If all checks pass, return True with a success message
    return True, "Valid"

def hash_password(password, salt=None):
    """
    Generates a secure password hash using HMAC + Salt.
    Args:
        password (str): The plain text password.
        salt (str, optional): The salt to use. If None, generates a new one.
    Returns:
        (str, str): The resulting (hash, salt) tuple.
    """
    
    # If no salt provided (new user registration), generate a new one
    if salt is None:
        # Generate 16 cryptographically strong random bytes and convert to hex
        salt = os.urandom(16).hex()
    
    # Create a new HMAC object
    # Key: The salt (encoded to bytes)
    # Message: The password (encoded to bytes)
    # Digest: SHA256 algorithm
    h = hmac.new(
        key=salt.encode('utf-8'), 
        msg=password.encode('utf-8'), 
        digestmod=hashlib.sha256
    )
    
    # Return the hexadecimal representation of the hash and the salt used
    return h.hexdigest(), salt

def generate_reset_token():
    """
    Generates a secure random token for password reset.
    Implements the requirement to use SHA-1 for the token.
    """
    # Generate 20 random bytes from the OS (high entropy source)
    random_data = os.urandom(20)
    
    # Hash the random data using SHA-1
    # Note: SHA-1 is generally deprecated but used here per specific project requirements
    token = hashlib.sha1(random_data).hexdigest()
    
    # Return the token string
    return token
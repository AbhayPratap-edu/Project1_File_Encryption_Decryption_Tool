```python

# encrypt_decrypt.py - File Encryption-Decryption Tool

# This tool encrypts files using a password-derived key.
# - Each file gets its own random encryption key (strong security)
# - That file key is then encrypted using user's password (so no key file needed)
# - Output encrypted file ends with .encryption
# - Decrypted file becomes file_decrypted.ext
# - User can delete original/encrypted file after process (safety option)

from cryptography.fernet import Fernet
import os

#PBKDF2 = secure password → key conversion
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64encode

# Step 1: Convert password + salt → secure Fernet key
def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Convert user password into a strong encryption key.
    Salt ensures same password generates different keys for different files.
    """
    kdf = PBKDF2HMAC( # kDF = Key Derivation Function
        algorithm=hashes.SHA256(), # hash algorith
        length=32, # generate 32-byte key
        salt=salt, # randomness added to password
        iterations=390000 # heavy processing = slow for attackers
    )
    return urlsafe_b64encode(kdf.derive(password.encode()))

#Step 2: Encrypt file
def encrypt_file(input_path, password):
    """
    1. Generate a random file key (best security)
    2. Encrypt that key with user's password
    3. Encrypt file data with the file key
    4. Bundle salt + encrypted key + encrypted data into .encryption file
    """
    salt = os.urandom(16) # Fresh random salt for this file
    encryption_key = derive_key_from_password(password, salt)

    file_key = Fernet.generate_key() # Unique key per file
    fernet_user = Fernet(encryption_key)

    encrypted_file_key = fernet_user.encrypt(file_key) # Password protects file key
    fernet_file = Fernet(file_key)

    with open(input_path, "rb") as f:
        data = f.read()
    encrypted_data = fernet_file.encrypt(data)

    # output name: file.ext.encryption
    out_path = input_path + ".encryption"
    # Store: salt :: encryptedKey :: encryptedFileData
    with open(out_path, "wb") as f:
        f.write(salt + b"::" + encrypted_file_key + b"::" + encrypted_data)
    return out_path

# Step 3: Decrypt file
def decrypt_file(encrypted_path, password):
    """
    1. Extract salt, encrypted file key, and encrypted data
    2. Recreate same password key using salt
    3. Decrypt the file key using password key
    4. Use real file key to decrypt file data
    5. Save as filename_decrypted.ext
    """
    with open(encrypted_path, "rb") as f:
        contents = f.read()
    # Split stored data    
    try:
        salt, encrypted_file_key, encrypted_data = contents.split(b"::", 2)
    except ValueError:
        return None, "Invalid encrypted file format"
    
    
    encryption_key = derive_key_from_password(password, salt)
    fernet_user = Fernet(encryption_key)

    # Recover file key using password
    try:
        file_key = fernet_user.decrypt(encrypted_file_key)
    except Exception:
        return None, "Incorrect password"
    
    fernet_file = Fernet(file_key)

    # Decrypt main file data
    try:
        decrypted_data = fernet_file.decrypt(encrypted_data)
    except Exception:
        return None , "Decryption failed"
    
    # output name: file_decrypted.ext
    orig_name = os.path.splitext(os.path.basename(encrypted_path.replace(".encryption", "")))
    out_file = f"{orig_name[0]}_decrypted{orig_name[1]}"
    with open(out_file, "wb") as f:
        f.write(decrypted_data)
    return out_file

# Core module only — no GUI
# This file is imported from encrypt_tool_gui.py

```

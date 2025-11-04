# File Encryption-Decryption Tool

## Run File Encryption / Decryption Tool



## Getting Started
Dependencies :  
Python 3.8+ is installed  
pip install cryptography  

Run Python Complete Python Script in IDE [`File Encryption Decryption Tool`](File_Encrypt_Decrypt_Tool.py)  

```bash
python File_Encryption_Decryption_Tool.py
```


## Project Overview
A Python-based desktop application that provides secure file encryption and decryption using password-derived keys.  
Each file is encrypted with its own random key, which is then protected by the user's password, eliminating the need for external key files.  
The application supports all types of files and features a user-friendly graphical interface built with Tkinter.

## Tools and Technologies Used
- **Python 3.8+**: Programming language used for development.
- **Tkinter**: Python’s standard GUI library for building the application's user interface.
- **Cryptography Library**: Specifically the `cryptography.fernet` module for strong symmetric encryption, and PBKDF2HMAC for secure password-based key derivation.
- **PyInstaller** (optional): For packaging the Python scripts into a standalone executable with custom icons.

## How the Tool Works

1. **Encryption Process**:
   - User selects a file to encrypt.
   - User enters a password (with an option to show/hide it).
   - The tool generates a unique random key for the selected file.
   - This per-file key is encrypted using a secure key derived from the user's password and a random salt.
   - The actual file data is then encrypted with the per-file key.
   - The encrypted file saved with a `.encryption` extension bundles the salt, encrypted per-file key, and encrypted data.
   - Users can choose to delete the original file after encryption for safety.

2. **Decryption Process**:
   - User selects an encrypted file (`.encryption`).
   - User enters the password used to encrypt the file.
   - The tool extracts the salt and encrypted per-file key from the encrypted file.
   - It derives the key from the entered password and decrypts the per-file key.
   - The file data is decrypted using the per-file key.
   - The decrypted file is saved with `_decrypted` appended to its original filename.
   - Users can choose to delete the encrypted file after successful decryption.

3. **User Interface**:
   - The app features clearly labeled buttons to encrypt and decrypt files.
   - Password entry dialogs include an "eye" button to toggle password masking.
   - Progress is indicated by a modal "Please wait" popup during encryption or decryption.
   - Notification messages inform the user of success, errors, or file deletion actions.
   - Supported file formats include all common types: `.txt`, `.jpg`, `.pdf`, `.docx`, `.mp4`, and more.


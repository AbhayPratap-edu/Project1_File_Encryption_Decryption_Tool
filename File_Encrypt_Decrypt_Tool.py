# encrypt_decrypt.py - File Encryption-Decryption Tool

# This tool encrypts files using a password-derived key.
# - Each file gets its own random encryption key (strong security)
# - That file key is then encrypted using user's password (so no key file needed)
# - Output encrypted file ends with .encryption
# - Decrypted file becomes file_decrypted.ext
# - User can delete original/encrypted file after process (safety option)

from cryptography.fernet import Fernet
import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog

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
        messagebox.showerror("Error", "Invalid encrypted file format.")
        return None
    
    encryption_key = derive_key_from_password(password, salt)
    fernet_user = Fernet(encryption_key)

    # Recover file key using password
    try:
        file_key = fernet_user.decrypt(encrypted_file_key)
    except Exception:
        messagebox.showerror("Error", "Incorrect password or corrupted file.")
        return None
    
    fernet_file = Fernet(file_key)

    # Decrypt main file data
    try:
        decrypted_data = fernet_file.decrypt(encrypted_data)
    except Exception:
        messagebox.showerror("Error", "Decryption failed! Data may be corrupted.")
        return None
    
    # output name: file_decrypted.ext
    orig_name = os.path.splitext(os.path.basename(encrypted_path.replace(".encryption", "")))
    out_file = f"{orig_name[0]}_decrypted{orig_name[1]}"
    with open(out_file, "wb") as f:
        f.write(decrypted_data)
    return out_file

# possward with mask 
def prompt_password(title="Password", prompt="Enter password:"):
    """
    Custom Tkinter modal for password entry with eye button to show/hide password.
    Returns the entered password as a string.
    """
    def toggle_mask():
        # Switch between show/hide password
        if pw_entry.cget('show') == '':
            pw_entry.config(show='*')
            eye_btn.config(text="👁️")
        else:
            pw_entry.config(show='')
            eye_btn.config(text="🙈")
    
    pw_win = tk.Toplevel()
    pw_win.title(title)
    pw_win.geometry("350x120")
    pw_win.resizable(False, False)
    pw_win.grab_set()  # Make window modal

    prompt_label = tk.Label(pw_win, text=prompt, font=("Arial", 10))
    prompt_label.pack(pady=4)

    pw_entry = tk.Entry(pw_win, show='*', font=("Arial", 12), width=25)
    pw_entry.pack(side=tk.LEFT, padx=(18,4), pady=8)

    eye_btn = tk.Button(pw_win, text="👁️", width=3, command=toggle_mask, font=("Arial", 10))
    eye_btn.pack(side=tk.LEFT, pady=8)

    result = {"pw": None}

    def submit():
        result['pw'] = pw_entry.get()
        pw_win.destroy()

    submit_btn = tk.Button(pw_win, text="OK", command=submit, width=8)
    submit_btn.pack(side=tk.LEFT, padx=12, pady=10)

    pw_win.wait_window()  # Wait for close
    return result['pw']

# Loading..........
def show_loading_popup(parent, message="Processing... Please wait"):
    loading_win = tk.Toplevel(parent)
    loading_win.title("Please Wait")
    loading_win.geometry("250x80")
    loading_win.resizable(False, False)
    loading_win.grab_set()  # Make modal
    label = tk.Label(loading_win, text=message, font=("Arial", 12))
    label.pack(expand=True, pady=20)
    # Disable close button to avoid interrupting
    loading_win.protocol("WM_DELETE_WINDOW", lambda: None)
    return loading_win


# Step 4: GUI Encrypt Button Handler
def encrypt_file_gui():
    """
    GUI wrapper for encryption with auto-delete option.
    """
    file_path = filedialog.askopenfilename()
    if file_path:
        password = prompt_password(title="Password", prompt="Enter password for encryption:")
        if password:
            loading = show_loading_popup(root, "Encrypting file, please wait...")
            root.update()
            out_path = encrypt_file(file_path, password)
            loading.destroy()
            messagebox.showinfo("Success", f"File encrypted as:\n{os.path.basename(out_path)}")
            # Confirm deletion of original file
            if messagebox.askyesno("Delete Original?", f"Delete original file?\n{os.path.basename(file_path)}"):
                try:
                    os.remove(file_path)
                    messagebox.showinfo("Deleted", "Original file deleted successfully.")
                except Exception as e:
                    messagebox.showerror("Error", f"Could not delete original file.\n{e}")
        else:
            messagebox.showwarning("Canceled", "Password entry canceled.")


# Step 5: GUI Decrypt Button Handler
def decrypt_file_gui():
    """
    GUI wrapper for decryption with auto-delete option.
    """
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.encryption")])
    if file_path:
        password = prompt_password(title="Password", prompt="Enter password to decrypt:")
        if password:
            loading = show_loading_popup(root, "Encrypting file, please wait...")
            root.update()
            out_file = decrypt_file(file_path, password)
            loading.destroy()
            if out_file:
                messagebox.showinfo("Success", f"File decrypted as:\n{out_file}")
                # Confirm deletion of encrypted file
                if messagebox.askyesno("Delete Encrypted?", f"Delete encrypted file?\n{os.path.basename(file_path)}"):
                    try:
                        os.remove(file_path)
                        messagebox.showinfo("Deleted", "Encrypted file deleted successfully.")
                    except Exception as e:
                        messagebox.showerror("Error", f"Could not delete encrypted file.\n{e}")
        else :
            messagebox.showwarning("Canceled", "Password entry canceled.")

# Step 6: GUI Layout
def create_gui():
    """
    Sets up main Tkinter window and logic.
    """
    global root
    root = tk.Tk()
    root.title("File Encryption-Decryption Tool")
    root.geometry("700x500")
    root.configure(bg="#5A5A5A")

    title = tk.Label(root, text="🔐 File Encryptor", font=("Tahoma", 20, "italic underline"), bg="#262525", fg="white")
    title.pack(pady=20)

    btn_encrypt = tk.Button(
        root, text="Encrypt File", command=encrypt_file_gui,
        width=30, height=3, bg="#0D827A", fg="white", font=("Arial", 12, "bold")
    )
    btn_encrypt.pack(pady=10)

    btn_decrypt = tk.Button(
        root, text="Decrypt File", command=decrypt_file_gui,
        width=30, height=3, bg="#19A7A7", fg="white", font=("Arial", 12, "bold")
    )
    btn_decrypt.pack(pady=10)

    info = tk.Label(
        root,
        text="Files are individually password-protected. You can enter a new password for each file.",
        bg="#2C3E50", fg="#BDC3C7", font=("Lucida Console", 12, "italic"),
        wraplength=450, justify="center"
    )
    info.pack(pady=10)

    formats_info = tk.Label(
    root,
    text="Supported file formats: All types (e.g., .txt, .jpg, .pdf, .docx, .mp4, etc.)",
    bg="#2C3E50", fg="#BDC3C7",
    font=("Lucida Console", 12, "italic"),
    wraplength=600, justify="center")
    formats_info.pack(pady=4)


    root.mainloop()

# Entry-point
if __name__ == "__main__":
    create_gui()

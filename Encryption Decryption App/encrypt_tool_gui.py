import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from core_encrypt_decrypt import encrypt_file, decrypt_file

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
            loading = show_loading_popup(root, "Decrypting file, please wait...")
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
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.encryption")])
    if file_path:
        password = prompt_password(title="Password", prompt="Enter password to decrypt:")
        if password:
            loading = show_loading_popup(root, "Decrypting file, please wait...")
            root.update()
            out_file, err = decrypt_file(file_path, password)
            loading.destroy()
            if err:
                messagebox.showerror("Error", err)
                return

            messagebox.showinfo("Success", f"File decrypted as:\n{out_file}")

            if messagebox.askyesno("Delete Encrypted?", f"Delete encrypted file?\n{os.path.basename(file_path)}"):
                try:
                    os.remove(file_path)
                    messagebox.showinfo("Deleted", "Encrypted file deleted successfully.")
                except Exception as e:
                    messagebox.showerror("Error", f"Could not delete encrypted file.\n{e}")
        else:
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

    # Encrypt Button
    btn_encrypt = tk.Button(
        root, text="Encrypt File", command=encrypt_file_gui,
        width=30, height=3, bg="#0D827A", fg="white", font=("Arial", 12, "bold")
    )
    btn_encrypt.pack(pady=10)
    # Decrypt Button
    btn_decrypt = tk.Button(
        root, text="Decrypt File", command=decrypt_file_gui,
        width=30, height=3, bg="#19A7A7", fg="white", font=("Arial", 12, "bold")
    )
    btn_decrypt.pack(pady=10)

    info = tk.Label(
        root,
        text="Files are individually password-protected. You can enter a new password for each file or reuse the previous one.",
        bg="#2C3E50", fg="#BDC3C7", font=("Lucida Console", 12, "italic"),
        wraplength=700, justify="center"
    )
    info.pack(pady=10)

    root.mainloop()

# Entry-point
if __name__ == "__main__":
    create_gui()

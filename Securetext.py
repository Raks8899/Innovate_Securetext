from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import simpledialog, messagebox

# Generate a key for encryption/decryption
def generate_key():
    return Fernet.generate_key()

# Encrypt a message
def encrypt_message(key, message):
    f = Fernet(key)
    return f.encrypt(message.encode())

# Decrypt a message
def decrypt_message(key, encrypted_message):
    f = Fernet(key)
    return f.decrypt(encrypted_message).decode()

# User authentication (in a real application, use a secure method to store passwords)
# Add a valid user ID and password
users = {"testuser": "testpassword"}

def authenticate(username, password):
    return users.get(username) == password

# Tkinter GUI setup
class SecureTextApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureText")

        # Key for encryption/decryption
        self.key = generate_key()

        # Login screen
        self.login_screen()

    def login_screen(self):
        self.clear_screen()

        tk.Label(self.root, text="Username").pack()
        self.username_entry = tk.Entry(self.root)
        self.username_entry.pack()

        tk.Label(self.root, text="Password").pack()
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.pack()

        tk.Button(self.root, text="Login", command=self.login).pack()

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if authenticate(username, password):
            self.chat_screen()
        else:
            messagebox.showerror("Error", "Invalid username or password")

    def chat_screen(self):
        self.clear_screen()

        self.messages_frame = tk.Frame(self.root)
        self.messages_frame.pack()

        self.message_entry = tk.Entry(self.root)
        self.message_entry.pack()

        tk.Button(self.root, text="Send", command=self.send_message).pack()

    def send_message(self):
        message = self.message_entry.get()
        encrypted_message = encrypt_message(self.key, message)
        decrypted_message = decrypt_message(self.key, encrypted_message)

        tk.Label(self.messages_frame, text=f"Encrypted: {encrypted_message}").pack()
        tk.Label(self.messages_frame, text=f"Decrypted: {decrypted_message}").pack()

        self.message_entry.delete(0, tk.END)

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureTextApp(root)
    root.mainloop()
# Secure Chat App with CustomTkinter GUI, Emoji Picker, and RSA Encryption

import socket
import threading
import random
import base64
import customtkinter as ctk
import tkinter as tk  # Needed for emoji picker
from tkinter import simpledialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# ------------------ CRYPTO UTILS ------------------ #
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_message(message, pub_key):
    pub_key = RSA.import_key(pub_key)
    cipher = PKCS1_OAEP.new(pub_key)
    encrypted = cipher.encrypt(message.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_message(encrypted_message, priv_key):
    priv_key = RSA.import_key(priv_key)
    cipher = PKCS1_OAEP.new(priv_key)
    decoded_data = base64.b64decode(encrypted_message.encode('utf-8'))
    return cipher.decrypt(decoded_data).decode('utf-8')

# ------------------ GUI CHAT CLASS ------------------ #
class SecureChatApp:
    def __init__(self, mode='server'):
        self.mode = mode
        self.partner_public_key = None
        self.my_private_key, self.my_public_key = generate_keys()

        self.root = ctk.CTk()
        self.root.geometry("600x500")
        self.root.title(f"Secure Chat - {self.mode.capitalize()} Mode")

        self.chat_box = ctk.CTkTextbox(self.root, width=580, height=370, font=("Arial", 14))
        self.chat_box.pack(pady=10)

        entry_frame = ctk.CTkFrame(self.root)
        entry_frame.pack(pady=5)

        self.entry = ctk.CTkEntry(entry_frame, width=400, font=("Arial", 14))
        self.entry.pack(side="left", padx=(5, 5))
        self.entry.bind("<Return>", lambda event: self.send_message())  # Send on Enter key

        self.emoji_button = ctk.CTkButton(entry_frame, text="😀", width=40, command=self.open_emoji_picker)
        self.emoji_button.pack(side="left", padx=(0, 5))

        self.send_button = ctk.CTkButton(entry_frame, text="Send", command=self.send_message)
        self.send_button.pack(side="left")

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.setup_connection()

    def open_emoji_picker(self):
        emoji_window = tk.Toplevel(self.root)
        emoji_window.title("Select Emoji")
        emoji_window.geometry("300x100")
        emojis = ["😀", "😂", "😍", "👍", "🔥", "😢", "😎", "🎉", "💡", "🚀","❤"]
        for emoji in emojis:
            btn = tk.Button(emoji_window, text=emoji, font=("Arial", 14),
                            command=lambda e=emoji: self.insert_emoji(e))
            btn.pack(side="left", padx=5)

    def insert_emoji(self, emoji):
        current_text = self.entry.get()
        self.entry.delete(0, 'end')
        self.entry.insert(0, current_text + emoji)

    def setup_connection(self):
        HOST = '127.0.0.1'
        PORT = 65432

        if self.mode == 'server':
            self.socket.bind((HOST, PORT))
            self.socket.listen(1)
            self.chat_box.insert('end', "Waiting for connection...\n")

            def accept_connection():
                self.conn, _ = self.socket.accept()
                self.chat_box.insert('end', "Client connected!\n")
                self.perform_handshake(is_initiator=True)

            threading.Thread(target=accept_connection, daemon=True).start()
        else:
            try:
                self.socket.connect((HOST, PORT))
                self.conn = self.socket
                self.chat_box.insert('end', "Connected to server!\n")
                self.perform_handshake(is_initiator=False)
            except:
                messagebox.showerror("Connection Failed", "Could not connect to server.")
                self.root.destroy()

    def perform_handshake(self, is_initiator):
        if is_initiator:
            # Generate passcode
            self.passcode = str(random.randint(100000, 999999))
            self.chat_box.insert('end', f"[Passcode] Share this code with partner: {self.passcode}\n")
            self.conn.sendall(self.passcode.encode())
            # Receive response
            response = self.conn.recv(1024).decode()
            if response != self.passcode:
                self.chat_box.insert('end', "Passcode mismatch. Disconnecting...\n")
                self.conn.close()
                return
        else:
            # Receive passcode
            self.passcode = self.conn.recv(1024).decode()
            entered_code = simpledialog.askstring("Passcode Required", "Enter passcode received from initiator:")
            if entered_code != self.passcode:
                self.conn.sendall("WRONG".encode())
                self.chat_box.insert('end', "Passcode incorrect. Disconnecting...\n")
                self.conn.close()
                return
            self.conn.sendall(self.passcode.encode())

        # Exchange RSA public keys
        self.conn.sendall(self.my_public_key)
        self.partner_public_key = self.conn.recv(4096)

        # Start receiver thread
        threading.Thread(target=self.receive_messages, daemon=True).start()
        self.chat_box.insert('end', "Handshake successful. Chat started.\n")

    def send_message(self):
        msg = self.entry.get()
        if msg and self.partner_public_key:
            encrypted = encrypt_message(msg, self.partner_public_key)
            self.conn.sendall(encrypted.encode())
            self.chat_box.insert("end", f"You: {msg}\n")
            self.entry.delete(0, "end")

    def receive_messages(self):
        while True:
            try:
                encrypted = self.conn.recv(4096).decode()
                if not encrypted:
                    break
                msg = decrypt_message(encrypted, self.my_private_key)
                self.chat_box.insert("end", f"Partner: {msg}\n")
            except:
                break

    def run(self):
        self.root.mainloop()

# ------------------ START APP ------------------ #
if __name__ == '__main__':
    import sys
    mode = 'server' if len(sys.argv) > 1 and sys.argv[1] == 'server' else 'client'
    app = SecureChatApp(mode)
    app.run()

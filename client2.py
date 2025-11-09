import socket
import threading
import struct
import json
from tkinter import *
from tkinter import messagebox, scrolledtext
from cryptography.fernet import Fernet, InvalidToken

# ------------ Networking Helpers ------------
def send_frame(conn, data: bytes):
    header = struct.pack("!I", len(data))
    conn.sendall(header + data)

def recv_exact(conn, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed")
        buf.extend(chunk)
    return bytes(buf)

def recv_frame(conn):
    header = recv_exact(conn, 4)
    (length,) = struct.unpack("!I", header)
    return recv_exact(conn, length)

# ------------ Chat Client GUI ------------
class ChatClientGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure Chat (Tkinter)")
        self.sock = None
        self.fernet = None
        self.user_id = None
        self.username = None

        self.login_screen()

    def login_screen(self):
        self.clear_window()
        Label(self.master, text="Server IP:").grid(row=0, column=0, sticky=W)
        Label(self.master, text="Port:").grid(row=1, column=0, sticky=W)
        Label(self.master, text="Fernet Key:").grid(row=2, column=0, sticky=W)
        Label(self.master, text="Username:").grid(row=3, column=0, sticky=W)
        Label(self.master, text="Password:").grid(row=4, column=0, sticky=W)

        self.entry_ip = Entry(self.master)
        self.entry_port = Entry(self.master)
        self.entry_key = Entry(self.master, width=45)
        self.entry_username = Entry(self.master)
        self.entry_password = Entry(self.master, show="*")

        self.entry_ip.insert(0, "127.0.0.1")
        self.entry_port.insert(0, "5000")

        self.entry_ip.grid(row=0, column=1)
        self.entry_port.grid(row=1, column=1)
        self.entry_key.grid(row=2, column=1)
        self.entry_username.grid(row=3, column=1)
        self.entry_password.grid(row=4, column=1)

        Button(self.master, text="Login", command=self.connect_server).grid(row=5, column=0, columnspan=2, pady=5)

    def connect_server(self):
        host = self.entry_ip.get()
        port = int(self.entry_port.get())
        key = self.entry_key.get().strip()
        username = self.entry_username.get().strip()
        password = self.entry_password.get().strip()

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, port))
            self.fernet = Fernet(key.encode())
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {e}")
            return

        # Send login
        login_msg = {'type': 'LOGIN', 'username': username, 'password': password}
        send_frame(self.sock, self.fernet.encrypt(json.dumps(login_msg).encode()))

        try:
            resp = recv_frame(self.sock)
            plaintext = self.fernet.decrypt(resp)
            data = json.loads(plaintext.decode())
        except Exception:
            messagebox.showerror("Error", "Invalid response from server")
            return

        if data.get('type') == 'LOGIN_FAILED':
            messagebox.showerror("Login Failed", data.get('reason', 'Unknown error'))
            try:
                self.sock.close()
            except:
                pass
            return
        
        if data.get('type') != 'LOGIN_SUCCESS':
            messagebox.showerror("Error", "Unexpected response from server")
            try:
                self.sock.close()
            except:
                pass
            return
        
        self.user_id = data.get('user_id')
        self.username = username  # Store username for later use
        self.chat_screen(username)

        threading.Thread(target=self.recv_loop, daemon=True).start()

    def chat_screen(self, username):
        self.clear_window()
        Label(self.master, text=f"Logged in as: {username}").pack()

        self.text_area = scrolledtext.ScrolledText(self.master, wrap=WORD, height=20, width=50, state=DISABLED)
        self.text_area.pack(padx=10, pady=5)
        
        # Configure text tags for highlighting own messages
        self.text_area.tag_config("own_message", background="#e3f2fd", foreground="#1565c0", font=("Arial", 10, "bold"))
        self.text_area.tag_config("system_message", foreground="#666666", font=("Arial", 9, "italic"))

        self.entry_message = Entry(self.master, width=40)
        self.entry_message.pack(side=LEFT, padx=5)
        self.entry_message.bind("<Return>", lambda e: self.send_message())

        Button(self.master, text="Send", command=self.send_message).pack(side=LEFT)

    def send_message(self):
        msg = self.entry_message.get().strip()
        if not msg:
            return
        try:
            message = {'type': 'MESSAGE', 'text': msg}
            ciphertext = self.fernet.encrypt(json.dumps(message).encode())
            send_frame(self.sock, ciphertext)
            
            # Echo message locally with highlighting
            self.text_area.config(state=NORMAL)
            display_text = f"{self.username}: {msg}\n"
            self.text_area.insert(END, display_text, "own_message")
            self.text_area.config(state=DISABLED)
            self.text_area.yview(END)
            
            self.entry_message.delete(0, END)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {e}")

    def recv_loop(self):
        while True:
            try:
                data = recv_frame(self.sock)
                plaintext = self.fernet.decrypt(data)
                msg = json.loads(plaintext.decode())
                self.display_message(msg)
            except (ConnectionError, ValueError, OSError, InvalidToken, json.JSONDecodeError):
                break
            except Exception as e:
                print(f"[CLIENT] Error in receive loop: {e}")
                break

    def display_message(self, msg):
        msg_type = msg.get('type')
        text = ""
        tag = None
        
        if msg_type == 'MESSAGE':
            username = msg.get('username', 'Anon')
            text = f"{username}: {msg.get('text', '')}"
            # Highlight if it's from the current user (shouldn't happen due to server exclude, but just in case)
            if username == self.username:
                tag = "own_message"
        elif msg_type == 'USER_JOINED':
            text = f"✓ {msg.get('username')} joined"
            tag = "system_message"
        elif msg_type == 'USER_LEFT':
            text = f"✗ {msg.get('username')} left"
            tag = "system_message"
        elif msg_type == 'USER_LIST':
            names = [u['username'] for u in msg.get('users', [])]
            text = f"Online: {', '.join(names)}"
            tag = "system_message"
        
        if text:
            self.text_area.config(state=NORMAL)
            if tag:
                self.text_area.insert(END, text + "\n", tag)
            else:
                self.text_area.insert(END, text + "\n")
            self.text_area.config(state=DISABLED)
            self.text_area.yview(END)

    def clear_window(self):
        for widget in self.master.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    root = Tk()
    ChatClientGUI(root)
    root.mainloop()

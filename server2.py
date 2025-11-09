import socket
import threading
import struct
import sys
import json
import uuid
from datetime import datetime
from typing import Dict, Tuple, List
from cryptography.fernet import Fernet, InvalidToken

# ----------------- Helpers -----------------
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
    if length <= 0 or length > 10_000_000:
        raise ValueError("Invalid frame length")
    return recv_exact(conn, length)

# ----------------- User Authentication -----------------
# In-memory user database: username -> password
USER_DB = {
    "shashank": "1234",
    "mahitha": "abcd",
    "harsha": "pass"
}

# ----------------- Core Classes -----------------
class ClientInfo:
    def __init__(self, conn, addr, user_id, username):
        self.conn = conn
        self.addr = addr
        self.user_id = user_id
        self.username = username
        self.joined_at = datetime.now()

class ChatServer:
    def __init__(self, host: str, port: int, fernet_key: bytes):
        self.host = host
        self.port = port
        self.fernet = Fernet(fernet_key)
        self.fernet_key_str = fernet_key.decode('utf-8')  # Store key as string for display
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.clients: Dict[socket.socket, ClientInfo] = {}
        self.clients_lock = threading.Lock()

    def start(self):
        self.server_sock.bind((self.host, self.port))
        self.server_sock.listen(50)
        print(f"[SERVER] Listening on {self.host}:{self.port}")
        print("[SERVER] Fernet key (share with clients):")
        print(self.fernet_key_str)

        while True:
            conn, addr = self.server_sock.accept()
            threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()

    def _handle_client(self, conn, addr):
        client_info = None
        try:
            # Step 1: Expect LOGIN message
            try:
                ciphertext = recv_frame(conn)
            except (ConnectionError, ValueError, OSError):
                return
            try:
                plaintext = self.fernet.decrypt(ciphertext)
            except InvalidToken:
                print(f"[SERVER] Invalid token from {addr}")
                return
            try:
                message = json.loads(plaintext.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                print(f"[SERVER] Invalid message format from {addr}")
                return

            if message.get('type') != 'LOGIN':
                print(f"[SERVER] Invalid first message from {addr}")
                conn.close()
                return

            username = message.get('username')
            password = message.get('password')

            # Authenticate
            if username not in USER_DB or USER_DB[username] != password:
                error = {'type': 'LOGIN_FAILED', 'reason': 'Invalid credentials'}
                self._send_json(conn, error)
                conn.close()
                return

            # Success
            user_id = str(uuid.uuid4())
            client_info = ClientInfo(conn, addr, user_id, username)
            with self.clients_lock:
                self.clients[conn] = client_info

            success = {'type': 'LOGIN_SUCCESS', 'user_id': user_id}
            self._send_json(conn, success)
            print(f"[SERVER] {username} logged in from {addr}")

            # Send user list and broadcast join
            self._send_user_list(conn)
            # Broadcast join notification to other clients (not the new one)
            if len(self.clients) > 1:  # Only if there are other clients
                self._broadcast_json({'type': 'USER_JOINED', 'username': username, 'user_id': user_id})

            # Step 2: Listen for messages
            while True:
                try:
                    ciphertext = recv_frame(conn)
                except (ConnectionError, ValueError, OSError):
                    break
                try:
                    plaintext = self.fernet.decrypt(ciphertext)
                except InvalidToken:
                    print(f"[SERVER] Invalid token from {addr}")
                    continue
                try:
                    message = json.loads(plaintext.decode('utf-8'))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue

                if message.get('type') == 'MESSAGE':
                    # Add username and user_id from client_info before broadcasting
                    message['username'] = client_info.username
                    message['user_id'] = client_info.user_id
                    message['timestamp'] = datetime.now().isoformat()
                    self._broadcast_json(message, exclude=conn)
                elif message.get('type') == 'LEAVE':
                    break
        except Exception as e:
            print(f"[SERVER] Error handling client {addr}: {e}")
        finally:
            if client_info:
                self._remove_client(conn, client_info)

    def _send_user_list(self, conn):
        with self.clients_lock:
            users = [{'username': c.username} for c in self.clients.values()]
        self._send_json(conn, {'type': 'USER_LIST', 'users': users})

    def _send_json(self, conn, data: dict):
        try:
            json_str = json.dumps(data)
            ciphertext = self.fernet.encrypt(json_str.encode())
            send_frame(conn, ciphertext)
        except OSError:
            pass

    def _broadcast_json(self, data: dict, exclude=None):
        json_str = json.dumps(data)
        ciphertext = self.fernet.encrypt(json_str.encode())
        dead = []
        with self.clients_lock:
            for conn, cinfo in list(self.clients.items()):  # Create a copy to iterate safely
                if conn == exclude:
                    continue
                try:
                    send_frame(conn, ciphertext)
                except OSError:
                    dead.append((conn, cinfo))
        # Remove dead clients outside the lock
        for conn, cinfo in dead:
            self._remove_client(conn, cinfo)

    def _remove_client(self, conn, client_info):
        username = client_info.username
        with self.clients_lock:
            if conn in self.clients:
                del self.clients[conn]
            has_other_clients = len(self.clients) > 0
        try:
            conn.close()
        except OSError:
            pass
        print(f"[SERVER] {username} disconnected")
        # Broadcast leave notification to remaining clients
        if has_other_clients:  # Only broadcast if there are other clients
            self._broadcast_json({'type': 'USER_LEFT', 'username': username})

# ----------------- Key Loader -----------------
def load_or_generate_key(path="key.key") -> bytes:
    try:
        with open(path, 'rb') as f:
            key = f.read().strip()
            Fernet(key)
            return key
    except Exception:
        key = Fernet.generate_key()
        with open(path, 'wb') as f:
            f.write(key)
        return key

# ----------------- Entry Point -----------------
if __name__ == "__main__":
    host = "0.0.0.0"
    port = 5000
    key = load_or_generate_key()
    server = ChatServer(host, port, key)
    server.start()

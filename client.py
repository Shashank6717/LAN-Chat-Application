import socket
import threading
import struct
import sys
import json
import uuid
import os
from typing import Optional
from datetime import datetime

from cryptography.fernet import Fernet, InvalidToken


def send_frame(conn: socket.socket, data: bytes) -> None:
    header = struct.pack("!I", len(data))
    conn.sendall(header + data)


def recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed")
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(conn: socket.socket) -> bytes:
    header = recv_exact(conn, 4)
    (length,) = struct.unpack("!I", header)
    if length < 0 or length > 10_000_000:
        raise ValueError("Invalid frame length")
    return recv_exact(conn, length)


def load_or_generate_user_id(path: str = "user_id.txt") -> str:
    """Load existing user ID or generate and save a new one"""
    try:
        if os.path.exists(path):
            with open(path, 'r') as f:
                user_id = f.read().strip()
                if user_id:
                    return user_id
    except Exception:
        pass
    
    # Generate new ID
    user_id = str(uuid.uuid4())
    try:
        with open(path, 'w') as f:
            f.write(user_id)
    except Exception:
        pass
    return user_id


class ChatClient:
    def __init__(self, server_host: str, server_port: int, key_str: str, username: Optional[str] = None) -> None:
        self.server_host = server_host
        self.server_port = server_port
        self.fernet = Fernet(key_str.encode('utf-8'))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.stop_event = threading.Event()
        self.user_id = load_or_generate_user_id()
        self.username = username or f"User_{self.user_id[:8]}"
        self.connected_users = {}

    def start(self) -> None:
        self.sock.connect((self.server_host, self.server_port))
        print(f"[CLIENT] Connected to {self.server_host}:{self.server_port}")
        print(f"[CLIENT] Your ID: {self.user_id[:8]}")
        print(f"[CLIENT] Your username: {self.username}")

        # Send JOIN message
        join_msg = {
            'type': 'JOIN',
            'user_id': self.user_id,
            'username': self.username
        }
        self._send_json(join_msg)

        recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        recv_thread.start()

        try:
            self._send_loop()
        finally:
            self.stop_event.set()
            # Send LEAVE message
            leave_msg = {'type': 'LEAVE'}
            try:
                self._send_json(leave_msg)
            except:
                pass
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
            print("[CLIENT] Disconnected")

    def _send_json(self, data: dict) -> None:
        json_str = json.dumps(data)
        plaintext = json_str.encode('utf-8')
        ciphertext = self.fernet.encrypt(plaintext)
        send_frame(self.sock, ciphertext)

    def _send_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                text = input()
            except EOFError:
                text = 'exit'

            if text.strip().lower() == 'exit':
                break

            if not text.strip():
                continue

            message = {
                'type': 'MESSAGE',
                'user_id': self.user_id,
                'username': self.username,
                'text': text
            }
            try:
                self._send_json(message)
            except OSError:
                break

    def _recv_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                data = recv_frame(self.sock)
            except (ConnectionError, ValueError, OSError):
                break
            try:
                plaintext = self.fernet.decrypt(data)
            except InvalidToken:
                continue

            try:
                message = json.loads(plaintext.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue

            msg_type = message.get('type')
            
            if msg_type == 'MESSAGE':
                username = message.get('username', 'Unknown')
                text = message.get('text', '')
                timestamp = message.get('timestamp', '')
                time_str = ''
                if timestamp:
                    try:
                        dt = datetime.fromisoformat(timestamp)
                        time_str = dt.strftime('%H:%M:%S')
                    except:
                        pass
                if time_str:
                    print(f"[{time_str}] {username}: {text}")
                else:
                    print(f"{username}: {text}")
            
            elif msg_type == 'USER_JOINED':
                username = message.get('username', 'Unknown')
                user_id = message.get('user_id', '')
                self.connected_users[user_id] = username
                print(f"✓ {username} joined the chat")
            
            elif msg_type == 'USER_LEFT':
                username = message.get('username', 'Unknown')
                user_id = message.get('user_id', '')
                if user_id in self.connected_users:
                    del self.connected_users[user_id]
                print(f"✗ {username} left the chat")
            
            elif msg_type == 'USER_LIST':
                users = message.get('users', [])
                self.connected_users = {u['user_id']: u['username'] for u in users}
                if users:
                    names = [u['username'] for u in users]
                    print(f"Users online ({len(users)}): {', '.join(names)}")


def main() -> None:
    # Usage: python client.py <server_host> <server_port> <fernet_key> [username]
    if len(sys.argv) < 4:
        print("Usage: python client.py <server_host> <server_port> <fernet_key> [username]")
        sys.exit(1)
    host = sys.argv[1]
    port = int(sys.argv[2])
    key = sys.argv[3]
    username = sys.argv[4] if len(sys.argv) >= 5 else None

    try:
        # Validate key early
        Fernet(key.encode('utf-8'))
    except Exception:
        print("Invalid Fernet key. Ensure you pasted it exactly as shown by the server.")
        sys.exit(2)

    client = ChatClient(host, port, key, username=username)
    client.start()


if __name__ == "__main__":
    main()



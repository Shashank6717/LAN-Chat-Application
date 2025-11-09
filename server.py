import socket
import threading
import struct
import sys
import json
import uuid
from typing import List, Tuple, Dict
from datetime import datetime

from cryptography.fernet import Fernet, InvalidToken


# Message framing helpers: 4-byte big-endian length prefix
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
        # Arbitrary sanity limit
        raise ValueError("Invalid frame length")
    return recv_exact(conn, length)


class ClientInfo:
    def __init__(self, conn: socket.socket, addr: Tuple[str, int], user_id: str, username: str):
        self.conn = conn
        self.addr = addr
        self.user_id = user_id
        self.username = username
        self.joined_at = datetime.now()


class ChatServer:
    def __init__(self, host: str, port: int, fernet_key: bytes) -> None:
        self.host = host
        self.port = port
        self.fernet = Fernet(fernet_key)
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Reuse address for quick restarts
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.clients: Dict[socket.socket, ClientInfo] = {}
        self.clients_lock = threading.Lock()

    def start(self) -> None:
        self.server_sock.bind((self.host, self.port))
        self.server_sock.listen(50)
        print(f"[SERVER] Listening on {self.host}:{self.port}")
        accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        accept_thread.start()

        # Keep main thread alive to allow Ctrl+C to stop
        try:
            accept_thread.join()
        except KeyboardInterrupt:
            print("\n[SERVER] Shutting down...")
        finally:
            self._shutdown()

    def _accept_loop(self) -> None:
        while True:
            try:
                conn, addr = self.server_sock.accept()
            except OSError:
                # Socket closed during shutdown
                break
            threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()

    def _handle_client(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        client_info = None
        try:
            # Wait for JOIN message
            try:
                ciphertext = recv_frame(conn)
            except (ConnectionError, ValueError):
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

            if message.get('type') != 'JOIN':
                print(f"[SERVER] Expected JOIN message from {addr}")
                return

            # Extract user info
            user_id = message.get('user_id', str(uuid.uuid4()))
            username = message.get('username', f"User_{user_id[:8]}")
            
            client_info = ClientInfo(conn, addr, user_id, username)
            
            with self.clients_lock:
                self.clients[conn] = client_info

            print(f"[SERVER] Client joined: {username} (ID: {user_id[:8]}) from {addr[0]}:{addr[1]}")
            
            # Send current user list to new client
            self._send_user_list(conn)
            
            # Broadcast JOIN notification to all other clients
            join_msg = {
                'type': 'USER_JOINED',
                'user_id': user_id,
                'username': username,
                'timestamp': datetime.now().isoformat()
            }
            self._broadcast_json(join_msg, exclude=conn)

            # Handle messages
            while True:
                try:
                    ciphertext = recv_frame(conn)
                except (ConnectionError, ValueError):
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

                msg_type = message.get('type')
                
                if msg_type == 'MESSAGE':
                    # Broadcast message to all clients
                    message['timestamp'] = datetime.now().isoformat()
                    self._broadcast_json(message, exclude=conn)
                elif msg_type == 'LEAVE':
                    break

        finally:
            if client_info:
                self._remove_client(conn, client_info)

    def _send_user_list(self, conn: socket.socket) -> None:
        """Send list of currently connected users to a new client"""
        with self.clients_lock:
            users = [
                {
                    'user_id': info.user_id,
                    'username': info.username
                }
                for info in self.clients.values()
            ]
        
        user_list_msg = {
            'type': 'USER_LIST',
            'users': users,
            'timestamp': datetime.now().isoformat()
        }
        self._send_json(conn, user_list_msg)

    def _send_json(self, conn: socket.socket, data: dict) -> None:
        """Send a JSON message to a specific client"""
        try:
            json_str = json.dumps(data)
            plaintext = json_str.encode('utf-8')
            ciphertext = self.fernet.encrypt(plaintext)
            send_frame(conn, ciphertext)
        except OSError:
            pass

    def _broadcast_json(self, data: dict, exclude: socket.socket | None = None) -> None:
        """Broadcast a JSON message to all clients except exclude"""
        json_str = json.dumps(data)
        plaintext = json_str.encode('utf-8')
        ciphertext = self.fernet.encrypt(plaintext)
        
        dead: List[socket.socket] = []
        with self.clients_lock:
            for conn, info in self.clients.items():
                if exclude is not None and conn is exclude:
                    continue
                try:
                    send_frame(conn, ciphertext)
                except OSError:
                    dead.append(conn)
        
        # Remove dead connections
        for conn in dead:
            if conn in self.clients:
                info = self.clients[conn]
                del self.clients[conn]
                try:
                    conn.close()
                except OSError:
                    pass
                print(f"[SERVER] Client disconnected: {info.username} (ID: {info.user_id[:8]})")

    def _remove_client(self, conn: socket.socket, client_info: ClientInfo) -> None:
        with self.clients_lock:
            if conn in self.clients:
                del self.clients[conn]
        
        try:
            conn.close()
        except OSError:
            pass
        
        print(f"[SERVER] Client left: {client_info.username} (ID: {client_info.user_id[:8]})")
        
        # Broadcast LEAVE notification
        leave_msg = {
            'type': 'USER_LEFT',
            'user_id': client_info.user_id,
            'username': client_info.username,
            'timestamp': datetime.now().isoformat()
        }
        self._broadcast_json(leave_msg)

    def _shutdown(self) -> None:
        with self.clients_lock:
            for conn, info in self.clients.items():
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    conn.close()
                except OSError:
                    pass
            self.clients.clear()
        try:
            self.server_sock.close()
        except OSError:
            pass


def load_or_generate_key(path: str = "key.key") -> bytes:
    try:
        with open(path, 'rb') as f:
            key = f.read().strip()
            Fernet(key)  # validate
            return key
    except Exception:
        key = Fernet.generate_key()
        with open(path, 'wb') as f:
            f.write(key)
        return key


def main() -> None:
    # Defaults: 0.0.0.0:5000
    host = "0.0.0.0"
    port = 5000
    if len(sys.argv) >= 2:
        host = sys.argv[1]
    if len(sys.argv) >= 3:
        port = int(sys.argv[2])

    key = load_or_generate_key()
    print("[SERVER] Fernet key (share with clients):")
    print(key.decode('utf-8'))

    server = ChatServer(host, port, key)
    server.start()


if __name__ == "__main__":
    main()



# LAN Chat Application

This application provides two interfaces for LAN chatting:

1. Terminal-based interface
2. GUI-based interface

## Terminal Interface

To use the terminal-based chat:

1. Run the server: `python server.py`
2. Run the client: `python client.py`

## GUI Interface

To use the graphical interface:

1. Run the server: `python server2.py`
2. Run the client: `python client2.py`

### Important Note for GUI Server

The GUI server requires manual authentication. As a server administrator:

- You need to maintain a list of authorized users
- Each user must have a valid username and password
- Users cannot join the chat until their credentials are approved by the admin
- New users must contact the server administrator to get their credentials

## Requirements

- Python 3.x
- tkinter (for GUI version)
- socket library

## Setup

1. Clone this repository
2. Make sure all required libraries are installed
3. Choose either GUI or terminal interface based on your preference
4. Start the appropriate server first, then run the client(s)

---

# LAN Chat (TCP) with Fernet Encryption

## Prerequisites

- Python 3.8+
- Install dependencies: `pip install -r requirements.txt`

## How it works

- Server generates (or loads) a Fernet key and prints it. Share this key securely with clients.
- All messages are framed with a 4-byte length prefix and encrypted with the shared key.
- Server handles multiple clients via threads, decrypts incoming messages, and re-encrypts for broadcast.

## Run the server

```bash
python server.py [host] [port]
# Defaults: host=0.0.0.0, port=5000
```

The server will print a line similar to:

```bash
[SERVER] Fernet key (share with clients):
qfQ2o7s3r6i1...==
```

Copy that key for the clients.

## Run a client

```bash
python client.py <server_host> <server_port> <fernet_key> [username]

# Example (same machine):
python client.py 127.0.0.1 5000 qfQ2o7s3r6i1...== Alice
python client.py 127.0.0.1 5000 qfQ2o7s3r6i1...== Bob
```

## Usage

- Type messages and press Enter to send.
- Type `exit` and press Enter to disconnect.

## Notes

- The shared Fernet key is stored in `key.key` on the server for convenience. Regenerating the key (deleting the file) will require clients to use the new key.
- For LAN usage, run the server on a machine that is reachable by others and provide its IP address to the clients.
- All clients must use the exact same key output by the server.

## Optional enhancements (not implemented)

- GUI (Tkinter/PyQt), user authentication, file transfer, key rotation.

# GUI (Modern) – PySide6

## Install (already included in requirements):

```bash
pip install -r requirements.txt
```

## Run GUI Server (dashboard):

```bash
python gui_server.py
```

- Set Host/Port.
- Optionally paste an existing Fernet key; otherwise a new one is generated.
- Click Start Server. Copy the Active Key for clients.

## Run GUI Client:

```bash
python gui_client.py
```

- Click Connect, enter host/port/key and optional username.
- Type messages at the bottom and press Enter or Send.
- Disconnect via the button or send `exit`.

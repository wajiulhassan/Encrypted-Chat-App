"""
client.py — SecureChat TCP Client
Supports private messaging and user list updates.
"""

import sys, os, socket, threading, base64
from typing import Callable

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if THIS_DIR not in sys.path:
    sys.path.insert(0, THIS_DIR)

from crypto   import ECDHKeyExchange, encrypt, decrypt
from protocol import MsgType, build_message, read_message


class SecureChatClient:

    def __init__(self, host, port, username,
                 on_message: Callable,    # (sender, text)
                 on_status:  Callable,    # (text)
                 on_userlist: Callable):  # (list of usernames)
        self.host         = host
        self.port         = port
        self.username     = username
        self.on_message   = on_message
        self.on_status    = on_status
        self.on_userlist  = on_userlist

        self._sock        = None
        self._aes_key     = None
        self._ecdh        = ECDHKeyExchange()
        self._connected   = False
        self._seq_send    = 0

    def connect(self) -> bool:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.connect((self.host, self.port))
            self.on_status("Connected to server...")

            if not self._handshake():
                self.on_status("Handshake failed.")
                return False

            self._connected = True
            self.on_status("Encryption established (AES-256-CBC)")
            threading.Thread(target=self._recv_loop, daemon=True).start()
            return True

        except Exception as e:
            self.on_status(f"Connection error: {e}")
            return False

    def _handshake(self) -> bool:
        self._sock.sendall(
            build_message(MsgType.HELLO, {"username": self.username}, self.username)
        )
        msg = read_message(self._sock)
        if not msg or msg["type"] != MsgType.KEY_OFFER:
            return False
        server_pub = base64.b64decode(msg["payload"]["public_key"])

        my_pub = base64.b64encode(self._ecdh.public_key_bytes).decode()
        self._sock.sendall(
            build_message(MsgType.KEY_ACCEPT, {"public_key": my_pub}, self.username)
        )
        self._aes_key = self._ecdh.derive_shared_key(server_pub)
        ack = read_message(self._sock)
        return ack is not None and ack["type"] == MsgType.ACK

    def send_private(self, to_user: str, text: str) -> bool:
        """Send encrypted private message to specific user."""
        if not self._connected or not self._aes_key:
            return False
        try:
            encrypted = encrypt(text, self._aes_key, seq=self._seq_send)
            self._seq_send += 1
            self._sock.sendall(build_message(
                MsgType.CHAT,
                {"encrypted": encrypted, "to": to_user},
                self.username
            ))
            return True
        except Exception as e:
            self.on_status(f"Send error: {e}")
            return False

    def disconnect(self):
        self._connected = False
        if self._sock:
            try:
                self._sock.sendall(
                    build_message(MsgType.DISCONNECT, {}, self.username))
                self._sock.close()
            except Exception:
                pass

    def _recv_loop(self):
        while self._connected:
            try:
                msg = read_message(self._sock)
                if msg is None:
                    break
                self._handle(msg)
            except Exception as e:
                if self._connected:
                    self.on_status(f"Connection lost: {e}")
                break
        self._connected = False
        self.on_status("Disconnected from server.")

    def _handle(self, msg):
        mtype   = msg.get("type")
        sender  = msg.get("sender", "SERVER")
        payload = msg.get("payload", {})

        if mtype == MsgType.CHAT:
            try:
                text = decrypt(payload["encrypted"], self._aes_key)
                self.on_message(sender, text)
            except Exception as e:
                self.on_status(f"Decrypt error: {e}")

        elif mtype == MsgType.SYSTEM:
            event = payload.get("event")
            if event == "USERLIST":
                # Server sent updated online users list
                self.on_userlist(payload.get("users", []))
            else:
                self.on_status(payload.get("text", ""))

        elif mtype == MsgType.ERROR:
            self.on_status(f"Server error: {payload.get('text','')}")

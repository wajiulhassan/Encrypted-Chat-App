"""
server.py — SecureChat TCP Server
Supports private messaging between specific users.
"""

import sys, os, socket, threading, uuid, base64, json

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if THIS_DIR not in sys.path:
    sys.path.insert(0, THIS_DIR)

from crypto   import ECDHKeyExchange, decrypt, encrypt
from protocol import MsgType, build_message, read_message
from logger   import ChatLogger

HOST    = "0.0.0.0"
PORT    = 9999
BACKLOG = 64


class ClientSession:
    def __init__(self, conn, addr, session_id):
        self.conn        = conn
        self.addr        = addr
        self.session_id  = session_id
        self.username    = f"User_{session_id[:6]}"
        self.aes_key     = None
        self.ecdh        = ECDHKeyExchange()
        self.connected   = True
        self.seq_send    = 0
        self._lock       = threading.Lock()

    def send_raw(self, msg_type, payload, sender="SERVER"):
        try:
            data = build_message(msg_type, payload, sender)
            with self._lock:
                self.conn.sendall(data)
        except Exception:
            self.connected = False

    def send_encrypted(self, text, sender="SERVER"):
        if not self.aes_key:
            return
        try:
            payload = encrypt(text, self.aes_key, seq=self.seq_send)
            self.seq_send += 1
            self.send_raw(MsgType.CHAT, {"encrypted": payload}, sender)
        except Exception as e:
            print(f"[!] Send error to {self.username}: {e}")
            self.connected = False


class SecureChatServer:

    def __init__(self, host=HOST, port=PORT):
        self.host          = host
        self.port          = port
        self.sessions      = {}       # username -> ClientSession
        self.sessions_lock = threading.Lock()
        self.logger        = ChatLogger()
        self._running      = False
        self._server_sock  = None

    def start(self):
        self._running     = True
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(BACKLOG)
        self._server_sock.settimeout(1.0)

        print(f"""
\033[1m╔══════════════════════════════════════════╗
║      SecureChat Server — AES-256         ║
╠══════════════════════════════════════════╣
║  Host  : {self.host:<32}║
║  Port  : {self.port:<32}║
║  Mode  : Private Messaging               ║
╚══════════════════════════════════════════╝\033[0m
  Waiting for connections... (Ctrl+C to stop)
""")

        try:
            import signal
            signal.signal(signal.SIGINT, lambda *_: self._stop())
        except (ValueError, OSError):
            pass

        while self._running:
            try:
                conn, addr = self._server_sock.accept()
                sid     = str(uuid.uuid4())
                session = ClientSession(conn, addr, sid)
                t = threading.Thread(target=self._handle_client,
                                     args=(session,), daemon=True)
                t.start()
                print(f"\033[32m[+]\033[0m {addr[0]}:{addr[1]} connecting...")
            except socket.timeout:
                continue
            except OSError:
                break

    def _stop(self):
        self._running = False
        if self._server_sock:
            self._server_sock.close()

    # ── Handshake ─────────────────────────────────────────────

    def _handle_client(self, session):
        try:
            if not self._handshake(session):
                return

            # Check duplicate username
            with self.sessions_lock:
                if session.username in self.sessions:
                    session.send_raw(MsgType.ERROR,
                        {"text": f"Username '{session.username}' already taken!"})
                    return
                self.sessions[session.username] = session

            print(f"\033[32m[✓]\033[0m \033[36m{session.username}\033[0m "
                  f"connected (online: {len(self.sessions)})")

            # Send current online users list to new user
            self._send_userlist(session)

            # Broadcast updated user list to everyone
            self._broadcast_userlist()

            # Message loop
            while session.connected:
                msg = read_message(session.conn)
                if msg is None:
                    break
                self._dispatch(session, msg)

        except Exception as e:
            print(f"\033[31m[-]\033[0m Error {session.session_id[:8]}: {e}")
        finally:
            self._remove(session)

    def _handshake(self, session):
        hello = read_message(session.conn)
        if not hello or hello.get("type") != MsgType.HELLO:
            return False
        session.username = str(hello["payload"].get("username", ""))[:24].strip()
        if not session.username:
            return False

        server_pub = base64.b64encode(session.ecdh.public_key_bytes).decode()
        session.send_raw(MsgType.KEY_OFFER, {"public_key": server_pub})

        key_msg = read_message(session.conn)
        if not key_msg or key_msg.get("type") != MsgType.KEY_ACCEPT:
            return False
        client_pub = base64.b64decode(key_msg["payload"]["public_key"])
        session.aes_key = session.ecdh.derive_shared_key(client_pub)
        session.send_raw(MsgType.ACK, {"status": "KEY_ESTABLISHED"})
        return True

    # ── Dispatch ──────────────────────────────────────────────

    def _dispatch(self, session, msg):
        mtype = msg.get("type")

        if mtype == MsgType.CHAT:
            # Private message to specific user
            payload  = msg["payload"]
            enc_data = payload.get("encrypted")
            to_user  = payload.get("to")        # target username

            try:
                plaintext = decrypt(enc_data, session.aes_key)
            except Exception as e:
                session.send_encrypted(f"Decrypt error: {e}", sender="SERVER")
                return

            print(f"  \033[36m{session.username}\033[0m → "
                  f"\033[33m{to_user}\033[0m: {plaintext}")
            self.logger.log("CHAT", session.username, f"[to:{to_user}] {plaintext}")

            # Find recipient and forward
            with self.sessions_lock:
                recipient = self.sessions.get(to_user)

            if recipient and recipient.connected:
                recipient.send_encrypted(plaintext, sender=session.username)
            else:
                session.send_encrypted(
                    f"{to_user} is offline or not found.",
                    sender="SERVER"
                )

        elif mtype == MsgType.DISCONNECT:
            session.connected = False

    # ── User List ─────────────────────────────────────────────

    def _send_userlist(self, session):
        """Send current online users to one client."""
        with self.sessions_lock:
            users = [u for u in self.sessions.keys() if u != session.username]
        session.send_raw(MsgType.SYSTEM, {
            "event": "USERLIST",
            "users": users
        })

    def _broadcast_userlist(self):
        """Broadcast updated user list to ALL connected clients."""
        with self.sessions_lock:
            all_users  = list(self.sessions.keys())
            all_sessions = list(self.sessions.values())

        for s in all_sessions:
            others = [u for u in all_users if u != s.username]
            s.send_raw(MsgType.SYSTEM, {
                "event": "USERLIST",
                "users": others
            })

    def _remove(self, session):
        with self.sessions_lock:
            if self.sessions.get(session.username) is session:
                del self.sessions[session.username]
        try:
            session.conn.close()
        except Exception:
            pass
        print(f"\033[31m[-]\033[0m \033[36m{session.username}\033[0m "
              f"disconnected (online: {len(self.sessions)})")
        self.logger.log("LEAVE", session.username, "left")
        self._broadcast_userlist()


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", default=9999, type=int)
    args = p.parse_args()
    try:
        SecureChatServer(host=args.host, port=args.port).start()
    except KeyboardInterrupt:
        print("\n[!] Server stopped.")

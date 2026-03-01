"""
logger.py — Encrypted Message Logger
Logs all chat to an AES-256-CBC encrypted file. No subfolder dependencies.
"""

import os
import json
import time
import base64
import hashlib
import threading
from pathlib import Path

# Import from same directory
from crypto import encrypt, decrypt, derive_key

LOG_DIR      = Path("logs")
LOG_FILE     = LOG_DIR / "chat.log"
LOG_KEY_FILE = LOG_DIR / ".log_key"


class ChatLogger:
    """Thread-safe encrypted chat logger. Each entry AES-256 encrypted on disk."""

    def __init__(self, passphrase: str = "SecureChatLogKey#2025"):
        self._lock = threading.Lock()
        LOG_DIR.mkdir(exist_ok=True)
        self._key  = self._load_or_create_key(passphrase)

    def _load_or_create_key(self, passphrase: str) -> bytes:
        if LOG_KEY_FILE.exists():
            data = json.loads(LOG_KEY_FILE.read_text())
            salt = base64.b64decode(data["salt"])
            key, _ = derive_key(passphrase, salt)
            return key
        key, salt = derive_key(passphrase)
        LOG_KEY_FILE.write_text(json.dumps({"salt": base64.b64encode(salt).decode()}))
        return key

    def log(self, event_type: str, sender: str, content: str, room: str = "global"):
        """Encrypt and append one log entry."""
        entry = {
            "time":    time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "type":    event_type,
            "room":    room,
            "sender":  sender,
            "content": content,
        }
        encrypted = encrypt(json.dumps(entry), self._key)
        with self._lock:
            with open(LOG_FILE, "a") as f:
                f.write(json.dumps(encrypted) + "\n")

    def read_logs(self) -> list:
        """Decrypt and return all log entries."""
        if not LOG_FILE.exists():
            return []
        entries = []
        with open(LOG_FILE) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    payload   = json.loads(line)
                    plaintext = decrypt(payload, self._key)
                    entries.append(json.loads(plaintext))
                except Exception as e:
                    entries.append({"error": str(e), "raw": line[:60]})
        return entries

    def print_logs(self):
        """Pretty-print all decrypted log entries."""
        logs = self.read_logs()
        print(f"\n{'─'*60}")
        print(f"  SecureChat Log — {len(logs)} entries")
        print(f"{'─'*60}")
        for entry in logs:
            if "error" in entry:
                print(f"  [ERR] {entry}")
            else:
                print(f"  [{entry['time']}] <{entry['sender']}> {entry['content']}")
        print(f"{'─'*60}\n")

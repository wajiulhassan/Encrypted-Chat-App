"""
protocol.py — Message Wire Protocol
Length-prefixed JSON over TCP. No subfolder dependencies.
"""

import json
import struct
import time
import uuid
from enum import Enum


class MsgType(str, Enum):
    HELLO      = "HELLO"
    KEY_OFFER  = "KEY_OFFER"
    KEY_ACCEPT = "KEY_ACCEPT"
    CHAT       = "CHAT"
    SYSTEM     = "SYSTEM"
    ACK        = "ACK"
    DISCONNECT = "DISCONNECT"
    ERROR      = "ERROR"


def build_message(msg_type: MsgType, payload: dict, sender: str = "anonymous") -> bytes:
    """
    Serialize message to wire format: [4-byte big-endian length][JSON body]
    """
    body = {
        "id":        str(uuid.uuid4()),
        "type":      msg_type.value,
        "sender":    sender,
        "timestamp": time.time(),
        "payload":   payload,
    }
    data          = json.dumps(body).encode("utf-8")
    length_prefix = struct.pack(">I", len(data))
    return length_prefix + data


def read_message(sock) -> dict:
    """
    Read one complete message from a TCP socket.
    Returns parsed dict or None on connection close.
    """
    raw_len = _recv_exact(sock, 4)
    if raw_len is None:
        return None
    msg_len = struct.unpack(">I", raw_len)[0]

    if msg_len > 1_048_576:   # 1 MB max
        raise ValueError(f"Message too large: {msg_len} bytes")

    raw_body = _recv_exact(sock, msg_len)
    if raw_body is None:
        return None

    return json.loads(raw_body.decode("utf-8"))


def _recv_exact(sock, n: int) -> bytes:
    """Reliably read exactly n bytes from a socket."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

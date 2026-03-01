"""
crypto.py — AES-256-CBC Encryption + ECDH + Ed25519 + HMAC-SHA256
No external folder dependencies. Drop this file anywhere and import directly.
"""

import os, base64, hashlib, hmac, struct, time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

BLOCK_SIZE = 128   # AES block bits
KEY_SIZE   = 32    # AES-256 = 32 bytes
IV_SIZE    = 16    # AES IV = 16 bytes


# ── AES-256-CBC ───────────────────────────────────────────────

def generate_iv() -> bytes:
    """Cryptographically secure random IV — unique per message."""
    return os.urandom(IV_SIZE)


def derive_key(passphrase: str, salt: bytes = None):
    """
    Derive AES-256 key from passphrase using PBKDF2-HMAC-SHA256.
    Returns (key_bytes, salt_bytes).
    """
    if salt is None:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 600_000, KEY_SIZE)
    return key, salt


def encrypt(plaintext: str, key: bytes, seq: int = 0) -> dict:
    """
    Encrypt plaintext with AES-256-CBC.
    seq is bound into the HMAC to prevent replay attacks.
    Returns dict: {iv, ciphertext, hmac, seq}
    """
    iv = generate_iv()

    # PKCS7 pad then encrypt
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    ct = cipher.encryptor().update(padded) + cipher.encryptor().finalize()

    # Rebuild encryptor for proper finalization
    enc_obj = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
    ct = enc_obj.update(padded) + enc_obj.finalize()

    # HMAC-SHA256 over: seq(4 bytes) + iv + ciphertext
    seq_b = struct.pack(">I", seq)
    mac   = hmac.new(key, seq_b + iv + ct, hashlib.sha256).digest()

    return {
        "iv":         base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
        "hmac":       base64.b64encode(mac).decode(),
        "seq":        seq,
    }


def decrypt(payload: dict, key: bytes, expected_seq: int = None) -> str:
    """
    Decrypt AES-256-CBC payload.
    Verifies HMAC first (prevents padding oracle).
    Verifies sequence number (prevents replay).
    Raises ValueError on any failure.
    """
    iv   = base64.b64decode(payload["iv"])
    ct   = base64.b64decode(payload["ciphertext"])
    rmac = base64.b64decode(payload["hmac"])
    seq  = payload.get("seq", 0)

    # Sequence check
    if expected_seq is not None and seq != expected_seq:
        raise ValueError(
            f"Sequence mismatch: expected {expected_seq}, got {seq}. Replay attack?"
        )

    # HMAC verify before decrypt
    seq_b = struct.pack(">I", seq)
    emac  = hmac.new(key, seq_b + iv + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(emac, rmac):
        raise ValueError("HMAC verification failed — message tampered!")

    # Decrypt + unpad
    dec_obj = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
    padded  = dec_obj.update(ct) + dec_obj.finalize()
    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode("utf-8")


# ── Ed25519 Identity Key (MITM defense) ──────────────────────

class IdentityKey:
    """
    Long-term Ed25519 signing key.
    Server signs its ECDH public key — client verifies against pinned identity.
    A MITM cannot forge this signature without the server's private key.
    """

    def __init__(self, private_key=None):
        if private_key is None:
            self._private = Ed25519PrivateKey.generate()
        else:
            self._private = private_key
        self._public = self._private.public_key()

    @classmethod
    def generate(cls):
        return cls()

    @classmethod
    def from_public_bytes(cls, pub_bytes: bytes):
        """Construct a verify-only key (no private key)."""
        obj = object.__new__(cls)
        obj._private = None
        obj._public  = Ed25519PublicKey.from_public_bytes(pub_bytes)
        return obj

    @classmethod
    def load_or_generate(cls, path: str):
        """Load from PEM file or generate new and save."""
        from pathlib import Path
        p = Path(path)
        if p.exists():
            priv = serialization.load_pem_private_key(p.read_bytes(), password=None)
            return cls(private_key=priv)
        key = cls.generate()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(key._private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        return key

    def sign(self, data: bytes) -> bytes:
        if self._private is None:
            raise RuntimeError("No private key — cannot sign.")
        return self._private.sign(data)

    def verify(self, data: bytes, signature: bytes):
        """Raises InvalidSignature if verification fails (MITM detected)."""
        try:
            self._public.verify(signature, data)
        except InvalidSignature:
            raise InvalidSignature(
                "SIGNATURE INVALID — Man-in-the-Middle attack detected! "
                "Server identity cannot be verified. Connection aborted."
            )

    def public_bytes(self) -> bytes:
        return self._public.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def fingerprint(self) -> str:
        """SHA-256 fingerprint (like SSH host key fingerprint)."""
        d = hashlib.sha256(self.public_bytes()).digest()
        return ":".join(f"{b:02x}" for b in d[:16])


# ── Authenticated ECDH (MITM-proof key exchange) ─────────────

class AuthenticatedECDH:
    """
    X25519 ECDH where each side signs their ephemeral public key
    with their long-term Ed25519 identity key.

    MITM is defeated because:
      - Server signs its X25519 pubkey with Ed25519 private key
      - Client verifies this against the pinned server identity pubkey
      - Eve cannot forge the signature without the server's Ed25519 private key
    """

    def __init__(self, identity: IdentityKey):
        self._identity  = identity
        self._ecdh_priv = X25519PrivateKey.generate()
        self.ecdh_pub_bytes = self._ecdh_priv.public_key().public_bytes_raw()

    def signed_offer(self) -> dict:
        """Create a signed KEY_OFFER. Cannot be forged without Ed25519 private key."""
        sig = self._identity.sign(self.ecdh_pub_bytes)
        return {
            "ecdh_pub":  base64.b64encode(self.ecdh_pub_bytes).decode(),
            "signature": base64.b64encode(sig).decode(),
            "identity":  base64.b64encode(self._identity.public_bytes()).decode(),
            "timestamp": time.time(),
        }

    def verify_and_derive(self, offer: dict, pinned_identity: bytes = None) -> bytes:
        """
        Verify peer's signed offer then derive shared AES-256 session key.
        pinned_identity: if set, peer identity MUST match (MITM protection).
        """
        peer_ecdh = base64.b64decode(offer["ecdh_pub"])
        sig       = base64.b64decode(offer["signature"])
        peer_id   = base64.b64decode(offer["identity"])

        # Key pinning: identity must match what we expect
        if pinned_identity is not None:
            if not hmac.compare_digest(peer_id, pinned_identity):
                raise ValueError(
                    "SERVER IDENTITY MISMATCH — Key pinning violation!\n"
                    "This is a strong indicator of a Man-in-the-Middle attack.\n"
                    "Connection aborted."
                )

        # Signature verification — cannot be forged
        IdentityKey.from_public_bytes(peer_id).verify(peer_ecdh, sig)

        # ECDH shared secret → HKDF → AES-256 key
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        peer_pub = X25519PublicKey.from_public_bytes(peer_ecdh)
        shared   = self._ecdh_priv.exchange(peer_pub)
        hkdf = HKDF(
            algorithm=hashes.SHA256(), length=KEY_SIZE,
            salt=None, info=b"SecureChat-v2-AES256",
            backend=default_backend()
        )
        return hkdf.derive(shared)


# ── Legacy unauthenticated ECDH (kept for compatibility) ─────

class ECDHKeyExchange:
    """Basic X25519 ECDH without Ed25519 signing. Vulnerable to MITM."""

    def __init__(self):
        self._private_key   = X25519PrivateKey.generate()
        self.public_key_bytes = self._private_key.public_key().public_bytes_raw()

    def derive_shared_key(self, peer_pub_bytes: bytes) -> bytes:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        peer    = X25519PublicKey.from_public_bytes(peer_pub_bytes)
        shared  = self._private_key.exchange(peer)
        hkdf = HKDF(
            algorithm=hashes.SHA256(), length=KEY_SIZE,
            salt=None, info=b"SecureChat-AES256-SessionKey",
            backend=default_backend()
        )
        return hkdf.derive(shared)


# ── Session Transcript Hash ───────────────────────────────────

class TranscriptHash:
    """Rolling SHA-256 of all messages. Detects injection/reordering."""

    def __init__(self):
        self._h = hashlib.sha256()

    def update(self, sender: str, ciphertext: bytes):
        self._h.update(sender.encode() + b":" + ciphertext)

    def digest(self) -> str:
        return self._h.hexdigest()

# SecureChat — Security Audit & Attack Surface Analysis

## Attack Matrix: Before vs After Hardening

| Attack Vector                          | v1 Status     | v2 Status        | Defense Mechanism                         |
|----------------------------------------|---------------|------------------|-------------------------------------------|
| Passive eavesdropping (Wireshark)      | ✅ BLOCKED     | ✅ BLOCKED        | AES-256-CBC — ciphertext only on wire     |
| Message tampering / bit-flip           | ✅ BLOCKED     | ✅ BLOCKED        | HMAC-SHA256 (Encrypt-then-MAC)            |
| Padding oracle attack                  | ✅ BLOCKED     | ✅ BLOCKED        | MAC verified BEFORE decryption            |
| IV reuse attack                        | ✅ BLOCKED     | ✅ BLOCKED        | os.urandom(16) per message                |
| **Man-in-the-Middle (ECDH)**           | ❌ VULNERABLE  | ✅ BLOCKED        | Ed25519 signatures + identity pinning     |
| Replay attack                          | ⚠️ PARTIAL     | ✅ BLOCKED        | Sequence numbers bound into HMAC          |
| Message reordering                     | ❌ VULNERABLE  | ✅ BLOCKED        | Sequence counter enforced                 |
| Key substitution (MITM)                | ❌ VULNERABLE  | ✅ BLOCKED        | Ed25519 signature over ECDH pubkey        |
| Impersonation (fake server)            | ❌ VULNERABLE  | ✅ BLOCKED        | Server identity key pinning               |
| Session injection                      | ❌ VULNERABLE  | ✅ BLOCKED        | Transcript rolling hash                   |
| Brute-force (passphrase)               | ✅ BLOCKED     | ✅ BLOCKED        | PBKDF2-HMAC-SHA256, 600k iterations       |
| Log tampering                          | ✅ BLOCKED     | ✅ BLOCKED        | AES-encrypted log file                    |

---

## The MITM Attack — Explained

### How it worked (v1)
```
Alice                     Eve (MITM)                  Server
  │── HELLO ────────────▶ │── HELLO ─────────────────▶ │
  │                       │◀─ KEY_OFFER {srv_pub} ───── │
  │◀─ KEY_OFFER {eve_pub}─│                             │
  │── KEY_ACCEPT {A_pub} ▶│── KEY_ACCEPT {eve_pub} ───▶ │
  │                       │                             │
  │  Key_AE established   │  Key_ES established         │
  │                       │                             │
  │── [AES encrypted msg]▶│ (decrypts with Key_AE)      │
  │                       │ (re-encrypts with Key_ES) ──▶│
  │                       │           ↑                 │
  │                       │    Eve reads ALL plaintext   │
```

### Why it's impossible now (v2)
```
Alice                     Eve (MITM)                  Server
  │                                                     │
  │                 Server sends:                       │
  │                 ecdh_pub + Ed25519_sig(ecdh_pub)    │
  │◀─ KEY_OFFER ────────────────────────────────────────│
  │                                                     │
  │ Alice verifies: Ed25519_verify(ecdh_pub, sig, pinned_server_pubkey)
  │                                                     │
  │ If Eve substituted ecdh_pub → signature is INVALID  │
  │ Eve cannot forge signature without server's Ed25519 private key
  │ → InvalidSignature raised → connection aborted ✓    │
```

---

## Defense Layers (Defense in Depth)

```
Layer 1: Transport
  └─ TCP socket (no TLS needed — we implement equivalent at app layer)

Layer 2: Key Exchange Authentication
  └─ X25519 ECDH ephemeral key exchange
  └─ Ed25519 signatures on ECDH public keys (defeats MITM)
  └─ Server identity key pinning (TOFU or pre-pinned)

Layer 3: Symmetric Encryption
  └─ AES-256-CBC with PKCS7 padding
  └─ Fresh os.urandom(16) IV every message
  └─ 256-bit session key derived via HKDF-SHA256

Layer 4: Message Integrity & Authentication
  └─ HMAC-SHA256 (Encrypt-then-MAC)
  └─ Sequence numbers bound into HMAC (replay/reorder protection)
  └─ HMAC verified BEFORE decryption (prevents padding oracle)

Layer 5: Session Integrity
  └─ Rolling transcript SHA-256 hash
  └─ Both sides can compare hashes to detect injection

Layer 6: Data at Rest
  └─ AES-256-CBC encrypted log files
  └─ Separate key file with PBKDF2-derived key
```

---

## Remaining Limitations (honest disclosure)

### 1. No TLS on transport
The app-layer crypto is strong, but a sophisticated attacker could perform TCP-level DoS (RST injection, etc.). Adding TLS with `ssl.wrap_socket()` would harden this.

### 2. TOFU (Trust On First Use) for new clients
The first time a client connects, it must accept the server's identity key without prior verification — similar to SSH the first time. After that, it's pinned. An attacker who is present on the VERY FIRST connection could still succeed.

**Mitigations:**
- Pre-distribute server fingerprint out-of-band (email, QR code, etc.)
- Certificate Authority model

### 3. No forward secrecy revocation
If the server's Ed25519 private key is stolen, an attacker could retroactively impersonate the server for future sessions. Session keys themselves are ephemeral (X25519), so past traffic remains safe.

### 4. No rate limiting / DoS protection
A flood of connection attempts can exhaust server threads. Production mitigation: connection rate limiting per IP.

### 5. No client authentication (server trusts any connecting client)
The server verifies its own identity to clients, but doesn't require clients to prove who they are beyond a username string. Adding mutual Ed25519 authentication would close this.

---

## Key Fingerprint Verification (SSH-style)

When connecting for the first time, clients should verify the server fingerprint out-of-band:

```
Server fingerprint: a1:b2:c3:d4:e5:f6:07:18:29:3a:4b:5c:6d:7e:8f:90

Verify this matches the fingerprint your server admin published!
```

This is equivalent to the SSH warning:
> "The authenticity of host X can't be established. Are you sure you want to continue?"

---

## Cryptographic Primitives Summary

| Primitive           | Algorithm           | Key/Output Size | Standard     |
|---------------------|---------------------|-----------------|--------------|
| Symmetric cipher    | AES-CBC             | 256-bit key     | NIST FIPS 197|
| Key derivation      | HKDF                | 256-bit         | RFC 5869     |
| Password KDF        | PBKDF2-HMAC-SHA256  | 256-bit, 600k   | NIST SP 800  |
| Message auth        | HMAC-SHA256         | 256-bit         | RFC 2104     |
| Key exchange        | X25519 ECDH         | 256-bit         | RFC 7748     |
| Identity signing    | Ed25519             | 256-bit         | RFC 8032     |
| Session integrity   | SHA-256 (rolling)   | 256-bit         | FIPS 180-4   |

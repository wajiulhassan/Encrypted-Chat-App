# 🔐 SecureChat — AES-256 Encrypted Chat

A professional, production-ready encrypted chat system built in Python.
Single entry point: `main.py` connects and runs everything.

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run tests to verify crypto stack
python main.py test

# 3. Start the server (Terminal 1)
python main.py server

# 4. Launch GUI client (Terminal 2, 3, 4...)
python main.py client

# 5. Terminal client (no GUI needed)
python main.py client --cli --username Alice

# 6. View encrypted logs
python main.py logs
```

---

## All Commands

| Command | Description |
|---|---|
| `python main.py` | Show help and all modes |
| `python main.py server` | Start TCP server on 0.0.0.0:9999 |
| `python main.py server --port 8888` | Custom port |
| `python main.py client` | Launch GUI client |
| `python main.py client --username Bob` | Pre-fill username |
| `python main.py client --host 10.0.0.5` | Connect to remote server |
| `python main.py client --cli` | Terminal mode (no Tkinter) |
| `python main.py logs` | View all decrypted logs |
| `python main.py logs --filter Alice` | Filter logs by keyword |
| `python main.py test` | Run 13-test security suite |

---

## Project Structure

```
SecureChat/
├── main.py              ← ENTRY POINT — runs everything
├── server/
│   └── server.py        ← TCP server, multi-client threading
├── client/
│   ├── client.py        ← Headless encrypted TCP client
│   └── gui_client.py    ← Dark-theme Tkinter GUI
├── shared/
│   ├── crypto.py        ← AES-256-CBC, ECDH, Ed25519, HMAC
│   ├── protocol.py      ← Length-prefixed JSON wire format
│   └── logger.py        ← Encrypted on-disk log
├── web_ui/
│   └── index.html       ← Browser UI demo
├── logs/
│   └── chat.log         ← AES-256 encrypted log file
├── SECURITY.md          ← Attack surface analysis
└── requirements.txt
```

---

## Security Stack

| Layer | Implementation |
|---|---|
| Symmetric cipher | AES-256-CBC |
| Key exchange | X25519 ECDH (ephemeral per session) |
| Key derivation | HKDF-SHA256 |
| MITM defense | Ed25519 signed ECDH keys + identity pinning |
| Message integrity | HMAC-SHA256 (Encrypt-then-MAC) |
| Replay protection | Sequence numbers bound into HMAC |
| IV policy | os.urandom(16) — unique per message |
| Password KDF | PBKDF2-HMAC-SHA256, 600k iterations |
| Log encryption | AES-256-CBC on disk |

---

## Requirements

- Python 3.10+
- `cryptography` library
- Tkinter (for GUI mode — included with Python on Windows/macOS; `sudo apt install python3-tk` on Linux)

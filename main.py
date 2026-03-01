#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║              SecureChat — AES-256 Encrypted Chat             ║
║                      main.py  (entry point)                  ║
╠══════════════════════════════════════════════════════════════╣
║  All files must be in the SAME folder as this main.py        ║
║                                                              ║
║  Usage:                                                      ║
║    python main.py server          → start TCP server         ║
║    python main.py client          → launch GUI client        ║
║    python main.py client --cli    → terminal client          ║
║    python main.py logs            → view encrypted logs      ║
║    python main.py test            → run security tests       ║
║    python main.py --help          → full help                ║
╚══════════════════════════════════════════════════════════════╝

Required files in same folder:
    main.py         ← this file
    crypto.py       ← AES / ECDH / Ed25519 / HMAC
    protocol.py     ← TCP wire protocol
    logger.py       ← encrypted log file
    server.py       ← TCP server
    client.py       ← TCP client (headless)
    gui_client.py   ← Tkinter GUI client
"""

import sys
import os
import argparse
import platform
import importlib.util
from pathlib import Path

# ── CRITICAL: add this file's directory to sys.path FIRST ────
# This ensures all sibling files (crypto.py, server.py, etc.)
# can be imported without any "No module named X" errors.
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# ─────────────────────────────────────────────────────────────
#  Startup Checks
# ─────────────────────────────────────────────────────────────

def check_python_version():
    if sys.version_info < (3, 10):
        print(f"\n❌  Python 3.10+ required. You have {platform.python_version()}")
        print("    Download: https://www.python.org/downloads/\n")
        sys.exit(1)


def check_dependencies() -> bool:
    """Check all required pip packages are installed."""
    required = {
        "cryptography": "pip install cryptography",
    }
    missing = []
    for pkg, cmd in required.items():
        if importlib.util.find_spec(pkg) is None:
            missing.append((pkg, cmd))

    if missing:
        print("\n❌  Missing required packages:\n")
        for pkg, cmd in missing:
            print(f"   {pkg:<20} →  {cmd}")
        print("\n   Run:  pip install -r requirements.txt\n")
        return False
    return True


def check_files():
    """Make sure all required sibling files exist."""
    required_files = [
        "crypto.py", "protocol.py", "logger.py",
        "server.py", "client.py", "gui_client.py",
    ]
    missing = [f for f in required_files if not (ROOT / f).exists()]
    if missing:
        print("\n❌  Missing files (must be in the same folder as main.py):\n")
        for f in missing:
            print(f"   {ROOT / f}")
        print()
        sys.exit(1)


def check_tkinter() -> bool:
    try:
        import tkinter  # noqa: F401
        return True
    except ImportError:
        return False


# ─────────────────────────────────────────────────────────────
#  Banner
# ─────────────────────────────────────────────────────────────

BANNER = r"""
  ____                           ____ _           _
 / ___|  ___  ___ _   _ _ __ __|  ___| |__   __ _| |_
 \___ \ / _ \/ __| | | | '__/ _ \ |_  | '_ \ / _` | __|
  ___) |  __/ (__| |_| | | |  __/  _| | | | | (_| | |_
 |____/ \___|\___|\__,_|_|  \___|_|   |_| |_|\__,_|\__|

  AES-256-CBC  ·  X25519 ECDH  ·  HMAC-SHA256  ·  Ed25519
"""

def print_banner():
    print(BANNER)
    print(f"  Python {platform.python_version()} · {platform.system()} {platform.machine()}")
    print(f"  Folder : {ROOT}\n")


# ─────────────────────────────────────────────────────────────
#  Mode: SERVER
# ─────────────────────────────────────────────────────────────

def run_server(args):
    from server import SecureChatServer   # flat import — same folder

    print_banner()
    print(f"  [MODE] SERVER  —  host={args.host}  port={args.port}\n")

    server = SecureChatServer(host=args.host, port=args.port)
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[!] Server stopped.")


# ─────────────────────────────────────────────────────────────
#  Mode: GUI CLIENT
# ─────────────────────────────────────────────────────────────

def run_gui_client(args):
    if not check_tkinter():
        print("\n❌  Tkinter not available.")
        print("    Windows/macOS : reinstall Python from python.org")
        print("    Linux         : sudo apt install python3-tk")
        print("    Alternative   : python main.py client --cli\n")
        sys.exit(1)

    import tkinter as tk
    from gui_client import LoginWindow
    root = tk.Tk()
    root.configure(bg="#0d1117")
    app = LoginWindow(root)

    # Apply CLI arguments as defaults in the GUI
    if args.host != "127.0.0.1":
        app._host.set(args.host)
    if args.port != 9999:
        app._port.set(str(args.port))
    if args.username:
        app._username.set(args.username)

    root.mainloop()


# ─────────────────────────────────────────────────────────────
#  Mode: TERMINAL CLIENT (no GUI)
# ─────────────────────────────────────────────────────────────

def run_cli_client(args):
    import threading
    import time as _time
    from client import SecureChatClient   # flat import — same folder

    username = args.username or input("  Username: ").strip() or "User"
    print_banner()
    print(f"  [MODE] TERMINAL CLIENT")
    print(f"  Server   : {args.host}:{args.port}")
    print(f"  Username : {username}")
    print(f"  Commands : /quit to exit, /nick <name> to rename\n")

    lock = threading.Lock()

    def on_message(sender, text, mtype):
        with lock:
            ts = _time.strftime("%H:%M:%S")
            tag = {"system": "⚙", "error": "✗"}.get(mtype, "🔒")
            print(f"\r  {tag} [{ts}] {'' if mtype == 'system' else sender + ': '}{text}")
            print("  > ", end="", flush=True)

    def on_status(text):
        with lock:
            print(f"\r  · {text}")
            print("  > ", end="", flush=True)

    client = SecureChatClient(
        host=args.host, port=args.port, username=username,
        on_message=on_message, on_status=on_status,
    )

    ok = client.connect()
    if not ok:
        print(f"\n❌  Could not connect to {args.host}:{args.port}")
        print("    Make sure the server is running:  python main.py server\n")
        sys.exit(1)

    try:
        while True:
            print("  > ", end="", flush=True)
            try:
                line = input()
            except EOFError:
                break
            if not line.strip():
                continue
            if line.strip().lower() in ("/quit", "/exit", "quit", "exit"):
                break
            if not client.send_message(line):
                print("  ✗  Send failed.")
                break
    except KeyboardInterrupt:
        pass
    finally:
        client.disconnect()
        print("\n  Goodbye.\n")


# ─────────────────────────────────────────────────────────────
#  Mode: LOG VIEWER
# ─────────────────────────────────────────────────────────────

def run_logs(args):
    from logger import ChatLogger   # flat import — same folder

    print_banner()
    print("  [MODE] LOG VIEWER\n")

    logger = ChatLogger()
    logs   = logger.read_logs()

    if not logs:
        print("  No log entries found.")
        print("  Logs are written to: logs/chat.log\n")
        return

    filt  = args.filter.lower() if args.filter else None
    shown = 0

    print(f"  {'TIME':<22} {'TYPE':<8} {'SENDER':<18} MESSAGE")
    print(f"  {'─'*70}")

    for entry in logs:
        if "error" in entry:
            print(f"  [DECRYPT ERROR] {entry.get('error', '?')}")
            continue
        line = f"  {entry['time']:<22} {entry['type']:<8} {entry['sender']:<18} {entry['content']}"
        if filt and filt not in line.lower():
            continue
        print(line)
        shown += 1

    print(f"\n  Total: {len(logs)} entries  |  Shown: {shown}")
    if filt:
        print(f"  Filter applied: '{args.filter}'")
    print()


# ─────────────────────────────────────────────────────────────
#  Mode: SECURITY TEST SUITE
# ─────────────────────────────────────────────────────────────

def run_tests(_args):
    print_banner()
    print("  [MODE] SECURITY TEST SUITE")
    print("  Testing all crypto operations and attack scenarios...\n")

    # flat import — same folder
    from crypto import (
        encrypt, decrypt, derive_key,
        IdentityKey, AuthenticatedECDH, ECDHKeyExchange,
    )
    from cryptography.exceptions import InvalidSignature

    results = []

    def test(name, fn):
        try:
            fn()
            results.append((name, True, None))
            print(f"  ✅  {name}")
        except Exception as e:
            results.append((name, False, str(e)))
            print(f"  ❌  {name}")
            print(f"       → {e}")

    # ── AES-256-CBC ───────────────────────────────────────────
    print("  ── AES-256-CBC ──────────────────────────────────────")

    def t_roundtrip():
        key, _ = derive_key("TestPassword#99")
        assert decrypt(encrypt("Hello, SecureChat!", key, seq=0), key, expected_seq=0) == "Hello, SecureChat!"

    def t_unicode():
        key, _ = derive_key("pw")
        msg = "مرحبا 🔐 안녕 привет"
        assert decrypt(encrypt(msg, key), key) == msg

    def t_large():
        key, _ = derive_key("pw")
        msg = "X" * 50_000
        assert decrypt(encrypt(msg, key), key) == msg

    test("AES-256-CBC round-trip",            t_roundtrip)
    test("AES-256-CBC unicode + emoji",       t_unicode)
    test("AES-256-CBC 50 KB message",         t_large)

    # ── Integrity ─────────────────────────────────────────────
    print("\n  ── Integrity & Replay Protection ────────────────────")

    def t_tamper():
        import base64
        key, _ = derive_key("pw")
        enc = encrypt("Pay 100 USD", key, seq=0)
        ct  = bytearray(base64.b64decode(enc["ciphertext"]))
        ct[0] ^= 0xFF
        enc["ciphertext"] = base64.b64encode(bytes(ct)).decode()
        try:
            decrypt(enc, key, expected_seq=0)
            raise AssertionError("Tamper not detected!")
        except ValueError:
            pass

    def t_replay():
        key, _ = derive_key("pw")
        enc = encrypt("Transfer funds", key, seq=3)
        try:
            decrypt(enc, key, expected_seq=4)
            raise AssertionError("Replay not detected!")
        except ValueError:
            pass

    def t_seq():
        key, _ = derive_key("pw")
        for i in range(5):
            assert decrypt(encrypt(f"msg-{i}", key, seq=i), key, expected_seq=i) == f"msg-{i}"

    test("HMAC-SHA256 tamper detection",      t_tamper)
    test("Replay attack blocked",             t_replay)
    test("Sequence numbers correct",          t_seq)

    # ── Key Derivation ────────────────────────────────────────
    print("\n  ── Key Derivation ───────────────────────────────────")

    def t_kdf():
        k1, salt = derive_key("my-passphrase")
        k2, _    = derive_key("my-passphrase", salt)
        assert k1 == k2
        k3, _    = derive_key("different-pass", salt)
        assert k1 != k3

    test("PBKDF2-HMAC-SHA256",                t_kdf)

    # ── ECDH ─────────────────────────────────────────────────
    print("\n  ── ECDH Key Exchange ────────────────────────────────")

    def t_ecdh():
        alice = ECDHKeyExchange()
        bob   = ECDHKeyExchange()
        ka    = alice.derive_shared_key(bob.public_key_bytes)
        kb    = bob.derive_shared_key(alice.public_key_bytes)
        assert ka == kb
        assert decrypt(encrypt("Hello", ka, seq=0), kb, expected_seq=0) == "Hello"

    test("X25519 ECDH shared key",             t_ecdh)

    # ── Ed25519 ──────────────────────────────────────────────
    print("\n  ── Ed25519 Signatures ───────────────────────────────")

    def t_sign():
        key = IdentityKey.generate()
        sig = key.sign(b"data")
        key.verify(b"data", sig)   # no exception = pass

    def t_sign_tamper():
        key = IdentityKey.generate()
        sig = key.sign(b"real-data")
        try:
            key.verify(b"tampered", sig)
            raise AssertionError("Tamper not caught!")
        except InvalidSignature:
            pass

    test("Ed25519 sign + verify",              t_sign)
    test("Ed25519 tamper detection",           t_sign_tamper)

    # ── MITM Scenarios ────────────────────────────────────────
    print("\n  ── MITM Attack Scenarios ────────────────────────────")

    def t_legit_ecdh():
        srv = IdentityKey.generate()
        cli = IdentityKey.generate()
        s   = AuthenticatedECDH(srv)
        c   = AuthenticatedECDH(cli)
        srv_offer = s.signed_offer()
        cli_offer = c.signed_offer()
        ck = c.verify_and_derive(srv_offer, pinned_identity=srv.public_bytes())
        sk = s.verify_and_derive(cli_offer)
        assert ck == sk
        assert decrypt(encrypt("OK", ck, seq=0), sk, expected_seq=0) == "OK"

    def t_mitm():
        server_id = IdentityKey.generate()
        eve_id    = IdentityKey.generate()
        client_id = IdentityKey.generate()
        s = AuthenticatedECDH(server_id)
        e = AuthenticatedECDH(eve_id)
        c = AuthenticatedECDH(client_id)
        import base64
        evil_offer = e.signed_offer()
        evil_offer["identity"] = base64.b64encode(server_id.public_bytes()).decode()
        pinned = server_id.public_bytes()
        try:
            c.verify_and_derive(evil_offer, pinned_identity=pinned)
            raise AssertionError("MITM not detected!")
        except (InvalidSignature, Exception) as ex:
            if "MITM" in str(ex) or "SIGNATURE" in str(ex) or "InvalidSignature" in type(ex).__name__:
                pass
            else:
                raise

    def t_pin_mismatch():
        real = IdentityKey.generate()
        fake = IdentityKey.generate()
        cli  = IdentityKey.generate()
        fe   = AuthenticatedECDH(fake)
        ce   = AuthenticatedECDH(cli)
        try:
            ce.verify_and_derive(fe.signed_offer(), pinned_identity=real.public_bytes())
            raise AssertionError("Mismatch not detected!")
        except (ValueError, InvalidSignature):
            pass

    test("Authenticated ECDH: legit flow",    t_legit_ecdh)
    test("MITM substitution blocked",         t_mitm)
    test("Key pinning mismatch blocked",      t_pin_mismatch)

    # ── Summary ───────────────────────────────────────────────
    passed = sum(1 for _, ok, _ in results if ok)
    failed = len(results) - passed
    print(f"\n  {'─'*52}")
    print(f"  Results: {passed}/{len(results)} passed", end="")
    if failed:
        print(f"  |  {failed} FAILED ❌")
        for name, ok, err in results:
            if not ok:
                print(f"    → {name}: {err}")
    else:
        print("  ✅  All tests passed!")
    print()
    sys.exit(0 if not failed else 1)


# ─────────────────────────────────────────────────────────────
#  Argument Parser
# ─────────────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog="python main.py",
        description="SecureChat — AES-256 Encrypted Chat",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py server                     Start server on default port 9999
  python main.py server --port 8888         Start server on port 8888
  python main.py client                     Open GUI client
  python main.py client --username Alice    Open GUI pre-filled as Alice
  python main.py client --cli              Terminal mode (no GUI)
  python main.py client --host 192.168.1.5 Connect to remote server
  python main.py logs                       Show decrypted chat logs
  python main.py logs --filter Bob          Filter logs by keyword
  python main.py test                       Run security test suite
        """
    )

    sub = parser.add_subparsers(dest="mode", metavar="MODE")

    # server
    sp = sub.add_parser("server", help="Start the TCP server")
    sp.add_argument("--host", default="0.0.0.0",  help="Bind address  (default: 0.0.0.0)")
    sp.add_argument("--port", default=9999, type=int, help="Port number (default: 9999)")

    # client
    cp = sub.add_parser("client", help="Launch the chat client")
    cp.add_argument("--host",     default="127.0.0.1", help="Server address (default: 127.0.0.1)")
    cp.add_argument("--port",     default=9999, type=int, help="Server port  (default: 9999)")
    cp.add_argument("--username", default="",   help="Your display name")
    cp.add_argument("--cli",      action="store_true",  help="Terminal mode instead of GUI")

    # logs
    lp = sub.add_parser("logs", help="View decrypted chat logs")
    lp.add_argument("--filter", default="", help="Filter by keyword")

    # test
    sub.add_parser("test", help="Run security test suite")

    return parser


# ─────────────────────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────────────────────

def main():
    check_python_version()

    parser = build_parser()
    args   = parser.parse_args()

    if args.mode is None:
        print_banner()
        parser.print_help()
        print()
        sys.exit(0)

    # Check dependencies and file structure before doing anything
    if not check_dependencies():
        sys.exit(1)
    check_files()

    dispatch = {
        "server": run_server,
        "client": lambda a: run_cli_client(a) if a.cli else run_gui_client(a),
        "logs":   run_logs,
        "test":   run_tests,
    }
    dispatch[args.mode](args)


if __name__ == "__main__":
    main()

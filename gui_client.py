"""
gui_client.py — SecureChat GUI
Screen 1: Login (enter username, connect)
Screen 2: Dashboard (online users list)
Screen 3: Chat windows (one per conversation, multiple allowed)
"""

import sys, os, threading, time
import tkinter as tk
from tkinter import scrolledtext, messagebox

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if THIS_DIR not in sys.path:
    sys.path.insert(0, THIS_DIR)

from client import SecureChatClient
from crypto import encrypt

# ── Colors ────────────────────────────────────────────────────
BG        = "#0d1117"
BG2       = "#161b22"
BG3       = "#21262d"
BORDER    = "#30363d"
ACCENT    = "#58a6ff"
ACCENT2   = "#3fb950"
WARN      = "#f85149"
TEXT      = "#e6edf3"
MUTED     = "#8b949e"
ORANGE    = "#f0883e"


# ═════════════════════════════════════════════════════════════
#  SCREEN 1 — LOGIN WINDOW
# ═════════════════════════════════════════════════════════════

class LoginWindow:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SecureChat — Login")
        self.root.geometry("420x480")
        self.root.configure(bg=BG)
        self.root.resizable(False, False)
        self.root.protocol("WM_DELETE_WINDOW", self.root.destroy)

        self._username = tk.StringVar(value="")
        self._host     = tk.StringVar(value="127.0.0.1")
        self._port     = tk.StringVar(value="9999")
        self._build()

    def _build(self):
        # Header
        hdr = tk.Frame(self.root, bg=BG2, height=100)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)
        tk.Label(hdr, text="🔐", bg=BG2, font=("Arial", 36)).pack(pady=(14, 0))
        tk.Label(hdr, text="SecureChat", bg=BG2, fg=TEXT,
                 font=("Courier New", 18, "bold")).pack()

        # Form
        frm = tk.Frame(self.root, bg=BG, padx=40)
        frm.pack(fill=tk.BOTH, expand=True, pady=20)

        def field(parent, label, var, placeholder=""):
            tk.Label(parent, text=label, bg=BG, fg=MUTED,
                     font=("Courier New", 9), anchor="w").pack(fill=tk.X, pady=(10, 2))
            e = tk.Entry(parent, textvariable=var, bg=BG3, fg=TEXT,
                         insertbackground=TEXT, relief=tk.FLAT,
                         font=("Courier New", 13))
            e.pack(fill=tk.X, ipady=8)
            return e

        name_entry = field(frm, "YOUR USERNAME", self._username)
        name_entry.focus_set()
        field(frm, "SERVER HOST", self._host)
        field(frm, "SERVER PORT", self._port)

        # Status label
        self._status = tk.Label(frm, text="", bg=BG, fg=WARN,
                                 font=("Courier New", 9))
        self._status.pack(pady=6)

        # Connect button
        self._btn = tk.Button(
            frm, text="Connect & Join", bg=ACCENT, fg="#000",
            font=("Courier New", 12, "bold"), relief=tk.FLAT,
            cursor="hand2", command=self._connect, activebackground="#79c0ff"
        )
        self._btn.pack(fill=tk.X, ipady=10, pady=(4, 0))

        # Hint
        tk.Label(frm, text="AES-256-CBC · X25519 ECDH · HMAC-SHA256",
                 bg=BG, fg=MUTED, font=("Courier New", 8)).pack(pady=8)

        self.root.bind("<Return>", lambda e: self._connect())

    def _connect(self):
        username = self._username.get().strip()
        host     = self._host.get().strip()
        port_str = self._port.get().strip()

        if not username:
            self._status.config(text="⚠ Please enter a username")
            return
        if len(username) < 2:
            self._status.config(text="⚠ Username must be at least 2 characters")
            return
        try:
            port = int(port_str)
        except ValueError:
            self._status.config(text="⚠ Invalid port number")
            return

        self._btn.config(text="Connecting...", state=tk.DISABLED,
                         bg=BG3, fg=MUTED)
        self._status.config(text="")

        def do():
            # Try to connect
            tmp_status = []
            client = SecureChatClient(
                host=host, port=port, username=username,
                on_message=lambda s, t: None,
                on_status=lambda t: tmp_status.append(t),
                on_userlist=lambda u: None,
            )
            ok = client.connect()
            if ok:
                client.disconnect()
                self.root.after(0, self._open_dashboard, username, host, port)
            else:
                err = tmp_status[-1] if tmp_status else "Could not connect"
                self.root.after(0, self._conn_failed, err)

        threading.Thread(target=do, daemon=True).start()

    def _open_dashboard(self, username, host, port):
        self.root.destroy()
        new_root = tk.Tk()
        new_root.configure(bg=BG)
        DashboardWindow(new_root, username=username, host=host, port=port)
        new_root.mainloop()

    def _conn_failed(self, err):
        self._btn.config(text="Connect & Join", state=tk.NORMAL,
                         bg=ACCENT, fg="#000")
        self._status.config(text=f"✗ {err}")


# ═════════════════════════════════════════════════════════════
#  SCREEN 2 — DASHBOARD (users list + active chats)
# ═════════════════════════════════════════════════════════════

class DashboardWindow:
    def __init__(self, root: tk.Tk, username: str, host: str, port: int):
        self.root     = root
        self.username = username
        self.host     = host
        self.port     = port

        self.root.title(f"SecureChat — {username}")
        self.root.geometry("860x560")
        self.root.configure(bg=BG)
        self.root.minsize(700, 450)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        # Active chat windows: {other_username: ChatWindow}
        self._chats: dict = {}
        self._client      = None
        self._online_users = []

        self._build()
        self._connect()

    def _build(self):
        # ── Top bar
        topbar = tk.Frame(self.root, bg=BG2, height=52)
        topbar.pack(fill=tk.X)
        topbar.pack_propagate(False)

        tk.Label(topbar, text="🔐 SecureChat", bg=BG2, fg=TEXT,
                 font=("Courier New", 14, "bold"), padx=16).pack(side=tk.LEFT, pady=12)

        tk.Label(topbar, text=f"Logged in as:", bg=BG2, fg=MUTED,
                 font=("Courier New", 9)).pack(side=tk.RIGHT, padx=(0, 4), pady=12)
        tk.Label(topbar, text=self.username, bg=BG2, fg=ACCENT,
                 font=("Courier New", 11, "bold")).pack(side=tk.RIGHT, pady=12)

        self._dot = tk.Label(topbar, text="●", bg=BG2, fg=WARN, font=("Arial", 14))
        self._dot.pack(side=tk.RIGHT, padx=(0, 8), pady=12)

        # ── Main area
        main = tk.Frame(self.root, bg=BG)
        main.pack(fill=tk.BOTH, expand=True)

        # ── Left: Users Panel
        left = tk.Frame(main, bg=BG2, width=220)
        left.pack(fill=tk.Y, side=tk.LEFT)
        left.pack_propagate(False)

        tk.Label(left, text="ONLINE USERS", bg=BG2, fg=MUTED,
                 font=("Courier New", 9, "bold"), pady=14).pack(fill=tk.X, padx=14)

        tk.Frame(left, bg=BORDER, height=1).pack(fill=tk.X)

        # Scrollable user list
        self._users_frame = tk.Frame(left, bg=BG2)
        self._users_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        self._no_users_lbl = tk.Label(
            self._users_frame,
            text="Waiting for others\nto join...",
            bg=BG2, fg=MUTED,
            font=("Courier New", 9),
            justify=tk.CENTER
        )
        self._no_users_lbl.pack(pady=20)

        # Bottom status in sidebar
        tk.Frame(left, bg=BORDER, height=1).pack(fill=tk.X)
        self._conn_lbl = tk.Label(left, text="Connecting...", bg=BG2, fg=MUTED,
                                   font=("Courier New", 8), pady=8)
        self._conn_lbl.pack()

        # ── Separator
        tk.Frame(main, bg=BORDER, width=1).pack(fill=tk.Y, side=tk.LEFT)

        # ── Right: Main area
        right = tk.Frame(main, bg=BG)
        right.pack(fill=tk.BOTH, expand=True)

        # Welcome / instruction panel
        self._welcome = tk.Frame(right, bg=BG)
        self._welcome.pack(fill=tk.BOTH, expand=True)

        tk.Label(self._welcome, text="👈  Select a user to start chatting",
                 bg=BG, fg=MUTED,
                 font=("Courier New", 13)).pack(expand=True)
        tk.Label(self._welcome,
                 text="You can open multiple private chat windows simultaneously.",
                 bg=BG, fg=MUTED,
                 font=("Courier New", 9)).pack(pady=(0, 40))

    def _connect(self):
        def do():
            self._client = SecureChatClient(
                host=self.host, port=self.port,
                username=self.username,
                on_message=self._on_message,
                on_status=self._on_status,
                on_userlist=self._on_userlist,
            )
            ok = self._client.connect()
            self.root.after(0, self._post_connect, ok)

        threading.Thread(target=do, daemon=True).start()

    def _post_connect(self, ok):
        if ok:
            self._dot.config(fg=ACCENT2)
            self._conn_lbl.config(text="🔒 Encrypted", fg=ACCENT2)
        else:
            self._dot.config(fg=WARN)
            self._conn_lbl.config(text="✗ Disconnected", fg=WARN)

    # ── Callbacks from client thread ──────────────────────────

    def _on_message(self, sender: str, text: str):
        """Incoming private message — route to correct chat window."""
        self.root.after(0, self._route_message, sender, text)

    def _on_status(self, text: str):
        self.root.after(0, lambda: self._conn_lbl.config(text=text[:30]))

    def _on_userlist(self, users: list):
        """Server sent updated online users list."""
        self.root.after(0, self._refresh_users, users)

    def _route_message(self, sender: str, text: str):
        """Open chat window if not open, then deliver message."""
        if sender not in self._chats or not self._chats[sender].is_alive():
            self._open_chat(sender)
        self._chats[sender].receive_message(sender, text)

    # ── User list UI ──────────────────────────────────────────

    def _refresh_users(self, users: list):
        self._online_users = users

        # Clear existing buttons
        for w in self._users_frame.winfo_children():
            w.destroy()

        if not users:
            tk.Label(self._users_frame,
                     text="No other users\nonline yet...",
                     bg=BG2, fg=MUTED,
                     font=("Courier New", 9),
                     justify=tk.CENTER).pack(pady=20)
            return

        tk.Label(self._users_frame,
                 text=f"{len(users)} user(s) online",
                 bg=BG2, fg=MUTED,
                 font=("Courier New", 8)).pack(anchor="w", padx=4, pady=(4, 8))

        for uname in users:
            self._make_user_btn(uname)

        # Notify open chat windows of disconnected users
        for open_user in list(self._chats.keys()):
            if open_user not in users and open_user in self._chats:
                w = self._chats[open_user]
                if w.is_alive():
                    w.set_offline()

    def _make_user_btn(self, uname: str):
        btn_frame = tk.Frame(self._users_frame, bg=BG2)
        btn_frame.pack(fill=tk.X, pady=2)

        # Unread indicator
        indicator = tk.Label(btn_frame, text="", bg=BG2,
                              font=("Arial", 8), fg=ORANGE, width=2)
        indicator.pack(side=tk.LEFT, padx=(2, 0))

        btn = tk.Button(
            btn_frame,
            text=f"  {uname}",
            bg=BG3, fg=TEXT,
            font=("Courier New", 11),
            relief=tk.FLAT, cursor="hand2",
            anchor="w",
            activebackground=BORDER,
            command=lambda u=uname: self._open_chat(u)
        )
        btn.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=8)

        # Chat icon
        tk.Label(btn_frame, text="💬", bg=BG2,
                 font=("Arial", 10)).pack(side=tk.RIGHT, padx=6)

        # Hover effects
        btn.bind("<Enter>", lambda e: btn.config(bg=BORDER))
        btn.bind("<Leave>", lambda e: btn.config(bg=BG3))

    # ── Open / manage chat windows ────────────────────────────

    def _open_chat(self, other_user: str):
        """Open a chat window for a private conversation."""
        # If already open, just bring to front
        if other_user in self._chats and self._chats[other_user].is_alive():
            self._chats[other_user].focus()
            return

        # Create new chat window
        win = ChatWindow(
            parent_root=self.root,
            my_username=self.username,
            other_username=other_user,
            send_fn=lambda text, to=other_user: self._client.send_private(to, text)
        )
        self._chats[other_user] = win

    def _on_close(self):
        if self._client:
            self._client.disconnect()
        # Close all chat windows
        for win in self._chats.values():
            win.close()
        self.root.destroy()


# ═════════════════════════════════════════════════════════════
#  SCREEN 3 — CHAT WINDOW (one per conversation)
# ═════════════════════════════════════════════════════════════

class ChatWindow:
    def __init__(self, parent_root, my_username, other_username, send_fn):
        self.my_username    = my_username
        self.other_username = other_username
        self.send_fn        = send_fn
        self._alive         = True

        # Create independent Toplevel window
        self.win = tk.Toplevel(parent_root)
        self.win.title(f"Chat with {other_username}")
        self.win.geometry("600x480")
        self.win.configure(bg=BG)
        self.win.minsize(480, 360)
        self.win.protocol("WM_DELETE_WINDOW", self.close)

        self._build()

        # Bring to front
        self.win.lift()
        self.win.focus_force()

    def _build(self):
        # ── Header
        hdr = tk.Frame(self.win, bg=BG2, height=52)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)

        av = tk.Label(hdr, text=self.other_username[0].upper(),
                      bg=BORDER, fg=ACCENT2,
                      font=("Courier New", 14, "bold"),
                      width=2, height=1)
        av.pack(side=tk.LEFT, padx=14, pady=10)

        info = tk.Frame(hdr, bg=BG2)
        info.pack(side=tk.LEFT, pady=10)
        tk.Label(info, text=self.other_username, bg=BG2, fg=TEXT,
                 font=("Courier New", 13, "bold")).pack(anchor="w")

        self._status_lbl = tk.Label(info, text="● Online — AES-256 Encrypted",
                                     bg=BG2, fg=ACCENT2,
                                     font=("Courier New", 8))
        self._status_lbl.pack(anchor="w")

        tk.Label(hdr, text="🔒", bg=BG2, font=("Arial", 18)).pack(side=tk.RIGHT, padx=14)

        # ── Messages
        self._display = scrolledtext.ScrolledText(
            self.win, bg=BG, fg=TEXT,
            font=("Courier New", 11),
            relief=tk.FLAT, state=tk.DISABLED,
            wrap=tk.WORD, padx=14, pady=10,
            spacing3=4, highlightthickness=0
        )
        self._display.pack(fill=tk.BOTH, expand=True)

        # Tags
        self._display.tag_config("self_name", foreground=ACCENT,
                                  font=("Courier New", 10, "bold"))
        self._display.tag_config("peer_name", foreground=ACCENT2,
                                  font=("Courier New", 10, "bold"))
        self._display.tag_config("self_msg",  foreground=TEXT)
        self._display.tag_config("peer_msg",  foreground=TEXT)
        self._display.tag_config("ts",        foreground=MUTED,
                                  font=("Courier New", 8))
        self._display.tag_config("system",    foreground=ORANGE,
                                  font=("Courier New", 9, "italic"))
        self._display.tag_config("divider",   foreground=BORDER)

        self._append_system(
            f"Private chat with {self.other_username} — "
            f"messages are end-to-end encrypted 🔒"
        )

        # ── Input bar
        bar = tk.Frame(self.win, bg=BG2)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        tk.Frame(bar, bg=BORDER, height=1).pack(fill=tk.X)

        inner = tk.Frame(bar, bg=BG2, pady=10, padx=12)
        inner.pack(fill=tk.X)

        tk.Label(inner, text="🔒", bg=BG2, font=("Arial", 13)).pack(
            side=tk.LEFT, padx=(0, 8))

        self._input = tk.Entry(
            inner, bg=BG3, fg=TEXT, insertbackground=TEXT,
            relief=tk.FLAT, font=("Courier New", 12)
        )
        self._input.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=8, padx=(0, 10))
        self._input.bind("<Return>", self._send)
        self._input.focus_set()

        self._send_btn = tk.Button(
            inner, text="Send ⮞", bg=ACCENT, fg="#000",
            font=("Courier New", 11, "bold"), relief=tk.FLAT,
            cursor="hand2", command=self._send,
            activebackground="#79c0ff"
        )
        self._send_btn.pack(side=tk.RIGHT, ipady=8, ipadx=14)

        # Cipher preview
        self._enc_hint = tk.Label(
            bar, text="", bg=BG2, fg=MUTED, font=("Courier New", 8)
        )
        self._enc_hint.pack(side=tk.RIGHT, padx=14, pady=(0, 6))

    # ── Send ──────────────────────────────────────────────────

    def _send(self, event=None):
        text = self._input.get().strip()
        if not text:
            return
        self._input.delete(0, tk.END)
        self._enc_hint.config(text="")

        ok = self.send_fn(text)
        if ok:
            self._append_self(text)
        else:
            self._append_system("Failed to send message.")

    # ── Receive ───────────────────────────────────────────────

    def receive_message(self, sender: str, text: str):
        """Called from dashboard when a message arrives for this chat."""
        self.win.after(0, self._append_peer, text)
        # Bring window to attention
        self.win.after(0, self.win.bell)

    def set_offline(self):
        """Called when the other user disconnects."""
        self.win.after(0, lambda: self._status_lbl.config(
            text="● Offline", fg=WARN))
        self.win.after(0, lambda: self._append_system(
            f"{self.other_username} has gone offline."))
        self.win.after(0, lambda: self._send_btn.config(
            state=tk.DISABLED, bg=BG3, fg=MUTED))

    # ── Display helpers ───────────────────────────────────────

    def _ts(self):
        return time.strftime("%H:%M:%S")

    def _append_self(self, text: str):
        self._display.config(state=tk.NORMAL)
        self._display.insert(tk.END, f"[{self._ts()}] ", "ts")
        self._display.insert(tk.END, f"{self.my_username}: ", "self_name")
        self._display.insert(tk.END, f"{text}\n", "self_msg")
        self._display.config(state=tk.DISABLED)
        self._display.see(tk.END)

    def _append_peer(self, text: str):
        self._display.config(state=tk.NORMAL)
        self._display.insert(tk.END, f"[{self._ts()}] ", "ts")
        self._display.insert(tk.END, f"{self.other_username}: ", "peer_name")
        self._display.insert(tk.END, f"{text}\n", "peer_msg")
        self._display.config(state=tk.DISABLED)
        self._display.see(tk.END)

    def _append_system(self, text: str):
        self._display.config(state=tk.NORMAL)
        self._display.insert(tk.END, f"  ⚙ {text}\n", "system")
        self._display.config(state=tk.DISABLED)
        self._display.see(tk.END)

    # ── Lifecycle ─────────────────────────────────────────────

    def is_alive(self):
        try:
            return self._alive and self.win.winfo_exists()
        except Exception:
            return False

    def focus(self):
        try:
            self.win.lift()
            self.win.focus_force()
        except Exception:
            pass

    def close(self):
        self._alive = False
        try:
            self.win.destroy()
        except Exception:
            pass


# ═════════════════════════════════════════════════════════════
#  Entry Point
# ═════════════════════════════════════════════════════════════

def main():
    root = tk.Tk()
    root.configure(bg=BG)
    LoginWindow(root)
    root.mainloop()


if __name__ == "__main__":
    main()

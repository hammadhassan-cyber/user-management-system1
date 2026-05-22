import csv
import hashlib
import os
import re
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta
from typing import Optional

# ── GUI ───────────────────────────────────────────────────────────────
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk


# ═════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════

DB_PATH           = "user_management.db"
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES   = 15
APP_TITLE         = "User Management System"
FF                = "Segoe UI"          # font family


# ═════════════════════════════════════════════════════════════════════
#  COLOUR PALETTE
# ═════════════════════════════════════════════════════════════════════

C = {
    "bg":       "#0f1117",
    "surface":  "#1a1d27",
    "surface2": "#22263a",
    "accent":   "#6366f1",
    "accent2":  "#818cf8",
    "danger":   "#ef4444",
    "success":  "#22c55e",
    "warning":  "#f59e0b",
    "text":     "#f1f5f9",
    "muted":    "#94a3b8",
    "border":   "#2e3347",
    "entry":    "#1e2235",
}


# ═════════════════════════════════════════════════════════════════════
#  DATABASE LAYER
# ═════════════════════════════════════════════════════════════════════

class Database:
    """
    Thin wrapper around sqlite3.  One connection per thread via
    threading.local() – safe for Tkinter + background work.
    """

    def __init__(self, path: str = DB_PATH) -> None:
        self._path  = path
        self._local = threading.local()
        self._bootstrap()

    # ── connection ────────────────────────────────────────────────────

    @property
    def _conn(self) -> sqlite3.Connection:
        if not getattr(self._local, "conn", None):
            conn = sqlite3.connect(self._path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode  = WAL")
            self._local.conn = conn
        return self._local.conn

    def close(self) -> None:
        if getattr(self._local, "conn", None):
            self._local.conn.close()
            self._local.conn = None

    # ── schema ────────────────────────────────────────────────────────

    def _bootstrap(self) -> None:
        with self._conn:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    username    TEXT    NOT NULL UNIQUE COLLATE NOCASE,
                    email       TEXT    NOT NULL UNIQUE COLLATE NOCASE,
                    password    TEXT    NOT NULL,
                    salt        TEXT    NOT NULL,
                    phone       TEXT    DEFAULT '',
                    role        TEXT    NOT NULL DEFAULT 'User'
                                        CHECK(role IN ('Admin','User')),
                    is_active   INTEGER NOT NULL DEFAULT 1,
                    created_at  TEXT    NOT NULL
                );

                CREATE TABLE IF NOT EXISTS login_attempts (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    username     TEXT    NOT NULL COLLATE NOCASE,
                    attempted_at TEXT    NOT NULL,
                    success      INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS reset_tokens (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    token      TEXT    NOT NULL UNIQUE,
                    expires_at TEXT    NOT NULL,
                    used       INTEGER NOT NULL DEFAULT 0
                );
            """)
        # seed default admin once
        if not self.fetchone("SELECT 1 FROM users WHERE role='Admin'"):
            salt = secrets.token_hex(32)
            pw   = _hash_pw("Admin@123", salt)
            self.run(
                "INSERT INTO users(username,email,password,salt,phone,role,created_at)"
                " VALUES(?,?,?,?,?,?,?)",
                ("admin", "admin@system.local", pw, salt, "", "Admin",
                 _now()),
                commit=True,
            )

    # ── helpers ───────────────────────────────────────────────────────

    def run(self, sql: str, params: tuple = (), *, commit: bool = False
            ) -> sqlite3.Cursor:
        cur = self._conn.execute(sql, params)
        if commit:
            self._conn.commit()
        return cur

    def fetchone(self, sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        return self._conn.execute(sql, params).fetchone()

    def fetchall(self, sql: str, params: tuple = ()) -> list:
        return self._conn.execute(sql, params).fetchall()

    def commit(self) -> None:
        self._conn.commit()


# ═════════════════════════════════════════════════════════════════════
#  SECURITY / VALIDATION HELPERS
# ═════════════════════════════════════════════════════════════════════

def _now() -> str:
    return datetime.now().isoformat(sep=" ", timespec="seconds")


def _hash_pw(password: str, salt: str) -> str:
    """PBKDF2-HMAC-SHA256 — never store plain-text passwords."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt.encode(),
        iterations=260_000,
    ).hex()


def _validate_email(email: str) -> bool:
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email))


def _validate_password(pw: str) -> tuple:
    """Returns (ok: bool, message: str)."""
    if len(pw) < 8:
        return False, "Password must be at least 8 characters."
    if not re.search(r"[A-Z]", pw):
        return False, "Password needs at least one uppercase letter."
    if not re.search(r"[0-9]", pw):
        return False, "Password needs at least one digit."
    if not re.search(r'[!@#$%^&*()\-_=+\[\]{};:\'",.<>?/\\|`~]', pw):
        return False, "Password needs at least one special character."
    return True, ""


def _validate_phone(phone: str) -> bool:
    return not phone or bool(re.fullmatch(r"\+?[\d\s\-]{7,15}", phone))


# ═════════════════════════════════════════════════════════════════════
#  SERVICE LAYER  (all business logic lives here — no GUI imports)
# ═════════════════════════════════════════════════════════════════════

class UserService:
    """Single facade the GUI uses.  Returns plain dicts, no Tk objects."""

    def __init__(self, db: Database) -> None:
        self._db = db

    # ── lock-out helpers ──────────────────────────────────────────────

    def _failed_count(self, username: str) -> int:
        cutoff = (datetime.now() - timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
        row = self._db.fetchone(
            "SELECT COUNT(*) FROM login_attempts"
            " WHERE username=? AND success=0 AND attempted_at>?",
            (username, cutoff),
        )
        return row[0] if row else 0

    def _is_locked(self, username: str) -> tuple:
        """Returns (locked: bool, seconds_remaining: int)."""
        if self._failed_count(username) >= MAX_LOGIN_ATTEMPTS:
            row = self._db.fetchone(
                "SELECT attempted_at FROM login_attempts"
                " WHERE username=? AND success=0"
                " ORDER BY attempted_at DESC LIMIT 1",
                (username,),
            )
            if row:
                unlock = (
                    datetime.fromisoformat(row[0])
                    + timedelta(minutes=LOCKOUT_MINUTES)
                )
                secs = max(0, int((unlock - datetime.now()).total_seconds()))
                return True, secs
        return False, 0

    def _log_attempt(self, username: str, success: bool) -> None:
        self._db.run(
            "INSERT INTO login_attempts(username,attempted_at,success) VALUES(?,?,?)",
            (username, _now(), int(success)),
            commit=True,
        )

    # ── authentication ────────────────────────────────────────────────

    def register(self, username: str, email: str, password: str,
                 phone: str = "", role: str = "User") -> dict:
        username = username.strip()
        email    = email.strip().lower()
        phone    = phone.strip()

        if len(username) < 3:
            return {"ok": False, "msg": "Username must be at least 3 characters."}
        if not _validate_email(email):
            return {"ok": False, "msg": "Invalid e-mail address."}
        ok, msg = _validate_password(password)
        if not ok:
            return {"ok": False, "msg": msg}
        if not _validate_phone(phone):
            return {"ok": False, "msg": "Invalid phone number."}

        if self._db.fetchone("SELECT 1 FROM users WHERE username=?", (username,)):
            return {"ok": False, "msg": "Username already taken."}
        if self._db.fetchone("SELECT 1 FROM users WHERE email=?", (email,)):
            return {"ok": False, "msg": "E-mail already registered."}

        salt   = secrets.token_hex(32)
        hashed = _hash_pw(password, salt)
        self._db.run(
            "INSERT INTO users(username,email,password,salt,phone,role,created_at)"
            " VALUES(?,?,?,?,?,?,?)",
            (username, email, hashed, salt, phone, role, _now()),
            commit=True,
        )
        return {"ok": True, "msg": "Account created successfully!"}

    def login(self, username: str, password: str) -> dict:
        username = username.strip()
        locked, secs = self._is_locked(username)
        if locked:
            m, s = divmod(secs, 60)
            return {"ok": False,
                    "msg": f"Account locked. Try again in {m}m {s}s."}

        user = self._db.fetchone(
            "SELECT * FROM users WHERE username=? AND is_active=1",
            (username,),
        )
        if not user or _hash_pw(password, user["salt"]) != user["password"]:
            self._log_attempt(username, False)
            left = max(0, MAX_LOGIN_ATTEMPTS - self._failed_count(username))
            return {"ok": False,
                    "msg": f"Invalid credentials. {left} attempt(s) left before lock."}

        self._log_attempt(username, True)
        return {"ok": True, "msg": "Welcome back!", "user": dict(user)}

    # ── CRUD ──────────────────────────────────────────────────────────

    def get_user(self, user_id: int) -> Optional[dict]:
        row = self._db.fetchone("SELECT * FROM users WHERE id=?", (user_id,))
        return dict(row) if row else None

    def update_profile(self, user_id: int, email: str,
                       phone: str, new_password: str = "") -> dict:
        email = email.strip().lower()
        phone = phone.strip()

        if not _validate_email(email):
            return {"ok": False, "msg": "Invalid e-mail address."}
        if not _validate_phone(phone):
            return {"ok": False, "msg": "Invalid phone number."}
        dup = self._db.fetchone(
            "SELECT id FROM users WHERE email=? AND id<>?", (email, user_id)
        )
        if dup:
            return {"ok": False, "msg": "E-mail used by another account."}

        if new_password:
            ok, msg = _validate_password(new_password)
            if not ok:
                return {"ok": False, "msg": msg}
            salt   = secrets.token_hex(32)
            hashed = _hash_pw(new_password, salt)
            self._db.run(
                "UPDATE users SET email=?,phone=?,password=?,salt=? WHERE id=?",
                (email, phone, hashed, salt, user_id),
                commit=True,
            )
        else:
            self._db.run(
                "UPDATE users SET email=?,phone=? WHERE id=?",
                (email, phone, user_id),
                commit=True,
            )
        return {"ok": True, "msg": "Profile updated successfully!"}

    def delete_user(self, target_id: int,
                    requesting_id: int, is_admin: bool) -> dict:
        target = self._db.fetchone("SELECT * FROM users WHERE id=?", (target_id,))
        if not target:
            return {"ok": False, "msg": "User not found."}
        if not is_admin and target_id != requesting_id:
            return {"ok": False, "msg": "Permission denied."}
        if target["role"] == "Admin":
            count = self._db.fetchone(
                "SELECT COUNT(*) FROM users WHERE role='Admin'"
            )
            if count and count[0] <= 1:
                return {"ok": False,
                        "msg": "Cannot delete the sole admin account."}
        self._db.run("DELETE FROM users WHERE id=?", (target_id,), commit=True)
        return {"ok": True, "msg": "User deleted."}

    # ── admin queries ─────────────────────────────────────────────────

    def list_users(self, search: str = "",
                   role_filter: str = "All") -> list:
        sql    = "SELECT * FROM users WHERE 1=1"
        params = []
        if search:
            sql += " AND (username LIKE ? OR email LIKE ?)"
            params += [f"%{search}%", f"%{search}%"]
        if role_filter != "All":
            sql += " AND role=?"
            params.append(role_filter)
        sql += " ORDER BY created_at DESC"
        return [dict(r) for r in self._db.fetchall(sql, tuple(params))]

    def set_role(self, user_id: int, role: str) -> dict:
        if role not in ("Admin", "User"):
            return {"ok": False, "msg": "Invalid role."}
        self._db.run("UPDATE users SET role=? WHERE id=?",
                     (role, user_id), commit=True)
        return {"ok": True, "msg": f"Role set to {role}."}

    def toggle_active(self, user_id: int) -> dict:
        row = self._db.fetchone(
            "SELECT is_active FROM users WHERE id=?", (user_id,)
        )
        if not row:
            return {"ok": False, "msg": "User not found."}
        new_val = 0 if row["is_active"] else 1
        self._db.run("UPDATE users SET is_active=? WHERE id=?",
                     (new_val, user_id), commit=True)
        return {"ok": True,
                "msg": "User " + ("activated." if new_val else "deactivated.")}

    def export_csv(self, filepath: str) -> dict:
        users  = self.list_users()
        fields = ["id", "username", "email", "phone",
                  "role", "is_active", "created_at"]
        try:
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
                w.writeheader()
                w.writerows(users)
            return {"ok": True,
                    "msg": f"Exported {len(users)} user(s) to:\n{filepath}"}
        except OSError as exc:
            return {"ok": False, "msg": str(exc)}

    # ── password-reset (token simulation) ────────────────────────────

    def generate_reset_token(self, email: str) -> dict:
        email = email.strip().lower()
        user  = self._db.fetchone(
            "SELECT id, username FROM users WHERE email=? AND is_active=1",
            (email,),
        )
        if not user:
            return {"ok": False,
                    "msg": "No active account found for that e-mail."}
        token   = secrets.token_urlsafe(32)
        expires = (datetime.now() + timedelta(hours=1)).isoformat()
        self._db.run(
            "INSERT INTO reset_tokens(user_id,token,expires_at) VALUES(?,?,?)",
            (user["id"], token, expires),
            commit=True,
        )
        return {"ok": True, "msg": "Token generated.",
                "token": token, "username": user["username"]}

    def reset_with_token(self, token: str, new_password: str) -> dict:
        row = self._db.fetchone(
            "SELECT rt.user_id FROM reset_tokens rt"
            " WHERE rt.token=? AND rt.used=0 AND rt.expires_at>?",
            (token, datetime.now().isoformat()),
        )
        if not row:
            return {"ok": False, "msg": "Token is invalid or has expired."}
        ok, msg = _validate_password(new_password)
        if not ok:
            return {"ok": False, "msg": msg}
        salt   = secrets.token_hex(32)
        hashed = _hash_pw(new_password, salt)
        uid    = row["user_id"]
        self._db.run("UPDATE users SET password=?,salt=? WHERE id=?",
                     (hashed, salt, uid), commit=True)
        self._db.run("UPDATE reset_tokens SET used=1 WHERE token=?",
                     (token,), commit=True)
        return {"ok": True, "msg": "Password reset successfully!"}

    def login_history(self, username: str, limit: int = 10) -> list:
        return [
            dict(r) for r in self._db.fetchall(
                "SELECT attempted_at, success FROM login_attempts"
                " WHERE username=? ORDER BY attempted_at DESC LIMIT ?",
                (username, limit),
            )
        ]


# ═════════════════════════════════════════════════════════════════════
#  GUI — THEME
# ═════════════════════════════════════════════════════════════════════

def _apply_theme(root: tk.Tk) -> None:
    s = ttk.Style(root)
    s.theme_use("clam")

    s.configure(".",
                background=C["bg"], foreground=C["text"],
                font=(FF, 10), borderwidth=0, relief="flat")

    s.configure("TFrame",           background=C["bg"])
    s.configure("Card.TFrame",      background=C["surface"])
    s.configure("Card2.TFrame",     background=C["surface2"])
    s.configure("Sidebar.TFrame",   background=C["surface"])

    s.configure("TLabel",           background=C["bg"],      foreground=C["text"])
    s.configure("Card.TLabel",      background=C["surface"], foreground=C["text"])
    s.configure("Muted.TLabel",     background=C["bg"],      foreground=C["muted"])
    s.configure("CardMuted.TLabel", background=C["surface"], foreground=C["muted"])
    s.configure("Title.TLabel",     background=C["bg"],
                foreground=C["accent2"], font=(FF, 22, "bold"))
    s.configure("Header.TLabel",    background=C["bg"],
                foreground=C["text"],   font=(FF, 14, "bold"))
    s.configure("CardHeader.TLabel",background=C["surface"],
                foreground=C["text"],   font=(FF, 13, "bold"))
    s.configure("Success.TLabel",   background=C["bg"],      foreground=C["success"])
    s.configure("Error.TLabel",     background=C["bg"],      foreground=C["danger"])
    s.configure("CardSuccess.TLabel",background=C["surface"],foreground=C["success"])
    s.configure("CardError.TLabel", background=C["surface"], foreground=C["danger"])

    s.configure("TEntry",
                fieldbackground=C["entry"], foreground=C["text"],
                insertcolor=C["text"],      bordercolor=C["border"],
                lightcolor=C["border"],     darkcolor=C["border"],
                font=(FF, 10), padding=7)
    s.map("TEntry",
          fieldbackground=[("focus", C["surface2"])],
          bordercolor=[("focus", C["accent"])])

    def _btn(name, bg, fg="#ffffff", abg=None):
        s.configure(f"{name}.TButton",
                    background=bg, foreground=fg,
                    font=(FF, 10, "bold"), padding=(14, 7),
                    borderwidth=0, relief="flat")
        s.map(f"{name}.TButton",
              background=[("active", abg or bg),
                          ("pressed", bg)],
              foreground=[("active", fg)])

    _btn("Accent",  C["accent"],  abg=C["accent2"])
    _btn("Danger",  C["danger"],  abg="#dc2626")
    _btn("Ghost",   C["surface"], fg=C["muted"],
         abg=C["surface2"])
    _btn("Success", C["success"], abg="#16a34a")

    s.configure("Treeview",
                background=C["surface"], foreground=C["text"],
                fieldbackground=C["surface"], rowheight=30,
                font=(FF, 10))
    s.configure("Treeview.Heading",
                background=C["surface2"], foreground=C["accent2"],
                font=(FF, 10, "bold"), relief="flat")
    s.map("Treeview",
          background=[("selected", C["accent"])],
          foreground=[("selected", "#ffffff")])

    s.configure("TCombobox",
                fieldbackground=C["entry"], foreground=C["text"],
                background=C["surface"],   selectbackground=C["accent"],
                font=(FF, 10))

    s.configure("TScrollbar",
                background=C["surface2"], troughcolor=C["surface"],
                arrowcolor=C["muted"],    borderwidth=0)

    s.configure("TSeparator", background=C["border"])


# ═════════════════════════════════════════════════════════════════════
#  GUI — REUSABLE BUILDING BLOCKS
# ═════════════════════════════════════════════════════════════════════

class PlaceholderEntry(ttk.Entry):
    """Entry with greyed placeholder text and optional password masking."""

    def __init__(self, parent, placeholder: str = "",
                 password: bool = False, **kw) -> None:
        super().__init__(parent, **kw)
        self._ph       = placeholder
        self._pw       = password
        self._active   = False          # False = showing placeholder
        self.bind("<FocusIn>",  self._focus_in)
        self.bind("<FocusOut>", self._focus_out)
        self._show_placeholder()

    def _show_placeholder(self) -> None:
        self._active = False
        self.config(show="", foreground=C["muted"])
        self.delete(0, tk.END)
        self.insert(0, self._ph)

    def _focus_in(self, _=None) -> None:
        if not self._active:
            self._active = True
            self.delete(0, tk.END)
            self.config(show="•" if self._pw else "",
                        foreground=C["text"])

    def _focus_out(self, _=None) -> None:
        if not self.get():
            self._show_placeholder()

    def value(self) -> str:
        """Return the real typed value (empty string if placeholder shown)."""
        return "" if not self._active else self.get()

    def set_value(self, text: str) -> None:
        """Pre-fill the entry with a real value."""
        self._active = True
        self.delete(0, tk.END)
        self.config(show="•" if self._pw else "",
                    foreground=C["text"])
        self.insert(0, text)


def labeled_field(parent, label: str, placeholder: str = "",
                  password: bool = False,
                  bg: str = C["bg"]) -> PlaceholderEntry:
    """
    Returns a PlaceholderEntry after packing a label + entry pair
    into *parent*.
    """
    lbl_style = "CardMuted.TLabel" if bg == C["surface"] else "Muted.TLabel"
    ttk.Label(parent, text=label, style=lbl_style,
              font=(FF, 9)).pack(anchor="w", pady=(8, 2))
    e = PlaceholderEntry(parent, placeholder=placeholder, password=password)
    e.pack(fill="x")
    return e


def divider(parent, bg: str = C["bg"]) -> None:
    ttk.Separator(parent, orient="horizontal").pack(fill="x", pady=10)


def status_label(parent, bg: str = C["bg"]) -> tk.StringVar:
    """Creates a status label and returns its StringVar."""
    var = tk.StringVar()
    ttk.Label(parent, textvariable=var, style="CardError.TLabel",
              wraplength=340, justify="left").pack(anchor="w", pady=(6, 0))
    return var


# ═════════════════════════════════════════════════════════════════════
#  GUI — LOGIN SCREEN
# ═════════════════════════════════════════════════════════════════════

class LoginScreen(ttk.Frame):

    def __init__(self, parent, svc: UserService, on_login) -> None:
        super().__init__(parent)
        self._svc      = svc
        self._on_login = on_login
        self._build()

    def _build(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        wrap = ttk.Frame(self)
        wrap.grid(row=0, column=0)

        # ── branding
        ttk.Label(wrap, text="⬡ UMS", style="Title.TLabel",
                  font=(FF, 32, "bold")).pack(pady=(50, 4))
        ttk.Label(wrap, text="User Management System",
                  style="Muted.TLabel").pack(pady=(0, 32))

        # ── card
        card = ttk.Frame(wrap, style="Card.TFrame")
        card.pack(ipadx=30, ipady=24)

        inner = ttk.Frame(card, style="Card.TFrame")
        inner.pack(fill="both", padx=30, pady=24)

        ttk.Label(inner, text="Sign In",
                  style="CardHeader.TLabel").pack(anchor="w", pady=(0, 14))

        self._u = labeled_field(inner, "Username", "your username", bg=C["surface"])
        self._p = labeled_field(inner, "Password", "your password",
                                password=True, bg=C["surface"])

        ttk.Button(inner, text="Forgot password?", style="Ghost.TButton",
                   command=self._forgot).pack(anchor="e", pady=(6, 12))

        ttk.Button(inner, text="Sign In  →", style="Accent.TButton",
                   command=self._login).pack(fill="x")

        divider(inner, C["surface"])

        row = ttk.Frame(inner, style="Card.TFrame")
        row.pack()
        ttk.Label(row, text="No account? ",
                  style="CardMuted.TLabel").pack(side="left")
        ttk.Button(row, text="Register here", style="Ghost.TButton",
                   command=self._go_register).pack(side="left")

        self._msg = tk.StringVar()
        ttk.Label(inner, textvariable=self._msg,
                  style="CardError.TLabel",
                  wraplength=300).pack(pady=(10, 0))

        self.bind_all("<Return>", lambda _: self._login())

    # ── actions ────────────────────────────────────────────────────────

    def _login(self) -> None:
        u = self._u.value().strip()
        p = self._p.value()
        if not u or not p:
            self._msg.set("Please enter username and password.")
            return
        res = self._svc.login(u, p)
        if res["ok"]:
            self._msg.set("")
            self.unbind_all("<Return>")
            self._on_login(res["user"])
        else:
            self._msg.set(res["msg"])

    def _go_register(self) -> None:
        RegisterDialog(self, self._svc)

    def _forgot(self) -> None:
        ForgotPasswordDialog(self, self._svc)


# ═════════════════════════════════════════════════════════════════════
#  GUI — REGISTER DIALOG
# ═════════════════════════════════════════════════════════════════════

class RegisterDialog(tk.Toplevel):

    def __init__(self, parent, svc: UserService,
                 callback=None, admin_mode: bool = False) -> None:
        super().__init__(parent)
        self.title("Create Account")
        self.resizable(False, False)
        self.configure(bg=C["bg"])
        self._svc        = svc
        self._callback   = callback
        self._admin_mode = admin_mode
        self._build()
        self.grab_set()
        self.focus_force()

    def _build(self) -> None:
        f = ttk.Frame(self, style="Card.TFrame")
        f.pack(fill="both", expand=True, padx=0, pady=0)
        inner = ttk.Frame(f, style="Card.TFrame")
        inner.pack(fill="both", padx=32, pady=28)

        ttk.Label(inner, text="Create Account",
                  style="CardHeader.TLabel").pack(anchor="w", pady=(0, 14))

        self._user  = labeled_field(inner, "Username *",     "min 3 chars",  bg=C["surface"])
        self._email = labeled_field(inner, "Email *",        "user@mail.com",bg=C["surface"])
        self._pw    = labeled_field(inner, "Password *",     "min 8 chars",
                                    password=True, bg=C["surface"])
        self._pw2   = labeled_field(inner, "Confirm Password *", "",
                                    password=True, bg=C["surface"])
        self._phone = labeled_field(inner, "Phone",          "+1234567890",  bg=C["surface"])

        if self._admin_mode:
            ttk.Label(inner, text="Role", style="CardMuted.TLabel",
                      font=(FF, 9)).pack(anchor="w", pady=(8, 2))
            self._role_var = tk.StringVar(value="User")
            ttk.Combobox(inner, textvariable=self._role_var,
                         values=["User", "Admin"],
                         state="readonly", width=14).pack(anchor="w")
        else:
            self._role_var = tk.StringVar(value="User")

        self._msg = tk.StringVar()
        ttk.Label(inner, textvariable=self._msg,
                  style="CardError.TLabel",
                  wraplength=320).pack(anchor="w", pady=(8, 0))

        ttk.Button(inner, text="Create Account", style="Accent.TButton",
                   command=self._submit).pack(fill="x", pady=(14, 0))

    def _submit(self) -> None:
        u   = self._user.value().strip()
        em  = self._email.value().strip()
        pw  = self._pw.value()
        pw2 = self._pw2.value()
        ph  = self._phone.value().strip()
        role= self._role_var.get()

        if pw != pw2:
            self._msg.set("Passwords do not match.")
            return
        res = self._svc.register(u, em, pw, ph, role)
        if res["ok"]:
            messagebox.showinfo("Success", res["msg"], parent=self)
            if self._callback:
                self._callback()
            self.destroy()
        else:
            self._msg.set(res["msg"])


# ═════════════════════════════════════════════════════════════════════
#  GUI — FORGOT PASSWORD DIALOG (2-step)
# ═════════════════════════════════════════════════════════════════════

class ForgotPasswordDialog(tk.Toplevel):

    def __init__(self, parent, svc: UserService) -> None:
        super().__init__(parent)
        self.title("Forgot Password")
        self.resizable(False, False)
        self.configure(bg=C["bg"])
        self._svc   = svc
        self._token = ""
        self._build_step1()
        self.grab_set()
        self.focus_force()

    def _clear(self) -> None:
        for w in self.winfo_children():
            w.destroy()

    # ── step 1 : request token ────────────────────────────────────────

    def _build_step1(self) -> None:
        self._clear()
        inner = ttk.Frame(self, style="Card.TFrame")
        inner.pack(fill="both", padx=32, pady=28)

        ttk.Label(inner, text="Forgot Password",
                  style="CardHeader.TLabel").pack(anchor="w", pady=(0, 6))
        ttk.Label(inner,
                  text="Enter your registered e-mail to receive a reset token.",
                  style="CardMuted.TLabel",
                  wraplength=300).pack(anchor="w", pady=(0, 12))

        self._email_e = labeled_field(inner, "E-mail", "user@mail.com",
                                      bg=C["surface"])
        self._msg = tk.StringVar()
        ttk.Label(inner, textvariable=self._msg,
                  style="CardError.TLabel",
                  wraplength=300).pack(anchor="w", pady=(6, 0))

        ttk.Button(inner, text="Request Token", style="Accent.TButton",
                   command=self._step1).pack(fill="x", pady=(14, 0))

    def _step1(self) -> None:
        email = self._email_e.value().strip()
        if not email:
            self._msg.set("Please enter your e-mail.")
            return
        res = self._svc.generate_reset_token(email)
        if not res["ok"]:
            self._msg.set(res["msg"])
            return
        self._token = res["token"]
        messagebox.showinfo(
            "Token Generated",
            f"Your one-time reset token (valid 1 hour):\n\n{self._token}\n\n"
            "(In a real application this would be sent to your e-mail.)",
            parent=self,
        )
        self._build_step2()

    # ── step 2 : enter token + new password ──────────────────────────

    def _build_step2(self) -> None:
        self._clear()
        inner = ttk.Frame(self, style="Card.TFrame")
        inner.pack(fill="both", padx=32, pady=28)

        ttk.Label(inner, text="Reset Password",
                  style="CardHeader.TLabel").pack(anchor="w", pady=(0, 14))

        self._tok_e = labeled_field(inner, "Reset Token", "paste token here",
                                    bg=C["surface"])
        if self._token:
            self._tok_e.set_value(self._token)

        self._pw_e  = labeled_field(inner, "New Password", "",
                                    password=True, bg=C["surface"])
        self._pw2_e = labeled_field(inner, "Confirm Password", "",
                                    password=True, bg=C["surface"])

        self._msg = tk.StringVar()
        ttk.Label(inner, textvariable=self._msg,
                  style="CardError.TLabel",
                  wraplength=300).pack(anchor="w", pady=(6, 0))

        ttk.Button(inner, text="Reset Password", style="Accent.TButton",
                   command=self._step2).pack(fill="x", pady=(14, 0))

    def _step2(self) -> None:
        tok = self._tok_e.value().strip()
        pw  = self._pw_e.value()
        pw2 = self._pw2_e.value()
        if pw != pw2:
            self._msg.set("Passwords do not match.")
            return
        if not tok:
            self._msg.set("Please enter the reset token.")
            return
        res = self._svc.reset_with_token(tok, pw)
        if res["ok"]:
            messagebox.showinfo("Done", res["msg"], parent=self)
            self.destroy()
        else:
            self._msg.set(res["msg"])


# ═════════════════════════════════════════════════════════════════════
#  GUI — MAIN WINDOW  (after login)
# ═════════════════════════════════════════════════════════════════════

class MainWindow(ttk.Frame):

    _NAV = [
        ("👤", "My Profile",   "profile"),
        ("✏️", "Edit Profile", "edit"),
        ("🔒", "Security",     "security"),
        ("🛡️", "Admin Panel",  "admin"),      # admin-only
        ("🚪", "Sign Out",     "logout"),
    ]

    def __init__(self, parent, svc: UserService,
                 user: dict, on_logout) -> None:
        super().__init__(parent)
        self._svc       = svc
        self._user      = user
        self._on_logout = on_logout
        self._nav_btns  = {}
        self._build()
        self._navigate("profile")

    # ── layout ────────────────────────────────────────────────────────

    def _build(self) -> None:
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        # ── sidebar ──────────────────────────────────────────────────
        sb = tk.Frame(self, bg=C["surface"], width=210)
        sb.grid(row=0, column=0, sticky="nsew")
        sb.grid_propagate(False)

        tk.Label(sb, text="⬡ UMS",
                 bg=C["surface"], fg=C["accent2"],
                 font=(FF, 17, "bold")).pack(pady=(26, 2))
        tk.Label(sb, text=self._user["username"],
                 bg=C["surface"], fg=C["muted"],
                 font=(FF, 10)).pack()
        rc = C["warning"] if self._user["role"] == "Admin" else C["success"]
        tk.Label(sb, text=f"● {self._user['role']}",
                 bg=C["surface"], fg=rc,
                 font=(FF, 9, "bold")).pack(pady=(2, 20))

        tk.Frame(sb, bg=C["border"], height=1).pack(fill="x", padx=16, pady=4)

        for icon, label, key in self._NAV:
            if key == "admin" and self._user["role"] != "Admin":
                continue
            btn = tk.Button(
                sb,
                text=f"  {icon}  {label}",
                bg=C["surface"], fg=C["muted"],
                font=(FF, 10), anchor="w",
                bd=0, relief="flat", cursor="hand2",
                activebackground=C["surface2"],
                activeforeground=C["text"],
                command=lambda k=key: self._navigate(k),
            )
            btn.pack(fill="x", padx=8, pady=2, ipady=7)
            self._nav_btns[key] = btn

        # ── content area ─────────────────────────────────────────────
        self._area = ttk.Frame(self)
        self._area.grid(row=0, column=1, sticky="nsew")
        self._area.columnconfigure(0, weight=1)
        self._area.rowconfigure(0, weight=1)

    def _navigate(self, key: str) -> None:
        # highlight
        for k, b in self._nav_btns.items():
            b.config(
                bg=C["surface2"] if k == key else C["surface"],
                fg=C["text"]     if k == key else C["muted"],
            )

        if key == "logout":
            if messagebox.askyesno("Sign Out",
                                   "Sign out of your account?",
                                   parent=self):
                self._on_logout()
            else:
                # un-highlight logout
                self._nav_btns["logout"].config(bg=C["surface"], fg=C["muted"])
            return

        for w in self._area.winfo_children():
            w.destroy()

        panels = {
            "profile":  ProfilePanel,
            "edit":     EditProfilePanel,
            "security": SecurityPanel,
            "admin":    AdminPanel,
        }
        cls = panels.get(key)
        if cls:
            p = cls(self._area, self._svc, self._user,
                    on_user_change=self._on_user_change)
            p.grid(row=0, column=0, sticky="nsew")

    def _on_user_change(self, updated: Optional[dict]) -> None:
        if updated is None:
            self._on_logout()
        else:
            self._user = updated


# ═════════════════════════════════════════════════════════════════════
#  GUI — PANELS
# ═════════════════════════════════════════════════════════════════════

class _ScrollableFrame(ttk.Frame):
    """A vertically scrollable container."""

    def __init__(self, parent, **kw) -> None:
        outer = ttk.Frame(parent, **kw)
        outer.grid(row=0, column=0, sticky="nsew")
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(0, weight=1)

        canvas = tk.Canvas(outer, bg=C["bg"], highlightthickness=0)
        vsb    = ttk.Scrollbar(outer, orient="vertical",
                               command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        canvas.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        self._inner = ttk.Frame(canvas)
        wid = canvas.create_window((0, 0), window=self._inner, anchor="nw")

        def _resize(e):
            canvas.itemconfig(wid, width=e.width)
        canvas.bind("<Configure>", _resize)
        self._inner.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            ),
        )
        # forward Pack/Grid calls to the outer frame
        super().__init__(parent, **kw)

    @property
    def inner(self) -> ttk.Frame:
        return self._inner


# ── Profile ───────────────────────────────────────────────────────────

class ProfilePanel(ttk.Frame):

    def __init__(self, parent, svc, user, on_user_change=None) -> None:
        super().__init__(parent)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self._user = user
        self._build()

    def _build(self) -> None:
        wrap = ttk.Frame(self)
        wrap.grid(row=0, column=0, sticky="n", padx=36, pady=36)
        wrap.columnconfigure(0, weight=1)

        ttk.Label(wrap, text="My Profile", style="Title.TLabel").grid(
            row=0, column=0, sticky="w", pady=(0, 24))

        card = ttk.Frame(wrap, style="Card.TFrame")
        card.grid(row=1, column=0, sticky="ew")
        card.columnconfigure(1, weight=1)

        u = self._user
        rows = [
            ("User ID",      str(u.get("id", ""))),
            ("Username",     u.get("username", "")),
            ("E-mail",       u.get("email", "")),
            ("Phone",        u.get("phone") or "—"),
            ("Role",         u.get("role", "")),
            ("Status",       "Active" if u.get("is_active") else "Inactive"),
            ("Member Since", (u.get("created_at") or "")[:10]),
        ]
        for i, (lbl, val) in enumerate(rows):
            fg = C["warning"] if lbl == "Role" and val == "Admin" else C["text"]
            ttk.Label(card, text=lbl + ":",
                      style="CardMuted.TLabel").grid(
                row=i, column=0, sticky="w", padx=(24, 40), pady=11)
            tk.Label(card, text=val,
                     bg=C["surface"], fg=fg,
                     font=(FF, 10, "bold")).grid(
                row=i, column=1, sticky="w", padx=(0, 24), pady=11)


# ── Edit Profile ──────────────────────────────────────────────────────

class EditProfilePanel(ttk.Frame):

    def __init__(self, parent, svc, user, on_user_change=None) -> None:
        super().__init__(parent)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self._svc    = svc
        self._user   = user
        self._change = on_user_change
        self._build()

    def _build(self) -> None:
        wrap = ttk.Frame(self)
        wrap.grid(row=0, column=0, sticky="n", padx=36, pady=36)
        wrap.columnconfigure(0, weight=1)

        ttk.Label(wrap, text="Edit Profile", style="Title.TLabel").grid(
            row=0, column=0, sticky="w", pady=(0, 24))

        card  = ttk.Frame(wrap, style="Card.TFrame")
        card.grid(row=1, column=0, sticky="ew")
        inner = ttk.Frame(card, style="Card.TFrame")
        inner.pack(fill="both", padx=28, pady=24)

        self._email = labeled_field(inner, "E-mail *", "", bg=C["surface"])
        self._email.set_value(self._user.get("email", ""))

        self._phone = labeled_field(inner, "Phone", "", bg=C["surface"])
        self._phone.set_value(self._user.get("phone") or "")

        divider(inner, C["surface"])
        ttk.Label(inner,
                  text="Change Password  — leave blank to keep current",
                  style="CardMuted.TLabel",
                  font=(FF, 9)).pack(anchor="w", pady=(0, 4))

        self._pw  = labeled_field(inner, "New Password", "",
                                  password=True, bg=C["surface"])
        self._pw2 = labeled_field(inner, "Confirm New Password", "",
                                  password=True, bg=C["surface"])

        self._msg = tk.StringVar()
        lbl = ttk.Label(inner, textvariable=self._msg,
                        wraplength=360, justify="left")
        lbl.pack(anchor="w", pady=(8, 0))
        self._msg_lbl = lbl

        btn_row = ttk.Frame(inner, style="Card.TFrame")
        btn_row.pack(fill="x", pady=(16, 0))
        ttk.Button(btn_row, text="Save Changes", style="Accent.TButton",
                   command=self._save).pack(side="left")
        ttk.Button(btn_row, text="Delete My Account", style="Danger.TButton",
                   command=self._delete).pack(side="right")

    def _set_msg(self, text: str, ok: bool = False) -> None:
        self._msg.set(text)
        style = "CardSuccess.TLabel" if ok else "CardError.TLabel"
        self._msg_lbl.configure(style=style)

    def _save(self) -> None:
        em  = self._email.value().strip()
        ph  = self._phone.value().strip()
        pw  = self._pw.value()
        pw2 = self._pw2.value()
        if pw != pw2:
            self._set_msg("Passwords do not match.")
            return
        res = self._svc.update_profile(self._user["id"], em, ph, pw)
        self._set_msg(res["msg"], ok=res["ok"])
        if res["ok"] and self._change:
            upd = self._svc.get_user(self._user["id"])
            if upd:
                self._change(upd)

    def _delete(self) -> None:
        if messagebox.askyesno(
            "Delete Account",
            "This will permanently delete your account. Are you sure?",
            parent=self,
        ):
            res = self._svc.delete_user(
                self._user["id"],
                self._user["id"],
                self._user["role"] == "Admin",
            )
            if res["ok"]:
                messagebox.showinfo("Deleted", res["msg"])
                if self._change:
                    self._change(None)   # triggers logout
            else:
                messagebox.showerror("Error", res["msg"])


# ── Security ──────────────────────────────────────────────────────────

class SecurityPanel(ttk.Frame):

    def __init__(self, parent, svc, user, on_user_change=None) -> None:
        super().__init__(parent)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self._svc  = svc
        self._user = user
        self._build()

    def _build(self) -> None:
        wrap = ttk.Frame(self)
        wrap.grid(row=0, column=0, sticky="n", padx=36, pady=36)
        wrap.columnconfigure(0, weight=1)

        ttk.Label(wrap, text="Security", style="Title.TLabel").grid(
            row=0, column=0, sticky="w", pady=(0, 24))

        card  = ttk.Frame(wrap, style="Card.TFrame")
        card.grid(row=1, column=0, sticky="ew")
        inner = ttk.Frame(card, style="Card.TFrame")
        inner.pack(fill="both", padx=28, pady=22)

        ttk.Label(inner, text="Recent Login Attempts (last 10)",
                  style="CardHeader.TLabel").pack(anchor="w", pady=(0, 12))

        history = self._svc.login_history(self._user["username"], 10)
        if not history:
            ttk.Label(inner, text="No login history found.",
                      style="CardMuted.TLabel").pack()
            return

        cols = ("Date / Time", "Status")
        tree = ttk.Treeview(inner, columns=cols, show="headings",
                            height=min(len(history), 10))
        tree.heading("Date / Time", text="Date / Time")
        tree.heading("Status",      text="Status")
        tree.column("Date / Time",  width=200, anchor="w")
        tree.column("Status",       width=120, anchor="w")

        tree.tag_configure("ok",  foreground=C["success"])
        tree.tag_configure("bad", foreground=C["danger"])

        for r in history:
            ok  = bool(r["success"])
            tag = "ok" if ok else "bad"
            tree.insert("", "end",
                        values=(r["attempted_at"][:19],
                                "✅  Success" if ok else "❌  Failed"),
                        tags=(tag,))
        tree.pack(fill="x")


# ── Admin Panel ───────────────────────────────────────────────────────

class AdminPanel(ttk.Frame):

    def __init__(self, parent, svc, user, on_user_change=None) -> None:
        super().__init__(parent)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self._svc  = svc
        self._user = user
        self._build()
        self._refresh()

    # ── build ─────────────────────────────────────────────────────────

    def _build(self) -> None:
        # toolbar
        tb = ttk.Frame(self, style="Card.TFrame")
        tb.grid(row=0, column=0, sticky="ew")
        tb.columnconfigure(2, weight=1)

        ttk.Label(tb, text="Admin Panel",
                  style="CardHeader.TLabel",
                  font=(FF, 16, "bold"),
                  background=C["surface"]).grid(
            row=0, column=0, padx=20, pady=14, sticky="w")

        ttk.Button(tb, text="＋  New User", style="Accent.TButton",
                   command=self._new_user).grid(row=0, column=1, padx=6)

        # search + filter row
        sf = ttk.Frame(tb, style="Card.TFrame")
        sf.grid(row=0, column=2, padx=8, sticky="e")

        ttk.Label(sf, text="Search:", style="CardMuted.TLabel",
                  background=C["surface"]).pack(side="left", padx=(0, 5))
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._refresh())
        ttk.Entry(sf, textvariable=self._search_var, width=20).pack(side="left")

        ttk.Label(sf, text="  Role:", style="CardMuted.TLabel",
                  background=C["surface"]).pack(side="left", padx=(10, 5))
        self._role_var = tk.StringVar(value="All")
        self._role_var.trace_add("write", lambda *_: self._refresh())
        ttk.Combobox(sf, textvariable=self._role_var,
                     values=["All", "Admin", "User"],
                     state="readonly", width=8).pack(side="left")

        ttk.Button(tb, text="Export CSV", style="Ghost.TButton",
                   command=self._export).grid(row=0, column=3, padx=(6, 18))

        # table
        tf = ttk.Frame(self)
        tf.grid(row=1, column=0, sticky="nsew", padx=20, pady=(8, 20))
        tf.columnconfigure(0, weight=1)
        tf.rowconfigure(0, weight=1)

        cols = ("ID", "Username", "Email", "Phone",
                "Role", "Status", "Created")
        self._tree = ttk.Treeview(tf, columns=cols,
                                  show="headings", selectmode="browse")
        widths = {"ID": 40, "Username": 115, "Email": 195,
                  "Phone": 110, "Role": 65, "Status": 70, "Created": 95}
        for c in cols:
            self._tree.heading(c, text=c)
            self._tree.column(c, width=widths[c], anchor="w")

        vsb = ttk.Scrollbar(tf, orient="vertical",
                            command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        self._tree.tag_configure("adm",      foreground=C["warning"])
        self._tree.tag_configure("inactive", foreground=C["muted"])

        # context menu
        self._ctx = tk.Menu(self, tearoff=0,
                            bg=C["surface2"], fg=C["text"],
                            activebackground=C["accent"],
                            activeforeground="#fff", bd=0)
        self._ctx.add_command(label="✏️   Edit",          command=self._edit_sel)
        self._ctx.add_command(label="🔄   Toggle Active", command=self._toggle_sel)
        self._ctx.add_command(label="👑   Make Admin",    command=lambda: self._role_sel("Admin"))
        self._ctx.add_command(label="👤   Make User",     command=lambda: self._role_sel("User"))
        self._ctx.add_separator()
        self._ctx.add_command(label="🗑️   Delete",        command=self._delete_sel)

        self._tree.bind("<Button-3>",  self._show_ctx)
        self._tree.bind("<Double-1>",  lambda _: self._edit_sel())

        # status bar
        self._status = tk.StringVar()
        ttk.Label(self, textvariable=self._status,
                  style="Muted.TLabel").grid(
            row=2, column=0, sticky="w", padx=20, pady=(0, 8))

    # ── data ──────────────────────────────────────────────────────────

    def _refresh(self) -> None:
        search = self._search_var.get()
        role   = self._role_var.get()
        users  = self._svc.list_users(search, role)
        self._tree.delete(*self._tree.get_children())
        for u in users:
            tags = []
            if u["role"] == "Admin":     tags.append("adm")
            if not u["is_active"]:       tags.append("inactive")
            self._tree.insert(
                "", "end", iid=str(u["id"]),
                values=(
                    u["id"], u["username"], u["email"],
                    u["phone"] or "—", u["role"],
                    "Active" if u["is_active"] else "Inactive",
                    (u["created_at"] or "")[:10],
                ),
                tags=tuple(tags),
            )
        self._status.set(f"{len(users)} user(s) shown")

    # ── context helpers ───────────────────────────────────────────────

    def _selected_id(self) -> Optional[int]:
        sel = self._tree.selection()
        return int(sel[0]) if sel else None

    def _show_ctx(self, event) -> None:
        row = self._tree.identify_row(event.y)
        if row:
            self._tree.selection_set(row)
            try:
                self._ctx.tk_popup(event.x_root, event.y_root)
            finally:
                self._ctx.grab_release()

    # ── actions ───────────────────────────────────────────────────────

    def _new_user(self) -> None:
        RegisterDialog(self, self._svc,
                       callback=self._refresh, admin_mode=True)

    def _edit_sel(self) -> None:
        uid = self._selected_id()
        if uid is None:
            return
        user = self._svc.get_user(uid)
        if user:
            AdminEditDialog(self, self._svc, user, callback=self._refresh)

    def _toggle_sel(self) -> None:
        uid = self._selected_id()
        if uid is None:
            return
        res = self._svc.toggle_active(uid)
        messagebox.showinfo("Done", res["msg"], parent=self)
        self._refresh()

    def _role_sel(self, role: str) -> None:
        uid = self._selected_id()
        if uid is None:
            return
        res = self._svc.set_role(uid, role)
        messagebox.showinfo("Done", res["msg"], parent=self)
        self._refresh()

    def _delete_sel(self) -> None:
        uid = self._selected_id()
        if uid is None:
            return
        if messagebox.askyesno("Delete",
                               "Permanently delete this user?",
                               parent=self):
            res = self._svc.delete_user(uid, self._user["id"], True)
            if res["ok"]:
                self._refresh()
            else:
                messagebox.showerror("Error", res["msg"], parent=self)

    def _export(self) -> None:
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Export Users to CSV",
            parent=self,
        )
        if path:
            res = self._svc.export_csv(path)
            fn = messagebox.showinfo if res["ok"] else messagebox.showerror
            fn("Export", res["msg"], parent=self)


# ── Admin Edit Dialog ─────────────────────────────────────────────────

class AdminEditDialog(tk.Toplevel):

    def __init__(self, parent, svc: UserService,
                 user: dict, callback=None) -> None:
        super().__init__(parent)
        self.title(f"Edit  @{user['username']}")
        self.resizable(False, False)
        self.configure(bg=C["bg"])
        self._svc      = svc
        self._user     = user
        self._callback = callback
        self._build()
        self.grab_set()
        self.focus_force()

    def _build(self) -> None:
        inner = ttk.Frame(self, style="Card.TFrame")
        inner.pack(fill="both", padx=32, pady=28)

        ttk.Label(inner, text=f"Editing  @{self._user['username']}",
                  style="CardHeader.TLabel").pack(anchor="w", pady=(0, 14))

        self._email = labeled_field(inner, "E-mail", "", bg=C["surface"])
        self._email.set_value(self._user.get("email", ""))

        self._phone = labeled_field(inner, "Phone", "", bg=C["surface"])
        self._phone.set_value(self._user.get("phone") or "")

        self._pw = labeled_field(inner, "New Password (leave blank to keep)",
                                 "", password=True, bg=C["surface"])

        self._msg = tk.StringVar()
        ttk.Label(inner, textvariable=self._msg,
                  style="CardError.TLabel",
                  wraplength=300).pack(anchor="w", pady=(8, 0))

        ttk.Button(inner, text="Save Changes", style="Accent.TButton",
                   command=self._save).pack(fill="x", pady=(14, 0))

    def _save(self) -> None:
        em = self._email.value().strip()
        ph = self._phone.value().strip()
        pw = self._pw.value()
        res = self._svc.update_profile(self._user["id"], em, ph, pw)
        if res["ok"]:
            messagebox.showinfo("Saved", res["msg"], parent=self)
            if self._callback:
                self._callback()
            self.destroy()
        else:
            self._msg.set(res["msg"])


# ═════════════════════════════════════════════════════════════════════
#  APPLICATION ROOT
# ═════════════════════════════════════════════════════════════════════

class App:
    """Bootstrap: create DB → Service → Tk root → first screen."""

    def __init__(self) -> None:
        self._db  = Database()
        self._svc = UserService(self._db)

        self._root = tk.Tk()
        self._root.title(APP_TITLE)
        self._root.geometry("1100x700")
        self._root.minsize(860, 580)
        self._root.configure(bg=C["bg"])
        _apply_theme(self._root)
        self._center()

        self._frame: Optional[ttk.Frame] = None
        self._show_login()

    def _center(self) -> None:
        self._root.update_idletasks()
        sw = self._root.winfo_screenwidth()
        sh = self._root.winfo_screenheight()
        w  = self._root.winfo_width()
        h  = self._root.winfo_height()
        self._root.geometry(f"+{(sw - w) // 2}+{(sh - h) // 2}")

    def _swap(self, frame: ttk.Frame) -> None:
        if self._frame:
            self._frame.destroy()
        self._frame = frame
        self._frame.pack(fill="both", expand=True)

    def _show_login(self) -> None:
        self._swap(
            LoginScreen(self._root, self._svc, on_login=self._on_login)
        )

    def _on_login(self, user: dict) -> None:
        self._swap(
            MainWindow(
                self._root, self._svc, user,
                on_logout=self._on_logout,
            )
        )

    def _on_logout(self) -> None:
        self._show_login()

    def run(self) -> None:
        try:
            self._root.mainloop()
        finally:
            self._db.close()


# ═════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print(
        "\n"
        "  ╔══════════════════════════════════════════╗\n"
        "  ║   SQLite User Management System          ║\n"
        "  ║   Default login:  admin / Admin@123      ║\n"
        "  ╚══════════════════════════════════════════╝\n"
    )
    App().run()

"""Acme customer portal with a username/password login.

Python standard library only, so it runs anywhere without installing packages::

    python app.py

Configuration (environment variables):

    HOST           bind address, default 0.0.0.0
    PORT           bind port, default 8000
    BASE_PATH      path prefix used by the reverse proxy, e.g. /login-demo
    COOKIE_SECURE  set to true when the public URL is HTTPS
"""

from __future__ import annotations

import html
import os
import secrets
import urllib.parse
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import auth

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))
BASE_PATH = os.environ.get("BASE_PATH", "").rstrip("/")
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").strip().lower() in {"1", "true", "yes"}

COOKIE_NAME = "demo_session"
COOKIE_PATH = BASE_PATH or "/"

# Account store. A real deployment keeps these rows in a database; the demo keeps
# the same shape in memory. Only the salt and the password hash are stored.
ACCOUNTS = {
    "owner": {
        "salt": "6f1d2c3b4a5e6f70",
        # PBKDF2-SHA256 hash of the demo password.
        "password_hash": "b64cd66fdb6e00b76746ca59445f8892f74ad4a02db7dcd3d33f1341830a02f3",
    }
}

# token -> username
SESSIONS: dict[str, str] = {}

STYLE = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body {
  margin: 0; min-height: 100vh; display: flex; flex-direction: column;
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  background: #0f172a; color: #e2e8f0;
}
header { padding: 1rem 1.5rem; border-bottom: 1px solid #1f2a44; font-size: 1.05rem; }
main { flex: 1; display: grid; place-items: center; padding: 2rem 1rem; }
footer { padding: 1rem 1.5rem; color: #7c8aa5; font-size: 0.85rem; text-align: center; }
.card {
  width: 100%; max-width: 22rem; background: #16213a; border: 1px solid #24304b;
  border-radius: 14px; padding: 1.5rem; box-shadow: 0 12px 30px rgba(0,0,0,.35);
}
.card.wide { max-width: 34rem; }
h1 { margin: 0 0 1rem; font-size: 1.35rem; }
label { display: block; margin: 0.75rem 0 0.3rem; font-size: 0.9rem; color: #a9b6cd; }
input {
  width: 100%; padding: 0.6rem 0.7rem; border-radius: 9px; border: 1px solid #2c3a58;
  background: #0e1729; color: inherit; font-size: 1rem;
}
button {
  margin-top: 1rem; width: 100%; padding: 0.65rem 1rem; border: 0; border-radius: 9px;
  background: #3b82f6; color: #fff; font-size: 1rem; font-weight: 600; cursor: pointer;
}
button:hover { background: #2f6fd6; }
.error { background: #3b1d24; border: 1px solid #7f1d2d; color: #fecdd3; padding: 0.6rem 0.75rem; border-radius: 9px; }
.hint { color: #8b9ab5; font-size: 0.85rem; margin-top: 1rem; }
code { background: #0b1324; padding: 0.1rem 0.35rem; border-radius: 5px; }
ul { padding-left: 1.1rem; color: #c3cee1; }
a { color: #7db0ff; }
"""


def check_login(username: str, password: str) -> bool:
    """Return True when the username/password pair belongs to a known account."""
    account = ACCOUNTS.get((username or "").strip().lower())
    if not account:
        return False
    return auth.verify_password(password, account["password_hash"], account["salt"])


def _layout(title: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{html.escape(title)}</title>
<style>{STYLE}</style>
</head>
<body>
<header><strong>Acme Customer Portal</strong></header>
<main>{body}</main>
<footer>Demo application &middot; Python standard library only</footer>
</body>
</html>"""


def _login_page(error: str | None = None) -> str:
    note = f'<p class="error">{html.escape(error)}</p>' if error else ""
    return _layout(
        "Sign in",
        f"""
<section class="card">
  <h1>Sign in</h1>
  {note}
  <form method="post" action="{BASE_PATH}/login">
    <label for="username">Username</label>
    <input id="username" name="username" value="owner" autocomplete="username" required />
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required />
    <button type="submit">Sign in</button>
  </form>
  <p class="hint">Demo account: <code>owner</code> / <code>demo1234</code></p>
</section>""",
    )


def _dashboard_page(username: str) -> str:
    return _layout(
        "Dashboard",
        f"""
<section class="card wide">
  <h1>Welcome, {html.escape(username)}</h1>
  <p>You are signed in to the customer portal.</p>
  <ul>
    <li>Open invoices: 2</li>
    <li>Support requests: 1</li>
    <li>Plan: Starter</li>
  </ul>
  <p><a href="{BASE_PATH}/logout">Sign out</a></p>
</section>""",
    )


class Handler(BaseHTTPRequestHandler):
    server_version = "LoginDemo/1.0"

    # --- helpers ---------------------------------------------------------
    def _send(self, status: int, body: str, content_type: str, headers: dict | None = None) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _html(self, status: int, body: str, headers: dict | None = None) -> None:
        self._send(status, body, "text/html; charset=utf-8", headers)

    def _redirect(self, location: str, headers: dict | None = None) -> None:
        extra = {"Location": location}
        extra.update(headers or {})
        self._send(303, "", "text/plain; charset=utf-8", extra)

    def _session_token(self) -> str | None:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:
            return None
        morsel = jar.get(COOKIE_NAME)
        return morsel.value if morsel else None

    def _current_user(self) -> str | None:
        token = self._session_token()
        return SESSIONS.get(token) if token else None

    def _session_cookie(self, value: str, max_age: int | None = None) -> str:
        parts = [f"{COOKIE_NAME}={value}", f"Path={COOKIE_PATH}", "HttpOnly", "SameSite=Lax"]
        if COOKIE_SECURE:
            parts.append("Secure")
        if max_age is not None:
            parts.append(f"Max-Age={max_age}")
        return "; ".join(parts)

    # --- routes ----------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 (http.server naming)
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/healthz":
            self._send(200, "ok", "text/plain; charset=utf-8")
            return
        if path == "/logout":
            token = self._session_token()
            if token:
                SESSIONS.pop(token, None)
            self._redirect(f"{BASE_PATH}/", {"Set-Cookie": self._session_cookie("", max_age=0)})
            return
        if path in {"/", "/login"}:
            user = self._current_user()
            if user:
                self._html(200, _dashboard_page(user))
                return
            error = "Wrong username or password." if "error" in query else None
            self._html(200, _login_page(error))
            return
        self._html(404, _layout("Not found", '<section class="card"><h1>Not found</h1></section>'))

    def do_POST(self) -> None:  # noqa: N802 (http.server naming)
        path = urllib.parse.urlsplit(self.path).path
        if path != "/login":
            self._html(404, _layout("Not found", '<section class="card"><h1>Not found</h1></section>'))
            return

        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        form = urllib.parse.parse_qs(raw)
        username = (form.get("username") or [""])[0]
        password = (form.get("password") or [""])[0]

        if not check_login(username, password):
            self._redirect(f"{BASE_PATH}/?error=1")
            return

        token = secrets.token_urlsafe(24)
        SESSIONS[token] = username.strip().lower()
        self._redirect(f"{BASE_PATH}/", {"Set-Cookie": self._session_cookie(token)})


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"login-demo listening on http://{HOST}:{PORT}{BASE_PATH or ''}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

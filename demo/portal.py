"""Demo portal: a mock university portal that is a client of the Sentinel API.

It is not part of Sentinel. It owns the (in-memory) sessions and the login
check, and follows the portal integration rules P-1 to P-5 of docs/PRD.md.
The "client IP" of each request is whatever the page sends: a simulated IP.

Run:  python demo/portal.py
"""

import json
import os
import secrets
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

_HERE = os.path.dirname(os.path.abspath(__file__))

# The portal's own user database. Sentinel never sees passwords.
USERS = {"student": "correct-password"}


class SentinelUnavailable(Exception):
    pass


class SentinelClient:
    def __init__(self, base_url: str, portal_key: str, admin_key: str):
        self.base_url = base_url.rstrip("/")
        self.portal_key, self.admin_key = portal_key, admin_key

    def call(self, method: str, path: str, key: str, body=None) -> dict:
        """One Sentinel call, returned as a record the page can display."""
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base_url + path, data=data, method=method)
        req.add_header("Authorization", f"Bearer {key}")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                status, answer = resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            if exc.code >= 500:
                raise SentinelUnavailable(f"Sentinel returned {exc.code}") from None
            status, answer = exc.code, json.loads(exc.read())
        except (OSError, ValueError) as exc:  # refused, timed out, not JSON
            raise SentinelUnavailable(str(exc)) from None
        record = {"request": f"{method} {path}", "status": status, "response": answer}
        if body is not None:
            record["body"] = body
        return record

    def check(self, ip: str, context: str) -> dict:
        query = urlencode({"ip": ip, "context": context})
        return self.call("GET", f"/v1/check?{query}", self.portal_key)

    def report(self, ip: str, outcome: str, username: str) -> dict:
        body = {"ip": ip, "outcome": outcome, "username": username}
        return self.call("POST", "/v1/login-attempts", self.portal_key, body)


def _rejected(call: dict) -> dict:
    """Sentinel refused the request itself (for example an invalid IP)."""
    error = call["response"].get("error", {})
    return {"outcome": "error", "message": error.get("message", "request rejected"),
            "sentinel": [call]}


class Portal:
    def __init__(self, client: SentinelClient):
        self.client = client
        self.sessions: dict[str, str] = {}  # token -> username; Sentinel stores none of this

    def login(self, ip: str, username: str, password: str) -> dict:
        calls = []
        try:
            # P-1: ask before verifying the password.
            check = self.client.check(ip, "login")
            calls.append(check)
            if check["status"] != 200:
                return _rejected(check)
            if not check["response"]["allow"]:
                return {"outcome": "blocked", "explanation": check["response"]["explanation"],
                        "password_verified": False, "sentinel": calls}

            correct = USERS.get(username) == password

            # P-2: report the outcome; a "banned" answer means no session.
            report = self.client.report(ip, "success" if correct else "failure", username)
            calls.append(report)
            if report["status"] != 200:
                return _rejected(report)
            if report["response"]["banned"]:
                return {"outcome": "blocked", "explanation": report["response"]["explanation"],
                        "ban_triggered": report["response"]["ban_triggered"],
                        "password_verified": True, "sentinel": calls}
        except SentinelUnavailable as exc:
            # P-3: logins fail closed.
            return {"outcome": "unavailable", "sentinel": calls,
                    "message": f"Sign-in is temporarily unavailable, try again shortly. ({exc})"}

        if not correct:
            return {"outcome": "wrong_password", "sentinel": calls}
        token = secrets.token_urlsafe(16)
        self.sessions[token] = username
        return {"outcome": "signed_in", "session": token, "username": username, "sentinel": calls}

    def session_request(self, ip: str, token: str) -> dict:
        username = self.sessions.get(token)
        if username is None:
            return {"outcome": "no_session", "sentinel": []}
        try:
            check = self.client.check(ip, "session")
        except SentinelUnavailable as exc:
            # P-4: existing sessions fail open.
            return {"outcome": "allowed", "username": username, "sentinel": [],
                    "message": f"Sentinel did not answer; the session continues. ({exc})"}
        if check["status"] != 200:
            return _rejected(check)
        answer = check["response"]
        return {"outcome": "allowed" if answer["allow"] else "blocked", "username": username,
                "ip_banned": answer["banned"], "sentinel": [check]}

    def status(self, ip: str, context: str) -> dict:
        return self._passthrough(lambda: self.client.check(ip, context))

    def admin_bans(self) -> dict:
        return self._passthrough(lambda: self.client.call(
            "GET", "/v1/bans?status=active", self.client.admin_key))

    def admin_unban(self, ban_id: str) -> dict:
        return self._passthrough(lambda: self.client.call(
            "DELETE", f"/v1/bans/{ban_id}", self.client.admin_key))

    @staticmethod
    def _passthrough(call) -> dict:
        try:
            record = call()
        except SentinelUnavailable as exc:
            return {"outcome": "unavailable", "message": str(exc), "sentinel": []}
        if record["status"] != 200:
            return _rejected(record)
        return {"outcome": "ok", "sentinel": [record]}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _send(self, status: int, payload: bytes, content_type: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _json(self, body: dict, status: int = 200):
        self._send(status, json.dumps(body).encode(), "application/json")

    def do_GET(self):
        portal = self.server.portal
        url = urlsplit(self.path)
        query = {k: v[0] for k, v in parse_qs(url.query).items()}
        if url.path == "/":
            with open(os.path.join(_HERE, "index.html"), "rb") as page:
                self._send(200, page.read(), "text/html; charset=utf-8")
        elif url.path == "/api/check":
            self._json(portal.status(query.get("ip", ""), query.get("context", "login")))
        elif url.path == "/api/admin/bans":
            self._json(portal.admin_bans())
        else:
            self._json({"outcome": "error", "message": "not found"}, 404)

    def do_POST(self):
        portal = self.server.portal
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            field = lambda name: str(body.get(name, ""))
        except (ValueError, AttributeError):
            self._json({"outcome": "error", "message": "bad request"}, 400)
            return
        if self.path == "/api/login":
            self._json(portal.login(field("ip"), field("username"), field("password")))
        elif self.path == "/api/session":
            self._json(portal.session_request(field("ip"), field("token")))
        elif self.path == "/api/admin/unban":
            self._json(portal.admin_unban(field("id")))
        else:
            self._json({"outcome": "error", "message": "not found"}, 404)


def create_portal(host: str, port: int, sentinel_url: str, portal_key: str, admin_key: str):
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    server.portal = Portal(SentinelClient(sentinel_url, portal_key, admin_key))
    return server


def main() -> int:
    env = os.environ
    portal_key, admin_key = env.get("SENTINEL_PORTAL_KEY"), env.get("SENTINEL_ADMIN_KEY")
    if not portal_key or not admin_key:
        print("demo: set SENTINEL_PORTAL_KEY and SENTINEL_ADMIN_KEY (same values as Sentinel)",
              file=sys.stderr)
        return 2
    sentinel_url = env.get("SENTINEL_URL") or "http://127.0.0.1:8080"
    port = int(env.get("DEMO_PORT") or 8081)
    server = create_portal("127.0.0.1", port, sentinel_url, portal_key, admin_key)
    print(f"demo portal: open http://127.0.0.1:{port}/  (Sentinel at {sentinel_url})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

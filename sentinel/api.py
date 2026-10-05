"""HTTP API: authentication, validation, IP normalisation, routing."""

import hmac
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .clock import SystemClock, format_ms
from .config import Config
from .ips import InvalidIP, canonical_ip
from .service import BanNotFound, Sentinel, explanation
from .store import BanStore

PORTAL, ADMIN = "portal", "admin"
_MAX_BODY = 64 * 1024
_STATUSES = ("active", "expired", "revoked")
_CONTEXTS = ("login", "session")
_DEFAULT_LIMIT, _MAX_LIMIT = 50, 200


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def _invalid(message: str) -> ApiError:
    return ApiError(400, "invalid_request", message)


def _ip(text) -> str:
    try:
        return canonical_ip(text)
    except InvalidIP as exc:
        raise ApiError(400, "invalid_ip", str(exc)) from None


def ban_json(ban, now_ms: int, include_evidence: bool) -> dict:
    body = {
        "id": ban.id,
        "ip": ban.ip,
        "reason": ban.reason,
        "status": ban.status(now_ms),
        "triggered_at": format_ms(ban.triggered_at),
        "expires_at": format_ms(ban.expires_at),
        "revoked_at": format_ms(ban.revoked_at) if ban.revoked_at is not None else None,
        "rule": ban.rule,
    }
    if include_evidence:  # admin key only
        body["evidence"] = [
            {"received_at": format_ms(e["received_at"]), "username": e["username"]}
            for e in ban.evidence
        ]
    return body


class Handler(BaseHTTPRequestHandler):
    server_version = "Sentinel"

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_DELETE(self):
        self._handle("DELETE")

    def _handle(self, method: str):
        try:
            status, body = 200, self._route(method)
        except ApiError as exc:
            status, body = exc.status, {"error": {"code": exc.code, "message": exc.message}}
        except Exception:
            status = 500
            body = {"error": {"code": "internal_error", "message": "internal error"}}
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _route(self, method: str) -> dict:
        url = urlsplit(self.path)
        path = url.path
        if method == "POST" and path == "/v1/login-attempts":
            self._authenticate(PORTAL)
            return self._report()
        if method == "GET" and path == "/v1/check":
            self._authenticate(PORTAL)
            return self._check(self._query(url))
        if method == "GET" and path == "/v1/bans":
            self._authenticate(ADMIN)
            return self._list(self._query(url))
        if method == "DELETE" and path.startswith("/v1/bans/"):
            ban_id = path[len("/v1/bans/"):]
            if ban_id and "/" not in ban_id:
                self._authenticate(ADMIN)
                return self._revoke(ban_id)
        raise ApiError(404, "not_found", "no such endpoint")

    def _authenticate(self, role: str):
        config = self.server.sentinel.config
        keys = {PORTAL: config.portal_key, ADMIN: config.admin_key}
        scheme, _, presented = (self.headers.get("Authorization") or "").partition(" ")
        if scheme != "Bearer" or not presented:
            raise ApiError(401, "unauthorized", "key missing or wrong")
        presented = presented.encode("utf-8")
        matches = {r: hmac.compare_digest(presented, k.encode("utf-8")) for r, k in keys.items()}
        if matches[role]:
            return
        if any(matches.values()):
            raise ApiError(403, "forbidden", "this key is not accepted by this endpoint")
        raise ApiError(401, "unauthorized", "key missing or wrong")

    @staticmethod
    def _query(url) -> dict:
        query = {}
        for name, values in parse_qs(url.query, keep_blank_values=True).items():
            if len(values) != 1:
                raise _invalid(f"{name} is given more than once")
            query[name] = values[0]
        return query

    def _json_body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise _invalid("invalid Content-Length") from None
        if length < 0 or length > _MAX_BODY:
            raise _invalid("request body is too large")
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except ValueError:
            raise _invalid("body is not valid JSON") from None
        if not isinstance(body, dict):
            raise _invalid("body must be a JSON object")
        return body

    def _report(self) -> dict:
        body = self._json_body()
        if "ip" not in body:
            raise _invalid("ip is required")
        outcome = body.get("outcome")
        if outcome not in ("success", "failure"):
            raise _invalid('outcome must be "success" or "failure"')
        username = body.get("username")
        if username is not None and not isinstance(username, str):
            raise _invalid("username must be a string")
        ip = _ip(body["ip"])
        # Any timestamp the caller sent is ignored; Sentinel's clock is the only one.
        verdict = self.server.sentinel.report(ip, outcome, username)
        answer = {
            "ip": verdict.ip,
            "banned": verdict.banned,
            "ban_triggered": verdict.ban_triggered,
            "ban": ban_json(verdict.ban, verdict.now_ms, False) if verdict.banned else None,
            "explanation": explanation(verdict.ban, verdict.now_ms),
        }
        if verdict.warning is not None:  # present only when the alert fires
            answer["warning"] = verdict.warning
        return answer

    def _check(self, query: dict) -> dict:
        if "ip" not in query:
            raise _invalid("ip is required")
        context = query.get("context", "login")
        if context not in _CONTEXTS:
            raise _invalid("context must be login or session")
        verdict = self.server.sentinel.check(_ip(query["ip"]))
        return {
            "ip": verdict.ip,
            "context": context,
            "banned": verdict.banned,
            # A ban governs login attempts, not existing sessions (D-15). The
            # portal asserts the session is valid; Sentinel stores nothing about it.
            "allow": context == "session" or not verdict.banned,
            "ban": ban_json(verdict.ban, verdict.now_ms, False) if verdict.banned else None,
            "explanation": explanation(verdict.ban, verdict.now_ms),
            "checked_at": format_ms(verdict.now_ms),
        }

    def _list(self, query: dict) -> dict:
        ip = _ip(query["ip"]) if "ip" in query else None
        status = query.get("status")
        if status is not None and status not in _STATUSES:
            raise _invalid("status must be active, expired or revoked")
        limit = _DEFAULT_LIMIT
        if "limit" in query:
            raw = query["limit"]
            if not (raw.isascii() and raw.isdigit()) or not 1 <= int(raw) <= _MAX_LIMIT:
                raise _invalid(f"limit must be a whole number from 1 to {_MAX_LIMIT}")
            limit = int(raw)
        bans, now = self.server.sentinel.list_bans(ip, status, limit)
        return {"bans": [ban_json(ban, now, True) for ban in bans]}

    def _revoke(self, ban_id: str) -> dict:
        try:
            ban, now = self.server.sentinel.revoke(ban_id)
        except BanNotFound:
            raise ApiError(404, "not_found", "no ban with that id") from None
        return ban_json(ban, now, True)


class SentinelServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128

    def __init__(self, address, sentinel: Sentinel):
        super().__init__(address, Handler)
        self.sentinel = sentinel

    def server_close(self):
        super().server_close()
        self.sentinel.close()


def create_server(config: Config, clock=None) -> SentinelServer:
    sentinel = Sentinel(config, BanStore(config.db_path), clock or SystemClock())
    return SentinelServer((config.host, config.port), sentinel)

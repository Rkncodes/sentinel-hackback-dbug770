"""Test harness: a controllable clock and helpers to run Sentinel in-process."""

import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timezone

from sentinel.api import create_server
from sentinel.config import Config
from sentinel.service import Sentinel
from sentinel.store import BanStore

PORTAL_KEY = "test-portal-key"
ADMIN_KEY = "test-admin-key"
T0 = int(datetime(2026, 10, 5, 10, 0, 0, tzinfo=timezone.utc).timestamp() * 1000)

IP_A = "203.0.113.7"
IP_B = "198.51.100.20"


class FakeClock:
    """Replaces Sentinel's clock in tests. Time moves only when told to."""

    def __init__(self, now_ms: int = T0):
        self._now = now_ms

    def now_ms(self) -> int:
        return self._now

    def set(self, now_ms: int) -> None:
        self._now = now_ms

    def advance(self, ms: int) -> None:
        self._now += ms


def parse_ts(text: str) -> int:
    dt = datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    return round(dt.timestamp() * 1000)


class TempDirCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db_path = os.path.join(tmp.name, "sentinel.db")
        self.clock = FakeClock()

    def config(self, **overrides) -> Config:
        values = dict(portal_key=PORTAL_KEY, admin_key=ADMIN_KEY,
                      db_path=self.db_path, host="127.0.0.1", port=0)
        values.update(overrides)
        return Config(**values)


class ServiceCase(TempDirCase):
    """Sentinel's core, called directly."""

    def setUp(self):
        super().setUp()
        self.sentinel = self.open()

    def open(self, **overrides) -> Sentinel:
        config = self.config(**overrides)
        sentinel = Sentinel(config, BanStore(config.db_path), self.clock)
        self.addCleanup(sentinel.close)
        return sentinel

    def fail(self, ip=IP_A, username=None, sentinel=None):
        return (sentinel or self.sentinel).report(ip, "failure", username)

    def fail_times(self, n, ip=IP_A, step_ms=1000):
        """n failures, step_ms apart; the clock is left at the last one."""
        verdict = None
        for i in range(n):
            if i:
                self.clock.advance(step_ms)
            verdict = self.fail(ip)
        return verdict


class ApiCase(TempDirCase):
    """Sentinel behind its HTTP API, on an ephemeral local port."""

    def setUp(self):
        super().setUp()
        self.server = create_server(self.config(), clock=self.clock)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(thread.join)
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def request(self, method, path, key=PORTAL_KEY, body=None, raw=None, headers=None):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if key is not None:
            req.add_header("Authorization", f"Bearer {key}")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        for name, value in (headers or {}).items():
            req.add_header(name, value)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def report(self, ip, outcome="failure", username=None):
        body = {"ip": ip, "outcome": outcome}
        if username is not None:
            body["username"] = username
        status, answer = self.request("POST", "/v1/login-attempts", body=body)
        self.assertEqual(status, 200, answer)
        return answer

    def check(self, ip):
        status, answer = self.request("GET", f"/v1/check?ip={ip}")
        self.assertEqual(status, 200, answer)
        return answer

    def ban(self, ip=IP_A):
        """Ten failures one second apart; returns the answer to the tenth."""
        answer = None
        for i in range(10):
            if i:
                self.clock.advance(1000)
            answer = self.report(ip, username=f"user{i}")
        return answer

    def assertError(self, response, status, code):
        self.assertEqual(response[0], status, response[1])
        self.assertEqual(response[1]["error"]["code"], code)
        self.assertIsInstance(response[1]["error"]["message"], str)

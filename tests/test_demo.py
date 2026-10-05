"""Smoke test of the demo portal against a real Sentinel, real clock, short ban.

The portal (demo/portal.py) is a client of the Sentinel API; nothing here
reaches into Sentinel except through HTTP.
"""

import json
import threading
import time
import urllib.request

from demo.portal import create_portal
from sentinel.api import create_server

from .support import ADMIN_KEY, IP_A, IP_B, PORTAL_KEY, TempDirCase, parse_ts

BAN_SECONDS = 3


class DemoPortalCase(TempDirCase):
    sentinel_running = True

    def setUp(self):
        super().setUp()
        self.sentinel = create_server(self.config(ban_duration_seconds=BAN_SECONDS))  # real clock
        sentinel_url = f"http://127.0.0.1:{self.sentinel.server_address[1]}"
        self.portal = create_portal("127.0.0.1", 0, sentinel_url, PORTAL_KEY, ADMIN_KEY)
        self.base = f"http://127.0.0.1:{self.portal.server_address[1]}"
        self.addCleanup(self.sentinel.server_close)
        self.addCleanup(self.portal.server_close)
        servers = [self.portal] + ([self.sentinel] if self.sentinel_running else [])
        for server in servers:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(thread.join)
            self.addCleanup(server.shutdown)

    def get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=10) as resp:
            return json.loads(resp.read())

    def post(self, path, body):
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode(), method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    def login(self, ip, password="correct-password"):
        return self.post("/api/login", {"ip": ip, "username": "student", "password": password})

    def check(self, ip, context="login"):
        return self.get(f"/api/check?ip={ip}&context={context}")["sentinel"][0]["response"]

    def active_bans(self):
        return self.get("/api/admin/bans")["sentinel"][0]["response"]["bans"]


class DemoFlowTests(DemoPortalCase):
    def test_page_is_served(self):
        with urllib.request.urlopen(self.base + "/", timeout=10) as resp:
            page = resp.read().decode()
        for label in ("ATTACKER", "LEGITIMATE USER", "EXISTING SESSION", "NEW LOGIN", "ADMIN"):
            self.assertIn(label, page)

    def test_complete_demo_flow(self):
        # A student signs in on IP A before the attack.
        session = self.login(IP_A)
        self.assertEqual(session["outcome"], "signed_in")

        # ATTACKER: nine failures are counted, the tenth triggers the ban.
        for n in range(1, 10):
            self.assertEqual(self.login(IP_A, "wrong")["outcome"], "wrong_password", n)
        tenth = self.login(IP_A, "wrong")
        self.assertEqual(tenth["outcome"], "blocked")
        self.assertTrue(tenth["ban_triggered"])
        explanation = tenth["explanation"]
        self.assertTrue(explanation["blocked"])
        self.assertEqual(explanation["reason_code"], "failed_login_threshold")
        self.assertEqual(explanation["retry_after_seconds"], BAN_SECONDS)
        self.assertTrue(self.check(IP_A)["banned"])

        # LEGITIMATE USER on IP B is unaffected.
        self.assertEqual(self.login(IP_B)["outcome"], "signed_in")
        b = self.check(IP_B)
        self.assertEqual((b["banned"], b["allow"], b["explanation"]), (False, True, None))

        # EXISTING SESSION on A: allowed while banned.
        request = self.post("/api/session", {"ip": IP_A, "token": session["session"]})
        self.assertEqual(request["outcome"], "allowed")
        self.assertTrue(request["ip_banned"])
        self.assertEqual(request["sentinel"][0]["response"]["context"], "session")

        # NEW LOGIN on A with the correct password: blocked, password never verified.
        blocked = self.login(IP_A)
        self.assertEqual(blocked["outcome"], "blocked")
        self.assertFalse(blocked["password_verified"])
        self.assertNotIn("session", blocked)
        self.assertEqual(len(blocked["sentinel"]), 1)
        self.assertEqual(blocked["explanation"]["expires_at"], explanation["expires_at"])
        self.assertNotIn("student", json.dumps(blocked["explanation"]))

        # ADMIN sees the active ban, with evidence.
        (ban,) = self.active_bans()
        self.assertEqual(ban["ip"], IP_A)
        self.assertEqual(len(ban["evidence"]), 10)

        # EXACT EXPIRY: nothing is called to lift it; wait for the real clock.
        expires_at = parse_ts(explanation["expires_at"])
        time.sleep(max(0, expires_at / 1000 - time.time()) + 0.05)
        after = self.check(IP_A)
        self.assertFalse(after["banned"])
        self.assertIsNone(after["explanation"])
        self.assertGreaterEqual(parse_ts(after["checked_at"]), expires_at)
        self.assertEqual(self.active_bans(), [])
        self.assertEqual(self.login(IP_A)["outcome"], "signed_in")

    def test_lucky_guess_is_flagged_and_the_ban_flow_still_works(self):
        for _ in range(5):
            self.assertEqual(self.login(IP_A, "wrong")["outcome"], "wrong_password")
        guess = self.login(IP_A)  # correct password, before the ban threshold
        self.assertEqual(guess["outcome"], "signed_in")
        self.assertEqual(guess["warning"]["code"], "success_after_failed_attempts")
        self.assertEqual(guess["warning"]["failed_attempts"], 5)
        self.assertFalse(self.check(IP_A)["banned"])
        self.assertIsNone(self.login(IP_B)["warning"])  # another address: no alert

        # The success reset nothing: five more failures reach the threshold of ten.
        for _ in range(4):
            self.assertEqual(self.login(IP_A, "wrong")["outcome"], "wrong_password")
        tenth = self.login(IP_A, "wrong")
        self.assertEqual(tenth["outcome"], "blocked")
        self.assertTrue(tenth["ban_triggered"])
        self.assertEqual(self.login(IP_A)["outcome"], "blocked")

    def test_admin_unban(self):
        for _ in range(10):
            last = self.login(IP_A, "wrong")
        self.assertTrue(last["ban_triggered"])
        (ban,) = self.active_bans()
        unbanned = self.post("/api/admin/unban", {"id": ban["id"]})
        self.assertEqual(unbanned["outcome"], "ok")
        self.assertEqual(unbanned["sentinel"][0]["response"]["status"], "revoked")
        self.assertFalse(self.check(IP_A)["banned"])
        self.assertEqual(self.active_bans(), [])

    def test_invalid_simulated_ip_is_reported(self):
        answer = self.login("not-an-ip")
        self.assertEqual(answer["outcome"], "error")
        self.assertEqual(answer["sentinel"][0]["response"]["error"]["code"], "invalid_ip")


class SentinelDownTests(DemoPortalCase):
    sentinel_running = False  # bound but never served: every call times out or is refused

    def setUp(self):
        super().setUp()
        self.sentinel.server_close()  # connections are now refused

    def test_logins_fail_closed_and_sessions_fail_open(self):
        self.assertEqual(self.login(IP_B)["outcome"], "unavailable")
        self.assertEqual(self.portal.portal.sessions, {})
        self.portal.portal.sessions["existing"] = "student"
        request = self.post("/api/session", {"ip": IP_B, "token": "existing"})
        self.assertEqual(request["outcome"], "allowed")

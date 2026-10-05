"""Improvement 1: existing authenticated sessions continue during an IP ban (FR-13, A-1 to A-3)."""

import sqlite3

from .support import ADMIN_KEY, IP_A, IP_B, ApiCase, parse_ts


class SessionPreservationTests(ApiCase):
    def check_in(self, context, ip=IP_A):
        status, answer = self.request("GET", f"/v1/check?ip={ip}&context={context}")
        self.assertEqual(status, 200, answer)
        return answer

    def stored_bans(self):
        status, answer = self.request("GET", "/v1/bans", key=ADMIN_KEY)
        self.assertEqual(status, 200, answer)
        return answer["bans"]

    def test_a_existing_session_from_banned_ip_remains_allowed(self):
        ban = self.ban()["ban"]
        answer = self.check_in("session")
        self.assertEqual(answer["context"], "session")
        self.assertTrue(answer["banned"])  # stated truthfully
        self.assertTrue(answer["allow"])
        self.assertEqual(answer["ban"], ban)

    def test_b_new_login_from_same_banned_ip_remains_blocked(self):
        ban = self.ban()["ban"]
        self.assertTrue(self.check_in("session")["allow"])
        for answer in (self.check_in("login"), self.check(IP_A)):  # explicit and default
            self.assertEqual(answer["context"], "login")
            self.assertTrue(answer["banned"])
            self.assertFalse(answer["allow"])
            self.assertEqual(answer["ban"]["expires_at"], ban["expires_at"])

    def test_c_login_after_ban_is_created_cannot_obtain_a_session(self):
        # A login is in flight: checked before the ban exists ...
        for _ in range(9):
            self.report(IP_A)
        self.assertTrue(self.check_in("login")["allow"])
        # ... the ban is created ...
        ban = self.report(IP_A)["ban"]
        # ... and the in-flight login is verified afterwards, with correct credentials.
        answer = self.report(IP_A, outcome="success", username="student")
        self.assertTrue(answer["banned"])  # so the portal must not create a session (P-2)
        self.assertFalse(answer["ban_triggered"])
        self.assertEqual(answer["ban"], ban)
        # Session-context checks open no door for logins either.
        self.check_in("session")
        self.assertFalse(self.check_in("login")["allow"])
        self.assertTrue(self.report(IP_A, outcome="success")["banned"])

    def test_d_session_checks_do_not_change_the_ban(self):
        self.ban()
        (before,) = self.stored_bans()
        for _ in range(50):
            answer = self.check_in("session")
            self.assertTrue(answer["banned"])
            self.assertEqual(answer["ban"]["expires_at"], before["expires_at"])
        self.assertEqual(self.stored_bans(), [before])  # same record, still active

        # Expiry is neither shortened nor extended.
        expires_at = parse_ts(before["expires_at"])
        self.clock.set(expires_at - 1)
        self.assertTrue(self.check_in("session")["banned"])
        self.assertFalse(self.check_in("login")["allow"])
        self.clock.set(expires_at)
        self.assertFalse(self.check_in("session")["banned"])
        self.assertTrue(self.check_in("login")["allow"])

    def test_session_checks_are_never_counted(self):
        for _ in range(9):
            self.report(IP_A)
        for _ in range(30):
            self.assertFalse(self.check_in("session")["banned"])
        self.assertFalse(self.check(IP_A)["banned"])
        self.assertTrue(self.report(IP_A)["ban_triggered"])  # exactly the tenth failure

    def test_session_context_on_unbanned_ip_behaves_normally(self):
        answer = self.check_in("session", IP_B)
        self.assertEqual(answer, {
            "ip": IP_B, "context": "session", "banned": False, "allow": True,
            "ban": None, "explanation": None, "checked_at": "2026-10-05T10:00:00.000Z",
        })

    def test_unknown_context_is_rejected(self):
        for bad in ("admin", "SESSION", ""):
            self.assertError(
                self.request("GET", f"/v1/check?ip={IP_A}&context={bad}"), 400, "invalid_request"
            )

    def test_sentinel_stores_no_session_data(self):
        self.ban()
        for _ in range(5):
            self.check_in("session")
            self.check_in("session", IP_B)
        self.assertEqual(self.server.sentinel.tracked_ips(), 0)
        db = sqlite3.connect(self.db_path)
        try:
            tables = {row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")}
            rows = db.execute("SELECT COUNT(*) FROM bans").fetchone()[0]
        finally:
            db.close()
        self.assertEqual(tables, {"bans"})
        self.assertEqual(rows, 1)

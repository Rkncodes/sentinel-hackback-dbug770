"""Improvement 2: end-user-facing ban explanation (FR-14, A-4, A-5)."""

import json
import sqlite3

from .support import ADMIN_KEY, IP_A, IP_B, ApiCase, parse_ts

EXPLANATION_FIELDS = {
    "blocked", "reason_code", "message", "started_at", "expires_at", "retry_after_seconds",
}
MESSAGE = (
    "Sign-in from your network address is temporarily blocked "
    "because of too many failed sign-in attempts."
)


class BanExplanationTests(ApiCase):
    def check_in(self, context, ip=IP_A):
        status, answer = self.request("GET", f"/v1/check?ip={ip}&context={context}")
        self.assertEqual(status, 200, answer)
        return answer

    def test_blocked_login_carries_the_explanation(self):
        ban = self.ban()["ban"]  # triggered 10:00:09.000, expires 10:15:09.000
        self.clock.advance(48_000)
        answer = self.check(IP_A)
        self.assertTrue(answer["banned"])
        self.assertFalse(answer["allow"])
        self.assertEqual(answer["explanation"], {
            "blocked": True,
            "reason_code": "failed_login_threshold",
            "message": MESSAGE,
            "started_at": "2026-10-05T10:00:09.000Z",
            "expires_at": "2026-10-05T10:15:09.000Z",
            "retry_after_seconds": 852,
        })
        # Start and expiry are the ban's own.
        self.assertEqual(answer["explanation"]["started_at"], ban["triggered_at"])
        self.assertEqual(answer["explanation"]["expires_at"], ban["expires_at"])
        self.assertEqual(answer["explanation"]["reason_code"], ban["reason"])

    def test_report_that_triggers_the_ban_carries_the_explanation(self):
        answer = self.ban()
        self.assertTrue(answer["ban_triggered"])
        self.assertEqual(set(answer["explanation"]), EXPLANATION_FIELDS)
        self.assertIs(answer["explanation"]["blocked"], True)
        self.assertEqual(answer["explanation"]["retry_after_seconds"], 900)

    def test_every_banned_answer_carries_it(self):
        self.ban()
        self.clock.advance(1000)
        answers = [
            self.check(IP_A),
            self.check_in("login"),
            self.check_in("session"),
            self.report(IP_A, outcome="failure"),
            self.report(IP_A, outcome="success"),
        ]
        for answer in answers:
            self.assertTrue(answer["banned"])
            self.assertEqual(answer["explanation"], answers[0]["explanation"])
        self.assertEqual(answers[0]["explanation"]["retry_after_seconds"], 899)

    def test_seconds_remaining_is_rounded_up(self):
        ban = self.ban()["ban"]
        expires_at = parse_ts(ban["expires_at"])
        cases = [  # (time before expiry in ms, expected seconds)
            (900_000, 900), (899_999, 900), (899_001, 900), (899_000, 899),
            (60_000, 60), (59_999, 60), (2_000, 2), (1_001, 2), (1_000, 1), (999, 1), (1, 1),
        ]
        for before_ms, seconds in cases:
            self.clock.set(expires_at - before_ms)
            answer = self.check(IP_A)
            self.assertTrue(answer["banned"], before_ms)
            self.assertEqual(answer["explanation"]["retry_after_seconds"], seconds, before_ms)
            self.assertIsInstance(answer["explanation"]["retry_after_seconds"], int)

    def test_explanation_disappears_exactly_at_expiry(self):
        ban = self.ban()["ban"]
        expires_at = parse_ts(ban["expires_at"])

        self.clock.set(expires_at - 1)
        for answer in (self.check(IP_A), self.check_in("session")):
            self.assertTrue(answer["banned"])
            self.assertEqual(answer["explanation"]["retry_after_seconds"], 1)  # never zero

        self.clock.set(expires_at)
        for answer in (self.check(IP_A), self.check_in("session"),
                       self.report(IP_A, outcome="success")):
            self.assertFalse(answer["banned"])
            self.assertIsNone(answer["ban"])
            self.assertIn("explanation", answer)
            self.assertIsNone(answer["explanation"])

    def test_explanation_disappears_on_manual_unban(self):
        ban = self.ban()["ban"]
        self.request("DELETE", f"/v1/bans/{ban['id']}", key=ADMIN_KEY)
        answer = self.check(IP_A)
        self.assertFalse(answer["banned"])
        self.assertIsNone(answer["explanation"])

    def test_unbanned_ip_has_no_explanation(self):
        self.assertIsNone(self.check(IP_B)["explanation"])
        self.assertIsNone(self.check_in("session", IP_B)["explanation"])
        for outcome in ("failure", "success"):
            self.assertIsNone(self.report(IP_B, outcome=outcome)["explanation"])
        self.ban(IP_A)  # someone else's ban changes nothing for B
        self.assertIsNone(self.check(IP_B)["explanation"])

    def test_explanation_exposes_no_usernames_evidence_or_rule_values(self):
        for i in range(10):
            answer = self.report(IP_A, username=f"secret-user-{i}")
        explanation = answer["explanation"]
        self.assertEqual(set(explanation), EXPLANATION_FIELDS)
        text = json.dumps(explanation)
        for leaked in ("secret-user", "evidence", "username", "rule",
                       "window_seconds", "ban_duration", "admin", "ban_", IP_A):
            self.assertNotIn(leaked, text)
        self.assertNotIn("10", explanation["message"])  # no rule numbers in the wording
        # Nothing in any portal answer carries the usernames either.
        for portal_answer in (answer, self.check(IP_A), self.check_in("session")):
            self.assertNotIn("secret-user", json.dumps(portal_answer))
            self.assertNotIn("evidence", portal_answer["ban"])
        # The admin still sees the evidence.
        _, listing = self.request("GET", "/v1/bans", key=ADMIN_KEY)
        self.assertEqual(listing["bans"][0]["evidence"][0]["username"], "secret-user-0")
        self.assertNotIn("explanation", listing["bans"][0])

    def test_session_context_stays_allowed_and_does_not_alter_the_ban(self):
        self.ban()
        _, before = self.request("GET", "/v1/bans", key=ADMIN_KEY)
        for _ in range(20):
            answer = self.check_in("session")
            self.assertTrue(answer["allow"])  # still not a blocked-login answer
            self.assertTrue(answer["banned"])
            self.assertEqual(answer["explanation"]["expires_at"], before["bans"][0]["expires_at"])
        _, after = self.request("GET", "/v1/bans", key=ADMIN_KEY)
        self.assertEqual(after, before)
        self.assertFalse(self.check_in("login")["allow"])

    def test_explanation_is_not_stored(self):
        self.ban()
        self.check(IP_A)
        db = sqlite3.connect(self.db_path)
        try:
            tables = {row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")}
            columns = {row[1] for row in db.execute("PRAGMA table_info(bans)")}
        finally:
            db.close()
        self.assertEqual(tables, {"bans"})
        self.assertFalse({"message", "explanation", "retry_after_seconds"} & columns)

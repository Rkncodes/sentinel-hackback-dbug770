"""Extension: alert on a successful login that follows repeated failures
for the same account from the same address."""

import json

from sentinel.config import Config, ConfigError

from .support import ADMIN_KEY, IP_A, IP_B, T0, ApiCase, ServiceCase

WARNING = {
    "code": "success_after_failed_attempts",
    "message": "Successful login followed repeated failed attempts from this address.",
    "failed_attempts": 5,
}


class SuccessAlertTests(ServiceCase):
    def fails(self, n, username="student", ip=IP_A):
        for _ in range(n):
            verdict = self.sentinel.report(ip, "failure", username)
            self.assertFalse(verdict.banned)
            self.assertIsNone(verdict.warning)  # a failure never carries the alert

    def succeed(self, username="student", ip=IP_A):
        return self.sentinel.report(ip, "success", username)

    def test_alert_at_exactly_the_threshold(self):
        self.fails(5)
        verdict = self.succeed()
        self.assertEqual(verdict.warning, WARNING)
        self.assertFalse(verdict.banned)

    def test_no_alert_one_below_the_threshold(self):
        self.fails(4)
        self.assertIsNone(self.succeed().warning)

    def test_no_alert_without_failures(self):
        self.assertIsNone(self.succeed().warning)

    def test_alert_above_the_threshold_reports_the_count(self):
        self.fails(7)
        self.assertEqual(self.succeed().warning["failed_attempts"], 7)

    def test_different_username_on_same_ip_does_not_alert(self):
        self.fails(5, username="student")
        self.assertIsNone(self.succeed(username="professor").warning)

    def test_usernames_do_not_add_up(self):
        self.fails(4, username="student")
        self.fails(4, username="professor")
        self.assertIsNone(self.succeed(username="student").warning)
        self.assertIsNone(self.succeed(username="professor").warning)
        self.fails(1, username="student")
        self.assertEqual(self.succeed(username="student").warning, WARNING)  # counts only its own 5
        self.assertIsNone(self.succeed(username="professor").warning)

    def test_same_username_on_different_ip_does_not_alert(self):
        self.fails(5, ip=IP_A)
        self.assertIsNone(self.succeed(ip=IP_B).warning)
        self.assertEqual(self.succeed(ip=IP_A).warning, WARNING)

    def test_failures_older_than_the_window_do_not_count(self):
        self.fails(5)  # all at T0
        self.clock.set(T0 + 60_000)
        self.assertEqual(self.succeed().warning, WARNING)  # exactly 60 s old still counts
        self.clock.set(T0 + 60_001)
        self.assertIsNone(self.succeed().warning)

    def test_only_failures_inside_the_window_are_counted(self):
        self.fails(3)  # T0
        self.clock.set(T0 + 30_000)
        self.fails(4)
        self.clock.set(T0 + 60_001)  # the first three have aged out
        self.assertIsNone(self.succeed().warning)

    def test_missing_username_does_not_alert(self):
        self.fails(5)
        self.assertIsNone(self.succeed(username=None).warning)
        self.assertIsNone(self.succeed(username="").warning)

    def test_failures_without_username_do_not_alert(self):
        self.fails(5, username=None)
        self.assertIsNone(self.succeed(username="student").warning)
        self.assertIsNone(self.succeed(username=None).warning)

    def test_success_does_not_reset_the_failure_count(self):
        self.fails(5)
        self.assertEqual(self.succeed().warning, WARNING)
        self.assertEqual(self.succeed().warning, WARNING)  # still there on a second success
        self.fails(4)
        tenth = self.sentinel.report(IP_A, "failure", "student")
        self.assertTrue(tenth.ban_triggered)  # 5 + 4 + 1: the success changed nothing
        self.assertEqual(len(tenth.ban.evidence), 10)

    def test_success_is_not_counted_as_a_failure(self):
        self.fails(9)
        for _ in range(20):
            self.assertFalse(self.succeed().banned)
        self.assertEqual(self.succeed().warning["failed_attempts"], 9)
        self.assertEqual(self.sentinel.list_bans(None, None, 200)[0], [])

    def test_alert_does_not_create_a_ban(self):
        self.fails(5)
        self.succeed()
        self.assertEqual(self.sentinel.list_bans(None, None, 200)[0], [])
        self.assertFalse(self.sentinel.check(IP_A).banned)

    def test_already_banned_ip_gets_the_normal_banned_answer(self):
        for _ in range(10):
            ban = self.sentinel.report(IP_A, "failure", "student").ban
        self.clock.advance(1000)
        verdict = self.succeed()
        self.assertTrue(verdict.banned)
        self.assertFalse(verdict.ban_triggered)
        self.assertIsNone(verdict.warning)
        self.assertEqual(verdict.ban, ban)  # not extended, not replaced
        self.assertEqual(self.sentinel.list_bans(None, None, 200)[0], [ban])

    def test_no_alert_from_failures_that_caused_a_finished_ban(self):
        for _ in range(10):
            ban = self.sentinel.report(IP_A, "failure", "student").ban
        self.clock.set(ban.expires_at)
        self.assertIsNone(self.succeed().warning)  # the IP started again from zero

    def test_threshold_is_configurable(self):
        sentinel = self.open(success_alert_threshold=2)
        sentinel.report(IP_A, "failure", "student")
        self.assertIsNone(sentinel.report(IP_A, "success", "student").warning)
        sentinel.report(IP_A, "failure", "student")
        warning = sentinel.report(IP_A, "success", "student").warning
        self.assertEqual(warning["failed_attempts"], 2)

    def test_threshold_configuration(self):
        keys = {"SENTINEL_PORTAL_KEY": "p", "SENTINEL_ADMIN_KEY": "a"}
        self.assertEqual(Config.from_env(keys).success_alert_threshold, 5)
        configured = Config.from_env({**keys, "SENTINEL_SUCCESS_ALERT_THRESHOLD": "3"})
        self.assertEqual(configured.success_alert_threshold, 3)
        for bad in ("0", "-2", "many"):
            with self.assertRaises(ConfigError, msg=bad):
                Config.from_env({**keys, "SENTINEL_SUCCESS_ALERT_THRESHOLD": bad})

    def test_unreachable_threshold_is_rejected(self):
        keys = {"SENTINEL_PORTAL_KEY": "p", "SENTINEL_ADMIN_KEY": "a"}
        for alert, ban in (("10", "10"), ("11", "10"), ("5", "5"), ("3", "2")):
            with self.assertRaises(ConfigError, msg=(alert, ban)):
                Config.from_env({**keys, "SENTINEL_THRESHOLD": ban,
                                 "SENTINEL_SUCCESS_ALERT_THRESHOLD": alert})
        with self.assertRaises(ConfigError):
            self.config(threshold=4, success_alert_threshold=4)
        highest = Config.from_env({**keys, "SENTINEL_SUCCESS_ALERT_THRESHOLD": "9"})
        self.assertEqual(highest.success_alert_threshold, 9)  # one below the ban threshold

    def test_default_stays_below_a_low_ban_threshold(self):
        keys = {"SENTINEL_PORTAL_KEY": "p", "SENTINEL_ADMIN_KEY": "a"}
        expected = {"10": 5, "6": 5, "5": 4, "3": 2, "2": 1, "1": None}
        for ban, alert in expected.items():
            config = Config.from_env({**keys, "SENTINEL_THRESHOLD": ban})
            self.assertEqual(config.success_alert_threshold, alert, ban)

    def test_alert_is_off_when_the_ban_threshold_is_one(self):
        sentinel = self.open(threshold=1)
        self.assertIsNone(sentinel.report(IP_A, "success", "student").warning)
        self.assertTrue(sentinel.report(IP_A, "failure", "student").ban_triggered)

    def test_highest_allowed_threshold_can_still_fire(self):
        sentinel = self.open(success_alert_threshold=9)
        for _ in range(9):
            sentinel.report(IP_A, "failure", "student")
        self.assertEqual(sentinel.report(IP_A, "success", "student").warning["failed_attempts"], 9)


class SuccessAlertApiTests(ApiCase):
    def test_warning_in_the_report_answer(self):
        for _ in range(5):
            answer = self.report(IP_A, username="student")
            self.assertNotIn("warning", answer)
        answer = self.report(f"::ffff:{IP_A}", outcome="success", username="student")
        self.assertEqual(answer, {
            "ip": IP_A, "banned": False, "ban_triggered": False, "ban": None, "explanation": None,
            "warning": WARNING,
        })

    def test_no_warning_key_when_there_is_no_alert(self):
        for _ in range(4):
            self.report(IP_A, username="student")
        self.assertNotIn("warning", self.report(IP_A, outcome="success", username="student"))
        self.assertNotIn("warning", self.report(IP_A, outcome="success"))
        self.assertNotIn("warning", self.check(IP_A))

    def test_warning_exposes_no_username_or_history(self):
        for i in range(4):
            self.report(IP_A, username=f"other-user-{i}")
        for _ in range(5):
            self.report(IP_A, username="secret-student")
        answer = self.report(IP_A, outcome="success", username="secret-student")
        self.assertEqual(set(answer["warning"]), {"code", "message", "failed_attempts"})
        text = json.dumps(answer)
        for leaked in ("secret-student", "other-user", "received_at", "evidence"):
            self.assertNotIn(leaked, text)

    def test_banned_ip_is_still_blocked_and_carries_no_warning(self):
        for _ in range(10):
            self.report(IP_A, username="student")
        answer = self.report(IP_A, outcome="success", username="student")
        self.assertTrue(answer["banned"])
        self.assertFalse(answer["ban_triggered"])
        self.assertIsNotNone(answer["explanation"])
        self.assertNotIn("warning", answer)
        self.assertFalse(self.check(IP_A)["allow"])

    def test_alert_stores_nothing(self):
        for _ in range(5):
            self.report(IP_A, username="student")
        self.report(IP_A, outcome="success", username="student")
        _, listing = self.request("GET", "/v1/bans", key=ADMIN_KEY)
        self.assertEqual(listing, {"bans": []})
        check = self.check(IP_A)
        self.assertEqual((check["banned"], check["allow"]), (False, True))

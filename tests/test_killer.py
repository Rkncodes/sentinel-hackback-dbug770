"""The three Killer Tests, through the HTTP API (API.md section 4)."""

from .support import ApiCase, IP_A, IP_B, parse_ts


class KillerTests(ApiCase):
    def test_kt1_ten_failed_logins_within_a_minute_ban_the_ip(self):
        for n in range(1, 10):
            answer = self.report(IP_A)
            self.assertFalse(answer["banned"], f"report {n}")
            self.assertFalse(answer["ban_triggered"], f"report {n}")
            self.assertIsNone(answer["ban"])
            self.clock.advance(6000)
        # After only 9, a check says not banned.
        self.assertFalse(self.check(IP_A)["banned"])

        tenth = self.report(IP_A)  # 54 s after the first
        self.assertTrue(tenth["banned"])
        self.assertTrue(tenth["ban_triggered"])
        self.assertEqual(tenth["ban"]["status"], "active")

        check = self.check(IP_A)
        self.assertTrue(check["banned"])
        self.assertFalse(check["allow"])
        self.assertEqual(check["ban"]["id"], tenth["ban"]["id"])

    def test_kt2_normal_user_on_another_ip_is_not_affected(self):
        def assert_b_untouched():
            check = self.check(IP_B)
            self.assertFalse(check["banned"])
            self.assertTrue(check["allow"])
            self.assertIsNone(check["ban"])

        assert_b_untouched()  # before
        for n in range(10):
            self.report(IP_A)
            if n == 4:  # during the attack
                login = self.report(IP_B, outcome="success", username="student")
                self.assertFalse(login["banned"])
                self.assertIsNone(login["ban"])
                assert_b_untouched()
            self.clock.advance(1000)
        self.assertTrue(self.check(IP_A)["banned"])

        assert_b_untouched()  # after, while A is banned
        login = self.report(IP_B, outcome="success", username="student")
        self.assertFalse(login["banned"])
        assert_b_untouched()

    def test_kt3_ban_is_lifted_exactly_when_it_expires(self):
        ban = self.ban(IP_A)["ban"]
        expires_at = parse_ts(ban["expires_at"])
        self.assertEqual(expires_at - parse_ts(ban["triggered_at"]), 900_000)

        self.clock.set(expires_at - 1)  # one instant before
        before = self.check(IP_A)
        self.assertTrue(before["banned"])
        self.assertFalse(before["allow"])

        self.clock.set(expires_at)  # at expires_at
        at = self.check(IP_A)
        self.assertFalse(at["banned"])
        self.assertTrue(at["allow"])
        self.assertIsNone(at["ban"])
        self.assertEqual(at["checked_at"], ban["expires_at"])

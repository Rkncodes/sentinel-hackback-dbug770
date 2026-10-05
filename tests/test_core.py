"""Core behavior, called directly: detection, ban lifecycle, concurrency, restart."""

import threading
import unittest

from sentinel.clock import format_ms
from sentinel.config import Config, ConfigError
from sentinel.ips import InvalidIP, canonical_ip
from sentinel.service import BanNotFound

from .support import IP_A, IP_B, T0, ServiceCase


class DetectionTests(ServiceCase):
    def test_ninth_failure_does_not_ban_tenth_does(self):
        ninth = self.fail_times(9)
        self.assertFalse(ninth.banned)
        tenth = self.fail()
        self.assertTrue(tenth.banned)
        self.assertTrue(tenth.ban_triggered)
        self.assertTrue(self.sentinel.check(IP_A).banned)

    def test_ten_failures_spanning_exactly_the_window_ban(self):
        self.fail_times(9)  # T0 .. T0+8s
        self.clock.set(T0 + 60_000)
        self.assertTrue(self.fail().ban_triggered)

    def test_ten_failures_spanning_more_than_the_window_do_not_ban(self):
        self.fail_times(9)
        self.clock.set(T0 + 60_001)
        self.assertFalse(self.fail().banned)  # the first failure no longer counts
        # The window slides: nine remain, so one more inside it bans.
        self.assertTrue(self.fail().ban_triggered)

    def test_successes_never_count_and_never_reset(self):
        for _ in range(50):
            self.assertFalse(self.sentinel.report(IP_A, "success", "u").banned)
        self.fail_times(9)
        self.assertFalse(self.sentinel.report(IP_A, "success", "u").banned)
        self.assertTrue(self.fail().ban_triggered)

    def test_counting_is_per_ip(self):
        self.fail_times(9, IP_A, step_ms=0)
        self.fail_times(9, IP_B, step_ms=0)
        self.assertFalse(self.sentinel.check(IP_A).banned)
        self.assertFalse(self.sentinel.check(IP_B).banned)
        self.assertTrue(self.fail(IP_A).ban_triggered)
        self.assertFalse(self.sentinel.check(IP_B).banned)

    def test_ban_record_holds_rule_and_evidence(self):
        for i in range(10):
            verdict = self.fail(username=f"user{i}" if i else None)
            self.clock.advance(1000)
        ban = verdict.ban
        self.assertEqual(ban.ip, IP_A)
        self.assertEqual(ban.reason, "failed_login_threshold")
        self.assertEqual(ban.triggered_at, T0 + 9000)
        self.assertEqual(ban.expires_at, T0 + 9000 + 900_000)
        self.assertIsNone(ban.revoked_at)
        self.assertEqual(ban.rule, {"threshold": 10, "window_seconds": 60, "ban_duration_seconds": 900})
        self.assertEqual(len(ban.evidence), 10)
        self.assertEqual(ban.evidence[0], {"received_at": T0, "username": None})
        self.assertEqual(ban.evidence[9], {"received_at": T0 + 9000, "username": "user9"})

    def test_configured_rule_values_are_used(self):
        sentinel = self.open(threshold=3, window_seconds=5, ban_duration_seconds=30)
        self.fail(sentinel=sentinel)
        self.clock.advance(5000)
        self.fail(sentinel=sentinel)
        verdict = self.fail(sentinel=sentinel)
        self.assertTrue(verdict.ban_triggered)
        self.assertEqual(verdict.ban.expires_at - verdict.ban.triggered_at, 30_000)

    def test_idle_windows_are_swept_from_memory(self):
        self.fail(IP_A)
        self.clock.advance(60_000)
        self.fail(IP_B)
        self.sentinel.sweep()
        self.assertEqual(self.sentinel.tracked_ips(), 2)  # exactly 60 s old is kept
        self.clock.advance(1)
        self.sentinel.sweep()
        self.assertEqual(self.sentinel.tracked_ips(), 1)


class BanLifecycleTests(ServiceCase):
    def test_reports_from_a_banned_ip_do_not_extend_or_retrigger(self):
        ban = self.fail_times(10).ban
        for outcome in ["failure"] * 25 + ["success"]:
            self.clock.advance(1000)
            verdict = self.sentinel.report(IP_A, outcome, None)
            self.assertTrue(verdict.banned)
            self.assertFalse(verdict.ban_triggered)
            self.assertEqual(verdict.ban, ban)
        bans, _ = self.sentinel.list_bans(None, None, 200)
        self.assertEqual(bans, [ban])

    def test_expiry_is_half_open(self):
        ban = self.fail_times(10).ban
        self.clock.set(ban.expires_at - 1)
        self.assertTrue(self.sentinel.check(IP_A).banned)
        self.assertEqual(ban.status(self.clock.now_ms()), "active")
        self.clock.set(ban.expires_at)
        self.assertFalse(self.sentinel.check(IP_A).banned)
        self.assertEqual(ban.status(self.clock.now_ms()), "expired")

    def test_after_expiry_the_ip_starts_from_zero(self):
        ban = self.fail_times(10).ban
        self.clock.advance(1000)
        for _ in range(9):  # sent while banned: not counted
            self.fail()
        self.clock.set(ban.expires_at)
        self.assertFalse(self.fail_times(9, step_ms=0).banned)
        second = self.fail()
        self.assertTrue(second.ban_triggered)
        self.assertNotEqual(second.ban.id, ban.id)

    def test_bans_survive_restart_and_failure_windows_do_not(self):
        ban = self.fail_times(10, IP_A).ban
        self.fail_times(9, IP_B, step_ms=0)
        self.sentinel.close()

        restarted = self.open()
        verdict = restarted.check(IP_A)
        self.assertTrue(verdict.banned)
        self.assertEqual(verdict.ban, ban)
        # B's nine failures were in memory only; this is failure 1, not 10.
        self.assertFalse(self.fail(IP_B, sentinel=restarted).banned)
        self.clock.set(ban.expires_at)
        self.assertFalse(restarted.check(IP_A).banned)

    def test_config_change_does_not_alter_existing_bans(self):
        ban = self.fail_times(10).ban
        self.sentinel.close()
        restarted = self.open(ban_duration_seconds=5)
        self.assertEqual(restarted.check(IP_A).ban, ban)

    def test_manual_unban(self):
        ban = self.fail_times(10).ban
        self.clock.advance(5000)
        revoked, _ = self.sentinel.revoke(ban.id)
        self.assertEqual(revoked.revoked_at, T0 + 14_000)
        self.assertEqual(revoked.expires_at, ban.expires_at)
        self.assertEqual(revoked.status(self.clock.now_ms()), "revoked")
        self.assertFalse(self.sentinel.check(IP_A).banned)

    def test_manual_unban_is_idempotent(self):
        ban = self.fail_times(10).ban
        self.clock.advance(5000)
        first, _ = self.sentinel.revoke(ban.id)
        self.fail_times(4, step_ms=0)  # a new count that a repeat must not clear
        self.clock.advance(5000)
        second, _ = self.sentinel.revoke(ban.id)
        self.assertEqual(second, first)
        self.fail_times(5, step_ms=0)
        self.assertTrue(self.fail().ban_triggered)  # 4 + 5 + 1

    def test_unban_of_expired_ban_changes_nothing(self):
        ban = self.fail_times(10).ban
        self.clock.set(ban.expires_at)
        same, now = self.sentinel.revoke(ban.id)
        self.assertEqual(same, ban)
        self.assertEqual(same.status(now), "expired")

    def test_unbanned_ip_can_be_banned_again_from_zero(self):
        ban = self.fail_times(10).ban
        self.sentinel.revoke(ban.id)
        self.assertFalse(self.fail_times(9, step_ms=0).banned)
        self.assertTrue(self.fail().ban_triggered)

    def test_unban_unknown_id(self):
        with self.assertRaises(BanNotFound):
            self.sentinel.revoke("ban_missing")

    def test_list_filters_by_status_and_ip_newest_first(self):
        first = self.fail_times(10, IP_A, step_ms=0).ban
        self.clock.advance(1000)
        second = self.fail_times(10, IP_B, step_ms=0).ban
        self.sentinel.revoke(second.id)
        self.clock.advance(1000)
        third = self.fail_times(10, IP_B, step_ms=0).ban

        def ids(ip=None, status=None, limit=50):
            return [b.id for b in self.sentinel.list_bans(ip, status, limit)[0]]

        self.assertEqual(ids(), [third.id, second.id, first.id])
        self.assertEqual(ids(limit=2), [third.id, second.id])
        self.assertEqual(ids(ip=IP_B), [third.id, second.id])
        self.assertEqual(ids(status="active"), [third.id, first.id])
        self.assertEqual(ids(status="revoked"), [second.id])
        self.assertEqual(ids(status="expired"), [])
        self.clock.set(first.expires_at)
        self.assertEqual(ids(status="expired"), [first.id])
        self.assertEqual(ids(status="active"), [third.id])


class ConcurrencyTests(ServiceCase):
    def _concurrently(self, n, action):
        barrier = threading.Barrier(n)
        results, errors = [], []

        def run():
            try:
                barrier.wait()
                results.append(action())
            except Exception as exc:  # surfaced by the assertion below
                errors.append(exc)

        threads = [threading.Thread(target=run) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        return results

    def test_concurrent_failures_create_exactly_one_ban(self):
        verdicts = self._concurrently(40, self.fail)
        self.assertEqual(sum(v.ban_triggered for v in verdicts), 1)
        self.assertEqual(sum(not v.banned for v in verdicts), 9)
        self.assertEqual(sum(v.banned for v in verdicts), 31)
        bans, _ = self.sentinel.list_bans(None, None, 200)
        self.assertEqual(len(bans), 1)
        self.assertEqual(len(bans[0].evidence), 10)

    def test_concurrent_failures_are_not_lost(self):
        verdicts = self._concurrently(9, self.fail)
        self.assertFalse(any(v.banned for v in verdicts))
        self.assertTrue(self.fail().ban_triggered)  # nine were counted, so this is the tenth

    def test_concurrent_ips_do_not_interfere(self):
        ips = [f"10.0.{i}.1" for i in range(8)]
        barrier = threading.Barrier(len(ips))

        def attack(ip):
            barrier.wait()
            for _ in range(10):
                self.sentinel.report(ip, "failure", None)

        threads = [threading.Thread(target=attack, args=(ip,)) for ip in ips]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        bans, _ = self.sentinel.list_bans(None, None, 200)
        self.assertEqual(sorted(b.ip for b in bans), sorted(ips))
        self.assertFalse(self.sentinel.check(IP_B).banned)


class IpTests(unittest.TestCase):
    def test_canonical_forms(self):
        self.assertEqual(canonical_ip("203.0.113.7"), "203.0.113.7")
        self.assertEqual(canonical_ip("::ffff:203.0.113.7"), "203.0.113.7")
        self.assertEqual(canonical_ip("2001:0DB8:0000:0000:0000:0000:0000:0001"), "2001:db8::1")

    def test_rejects_anything_that_is_not_a_single_ip(self):
        for bad in ("", "banana", "203.0.113.0/24", "203.0.113.7 ", "1.2.3", "256.1.1.1",
                    "fe80::1%eth0", "203.0.113.7,198.51.100.20", None, 5):
            with self.assertRaises(InvalidIP, msg=repr(bad)):
                canonical_ip(bad)


class IpEquivalenceTests(ServiceCase):
    def test_mapped_and_plain_ipv4_share_one_count(self):
        for i in range(10):
            text = IP_A if i % 2 else f"::ffff:{IP_A}"
            verdict = self.sentinel.report(canonical_ip(text), "failure", None)
        self.assertTrue(verdict.ban_triggered)
        self.assertEqual(verdict.ban.ip, IP_A)


class ConfigAndClockTests(unittest.TestCase):
    def test_defaults(self):
        config = Config.from_env({"SENTINEL_PORTAL_KEY": "p", "SENTINEL_ADMIN_KEY": "a"})
        self.assertEqual(
            (config.threshold, config.window_seconds, config.ban_duration_seconds), (10, 60, 900)
        )

    def test_overrides(self):
        config = Config.from_env({
            "SENTINEL_PORTAL_KEY": "p", "SENTINEL_ADMIN_KEY": "a",
            "SENTINEL_THRESHOLD": "5", "SENTINEL_WINDOW_SECONDS": "30",
            "SENTINEL_BAN_DURATION_SECONDS": "20",
        })
        self.assertEqual(
            (config.threshold, config.window_seconds, config.ban_duration_seconds), (5, 30, 20)
        )

    def test_invalid_configuration_is_refused(self):
        good = {"SENTINEL_PORTAL_KEY": "p", "SENTINEL_ADMIN_KEY": "a"}
        for bad in ({"SENTINEL_ADMIN_KEY": ""}, {"SENTINEL_PORTAL_KEY": ""},
                    {"SENTINEL_ADMIN_KEY": "p"}, {"SENTINEL_THRESHOLD": "0"},
                    {"SENTINEL_WINDOW_SECONDS": "-1"}, {"SENTINEL_BAN_DURATION_SECONDS": "soon"}):
            with self.assertRaises(ConfigError, msg=bad):
                Config.from_env({**good, **bad})

    def test_timestamp_format(self):
        self.assertEqual(format_ms(T0), "2026-10-05T10:00:00.000Z")
        self.assertEqual(format_ms(T0 + 41_250), "2026-10-05T10:00:41.250Z")

"""The HTTP contract: keys, validation, error bodies, response shapes."""

import threading

from .support import ADMIN_KEY, IP_A, IP_B, PORTAL_KEY, ApiCase, parse_ts

BAN_FIELDS = {"id", "ip", "reason", "status", "triggered_at", "expires_at", "revoked_at", "rule"}


class AccessControlTests(ApiCase):
    ENDPOINTS = [
        ("POST", "/v1/login-attempts", PORTAL_KEY),
        ("GET", f"/v1/check?ip={IP_A}", PORTAL_KEY),
        ("GET", "/v1/bans", ADMIN_KEY),
        ("DELETE", "/v1/bans/ban_x", ADMIN_KEY),
    ]

    def test_missing_or_wrong_key_is_unauthorized(self):
        for method, path, _ in self.ENDPOINTS:
            self.assertError(self.request(method, path, key=None), 401, "unauthorized")
            self.assertError(self.request(method, path, key="wrong"), 401, "unauthorized")
            self.assertError(
                self.request(method, path, key=None, headers={"Authorization": PORTAL_KEY}),
                401, "unauthorized",
            )

    def test_each_key_is_refused_by_the_other_keys_endpoints(self):
        for method, path, right_key in self.ENDPOINTS:
            other = ADMIN_KEY if right_key == PORTAL_KEY else PORTAL_KEY
            self.assertError(self.request(method, path, key=other), 403, "forbidden")

    def test_unknown_endpoint(self):
        self.assertError(self.request("GET", "/v1/nope"), 404, "not_found")


class LoginAttemptsTests(ApiCase):
    def test_validation(self):
        post = lambda **kw: self.request("POST", "/v1/login-attempts", **kw)
        self.assertError(post(raw=b"{not json"), 400, "invalid_request")
        self.assertError(post(body=["x"]), 400, "invalid_request")
        self.assertError(post(body={"outcome": "failure"}), 400, "invalid_request")
        self.assertError(post(body={"ip": IP_A}), 400, "invalid_request")
        self.assertError(post(body={"ip": IP_A, "outcome": "maybe"}), 400, "invalid_request")
        self.assertError(post(body={"ip": IP_A, "outcome": "failure", "username": 7}), 400, "invalid_request")
        self.assertError(post(body={"ip": "banana", "outcome": "failure"}), 400, "invalid_ip")
        self.assertError(post(body={"ip": "203.0.113.0/24", "outcome": "failure"}), 400, "invalid_ip")
        # None of the rejected reports was counted.
        for _ in range(9):
            self.assertFalse(self.report(IP_A)["banned"])

    def test_answer_shape_and_canonical_ip(self):
        answer = self.report(f"::ffff:{IP_A}")
        self.assertEqual(answer, {
            "ip": IP_A, "banned": False, "ban_triggered": False, "ban": None, "explanation": None,
        })

    def test_ban_in_answer_has_no_evidence(self):
        answer = self.ban()
        self.assertEqual(set(answer["ban"]), BAN_FIELDS)
        self.assertEqual(answer["ban"]["ip"], IP_A)
        self.assertEqual(answer["ban"]["reason"], "failed_login_threshold")
        self.assertIsNone(answer["ban"]["revoked_at"])
        self.assertEqual(
            answer["ban"]["rule"],
            {"threshold": 10, "window_seconds": 60, "ban_duration_seconds": 900},
        )

    def test_caller_supplied_timestamps_are_ignored(self):
        for _ in range(10):
            status, answer = self.request("POST", "/v1/login-attempts", body={
                "ip": IP_A, "outcome": "failure",
                "received_at": "1999-01-01T00:00:00.000Z", "timestamp": 0,
            })
            self.assertEqual(status, 200)
        self.assertTrue(answer["ban_triggered"])
        self.assertEqual(answer["ban"]["triggered_at"], "2026-10-05T10:00:00.000Z")

    def test_report_from_banned_ip_is_answered_banned_without_retrigger(self):
        ban = self.ban()["ban"]
        self.clock.advance(1000)
        for outcome in ("failure", "success"):
            answer = self.report(IP_A, outcome=outcome)
            self.assertTrue(answer["banned"])
            self.assertFalse(answer["ban_triggered"])
            self.assertEqual(answer["ban"], ban)

    def test_concurrent_reports_create_exactly_one_ban(self):
        answers, barrier = [], threading.Barrier(30)

        def send():
            barrier.wait()
            answers.append(self.report(IP_A))

        threads = [threading.Thread(target=send) for _ in range(30)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(answers), 30)
        self.assertEqual(sum(a["ban_triggered"] for a in answers), 1)
        self.assertEqual(sum(not a["banned"] for a in answers), 9)
        _, listing = self.request("GET", "/v1/bans", key=ADMIN_KEY)
        self.assertEqual(len(listing["bans"]), 1)
        self.assertEqual(len(listing["bans"][0]["evidence"]), 10)


class CheckTests(ApiCase):
    def test_validation(self):
        self.assertError(self.request("GET", "/v1/check"), 400, "invalid_request")
        self.assertError(self.request("GET", "/v1/check?ip=banana"), 400, "invalid_ip")
        self.assertError(self.request("GET", f"/v1/check?ip={IP_A}&context=admin"), 400, "invalid_request")

    def test_unseen_ip_is_simply_not_banned(self):
        self.assertEqual(self.check(IP_B), {
            "ip": IP_B, "context": "login", "banned": False, "allow": True,
            "ban": None, "explanation": None, "checked_at": "2026-10-05T10:00:00.000Z",
        })

    def test_banned_answer(self):
        ban = self.ban()["ban"]
        self.clock.advance(500)
        status, answer = self.request("GET", f"/v1/check?ip={IP_A}&context=login")
        self.assertEqual(status, 200)
        self.assertEqual(answer, {
            "ip": IP_A, "context": "login", "banned": True, "allow": False,
            "ban": ban,
            "explanation": {
                "blocked": True,
                "reason_code": "failed_login_threshold",
                "message": "Sign-in from your network address is temporarily blocked "
                           "because of too many failed sign-in attempts.",
                "started_at": "2026-10-05T10:00:09.000Z",
                "expires_at": "2026-10-05T10:15:09.000Z",
                "retry_after_seconds": 900,
            },
            "checked_at": "2026-10-05T10:00:09.500Z",
        })

    def test_check_changes_nothing(self):
        for _ in range(9):
            self.report(IP_A)
        for _ in range(20):
            self.check(IP_A)
        self.assertTrue(self.report(IP_A)["ban_triggered"])


class BansTests(ApiCase):
    def list(self, query=""):
        status, answer = self.request("GET", "/v1/bans" + query, key=ADMIN_KEY)
        self.assertEqual(status, 200, answer)
        return answer["bans"]

    def test_empty(self):
        self.assertEqual(self.list(), [])

    def test_validation(self):
        get = lambda q: self.request("GET", "/v1/bans" + q, key=ADMIN_KEY)
        for bad in ("?limit=0", "?limit=201", "?limit=-1", "?limit=ten", "?limit=", "?limit=1.5"):
            self.assertError(get(bad), 400, "invalid_request")
        self.assertError(get("?status=banned"), 400, "invalid_request")
        self.assertError(get("?ip=banana"), 400, "invalid_ip")
        self.assertEqual(get("?limit=1")[0], 200)
        self.assertEqual(get("?limit=200")[0], 200)

    def test_admin_sees_full_ban_with_evidence(self):
        ban = self.ban()["ban"]
        (listed,) = self.list()
        self.assertEqual({k: listed[k] for k in BAN_FIELDS}, ban)
        self.assertEqual(len(listed["evidence"]), 10)
        self.assertEqual(listed["evidence"][0],
                         {"received_at": "2026-10-05T10:00:00.000Z", "username": "user0"})
        self.assertEqual(listed["evidence"][9]["received_at"], listed["triggered_at"])

    def test_username_is_null_when_not_sent(self):
        for _ in range(10):
            self.report(IP_A)
        self.assertIsNone(self.list()[0]["evidence"][0]["username"])

    def test_filters_and_order(self):
        a = self.ban(IP_A)["ban"]
        self.clock.advance(1000)
        b = self.ban(IP_B)["ban"]
        self.assertEqual([x["id"] for x in self.list()], [b["id"], a["id"]])
        self.assertEqual([x["id"] for x in self.list("?limit=1")], [b["id"]])
        self.assertEqual([x["id"] for x in self.list(f"?ip=::ffff:{IP_A}")], [a["id"]])
        self.clock.set(parse_ts(a["expires_at"]))
        self.assertEqual([x["id"] for x in self.list("?status=expired")], [a["id"]])
        self.assertEqual([x["id"] for x in self.list("?status=active")], [b["id"]])
        self.assertEqual(self.list("?status=revoked"), [])

    def test_unban(self):
        ban = self.ban()["ban"]
        self.clock.advance(5000)
        status, revoked = self.request("DELETE", f"/v1/bans/{ban['id']}", key=ADMIN_KEY)
        self.assertEqual(status, 200)
        self.assertEqual(revoked["status"], "revoked")
        self.assertEqual(revoked["revoked_at"], "2026-10-05T10:00:14.000Z")
        self.assertEqual(revoked["expires_at"], ban["expires_at"])
        self.assertEqual(len(revoked["evidence"]), 10)
        check = self.check(IP_A)
        self.assertFalse(check["banned"])
        self.assertTrue(check["allow"])

        self.clock.advance(5000)
        again = self.request("DELETE", f"/v1/bans/{ban['id']}", key=ADMIN_KEY)
        self.assertEqual(again, (200, revoked))
        self.assertEqual(self.list("?status=revoked"), [revoked])

    def test_unban_expired_ban_changes_nothing(self):
        ban = self.ban()["ban"]
        self.clock.set(parse_ts(ban["expires_at"]))
        status, same = self.request("DELETE", f"/v1/bans/{ban['id']}", key=ADMIN_KEY)
        self.assertEqual(status, 200)
        self.assertEqual(same["status"], "expired")
        self.assertIsNone(same["revoked_at"])

    def test_unban_unknown_id(self):
        self.assertError(self.request("DELETE", "/v1/bans/ban_missing", key=ADMIN_KEY), 404, "not_found")

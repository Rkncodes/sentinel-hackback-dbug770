"""Optional AI incident brief: Sentinel's facts, the Groq client, the fallback, the endpoint.

No test here talks to the real Groq API. The HTTP call is replaced by a mock.
"""

import io
import json
import unittest
import urllib.error
from unittest import mock

from sentinel.brief import (SYSTEM_PROMPT, BriefUnavailable, GroqBriefer, clean_brief,
                            fallback_brief, incident_brief)
from sentinel.config import Config

from .support import ADMIN_KEY, IP_A, IP_B, PORTAL_KEY, T0, ApiCase, ServiceCase
from .test_demo import DemoPortalCase

SECRET = "gsk_test_secret_key_1234567890"
FACT_KEYS = {
    "source_ip", "generated_at", "status", "action", "currently_banned", "failed_attempts",
    "threshold", "window_seconds", "threshold_reached", "ban", "success_alert", "last_ban",
}
GOOD_TEXT = "Sentinel banned the address after ten failed sign-in attempts. The ban is active and expires soon."


class FactsTests(ServiceCase):
    def fails(self, n, username="student", ip=IP_A):
        for _ in range(n):
            verdict = self.sentinel.report(ip, "failure", username)
        return verdict

    def facts(self, ip=IP_A):
        return self.sentinel.incident_facts(ip)

    def test_clear(self):
        facts = self.facts()
        self.assertEqual(set(facts), FACT_KEYS)
        self.assertEqual(facts, {
            "source_ip": IP_A, "generated_at": "2026-10-05T10:00:00.000Z",
            "status": "clear", "action": "none", "currently_banned": False,
            "failed_attempts": 0, "threshold": 10, "window_seconds": 60, "threshold_reached": False,
            "ban": None, "success_alert": None, "last_ban": None,
        })

    def test_monitoring(self):
        self.fails(3)
        facts = self.facts()
        self.assertEqual((facts["status"], facts["action"], facts["failed_attempts"]), ("monitoring", "none", 3))
        self.assertFalse(facts["threshold_reached"])
        self.assertEqual(self.facts(IP_B)["status"], "clear")  # per address

    def test_flagged_after_a_lucky_guess(self):
        self.fails(5)
        self.clock.advance(1000)
        self.assertIsNotNone(self.sentinel.report(IP_A, "success", "student").warning)
        facts = self.facts()
        self.assertEqual((facts["status"], facts["action"]), ("flagged", "login_allowed_and_flagged"))
        self.assertFalse(facts["currently_banned"])
        self.assertEqual(facts["failed_attempts"], 5)
        self.assertEqual(facts["success_alert"], {
            "code": "success_after_failed_attempts", "failed_attempts": 5, "at": "2026-10-05T10:00:01.000Z"})

    def test_banned(self):
        ban = self.fails(10).ban
        self.clock.advance(30_500)
        facts = self.facts()
        self.assertEqual((facts["status"], facts["action"]), ("banned", "ip_banned"))
        self.assertTrue(facts["currently_banned"])
        self.assertTrue(facts["threshold_reached"])
        self.assertEqual(facts["failed_attempts"], 10)
        self.assertEqual(facts["ban"], {
            "reason": "failed_login_threshold", "started_at": "2026-10-05T10:00:00.000Z",
            "expires_at": "2026-10-05T10:15:00.000Z", "seconds_remaining": 870})
        self.assertIsNone(facts["success_alert"])
        self.assertIsNone(facts["last_ban"])
        self.assertEqual(self.sentinel.check(IP_A).ban, ban)

    def test_ban_that_followed_a_lucky_guess_still_mentions_it(self):
        self.fails(5)
        self.sentinel.report(IP_A, "success", "student")
        self.assertTrue(self.fails(5).ban_triggered)
        facts = self.facts()
        self.assertEqual(facts["status"], "banned")
        self.assertEqual(facts["success_alert"]["failed_attempts"], 5)

    def test_alert_note_ages_out_with_the_window(self):
        self.fails(5)
        self.sentinel.report(IP_A, "success", "student")
        self.clock.set(T0 + 60_000)
        self.assertEqual(self.facts()["status"], "flagged")
        self.clock.set(T0 + 60_001)
        facts = self.facts()
        self.assertEqual((facts["status"], facts["success_alert"], facts["failed_attempts"]), ("clear", None, 0))

    def test_after_expiry(self):
        self.fails(5)
        self.sentinel.report(IP_A, "success", "student")
        ban = self.fails(5).ban
        self.clock.set(ban.expires_at)
        facts = self.facts()
        self.assertEqual((facts["status"], facts["action"], facts["currently_banned"]), ("clear", "none", False))
        self.assertIsNone(facts["ban"])
        self.assertIsNone(facts["success_alert"])  # it belonged to the ban that has ended
        self.assertEqual(facts["last_ban"], {
            "reason": "failed_login_threshold", "started_at": "2026-10-05T10:00:00.000Z",
            "ended_at": "2026-10-05T10:15:00.000Z", "ended_by": "expiry"})

    def test_after_manual_unban(self):
        ban = self.fails(10).ban
        self.clock.advance(5000)
        self.sentinel.revoke(ban.id)
        last = self.facts()["last_ban"]
        self.assertEqual((last["ended_by"], last["ended_at"]), ("administrator", "2026-10-05T10:00:05.000Z"))

    def test_facts_carry_no_usernames_or_evidence(self):
        for i in range(5):
            self.sentinel.report(IP_A, "failure", "secret-student")
        self.sentinel.report(IP_A, "success", "secret-student")
        for i in range(5):
            self.sentinel.report(IP_A, "failure", f"other-user-{i}")
        for facts in (self.facts(),):
            text = json.dumps(facts) + fallback_brief(facts)
            for leaked in ("secret-student", "other-user", "username", "evidence", "password"):
                self.assertNotIn(leaked, text)

    def test_gathering_facts_changes_nothing(self):
        self.fails(9)
        for _ in range(25):
            self.assertEqual(self.facts()["failed_attempts"], 9)
        ban = self.fails(1).ban  # still exactly the tenth failure
        self.assertIsNotNone(ban)
        for _ in range(25):
            self.facts()
        self.assertEqual(self.sentinel.list_bans(None, None, 200)[0], [ban])
        self.assertEqual(self.sentinel.check(IP_A).ban, ban)

    def test_old_alert_notes_are_swept_from_memory(self):
        self.fails(5)
        self.sentinel.report(IP_A, "success", "student")
        self.sentinel.sweep()
        self.assertEqual(len(self.sentinel._alerts), 1)
        self.clock.advance((60 + 900) * 1000 + 1)
        self.sentinel.sweep()
        self.assertEqual(self.sentinel._alerts, {})


class FallbackBriefTests(ServiceCase):
    def brief(self):
        return fallback_brief(self.sentinel.incident_facts(IP_A))

    def assertBrief(self, text, *expected):
        self.assertTrue(2 <= text.count(". ") + 1 <= 5, text)
        for fragment in expected:
            self.assertIn(fragment, text)

    def test_every_state_gets_a_useful_summary(self):
        self.assertIn("No active security event for 203.0.113.7", self.brief())
        for _ in range(3):
            self.sentinel.report(IP_A, "failure", "student")
        self.assertBrief(self.brief(), IP_A, "3 failed sign-in attempts", "60-second", "threshold of 10", "No ban is active")
        for _ in range(2):
            self.sentinel.report(IP_A, "failure", "student")
        self.sentinel.report(IP_A, "success", "student")
        self.assertBrief(self.brief(), "allowed but flagged", "5 failed sign-in attempts", "No ban is active",
                         "took no blocking action")
        for _ in range(5):
            ban = self.sentinel.report(IP_A, "failure", "student").ban
        self.assertBrief(self.brief(), "automatically banned 203.0.113.7", "10 failed sign-in attempts",
                         "2026-10-05T10:15:00.000Z", "900 seconds", "existing sessions continue",
                         "allowed but flagged")
        self.clock.set(ban.expires_at)
        self.assertBrief(self.brief(), "No active security event", "expired at 2026-10-05T10:15:00.000Z")

    def test_unban_is_described(self):
        for _ in range(10):
            ban = self.sentinel.report(IP_A, "failure", None).ban
        self.sentinel.revoke(ban.id)
        self.assertIn("was lifted by an administrator", self.brief())


def _response(body):
    payload = body if isinstance(body, bytes) else json.dumps(body).encode()
    response = mock.MagicMock()
    response.__enter__.return_value.read.return_value = payload
    return response


def _completion(text):
    return _response({"choices": [{"message": {"role": "assistant", "content": text}}]})


class GroqClientTests(unittest.TestCase):
    FACTS = {"source_ip": IP_A, "status": "banned", "failed_attempts": 10}

    def briefer(self):
        return GroqBriefer(SECRET, "test-model", "https://api.groq.example/openai/v1/")

    def test_success_and_request_shape(self):
        with mock.patch("sentinel.brief.urllib.request.urlopen", return_value=_completion(GOOD_TEXT)) as urlopen:
            self.assertEqual(self.briefer().generate(self.FACTS), GOOD_TEXT)
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.groq.example/openai/v1/chat/completions")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.get_header("Authorization"), f"Bearer {SECRET}")
        self.assertEqual(urlopen.call_args.kwargs["timeout"], 8.0)
        body = json.loads(request.data)
        self.assertEqual(body["model"], "test-model")
        system, user = body["messages"]
        self.assertEqual((system["role"], system["content"]), ("system", SYSTEM_PROMPT))
        for rule in ("Summarize only the supplied structured security facts", "Never invent facts",
                     "Never make or recommend a ban decision", "deterministic security engine is authoritative"):
            self.assertIn(rule, SYSTEM_PROMPT)
        self.assertIn(json.dumps(self.FACTS), user["content"])
        self.assertNotIn(SECRET, request.data.decode())  # the key travels in the header only

    def test_request_uses_max_completion_tokens_and_hides_reasoning(self):
        config = Config.from_env({"SENTINEL_PORTAL_KEY": "p", "SENTINEL_ADMIN_KEY": "a",
                                  "GROQ_API_KEY": SECRET, "GROQ_MODEL": "openai/gpt-oss-20b"})
        briefer = GroqBriefer(config.groq_api_key, config.groq_model, config.groq_base_url)
        # The shape Groq returns for a reasoning model once the budget covers the answer.
        reply = _response({
            "id": "chatcmpl-test", "object": "chat.completion", "model": "openai/gpt-oss-20b",
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": GOOD_TEXT}}],
            "usage": {"completion_tokens": 96, "completion_tokens_details": {"reasoning_tokens": 61}},
        })
        facts = {"source_ip": IP_A, "status": "banned", "failed_attempts": 10}
        with mock.patch("sentinel.brief.urllib.request.urlopen", return_value=reply) as urlopen:
            answer = incident_brief(facts, briefer)
        self.assertEqual(answer, {"source": "groq", "brief": GOOD_TEXT, "facts": facts})

        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.groq.com/openai/v1/chat/completions")
        body = json.loads(request.data)
        self.assertEqual(body["model"], "openai/gpt-oss-20b")  # from GROQ_MODEL
        self.assertNotIn("max_tokens", body)
        self.assertIsInstance(body["max_completion_tokens"], int)
        self.assertGreaterEqual(body["max_completion_tokens"], 150)
        self.assertIs(body["include_reasoning"], False)

    def test_budget_spent_on_reasoning_falls_back(self):
        # What the direct test showed: finish_reason "length", every token spent on reasoning.
        exhausted = _response({"choices": [{"finish_reason": "length",
                                            "message": {"role": "assistant", "content": ""}}],
                               "usage": {"completion_tokens": 20,
                                         "completion_tokens_details": {"reasoning_tokens": 18}}})
        facts = {"source_ip": IP_A, "window_seconds": 60, "threshold": 10, "failed_attempts": 0,
                 "success_alert": None, "ban": None, "last_ban": None}
        with mock.patch("sentinel.brief.urllib.request.urlopen", return_value=exhausted):
            with self.assertRaises(BriefUnavailable):
                self.briefer().generate(facts)
            answer = incident_brief(facts, self.briefer())
        self.assertEqual((answer["source"], answer["brief"]), ("fallback", fallback_brief(facts)))

    def test_reply_cut_off_by_the_budget_keeps_only_whole_sentences(self):
        def cut(content):
            return _response({"choices": [{"finish_reason": "length",
                                           "message": {"role": "assistant", "content": content}}]})

        partial = "Sentinel banned 203.0.113.7 at 2026-10-05T10:00:41.250Z after ten failures. The ban expires in abo"
        with mock.patch("sentinel.brief.urllib.request.urlopen", return_value=cut(partial)):
            self.assertEqual(self.briefer().generate(self.FACTS),
                             "Sentinel banned 203.0.113.7 at 2026-10-05T10:00:41.250Z after ten failures.")
        with mock.patch("sentinel.brief.urllib.request.urlopen", return_value=cut("Sentinel banned the address aft")):
            with self.assertRaises(BriefUnavailable):
                self.briefer().generate(self.FACTS)

    def test_content_given_as_parts_is_read(self):
        parts = [{"type": "text", "text": "Sentinel banned the address after ten failed attempts."},
                 {"type": "text", "text": "The ban is active."}]
        with mock.patch("sentinel.brief.urllib.request.urlopen", return_value=_completion(parts)):
            self.assertEqual(self.briefer().generate(self.FACTS),
                             "Sentinel banned the address after ten failed attempts. The ban is active.")

    def test_model_output_is_cleaned(self):
        messy = "**Summary**\n\n- Sentinel banned `203.0.113.7` after ten failed attempts.\n- The ban is active.\x07"
        with mock.patch("sentinel.brief.urllib.request.urlopen", return_value=_completion(messy)):
            text = self.briefer().generate(self.FACTS)
        self.assertEqual(text, "Summary Sentinel banned 203.0.113.7 after ten failed attempts. The ban is active.")

    def test_every_failure_becomes_brief_unavailable(self):
        http_error = urllib.error.HTTPError("u", 401, "Unauthorized", {}, io.BytesIO(b'{"error": "bad key"}'))
        failures = {
            "connection refused": urllib.error.URLError("refused"),
            "timeout": TimeoutError("timed out"),
            "http 401": http_error,
            "not json": _response(b"<html>gateway error</html>"),
            "no choices": _response({"choices": []}),
            "wrong shape": _response({"result": "ok"}),
            "not text": _completion(None),
            "empty": _completion("   "),
            "too short": _completion("ok"),
            "too long": _completion("word " * 400),
            "echoes the key": _completion(f"The configured key is {SECRET} and the address was banned."),
        }
        for label, outcome in failures.items():
            kwargs = {"side_effect": outcome} if isinstance(outcome, Exception) else {"return_value": outcome}
            with mock.patch("sentinel.brief.urllib.request.urlopen", **kwargs):
                with self.assertRaises(BriefUnavailable, msg=label) as raised:
                    self.briefer().generate(self.FACTS)
            self.assertNotIn(SECRET, str(raised.exception), label)
            self.assertIsNone(raised.exception.__cause__, label)

    def test_clean_brief_keeps_codes_and_plain_text(self):
        text = "The sign-in was flagged (success_after_failed_attempts) but allowed."
        self.assertEqual(clean_brief(text), text)

    def test_incident_brief_chooses_the_source(self):
        facts = {"source_ip": IP_A, "window_seconds": 60, "threshold": 10, "failed_attempts": 0,
                 "success_alert": None, "ban": None, "last_ban": None}

        class Boom:
            def generate(self, facts):
                raise RuntimeError("unexpected")

        good = mock.Mock(generate=mock.Mock(return_value=GOOD_TEXT))
        self.assertEqual(incident_brief(facts, good), {"source": "groq", "brief": GOOD_TEXT, "facts": facts})
        for unavailable in (None, mock.Mock(generate=mock.Mock(side_effect=BriefUnavailable("x"))), Boom()):
            answer = incident_brief(facts, unavailable)
            self.assertEqual((answer["source"], answer["brief"]), ("fallback", fallback_brief(facts)))


class ConfigTests(unittest.TestCase):
    KEYS = {"SENTINEL_PORTAL_KEY": "p", "SENTINEL_ADMIN_KEY": "a"}

    def test_groq_is_off_by_default(self):
        config = Config.from_env(self.KEYS)
        self.assertEqual(config.groq_api_key, "")
        self.assertEqual(config.groq_model, "openai/gpt-oss-20b")
        self.assertEqual(config.groq_base_url, "https://api.groq.com/openai/v1")

    def test_groq_settings_and_key_never_in_repr(self):
        config = Config.from_env({**self.KEYS, "GROQ_API_KEY": f" {SECRET} ", "GROQ_MODEL": "some-model"})
        self.assertEqual((config.groq_api_key, config.groq_model), (SECRET, "some-model"))
        self.assertNotIn(SECRET, repr(config))
        self.assertNotIn(SECRET, str(config))


class IncidentBriefApiTests(ApiCase):
    def brief(self, ip=IP_A, key=ADMIN_KEY):
        return self.request("POST", "/v1/incident-brief", key=key, body={"ip": ip})

    def test_without_a_key_the_deterministic_fallback_is_returned(self):
        self.assertIsNone(self.server.briefer)
        self.ban()
        status, answer = self.brief()
        self.assertEqual(status, 200)
        self.assertEqual(set(answer), {"source", "brief", "facts"})
        self.assertEqual(answer["source"], "fallback")
        self.assertEqual(set(answer["facts"]), FACT_KEYS)
        self.assertEqual(answer["facts"]["status"], "banned")
        self.assertEqual(answer["brief"], fallback_brief(answer["facts"]))
        self.assertIn("automatically banned 203.0.113.7", answer["brief"])

    def test_groq_success_returns_the_generated_brief(self):
        self.server.briefer = mock.Mock(generate=mock.Mock(return_value=GOOD_TEXT))
        self.ban()
        status, answer = self.brief(f"::ffff:{IP_A}")
        self.assertEqual((status, answer["source"], answer["brief"]), (200, "groq", GOOD_TEXT))
        self.assertEqual(answer["facts"]["source_ip"], IP_A)
        # Groq was given Sentinel's facts, and exactly the facts that were returned.
        self.server.briefer.generate.assert_called_once_with(answer["facts"])

    def test_groq_failure_or_timeout_falls_back(self):
        for failure in (BriefUnavailable("failed"), TimeoutError("timed out"), RuntimeError("anything")):
            self.server.briefer = mock.Mock(generate=mock.Mock(side_effect=failure))
            status, answer = self.brief()
            self.assertEqual((status, answer["source"]), (200, "fallback"), failure)
            self.assertEqual(answer["brief"], fallback_brief(answer["facts"]))
            self.assertNotIn("Traceback", json.dumps(answer))

    def test_access_and_validation(self):
        # Sent without a body: a request refused at the key check is answered before its
        # body is read, and on Windows the client can then see a reset instead of the answer.
        self.assertError(self.request("POST", "/v1/incident-brief", key=PORTAL_KEY), 403, "forbidden")
        self.assertError(self.request("POST", "/v1/incident-brief", key=None), 401, "unauthorized")
        self.assertError(self.request("POST", "/v1/incident-brief", key=ADMIN_KEY, body={}), 400, "invalid_request")
        self.assertError(self.brief("banana"), 400, "invalid_ip")
        self.assertError(self.request("GET", "/v1/incident-brief", key=ADMIN_KEY), 404, "not_found")

    def test_caller_cannot_supply_the_facts(self):
        status, answer = self.request("POST", "/v1/incident-brief", key=ADMIN_KEY, body={
            "ip": IP_A, "status": "banned", "currently_banned": True, "failed_attempts": 999,
            "facts": {"status": "banned"}})
        self.assertEqual(status, 200)
        self.assertEqual((answer["facts"]["status"], answer["facts"]["failed_attempts"]), ("clear", 0))

    def test_brief_never_changes_security_state(self):
        for _ in range(9):
            self.report(IP_A, username="student")
        for _ in range(10):
            self.brief()
        tenth = self.report(IP_A, username="student")
        self.assertTrue(tenth["ban_triggered"])  # the briefs counted nothing
        _, before = self.request("GET", "/v1/bans", key=ADMIN_KEY)
        for _ in range(10):
            self.brief()
        _, after = self.request("GET", "/v1/bans", key=ADMIN_KEY)
        self.assertEqual(after, before)
        check = self.check(IP_A)
        self.assertEqual((check["banned"], check["allow"]), (True, False))
        self.assertEqual(self.request("GET", f"/v1/check?ip={IP_A}&context=session")[1]["allow"], True)

    def test_success_alert_answer_is_unchanged_and_reaches_the_brief(self):
        for _ in range(5):
            self.report(IP_A, username="student")
        answer = self.report(IP_A, outcome="success", username="student")
        self.assertEqual(answer, {
            "ip": IP_A, "banned": False, "ban_triggered": False, "ban": None, "explanation": None,
            "warning": {"code": "success_after_failed_attempts",
                        "message": "Successful login followed repeated failed attempts from this address.",
                        "failed_attempts": 5}})
        _, brief = self.brief()
        self.assertEqual(brief["facts"]["status"], "flagged")
        self.assertIn("allowed but flagged", brief["brief"])
        self.assertNotIn("student", json.dumps(brief))


class KeyIsNeverExposedTests(ApiCase):
    """A real GroqBriefer with a key, pointed at a port where nothing listens."""

    def config(self, **overrides):
        return super().config(groq_api_key=SECRET, groq_model="test-model",
                              groq_base_url="http://127.0.0.1:9/openai/v1", **overrides)

    def test_key_is_in_no_response(self):
        self.assertIsInstance(self.server.briefer, GroqBriefer)
        self.ban()
        answers = [
            self.request("POST", "/v1/incident-brief", key=ADMIN_KEY, body={"ip": IP_A}),
            self.request("GET", "/v1/bans", key=ADMIN_KEY),
            self.request("GET", f"/v1/check?ip={IP_A}"),
            self.request("POST", "/v1/incident-brief", key=PORTAL_KEY),
            self.request("POST", "/v1/incident-brief", key=ADMIN_KEY, body={"ip": "banana"}),
        ]
        self.assertEqual(answers[0][1]["source"], "fallback")  # the unreachable Groq degraded quietly
        for status, body in answers:
            text = json.dumps(body)
            self.assertNotIn(SECRET, text)
            self.assertNotIn("gsk_", text)
            self.assertNotIn("api_key", text.lower())


class DemoPortalBriefTests(DemoPortalCase):
    def test_portal_relays_the_brief_for_the_current_state(self):
        clear = self.post("/api/admin/incident-brief", {"ip": IP_A})
        self.assertEqual(clear["outcome"], "ok")
        self.assertEqual(clear["sentinel"][0]["response"]["facts"]["status"], "clear")

        for _ in range(5):
            self.login(IP_A, "wrong")
        self.login(IP_A)  # the lucky guess
        flagged = self.post("/api/admin/incident-brief", {"ip": IP_A})["sentinel"][0]["response"]
        self.assertEqual((flagged["source"], flagged["facts"]["status"]), ("fallback", "flagged"))

        for _ in range(5):
            self.login(IP_A, "wrong")
        banned = self.post("/api/admin/incident-brief", {"ip": IP_A})["sentinel"][0]["response"]
        self.assertEqual(banned["facts"]["status"], "banned")
        self.assertIn("automatically banned", banned["brief"])
        self.assertEqual(self.post("/api/admin/incident-brief", {"ip": "nope"})["outcome"], "error")

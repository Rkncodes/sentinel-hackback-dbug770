"""Optional AI incident brief for administrators.

Sentinel's structured facts about one address are turned into a short summary:
by Groq when a key is configured and the call succeeds, otherwise by the
deterministic fallback below. The brief is informational only. It never takes
part in a security decision.
"""

import json
import re
import urllib.error
import urllib.request

SYSTEM_PROMPT = (
    "You are an incident-summary assistant for Sentinel. Summarize only the supplied "
    "structured security facts. Never invent facts. Never make or recommend a ban decision. "
    "Sentinel's deterministic security engine is authoritative. "
    "Write 2 to 4 plain sentences for an administrator. No markdown, no lists, no headings. "
    "Do not mention usernames, passwords or secrets, and do not recommend changing "
    "Sentinel's behavior."
)

_MIN_LENGTH, _MAX_LENGTH = 20, 800
_COMPLETION_BUDGET = 400  # tokens: a 2-4 sentence brief plus a reasoning model's reasoning


class BriefUnavailable(Exception):
    """The AI brief could not be produced. Carries no detail worth showing to a user."""


def clean_brief(text) -> str:
    """Validate and normalise model output before it is shown; raise if unusable."""
    if not isinstance(text, str):
        raise BriefUnavailable("no text")
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", text)          # control characters, newlines
    text = re.sub(r"[*#`>|]+", "", text)                   # markdown markers
    text = re.sub(r"(^|\s)[-•]\s+", r"\1", text)           # list bullets
    text = re.sub(r"\s+", " ", text).strip()
    if not _MIN_LENGTH <= len(text) <= _MAX_LENGTH:
        raise BriefUnavailable("unusable length")
    return text


def _message_text(answer) -> str:
    """The text of choices[0].message.content, whatever shape it arrives in.

    Content may be a string, a list of text parts, or empty when the model ran out of
    budget. A reply cut off by the budget is trimmed back to its last whole sentence.
    """
    choice = answer["choices"][0]
    content = choice["message"].get("content")
    if isinstance(content, list):
        content = " ".join(
            part.get("text", "") if isinstance(part, dict) else str(part) for part in content)
    if not isinstance(content, str) or not content.strip():
        raise ValueError("no content")
    if choice.get("finish_reason") == "length":
        ends = [m.end() for m in re.finditer(r"[.!?](?=\s|$)", content)]
        if not ends:
            raise ValueError("truncated before a full sentence")
        content = content[:ends[-1]]
    return content


class GroqBriefer:
    """Asks Groq's OpenAI-compatible chat endpoint for the brief. Standard library only."""

    def __init__(self, api_key: str, model: str, base_url: str, timeout: float = 8.0):
        self._api_key = api_key
        self.model = model
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._timeout = timeout

    def generate(self, facts: dict) -> str:
        payload = {
            "model": self.model,
            "temperature": 0.2,
            # Reasoning models (such as openai/gpt-oss-20b) spend completion tokens on
            # reasoning before writing any content, so the budget must cover both.
            "max_completion_tokens": _COMPLETION_BUDGET,
            "include_reasoning": False,  # only the brief itself is wanted back
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": "Security facts from Sentinel (JSON):\n" + json.dumps(facts)},
            ],
        }
        request = urllib.request.Request(self._url, data=json.dumps(payload).encode("utf-8"), method="POST")
        request.add_header("Authorization", f"Bearer {self._api_key}")
        request.add_header("Content-Type", "application/json")
        request.add_header("User-Agent", "sentinel-incident-brief/1.0")
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                answer = json.loads(response.read())
            text = _message_text(answer)
        except (OSError, ValueError, KeyError, IndexError, TypeError, AttributeError):
            # Refused, timed out, HTTP error, not JSON, unexpected shape. The cause is
            # deliberately dropped: it may quote the request, which carries the key.
            raise BriefUnavailable("Groq request failed") from None
        text = clean_brief(text)
        if self._api_key in text:
            raise BriefUnavailable("unsafe output")
        return text


def fallback_brief(facts: dict) -> str:
    """A useful summary built from the facts alone. Deterministic; invents nothing."""
    ip, window, threshold = facts["source_ip"], facts["window_seconds"], facts["threshold"]
    failures, alert, ban, last = facts["failed_attempts"], facts["success_alert"], facts["ban"], facts["last_ban"]
    attempts = lambda n: f"{n} failed sign-in attempt" + ("" if n == 1 else "s")

    if ban is not None:
        text = (
            f"Sentinel automatically banned {ip} after {attempts(failures)} within {window} seconds, "
            f"reaching the threshold of {threshold}. The ban started at {ban['started_at']} and expires at "
            f"{ban['expires_at']}, about {ban['seconds_remaining']} seconds from now. New sign-ins from this "
            "address are refused while existing sessions continue."
        )
        if alert is not None:
            text += (f" Before the ban, a successful sign-in from this address followed "
                     f"{attempts(alert['failed_attempts'])} and was allowed but flagged.")
        return text
    if alert is not None:
        return (
            f"A successful sign-in from {ip} followed {attempts(alert['failed_attempts'])} on the same account "
            f"and was allowed but flagged ({alert['code']}). No ban is active: {attempts(failures)} "
            f"{'is' if failures == 1 else 'are'} inside the {window}-second window, below the threshold of "
            f"{threshold}. Sentinel took no blocking action."
        )
    if failures:
        return (
            f"{ip} has {attempts(failures)} inside the {window}-second window, below the ban threshold of "
            f"{threshold}. No ban is active and no alert has been raised."
        )
    text = (f"No active security event for {ip}: no ban is active and no failed sign-in attempts are "
            f"inside the {window}-second window.")
    if last is not None:
        how = "was lifted by an administrator" if last["ended_by"] == "administrator" else "expired"
        text += f" The most recent ban on this address started at {last['started_at']} and {how} at {last['ended_at']}."
    return text


def incident_brief(facts: dict, briefer) -> dict:
    """The endpoint's answer: Groq's brief when available, the fallback otherwise."""
    if briefer is not None:
        try:
            return {"source": "groq", "brief": briefer.generate(facts), "facts": facts}
        except BriefUnavailable:
            pass
        except Exception:  # an optional layer must never break the endpoint
            pass
    return {"source": "fallback", "brief": fallback_brief(facts), "facts": facts}

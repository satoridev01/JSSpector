"""Shared Claude usage-limit scheduling for autonomous online workers."""

from __future__ import annotations

import json
import re
import threading
import time
from datetime import datetime, timedelta


RESET_MARGIN = timedelta(minutes=1)
USAGE_LIMIT_RE = re.compile(
    r"usage limit|session limit|rate.?limit|quota exceeded|credit balance"
    r"|usage_limit_reached|insufficient_quota|overloaded_error"
    r"|hit your (?:\d+(?:-hour)?|[^\r\n]+?) limit",
    re.IGNORECASE,
)
RESET_TIME_RE = re.compile(
    r"\bresets?(?:\s+at)?\s+(?:(?P<date>\d{4}-\d{2}-\d{2})[ T])?"
    r"(?P<hour>\d{1,2})(?::(?P<minute>\d{2}))?\s*(?P<ampm>[ap]m)?\b",
    re.IGNORECASE,
)
RESET_NAMED_DATE_RE = re.compile(
    r"\bresets?(?:\s+at)?\s+"
    r"(?P<month>Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|"
    r"Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|"
    r"Nov(?:ember)?|Dec(?:ember)?)\s+"
    r"(?P<day>\d{1,2})(?:,?\s+(?P<year>\d{4}))?\s+(?:at\s+)?"
    r"(?P<hour>\d{1,2})(?::(?P<minute>\d{2}))?\s*(?P<ampm>[ap]m)?\b",
    re.IGNORECASE,
)


def usage_limit_message(*values: object) -> str:
    """Return the bounded line carrying Claude's reset notice, if present."""
    for value in values:
        if isinstance(value, dict):
            nested = usage_limit_message(value.get("result"), value.get("api_error"))
            if nested:
                return nested
        text = str(value or "")
        if isinstance(value, str) and value.lstrip().startswith("{"):
            try:
                nested = usage_limit_message(json.loads(value))
            except (TypeError, json.JSONDecodeError):
                nested = ""
            if nested:
                return nested
        for line in text.splitlines():
            if USAGE_LIMIT_RE.search(line):
                return line.strip()[:2000]
    return ""


def resume_at(message: str, now: datetime | None = None) -> datetime:
    """Parse Claude's reset time and add a one-minute safety margin."""
    now = now or datetime.now().astimezone()
    named = RESET_NAMED_DATE_RE.search(str(message))
    if named:
        month = datetime.strptime(named.group("month")[:3], "%b").month
        year = int(named.group("year") or now.year)
        hour = int(named.group("hour"))
        minute = int(named.group("minute") or 0)
        ampm = (named.group("ampm") or "").lower()
        if ampm:
            hour = hour % 12 + (12 if ampm == "pm" else 0)
        reset = datetime(
            year,
            month,
            int(named.group("day")),
            hour,
            minute,
            tzinfo=now.tzinfo,
        )
        if not named.group("year") and reset + RESET_MARGIN <= now:
            reset = reset.replace(year=year + 1)
        return reset + RESET_MARGIN
    match = RESET_TIME_RE.search(str(message))
    if not match:
        return now + timedelta(hours=5) + RESET_MARGIN
    hour = int(match.group("hour"))
    minute = int(match.group("minute") or 0)
    ampm = (match.group("ampm") or "").lower()
    if ampm:
        hour = hour % 12 + (12 if ampm == "pm" else 0)
    date = (
        datetime.fromisoformat(match.group("date")).date()
        if match.group("date")
        else now.date()
    )
    reset = datetime.combine(date, datetime.min.time(), tzinfo=now.tzinfo).replace(
        hour=hour, minute=minute
    )
    deadline = reset + RESET_MARGIN
    if not match.group("date") and deadline <= now:
        deadline += timedelta(days=1)
    return deadline


class UsageGate:
    """One shared pause deadline used by every local Claude consumer."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._resume_at: datetime | None = None

    def pause(self, message: str) -> tuple[datetime, bool]:
        deadline = resume_at(message)
        with self._lock:
            changed = self._resume_at is None or deadline > self._resume_at
            if changed:
                self._resume_at = deadline
            return self._resume_at, changed

    def wait(self, stop: threading.Event) -> bool:
        """Wait until capacity returns; false means the run was interrupted."""
        while True:
            with self._lock:
                deadline = self._resume_at
            if deadline is None:
                return True
            delay = (deadline - datetime.now().astimezone()).total_seconds()
            if delay <= 0:
                with self._lock:
                    if self._resume_at == deadline:
                        self._resume_at = None
                return True
            if stop.wait(min(delay, 60.0)):
                return False
            time.sleep(0)

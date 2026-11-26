"""GitHub REST client: a pool of tokens, repository search and PVR checks.

Stdlib only, so it runs inside the Satori job. Each token has its own rate-limit windows
(``core`` for PVR checks, ``search`` for repository search), so a pool of N tokens gives
about N times the throughput. The pool hands each call to the next token in turn; every
token paces itself under GitHub's limits and waits out its own window when it runs dry.
"""
import itertools
import json
import logging
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.client import HTTPException

API = "https://api.github.com"
USER_AGENT = "jsspector-online"
CORE_RESERVE = 50  # calls left in each core window (tokens here are dedicated to discovery)
SEARCH_RESERVE = 1  # one search call left per window
CORE_INTERVAL = 0.1  # seconds between a token's core calls: under the secondary limit
SEARCH_INTERVAL = 2.1  # seconds between a token's search calls: 30 per minute
RETRIES = 5
REQUEST_TIMEOUT = 10  # bounds operator cancellation while urllib owns the thread
SEARCH_PAGE = 100  # results per search page (GitHub's maximum)
SEARCH_MAX = 1000  # results GitHub returns for one query, however many match

log = logging.getLogger("github")


class Budget:
    """Paces one GitHub rate-limit window for one token.

    Calls go out at most every ``interval`` seconds; once the window is down to ``reserve``
    calls every caller sleeps until it resets.
    """

    def __init__(self, interval, reserve, *, label, on_wait=lambda _label, _seconds: None):
        self.interval = interval
        self.reserve = reserve
        self.label = label
        self.on_wait = on_wait
        self._lock = threading.Lock()
        self._next = 0.0
        self.remaining = None
        self.reset = 0.0
        self.waited = 0.0

    def acquire(self, should_stop=lambda: False):
        """Block until this token may make the next call, unless the run is stopping."""
        with self._lock:
            now = time.time()
            start = max(now, self._next)
            if self.remaining is not None and self.remaining <= self.reserve \
                    and self.reset > start:
                self.waited += self.reset + 1 - start
                start = self.reset + 1
                self.remaining = None
            elif self.remaining is not None:
                self.remaining -= 1
            self._next = start + self.interval
        delay = max(0.0, start - now)
        if delay >= 1.0:
            self.on_wait(self.label, delay)
        deadline = time.monotonic() + delay
        while True:
            if should_stop():
                return False
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(0.2, remaining))
        return not should_stop()

    def defer(self, seconds):
        """Share a secondary-limit cooldown across every worker using this token."""
        with self._lock:
            now = time.time()
            deferred = max(self._next, now + seconds)
            self.waited += max(0.0, deferred - max(now, self._next))
            self._next = deferred

    def update(self, headers):
        """Record the window state GitHub reports on every response."""
        try:
            remaining = int(headers["X-RateLimit-Remaining"])
            reset = float(headers["X-RateLimit-Reset"])
        except (KeyError, TypeError, ValueError):
            return
        with self._lock:
            self.remaining, self.reset = remaining, reset


def rate_limit_pause(err):
    """Seconds to wait before retrying if err is a GitHub rate limit, else None."""
    if err.code not in (403, 429):
        return None
    retry_after = err.headers.get("Retry-After")
    if retry_after and retry_after.isdigit():
        return int(retry_after)
    if err.headers.get("X-RateLimit-Remaining") == "0":
        return 0  # the window's Budget sleeps until the reset it just recorded
    if b"rate limit" in err.read().lower():
        return 60  # secondary rate limit without headers
    return None


class Session:
    """One token: its auth header and its core and search rate-limit windows."""

    def __init__(self, token, should_stop=lambda: False, on_status=lambda _message: None):
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28",
        }
        self.on_status = on_status
        self._status_lock = threading.Lock()
        self._next_status = 0.0
        self.core = Budget(
            CORE_INTERVAL, CORE_RESERVE, label="core", on_wait=self.notice_wait
        )
        self.search = Budget(
            SEARCH_INTERVAL, SEARCH_RESERVE, label="search", on_wait=self.notice_wait
        )
        self.should_stop = should_stop

    def notice_wait(self, label, seconds):
        """Publish a bounded wait notice without flooding concurrent workers."""
        now = time.monotonic()
        with self._status_lock:
            if now < self._next_status:
                return
            self._next_status = now + 5.0
        self.on_status(f"GitHub {label} budget waiting about {int(seconds + 0.999)}s")

    def wait(self, seconds):
        """Sleep in cancellable slices rather than hiding a stopped run in backoff."""
        deadline = time.monotonic() + seconds
        while True:
            if self.should_stop():
                return False
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(0.2, remaining))
        return not self.should_stop()

    def call(self, url, budget):
        """GET url -> (HTTP status, payload); status 0 if every retry failed."""
        for attempt in range(RETRIES):
            if not budget.acquire(self.should_stop):
                return 0, None
            request = urllib.request.Request(url, headers=self.headers)
            try:
                with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
                    budget.update(response.headers)
                    return response.status, json.load(response)
            except urllib.error.HTTPError as err:
                budget.update(err.headers)
                pause = rate_limit_pause(err)
                if pause is None and err.code < 500:
                    return err.code, None
                if pause is not None:
                    if pause > 0:
                        budget.defer(pause)
                    continue
                if not self.wait(2 ** attempt):
                    return 0, None
            except (OSError, ValueError, HTTPException):  # network, cut connection, bad body
                if not self.wait(2 ** attempt):
                    return 0, None
        return 0, None


class TokenPool:
    """A pool of tokens that spreads calls across them, round-robin."""

    def __init__(
        self, tokens, should_stop=lambda: False, on_status=lambda _message: None
    ):
        if not tokens:
            raise ValueError("TokenPool needs at least one token")
        self.sessions = [Session(token, should_stop, on_status) for token in tokens]
        self._turn = itertools.cycle(self.sessions)
        self._lock = threading.Lock()

    def _next(self):
        with self._lock:
            return next(self._turn)

    @property
    def waited(self):
        """Total seconds every token spent waiting out an exhausted window."""
        return sum(s.core.waited + s.search.waited for s in self.sessions)

    @property
    def recommended_parallelism(self):
        """Enough overlap for HTTP latency without overwhelming one credential."""
        return max(1, len(self.sessions) * 2)

    def has_pvr(self, repo):
        """Whether repo has private vulnerability reporting on; None if GitHub did not
        answer. 403/404/451 (no access, gone, legal) count as no PVR."""
        session = self._next()
        status, payload = session.call(
            f"{API}/repos/{repo}/private-vulnerability-reporting", session.core)
        if status == 200:
            return bool((payload or {}).get("enabled"))
        return False if status in (403, 404, 451) else None

    def search(self, query, page=1):
        """One page of a repository search -> (items, total_count); (None, 0) on failure."""
        url = (f"{API}/search/repositories?q={urllib.parse.quote(query)}"
               f"&per_page={SEARCH_PAGE}&page={page}&sort=updated&order=desc")
        session = self._next()
        status, payload = session.call(url, session.search)
        if status != 200 or payload is None:
            return None, 0
        return payload.get("items", []), payload.get("total_count", 0)

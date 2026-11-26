#!/usr/bin/env python3
"""Stage 1 (discover): public GitHub repos in LANGUAGE, optionally filtered by private
vulnerability reporting (PVR).

Candidates come from the GitHub Search API in exhaustive star-count partitions. The partitions
exist only to stay below GitHub's result cap: by default they include every star count and impose
no minimum fork count. Each resolved batch is prioritized by fork count, highest first, before it
is yielded to the scanner. Each candidate's PVR status is one core REST call, so a pool of tokens
multiplies throughput. Discovery yields selected repos batch by batch, so a consumer can scan them
while it keeps searching.

A search query returns at most 1000 results however many match, so each tier is walked in
time windows narrow enough to stay under that cap.

Env: GITHUB_TOKENS (comma/space separated, required), LANGUAGE (JavaScript), LIMIT (0 = no
limit), MIN_FORKS (minimum forks; default 0 = no minimum), SINCE_SECONDS (how far back
in push time to search; default 365 days), ALL_CANDIDATES (0 = skip repositories with no
stars; included by default), PVR_MODE (on = only repos that accept private vulnerability reports, the
default; off = only repos that do not; any = either, skip the PVR check entirely). Skips
repos listed in exclude.txt. Writes repos.txt (the repos worth scanning under PVR_MODE),
checked.txt (the rest, so later runs skip them) and discover.json.
"""
import json
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

import github

LOOKBACK_SECONDS = 365 * 24 * 3600  # default push-time window when none is given
DEFAULT_MIN_FORKS = 0
PVR_MODES = ("on", "off", "any")
TIERS = ("stars:>=100", "stars:10..99", "stars:1..9")  # highest PVR rate first
ZERO_STAR_TIER = "stars:0"  # included by default; includes user and organization owners
MIN_WINDOW = timedelta(minutes=2)  # do not bisect a push-time window smaller than this
TIME_FMT = "%Y-%m-%dT%H:%M:%SZ"
POLL_GAP = 15.0   # seconds between sweeps while watching continuously
POLL_SLICE = 0.5  # nap granularity, so a stop signal is noticed within this


def _utcnow():
    """Current UTC time; injectable in tests via Watch.clock."""
    return datetime.now(timezone.utc)


log = logging.getLogger("discover")


@dataclass
class Config:
    """Discovery parameters."""

    language: str = "JavaScript"
    limit: int = 0
    min_forks: int = DEFAULT_MIN_FORKS
    since_seconds: int = LOOKBACK_SECONDS
    all_candidates: bool = True
    pvr_mode: str = "on"
    pvr_parallel: int = 8
    out: Path = Path(".")
    exclude: frozenset = frozenset()
    should_stop: Callable[[], bool] = lambda: False
    on_progress: Callable[[str], None] = lambda _message: None

    def __post_init__(self):
        if self.min_forks < 0:
            raise ValueError("min_forks must be non-negative")
        if self.pvr_mode not in PVR_MODES:
            raise ValueError(f"pvr_mode must be one of {PVR_MODES}, got {self.pvr_mode!r}")
        if self.pvr_parallel < 1:
            raise ValueError("pvr_parallel must be positive")

    @classmethod
    def from_env(cls, out=Path(".")):
        """Build from environment variables, as the job passes them."""
        exclude = out / "exclude.txt"
        return cls(
            language=os.environ.get("LANGUAGE") or "JavaScript",
            limit=int(os.environ.get("LIMIT") or 0),
            min_forks=int(os.environ.get("MIN_FORKS") or DEFAULT_MIN_FORKS),
            since_seconds=int(os.environ.get("SINCE_SECONDS") or LOOKBACK_SECONDS),
            all_candidates=os.environ.get("ALL_CANDIDATES", "1") != "0",
            pvr_mode=os.environ.get("PVR_MODE") or "on",
            pvr_parallel=int(os.environ.get("PVR_PARALLEL") or 8),
            out=out,
            exclude=frozenset(exclude.read_text(encoding="utf-8").split())
            if exclude.exists() else frozenset(),
        )


@dataclass
class Candidate:
    """A repository the search returned, with the fields that predict PVR and scan cost."""

    repo: str
    stars: int = 0
    forks: int = 0
    size_kb: int = 0
    org: bool = False
    licensed: bool = False
    security_advisories: str = "unknown"


@dataclass
class Metrics:
    """Counters written to discover.json."""

    searches: int = 0
    candidates: int = 0
    pvr_checks: int = 0
    positives: int = 0
    found: int = 0
    errors: int = 0
    rate_limited_s: float = 0.0
    elapsed_s: float = 0.0

    def summary(self):
        """Counters plus the rates the coordinator uses to project larger runs."""
        hours = max(self.elapsed_s, 1.0) / 3600
        return {
            **asdict(self),
            "hit_rate": round(self.positives / self.pvr_checks, 4) if self.pvr_checks else 0.0,
            "checks_per_hour": round(self.pvr_checks / hours),
            "found_per_hour": round(self.found / hours, 1),
        }


def format_summary(label, summary):
    """A flat metrics dict as an aligned key: value table -- stdlib only, no rich, since this
    runs inside the Satori job. Plain padded columns, not a box: simpler to get right than
    box-drawing characters when the output is piped through several layers of log capture."""
    width = max((len(key) for key in summary), default=0)
    rows = "\n".join(f"  {key:<{width}} : {value}" for key, value in summary.items())
    return f"{label}:\n{rows}"


def iso(moment):
    """A datetime as the Search API's push-time bound."""
    return moment.strftime(TIME_FMT)


def candidate_of(item):
    """A Candidate from one search result."""
    owner = item.get("owner") or {}
    return Candidate(
        repo=item["full_name"],
        stars=item.get("stargazers_count", 0),
        forks=item.get("forks_count", 0),
        size_kb=item.get("size", 0),
        org=owner.get("type") == "Organization",
        licensed=bool(item.get("license")),
    )


def prioritize_batch(candidates):
    """Most-forked repositories first, with a stable name tie-breaker.

    Sorting only the bounded batch preserves streaming and backpressure: online work starts before
    GitHub has finished enumerating the complete 24-hour inventory.
    """
    return sorted(
        candidates,
        key=lambda candidate: (-candidate.forks, candidate.repo.casefold(), candidate.repo),
    )


def tier_query(cfg, tier, start, end):
    """Search query for one star tier and push-time window."""
    forks = f" forks:>={cfg.min_forks}" if cfg.min_forks else ""
    return (f"language:{cfg.language} fork:false archived:false "
            f"{tier}{forks} pushed:{iso(start)}..{iso(end)}")


@dataclass
class Watch:
    """Keep discovering for duration_s, sweeping the fresh window every poll_gap seconds and
    stopping early when should_stop() turns true (e.g. a SIGTERM): a time-boxed monitor whose
    end-of-run metrics are the batch yield -- what was found in that time."""

    duration_s: float
    poll_gap: float = POLL_GAP
    should_stop: Callable[[], bool] = lambda: False
    clock: Callable[[], datetime] = _utcnow
    monotonic: Callable[[], float] = time.monotonic


class Searcher:
    """Streams search candidates across exhaustive star partitions, deduped."""

    def __init__(self, pool, cfg):
        self.pool = pool
        self.cfg = cfg
        self.metrics = Metrics()
        self.seen = set(cfg.exclude)

    def windows(self, tier, start, end):
        """(start, end, total) push-time windows of one tier, newest first, each with no
        more results than the search cap, splitting windows that exceed it."""
        pending = [(start, end)]
        while pending:
            low, high = pending.pop()
            _, total = self.pool.search(tier_query(self.cfg, tier, low, high), 1)
            self.metrics.searches += 1
            self.cfg.on_progress(
                f"GitHub search {tier}: {total} matches in current time window"
            )
            if total <= github.SEARCH_MAX or high - low <= MIN_WINDOW:
                if total:
                    yield low, high, total
            else:
                middle = low + (high - low) / 2
                pending.append((low, middle))   # older half after
                pending.append((middle, high))  # newer half first (popped next)

    def tier(self, tier, start, end):
        """Candidates of one star tier between start and end, newest first, deduped."""
        for low, high, total in self.windows(tier, start, end):
            for page in range(1, min(total, github.SEARCH_MAX) // github.SEARCH_PAGE + 2):
                items, _ = self.pool.search(tier_query(self.cfg, tier, low, high), page)
                self.metrics.searches += 1
                if not items:
                    break
                yield from self._new(items, tier)

    def _new(self, items, tier):
        """Not-yet-seen, worth-checking candidates among search results."""
        for item in items:
            candidate = candidate_of(item)
            if candidate.repo in self.seen:
                continue
            self.seen.add(candidate.repo)
            if candidate.forks >= self.cfg.min_forks:
                yield candidate

    def stream(self, now, start=None):
        """Every candidate in ``start..now``, tier by tier and newest push first.

        Without an explicit start this is the configured full lookback.  Watch mode supplies
        the previous sweep's end after its first pass, so polling costs only the newly elapsed
        time range instead of re-fetching the entire historical pool.
        """
        start = start or now - timedelta(seconds=self.cfg.since_seconds)
        tiers = TIERS + ((ZERO_STAR_TIER,) if self.cfg.all_candidates else ())
        for tier in tiers:
            for candidate in self.tier(tier, start, now):
                self.metrics.candidates += 1
                yield candidate


class Discovery:
    """One discovery run over the search tiers until LIMIT PVR repos are found."""

    def __init__(self, pool, cfg):
        self.pool = pool
        self.cfg = cfg
        self.searcher = Searcher(pool, cfg)
        self.metrics = self.searcher.metrics
        self.found = []

    def done(self):
        """Whether LIMIT repos were found."""
        return bool(self.cfg.limit) and len(self.found) >= self.cfg.limit

    def run(self, now=None, on_found=None, watch=None):
        """Discover; writes repos.txt as repos are found, plus checked.txt and discover.json.
        Calls on_found(candidate) for each PVR repo, so a consumer can scan it right away.
        With a Watch, keeps sweeping the fresh window until its deadline or should_stop,
        deduping across sweeps (a time-boxed monitor); otherwise does one sweep."""
        started = time.time()
        self.cfg.out.mkdir(parents=True, exist_ok=True)
        with (self.cfg.out / "repos.txt").open("w", encoding="utf-8") as found, \
                (self.cfg.out / "checked.txt").open("w", encoding="utf-8") as negatives:
            sinks = {True: found, False: negatives}
            if watch is None:
                self._sweep(
                    now or _utcnow(),
                    sinks,
                    on_found,
                    lambda: self.done() or self.cfg.should_stop(),
                )
            else:
                self._watch(watch, sinks, on_found)
        self.metrics.rate_limited_s = round(self.pool.waited)
        self.metrics.elapsed_s = round(time.time() - started, 1)
        summary = self.metrics.summary()
        (self.cfg.out / "discover.json").write_text(
            json.dumps(summary, indent=2), encoding="utf-8")
        log.info(format_summary("discover", summary))
        return summary

    def _sweep(self, now, sinks, on_found, guard, start=None):
        """One pass over the tiers, newest push first; stops early when guard() is true."""
        candidates = self.searcher.stream(now, start=start)
        if self.cfg.pvr_mode == "any":
            batch = []
            for candidate in candidates:
                if guard():
                    break
                batch.append(candidate)
                if len(batch) == 64:
                    self._record_unchecked_batch(batch, sinks, on_found, guard)
                    batch = []
            if batch and not guard():
                self._record_unchecked_batch(batch, sinks, on_found, guard)
            return

        # Preserve Search API order while overlapping the independent PVR endpoint calls.  The
        # bounded batch keeps memory flat for inventories with tens of thousands of repositories.
        workers = min(self.cfg.pvr_parallel, self.pool.recommended_parallelism)
        batch_size = max(64, workers * 8)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            batch = []
            for candidate in candidates:
                if guard():
                    break
                batch.append(candidate)
                if len(batch) == batch_size:
                    self._check_batch(batch, executor, sinks, on_found, guard)
                    batch = []
            if batch and not guard():
                self._check_batch(batch, executor, sinks, on_found, guard)

    def _check_batch(self, candidates, executor, sinks, on_found, guard):
        """Resolve PVR concurrently, then commit the batch in fork-priority order."""
        candidates = prioritize_batch(candidates)
        self.cfg.on_progress(
            f"checking security advisories for {len(candidates)} repositories; "
            "most-forked first"
        )
        statuses = executor.map(self.pool.has_pvr, (item.repo for item in candidates))
        for index, (candidate, enabled) in enumerate(
            zip(candidates, statuses, strict=True), start=1
        ):
            self.metrics.pvr_checks += 1
            if guard():
                break
            self._record(candidate, enabled, sinks, on_found)
            if index == 1 or index % 16 == 0 or index == len(candidates):
                self.cfg.on_progress(
                    f"security advisory checks {index}/{len(candidates)}; "
                    f"{self.metrics.found} repositories selected"
                )

    def _record_unchecked_batch(self, candidates, sinks, on_found, guard):
        """Commit an unfiltered batch in the same fork-priority order as PVR batches."""
        for candidate in prioritize_batch(candidates):
            if guard():
                break
            self.check(candidate, sinks, on_found)

    def _watch(self, watch, sinks, on_found):
        """Sweep repeatedly until the watch's deadline, should_stop or the limit; dedup across
        sweeps means only newly pushed repos cost a PVR check."""
        deadline = watch.monotonic() + watch.duration_s

        def guard():
            return self.done() or watch.should_stop() or watch.monotonic() >= deadline

        previous_end = None
        while not guard():
            current_end = watch.clock()
            self._sweep(current_end, sinks, on_found, guard, start=previous_end)
            previous_end = current_end
            wake = watch.monotonic() + watch.poll_gap
            while not guard() and watch.monotonic() < wake:
                time.sleep(min(POLL_SLICE, wake - watch.monotonic()))

    def check(self, candidate, sinks, on_found=None):
        """Check one candidate's PVR status against cfg.pvr_mode and record it; streams
        wanted repos to on_found. pvr_mode "any" skips the PVR check entirely (every
        candidate is wanted), so it costs no extra API call."""
        if self.cfg.pvr_mode == "any":
            wanted = True
        else:
            enabled = self.pool.has_pvr(candidate.repo)
            self.metrics.pvr_checks += 1
            return self._record(candidate, enabled, sinks, on_found)
        self._record_wanted(candidate, wanted, sinks, on_found)

    def _record(self, candidate, enabled, sinks, on_found=None):
        """Record one already-resolved advisory state without changing result order."""
        if enabled is None:
            self.metrics.errors += 1
            return
        self.metrics.positives += enabled
        candidate.security_advisories = "enabled" if enabled else "disabled"
        wanted = enabled if self.cfg.pvr_mode == "on" else not enabled
        self._record_wanted(candidate, wanted, sinks, on_found)

    def _record_wanted(self, candidate, wanted, sinks, on_found=None):
        """Write one classified candidate and publish wanted candidates to the consumer."""
        if wanted and self.done():
            return  # past the limit: record nowhere, so a later run finds it again
        sinks[wanted].write(candidate.repo + "\n")
        sinks[wanted].flush()
        if wanted:
            self.found.append(candidate.repo)
            self.metrics.found = len(self.found)
            if on_found:
                on_found(candidate)


def pool_from_env(*, should_stop=lambda: False, on_status=lambda _message: None):
    """A TokenPool from GITHUB_TOKENS (comma or space separated), or None if unset."""
    raw = os.environ.get("GITHUB_TOKENS") or os.environ.get("GITHUB_TOKEN") or ""
    tokens = [token for token in raw.replace(",", " ").split() if token]
    return (
        github.TokenPool(tokens, should_stop=should_stop, on_status=on_status)
        if tokens
        else None
    )


def main():
    """Entry point for a discover-only run."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
    pool = pool_from_env()
    if pool is None:
        log.error("GITHUB_TOKENS is required")
        return 1
    Discovery(pool, Config.from_env()).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())

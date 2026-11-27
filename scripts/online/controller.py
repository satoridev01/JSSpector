#!/usr/bin/env python3
"""Controller for JSSpector's autonomous, verified-only online research mode.

Discovery, static analysis and Docker verification happen before synchronization. A private
Satori report is created only after JSSpector returns
``exploitation.outcome == \"verified\"``, and it contains only those verified findings.
"""

from __future__ import annotations

import argparse
import fcntl
import functools
import hashlib
import json
import os
import re
import shlex
import signal
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import CancelledError, Future, ThreadPoolExecutor
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

import discover
import github
import resources
from claude_limits import UsageGate, usage_limit_message


ROOT = Path(__file__).resolve().parent
DEFAULT_OUT = ROOT / "runs" / "jsspector-online"
DEFAULT_SINCE_SECONDS = 24 * 60 * 60
DEFAULT_SCANNER = Path(
    os.environ.get("JSSPECTOR_BINARY")
    or ROOT.parents[1] / "target" / "release" / "jsspector"
)
SEVERITY_ORDER = {"critical": 0, "high": 1}
RETRYABLE_STATUSES = {
    "clone-timeout",
    "static-timeout",
    "verify-timeout",
    "verify-startup-timeout",
    "verify-candidate-idle-timeout",
    "verify-candidate-hard-timeout",
    "verify-repository-timeout",
    "fix-timeout",
}
VERIFY_RUN_LABEL_KEY = "ci.satori.jsspector.verify-run"
GIB = 1024**3
DOCKER_QUERY_TIMEOUT_S = 30
DOCKER_CLEANUP_TIMEOUT_S = 180
DISK_WATCHDOG_INTERVAL_S = 60
DOCKER_CLEANUP_LOCK = threading.Lock()
EVENT_LOCK = threading.Lock()
LOG_LOCK = threading.Lock()
EVENT_PREFIX = "@@JSSPECTOR_ONLINE@@"
VERIFY_PROGRESS_PREFIX = "@@JSSPECTOR_VERIFY@@"
LOG_PATH: Path | None = None
SHUTDOWN = threading.Event()
ACTIVE_PROCESSES: dict[int, subprocess.Popen[str]] = {}
ACTIVE_PROCESSES_LOCK = threading.Lock()
CLAUDE_USAGE_GATE = UsageGate()


@dataclass(frozen=True)
class ResearchResult:
    """One repository's terminal local result."""

    repository: str
    revision: str | None = None
    security_advisories: str = "unknown"
    repository_forks: int = 0
    repository_stars: int = 0
    report: dict[str, Any] | None = None
    findings: tuple[dict[str, Any], ...] = ()
    failed: bool = False
    failure_reason: str | None = None
    fix_attempted: bool = False
    fix_proven: bool = False
    docker_cleanup_failures: int = 0
    cancelled: bool = False
    elapsed_s: float = 0.0
    # Improvement metrics: Docker slot time, its split by verifier phase, and whether a candidate
    # was actually driven ("not-reproduced") or none could be ("skipped", with the first reason).
    slot_s: float = 0.0
    phases: dict[str, float] = field(default_factory=dict)
    driven: str = ""
    skip_reason: str | None = None


@dataclass(frozen=True)
class StaticResult:
    """One repository after the cheap deterministic scan."""

    repository: str
    revision: str | None = None
    security_advisories: str = "unknown"
    repository_forks: int = 0
    repository_stars: int = 0
    report: dict[str, Any] | None = None
    candidates: tuple[dict[str, Any], ...] = ()
    checkout: Path | None = None
    failed: bool = False
    failure_reason: str | None = None
    cancelled: bool = False
    elapsed_s: float = 0.0


@dataclass
class VerificationBudgetState:
    """Adaptive deadlines for one repository's dynamic verification."""

    started: float
    startup_s: int
    candidate_soft_s: int
    candidate_hard_s: int
    normal_s: int
    extended_s: int
    fix_s: int
    phase: str = "repository"
    phase_started: float | None = None
    candidate_activity: bool = False
    candidate_positive: bool = False
    repository_positive: bool = False
    finishing_deadline: float | None = None
    phase_clock: float | None = None
    phase_totals: dict[str, float] = field(default_factory=dict)

    def _account(self, now: float) -> None:
        """Charge the time since the last phase change to the phase that just ended."""
        clock = self.started if self.phase_clock is None else self.phase_clock
        self.phase_totals[self.phase] = self.phase_totals.get(self.phase, 0.0) + max(
            0.0, now - clock
        )
        self.phase_clock = now

    def close(self, now: float) -> dict[str, float]:
        """Seconds spent per phase once the verifier has exited."""
        self._account(now)
        return {phase: round(value, 1) for phase, value in self.phase_totals.items()}

    def observe(self, payload: dict[str, Any], now: float) -> None:
        event = payload.get("event")
        if event in {
            "candidate_started",
            "app_ready",
            "fix_started",
            "fix_finished",
            "candidate_finished",
        }:
            self._account(now)
        if event == "candidate_started":
            self.phase = "startup"
            self.phase_started = now
            self.candidate_activity = False
            self.candidate_positive = False
        elif event == "app_ready":
            self.phase = "candidate"
            self.phase_started = now
        elif event == "request_activity":
            self.candidate_activity = True
        elif event == "positive_evidence":
            self.candidate_activity = True
            self.candidate_positive = True
            self.repository_positive = True
        elif event == "fix_started":
            self.phase = "fix"
            self.phase_started = now
        elif event == "fix_finished":
            self.phase = "finishing"
            self.phase_started = now
            self.finishing_deadline = now + 60
        elif event == "candidate_finished":
            if self.phase != "finishing":
                self.phase = "repository"
                self.phase_started = None
                self.candidate_activity = False
                self.candidate_positive = False

    def timed_out(self, now: float) -> str | None:
        if self.phase == "fix" and self.phase_started is not None:
            return "fix-timeout" if now >= self.phase_started + self.fix_s else None
        if self.phase == "finishing":
            return (
                "fix-timeout"
                if self.finishing_deadline is not None and now >= self.finishing_deadline
                else None
            )
        if self.phase == "startup" and self.phase_started is not None:
            if now >= self.phase_started + self.startup_s:
                return "verify-startup-timeout"
        if self.phase == "candidate" and self.phase_started is not None:
            if not self.candidate_positive:
                if not self.candidate_activity and now >= self.phase_started + self.candidate_soft_s:
                    return "verify-candidate-idle-timeout"
                if now >= self.phase_started + self.candidate_hard_s:
                    return "verify-candidate-hard-timeout"
        repository_budget = self.extended_s if self.repository_positive else self.normal_s
        if now >= self.started + repository_budget:
            return "verify-repository-timeout"
        return None


@dataclass(frozen=True)
class DockerInventory:
    """Docker objects that existed before this online run started."""

    images: frozenset[str]
    volumes: frozenset[str]


def log(message: str) -> None:
    """Timestamped progress that remains readable when two workers interleave."""
    stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"[{stamp}] {message}"
    with LOG_LOCK:
        print(line, flush=True)
        if LOG_PATH is not None:
            try:
                with LOG_PATH.open("a", encoding="utf-8") as stream:
                    stream.write(line + "\n")
            except OSError as error:
                print(f"jsspector: cannot append {LOG_PATH}: {error}", file=sys.stderr)


def emit_event(kind: str, **fields: Any) -> None:
    """Publish one machine-readable TUI event without making logs the API."""
    if os.environ.get("JSSPECTOR_ONLINE_EVENTS") != "1":
        return
    payload = {"schema": 1, "type": kind, **fields}
    with EVENT_LOCK:
        print(EVENT_PREFIX + json.dumps(payload, sort_keys=True), flush=True)


def _owned_process_groups(root_pid: int) -> set[int]:
    """Process groups below one owned command, including nested tool sessions."""
    if os.name != "posix":
        return {root_pid}
    try:
        output = subprocess.run(
            ["ps", "-axo", "pid=,ppid=,pgid="],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return {root_pid}
    rows: dict[int, tuple[int, int]] = {}
    for line in output.splitlines():
        try:
            pid, parent, group = (int(value) for value in line.split())
        except (TypeError, ValueError):
            continue
        rows[pid] = (parent, group)
    descendants = {root_pid}
    changed = True
    while changed:
        changed = False
        for pid, (parent, _group) in rows.items():
            if parent in descendants and pid not in descendants:
                descendants.add(pid)
                changed = True
    groups = {rows[pid][1] for pid in descendants if pid in rows}
    groups.add(root_pid)
    groups.discard(os.getpgrp())
    return groups


def terminate_process_tree(process: subprocess.Popen[str]) -> None:
    """Stop only subprocesses owned by this controller."""
    if os.name != "posix":
        try:
            process.kill()
        except ProcessLookupError:
            pass
        return
    for group in _owned_process_groups(process.pid):
        try:
            os.killpg(group, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def request_shutdown(
    _signum: int | None = None,
    _frame: Any = None,
    *,
    message: str = "operator requested a safe stop",
) -> None:
    """Make TUI cancellation bounded and leave no scanner or Claude children behind."""
    if SHUTDOWN.is_set():
        return
    SHUTDOWN.set()
    emit_event("run_stopping", message=message)
    with ACTIVE_PROCESSES_LOCK:
        processes = list(ACTIVE_PROCESSES.values())
    for process in processes:
        terminate_process_tree(process)


def run(
    command: list[str],
    *,
    capture: bool = False,
    timeout: int | None = None,
    log_path: Path | None = None,
    input_text: str | None = None,
    environment: dict[str, str] | None = None,
    echo_capture: bool = True,
    timeout_label: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a command with an optional whole-process-group deadline and artifact log."""
    if capture and log_path is not None:
        raise ValueError("capture and log_path are mutually exclusive")
    if SHUTDOWN.is_set():
        return subprocess.CompletedProcess(command, 130, "", "interrupted")
    log("RUN " + " ".join(command))
    handle = None
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handle = log_path.open("w", encoding="utf-8")
    try:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            text=True,
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture else handle,
            stderr=subprocess.PIPE if capture else (subprocess.STDOUT if handle else None),
            start_new_session=True,
            env=environment,
        )
        with ACTIVE_PROCESSES_LOCK:
            ACTIVE_PROCESSES[process.pid] = process
        timed_out = False
        try:
            stdout, stderr = process.communicate(input=input_text, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            detail = f" label={timeout_label}" if timeout_label else ""
            log(f"TIMEOUT after={timeout}s command={command[0]}{detail}")
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                stdout, stderr = process.communicate()
        finally:
            with ACTIVE_PROCESSES_LOCK:
                ACTIVE_PROCESSES.pop(process.pid, None)
        result = subprocess.CompletedProcess(
            command,
            124 if timed_out else process.returncode,
            stdout,
            stderr,
        )
    finally:
        if handle is not None:
            handle.close()
    if capture and echo_capture:
        if result.stdout:
            print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
        if result.stderr:
            print(
                result.stderr,
                end="" if result.stderr.endswith("\n") else "\n",
                file=sys.stderr,
            )
    return result


def run_verification(
    command: list[str],
    *,
    log_path: Path,
    environment: dict[str, str],
    budgets: VerificationBudgetState,
    repository: str,
) -> subprocess.CompletedProcess[str]:
    """Run the verifier under phase-aware, evidence-sensitive deadlines."""
    if SHUTDOWN.is_set():
        return subprocess.CompletedProcess(command, 130, "", "interrupted")
    log("RUN " + " ".join(command))
    log_path.parent.mkdir(parents=True, exist_ok=True)
    timeout_reason: str | None = None
    with log_path.open("w", encoding="utf-8") as handle:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            text=True,
            stdin=subprocess.DEVNULL,
            stdout=handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env=environment,
        )
        with ACTIVE_PROCESSES_LOCK:
            ACTIVE_PROCESSES[process.pid] = process
        try:
            with log_path.open("r", encoding="utf-8", errors="replace") as stream:
                while process.poll() is None:
                    while line := stream.readline():
                        marker = line.find(VERIFY_PROGRESS_PREFIX)
                        if marker < 0:
                            continue
                        try:
                            payload = json.loads(
                                line[marker + len(VERIFY_PROGRESS_PREFIX):]
                            )
                        except json.JSONDecodeError:
                            continue
                        if isinstance(payload, dict):
                            budgets.observe(payload, time.monotonic())
                    if process.poll() is not None:
                        break
                    timeout_reason = budgets.timed_out(time.monotonic())
                    if timeout_reason is not None:
                        log(
                            f"TIMEOUT reason={timeout_reason} repository={repository} "
                            f"positive={str(budgets.repository_positive).lower()}"
                        )
                        try:
                            os.killpg(process.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            try:
                                os.killpg(process.pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                            process.wait()
                        break
                    time.sleep(0.25)
        finally:
            with ACTIVE_PROCESSES_LOCK:
                ACTIVE_PROCESSES.pop(process.pid, None)
    return subprocess.CompletedProcess(
        command,
        124 if timeout_reason is not None else process.returncode,
        None,
        timeout_reason,
    )


def read_json(path: Path) -> dict[str, Any]:
    """Read an object report with a useful failure."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise RuntimeError(f"expected an object in {path}")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    """Atomically publish state so an interrupted online run can safely restart."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def read_state(path: Path) -> dict[str, Any]:
    """Global deduplication across bounded 24-hour runs."""
    if not path.exists():
        return {"schema_version": 1, "processed": {}, "synced": {}}
    state = read_json(path)
    if not isinstance(state.get("processed"), dict) or not isinstance(
        state.get("synced"), dict
    ):
        raise RuntimeError(f"invalid online state: {path}")
    return state


def completed_repositories(state: dict[str, Any]) -> frozenset[str]:
    """Repositories whose terminal result should be skipped on the next pass."""
    return frozenset(
        repository
        for repository, value in state["processed"].items()
        if not (
            isinstance(value, dict) and value.get("status") in RETRYABLE_STATUSES
        )
    )


def _satori_paged_items(
    satori_cli: str, command: list[str], *, quantity: int = 200
) -> list[dict[str, Any]]:
    """Read every item from one account-level Satori collection."""
    page = 1
    collected: list[dict[str, Any]] = []
    while True:
        payload = _satori_json(
            [
                satori_cli,
                "--json",
                "--page",
                str(page),
                "--quantity",
                str(quantity),
                *command,
            ]
        )
        items = payload.get("items")
        if not isinstance(items, list):
            raise RuntimeError(f"Satori {' '.join(command)} returned no items array")
        page_items = [item for item in items if isinstance(item, dict)]
        collected.extend(page_items)
        total = payload.get("total")
        if not page_items or (isinstance(total, int) and len(collected) >= total):
            return collected
        if len(page_items) < quantity:
            return collected
        page += 1


def satori_repository_blacklist(satori_cli: str) -> dict[str, list[str]]:
    """Repositories already represented by an account Issue or external report."""
    issues = _satori_paged_items(satori_cli, ["issues"])
    advisories = _satori_paged_items(satori_cli, ["advisories"])

    def repositories(items: list[dict[str, Any]]) -> list[str]:
        return sorted(
            {
                repository.strip()
                for item in items
                if isinstance((repository := item.get("repository")), str)
                and repository.strip()
            },
            key=str.casefold,
        )

    return {"issues": repositories(issues), "advisories": repositories(advisories)}


def acquire_run_lock(out: Path):
    """Give one controller exclusive ownership of an output state directory."""
    out.mkdir(parents=True, exist_ok=True)
    handle = (out / "online.lock").open("a+", encoding="utf-8")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        handle.close()
        raise RuntimeError(
            f"another jsspector online process owns {out}; use its TUI or another --out"
        ) from error
    handle.seek(0)
    handle.truncate()
    handle.write(f"pid={os.getpid()}\n")
    handle.flush()
    return handle


# Sources the verifier drives without an HTTP route (browser, socket, MCP, archive and queue
# planners); an `http` or `stored` source needs the entry point the static inventory resolved.
ROUTED_SOURCES = frozenset({"http", "stored"})


def drivable(finding: dict[str, Any]) -> bool:
    """Whether strict verification can plausibly send this candidate anything.

    The verifier skips an HTTP-sourced candidate without an entry point ("no entry point maps to
    this sink") after spending a Docker slot on it, so such candidates go last: with several
    candidates in a repository, they must not crowd out ones that can actually be driven.
    """
    if finding.get("entry"):
        return True
    source = finding.get("source")
    kind = source.get("kind") if isinstance(source, dict) else None
    if kind == "stored":
        stored_by = finding.get("stored_by")
        return isinstance(stored_by, dict) and bool(stored_by.get("entry"))
    return kind not in ROUTED_SOURCES


def unverified_kind(
    report: dict[str, Any], candidates: tuple[dict[str, Any], ...]
) -> tuple[str, str | None]:
    """("not-reproduced" | "skipped", first skip reason) for the selected candidates.

    A candidate that was driven and did not reproduce costs probing time; one that was skipped
    (the app never launched, no route matched) points at launch or routing support to improve.
    """
    selected = {
        candidate.get("fingerprint")
        for candidate in candidates
        if isinstance(candidate, dict)
    }
    outcomes: list[tuple[str, str | None]] = []
    for finding in report.get("findings", []):
        if not isinstance(finding, dict) or finding.get("fingerprint") not in selected:
            continue
        exploitation = finding.get("exploitation")
        if isinstance(exploitation, dict) and isinstance(exploitation.get("outcome"), str):
            reason = exploitation.get("reason")
            outcomes.append(
                (exploitation["outcome"], reason if isinstance(reason, str) else None)
            )
    if any(outcome == "not-reproduced" for outcome, _reason in outcomes):
        return "not-reproduced", None
    skipped = [reason for outcome, reason in outcomes if outcome == "skipped"]
    if skipped:
        return "skipped", next((reason for reason in skipped if reason), None)
    return "not-reproduced", None


def verified_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    """The only findings allowed through the Satori boundary.

    Reaching an attacker-selected file is useful verifier evidence, but a file-existence oracle
    alone does not demonstrate enough confidentiality, integrity, or availability impact to enter
    the public-repository reporting inbox.
    """
    return [
        finding
        for finding in report.get("findings", [])
        if isinstance(finding, dict)
        and isinstance(finding.get("exploitation"), dict)
        and finding["exploitation"].get("outcome") == "verified"
        and finding["exploitation"].get("impact") != "file-existence-only"
        and isinstance(finding.get("fingerprint"), str)
    ]


def filtered_report(report: dict[str, Any]) -> dict[str, Any]:
    """Return a detached report containing no unverified candidate findings."""
    filtered = dict(report)
    filtered["findings"] = verified_findings(report)
    return filtered


def sync_key(
    repository: str, revision: str, findings: tuple[dict[str, Any], ...]
) -> str:
    """Stable idempotency key for exactly this verified evidence."""
    fingerprints = sorted(finding["fingerprint"] for finding in findings)
    value = "\0".join((repository.lower(), revision, *fingerprints))
    return hashlib.sha256(value.encode()).hexdigest()


def github_pool(on_status: Callable[[str], None] = lambda _message: None) -> github.TokenPool:
    """Use the existing token pool convention, falling back to the authenticated gh CLI."""
    pool = discover.pool_from_env(
        should_stop=SHUTDOWN.is_set, on_status=on_status
    )
    if pool is not None:
        return pool
    token = subprocess.run(
        ["gh", "auth", "token"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if token.returncode or not token.stdout.strip():
        raise SystemExit("GITHUB_TOKENS is unset and gh is not authenticated")
    return github.TokenPool(
        [token.stdout.strip()],
        should_stop=SHUTDOWN.is_set,
        on_status=on_status,
    )


def _docker_ids(arguments: list[str]) -> tuple[str, ...]:
    try:
        completed = subprocess.run(
            ["docker", *arguments],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=DOCKER_QUERY_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired):
        log(f"DOCKER_OWNERSHIP_QUERY_FAILED {' '.join(arguments)}")
        return ()
    if completed.returncode:
        log(f"DOCKER_OWNERSHIP_QUERY_FAILED {' '.join(arguments)}")
        return ()
    return tuple(sorted(set(completed.stdout.split())))


def _docker_lines(arguments: list[str]) -> tuple[str, ...]:
    """Return distinct Docker output records without splitting formatted rows."""
    try:
        completed = subprocess.run(
            ["docker", *arguments],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=DOCKER_QUERY_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired):
        log(f"DOCKER_OWNERSHIP_QUERY_FAILED {' '.join(arguments)}")
        return ()
    if completed.returncode:
        log(f"DOCKER_OWNERSHIP_QUERY_FAILED {' '.join(arguments)}")
        return ()
    return tuple(sorted({line.strip() for line in completed.stdout.splitlines() if line.strip()}))


def capture_docker_inventory() -> DockerInventory | None:
    """Snapshot user Docker objects so online GC never deletes pre-existing data."""
    commands = (
        (["docker", "image", "ls", "-aq"], "images"),
        (["docker", "volume", "ls", "-q"], "volumes"),
    )
    captured: dict[str, frozenset[str]] = {}
    for command, name in commands:
        try:
            completed = subprocess.run(
                command,
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
                timeout=DOCKER_QUERY_TIMEOUT_S,
            )
        except (OSError, subprocess.TimeoutExpired):
            log(f"DOCKER_INVENTORY_FAILED resource={name}")
            return None
        if completed.returncode:
            log(f"DOCKER_INVENTORY_FAILED resource={name}")
            return None
        captured[name] = frozenset(completed.stdout.split())
    return DockerInventory(images=captured["images"], volumes=captured["volumes"])


@functools.lru_cache(maxsize=1)
def buildx_prune_flags() -> frozenset[str]:
    """Long options this host's `docker buildx prune` accepts.

    The flags moved between buildx releases (`--timeout` is recent; `--max-used-space` replaced
    `--keep-storage`), and one unknown flag fails the whole prune.
    """
    try:
        completed = subprocess.run(
            ["docker", "buildx", "prune", "--help"],
            text=True,
            capture_output=True,
            check=False,
            timeout=DOCKER_QUERY_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired):
        return frozenset()
    return frozenset(re.findall(r"--[a-z][a-z-]+", completed.stdout + completed.stderr))


def buildx_prune_command(cache_gb: int, min_free_gb: int) -> list[str]:
    """Bound BuildKit's cache with the options this buildx supports."""
    flags = buildx_prune_flags()
    prune = ["docker", "buildx", "prune", "--force"]
    if "--max-used-space" in flags or "--keep-storage" not in flags:
        prune.extend(("--max-used-space", f"{cache_gb}GB"))
    else:
        prune.extend(("--keep-storage", f"{cache_gb}GB"))
    # Without buildx's own deadline the subprocess timeout still bounds the call.
    if "--timeout" in flags:
        prune.extend(("--timeout", "2m"))
    if min_free_gb and "--min-free-space" in flags:
        prune.extend(("--min-free-space", f"{min_free_gb}GB"))
    return prune


# Per-verification images, removed with their verification's label; anything else named (node,
# mongo, postgres, the content-addressed XSS browser) is reusable by the next verification.
SESSION_IMAGE_REPOSITORIES = frozenset({"jsspector-verify", "jsspector-verify-browser"})


def reusable_images() -> frozenset[str]:
    """Short IDs of named images a later verification will build on or run again.

    Deleting a pulled base image every few verifications forces the next build to download it
    again, on the same link every clone and npm install shares.
    """
    try:
        completed = subprocess.run(
            ["docker", "image", "ls", "-a", "--format", "{{.ID}}\t{{.Repository}}"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=DOCKER_QUERY_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired):
        return frozenset()
    if completed.returncode:
        return frozenset()
    keep = set()
    for line in completed.stdout.splitlines():
        image, _, repository = line.partition("\t")
        repository = repository.strip()
        if repository and repository != "<none>" and repository not in SESSION_IMAGE_REPOSITORIES:
            keep.add(image.strip())
    return frozenset(keep)


def _docker_cleanup_command(command: list[str]) -> dict[str, Any] | None:
    """Run one bounded GC command and return a compact failure, if any."""
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=DOCKER_CLEANUP_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"command": command, "stderr": str(error)}
    if completed.returncode:
        return {"command": command, "stderr": completed.stderr[-2000:]}
    return None


def cleanup_online_docker_storage(
    baseline: DockerInventory | None,
    *,
    cache_gb: int,
    min_free_gb: int,
    artifact: Path | None = None,
    keep_reusable_images: bool = False,
) -> dict[str, Any]:
    """Bound BuildKit and remove only images/volumes created after this run began.

    Base images and anonymous volumes cannot inherit the verifier label. Taking a baseline lets the
    controller reclaim those objects without touching Docker data that belonged to the operator
    before `jsspector online` started. Objects still used by an active worker are left for the next
    GC cycle. A periodic cycle with disk to spare keeps named, reusable images (pulled base images,
    the XSS browser) so later builds do not download them again; disk pressure and the final
    cleanup remove them too.
    """
    removed_candidates = {"images": 0, "volumes": 0, "kept_images": 0}
    failures: list[dict[str, Any]] = []
    with DOCKER_CLEANUP_LOCK:
        if baseline is not None:
            current = capture_docker_inventory()
            if current is None:
                failures.append(
                    {"command": ["docker", "inventory"], "stderr": "inventory failed"}
                )
            else:
                new_images = sorted(current.images - baseline.images)
                new_volumes = sorted(current.volumes - baseline.volumes)
                kept = frozenset()
                if keep_reusable_images:
                    kept = reusable_images() & frozenset(new_images)
                    new_images = [image for image in new_images if image not in kept]
                removed_candidates = {
                    "images": len(new_images),
                    "volumes": len(new_volumes),
                    "kept_images": len(kept),
                }
                # No --force: Docker keeps anything an active verification still references.
                for resource, identifiers in (
                    ("image", new_images),
                    ("volume", new_volumes),
                ):
                    for start in range(0, len(identifiers), 100):
                        command = ["docker", resource, "rm", *identifiers[start : start + 100]]
                        failure = _docker_cleanup_command(command)
                        if failure is not None:
                            # A busy object is expected while another lane is active. It remains in
                            # the run delta and will be retried by the next cycle/final cleanup.
                            log(
                                f"DOCKER_GC_DEFERRED resource={resource} "
                                f"count={len(identifiers[start : start + 100])}"
                            )
        prune = buildx_prune_command(cache_gb, min_free_gb)
        failure = _docker_cleanup_command(prune)
        if failure is not None:
            failures.append(failure)
    result = {**removed_candidates, "cache_limit_gb": cache_gb, "failures": failures}
    if artifact is not None:
        write_json(artifact, result)
    log(
        f"DOCKER_STORAGE_GC images={removed_candidates['images']} "
        f"kept_images={removed_candidates['kept_images']} "
        f"volumes={removed_candidates['volumes']} cache_limit_gb={cache_gb} "
        f"failures={len(failures)}"
    )
    return result


def free_disk_gb(path: Path) -> float:
    """Host filesystem headroom at the run directory."""
    return shutil.disk_usage(path).free / GIB


def _owned_docker_resources(run_label: str) -> dict[str, tuple[str, ...]]:
    """Resources carrying this exact verifier ownership label."""
    label = f"label={VERIFY_RUN_LABEL_KEY}={run_label}"
    image_rows = _docker_lines(
        [
            "image",
            "ls",
            "--filter",
            label,
            "--format",
            "{{.ID}} {{.Repository}}:{{.Tag}}",
        ]
    )
    image_tags: dict[str, set[str]] = {}
    for row in image_rows:
        image_id, separator, tag = row.partition(" ")
        if separator:
            image_tags.setdefault(image_id, set()).add(tag)
    disposable_images = tuple(
        sorted(
            image_id
            for image_id, tags in image_tags.items()
            if not any(
                tag.startswith("jsspector-verify-cache:")
                or tag.startswith("jsspector-verify-xss-browser:")
                for tag in tags
            )
        )
    )
    return {
        "containers": _docker_ids(
            ["ps", "-a", "--filter", label, "--format", "{{.Names}}"]
        ),
        "networks": _docker_ids(["network", "ls", "--filter", label, "--quiet"]),
        # Use IDs so a failed teardown cannot hide its image behind <none>:<none>. Dependency and
        # browser-base cache images deliberately survive because rebuilding them would dominate
        # throughput.
        "images": disposable_images,
    }


def cleanup_owned_docker_resources(
    run_label: str, *, artifact: Path
) -> dict[str, Any]:
    """Remove only Docker resources carrying this exact verifier ownership label."""
    with DOCKER_CLEANUP_LOCK:
        resources = _owned_docker_resources(run_label)
        containers = resources["containers"]
        networks = resources["networks"]
        images = resources["images"]
        commands = []
        if containers:
            commands.append(["docker", "rm", "--force", "--volumes", *containers])
        if networks:
            commands.append(["docker", "network", "rm", *networks])
        if images:
            commands.append(["docker", "image", "rm", "--force", *images])
        failures = []
        for command in commands:
            failure = _docker_cleanup_command(command)
            if failure is not None:
                failures.append(failure)
    result = {
        "containers": containers,
        "networks": networks,
        "images": images,
        "failures": failures,
    }
    write_json(artifact, result)
    log(
        f"DOCKER_CLEANUP containers={len(containers)} networks={len(networks)} "
        f"images={len(images)} failures={len(failures)}"
    )
    return result


def verification_run_label(
    run_label: str, repository: str, revision: str, lane: str
) -> str:
    """One valid Docker ownership value per repository verification."""
    digest = hashlib.sha256(
        "\0".join((repository.lower(), revision, lane)).encode()
    ).hexdigest()[:12]
    suffix = f"_{digest}"
    return f"{run_label[: 64 - len(suffix)]}{suffix}"


def cleanup_stale_jsspector_containers(
    run_label: str,
    *,
    min_age_s: int,
    now: datetime | None = None,
) -> tuple[str, ...]:
    """Remove timed-out containers from this run without touching active work.

    A valid verification cannot own a container older than its process deadline. Exact ownership
    labels prevent one concurrent online run from touching another run's resources.
    """
    reference = now or datetime.now(UTC)
    with DOCKER_CLEANUP_LOCK:
        candidates = list(_owned_docker_resources(run_label)["containers"])
        if not candidates:
            return ()
        inspected = subprocess.run(
            ["docker", "container", "inspect", *candidates],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if inspected.returncode:
            log("DOCKER_STALE_INSPECT_FAILED")
            return ()
        try:
            containers = json.loads(inspected.stdout)
        except json.JSONDecodeError:
            log("DOCKER_STALE_INSPECT_INVALID_JSON")
            return ()
        stale = []
        for container in containers:
            if not isinstance(container, dict):
                continue
            name = str(container.get("Name") or "").lstrip("/")
            created_raw = container.get("Created")
            if name not in candidates or not isinstance(created_raw, str):
                continue
            try:
                created = datetime.fromisoformat(created_raw.replace("Z", "+00:00"))
            except ValueError:
                continue
            if (reference - created).total_seconds() >= min_age_s:
                stale.append(name)
        if not stale:
            return ()
        removed = subprocess.run(
            ["docker", "rm", "--force", "--volumes", *stale],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if removed.returncode:
            log(f"DOCKER_STALE_CLEANUP_FAILED containers={len(stale)}")
            return ()
        log(f"DOCKER_STALE_CLEANUP containers={len(stale)}")
        return tuple(stale)


def checkout_directory(run_dir: Path, repository: str) -> Path:
    """A collision-resistant, run-owned checkout reused by every research stage."""
    slug = repository.replace("/", "__")
    digest = hashlib.sha256(repository.lower().encode()).hexdigest()[:12]
    return run_dir / "checkouts" / f"{slug}-{digest}"


def remove_checkout(checkout: Path, run_dir: Path) -> None:
    """Remove only a checkout owned by this run."""
    root = (run_dir / "checkouts").resolve()
    resolved = checkout.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise RuntimeError(f"refusing to remove non-run checkout: {checkout}") from error
    shutil.rmtree(resolved, ignore_errors=True)


def clone_repository(
    repository: str,
    *,
    args: argparse.Namespace,
    run_dir: Path,
) -> tuple[Path | None, str | None]:
    """Create one shallow checkout for static analysis, proof, and fixing.

    A normal shallow clone is intentional. The old partial clone lazily fetched blobs during
    checkout, and every stage repeated it; all observed research timeouts were stuck there.
    """
    checkout = checkout_directory(run_dir, repository)
    checkout.parent.mkdir(parents=True, exist_ok=True)
    if checkout.exists():
        remove_checkout(checkout, run_dir)
    git = shutil.which("git")
    if git is None:
        return None, "clone-failed"
    slug = repository.replace("/", "__")
    completed = run(
        [
            git,
            "-c",
            "advice.detachedHead=false",
            "clone",
            "--depth",
            "1",
            "--single-branch",
            "--no-tags",
            f"https://github.com/{repository}.git",
            str(checkout),
        ],
        timeout=args.clone_timeout,
        log_path=run_dir / "logs" / f"{slug}.clone.log",
        environment={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        timeout_label=f"clone:{repository}",
    )
    if completed.returncode:
        remove_checkout(checkout, run_dir)
        if completed.returncode == 130 or SHUTDOWN.is_set():
            return None, "cancelled"
        return None, "clone-timeout" if completed.returncode == 124 else "clone-failed"
    return checkout, None


def static_repository(
    candidate: discover.Candidate,
    *,
    args: argparse.Namespace,
    scanner: Path,
    run_dir: Path,
) -> StaticResult:
    """Find high-signal candidates without invoking Docker or Claude."""
    started = time.monotonic()
    repository = candidate.repo
    security_advisories = candidate.security_advisories
    repository_forks = candidate.forks
    repository_stars = candidate.stars
    slug = repository.replace("/", "__")
    static_path = run_dir / "reports" / f"{slug}.static.json"
    static_path.parent.mkdir(parents=True, exist_ok=True)

    checkout, clone_failure = clone_repository(
        repository,
        args=args,
        run_dir=run_dir,
    )
    if clone_failure is not None:
        if clone_failure == "cancelled":
            return StaticResult(
                repository=repository,
                security_advisories=security_advisories,
                repository_forks=repository_forks,
                repository_stars=repository_stars,
                cancelled=True,
                elapsed_s=round(time.monotonic() - started, 1),
            )
        log(f"CLONE_FAILED {repository} reason={clone_failure}")
        return StaticResult(
            repository=repository,
            security_advisories=security_advisories,
            repository_forks=repository_forks,
            repository_stars=repository_stars,
            failed=True,
            failure_reason=clone_failure,
            elapsed_s=round(time.monotonic() - started, 1),
        )
    assert checkout is not None

    result = run(
        [
            str(scanner),
            "scan",
            str(checkout),
            "--format",
            "json",
            "--output",
            str(static_path),
            "--min-severity",
            "high",
            "--allow-incomplete",
            "--no-config",
            "--no-inline-ignores",
            "--threads",
            str(args.scan_threads),
        ],
        timeout=args.static_timeout,
        log_path=run_dir / "logs" / f"{slug}.static.log",
        timeout_label=f"static:{repository}",
    )
    if result.returncode:
        remove_checkout(checkout, run_dir)
        if result.returncode == 130 or SHUTDOWN.is_set():
            return StaticResult(
                repository=repository,
                security_advisories=security_advisories,
                repository_forks=repository_forks,
                repository_stars=repository_stars,
                cancelled=True,
                elapsed_s=round(time.monotonic() - started, 1),
            )
        log(f"STATIC_FAILED {repository} exit={result.returncode}")
        reason = "static-timeout" if result.returncode == 124 else "static-failed"
        return StaticResult(
            repository=repository,
            security_advisories=security_advisories,
            repository_forks=repository_forks,
            repository_stars=repository_stars,
            failed=True,
            failure_reason=reason,
            elapsed_s=round(time.monotonic() - started, 1),
        )

    static = read_json(static_path)
    revision = (static.get("git") or {}).get("revision")
    candidates = [
        finding
        for finding in static.get("findings", [])
        if isinstance(finding, dict)
        and finding.get("severity") in SEVERITY_ORDER
        and isinstance(finding.get("fingerprint"), str)
    ]
    candidates.sort(
        key=lambda finding: (
            not drivable(finding),
            SEVERITY_ORDER[finding["severity"]],
            finding["fingerprint"],
        )
    )
    if not candidates:
        log(f"NO_HIGH_FINDINGS {repository}")
        remove_checkout(checkout, run_dir)
        return StaticResult(
            repository=repository,
            revision=revision,
            security_advisories=security_advisories,
            repository_forks=repository_forks,
            repository_stars=repository_stars,
            report=static,
            elapsed_s=round(time.monotonic() - started, 1),
        )
    if not isinstance(revision, str) or not revision:
        log(f"NO_REVISION {repository}; refusing an unpinned verification")
        remove_checkout(checkout, run_dir)
        return StaticResult(
            repository=repository,
            security_advisories=security_advisories,
            repository_forks=repository_forks,
            repository_stars=repository_stars,
            failed=True,
            failure_reason="missing-revision",
            elapsed_s=round(time.monotonic() - started, 1),
        )

    log(f"STATIC_CANDIDATES {repository}@{revision} count={len(candidates)}")
    return StaticResult(
        repository=repository,
        revision=revision,
        security_advisories=security_advisories,
        repository_forks=repository_forks,
        repository_stars=repository_stars,
        report=static,
        candidates=tuple(candidates),
        checkout=checkout,
        elapsed_s=round(time.monotonic() - started, 1),
    )


def _candidate_summary(finding: dict[str, Any]) -> dict[str, Any]:
    """Bounded evidence sent to Claude for ordering, never for a verdict."""
    return {
        key: finding.get(key)
        for key in (
            "fingerprint",
            "severity",
            "title",
            "description",
            "file",
            "line",
            "source",
            "sink",
            "route",
        )
        if finding.get(key) is not None
    }


def _first_json(value: str) -> Any:
    """Decode the first JSON value while tolerating CLI notices or model epilogues."""
    decoder = json.JSONDecoder()
    stripped = value.strip()
    try:
        decoded, _end = decoder.raw_decode(stripped)
        return decoded
    except json.JSONDecodeError as initial_error:
        for index, character in enumerate(stripped):
            if character not in "[{":
                continue
            try:
                decoded, _end = decoder.raw_decode(stripped, index)
                return decoded
            except json.JSONDecodeError:
                continue
        raise initial_error


def _decode_claude(stdout: str) -> Any:
    envelope = _first_json(stdout)
    payload = envelope.get("result", envelope) if isinstance(envelope, dict) else envelope
    if isinstance(payload, str):
        value = payload.strip()
        if value.startswith("```json") and value.endswith("```"):
            value = value[7:-3].strip()
        payload = _first_json(value)
    return payload


def claude_environment() -> dict[str, str]:
    """Prefer the operator's authenticated Claude account over injected API billing."""
    environment = os.environ.copy()
    environment.pop("ANTHROPIC_API_KEY", None)
    environment.pop("ANTHROPIC_AUTH_TOKEN", None)
    return environment


def claude_rank(
    result: StaticResult,
    *,
    args: argparse.Namespace,
    run_dir: Path,
) -> tuple[dict[str, Any], ...]:
    """Use one bounded Claude call to prioritize candidates; it cannot mark proof."""
    candidates = list(result.candidates[: args.ai_candidates])
    if not candidates or args.ai_attempts < 1:
        return tuple(candidates[: args.max_candidates])
    prompt = {
        "repository": result.repository,
        "revision": result.revision,
        "task": (
            "Rank these static JavaScript taint findings by likelihood that an anonymous "
            "or low-privilege attacker can reproduce meaningful impact against a locally "
            "started disposable copy. Return JSON only as "
            "{\"fingerprints\":[\"...\"]}. Do not claim a vulnerability is verified."
        ),
        "candidates": [_candidate_summary(item) for item in candidates],
    }
    command = [
        "claude",
        "-p",
        "--model",
        args.ai_model,
        "--output-format",
        "json",
        "--tools",
        "",
        "--allowedTools",
        "",
        "--permission-mode",
        "dontAsk",
        "--setting-sources",
        "",
        "--strict-mcp-config",
        "--disable-slash-commands",
        "--no-session-persistence",
    ]
    log(f"CLAUDE_RANK {result.repository} candidates={len(candidates)}")
    try:
        while True:
            if not CLAUDE_USAGE_GATE.wait(SHUTDOWN):
                raise RuntimeError("online run interrupted")
            completed = run(
                command,
                input_text=json.dumps(prompt),
                capture=True,
                timeout=args.ai_timeout,
                environment=claude_environment(),
            )
            if not completed.returncode:
                break
            limited = usage_limit_message(completed.stdout, completed.stderr)
            if not limited:
                raise RuntimeError(
                    completed.stderr.strip() or "Claude exited unsuccessfully"
                )
            deadline, changed = CLAUDE_USAGE_GATE.pause(limited)
            if changed:
                log(f"CLAUDE_PAUSED until={deadline.isoformat(timespec='minutes')}")
                emit_event(
                    "ai_paused",
                    repository=result.repository,
                    message=f"Claude capacity resumes at {deadline.isoformat(timespec='minutes')}",
                )
        payload = _decode_claude(completed.stdout)
        fingerprints = payload.get("fingerprints") if isinstance(payload, dict) else None
        if not isinstance(fingerprints, list):
            raise ValueError("Claude returned no fingerprint list")
        by_fingerprint = {item["fingerprint"]: item for item in candidates}
        ordered = []
        seen = set()
        for fingerprint in fingerprints:
            if fingerprint in by_fingerprint and fingerprint not in seen:
                ordered.append(by_fingerprint[fingerprint])
                seen.add(fingerprint)
        ordered.extend(
            item for item in candidates if item["fingerprint"] not in seen
        )
        artifact = run_dir / "claude" / f"{result.repository.replace('/', '__')}.json"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(
            json.dumps(
                {
                    "repository": result.repository,
                    "revision": result.revision,
                    "ranking": [item["fingerprint"] for item in ordered],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return tuple(ordered[: args.max_candidates])
    except (
        OSError,
        subprocess.TimeoutExpired,
        RuntimeError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        log(f"CLAUDE_RANK_FAILED {result.repository}: {error}; deterministic fallback")
        return tuple(candidates[: args.max_candidates])


def fix_learning_flag() -> str:
    """Publish anonymous recipes when a source checkout can evolve itself."""
    return (
        "--publish-fixes"
        if os.environ.get("JSSPECTOR_PUBLISH_FIXES")
        else "--learn-fixes"
    )


def verify_repository(
    static: StaticResult,
    *,
    candidates: tuple[dict[str, Any], ...],
    args: argparse.Namespace,
    scanner: Path,
    run_dir: Path,
    lane: str,
    docker_slots: resources.AdjustableSlots | threading.Semaphore,
    run_label: str,
) -> ResearchResult:
    """Require strict Docker proof for the selected candidate ordering."""
    started = time.monotonic()
    repository = static.repository
    revision = static.revision
    if not candidates or not revision:
        return ResearchResult(
            repository=repository,
            revision=revision,
            security_advisories=static.security_advisories,
            repository_forks=static.repository_forks,
            repository_stars=static.repository_stars,
            elapsed_s=round(time.monotonic() - started, 1),
        )
    if static.checkout is None or not static.checkout.is_dir():
        return ResearchResult(
            repository=repository,
            revision=revision,
            security_advisories=static.security_advisories,
            repository_forks=static.repository_forks,
            repository_stars=static.repository_stars,
            failed=True,
            failure_reason="checkout-missing",
            elapsed_s=round(time.monotonic() - started, 1),
        )
    slug = repository.replace("/", "__")
    startup_timeout = getattr(args, "verify_startup_timeout", 180)
    candidate_soft_timeout = getattr(args, "verify_candidate_soft_timeout", 180)
    candidate_hard_timeout = getattr(args, "verify_candidate_hard_timeout", 300)
    extended_timeout = getattr(args, "verify_extended_timeout", 1800)
    verified_path = run_dir / "reports" / f"{slug}.{lane}.verified.json"
    emit_event(
        "verification_started",
        repository=repository,
        lane=lane,
        candidates=len(candidates),
    )

    pinned = f"{repository}@{revision}"
    command = [
        str(scanner),
        "scan",
        str(static.checkout),
        "--verify=strict",
        "--verify-until-first",
        "--format",
        "json",
        "--output",
        str(verified_path),
        "--min-severity",
        "high",
        "--allow-incomplete",
        "--no-config",
        "--no-inline-ignores",
        "--threads",
        str(args.verify_threads),
    ]
    fix_attempts = getattr(args, "fix_attempts", 0)
    if fix_attempts > 0:
        command.extend(
            (
                "--fix-attempts",
                str(fix_attempts),
                "--fix-timeout",
                str(args.fix_timeout),
                "--fix-model",
                args.fix_model,
            )
        )
        if args.learn_fixes:
            command.append(fix_learning_flag())
    else:
        command.append("--no-fix")
    for finding in candidates:
        command.extend(("--verify-fingerprint", finding["fingerprint"]))
    docker_label = verification_run_label(run_label, repository, revision, lane)
    cleanup_artifact = run_dir / "logs" / f"{slug}.{lane}.docker-cleanup.json"
    log(
        f"VERIFY lane={lane} {pinned} candidates={len(candidates)} "
        f"startup_budget={startup_timeout}s "
        f"candidate_soft_budget={candidate_soft_timeout}s "
        f"candidate_hard_budget={candidate_hard_timeout}s "
        f"exploit_budget={args.verify_timeout}s "
        f"extended_budget={extended_timeout}s fix_budget="
        f"{args.fix_timeout if fix_attempts > 0 else 0}s"
    )
    budgets = VerificationBudgetState(
        started=time.monotonic(),
        startup_s=startup_timeout,
        candidate_soft_s=candidate_soft_timeout,
        candidate_hard_s=candidate_hard_timeout,
        normal_s=args.verify_timeout,
        extended_s=extended_timeout,
        fix_s=args.fix_timeout,
    )
    with docker_slots:
        slot_started = time.monotonic()
        budgets.started = slot_started
        try:
            result = run_verification(
                command,
                log_path=run_dir / "logs" / f"{slug}.{lane}.verify.log",
                environment={
                    **os.environ,
                    "JSS_VERIFY_RUN_LABEL": docker_label,
                    "JSS_VERIFY_PROGRESS": "1",
                    # Research reports keep the exact verifier streams while this campaign is
                    # being calibrated. Command/header credential redaction remains enabled in
                    # JSSpector; operators can restore output redaction with
                    # JSS_REPORT_RAW_OUTPUT=0 without changing code.
                    "JSS_REPORT_RAW_OUTPUT": os.environ.get(
                        "JSS_REPORT_RAW_OUTPUT", "1"
                    ),
                },
                budgets=budgets,
                repository=repository,
            )
        finally:
            phases = budgets.close(time.monotonic())
            docker_cleanup = cleanup_owned_docker_resources(
                docker_label,
                artifact=cleanup_artifact,
            )
    slot_s = round(time.monotonic() - slot_started, 1)
    docker_cleanup_failures = len(docker_cleanup["failures"])
    if result.returncode:
        if result.returncode == 130 or SHUTDOWN.is_set():
            return ResearchResult(
                repository=repository,
                revision=revision,
                security_advisories=static.security_advisories,
                repository_forks=static.repository_forks,
                repository_stars=static.repository_stars,
                docker_cleanup_failures=docker_cleanup_failures,
                cancelled=True,
                elapsed_s=round(time.monotonic() - started, 1),
                slot_s=slot_s,
                phases=phases,
            )
        log(f"VERIFY_FAILED {pinned} exit={result.returncode}")
        reason = (
            result.stderr
            if result.returncode == 124 and isinstance(result.stderr, str)
            else "verify-failed"
        )
        return ResearchResult(
            repository=repository,
            revision=revision,
            security_advisories=static.security_advisories,
            repository_forks=static.repository_forks,
            repository_stars=static.repository_stars,
            failed=True,
            failure_reason=reason,
            docker_cleanup_failures=docker_cleanup_failures,
            elapsed_s=round(time.monotonic() - started, 1),
            slot_s=slot_s,
            phases=phases,
        )

    report = read_json(verified_path)
    verified = verified_findings(report)
    if not verified:
        driven, skip_reason = unverified_kind(report, candidates)
        log(f"NO_VERIFIED_EXPLOIT {pinned} driven={driven}")
        return ResearchResult(
            repository=repository,
            revision=revision,
            security_advisories=static.security_advisories,
            repository_forks=static.repository_forks,
            repository_stars=static.repository_stars,
            docker_cleanup_failures=docker_cleanup_failures,
            elapsed_s=round(time.monotonic() - started, 1),
            slot_s=slot_s,
            phases=phases,
            driven=driven,
            skip_reason=skip_reason,
        )
    log(f"VERIFIED_EXPLOIT {pinned} count={len(verified)}")
    fix_attempted = fix_attempts > 0
    fix_proven = any(
        isinstance(finding.get("fix"), dict)
        and finding["fix"].get("outcome") == "proven"
        for finding in verified
    )
    if fix_attempted:
        log(f"FIX_ATTEMPTED {pinned} proven={str(fix_proven).lower()} single_pass=true")
    return ResearchResult(
        repository=repository,
        revision=revision,
        security_advisories=static.security_advisories,
        repository_forks=static.repository_forks,
        repository_stars=static.repository_stars,
        report=report,
        findings=tuple(verified),
        fix_attempted=fix_attempted,
        fix_proven=fix_proven,
        docker_cleanup_failures=docker_cleanup_failures,
        elapsed_s=round(time.monotonic() - started, 1),
        slot_s=slot_s,
        phases=phases,
    )


def synchronize(
    result: ResearchResult,
    *,
    satori_cli: str,
    state: dict[str, Any],
    state_path: Path,
    state_lock: threading.Lock,
) -> bool:
    """Create one private Satori execution and expose its verified issues for reporting."""
    if result.report is None or result.revision is None or not result.findings:
        return True
    key = sync_key(result.repository, result.revision, result.findings)
    with state_lock:
        synced_state = state["synced"].get(key)
        if (
            isinstance(synced_state, dict)
            and synced_state.get("confirmed_status") == "TP"
        ):
            log(f"ALREADY_SYNCED {result.repository}@{result.revision}")
            emit_event(
                "sync_finished",
                repository=result.repository,
                success=True,
                duplicate=True,
                findings=len(result.findings),
            )
            return True

    report = filtered_report(result.report)
    report["security_advisories"] = result.security_advisories
    if not report["findings"]:
        raise RuntimeError(
            "verified-only synchronization received no verified findings"
        )
    try:
        existing = satori_reports_for_key(satori_cli, key)
    except RuntimeError as error:
        log(f"SYNC_LOOKUP_FAILED {result.repository}@{result.revision}: {error}")
        emit_event("sync_finished", repository=result.repository, success=False)
        return False

    if not existing:
        with tempfile.TemporaryDirectory(prefix="jsspector-verified-sync-") as temporary:
            stage = Path(temporary)
            # Satori keys structured-output parsing to the command that produced the bytes. Replay
            # the already-proven report through a tiny command named ``jsspector`` rather than
            # ``cat`` directly, so it is ingested exactly like ``jsspector scan --format json``
            # without re-running or weakening verification.
            replay = stage / "jsspector"
            replay.write_text(
                "#!/bin/sh\n"
                f"exec cat -- {shlex.quote(str(stage / 'report.json'))}\n",
                encoding="utf-8",
            )
            replay.chmod(0o700)
            replay_command = f"{shlex.quote(str(replay))} scan --format json ."
            (stage / ".satori.yml").write_text(
                "settings:\n"
                "  name: JSSpector verified exploit\n"
                "test:\n"
                "  run:\n"
                f"    - {json.dumps(replay_command)}\n",
                encoding="utf-8",
            )
            (stage / "report.json").write_text(
                json.dumps(report, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            command = [
                satori_cli,
                "--json",
                "local",
                str(stage),
                "--repo",
                result.repository,
                "--visibility",
                "private",
                "--tag",
                "campaign",
                "verified_research",
                "--tag",
                "repo",
                result.repository,
                "--tag",
                "revision",
                result.revision,
                "--tag",
                "security_advisories",
                result.security_advisories,
                "--tag",
                "repository_forks",
                str(result.repository_forks),
                "--tag",
                "repository_stars",
                str(result.repository_stars),
                "--tag",
                "sync_key",
                key,
                "--sync",
            ]
            synced = run(command, capture=True)
        if synced.returncode:
            log(
                f"SYNC_FAILED {result.repository}@{result.revision} "
                f"exit={synced.returncode}"
            )
            emit_event("sync_finished", repository=result.repository, success=False)
            return False
    else:
        log(f"SYNC_RESUME {result.repository}@{result.revision}")

    materialized = wait_for_satori_issues(
        satori_cli,
        key,
        repository=result.repository,
        expected=len(result.findings),
    )
    if materialized is None:
        log(f"SYNC_ISSUES_TIMEOUT {result.repository}@{result.revision}")
        emit_event("sync_finished", repository=result.repository, success=False)
        return False
    execution_id, issues = materialized

    try:
        confirmed = confirm_satori_issues_true_positive(
            satori_cli,
            execution_id,
            issues,
            repository=result.repository,
        )
    except RuntimeError as error:
        log(f"SYNC_CONFIRM_FAILED {result.repository}@{result.revision}: {error}")
        emit_event("sync_finished", repository=result.repository, success=False)
        return False
    if not confirmed:
        log(f"SYNC_CONFIRM_TIMEOUT {result.repository}@{result.revision}")
        emit_event("sync_finished", repository=result.repository, success=False)
        return False

    with state_lock:
        state["synced"][key] = {
            "repository": result.repository,
            "revision": result.revision,
            "fingerprints": sorted(
                finding["fingerprint"] for finding in result.findings
            ),
            "execution_id": execution_id,
            "synced_at": datetime.now(UTC).isoformat(),
            "confirmed_status": "TP",
            "confirmed_at": datetime.now(UTC).isoformat(),
        }
        write_json(state_path, state)
    log(
        f"SYNCED_PRIVATE {result.repository}@{result.revision} "
        f"verified={len(result.findings)}"
    )
    emit_event(
        "sync_finished",
        repository=result.repository,
        success=True,
        findings=len(result.findings),
    )
    return True


def _satori_json(command: list[str]) -> dict[str, Any]:
    """Run one read-only Satori query and decode its JSON envelope."""
    completed = run(command, capture=True, echo_capture=False)
    if completed.returncode:
        raise RuntimeError(f"Satori query exited {completed.returncode}")
    try:
        payload = _first_json(completed.stdout or "")
    except (json.JSONDecodeError, ValueError) as error:
        raise RuntimeError("Satori query returned no JSON") from error
    if not isinstance(payload, dict):
        raise RuntimeError("Satori query returned a non-object JSON value")
    return payload


def satori_reports_for_key(satori_cli: str, key: str) -> list[dict[str, Any]]:
    """Find the external idempotency marker before creating another execution."""
    payload = _satori_json(
        [
            satori_cli,
            "--json",
            "reports",
            "search",
            "--tag",
            f"sync_key:{key}",
            "--quantity",
            "10",
        ]
    )
    items = payload.get("items")
    if not isinstance(items, list):
        raise RuntimeError("Satori report search returned no items array")
    return [item for item in items if isinstance(item, dict)]


def satori_issues(satori_cli: str, execution_id: str) -> list[dict[str, Any]]:
    """Read the findings materialized for one synchronized execution."""
    payload = _satori_json(
        [
            satori_cli,
            "--json",
            "issues",
            execution_id,
            "--quantity",
            "100",
        ]
    )
    items = payload.get("items")
    if not isinstance(items, list):
        raise RuntimeError("Satori issues query returned no items array")
    return [item for item in items if isinstance(item, dict)]


def wait_for_satori_issues(
    satori_cli: str,
    key: str,
    *,
    repository: str,
    expected: int,
    timeout_s: int = 120,
) -> tuple[str, list[dict[str, Any]]] | None:
    """Wait until Satori has materialized every verified finding as exploitable."""
    deadline = time.monotonic() + timeout_s
    while not SHUTDOWN.is_set() and time.monotonic() < deadline:
        try:
            reports = satori_reports_for_key(satori_cli, key)
            for report in reports:
                execution_id = report.get("id")
                if not isinstance(execution_id, str):
                    continue
                issues = satori_issues(satori_cli, execution_id)
                if len(issues) != expected:
                    continue
                if all(
                    issue.get("source") == "TOOL"
                    and issue.get("exploitability") == "EXPLOITABLE"
                    and issue.get("repository") == repository
                    for issue in issues
                ):
                    return execution_id, issues
        except RuntimeError as error:
            log(f"SYNC_ISSUES_PENDING {repository}: {error}")
        SHUTDOWN.wait(2)
    return None


def confirm_satori_issues_true_positive(
    satori_cli: str,
    execution_id: str,
    issues: list[dict[str, Any]],
    *,
    repository: str,
    timeout_s: int = 30,
) -> bool:
    """Promote verified online findings to TP and confirm they are reportable.

    The dashboard's ``/issues`` inbox intentionally defaults to true positives.
    Online verification already proved exploitation, so leaving these findings in
    the ingestion default ``OPEN`` state makes a successfully synchronized issue
    invisible.  The mutation is idempotent and is confirmed with a fresh read
    before the synchronization is recorded as complete.
    """
    finding_ids: set[str] = set()
    for issue in issues:
        finding_id = issue.get("id")
        if not isinstance(finding_id, str) or not finding_id:
            raise RuntimeError("materialized Satori issue has no finding id")
        if (
            issue.get("source") != "TOOL"
            or issue.get("exploitability") != "EXPLOITABLE"
            or issue.get("repository") != repository
        ):
            raise RuntimeError("materialized Satori issue failed the verified gate")
        finding_ids.add(finding_id)
        if issue.get("status") == "TP":
            continue
        promoted = run(
            [
                satori_cli,
                "issue",
                finding_id,
                "status",
                "TP",
            ],
            capture=True,
            echo_capture=False,
        )
        if promoted.returncode:
            raise RuntimeError(
                f"Satori status update for {finding_id} exited {promoted.returncode}"
            )

    deadline = time.monotonic() + timeout_s
    while not SHUTDOWN.is_set() and time.monotonic() < deadline:
        current = satori_issues(satori_cli, execution_id)
        confirmed_ids = {
            issue.get("id")
            for issue in current
            if issue.get("status") == "TP"
            and issue.get("source") == "TOOL"
            and issue.get("exploitability") == "EXPLOITABLE"
            and issue.get("repository") == repository
        }
        if confirmed_ids == finding_ids:
            return True
        SHUTDOWN.wait(1)
    return False


def parse_duration(value: str) -> int:
    """Parse a compact discovery lookback such as 45m, 24h or 7d."""
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    normalized = value.strip().lower()
    unit = normalized[-1:] if normalized[-1:] in units else "s"
    number = normalized[:-1] if normalized[-1:] in units else normalized
    try:
        seconds = int(number) * units[unit]
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            f"bad duration {value!r}; use e.g. 24h"
        ) from error
    if seconds <= 0:
        raise argparse.ArgumentTypeError("duration must be positive")
    return seconds


def positive(value: str) -> int:
    """Argparse type for bounded worker and attempt counts."""
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected a positive integer") from error
    if number < 1:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return number


def utilization(value: str) -> float:
    """Argparse type for a whole-host utilization target."""
    try:
        number = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected a fraction such as 0.8") from error
    if not 0.1 <= number <= 0.95:
        raise argparse.ArgumentTypeError("expected a fraction between 0.1 and 0.95")
    return number


def non_negative(value: str) -> int:
    """Argparse type for optional attempts where zero disables the step."""
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected a non-negative integer") from error
    if number < 0:
        raise argparse.ArgumentTypeError("expected a non-negative integer")
    return number


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Verified-only online controller command line."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since", type=parse_duration, default=DEFAULT_SINCE_SECONDS)
    parser.add_argument(
        "--min-forks",
        type=int,
        default=0,
        help="minimum fork count; 0 includes repositories with no forks (default: 0)",
    )
    parser.add_argument(
        "--limit", type=int, default=0, help="0 scans every discovered repo"
    )
    parser.add_argument(
        "--max-repo-size-mb",
        type=positive,
        default=100,
        help="skip repositories larger than this GitHub size (default: 100 MiB)",
    )
    parser.add_argument("--language", default="JavaScript")
    parser.add_argument("--pvr", choices=discover.PVR_MODES, default="off")
    parser.add_argument(
        "--all-candidates",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="include every zero-star repository, for both users and organizations",
    )
    parser.add_argument(
        "--repos-file",
        type=Path,
        help="use this deterministic owner/repo inventory instead of GitHub Search",
    )
    parser.add_argument("--pvr-parallel", type=positive, default=8)
    parser.add_argument(
        "--static-parallel",
        type=positive,
        default=None,
        help="concurrent one-thread static scans (default: auto, at least 12)",
    )
    parser.add_argument(
        "--max-checkouts",
        type=positive,
        default=None,
        help=(
            "maximum run-owned repository checkouts retained across static analysis "
            "and verification (default: auto, at least 24)"
        ),
    )
    parser.add_argument(
        "--parallel-no-ai",
        type=positive,
        default=None,
        help="deterministic verification workers (default: auto, Docker slots minus the AI lane)",
    )
    parser.add_argument("--parallel-ai", type=positive, default=2)
    parser.add_argument(
        "--parallel-docker",
        type=positive,
        default=None,
        help=(
            "global Docker verification cap shared by both lanes (default: auto, sized "
            "from this host's free CPU and memory)"
        ),
    )
    parser.add_argument(
        "--target-utilization",
        type=utilization,
        default=resources.DEFAULT_TARGET,
        help="whole-host CPU and memory share auto-sizing aims for (default: 0.8)",
    )
    parser.add_argument(
        "--no-governor",
        action="store_true",
        help="keep auto-sized worker counts fixed instead of adjusting them to the target",
    )
    parser.add_argument(
        "--estimate",
        action="store_true",
        help="print the concurrency this host supports and exit without running a pass",
    )
    parser.add_argument(
        "--calibrate",
        action="store_true",
        help=(
            "measure verification cost on this host with a local, fix-free, deterministic "
            "pass and save the host profile"
        ),
    )
    parser.add_argument(
        "--calibrate-minutes",
        type=positive,
        default=30,
        help="measured calibration window after the first verification starts (default: 30)",
    )
    parser.add_argument(
        "--profile",
        type=Path,
        default=None,
        help="host profile written by --calibrate (default: ~/.config/jsspector/online-profile.json)",
    )
    parser.add_argument(
        "--min-free-gb",
        type=non_negative,
        default=100,
        help="stop safely if Docker GC cannot preserve this much host disk (default: 100)",
    )
    parser.add_argument(
        "--docker-cache-gb",
        type=positive,
        default=20,
        help="maximum BuildKit cache retained by online GC (default: 20)",
    )
    parser.add_argument(
        "--docker-gc-every",
        type=positive,
        default=8,
        help="run Docker storage GC after this many verifications (default: 8)",
    )
    parser.add_argument("--scan-threads", type=positive, default=1)
    parser.add_argument("--verify-threads", type=positive, default=2)
    parser.add_argument(
        "--clone-timeout",
        type=positive,
        default=120,
        help="deadline for the one reusable shallow checkout per repository (default: 120s)",
    )
    parser.add_argument("--static-timeout", type=positive, default=600)
    parser.add_argument(
        "--verify-startup-timeout",
        type=positive,
        default=180,
        help="build/start ceiling for one selected candidate (default: 180s)",
    )
    parser.add_argument(
        "--verify-candidate-soft-timeout",
        type=positive,
        default=180,
        help="idle candidate decision point (default: 180s)",
    )
    parser.add_argument(
        "--verify-candidate-hard-timeout",
        type=positive,
        default=300,
        help="candidate ceiling after real request activity (default: 300s)",
    )
    parser.add_argument(
        "--verify-timeout",
        type=positive,
        default=900,
        help="normal wall-clock exploitation budget per repository (default: 900s)",
    )
    parser.add_argument(
        "--verify-extended-timeout",
        type=positive,
        default=1800,
        help="repository budget after positive evidence (default: 1800s)",
    )
    parser.add_argument("--max-candidates", type=positive, default=5)
    parser.add_argument("--ai-candidates", type=positive, default=20)
    parser.add_argument(
        "--ai-attempts",
        type=positive,
        default=1,
        help="bounded Claude ranking attempts per AI-lane repository (default: 1)",
    )
    parser.add_argument("--ai-model", default="claude-opus-5-5")
    parser.add_argument("--ai-timeout", type=positive, default=60)
    parser.add_argument(
        "--fix-attempts",
        type=non_negative,
        default=0,
        help="best-effort Opus fix attempts after proof; 0 disables fixing",
    )
    parser.add_argument(
        "--fix-timeout",
        type=positive,
        default=600,
        help="LLM fix budget after verified exploitation (default: 600s)",
    )
    parser.add_argument("--fix-model", default="claude-opus-5-5")
    parser.add_argument(
        "--learn-fixes",
        action="store_true",
        help="record only dynamically proven fixes in JSSpector's local recipe corpus",
    )
    parser.add_argument("--scanner", type=Path, default=DEFAULT_SCANNER)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--satori-cli", default="satori-v2")
    parser.add_argument("--satori-profile", default="satoridev05")
    parser.add_argument(
        "--satori-sync",
        action="store_true",
        help="create private Satori reports for verified exploits only",
    )
    args = parser.parse_args(argv)
    if args.min_forks < 0:
        parser.error("--min-forks must be non-negative")
    if args.limit < 0:
        parser.error("--limit must be non-negative")
    if args.verify_candidate_hard_timeout < args.verify_candidate_soft_timeout:
        parser.error("--verify-candidate-hard-timeout must be at least the soft timeout")
    if args.verify_extended_timeout < args.verify_timeout:
        parser.error("--verify-extended-timeout must be at least --verify-timeout")
    if args.estimate and args.calibrate:
        parser.error("--estimate and --calibrate are mutually exclusive")
    # A calibration measures hardware: it never publishes, fixes or spends Opus usage.
    args.ai_lane = not args.calibrate
    if args.calibrate:
        args.satori_sync = False
        args.fix_attempts = 0
        args.learn_fixes = False
    return args


def candidates_from_file(
    path: Path,
    *,
    args: argparse.Namespace,
    state: dict[str, Any],
    remote_blacklist: frozenset[str],
    run_dir: Path,
    on_found: Callable[[discover.Candidate], None] | None = None,
) -> tuple[list[discover.Candidate], dict[str, Any]]:
    """Load a stable inventory and apply the requested PVR policy once."""
    inventory = path.expanduser().resolve()
    if not inventory.is_file():
        raise SystemExit(f"repository inventory not found: {inventory}")
    repositories = []
    seen = set()
    completed = {
        repository.casefold()
        for repository in completed_repositories(state) | remote_blacklist
    }
    for line in inventory.read_text(encoding="utf-8").splitlines():
        repository = line.strip()
        if not repository or repository.startswith("#") or repository in seen:
            continue
        seen.add(repository)
        if repository.casefold() not in completed:
            repositories.append(repository)
    pool = github_pool()
    wanted: list[discover.Candidate] = []
    rejected = []
    pvr_errors = []
    pvr_workers = min(args.pvr_parallel, pool.recommended_parallelism)
    batch_size = max(64, pvr_workers * 8)
    pvr_executor = ThreadPoolExecutor(max_workers=pvr_workers)
    oversized = []
    try:
        for offset in range(0, len(repositories), batch_size):
            if args.limit and len(wanted) >= args.limit:
                break
            batch = repositories[offset:offset + batch_size]
            metadata = list(pvr_executor.map(pool.repository, batch))
            statuses = (
                [None] * len(batch)
                if args.pvr == "any"
                else list(pvr_executor.map(pool.has_pvr, batch))
            )
            for repository, info, enabled in zip(batch, metadata, statuses, strict=True):
                if args.limit and len(wanted) >= args.limit:
                    break
                if info is None:
                    pvr_errors.append(repository)
                    continue
                size_kb = int(info.get("size") or 0)
                if size_kb > args.max_repo_size_mb * 1024:
                    oversized.append(repository)
                    continue
                if args.pvr == "any":
                    keep = True
                    advisory_state = "unknown"
                elif enabled is None:
                    pvr_errors.append(repository)
                    continue
                else:
                    keep = enabled if args.pvr == "on" else not enabled
                    advisory_state = "enabled" if enabled else "disabled"
                if keep:
                    candidate = discover.Candidate(
                        repo=repository,
                        stars=int(info.get("stargazers_count") or 0),
                        forks=int(info.get("forks_count") or 0),
                        size_kb=size_kb,
                        security_advisories=advisory_state,
                    )
                    wanted.append(candidate)
                    if on_found is not None:
                        on_found(candidate)
                else:
                    rejected.append(repository)
                emit_event(
                    "discovery_progress",
                    repository=repository,
                    found=len(wanted),
                    checked=len(wanted) + len(rejected) + len(pvr_errors),
                )
    finally:
        pvr_executor.shutdown()
    (run_dir / "repos.txt").write_text(
        "".join(f"{candidate.repo}\n" for candidate in wanted), encoding="utf-8"
    )
    (run_dir / "checked.txt").write_text(
        "".join(f"{repository}\n" for repository in rejected), encoding="utf-8"
    )
    (run_dir / "pvr-errors.txt").write_text(
        "".join(f"{repository}\n" for repository in pvr_errors), encoding="utf-8"
    )
    (run_dir / "oversized.txt").write_text(
        "".join(f"{repository}\n" for repository in oversized), encoding="utf-8"
    )
    return (
        wanted,
        {
            "source": str(inventory),
            "source_total": len(repositories),
            "inventory": len(wanted) + len(rejected) + len(pvr_errors),
            "found": len(wanted),
            "pvr_filtered": len(rejected),
            "pvr_errors": len(pvr_errors),
            "oversized": len(oversized),
        },
    )


def discover_candidates(
    *,
    args: argparse.Namespace,
    state: dict[str, Any],
    remote_blacklist: frozenset[str],
    run_dir: Path,
    on_found: Callable[[discover.Candidate], None] | None = None,
) -> tuple[list[discover.Candidate], dict[str, Any]]:
    """Use the existing exhaustive, time-windowed GitHub discovery engine."""
    def progress(message: str) -> None:
        log(f"DISCOVERY {message}")
        emit_event("discovery_status", message=message)

    pool = github_pool(on_status=progress)
    cfg = discover.Config(
        language=args.language,
        limit=args.limit,
        min_forks=args.min_forks,
        max_repo_size_kb=args.max_repo_size_mb * 1024,
        since_seconds=args.since,
        all_candidates=args.all_candidates,
        pvr_mode=args.pvr,
        pvr_parallel=args.pvr_parallel,
        out=run_dir,
        exclude=completed_repositories(state) | remote_blacklist,
        should_stop=SHUTDOWN.is_set,
        on_progress=progress,
    )
    discovery = discover.Discovery(pool, cfg)
    candidates: list[discover.Candidate] = []

    def found(candidate: discover.Candidate) -> None:
        candidates.append(candidate)
        if on_found is not None:
            on_found(candidate)
        emit_event(
            "discovery_progress",
            repository=candidate.repo,
            found=len(candidates),
        )

    metrics = discovery.run(on_found=found)
    return candidates, metrics


def choose_lane(index: int, args: argparse.Namespace) -> str:
    """Stable weighted assignment independent of completion timing."""
    if not getattr(args, "ai_lane", True):
        return "no-ai"
    workers = args.parallel_no_ai + args.parallel_ai
    return "no-ai" if index % workers < args.parallel_no_ai else "ai"


@dataclass(frozen=True)
class Capacity:
    """How this pass was sized, and how it adapts while it runs."""

    host: resources.Host
    costs: resources.Costs
    plan: resources.Plan
    governed: bool
    calibration: resources.Calibration | None
    profile_path: Path
    notes: tuple[str, ...]


def plan_capacity(args: argparse.Namespace, out: Path) -> Capacity:
    """Resolve every auto-sized worker count in place from the resources free right now.

    Costs come from this host's calibration profile when one matches the hardware, else from the
    built-in model. Explicit counts are kept; the governor only runs when the Docker and
    deterministic counts are both automatic, so an operator's fixed numbers stay fixed.
    """
    host = resources.probe_host(out)
    profile_path = (args.profile or resources.default_profile_path()).expanduser()
    costs, note = resources.load_profile(profile_path, host)
    notes = (note,) if note else ()
    costs = costs or resources.Costs()
    plan = resources.estimate(
        host,
        costs,
        target=args.target_utilization,
        parallel_ai=args.parallel_ai,
        ai_lane=args.ai_lane,
        static_parallel=args.static_parallel,
        max_checkouts=args.max_checkouts,
        parallel_no_ai=args.parallel_no_ai,
        parallel_docker=args.parallel_docker,
        max_repo_size_mb=args.max_repo_size_mb,
    )
    calibration = None
    if args.calibrate:
        high = plan.parallel_docker
        low = max(1, round(high / 2))
        high = max(high, low + resources.MIN_FIT_SPREAD)
        calibration = resources.Calibration(
            low=low, high=high, window_s=args.calibrate_minutes * 60.0
        )
        # Size the pools for the high level; the monitor starts the slots at the low one.
        plan = replace(
            plan,
            parallel_docker=high,
            parallel_no_ai=high,
            docker_ceiling=max(plan.docker_ceiling, high),
            max_checkouts=max(
                plan.max_checkouts,
                plan.static_parallel + resources.QUEUE_PER_SLOT * high,
            ),
        )
    governed = bool(
        not args.no_governor
        and calibration is None
        and args.parallel_docker is None
        and args.parallel_no_ai is None
    )
    args.static_parallel = plan.static_parallel
    args.max_checkouts = plan.max_checkouts
    args.parallel_no_ai = plan.parallel_no_ai
    args.parallel_docker = plan.parallel_docker
    return Capacity(
        host=host,
        costs=costs,
        plan=plan,
        governed=governed,
        calibration=calibration,
        profile_path=profile_path,
        notes=notes,
    )


def main(argv: list[str] | None = None) -> int:
    """Discover, scan, and run separate deterministic and Claude-ranked lanes."""
    global LOG_PATH
    SHUTDOWN.clear()
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGINT, request_shutdown)
        signal.signal(signal.SIGTERM, request_shutdown)
    args = parse_args(argv)
    os.environ["SATORI_PROFILE"] = args.satori_profile
    scanner = args.scanner.expanduser().resolve()
    if not scanner.is_file():
        raise SystemExit(
            f"scanner not found: {scanner}; build JSSpector or set JSSPECTOR_BINARY"
        )
    capacity = plan_capacity(args, args.out.expanduser().resolve())
    if args.estimate:
        for note in capacity.notes:
            print(f"jsspector: {note}", file=sys.stderr)
        print(
            resources.render_plan(
                capacity.host,
                capacity.costs,
                capacity.plan,
                target=args.target_utilization,
                governed=capacity.governed,
                ai_lane=args.ai_lane,
            ),
            flush=True,
        )
        return 0
    if args.satori_sync:
        satori_cli = shutil.which(args.satori_cli)
        if satori_cli is None:
            raise SystemExit(f"Satori CLI not found: {args.satori_cli}")
        auth = subprocess.run(
            [satori_cli, "whoami"],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if auth.returncode:
            raise SystemExit("Satori CLI is not authenticated")
    else:
        satori_cli = args.satori_cli

    out = args.out.expanduser().resolve()
    _run_lock = acquire_run_lock(out)
    state_path = out / "state.json"
    state = read_state(state_path)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    run_label = f"online_{stamp}_{os.getpid()}"
    run_dir = out / "runs" / stamp
    run_dir.mkdir(parents=True, exist_ok=False)
    if args.calibrate:
        state_path = run_dir / "state.json"
        state = read_state(state_path)
    LOG_PATH = run_dir / "online.log"
    for note in capacity.notes:
        log(f"CAPACITY_NOTE {note}")
    plan = capacity.plan
    log(
        f"CAPACITY host={capacity.host.cpu_model!r} cpus={capacity.host.logical_cpus} "
        f"capacity={capacity.host.capacity_cpus:g} busy={capacity.host.busy_cpus:g} "
        f"memory_gib={capacity.host.mem_total_gib:g} "
        f"available_gib={capacity.host.mem_available_gib:g} docker={capacity.host.docker} "
        f"costs={capacity.costs.source!r} target={args.target_utilization:g} "
        f"docker_slots={plan.parallel_docker} floor={plan.docker_floor} "
        f"ceiling={plan.docker_ceiling} limited_by={plan.limited_by} "
        f"governed={capacity.governed} calibrate={args.calibrate}"
    )
    write_json(
        run_dir / "capacity.json",
        {
            "host": asdict(capacity.host),
            "costs": asdict(capacity.costs),
            "plan": asdict(plan),
            "target": args.target_utilization,
            "governed": capacity.governed,
            "calibration": (
                {
                    "low": capacity.calibration.low,
                    "high": capacity.calibration.high,
                    "minutes": args.calibrate_minutes,
                }
                if capacity.calibration
                else None
            ),
        },
    )
    remote_blacklist: frozenset[str] = frozenset()
    if args.satori_sync:
        try:
            inventory = satori_repository_blacklist(satori_cli)
        except RuntimeError as error:
            _run_lock.close()
            LOG_PATH = None
            raise SystemExit(
                f"cannot build the mandatory Satori repository blacklist: {error}"
            ) from error
        remote_blacklist = frozenset(
            repository
            for repositories in inventory.values()
            for repository in repositories
        )
        write_json(
            run_dir / "satori-repository-blacklist.json",
            {
                **inventory,
                "repositories": sorted(remote_blacklist, key=str.casefold),
                "profile": args.satori_profile,
            },
        )
        log(
            f"SATORI_BLACKLIST profile={args.satori_profile} "
            f"issues={len(inventory['issues'])} "
            f"advisories={len(inventory['advisories'])} "
            f"unique={len(remote_blacklist)}"
        )
    started = time.monotonic()
    docker_baseline = capture_docker_inventory()
    initial_gc = cleanup_online_docker_storage(
        docker_baseline,
        cache_gb=args.docker_cache_gb,
        min_free_gb=args.min_free_gb,
        artifact=run_dir / "docker-storage-initial.json",
    )
    initial_free_gb = free_disk_gb(out)
    log(
        f"DISK_PREFLIGHT free_gb={initial_free_gb:.1f} "
        f"required_gb={args.min_free_gb}"
    )
    if args.min_free_gb and initial_free_gb < args.min_free_gb:
        _run_lock.close()
        LOG_PATH = None
        raise SystemExit(
            f"only {initial_free_gb:.1f} GiB free after Docker GC; "
            f"jsspector online requires {args.min_free_gb} GiB"
        )
    emit_event(
        "run_started",
        run_id=stamp,
        output=str(run_dir),
        total=0,
    )
    emit_event("discovery_started", output=str(run_dir))

    counters = {
        "static_completed": 0,
        "static_failed": 0,
        "static_timeout": 0,
        "clone_failed": 0,
        "clone_timeout": 0,
        "no_high_findings": 0,
        "no_ai_submitted": 0,
        "ai_submitted": 0,
        "verified_repositories": 0,
        "verified_findings": 0,
        "verification_failed": 0,
        "verification_timeout": 0,
        "fix_attempted": 0,
        "fix_proven": 0,
        "sync_failed": 0,
        "docker_cleanup_failed": 0,
        "docker_storage_gc_failed": len(initial_gc["failures"]),
        "docker_storage_gc_cycles": 1,
    }
    docker_slots = resources.AdjustableSlots(args.parallel_docker, wake=SHUTDOWN)
    no_ai_gate = resources.AdjustableSlots(args.parallel_no_ai, wake=SHUTDOWN)
    if capacity.calibration is not None:
        docker_slots.set_limit(capacity.calibration.low)
        no_ai_gate.set_limit(capacity.calibration.low)
    ai_workers = args.parallel_ai if args.ai_lane else 0
    static_running = 0
    static_running_lock = threading.Lock()
    # Verifications submitted to a lane's pool but not yet picked up by one of its threads: the
    # backlog a pool's own queue hides from the slot gates.
    verification_backlog = 0
    backlog_lock = threading.Lock()

    def backlog_started() -> None:
        nonlocal verification_backlog
        with backlog_lock:
            verification_backlog -= 1
    monitor = resources.Monitor(
        host=capacity.host,
        plan=plan,
        target=args.target_utilization,
        docker_slots=docker_slots,
        no_ai_gate=no_ai_gate,
        ai_workers=ai_workers,
        governed=capacity.governed,
        calibration=capacity.calibration,
        static_active=lambda: static_running,
        emit=emit_event,
        log=log,
        on_calibrated=lambda message: request_shutdown(message=message),
        record_path=run_dir / "resources.jsonl",
        checkouts=lambda: (checkout_slots.held, checkout_slots.capacity),
        backlog=lambda: verification_backlog,
    )
    checkout_slots = resources.CountedSemaphore(args.max_checkouts)
    state_lock = threading.Lock()
    failures_lock = threading.Lock()
    storage_gc_lock = threading.Lock()
    verification_completions = 0
    timeout_repositories: set[str] = set()
    failures: list[dict[str, Any]] = []

    def maintain_docker_storage(
        *, force: bool = False, completed_verification: bool = True
    ) -> None:
        """Run periodic GC and stop before Docker can consume the host filesystem."""
        nonlocal verification_completions
        with storage_gc_lock:
            if completed_verification:
                verification_completions += 1
            free_before = free_disk_gb(out)
            due = bool(
                completed_verification
                and verification_completions % args.docker_gc_every == 0
            )
            under_budget = bool(args.min_free_gb and free_before < args.min_free_gb)
            if not (force or due or under_budget):
                return
            result = cleanup_online_docker_storage(
                docker_baseline,
                cache_gb=args.docker_cache_gb,
                min_free_gb=args.min_free_gb,
                keep_reusable_images=not (force or under_budget),
            )
            free_after = free_disk_gb(out)
            with state_lock:
                counters["docker_storage_gc_cycles"] += 1
                counters["docker_storage_gc_failed"] += len(result["failures"])
            log(
                f"DISK_BUDGET free_before_gb={free_before:.1f} "
                f"free_after_gb={free_after:.1f} required_gb={args.min_free_gb}"
            )
            emit_event(
                "storage_gc",
                free_gb=round(free_after, 1),
                minimum_gb=args.min_free_gb,
                images=result["images"],
                volumes=result["volumes"],
            )
            if args.min_free_gb and free_after < args.min_free_gb:
                log(
                    f"DISK_PRESSURE_STOP free_gb={free_after:.1f} "
                    f"required_gb={args.min_free_gb}"
                )
                emit_event(
                    "operational_failure",
                    repository="",
                    message=(
                        f"disk safety stop: {free_after:.1f} GiB free, "
                        f"{args.min_free_gb} GiB required"
                    ),
                )
                request_shutdown()

    def record_failure(
        *,
        stage: str,
        repository: str,
        reason: str,
        elapsed_s: float | None = None,
        lane: str | None = None,
        artifact: str | None = None,
    ) -> None:
        """Retain a compact, per-run failure inventory for tuning and replay."""
        failure: dict[str, Any] = {
            "stage": stage,
            "repository": repository,
            "reason": reason,
            "retryable": reason in RETRYABLE_STATUSES,
        }
        if elapsed_s is not None:
            failure["elapsed_s"] = elapsed_s
        if lane is not None:
            failure["lane"] = lane
        if artifact is not None:
            failure["artifact"] = artifact
        with failures_lock:
            failures.append(failure)

    def no_ai_job(static: StaticResult) -> ResearchResult:
        backlog_started()
        selected = tuple(static.candidates[: args.max_candidates])
        # The gate is what the governor widens and narrows; with fixed counts the pool size
        # equals the gate and it never blocks.
        no_ai_gate.acquire()
        try:
            return verify_repository(
                static,
                candidates=selected,
                args=args,
                scanner=scanner,
                run_dir=run_dir,
                lane="no-ai",
                docker_slots=docker_slots,
                run_label=run_label,
            )
        finally:
            no_ai_gate.release()

    def ai_job(static: StaticResult) -> ResearchResult:
        backlog_started()
        selected = claude_rank(static, args=args, run_dir=run_dir)
        return verify_repository(
            static,
            candidates=selected,
            args=args,
            scanner=scanner,
            run_dir=run_dir,
            lane="ai",
            docker_slots=docker_slots,
            run_label=run_label,
        )

    def finish_verification(
        future: Future[ResearchResult], *, lane: str, repository: str
    ) -> None:
        """Persist a terminal verification immediately, while discovery still runs."""
        try:
            result = future.result()
        except CancelledError:
            return
        except Exception as error:
            if SHUTDOWN.is_set():
                return
            finished_at = monitor.now()
            monitor.record(
                resources.VerificationRecord(
                    lane=lane,
                    outcome="error",
                    started=finished_at,
                    finished=finished_at,
                    slot_s=0.0,
                )
            )
            record_failure(
                stage="verification",
                repository=repository,
                reason="verification-exception",
                lane=lane,
                artifact="online.log",
            )
            with state_lock:
                counters["verification_failed"] += 1
                state["processed"][repository] = {
                    "status": "verification-exception",
                    "lane": lane,
                    "error": str(error),
                    "processed_at": datetime.now(UTC).isoformat(),
                }
                write_json(state_path, state)
            log(f"RESEARCH_FAILED lane={lane} repository={repository} error={error}")
            emit_event(
                "verification_finished",
                repository=repository,
                lane=lane,
                outcome="failed",
                findings=0,
                message=str(error),
            )
            return
        if result.docker_cleanup_failures:
            slug = result.repository.replace("/", "__")
            with state_lock:
                counters["docker_cleanup_failed"] += result.docker_cleanup_failures
            record_failure(
                stage="docker-cleanup",
                repository=result.repository,
                reason="docker-cleanup-failed",
                elapsed_s=result.elapsed_s,
                lane=lane,
                artifact=f"logs/{slug}.{lane}.docker-cleanup.json",
            )
            emit_event(
                "operational_failure",
                repository=result.repository,
                message="Docker garbage collection failed",
            )
        outcome = resources.outcome_kind(
            cancelled=result.cancelled,
            failed=result.failed,
            failure_reason=result.failure_reason,
            findings=len(result.findings),
            driven=result.driven,
        )
        if outcome is not None:
            finished_at = monitor.now()
            monitor.record(
                resources.VerificationRecord(
                    lane=lane,
                    outcome=outcome,
                    started=finished_at - result.slot_s,
                    finished=finished_at,
                    slot_s=result.slot_s,
                    phases=dict(result.phases),
                    findings=len(result.findings),
                    skip_reason=result.skip_reason,
                )
            )
        if result.cancelled:
            return
        if result.failed:
            slug = result.repository.replace("/", "__")
            record_failure(
                stage="verification",
                repository=result.repository,
                reason=result.failure_reason or "verify-failed",
                elapsed_s=result.elapsed_s,
                lane=lane,
                artifact=f"logs/{slug}.{lane}.verify.log",
            )
            with state_lock:
                counters["verification_failed"] += 1
                if result.failure_reason in RETRYABLE_STATUSES and result.failure_reason not in {
                    "clone-timeout",
                    "static-timeout",
                }:
                    counters["verification_timeout"] += 1
                    timeout_repositories.add(result.repository)
                state["processed"][result.repository] = {
                    "revision": result.revision,
                    "status": result.failure_reason or "verify-failed",
                    "lane": lane,
                    "elapsed_s": result.elapsed_s,
                    "processed_at": datetime.now(UTC).isoformat(),
                }
                write_json(state_path, state)
            emit_event(
                "verification_finished",
                repository=result.repository,
                lane=lane,
                outcome="failed",
                findings=0,
                message=result.failure_reason,
            )
            return
        with state_lock:
            if result.findings:
                counters["verified_repositories"] += 1
                counters["verified_findings"] += len(result.findings)
            if result.fix_attempted:
                counters["fix_attempted"] += 1
            if result.fix_proven:
                counters["fix_proven"] += 1
        emit_event(
            "verification_finished",
            repository=result.repository,
            lane=lane,
            outcome="verified" if result.findings else "not-verified",
            findings=len(result.findings),
            fix_attempted=result.fix_attempted,
            fix_proven=result.fix_proven,
        )
        if (
            args.satori_sync
            and result.findings
            and not synchronize(
                result,
                satori_cli=satori_cli,
                state=state,
                state_path=state_path,
                state_lock=state_lock,
            )
        ):
            record_failure(
                stage="sync",
                repository=result.repository,
                reason="sync-failed",
                elapsed_s=result.elapsed_s,
                lane=lane,
                artifact="online.log",
            )
            with state_lock:
                counters["sync_failed"] += 1
            return
        with state_lock:
            state["processed"][result.repository] = {
                "revision": result.revision,
                "verified": len(result.findings),
                "fix_attempted": result.fix_attempted,
                "fix_proven": result.fix_proven,
                "lane": lane,
                "elapsed_s": result.elapsed_s,
                "processed_at": datetime.now(UTC).isoformat(),
            }
            write_json(state_path, state)

    def finish_verification_with_cleanup(
        future: Future[ResearchResult],
        *,
        lane: str,
        repository: str,
        checkout: Path | None,
    ) -> None:
        try:
            finish_verification(future, lane=lane, repository=repository)
        finally:
            if checkout is not None and checkout.exists():
                remove_checkout(checkout, run_dir)
            checkout_slots.release()
            maintain_docker_storage()

    def static_job(candidate: discover.Candidate) -> StaticResult:
        """Bound retained checkouts while allowing discovery itself to continue streaming."""
        while not SHUTDOWN.is_set():
            if checkout_slots.acquire(timeout=0.5):
                break
        else:
            return StaticResult(
                repository=candidate.repo,
                security_advisories=candidate.security_advisories,
                repository_forks=candidate.forks,
                repository_stars=candidate.stars,
                cancelled=True,
            )
        nonlocal static_running
        with static_running_lock:
            static_running += 1
        try:
            result = static_repository(
                candidate,
                args=args,
                scanner=scanner,
                run_dir=run_dir,
            )
        except Exception:
            checkout_slots.release()
            raise
        finally:
            with static_running_lock:
                static_running -= 1
        if result.checkout is None:
            checkout_slots.release()
        return result

    def finish_static(
        future: Future[StaticResult], *, index: int, repository: str
    ) -> None:
        """Advance one discovered repository without waiting for discovery to finish."""
        try:
            static = future.result()
        except CancelledError:
            return
        except Exception as error:
            if SHUTDOWN.is_set():
                return
            record_failure(
                stage="static",
                repository=repository,
                reason="static-exception",
                artifact="online.log",
            )
            with state_lock:
                counters["static_failed"] += 1
            log(f"STATIC_FAILED repository={repository} unhandled={error}")
            emit_event(
                "static_finished",
                repository=repository,
                outcome="failed",
                message=str(error),
            )
            return

        if static.cancelled:
            return
        with state_lock:
            counters["static_completed"] += 1
        if static.failed:
            slug = static.repository.replace("/", "__")
            reason = static.failure_reason or "static-failed"
            stage = "clone" if reason.startswith("clone-") else "static"
            suffix = "clone" if stage == "clone" else "static"
            record_failure(
                stage=stage,
                repository=static.repository,
                reason=reason,
                elapsed_s=static.elapsed_s,
                artifact=f"logs/{slug}.{suffix}.log",
            )
            with state_lock:
                counters["static_failed"] += 1
                if static.failure_reason == "static-timeout":
                    counters["static_timeout"] += 1
                    timeout_repositories.add(static.repository)
                if static.failure_reason in {"clone-failed", "clone-timeout"}:
                    counters["clone_failed"] += 1
                if static.failure_reason == "clone-timeout":
                    counters["clone_timeout"] += 1
                    timeout_repositories.add(static.repository)
                state["processed"][static.repository] = {
                    "status": static.failure_reason or "static-failed",
                    "elapsed_s": static.elapsed_s,
                    "processed_at": datetime.now(UTC).isoformat(),
                }
                write_json(state_path, state)
            emit_event(
                "static_finished",
                repository=static.repository,
                outcome="failed",
                message=static.failure_reason,
            )
            return
        if not static.candidates:
            with state_lock:
                counters["no_high_findings"] += 1
                state["processed"][static.repository] = {
                    "revision": static.revision,
                    "verified": 0,
                    "elapsed_s": static.elapsed_s,
                    "processed_at": datetime.now(UTC).isoformat(),
                }
                write_json(state_path, state)
            emit_event(
                "static_finished",
                repository=static.repository,
                outcome="clean",
            )
            return

        emit_event(
            "static_finished",
            repository=static.repository,
            outcome="candidates",
            findings=len(static.candidates),
        )
        if SHUTDOWN.is_set():
            if static.checkout is not None and static.checkout.exists():
                remove_checkout(static.checkout, run_dir)
            checkout_slots.release()
            return
        lane = choose_lane(index, args)
        # Publish queueing before submit: a fast deterministic worker can otherwise emit
        # verification_started first and leave the TUI with a phantom queued item.
        emit_event(
            "verification_queued", repository=static.repository, lane=lane
        )
        nonlocal verification_backlog
        with backlog_lock:
            verification_backlog += 1
        try:
            if lane == "ai":
                submitted = ai_executor.submit(ai_job, static)
                with state_lock:
                    counters["ai_submitted"] += 1
            else:
                submitted = no_ai_executor.submit(no_ai_job, static)
                with state_lock:
                    counters["no_ai_submitted"] += 1
        except RuntimeError:
            with backlog_lock:
                verification_backlog -= 1
            if static.checkout is not None and static.checkout.exists():
                remove_checkout(static.checkout, run_dir)
            checkout_slots.release()
            if not SHUTDOWN.is_set():
                raise
            return
        submitted.add_done_callback(
            lambda done, selected_lane=lane, selected_repository=static.repository, checkout=static.checkout: (
                finish_verification_with_cleanup(
                    done,
                    lane=selected_lane,
                    repository=selected_repository,
                    checkout=checkout,
                )
            )
        )

    log(
        f"ONLINE_START since={args.since}s min_forks={args.min_forks} pvr={args.pvr} "
        f"max_repo_size_mb={args.max_repo_size_mb} "
        f"static_parallel={args.static_parallel} "
        f"max_checkouts={args.max_checkouts} "
        f"parallel_no_ai={args.parallel_no_ai} parallel_ai={args.parallel_ai} "
        f"parallel_docker={args.parallel_docker} ai_attempts={args.ai_attempts} "
        f"ai_lane={args.ai_lane} governor={capacity.governed} "
        f"target={args.target_utilization:g} "
        f"min_free_gb={args.min_free_gb} docker_cache_gb={args.docker_cache_gb} "
        f"docker_gc_every={args.docker_gc_every} "
        f"verify_startup={args.verify_startup_timeout}s "
        f"verify_candidate={args.verify_candidate_soft_timeout}/"
        f"{args.verify_candidate_hard_timeout}s "
        f"verify_repository={args.verify_timeout}/{args.verify_extended_timeout}s "
        f"ai_model={args.ai_model} fix_attempts={args.fix_attempts} "
        f"learn_fixes={args.learn_fixes} "
        f"satori_sync={args.satori_sync} satori_blacklist={len(remote_blacklist)}"
    )
    static_executor = ThreadPoolExecutor(max_workers=args.static_parallel)
    # A governed pass may widen the deterministic gate up to the ceiling, so its pool is sized for
    # that; idle pool threads cost nothing and queued repositories wait at the gate in order.
    no_ai_workers = (
        max(args.parallel_no_ai, plan.docker_ceiling - ai_workers)
        if capacity.governed or capacity.calibration is not None
        else args.parallel_no_ai
    )
    no_ai_executor = ThreadPoolExecutor(max_workers=no_ai_workers)
    ai_executor = ThreadPoolExecutor(max_workers=args.parallel_ai)
    storage_monitor_stop = threading.Event()

    def monitor_disk_budget() -> None:
        """Catch one runaway build before it can exhaust the disk between GC cycles."""
        while not storage_monitor_stop.wait(DISK_WATCHDOG_INTERVAL_S):
            if SHUTDOWN.is_set():
                return
            if args.min_free_gb and free_disk_gb(out) < args.min_free_gb:
                maintain_docker_storage(force=True, completed_verification=False)

    storage_monitor = threading.Thread(
        target=monitor_disk_budget,
        name="jsspector-online-disk-guard",
        daemon=True,
    )
    storage_monitor.start()
    monitor.start()
    emit_event(
        "resources",
        slots=docker_slots.limit,
        active=0,
        waiting=0,
        message=(
            f"capacity: docker {docker_slots.limit} of {plan.docker_ceiling} max, "
            f"static {args.static_parallel}, checkouts {args.max_checkouts}"
            + (
                f", governor holds {args.target_utilization:.0%}"
                if capacity.governed
                else ""
            )
            + (
                f", calibrating {capacity.calibration.low}→{capacity.calibration.high} slots"
                if capacity.calibration
                else ""
            )
        ),
    )
    scheduled = 0

    def schedule(candidate: discover.Candidate) -> None:
        """Feed discovery directly into the static stage without a global barrier."""
        nonlocal scheduled
        index = scheduled
        scheduled += 1
        submitted = static_executor.submit(
            static_job,
            candidate,
        )
        submitted.add_done_callback(
            lambda done, selected_index=index, repository=candidate.repo: (
                finish_static(
                    done,
                    index=selected_index,
                    repository=repository,
                )
            )
        )

    try:
        if args.repos_file:
            candidates, discovery_metrics = candidates_from_file(
                args.repos_file,
                args=args,
                state=state,
                remote_blacklist=remote_blacklist,
                run_dir=run_dir,
                on_found=schedule,
            )
        else:
            candidates, discovery_metrics = discover_candidates(
                args=args,
                state=state,
                remote_blacklist=remote_blacklist,
                run_dir=run_dir,
                on_found=schedule,
            )
        emit_event(
            "discovery_completed",
            found=discovery_metrics.get("found", len(candidates)),
            total=len(candidates),
        )
    finally:
        # Static callbacks are the only producers for the verification pools. Closing this pool
        # first guarantees no late submission can race either verification shutdown.
        static_executor.shutdown(wait=True, cancel_futures=SHUTDOWN.is_set())
        no_ai_executor.shutdown(wait=True, cancel_futures=SHUTDOWN.is_set())
        ai_executor.shutdown(wait=True, cancel_futures=SHUTDOWN.is_set())
        storage_monitor_stop.set()
        storage_monitor.join(timeout=10)
        monitor.stop()
        monitor.join(timeout=10)

    checkouts_root = run_dir / "checkouts"
    if checkouts_root.exists():
        for checkout in checkouts_root.iterdir():
            if checkout.is_dir():
                remove_checkout(checkout, run_dir)
        try:
            checkouts_root.rmdir()
        except OSError:
            pass

    cleanup = cleanup_owned_docker_resources(
        run_label, artifact=run_dir / "docker-cleanup.json"
    )
    counters["docker_cleanup_failed"] += len(cleanup["failures"])
    final_storage_gc = cleanup_online_docker_storage(
        docker_baseline,
        cache_gb=args.docker_cache_gb,
        min_free_gb=args.min_free_gb,
        artifact=run_dir / "docker-storage-final.json",
    )
    counters["docker_storage_gc_cycles"] += 1
    counters["docker_storage_gc_failed"] += len(final_storage_gc["failures"])

    # Repositories rejected by the PVR filter are not queried again on every bounded run unless
    # the operator explicitly clears state.json.
    checked = run_dir / "checked.txt"
    if checked.exists():
        for repository in checked.read_text(encoding="utf-8").split():
            state["processed"].setdefault(
                repository,
                {
                    "status": "pvr-filtered",
                    "processed_at": datetime.now(UTC).isoformat(),
                },
            )
        write_json(state_path, state)

    timeout_retries = sorted(timeout_repositories)
    (run_dir / "retry-timeouts.txt").write_text(
        "".join(f"{repository}\n" for repository in timeout_retries),
        encoding="utf-8",
    )
    counters["timeout_retries"] = len(timeout_retries)
    with failures_lock:
        ordered_failures = sorted(
            failures,
            key=lambda failure: (
                failure["stage"],
                failure["repository"],
                failure["reason"],
            ),
        )
    write_json(run_dir / "failures.json", {"failures": ordered_failures})

    performance = resources.performance_summary(
        monitor.performance.snapshot(),
        list(monitor.samples),
        static_parallel=args.static_parallel,
    )
    for line in resources.performance_lines(performance, performance, window="whole pass"):
        log(f"PERFORMANCE {line}")
    run_metrics = {
        "discovery": discovery_metrics,
        **counters,
        "performance": performance,
        "elapsed_s": round(time.monotonic() - started, 1),
        "configuration": {
            "pvr_parallel": args.pvr_parallel,
            "max_repo_size_mb": args.max_repo_size_mb,
            "satori_profile": args.satori_profile,
            "satori_blacklist": len(remote_blacklist),
            "static_parallel": args.static_parallel,
            "max_checkouts": args.max_checkouts,
            "parallel_no_ai": args.parallel_no_ai,
            "parallel_ai": args.parallel_ai,
            "parallel_docker": args.parallel_docker,
            "docker_slots_final": docker_slots.limit,
            "docker_ceiling": plan.docker_ceiling,
            "target_utilization": args.target_utilization,
            "governed": capacity.governed,
            "capacity_limited_by": plan.limited_by,
            "costs": capacity.costs.source,
            "calibrate": args.calibrate,
            "min_free_gb": args.min_free_gb,
            "docker_cache_gb": args.docker_cache_gb,
            "docker_gc_every": args.docker_gc_every,
            "verify_run_label": run_label,
            "scan_threads": args.scan_threads,
            "verify_threads": args.verify_threads,
            "max_candidates": args.max_candidates,
            "ai_candidates": args.ai_candidates,
            "ai_attempts": args.ai_attempts,
            "ai_timeout": args.ai_timeout,
            "ai_model": args.ai_model,
            "fix_attempts": args.fix_attempts,
            "fix_timeout": args.fix_timeout,
            "fix_model": args.fix_model,
            "learn_fixes": args.learn_fixes,
            "clone_timeout": args.clone_timeout,
            "static_timeout": args.static_timeout,
            "verify_timeout": args.verify_timeout,
            "verify_extended_timeout": args.verify_extended_timeout,
            "verify_startup_timeout": args.verify_startup_timeout,
            "verify_candidate_soft_timeout": args.verify_candidate_soft_timeout,
            "verify_candidate_hard_timeout": args.verify_candidate_hard_timeout,
        },
    }
    write_json(run_dir / "online.json", run_metrics)
    repository_failures = counters["static_failed"] + counters["verification_failed"]
    fatal_failures = (
        counters["sync_failed"]
        + counters["docker_cleanup_failed"]
        + counters["docker_storage_gc_failed"]
    )
    log(
        f"ONLINE_DONE discovered={discovery_metrics['found']} "
        f"static={counters['static_completed']} "
        f"verified_repositories={counters['verified_repositories']} "
        f"repository_failures={repository_failures} fatal_failures={fatal_failures}"
    )
    if capacity.calibration is not None:
        calibration = capacity.calibration
        result = resources.analyze_calibration(
            monitor.samples,
            calibration,
            records=monitor.performance.snapshot(),
            host=capacity.host,
            target=args.target_utilization,
            parallel_ai=args.parallel_ai,
            static_parallel=args.static_parallel,
            max_repo_size_mb=args.max_repo_size_mb,
        )
        saved: Path | None = None
        if "error" not in result:
            resources.save_profile(
                capacity.profile_path,
                resources.calibration_profile(
                    result, host=capacity.host, target=args.target_utilization
                ),
            )
            saved = capacity.profile_path
        write_json(run_dir / "calibration.json", result)
        report = resources.render_calibration(
            result, target=args.target_utilization, profile=saved
        )
        log(f"CALIBRATION_RESULT saved={saved is not None} artifact=calibration.json")
        print(report, flush=True)
        emit_event(
            "calibration_finished",
            output=str(run_dir),
            success=saved is not None,
            report=report,
        )
        completed_window = calibration.phase == "done"
        _run_lock.close()
        LOG_PATH = None
        if saved is not None:
            return 0
        return 130 if SHUTDOWN.is_set() and not completed_window else 1
    if SHUTDOWN.is_set():
        emit_event("run_interrupted", output=str(run_dir))
        _run_lock.close()
        LOG_PATH = None
        return 130
    emit_event(
        "run_finished",
        output=str(run_dir),
        verified_findings=counters["verified_findings"],
        failures=repository_failures + fatal_failures,
    )
    exit_code = 1 if fatal_failures else 0
    _run_lock.close()
    LOG_PATH = None
    return exit_code


if __name__ == "__main__":
    sys.exit(main())

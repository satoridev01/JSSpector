#!/usr/bin/env python3
"""Reproducible metrics for bounded ``jsspector online`` experiments.

The online controller is deliberately dependency-free, so this module only uses
the Python standard library. It accepts both the controller's prefixed terminal
events and plain JSONL written by :class:`EventRecorder`. Incomplete work is
reported as *censored*: ending a one-hour experiment is not evidence that a
repository, exploit, fix, or peer review failed.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence


EVENT_PREFIX = "@@JSSPECTOR_ONLINE@@"
SCHEMA_VERSION = 1
TERMINAL_SUFFIXES = (
    "_finished",
    "_completed",
    "_failed",
    "_timeout",
    "_cancelled",
    "_censored",
)
# Lifecycle clocks such as ``run_started`` and ``experiment_started`` describe the
# measurement window, not admitted work.  Only an unfinished stage from this set
# may be inferred as censored when its terminal event is absent.
IMPLICIT_CENSOR_STAGES = frozenset(
    {
        "clone",
        "static",
        "verification",
        "fix",
        "peer_review",
        "recipe_promotion",
        "sync",
    }
)
SENSITIVE_KEY_PARTS = (
    "token",
    "secret",
    "password",
    "credential",
    "api_key",
    "private_key",
)
WOULD_PUBLISH_DECISIONS = frozenset({"publish_fixed", "publish_unfixed"})
EXPLOIT_LABELS = frozenset({"real", "false_positive"})
FIX_LABELS = frozenset({"verified", "rejected", "not_applicable"})


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def _redact(value: Any, key: str = "") -> Any:
    """Remove credentials while retaining configuration used for comparison."""
    lowered = key.casefold()
    if key and any(part in lowered for part in SENSITIVE_KEY_PARTS):
        return "<redacted>"
    if isinstance(value, Mapping):
        return {str(child): _redact(item, str(child)) for child, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return repr(value)


def configuration_snapshot(
    configuration: Mapping[str, Any],
    *,
    experiment_id: str,
    policy_version: str,
    git_revision: str | None = None,
) -> dict[str, Any]:
    """A credential-free, content-addressed experiment configuration."""
    redacted = _redact(configuration)
    canonical = json.dumps(
        {
            "configuration": redacted,
            "policy_version": policy_version,
            "git_revision": git_revision,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    snapshot: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "experiment_id": experiment_id,
        "policy_version": policy_version,
        "configuration_sha256": hashlib.sha256(canonical).hexdigest(),
        "configuration": redacted,
        "recorded_at": datetime.now(UTC).isoformat(),
    }
    if git_revision:
        snapshot["git_revision"] = git_revision
    return snapshot


def write_configuration_snapshot(
    path: Path,
    configuration: Mapping[str, Any],
    *,
    experiment_id: str,
    policy_version: str,
    git_revision: str | None = None,
) -> dict[str, Any]:
    snapshot = configuration_snapshot(
        configuration,
        experiment_id=experiment_id,
        policy_version=policy_version,
        git_revision=git_revision,
    )
    _atomic_json(path, snapshot)
    return snapshot


class EventRecorder:
    """Append-only event recording for controller and peer-review stages."""

    def __init__(self, path: Path, *, experiment_id: str, policy_version: str) -> None:
        self.path = path
        self.experiment_id = experiment_id
        self.policy_version = policy_version
        self.started = time.monotonic()
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, kind: str, **fields: Any) -> dict[str, Any]:
        payload = {
            "schema": SCHEMA_VERSION,
            "type": kind,
            "experiment_id": self.experiment_id,
            "policy_version": self.policy_version,
            "recorded_at": datetime.now(UTC).isoformat(),
            "monotonic_ms": round((time.monotonic() - self.started) * 1000, 3),
            **fields,
        }
        line = json.dumps(payload, sort_keys=True) + "\n"
        with self._lock:
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(line)
        return payload

    @contextlib.contextmanager
    def stage(self, name: str, **identity: Any) -> Iterator[None]:
        """Record one stage, preserving cancellation as censored instead of failed."""
        started = time.monotonic()
        self.record("stage_started", stage=name, **identity)
        try:
            yield
        except (KeyboardInterrupt, SystemExit):
            self.record(
                "stage_censored",
                stage=name,
                duration_ms=round((time.monotonic() - started) * 1000, 3),
                **identity,
            )
            raise
        except BaseException as error:
            self.record(
                "stage_failed",
                stage=name,
                duration_ms=round((time.monotonic() - started) * 1000, 3),
                error_type=type(error).__name__,
                **identity,
            )
            raise
        else:
            self.record(
                "stage_finished",
                stage=name,
                duration_ms=round((time.monotonic() - started) * 1000, 3),
                **identity,
            )


@dataclass(frozen=True)
class JsonlRead:
    items: tuple[dict[str, Any], ...]
    invalid_lines: int = 0


def _json_object(line: str) -> dict[str, Any] | None:
    stripped = line.strip()
    if not stripped:
        return None
    marker = stripped.find(EVENT_PREFIX)
    if marker >= 0:
        stripped = stripped[marker + len(EVENT_PREFIX) :]
    try:
        value = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def read_jsonl(path: Path) -> JsonlRead:
    items: list[dict[str, Any]] = []
    invalid = 0
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return JsonlRead((), 1)
    for line in lines:
        if not line.strip():
            continue
        value = _json_object(line)
        if value is None:
            invalid += 1
        else:
            items.append(value)
    return JsonlRead(tuple(items), invalid)


def case_id(repository: str, revision: str, fingerprint: str) -> str:
    """Return the collision-resistant identity used by offline ground truth."""
    if not repository or "@" in repository or "#" in repository:
        raise ValueError("case repository must be non-empty and contain no @ or #")
    if not revision or "#" in revision:
        raise ValueError("case revision must be non-empty and contain no #")
    if not fingerprint:
        raise ValueError("case fingerprint must be non-empty")
    return f"{repository}@{revision}#{fingerprint}"


def _evidence_case(path: Path) -> tuple[str, dict[str, str]] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(value, Mapping):
        return None
    repository = value.get("repository")
    revision = value.get("revision")
    fingerprint = value.get("finding_fingerprint")
    if not all(
        isinstance(item, str) and item
        for item in (repository, revision, fingerprint)
    ):
        return None
    try:
        identity = case_id(repository, revision, fingerprint)
    except ValueError:
        return None
    return identity, {
        "repository": repository,
        "revision": revision,
        "fingerprint": fingerprint,
    }


def read_evidence_cases(paths: Iterable[Path]) -> tuple[dict[str, dict[str, str]], int]:
    """Read controller-owned case identities independently of model verdicts."""
    cases: dict[str, dict[str, str]] = {}
    invalid = 0
    for path in paths:
        loaded = _evidence_case(path)
        if loaded is None:
            invalid += 1
            continue
        identity, metadata = loaded
        existing = cases.get(identity)
        if existing is not None and existing != metadata:
            invalid += 1
            continue
        cases[identity] = metadata
    return cases, invalid


def read_verdicts(paths: Iterable[Path]) -> tuple[list[dict[str, Any]], int]:
    """Read verdicts and bind each one to its trusted sibling evidence identity.

    Repository identity is deliberately not accepted from model output.  A
    verdict may participate in offline labelled quality only when the sibling
    ``evidence.json`` supplies ``repository@revision#fingerprint``.
    """
    verdicts: list[dict[str, Any]] = []
    invalid = 0
    for path in paths:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            invalid += 1
            continue
        if isinstance(value, dict):
            verdict = dict(value)
            evidence_path = path.with_name("evidence.json")
            if evidence_path.exists():
                loaded = _evidence_case(evidence_path)
                if loaded is None:
                    invalid += 1
                    continue
                identity, metadata = loaded
                fingerprint = verdict.get("finding_fingerprint")
                if fingerprint != metadata["fingerprint"]:
                    invalid += 1
                    continue
                verdict["_case_id"] = identity
                verdict["_case"] = metadata
            verdicts.append(verdict)
        elif isinstance(value, list):
            # Bundled controller verdicts are one object per evidence directory;
            # accepting an array would make the sibling identity ambiguous.
            invalid += 1
        else:
            invalid += 1
    return verdicts, invalid


def percentile(values: Sequence[float], percent: float) -> float | None:
    """Linear percentile, matching common monitoring systems for small samples."""
    if not values:
        return None
    ordered = sorted(float(value) for value in values)
    if len(ordered) == 1:
        return round(ordered[0], 3)
    position = max(0.0, min(1.0, percent)) * (len(ordered) - 1)
    low = math.floor(position)
    high = math.ceil(position)
    value = ordered[low] + (ordered[high] - ordered[low]) * (position - low)
    return round(value, 3)


def distribution(
    values: Iterable[float], *, unit: str = ""
) -> dict[str, float | int | None]:
    numbers = [float(value) for value in values]
    suffix = f"_{unit}" if unit else ""
    return {
        "count": len(numbers),
        f"p50{suffix}": percentile(numbers, 0.50),
        f"p90{suffix}": percentile(numbers, 0.90),
        f"p95{suffix}": percentile(numbers, 0.95),
        f"max{suffix}": round(max(numbers), 3) if numbers else None,
    }


def _event_stage(event: Mapping[str, Any]) -> str | None:
    if isinstance(event.get("stage"), str):
        return str(event["stage"])
    kind = event.get("type")
    if not isinstance(kind, str):
        return None
    for suffix in ("_queued", "_started", *TERMINAL_SUFFIXES):
        if kind.endswith(suffix):
            return kind[: -len(suffix)]
    return None


def _identity(event: Mapping[str, Any], stage: str) -> tuple[str, ...]:
    return (
        stage,
        str(event.get("repository", "")),
        str(event.get("fingerprint", "")),
        str(event.get("lane", "")),
        str(event.get("attempt", "")),
        str(event.get("agent", "")),
    )


def _duration_ms(event: Mapping[str, Any]) -> float | None:
    for key, multiplier in (
        ("duration_ms", 1.0),
        ("elapsed_ms", 1.0),
        ("elapsed_s", 1000.0),
    ):
        value = event.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return max(0.0, float(value) * multiplier)
    return None


def _clock_ms(event: Mapping[str, Any]) -> float | None:
    value = event.get("monotonic_ms")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return None


def _review_duration(verdict: Mapping[str, Any]) -> float | None:
    reviewer = verdict.get("reviewer")
    if isinstance(reviewer, Mapping):
        duration = _duration_ms(reviewer)
        if duration is not None:
            return duration
    return _duration_ms(verdict)


def _agent_durations(verdict: Mapping[str, Any]) -> Iterator[tuple[str, float]]:
    values = verdict.get("agents", verdict.get("agent_results", []))
    if isinstance(values, Mapping):
        values = [
            dict(result, agent=name) if isinstance(result, Mapping) else result
            for name, result in values.items()
        ]
    if not isinstance(values, list):
        return
    for result in values:
        if not isinstance(result, Mapping):
            continue
        duration = _duration_ms(result)
        if duration is not None:
            yield str(result.get("agent", result.get("role", "unknown"))), duration


def read_labels(path: Path | None) -> dict[str, dict[str, str]]:
    """Load blind labels keyed by repository, revision and finding fingerprint.

    Labels are joined only while computing metrics; they are never copied into a review bundle.
    The accepted shape is
    ``{"owner/repo@commit#fingerprint": {"exploit": "real", "fix": "verified"}}``
    or the same mapping nested under ``findings``.  Composite identities prevent the same
    fingerprint in two repositories or revisions from sharing ground truth accidentally.
    """

    if path is None:
        return {}
    try:
        value = json.loads(path.expanduser().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"reading experiment labels {path}: {error}") from error
    if isinstance(value, Mapping) and "findings" in value:
        value = value["findings"]
    if not isinstance(value, Mapping):
        raise ValueError("experiment labels must be an object keyed by fingerprint")
    labels: dict[str, dict[str, str]] = {}
    for identity, expected in value.items():
        if (
            not isinstance(identity, str)
            or "@" not in identity
            or "#" not in identity
            or identity.index("@") == 0
            or identity.rindex("#") <= identity.index("@") + 1
            or identity.endswith("#")
        ):
            raise ValueError(
                "experiment labels must use repository@revision#fingerprint keys"
            )
        if not isinstance(expected, Mapping) or not isinstance(
            expected.get("exploit"), str
        ):
            raise ValueError(f"experiment label {identity} needs exploit")
        exploit = str(expected["exploit"]).casefold()
        if exploit not in EXPLOIT_LABELS:
            raise ValueError(
                f"experiment label {identity} exploit must be one of "
                f"{', '.join(sorted(EXPLOIT_LABELS))}"
            )
        label = {"exploit": exploit}
        if isinstance(expected.get("fix"), str):
            fix = str(expected["fix"]).casefold()
            if fix not in FIX_LABELS:
                raise ValueError(
                    f"experiment label {identity} fix must be one of "
                    f"{', '.join(sorted(FIX_LABELS))}"
                )
            label["fix"] = fix
        labels[identity] = label
    return labels


def _ground_truth(
    verdict: Mapping[str, Any],
    labels: Mapping[str, Mapping[str, str]],
) -> tuple[str | None, str | None]:
    identity = verdict.get("_case_id")
    if isinstance(identity, str) and identity in labels:
        expected = labels[identity]
        return expected.get("exploit"), expected.get("fix")
    # Ground truth embedded in a model-produced verdict is not blind and must not
    # influence evaluation.
    return None, None


def summarize(
    events: Sequence[Mapping[str, Any]],
    verdicts: Sequence[Mapping[str, Any]],
    *,
    resource_samples: Sequence[Mapping[str, Any]] = (),
    labels: Mapping[str, Mapping[str, str]] | None = None,
    evidence_cases: Mapping[str, Mapping[str, str]] | None = None,
    invalid_lines: int = 0,
    invalid_verdicts: int = 0,
    invalid_evidence: int = 0,
) -> dict[str, Any]:
    """Summarize an epoch without treating work cut off by the epoch as failure."""
    labels = labels or {}
    event_counts = Counter(
        str(event.get("type")) for event in events if isinstance(event.get("type"), str)
    )
    outcomes: Counter[str] = Counter()
    stages: defaultdict[str, list[float]] = defaultdict(list)
    starts: defaultdict[tuple[str, ...], list[float]] = defaultdict(list)
    censored: Counter[str] = Counter()
    failures: Counter[str] = Counter()
    funnel: Counter[str] = Counter()
    gc_free: list[float] = []

    for event in events:
        kind = event.get("type")
        if not isinstance(kind, str):
            continue
        stage = _event_stage(event)
        outcome = event.get("outcome")
        if isinstance(outcome, str):
            outcomes[outcome] += 1
        if kind == "verification_finished":
            if outcome == "verified":
                funnel["locally_verified_findings"] += int(
                    event.get("findings", 1) or 0
                )
            if event.get("fix_proven") is True:
                funnel["locally_proven_fixes"] += 1
        elif kind == "sync_finished" and event.get("success") is True:
            funnel["satori_synced_findings"] += int(event.get("findings", 1) or 0)
        elif kind == "storage_gc" and isinstance(event.get("free_gb"), (int, float)):
            gc_free.append(float(event["free_gb"]))
        elif kind == "operational_failure":
            failures["operational"] += 1

        if stage is None:
            continue
        identity = _identity(event, stage)
        if kind.endswith("_started"):
            clock = _clock_ms(event)
            if clock is not None:
                starts[identity].append(clock)
            continue
        if not kind.endswith(TERMINAL_SUFFIXES):
            continue
        duration = _duration_ms(event)
        clock = _clock_ms(event)
        if duration is None and clock is not None and starts[identity]:
            duration = max(0.0, clock - starts[identity].pop())
        elif starts[identity]:
            starts[identity].pop()
        if duration is not None:
            stages[stage].append(duration)
        if kind.endswith(("_censored", "_cancelled")):
            censored[stage] += 1
        elif kind.endswith(("_failed", "_timeout")) or outcome in {
            "failed",
            "error",
            "timeout",
        }:
            failures[stage] += 1

    # Anything that was admitted but not terminal when the epoch stopped is censored.
    for identity, clocks in starts.items():
        if clocks and identity[0] in IMPLICIT_CENSOR_STAGES:
            censored[identity[0]] += len(clocks)

    decisions: Counter[str] = Counter()
    exploit_verdicts: Counter[str] = Counter()
    fix_statuses: Counter[str] = Counter()
    review_durations: list[float] = []
    agent_times: defaultdict[str, list[float]] = defaultdict(list)
    quality = Counter()
    labelled_reviewed: set[str] = set()
    for verdict in verdicts:
        decision = verdict.get("decision")
        if isinstance(decision, str):
            normalized_decision = decision.casefold()
            decisions[normalized_decision] += 1
        else:
            normalized_decision = "invalid"
        exploit = verdict.get("exploit")
        exploit_verdict = (
            exploit.get("verdict")
            if isinstance(exploit, Mapping)
            else verdict.get("exploit_verdict")
        )
        if isinstance(exploit_verdict, str):
            exploit_verdicts[exploit_verdict.casefold()] += 1
        fix = verdict.get("fix")
        fix_status = (
            fix.get("status") if isinstance(fix, Mapping) else verdict.get("fix_status")
        )
        if isinstance(fix_status, str):
            fix_statuses[fix_status.casefold()] += 1
        duration = _review_duration(verdict)
        if duration is not None:
            review_durations.append(duration)
        for agent, agent_duration in _agent_durations(verdict):
            agent_times[agent].append(agent_duration)

        expected_exploit, expected_fix = _ground_truth(verdict, labels)
        if expected_exploit is None:
            continue
        identity = verdict.get("_case_id")
        if not isinstance(identity, str) or identity in labelled_reviewed:
            continue
        labelled_reviewed.add(identity)
        real = expected_exploit == "real"
        false_positive = expected_exploit == "false_positive"
        published = normalized_decision in WOULD_PUBLISH_DECISIONS
        deleted = normalized_decision in {
            "delete_false_positive",
            "false_positive",
            "drop_false_positive",
        }
        if false_positive and published:
            quality["false_published"] += 1
        if real and deleted:
            quality["real_deleted"] += 1
        if real and not published and not deleted:
            quality["real_held"] += 1
        if (
            expected_fix
            and expected_fix != "verified"
            and normalized_decision == "publish_fixed"
        ):
            quality["bad_fix_attached"] += 1
        correct = (real and published) or (false_positive and deleted)
        if correct and not (
            normalized_decision == "publish_fixed"
            and expected_fix
            and expected_fix != "verified"
        ):
            quality["correct"] += 1

    labelled_ids = set(labels)
    missing_verdicts = labelled_ids - labelled_reviewed
    for identity in missing_verdicts:
        quality["missing_verdict"] += 1
        if labels[identity].get("exploit") == "real":
            quality["real_held"] += 1
    observed_ids = set(evidence_cases or {}) | labelled_reviewed
    labelled_observed = labelled_ids & observed_ids
    labelled = len(labelled_ids)

    funnel["peer_reviewed_findings"] = len(verdicts)
    funnel["peer_real_findings"] = sum(
        exploit_verdicts[value] for value in ("real", "verified")
    )
    funnel["would_publish_fixed"] = decisions["publish_fixed"]
    funnel["would_publish_unfixed"] = decisions["publish_unfixed"]
    funnel["would_retry_fix"] = decisions["retry_fix"]
    funnel["peer_false_positive"] = sum(
        decisions[value]
        for value in ("delete_false_positive", "false_positive", "drop_false_positive")
    )
    funnel["peer_inconclusive"] = sum(
        decisions[value]
        for value in ("hold_inconclusive", "inconclusive", "review_operational_failure")
    )

    samples = list(resource_samples)
    cpu = [
        float(item["cpu_fraction"]) * 100
        for item in samples
        if isinstance(item.get("cpu_fraction"), (int, float))
    ]
    memory = [
        float(item["mem_fraction"]) * 100
        for item in samples
        if isinstance(item.get("mem_fraction"), (int, float))
    ]
    sampled_disk = [
        float(item["disk_free_gib"])
        for item in samples
        if isinstance(item.get("disk_free_gib"), (int, float))
    ]
    cleanup_failures = sum(
        int(event["failures"])
        for event in events
        if event.get("type") in {"docker_cleanup_finished", "storage_gc"}
        and isinstance(event.get("failures"), int)
        and event["failures"] > 0
    ) + sum(
        1
        for event in events
        if event.get("type") == "operational_failure"
        and "cleanup" in str(event.get("message", "")).casefold()
    )
    gc_disk = [
        float(event["free_gib"])
        for event in events
        if event.get("type") == "storage_gc"
        and isinstance(event.get("free_gib"), (int, float))
    ]
    disk = gc_disk if len(gc_disk) >= 2 else sampled_disk
    resources = {
        "samples": len(samples),
        "cpu_percent": distribution(cpu, unit="percent"),
        "memory_percent": distribution(memory, unit="percent"),
        "disk_free_gib": distribution(disk, unit="gib"),
        "disk_delta_gib": round(disk[-1] - disk[0], 3) if len(disk) >= 2 else None,
        "storage_gc_free_gib_first": gc_free[0] if gc_free else None,
        "storage_gc_free_gib_last": gc_free[-1] if gc_free else None,
        "cleanup_failures": cleanup_failures,
    }
    quality_summary: dict[str, Any] = {
        "labelled": labelled,
        "labelled_observed": len(labelled_observed),
        "labelled_reviewed": len(labelled_reviewed),
        "labelled_missing_verdict": len(missing_verdicts),
        **dict(sorted(quality.items())),
        "accuracy": round(quality["correct"] / labelled, 4) if labelled else None,
        "review_coverage": (
            round(len(labelled_reviewed) / labelled, 4) if labelled else None
        ),
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "inputs": {
            "events": len(events),
            "verdicts": len(verdicts),
            "invalid_event_lines": invalid_lines,
            "invalid_verdicts": invalid_verdicts,
            "invalid_evidence": invalid_evidence,
            "evidence_cases": len(evidence_cases or {}),
        },
        "event_counts": dict(sorted(event_counts.items())),
        "outcomes": dict(sorted(outcomes.items())),
        "funnel": dict(sorted(funnel.items())),
        "decisions": dict(sorted(decisions.items())),
        "exploit_verdicts": dict(sorted(exploit_verdicts.items())),
        "fix_statuses": dict(sorted(fix_statuses.items())),
        "latency": {
            "stages": {
                name: distribution(values, unit="ms")
                for name, values in sorted(stages.items())
            },
            "peer_review": distribution(review_durations, unit="ms"),
            "agents": {
                name: distribution(values, unit="ms")
                for name, values in sorted(agent_times.items())
            },
        },
        "failures": dict(sorted(failures.items())),
        "censored": dict(sorted(censored.items())),
        "quality": quality_summary,
        "resources": resources,
    }


def summarize_files(
    event_paths: Sequence[Path],
    verdict_paths: Sequence[Path],
    *,
    resource_paths: Sequence[Path] = (),
    evidence_paths: Sequence[Path] = (),
    labels: Mapping[str, Mapping[str, str]] | None = None,
) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    resources: list[dict[str, Any]] = []
    invalid_lines = 0
    for path in event_paths:
        loaded = read_jsonl(path)
        events.extend(loaded.items)
        invalid_lines += loaded.invalid_lines
    for path in resource_paths:
        loaded = read_jsonl(path)
        resources.extend(loaded.items)
        invalid_lines += loaded.invalid_lines
    verdicts, invalid_verdicts = read_verdicts(verdict_paths)
    discovered_evidence = {path.resolve() for path in evidence_paths}
    discovered_evidence.update(
        path.with_name("evidence.json").resolve()
        for path in verdict_paths
        if path.with_name("evidence.json").is_file()
    )
    # The controller supplies event files from the run root.  Discovering all
    # evidence bundles here includes labelled reviews that timed out or were
    # censored before they could produce verdict.json.
    for path in event_paths:
        peer_reviews = path.parent / "peer-reviews"
        if peer_reviews.is_dir():
            discovered_evidence.update(
                candidate.resolve()
                for candidate in peer_reviews.glob("**/evidence.json")
            )
    evidence_cases, invalid_evidence = read_evidence_cases(
        sorted(discovered_evidence)
    )
    return summarize(
        events,
        verdicts,
        resource_samples=resources,
        labels=labels,
        evidence_cases=evidence_cases,
        invalid_lines=invalid_lines,
        invalid_verdicts=invalid_verdicts,
        invalid_evidence=invalid_evidence,
    )


def _cell(value: Any) -> str:
    return "—" if value is None else str(value)


def render_markdown(summary: Mapping[str, Any]) -> str:
    funnel = summary.get("funnel", {})
    quality = summary.get("quality", {})
    resources = summary.get("resources", {})
    lines = [
        "# JSSpector experiment summary",
        "",
        f"Generated: `{summary.get('generated_at', 'unknown')}`",
        "",
        "## Quality funnel",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
    ]
    for name, value in sorted(funnel.items() if isinstance(funnel, Mapping) else []):
        lines.append(f"| {name.replace('_', ' ')} | {value} |")
    lines += [
        "",
        "## Decisions",
        "",
        "| Decision | Count |",
        "| --- | ---: |",
    ]
    for name, value in sorted((summary.get("decisions") or {}).items()):
        lines.append(f"| {name} | {value} |")
    lines += [
        "",
        "## Latency",
        "",
        "| Stage | Count | p50 ms | p90 ms | p95 ms | max ms |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    latency = summary.get("latency", {})
    stage_latency = latency.get("stages", {}) if isinstance(latency, Mapping) else {}
    for name, values in sorted(
        stage_latency.items() if isinstance(stage_latency, Mapping) else []
    ):
        row = (
            _cell(values.get("count")),
            _cell(values.get("p50_ms")),
            _cell(values.get("p90_ms")),
            _cell(values.get("p95_ms")),
            _cell(values.get("max_ms")),
        )
        lines.append(
            f"| {name} | {row[0]} | {row[1]} | {row[2]} | {row[3]} | {row[4]} |"
        )
    review = latency.get("peer_review", {}) if isinstance(latency, Mapping) else {}
    review_row = (
        _cell(review.get("count")),
        _cell(review.get("p50_ms")),
        _cell(review.get("p90_ms")),
        _cell(review.get("p95_ms")),
        _cell(review.get("max_ms")),
    )
    lines.append("| peer review verdicts | " + " | ".join(review_row) + " |")
    labelled_accuracy = (
        quality.get("accuracy") if isinstance(quality, Mapping) else None
    )
    review_coverage = (
        quality.get("review_coverage") if isinstance(quality, Mapping) else None
    )
    missing_verdicts = (
        quality.get("labelled_missing_verdict", 0)
        if isinstance(quality, Mapping)
        else 0
    )
    false_published = (
        quality.get("false_published", 0) if isinstance(quality, Mapping) else 0
    )
    real_deleted = quality.get("real_deleted", 0) if isinstance(quality, Mapping) else 0
    bad_fix = quality.get("bad_fix_attached", 0) if isinstance(quality, Mapping) else 0
    cleanup_failures = (
        resources.get("cleanup_failures", 0) if isinstance(resources, Mapping) else 0
    )
    disk_delta = (
        resources.get("disk_delta_gib") if isinstance(resources, Mapping) else None
    )
    lines += [
        "",
        "## Safety and resources",
        "",
        f"- Labelled accuracy: `{_cell(labelled_accuracy)}`",
        f"- Labelled review coverage: `{_cell(review_coverage)}`",
        f"- Labelled cases missing a verdict: `{missing_verdicts}`",
        f"- False findings that would publish: `{false_published}`",
        f"- Real findings that would be deleted: `{real_deleted}`",
        f"- Bad fixes that would attach: `{bad_fix}`",
        f"- Censored work: `{sum((summary.get('censored') or {}).values())}`",
        f"- Cleanup failures: `{cleanup_failures}`",
        f"- Disk delta GiB: `{_cell(disk_delta)}`",
        "",
    ]
    return "\n".join(lines)


def write_summary(
    output_dir: Path,
    summary: Mapping[str, Any],
    *,
    stem: str = "experiment-summary",
) -> tuple[Path, Path]:
    json_path = output_dir / f"{stem}.json"
    markdown_path = output_dir / f"{stem}.md"
    _atomic_json(json_path, summary)
    markdown_path.write_text(render_markdown(summary), encoding="utf-8")
    return json_path, markdown_path


def main(argv: Sequence[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run",
        type=Path,
        action="append",
        default=[],
        help="discover events, resources and peer-review verdicts below one online run directory",
    )
    parser.add_argument("--events", type=Path, action="append", default=[])
    parser.add_argument("--verdict", type=Path, action="append", default=[])
    parser.add_argument("--evidence", type=Path, action="append", default=[])
    parser.add_argument("--resources", type=Path, action="append", default=[])
    parser.add_argument("--labels", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    for run in args.run:
        if (run / "events.jsonl").is_file():
            args.events.append(run / "events.jsonl")
        if (run / "resources.jsonl").is_file():
            args.resources.append(run / "resources.jsonl")
        args.verdict.extend(sorted((run / "peer-reviews").glob("**/verdict.json")))
    summary = summarize_files(
        args.events,
        args.verdict,
        resource_paths=args.resources,
        evidence_paths=args.evidence,
        labels=read_labels(args.labels),
    )
    json_path, markdown_path = write_summary(args.out, summary)
    print(json_path)
    print(markdown_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

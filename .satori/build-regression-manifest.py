#!/usr/bin/env python3
"""Build the pinned JSSpector exploitability regression corpus.

The Satori advisory is the durable index.  Local jsspector-monitor artifacts add the exact scanner
revision, fingerprint and structured PoC when they are available.  Older monitor runs did not retain
that context, so their repository revision is resolved to the default-branch commit that GitHub
reported at the advisory timestamp.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PRUNE = {
    ".cargo-target",
    ".git",
    ".venv",
    "__pycache__",
    "checkout",
    "node_modules",
    "scanner-generations",
    "target-evidence",
}


def command_json(argv: list[str], *, env: dict[str, str] | None = None) -> Any:
    completed = subprocess.run(
        argv,
        check=True,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        env=env,
    )
    return json.loads(completed.stdout)


def monitor_contexts(root: Path) -> dict[str, list[dict[str, Any]]]:
    contexts: dict[str, list[dict[str, Any]]] = {}
    if not root.is_dir():
        return contexts
    for base, dirs, files in os.walk(root):
        dirs[:] = [name for name in dirs if name not in PRUNE]
        if "context.json" not in files or "selfcheck" not in Path(base).parts:
            continue
        directory = Path(base)
        try:
            context = json.loads((directory / "context.json").read_text())
        except (OSError, json.JSONDecodeError):
            continue
        finding_id = context.get("finding_id")
        if not finding_id or not context.get("revision"):
            continue
        record: dict[str, Any] = {"context": context, "directory": str(directory)}
        for name in ("evidence", "finding", "result"):
            try:
                record[name] = json.loads((directory / f"{name}.json").read_text())
            except (OSError, json.JSONDecodeError):
                pass
        contexts.setdefault(finding_id, []).append(record)
    return contexts


def best_context(records: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not records:
        return None
    return max(
        records,
        key=lambda record: (
            (record.get("result") or {}).get("outcome") == "verified",
            (record.get("evidence") or {}).get("verification", {}).get("outcome") == "verified",
            record["directory"],
        ),
    )


def historical_head(repository: str, timestamp: str) -> str:
    until = timestamp.replace("+00:00", "Z")
    output = subprocess.run(
        [
            "gh",
            "api",
            "-X",
            "GET",
            f"repos/{repository}/commits",
            "-f",
            f"until={until}",
            "-f",
            "per_page=1",
            "--jq",
            ".[0].sha",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
    ).stdout.strip()
    if len(output) != 40:
        raise RuntimeError(f"GitHub returned no historical commit for {repository} at {timestamp}")
    return output


def finding_from(record: dict[str, Any] | None) -> dict[str, Any] | None:
    if not record:
        return None
    evidence = record.get("evidence") or {}
    finding = evidence.get("finding")
    if isinstance(finding, dict):
        return finding
    result = record.get("result") or {}
    current = result.get("current_finding")
    return current if isinstance(current, dict) else None


def advisory_file(description: str) -> str | None:
    match = re.search(r"File:\s+`?([^\n`(]+)", description)
    return match.group(1).strip() if match else None


def advisory_class(title: str) -> str | None:
    text = title.lower()
    if "server-side request forgery" in text or "ssrf" in text:
        return "ssrf"
    if "nosql" in text or "operator injection" in text or "array-valued email" in text:
        return "nosql-injection"
    if "sql injection" in text:
        return "sql-injection"
    if "prototype pollution" in text:
        return "prototype-pollution"
    if "cross-site scripting" in text or "xss" in text:
        return "xss"
    if "command injection" in text:
        return "command-injection"
    if "code injection" in text or "javascript execution" in text:
        return "code-injection"
    if "path traversal" in text or "arbitrary file" in text or "out-of-root" in text:
        return "path-traversal"
    return None


def advisory_poc(description: str) -> dict[str, str] | None:
    match = re.search(r"POC:.*?```[^\n]*\n(.*?)```", description, re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    transcript = match.group(1).strip()
    evidence = re.search(r"^Evidence:\s*(.+)$", description, re.IGNORECASE | re.MULTILINE)
    result = {"transcript": transcript}
    if evidence:
        result["evidence"] = evidence.group(1).strip()
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--organization", default="12")
    parser.add_argument(
        "--monitor-runs",
        type=Path,
        default=Path.home() / "repos/jsspector-monitor/runs",
    )
    parser.add_argument("--repos", type=Path, default=Path(".satori/repos.txt"))
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(".satori/exploitability-regressions.json"),
    )
    parser.add_argument(
        "--targets-output",
        type=Path,
        default=Path(".satori/exploitability-targets.txt"),
    )
    parser.add_argument(
        "--index-output",
        type=Path,
        default=Path(".satori/exploitability-targets.json"),
    )
    args = parser.parse_args()

    if not shutil.which("satori-v2"):
        parser.error("satori-v2 is required")
    if not shutil.which("gh"):
        parser.error("gh is required to pin revisions missing from monitor artifacts")

    repositories = {
        line.strip()
        for line in args.repos.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    env = os.environ.copy()
    env["SATORI_ORGANIZATION"] = str(args.organization)
    response = command_json(["satori-v2", "advisories", "--json", "-l", "200"], env=env)
    advisories = [
        advisory
        for advisory in response.get("items", [])
        if advisory.get("repository") in repositories
    ]
    contexts = monitor_contexts(args.monitor_runs)
    revision_cache: dict[tuple[str, str], str] = {}
    cases: list[dict[str, Any]] = []

    for advisory in advisories:
        finding_id = advisory["finding_id"]
        record = best_context(contexts.get(finding_id, []))
        finding = finding_from(record)
        context = (record or {}).get("context") or {}
        revision = context.get("revision")
        revision_source = "monitor-context"
        if not revision:
            key = (advisory["repository"], advisory["created_at"])
            revision = revision_cache.get(key)
            if not revision:
                revision = historical_head(*key)
                revision_cache[key] = revision
            revision_source = "github-head-at-advisory-time"

        description = advisory.get("description") or ""
        poc = (finding or {}).get("poc") or advisory_poc(description)
        case = {
            "repository": advisory["repository"],
            "revision": revision,
            "revision_source": revision_source,
            "finding_id": finding_id,
            "advisory_id": advisory["id"],
            "expected_exploitability": advisory.get("exploitability", "UNKNOWN").lower(),
            "title": advisory["title"],
            "file": (finding or {}).get("file") or advisory_file(description),
            "class": (finding or {}).get("class") or advisory_class(advisory["title"]),
            "scanner_fingerprint": (finding or {}).get("fingerprint"),
            "satori_fingerprint": ((record or {}).get("finding") or {}).get("fingerprint"),
            "scanner_version": context.get("scanner_version"),
            "scanner_sha256": context.get("scanner_sha256"),
            "expected_outcome": "verified"
            if advisory.get("exploitability") == "EXPLOITABLE"
            else "unknown",
            "poc": poc,
        }
        cases.append(case)

    cases.sort(key=lambda case: (case["repository"].lower(), case["advisory_id"]))
    manifest = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_organization": str(args.organization),
        "repositories": len({case["repository"] for case in cases}),
        "positive_repositories": len(
            {
                case["repository"]
                for case in cases
                if case["expected_outcome"] == "verified"
            }
        ),
        "cases": cases,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    grouped: dict[tuple[str, str], set[str]] = {}
    for case in cases:
        if case["expected_outcome"] != "verified":
            continue
        key = (case["repository"], case["revision"])
        grouped.setdefault(key, set())
        if case.get("scanner_fingerprint"):
            grouped[key].add(case["scanner_fingerprint"])
    replayable = {
        key: fingerprints for key, fingerprints in grouped.items() if fingerprints
    }
    targets = sorted(
        {
            f"{repository}@{revision}"
            for repository, revision in replayable
        },
        key=str.lower,
    )
    args.targets_output.write_text("\n".join(targets) + "\n")
    index = {
        "schema_version": 1,
        "targets": [
            {
                "repository": repository,
                "revision": revision,
                "fingerprints": sorted(fingerprints),
                "cases": [
                    {
                        "fingerprint": case["scanner_fingerprint"],
                        "file": case.get("file"),
                        "class": case.get("class"),
                        "title": case.get("title"),
                    }
                    for case in cases
                    if case["repository"] == repository
                    and case["revision"] == revision
                    and case.get("scanner_fingerprint") in fingerprints
                ],
            }
            for (repository, revision), fingerprints in sorted(
                replayable.items(), key=lambda item: (item[0][0].lower(), item[0][1])
            )
        ],
    }
    args.index_output.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n")
    print(
        f"wrote {len(cases)} cases across {manifest['repositories']} repositories "
        f"({manifest['positive_repositories']} positive; {len(targets)} replayable targets; "
        f"{len(grouped) - len(replayable)} missing fingerprints) "
        f"to {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

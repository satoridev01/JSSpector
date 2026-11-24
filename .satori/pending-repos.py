#!/usr/bin/env python3
"""List pinned repositories whose exploitable benchmark cases are not recovered yet."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def pending_repositories(benchmark: Path, targets: Path) -> list[str]:
    cases = json.loads(benchmark.read_text())["cases"]
    recovered: set[str] = set()
    if targets.is_file():
        for target in json.loads(targets.read_text()).get("targets", []):
            recovered.update(
                case["finding_id"]
                for case in target.get("cases", [])
                if case.get("finding_id")
            )
    pending = {
        f"{case['repository']}@{case['revision']}"
        for case in cases
        if case.get("expected_exploitability", "").lower() == "exploitable"
        and not case.get("scanner_fingerprint")
        and case["finding_id"] not in recovered
    }
    return sorted(pending, key=str.casefold)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--benchmark",
        type=Path,
        default=Path(".satori/exploitability-regressions.json"),
    )
    parser.add_argument(
        "--targets",
        type=Path,
        default=Path(".satori/exploitability-targets.json"),
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    text = "".join(f"{repository}\n" for repository in pending_repositories(args.benchmark, args.targets))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_suffix(args.output.suffix + ".tmp")
        temporary.write_text(text)
        temporary.replace(args.output)
    else:
        print(text, end="")


if __name__ == "__main__":
    main()

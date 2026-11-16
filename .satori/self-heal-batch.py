#!/usr/bin/env python3
"""Run independent self-healing repository workers and merge their recovered identities."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import sys
import threading
from pathlib import Path


REPOSITORY = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:@[A-Za-z0-9][A-Za-z0-9._/-]{0,127})?$"
)


def run(command: list[str], cwd: Path, env: dict[str, str] | None = None) -> None:
    subprocess.run(command, cwd=cwd, env=env, check=True)


def output(command: list[str], cwd: Path) -> str:
    return subprocess.check_output(command, cwd=cwd, text=True).strip()


def repositories(path: Path) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for number, raw in enumerate(path.read_text().splitlines(), 1):
        value = raw.split("#", 1)[0].strip()
        if not value:
            continue
        if not REPOSITORY.fullmatch(value):
            raise SystemExit(f"{path}:{number}: invalid repository: {value}")
        lowered = value.lower()
        if lowered not in seen:
            seen.add(lowered)
            found.append(value)
    if not found:
        raise SystemExit(f"repository list is empty: {path}")
    return found


def prepare_worker(root: Path, base: Path, index: int, remote: str, branch: str) -> tuple[Path, Path]:
    worker = base / "workers" / str(index)
    resolved_base = base.resolve()
    if worker.exists():
        if resolved_base not in worker.resolve().parents:
            raise RuntimeError(f"refusing to replace worker outside {resolved_base}: {worker}")
        shutil.rmtree(worker)
    worker.parent.mkdir(parents=True, exist_ok=True)
    run(
        [
            "git",
            "clone",
            "--quiet",
            "--reference",
            str(root),
            "--single-branch",
            "--branch",
            branch,
            remote,
            str(worker),
        ],
        root,
    )
    target = base / "worker-targets" / f"{index}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    source = root / ".satori/exploitability-targets.json"
    if source.is_file():
        shutil.copyfile(source, target)
    else:
        target.write_text('{"schema_version":1,"targets":[]}\n')
    return worker, target


def worker_loop(
    index: int,
    worker: Path,
    target: Path,
    queue: list[str],
    lock: threading.Lock,
    integration_lock: Path,
) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    while True:
        with lock:
            if not queue:
                return results
            repository = queue.pop(0)
        print(f"[worker {index}] starting {repository}", flush=True)
        environment = os.environ.copy()
        environment["JSSPECTOR_INTEGRATION_LOCK"] = str(integration_lock)
        try:
            run(
                [
                    str(worker / ".satori/self-heal.sh"),
                    "--repo",
                    repository,
                    "--targets",
                    str(target),
                    "--cache",
                    str(worker / "target/self-heal"),
                ],
                worker,
                environment,
            )
        except subprocess.CalledProcessError as error:
            print(f"[worker {index}] FAILED {repository}: exit {error.returncode}", file=sys.stderr, flush=True)
            results.append((repository, "failed"))
        else:
            print(f"[worker {index}] completed {repository}", flush=True)
            results.append((repository, "completed"))


def merge_targets(paths: list[Path]) -> dict:
    targets: dict[tuple[str, str], dict] = {}
    for path in paths:
        if not path.is_file():
            continue
        for target in json.loads(path.read_text()).get("targets", []):
            key = (target["repository"], target["revision"])
            merged = targets.setdefault(
                key,
                {
                    "repository": key[0],
                    "revision": key[1],
                    "fingerprints": [],
                    "cases": [],
                },
            )
            for fingerprint in target.get("fingerprints", []):
                if fingerprint not in merged["fingerprints"]:
                    merged["fingerprints"].append(fingerprint)
            for incoming in target.get("cases", []):
                finding_id = incoming.get("finding_id")
                fingerprint = incoming.get("fingerprint")
                match = next(
                    (
                        index
                        for index, existing in enumerate(merged["cases"])
                        if (finding_id and existing.get("finding_id") == finding_id)
                        or (fingerprint and existing.get("fingerprint") == fingerprint)
                    ),
                    None,
                )
                if match is None:
                    merged["cases"].append(incoming)
                else:
                    merged["cases"][match] = {**merged["cases"][match], **incoming}
    return {
        "schema_version": 1,
        "targets": list(targets.values()),
    }


def push(root: Path) -> None:
    environment = os.environ.copy()
    first = subprocess.run(["git", "push"], cwd=root, env=environment)
    if first.returncode == 0:
        return
    if "GITHUB_TOKEN" in environment:
        print(
            "self-heal: configured GITHUB_TOKEN could not push; retrying with Git credentials",
            file=sys.stderr,
            flush=True,
        )
    environment.pop("GITHUB_TOKEN", None)
    run(["git", "push"], root, environment)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repos", type=Path, required=True)
    parser.add_argument("--parallel", type=int, default=1)
    args = parser.parse_args()
    if not 1 <= args.parallel <= 16:
        raise SystemExit("--parallel must be between 1 and 16")

    root = Path(output(["git", "rev-parse", "--show-toplevel"], Path.cwd()))
    if output(["git", "status", "--porcelain"], root):
        raise SystemExit("parallel self-heal requires a clean JSSpector checkout")
    run(["git", "pull", "--ff-only"], root)
    if output(["git", "rev-list", "--count", "@{upstream}..HEAD"], root) != "0":
        raise SystemExit("parallel self-heal requires every local commit to be published")

    pending = repositories(args.repos.resolve())
    remote = output(["git", "remote", "get-url", "origin"], root)
    branch = output(["git", "branch", "--show-current"], root)
    if not branch:
        raise SystemExit("parallel self-heal requires a named branch")
    base = root / "target/self-heal-batch"
    integration_lock = base / "integration.lock"
    integration_lock.parent.mkdir(parents=True, exist_ok=True)
    count = min(args.parallel, len(pending))
    workers = [prepare_worker(root, base, index + 1, remote, branch) for index in range(count)]

    queue_lock = threading.Lock()
    queue = pending.copy()
    all_results: list[tuple[str, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=count) as executor:
        futures = [
            executor.submit(worker_loop, index + 1, worker, target, queue, queue_lock, integration_lock)
            for index, (worker, target) in enumerate(workers)
        ]
        for future in concurrent.futures.as_completed(futures):
            all_results.extend(future.result())

    run(["git", "pull", "--ff-only"], root)
    target_path = root / ".satori/exploitability-targets.json"
    merged = merge_targets([target_path, *(target for _, target in workers)])
    target_path.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n")
    pending_path = root / ".satori/pending-repos.txt"
    run(
        [
            "python3",
            str(root / ".satori/pending-repos.py"),
            "--output",
            str(pending_path),
        ],
        root,
    )
    run(["git", "add", "--", str(target_path), str(pending_path)], root)
    staged = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=root)
    if staged.returncode == 1:
        run(
            [
                "git",
                "-c",
                "user.name=JSSpector self-heal",
                "-c",
                "user.email=self-heal@localhost.invalid",
                "commit",
                "-m",
                "Record recovered exploitability identities",
            ],
            root,
        )
        push(root)
    elif staged.returncode != 0:
        raise SystemExit("could not inspect merged benchmark identities")
    run(["cargo", "build", "--release", "--locked", "-p", "jsspector"], root)

    failures = [repository for repository, status in all_results if status == "failed"]
    print(
        f"completed {len(all_results) - len(failures)}/{len(all_results)} repositories; "
        f"{len(failures)} failed",
        flush=True,
    )
    if failures:
        print("failed repositories:\n" + "\n".join(failures), file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()

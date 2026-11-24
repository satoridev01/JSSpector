#!/usr/bin/env python3
"""Run independent self-healing repository workers and merge their recovered identities."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import signal
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path


REPOSITORY = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:@[A-Za-z0-9][A-Za-z0-9._/-]{0,127})?$"
)
STOP = threading.Event()
ACTIVE_LOCK = threading.Lock()
ACTIVE: set[subprocess.Popen] = set()


def run(command: list[str], cwd: Path, env: dict[str, str] | None = None) -> None:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        start_new_session=os.name == "posix",
    )
    with ACTIVE_LOCK:
        ACTIVE.add(process)
    try:
        returncode = process.wait()
    finally:
        with ACTIVE_LOCK:
            ACTIVE.discard(process)
    if returncode:
        raise subprocess.CalledProcessError(returncode, command)


def session_pids(session: int) -> list[int]:
    if os.name != "posix":
        return []
    try:
        listing = subprocess.check_output(
            ["ps", "-axo", "pid=,sid="], text=True, stderr=subprocess.DEVNULL
        )
    except (OSError, subprocess.CalledProcessError):
        return []
    found: list[int] = []
    for line in listing.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1] == str(session):
            found.append(int(fields[0]))
    return found


def signal_sessions(sessions: list[int], requested: signal.Signals) -> None:
    for session in sessions:
        pids = session_pids(session)
        if not pids:
            pids = [session]
        # Signal descendants before the session leader so it cannot exit and hide their session id
        # from the force-kill pass below.
        for pid in sorted(pids, key=lambda value: value == session):
            try:
                os.kill(pid, requested)
            except (ProcessLookupError, PermissionError):
                pass


def terminate_active() -> None:
    with ACTIVE_LOCK:
        processes = list(ACTIVE)
    sessions = [process.pid for process in processes]
    if os.name == "posix":
        signal_sessions(sessions, signal.SIGTERM)
    else:
        for process in processes:
            if process.poll() is None:
                process.terminate()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and any(
        process.poll() is None for process in processes
    ):
        time.sleep(0.05)
    if os.name == "posix":
        signal_sessions(sessions, signal.SIGKILL)
    else:
        for process in processes:
            if process.poll() is None:
                process.kill()


def interrupt_as_keyboard(_number: int, _frame: object) -> None:
    raise KeyboardInterrupt


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
            if STOP.is_set() or not queue:
                return results
            repository = queue.pop(0)
        print(f"[worker {index}] starting {repository}", flush=True)
        environment = os.environ.copy()
        environment["JSSPECTOR_INTEGRATION_LOCK"] = str(integration_lock)
        target_before = target.with_suffix(".before.json")
        shutil.copyfile(target, target_before)
        try:
            run(
                [
                    str(worker / ".satori/self-heal.sh"),
                    "--repo",
                    repository,
                    "--push",
                    "--targets",
                    str(target),
                    "--cache",
                    str(worker / "target/self-heal"),
                ],
                worker,
                environment,
            )
        except subprocess.CalledProcessError as error:
            shutil.copyfile(target_before, target)
            if STOP.is_set():
                return results
            print(f"[worker {index}] FAILED {repository}: exit {error.returncode}", file=sys.stderr, flush=True)
            results.append((repository, "failed"))
            dirty = output(["git", "status", "--porcelain"], worker)
            ahead = output(["git", "rev-list", "--count", "@{upstream}..HEAD"], worker)
            if dirty or ahead != "0":
                print(
                    f"[worker {index}] HALTED after {repository}: "
                    f"checkout needs reconciliation (dirty={bool(dirty)} ahead={ahead})",
                    file=sys.stderr,
                    flush=True,
                )
                return results
        else:
            print(f"[worker {index}] completed {repository}", flush=True)
            results.append((repository, "completed"))
        finally:
            target_before.unlink(missing_ok=True)


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
                    "identities": [],
                    "cases": [],
                },
            )
            for fingerprint in target.get("fingerprints", []):
                if fingerprint not in merged["fingerprints"]:
                    merged["fingerprints"].append(fingerprint)
            for identity in target.get("identities", []):
                if identity not in merged["identities"]:
                    merged["identities"].append(identity)
            for incoming in target.get("cases", []):
                finding_id = incoming.get("finding_id")
                fingerprint = incoming.get("fingerprint")
                identity = incoming.get("identity")
                match = next(
                    (
                        index
                        for index, existing in enumerate(merged["cases"])
                        if (finding_id and existing.get("finding_id") == finding_id)
                        or (identity and existing.get("identity") == identity)
                        or (fingerprint and existing.get("fingerprint") == fingerprint)
                    ),
                    None,
                )
                if match is None:
                    merged["cases"].append(dict(incoming))
                else:
                    # A schema-1 worker can carry the same case without the newer identity fields.
                    # Never let a null/empty legacy value erase evidence another worker recovered.
                    updates = {
                        key: value
                        for key, value in incoming.items()
                        if value is not None and value != ""
                    }
                    merged["cases"][match] = {**merged["cases"][match], **updates}
    merged_targets = list(targets.values())
    for target in merged_targets:
        for case in target["cases"]:
            fingerprint = case.get("fingerprint")
            identity = case.get("identity")
            if fingerprint and fingerprint not in target["fingerprints"]:
                target["fingerprints"].append(fingerprint)
            if identity and identity not in target["identities"]:
                target["identities"].append(identity)
        target["fingerprints"].sort()
        target["identities"].sort()
        target["cases"].sort(
            key=lambda case: (
                case.get("finding_id") or "",
                case.get("identity") or "",
                case.get("fingerprint") or "",
            )
        )
    merged_targets.sort(key=lambda target: (target["repository"].lower(), target["revision"]))
    return {
        "schema_version": 2,
        "targets": merged_targets,
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
    parser.add_argument("--push", action="store_true")
    args = parser.parse_args()
    if not args.push:
        raise SystemExit(
            "parallel evolution requires explicit --push so workers can share generations"
        )
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
    previous_term = signal.signal(signal.SIGTERM, interrupt_as_keyboard)
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=count)
    futures: list[concurrent.futures.Future[list[tuple[str, str]]]] = []
    try:
        futures = [
            executor.submit(worker_loop, index + 1, worker, target, queue, queue_lock, integration_lock)
            for index, (worker, target) in enumerate(workers)
        ]
        for future in concurrent.futures.as_completed(futures):
            all_results.extend(future.result())
    except KeyboardInterrupt:
        STOP.set()
        terminate_active()
        for future in futures:
            future.cancel()
        executor.shutdown(wait=True, cancel_futures=True)
        raise SystemExit(130) from None
    else:
        executor.shutdown(wait=True)
    finally:
        signal.signal(signal.SIGTERM, previous_term)

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

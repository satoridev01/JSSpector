# `jsspector online`

`jsspector online` is JSSpector's autonomous, verified-only research mode. The Rust command owns
the user interface and embeds the stdlib-only Python controller used for discovery and scheduling.
It does not import or execute `jsspector-monitor`.

## Pipeline

1. GitHub Search has no minimum fork or star filter. It is split into exhaustive bounded time and
   star windows solely so the 1,000-result API ceiling cannot silently truncate the inventory.
   Repository names are deduplicated and persisted. Each resolved batch is ordered by fork count,
   highest first, before it enters static analysis, prioritizing the most reused code without a
   full-inventory barrier.
2. Private vulnerability reporting is checked explicitly in bounded parallel batches whose
   results are committed in fork-priority order. An unknown result is never treated as enabled, and its
   state travels with every report as `security_advisories`.
3. Each resolved discovery batch immediately feeds twelve one-thread static workers; there is no
   full-inventory barrier. A repository is shallow-cloned once into a run-owned checkout, and that
   exact checkout is reused by static analysis, proof, and fixing. Static scans produce
   high/critical candidates at immutable revisions.
4. Stable inventory indexes assign repositories to two deterministic workers or two Opus-ranked
   workers. Opus receives bounded finding summaries and may only reorder fingerprints.
5. Both lanes share four Docker slots. Strict verification must return a structured
   `exploitation.outcome` of `verified`; an exit code, static finding, model judgment or reflected
   payload is insufficient. A path-traversal file-existence oracle is recorded with
   `impact: file-existence-only` but does not cross the Satori boundary unless content disclosure,
   modification, or an availability impact is independently demonstrated.
6. A 24-slot checkout budget spans static analysis and verification. Discovery may continue, but
   cloning pauses when that budget is full and resumes as completed checks release their checkout;
   the verification backlog therefore cannot grow disk use without bound.
7. After proof, one best-effort Opus fix pass runs in the same scanner process and verification
   sandbox. It does not clone or reproduce the repository in a second scan. Only a fix proved
   against the same exploit and a benign control enters the local recipe corpus. Fix failure does
   not hide the issue.
8. The verified exploit is synchronized privately to Satori. The uploaded report contains only
   verified findings (plus a proven fix when one exists) and uses a
   repository/revision/fingerprint idempotency key. Completion is recorded only after Satori has
   materialized the matching exploitable issues and confirmed each one as `TP`, which makes it
   visible in the `/issues` reporting inbox.

## Operational invariants retained from the retired monitor

- State and artifacts are written atomically, so interruption is resumable.
- One controller exclusively owns each output directory; parallelism lives inside its bounded
  queues, so concurrent processes cannot overwrite the same `state.json`.
- Search and GitHub core budgets are separate, paced and retry bounded.
- Advisory checks use at most two overlapping requests per GitHub token. Secondary-limit
  cooldowns are shared by all workers and surfaced in both the TUI and `online.log`.
- Claude capacity limits pause the shared AI lane until the reported reset instead of converting a
  capacity problem into a security verdict. Ranking has a 60-second deadline; a hung model call
  falls back to deterministic ordering and is never retried within the pass.
- Every subprocess has a wall deadline. TUI cancellation terminates the controller's owned process
  tree. Every repository verification gets a distinct Docker ownership label and runs a mandatory
  garbage-collection pass before its worker slot is released, including after timeout or
  cancellation. It removes disposable containers, networks and session images by exact label.
  Database state is mounted as tmpfs, so official MongoDB/Postgres/MySQL image declarations do not
  create persistent anonymous data volumes. A second run-scoped collector snapshots Docker at
  startup, removes only images and volumes created during the pass, and bounds BuildKit cache to
  20 GB every eight completed verifications. A watchdog also checks once per minute that the host
  retains 100 GiB by default; if collection cannot restore that reserve, the controller stops safely
  while preserving resumable state. Docker objects that predate the run are never targets of the
  run-scoped image/volume collector.
- Only timeouts from the current run are retained in its `retry-timeouts.txt`; they are not silently
  classified as clean and remain eligible for the next pass.
- Static scans have a ten-minute default deadline, overrideable with `--static-timeout SECONDS`.
- Cloning has an independent two-minute default deadline. Dynamic exploitation has a 30-minute
  budget; a verified result gets a separate ten-minute fixing budget in the same process.
- Operator cancellation is neither an operational failure nor a terminal repository result.
  Pending work remains eligible for the next resumable pass.
- Repository revisions and finding fingerprints are pinned before dynamic work.
- Satori synchronization is private and idempotent. Online mode has no GitHub publication path.

Capabilities deliberately not migrated are remote Satori scanning, TP/FP model voting, advisory
publication, self-editing monitor code and automatic Git pushes. JSSpector's scanner and proof
engine are the authority; AI remains a bounded proposer.

## TUI and automation

The controller writes a versioned, line-delimited event stream to its parent. The TUI consumes those events
rather than parsing human log text. Non-interactive stdout automatically uses normal logs;
`--no-tui` makes that behavior explicit. Private artifacts remain under:

```text
runs/jsspector-online/
  online.lock
  state.json
  runs/<UTC run id>/
    repos.txt
    checked.txt
    pvr-errors.txt
    reports/
    logs/
    claude/
    retry-timeouts.txt
    failures.json
    online.log
    online.json
    docker-cleanup.json
    docker-storage-initial.json
    docker-storage-final.json
```

The durable state records processed repositories and synchronized proof identities. Deleting it is
an explicit request to revisit earlier work.

`failures.json` is the structured post-mortem index for that pass. Each entry names the stage,
repository, reason, retryability and the relative log artifact, so operational failures can be
separated from clean scans and non-reproduced candidates without parsing the TUI.

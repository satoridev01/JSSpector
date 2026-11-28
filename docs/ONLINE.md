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
3. Each resolved discovery batch immediately feeds the one-thread static workers (twelve or more;
   see Capacity below); there is no
   full-inventory barrier. A repository is shallow-cloned once into a run-owned checkout, and that
   exact checkout is reused by static analysis, proof, and fixing. Static scans produce
   high/critical candidates at immutable revisions.
4. Stable inventory indexes assign repositories to the deterministic workers or the two Opus-ranked
   workers, in proportion to their counts. When the Opus lane already has two repositories per worker
   waiting, new ones go to the deterministic lane (`AI_OVERFLOW`), so a lagging lane cannot hold the
   whole checkout budget. Opus receives bounded finding summaries and may only reorder fingerprints.
5. Both lanes share the Docker verification slots (four on the reference laptop). Strict verification must return a structured
   `exploitation.outcome` of `verified`; an exit code, static finding, model judgment or reflected
   payload is insufficient. A path-traversal file-existence oracle is recorded with
   `impact: file-existence-only` but does not cross the Satori boundary unless content disclosure,
   modification, or an availability impact is independently demonstrated.
6. A checkout budget (at least 24 slots) spans static analysis and verification. Discovery may continue, but
   cloning pauses when that budget is full and resumes as completed checks release their checkout;
   the verification backlog therefore cannot grow disk use without bound.
7. After proof, one best-effort Opus fix pass runs in the same scanner process and verification
   sandbox. It does not clone or reproduce the repository in a second scan. Only a fix proved
   against the same exploit and a benign control can continue. A newly learned recipe is staged as
   repository-neutral JSON; it does not yet enter or publish the shared corpus. Fix failure does not
   hide the issue.
8. A ten-minute Codex gate pins `gpt-5.6-sol`, medium effort and `daybreak_blue`. Its coordinator
   starts `exploit_replayer`, `exploit_skeptic` and `fix_adversary` concurrently, records each
   independent conclusion and adjudicates their dissent. A real exploit may continue with or
   without a fix; a timeout or operational failure is inconclusive, never a false positive. The
   session is read-only and receives neither Satori nor GitHub environment credentials. The
   controller does not trust the model-authored agent list: it independently verifies three spawn
   edges, their pinned model/effort and three completed turns in Codex's local state, records a
   hashed collaboration receipt, then deletes all four Codex sessions. Missing evidence blocks the
   finding.
9. Only a peer-approved exploit is synchronized privately to Satori. The uploaded report contains only
   verified findings (plus a proven fix when one exists) and uses a
   repository/revision/fingerprint idempotency key. Completion is recorded only after Satori has
   materialized the matching exploitable issues and confirmed each one as `TP`, which makes it
   visible in the `/issues` reporting inbox. The exact reviewed report is queued durably before
   the first Satori mutation, so a later run resumes confirmation even if the newly materialized
   issue already causes discovery to blacklist that repository.
10. After successful synchronization, an approved anonymous recipe stage is promoted through an
    exact SHA-256-bound attestation. The recipes enter the local corpus immediately, while one
    version bump and atomic branch/tag push is batched after the run drains instead of once per
    finding. The tag triggers the trusted-publisher PyPI workflow; GitHub Actions, not the online
    controller, confirms the eventual PyPI publication. Push remains the default for autonomous
    evolution; an interrupted local release or failed push stays pending in durable state and is
    retried idempotently on the next run.

## Operational invariants retained from the retired monitor

- State and artifacts are written atomically, so interruption is resumable.
- One controller exclusively owns each output directory; parallelism lives inside its bounded
  queues, so concurrent processes cannot overwrite the same `state.json`.
- Search and GitHub core budgets are separate, paced and retry bounded. The pool uses every token it
  finds (`GITHUB_TOKENS`, then `~/.config/jsspector/github-tokens`, then `gh auth token`): the
  private-vulnerability-reporting check costs one core call per discovered repository, so a full
  24-hour window outgrows one account's 5,000 calls an hour.
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
- Cloning has an independent two-minute default deadline. Dynamic exploitation has a 15-minute
  budget, extended to 30 minutes only by sink or canary evidence (an answering route is activity);
  each candidate without positive evidence has a three-minute ceiling, a verified result gets a
  separate twenty-minute fixing budget in the same process, and peer review gets ten minutes.
- Operator cancellation is neither an operational failure nor a terminal repository result.
  Pending work remains eligible for the next resumable pass.
- Repository revisions and finding fingerprints are pinned before dynamic work.
- Satori synchronization is private and idempotent. Online mode has no GitHub publication path.

Capabilities deliberately not migrated are remote Satori scanning, unverified TP/FP voting,
GitHub issue/advisory publication and self-editing monitor code. JSSpector's scanner and proof
engine remain the authority; AI is a bounded proposer, and recipe pushes require both dynamic fix
proof and the independent peer attestation.

## One-hour improvement epochs

The first iterations run in shadow mode: they execute exploitation, fixing and the three-agent
review but cannot create Satori state or promote recipes. Shadow mode still reads the Satori issue
and advisory inventory with the `satoridev05` profile so already-reported repositories are excluded
before discovery; it performs no Satori writes.

```bash
jsspector online \
  --experiment-minutes 60 \
  --experiment-drain-minutes 30 \
  --experiment-id pgx-shadow-01 \
  --no-tui
```

Admission runs for 30 minutes; the final 30 minutes only drain admitted work. This matches the
maximum 20-minute fix plus ten-minute review tail instead of systematically censoring that tail.
At the hard hour, unfinished work is cancelled and reported as **censored**, not failed. Every
epoch records its full
credential-redacted configuration hash, events, resource samples, peer verdicts and JSON/Markdown
summary. Each epoch uses a run-local state/cache, so it cannot mark production repositories as
processed and a frozen inventory can be replayed in the next epoch. Compare epochs on the same
inventory before changing one policy variable. Promote shadow
mode to the enforced Satori gate only after reviewing false-publish/real-delete counts, rejected-fix
rate, p50/p90/p95 stage times, throughput, censored work, Docker cleanup and disk deltas.

The peer-review allowance is one ten-minute wall-clock budget, not ten minutes per agent: the three
specialists run concurrently inside it, then the coordinator adjudicates and the controller verifies
and deletes their sessions. A missing specialist, timeout or invalid receipt holds the finding.

For blind quality measurements, keep labels outside the checkout and pass them only to the offline
metrics join. They are never accepted by `jsspector online` and are never copied into a reviewer
bundle. Label keys bind repository, immutable revision and fingerprint:

```json
{
  "findings": {
    "owner/repository@0123456789abcdef#finding-fingerprint": {
      "exploit": "real",
      "fix": "verified"
    }
  }
}
```

```bash
jsspector online \
  --repos-file /srv/jsspector/epochs/pgx-shadow-01/experiment-inventory.jsonl \
  --experiment-minutes 60 \
  --experiment-drain-minutes 30 \
  --experiment-id pgx-shadow-02 \
  --no-tui

RUN_DIR=runs/jsspector-online/runs/20261128T000000000000Z
python3 scripts/online/experiment.py \
  --run "$RUN_DIR" \
  --labels /srv/jsspector/epochs/blind-labels.json \
  --out /srv/jsspector/epochs/pgx-shadow-02/metrics
```

The repeatable tuning loop is:

1. Run a baseline epoch and preserve its `experiment-inventory.jsonl`, configuration hash and
   summaries. The command may take a little longer than 60 minutes because final cancellation,
   session deletion and Docker cleanup happen after the hard measurement deadline.
2. Independently adjudicate a representative set of fingerprints into the blind label file.
3. Replay that pinned JSONL inventory with `--repos-file`; change exactly one policy variable.
4. Run another 30-minute admission + 30-minute drain epoch and compare funnel, labelled quality,
   p50/p90/p95 phase latency, issues per hour, censored work, cleanup failures and disk delta.
5. Keep the change only when safety does not regress and the intended metric improves; otherwise
   revert it. Extend the label set for disagreements and repeat.

An unlabelled first epoch measures throughput and operations, not accuracy: zero labelled errors
with `quality.labelled = 0` is **not** evidence that the gate is correct. Before enforced publishing,
require zero false publishes, zero real deletes and zero bad fixes on the labelled comparison set,
plus zero cleanup failures and no unexplained disk growth.

### Reviewer isolation prerequisite

Read-only sandboxing prevents mutation but is not a hard confidentiality boundary for every file
readable by the operating-system user. On PGX, run the online controller under a dedicated,
unprivileged OS account with its own `HOME`/`CODEX_HOME`, a Codex login, no GitHub/Satori/package
registry credentials, and access only to the run directory and subject checkouts. Environment
sanitization is defense in depth, not a substitute for that account boundary. Independent runtime
replay is best-effort in the first shadow epoch: if the verifier runtime has already been collected
and the recorded evidence is insufficient, the reviewer must return `hold_inconclusive` rather than
inventing reproduction. The first epoch measures how often a narrow controller-owned replay
interface is actually needed before adding one.

## Capacity

Worker counts are derived from the host rather than fixed, by the bundled `resources.py`:

- **Probe.** Logical CPUs honor affinity and a cgroup quota; on Arm big.LITTLE and Apple
  performance/efficiency cores they are also weighted by relative core capacity, because a
  verification needs more core-time on a slower core. CPU already busy is sampled from `/proc/stat`,
  memory comes from `MemAvailable` (bounded by a cgroup limit), and under Docker Desktop or any other
  VM engine both are bounded by the VM that `docker info` reports.
- **Plan.** The budget is the target share of the whole machine (`--target-utilization`, 0.8)
  minus what other processes use now. Docker slots are the most that fit both the CPU and the memory
  budget at the per-verification cost (built-in: 0.9 full-capacity CPU and 1.5 GiB; or calibrated).
  Up to `--parallel-ai` slots feed the Opus-ranked lane after reserving one deterministic worker; on
  an already-loaded host the optional AI lane can be suspended instead of forcing the machine above
  its target. Static workers are `max(12, ¾ × slots)`; retained checkouts are `static + 3 × ceiling`
  (at least 24, and at most a tenth of free disk at `--max-repo-size-mb` each). The governor can
  shrink to one verification and its ceiling is twice the plan or what memory allows at a
  per-verification peak of 4.5 GiB, whichever is lower. Explicit Docker/deterministic counts win and
  the rest are derived from them.
- **Governor.** Every five seconds the monitor samples whole-host CPU, memory and PSI. Memory above
  target + 7 points (or memory stalls) cuts the Docker slot limit by a quarter; a two-minute CPU
  mean above target + 8 points removes one slot; one slot is added only when both resources are 10
  points below the target, downloads are below 90% of the link ceiling a calibration measured,
  every deterministic slot is busy with work waiting, and the last change is at least 150 seconds
  old. It may climb past a calibrated start up to what CPU and memory fit (at most twice the start),
  never past a hard cap. Lowering the limit never interrupts a running verification. Explicit lane
  counts, `--calibrate` and `--no-governor` disable it.
- **Operator control.** Every sample also reads `control.json` in the run directory (the TUI's `+`,
  `-` and `a` write it): `{"docker_slots": N}` fixes the slots (at least one deterministic slot;
  the checkout budget grows with them) and pauses the governor except for its memory guard, and
  `{"docker_slots": "auto"}` resumes it. The deterministic pool is sized for the maximum, so the slot
  gate, not the pool, is what bounds verifications.
- **Calibration.** `--calibrate` forces a local, fix-free, deterministic-only pass with its own state.
  Starting at the first verification it holds half the estimated slots for 40% of the window, then
  the estimate; samples after a three-minute warm-up are fitted (least squares) against the number of
  running verifications. The slope is the per-verification CPU and memory and the intercept the
  pass's own overhead above what was busy at the start. The improvement metrics below then judge
  where a pass should start. It starts at most at the highest level calibration ran, and at the low
  level when the bytes received on physical interfaces stayed flat while the slots grew by half or
  more (the link levelled off; its p95 is kept as the link ceiling) or when verifications per hour
  grew by less than a quarter of the proportional gain while Docker limited the low level (with a
  clone- or discovery-bound low level the comparison says nothing about slots). If verification
  limited the high level less than half the time, more slots alone would not help; a static-bound
  level raises static workers to 1.5 per slot, unless the link was saturated. Only timeouts that are
  significantly more frequent at the high level (one-sided Fisher exact test, p < 0.05, at least
  three) set a hard cap. A smaller rise is reported but not acted on: an Electron app or a large
  monorepo can exceed the startup budget on an idle host, so a few extra timeouts are not evidence
  of contention by themselves. The profile is keyed to the hardware (CPU model, logical CPUs, memory, Docker engine)
  and ignored elsewhere.
- **Improvement metrics.** Issues per hour is verifications per hour times issues per verification;
  three measurements say which factor to work on. *Docker time* splits slot time by outcome
  (verified, not reproduced, skipped because no candidate could be driven, timeout, error) and by
  verifier phase (build/start, probing, fix), with the most common skip reasons; a large timeout
  share argues for tighter deadlines, skips for launch support, build time for caching. *Bottleneck*
  classifies every sample as limited by verification (the slots full with work waiting, at a gate or
  in a lane pool's queue), checkouts (the budget full while the slots have room), static/clone
  (every static worker busy) or discovery.
  *Lanes* gives issues per slot-hour for the deterministic and Opus-ranked lanes, the evidence for
  `--parallel-ai`. The TUI shows them live; `online.json` keeps them as `performance`.

`jsspector online --estimate` prints the probe, cost, budget and plan without running anything.

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
    fix-stages/            # anonymous and inert until attested promotion
    peer-reviews/          # immutable evidence, agent events and schema-bound verdicts
    logs/
    claude/
    retry-timeouts.txt
    failures.json
    online.log
    online.json
    capacity.json          # probe, costs and plan this pass started with
    control.json           # optional operator command: {"docker_slots": N | "auto"}
    resources.jsonl        # one whole-host sample every five seconds
    experiment-configuration.json
    experiment-inventory.jsonl # repository metadata plus the exact scanned revisions
    experiment-summary.json
    experiment-summary.md
    calibration.json       # --calibrate only: fit, per-level throughput and recommendation
    docker-cleanup.json
    docker-storage-initial.json
    docker-storage-final.json
```

A calibration writes `state.json` inside its run directory instead, so it never marks repositories
as processed for real passes. The durable state records processed repositories and synchronized
proof identities. Deleting it is
an explicit request to revisit earlier work.

`failures.json` is the structured post-mortem index for that pass. Each entry names the stage,
repository, reason, retryability and the relative log artifact, so operational failures can be
separated from clean scans and non-reproduced candidates without parsing the TUI.

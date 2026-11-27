# JSSpector

**JSSpector** is an auto-evolving security analyzer for JavaScript and TypeScript. It combines
deterministic static analysis with dynamic verification to find vulnerabilities that are not only
plausible in code, but demonstrably exploitable. It chains attack paths from an entry point,
through data flow across functions and files, to a dangerous sink, then attempts to reproduce the
effect in a disposable runtime.

JSSpector can also propose a minimal fix and validate it against the same exploit. A fix is accepted
only when the exploit works before the change, stops working after it, becomes reproducible again
when the vulnerable code is restored, and a benign control proves that the application still works.

The system improves across consecutive runs. Proven exploit and fix strategies can be recorded and
replayed deterministically, while `jsspector evolve` can use an AI repair agent to extend scanner
coverage when a benchmark exposes a blind spot. AI proposes candidates; it never decides what is
true. New scanner capabilities and fixes are promoted only after deterministic reproduction,
regression tests and precision holdouts pass. Validated generations are published by default so
other machines and later runs start from the improved capability; `--no-push` keeps one local.

> **Status: pre-alpha.** `jsspector scan` (taint findings, as text, JSON or SARIF, with baselines and a CI exit code), `jsspector routes` (entry-point inventory, OpenAPI 3.1) and `jsspector explain` work today. Framework knowledge lives in YAML packs ([`packs/`](packs/)); the engine lowers each file to an owned IR, links modules across files (relative imports, monorepo workspace packages, barrels) and follows values through function summaries.

## Autonomous online research

```sh
jsspector online
```

`online` opens a TUI and performs one resumable pass over public JavaScript repositories pushed in
the last 24 hours, with no minimum forks or stars and GitHub private vulnerability reporting
disabled. GitHub search is exhaustively partitioned by star count only to avoid its 1,000-result
ceiling; those partitions exclude no star count. Inside every resolved discovery batch,
repositories are sent to analysis from most-forked to least-forked, using forks as the proxy for
downstream usage.
Worker counts are sized for the machine `online` runs on. At startup it measures the CPUs, memory
and disk that are free right now (on macOS, those of the Docker VM) and plans for about 80% of the
whole host (`--target-utilization`): one concurrent Docker verification costs about one CPU and
1.5 GiB on average, while a one-thread static worker mostly waits on its `git clone`. On the 10-core,
32-GB Mac with 16 GB assigned to Docker that the former fixed defaults were tuned for, this
reproduces them: 12 static workers feed two deterministic verification workers and two Opus
5.5-ranked workers, with at most four Docker verifications at once and 24 retained checkouts. A
20-core Arm host with 120 GB gets about twelve Docker verifications, ten of them deterministic: the
Opus lane keeps its two workers and the deterministic lane takes the remaining slots. While the pass
runs, a governor samples the host every five seconds and moves the Docker slot limit to stay near
the target (memory first, by a quarter; CPU by one slot) without interrupting running
verifications, so a model server or build started mid-pass shrinks it. Explicit
`--parallel-docker`, `--parallel-no-ai`, `--static-parallel` and `--max-checkouts` are kept as
given; explicit lane counts or `--no-governor` keep the slots fixed. The retained-checkout budget
still bounds disk use, so a slow verification queue cannot consume the disk without bound.

```sh
jsspector online --estimate     # what this host supports and why; runs nothing
jsspector online --calibrate    # measure this host (about 35 minutes) and save its profile
```

`--calibrate` runs a real pass that never publishes, fixes or calls Opus. Every slot goes to the
deterministic lane, first at half the estimate and then at the estimate, for `--calibrate-minutes`
(30 by default, counted from the first verification). Fitting the sampled whole-host CPU and memory
against the number of running verifications yields this host's per-verification cost, which is
saved to `~/.config/jsspector/online-profile.json`; later passes on the same hardware size
themselves from it. The same improvement metrics judge whether running that many pays: if
verifications per hour did not grow with the slots, or the downloads that every clone, npm install
and image pull share stayed at the link's ceiling, the profile caps the slots at the lower level; a
static-bound pass raises static workers, unless the clones share a saturated link; and timeouts that
are significantly more frequent at the higher level (a one-sided Fisher exact test, since repositories
differ widely) cap the slots there. A smaller rise is reported, not acted on. Every sample also
records the bytes received on physical network interfaces. A calibration keeps its own state in its run directory, so the repositories it
touched remain eligible for real passes.

Discovery streams each
resolved batch directly into static analysis, so scanning and verification begin while GitHub
continues building the inventory.
Each repository gets one reusable shallow checkout (120-second default clone deadline), rather
than being cloned again for static analysis, exploitation, and fixing. Static analysis has a
ten-minute deadline. Strict exploitation may use up to 30 minutes; when it succeeds, the same
process and sandbox get a separate ten-minute fix budget. Timeouts remain explicitly retryable
rather than being classified as clean. Every verification has its own Docker ownership label and is
garbage-collected before its worker slot is released. Database state uses tmpfs rather than
anonymous persistent volumes. Every eight completed verifications, the controller also removes
images and volumes created since this run began and bounds BuildKit cache to 20 GB. It preserves
images and volumes that existed before the run. A watchdog checks a 100-GiB host-disk reserve before
the pass and once per minute; if GC cannot restore that headroom, active work is stopped safely with
resumable state instead of filling the disk. These defaults can be tuned with
`--docker-gc-every`, `--docker-cache-gb`, and
`--min-free-gb` (`--min-free-gb 0` disables only the disk guard).
The TUI shows discovery, static progress, both queues,
verified exploits with their average per hour, proven fixes, Satori synchronization, and the live
Docker slot limit with whole-host CPU and memory use. Its "Where to improve" panel keeps only
measurements that point at a change: where Docker slot time goes (verified, not reproduced, skipped
because the app never launched, timeout; and build/start versus probing), which stage limits the
pass (verification, checkouts, static/clone or discovery), and issues per slot-hour for each lane.
The same summary is saved as `performance` in each pass's `online.json`, so passes can be compared
before and after a change. `+` and `-` raise or lower the Docker verification slots while the pass
runs (the governor pauses; its memory guard still applies), `a` hands them back to the governor, and
`h` shows the keys and what each measurement means. Without the TUI, writing `{"docker_slots": 12}`
or `{"docker_slots": "auto"}` to `control.json` in the run directory does the same. Press `q` or Ctrl-C for a bounded stop;
finished work remains in `runs/jsspector-online` and the next run skips it.

AI only orders candidates and proposes a best-effort fix. It cannot declare a vulnerability real.
Only a finding with `exploitation.outcome == "verified"` after strict dynamic reproduction becomes
a private Satori issue, and a path-traversal proof that demonstrates only file existence is kept
local rather than treated as material CIA impact. File-content disclosure, modification, or a
demonstrated availability effect still crosses the gate. A verified exploit gets one Opus fix
attempt in that same proof pass; only
a dynamically proven fix is learned, and failure to find a fix never hides the issue. Satori sync
promotes the materialized finding to a confirmed `TP` before counting it as visible in `/issues`.
Reports carry
`security_advisories: enabled|disabled|unknown` and the same Satori tag, so clients can enable the
Advisory action only when GitHub exposes that private channel. Nothing is filed or published on
GitHub by this command.

Each AI-lane repository receives at most one Opus 5.5 ranking call. It has a 60-second deadline;
timeout uses the original deterministic order instead of retrying or blocking a worker for minutes.

Use `--local-only` to disable Satori synchronization, `--no-evolve` to disable the post-proof fix
attempt, `--repos-file FILE` to replay a frozen inventory, and `--no-tui` for append-only logs in an
automation. Worker counts, stage deadlines and the discovery window remain individually
overrideable. The bundled
controller requires Python 3, authenticated `gh`, `claude` and `satori-v2` CLIs, and Docker; it has
no runtime dependency on `jsspector-monitor` or on a JSSpector source checkout. See
[`docs/ONLINE.md`](docs/ONLINE.md) for the pipeline invariants and artifact layout.

## Quick start

```sh
python3 -m pip install jsspector
jsspector scan path/to/repo
```

PyPI installs the native binary for macOS or Linux (x86_64 or arm64) into the active Python
environment. For an isolated global CLI — required on distributions whose system Python refuses
pip installs (PEP 668, e.g. recent Debian and Ubuntu) — use `pipx install jsspector`. Either way,
`jsspector update` upgrades that same installation to the newest PyPI release, through
`pipx upgrade` when pipx owns it. Releases are built with
[dist](https://github.com/axodotdev/cargo-dist) when a version tag is pushed: archives, checksums
and the shell installer remain available on
[GitHub Releases](https://github.com/satoridev01/JSSpector/releases). The shell installer is:

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/satoridev01/JSSpector/releases/latest/download/jsspector-installer.sh | sh
```

From source: `cargo install --git https://github.com/satoridev01/JSSpector --locked jsspector`.

```
  routes/files.js
  ❯❯❱ jsspector.path-traversal [HIGH] 5c1e0f6a2b9d4e7f
          Data from `req.query` (http) is used as a file path without confinement.
          in GET /invoice, auth: none-detected

        15┆ fs.readFile(target, 'utf8', (err, data) => {
          ↳ source: routes/files.js:13
        13┆ const filename = req.query.filename;
          ↳ through path.join(): routes/files.js:14
        14┆ const target = path.join(INVOICE_DIR, filename);
          ⋮┆----------------------------------------

5 finding(s) in 7 file(s) scanned (0 skipped) in 0.01s
```

Each finding shows the sink, then every step from the source to it, across files, with the code line of each step. The hex string is the finding's fingerprint.

| Option | Meaning |
|---|---|
| `--min-severity critical\|high\|medium\|low` | Lowest severity reported (default `low`: everything) |
| `-f, --format text\|json\|sarif` | Readable list (default), the full JSON report, or SARIF 2.1.0 |
| `-o, --output FILE` | Write the report to a file |
| `--fail-on SEVERITY` | Exit with code 1 when a reported finding not in the baseline is at or above this |
| `--allow-incomplete` | Permit exit 0 when selected files could not be fully analyzed; reports still say `complete: false` |
| `--baseline FILE` / `--write-baseline FILE` | Report only findings not in FILE / record the current findings in FILE |
| `--exclude GLOB` | Skip paths (like `.gitignore`; repeatable) |
| `--no-inline-ignores` | Do not honor target-owned `jsspector-ignore` comments (automatic with `--repo`) |
| `--include tests,examples,docs,generated,vendor\|all` | Also scan these file classes (source files always are) |
| `--config FILE` / `--repo-config` | Read settings from FILE / from `.jsspector.yml` in the scanned directory (neither by default) |
| `--threads N` | Worker threads (default: all cores) |

The output is byte-identical for any thread count. A file that cannot be parsed is reported as
skipped, never a process crash. A scan with a skipped, panicked or depth-truncated selected file is
incomplete and exits 3 unless `--allow-incomplete` is explicit; JSON carries `complete: false` and
SARIF sets `executionSuccessful: false`. Exit codes: 0 = complete with no finding at `--fail-on`
(or no `--fail-on`), 1 = findings at or above it, 2 = usage or configuration error, 3 = engine,
I/O or incomplete-analysis error.

### Configuration

Settings are read only when asked for: from `--config FILE`, or with `--repo-config` from
`.jsspector.yml` in the scanned directory. A scanned repository's own file is ignored by default, so
it cannot exclude or disable what would report it. Command-line options win:

```yaml
min_severity: high
fail_on: high
exclude: ["scripts/", "*.min.js"]        # globs, like .gitignore
include: [tests]                         # extra file classes to scan
baseline: .jsspector-baseline.json
disable: [prototype-pollution]           # classes not to report
packs: [security/our-orm.yaml]           # extra packs, same schema as packs/*.yaml
auth:
  require: [mustBeLoggedIn]              # middleware/guard names that require a login
  admin: [mustBeAdmin]                   # ... or an admin
```

### Explaining

```sh
jsspector explain sql-injection          # the rule: CWE, what it means, how to fix, what counts as safe, sinks
jsspector explain 5c1e0f6a path/to/repo  # one finding by fingerprint (or a unique prefix): code at every step
```

### Entry points

```sh
jsspector routes path/to/repo            # table: method, full path, auth, handler, file:line, inputs
jsspector routes --json path/to/repo
jsspector routes --openapi path/to/repo  # OpenAPI 3.1 of the HTTP routes
```

Routes are followed through router mounts across files (`app.use('/api', require('./routes/users'))`, factories such as `app.use('/users', users())`), route tables and registration helpers. Covered: Express/Koa/Hono/Fastify routers (array paths, `app.route('/book').get(...)` chains, verb-first `router.route('POST', path, h)`, Hono `app.route()` mounts and `basePath`, Koa router prefixes, `fastify.register(plugin, { prefix })`), `fastify.route`, NestJS controllers, Next.js `app/**/route.ts` and `pages/api` (including `export { handler as GET }` and wrapped default exports), raw `http.createServer`, socket.io events, Electron IPC, GraphQL resolver maps, tRPC procedures and queue processors. `--openapi` writes OpenAPI 3.1 paths with unique operation ids.

### What `scan` covers

- **Sources:** Express/Fastify/Koa/Hono/Next.js/NestJS request data (and helpers that take the request), socket.io events (including `onAny` and connection sockets), Meteor methods, Electron `ipcMain`, `postMessage` and extension messages, GraphQL `args`, tRPC `input`, job payloads, archive entry names, n8n node parameters and webhook data, MCP tool, prompt and resource arguments (medium when the server is reached only over stdio), LLM tool definitions (medium), browser URL sources (`location`, `document.referrer`, `window.name`), React props (medium), `process.argv` (low).
- **Sinks:** command and code injection (`child_process` incl. `shell: true` and argument injection, `eval`, `Function`, `vm`, computed `require`/`import()`, `executeJavaScript`, `shell.openExternal`, simple-git, node-ssh, MCP stdio transports), SQL built from text, NoSQL operator injection (object-capable values in queries and aggregation pipelines), path traversal, SSRF (attacker-chosen URL start), XSS (`innerHTML`, jQuery, `document.write`, `dangerouslySetInnerHTML`, navigation to `javascript:`, URL attributes such as `<a href>`, `<iframe src>` and `a.href = v`), prototype pollution (`o[k1][k2] = v`, deep-set helpers).
- **Flow:** assignments, destructuring, templates, string methods, collections (`push`, `Object.assign`, `Object.entries`, `Array.from`, `Promise.all`, clones), callbacks (`map`, `forEach`, `reduce`, `then`, `replace`, by reference too), regex captures, rest parameters, object fields (field by field, spreads included, keys apart from values, tuple positions), instance fields across methods, ES5 classes, `call`/`apply`, typed instances (`new`, annotations, fields, factories and singleton accessors, dispatched to the classes that extend or implement a base, properties every assignment types alike), return values and parameter-to-sink summaries (every contributing parameter and field, sinks inside callbacks belonging to their function), followed across files (up to 8 hops) through relative imports, workspace packages, barrels and constructor injection.
- **Guards:** validation that exits (`if (!/^\w+$/.test(x)) return`), allowlists (also in regex captures and matches), containment (`p === base || p.startsWith(base + sep)`, never against a base the request chose), comparisons with constants, `typeof`/`check()` type checks (NoSQL), `--` before positional arguments and leading-dash checks, fields the code overwrote, schema validation results, URL checks (`sanitizeUrl`), validators and escapers listed in packs.
- **Auth:** each finding carries `auth` (`none-detected`, `user`, `admin`) from route middleware, `router.use`, guard decorators and in-handler checks; admin-only paths are one level lower.
- **Precision:** NoSQL query sinks apply where the project has a MongoDB driver (or is a Meteor app); browser-side sources never reach server sinks; a service worker's `request` is the page's; appending a created DOM node is no HTML injection; `location.href` starts with the page's own origin.
- **Output:** grouped by sink file with every step from source to sink. JSON and SARIF carry the short line-independent `fingerprint` used by baselines and exact verification selection, plus a versioned SHA-256 `identity` used to deduplicate the same semantic flow across scanner runs. JSON findings start with a readable `title` and carry `resource` (sink file:line), `description` and `remediation`. With `--verify`, each selected JSON finding also carries its exact `exploitation` outcome and a structured `poc` when exploitation was verified, so issue trackers such as Satori can ingest the evidence directly; credential headers and JWTs are redacted, and authenticated response bodies leave only their byte count. A verified finding also carries a `fix` (see below). In a git checkout, the JSON report also carries `git`: the `origin` repository (without credentials), the `revision`, the scanned directory's `path` in the repository (fix diffs are relative to it) and whether tracked files were `dirty`.

Dynamic verification uses effects specific to the sink rather than treating reflected input as
proof. JavaScript execution first attempts a read-only `/etc/shadow` read inside the disposable app
container, falls back to `/etc/passwd`, and records only the file bytes decoded by the exact PoC
command; an interpreter-computed product remains the portable fallback when `require` is absent.
Shell execution uses the computed product, and a tainted executable passed to `spawn`/`execFile` is
also tried directly with the read-only `id` program. Blind execution and SSRF use an independently
observed callback; traversal reads use a secret planted file or a controlled OS-file read, while
create/delete/overwrite sinks use isolated filesystem state differentials. SQL, NoSQL and prototype
pollution use agreeing negative controls and database/object-state differentials. A response that
merely echoes the payload, static `uid=` or passwd-shaped text, or a driver request that failed is
never a verified exploit. When a Node application using `node-config` explicitly ships an
`unsafe` profile, verification selects that application-owned profile inside the disposable
sandbox; no repository-specific CLI parameter is required.

The app is started the way its project runs it: the package's start script, or the finding's own
file run with `node` when that file constructs a server and listens. Such a file often only exports
its server (the project's CLI is what calls `listen`), so when the in-place launch exits without
listening, the package's start script (the repository root's when the file's directory has no
package) is tried before the finding is skipped; the image rebuild reuses its cached install layer.
Database sidecars keep their data on tmpfs at the path their official image declares:
`/var/lib/postgresql` from Postgres 18, `/var/lib/postgresql/data` before.

### Proven fixes

With `--verify`, every verified finding also gets a `fix`: a minimal code change proven, in the
same sandbox that reproduced the exploit, to stop it. A change counts as `proven` only when the
app still starts with it and a candidate/original/candidate proof makes the exploit stop, return
when the vulnerable source is restored, and stop again when the change is reapplied. This prevents
persistent database or application state from passing an unrelated edit as a fix. A benign request
to the route must still get the HTTP status it got before the change — so a change that merely
breaks the route never passes. For an XSS (server-reflected or DOM, in Docker or the local runtime) the probe is the
same headless-browser load, every one of which must actually load, and the page must keep its legitimate
behavior with a benign value sent the same way — still showing a plain value in an HTML page, or for
a DOM navigation sink still navigating to an ordinary `http` URL — so a change that merely drops the
value, or answers it as plain text, never passes either. The scanned checkout is not left modified: Docker keeps the
change in the container, and the local runtime writes it back once the proof is over. The report
carries the change as a unified diff, with the original file's fingerprint so the diff can be
re-applied and re-proved later.

JSSpector applies no fix pattern by itself. Candidates come from an LLM through the `claude` CLI, which is told why each earlier candidate failed and shown the fix recipes already proven for the finding's class. The outcome is `proven` (with the diff and its strategy), `unproven` (every candidate failed a control, each one listed with its reason) or `unsupported` (nothing could be tried here, such as a DOM XSS that imports a module from the URL, or no LLM and no recorded fix).

When explicitly requested, a proven fix can be kept in a recipe store under
`$JSSPECTOR_FIX_RECIPES`, `$XDG_DATA_HOME/jsspector/fix-recipes`, or
`~/.local/share/jsspector/fix-recipes` (in that order). Repository-neutral recipes are public
evolution data. Exact examples never belong in the public JSSpector checkout: even without an
owner/repository field, their code, paths and PoCs can disclose an unreported vulnerability by
correlation.

- as a **recipe**: its class, the sink's callee, what the change introduced and a short before/after. Recipes of the same class, the same sink first, are shown to the LLM so later fixes of that pattern tend to pass on the first candidate. Each recipe counts the times it was shown and the times the first candidate was then proven. A few recipes ship with JSSpector as a starting point.
- as an **example**: the finding's and the file's fingerprints, the file's path, the exact change, the request that reproduced the exploit (with credential headers and tokens redacted) and the status a benign request kept. When the same finding shows up again on the same file content, the change is replayed and proved again, with no LLM. This is how a rescan of the same commit reproduces both the exploit and its fix deterministically.

`--learn-fixes` records both the reusable recipe and the exact replay example in the private local
store. `--publish-fixes` records only the bounded anonymous recipe schema, never an example, then
runs it through the same versioned evolution transaction: validate the complete public corpus,
commit it, bump the patch version, compile and test the binary with that corpus embedded, and
atomically push the branch and release tag. A wheel installed from PyPI therefore uses the evolved
recipes without depending on this source checkout. A failed validation or push never forces or
partially publishes a release.

```sh
jsspector scan . --verify                  # verify, then prove a fix for each verified finding
jsspector scan . --verify --no-fix-llm     # replay recorded fixes only, no LLM
jsspector scan . --verify --no-fix         # verification only
jsspector scan . --verify --verify-until-first \
  --verify-fingerprint FIRST --verify-fingerprint SECOND  # ranked backlog: stop at first proof
jsspector scan . --verify --learn-fixes    # also record newly proven fixes locally
jsspector scan . --verify --publish-fixes  # evolve, release and embed an anonymous proven recipe
```

`--fix-attempts` (default 3) bounds the LLM candidates, `--fix-timeout` (default 600 seconds) the
total time per finding, and `--fix-model` picks the LLM model.

### Exploiting a socket.io event

`--verify` also drives a finding whose source is a socket.io event payload
(`socket.on('name', (data, cb) => ...)`): it speaks the Engine.IO long-polling wire protocol
directly (no `socket.io-client` dependency), connects to the same app session an HTTP finding
uses, and emits the event carrying each payload, in Docker or the local runtime alike. Restricted
for now to path traversal, command/code injection and SSRF (NoSQL/SQL injection and prototype
pollution need request-input or sibling enrichment not wired up for a socket source yet), the
default namespace and Engine.IO protocol v4 (socket.io v3/v4; an older v2 server or a custom
`path:` option is not recognized), and anonymous events (one behind a `socket.use`/handshake
check is not driven yet). A fix is proven the way an HTTP one is: the event must stop reproducing
and a plain payload must still be acknowledged — an event the change stops answering at all fails
that control.

### Exploiting an MCP tool call

A finding whose source is the arguments of an MCP (Model Context Protocol) tool — `server.tool`,
`registerTool`, a low-level `setRequestHandler(CallToolRequestSchema)` or FastMCP's `addTool` — is
driven live, in Docker or the local runtime alike: over HTTP when the server listens, and through a
bridge when it speaks only stdio. Path traversal, command/code injection and SSRF are covered.

The server is found and read, not guessed. JSSpector looks for the endpoint at the paths the source
mounts it at, then the conventional ones (`/mcp`, `/`, `/sse`, ...), speaking each of the three HTTP
transports with a dependency-free client that runs inside the app's own session: Streamable HTTP
stateless, Streamable HTTP with a session id, and the legacy HTTP+SSE pair. It then asks the server
what it offers (`tools/list`). A finding rarely says which argument of the tool carries the tainted
value — the arguments object is usually passed whole to helpers, often across files — so the tool's
own JSON Schema decides: every free-text argument is a candidate for the payload, the likeliest
first, and the other required arguments are filled with values the schema accepts, because a server
validates arguments before its handler runs. Each (tool, argument) pair gets a bounded number of
requests, so a server with a hundred tools is not hammered for the one the finding is about.

The report's reproduction is a command, not a description: plain `curl` (initialize, initialized,
then `tools/call`) for Streamable HTTP, and the official client for the legacy event stream.

A call the tool's schema rejects never reached the handler, which is not the same as the handler
resisting it: such a finding is reported as skipped, with the schema's own message, never as not
reproduced. So is a server that asks for credentials (verification does not log in). A fix is
proven against the concrete call that was exploited: the exploit must stop reproducing and the same
tool must still answer a plain value as it did before the change.

Most MCP servers are not HTTP servers: an editor or `npx` starts them as a child process and talks
over its stdin and stdout, so they bind no port. When the app does not listen, or listens at no MCP
endpoint, JSSpector launches it again behind a small bridge that runs in the app's place, starts the
repository's own stdio server as its child and serves it as a Streamable HTTP endpoint on the
session's port. Discovery, the call driver, the oracles and the fix proof then work on it unchanged.
Which command starts the server is tried out, not assumed: the package's `bin` and `main`, a
`start`-style script that is a plain `node <file>`, the sub-commands its CLI defines for serving
(`server start`, `mcp:serve`), and the module that constructs the stdio transport, each one run until
the first answers `initialize`. A crash a payload causes restarts the server for the attempts that
follow, and a launch that found nothing says what every command did and what the last one wrote to
stderr. The reproduction in the report is the official client starting the server and calling the
tool, so anyone with the package built can replay it.

### Verifying without Docker

`--verify` runs each app in a disposable Docker container. In an environment that is already
disposable and has no Docker, such as a dedicated CI or Satori job, `--local` runs the app there
instead, with the same exploit and fix proofs:

```sh
jsspector scan . --verify --local --format json
```

Local verification installs dependencies and executes the scanned repository's build and runtime
scripts. Use it only inside a disposable worker with an allowlisted environment and no reusable
credentials or host filesystem access; it is not a sandbox for an untrusted repository.

The backing services an app needs are provisioned on demand, only for an app that needs them and only when the host lacks them: MongoDB 7.0 (with `mongosh`) for an app with a MongoDB driver, Redis 7.2 (built from source; needs `make` and a C compiler) for an app with a Redis client. They are cached under the system temp directory, so later runs start them at once. A service that cannot be provisioned leaves the app running without it, and a finding that then does not reproduce is reported as skipped rather than not reproduced.

### Scanning a GitHub repository

`scan --repo` accepts either the repository HEAD or a pinned revision, clones it and performs the
same static scan as a local path. Dynamic execution happens only with an explicit `--verify`; a
normal repository scan never repairs JSSpector, writes recipes, commits or pushes. Because the
remote source is not trusted policy, `--repo` does not honor its `jsspector-ignore` comments:

```sh
jsspector scan --repo owner/repository
jsspector scan --repo owner/repository@revision --verify
```

### Auto-evolution across consecutive runs

Evolution covers both scanner capability repairs and anonymous recipes learned from proven fixes.
It requires a clean, published JSSpector checkout and may invoke the repair agent and commit
validated changes. Validated repairs push by default; `--no-push` keeps a single-repository scanner
evolution local for review. Online fix learning promotes its anonymous recipe automatically through
a patch release; exact replay examples remain private. Batch workers always publish because they
exchange validated generations through the upstream branch. This makes consecutive runs
cumulative: every worker begins from the latest accepted scanner and recipe generation, and only a
generation that passes the deterministic promotion gates can become the starting point for the
next run:

```sh
jsspector evolve --repo owner/repository
jsspector evolve --repo owner/repository --no-push
python3 .satori/pending-repos.py --output .satori/pending-repos.txt
jsspector evolve --repos .satori/pending-repos.txt --parallel 2
```

The list contains one `owner/repository@revision` per line. Workers diagnose and prepare repairs in
independent JSSpector clones. Integration, exact dynamic revalidation, commits and pushes are
serialized, and the pending list is regenerated after recovered identities are merged.

The repair agent works in an isolated JSSpector worktree, receives no shell or Git access, and sees
the target checkout through a temporarily read-only tree. It may change only the static scanner, its
integration tests and packs; the CLI, dynamic verifier and controller that judge the change are an
immutable trust boundary. A benchmark gap that requires a new dynamic oracle therefore stops for a
reviewed verifier change instead of letting the repair candidate redefine success. The controller
rebuilds the candidate, reproduces the exact pinned finding with a structured PoC, integrates
accepted changes, and reruns the full CI suite plus exact-case validation against the integrated
`HEAD` before any push.
Each candidate and integrated generation also scans randomized safe counterparts for command
injection, traversal, SQL injection, SSRF, NoSQL injection and DOM data flow. Any finding in that
controller-owned precision holdout rejects the generation before it can be promoted.
Diagnostics and repair transcripts live in the private evolution cache. Transcript capture is
bounded (16 MiB for the structured stream and 2 MiB for stderr), continues draining the child after
the bound, and marks truncated artifacts. Reports, baselines, recipes and controller artifacts are
published by atomic replacement, so an untrusted checkout cannot redirect a write through a
pre-existing destination symlink.
Validated scanner generations are patch-versioned and pushed atomically with their Git tag. The
tag builds the GitHub Release, which publishes the four native wheels to PyPI; another installation
can then receive the capability with `jsspector update`.
The controller's diagnostic `--no-repair` mode never writes identities or commits, while a local
evolution with `--no-push` still runs the same full promotion gates before leaving its commits for
review.
This standalone flow requires authenticated Satori, repair-agent and GitHub CLIs; it does not
require a supervising agent. `SATORI_ORGANIZATION` selects a Satori organization; without it the
Satori CLI uses its own.

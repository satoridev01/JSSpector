# JSSpector

**JSSpector** is a static analyzer (SAST) for JavaScript and TypeScript. It finds **high and critical vulnerabilities by chaining attack paths through the code**: from an entry point, through data flow across functions and files, to a dangerous sink.

> **Status: pre-alpha.** `jsspector scan` (taint findings, as text, JSON or SARIF, with baselines and a CI exit code), `jsspector routes` (entry-point inventory, OpenAPI 3.1) and `jsspector explain` work today. Framework knowledge lives in YAML packs ([`packs/`](packs/)); the engine lowers each file to an owned IR, links modules across files (relative imports, monorepo workspace packages, barrels) and follows values through function summaries. See [`docs/PLAN.md`](docs/PLAN.md) for the roadmap.

## Quick start

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/satoridev01/JSSpector/releases/latest/download/jsspector-installer.sh | sh
jsspector scan path/to/repo
```

The installer puts the binary for your platform in `~/.cargo/bin`. Releases are built with [dist](https://github.com/axodotdev/cargo-dist) for macOS and Linux (x86_64 and arm64) when a version tag is pushed: the archives, their checksums and the installer are on [GitHub Releases](https://github.com/satoridev01/JSSpector/releases). From source: `cargo install --git https://github.com/satoridev01/JSSpector --locked jsspector`.

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
| `--baseline FILE` / `--write-baseline FILE` | Report only findings not in FILE / record the current findings in FILE |
| `--exclude GLOB` | Skip paths (like `.gitignore`; repeatable) |
| `--include tests,examples,docs,generated,vendor\|all` | Also scan these file classes (source files always are) |
| `--config FILE` / `--repo-config` | Read settings from FILE / from `.jsspector.yml` in the scanned directory (neither by default) |
| `--threads N` | Worker threads (default: all cores) |

The output is byte-identical for any thread count. A file that cannot be parsed is reported as skipped, never a crash. Exit codes: 0 = no finding at `--fail-on` (or no `--fail-on`), 1 = findings at or above it, 2 = usage or configuration error, 3 = engine or I/O error.

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
- **Output:** grouped by sink file with every step from source to sink; JSON and SARIF carry line-independent fingerprints for baselines. JSON findings start with a readable `title` and carry `resource` (sink file:line), `description` and `remediation`. With `--verify`, each selected JSON finding also carries its exact `exploitation` outcome and a structured `poc` when exploitation was verified, so issue trackers such as Satori can ingest the evidence directly; a verified finding also carries a `fix` (see below). In a git checkout, the JSON report also carries `git`: the `origin` repository (without credentials), the `revision`, the scanned directory's `path` in the repository (fix diffs are relative to it) and whether tracked files were `dirty`.

### Proven fixes

With `--verify`, every verified finding also gets a `fix`: a minimal code change proven, in the
same sandbox that reproduced the exploit, to stop it. A change counts as `proven` only when the
app still starts with it, the same probe no longer reproduces, and a benign request to the route
still gets the HTTP status it got before the change — so a change that merely breaks the route
never passes. The scanned checkout is never modified; the report carries the change as a unified
diff, with the original file's fingerprint so the diff can be re-applied and re-proved later.

JSSpector applies no fix pattern by itself. Candidates come from an LLM through the `claude` CLI, which is told why each earlier candidate failed and shown the fix recipes already proven for the finding's class. The outcome is `proven` (with the diff and its strategy), `unproven` (every candidate failed a control, each one listed with its reason) or `unsupported` (nothing could be tried here, such as a browser-driven finding, or no LLM and no recorded fix).

Every proven fix is kept in a recipe store (`--fix-recipes DIR`, by default `jsspector/fix-recipes` in the user's cache directory):

- as a **recipe**: its class, the sink's callee, what the change introduced and a short before/after. Recipes of the same class, the same sink first, are shown to the LLM so later fixes of that pattern tend to pass on the first candidate. Each recipe counts the times it was shown and the times the first candidate was then proven. A few recipes ship with JSSpector as a starting point.
- as an **example**: the finding's and the file's fingerprints, the exact change, the request that reproduced the exploit and the status a benign request kept. When the same finding shows up again on the same file content, the change is replayed and proved again, with no LLM. This is how a rescan of the same commit reproduces both the exploit and its fix deterministically.

```sh
jsspector scan . --verify                  # verify, then prove a fix for each verified finding
jsspector scan . --verify --no-fix-llm     # replay recorded fixes only, no LLM
jsspector scan . --verify --no-fix         # verification only
```

`--fix-attempts` (default 3) bounds the LLM candidates, `--fix-timeout` (default 600 seconds) the
total time per finding, and `--fix-model` picks the LLM model.

### Verifying without Docker

`--verify` runs each app in a disposable Docker container. In an environment that is already disposable and has no Docker, such as a CI or Satori job, `--local` runs the app there instead, with the same exploit and fix proofs:

```sh
jsspector scan . --verify --local --format json
```

The backing services an app needs are provisioned on demand, only for an app that needs them and only when the host lacks them: MongoDB 7.0 (with `mongosh`) for an app with a MongoDB driver, Redis 7.2 (built from source; needs `make` and a C compiler) for an app with a Redis client. They are cached under the system temp directory, so later runs start them at once. A service that cannot be provisioned leaves the app running without it, and a finding that then does not reproduce is reported as skipped rather than not reproduced.

### Scanning a GitHub repository

`scan --repo` accepts either the repository HEAD or a pinned revision, and clones and scans it
directly. `--self-heal` first validates and repairs the scanner against the historical benchmark
(it needs a clean, published JSSpector checkout):

```sh
jsspector scan --repo owner/repository --verify
jsspector scan --repo owner/repository@revision --verify
jsspector scan --repo owner/repository --self-heal
```

To complete a pinned corpus with two independent workers:

```sh
python3 .satori/pending-repos.py --output .satori/pending-repos.txt
jsspector scan --repos .satori/pending-repos.txt --parallel 2
```

The list contains one `owner/repository@revision` per line. Workers diagnose and prepare repairs in
independent JSSpector clones. Integration, exact dynamic revalidation, commits and pushes are
serialized, and the pending list is regenerated after recovered identities are merged.

The repair agent works in an isolated JSSpector worktree and cannot edit the scanned repository,
benchmark or trusted controller. A candidate is incorporated only after the controller independently
rebuilds the scanner and reproduces the exact finding with a structured PoC. Validated generations
are committed and pushed so another computer starts from the new capability. This standalone flow
requires authenticated Satori, repair-agent and GitHub CLIs;
it does not require a supervising agent. Organization 12 is the default and can be overridden with
`SATORI_ORGANIZATION`.

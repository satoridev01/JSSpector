# JSSpector

**JSSpector** is a static analyzer (SAST) for JavaScript and TypeScript. It finds **high and critical vulnerabilities by chaining attack paths through the code**: from an entry point, through data flow across functions and files, to a dangerous sink.

> **Status: pre-alpha.** `jsspector scan` (taint findings, as text, JSON or SARIF, with baselines and a CI exit code), `jsspector routes` (entry-point inventory, OpenAPI 3.1) and `jsspector explain` work today. Framework knowledge lives in YAML packs ([`packs/`](packs/)); the engine lowers each file to an owned IR, links modules across files (relative imports, monorepo workspace packages, barrels) and follows values through function summaries. See [`docs/PLAN.md`](docs/PLAN.md) for the roadmap.

## Quick start

```sh
cargo install --git https://github.com/satoridev01/JSSpector --locked jsspector
jsspector scan path/to/repo
```

Releases are built with [dist](https://github.com/axodotdev/cargo-dist) for macOS and Linux (x86_64 and arm64) when a version tag is pushed: archives and a shell installer on GitHub Releases, and a Homebrew formula (`brew install satoridev01/tap/jsspector`) once the first release is out.

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
| `--min-severity critical\|high\|medium\|low` | Lowest severity reported (default `high`) |
| `-f, --format text\|json\|sarif` | Readable list (default), the full JSON report, or SARIF 2.1.0 |
| `-o, --output FILE` | Write the report to a file |
| `--fail-on SEVERITY` | Exit with code 1 when a reported finding not in the baseline is at or above this |
| `--baseline FILE` / `--write-baseline FILE` | Report only findings not in FILE / record the current findings in FILE |
| `--exclude GLOB` | Skip paths (like `.gitignore`; repeatable) |
| `--include tests,examples,docs,generated,vendor\|all` | Also scan these file classes (source files always are) |
| `--config FILE` / `--no-config` | Settings file instead of `./.jsspector.yml` / ignore it |
| `--threads N` | Worker threads (default: all cores) |

The output is byte-identical for any thread count. A file that cannot be parsed is reported as skipped, never a crash. Exit codes: 0 = no finding at `--fail-on` (or no `--fail-on`), 1 = findings at or above it, 2 = usage or configuration error, 3 = engine or I/O error.

### In CI

```sh
jsspector scan . --format sarif --output jsspector.sarif   # upload to GitHub code scanning
jsspector scan . --write-baseline .jsspector-baseline.json # accept what is there today
jsspector scan . --baseline .jsspector-baseline.json --fail-on high
```

SARIF results carry the witness path as a `codeFlow`, the fingerprint in `partialFingerprints`, CWE tags and a `security-severity` per rule, with columns in UTF-16 code units. A baseline holds fingerprints, which do not depend on line numbers: moving code around does not resurface accepted findings. A saved JSON report or SARIF log works as a baseline too.

To silence one finding in the code, put a comment on the sink's line or the line above it: `// jsspector-ignore sql-injection -- id is an integer` (no class name silences every class there).

### Configuration

`.jsspector.yml` in the scanned directory (command-line options win):

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
- **Output:** grouped by sink file with every step from source to sink; JSON and SARIF carry line-independent fingerprints for baselines. JSON findings start with a readable `title` and carry `resource` (sink file:line), `description` and `remediation`, the fields issue trackers such as Satori read.

### Packs

Every framework or library fact is data in [`packs/*.yaml`](packs/) (sources, sinks with argument rules, propagators, sanitizers, guards, route conventions, auth patterns). `cargo xtask ci` fails if the engine repeats a name a pack lists.

### Linking and the IR

Each file is lowered to an owned IR (`jss_core::ir`: imports resolved to files, exports, functions with their calls and flows, entry points, mounts). Imports resolve relative paths, monorepo workspace packages (`package.json` names, `dist/` mapped back to `src/`), tsconfig/jsconfig `baseUrl` and `paths`, barrels (`export * from`) and namespace re-exports. Summaries, route templates and constants (enum members, `const` strings) cross files through those links, iterated until nothing new is learned. Findings are linked to the entry point that reaches them through the call graph, and take that route's authentication (including middleware on mounts in other files). `jsspector ir` prints the IR and call graph.

### Measuring

`cargo xtask replay` scores `scan` against the verified CVE-replay pairs in [`corpus/research/`](corpus/research/): a finding of the advisory's class must have its sink in the advisory's file (nearest to its line) at the vulnerable commit, and that finding's line-independent key must be gone at the fix. Repositories are fetched blobless and sparse; nothing in them is run.

Latest measurements (2026-11-01, static reading only):

| What | Result |
|---|---|
| Route recall vs the project's own OpenAPI spec: immich (NestJS) | 245/245 operations (100%); 99.2% of our operations are in the spec |
| Route recall vs spec: NodeBB (Express + route helpers and a table of route modules) | 152/153 with the plugin-remountable mounts (`admin`, `tags`, `groups`), named at run time, as path parameters (`/api/{mount}/uploadlogo`); 106/153 against the spec's literal mount names. The miss is in the spec but registered nowhere in the code |
| socket.io events, uptime-kuma server | 71/71 |
| Electron `ipcMain` channels, OpenWhispr | 558/575 (97%) |
| CVE replay, covered classes | 21/69 detected (path traversal 9/15, command injection 3/4, XSS 3/15, prototype pollution 3/8, NoSQL 2/3, SQL 1/10), 15/21 cleared at the fix |
| 100-repo corpus | 35,765 files in about 107 s, 0 panics, identical output at 1 and 10 threads; 158 HIGH/CRITICAL candidates, including both hand-confirmed true positives |

`cargo xtask corpus --list FILE` fetches a list of repositories (`owner/name@commit`, shallow and sparse; nothing in them is run), scans each one and writes per-repository reports, a `summary.json` and a table; it fails if the scanner crashes or panics on any file. [`.satori.yml`](.satori.yml) runs the same job on Satori with the list given as input (`-d CORPUS="..."`), so the corpus list never has to be committed. Keep those runs private: HEAD findings may be undisclosed vulnerabilities.

The n8n public API is defined by its OpenAPI document (`express-openapi-validator` wires operations to handlers), so it has no route registrations to extract; its internal `@RestController` API (263 routes) is inventoried with each route's authentication.

## What it will do (the plan)

- **Entry-point inventory.** JSSpector lists every way input reaches an app: method, full path with mount prefixes, handler, middleware and auth status, and the request inputs read.
  - It covers HTTP routes plus non-HTTP entry points: socket.io/ws events, GraphQL resolvers, tRPC procedures, queue consumers, CLI/env, Electron IPC and client-side DOM sources.
  - The inventory is exported as JSON and **OpenAPI 3.1**.
- **Attack-path findings.** Inter-procedural, cross-file taint analysis runs from those entry points to sinks.
  - Sink classes include command and code injection, SQL/NoSQL injection, path traversal, SSRF, prototype pollution, SSTI and XSS.
  - Every finding comes with a full witness path (SARIF `codeFlows`) and a severity that accounts for reachability, i.e. whether an unauthenticated user can reach it.
- **Data-driven framework knowledge.** Express, Koa, Fastify, NestJS, Next.js, socket.io and others are described in YAML *packs*. The packs use CodeQL Models-as-Data style access paths; the engine itself contains no framework names.

## How it is built

- A single native binary in **Rust**, built on [oxc](https://github.com/oxc-project/oxc) for parsing, semantic analysis and module resolution.
- Per-file facts are lowered to an owned IR and then solved globally.
- **One value-flow core serves both route extraction and taint.** Routes come from instantiating symbolic function summaries, which is how JSSpector resolves routes registered through helpers, route tables, wrappers, decorator registries and filesystem conventions.
- Output is deterministic and line-independent fingerprints are used for baselines. Instead of silently dropping anything, JSSpector reports explicit diagnostics.

## How it is measured

JSSpector is developed against **about 100 widely used, real-world JS/TS repositories**, worked through in batches of 10, plus a holdout set. It is scored by **CVE replay**:
1. For each published critical/high advisory, scan the commit before the fix: the vulnerability must be found.
2. Scan the fix commit: the finding must be gone.

Route extraction is scored against OpenAPI specs that the projects commit themselves. No apps are executed; everything is static. The seed research is in [`corpus/research/`](corpus/research/).

## Responsible use

Scanning real projects at HEAD can surface undisclosed vulnerabilities. Those findings are never published in this repository; they go through coordinated disclosure. See [`SECURITY.md`](SECURITY.md).

## License

Apache License 2.0. See [`LICENSE`](LICENSE).

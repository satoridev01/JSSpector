# JSSpector

**JSSpector** is a static analyzer (SAST) for JavaScript and TypeScript. It finds **high and critical vulnerabilities by chaining attack paths through the code**: from an entry point, through data flow across functions and files, to a dangerous sink.

> **Status: pre-alpha.** `jsspector scan` (taint findings) and `jsspector routes` (entry-point inventory, OpenAPI 3.1) work today. Framework knowledge lives in YAML packs ([`packs/`](packs/)); the engine lowers each file to an owned IR, links modules across files (relative imports, monorepo workspace packages, barrels) and follows values through function summaries. See [`docs/PLAN.md`](docs/PLAN.md) for the roadmap.

## Quick start

```sh
cargo install --git https://github.com/satoridev01/JSSpector --locked jsspector
jsspector scan path/to/repo
```

```
  routes/files.js
  ❯❯❱ jsspector.path-traversal [HIGH]
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

Each finding shows the sink, then every step from the source to it, across files, with the code line of each step.

| Option | Meaning |
|---|---|
| `--min-severity critical\|high\|medium\|low` | Lowest severity reported (default `high`) |
| `--json` | Full JSON report: findings with traces, skipped files, line-independent keys |
| `--include tests,examples,docs,generated,vendor\|all` | Also scan these file classes (source files always are) |
| `--threads N` | Worker threads (default: all cores) |

The output is byte-identical for any thread count. A file that cannot be parsed is reported as skipped, never a crash.

### Entry points

```sh
jsspector routes path/to/repo            # table: method, full path, auth, handler, file:line, inputs
jsspector routes --json path/to/repo
jsspector routes --openapi path/to/repo  # OpenAPI 3.1 of the HTTP routes
```

Routes are followed through router mounts across files (`app.use('/api', require('./routes/users'))`), route tables and registration helpers. Covered: Express/Koa/Hono/Fastify routers, `fastify.route`, NestJS controllers, Next.js `app/**/route.ts` and `pages/api`, raw `http.createServer`, socket.io events, Electron IPC, GraphQL resolver maps, tRPC procedures and queue processors.

### What `scan` covers

- **Sources:** Express/Fastify/Koa/Hono/Next.js/NestJS request data (and helpers that take the request), socket.io events (including `onAny` and connection sockets), Meteor methods, Electron `ipcMain`, `postMessage` and extension messages, GraphQL `args`, tRPC `input`, job payloads, archive entry names, browser URL sources (`location`, `document.referrer`, `window.name`), React props (medium), `process.argv` (low).
- **Sinks:** command and code injection (`child_process` incl. `shell: true` and argument injection, `eval`, `Function`, `vm`, `executeJavaScript`, `shell.openExternal`), SQL built from text, NoSQL operator injection (object-capable values in queries), path traversal, SSRF (attacker-chosen URL start), XSS (`innerHTML`, jQuery, `document.write`, `dangerouslySetInnerHTML`, navigation to `javascript:`), prototype pollution (`o[k1][k2] = v`, deep-set helpers).
- **Flow:** assignments, destructuring, templates, string methods, array callbacks, object fields (field by field), instance fields across methods, return values and parameter-to-sink summaries, followed across files (up to 4 hops) through relative imports, workspace packages, barrels and constructor injection.
- **Guards:** validation that exits (`if (!/^\w+$/.test(x)) return`), allowlists, `startsWith` containment, comparisons with constants, `typeof`/`check()` type checks (NoSQL), validators and escapers listed in packs.
- **Auth:** each finding carries `auth` (`none-detected`, `user`, `admin`) from route middleware, `router.use`, guard decorators and in-handler checks; admin-only paths are one level lower.
- **Output:** grouped by sink file with every step from source to sink; `--json` adds stable fingerprints for baselines.

### Packs

Every framework or library fact is data in [`packs/*.yaml`](packs/) (sources, sinks with argument rules, propagators, sanitizers, guards, route conventions, auth patterns). `cargo xtask ci` fails if the engine repeats a name a pack lists.

### Measuring

`cargo xtask replay` scores `scan` against the verified CVE-replay pairs in [`corpus/research/`](corpus/research/): the advisory's sink must be found at the vulnerable commit and gone at the fix. Repositories are fetched blobless and sparse; nothing in them is run.

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

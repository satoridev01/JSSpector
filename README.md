# JSSpector

**JSSpector** is a static analyzer (SAST) for JavaScript and TypeScript. It finds **high and critical vulnerabilities by chaining attack paths through the code**: from an entry point, through data flow across functions and files, to a dangerous sink.

> **Status: pre-alpha.** `jsspector scan` v0 works today: a heuristic taint scan with same-file and cross-file (relative import) summaries. The full engine (owned IR, module linker, YAML packs, entry-point inventory) is planned in [`docs/PLAN.md`](docs/PLAN.md).

## Quick start

```sh
cargo install --git https://github.com/satoridev01/JSSpector --locked jsspector
jsspector scan path/to/repo
```

```
  routes/files.js
  ❯❯❱ jsspector.path-traversal [HIGH]
          Data from `req.query` (http) is used as a file path without confinement.
          in GET /invoice, auth: unknown

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

### What `scan` v0 covers

- **Sources:** Express/Fastify/Koa/Hono/Next.js/NestJS request data, socket.io events, Meteor methods, Electron `ipcMain` handlers, `postMessage` and browser-extension messages, archive entry names, `process.argv` (always low).
- **Sinks:** command and code injection (`child_process`, `eval`, `Function`, `vm`, `shell.openExternal`), SQL built by concatenation or templates, path traversal (`fs`, `res.sendFile`), SSRF (the URL start is controlled), XSS (`innerHTML`, jQuery HTML), prototype pollution (`obj[k1][k2] = v`).
- **Flow:** assignments, destructuring, templates, concatenation, string pass-through methods, `path.join`. Calls into named functions are followed two levels deep, in the same file or through a relative import.
- **Known limits:** validation guards (regex, allowlists, `startsWith`) are not recognized; an object holding one tainted field is tainted as a whole; auth is always `unknown`. Every finding needs a human read.
- **Debt:** sources and sinks are hard-coded in `crates/jss-frontend/src/taint/models.rs` until YAML packs exist.

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

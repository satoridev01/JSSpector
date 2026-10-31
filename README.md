# JSSpector

**JSSpector** is a static analyzer (SAST) for JavaScript and TypeScript. It finds **high and critical vulnerabilities by chaining attack paths through the code**: from an entry point, through data flow across functions and files, to a dangerous sink.

> **Status: pre-alpha.** The design is agreed and implementation is starting. See [`docs/PLAN.md`](docs/PLAN.md).

## What it does

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

# JSSpector — implementation plan

## Context

**What we're building.** JSSpector is a static analyzer for JavaScript/TypeScript. It finds **HIGH and CRITICAL** vulnerabilities by **chaining attack paths through the code**: entry point → data flow across functions and files → dangerous sink. The entry-point inventory (HTTP routes, non-HTTP entries, client-side sources) is a first-class output (JSON + OpenAPI 3.1) and is also the taint engine's source model. The repo is greenfield: `github.com/satoridev01/JSSpector` (public), with local clone `/Users/fear/repos/JSSpector` holding only `.git`.

**Why this design.**
- PySpector (same ecosystem, Rust core) is our prior art. We copy what worked and avoid the flaws we verified in its code.
- A census of 12 real repos showed that **75–95% of routes are not literal `app.get('/x')` calls**. They come from project helpers, router classes plus route tables, wrappers, decorator registries, config objects and filesystem conventions. Route extraction therefore has to run on the same inter-procedural value-flow engine as taint, not on pattern matching.

**Decisions made by fear:**
- Core in **Rust + oxc**, as a single native binary.
- v1 scope: server HTTP routes, **non-HTTP entry points**, **client-side JS**, and **OpenAPI export**.
- **Purely static**: no booting apps and no Docker oracles.
- **No deliberately vulnerable training apps** (no juice-shop, DVNA, NodeGoat, dvws-node). The corpus is widely used, real-world JS/TS software only.
- **Corpus: about 100 repos, debugged in 10 batches of 10.** Ten repos alone won't surface enough real HIGH/CRITICAL findings. Batches run locally first; Satori handles full-corpus runs later.
- **Ground truth = "CVE replay"**: for each repo's published critical/high advisories, scan the vulnerable commit (the fix commit's parent) and expect a finding at the sink; scan the fix commit and expect none. Route ground truth = OpenAPI specs committed in the repos (immich, NodeBB, n8n public API).

## Plan at a glance

1. **Single Rust + oxc binary.**
   - oxc is confined to one crate (`jss-frontend`).
   - Per-file owned IR feeds a global solve.
   - Deterministic, panic-free, and every drop or cap is reported as a diagnostic.
2. **One value-flow core for routes and taint.** Symbolic, effect-carrying function summaries mean **route extraction is summary instantiation**. That covers helpers, route tables, wrappers, decorator registries and filesystem conventions, which together are 75–95% of real routes.
3. **All framework knowledge lives in YAML packs.**
   - Access paths compatible with CodeQL Models-as-Data.
   - Exact matching on import identity.
   - No pattern-only rules.
4. **Taint engine:**
   - Taint = provenance + a per-class sanitizer mask; access paths with k = 3.
   - Parametric summaries; SCC fixpoint that re-queues callers.
   - Every finding carries a **witness path from an entry point (route + auth status) to the sink**.
   - Severity is driven by reachability: unauthenticated adds +1.
5. **Outputs:**
   - Entry-point inventory as JSON + **OpenAPI 3.1**.
   - Findings as JSON or SARIF with codeFlows.
   - Line-independent fingerprints; exit codes.
6. **Measurement = CVE replay** on 100 real repos in 10 batches, plus 10 holdout repos.
   - An advisory counts as detected at `fix^1` and cleared at the fix commit.
   - Route recall is measured against committed specs.
   - 84 verified replay pairs are already seeded.
7. **Delivery:**
   - M0–M5 over about 15 weeks, at most 1 week per batch; misses decide what gets built next.
   - Satori takes the full-corpus runs from about batch 3–4.
   - HEAD findings stay private, with coordinated disclosure.

## PySpector lessons → JSSpector decisions

| PySpector (verified in its code) | JSSpector decision |
|---|---|
| ✅ Provenance lattice (HttpRequest / OperatorConfig / Developer / System + sanitized variants); sinks declare `triggers_on` | Copy, but represent taint as **origin + a bitmask of cleared vulnerability classes**. In PySpector, Html/SqlSanitized actually clear every sink (code contradicts docs). |
| ✅ Function summaries + global fixpoint, rayon-parallel | Copy, done properly: summaries keyed by a **resolved FunctionId**, SCC-ordered bottom-up, **callers re-queued** when a callee summary changes, caps reported. PySpector never populates `param_flows_to_return` and looks summaries up by `ends_with("::name")`. |
| ✅ Cheap per-file source-marker prefilter (~80% skipped) | Copy, but derive markers from the models (no drifting hardcoded list) and apply it at every repo size. |
| ✅ Exclude tests/docs/examples as entry points | Copy, defined in **one** place (PySpector has 5), overridable per corpus entry. |
| ✅ Satori playbook with negative assertions on real repos; 8 repos × 5 runs benchmark | Copy for the cloud phase (after local). |
| ✅ TP/FP paired tests; per-rule confirmed-TP evidence | Copy, and add inter-procedural and cross-file tests (PySpector has none) plus a confirmed-TP ledger checked in. |
| ❌ Bare-name call resolution; IDs `file::name` (methods collide); name-keyed call-site taint | Resolve calls with **oxc_semantic symbols + oxc_resolver + our export linker**. Use a field-based fallback only at low confidence, and always report it. |
| ❌ One namespace for vars/attrs/callees; field-insensitive | **Access paths** (`req.body.user.id`), k-limited. |
| ❌ Two-way substring matching of model names | Models match on **resolved import identity + CodeQL-style access paths** (`[child_process, "Member[exec,execSync].Argument[0]"]`), never on substrings. |
| ❌ Framework knowledge split across ~10 Rust const lists + TOML | **All** framework/library knowledge lives in data model packs. The core holds zero framework names, enforced by a CI grep. |
| ❌ Python→JSON AST→Rust handoff (3 cache layers + process pool) | Parse and analyze in one process; per-file facts are owned and serializable, cached by content hash. |
| ❌ CFG ignores try/catch/finally; branch sanitizers ignored; no destructuring; `await` not unwrapped | Use oxc's CFG (or our own over our IR) with exceptions, short-circuit evaluation and destructuring lowering. `await`/promises are first-class. |
| ❌ Silent drops, silent caps, `unwrap` panics, non-UTF-8 path panic | Per-file isolation; every drop or cap becomes a **diagnostic** in the output; no panics in release builds. |
| ❌ Fingerprint = sha1(rule\|abs path\|line\|code); no exit code; HashMap output order; no column or trace | Line-independent fingerprints; deterministic sorted output; exit codes; every finding carries a full **witness path** (SARIF `codeFlows`). |
| ❌ 142 noisy rules deleted in one PR; regex secret scanners | Ship only HIGH/CRITICAL taint sink classes, each with fixture plus corpus evidence. Leave secrets and linting to existing tools (Satori already has trufflehog/semgrep playbooks). |
| ❌ No endpoint inventory output at all | The entry-point inventory is **deliverable #1**. |

## Architecture

**Approach.**
- The **target design** below is the whole system. It is **delivered in stages**: build the thinnest route→sink slice first, then add only what the current batch's misses demand.
- Four things are fixed from day 1, so later stages never force a rewrite:
  1. Per-file **facts and IR** feed a **global solve**.
  2. **One value-flow core** serves both routes and taint.
  3. Every heuristic carries a **confidence** and every failure a **reason code**.
  4. **Versioned output and line-independent fingerprints**.

### Workspace (start with few crates; isolate oxc)
```
Cargo.toml                 # workspace; version lives only here; Cargo.lock committed
rust-toolchain.toml        # Rust ≥ 1.97 (oxc 0.156 MSRV, edition 2024)
crates/jss-frontend/       # ONLY crate that depends on oxc (=0.156.0): parse, semantic, lower → IR, LineIndex
crates/jss-core/           # modules: ir, resolve (oxc_resolver =11.24.3), link, flow, summaries,
                           #          taint, entry, chain, models, report
crates/jsspector/          # CLI (clap): routes | scan | explain
xtask/                     # corpus harness: import|verify|fetch|run|score|triage|misses|diff
packs/<name>/pack.yaml     # ALL framework/library knowledge (YAML, CodeQL MaD-style); embedded + --packs DIR
packs/<name>/tests/        # golden tests per pack: <case>/{app/, expected.json}
schema/                    # JSON Schemas for output, packs and .jsspector.yml
fixtures/<idiom>/          # our own mini-apps with inline // @route / @expect / @safe annotations
corpus/{repos,anchors.lock.json,baselines,reports}/
```
- Split `jss-core` into separate crates only when compile times demand it.

**Critical files to create first:**
- `Cargo.toml`, `rust-toolchain.toml`, `.github/workflows/ci.yml` (fmt, clippy deny-lints, tests on macOS + Linux, cargo-deny, determinism check).
- `crates/jss-frontend/src/{parse.rs, lower.rs, line_index.rs}`.
- `crates/jss-core/src/{ir.rs, link/{cjs.rs, workspace_fs.rs}, summaries.rs, taint.rs, entry/{effects.rs, guards.rs}, chain.rs, report/{json.rs, sarif.rs, openapi.rs}}`.
- `packs/{core,node,express,koa,socket.io}/pack.yaml` + golden tests.
- `schema/{entrypoint,finding,pack}.schema.json`.
- `xtask/src/corpus.rs`; `corpus/repos/NodeBB__NodeBB.toml` (the template).
- `corpus/research/{cve-replay-seed.json, candidate-pool.json}`: the verified seed pairs and the 148-candidate pool, saved on day 1 from this planning session's research output.

**What we reuse:**
- oxc_parser / oxc_semantic / oxc_resolver, pinned exactly.
- CodeQL's JS Models-as-Data rows (MIT, with attribution) as the starting sink and summary set.
- PySpector patterns, **reimplemented, not copied**:
  - the provenance lattice and `triggers_on` (`src/pyspector/_rust_core/src/analysis/taint_analysis.rs` lines 13–90 and 1312–1336);
  - the `.satori.yml` negative-assertion playbook;
  - the `benchmarks/speed/benchmark.sh` 5-run-median methodology.
- Keeping oxc in one crate limits the blast radius of its roughly weekly breaking releases (0.149 → 0.156 took seven weeks).

### Pipeline
1. **Discover** files, sorted and contained to the root. One path classifier labels each file test, docs, example, generated, minified, vendor or source.
2. **Frontend, in parallel** (rayon; one oxc `Allocator` per thread, reset per file): parse + semantic → owned, serde, lifetime-free `FileFacts`. These hold imports/exports, classes, a lowered `FuncIr` per function and diagnostics. They are cached by blake3 over (bytes, source type, options, IR version).
3. **Link:**
   - ESM, plus a **CommonJS model** built by us: each CJS body lowers to Node's wrapper function, and the module's value is `module.exports` at the end.
   - Compiled-TS interop: `__exportStar`, `defineProperty` getters, `__importDefault`.
   - TS paths via `resolve_file` with tsconfig set to Auto.
   - Workspaces without `node_modules`, through an overlay `FileSystem` that fakes `node_modules/<pkg>` symlinks, plus outDir→rootDir remapping.
   - Dynamic `require` becomes a glob over known files, capped at 64 matches and reported.
   - Unresolved bare specifiers become `External{pkg, subpath}` API roots. Models key on these exactly, never by substring.
4. **Value flow and call graph:**
   - Binding resolution comes from oxc `Scoping` plus the linker, then classes/prototypes/`this`/`super`, object-literal method maps, and `new X()` instances.
   - DI: TS constructor parameter types, and `Container.get(C)` → a singleton instance.
   - Event emitters are keyed by (emitter, constant event).
   - Later, when misses show unresolved callees dominating (expected with DI frameworks), this grows into Andersen-style points-to.
   - **ACG fallback** (Feldthaus et al., ICSE'13): used only when 4 or fewer candidate functions exist. Such edges are tagged `FieldBased`, capped at Medium confidence and counted.
5. **Bottom-up symbolic summaries:**
   - Order: Tarjan SCCs, callees first, run in parallel as their dependencies finish.
   - **Callers are re-queued whenever a callee's summary changes.**
   - Closures carry symbolic captures. Calls through parameters or captures become **call ports** that each caller fills in.
   - Loops over finite constant arrays are enumerated element by element.
   - Summaries also record **effects**: `Register{recv, method, path, handlers}`, `Mount{recv, prefix, child, mw}`, `Listen{emitter, event, cb}`, `ChannelWrite`, `HttpCall`, `Provide`. **Route extraction is just summary instantiation.** That is what resolves NodeBB `setupApiRoute`, parse-server route tables plus the `app[method]` loop, Ghost `http()`/`lazyUse`, n8n's decorator registry, and handler factories.
6. **Top-down instantiation** from entry roots produces the entry-point inventory, per-entry taint and channel joins.
7. **Witness paths, severity, reports.**

### IR (owned; operands are access paths; separate namespaces fix PySpector's single shared namespace)
```rust
pub struct Place { base: Base, path: SmallVec<[Key; 2]> }
pub enum Base  { Var(VarId), This, Capture(u16), ModVar(u32), Import(u32), Global(Atom) }
pub enum Key   { Name(Atom), Index(u32), Dyn(VarId), Any }
pub enum Instr { Assign{dst: Place, src: Operand}, Concat{dst, parts}, Op{dst, op, args},
                 Call{dst, callee: Callee, this: Operand, args: Vec<Arg>, kind: CallKind, site},
                 Alloc{dst, what: AllocKind, site}, Require{dst, spec: SpecExpr, site}, Await{dst, src} }
pub enum Term  { Goto(B), Branch{cond, t, f}, Return(Op), Throw(Op), Finally{exits}, Unreachable }
// every Block has `handler: Option<BlockId>`: exceptional edges for try/catch/finally
```

How constructs lower:
- **Destructuring** becomes one assignment per leaf: `{body:{name}} = p0` becomes `name = p0.body.name`.
- **Optional chaining** becomes a nullish branch.
- **`&&`, `||`, `??` and `?:`** become real blocks, so branch sanitizers and guards are visible to the analysis.
- **Template literals** become `Concat`. **Tagged templates** become `Call{Tagged}`, so `` sql`…` `` can be modeled as safe.
- **`await`** becomes `Await`.
- **Closures** get explicit captures; captured bindings that are also mutated become heap cells.
- **Classes:** each method, getter, setter and static becomes a `FuncIr`, and the class records its constructor parameter types.
- **Decorators** become calls and are also recorded as facts.
- **`finally`** fans out to every exit.
- Lowering matches the AST **exhaustively**, so a new oxc node kind fails the build instead of being silently skipped.

### Taint engine (Pysa-style: sources propagate forward, sinks backward)
- **Labels:** `Label{prov, clean: VulnMask}`.
  - `prov` is one of HttpRequest, ExternalMsg, DomUntrusted, Stored(channel), OperatorConfig, Developer or System.
  - A sanitizer **sets the bit for its class** in `clean`: escape-html clears XSS, `path.basename` clears traversal, `Number`/`parseInt` clear every string-injection class.
  - A sink fires only if `prov` is in its `triggers` set and its class bit is not set. This fixes PySpector, where sanitizers clear every sink regardless of class.
- **Access paths:** k = 3, then collapse.
- **Parametric summaries:** `sink_reach`, `tito` (taint in, taint out), `gen`, `ret`, `effects`. Shared helpers don't mix taint across their callers.
- **Source roles are assigned at instantiation.** For example, an Express handler's `Param(0)` is a Request: `.body/.query/.params/.headers/.cookies` are sources, `.user` is not. Each handler is analyzed once and checked per entry point.
- **Guards** (anchored-regex `.test`, allowlist `.includes`, validator functions) refine the true branch.
- **Caps and widening:**
  - SCC iterations: 50.
  - Facts per function: 4k.
  - Access-path width: 32.
  - Every cap hit becomes a **diagnostic** and lowers confidence. Nothing is dropped silently.
- **Prefilter:** only functions reachable from entry handlers or source-bearing functions are analyzed, plus a per-file marker bitset derived from the models. Output reports "analyzed X of Y functions".

### Attack-path chaining and severity
- **Witness:** steps of kind Source, Assign, Arg, Return, Store, Load, Sanitizer, ChanWrite, ChanRead or Sink, each with file, line, UTF-16 column and function. Ties are broken deterministically.
- **Entry points** are linked to findings, with **auth status** computed from:
  - middleware order;
  - models (passport, express-jwt, Nest guards, n8n `skipAuth`, Next.js wrappers such as `withSession`);
  - name-based guesses, at low confidence only.
- **Severity = class base × reachability × provenance × confidence:**
  - **Critical** base: code execution, command injection, deserialization.
  - **High** base: SQL/NoSQL injection, SSRF on a full URL, XXE, traversal on writes.
  - Reachable unauthenticated: **+1** (capped at Critical). Authenticated: ±0. Admin-only: −1.
  - No linked entry point: −1 and flagged. `unknown` auth: ±0 and flagged.
  - OperatorConfig provenance caps at Low.
  - Low confidence is never shown as High or Critical by default.
  - **Default output: HIGH and above.**
- **Second-order flows (v1: one hop).** `ChannelWrite` effects cover ORM model fields (Sequelize, Mongoose, Prisma, TypeORM) and constant cache keys. Reads produce `Stored(ch)` taint. The witness spans both the writing entry point and the reading one.
- **Full-stack links (v1):**
  - Client `HttpCall`s (fetch, axios with `baseURL`, Angular `HttpClient`) are matched to server routes segment by segment, for the inventory and for coverage.
  - DOM sources (location, postMessage) flowing to DOM sinks are covered.
  - Server-response→DOM chains come in **v1.1**.

### Robustness and determinism
- **Panics:**
  - Build with `panic = "unwind"`, and wrap each file and each function in `catch_unwind`; a failing function gets an "unknown" summary.
  - Lints deny `unwrap`, `expect`, `panic` and indexing.
  - oxc's `reference_id()`/`symbol_id()` accessors panic on `None`, so we read the cells with `.get()`.
- **Stack overflow can't be caught** (oxc#21953), so:
  - rayon worker stacks of 256 MiB;
  - a nesting-depth prescan that skips files deeper than 2k.
- **Skipped files, each with a diagnostic:**
  - files over 2 MiB;
  - minified files (a line over 20k characters, or an average line over 300);
  - generated files (`@generated`, `.d.ts`, `dist/`).
- **Paths:**
  - Non-UTF-8 paths are kept as `OsString`.
  - No symlinks are followed out of the root.
  - Resolver results outside the root become `External`.
- **Determinism:**
  - clippy `disallowed_types` bans std `HashMap`/`HashSet`.
  - Every parallel result is sorted.
  - IDs are derived from content.
  - CI checks that output is **byte-identical at 1 and 10 threads**.
- **Fingerprint:** blake3 over (rule, relative path, enclosing function's qualified name, sink API + argument index, source API, entry route key, ordinal). It contains **no line numbers or absolute paths** and goes into SARIF `partialFingerprints`.
- **Exit codes:** 0 clean / 1 findings at or above `--fail-on` that aren't in the baseline / 2 usage or config error / 3 engine error or incomplete analysis.
- **Performance targets** (n8n backend, about 27 MB of source, 10 cores):
  - Frontend: ≤3 s cold, ≤0.5 s warm.
  - Link + flow: ≤4 s.
  - Summaries + instantiation: ≤15 s.
  - **Total: ≤25 s, at most 4 GB RSS.**
  - Measured with a `--stats` JSON, hyperfine and samply; mimalloc as the allocator.

### oxc 0.156 facts we design around (checked against source)
- **Parsing:**
  - `ParserReturn.fatal_error` means an empty program, which we report as a ParseFailed diagnostic. Files with recovered errors are still analyzed, at lower confidence.
  - `SourceType::from_path` doesn't enable JSX for `.js` and fails on non-UTF-8 names, so we build SourceType from the extension plus package.json `"type"`.
- **Semantic:**
  - `with_cfg` needs the `cfg` feature, and oxc_cfg is statement-level with no optional chaining, so we build our own expression-level CFG during lowering.
  - `ModuleRecord` is ESM-only, so the CommonJS model is ours.
  - There is no line/column API, so we write our own `LineIndex`, which also produces UTF-16 columns for SARIF.
- **oxc_resolver:**
  - Set `node_path:false` and `yarn_pnp:false`, so results don't depend on the environment.
  - Add `extension_alias` mapping `.js` to `[.ts, .tsx, .js]`, and conditions `[node, import, require, default]`.

## Model packs and entry points (all framework knowledge is data)

**Pack format: YAML.**
- **Layout:** `packs/<name>/pack.yaml`, plus golden tests in `packs/<name>/tests/<case>/{app/,expected.json}`. Packs are embedded with `include_str!` and extended with `--packs DIR`.
- **Strict schema:** strict serde (`deny_unknown_fields`) and a published JSON Schema.
- **CI check:** fails if a module name declared by a pack appears as a string literal in `crates/**/*.rs`.
- **Why YAML over TOML:**
  - Entry semantics are nested: argument slots, path rules, schema tables.
  - YAML rows are compatible with **CodeQL Models-as-Data**, whose MIT-licensed JS sink/summary rows we can import with attribution.
- **Access paths** use the MaD tokens: `Member`, `Argument[0..]`, `Argument[N-1]`, `Parameter`, `ReturnValue`, `Awaited`, `Instance`, `ArrayElement`, `AnyMember`, `Fuzzy`, `WithStringArgument`, `Decorated*`. We add `Exported[n]`, `JsxAttr[n]`, `WithArgument[i=v]` and `A|B`.
- **Matching** is by resolved import identity, decorators included: `@Body`, `@Body()` and aliased imports all match, and `@mock.patch` can never become a route.
- **Precedence:** a pack row overrides inference for the API it names. Everything else, including workspace packages, is summarized from source.
- **No pattern-only rules in v1:** every finding starts at an entry point.

```yaml
# packs/core/classes.yaml: provenance lattice + vulnerability classes (PySpector's idea, fixed)
provenance: {HttpRequest: {attacker: true}, ClientURL: {attacker: true}, ClientMessage: {attacker: true},
  RendererIPC: {attacker: true, severity_delta: -1}, ChannelMessage: {inherit: producer},
  OperatorConfig: {attacker: false}, DeveloperDefined: {attacker: false}, SystemGenerated: {attacker: false}}
classes: {command-injection: {cwe: CWE-78, base: critical}, code-injection: {cwe: CWE-94, base: critical},
  sql-injection: {cwe: CWE-89, base: high}, path-traversal: {cwe: CWE-22, base: high}, ssrf: {cwe: CWE-918, base: high}}
# packs/node/pack.yaml: MaD rows [package, access path, class | effect]
sinks:      [[child_process, "Member[exec,execSync].Argument[0]", command-injection]]
sanitizers: [[shell-quote, "Member[quote].ReturnValue", {clears: [command-injection]}]]
```
```yaml
# packs/express/pack.yaml (abridged)
types: {express.App: [[express, ReturnValue]], express.Router: [[express, "Member[Router].ReturnValue"]]}
routers:
  "express.App|express.Router":
    register: {member: "get,post,put,patch,delete,options,head,all", method: member,
               path: "Argument[0]", handlers: "Argument[1..]", returns: this}
    use:      {member: use, path: {arg: 0, optional: true}, targets: "Argument[0..]"}   # router ⇒ Mount, fn ⇒ ordered Use
    route_object: {member: route, path: "Argument[0]", returns: express.Route}
handler: {params: [req, res, next], request: express.Request}
request:
  express.Request:
    provenance: HttpRequest
    inputs: [{path: "Member[body]", in: body}, {path: "Member[query]", in: query}, {path: "Member[params]", in: path},
             {path: "Member[headers]", in: header}, {path: "Member[get,header]", in: header, name: "Argument[0]"},
             {path: "Member[cookies,signedCookies]", in: cookie}, {path: "Member[file,files]", in: body}]
```
```yaml
# packs/nestjs (decorators) + packs/nextjs (filesystem convention), abridged
decorators:
  controller: {at: ["@nestjs/common", "Member[Controller]"], prefix: "Argument[0] | Argument[0].Member[path]"}
  route:   {at: ["@nestjs/common", "Member[Get,Post,Put,Patch,Delete,Options,Head,All]"], method: member, path: "Argument[0]"}
  params:  [{at: ["@nestjs/common", "Member[Body]"], in: body, name: "Argument[0]", schema: declared-type}]
  compose: [["@nestjs/common", "Member[applyDecorators]"]]      # immich @Authenticated()
app: {global_prefix: {member: setGlobalPrefix, value: "Argument[0]", exclude: "Argument[1].Member[exclude]"}}
conventions:
  - kind: http.route
    roots: [app, src/app]
    file: "**/route.{ts,tsx,js,jsx,mjs}"
    exports: {GET: GET, POST: POST, PUT: PUT, PATCH: PATCH, DELETE: DELETE}      # incl. `export {h as GET}`
    segments: [{re: '^\(.+\)$', to: ''}, {re: '^\[\.\.\.([^\]]+)\]$', to: '{$1}', catchall: true}, {re: '^\[([^\]]+)\]$', to: '{$1}'}]
```

**Route extraction semantics (generic, built on the value-flow core).**
- **Router values:** pack `types` tag allocation sites as router values. They flow through fields, returns, exports and closures like any other value.
- **Ordered effects:** a registrar call appends an effect to its receiver's log: `Route(methods, path, handlers)`, `Use`, `Mount(prefix, child)`, `Param`, `Prefix`, `Hook`, `Entry(kind, name, handler)`, `Produce/Consume(channel)`.
- **Symbolic strings:** paths and methods are literals plus `Env(name, default)`, `Config(key, default)` and `Unknown(site)`.
- **Summaries carry effects,** input reads and **transparent-wrapper** mappings. Effects are instantiated in the caller's CFG order, so middleware order survives helper functions.
- **Bounded unrolling** (K ≤ 256) runs over finite collections: `for..of`, `forEach/map/reduce`, `Object.keys/entries`, Map/Set.
- **Computed members** (`router[verb]`, `app[m].call(app, …)`) expand once per constant key. `call`/`apply`/`bind` are handled as language semantics.
- **Tainted-key dispatch:** `obj[k]()`, or `split('.')` plus a walk over a known object, expands to one entry per reachable function (depth ≤ 3) and flags a CWE-470 candidate. This is how NodeBB's 141 socket RPC handlers become entry points.
- **Decorators** desugar to calls (legacy and stage-3). `Container.get(C)` gives a DI singleton.
- **Graph assembly:**
  - Roots are `serve` sites, convention files, and unmounted app objects reachable from package.json `main`/`bin`/`scripts`.
  - A route's middleware chain is the earlier `Use` effects with a matching prefix, plus every handler but the last.
  - Code unreachable from any root is **orphaned** and is not an entry point.

| Census idiom | Generic mechanism | Small pack |
|---|---|---|
| NodeBB `setupApiRoute(router, verb, path, mws, ctrl)`: rest params, `/api${path}` twins | parametric effect summaries | none |
| NodeBB socket RPC (141 handlers) | `onAny` entry, template-`require` unrolling, tainted-key dispatch | socket.io |
| parse-server PromiseRouter tables + `expressApp[m.toLowerCase()]` loop | heap route records, `forEach` unrolling, computed members | `X-Parse-*` header rows |
| Ghost `lazyUse` + `http(api.posts.browse)`, 6–7 mount hops | summaries of functions assigned onto the app; getter-lazy-require; pipeline summary | express-lazy-router, @tryghost/api-framework adapter |
| Strapi config routes + `createCoreRouter(uid)` | filesystem convention, `'ctrl.action'` handler resolution, CRUD template from `schema.json` | strapi |
| n8n `@RestController/@Get` registry → `router[route.method]` | decorator desugaring, DI singleton, Map unrolling | @n8n/decorators (+`@Env` defaults) until heap precision is enough |
| dub `export const GET = withWorkspace(h)` | Next.js convention + wrapper mapping | nextjs |
| immich NestJS `@Authenticated`/`applyDecorators`; uptime-kuma `prefix + "join"` | decorators, constant folding | nestjs, socket.io |

**Unresolved parts are explicit, never dropped.**
- Symbolic prefixes such as `${env.N8N_ENDPOINT_REST:-rest}`, `${config.relative_path:-}` and `${config.mountPath:-/parse}`.
- `{dynamic}` segments and `handler.resolved=false`.
- Routers with no resolved mount, listed under `{unmounted}`.
- Plugin hooks (NodeBB `static:api.routes`) as `extension_point` records.

Confidence levels, each with `reasons[]`:
- **high:** all parts constant and the handler resolved.
- **medium:** env/config symbols with defaults, or a fallback pack.
- **low:** `{dynamic}` parts, an unresolved handler or mount, or K exceeded.

**Inputs.**
- Reads of the request role become `(in, name)` pairs: member chains, destructuring, constant keys, and reads inside callees through summaries.
- Whole-object uses (`User.create(req.body)`) record `name:"*"`, the mass-assignment case.
- Schema tables interpret zod (including `createZodDto` and `Z.class`), joi/celebrate, express-validator, class-validator, TypeBox/fastify schema, and Ghost's `options/data` arrays.
- A field becomes **TypeConstrained**, which injection classes ignore, only when the schema is actually *enforced* (framework validation, zod `parse` output, or a guard-proven validator) and the field is typed int, bool, enum, uuid or pattern.

**Auth context.**
- **Pack declarations:**
  - guard effects: `authn.require`, `authn.identify`, `authz`, `public`, `login`;
  - `verifiers`: jsonwebtoken, jose, next-auth…;
  - `identity_fields`: `req.user`, `ctx.state.user`;
  - `deny` responses: 401/403.
- **Guard inference** runs over our IR CFG on project middleware, wrappers, Nest `canActivate` and tRPC `.use`:
  - *require*: every continue point is dominated by the allow branch of an Identity-dependent check whose other branch denies.
  - *identify*: it only writes Identity.
  - *conditional*: anything else. The residual predicate is partially evaluated per route (method, full path, decorator metadata).
- **Checked on the corpus:**
  - NodeBB: `authenticateRequest` is identify, `ensureLoggedIn` is require.
  - Ghost: `authAdminApi` is identify followed by require.
  - immich: `@Authenticated` metadata yields `public:true` routes.
  - dub: `withWorkspace` is conditional only for `/api/links`.
  - n8n: `skipAuth`.
- **Reachable-unauthenticated** means no require precedes the handler, or every require is conditional on request-controlled data. Any unresolved element in the chain gives **`unknown`**, never "unauthenticated".
- Projects can override in `.jsspector.yml` (`auth.require: [...]`).

**Non-HTTP entries (v1):**
- socket.io/ws events: `on`, `onAny`, computed names.
- GraphQL fields: Apollo/Yoga resolver maps, Nest `@Resolver/@Query/@Mutation/@Args`.
- tRPC procedures: builder chains and adapters.
- Queue consumers (bull/bullmq), with **channels** that join producers to consumers by name.
- CLI (commander/yargs, `process.argv`) and env, as `OperatorConfig`.
- Electron `ipcMain.handle/on`, as `RendererIPC` (attacker-controlled, −1 severity).
- DOM sources → DOM sinks:
  - sources: `location.*`, `document.referrer`, `window.name`, postMessage `data`, Angular `ActivatedRoute`;
  - sinks: `innerHTML`, `insertAdjacentHTML`, `document.write`, jQuery `.html`, `bypassSecurityTrust*`, `dangerouslySetInnerHTML`, string `eval`/`setTimeout`;
  - `location` redirects escalate to XSS on a `javascript:` URL;
  - origin-check guards on `message` handlers.

**Client-side.**
- **Request issuers:** fetch, axios (including `create({baseURL})`), XHR, jQuery ajax, Angular `HttpClient`. URLs are folded across files.
- **Matching** to server templates is segment by segment:
  - literal beats param beats catch-all;
  - methods must agree;
  - ties are scored;
  - foreign origins become `external_endpoint`.
- **Full-stack chains** are reported only when they add capability:
  - a one-click attack that rides the victim's auth;
  - client-side path traversal through a tainted path segment;
  - a response that flows back into a client sink.
- **Minified bundles** are skipped and listed: `.min.js`, average line over 500, `sourceMappingURL`, high short-identifier ratio. Sourcemap reconstruction comes later.

**Entry-point record (JSON, abridged).**
```json
{"id":"ep_3f9a1c7e22b0","kind":"http.route","framework":"express","methods":["PUT"],
 "path":"/api/v3/users/{uid}","params":[{"name":"uid","in":"path"}],
 "inputs":[{"in":"body","name":"email","constrained":false,"evidence":[{"file":"src/controllers/write/users.js","line":41,"expr":"req.body.email"}]}],
 "handler":{"symbol":"Users.update","file":"src/controllers/write/users.js","line":38,"resolved":true},
 "registration":{"file":"src/routes/write/users.js","line":29,"via":["setupApiRoute src/routes/helpers.js:58"]},
 "mount_chain":[{"prefix":"${config.relative_path:-}"},{"prefix":"/api/v3/users","file":"src/routes/write/index.js","line":36}],
 "middleware":[{"name":"authenticateRequest","effect":"authn.identify"},{"name":"ensureLoggedIn","effect":"authn.require"}],
 "auth":{"status":"enforced"},"reachable_unauthenticated":false,"confidence":"medium","reasons":["config-symbol"]}
```
- **Stable ID** = `sha256(kind|framework|methods|path with params erased|handler symbol)[:12]`, with no line numbers.
- **OpenAPI 3.1 mapping:**
  - One operation per (method, path), with `operationId` set to the ID.
  - Public routes get `security: []`.
  - Symbolic prefixes become `servers` variables with the env defaults.
  - Schemas come from validators (3.1 embeds JSON Schema 2020-12). Names seen only in code get `{}` plus evidence.
  - tRPC becomes `/trpc/{proc}`. Server actions become `POST` plus a `Next-Action` header.
  - Sockets, queues, IPC, CLI and DOM entries go under `x-jsspector-entrypoints`.
  - Per-operation `x-jsspector-{id,handler,mount-chain,middleware,auth,confidence,unresolved,evidence,findings}`.

**Pack priority (by real-world corpus coverage).**
1. `core` + `node` sinks: child_process, fs, vm, SSRF clients, raw SQL, Mongo operators, template engines, deserializers.
2. `express` + multer/body-parser/cookie-parser/express-session/passport/express-jwt/express-validator/celebrate/joi.
3. `socket.io` + `ws`.
4. `zod` / `class-validator` / `nestjs`.
5. `nextjs` + next-safe-action + next-auth.
6. `koa` + `@koa/router` + `strapi`; `fastify` + autoload + TypeBox; `hapi`; `hono`.
7. `graphql`, `trpc`.
8. `dom` + `angular`/`react`/`jquery` + request issuers.
9. `bull`/`bullmq`, commander/yargs, `electron`, config libraries (nconf, config, dotenv).
10. **Automation/AI platform packs:**
    - workflow-node-parameter sources (n8n `getNodeParameter`, Flowise `nodeData.inputs`);
    - the expression-evaluator sink;
    - the `@modelcontextprotocol/sdk` stdio-transport spawn sink;
    - LLM-tool/agent plugin entry points.

    These are pulled forward if the AI/automation batch comes early, because those repos carry the most critical advisories.

Small adapter packs (@tryghost/api-framework, express-lazy-router, @n8n/decorators, parse-server rows) are added only when misses demand them.

## Corpus, ground truth and measurement (CVE replay, all static)

**Corpus shape.**
- 100 real-world JS/TS repos in **10 batches of 10**.
- Plus **10 holdout repos**, taken from the reserves with a fixed seed. They are never debugged against and are scored only at M3 and M5, to catch overfitting.
- The batch list is in the *Corpus batches* section (from the discovery research).

**Honesty rules.**
- Corpus scans get no per-repo hints beyond scan roots and excludes.
- Models may name library APIs, never an app's own functions.
- Recall is also printed over **all** advisories, including out-of-scope ones, so scope labels can't flatter the numbers.

**Manifest: one TOML file per repo,** `corpus/repos/<owner>__<name>.toml`. TOML suits these flat records; packs use YAML because they are nested and MaD-compatible.
```toml
schema = 1
repo   = "NodeBB/NodeBB"
batch  = 1                          # 1..10 | "holdout"
head   = "2e04195762088c0720a5186425a9c7ea493bd1a7"
[scan]
roots   = ["src", "public/src"]
exclude = ["test/**", "public/vendor/**"]
[[routes_oracle]]                   # committed spec, read at head; servers[0].url prepended
spec = "public/openapi/write.yaml"
[[advisory]]
id    = "GHSA-vh2g-6c4x-5hmp"
severity = "critical"
cwe   = ["CWE-22"]
fix   = ["ec58700f6dff8e5b4af1544f6205ec362b593092"]   # vuln = first^1, fix = last
pair  = "commit"                    # commit | merge | tags
scope = "in"                        # or out:authz | out:dos | out:dependency | out:ci | out:supply-chain | out:non-js | out:unparseable
anchors = "auto"                    # or explicit path/function/lines
```

**What `xtask corpus verify` does:**
- Works out the vulnerable commit (`fix^1`).
- Checks that the fix touches JS/TS inside the scan roots.
- Takes the fix diff's JS/TS hunks (±3 lines, both sides) as **anchors**.
- Flags noisy fixes (more than 5 files or 300 lines), which need anchors set by hand.
- Writes `corpus/anchors.lock.json`, which is committed so scoring is reproducible.
- Note: the per-repo advisory API often lists only patched versions. The **global** advisory record usually carries the fix commit.

**Scoring rules.**
- **Detected:**
  - A finding of a matching CWE class whose source, **any trace step**, or sink touches an anchor in the vulnerable commit.
  - The sink line alone is not enough. In NodeBB GHSA-vh2g-6c4x-5hmp the fix is in a socket handler plus `src/api/users.js`, while the sink is elsewhere.
  - Weaker matches (same function only, or below HIGH) are reported separately.
- **Cleared:** at the fix commit, no matching finding touches the fix-side anchors and the fingerprint is gone. A finding that survives the fix is an automatic, unbiased FP signal, usually a sanitizer we don't model yet.

**Metrics (per batch and cumulative):**
- **Accuracy:** HIGH+ recall, path-level recall (an entry point is attached), and clearance rate.
- **Miss taxonomy:** entry not resolved / source not modeled / flow lost (inter-procedural, callback, async, collection) / sink not modeled / parse error.
- **Volume and precision at HEAD:** HIGH+ findings per KLOC, and precision at HEAD with a Wilson 95% interval.
- **Routes:** route recall and precision against the committed specs.
- **Health:** parse rate, panics, unresolved items per KLOC, time, peak memory.

**FP review.**
- Triage every CRITICAL plus a stratified sample of up to 40 HIGH findings at HEAD.
- Verdicts: TP / TP-wrong-severity / FP+reason / unsure.
- A rule with 15 or more verdicts and under 50% precision drops to MEDIUM by default.

**Route matching.**
- Normalization:
  - `:id`, `:id(\d+)`, `[id]` and `{id}` all become a positional `{}`.
  - Optional parameters match both ways.
  - `*` and `[...x]` become `{*}`.
  - Trailing slashes are dropped.
- Env- or config-derived prefix parts come out as `{$env:X}`. They match anything and are counted separately as "symbolic".
- Precision is computed only inside the area the spec covers (for n8n, the public API).

**Batch loop (at most one week per batch).**
1. Import, verify, fetch, run, score.
2. The agent proposes miss reasons from the diagnostics; fear confirms.
3. Fix the largest miss classes **in a general way**. Each fix comes with a fixture we write ourselves; corpus code is never copied, for licensing reasons.
4. Run regression re-runs, then close the batch.

**Batch exit criteria:**
1. 0 panics; ≥99.5% of files parse; every scan within budget.
2. Every advisory has a scope label and is either detected or has a miss reason.
3. Cumulative recall has not dropped, and the batch meets the milestone target.
4. Clearance ≥75%.
5. HEAD precision and volume within target.
6. `corpus/reports/batch-NN.md` committed.

**Regression runs.**
- **Every engine PR (local, ≤10 min):** unit and fixture tests, plus a "sentinel set": every pair currently detected and cleared, plus HEAD scans of the spec repos.
- **Batch close:** all closed batches.
- **What counts as a regression:**
  - lost detection or lost clearance;
  - route recall down by 1 point or more;
  - a new panic or parse failure;
  - time or memory up 25% or more (median of 3 runs, enforced on Satori).

**Caching and budget (10-core / 32 GB Mac).**
- **Git cache:** one bare repo per corpus repo, in `$JSSPECTOR_CORPUS_DIR` outside the project.
  - Each needed commit is fetched with `git fetch --depth=2 --filter=blob:none origin <sha>`, which also brings `fix^1`.
  - One reusable sparse checkout per repo is switched between commits.
  - **Corpus code is never executed.**
- **Results cache:** keyed by commit, roots hash, build ID and packs hash.
- **Per-file fact cache:** keyed by content hash, added once vuln/fix pairs push a batch over budget.
- **Budget:**
  - Per scan: median ≤10 s, maximum ≤60 s, ≤4 GB memory.
  - Per batch: about 60 scans in ≤20 min with a warm cache.
  - Full corpus: about 600 scans, roughly 2–2.5 h locally.

**Satori.** Move the full regression to Satori when the local run goes over 45 minutes (around batch 3 or 4), or when clean timing medians are needed.
- One job per batch plus the holdout, in parallel.
- Each job builds a release binary, then runs `corpus fetch`, `run` and `score --batch N --fail-on-regression`.
- Asserts: return code 0 and no `panicked at`, PySpector-style.
- Reports set to private visibility.
- Benchmark: median of 5 runs on a fixed subset.

**Disclosure hygiene (the repo is public).**
- Advisory replay data is public knowledge and can be committed.
- **HEAD findings on real apps may be undisclosed 0-days.** They and the triage ledger live in a **private** repo.
- Public reports show aggregates only.
- Confirmed TPs go through coordinated disclosure.

### CVE-replay seed (already researched and verified)

We triaged every published critical/high advisory in 15 corpus repos:
- **120 critical + 338 high**, of which **216 are taint-style**.
- A skeptic agent then checked 85 replay candidates against the real fix diff and the sink line at the vulnerable commit: **77 verified, 7 corrected, 1 refuted**.
- That leaves **84 replay pairs ready to become manifests** (fix SHA, vulnerable commit = fix^1, sink file:line). The results are saved in the research output for import on day 3.
- **71 of the pairs are taint-style:** 10 SQLi, 3 NoSQLi, 15 path traversal, 5 code injection, 4 command injection, **8 prototype pollution**, 9 SSRF, 15 XSS (about 9 client-side), 1 SSTI, 1 open redirect.
- The other 13 (authn/authz, info leak, DoS, mass assignment) count only toward all-advisory recall.

| Repo | Pairs | Highlights (CVE) |
|---|---|---|
| parse-server | 8, all critical | 5× Postgres SQLi (2024-27298, 2024-39309, 2026-31840/31856/31871); NoSQL operator injection (2026-32248, 2020-5251); prototype pollution→RCE (2022-24760) |
| n8n | 8 | expression code injection (2025-68613); form path traversal "Ni8mare" (2026-21858); Git node command injection (2026-25053); 3× prototype pollution; data-table SQLi; SSH traversal |
| Flowise | 8 | CustomMCP code injection (2025-59528); MCP command injection (2026-40933); 3× path traversal; SSRF; MongoDB NoSQLi; UI XSS |
| directus | 8 | file-import traversal (2025-55746); geometry SQLi; 2× prototype pollution; TUS traversal; 2× SSRF; XSS |
| LibreChat | 8 | MCP command injection (2026-22252); 5× SSRF (actions, custom endpoints) |
| Ghost | 7 | input-serializer SQLi (2026-26980); 2× code injection (i18n, `get` helper); traversal; 3× XSS |
| strapi | 7 | SSTI (2023-22621); schema-builder SQLi (2026-22599); open redirect; mass assignment |
| outline | 7 | GitLab plugin SSRF; ZipHelper traversal (2026-43888); 3× editor XSS |
| NodeBB | 5, all critical | traversal (2023-26045, 2021-43788); 2× prototype pollution via socket.io (2021-43787, 2022-46164) |
| etherpad-lite / anything-llm / immich / cal.com / uptime-kuma / node-red | 5 / 5 / 3 / 2 / 2 / 1 | Minify traversal, ExportHtml XSS; SQL-agent SQLi, filesystem-plugin command injection; web XSS; plugin-manager code injection (2023-36821); localfilesystem traversal (2021-21298) |

**What the data changes in the plan:**
1. **Prototype pollution moves from deferred into M2.** It is frequent among critical advisories. The sink class is: tainted dynamic-key writes (`o[k1][k2] = v`) plus deep set/merge helpers, including project-local ones such as directus `set-deep.ts`. A gadget that reaches code execution escalates it to Critical.
2. **Automation and AI platforms need two more sources/sinks.** n8n and Flowise alone have 63 critical advisories, mostly inside workflow "nodes":
   - **Node-parameter sources:** `getNodeParameter`, Flowise `nodeData.inputs`. Their provenance is attacker-controlled when workflow editors are less trusted than the host.
   - An **MCP SDK stdio-transport spawn sink** (`StdioClientTransport({command, args})`), which LibreChat and Flowise both hit.
3. **Server-side HTML XSS** (Ghost helpers, etherpad export) needs a careful sink class with content-type conditions.
4. **Batch-1 calibration advisories** (short, single-file server fixes in batch-1 repos):
   - NodeBB CVE-2023-26045 (path traversal through a socket handler);
   - uptime-kuma GHSA-5px6-fx2w-459r (socket-handler traversal);
   - etherpad GHSA-mc8w-wjhw-45x5 (Minify path traversal).

   These serve as **early sentinels** for batches 2–3:
   - parse-server CVE-2026-31856 and CVE-2026-32248;
   - node-red CVE-2021-21298.

### Corpus batches (100 repos, 10 × 10)

**Where the list comes from.**
- A discovery pass collected 148 candidates from three angles: npm advisory DB, self-hosted apps, framework coverage.
- A critic spot-checked about 60 of them against `gh api`. Advisory counts matched exactly, and renames were confirmed: `react/react`, `calcom/cal.diy`, `LibreChat-AI/LibreChat`, `ether/etherpad`, `karakeep-app/karakeep`, `lobehub/lobehub`.
- Batches go from small to huge, and roughly follow the order in which the roadmap adds support.
- About **1,900 published critical/high advisories** across the 100, before scoping. The 15-repo sample suggests about 45% are taint-style, so roughly **800 replay candidates**.

| B | Theme (milestone) | Repos | Crit+High |
|---|---|---|---|
| 1 | Smoke: small Express/socket.io (M1) | mongo-express/mongo-express, louislam/dockge, louislam/uptime-kuma, frangoteam/FUXA, ether/etherpad, advplyr/audiobookshelf, SillyTavern/SillyTavern, chartbrew/chartbrew, MagicMirrorOrg/MagicMirror, **NodeBB/NodeBB** (calibration anchor) | ≈84 |
| 2 | Medium Express/Koa/Fastify apps (M2) | hedgedoc/hedgedoc (1.x tags), apostrophecms/apostrophe, saltcorn/saltcorn, node-red/node-red, docmost/docmost, Unleash/unleash, verdaccio/verdaccio, Mintplex-Labs/anything-llm, Chocobozzz/PeerTube, samanhappy/mcphub | ≈87 |
| 3 | Framework cores (raw `node:http` sources) (M2) | fastify/fastify, koajs/koa, honojs/hono, feathersjs/feathers, nestjs/nest, h3js/h3, plankanban/planka (Sails), **parse-community/parse-server**, socketio/socket.io, sveltejs/kit | ≈127 |
| 4 | Next.js / Remix / Workers apps (M3) | umami-software/umami, ChatGPTNextWeb/NextChat, decolua/9router, Dokploy/dokploy, baptisteArno/typebot.io, calcom/cal.diy, lukevella/rallly, homarr-labs/homarr, Mail-0/Zero, karakeep-app/karakeep | ≈127 |
| 5 | GraphQL / NestJS / headless CMS (M3) | keystonejs/keystone, vendurehq/vendure, hoppscotch/hoppscotch, twentyhq/twenty, heyform/heyform, requarks/wiki (v2 tags), **directus/directus**, teableio/teable, payloadcms/payload, **strapi/strapi** | ≈167 |
| 6 | Electron / IPC (M4) | electerm/electerm, Eugeny/tabby, dbgate/dbgate, laurent22/joplin, TriliumNext/Trilium, Foundry376/Mailspring, usebruno/bruno, dyad-sh/dyad, streetwriters/notesnook, siyuan-note/siyuan (TS/Electron parts only) | ≈140 |
| 7 | DOM / SPA / client rendering (M4) | jupyterlab/jupyterlab, scalar/scalar, mozilla/pdf.js, decaporg/decap-cms, jellyfin/jellyfin-web, mermaid-js/mermaid, open-webui/open-webui (frontend only), angular/angular, tinacms/tinacms, remix-run/react-router | ≈105 |
| 8 | Dev servers / CLI / MCP (M4) | vitejs/vite, webpack/webpack-dev-server, storybookjs/storybook, modelcontextprotocol/inspector, cloudflare/workers-sdk, nuxt/nuxt, withastro/astro, QwikDev/qwik, renovatebot/renovate, orval-labs/orval | ≈110 |
| 9 | Large AI / queue-heavy apps (M5) | **outline/outline**, misskey-dev/misskey, **immich-app/immich**, activepieces/activepieces, triggerdotdev/trigger.dev, Openpanel-dev/openpanel, gitroomhq/postiz-app, **LibreChat-AI/LibreChat**, OneUptime/oneuptime, **FlowiseAI/Flowise** (archived: replay only) | ≈307 |
| 10 | Huge monorepos, package-scoped (M5) | **n8n-io/n8n**, openclaw/openclaw (gateway packages), Budibase/budibase, nocodb/nocodb, RocketChat/Rocket.Chat, wekan/wekan, vercel/next.js (`packages/next`), **TryGhost/Ghost** (`ghost/core`), backstage/backstage (`*-backend` plugins), react/react (RSC/Flight + react-dom server) | ≈633 |

Bold marks repos that already have verified replay pairs from the seed.

**Reserves.** The **10 holdout** repos are drawn by fixed seed at M0 from this list:
- labring/FastGPT, lobehub/lobehub, Shelf-nu/shelf.nu, logto-io/logto, nocobase/nocobase
- firecrawl/firecrawl, paperclipai/paperclip, zereight/gitlab-mcp, better-auth/better-auth, documenso/documenso
- linkwarden/linkwarden, actualbudget/actual, rajnandan1/kener, gethomepage/homepage, novuhq/novu

**Admission rules (checked by `xtask corpus verify` before a batch starts):**
- Each repo needs **≥1 resolvable in-scope advisory**, and each batch **≥15**. Repos that fail are swapped from the reserves.
- Known replay problems: Dokploy (23 of its 51 critical/high have no fix information), heyform (20 of 21 have no patched version), requarks/wiki and hedgedoc (advisories are on old major branches; use release tags).
- Monorepos get **package-scoped roots**.
- Scope labels `out:authz` (CWE-284/285/287/639/862/863), `out:dos`, `out:dependency`, `out:ci`, `out:supply-chain` and `out:non-js` keep untestable advisories out of the recall denominator. Examples: bruno's npm supply-chain criticals, RSSHub's CI critical, code-server's bundled-Node CVE. They are still shown in all-advisory recall.

**Dropped from the pool:**
- **No ground truth:** fxa, loopback-next, restify.
- **Mostly non-JS:** ToolJet, cube, pnpm, appsmith, grafana.
- **Cost far above yield:** vscode, opencode, cline, AFFiNE, super-productivity.
- **Plain libraries** (axios, node-tar, handlebars, sequelize, jsPDF, systeminformation, simple-git, multer…): they need *library-mode* entry points, which come later.

**Gaps with no published critical/high ground truth:** browser extensions, queue-triggered flows, AWS Lambda handlers. These are covered by **synthetic fixtures and FP-only checks**.

## Roadmap (each milestone ends with corpus metrics improving)

| M | Weeks | Builds | Batches | Exit criteria (over all closed batches) |
|---|---|---|---|---|
| M0 | 1 | Toolchain; workspace with exact oxc pins; CI; file discovery + path classifier; parallel parse + `LineIndex`; diagnostics; `--stats`; `xtask corpus` skeleton | batch 1 fetched (HEAD + every advisory commit) | 0 panics; ≥99.5% of files parse; byte-identical output at 1 vs 10 threads |
| M1 | 2–3 | IR lowering; CJS/ESM linker + resolver overlay; `express`/`koa` packs (routes, mounts, cross-file handlers, one-level factories) + **minimal `socket.io`** (connection → `socket.on(event, h)` arguments as sources; batch 1 is socket-heavy); intra-procedural taint; 5 sink classes (command, code, SQL, path, SSRF) with TP/FP pairs; witness traces; fingerprint v1; `jsspector routes`; replay scorer | 1 | ≥1 advisory detected **entry→sink at HIGH+** and cleared at its fix; every batch-1 advisory has a scope label or miss reason |
| M2 | 4–6 | Bottom-up symbolic summaries (call ports, wrappers, factories, callbacks, async); sanitizer masks + guards; guard inference + severity; second-order channels (1 hop); **prototype-pollution sink class** (tainted dynamic-key writes, deep set/merge); NoSQL operator injection (object-valued inputs); raw `node:http` request sources (`createServer` handlers) for batch 3's framework cores | 2–3 | HIGH+ recall ≥25%; clearance ≥75%; HEAD precision ≥50% |
| M3 | 7–9 | Helper/route-table routes, unrolling, computed members, tainted-key dispatch; NestJS/decorators/DI; Fastify (+autoload); Next.js conventions; **GraphQL resolvers**; schema inputs; **OpenAPI 3.1** | 4–5 (holdout scored once) | Recall ≥35%; route recall NodeBB ≥80%, immich ≥90%, n8n public API ≥80% |
| M4 | 10–12 | Advanced socket.io (`onAny`, RPC dispatch)/ws, tRPC, queues + channels, CLI/env, Electron IPC; client request issuers + route matching; DOM XSS; dev-server and MCP packs | 6–8 | Recall ≥45% |
| M5 | 13–15 | SARIF 2.1.0 (codeFlows, partialFingerprints, security-severity, UTF-16 columns); baselines; `.jsspector.yml`; `explain`; cargo-dist + Homebrew tap; `.satori.yml` full-corpus job | 9–10 + holdout | Recall ≥50%; holdout within 10 points of recall; precision lower 95% bound ≥50%; **v0.1.0** |

- Targets are re-set after batch 2.
- **Misses decide the order.** For example, a minimal socket.io pack may move before M4.
- fear's time is about 1 day per batch: scope labels, miss confirmation, FP triage.

**De-risking spikes, scheduled early:**
1. **Symbolic summaries resolve ≥85% of routes** (week 3–4). Hand-lowered IR for NodeBB `setupApiRoute`, Ghost `lazyUse`, parse-server route tables and n8n's registry, scored against NodeBB's 240 spec paths and immich's 338 ops.
2. **Lowering completeness and oxc churn** (M0–M1). Golden IR snapshots on n8n and two other large repos; `cargo fuzz` on the frontend; replay the 0.155→0.156 upgrade to size the diff.
3. **Workspace resolution without node_modules ≥98%** (M0). A resolver-only binary run on n8n, immich, Strapi and dub, with misses sorted into categories.
4. **No giant SCCs** from DI, emitters or field-based edges (M2). SCC-size histogram on n8n and Ghost.
5. **Baseline precision at HIGH/CRITICAL** with intra-procedural taint only (end of M1, batch 1).

**Deferred:**
- Satori playbook *generation*.
- Vue/Svelte/Angular template extraction.
- ReDoS sinks. Prototype pollution is *not* deferred: the advisory data puts it in M2.
- TS type-checker-aware analysis.
- LSP; sourcemap reconstruction; HTML/TUI.
- **Library mode:** a library's exported API as its entry points (axios, node-tar, handlebars, sequelize…).

**Never:** `--url` cloning, executable plugins.

**First two weeks.**
| Day | Task |
|---|---|
| 1 | fear: install rustup (Rust ≥1.97); pick a license; enable branch protection and private vulnerability reporting; create the **private** companion repo for HEAD findings and the triage ledger. Agent: save the research outputs to `corpus/research/`; workspace skeleton, exact pins, `rust-toolchain.toml`, CI, SECURITY.md, README; save memory notes on the agreed design. |
| 2 | File discovery + path classifier; parallel parse; `LineIndex`; diagnostics; `--stats`. |
| 3 | Manifest schema; `xtask corpus import/verify/fetch` (bare git cache, `--filter=blob:none`); anchors lock. fear approves the batch-1 manifests. |
| 4 | `run`, `score`, `diff`; markdown report; determinism test. |
| 5 | Run batch 1 at HEAD and every advisory commit; fix crashes; calibrate budgets. fear labels advisory scope. |
| 6 | IR lowering v0 (imports/requires/exports, functions including anonymous ones, call sites, destructuring); pack loader + JSON Schema. |
| 7 | Linker (CJS model + resolver overlay); `express`/`koa` packs; routes, mounts and cross-file handlers; unresolved reasons. |
| 8 | `jsspector routes` (JSON/text); fixtures; route-recall scorer against the NodeBB and immich specs. |
| 9 | Intra-procedural taint; 5 sink classes with TP/FP pairs; traces; fingerprint v1. |
| 10 | Replay scorer; run batch 1; the agent drafts miss reasons and fear confirms; first PR with a corpus diff. |

## Verification

1. **Unit and fixture tests (`cargo test`).**
   - Per-idiom fixture apps with insta snapshots, plus inline `// @route`, `// @expect`, `// @safe` annotations that are checked for meaning, not just snapshotted.
   - Pack golden tests.
   - A TP/FP pair per sink class; a meta-test fails if one is missing.
   - Inter-procedural and cross-file cases: wrappers, factories, DAO methods, async, recursion limits.
2. **Determinism.** `cargo xtask determinism` runs the corpus sentinel at `RAYON_NUM_THREADS=1` and at 10 and requires byte-identical JSON. It runs in CI.
3. **Robustness.** Nightly `cargo fuzz run frontend`. Corpus runs must have 0 panics, and every skip must show up as a diagnostic.
4. **Routes, end to end.**
   - `jsspector routes <NodeBB@pinned> -f openapi` must cover ≥80% of `public/openapi/{read,write}.yaml` after normalization.
   - The same check runs against immich's `open-api/immich-openapi-specs.json`, through `cargo xtask corpus score --batch N`.
5. **Findings, end to end (CVE replay).**
   - `cargo xtask corpus run --batch 1 && cargo xtask corpus score --batch 1` must report the advisory **detected** at the vulnerable commit (a finding touching an anchor, with an entry point attached) and **cleared** at the fix commit.
   - `jsspector scan <repo@vuln> --fail-on high -f sarif` exits 1 there and 0 at the fix.
6. **Regression.** `cargo xtask corpus diff` against `corpus/baselines`. Every engine PR runs the sentinel set (≤10 min); every batch close runs all closed batches; on Satori, `satori run ./ --playbook=.satori.yml --sync` asserts return code 0 and no `panicked at`.
7. **Performance.** `jsspector scan --stats` plus hyperfine on the n8n backend must meet the targets (≤25 s, ≤4 GB) and stay within ±10% of the last run.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Helper, registry and decorator routes don't resolve, so there are no entry points | Spike 1; symbolic strings plus explicit `{dynamic}`/`unmounted` records; small adapter packs as a fallback |
| oxc API churn (weekly breaking releases) | Exact pins; oxc confined to `jss-frontend`; exhaustive matches; golden IR + corpus diff gate every upgrade |
| FP flood buries the HIGH/CRITICAL signal | Confidence gating; entry-point-anchored findings only; argument-shape conditions; FP review with automatic demotion; clearance at fix commits as an unbiased FP signal |
| Ground-truth noise (the fix is far from the sink; noisy fixes) | Anchors include source, trace and sink; noisy fixes get anchors set by hand; recall is also printed over all advisories |
| Scale and performance on 100 repos × advisory commits | Results and fact caches; per-scan budgets; Satori from about batch 3–4 |
| Leaking 0-days from HEAD scans | Private findings repo; public aggregates only; coordinated disclosure |

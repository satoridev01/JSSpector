use super::*;
use crate::parse::{parse_options, source_type};
use jss_core::{PackageType, SourceKind};
use oxc_allocator::Allocator;
use oxc_parser::Parser;

fn raw_findings(src: &str) -> Vec<RawFinding> {
    let allocator = Allocator::default();
    let ret = Parser::new(
        &allocator,
        src,
        source_type(SourceKind::Js, PackageType::CommonJs),
    )
    .with_options(parse_options())
    .parse();
    assert!(!ret.fatal_error, "{:?}", ret.diagnostics);
    scan_program(&ret.program, src).findings
}

/// (class, sink api, source kind) for every finding in `src`.
fn scan(src: &str) -> Vec<(VulnClass, Severity, String, &'static str)> {
    raw_findings(src)
        .into_iter()
        .map(|f| (f.class, f.severity, f.api, f.origin.kind))
        .collect()
}

/// [`scan`] of TypeScript.
fn scan_ts(src: &str) -> Vec<(VulnClass, Severity, String, &'static str)> {
    let allocator = Allocator::default();
    let ret = Parser::new(
        &allocator,
        src,
        source_type(SourceKind::Ts, PackageType::CommonJs),
    )
    .with_options(parse_options())
    .parse();
    assert!(!ret.fatal_error, "{:?}", ret.diagnostics);
    scan_program(&ret.program, src)
        .findings
        .into_iter()
        .map(|f| (f.class, f.severity, f.api, f.origin.kind))
        .collect()
}

const HEAD: &str = "const { exec, spawn } = require('child_process');\n\
        const fs = require('fs');\nconst path = require('path');\n\
        const axios = require('axios');\n";

fn one(body: &str) -> Vec<(VulnClass, Severity, String, &'static str)> {
    scan(&format!("{HEAD}{body}"))
}

#[test]
fn command_injection_through_concatenation() {
    let found =
        one("app.get('/p', (req, res) => { const h = req.query.host; exec('ping ' + h); });");
    assert_eq!(
        found,
        vec![(
            VulnClass::CommandInjection,
            Severity::Critical,
            "child_process.exec".to_owned(),
            "http"
        )]
    );
}

#[test]
fn helpers_declared_callers_first_get_summaries() {
    // Four levels, each helper declared before the one it calls.
    let found = one("app.get('/x', (req, res) => { a1(req.query.x); });\n\
             function a1(v) { b1(v); }\nfunction b1(v) { c1(v); }\nfunction c1(v) { d1(v); }\n\
             function d1(v) { exec('ls ' + v); }\n");
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].0, VulnClass::CommandInjection);
    // The same chain with a number at the end: nothing.
    assert!(
            one(
                "app.get('/x', (req, res) => { a1(req.query.x); });\n\
                 function a1(v) { b1(v); }\nfunction b1(v) { c1(v); }\nfunction c1(v) { d1(parseInt(v, 10)); }\n\
                 function d1(v) { exec('ls ' + v); }\n",
            )
            .is_empty()
        );
    // A self-recursive walker with no sink converges with no finding.
    assert!(
            one(
                "app.get('/x', (req, res) => { walk(req.body, 0); });\n\
                 function walk(o, d) { if (d > 3) return o; for (const k in o) walk(o[k], d + 1); return o; }\n",
            )
            .is_empty()
        );
}

#[test]
fn transitive_xss_summaries_preserve_each_material_call_path() {
    let src = "function renderPkceCard(authCode) {\n\
                       card.innerHTML = `<pre>${authCode}</pre>`;\n\
                   }\n\
                   function updatePkceDisplay(authCode) {\n\
                       renderPkceCard(authCode);\n\
                   }\n\
                   async function handleRedirectCallback() {\n\
                       const params = new URLSearchParams(window.location.search);\n\
                       const code = params.get('code');\n\
                       updatePkceDisplay(code || 'N/A');\n\
                       if (!code) return;\n\
                       const tokenData = await exchangeCodeForTokens(code);\n\
                       showTokens(tokenData);\n\
                   }\n\
                   function showTokens(tokenData) {\n\
                       const authCode = new URLSearchParams(window.location.search).get('code');\n\
                       renderPkceCard(authCode || 'N/A');\n\
                   }";
    let found = raw_findings(src);
    let functions: Vec<&str> = found
        .iter()
        .map(|finding| finding.function.as_str())
        .collect();
    assert_eq!(
        functions,
        ["handleRedirectCallback", "showTokens"],
        "both the direct pre-validation path and the later gated path must survive: {found:?}",
    );
    assert!(
        found
            .iter()
            .all(|finding| { finding.class == VulnClass::Xss && finding.api == ".innerHTML =" })
    );
    let direct = &found[0];
    assert!(
        direct
            .origin
            .steps
            .iter()
            .any(|(_, note)| note == "passed to `updatePkceDisplay()`")
    );
    assert!(
        direct
            .origin
            .steps
            .iter()
            .any(|(_, note)| note == "passed to `renderPkceCard()`")
    );
}

#[test]
fn a_class_field_calling_a_later_method_gets_its_summary() {
    let found = one(
        "class Node {\n  loadMethods = { list: async (data) => { await this.getTools(data); } };\n\
             async getTools(data) { return run(data.inputs.config); }\n}\n\
             function run(text) { return convert(text); }\nfunction convert(s) { return Function('return ' + s)(); }\n\
             const n = new Node();\napp.post('/x', async (req, res) => { await n.getTools(req.body); });\n",
    );
    assert!(
        found.iter().any(|f| f.0 == VulnClass::CodeInjection),
        "{found:?}"
    );
}

/// The classes and severities of `body`'s findings, in a route.
fn route(body: &str) -> Vec<(VulnClass, Severity)> {
    one(&format!(
        "const _ = require('lodash');\nconst deepcopy = require('deepcopy');\n\
             app.post('/x', async (req, res) => {{ {body} }});"
    ))
    .into_iter()
    .map(|f| (f.0, f.1))
    .collect()
}

#[test]
fn stores_taint_their_target() {
    use Severity::*;
    use VulnClass::*;
    assert_eq!(
        route("const a = ['--json']; a.push(req.query.p); spawn('rg', a);"),
        vec![(CommandInjection, Medium)]
    );
    assert_eq!(
        route(
            "const w = []; w.push('id = ' + req.query.id); db.query('SELECT * FROM t WHERE ' + w.join(' AND '));"
        ),
        vec![(SqlInjection, High)]
    );
    assert_eq!(
        route("const o = {}; Object.assign(o, req.body); exec(o.cmd);"),
        vec![(CommandInjection, Critical)]
    );
    assert_eq!(
        route(
            "const list = []; list.push(...req.body.files); for (const f of list) fs.readFileSync(f.path);"
        ),
        vec![(PathTraversal, High)]
    );
    // Nothing attacker-controlled stored.
    assert!(route("const a = ['ls']; a.push('-l'); spawn(a[0], a);").is_empty());
    assert!(
        route("const a = ['--v']; a.push(String(Number(req.query.n))); spawn('node', a);")
            .is_empty()
    );
    assert!(route("const s = new Set(); s.add(req.query.id); exec('ls');").is_empty());
}

#[test]
fn a_field_write_keeps_the_object_its_own_origin() {
    // `props` stays the route's body after a field is set from configuration: the helper's
    // summary must name `props` (argument 2), not `pub` (argument 1).
    let found = one(
        "function create(cfg, pub, props) {\n  const { targets } = pub;\n  \
             const t = targets.find((x) => x.ok);\n  props['mp'] = t;\n  \
             return db.collection('posts').findOne({ type: props.type });\n}\n\
             app.post('/x', (req, res) => create(CFG, PUB, req.body));\n",
    );
    assert!(
        found.iter().any(|f| f.0 == VulnClass::NosqlInjection),
        "{found:?}"
    );
}

#[test]
fn predicates_by_what_they_do_guard_their_callers() {
    let helpers = "const identity = (value) => typeof value === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(value);\n\
                       function okName(n) { return /^[a-z]+$/.test(n); }\n";
    for quiet in [
        "app.get('/s', (req, res) => { const id = req.query.id; if (!identity(id)) throw new Error('bad'); fs.readFileSync(path.join(DIR, id)); });",
        "app.get('/s', (req, res) => { if (!okName(req.query.n)) return res.end(); exec('run ' + req.query.n); });",
    ] {
        assert!(one(&format!("{helpers}{quiet}")).is_empty(), "{quiet}");
    }
    // A check that does not exit, or a predicate whose pattern admits a separator, cleans
    // nothing.
    let found = one(&format!(
        "{helpers}app.get('/s', (req, res) => {{ const id = req.query.id; if (!identity(id)) log('bad'); fs.readFileSync(path.join(DIR, id)); }});"
    ));
    assert_eq!(found.len(), 1, "{found:?}");
    let found = one(
        "const loose = (v) => /^[\\w/.-]+$/.test(v);\napp.get('/s', (req, res) => { const id = req.query.id; if (!loose(id)) throw new Error('bad'); fs.readFileSync(path.join(DIR, id)); });",
    );
    assert_eq!(found.len(), 1, "{found:?}");
}

#[test]
fn a_parameter_escaped_on_its_own_path_stays_escaped_once_merged() {
    // great_cto: `cwd` is replaced by a path checked to be inside the home directory, which
    // comes from `url`; merged with the unchecked `cwd` parameter, only `cwd` reaches the
    // read.
    let helpers = "function inside(x) { const r = path.resolve(x); return isInsideDir(HOME, r) ? r : null; }\n\
                       function dispatch(url, cwd) { const p = url.searchParams.get('project'); if (p) { const w = inside(p); if (w) { cwd = w; } } fs.readFileSync(path.join(cwd, 'x.json')); }\n";
    assert!(
            one(&format!(
                "{helpers}app.get('/b', (req, res) => {{ dispatch(new URL(req.url, BASE), process.cwd()); }});"
            ))
            .is_empty()
        );
    let found = one(&format!(
        "{helpers}app.get('/b', (req, res) => {{ dispatch(new URL(req.url, BASE), req.query.dir); }});"
    ));
    assert_eq!(
        found.iter().map(|f| f.0).collect::<Vec<_>>(),
        vec![VulnClass::PathTraversal],
        "{found:?}"
    );
}

#[test]
fn every_contributing_parameter_gets_a_summary() {
    use Severity::*;
    use VulnClass::*;
    // The second parameter, after the first, in a concatenation.
    assert_eq!(
        one(
            "function g1(a, b) { exec(b + a); }\napp.get('/x', (req, res) => g1(req.query.x, 'y'));"
        ),
        vec![(
            CommandInjection,
            Critical,
            "child_process.exec".to_owned(),
            "http"
        )]
    );
    assert!(
        one("function g1(a, b) { exec(b + a); }\napp.get('/x', (req, res) => g1('x', 'y'));")
            .is_empty()
    );
    // A helper returning an object it set from a second parameter returns both.
    let found = one(
        "function add(object, additions) { object.extra = additions; return object; }\n\
             app.post('/x', (req, res) => { const o = add(CONFIG, req.body); exec(o.cmd); });",
    );
    assert!(found.iter().any(|f| f.0 == CommandInjection), "{found:?}");
}

#[test]
fn a_parameter_after_a_fixed_base_is_not_at_the_start() {
    // `route` comes after the configured base URL: no SSRF; the base itself would be.
    let found = one(
        "function target(session, route) { return session.baseUrl + route; }\n\
             app.post('/x', async (req, res) => { await axios.get(target(SESSION, req.path)); });",
    );
    assert!(!found.iter().any(|f| f.0 == VulnClass::Ssrf), "{found:?}");
    let found = one(
        "function target(session, route) { return session.baseUrl + route; }\n\
             app.post('/x', async (req, res) => { await axios.get(target(req.body, '/v1')); });",
    );
    assert!(found.iter().any(|f| f.0 == VulnClass::Ssrf), "{found:?}");
}

#[test]
fn spread_objects_keep_their_known_fields() {
    // `endpoint` only ever comes from the environment; `url` is the client's.
    let found = route(
        "const o = { url: req.body.url, ...(process.env.E ? { endpoint: process.env.E } : {}) };\n\
             await axios.get(o.endpoint);\nawait send({ ...o, weeks: req.body.weeks });",
    );
    assert!(found.is_empty(), "{found:?}");
    // A spread of the body brings any field.
    assert_eq!(
        route("const o = { a: 1, ...req.body }; exec(o.cmd);"),
        vec![(VulnClass::CommandInjection, Severity::Critical)]
    );
    // Through a helper that reads one field of its argument.
    let found = one(
        "async function send({ endpoint, url }) { await axios.get(endpoint, { params: { url } }); }\n\
             app.post('/x', async (req, res) => { const o = { url: req.body.url, ...(E ? { endpoint: E } : {}) }; await send({ ...o, w: 1 }); });",
    );
    assert!(found.is_empty(), "{found:?}");
    let found = one(
        "async function send({ endpoint, url }) { await axios.get(endpoint, { params: { url } }); }\n\
             app.post('/x', async (req, res) => { const o = { endpoint: req.body.u }; await send({ ...o, w: 1 }); });",
    );
    assert!(found.iter().any(|f| f.0 == VulnClass::Ssrf), "{found:?}");
}

#[test]
fn equal_to_the_base_or_under_it_is_confined() {
    // `if (p !== dir && !p.startsWith(dir + sep)) continue;`: p is dir or inside it.
    let found = route(
        "const dir = '/srv/logs';\nfor (const name of req.body.names) {\n  \
             const p = path.resolve(path.join(dir, name));\n  \
             if (p !== dir && !p.startsWith(dir + path.sep)) continue;\n  fs.readFileSync(p);\n}",
    );
    assert!(found.is_empty(), "{found:?}");
    // An equality alone proves nothing.
    assert_eq!(
        route("const p = req.body.p; if (p !== other) return; fs.readFileSync(p);"),
        vec![(VulnClass::PathTraversal, Severity::High)]
    );
}

#[test]
fn injected_modules_are_modules() {
    // `options.path || path` is the path module (or a test's stand-in), not data.
    let found = one(
        "function open(options) {\n  const pathApi = options.path || path;\n  const fsApi = options.fs || fs;\n  \
             const p = pathApi.join('/srv/logs', 'app.log');\n  return fsApi.readFileSync(p);\n}\n\
             app.post('/x', (req, res) => open({ requested: req.body.name }));",
    );
    assert!(found.is_empty(), "{found:?}");
    // ...and its sinks are the module's sinks.
    let found = one(
        "function read(options, name) { const fsApi = options.fs || fs; return fsApi.readFileSync(name); }\n\
             app.post('/x', (req, res) => read({}, req.body.name));",
    );
    assert!(
        found.iter().any(|f| f.0 == VulnClass::PathTraversal),
        "{found:?}"
    );
}

#[test]
fn a_path_confined_to_a_directory_is_safe_to_open() {
    let head = "const { shell } = require('electron');\nconst path = require('path');\n";
    // `shell.openPath` opens the file a path names: a path confined to a directory is safe.
    let found = scan(&format!(
        "{head}ipcMain.handle('open', (_e, name) => {{ const p = path.resolve(path.join(LOGS, name));\n  \
             if (!p.startsWith(LOGS + path.sep)) return;\n  shell.openPath(p);\n}});"
    ));
    assert!(found.is_empty(), "{found:?}");
    let found = scan(&format!(
        "{head}ipcMain.handle('open', (_e, name) => {{ shell.openPath(name); }});"
    ));
    assert!(
        found.iter().any(|f| f.0 == VulnClass::CommandInjection),
        "{found:?}"
    );
}

#[test]
fn a_base_the_attacker_chose_confines_nothing() {
    // The base itself comes from a header: the containment check proves nothing.
    assert_eq!(
        route(
            "const base = path.resolve(path.join(ROOT, req.headers.blog));\n\
                 const p = path.resolve(path.join(base, req.body.p));\n\
                 if (p !== base && !p.startsWith(`${base}${path.sep}`)) return;\nfs.readFileSync(p);"
        ),
        vec![(VulnClass::PathTraversal, Severity::High)]
    );
    // A fixed base confines.
    assert!(
            route(
                "const base = path.resolve(ROOT);\nconst p = path.resolve(path.join(base, req.body.p));\n\
                 if (p !== base && !p.startsWith(`${base}${path.sep}`)) return;\nfs.readFileSync(p);"
            )
            .is_empty()
        );
    // A helper's base parameter is the caller's: the helper still confines its path.
    let found = one(
        "function safeJoin(base, p) { const r = path.resolve(base, p);\n  \
             if (!r.startsWith(base + path.sep)) throw new Error('x');\n  return r; }\n\
             app.get('/x', (req, res) => fs.readFileSync(safeJoin(UPLOADS, req.query.p)));",
    );
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn a_field_read_through_a_spread_parameter_stays_that_field() {
    // `cfg.url` is the `url` of the caller's `overrides`, which it set from the body.
    let found = one(
        "async function test(overrides) { const cfg = { ...defaults(), ...overrides }; await fetch(cfg.url); }\n\
             app.post('/t', async (req, res) => { const o = {}; if (req.body.url) o.url = req.body.url; await test(o); });",
    );
    assert!(found.iter().any(|f| f.0 == VulnClass::Ssrf), "{found:?}");
}

#[test]
fn the_page_url_starts_with_the_pages_own_origin() {
    // `location.href` cannot be a `javascript:` URL; its hash, sliced, can.
    assert!(scan("const to = new URL('/next', window.location.href).toString(); window.location.assign(window.location.href);").is_empty());
    let found = scan("window.location.assign(decodeURIComponent(window.location.hash.slice(1)));");
    assert!(found.iter().any(|f| f.0 == VulnClass::Xss), "{found:?}");
}

#[test]
fn a_joined_path_starts_with_its_root() {
    use Severity::*;
    use VulnClass::*;
    // Under a root, an argument cannot start with `-`: no argument injection.
    assert!(!route("const args = ['-i']; args.push(path.join(LIBRARY, req.params.file)); spawn('ffmpeg', args);")
            .contains(&(CommandInjection, Medium)));
    assert_eq!(
        route("const args = ['-i']; args.push(req.params.file); spawn('ffmpeg', args);"),
        vec![(CommandInjection, Medium)]
    );
    // Still a path traversal.
    assert_eq!(
        route("fs.readFileSync(path.join(LIBRARY, req.params.file));"),
        vec![(PathTraversal, High)]
    );
}

#[test]
fn sinks_in_callbacks_and_nested_functions_belong_to_the_parameters_function() {
    use VulnClass::*;
    let found = one(
        "function run(cmd) { return new Promise((resolve) => exec(cmd, resolve)); }\n\
             app.get('/x', (req, res) => run(req.query.c));",
    );
    assert!(found.iter().any(|f| f.0 == CommandInjection), "{found:?}");
    let found = one(
        "async function q(v) { await db.transaction(async (trx) => trx.raw('SELECT * FROM t WHERE a = ' + v)); }\n\
             app.get('/x', (req, res) => q(req.query.a));",
    );
    assert!(found.iter().any(|f| f.0 == SqlInjection), "{found:?}");
    let found = one(
        "function outer(a) { function inner(b) { exec('ls ' + a); } inner('x'); }\n\
             app.get('/x', (req, res) => outer(req.query.a));",
    );
    assert!(found.iter().any(|f| f.0 == CommandInjection), "{found:?}");
    assert!(
            one("function run(cmd) { return new Promise((r) => exec('ls', r)); }\napp.get('/x', (req, res) => run(req.query.c));")
                .is_empty()
        );
}

#[test]
fn rest_parameters_take_every_later_argument() {
    use VulnClass::*;
    let found = one(
        "function run(a, ...rest) { exec('ls ' + rest[0]); }\napp.get('/x', (req, res) => run('x', req.query.a));",
    );
    assert!(found.iter().any(|f| f.0 == CommandInjection), "{found:?}");
    let found = one(
        "function save(buf, ...p) { fs.writeFileSync(path.join(...p), buf); }\n\
             app.post('/x', (req, res) => save(B, ROOT, req.params.a));",
    );
    assert!(found.iter().any(|f| f.0 == PathTraversal), "{found:?}");
    let found = scan(
        "const { exec } = require('child_process');\n\
             io.on('connection', (socket) => { socket.onAny((event, ...args) => exec(args[0])); });",
    );
    assert!(found.iter().any(|f| f.0 == CommandInjection), "{found:?}");
    // The value lands in `a`; the rest is empty or clean.
    assert!(one("function f(a, ...rest) { exec('ls ' + rest[0]); }\napp.get('/x', (req, res) => f(req.query.a));").is_empty());
    assert!(one("function f(a, ...rest) { exec(a); }\napp.get('/x', (req, res) => f('ls', req.query.x));").is_empty());
}

#[test]
fn callbacks_get_elements_and_give_results() {
    use Severity::*;
    use VulnClass::*;
    let critical = vec![(CommandInjection, Critical)];
    assert_eq!(
        route("exec(req.body.list.map((p) => 'x' + p).join(' '));"),
        critical
    );
    assert_eq!(
        route("Promise.resolve(req.query.c).then((c) => exec(c));"),
        critical
    );
    assert_eq!(
        route(
            "const s = req.body.f.reduce((acc, f) => acc + ',' + f, ''); db.query('SELECT ' + s + ' FROM t');"
        ),
        vec![(SqlInjection, High)]
    );
    // A helper iterating its parameter: summarized, reported at the route.
    let found = one(
        "function runAll(list) { list.forEach((x) => exec(x)); }\napp.get('/a', (req, res) => runAll(req.body.list));",
    );
    assert!(found.iter().any(|f| f.0 == CommandInjection), "{found:?}");
    // A callback by reference: its summary, with the element as argument.
    let found = one(
        "function run(x) { exec(x); }\napp.get('/a', (req, res) => req.body.list.forEach(run));",
    );
    assert!(found.iter().any(|f| f.0 == CommandInjection), "{found:?}");
    // Nothing of the element returned; numbers; plain arrays.
    assert!(route("exec(req.body.list.map(() => 'x').join(' '));").is_empty());
    assert!(route("exec(req.body.ids.map(Number).join(' '));").is_empty());
    assert!(route("exec([1, 2].map((x) => x * 2).join(' '));").is_empty());
}

#[test]
fn replace_callbacks_and_regex_captures() {
    use Severity::*;
    use VulnClass::*;
    let critical = vec![(CommandInjection, Critical)];
    assert_eq!(
        route("req.query.s.replace(/x(.*)/g, (m, g) => exec(g));"),
        critical
    );
    assert_eq!(
        route("const m = /a(.*)/.exec(req.query.s); exec(m[1]);"),
        critical
    );
    assert_eq!(
        route("const re = /a(.*)/; const m = re.exec(req.query.s); exec(m[1]);"),
        critical
    );
    assert_eq!(route("exec(req.query.s.match(/a(.*)/)[1]);"), critical);
    assert!(route("'abc'.replace(/b/, (m) => exec(m));").is_empty());
    assert!(route("const m = /x/.exec(CONFIG.s); exec(m[0]);").is_empty());
}

#[test]
fn allowlist_captures_are_safe() {
    assert!(route(
            "const m = /^(\\d{15,25})\\.(png|gif)$/.exec(String(req.params.file || '')); res.sendFile(path.join(DIR, m[1] + '.' + m[2]));"
        )
        .is_empty());
    assert!(
        !route(
            "const m = /^(.+)\\.png$/.exec(req.params.file); res.sendFile(path.join(DIR, m[1]));"
        )
        .is_empty()
    );
    // What a match holds is made of what the pattern matches, anchored or not.
    assert!(route(
            "const m = req.params.file.match(/\\.([a-zA-Z0-9]{2,5})$/); const ext = m ? m[1] : 'bin'; res.sendFile(path.join(DIR, 'f.' + ext));"
        )
        .is_empty());
    assert!(
        !route("const m = req.params.file.match(/\\/(.*)$/); res.sendFile(path.join(DIR, m[1]));")
            .is_empty()
    );
}

#[test]
fn keys_and_values_are_told_apart() {
    use VulnClass::*;
    // A helper that builds SQL from its argument's keys: values from the body, keys fixed.
    let helper = "function update(table, fields) { const keys = Object.keys(fields);\n  \
                      db.prepare(`UPDATE t SET ${keys.map((k) => `${k} = ?`).join(', ')}`).run(...keys.map((k) => fields[k])); }\n";
    assert!(one(&format!(
            "{helper}app.post('/x', (req, res) => {{ const fields = {{}};\n  \
             for (const key of ['a', 'b']) fields[key] = req.body[key];\n  update('t', fields); }});"
        ))
        .is_empty());
    // ...the body itself: its keys are the attacker's.
    let found = one(&format!(
        "{helper}app.post('/x', (req, res) => update('t', req.body));"
    ));
    assert!(found.iter().any(|f| f.0 == SqlInjection), "{found:?}");
    // An attacker-chosen computed key.
    let found =
        route("const o = {}; o[req.query.k] = 1; for (const k of Object.keys(o)) exec('ls ' + k);");
    assert!(found.iter().any(|f| f.0 == CommandInjection), "{found:?}");
}

#[test]
fn tuples_keep_their_positions() {
    use VulnClass::*;
    // Literal keys, attacker values: `SET topic = ?` is not an injection.
    assert!(route(
            "const extras = []; extras.push(['topic', req.body.topic]); extras.push(['mode', 1]);\n\
             db.prepare(`UPDATE c SET ${extras.map(([k]) => `${k} = ?`).join(', ')}`).run(...extras.map(([, v]) => v));"
        )
        .is_empty());
    let found = route(
        "const extras = []; extras.push([req.body.col, 1]); db.prepare(`UPDATE c SET ${extras.map(([k]) => `${k} = ?`).join(', ')}`);",
    );
    assert!(found.iter().any(|f| f.0 == SqlInjection), "{found:?}");
    // `Object.entries` of a literal: keys are the code's.
    assert!(route("const o = { name: req.body.name }; for (const [k, v] of Object.entries(o)) db.query(`UPDATE t SET ${k} = ?`, [v]);").is_empty());
    let found = route(
        "for (const [k, v] of Object.entries(req.body)) db.query(`UPDATE t SET ${k} = ?`, [v]);",
    );
    assert!(found.iter().any(|f| f.0 == SqlInjection), "{found:?}");
}

#[test]
fn appending_a_created_node_is_no_html_injection() {
    assert!(scan("const iframe = document.createElement('iframe'); iframe.title = location.hash; shadowRoot.append(iframe);").is_empty());
    let found = scan("const html = '<b>' + location.hash + '</b>'; $(el).append(html);");
    assert!(found.iter().any(|f| f.0 == VulnClass::Xss), "{found:?}");
    // corosolto: created by another document, assigned after its declaration.
    assert!(scan("const doc = host.ownerDocument; let video = null; video = doc.createElement('video'); video.src = `/v/${location.hash}.webm`; media.append(video);").is_empty());
    assert!(scan("const row = template.content.cloneNode(true); row.title = location.hash; list.append(row);").is_empty());
    // A string is still markup for jQuery.
    let found = scan(
        "let video = null; video = '<video src=' + location.hash + '>'; $(media).append(video);",
    );
    assert!(found.iter().any(|f| f.0 == VulnClass::Xss), "{found:?}");
}

#[test]
fn a_relative_path_that_does_not_climb_confines_its_file() {
    let head = "const { join, relative } = require('path');\nconst fs = require('fs');\nconst app = express();\nconst publicRoot = '/srv/public';\n";
    // corosolto's dev tools, in place and through a variable.
    assert!(one(&format!("{head}app.get('/a', (req, res) => {{ const file = join(publicRoot, req.query.p); if (!relative(publicRoot, file).startsWith('..')) {{ res.end(fs.readFileSync(file)); }} }});")).is_empty());
    assert!(one(&format!("{head}app.get('/b', (req, res) => {{ const file = join(publicRoot, req.query.p); const rel = relative(publicRoot, file); if (rel.startsWith('..')) {{ return res.end(); }} res.end(fs.readFileSync(file)); }});")).is_empty());
    // A base the attacker chose confines nothing.
    assert_eq!(one(&format!("{head}app.get('/c', (req, res) => {{ const file = join(publicRoot, req.query.p); const rel = relative(req.query.base, file); if (rel.startsWith('..')) {{ return res.end(); }} res.end(fs.readFileSync(file)); }});")).len(), 1);
}

#[test]
fn string_methods_url_host_allowlists_and_branch_objects() {
    // p5.js signup: `email.toLowerCase()` threw unless `email` was a string.
    assert!(route("const { email } = req.body; const lower = email.toLowerCase(); await User.findOne({ email });").is_empty());
    let found = route("const { email } = req.body; await User.findOne({ email });");
    assert!(
        found.iter().any(|f| f.0 == VulnClass::NosqlInjection),
        "{found:?}"
    );
    // Steam_Buff: the host of a parsed URL checked against an allowlist.
    let hosts = "const HOSTS = new Set(['api.example.com']);\n";
    assert!(one(&format!("{hosts}app.post('/p', async (req, res) => {{ const url = new URL(req.body.url); if (!HOSTS.has(url.hostname)) {{ return res.end(); }} res.send(await fetch(url.toString())); }});")).is_empty());
    assert_eq!(one(&format!("{hosts}app.post('/q', async (req, res) => {{ const url = new URL(req.body.url); if (!url.pathname.startsWith('/api')) {{ return res.end(); }} res.send(await fetch(url.toString())); }});")).len(), 1);
    // bentopdf's dev proxy: the host copied first, the string the URL was parsed from sent.
    assert!(one(&format!("{hosts}app.post('/r', async (req, res) => {{ const target = req.query.url; let host; try {{ const parsed = new URL(target); host = parsed.hostname; }} catch {{ return res.end(); }} if (!HOSTS.has(host)) {{ return res.end(); }} res.send(await fetch(target)); }});")).is_empty());
    // The string replaced after the check is not what was checked.
    assert_eq!(one(&format!("{hosts}app.post('/s', async (req, res) => {{ let target = req.query.url; const parsed = new URL(target); if (!HOSTS.has(parsed.hostname)) {{ return res.end(); }} target = req.query.other; res.send(await fetch(target)); }});")).len(), 1);
    // yuvomi: `{ where, params }` from either branch; only `params` holds the request.
    assert!(route("const ids = req.body.ids; const scope = ids ? { where: `id IN (${ids.map(() => '?').join(',')})`, params: [...ids] } : { where: 'id > 0', params: [] }; db.prepare(`DELETE FROM t WHERE ${scope.where}`).run(...scope.params);").is_empty());
    let found = route(
        "const scope = req.body.x ? { where: `id = ${req.body.id}`, params: [] } : { where: 'id = 1', params: [] }; db.prepare(`DELETE FROM t WHERE ${scope.where}`).run();",
    );
    assert!(
        found.iter().any(|f| f.0 == VulnClass::SqlInjection),
        "{found:?}"
    );
}

#[test]
fn calls_reach_the_closest_function_of_that_name() {
    let top = "const app = express();\nfunction send(p) { return fs.readFileSync(p); }\n";
    // A nested `send` (hoisted or not) shadows the top-level one.
    assert!(one(&format!("{top}function shadowed(x) {{ const send = (m) => m.length; return send(x); }}\napp.get('/1', (req, res) => res.send(shadowed(req.query.f)));")).is_empty());
    assert!(one(&format!("{top}function hoisted(x) {{ return send(x); function send(m) {{ return String(m).length; }} }}\napp.get('/2', (req, res) => res.send(hoisted(req.query.f)));")).is_empty());
    assert_eq!(one(&format!("{top}function plain(x) {{ return send(x); }}\napp.get('/3', (req, res) => res.send(plain(req.query.f)));")).len(), 1);
    // dsh-codex: two `follow` closures of different functions; each call reaches its own.
    let follow = "const http = require('http');\nconst app = express();\n\
            function a(url) { const follow = (u) => u.length; return follow(url); }\n\
            function b(url) { const follow = (u) => http.get(u); return follow(url); }\n";
    assert!(
        one(&format!(
            "{follow}app.post('/a', (req, res) => {{ a(req.body.url); res.end(); }});"
        ))
        .is_empty()
    );
    assert_eq!(
        one(&format!(
            "{follow}app.post('/b', (req, res) => {{ b(req.body.url); res.end(); }});"
        ))
        .len(),
        1
    );
    // mStream's album art: the module a URL's scheme picks is that module either way.
    let found = one(
        "const http = require('http');\nconst https = require('https');\nconst app = express();\n\
            function get(u) { const mod = u.startsWith('https') ? https : http; return mod.get(u, (res) => res.resume()); }\n\
            app.post('/art', (req, res) => { get(req.body.url); res.end(); });\n",
    );
    assert!(found.iter().any(|f| f.0 == VulnClass::Ssrf), "{found:?}");
}

#[test]
fn middleware_that_lets_requests_through_guards_nothing() {
    let route =
        "app.get('/files', (req, res) => { res.send(fs.readFileSync(req.query.name)); });\n";
    let high = |guard: &str| {
        let found = one(&format!("const app = express();\n{guard}\n{route}"));
        assert!(
            !found.is_empty() && found.iter().all(|f| f.1 == Severity::High),
            "{guard}: {found:?}"
        );
    };
    // No credential: an origin, a protocol.
    high(
        "const ALLOWED = 'https://app.example.com';\napp.use((req, res, next) => { if (req.get('origin') !== ALLOWED) { return res.status(403).end(); } next(); });",
    );
    high(
        "app.use((req, res, next) => { if (req.protocol !== HTTPS) { return res.sendStatus(403); } next(); });",
    );
    // A way past the check: `next()` before it or in its answer, a conjunction.
    high(
        "app.use((req, res, next) => { if (req.method === 'GET') { return next(); } if (req.get('x-api-key') !== API_KEY) { return res.sendStatus(401); } next(); });",
    );
    high(
        "app.use((req, res, next) => { if (req.user && !req.user.isAdmin) { return res.sendStatus(403); } next(); });",
    );
    high(
        "app.use((req, res, next) => { if (!req.session.user) { res.status(401); return next(); } next(); });",
    );
    // Only on some runs, or under a path it cannot read.
    high(
        "if (TOKEN) { app.use((req, res, next) => { if (req.get('authorization') !== TOKEN) { return res.sendStatus(401); } next(); }); }",
    );
    high(
        "app.use(config.panelPath, (req, res, next) => { if (!req.session.admin) { return res.sendStatus(403); } next(); });",
    );
    // A verb's guard: its method and path only.
    high(
        "app.post('/files', (req, res, next) => { if (!req.session.admin) { return res.sendStatus(403); } next(); });",
    );
    high(
        "app.all('/fil', (req, res, next) => { if (!req.session.admin) { return res.sendStatus(403); } next(); });",
    );
    // A shared secret in a credential header still guards (admin).
    let secret = one(&format!(
        "const app = express();\napp.use((req, res, next) => {{ const authorization = req.header('Authorization'); if (authorization !== SECRET) {{ return res.status(403).end(); }} next(); }});\n{route}"
    ));
    assert!(
        !secret.is_empty() && secret.iter().all(|f| f.1 == Severity::Medium),
        "{secret:?}"
    );
}

#[test]
fn checks_that_other_values_pass_clean_nothing() {
    let fetches = |check: &str| {
        one(&format!("app.post('/p', async (req, res) => {{ const url = new URL(req.body.url); {check} res.send(await fetch(url.toString())); }});")).len()
    };
    // A prefix without the origin's `/`, a pattern, a denylist: other hosts pass.
    assert_eq!(
        fetches("if (!url.origin.startsWith(API_ORIGIN)) { return res.end(); }"),
        1
    );
    assert_eq!(
        fetches("if (!url.href.startsWith('https://api.example.com')) { return res.end(); }"),
        1
    );
    assert_eq!(
        fetches("if (!/^[a-z0-9.-]+$/i.test(url.hostname)) { return res.end(); }"),
        1
    );
    assert_eq!(
        fetches("if (isBlockedHost(url.hostname)) { return res.end(); }"),
        1
    );
    // With it, the string checked goes to that host.
    assert!(one("app.post('/q', async (req, res) => { const u = req.body.url; if (!u.startsWith('https://api.example.com/')) { return res.end(); } res.send(await fetch(u)); });").is_empty());
    assert_eq!(one("app.post('/q', async (req, res) => { const u = req.body.url; if (!u.startsWith('https://api.example.com')) { return res.end(); } res.send(await fetch(u)); });").len(), 1);
    // Facts that hold on one path only: a caught throw, `||=`, a short circuit.
    let users = |body: &str| route(body).len();
    assert_eq!(
        users(
            "const { email } = req.body; try { email.toLowerCase(); } catch (e) {} await User.findOne({ email });"
        ),
        1
    );
    assert_eq!(
        users(
            "const { email } = req.body; let name; name ||= email.trim(); await User.findOne({ email });"
        ),
        1
    );
    // `..` alone passes `startsWith('../')`; a relative check must use `'..'`.
    let rel = "const ROOT = '/srv/up';\napp.delete('/d', (req, res) => { const dir = path.join(ROOT, req.query.dir); const rel = path.relative(ROOT, dir); if (rel.startsWith('../')) { return res.end(); } fs.rmSync(dir, { recursive: true }); });";
    assert_eq!(one(rel).len(), 1);
    // A destructuring write replaces what was checked.
    assert_eq!(one("const ROOT = '/srv/up';\napp.post('/w', (req, res) => { let file = path.join(ROOT, req.query.f); const rel = path.relative(ROOT, file); ({ file } = req.body); if (rel.startsWith('..')) { return res.end(); } res.send(fs.readFileSync(file)); });").len(), 1);
}

#[test]
fn a_base_the_caller_passes_confines_as_much_as_it_is_the_callers() {
    let helpers = "const ROOT = '/srv/data';\n\
            function readInside(base, file) { const rel = path.relative(base, file); if (rel.startsWith('..')) { throw new Error('out'); } return fs.readFileSync(file); }\n\
            function isWithin(base, p) { const r = path.resolve(p); return r.startsWith(path.resolve(base) + path.sep); }\n";
    assert!(one(&format!("{helpers}app.get('/a', (req, res) => res.send(readInside(ROOT, path.join(ROOT, req.query.n))));")).is_empty());
    assert_eq!(one(&format!("{helpers}app.get('/b', (req, res) => {{ const base = path.join(ROOT, req.query.ws); res.send(readInside(base, path.join(base, req.query.n))); }});")).len(), 1);
    // Judged by its body, not by its name: inside the base the attacker chose.
    assert!(one(&format!("{helpers}app.get('/c', (req, res) => {{ const f = path.join(ROOT, req.query.n); if (!isWithin(ROOT, f)) {{ return res.end(); }} res.send(fs.readFileSync(f)); }});")).is_empty());
    assert_eq!(one(&format!("{helpers}app.get('/d', (req, res) => {{ const f = path.join(ROOT, req.query.n); if (!isWithin(req.query.base, f)) {{ return res.end(); }} res.send(fs.readFileSync(f)); }});")).len(), 1);
}

#[test]
fn filtering_untainted_values_by_a_parameter_does_not_taint_them() {
    // `file.startsWith(key)` picks among directory entries the server listed; the caller's
    // `key` decides which one, but never flows into the path.
    let helpers = "const DIR = './fixes';\n\
            function pick(key) { for (const file of fs.readdirSync(DIR)) { if (file.startsWith(key)) { return fs.readFileSync(DIR + '/' + file); } } }\n\
            function first(key) { const file = fs.readdirSync(DIR)[0]; if (file.startsWith(key)) { return fs.readFileSync(DIR + '/' + file); } }\n\
            function fixed(key) { const file = 'x.json'; if (file.startsWith(key)) { return fs.readFileSync(DIR + '/' + file); } }\n\
            function both(key, name) { const f = path.join(DIR, name); if (f.startsWith(key)) { return fs.readFileSync(f); } }\n";
    assert!(
        one(&format!(
            "{helpers}app.get('/a/:key', (req, res) => res.send(pick(req.params.key)));"
        ))
        .is_empty()
    );
    assert!(
        one(&format!(
            "{helpers}app.get('/b/:key', (req, res) => res.send(first(req.params.key)));"
        ))
        .is_empty()
    );
    assert!(
        one(&format!(
            "{helpers}app.get('/c/:key', (req, res) => res.send(fixed(req.params.key)));"
        ))
        .is_empty()
    );
    // A value that carries attacker data is still only as confined as the base it is checked
    // against: under an attacker-chosen base, nothing.
    assert_eq!(
        one(&format!(
            "{helpers}app.get('/d', (req, res) => res.send(both(req.query.base, req.query.n)));"
        ))
        .len(),
        1
    );
}

#[test]
fn a_segment_confined_under_one_base_is_confined_under_another() {
    // mStream getVPathInfo: the check is on `resolve(join(base, rel))`, but the function
    // returns `rel`, which the caller re-joins with a (DB-derived) base. `rel` cannot climb.
    let vpath = "const ROOT = '/srv/lib';\n\
            function vinfo(url) { const rel = path.relative('x', path.normalize(url)); const full = path.join(ROOT, rel); const r = path.resolve(full); if (r !== ROOT && !r.startsWith(ROOT + path.sep)) throw new Error('escape'); return { rel }; }\n";
    assert!(
            one(&format!("{vpath}app.get('/a', (req, res) => {{ const info = vinfo(req.query.f); res.send(fs.readFileSync(path.join('/other/base', info.rel))); }});")).is_empty(),
            "a segment proven not to climb should confine a re-join"
        );
    // In place: `full = join(base, seg)` confined, then `seg` re-joined elsewhere.
    assert!(one("const B = '/srv/b';\napp.get('/x', (req, res) => { const seg = req.query.s; const full = path.join(B, seg); const r = path.resolve(full); if (!r.startsWith(B + path.sep)) return res.end(); res.send(fs.readFileSync(path.join('/zzz', seg))); });").is_empty());
    // But a base the attacker chose confines nothing: the segment stays tainted.
    assert_eq!(
            one("app.get('/y', (req, res) => { const base = req.query.b; const seg = req.query.s; const full = path.join(base, seg); const r = path.resolve(full); if (!r.startsWith(base + path.sep)) return res.end(); res.send(fs.readFileSync(path.join('/zzz', seg))); });").len(),
            1
        );
}

#[test]
fn archives_whose_library_checks_entry_names() {
    // blot: yauzl rejects absolute and `..` entry names unless `decodeStrings: false`.
    let unzip = |options: &str| {
        one(&format!(
            "const yauzl = require('yauzl');\nfunction extract(zipPath, dir) {{ yauzl.open(zipPath, {options}, (err, zipfile) => {{ zipfile.on('entry', (entry) => {{ fs.createWriteStream(path.join(dir, entry.fileName)); }}); }}); }}"
        ))
    };
    assert!(unzip("{ lazyEntries: true }").is_empty());
    assert_eq!(
        unzip("{ lazyEntries: true, decodeStrings: false }").len(),
        1
    );
    assert_eq!(unzip("opts").len(), 1);
    // Another library's entries are the archive author's.
    assert_eq!(one("const unzipper = require('unzipper');\nfunction extract(stream, dir) { stream.pipe(unzipper.Parse()).on('entry', (entry) => { fs.createWriteStream(path.join(dir, entry.path)); }); }").len(), 1);
}

#[test]
fn dev_server_middleware_is_rated_like_any_server() {
    // module-federation's Modern.js plugin: Rsbuild's `dev.setupMiddlewares`.
    let rsbuild = one(
        "export const plugin = () => ({ dev: { setupMiddlewares: [(middlewares) => middlewares.unshift((req, res, next) => { fs.createReadStream(path.join(process.cwd(), 'dist' + req.url)).pipe(res); })] } });",
    );
    assert_eq!(rsbuild.len(), 1, "{rsbuild:?}");
    assert_eq!((rsbuild[0].1, rsbuild[0].3), (Severity::High, "dev-server"));
    let vite = one(
        "export default { plugins: [{ configureServer(server) { server.middlewares.use((req, res) => { res.end(fs.readFileSync(path.join('public', req.url))); }); } }] };",
    );
    assert_eq!(vite.len(), 1, "{vite:?}");
    assert_eq!((vite[0].1, vite[0].3), (Severity::High, "dev-server"));
    // A Redux store's middleware list is no server.
    assert!(one("const middlewares = [];\nmiddlewares.push((store) => (next) => (action) => next(action));").is_empty());
    // webpack-dev-server: `{ path, middleware }` objects.
    let webpack = one(
        "module.exports = { devServer: { setupMiddlewares: (middlewares, devServer) => { middlewares.unshift({ name: 'files', path: '/files', middleware: (req, res) => { res.end(fs.readFileSync(path.join('public', req.query.f))); } }); return middlewares; } } };",
    );
    assert_eq!(webpack.len(), 1, "{webpack:?}");
    assert_eq!(webpack[0].3, "dev-server");
    // Modern.js: `tools.devServer.before: [(req, res, next) => ...]`.
    let before = one(
        "export const plugin = () => ({ tools: { devServer: { before: [(req, res, next) => { fs.createReadStream(path.join('dist', req.url)).pipe(res); }], port: 8080 } } });",
    );
    assert_eq!(before.len(), 1, "{before:?}");
    assert_eq!((before[0].1, before[0].3), (Severity::High, "dev-server"));
    // Other options are only values.
    assert!(one("export default { devServer: { before: [], headers: { a: 'b' } } };").is_empty());
}

#[test]
fn the_left_side_of_and_is_the_value_only_when_falsy() {
    // webbrain's dev server: `m && ROOTS[m[1]]` is a base the server holds (or `null`).
    let server = "const http = require('http');\nconst ROOTS = { a: '/srv/a' };\n";
    assert!(one(&format!("{server}http.createServer((req, res) => {{ const m = req.url.match(/^\\/(\\w+)\\/(.+)$/); const base = m && ROOTS[m[1]]; if (!base) {{ return res.end(); }} const file = path.resolve(base, m[2]); if (!file.startsWith(path.resolve(base) + path.sep)) {{ return res.end(); }} fs.createReadStream(file).pipe(res); }});")).is_empty());
    // The right side is still the value.
    assert_eq!(one(&format!("{server}http.createServer((req, res) => {{ const m = req.url.match(/^\\/(.+)$/); const file = m && m[1]; fs.createReadStream(file).pipe(res); }});")).len(), 1);
}

#[test]
fn inline_middleware_that_answers_403_is_authentication() {
    let admin_area = "const fs = require('fs');\nconst app = express();\n\
            app.get('/admin/before', (req, res) => { res.send(fs.readFileSync(req.query.f)); });\n\
            app.all('/admin/{*path}', (req, res, next) => { if (req.user.admin !== true) { return res.status(403).end(); } next(); });\n\
            app.post('/admin/files', (req, res) => { res.send(fs.readFileSync(req.body.p)); });\n";
    let found = one(admin_area);
    assert!(found.iter().any(|f| f.1 == Severity::Medium), "{found:?}");
    assert!(
        found.iter().any(|f| f.1 == Severity::High),
        "registered before the guard: {found:?}"
    );
    // blot's internal service: a request header against a secret of the server.
    let secret = one("const fs = require('fs');\nconst app = express();\n\
            app.use((req, res, next) => { const authorization = req.header('Authorization'); if (authorization !== Authorization) { return res.status(403).send('no'); } next(); });\n\
            app.post('/delete', (req, res) => { fs.unlinkSync(req.body.path); res.end(); });\n");
    assert!(
        secret.iter().all(|f| f.1 == Severity::Medium) && !secret.is_empty(),
        "{secret:?}"
    );
    // A logged-in user is not an admin: still high.
    let user = one("const fs = require('fs');\nconst app = express();\n\
            app.use((req, res, next) => { if (!req.session.user) { return res.sendStatus(401); } next(); });\n\
            app.get('/f', (req, res) => { res.send(fs.readFileSync(req.query.f)); });\n");
    assert!(
        user.iter().all(|f| f.1 == Severity::High) && !user.is_empty(),
        "{user:?}"
    );
}

#[test]
fn confining_a_resolved_path_confines_the_path_it_resolves() {
    // compressing: `resolvedDestPath = path.resolve(destFilePath)` checked by a helper that
    // compares resolved paths, then `destFilePath` written.
    let head = "const path = require('path');\nconst fs = require('fs');\n\
            function within(child, parent) { const c = path.resolve(child); const p = path.resolve(parent); return c === p || c.startsWith(p + path.sep); }\n\
            const root = path.resolve('/srv/out');\n";
    assert!(one(&format!("{head}app.post('/x', (req, res) => {{ const dest = path.join(root, req.body.name); const resolved = path.resolve(dest); if (!within(resolved, root)) {{ return res.end(); }} fs.writeFileSync(dest, 'x'); }});")).is_empty());
    // Another path, unchecked, is still the attacker's.
    assert_eq!(one(&format!("{head}app.post('/y', (req, res) => {{ const other = path.join(root, req.body.other); const dest = path.join(root, req.body.name); const resolved = path.resolve(dest); if (!within(resolved, root)) {{ return res.end(); }} fs.writeFileSync(other, 'x'); }});")).len(), 1);
    // A base the attacker chose confines nothing.
    assert_eq!(one(&format!("{head}app.post('/z', (req, res) => {{ const dest = path.join(root, req.body.name); const resolved = path.resolve(dest); if (!within(resolved, req.body.base)) {{ return res.end(); }} fs.writeFileSync(dest, 'x'); }});")).len(), 1);
}

#[test]
fn a_check_after_building_a_path_cleans_what_was_built() {
    let head = "import { join } from 'path';\nimport { readFileSync } from 'fs';\n";
    // openGym: the file is joined first, the name checked after, the file read last.
    assert!(route(&format!("{head}app.get('/m', (req, res) => {{ const name = req.query.n; const file = join(root, 'still', name); if (!/^\\d{{4,5}}\\.(webp|mp4)$/.test(name)) {{ return res.end(); }} res.end(readFileSync(file)); }});")).is_empty());
    // A value changed on the way (decoded) is not what the check saw.
    assert_eq!(route(&format!("{head}app.get('/d', (req, res) => {{ const raw = req.query.n; const file = join(root, decodeURIComponent(raw)); if (!/^[a-z%0-9]+$/.test(raw)) {{ return res.end(); }} res.end(readFileSync(file)); }});")).len(), 1);
    // Built from the old value of a name written since.
    assert_eq!(route(&format!("{head}app.get('/r', (req, res) => {{ let name = req.query.a; const file = join(root, name); name = req.query.b; if (!/^\\d+$/.test(name)) {{ return res.end(); }} res.end(readFileSync(file)); }});")).len(), 1);
    // Two attacker parts: a check on one leaves the other.
    assert_eq!(route(&format!("{head}app.get('/t', (req, res) => {{ const a = req.query.a; const b = req.query.b; const file = join(root, a, b); if (!/^\\d+$/.test(a)) {{ return res.end(); }} res.end(readFileSync(file)); }});")).len(), 1);
}

#[test]
fn jumps_and_conditional_expressions_join_their_paths() {
    // `break` after a tainted assignment: the value leaves the loop with it.
    assert_eq!(route("app.get('/a', (req, res) => { let x = 'ls'; for (const k of [1, 2]) { if (k) { x = req.query.c; break; } } exec(x); });").len(), 1);
    // A guard that `continue`s still holds for the rest of the body.
    assert!(route("app.post('/b', (req, res) => { for (const f of req.body.files) { if (!/^[a-z]+$/.test(f)) continue; exec('x ' + f); } });").is_empty());
    // An assignment in one branch of `?:` or `&&` leaves the other path's value.
    assert_eq!(route("app.get('/c', (req, res) => { let x = req.query.c; req.query.f ? (x = 'ls') : 0; exec(x); });").len(), 1);
    assert_eq!(route("app.get('/d', (req, res) => { let x = req.query.c; req.query.f && (x = 'ls'); exec(x); });").len(), 1);
    // A node on one path only is still markup on the other.
    let found = scan(
        "let x = '<b>' + location.hash + '</b>'; if (window.cond) { x = document.createElement('b'); } $(el).append(x);",
    );
    assert!(found.iter().any(|f| f.0 == VulnClass::Xss), "{found:?}");
}

#[test]
fn a_parameter_never_borrows_a_named_regex() {
    // `re` is the caller's regex, not the file's `const re`; a `let` reassigned is neither.
    assert_eq!(route("function safe(s) { const re = /^[a-z]+$/; return re.test(s); }\nfunction pick(s, re) { const m = s.match(re); return m && m[0]; }\napp.get('/a', (req, res) => { exec('x ' + pick(req.query.s, new RegExp(req.query.r))); });").len(), 1);
    assert_eq!(route("app.get('/b', (req, res) => { let re = /^[a-z]+$/; re = new RegExp(req.query.r); const m = req.query.s.match(re); exec('x ' + m[0]); });").len(), 1);
}

#[test]
fn long_or_chains_of_guards_stay_small() {
    // Each `typeof x === 'string' && x === 'vN'` side gives two facts about `x`; combining a
    // 40-way `||` pair by pair once multiplied them at every level (gigabytes, then a kill).
    let chain: Vec<String> = (0..40)
        .map(|i| format!("(typeof x === 'string' && x === 'v{i}')"))
        .collect();
    let code = format!(
        "app.get('/a', (req, res) => {{ const x = req.query.x; if (!({})) {{ return res.end(); }} exec('run ' + x); }});",
        chain.join(" || ")
    );
    assert!(route(&code).is_empty());
}

#[test]
fn a_check_that_returns_on_bad_input_validates_nothing() {
    // The caller goes on after `return`: only a check that throws protects it.
    assert_eq!(
            route("function checkSafe(v) { if (!/^[a-z]+$/.test(v)) { return; } }\napp.post('/a', (req, res) => { const { n } = req.body; checkSafe(n); exec('run ' + n); });").len(),
            1
        );
    assert!(route("function checkSafe(v) { if (!/^[a-z]+$/.test(v)) { throw new Error('bad'); } }\napp.post('/a', (req, res) => { const { n } = req.body; checkSafe(n); exec('run ' + n); });").is_empty());
    assert_eq!(
            route("function checkStr(v) { if (typeof v !== 'string') { return; } }\napp.post('/b', async (req, res) => { const { uid } = req.body; checkStr(uid); await db.collection('c').deleteOne({ uid }); });").len(),
            1
        );
}

#[test]
fn string_checks_keep_query_operators_out() {
    // indiekit: `if (channel && typeof channel !== 'string') throw`, inline and in a void
    // validator; a falsy value is no operator either.
    assert!(route("app.post('/c', async (req, res) => { const { uid } = req.body; if (uid && typeof uid !== 'string') { throw new Error('x'); } await db.collection('c').deleteOne({ uid }); });").is_empty());
    assert!(route("function check(v) { if (typeof v !== 'string') { throw new Error('x'); } }\napp.post('/b', async (req, res) => { const { uid } = req.body; check(uid); await db.collection('c').deleteOne({ uid }); });").is_empty());
    let found = route(
        "app.post('/d', async (req, res) => { const { uid } = req.body; await db.collection('c').deleteOne({ uid }); });",
    );
    assert!(
        found.iter().any(|f| f.0 == VulnClass::NosqlInjection),
        "{found:?}"
    );
}

#[test]
fn a_constant_assigned_in_a_branch_holds_there_not_after() {
    // uptime-kuma: `executablePath = "/usr/bin/chromium"` right before the install.
    let install = "async function install(p) { childProcess.execSync(p + ' --version'); }\n\
            async function prepare(p) { if (p === '#x') { p = undefined; } else if (!p) { if (process.env.X) { p = '/usr/bin/chromium'; await install(p); } } return p; }\n";
    assert!(one(&format!("{install}io.on('connection', (socket) => {{ socket.on('t', (exe) => {{ prepare(exe); }}); }});")).is_empty());
    // Past the branch the other path's value is back.
    assert_eq!(
            one("io.on('connection', (socket) => { socket.on('u', (cmd) => { if (process.env.Y) { cmd = 'ls'; } exec(cmd); }); });").len(),
            1
        );
}

#[test]
fn captures_of_named_regexes_keep_their_charset() {
    // A local `const`, and a property of an object of regexes (RES's `regexes.profile`).
    assert!(scan("const re = /^\\/u\\/([\\w-]+)$/; const [, name] = location.hash.match(re) || []; el.innerHTML = name;").is_empty());
    assert!(scan("const regexes = { profile: /^\\/u\\/([\\w-]+)$/ }; const [, name] = location.hash.match(regexes.profile) || []; el.innerHTML = name;").is_empty());
    assert!(scan("const regexes = { profile: /^\\/u\\/([\\w-]+)$/ }; const m = regexes.profile.exec(location.hash); el.innerHTML = m[1];").is_empty());
    // A capture that admits markup does not clean it.
    let found = scan(
        "const regexes = { any: /^\\/u\\/(.+)$/ }; const [, name] = location.hash.match(regexes.any) || []; el.innerHTML = name;",
    );
    assert!(found.iter().any(|f| f.0 == VulnClass::Xss), "{found:?}");
}

#[test]
fn a_field_written_on_a_clean_object_taints_that_field() {
    // corosolto: `settings.map` from the URL is not `settings.wpnMode`.
    assert!(scan("const settings = load(); if (!x) { settings.map = location.hash; } el.innerHTML = settings.wpnMode;").is_empty());
    let field =
        scan("const settings = load(); settings.map = location.hash; el.innerHTML = settings.map;");
    assert!(field.iter().any(|f| f.0 == VulnClass::Xss), "{field:?}");
    // The object as a whole still carries it.
    let whole = scan(
        "const settings = load(); settings.map = location.hash; el.innerHTML = JSON.stringify(settings);",
    );
    assert!(whole.iter().any(|f| f.0 == VulnClass::Xss), "{whole:?}");
}

#[test]
fn a_service_workers_requests_are_the_pages() {
    let sw = "async function precache(request) { const base = new URL(request.url).origin; await fetch(base + '/avatars'); }\n\
                  self.addEventListener('fetch', (event) => event.respondWith(precache(event.request)));\n";
    assert!(scan(sw).is_empty(), "{:?}", scan(sw));
}

#[test]
fn callbacks_write_back_to_captured_variables() {
    use Severity::*;
    use VulnClass::*;
    let critical = vec![(CommandInjection, Critical)];
    assert_eq!(
        route("let s = ''; req.body.list.forEach((x) => { s += x; }); exec('ls ' + s);"),
        critical
    );
    assert_eq!(
        route(
            "const ref = { current: '' }; [1].forEach(() => { ref.current = req.query.a; }); exec(ref.current);"
        ),
        critical
    );
    // A shadowing local, a constant write: nothing comes back.
    assert!(
        route("let s = ''; req.body.list.forEach((x) => { let s = x; }); exec('ls ' + s);")
            .is_empty()
    );
    assert!(route("const ref = { current: '' }; [1].forEach(() => { ref.current = 'x'; }); exec(ref.current);").is_empty());
}

#[test]
fn uploads_keep_their_server_chosen_fields_through_collections() {
    assert!(one(
            "function collect(files) { return Object.values(files).flat(); }\n\
             app.post('/u', (req, res) => { const uploads = collect(req.files); uploads.map((f) => fs.remove(f.path)); });"
        )
        .is_empty());
    // The client's name is still the attacker's.
    let found = one(
        "app.post('/u', (req, res) => { req.files.forEach((f) => fs.writeFileSync(path.join(DIR, f.originalname), f.buffer)); });",
    );
    assert!(
        found.iter().any(|f| f.0 == VulnClass::PathTraversal),
        "{found:?}"
    );
    // Each upload of a loop handed to a helper keeps its server-chosen fields.
    let helpers = "function stage(file, name = file.filename) { fs.renameSync(path.join(path.dirname(file.path), name), '/srv/x'); }\n\
             function keep(file) { fs.writeFileSync('/up/' + file.originalname, ''); }\n";
    assert!(
            one(&format!(
                "{helpers}app.post('/u', (req, res) => {{ for (const file of req.files) {{ stage(file); }} }});"
            ))
            .is_empty()
        );
    let found = one(&format!(
        "{helpers}app.post('/u', (req, res) => {{ for (const file of req.files) {{ keep(file); }} }});"
    ));
    assert!(
        found.iter().any(|f| f.0 == VulnClass::PathTraversal),
        "{found:?}"
    );
}

#[test]
fn uploads_returned_by_a_request_helper_stay_uploads() {
    assert!(one(
            "function collectFiles(req) { const out = []; for (const key of Object.keys(req.files)) out.push(...req.files[key]); return out; }\n\
             app.post('/u', (req, res) => { const uploads = collectFiles(req); uploads.map((f) => fs.remove(f.path)); });"
        )
        .is_empty());
}

#[test]
fn typescript_parameter_properties_are_fields() {
    let head = "const { exec } = require('child_process');\n";
    let class =
        "class I { constructor(private readonly cfg: any) {} run() { exec(this.cfg.cmd); } }\n";
    let found = scan_ts(&format!(
        "{head}{class}app.post('/x', (req, res) => new I(req.body).run());"
    ));
    assert!(
        found.iter().any(|f| f.0 == VulnClass::CommandInjection),
        "{found:?}"
    );
    assert!(
        scan_ts(&format!(
            "{head}{class}app.post('/x', (req, res) => new I({{ cmd: 'ls' }}).run());"
        ))
        .is_empty()
    );
    // Without a modifier, the parameter is no field.
    assert!(scan_ts(&format!(
            "{head}class J {{ constructor(cfg: any) {{}} run() {{ exec((this as any).cfg.cmd); }} }}\n\
             app.post('/x', (req, res) => new J(req.body).run());"
        ))
        .is_empty());
}

#[test]
fn es5_constructors_and_prototype_methods_are_classes() {
    let found = one(
        "function C(x) { this.x = x; }\nC.prototype.run = function () { exec('ls ' + this.x); };\n\
             app.get('/x', (req, res) => new C(req.query.a).run());",
    );
    assert!(
        found.iter().any(|f| f.0 == VulnClass::CommandInjection),
        "{found:?}"
    );
    let found = one(
        "function D(x) { this.x = x; }\nD.prototype = { run() { exec('ls ' + this.x); } };\n\
             app.get('/x', (req, res) => new D(req.query.a).run());",
    );
    assert!(
        found.iter().any(|f| f.0 == VulnClass::CommandInjection),
        "{found:?}"
    );
    // Converted on the way in; a lowercase helper is no class.
    assert!(one(
            "function Point(x) { this.x = Number(x); }\nPoint.prototype.s = function () { exec('ls ' + this.x); };\n\
             app.get('/x', (req, res) => new Point(req.query.a).s());"
        )
        .is_empty());
}

#[test]
fn call_apply_and_forwarders_reach_the_function() {
    use VulnClass::*;
    let run = "function run(v) { exec('ls ' + v); }\n";
    for call in [
        "run.call(null, req.query.x)",
        "run.apply(null, [req.query.x])",
        "setImmediate(run, req.query.x)",
        "setTimeout(run, 10, req.query.x)",
    ] {
        let found = one(&format!("{run}app.get('/x', (req, res) => {call});"));
        assert!(
            found.iter().any(|f| f.0 == CommandInjection),
            "{call}: {found:?}"
        );
    }
    // Only the receiver (`this`) is tainted; a constant; the delay.
    for call in [
        "run.call(req.query.x)",
        "run.call(null, 'ls')",
        "setTimeout(run, req.query.ms)",
    ] {
        assert!(
            one(&format!("{run}app.get('/x', (req, res) => {call});")).is_empty(),
            "{call}"
        );
    }
}

#[test]
fn schema_results_argument_guards_and_quote_doubling() {
    use Severity::*;
    use VulnClass::*;
    let critical = vec![(CommandInjection, Critical)];
    // Validation results carry their input, typed.
    assert_eq!(
        route("const r = schema.safeParse(req.body); exec(r.data.cmd);"),
        critical
    );
    assert_eq!(route("exec(schema.parse(req.body).cmd);"), critical);
    assert!(route("exec('echo ' + schema.safeParse(req.body).success);").is_empty());
    assert!(!route("User.find(schema.parse(req.body));").contains(&(NosqlInjection, High)));
    // Argument injection: `--` ends the options; a leading-dash check rejects them.
    assert!(route("spawn('rg', ['--json', '--', req.query.p]);").is_empty());
    assert!(route("const p = req.query.p; if (p.startsWith('-')) throw new Error('x'); spawn('rg', ['--json', p]);").is_empty());
    assert_eq!(
        route("spawn('rg', [req.query.p, '--']);"),
        vec![(CommandInjection, Medium)]
    );
    // ... also through an arguments array built with `push`, or held in a variable.
    assert!(
        route("const args = ['--json']; args.push('--', req.query.p, '.'); spawn('rg', args);")
            .is_empty()
    );
    assert!(
        route("const args = ['--json', '--']; args.push(req.query.p); spawn('rg', args);")
            .is_empty()
    );
    assert!(route("const args = ['--json', '--', req.query.p]; spawn('rg', args);").is_empty());
    assert_eq!(
        route("const args = ['--json']; args.push(req.query.p, '--', '.'); spawn('rg', args);"),
        vec![(CommandInjection, Medium)]
    );
    assert_eq!(
        route(
            "const p = req.query.p; if (p.startsWith('-')) throw new Error('x'); exec('rg ' + p);"
        ),
        critical
    );
    // pg-promise methods; doubled quotes.
    assert_eq!(
        route("db.any('SELECT * FROM t WHERE a = ' + req.query.a);"),
        vec![(SqlInjection, High)]
    );
    assert!(route("db.any('SELECT * FROM t WHERE a = $1', [req.query.a]);").is_empty());
    assert!(route("const v = req.query.a.replace(/'/g, \"''\"); db.query(\"SELECT * FROM t WHERE a = '\" + v + \"'\");").is_empty());
    assert!(!route("const v = req.query.a.replace(/([^'])'/, \"$1''\"); db.query(\"SELECT * FROM t WHERE a = '\" + v + \"'\");").is_empty());
}

#[test]
fn computed_module_paths_are_code_injection_and_dirname_passes() {
    use Severity::*;
    use VulnClass::*;
    assert_eq!(route("require(req.query.m);"), vec![(CodeInjection, High)]);
    assert_eq!(
        route("await import(req.query.m);"),
        vec![(CodeInjection, High)]
    );
    assert!(route("require('./' + 'x'); require.resolve(req.query.m);").is_empty());
    assert!(
        route("for (const n of PLUGINS) require(path.join(__dirname, 'plugins', n));").is_empty()
    );
    assert_eq!(
        route("fs.mkdirSync(path.dirname(req.query.p));"),
        vec![(PathTraversal, High)]
    );
}

#[test]
fn instances_typed_by_fields_aliases_annotations_and_new() {
    use VulnClass::*;
    let svc = "class Svc { run(x) { exec('ls ' + x); } }\nclass Safe { run(x) { exec('ls ' + parseInt(x, 10)); } }\n";
    // A field set in the constructor.
    let found = one(&format!(
        "{svc}class Ctl {{ constructor() {{ this.svc = new Svc(); }} h(req) {{ this.svc.run(req.query.x); }} }}\n\
             const c = new Ctl();\napp.get('/x', (req, res) => c.h(req));"
    ));
    assert!(found.iter().any(|f| f.0 == CommandInjection), "{found:?}");
    // `new Svc().run(x)`; an alias.
    let found = one(&format!(
        "{svc}app.get('/x', (req, res) => new Svc().run(req.query.x));"
    ));
    assert!(found.iter().any(|f| f.0 == CommandInjection), "{found:?}");
    let found = one(&format!(
        "{svc}const a = new Svc();\nconst b = a;\napp.get('/x', (req, res) => b.run(req.query.x));"
    ));
    assert!(found.iter().any(|f| f.0 == CommandInjection), "{found:?}");
    // Only the constructed class's method.
    assert!(
        one(&format!(
            "{svc}app.get('/x', (req, res) => new Safe().run(req.query.x));"
        ))
        .is_empty()
    );
    // A TypeScript annotation, on a variable and on a parameter.
    let head = "const { exec } = require('child_process');\nclass Svc { run(x: string) { exec('ls ' + x); } }\n";
    let found = scan_ts(&format!(
        "{head}const s: Svc = make();\napp.get('/x', (req, res) => s.run(req.query.x));"
    ));
    assert!(found.iter().any(|f| f.0 == CommandInjection), "{found:?}");
    let found = scan_ts(&format!(
        "{head}function go(s: Svc, v: string) {{ s.run(v); }}\napp.get('/x', (req, res) => go(make(), req.query.x));"
    ));
    assert!(found.iter().any(|f| f.0 == CommandInjection), "{found:?}");
}

#[test]
fn n8n_node_parameters_and_webhooks() {
    use Severity::*;
    use VulnClass::*;
    let found = scan(
        "class N { async execute() { const p = this.getNodeParameter('pagination', 0); const r = {};\n  \
             p.parameters.forEach((x) => { r[x.type][x.name] = x.value; }); } }",
    );
    assert!(found.iter().any(|f| f.0 == PrototypePollution), "{found:?}");
    let found = scan(
        "class W { async webhook() { const files = this.getBodyData().files;\n  \
             for (const k of Object.keys(files)) await this.nodeHelpers.copyBinaryFile(files[k].filepath, 'x'); } }",
    );
    assert!(
        found.contains(&(PathTraversal, High, ".copyBinaryFile".to_owned(), "http"))
            || found.iter().any(|f| f.0 == PathTraversal && f.1 == High),
        "{found:?}"
    );
    // A local `location`; a whole statement; a number.
    assert!(scan("class L { execute() { let location = this.getNodeParameter('loc', 0); location = location.trim(); } }").is_empty());
    assert!(scan("class Q { async execute() { const q = this.getNodeParameter('query', 0); await conn.query(q); } }").is_empty());
    assert!(scan("const { exec } = require('child_process');\nclass E { execute() { exec('ls ' + parseInt(this.getNodeParameter('n', 0), 10)); } }").is_empty());
}

#[test]
fn instances_returned_by_functions_type_their_receivers() {
    use VulnClass::*;
    let classes = "class A { run(x) { exec('ls ' + x); } }\n\
            class B { run(x) { fs.readFileSync('/d/' + x); } }\n\
            class Safe { run(x) { exec('ls ' + parseInt(x, 10)); } }\n";
    // A factory of two classes: the method of each.
    let found = one(&format!(
        "{classes}function make(k) {{ switch (k) {{ case 'a': return new A(); default: return new B(); }} }}\n\
             app.get('/x', (req, res) => make(req.query.k).run(req.query.x));"
    ));
    assert!(found.iter().any(|f| f.0 == CommandInjection), "{found:?}");
    assert!(found.iter().any(|f| f.0 == PathTraversal), "{found:?}");
    // Bound to a variable, through `await`; reassigned.
    let found = one(&format!(
        "{classes}async function make() {{ return new A(); }}\n\
             app.get('/x', async (req, res) => {{ const c = await make(); c.run(req.query.x); }});"
    ));
    assert!(found.iter().any(|f| f.0 == CommandInjection), "{found:?}");
    let found = one(&format!(
        "{classes}function make() {{ return new A(); }}\n\
             app.get('/x', (req, res) => {{ let c = null; c = make(); c.run(req.query.x); }});"
    ));
    assert!(found.iter().any(|f| f.0 == CommandInjection), "{found:?}");
    // Only the class it returns.
    assert!(
        one(&format!(
            "{classes}function make() {{ return new Safe(); }}\n\
                 app.get('/x', (req, res) => make().run(req.query.x));"
        ))
        .is_empty()
    );
    // A singleton accessor, `new this()` in a static factory.
    let found = one(&format!(
        "{classes}class R {{ static get() {{ if (!R.inst) {{ R.inst = new R(); }} return R.inst; }} add(c) {{ exec(c); }} }}\n\
             app.get('/x', (req, res) => R.get().add(req.query.c));"
    ));
    assert!(found.iter().any(|f| f.0 == CommandInjection), "{found:?}");
    let found = one(&format!(
        "{classes}class F {{ static create() {{ return new this(); }} go(p) {{ fs.readFileSync(p); }} }}\n\
             app.get('/x', (req, res) => F.create().go(req.query.p));"
    ));
    assert!(found.iter().any(|f| f.0 == PathTraversal), "{found:?}");
    // A field holding what a factory returned.
    let found = one(&format!(
        "{classes}function make() {{ return new A(); }}\n\
             class Ctl {{ constructor() {{ this.c = make(); }} h(req) {{ this.c.run(req.query.x); }} }}\n\
             const ctl = new Ctl();\napp.get('/x', (req, res) => ctl.h(req));"
    ));
    assert!(found.iter().any(|f| f.0 == CommandInjection), "{found:?}");
    // A field of a returned object, destructured.
    let services = "function services() { return { a: new A(), safe: new Safe() }; }\n";
    let found = one(&format!(
        "{classes}{services}app.get('/x', (req, res) => {{ const {{ a }} = services(); a.run(req.query.x); }});"
    ));
    assert!(found.iter().any(|f| f.0 == CommandInjection), "{found:?}");
    assert!(
            one(&format!(
                "{classes}{services}app.get('/x', (req, res) => {{ const {{ safe }} = services(); safe.run(req.query.x); }});"
            ))
            .is_empty()
        );
    // `new this(o)` in a static factory runs the class's own constructor.
    let found = one(
        "class Conn { constructor(o) { this.cmd = o.cmd; } go() { exec(this.cmd); } static create(o) { const c = new this(o); return c; } }\n\
             app.get('/x', (req, res) => { Conn.create(req.query); });",
    );
    assert!(found.iter().any(|f| f.0 == CommandInjection), "{found:?}");
    // A TypeScript return type names the class.
    let head = "const { exec } = require('child_process');\nclass Svc { run(x: string) { exec('ls ' + x); } }\n";
    let found = scan_ts(&format!(
        "{head}function pick(): Svc {{ return lookup(); }}\n\
             app.get('/x', (req, res) => pick().run(req.query.x));"
    ));
    assert!(found.iter().any(|f| f.0 == CommandInjection), "{found:?}");
}

#[test]
fn llm_tool_handlers_take_model_input() {
    use Severity::*;
    use VulnClass::*;
    let found = one(
        "x.function({ name: 's', parameters: { type: 'object' }, handler: async ({ pattern = '' }) => exec('rg ' + pattern) });",
    );
    assert_eq!(
        found.iter().map(|f| (f.0, f.1, f.3)).collect::<Vec<_>>(),
        vec![(CommandInjection, Medium, "llm-tool")]
    );
    let found = one(
        "tool({ inputSchema: z.object({ q: z.string() }), execute: async ({ q }) => db.query('SELECT * FROM t WHERE a = ' + q) });",
    );
    assert!(found.iter().any(|f| f.0 == SqlInjection), "{found:?}");
    // A route configuration with array parameters; no schema.
    assert!(one("router.add({ path: '/x', parameters: [{ in: 'query' }], handler: (r) => exec('ls ' + r.q) });").is_empty());
    assert!(one("cfg({ schema: s, run: () => 1 });").is_empty());
}

#[test]
fn library_instances_are_their_clients() {
    use Severity::*;
    use VulnClass::*;
    let found = scan(
        "const axios = require('axios');\nconst c = axios.create({ timeout: 5 });\n\
             app.get('/x', async (req, res) => { await c.get(req.query.url); });",
    );
    assert!(found.iter().any(|f| f.0 == Ssrf), "{found:?}");
    assert!(scan(
            "const axios = require('axios');\nconst c = axios.create({ baseURL: 'https://api.x.com' });\n\
             app.get('/x', async (req, res) => { await c.get('/u/' + req.query.id); });"
        )
        .is_empty());
    let found = scan(
        "const simpleGit = require('simple-git');\nconst git = simpleGit().env('A', '1');\n\
             app.post('/x', async (req, res) => { await git.add(req.body.paths); });",
    );
    assert!(
        found.contains(&(CommandInjection, Medium, "git-cli.add".to_owned(), "http")),
        "{found:?}"
    );
    let found = scan(
        "const { NodeSSH } = require('node-ssh');\nconst ssh = new NodeSSH();\n\
             app.post('/x', async (req, res) => { await ssh.putFile(LOCAL, req.body.dest); });",
    );
    assert!(found.iter().any(|f| f.0 == PathTraversal), "{found:?}");
}

#[test]
fn element_methods_carry_their_receiver() {
    use Severity::*;
    use VulnClass::*;
    assert_eq!(
        route("const f = req.body.items.find((x) => x.ok); exec(f.cmd);"),
        vec![(CommandInjection, Critical)]
    );
    assert_eq!(
        route("const f = req.body.list.filter(Boolean).pop(); exec(f);"),
        vec![(CommandInjection, Critical)]
    );
    // A query's arguments are not its result; a constant table's element is clean.
    assert!(
        !route("const u = await User.find({ name: req.body.name }); exec(u.cmd);")
            .contains(&(CommandInjection, Critical))
    );
    assert!(
        route("const t = TYPES.find((v) => v === req.query.t); knex.raw('SELECT ' + t);")
            .is_empty()
    );
}

#[test]
fn collections_clones_and_keys() {
    use Severity::*;
    use VulnClass::*;
    let critical = vec![(CommandInjection, Critical)];
    assert_eq!(
        route("for (const [k, v] of Object.entries(req.body)) exec(v);"),
        critical
    );
    assert_eq!(
        route("const v = await Promise.all([req.query.a]); exec(v[0]);"),
        critical
    );
    assert_eq!(route("exec(structuredClone(req.body).c);"), critical);
    assert_eq!(route("exec(_.cloneDeep(req.body).c);"), critical);
    assert_eq!(route("exec(deepcopy(req.body).c);"), critical);
    assert_eq!(
        route("for (const k of Object.keys(req.body)) exec('ls ' + k);"),
        critical
    );
    assert_eq!(
        route("for (const k of Object.keys(req.body)) _.set(obj, k, 1);"),
        vec![(PrototypePollution, Medium)]
    );
    // Keys written in the code; a clean object picked by a tainted path.
    assert!(route("const o = { a: req.query.x }; for (const k in o) exec('ls ' + k);").is_empty());
    assert!(route("Object.keys(CONFIG).forEach((k) => exec('ls ' + k));").is_empty());
    assert!(route("exec(_.get(SETTINGS, req.query.p));").is_empty());
    assert!(route("for (const k of Object.keys({ a: req.query.x })) exec(k);").is_empty());
}

#[test]
fn literal_commands_and_numeric_conversions_are_not_findings() {
    assert!(one("app.get('/p', (req, res) => { exec('uptime'); const n = parseInt(req.query.n, 10); exec(`echo ${n}`); });").is_empty());
}

#[test]
fn regex_exec_is_not_child_process_exec() {
    assert!(scan("app.get('/p', (req, res) => { /x/.exec(req.query.a); });").is_empty());
}

#[test]
fn spawn_with_shell_true_is_critical() {
    let found =
        one("app.post('/r', (req, res) => { spawn('sh', ['-c', req.body.c], { shell: true }); });");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].1, Severity::Critical);
}

#[test]
fn path_traversal_and_basename() {
    let tp = one(
        "router.post('/f', function (r, s) { const { name } = r.body; fs.readFile(path.join(__dirname, name), cb); });",
    );
    assert_eq!(tp.len(), 1);
    assert_eq!(tp[0].0, VulnClass::PathTraversal);
    let fp = one(
        "router.post('/f', function (r, s) { const { name } = r.body; fs.readFile(path.join(__dirname, path.basename(name)), cb); s.sendFile(name, { root: __dirname }); });",
    );
    assert!(fp.is_empty(), "{fp:?}");
}

#[test]
fn sql_built_by_template_but_not_parameterized() {
    let tp = one(
        "app.get('/u', async (req, res) => { const id = req.params.id; await db.query(`SELECT * FROM t WHERE id = ${id}`); });",
    );
    assert_eq!(tp.len(), 1);
    assert_eq!(tp[0].0, VulnClass::SqlInjection);
    assert!(one("app.get('/u', async (req, res) => { await db.query('SELECT * FROM t WHERE id = ?', [req.params.id]); });").is_empty());
}

#[test]
fn ssrf_needs_control_of_the_url_start() {
    let tp = one(
        "app.post('/x', async (req, res) => { const u = req.body.url; await axios.get(u); await fetch(`${u}/x`); });",
    );
    assert_eq!(tp.len(), 2, "{tp:?}");
    assert!(one("app.post('/x', async (req, res) => { await axios.get('https://api.example.com/' + req.body.id); });").is_empty());
}

#[test]
fn eval_socket_and_web_request_sources() {
    assert_eq!(
        one("app.post('/e', (req, res) => { eval(req.body.code); });")[0].0,
        VulnClass::CodeInjection
    );
    assert_eq!(
        one(
            "io.on('connection', (socket) => { socket.on('run', (data, cb) => exec(data.cmd)); });"
        )[0]
        .3,
        "socket"
    );
    let next = scan(
        "import { exec } from 'node:child_process';\nexport async function POST(request) { const b = await request.json(); exec(b.cmd); }",
    );
    assert_eq!(next.len(), 1, "{next:?}");
}

#[test]
fn untainted_reassignment_clears_but_branches_only_add() {
    assert!(
        one("app.get('/p', (req, res) => { let h = req.query.h; h = 'x'; exec(h); });").is_empty()
    );
    assert_eq!(
        one("app.get('/p', (req, res) => { let h = 'x'; if (a) { h = req.query.h; } exec(h); });")
            .len(),
        1
    );
}

#[test]
fn runtime_code_shaped_like_handlers_without_requests_is_quiet() {
    // `(a, b)` callbacks that are not route registrations carry no request.
    assert!(one("list.forEach((item, i) => exec(item.cmd));").is_empty());
    assert!(one("function helper(cmd) { exec(cmd); }").is_empty());
}

#[test]
fn options_objects_count_only_through_their_url_fields() {
    assert!(scan("const http = require('http');\napp.get('/p', (req, res) => { http.request({ host: 'w', path: '/', headers: { ...req.headers } }); });").is_empty());
    assert_eq!(scan("const http = require('http');\napp.get('/p', (req, res) => { http.request({ host: req.query.h }); });").len(), 1);
}

#[test]
fn multer_storage_fields_are_not_client_data() {
    assert!(
        one("app.post('/u', up.single('f'), (req, res) => { fs.unlinkSync(req.file.path); });")
            .is_empty()
    );
    assert_eq!(one("app.post('/u', up.single('f'), (req, res) => { fs.unlinkSync(req.file.originalname); });").len(), 1);
}

#[test]
fn sql_needs_sql_looking_text() {
    assert_eq!(one("app.get('/u', (req, res) => { db.exec('SELECT * FROM t WHERE id = ' + req.query.id); });").len(), 1);
    assert!(one("app.get('/u', (req, res) => { cache.get('user:' + req.query.id); });").is_empty());
    // Query-builder fragments are SQL by contract, keyword or not, directly or through a
    // helper; their bindings are not.
    for found in [
        "app.get('/u', (req, res) => { knex('t').orderByRaw('\"t\".\"' + req.query.f + '\"'); });",
        "app.get('/u', (req, res) => { knex('t').orderByRaw(req.query.sort); });",
        "app.post('/u', (req, res) => { knex.schema.table('t', (table) => { table.specificType('c', `geometry(${req.body.t}, 4326)`); }); });",
        "function order(q, f) { q.orderByRaw(f); }\napp.get('/u', (req, res) => { order(qb, req.query.f); });",
    ] {
        let tp = one(found);
        assert_eq!(
            tp.iter().map(|f| f.0).collect::<Vec<_>>(),
            vec![VulnClass::SqlInjection],
            "{found}"
        );
    }
    for quiet in [
        "app.get('/u', (req, res) => { knex('t').whereRaw('id = ?', [req.query.id]); });",
        "app.get('/u', (req, res) => { _.orderBy(list, req.query.f); });",
        "function order(q, f) { q.orderByRaw(f); }\napp.get('/u', (req, res) => { order(qb, 'created_at desc'); });",
    ] {
        assert!(one(quiet).is_empty(), "{quiet}: {:?}", one(quiet));
    }
}

#[test]
fn meteor_methods_and_hono_context_are_sources() {
    let meteor = one("Meteor.methods({ run(cmd) { exec('ls ' + cmd); } });");
    assert_eq!(meteor.len(), 1);
    assert_eq!(meteor[0].3, "meteor");
    assert_eq!(
        one("app.get('/x', async (c) => { const q = c.req.query('d'); exec(`ls ${q}`); });").len(),
        1
    );
}

#[test]
fn same_file_helpers_are_followed_two_levels() {
    let src = "function run(cmd) { exec('sh -c ' + cmd); }\n\
                   const wrap = (x) => run(x);\n\
                   app.post('/r', (req, res) => { wrap(req.body.c); });";
    let found = one(src);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].3, "http");
    // A helper alone is not a finding, and a literal argument is not tainted.
    assert!(
        one("function run(cmd) { exec(cmd); }\napp.post('/r', (req, res) => { run('ls'); });")
            .is_empty()
    );
}

#[test]
fn client_side_sources_reach_html_and_open_external() {
    let pm = scan(
        "window.addEventListener('message', (e) => { el.innerHTML = '<b>' + e.data.name + '</b>'; });",
    );
    assert_eq!(pm.len(), 1, "{pm:?}");
    assert_eq!(pm[0].0, VulnClass::Xss);
    let ext = scan(
        "chrome.runtime.onMessage.addListener((msg, sender, reply) => { $('#x').html(`<i>${msg.t}</i>`); });",
    );
    assert_eq!(ext.len(), 1, "{ext:?}");
    // What the extension and the app send themselves is hardening (low); what other
    // extensions and web pages send is not.
    assert_eq!((ext[0].1, ext[0].3), (Severity::Low, "ext-internal"));
    let external = scan(
        "chrome.runtime.onMessageExternal.addListener((msg, sender, reply) => { $('#x').html(`<i>${msg.t}</i>`); });",
    );
    assert_eq!(external.len(), 1, "{external:?}");
    assert_eq!(
        (external[0].1, external[0].3),
        (Severity::High, "ext-message")
    );
    let ipc = scan("ipcMain.handle('open', (event, url) => { shell.openExternal(url); });");
    assert_eq!(ipc.len(), 1, "{ipc:?}");
    assert_eq!((ipc[0].1, ipc[0].3), (Severity::Low, "ipc"));
    // The IPC event object is not client data; a jQuery node append is not HTML.
    assert!(
        scan("ipcMain.on('x', (event) => { shell.openExternal(event.senderFrame.url); });")
            .is_empty()
    );
    assert!(
        scan("window.addEventListener('message', (e) => { $('#x').append(e.data); });").is_empty()
    );
}

#[test]
fn nest_decorators_connection_sockets_and_prototype_pollution() {
    let src = "import { exec } from 'child_process';\nclass C { @Get() find(@Query('p') p) { exec('ls ' + p); } }";
    let allocator = Allocator::default();
    let ret = Parser::new(
        &allocator,
        src,
        source_type(SourceKind::Ts, PackageType::CommonJs),
    )
    .with_options(parse_options())
    .parse();
    assert_eq!(scan_program(&ret.program, src).findings.len(), 1);
    assert_eq!(
        one("io.on('connection', (s) => { s.on('cmd', (d) => exec(d)); });").len(),
        1
    );
    let pp = one("app.post('/s', (req, res) => { const { a, b, v } = req.body; cfg[a][b] = v; });");
    assert_eq!(pp.len(), 1, "{pp:?}");
    assert_eq!(pp[0].0, VulnClass::PrototypePollution);
    assert!(one("app.post('/s', (req, res) => { cfg['x'][req.body.k] = 1; });").is_empty());
}

#[test]
fn a_ternary_that_repeats_an_allowlisted_expression_yields_a_listed_value() {
    let write = |pick: &str| {
        one(&format!(
                "app.post('/a', (req, res) => {{ const u = req.body.url; const ext = {pick}; fs.createWriteStream(`up/1.${{ext}}`); res.end(); }});"
            ))
            .len()
    };
    let ext = "u.split('.').slice(-1)[0].toLowerCase()";
    // The repeated expression is one of the listed values.
    assert_eq!(
        write(&format!("['jpg', 'png'].includes({ext}) ? {ext} : 'jpg'")),
        0
    );
    assert_eq!(
        write(&format!("!['jpg', 'png'].includes({ext}) ? 'jpg' : {ext}")),
        0
    );
    assert_eq!(write("['jpg', 'png'].includes(u) ? u : 'jpg'"), 0);
    // The value that failed the check, another expression, a substring test, a call that may
    // answer differently the second time: not confined.
    assert_eq!(
        write(&format!("!['jpg', 'png'].includes({ext}) ? {ext} : 'jpg'")),
        1
    );
    assert_eq!(
        write(&format!("['jpg', 'png'].includes({ext}) ? u : 'jpg'")),
        1
    );
    assert_eq!(write(&format!("u.includes({ext}) ? {ext} : 'jpg'")), 1);
    assert_eq!(
        write("['jpg', 'png'].includes(u.split('.').pop()) ? u.split('.').pop() : 'jpg'"),
        1
    );
    assert_eq!(write("['jpg', u].includes(u.trim()) ? u.trim() : 'jpg'"), 1);
}

#[test]
fn a_nested_write_in_a_helper_needs_both_keys_from_the_caller() {
    let helper = "const solves = {};\n\
            function store(key, phase, value) { if (!solves[key]) { solves[key] = {}; } solves[key][phase] = value; }\n\
            function storeFound(key, value) { store(key, 'find it', value); }\n";
    // A constant second key, directly or one helper up: nothing to pollute with.
    assert!(one(&format!("{helper}app.post('/a', (req, res) => {{ store(req.body.key, 'find it', true); res.end(); }});")).is_empty());
    assert!(one(&format!("{helper}app.post('/b', (req, res) => {{ storeFound(req.body.key, true); res.end(); }});")).is_empty());
    // Both keys from the request: `__proto__` then any property.
    let both = one(&format!(
        "{helper}app.post('/c', (req, res) => {{ store(req.body.key, req.body.phase, req.body.v); res.end(); }});"
    ));
    assert_eq!(both.len(), 1, "{both:?}");
    assert_eq!(both[0].0, VulnClass::PrototypePollution);
    // A second key the helper takes from the request itself needs nothing from the caller.
    let own = "const cfg = {};\nfunction setOwn(req, key) { cfg[key][req.body.p] = 1; }\n";
    assert_eq!(
        one(&format!(
            "{own}app.post('/d', (req, res) => {{ setOwn(req, req.body.k); res.end(); }});"
        ))
        .len(),
        1
    );
}

#[test]
fn helper_sinks_recheck_the_callers_value() {
    let fixed = "async function get(url) { return fetch(url); }\n\
                     app.get('/i/:c', async (req, res) => { await get(`https://x.org/${req.params.c}.png`); });";
    assert!(one(fixed).is_empty());
    let open = "async function get(url) { return fetch(url); }\n\
                    app.get('/i', async (req, res) => { await get(req.query.u); });";
    assert_eq!(one(open).len(), 1);
}

#[test]
fn evaluator_wrappers_are_code_sinks() {
    let finding = one(
        "const { eval: safeEval } = require('notevil'); app.post('/run', (req, res) => { res.send(safeEval(req.body.expression)); });",
    );
    assert_eq!(finding.len(), 1, "{finding:?}");
    assert_eq!(finding[0].0, VulnClass::CodeInjection);
    assert_eq!(finding[0].2, "notevil.eval");
}

#[test]
fn archive_entry_names_are_sources() {
    let yauzl = one(
        "zip.on('entry', (entry) => { fs.createWriteStream(path.join(dest, entry.fileName)); });",
    );
    assert_eq!(yauzl.len(), 1, "{yauzl:?}");
    assert_eq!(yauzl[0].3, "archive");
    let adm = one(
        "for (const e of zip.getEntries()) { fs.writeFileSync(path.join(out, e.entryName), e.getData()); }",
    );
    assert_eq!(adm.len(), 1, "{adm:?}");
    assert!(one("for (const e of zip.getEntries()) { fs.writeFileSync(path.join(out, path.basename(e.entryName)), x); }").is_empty());
    let open_buffer = one(
        "const uz = require('unzipper'); async function extract(data) { const directory = await uz.Open.buffer(data); for (const entry of directory.files) { fs.createWriteStream(path.join('uploads', entry.path)); } }",
    );
    assert_eq!(open_buffer.len(), 1, "{open_buffer:?}");
    assert_eq!(open_buffer[0].3, "archive");
    assert!(one("const other = { Open: { buffer() { return { files: [] }; } } }; async function extract(data) { const directory = await other.Open.buffer(data); for (const entry of directory.files) { fs.createWriteStream(path.join('uploads', entry.path)); } }").is_empty());
}

#[test]
fn next_const_handlers_and_hono_context_values() {
    assert_eq!(one("export const POST = async (request) => { const b = await request.json(); exec(b.cmd); };").len(), 1);
    assert!(one("app.get('/x', async (c) => { exec('ls ' + c.get('session').id); });").is_empty());
}

#[test]
fn handlers_passed_by_reference_get_client_data() {
    let src = "function onRun(data, cb) { exec('ls ' + data.dir); }\n\
                   io.on('connection', (socket) => { socket.on('run', onRun); });";
    assert_eq!(one(src).len(), 1);
    let ipc = "function openIt(event, url) { exec(url); }\nipcMain.handle('open', openIt);";
    assert_eq!(one(ipc).len(), 1);
}

#[test]
fn nosql_operator_injection_needs_an_object_capable_value() {
    let tp = one(
        "app.post('/login', async (req, res) => { await User.findOne({ email: req.body.email, password: req.body.password }); });",
    );
    assert_eq!(tp.len(), 1, "{tp:?}");
    assert_eq!(tp[0].0, VulnClass::NosqlInjection);
    assert!(one("app.post('/l', async (req, res) => { await User.findOne({ email: String(req.body.email) + '' }); });").is_empty());
    // Route params are always strings.
    assert!(
        one("app.get('/u/:id', async (req, res) => { await User.findById(req.params.id); });")
            .is_empty()
    );
    // Wrappers that take the collection's name first; aggregation pipelines.
    for found in [
        "app.get('/t', async (req, res) => { await db.find('_User', { token: req.query.t }); });",
        "app.post('/q', async (req, res) => { await database.find('_User', { $or: req.body.q }, { limit: 2 }); });",
        "app.post('/a', async (req, res) => { await posts.aggregate([{ $match: { type: req.body.type } }]); });",
    ] {
        let tp = one(found);
        assert_eq!(
            tp.iter().map(|f| f.0).collect::<Vec<_>>(),
            vec![VulnClass::NosqlInjection],
            "{found}"
        );
    }
    for quiet in [
        "app.get('/t', async (req, res) => { await db.find('_User', { token: String(req.query.t) }); });",
        "app.get('/t', async (req, res) => { await cache.find('k', { limit: 10 }); });",
        "app.get('/t', async (req, res) => { await db.find(name, { token: req.query.t }); });",
        "app.post('/a', async (req, res) => { await posts.aggregate([{ $match: { url: { $ne: req.body.url } } }]); });",
    ] {
        assert!(one(quiet).is_empty(), "{quiet}: {:?}", one(quiet));
    }
}

#[test]
fn raw_http_servers_and_fastify_route_objects_are_routes() {
    let raw = scan(
        "const http = require('http');\nconst { exec } = require('child_process');\nhttp.createServer((req, res) => { exec('ls ' + req.url); });",
    );
    assert_eq!(raw.len(), 1, "{raw:?}");
    let fastify = one(
        "fastify.route({ method: 'GET', url: '/x', handler: async (request, reply) => { exec('ls ' + request.query.d); } });",
    );
    assert_eq!(fastify.len(), 1, "{fastify:?}");
    // Azure Functions v4: `app.http('name', { route, methods, handler })` registers an HTTP route
    // whose handler reads the request, so a `request.params` value reaching a file sink is a finding.
    let azure = one(
        "app.http('getChunks', { route: 'chunks/{*filePath}', methods: ['GET'], handler: (request, context) => { const { filePath } = request.params; return { body: fs.readFileSync(path.join(__dirname, '../client', filePath)) }; } });",
    );
    assert_eq!(
        azure.iter().map(|f| (f.0, f.3)).collect::<Vec<_>>(),
        vec![(VulnClass::PathTraversal, "http")],
        "{azure:?}",
    );
    // The function name alone (no `handler`) is not a route object, so an ordinary `obj.http(name)`
    // call is not mistaken for one.
    assert!(one("widget.http('open', 'ignored');").is_empty());
}

#[test]
fn graphql_js_field_configs_and_relay_mutations_take_client_input() {
    use VulnClass::*;
    let found = one(
        "const Query = new GraphQLObjectType({ name: 'Query', fields: { run: { type: GraphQLString, args: { cmd: { type: GraphQLString } }, resolve: (source, args) => exec('ls ' + args.cmd) } } });",
    );
    assert_eq!(
        found.iter().map(|f| (f.0, f.3)).collect::<Vec<_>>(),
        vec![(CommandInjection, "graphql")]
    );
    let found = one(
        "const create = mutationWithClientMutationId({ name: 'Create', inputFields: { dir: { type: GraphQLString } }, outputFields: {}, mutateAndGetPayload: async (input) => fs.readFileSync('/srv/' + input.dir) });",
    );
    assert_eq!(
        found.iter().map(|f| (f.0, f.3)).collect::<Vec<_>>(),
        vec![(PathTraversal, "graphql")]
    );
    // The source of a field config is its second parameter, never the parent object.
    assert!(one("const T = new GraphQLObjectType({ name: 'T', fields: { f: { type: GraphQLString, args: {}, resolve: (source) => exec('ls ' + source.name) } } });").is_empty());
}

#[test]
fn graphql_trpc_queues_and_socket_on_any() {
    let gql = one(
        "const resolvers = { Query: { file(parent, args) { return fs.readFileSync(args.path); } } };",
    );
    assert_eq!(gql.len(), 1, "{gql:?}");
    assert_eq!(gql[0].3, "graphql");
    let trpc = one(
        "const r = t.procedure.input(z.string()).mutation(({ input, ctx }) => exec('ls ' + input));",
    );
    assert_eq!(trpc.len(), 1, "{trpc:?}");
    let trpc_opts = one("const r = t.procedure.query((opts) => exec('ls ' + opts.input.dir));");
    assert_eq!(trpc_opts.len(), 1, "{trpc_opts:?}");
    // A query on anything but a procedure is none: `connection.query(...)`.
    assert!(one("const r = connection.query((opts) => exec('ls ' + opts.input.dir));").is_empty());
    let queue =
        one("queue.process('convert', async (job) => { exec('convert ' + job.data.file); });");
    assert_eq!(queue.len(), 1, "{queue:?}");
    let any =
        one("io.on('connection', (socket) => { socket.onAny((event, data) => exec(data)); });");
    assert_eq!(any.len(), 1, "{any:?}");
}

#[test]
fn guards_from_real_false_positives_clean_the_value() {
    // uptime-kuma: regex allowlist before path.join
    assert!(one("io.on('connection', (socket) => { socket.on('ex', async (language, cb) => { if (!/^[a-z-]+$/.test(language)) { throw new Error('bad'); } fs.readdir(path.join('./x', language), cb); }); });").is_empty());
    // Haven: hex id regex, then a temp path
    assert!(one("app.post('/i', (req, res) => { const { importId } = req.body; if (!/^[a-f0-9]{32}$/.test(importId)) { return res.status(400).end(); } fs.readFile(path.join(tmp, importId), cb); });").is_empty());
    // mirotalksfu / OpenWhispr: resolved path must stay under the base
    assert!(one("app.post('/r', (req, res) => { const p = path.resolve(base, req.query.f); if (!p.startsWith(base)) { return res.status(400).end(); } fs.createWriteStream(p); });").is_empty());
    // positive form: use inside the validated block only
    assert!(one("app.get('/a', (req, res) => { const n = req.query.n; if (ALLOWED.includes(n)) { exec('run ' + n); } });").is_empty());
    assert_eq!(one("app.get('/a', (req, res) => { const n = req.query.n; if (ALLOWED.includes(n)) { log(n); } exec('run ' + n); });").len(), 1);
    // a guard that does not exit cleans nothing after it
    assert_eq!(one("app.get('/a', (req, res) => { const n = req.query.n; if (!/^\\w+$/.test(n)) { log('bad'); } exec('run ' + n); });").len(), 1);
    // a guard on a request field
    assert!(one("app.get('/a', (req, res) => { if (!isValidId(req.query.id)) return res.end(); exec('run ' + req.query.id); });").is_empty());
    // comparison with a constant
    assert!(one("app.get('/a', (req, res) => { const m = req.query.m; if (m !== 'fast' && m !== 'slow') return; exec('run ' + m); });").is_empty());
    // career-ops: a containment predicate named with its word inside the name, and a
    // lookup by equality in the server's own list.
    assert!(one("app.get('/a', (req, res) => { const abs = path.resolve(DIR, req.query.f); if (!isRegularContainedFile(abs, DIR)) { return res.end(); } fs.openSync(abs, 'r'); });").is_empty());
    assert!(one("app.get('/a', (req, res) => { const f = req.query.f; const doc = docs.find((d) => d.filename === f); if (!doc) { return res.end(); } fs.openSync(path.resolve(DIR, f), 'r'); });").is_empty());
    assert!(one("app.get('/a', (req, res) => { const f = req.query.f; if (!docs.some((d) => f === d.filename)) return res.end(); fs.openSync(path.resolve(DIR, f), 'r'); });").is_empty());
    // ... but a list the attacker sent proves nothing.
    assert_eq!(one("app.get('/a', (req, res) => { const f = req.query.f; const doc = req.body.docs.find((d) => d.filename === f); if (!doc) { return res.end(); } fs.openSync(path.resolve(DIR, f), 'r'); });").len(), 1);
    // mirotalksfu: js-xss's filterXSS escapes HTML.
    assert!(scan("const qs = new URLSearchParams(window.location.search); el.innerHTML = filterXSS(qs.get('message'));").is_empty());
    // qq-bridge: a strip that keeps word characters and CJK ideographs (`\u4e00-\u9fff`).
    assert!(one("app.get('/r', (req, res) => { const name = String(req.query.role).replace(/[^\\w\\u4e00-\\u9fff-]/g, ''); fs.readFileSync(path.join(DIR, name + '.md')); });").is_empty());
    // ... but full-width forms (`／`, `．`) are kept unread.
    assert_eq!(one("app.get('/r', (req, res) => { const name = String(req.query.role).replace(/[^\\w\\uff0e\\uff0f-]/g, ''); fs.readFileSync(path.join(DIR, name)); });").len(), 1);
    // tubehaus: a URLSearchParams in text is percent-encoded; a value read out of it is not.
    assert!(scan("const sp = new URLSearchParams(location.search); const u = new URLSearchParams({ q: sp.get('q') }); el.innerHTML = '<a href=\"?' + u + '\">x</a>';").is_empty());
    assert_eq!(scan("const sp = new URLSearchParams(location.search); el.innerHTML = '<b>' + sp.get('q') + '</b>';").len(), 1);
    // tubehaus: an escaper by what it does, whatever its name.
    assert!(scan("const ESC = { '<': '&lt;', '>': '&gt;' }; const esc = (v) => String(v).replace(/[&<>\"']/g, (c) => ESC[c]); el.innerHTML = '<b>' + esc(location.hash) + '</b>';").is_empty());
    assert_eq!(
        scan("el.innerHTML = '<b>' + String(location.hash).replace(/[<>]/g, '<i>') + '</b>';")
            .len(),
        1
    );
}

#[test]
fn type_assertions_rule_out_nosql_objects_only() {
    assert!(one("Meteor.methods({ load(boardId) { check(boardId, String); return Boards.find({ _id: boardId }); } });").is_empty());
    assert!(one("app.post('/l', async (req, res) => { const e = req.body.email; if (typeof e !== 'string') return; await User.findOne({ email: e }); });").is_empty());
    // a string check does not make SQL text safe
    assert_eq!(one("app.post('/l', async (req, res) => { const e = req.body.email; if (typeof e !== 'string') return; await db.query('SELECT * FROM u WHERE e = ' + e); });").len(), 1);
}

#[test]
fn object_fields_and_destructured_parameters_are_tracked_one_by_one() {
    // yuvomi: constant table name, tainted ids in another field
    let helper = "function replaceLinks(db, { table, ids }) { db.prepare(`DELETE FROM ${table} WHERE x = 1`).run(); }\n";
    assert!(one(&format!("{helper}app.post('/i', (req, res) => {{ replaceLinks(db, {{ table: 'docs', ids: req.body.ids }}); }});")).is_empty());
    assert_eq!(one(&format!("{helper}app.post('/i', (req, res) => {{ replaceLinks(db, {{ table: req.body.t, ids: 1 }}); }});")).len(), 1);
    // a variable holding an object literal
    assert!(one("app.get('/x', (req, res) => { const meta = { name: req.query.name, dir: '/srv' }; fs.readFileSync(path.join(meta.dir, 'a')); });").is_empty());
    assert_eq!(one("app.get('/x', (req, res) => { const meta = { name: req.query.name, dir: '/srv' }; fs.readFileSync(path.join(meta.dir, meta.name)); });").len(), 1);
    // a field written later
    assert_eq!(one("app.get('/x', (req, res) => { const o = { dir: '/srv' }; o.dir = req.query.d; fs.readFileSync(o.dir); });").len(), 1);
}

fn auth_of(src: &str) -> Vec<(Auth, Severity)> {
    let src = format!("{HEAD}{src}");
    let allocator = Allocator::default();
    let ret = Parser::new(
        &allocator,
        &src,
        source_type(SourceKind::Js, PackageType::CommonJs),
    )
    .with_options(parse_options())
    .parse();
    scan_program(&ret.program, &src)
        .findings
        .into_iter()
        .map(|f| (f.auth, f.severity))
        .collect()
}

#[test]
fn authentication_is_recognized_and_admin_only_lowers_severity() {
    assert_eq!(
        auth_of("app.get('/p', (req, res) => { exec('ping ' + req.query.h); });"),
        vec![(Auth::NoneDetected, Severity::Critical)]
    );
    assert_eq!(
        auth_of("app.get('/p', requireLogin, (req, res) => { exec('ping ' + req.query.h); });"),
        vec![(Auth::User, Severity::Critical)]
    );
    assert_eq!(
        auth_of(
            "app.post('/p', ensureFileIsPassed, (req, res) => { exec('ping ' + req.body.h); });"
        ),
        vec![(Auth::NoneDetected, Severity::Critical)]
    );
    assert_eq!(
        auth_of(
            "app.post('/p', userValidations.completeEmailLogin, (req, res) => { exec('ping ' + req.body.h); });"
        ),
        vec![(Auth::NoneDetected, Severity::Critical)],
        "a validator for a login operation is not authentication middleware"
    );
    assert_eq!(
        auth_of(
            "app.post('/p', authValidators.requireLogin, (req, res) => { exec('ping ' + req.body.h); });"
        ),
        vec![(Auth::User, Severity::Critical)],
        "an explicitly guard-shaped member stays authentication even under a validator namespace"
    );
    assert_eq!(
        auth_of(
            "router.use(passport.authenticate('jwt'));\nrouter.get('/p', (req, res) => { exec('ping ' + req.query.h); });"
        ),
        vec![(Auth::User, Severity::Critical)]
    );
    assert_eq!(
        auth_of("app.post('/p', isAdmin, (req, res) => { exec('ping ' + req.body.h); });"),
        vec![(Auth::Admin, Severity::High)]
    );
    assert_eq!(
        auth_of(
            "app.get('/p', (req, res) => { if (!req.user) { return res.sendStatus(401); } exec('ping ' + req.query.h); });"
        ),
        vec![(Auth::User, Severity::Critical)]
    );
    assert_eq!(
        auth_of(
            "fastify.post('/p', { onRequest: [fastify.authenticate] }, async req => { exec('ping ' + req.body.h); });"
        ),
        vec![(Auth::User, Severity::Critical)]
    );
    assert_eq!(
        auth_of(
            "defineRoute()({ useMiddlewares: ['withAuthentication'], fn: async (req, res) => { exec('ping ' + req.query.h); } });"
        ),
        vec![(Auth::User, Severity::Critical)]
    );
    assert_eq!(
        auth_of(
            "app.use(verify.databaseRelatedChallenges());\napp.use(security.updateAuthenticatedUsers());\n\
                 app.get('/p', (req, res) => { exec('ping ' + req.query.h); });"
        ),
        vec![(Auth::NoneDetected, Severity::Critical)]
    );
}

fn scan_jsx(src: &str) -> Vec<(VulnClass, Severity, String, &'static str)> {
    let allocator = Allocator::default();
    let ret = Parser::new(
        &allocator,
        src,
        source_type(SourceKind::Jsx, PackageType::Module),
    )
    .with_options(parse_options())
    .parse();
    assert!(!ret.fatal_error, "{:?}", ret.diagnostics);
    scan_program(&ret.program, src)
        .findings
        .into_iter()
        .map(|f| (f.class, f.severity, f.api, f.origin.kind))
        .collect()
}

#[test]
fn responses_of_attacker_chosen_urls_are_attacker_data() {
    use VulnClass::*;
    let helper = "async function doFetch(url) { const r = await fetch(url); return r.json(); }\n";
    for found in [
        "app.get('/a', async (req, res) => { const r = await fetch(req.query.url); const d = await r.json(); fs.writeFileSync('/x/' + d.name, ''); });",
        "app.get('/b', async (req, res) => { const d = await doFetch(req.query.url); fs.writeFileSync('/x/' + d.name, ''); });",
        "app.get('/c', async (req, res) => { const { data } = await axios.get(req.query.url); fs.writeFileSync('/x/' + data.name, ''); });",
    ] {
        let got = one(&format!("{helper}{found}"));
        assert!(got.iter().any(|f| f.0 == PathTraversal), "{found}: {got:?}");
    }
    // A response from a URL whose start the code fixed is the API's, not the attacker's.
    for quiet in [
        "app.get('/d', async (req, res) => { const r = await fetch('https://api.github.com/x?q=' + req.query.q); exec((await r.json()).cmd); });",
        "app.get('/e', async (req, res) => { const d = await doFetch('https://api.example.com/x?q=' + req.query.q); exec(d.cmd); });",
    ] {
        let got = one(&format!("{helper}{quiet}"));
        assert!(
            !got.iter().any(|f| f.0 == CommandInjection),
            "{quiet}: {got:?}"
        );
    }
}

#[test]
fn url_attributes_of_elements_are_url_sinks() {
    use VulnClass::Xss;
    // A component prop into an anchor's href: medium (props), the start is the attacker's.
    let found = scan_jsx("function L({ url }) { return <a href={url}>x</a>; }");
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!((found[0].0, found[0].1), (Xss, Severity::Medium));
    assert_eq!(found[0].2, "<a href>");
    let found = scan_jsx(
        "function Pdf(props) { const { href } = props.node.attrs; return <embed src={href} />; }",
    );
    assert_eq!(found.len(), 1, "{found:?}");
    // Components wrapped in `memo`, `forwardRef` or `observer` take props too.
    for wrapped in [
        "const L = memo(({ url }) => <a href={url}>x</a>);",
        "const L = React.forwardRef(({ url }, ref) => <a ref={ref} href={url}>x</a>);",
        "const L = observer(function Link({ url }) { return <a href={url}>x</a>; });",
    ] {
        assert_eq!(scan_jsx(wrapped).len(), 1, "{wrapped}");
    }
    // A fixed start, an image, a component, a checked URL: none.
    for quiet in [
        "function L({ id }) { return <a href={'/u/' + id}>x</a>; }",
        "function I({ url }) { return <img src={url} />; }",
        "function L({ url }) { return <Link href={url}>x</Link>; }",
        "function L({ url }) { return <a href={sanitizeUrl(url)}>x</a>; }",
        "function sanitizeUrl(u) { return u; }\nfunction L({ url }) { return <a href={sanitizeUrl(url)}>x</a>; }",
    ] {
        assert!(scan_jsx(quiet).is_empty(), "{quiet}: {:?}", scan_jsx(quiet));
    }
    // DOM: a created anchor's href, set or assigned.
    let found =
        scan("const a = document.createElement('a'); a.href = location.hash.slice(1); a.click();");
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].3, "dom");
    let found = scan(
        "const f = document.createElement('iframe'); f.setAttribute('src', location.hash.slice(1));",
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        scan("const i = document.createElement('img'); i.src = location.hash.slice(1);").is_empty()
    );
    assert!(
        scan("const a = document.createElement('a'); a.href = '/p/' + location.hash.slice(1);")
            .is_empty()
    );
}

#[test]
fn dangerously_set_inner_html_with_props_or_request_data() {
    let found = scan_jsx(
        "export function Label({ label }) { return <span dangerouslySetInnerHTML={{ __html: label }} />; }",
    );
    assert_eq!(
        found,
        vec![(
            VulnClass::Xss,
            Severity::Medium,
            "dangerouslySetInnerHTML".to_owned(),
            "props"
        )]
    );
    // array elements of tainted props, through a markdown renderer
    let mapped = scan_jsx(
        "function Chat({ messages }) { return <div>{messages.map((m) => <p dangerouslySetInnerHTML={{ __html: renderMarkdown(m.text) }} />)}</div>; }",
    );
    assert_eq!(mapped.len(), 1, "{mapped:?}");
    assert!(scan_jsx("function A({ x }) { return <p dangerouslySetInnerHTML={{ __html: '<b>static</b>' }} title={x} />; }").is_empty());
}

#[test]
fn a_tainted_argument_list_is_argument_injection() {
    let found = one(
        "io.on('connection', (s) => { s.on('install', (url) => { spawn('git', ['clone', url, dir]); }); });",
    );
    assert_eq!(
        found,
        vec![(
            VulnClass::CommandInjection,
            Severity::Medium,
            "child_process.spawn".to_owned(),
            "socket"
        )]
    );
}

#[test]
fn dom_xss_sources_and_sinks() {
    let found = scan(
        "const q = new URLSearchParams(location.search); el.innerHTML = '<b>' + location.hash.slice(1) + '</b>';",
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].3, "dom");
    assert_eq!(
        scan("document.write('<p>' + document.referrer + '</p>');").len(),
        1
    );
    assert_eq!(
        scan("window.location.href = location.hash.slice(1);").len(),
        1
    );
    // a fixed origin before the tainted part cannot become `javascript:`
    assert!(scan("location.href = '/search?q=' + location.hash.slice(1);").is_empty());
    assert_eq!(
        scan("setTimeout('render(' + location.hash + ')', 10);").len(),
        1
    );
    // `stream.write` is not `document.write`
    assert!(scan("stream.write(location.hash);").is_empty());
    // Values read out of the page's query: `URLSearchParams`, `url.searchParams.get()`.
    assert_eq!(
        scan("const p = new URLSearchParams(location.search); location.href = p.get('next');")
            .len(),
        1
    );
    assert_eq!(
            scan("const u = new URL(location.href); el.innerHTML = '<b>' + u.searchParams.get('q') + '</b>';")
                .len(),
            1
        );
    // A read keyed by attacker data out of a fixed table is the table's.
    assert!(scan("const ALLOWED = new Map([['a', '/a']]); location.href = ALLOWED.get(location.hash.slice(1)) || '/';").is_empty());
}

#[test]
fn a_request_value_built_into_an_html_response_is_reflected_xss() {
    let xss = |src: &str| -> Vec<(Severity, String)> {
        scan(src)
            .into_iter()
            .filter(|f| f.0 == VulnClass::Xss)
            .map(|f| (f.1, f.2))
            .collect()
    };
    // Markup in the text: a page for sure.
    assert_eq!(
        xss(
            "app.get('/hi', (req, res) => { res.send('<h1>Hello ' + req.query.name + '</h1>'); });"
        ),
        vec![(Severity::High, "res.send".to_owned())]
    );
    assert_eq!(
        xss("app.get('/hi', (req, res) => { res.send(`<p>${req.params.id} not found</p>`); });")
            .len(),
        1
    );
    // At the end of a chain of calls that return the response.
    assert_eq!(
        xss(
            "app.get('/hi', (req, res) => { res.status(404).send('<p>No ' + req.query.q + '</p>'); });"
        ),
        vec![(Severity::High, "res.send".to_owned())]
    );
    // Through a variable.
    assert_eq!(
            xss("app.get('/hi', (req, res) => { const page = '<div>' + req.query.q + '</div>'; res.send(page); });")
                .len(),
            1
        );
    // Express answers plain built text as HTML too: a weaker sign.
    assert_eq!(
        xss("app.get('/hi', (req, res) => { res.send('User ' + req.params.id + ' not found'); });"),
        vec![(Severity::Medium, "res.send".to_owned())]
    );
    // Node's raw response: only a body with markup is a page.
    assert_eq!(
            xss("http.createServer((req, res) => { const q = new URL(req.url, 'http://x').searchParams.get('q'); res.end('<b>' + q + '</b>'); });")
                .len(),
            1
        );
    assert!(xss("http.createServer((req, res) => { res.end('id=' + req.url); });").is_empty());
    // Escaped, a bare value, or an object answered as JSON: no page markup from the request.
    assert!(
            xss("app.get('/hi', (req, res) => { res.send('<h1>' + escapeHtml(req.query.name) + '</h1>'); });")
                .is_empty()
        );
    assert!(xss("app.get('/hi', (req, res) => { res.send(req.query.name); });").is_empty());
    assert!(
        xss("app.get('/hi', (req, res) => { res.send({ name: req.query.name }); });").is_empty()
    );
    // Another object's `send` is no response.
    assert!(
        xss("app.get('/hi', (req, res) => { socket.send('<b>' + req.query.q + '</b>'); });")
            .is_empty()
    );
}

#[test]
fn electron_sinks_and_bullmq_workers() {
    // A critical sink, capped: what the app's own renderer sends is hardening.
    assert_eq!(
        scan(
            "ipcMain.handle('run', (event, code) => { win.webContents.executeJavaScript(code); });"
        )[0]
        .1,
        Severity::Low
    );
    assert_eq!(
        scan("ipcMain.on('open', (event, p) => shell.openPath(p));").len(),
        1
    );
    let worker = one(
        "import { Worker } from 'bullmq';\nconst w = new Worker('convert', async (job) => { exec('convert ' + job.data.file); });",
    );
    assert_eq!(worker.len(), 1, "{worker:?}");
    assert_eq!(worker[0].3, "queue");
    // The browser's Web Worker is no queue.
    assert!(
        one(
            "const w = new Worker('convert', async (job) => { exec('convert ' + job.data.file); });"
        )
        .is_empty()
    );
}

#[test]
fn return_values_carry_parameter_taint() {
    let helper =
        "function clean(v) { return v.trim(); }\nfunction getDir(req) { return req.query.dir; }\n";
    assert_eq!(
        one(&format!(
            "{helper}app.get('/a', (req, res) => {{ exec('ls ' + clean(req.query.d)); }});"
        ))
        .len(),
        1
    );
    assert_eq!(
        one(&format!(
            "{helper}app.get('/a', (req, res) => {{ exec('ls ' + getDir(req)); }});"
        ))
        .len(),
        1
    );
    // a helper that returns a constant does not
    assert!(one("function fixed(v) { return 'x'; }\napp.get('/a', (req, res) => { exec('ls ' + fixed(req.query.d)); });").is_empty());
    // arrow helpers with expression bodies
    assert_eq!(one("const wrap = (v) => `\"${v}\"`;\napp.get('/a', (req, res) => { exec('ls ' + wrap(req.query.d)); });").len(), 1);
}

#[test]
fn deep_set_helpers_with_tainted_paths() {
    let found = scan(
        "const _ = require('lodash');\napp.post('/s', (req, res) => { _.set(settings, req.body.path, req.body.value); });",
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].0, VulnClass::PrototypePollution);
    assert!(scan("const _ = require('lodash');\napp.post('/s', (req, res) => { _.set(settings, 'theme', req.body.value); });").is_empty());
    // Map.set is not a deep write
    assert!(scan("app.post('/s', (req, res) => { cache.set(req.body.k, 1); });").is_empty());
}

#[test]
fn instance_fields_carry_taint_between_methods_and_through_constructors() {
    let class = "class Executor {\n  constructor(config) { this.url = config.url; }\n  execute() { return axios.get(this.url); }\n}\n";
    let found = one(&format!(
        "{class}app.post('/run', async (req, res) => {{ const e = new Executor(req.body); await e.execute(); }});"
    ));
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].0, VulnClass::Ssrf);
    // a constant field stays clean
    assert!(one("class E { constructor() { this.url = 'https://api.example.com'; } run() { return axios.get(this.url); } }").is_empty());
}

#[test]
fn rejecting_and_named_validators_clean_values() {
    // Flowise's fix: a predicate that is true for bad input, then an exit
    let fixed = "app.get('/f', (req, res) => { const id = req.query.id; if (isPathTraversal(id)) { throw new Error('bad'); } fs.createReadStream(path.join(base, id)); });";
    assert!(one(fixed).is_empty());
    let vulnerable = "app.get('/f', (req, res) => { const id = req.query.id; fs.createReadStream(path.join(base, id)); });";
    assert_eq!(one(vulnerable).len(), 1);
    assert!(one("app.get('/f', (req, res) => { const p = req.query.p; if (p.includes('..')) return res.end(); fs.readFileSync(p); });").is_empty());
    assert!(one("app.get('/f', (req, res) => { const u = req.query.u; if (!isValidUUID(u)) return; exec('x ' + u); });").is_empty());
    // `isInvalid` is a rejecter, not a validator
    assert_eq!(one("app.get('/f', (req, res) => { const u = req.query.u; if (!isInvalidName(u)) return; exec('x ' + u); });").len(), 1);
}

#[test]
fn returned_objects_keep_their_fields_apart() {
    let helper = "function prepare(bin, args) { return { command: bin, args: args }; }\n";
    // The message goes into the argument list, not the program: argument injection at most.
    let found = one(&format!(
        "{helper}app.post('/a', (req, res) => {{ const launch = prepare('codex', ['exec', req.body.message]); spawn(launch.command, launch.args); }});"
    ));
    assert_eq!(
        found,
        vec![(
            VulnClass::CommandInjection,
            Severity::Medium,
            "child_process.spawn".to_owned(),
            "http"
        )]
    );
    // The program itself from the request is the real thing.
    let found = one(&format!(
        "{helper}app.post('/a', (req, res) => {{ const {{ command, args }} = prepare(req.body.bin, []); spawn(command, args); }});"
    ));
    assert_eq!(
        found,
        vec![(
            VulnClass::CommandInjection,
            Severity::High,
            "child_process.spawn".to_owned(),
            "http"
        )]
    );
    // An object returned behind a condition keeps its fields apart too; so does an object a
    // call returns straight into another call (hibi's image cache).
    let helpers = "function locate(src, place) { const name = createHash('sha256').update(String(src)).digest('hex'); return place ? { url: src, path: path.join(place.data, name) } : null; }\n\
                       function keep(image) { fs.readFileSync(image.path); }\n\
                       function respond(src, place) { const image = locate(src, place); if (image) { keep(image); } }\n\
                       const placeOf = (tab) => ({ note: lookup(tab), data: DATA });\n";
    assert!(
            one(&format!(
                "{helpers}app.get('/i', (req, res) => {{ respond(req.query.src, placeOf(req.query.tab)); }});"
            ))
            .is_empty()
        );
    let found = one(&format!(
        "{helpers}app.get('/i', (req, res) => {{ respond('x', {{ data: req.query.dir }}); }});"
    ));
    assert_eq!(
        found.iter().map(|f| f.0).collect::<Vec<_>>(),
        vec![VulnClass::PathTraversal],
        "{found:?}"
    );
}

#[test]
fn allowlist_strips_clean_but_partial_replacements_do_not() {
    assert!(one("app.post('/s', (req, res) => { const id = String(req.body.id).replace(/[^a-z0-9_-]/gi, ''); fs.writeFileSync(path.join(dir, id + '.md'), x); });").is_empty());
    // removing `../` once is bypassable (`....//`): still a finding
    assert_eq!(one("app.post('/s', (req, res) => { const id = req.body.id.replace(/\\.\\.\\//g, ''); fs.writeFileSync(path.join(dir, id), x); });").len(), 1);
    // not global: only the first bad character goes
    assert_eq!(one("app.post('/s', (req, res) => { const id = req.body.id.replace(/[^a-z]/, ''); fs.writeFileSync(path.join(dir, id), x); });").len(), 1);
}

#[test]
fn library_deep_sets_are_medium() {
    let found = scan(
        "const _ = require('lodash');\napp.post('/s', (req, res) => { _.set(settings, req.body.path, 1); });",
    );
    assert_eq!(found[0].1, Severity::Medium);
}

#[test]
fn dev_server_middleware_and_mcp_tool_arguments_are_sources() {
    let dev = one(
        "export default { plugins: [{ configureServer(server) { server.middlewares.use((req, res, next) => { res.end(fs.readFileSync(path.join(root, req.url))); }); } }] };",
    );
    assert_eq!(
        dev,
        vec![(
            VulnClass::PathTraversal,
            Severity::High,
            "fs.readFileSync".to_owned(),
            "dev-server"
        )]
    );
    let mcp = one(
        "server.tool('run', 'Run a command', { cmd: z.string() }, async ({ cmd }) => { exec(cmd); });",
    );
    assert_eq!(
        mcp,
        vec![(
            VulnClass::CommandInjection,
            Severity::Critical,
            "child_process.exec".to_owned(),
            "mcp"
        )]
    );
    let low_level = one(
        "server.setRequestHandler(CallToolRequestSchema, async (request) => { const { path } = request.params.arguments; return fs.readFileSync(path); });",
    );
    assert_eq!(low_level.len(), 1, "{low_level:?}");
    let fastmcp = one(
        "server.addTool({ name: 'read', execute: async (args) => fs.readFileSync(args.file) });",
    );
    assert_eq!(fastmcp.len(), 1, "{fastmcp:?}");
    // A helper with a conventionally named `request` parameter takes the kind its callers
    // here pass it: an MCP request, not an HTTP one.
    let helper = one(
        "async function handleToolCall(request) { return fs.readFileSync(request.params.arguments.path); }\n\
             server.setRequestHandler(CallToolRequestSchema, async (request) => handleToolCall(request));",
    );
    assert!(!helper.is_empty(), "{helper:?}");
    assert!(helper.iter().all(|f| f.3 == "mcp"), "{helper:?}");
    let http = one(
        "function getFile(request) { return fs.readFileSync(request.query.path); }\n\
             app.get('/f', (req, res) => res.send(getFile(req)));",
    );
    assert!(http.iter().any(|f| f.3 == "http"), "{http:?}");
}

#[test]
fn a_local_escaper_makes_values_safe_for_its_class_only() {
    let classes = |body: &str| -> Vec<VulnClass> { one(body).into_iter().map(|f| f.0).collect() };
    let helper = "function escapeHtml(s) { return String(s).replace(/</g, '&lt;'); }\n";
    assert!(
            classes(&format!(
                "{helper}app.get('/p', (req, res) => {{ document.body.innerHTML = '<b>' + escapeHtml(req.query.n); }});"
            ))
            .is_empty()
        );
    // Escaped for HTML is not escaped for a shell.
    assert_eq!(
        classes(&format!(
            "{helper}app.get('/p', (req, res) => {{ exec('echo ' + escapeHtml(req.query.n)); }});"
        )),
        vec![VulnClass::CommandInjection]
    );
    // A helper that is no escaper still passes the value on.
    assert_eq!(
        classes(
            "function bold(s) { return '<b>' + s; }\n\
                 app.get('/p', (req, res) => { document.body.innerHTML = bold(req.query.n); });"
        ),
        vec![VulnClass::Xss]
    );
}

#[test]
fn mcp_stdio_transports_run_programs() {
    let found = scan(
        "import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';\n\
             app.post('/servers', (req, res) => {\n\
               const { command, args } = req.body;\n\
               const transport = new StdioClientTransport({ command, args });\n\
             });",
    );
    assert_eq!(
        found.iter().map(|f| (f.0, f.1)).collect::<Vec<_>>(),
        vec![(VulnClass::CommandInjection, Severity::Critical)],
        "{found:?}"
    );
    assert!(
            scan(
                "import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';\n\
                 const transport = new StdioClientTransport({ command: 'node', args: ['server.js'] });"
            )
            .is_empty()
        );
}

#[test]
fn json_stringify_passes_strings_on_and_strings_are_no_operator_objects() {
    assert_eq!(
        one("app.get('/p', (req, res) => { exec('notify ' + JSON.stringify(req.query.msg)); });")
            .len(),
        1
    );
    // A string cannot carry `{ \"$ne\": null }`.
    assert!(
            one("app.post('/l', async (req, res) => { await User.findOne({ email: String(req.body.email) }); });")
                .is_empty()
        );
    // JSON.parse can.
    assert_eq!(
            one("app.post('/l', async (req, res) => { await User.findOne({ email: JSON.parse(req.body.q) }); });")
                .iter()
                .map(|f| f.0)
                .collect::<Vec<_>>(),
            vec![VulnClass::NosqlInjection]
        );
}

#[test]
fn multipart_parser_events_carry_request_data() {
    let found = one("app.post('/up', (req, res) => {\n\
               const bb = busboy({ headers: req.headers });\n\
               bb.on('file', (name, stream, info) => {\n\
                 stream.pipe(fs.createWriteStream(path.join(dir, info.filename)));\n\
               });\n\
               req.pipe(bb);\n\
             });");
    assert_eq!(
        found.iter().map(|f| f.0).collect::<Vec<_>>(),
        vec![VulnClass::PathTraversal],
        "{found:?}"
    );
    // The temporary path is the parser's.
    assert!(
        one("app.post('/up', (req, res) => {\n\
                   const form = new multiparty.Form();\n\
                   form.on('file', (name, file) => { fs.remove(file.path); });\n\
                 });")
        .is_empty()
    );
}

#[test]
fn parameter_summaries_follow_the_field_that_reaches_the_sink() {
    // A function that hands its whole parameter on keeps the field the helper needs: through
    // a plain call, and through `new this(basic)` in a static factory.
    let chain = "function use(o) { exec('cmd ' + o.cmd); }\nfunction make(o) { use(o); }\n\
                     class F { constructor(basic) { this.cfg = basic.cfg; } run() { exec(this.cfg.cmd); } static create(basic) { return new this(basic); } }\n";
    for quiet in [
        "app.get('/p', (req, res) => { make({ name: req.query.n, cmd: 'ls' }); });",
        "app.get('/p', (req, res) => { F.create({ name: req.query.n, cfg: CONFIG }); });",
    ] {
        assert!(one(&format!("{chain}{quiet}")).is_empty(), "{quiet}");
    }
    for found in [
        "app.get('/p', (req, res) => { make({ name: 'a', cmd: req.query.c }); });",
        "app.get('/p', (req, res) => { F.create({ name: 'a', cfg: req.body }); });",
    ] {
        assert_eq!(one(&format!("{chain}{found}")).len(), 1, "{found}");
    }
    // A field the function overwrote before handing the object on is no longer the
    // caller's: a constant, or what another parameter held.
    let count = "function count(p) { coll.find({ type: p.type }); }\n";
    for quiet in [
        "function create(p) { p.type = 'note'; count(p); }",
        "function create(p, cfg) { p['type'] = cfg.kind; count(p); }",
    ] {
        let found = one(&format!(
            "{count}{quiet}\napp.post('/p', (req, res) => {{ create(req.body, CONFIG); }});"
        ));
        assert!(found.is_empty(), "{quiet}: {found:?}");
    }
    let found = one(&format!(
        "{count}function create(p) {{ p.other = 1; count(p); }}\napp.post('/p', (req, res) => {{ create(req.body); }});"
    ));
    assert_eq!(found.len(), 1, "{found:?}");
    // SQL a helper builds from several fields of its parameter: each field is followed, so
    // the one the caller did not overwrite still reaches the query.
    let build = "function build(o) { return { q: `SELECT IF(${o.a}, ${o.b}, ${o.c}) FROM t` }; }\n\
                     function run(o) { const { q } = build(o); db.query(q); }\n";
    assert!(
            one(&format!(
                "{build}app.get('/r', (req, res) => {{ const p = req.query; p.a = 1; p.b = 2; p.c = 3; run(p); }});"
            ))
            .is_empty()
        );
    let found = one(&format!(
        "{build}app.get('/r', (req, res) => {{ const p = req.query; p.a = 1; p.b = 2; run(p); }});"
    ));
    assert_eq!(
        found.iter().map(|f| f.0).collect::<Vec<_>>(),
        vec![VulnClass::SqlInjection],
        "{found:?}"
    );
    let helper = "function run(opts) { exec('cmd ' + opts.cmd); }\n";
    assert!(
        one(&format!(
            "{helper}app.get('/p', (req, res) => {{ run({{ cmd: 'ls', user: req.query.u }}); }});"
        ))
        .is_empty()
    );
    assert_eq!(
        one(&format!(
            "{helper}app.get('/p', (req, res) => {{ run({{ cmd: req.query.c, user: 'x' }}); }});"
        ))
        .len(),
        1
    );
    // An upload's temporary path is the server's; its original name is the client's.
    let helpers = "function discard(file) { fs.unlink(file.path, () => {}); }\n\
                       function keep(file) { fs.writeFileSync(path.join(dir, file.originalname), x); }\n";
    assert!(
        one(&format!(
            "{helpers}app.post('/u', upload.single('f'), (req, res) => {{ discard(req.file); }});"
        ))
        .is_empty()
    );
    assert_eq!(
        one(&format!(
            "{helpers}app.post('/u', upload.single('f'), (req, res) => {{ keep(req.file); }});"
        ))
        .iter()
        .map(|f| f.0)
        .collect::<Vec<_>>(),
        vec![VulnClass::PathTraversal]
    );
}

#[test]
fn auth_checks_on_what_an_auth_call_returned() {
    assert_eq!(
        auth_of(
            "app.post('/p', (req, res) => { const token = req.headers.authorization;\n\
                 const user = token ? verifyToken(token) : null;\n\
                 if (!user) return res.status(401).end();\n\
                 exec('ping ' + req.body.h); });"
        ),
        vec![(Auth::User, Severity::Critical)]
    );
    assert_eq!(
        auth_of(
            "app.post('/p', async (req, res) => { const session = await getServerSession(opts);\n\
                 if (!session) { return res.status(401).end(); }\n\
                 exec('ping ' + req.body.h); });"
        ),
        vec![(Auth::User, Severity::Critical)]
    );
    assert_eq!(
        auth_of(
            "app.post('/p', (req, res) => { if (!isAdmin(req)) return res.sendStatus(403);\n\
                 exec('ping ' + req.body.h); });"
        ),
        vec![(Auth::Admin, Severity::High)]
    );
    // A value from any other call proves nothing.
    assert_eq!(
        auth_of(
            "app.post('/p', (req, res) => { const item = lookup(req.body.id);\n\
                 if (!item) return res.status(404).end();\n\
                 exec('ping ' + req.body.h); });"
        ),
        vec![(Auth::NoneDetected, Severity::Critical)]
    );
}

#[test]
fn void_helpers_that_throw_validate_their_arguments() {
    let helper = "function assertSafeName(name) {\n\
                        if (!/^[\\w.-]+$/.test(name)) { throw new Error('bad name'); }\n\
                      }\n";
    assert!(
        one(&format!(
            "{helper}app.get('/f', (req, res) => {{ const name = req.query.name;\n\
                 assertSafeName(name);\n\
                 fs.readFile(path.join(dir, name), () => {{}}); }});"
        ))
        .is_empty()
    );
    // A predicate that returns its verdict validates nothing when the result is ignored.
    let predicate = "function looksFine(name) {\n\
                           if (!/^[\\w.-]+$/.test(name)) { return false; }\n\
                           return true;\n\
                         }\n";
    assert_eq!(
        one(&format!(
            "{predicate}app.get('/f', (req, res) => {{ const name = req.query.name;\n\
                 looksFine(name);\n\
                 fs.readFile(path.join(dir, name), () => {{}}); }});"
        ))
        .len(),
        1
    );
}

#[test]
fn guards_hold_only_where_they_were_checked() {
    let count = |body: &str| one(body).len();
    // A check on the whole request says nothing about its query.
    assert_eq!(
        count(
            "app.get('/p', (req, res) => { if (!hasValidSession(req)) return; exec('ls ' + req.query.d); });"
        ),
        1
    );
    // A validated path written again with other input is tainted again.
    assert_eq!(
        count(
            "app.post('/p', (req, res) => { const job = {}; job.name = req.query.a;\n\
                   if (!isValidName(job.name)) return;\n\
                   job.name = req.body.b; exec('x ' + job.name); });"
        ),
        1
    );
    // A callback parameter does not inherit the outer variable's facts.
    assert_eq!(
        count(
            "app.post('/p', (req, res) => { const data = req.body;\n\
                   if (!isValidCmd(data.cmd)) return;\n\
                   req.body.list.forEach((data) => exec(data.cmd)); });"
        ),
        1
    );
    // A check inside a loop does not hold after it (the loop may have broken out).
    assert_eq!(
        count(
            "app.get('/p', (req, res) => { const name = req.query.name;\n\
                   while (more()) { if (!isValidName(name)) break; step(); }\n\
                   exec('x ' + name); });"
        ),
        1
    );
    // Nor in another switch case.
    assert_eq!(
        count(
            "app.get('/p', (req, res) => { const name = req.query.name;\n\
                   switch (req.query.mode) { case 'a': if (!isValidName(name)) return; break;\n\
                   case 'b': exec('x ' + name); break; } });"
        ),
        1
    );
    // A throwing check in a try holds after it only when the catch block leaves.
    assert_eq!(
        count(
            "app.get('/p', (req, res) => { const name = req.query.name;\n\
                   try { assertValidName(name); } catch (e) { log(e); }\n\
                   exec('x ' + name); });"
        ),
        1
    );
    assert_eq!(
        count(
            "app.get('/p', (req, res) => { const name = req.query.name;\n\
                   try { assertValidName(name); } catch (e) { return res.sendStatus(400); }\n\
                   exec('x ' + name); });"
        ),
        0
    );
    // A typeof fact learned in a branch that does not leave holds only inside it.
    assert_eq!(
        count(
            "app.post('/p', async (req, res) => { const user = req.body.user;\n\
                   if (typeof user === 'string') { log(user); }\n\
                   await User.findOne({ name: user }); });"
        ),
        1
    );
    // The else branch starts from before the if, not from the then branch.
    assert_eq!(
        count(
            "app.get('/p', async (req, res) => { let url = req.query.u;\n\
                   if (req.query.a) { url = 'https://api.example.com/' + url; }\n\
                   else { await axios.get(url); } });"
        ),
        1
    );
}

#[test]
fn checks_make_values_safe_for_their_classes_only() {
    let classes = |body: &str| -> Vec<VulnClass> { one(body).into_iter().map(|f| f.0).collect() };
    // A valid URL can point anywhere.
    assert_eq!(
        classes(
            "app.get('/p', async (req, res) => { const url = req.query.u;\n\
                     if (!validator.isURL(url)) return; await axios.get(url); });"
        ),
        vec![VulnClass::Ssrf]
    );
    // No `..` means no traversal, not no shell metacharacters.
    let dots = "app.get('/p', (req, res) => { const p = req.query.p;\n\
                    if (p.includes('..')) return;\n";
    assert!(classes(&format!("{dots}fs.readFileSync(path.join(dir, p)); }});")).is_empty());
    assert_eq!(
        classes(&format!("{dots}exec('cat ' + p); }});")),
        vec![VulnClass::CommandInjection]
    );
    // A base name is a safe file name, not a safe shell word.
    assert!(
            classes("app.get('/p', (req, res) => { fs.readFile(path.join(dir, path.basename(req.query.f)), () => {}); });")
                .is_empty()
        );
    assert_eq!(
        classes("app.get('/p', (req, res) => { exec('cat ' + path.basename(req.query.f)); });"),
        vec![VulnClass::CommandInjection]
    );
    // encodeURIComponent leaves quotes alone.
    assert_eq!(
        classes(
            "app.get('/p', (req, res) => { db.query(\"SELECT * FROM t WHERE n = '\" + encodeURIComponent(req.query.n) + \"'\"); });"
        ),
        vec![VulnClass::SqlInjection]
    );
    // `^[\w./-]+$` admits `../`: safe for a shell, not as a path.
    let file = "app.get('/p', (req, res) => { const f = req.query.f;\n\
                    if (!/^[\\w./-]+$/.test(f)) return;\n";
    assert!(classes(&format!("{file}exec('cat ' + f); }});")).is_empty());
    assert_eq!(
        classes(&format!("{file}fs.readFileSync(f); }});")),
        vec![VulnClass::PathTraversal]
    );
    // An unanchored regex is no allowlist; in its matching branch it is no check at all.
    assert_eq!(
        classes(
            "app.get('/p', (req, res) => { const c = req.query.c;\n\
                     if (!/^ls/.test(c)) return; exec(c); });"
        ),
        vec![VulnClass::CommandInjection]
    );
    assert_eq!(
        classes(
            "app.get('/p', (req, res) => { const p = req.query.p;\n\
                     if (/\\.\\./.test(p)) { fs.readFileSync(p); } });"
        ),
        vec![VulnClass::PathTraversal]
    );
    // A scheme is not a host.
    assert_eq!(
        classes(
            "app.get('/p', async (req, res) => { const url = req.query.u;\n\
                     if (!url.startsWith('http')) return; await axios.get(url); });"
        ),
        vec![VulnClass::Ssrf]
    );
    assert!(
            classes("app.get('/p', async (req, res) => { const url = req.query.u;\n\
                     if (!url.startsWith('https://api.example.com/')) return; await axios.get(url); });")
                .is_empty()
        );
    // A negated name is no validator.
    assert_eq!(
        classes(
            "app.get('/p', (req, res) => { const c = req.query.c;\n\
                     if (isNotAllowed(c)) { exec(c); } });"
        ),
        vec![VulnClass::CommandInjection]
    );
}

#[test]
fn common_safe_shapes_are_not_reported() {
    let count = |body: &str| one(body).len();
    // A cache key or a query string is no SQL; a statement is.
    assert_eq!(
        count(
            "app.get('/p', async (req, res) => { await redis.get(`rate-limit:${req.ip}:${req.query.k}`); });"
        ),
        0
    );
    assert_eq!(
        count(
            "app.get('/p', async (req, res) => { await upstream.get(`/products?limit=${req.query.n}`); });"
        ),
        0
    );
    assert_eq!(
        count(
            "app.get('/p', (req, res) => { db.get(`SELECT * FROM t WHERE id = ${req.query.id}`); });"
        ),
        1
    );
    assert_eq!(
        count(
            "app.get('/p', (req, res) => { db.all('SELECT * FROM t' + ' WHERE n = ' + req.query.n); });"
        ),
        1
    );
    // A method of another object is not a same-named function of this file.
    assert_eq!(
        count(
            "class SnapshotStore { read(id) { return fs.readFileSync('/snap/' + id); } }\n\
                   app.get('/p', (req, res) => { res.json(this.cache.read(req.params.id)); });"
        ),
        0
    );
    assert_eq!(
        count(
            "class SnapshotStore { read(id) { return fs.readFileSync('/snap/' + id); } }\n\
                   const store = new SnapshotStore();\n\
                   app.get('/p', (req, res) => { res.json(store.read(req.params.id)); });"
        ),
        1
    );
    // Literal comparisons and ORM filters cannot carry operator objects from JSON.
    assert_eq!(
        count(
            "app.post('/l', async (req, res) => { await User.findOne({ email: { $eq: req.body.email } }); });"
        ),
        0
    );
    assert_eq!(
        count(
            "app.post('/l', async (req, res) => { await repo.findOne({ where: { email: req.body.email } }); });"
        ),
        0
    );
    // jQuery and Mongoose callbacks are no request handlers.
    assert_eq!(
        count("$.get('/api/x', function (data, status) { exec('x ' + data.cmd); });"),
        0
    );
    assert_eq!(
        count(
            "schema.post('findOneAndDelete', function (doc, next) { fs.unlinkSync(doc.path); });"
        ),
        0
    );
}

#[test]
fn nest_parameters_follow_their_decorators_and_pipes() {
    let src = |param: &str| {
        format!(
            "@Controller('items')\nexport class ItemsController {{\n\
                 @Get(':id') find({param}) {{ return this.db.query('SELECT * FROM items WHERE id = ' + id); }}\n}}\n"
        )
    };
    let found = |param: &str| scan(&src(param)).len();
    assert_eq!(found("@Param('id') id"), 1);
    assert_eq!(found("@Query('id', ParseIntPipe) id"), 0);
    assert_eq!(found("@Query('id', new ParseIntPipe()) id"), 0);
    // A route parameter is a string: no operator object.
    let nosql = scan(
        "@Controller('items')\nexport class ItemsController {\n\
             @Get(':id') find(@Param('id') id) { return this.model.findOne({ _id: id }); }\n}\n",
    );
    assert!(nosql.is_empty(), "{nosql:?}");
}

#[test]
fn meteor_check_patterns_decide_scalars() {
    let method = |pattern: &str| {
        one(&format!(
            "Meteor.methods({{ find(q) {{ check(q, {pattern}); return Tasks.find(q); }} }});"
        ))
        .len()
    };
    assert_eq!(method("Object"), 1);
    assert_eq!(method("Match.Any"), 1);
    assert_eq!(method("Match.Optional(Object)"), 1);
    assert_eq!(method("{ id: Object }"), 1);
    assert_eq!(method("String"), 0);
    assert_eq!(method("[String]"), 0);
    assert_eq!(
        method("{ boardId: String, drag: Match.Optional(Boolean) }"),
        0
    );
    assert_eq!(method("targetShape"), 0);
}

#[test]
fn method_sinks_skip_objects_that_hold_no_html() {
    assert!(
        one(
            "app.get('/p', (req, res) => { const out = new URLSearchParams(); \
                 out.append('q', '<b>' + req.query.n); res.json(out.toString()); });"
        )
        .is_empty()
    );
    assert_eq!(
        one("app.get('/p', (req, res) => { const out = $('#list'); \
                 out.append('<b>' + req.query.n); });")
        .len(),
        1
    );
}

#[test]
fn return_summaries_keep_what_the_helper_did() {
    // The helper puts a fixed base before the value: no attacker-chosen host.
    assert!(
        one(
            "function apiUrl(p) { return 'https://api.example.com/items/' + p; }\n\
                 app.get('/p', async (req, res) => { await axios.get(apiUrl(req.query.id)); });"
        )
        .is_empty()
    );
    // The helper builds SQL text around the value.
    let sql = one("function byTable(t) { return 'SELECT * FROM ' + t; }\n\
             app.get('/p', (req, res) => { db.query(byTable(req.query.t)); });");
    assert_eq!(
        sql.iter().map(|f| f.0).collect::<Vec<_>>(),
        vec![VulnClass::SqlInjection],
        "{sql:?}"
    );
    // A plain pass-through helper changes nothing.
    assert_eq!(
        one("function id(u) { return u; }\n\
                 app.get('/p', async (req, res) => { await axios.get(id(req.query.u)); });")
        .len(),
        1
    );
}

#[test]
fn deep_nesting_is_capped_not_overflowed() {
    let deep = format!("x = {}1{};", "f(".repeat(2000), ")".repeat(2000));
    let deep_arr = format!("x = {}1{};", "[".repeat(2000), "]".repeat(2000));
    for src in [deep, deep_arr] {
        // The parser needs its bounded stack (never a default thread); the walker's own
        // recursion is capped.
        let stack = crate::process::parser_stack_bound(src.as_bytes());
        let truncated = std::thread::Builder::new()
            .stack_size(stack)
            .spawn(move || {
                let allocator = Allocator::default();
                let ret = Parser::new(
                    &allocator,
                    &src,
                    source_type(SourceKind::Js, PackageType::CommonJs),
                )
                .with_options(parse_options())
                .parse();
                let result = scan_program(&ret.program, &src);
                assert!(result.findings.is_empty());
                result.truncated
            })
            .unwrap()
            .join()
            .unwrap();
        assert!(truncated);
    }
}

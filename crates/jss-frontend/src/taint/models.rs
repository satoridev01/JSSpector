//! Every piece of framework and library knowledge the v0 taint spike uses, in one place.
//!
//! DEBT (stated, not hidden): `docs/PLAN.md` says framework knowledge lives in YAML packs, enforced
//! by a CI grep. These tables are hard-coded so the spike could produce candidates fast. They
//! are kept together so they can move to packs as they are.

use jss_core::{Severity, VulnClass};

/// Properties of a request object that carry attacker-controlled data (Express, Fastify, Hapi,
/// Koa's `ctx` and `ctx.request`, Node's IncomingMessage).
pub const REQUEST_PROPS: &[&str] = &[
    "body",
    "query",
    "params",
    "headers",
    "cookies",
    "signedCookies",
    "payload",
    "files",
    "file",
    "url",
    "originalUrl",
    "path",
];

/// Fields of `req.file` / `req.files[i]` (multer) that the server chooses, not the client.
pub const UPLOAD_SERVER_FIELDS: &[&str] = &["path", "filename", "destination", "size"];

/// Literal text that looks like part of an SQL statement (a keyword as a whole word).
pub fn looks_like_sql(text: &str) -> bool {
    const KEYWORDS: &[&str] = &[
        "select", "insert", "update", "delete", "where", "from", "values", "order by", "group by",
        "limit", "join", "set",
    ];
    let lower = text.to_ascii_lowercase();
    KEYWORDS.iter().any(|keyword| {
        lower.match_indices(keyword).any(|(at, _)| {
            let before = lower.get(..at).and_then(|s| s.chars().next_back());
            let after = lower
                .get(at + keyword.len()..)
                .and_then(|s| s.chars().next());
            let boundary =
                |c: Option<char>| c.is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_');
            boundary(before) && boundary(after)
        })
    })
}

/// Methods of a request object whose result is attacker-controlled (`req.get('x')`,
/// `await request.json()` in Next.js/fetch-style handlers).
pub const REQUEST_METHODS: &[&str] = &[
    "get",
    "param",
    "header",
    "json",
    "text",
    "formData",
    "query",
    "parseBody",
];

/// Conventional names of a handler's request parameter.
pub const REQUEST_NAMES: &[&str] = &["req", "request"];

/// Methods that register a route handler: `app.post('/x', handler)`.
pub const ROUTE_METHODS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "del", "all", "use", "options", "head", "route",
];

/// Exported function names that are Next.js / web-standard route handlers.
pub const ROUTE_EXPORTS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE"];

/// socket.io events that carry no client data.
pub const SOCKET_BUILTIN_EVENTS: &[&str] = &[
    "connect",
    "connection",
    "disconnect",
    "disconnecting",
    "error",
    "connect_error",
    "reconnect",
];

/// Names of a socket.io event callback's acknowledgement parameter (not data).
pub const SOCKET_ACK_NAMES: &[&str] = &["cb", "callback", "ack", "fn", "done", "next"];

/// Methods whose result carries the taint of the receiver and arguments.
pub const PASS_METHODS: &[&str] = &[
    "trim",
    "trimStart",
    "trimEnd",
    "toLowerCase",
    "toUpperCase",
    "toLocaleLowerCase",
    "toLocaleUpperCase",
    "replace",
    "replaceAll",
    "slice",
    "substring",
    "substr",
    "split",
    "join",
    "concat",
    "toString",
    "padStart",
    "padEnd",
    "normalize",
    "at",
    "valueOf",
    "repeat",
];

/// Methods that build a string out of their arguments (the result is "built").
pub const BUILD_METHODS: &[&str] = &["concat", "join", "format"];

/// Global functions whose result carries their arguments' taint.
pub const PASS_GLOBALS: &[&str] = &[
    "String",
    "decodeURIComponent",
    "decodeURI",
    "unescape",
    "Buffer.from",
    "JSON.parse",
    "util.format",
];

/// `path` functions whose result carries their arguments' taint.
pub const PATH_PASS: &[&str] = &["join", "resolve", "normalize", "format", "relative"];

/// Calls that clear taint. Unknown calls clear it anyway in v0; these are listed so the intent
/// is explicit and survives a later "unknown calls propagate" change.
pub const CLEARING: &[&str] = &[
    "parseInt",
    "parseFloat",
    "Number",
    "Boolean",
    "path.basename",
    "basename",
];

/// Normalizes a module specifier to the family the sink tables use.
pub fn module_family(spec: &str) -> Option<&'static str> {
    let spec = spec.strip_prefix("node:").unwrap_or(spec);
    Some(match spec {
        "child_process" => "child_process",
        "fs" | "fs/promises" | "fs-extra" | "graceful-fs" | "original-fs" => "fs",
        "vm" => "vm",
        "path" | "path/posix" | "path/win32" | "upath" => "path",
        "http" | "https" | "http2" => "http",
        "axios" | "got" | "node-fetch" | "undici" | "request" | "superagent" | "needle"
        | "cross-fetch" | "isomorphic-fetch" | "ky" | "phin" => "http-client",
        "shelljs" => "shelljs",
        "execa" => "execa",
        "util" => "util",
        _ => return None,
    })
}

/// How a sink matches its arguments.
#[derive(Debug, Clone, Copy)]
pub enum ArgRule {
    /// The argument at this index is tainted.
    Any(usize),
    /// The argument at this index is tainted and was built by concatenation or a template.
    Built(usize),
    /// The argument at this index is a URL whose start (scheme and host) is tainted, or an
    /// options object whose url/host is.
    UrlPrefix(usize),
}

#[derive(Debug, Clone, Copy)]
pub struct Sink {
    pub class: VulnClass,
    pub severity: Severity,
    pub args: &'static [ArgRule],
}

const fn sink(class: VulnClass, severity: Severity, args: &'static [ArgRule]) -> Sink {
    Sink {
        class,
        severity,
        args,
    }
}

use ArgRule::{Any, Built, UrlPrefix};
use Severity::{Critical, High};
use VulnClass::{CodeInjection, CommandInjection, PathTraversal, SqlInjection, Ssrf};

/// A function exported by a module family: `(family, export)`. An empty export is the module
/// itself called as a function (`axios(url)`).
pub fn module_sink(family: &str, export: &str) -> Option<Sink> {
    Some(match (family, export) {
        ("child_process", "exec" | "execSync") => sink(CommandInjection, Critical, &[Any(0)]),
        // A tainted program name; `shell: true` is handled by the walker.
        ("child_process", "spawn" | "spawnSync" | "execFile" | "execFileSync" | "fork") => {
            sink(CommandInjection, High, &[Any(0)])
        }
        ("shelljs", "exec") => sink(CommandInjection, Critical, &[Any(0)]),
        ("execa", "execaCommand" | "execaCommandSync" | "command" | "commandSync") => {
            sink(CommandInjection, Critical, &[Any(0)])
        }
        ("execa", "" | "execa" | "execaSync") => sink(CommandInjection, High, &[Any(0)]),
        ("vm", "runInNewContext" | "runInThisContext" | "runInContext" | "compileFunction")
        | ("vm", "Script") => sink(CodeInjection, Critical, &[Any(0)]),
        (
            "fs",
            "readFile" | "readFileSync" | "writeFile" | "writeFileSync" | "appendFile"
            | "appendFileSync" | "createReadStream" | "createWriteStream" | "unlink" | "unlinkSync"
            | "rm" | "rmSync" | "rmdir" | "rmdirSync" | "readdir" | "readdirSync" | "open"
            | "openSync" | "outputFile" | "outputFileSync" | "remove" | "removeSync" | "readJson"
            | "readJsonSync" | "writeJson" | "writeJsonSync",
        ) => sink(PathTraversal, High, &[Any(0)]),
        (
            "fs",
            "rename" | "renameSync" | "copyFile" | "copyFileSync" | "cp" | "cpSync" | "copy"
            | "copySync" | "move" | "moveSync" | "symlink" | "symlinkSync",
        ) => sink(PathTraversal, High, &[Any(0), Any(1)]),
        ("http", "get" | "request") => sink(Ssrf, High, &[UrlPrefix(0)]),
        (
            "http-client",
            "" | "get" | "post" | "put" | "patch" | "delete" | "head" | "request" | "stream",
        ) => sink(Ssrf, High, &[UrlPrefix(0)]),
        _ => return None,
    })
}

/// Global functions (`eval(x)`, `fetch(url)`), by callee text.
pub fn global_sink(name: &str) -> Option<Sink> {
    Some(match name {
        "eval" | "Function" => sink(CodeInjection, Critical, &[Any(0), Any(1), Any(2)]),
        "fetch" => sink(Ssrf, High, &[UrlPrefix(0)]),
        _ => return None,
    })
}

/// Methods matched on any receiver: SQL query builders and response file senders.
pub fn method_sink(method: &str) -> Option<Sink> {
    Some(match method {
        "query" | "execute" | "raw" | "whereRaw" | "orderByRaw" | "havingRaw" | "joinRaw"
        | "$queryRawUnsafe" | "$executeRawUnsafe" | "unsafe" | "exec" | "all" | "run" | "get"
        | "prepare" | "each" => sink(SqlInjection, High, &[Built(0)]),
        // A `root` option makes these safe; the walker checks for it.
        "sendFile" | "download" => sink(PathTraversal, High, &[Any(0)]),
        _ => return None,
    })
}

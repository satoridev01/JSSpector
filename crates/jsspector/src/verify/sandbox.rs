//! The execution side of `--verify`: prepare the scanned repo, start the app, drive the derived
//! requests and tear everything down. The default Docker runtime keeps traffic on a private
//! network. `JSS_VERIFY_RUNTIME=local` is for an already-disposable CI sandbox such as a Satori job:
//! it reads the repository Dockerfile's package setup and exposed port, then runs the app as a child
//! process in that same sandbox without requiring nested Docker. Local execution is refused on an
//! ordinary host because a verified command injection would otherwise run with the developer's own
//! operating-system permissions.

use super::mcp::{self, McpDiscovery};
use super::payload::{self, Attempt, Canary, Signal};
use super::plan::{Entry, Method, Probe};
use super::{ControlObservation, Outcome, Reproduction};
use fs2::FileExt;
use serde::Deserialize;
use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::process::{Child, Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

mod auth;
mod browser;
mod oracles;
mod runtime;
pub(super) use browser::*;
pub(super) use runtime::*;

/// A monotonic request counter, used to give every driven request a distinct `X-Forwarded-For` so a
/// per-IP rate limiter never throttles the scanner's own probe volume (see [`request_spec`]).
static REQUEST_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

const BASE_IMAGE: &str = "node:22-slim";
const DEFAULT_NODE_MAJOR: u32 = 22;
/// The oldest Node a failed launch is retried on for a repository that pins an older runtime: the
/// launch shim is preloaded through `NODE_OPTIONS`, which Node supports from 8.
const MIN_FALLBACK_NODE_MAJOR: u32 = 8;

const VERIFY_RUN_LABEL_KEY: &str = "ci.satori.jsspector.verify-run";
const DB_IMAGE: &str = "mongo:6";
const DB_ALIASES: [&str; 4] = ["mongo", "mongodb", "db", "database"];
const DB_NAME: &str = "jssverifydb";
const REDIS_IMAGE: &str = "redis:7-alpine";
/// The MongoDB server the local runtime provisions on demand when an app needs a database and none
/// is installed. 7.0 is the oldest series published for Debian 12 (the image Satori runs) and speaks
/// the same wire protocol as the Docker runtime's `mongo:6` sidecar.
const LOCAL_MONGO_VERSION: &str = "7.0.28";
/// Downloads the `mongod` build for the host's OS, distribution and architecture.
const LOCAL_MONGO_DOWNLOADER: &str = "mongodb-memory-server-core@11.3.0";
/// The MongoDB shell provisioned alongside it, as MongoDB's own standalone build.
const LOCAL_MONGOSH_VERSION: &str = "2.13.0";
/// The Redis server the local runtime builds from source on demand: the series of the Docker
/// runtime's `redis:7-alpine` sidecar.
const LOCAL_REDIS_VERSION: &str = "7.2.11";

/// Enable full (level 2) profiling on every application database, so the server records the namespace
/// of every command it receives. Used to discover which collection a read-only sink actually queries.
const ENABLE_PROFILING_SCRIPT: &str = "db.getMongo().getDBNames().forEach(function(n){\
    if(['admin','local','config'].indexOf(n)>=0)return;\
    try{db.getSiblingDB(n).setProfilingLevel(2);}catch(e){}\
  });";

/// A mongosh script that reads the profiler and, for every recorded query whose filter references
/// the per-run sentinel `absent` (the injected field's benign `{$eq:<absent>}` value), inserts one
/// document the query selects: each scalar equality is copied verbatim and the one operator field
/// that references the sentinel is set to a present value, so the later match-all `{$ne:<absent>}`
/// returns it while the `{$eq:<absent>}`/`{$in:[]}` controls do not. A filter field that is itself an
/// object referencing the sentinel is the injected field; other operator fields (an earlier guard's
/// `{verified:true}` does not reference the sentinel, so it is skipped and left off the document,
/// keeping the planted record reachable past the guard). `absent` is 24 hex characters, so it needs
/// no escaping. Collection resolution covers find/count/findAndModify/update/delete/distinct; the
/// profiler is then disabled and its capped log dropped.
fn nosql_lookup_seed_script(absent: &str) -> String {
    format!(
        "var ABSENT='{absent}';var planted=0;\
         db.getMongo().getDBNames().forEach(function(n){{\
           if(['admin','local','config'].indexOf(n)>=0)return;\
           var d=db.getSiblingDB(n);\
           try{{d.getCollection('system.profile').find({{}}).forEach(function(e){{\
             if(!e.command)return;\
             var c=e.command;\
             var coll=c.find||c.count||c.findAndModify||c.findandmodify||c.update||c.delete||c.distinct;\
             if(!coll&&e.ns){{var p=e.ns.split('.');p.shift();coll=p.join('.');}}\
             if(typeof coll!=='string'||coll.indexOf('system.')===0)return;\
             var filter=c.filter||c.query;\
             if(!filter&&c.updates&&c.updates[0])filter=c.updates[0].q;\
             if(!filter&&c.deletes&&c.deletes[0])filter=c.deletes[0].q;\
             if(!filter||typeof filter!=='object')return;\
             if(JSON.stringify(filter).indexOf(ABSENT)<0)return;\
             var doc={{jss_seed:1}};var injected=false;\
             Object.keys(filter).forEach(function(k){{\
               if(k.charAt(0)==='$')return;\
               var v=filter[k];\
               if(v&&typeof v==='object'&&!Array.isArray(v)){{\
                 if(JSON.stringify(v).indexOf(ABSENT)>=0){{\
                   if(k==='_id'){{doc[k]=ObjectId();doc.id=doc[k].toString();\
                     doc.mid='/u/'+doc.id;doc.pl=[];}}\
                   else{{doc[k]='jss_lookup_seed';}}injected=true;}}\
               }}else if(v!==null&&typeof v!=='object'){{doc[k]=v;}}\
             }});\
             if(injected){{try{{d.getCollection(coll).insertOne(doc);planted++;}}catch(e2){{}}}}\
           }});}}catch(e){{}}\
           try{{d.setProfilingLevel(0);}}catch(e){{}}\
           try{{d.getCollection('system.profile').drop();}}catch(e){{}}\
         }});print('planted='+planted);"
    )
}

/// Read the profiler log, seed one document into every (otherwise empty) collection a profiled command
/// targeted — resolving the collection from the command's own field first, falling back to the `ns` —
/// then disable profiling and drop its capped log so only the seeded documents remain.
///
/// The seed document is shaped from the profiled command's own filter so it satisfies the query's
/// non-injected constraints: a plain equality (`{status:"active"}`) is copied verbatim, a range
/// (`{expires:{$gt:now}}`) is seeded with a value that satisfies it (a far-future date or a larger
/// number), and any other operator field (the probed field, which the benign control sends as
/// `{$eq:<absent>}`) is seeded with a neutral sentinel distinct from the injected token. Without this,
/// a query with a second required clause (an unexpired-token window, an owner id) never matches the
/// generic placeholder document and the match-all/match-none differential has nothing to observe. The
/// sentinel and derived values come only from the observed query, so nothing is tied to a target.
const SEED_PROFILED_SCRIPT: &str = "db.getMongo().getDBNames().forEach(function(n){\
    if(['admin','local','config'].indexOf(n)>=0)return;\
    var d=db.getSiblingDB(n);\
    var seeds={};\
    function satisfy(v){\
      if(v&&typeof v==='object'&&!Array.isArray(v)&&!(v instanceof Date)){\
        var ks=Object.keys(v);\
        var isOp=ks.length>0&&ks.every(function(k){return k.charAt(0)==='$';});\
        if(isOp){\
          if('$gt' in v||'$gte' in v){var b=('$gt' in v)?v.$gt:v.$gte;\
            if(b instanceof Date)return new Date(b.getTime()+31536000000);\
            if(typeof b==='number')return b+1000000000;return b;}\
          if('$lt' in v||'$lte' in v){var c2=('$lt' in v)?v.$lt:v.$lte;\
            if(c2 instanceof Date)return new Date(c2.getTime()-31536000000);\
            if(typeof c2==='number')return c2-1000000000;return c2;}\
          if('$in' in v&&Array.isArray(v.$in)&&v.$in.length>0)return v.$in[0];\
          return 'jss_seed';\
        }\
      }\
      return v;\
    }\
    try{d.getCollection('system.profile').find({}).forEach(function(e){\
      var c=null,f=null;\
      if(e.command){c=e.command.find||e.command.findAndModify||e.command.count||\
        e.command.aggregate||e.command.distinct||e.command.update||e.command.delete;\
        f=e.command.filter||e.command.query;}\
      if(!c&&e.ns){var p=e.ns.split('.');p.shift();c=p.join('.');}\
      if(typeof c!=='string'||c.indexOf('system.')===0)return;\
      var doc=seeds[c]||{jss_seed:1};\
      if(f&&typeof f==='object'){Object.keys(f).forEach(function(k){\
        if(k.charAt(0)==='$')return;\
        if(!doc.hasOwnProperty(k)||doc[k]==='jss_seed'){\
          try{doc[k]=satisfy(f[k]);}catch(e2){}}\
      });}\
      seeds[c]=doc;\
    });}catch(e){}\
    Object.keys(seeds).forEach(function(c){\
      try{if(d.getCollection(c).countDocuments({})===0)\
        d.getCollection(c).insertOne(seeds[c]);}catch(e){}\
    });\
    try{d.setProfilingLevel(0);}catch(e){}\
    try{d.getCollection('system.profile').drop();}catch(e){}\
  });";
const REDIS_ALIASES: [&str; 2] = ["redis", "cache"];
const LOCAL_FIXTURE_LOCK: &str = "jsspector-local-verify.lock";
const LOCAL_FIXTURE_MANIFEST: &str = "jsspector-local-fixtures.json";

/// Whether a Docker daemon is reachable. The CLI on some platforms exits 0 even when it cannot
/// connect, so this checks that `docker info` actually printed a server version, not an error.
pub fn available() -> bool {
    if local_runtime_requested() {
        return Command::new("node")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success());
    }
    let Ok(output) = Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output()
    else {
        return false;
    };
    let version = String::from_utf8_lossy(&output.stdout);
    let version = version.trim();
    // A real version starts with a digit; an error (or empty) does not.
    output.status.success() && version.bytes().next().is_some_and(|b| b.is_ascii_digit())
}

fn command_available(command: &str) -> bool {
    Command::new(command)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn available_local_port() -> Result<u16, String> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|error| format!("reserving a local marker port: {error}"))?;
    listener
        .local_addr()
        .map(|address| address.port())
        .map_err(|error| format!("reading the local marker port: {error}"))
}

fn local_listening_ports() -> Vec<u16> {
    let Ok(output) = Command::new("lsof")
        .args(["-nP", "-iTCP", "-sTCP:LISTEN"])
        .output()
    else {
        return Vec::new();
    };
    let mut ports = String::from_utf8_lossy(&output.stdout)
        .lines()
        .skip(1)
        .filter_map(|line| {
            line.split_whitespace().find_map(|field| {
                field
                    .rsplit_once(':')
                    .and_then(|(_, port)| port.parse::<u16>().ok())
            })
        })
        .collect::<Vec<_>>();
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn local_excluded_ports(
    baseline: &[u16],
    marker: Option<u16>,
    has_db: bool,
    has_redis: bool,
) -> Vec<u16> {
    let mut ports = baseline.to_vec();
    ports.extend(marker);
    ports.extend(has_db.then_some(27017));
    ports.extend(has_redis.then_some(6379));
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn wait_local_service(child: &mut Child, port: u16, name: &str) -> Result<(), String> {
    for _ in 0..80 {
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!(
                "local {name} exited before it was ready ({status})"
            ));
        }
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    let _ = child.kill();
    let _ = child.wait();
    Err(format!(
        "local {name} did not listen on port {port} within 20s"
    ))
}

/// Set by `scan --local`: run apps in this already-disposable environment instead of Docker.
static LOCAL_RUNTIME: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Selects the local runtime for this process (`scan --local`).
pub(super) fn request_local_runtime() {
    LOCAL_RUNTIME.store(true, std::sync::atomic::Ordering::Relaxed);
}

const LOCAL_RUNTIME_REFUSAL: &str = "--local executes untrusted repository code as the current OS user and is refused outside a disposable container; start Docker, or set JSS_VERIFY_DISPOSABLE=1 only inside a disposable VM/container";

fn local_runtime_is_disposable(acknowledgement: Option<&str>, in_container: bool) -> bool {
    acknowledgement.is_some_and(|value| value == "1") || in_container
}

fn local_runtime_selected() -> bool {
    LOCAL_RUNTIME.load(std::sync::atomic::Ordering::Relaxed)
        || std::env::var("JSS_VERIFY_RUNTIME").is_ok_and(|value| value == "local")
}

/// Why a requested local runtime may not start. A Docker container is already a disposable OS
/// boundary; other disposable workers must acknowledge that property explicitly.
pub(super) fn local_runtime_refusal() -> Option<&'static str> {
    let acknowledgement = std::env::var("JSS_VERIFY_DISPOSABLE").ok();
    (local_runtime_selected()
        && !local_runtime_is_disposable(
            acknowledgement.as_deref(),
            std::path::Path::new("/.dockerenv").is_file(),
        ))
    .then_some(LOCAL_RUNTIME_REFUSAL)
}

/// Whether apps run in this environment rather than in Docker: `scan --local`, or
/// `JSS_VERIFY_RUNTIME=local` (kept for existing scripts and for the self-heal controller's
/// re-invocation).
pub(super) fn local_runtime_requested() -> bool {
    local_runtime_selected() && local_runtime_refusal().is_none()
}

/// Where the MCP server of a session answers.
#[derive(Debug, Clone)]
struct McpEndpoint {
    transport: String,
    path: String,
    /// The command that starts the server, when it speaks only stdio and answers through the
    /// bridge: what a reproduction runs, since a reader has no bridge.
    stdio: Option<Vec<String>>,
}

/// What the MCP calls made for one candidate came back as.
#[derive(Debug, Default)]
struct McpCalls {
    total: usize,
    /// Calls the tool's input schema rejected (status 422): the payload never reached the handler.
    rejected: usize,
    /// The first rejection's text, for the reason a candidate is skipped with.
    first_rejection: Option<String>,
}

/// A built image, a private network, a marker service and a running app — launched fresh for one
/// finding's own attempts, never shared with another finding's (see `acquire_http_session`, which
/// tears down and relaunches rather than reusing a live session across findings, even on the same
/// app). [`Self::teardown`] removes all of it; [`Drop`] is a backstop.
pub struct Session {
    runtime: Runtime,
    tag: String,
    network: String,
    app: String,
    /// Docker runtime: the browser container a reflected XSS is loaded in, on the app's private
    /// network, started on the first reflected-XSS probe.
    xss_browser: Option<String>,
    /// socket.io events whose emit was never acked (see [`Session::socket_ack_wait`]).
    socket_unacked: RefCell<std::collections::BTreeSet<String>>,
    /// MCP discovery by candidate paths; a failure is kept too, so it is not repeated.
    mcp_discovery: RefCell<std::collections::BTreeMap<String, Result<McpDiscovery, String>>>,
    /// The MCP endpoint attempts are sent to: where the latest discovery found the server.
    mcp_endpoint: RefCell<Option<McpEndpoint>>,
    /// The concrete (tool, argument) probe an MCP exercise verified, so a fix is proven against
    /// that exact call rather than the open one the finding was planned as.
    mcp_resolved: RefCell<Option<Probe>>,
    /// Requests left for the candidate being tried; `None` is unbounded.
    attempt_budget: std::cell::Cell<Option<usize>>,
    /// The exact source expression this finding names.  Every positive proof must observe its token
    /// during the same driven request as the exploitation effect.
    sink_binding: Option<super::sink_binding::Binding>,
    last_sink_hit: std::cell::Cell<bool>,
    proof_sink_hit: std::cell::Cell<bool>,
    unbound_effect: std::cell::Cell<bool>,
    /// The concrete request that most recently verified this finding. Fix proof replays this exact
    /// request after each relaunch instead of searching the complete payload/route matrix again.
    /// Complex differential oracles that do not verify through [`Self::send`] leave this empty and
    /// retain the exhaustive fallback.
    last_verified_attempt: RefCell<Option<Attempt>>,
    /// A harmless resource-creation request needed before a query/evaluator route can run (for
    /// example, create one model cell before `/query` can evaluate an expression). Kept so fix
    /// relaunches and the displayed PoC repeat the same prerequisite deterministically.
    probe_setup: RefCell<Vec<Attempt>>,
    /// Transport/driver failures observed while exercising the current finding. A negative verdict
    /// is conclusive only when every request the verifier relied on was actually driven.
    driver_errors: RefCell<Vec<String>>,
    driver_successes: std::cell::Cell<usize>,
    /// MCP calls made for the candidate being tried (see [`McpCalls`]).
    mcp_calls: RefCell<McpCalls>,
    /// The session was launched through the stdio bridge (see [`super::stdio`]) rather than as the
    /// app itself: the MCP server is the bridge's child, and its state says whether one started.
    stdio_bridge: bool,
    /// The command the bridge found to start the stdio server, once it reported one.
    mcp_stdio: RefCell<Option<Vec<String>>>,
    marker: String,
    db: Option<String>,
    db_env: Vec<(String, String)>,
    redis: Option<String>,
    redis_env: Vec<(String, String)>,
    /// SQL databases the app needs before it listens (container name, plan); see
    /// [`super::services`]. Docker runtime only.
    sql: Vec<(String, super::services::SqlSidecar)>,
    /// Extra network aliases for the MongoDB sidecar (the Compose service names the app uses).
    mongo_aliases: Vec<String>,
    /// The MongoDB image the repository pins (Compose or CI); [`DB_IMAGE`] otherwise.
    mongo_image: Option<String>,
    /// Database names the app connects to by name in its own source (`mongodb://host/<name>`). A
    /// read-only query sink against such a database never writes, so MongoDB never creates it on disk
    /// and `listDatabases` (and so `getDBNames()`) omits it. Naming it lets the verifier enable
    /// profiling on the exact database the sink queries, so the query is recorded and its collection
    /// can be seeded for the match-all/match-none differential. Discovered by [`mongo_database_names`].
    mongo_databases: Vec<String>,
    /// The shell the MongoDB image ships (`mongosh` from 5.0 on, `mongo` before), found once.
    mongo_shell: std::cell::Cell<Option<&'static str>>,
    /// The app's environment for those databases (from its Compose service and its own
    /// `process.env` reads), applied after the generic database variables.
    service_env: Vec<(String, String)>,
    canary: Canary,
    /// The container port the app listens on: the one we ask for via `PORT`, or, for an app that
    /// fixes its own, the one port it is found listening on (see [`listening_probe_excluding`]).
    port: u16,
    /// Bumped per probe, so one probe's write/service marker never confirms another's.
    nonce: u32,
    /// For an app that drops root at startup (`process.setuid`/`setgid` to a uid/gid read from the
    /// environment), the non-root `uid:gid` to run the container as, so that privilege drop is a
    /// genuine no-op to the identity the process already holds — it ends up as the unprivileged user
    /// it meant to become, with nothing bypassed. `None` when the app performs no privilege drop.
    run_as: Option<(u32, u32)>,
    /// Environment the app's deployment supplies that the sandbox must reproduce for startup to
    /// succeed honestly (the uid/gid/port variables a privilege-dropping app reads). Seeded into
    /// every launch attempt.
    base_env: Vec<RequiredEnv>,
    /// `NODE_PATH` for the launched module when its dependencies are installed in a sibling
    /// application package that bundles it (see [`dependency_provider`]), pointing at that package's
    /// `node_modules` so the module's bare `require(...)` resolves — the same resolution the real app
    /// sets up for its bundled code. `None` when dependencies install in the launch directory itself.
    node_path: Option<String>,
    /// Whether the app uses Node's built-in `node:sqlite`, which requires the `--experimental-sqlite`
    /// runtime flag to load. When set, the flag is added to `NODE_OPTIONS` so the app's own database
    /// initialization succeeds honestly instead of throwing on an unavailable module — the flag is
    /// added only for apps that reference it, so it can never change the startup of an app that does
    /// not. Detected from the app's source (see [`uses_node_sqlite`]).
    node_sqlite: bool,
    /// Whether the launched entry is an Electron main-process module (see [`is_electron_main_process`]).
    /// Run directly with `node`, such a file throws because `require('electron')` returns the binary
    /// path rather than the main-process API, so `const { app } = require('electron')` is `undefined`
    /// and the app exits before its embedded HTTP server binds. When set, the Electron shim
    /// ([`ELECTRON_SHIM_JS`]) is preloaded through `NODE_OPTIONS`, supplying an inert main-process API
    /// so the app's own `whenReady` callback runs and the server listens — the same lifecycle Electron
    /// would drive, with nothing about the request path or the sink altered.
    electron_main: bool,
    /// When set, the synthetic per-request `X-Forwarded-For` (which de-buckets a per-IP rate limiter,
    /// see [`request_spec`]) is suppressed for the next requests. A genuine loopback request carries
    /// no forwarding header; an app that derives trust from the proxy chain (a loopback-only admin
    /// surface that treats any forwarding header as a remote proxy hop) would otherwise read the
    /// verifier's own loopback request as remote and refuse it before the sink. Toggled on only for a
    /// retry that represents the request's true loopback origin, never to grant access the request did
    /// not already have — a real remote attacker still presents a non-loopback socket.
    omit_forwarding: std::cell::Cell<bool>,
    /// Host repo root, used to map startup stack frames under `/app` back to app source.
    root: std::path::PathBuf,
    /// Bare package names the entry module `require`s inside a `try`/`catch` — modules it is written
    /// to tolerate the absence of (an optional native/platform bridge injected only on-device). When
    /// the missing-module stub is engaged, these are *not* stubbed: the launch shim lets their
    /// `require` throw so the app's own `catch` fallback runs, exactly as off-platform. Substituting
    /// an inert function-stub instead would make the guarded value truthy and crash the very fallback
    /// it was meant to avoid (`path.join(getDataPath())` on a non-string). Collected by
    /// [`guarded_bare_requires`]; empty when there is no entry module or it guards nothing.
    guarded_modules: Vec<String>,
    /// The app's launch command as a JSON argv array (the image `CMD`). Kept so a retry that must
    /// first provision a runtime file (a TLS key/cert the app reads before it listens; see
    /// [`missing_tls_material`]) can wrap the launch in a shell that stages that file and then
    /// `exec`s this exact command.
    start_command: String,
    /// Whether the app serves TLS: set when startup needed a self-signed key/cert pair provisioned
    /// so its `https`/`tls` server could bind. The driver then speaks HTTPS to it (see
    /// [`request_spec`]); it also falls back across protocols, so this is an ordering hint, not a
    /// security relaxation of the app.
    tls: bool,
    /// The app's own build step and the directory it runs in (inside the container for Docker, on
    /// disk for the local runtime), when preparing the app ran one: a source change only takes
    /// effect after it runs again (see [`Self::relaunch_with_files`]).
    rebuild: Option<(String, String)>,
    /// When the app runs the TypeScript compiler's output, the directory to compile in (inside the
    /// container for Docker, on disk for the local runtime): a changed TypeScript file is compiled
    /// with the project's own `tsc` rather than through the whole build script, whose other steps
    /// (a frontend bundle) may fail and leave the server's compiled code as it was.
    typescript: Option<TypescriptBuild>,
    /// How the local runtime last launched the app successfully, so it can be relaunched the same
    /// way with a changed file. `None` for Docker, which restarts its container instead.
    local_launch: Option<LocalLaunch>,
    /// Files the local runtime overwrote on disk to try a change, with their original content:
    /// restored by [`Self::restore_files`], and by teardown as a backstop.
    overwritten: Vec<(String, String)>,
    local_marker_port: Option<u16>,
    local_baseline_ports: Vec<u16>,
    /// Backing services the app declares a client for but the local runtime cannot provide (Redis
    /// without `redis-server` on PATH). The app is still launched without that service's connection
    /// settings — many apps treat a cache/queue as optional and fall back to in-process state when it
    /// is unconfigured — so a finding can be proved on the code path that does not need it. Because
    /// the environment is reduced, a negative result is never reported as `not-reproduced`: see
    /// [`qualify_reduced_environment`].
    unavailable_services: Vec<String>,
    /// `PATH` with the directories of backing-service binaries the local runtime provisioned
    /// (`mongod`, `mongosh`, `redis-server`) first, for the services it starts and the commands it
    /// runs against them. `None` when nothing was provisioned.
    service_path: Option<std::ffi::OsString>,
    torn_down: bool,
}

/// What the local runtime does with a declared Redis client: start a private `redis-server` when
/// one is installed or could be provisioned, otherwise launch without Redis and record the gap. A
/// declared client is not proof the app needs Redis to serve a request (it is often optional and
/// env-gated), so refusing to launch would skip findings whose path never touches it.
fn local_redis_plan(declared: bool, server_available: bool) -> (bool, Option<String>) {
    match (declared, server_available) {
        (true, true) => (true, None),
        (true, false) => (
            false,
            Some(
                "Redis (`redis-server` is not installed and could not be provisioned, so the app \
                 ran without Redis)"
                    .to_owned(),
            ),
        ),
        (false, _) => (false, None),
    }
}

/// Attach the services the sandbox could not provide to a launch failure, so a crash caused by
/// the missing service is not mistaken for an unrelated startup problem.
fn note_unavailable_services(error: String, unavailable: &[String]) -> String {
    if unavailable.is_empty() {
        error
    } else {
        format!("{error} (unavailable: {})", unavailable.join(", "))
    }
}

/// A run in a reduced environment (a declared backing service was unavailable) proves a finding
/// when it reproduces, because the proof is the app's own behavior. A negative result is
/// inconclusive, though: the vulnerable path may need the missing service. So it is reported as
/// skipped, with the reason, never as `not-reproduced`.
fn qualify_reduced_environment(outcome: Outcome, unavailable: &[String]) -> Outcome {
    match outcome {
        Outcome::NotReproduced { tried } if !unavailable.is_empty() => Outcome::Skipped {
            reason: format!(
                "not reproduced after {tried} request(s) in a reduced environment; unavailable: {}",
                unavailable.join(", ")
            ),
        },
        other => other,
    }
}

/// A negative verdict requires every request the verifier relied on to have reached its driver.
/// Transport failures are infrastructure uncertainty, never evidence that the vulnerability did
/// not reproduce. A positive proof or an already-explained skip is left unchanged.
fn qualify_driver_health(outcome: Outcome, errors: &[String], successes: usize) -> Outcome {
    match outcome {
        Outcome::NotReproduced { .. } if !errors.is_empty() => Outcome::Skipped {
            reason: format!(
                "verification transport was inconclusive: {} request(s) failed after {successes} completed ({})",
                errors.len(),
                errors.join("; ")
            ),
        },
        other => other,
    }
}

/// Filesystem fixtures a container launch stages ahead of the app's own command on a retry: TLS
/// key/cert material, Firebase service-account JSON, and committed runtime-config copies. Grouping
/// them keeps the launch call signature small as more startup preconditions are reproduced.
struct StartupStaging<'a> {
    cert_files: &'a [(String, bool)],
    cred_files: &'a [String],
    config_files: &'a [ConfigStage],
}

/// The settings a successful local launch ended up with (see `boot_local`'s retries).
#[derive(Clone)]
struct LocalLaunch {
    env: Vec<RequiredEnv>,
    stub_missing_modules: bool,
    mongodb_callback_promises: bool,
    next_development: bool,
    scratch_dirs: Vec<String>,
}

enum Runtime {
    Docker,
    Local {
        /// Root of the disposable checkout being verified. This can be wider than `app_root`
        /// when the runnable package lives in a workspace subdirectory but resolves startup
        /// fixtures (for example TLS material) relative to the checkout root.
        checkout_root: Box<std::path::PathBuf>,
        app_root: std::path::PathBuf,
        /// Package root whose dependency tree backs `app_root`. Kept separately for workspaces,
        /// where a startup crash can name a native addon installed at the repository root.
        install_root: Box<std::path::PathBuf>,
        log: std::path::PathBuf,
        command: Vec<String>,
        process: Box<RefCell<Option<Child>>>,
        services: Box<RefCell<Vec<Child>>>,
        service_dirs: Vec<std::path::PathBuf>,
        marker_log: std::path::PathBuf,
        created_files: Vec<std::path::PathBuf>,
        /// Private home presented to the application. Frameworks and CLIs commonly persist state
        /// under `os.homedir()`; verification must never write that state into the operator's real
        /// account.
        home_dir: Box<std::path::PathBuf>,
        /// A verifier-provisioned runtime directory (the package's declared Bun release, see
        /// [`provision_local_bun`]) put first on the application's `PATH`. `None` when the app
        /// needs nothing beyond the host tools.
        tool_dir: Box<Option<std::path::PathBuf>>,
        /// Serializes the fixed `/tmp/jss-*` helper namespace across scanner processes. The OS
        /// releases this lock even when a scan is interrupted, allowing the next run to recover
        /// fixtures recorded in the ownership manifest without touching unrelated files.
        _fixture_lock: File,
    },
}

impl Session {
    /// Builds the image from `root` and starts the app and marker service, or returns why it
    /// could not (no start script, build failure, app never listened). The caller turns an `Err`
    /// here into a skip reason for every drivable finding.
    #[cfg(test)]
    pub fn start(root: &std::path::Path) -> Result<Self, String> {
        Self::start_in(root, std::path::Path::new(""), None, &[], None)
    }

    /// Like [`Self::start`], but launches the package at `app` (relative to `root`, as chosen by
    /// [`app_dir`]) while the whole repo stays in the image, so the app can still import files
    /// outside its own directory. `entry_file` (relative to `root`) is the finding's own source
    /// file, used as the launch target when the app has no launchable manifest but the file is a
    /// self-contained server. `gating_sources` are the source texts of the sink's own module and the
    /// modules it imports: any external-service credential they read by name (a GitHub/API token the
    /// handler requires before it shells out) is reproduced as a configured deployment value so the
    /// sink's credential-gated branch is active (see [`credential_env`]). `launch`, an exec-form
    /// command (a JSON array), runs in place of the start command the manifest and the finding's
    /// file would give: how an MCP server that speaks only stdio is served, by the bridge that
    /// starts it (see [`super::stdio`]).
    pub fn start_in(
        root: &std::path::Path,
        app_path: &std::path::Path,
        entry_file: Option<&std::path::Path>,
        gating_sources: &[String],
        launch: Option<&str>,
    ) -> Result<Self, String> {
        if local_runtime_requested() {
            return Self::start_local(root, app_path, entry_file, gating_sources, launch);
        }
        let first = Self::start_on(root, app_path, entry_file, gating_sources, None, launch);
        let Err(err) = first else {
            return first;
        };
        let err = match Self::retry_with_start_script(
            root,
            app_path,
            entry_file,
            gating_sources,
            launch,
            &err,
        ) {
            Some(Ok(session)) => return Ok(session),
            Some(Err(message)) => message,
            None => err,
        };
        // An app written for an older Node (a native addon with no build for the current ABI, an API
        // since removed) installs or boots only on the runtime its repository pins. The default
        // runtime is tried first, so an app that already launches keeps launching exactly as before;
        // only a failed launch is retried, once, on the repository's own Node.
        let app_root = root.join(app_path);
        let install_root = root.join(install_path(root, app_path));
        let Some(image) = repo_node_fallback(root, &app_root, &install_root) else {
            return Err(err);
        };
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            eprintln!(
                "[verify] launch failed on the default Node; retrying on the repository's {image}"
            );
        }
        Self::start_on(
            root,
            app_path,
            entry_file,
            gating_sources,
            Some(&image),
            launch,
        )
        .map_err(|retry| {
            if retry == err {
                err
            } else {
                format!("{err}\n(on the repository's own {image} as well: {retry})")
            }
        })
    }

    /// After a failed launch of the finding's own file run in place (`node server/app.mjs`, chosen
    /// because the file constructs a listener and calls `.listen`), the project's own start script:
    /// the app package's, or the repository root's when the file's directory has no package. Such a
    /// file often only exports its server (the `listen` sits in a function the project's CLI calls,
    /// or it initializes state and returns), so it exits without listening while
    /// `"start": "node server/cli.mjs"` would serve it. `None` when no retry applies: a host shim
    /// launch (chosen because the manifest cannot serve the route), a manifest that would run the
    /// same command, or a front-end manifest (its dev server would answer on an unrelated port).
    /// The dependencies install in the same place, so the rebuild reuses the cached install layer.
    fn retry_with_start_script(
        root: &std::path::Path,
        app_path: &std::path::Path,
        entry_file: Option<&std::path::Path>,
        gating_sources: &[String],
        launch: Option<&str>,
        err: &str,
    ) -> Option<Result<Self, String>> {
        if launch.is_some() {
            return None;
        }
        let retry_path = start_script_retry(root, app_path, entry_file)?;
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            eprintln!(
                "[verify] launch of the finding's file failed; retrying with the start script of \
                 `{}`",
                if retry_path.as_os_str().is_empty() {
                    ".".to_owned()
                } else {
                    retry_path.display().to_string()
                }
            );
        }
        Some(
            Self::start_on(root, &retry_path, None, gating_sources, None, None).map_err(|retry| {
                if retry == err {
                    err.to_owned()
                } else {
                    format!("{err}\n(with the project's start script as well: {retry})")
                }
            }),
        )
    }

    /// One Docker launch of the app, on `node_image` when given (the repository's pinned runtime,
    /// see [`repo_node_fallback`]) or else the image [`base_image`] chooses.
    fn start_on(
        root: &std::path::Path,
        app_path: &std::path::Path,
        entry_file: Option<&std::path::Path>,
        gating_sources: &[String],
        node_image: Option<&str>,
        launch: Option<&str>,
    ) -> Result<Self, String> {
        let id = run_id();
        let canary = Canary::new(format!("{id}{}", short_rand()))
            .with_callback_host(configured_callback_host()?)
            .with_marker_host(Some(payload::MARKER_HOST.to_owned()));
        let tag = format!("jsspector-verify:{id}");
        let network = format!("jss-verify-net-{id}");
        let app = format!("jss-verify-app-{id}");
        let marker = format!("jss-verify-marker-{id}");
        let port = 3000;

        let app_root = root.join(app_path);
        let db = db_service(&app_root).then(|| format!("jss-verify-db-{id}"));
        let db_env = if db.is_some() {
            db_connection_env()
        } else {
            Vec::new()
        };
        let redis = redis_service(&app_root).then(|| format!("jss-verify-redis-{id}"));
        let redis_env = if redis.is_some() {
            redis_connection_env()
        } else {
            Vec::new()
        };
        // The SQL databases the app needs (its Compose file, else its drivers) and how it finds them.
        let services = super::services::plan(root, &app_root, db.is_some());
        let sql: Vec<(String, super::services::SqlSidecar)> = services
            .sql
            .iter()
            .enumerate()
            .map(|(index, sidecar)| (format!("jss-verify-sql{index}-{id}"), sidecar.clone()))
            .collect();
        let mongo_aliases = services.mongo_aliases.clone();
        let mongo_image = services.mongo_image.clone();
        let service_env = services.app_env.clone();
        let entry_rel = entry_file.and_then(|file| file.strip_prefix(app_path).ok());
        let start_command = match launch {
            Some(command) => command.to_owned(),
            None => start_command(&app_root, entry_rel)
                .ok_or_else(|| "no launchable script or `main` file in package.json".to_owned())?,
        };
        let workdir = container_dir(app_path)
            .ok_or_else(|| format!("unsupported app directory `{}`", app_path.display()))?;
        // Install dependencies where they are declared: the nearest manifest ancestor of the launch
        // directory. A standalone server launched from a manifest-less subdirectory draws its
        // dependencies from an ancestor package, so installing in the launch directory alone would
        // leave `require(...)` unresolved.
        let mut install_rel = install_path(root, app_path);
        // A shared route/server module whose own tree declares none of the packages it imports draws
        // its dependencies from a sibling application package that bundles it at build time (an
        // Electron desktop app, an embedded mobile backend) rather than from an ancestor manifest.
        // Install from that package and expose its `node_modules` through NODE_PATH — the same
        // resolution the real app wires up for its bundled code — or `require(...)` in the mounted
        // module stays unresolved and the app exits before it listens.
        let node_path = entry_file
            .and_then(|module| dependency_provider(root, &install_rel, module))
            .and_then(|provider| {
                let modules = format!("{}/node_modules", container_dir(&provider)?);
                install_rel = provider;
                Some(modules)
            });
        let install_root = root.join(&install_rel);
        let install_workdir = container_dir(&install_rel)
            .ok_or_else(|| format!("unsupported install directory `{}`", install_rel.display()))?;

        let build_env: Vec<(String, String)> = db_env
            .iter()
            .chain(redis_env.iter())
            .chain(service_env.iter())
            .cloned()
            .collect();
        // The same build step `build_image` bakes into the image, kept so a source change copied
        // into the running container can be built again before the app restarts.
        let rebuild = (!start_command.contains("/jss-azure-func-host")
            && !start_command.contains("/jss-worker-host"))
        .then(|| {
            std::fs::read_to_string(app_root.join("package.json"))
                .ok()
                .and_then(|manifest| build_script(&manifest, &app_root))
        })
        .flatten()
        .map(|script| {
            (
                workdir.clone(),
                build_command(package_manager(&install_root), script),
            )
        });
        build_image(
            root,
            &app_root,
            &install_root,
            &install_workdir,
            &workdir,
            &tag,
            &canary,
            &start_command,
            port,
            &build_env,
            node_image,
        )?;

        // An internal network: DNS between its members, no route to the internet.
        docker(&["network", "create", "--internal", &network])
            .map_err(|e| format!("could not create the private network: {e}"))?;

        // An app that drops root at startup needs a matching runtime user and the uid/gid/port
        // variables its deployment supplies; discover them from its own source so the privilege drop
        // runs honestly in the sandbox instead of crashing on an unset/undroppable id.
        let (run_as, mut base_env) = match privilege_drop_fixture(&app_root, port) {
            Some(fixture) => (Some(fixture.run_as), fixture.env),
            None => (None, Vec::new()),
        };
        if let Some(profile) = repository_verification_env(&app_root) {
            base_env.push(profile);
        }
        // A sink reached only when the deployment has configured an external-service credential (a
        // GitHub/API token the handler requires before it shells out) is a configuration precondition,
        // not input neutralization: reproduce it honestly by setting that credential to a strong
        // random filler, so the credential-gated branch is live. A random value can only enable a
        // "credential configured" path, never match a real secret or relax an authentication check.
        for cred in credential_env(gating_sources) {
            if base_env.iter().all(|existing| existing.name != cred.name) {
                base_env.push(cred);
            }
        }
        for cfg in config_source_env(gating_sources) {
            if base_env.iter().all(|existing| existing.name != cfg.name) {
                base_env.push(cfg);
            }
        }
        let guarded_modules = guarded_modules(root, entry_file, gating_sources);
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            eprintln!(
                "[verify] launch plan app={} command={} env={:?} guarded-modules={guarded_modules:?}",
                app_path.display(),
                start_command,
                base_env
                    .iter()
                    .map(|item| (&item.name, &item.value))
                    .collect::<Vec<_>>()
            );
        }

        let mongo_databases = if db.is_some() {
            mongo_database_names(&app_root)
        } else {
            Default::default()
        };
        let mut session = Self {
            runtime: Runtime::Docker,
            tag,
            network,
            app,
            marker,
            db,
            db_env,
            redis,
            redis_env,
            sql,
            mongo_aliases,
            mongo_image,
            mongo_databases,
            mongo_shell: std::cell::Cell::new(None),
            service_env,
            canary,
            port,
            nonce: 0,
            run_as,
            base_env,
            node_path,
            node_sqlite: uses_node_sqlite(root, &app_root),
            electron_main: entry_file
                .is_some_and(|entry| is_electron_main_process(&root.join(entry))),
            omit_forwarding: std::cell::Cell::new(false),
            root: root.to_path_buf(),
            guarded_modules,
            start_command: start_command.clone(),
            tls: false,
            rebuild,
            typescript: typescript_build(&app_root).map(|no_emit_on_error| TypescriptBuild {
                workdir: workdir.clone(),
                no_emit_on_error,
            }),
            local_launch: None,
            overwritten: Vec::new(),
            local_marker_port: None,
            local_baseline_ports: Vec::new(),
            unavailable_services: Vec::new(),
            service_path: None,
            torn_down: false,
            xss_browser: None,
            socket_unacked: RefCell::new(std::collections::BTreeSet::new()),
            mcp_discovery: RefCell::new(std::collections::BTreeMap::new()),
            mcp_endpoint: RefCell::new(None),
            mcp_resolved: RefCell::new(None),
            attempt_budget: std::cell::Cell::new(None),
            sink_binding: None,
            last_sink_hit: std::cell::Cell::new(false),
            proof_sink_hit: std::cell::Cell::new(false),
            unbound_effect: std::cell::Cell::new(false),
            last_verified_attempt: RefCell::new(None),
            probe_setup: RefCell::new(Vec::new()),
            driver_errors: RefCell::new(Vec::new()),
            driver_successes: std::cell::Cell::new(0),
            mcp_calls: RefCell::new(McpCalls::default()),
            stdio_bridge: launch.is_some_and(is_bridge_command),
            mcp_stdio: RefCell::new(None),
        };
        if let Err(err) = session.boot() {
            session.teardown();
            return Err(err);
        }
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            eprintln!(
                "[verify] launched app={} command={} port={} logs[{}]",
                app_path.display(),
                start_command,
                session.port,
                session.tail_logs(&session.app)
            );
        }
        Ok(session)
    }

    fn start_local(
        root: &std::path::Path,
        app_path: &std::path::Path,
        entry_file: Option<&std::path::Path>,
        gating_sources: &[String],
        launch: Option<&str>,
    ) -> Result<Self, String> {
        let id = run_id();
        let callback_host = configured_callback_host()?;
        let local_marker_port = Some(available_local_port()?);
        // Use the canonical hexadecimal spelling of loopback for the URL driven through the
        // application. Node resolves it to 127.0.0.1, while a verifier still exercises handlers
        // that reject only the literal `127.*` hostname before making the request. The marker
        // remains bound exclusively to loopback, so this never sends verification traffic outside
        // the disposable sandbox.
        let marker_host = local_marker_port.map(|port| format!("0x7f000001:{port}"));
        let canary = Canary::new(format!("{id}{}", short_rand()))
            .with_callback_host(callback_host)
            .with_marker_host(marker_host);
        let app_root = root.join(app_path);
        let app_needs_db = db_service(&app_root);
        let mongo_installed = command_available("mongod") && command_available("mongosh");
        let ephemeral_db_command = (!mongo_installed)
            .then(|| local_ephemeral_mongo_next_launch(&app_root))
            .flatten();
        let manages_ephemeral_db = app_needs_db && ephemeral_db_command.is_some();
        // A backing service the app needs but the host lacks is provisioned now, for this app only:
        // a repository without a database client never pays for one. A service that cannot be
        // provisioned leaves the app launchable without it, and is recorded so a negative result
        // is not reported as `not-reproduced` (see [`qualify_reduced_environment`]).
        let mut unavailable_services: Vec<String> = Vec::new();
        let mut service_tools: Vec<std::path::PathBuf> = Vec::new();
        let has_local_mongo = mongo_installed
            || (app_needs_db
                && !manages_ephemeral_db
                && match provision_local_mongo() {
                    Ok(bin) => {
                        service_tools.push(bin);
                        true
                    }
                    Err(error) => {
                        eprintln!("jsspector: MongoDB could not be provisioned: {error}");
                        unavailable_services.push(
                            "MongoDB (`mongod` is not installed and could not be provisioned, so \
                             the app ran without a database)"
                                .to_owned(),
                        );
                        false
                    }
                });
        let needs_db = app_needs_db && !manages_ephemeral_db && has_local_mongo;
        let declares_redis = redis_service(&app_root);
        let redis_available = declares_redis
            && (command_available("redis-server")
                || match provision_local_redis() {
                    Ok(bin) => {
                        service_tools.push(bin);
                        true
                    }
                    Err(error) => {
                        eprintln!("jsspector: Redis could not be provisioned: {error}");
                        false
                    }
                });
        let (needs_redis, missing_redis) = local_redis_plan(declares_redis, redis_available);
        unavailable_services.extend(missing_redis);
        let service_path = (!service_tools.is_empty()).then(|| path_with_tool_dirs(&service_tools));
        let entry_rel = entry_file.and_then(|file| file.strip_prefix(app_path).ok());
        // Install and build before choosing the launch command. A package whose start script names
        // generated output (`node dist/index.js`) must be evaluated after its `compile`/`build`
        // script has had a chance to create that output; otherwise a fresh checkout incorrectly
        // falls back to hosting one router module while a previously prepared checkout runs the real
        // application.
        let mut install_rel = install_path(root, app_path);
        let node_path = entry_file
            .and_then(|module| dependency_provider(root, &install_rel, module))
            .map(|provider| {
                install_rel = provider.clone();
                root.join(provider)
                    .join("node_modules")
                    .display()
                    .to_string()
            });
        let install_root = root.join(&install_rel);
        // A package written for Bun runs its own startup and scripts with Bun; provide that runtime
        // before installing, so its build and launch scripts execute as the project intends.
        let tool_dir = match provision_local_bun(&app_root)? {
            Some(dir) => Some(dir),
            None if install_root != app_root => provision_local_bun(&install_root)?,
            None => None,
        };
        let home_dir = std::env::temp_dir().join(format!("jsspector-home-{id}"));
        prepare_local_app(root, &install_root, tool_dir.as_deref(), &home_dir)?;
        // The same build step `prepare_local_app` ran, kept so a changed source file can be built
        // again before the app is relaunched with it.
        let local_rebuild = std::fs::read_to_string(install_root.join("package.json"))
            .ok()
            .and_then(|manifest| build_script(&manifest, &install_root))
            .map(|script| {
                (
                    install_root.display().to_string(),
                    build_command(package_manager(&install_root), script),
                )
            });
        let local_typescript =
            typescript_build(&app_root).map(|no_emit_on_error| TypescriptBuild {
                workdir: app_root.display().to_string(),
                no_emit_on_error,
            });
        // An install may have to fall back to `--ignore-scripts` when an unrelated lifecycle step
        // fails (for example a frontend build), leaving the backend `start` target absent. If this
        // package itself declares that its start target is TypeScript output, compile that output
        // directly with its own local compiler. Accept a nonzero compiler exit only when it emitted
        // the exact target anyway, matching TypeScript's `noEmitOnError: false` behavior.
        if local_typescript.is_some() && missing_node_start_target(&app_root) {
            let compiled = run_local_setup(&app_root, TSC_COMMAND, tool_dir.as_deref(), &home_dir);
            if missing_node_start_target(&app_root) {
                compiled?;
                return Err(
                    "the TypeScript build completed without creating the declared start target"
                        .to_owned(),
                );
            }
        }
        let start_command = if let Some(command) = launch {
            command.to_owned()
        } else if let Some(command) = ephemeral_db_command {
            command
        } else if app_needs_db
            && !has_local_mongo
            && let Some(file) = entry_rel
                .and_then(|path| path.to_str())
                .and_then(|path| package_file(&app_root, path))
            && is_express_factory_module(&app_root.join(&file))
        {
            // Some applications make their production bootstrap wait for MongoDB before opening
            // the HTTP listener, even though the route under test is independent of the database.
            // Mount an exported Express factory through the existing host in that situation. This
            // executes the application's real middleware, route and sink without inventing a DB or
            // changing repository code.
            express_host_command(&file)
        } else {
            start_command(&app_root, entry_rel)
                .ok_or_else(|| "no launchable script or `main` file in package.json".to_owned())?
        };
        let mut local_command: Vec<String> = serde_json::from_str(&start_command)
            .map_err(|error| format!("invalid generated start command: {error}"))?;
        if local_command.is_empty() {
            return Err("generated start command is empty".to_owned());
        }
        for argument in &mut local_command {
            *argument = localize_helper_paths(argument);
        }
        let fixture_lock = acquire_local_fixture_lock()?;
        let created_files = plant_local_files(&canary)?;
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            eprintln!(
                "[verify] local fixtures planted count={} canary={} exists={}",
                created_files.len(),
                canary.planted_file(),
                std::path::Path::new(&canary.planted_file()).is_file(),
            );
        }
        let log = std::env::temp_dir().join(format!("jsspector-verify-{id}.log"));
        let marker_log = std::env::temp_dir().join(format!("jsspector-marker-{id}.log"));
        let mut service_dirs = Vec::new();
        if needs_db {
            service_dirs.push(std::env::temp_dir().join(format!("jsspector-mongo-{id}")));
        }
        if needs_redis {
            service_dirs.push(std::env::temp_dir().join(format!("jsspector-redis-{id}")));
        }
        service_dirs.push(home_dir.clone());
        // Every local launch receives a private free port through `PORT`. Applications that hard-code
        // their listener are still discovered by the readiness probe, while platform-host shims and
        // ordinary `process.env.PORT` servers cannot collide with an orphan from an interrupted scan.
        let port = available_local_port()?;
        let (run_as, mut base_env) = match local_privilege_drop_fixture(&app_root, port) {
            Some(fixture) => (Some(fixture.run_as), fixture.env),
            None => (None, Vec::new()),
        };
        if let Some(profile) = repository_verification_env(&app_root) {
            base_env.push(profile);
        }
        for cred in credential_env(gating_sources) {
            if base_env.iter().all(|existing| existing.name != cred.name) {
                base_env.push(cred);
            }
        }
        for cfg in config_source_env(gating_sources) {
            if base_env.iter().all(|existing| existing.name != cfg.name) {
                base_env.push(cfg);
            }
        }
        let guarded_modules = guarded_modules(root, entry_file, gating_sources);
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            eprintln!(
                "[verify] local launch plan app={} command={} env={:?} db={} redis={} guarded-modules={guarded_modules:?}",
                app_path.display(),
                start_command,
                base_env
                    .iter()
                    .map(|item| (&item.name, &item.value))
                    .collect::<Vec<_>>(),
                needs_db,
                needs_redis,
            );
        }
        let mut session = Self {
            runtime: Runtime::Local {
                checkout_root: Box::new(root.to_path_buf()),
                app_root,
                install_root: Box::new(install_root),
                log,
                command: local_command,
                process: Box::new(RefCell::new(None)),
                services: Box::new(RefCell::new(Vec::new())),
                service_dirs,
                marker_log,
                created_files,
                home_dir: Box::new(home_dir),
                tool_dir: Box::new(tool_dir),
                _fixture_lock: fixture_lock,
            },
            tag: String::new(),
            network: String::new(),
            app: format!("jss-local-app-{id}"),
            marker: String::new(),
            db: needs_db.then(|| "local-mongo".to_owned()),
            db_env: needs_db.then(local_db_connection_env).unwrap_or_default(),
            redis: needs_redis.then(|| "local-redis".to_owned()),
            redis_env: needs_redis
                .then(local_redis_connection_env)
                .unwrap_or_default(),
            sql: Vec::new(),
            mongo_aliases: Vec::new(),
            mongo_image: None,
            mongo_databases: if needs_db {
                mongo_database_names(&root.join(app_path))
            } else {
                Default::default()
            },
            mongo_shell: std::cell::Cell::new(None),
            service_env: Vec::new(),
            canary,
            port,
            nonce: 0,
            run_as,
            base_env,
            node_path,
            node_sqlite: uses_node_sqlite(root, &root.join(app_path)),
            electron_main: entry_file
                .is_some_and(|entry| is_electron_main_process(&root.join(entry))),
            omit_forwarding: std::cell::Cell::new(false),
            root: root.to_path_buf(),
            guarded_modules,
            start_command: start_command.clone(),
            tls: false,
            rebuild: local_rebuild,
            typescript: local_typescript,
            local_launch: None,
            overwritten: Vec::new(),
            local_marker_port,
            local_baseline_ports: Vec::new(),
            unavailable_services,
            service_path,
            torn_down: false,
            xss_browser: None,
            socket_unacked: RefCell::new(std::collections::BTreeSet::new()),
            mcp_discovery: RefCell::new(std::collections::BTreeMap::new()),
            mcp_endpoint: RefCell::new(None),
            mcp_resolved: RefCell::new(None),
            attempt_budget: std::cell::Cell::new(None),
            sink_binding: None,
            last_sink_hit: std::cell::Cell::new(false),
            proof_sink_hit: std::cell::Cell::new(false),
            unbound_effect: std::cell::Cell::new(false),
            last_verified_attempt: RefCell::new(None),
            probe_setup: RefCell::new(Vec::new()),
            driver_errors: RefCell::new(Vec::new()),
            driver_successes: std::cell::Cell::new(0),
            mcp_calls: RefCell::new(McpCalls::default()),
            stdio_bridge: launch.is_some_and(is_bridge_command),
            mcp_stdio: RefCell::new(None),
        };
        session.start_local_services()?;
        session.local_baseline_ports = local_listening_ports();
        session
            .boot_local()
            .map_err(|error| note_unavailable_services(error, &session.unavailable_services))?;
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            eprintln!(
                "[verify] local launched app={} command={} port={} logs[{}]",
                app_path.display(),
                start_command,
                session.port,
                session.tail_logs(&session.app)
            );
        }
        Ok(session)
    }

    fn start_local_services(&self) -> Result<(), String> {
        let Runtime::Local {
            services,
            service_dirs,
            marker_log,
            home_dir,
            ..
        } = &self.runtime
        else {
            return Err("local sidecars requested for a Docker session".to_owned());
        };
        if let Some(port) = self.local_marker_port {
            let log = std::fs::File::create(marker_log)
                .map_err(|error| format!("creating local marker log: {error}"))?;
            let stderr = log
                .try_clone()
                .map_err(|error| format!("opening local marker log: {error}"))?;
            let mut command = Command::new("node");
            isolate_local_command(&mut command, home_dir, None)?;
            let mut marker = command
                .arg("/tmp/jss-marker.js")
                .env("JSS_MARKER_PORT", port.to_string())
                .stdout(log)
                .stderr(stderr)
                .spawn()
                .map_err(|error| format!("starting local marker service: {error}"))?;
            wait_local_service(&mut marker, port, "marker")?;
            services.borrow_mut().push(marker);
        }
        let mut directory = service_dirs.iter();
        if self.db.is_some() {
            let dir = directory
                .next()
                .ok_or_else(|| "missing local MongoDB directory".to_owned())?;
            std::fs::create_dir_all(dir)
                .map_err(|error| format!("creating local MongoDB directory: {error}"))?;
            let log = std::fs::File::create(dir.join("mongod.log"))
                .map_err(|error| format!("creating local MongoDB log: {error}"))?;
            let stderr = log
                .try_clone()
                .map_err(|error| format!("opening local MongoDB log: {error}"))?;
            let mut command = Command::new("mongod");
            isolate_local_command(&mut command, home_dir, None)?;
            if let Some(path) = &self.service_path {
                command.env("PATH", path);
            }
            let mut child = command
                .args([
                    "--bind_ip",
                    "127.0.0.1",
                    "--port",
                    "27017",
                    "--nounixsocket",
                    "--quiet",
                ])
                .arg("--dbpath")
                .arg(dir)
                .stdout(log)
                .stderr(stderr)
                .spawn()
                .map_err(|error| format!("starting local MongoDB: {error}"))?;
            wait_local_service(&mut child, 27017, "MongoDB")?;
            services.borrow_mut().push(child);
        }
        if self.redis.is_some() {
            let dir = directory
                .next()
                .ok_or_else(|| "missing local Redis directory".to_owned())?;
            std::fs::create_dir_all(dir)
                .map_err(|error| format!("creating local Redis directory: {error}"))?;
            let log = std::fs::File::create(dir.join("redis.log"))
                .map_err(|error| format!("creating local Redis log: {error}"))?;
            let stderr = log
                .try_clone()
                .map_err(|error| format!("opening local Redis log: {error}"))?;
            let mut command = Command::new("redis-server");
            isolate_local_command(&mut command, home_dir, None)?;
            if let Some(path) = &self.service_path {
                command.env("PATH", path);
            }
            let mut child = command
                .args([
                    "--bind",
                    "127.0.0.1",
                    "--port",
                    "6379",
                    "--save",
                    "",
                    "--appendonly",
                    "no",
                ])
                .arg("--dir")
                .arg(dir)
                .stdout(log)
                .stderr(stderr)
                .spawn()
                .map_err(|error| format!("starting local Redis: {error}"))?;
            wait_local_service(&mut child, 6379, "Redis")?;
            services.borrow_mut().push(child);
        }
        Ok(())
    }

    fn boot_local(&mut self) -> Result<(), String> {
        let mut env = self.base_env.clone();
        let mut stub_missing_modules = false;
        let mut mongodb_callback_promises = false;
        let mut scratch_dirs = Vec::new();
        let mut cert_files: Vec<String> = Vec::new();
        let mut cred_files: Vec<String> = Vec::new();
        let mut dotenv_files: Vec<String> = Vec::new();
        let mut config_files: Vec<ConfigStage> = Vec::new();
        let mut generated_config_retry = false;
        let mut next_development_retry = false;
        let mut rebuilt_native_packages = std::collections::BTreeSet::new();
        for attempt in 1..=5 {
            self.run_local_app(
                &env,
                stub_missing_modules,
                mongodb_callback_promises,
                next_development_retry,
                &scratch_dirs,
            )?;
            let err = match self.wait_until_listening() {
                Ok(port) => {
                    self.port = port;
                    restore_local_read_canaries(&self.canary)?;
                    self.seed_db();
                    self.local_launch = Some(LocalLaunch {
                        env: env.clone(),
                        stub_missing_modules,
                        mongodb_callback_promises,
                        next_development: next_development_retry,
                        scratch_dirs: scratch_dirs.clone(),
                    });
                    return Ok(());
                }
                Err(error) => error,
            };
            let mut missing = Vec::new();
            for wanted in required_env(&err)
                .into_iter()
                .chain(config_env(&err, &self.root))
            {
                if env.iter().all(|have| have.name != wanted.name)
                    && missing
                        .iter()
                        .all(|have: &RequiredEnv| have.name != wanted.name)
                {
                    missing.push(wanted);
                }
            }
            let enable_module_stub = !stub_missing_modules && missing_bare_module(&err);
            let enable_mongodb_callback_promises =
                !mongodb_callback_promises && missing_mongodb_collection_promise(&err);
            let new_dir = missing_write_dir(&err).filter(|dir| !scratch_dirs.contains(dir));
            let new_cert = missing_tls_material(&err)
                .filter(|(path, _)| !cert_files.iter().any(|have| have == path));
            let new_dotenv = missing_dotenv_file(&err)
                .filter(|path| !dotenv_files.iter().any(|have| have == path));
            let new_cred = missing_service_account_json(&err, &self.root)
                .filter(|path| !cred_files.iter().any(|have| have == path));
            let new_config = missing_config_file_local(&err)
                .filter(|stage| config_files.iter().all(|have| have.target != stage.target));
            let retry_generated_config = !generated_config_retry && generated_startup_config(&err);
            let next_development_available = match &self.runtime {
                Runtime::Local { app_root, .. } => {
                    next_development_command(app_root, self.port).is_some()
                }
                Runtime::Docker => false,
            };
            let retry_next_development = !next_development_retry
                && missing_next_production_build(&err)
                && next_development_available;
            let rebuild_native_package = missing_native_package(&err).filter(|package| {
                !rebuilt_native_packages.contains(package)
                    && matches!(&self.runtime, Runtime::Local { .. })
            });
            if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
                eprintln!(
                    "[verify] local startup attempt {attempt} failed; retry mongodb-collections={} module-stub={} generated-config={} next-dev={} native-package={:?}",
                    enable_mongodb_callback_promises,
                    enable_module_stub,
                    retry_generated_config,
                    retry_next_development,
                    rebuild_native_package,
                );
            }
            if missing.is_empty()
                && !enable_module_stub
                && !enable_mongodb_callback_promises
                && new_dir.is_none()
                && new_cert.is_none()
                && new_cred.is_none()
                && new_dotenv.is_none()
                && new_config.is_none()
                && !retry_generated_config
                && !retry_next_development
                && rebuild_native_package.is_none()
            {
                return Err(err);
            }
            if let Some(package) = rebuild_native_package {
                let Runtime::Local {
                    install_root,
                    tool_dir,
                    home_dir,
                    ..
                } = &self.runtime
                else {
                    unreachable!("native rebuild is local-only")
                };
                rebuild_local_native_package(
                    install_root,
                    &package,
                    tool_dir.as_deref(),
                    home_dir,
                )?;
                rebuilt_native_packages.insert(package);
            }
            env.extend(missing);
            stub_missing_modules |= enable_module_stub;
            mongodb_callback_promises |= enable_mongodb_callback_promises;
            generated_config_retry |= retry_generated_config;
            next_development_retry |= retry_next_development;
            if let Some(dir) = new_dir {
                scratch_dirs.push(dir);
            }
            if let Some((path, is_key)) = new_cert {
                self.stage_local_tls_file(&path, is_key)?;
                cert_files.push(path);
                self.tls = true;
            }
            if let Some(path) = new_dotenv {
                self.stage_local_dotenv_file(&path)?;
                dotenv_files.push(path);
            }
            if let Some(path) = new_cred {
                self.stage_local_checkout_file(
                    &path,
                    SERVICE_ACCOUNT_JSON.as_bytes(),
                    "service-account credential",
                )?;
                cred_files.push(path);
            }
            if let Some(config) = new_config {
                self.stage_local_config_file(&config)?;
                config_files.push(config);
            }
        }
        Err("the app still could not start after five launch attempts".to_owned())
    }

    /// Copies the deployment's own committed config template to the path its loader read, inside the
    /// disposable local checkout (see [`missing_config_file_local`]). Reproduces the first-run step a
    /// deployment's entrypoint performs; never invents configuration, and never overwrites a config
    /// the checkout already shipped.
    fn stage_local_config_file(&mut self, config: &ConfigStage) -> Result<(), String> {
        if std::path::Path::new(&config.target).exists() {
            return Ok(());
        }
        let contents = std::fs::read(&config.template)
            .map_err(|error| format!("reading config template {}: {error}", config.template))?;
        self.stage_local_checkout_file(&config.target, &contents, "runtime configuration")
    }

    /// Stages the verifier's throwaway matching TLS pair only at a path inside the disposable local
    /// checkout. This mirrors the container retry without ever writing elsewhere on the host.
    fn stage_local_tls_file(&mut self, path: &str, is_key: bool) -> Result<(), String> {
        let contents = if is_key { MARKER_KEY } else { MARKER_CERT };
        self.stage_local_checkout_file(path, contents.as_bytes(), "TLS material")
    }

    /// Uses the repository's documented dotenv template when present; otherwise an empty dotenv
    /// file lets loaders proceed with their normal defaults without inventing configuration.
    fn stage_local_dotenv_file(&mut self, path: &str) -> Result<(), String> {
        let target = std::path::Path::new(path);
        let parent = target
            .parent()
            .ok_or_else(|| format!("dotenv path has no parent: {path}"))?;
        let contents = [".env.example", ".env.sample", ".env.template"]
            .iter()
            .map(|name| parent.join(name))
            .find_map(|candidate| std::fs::read(candidate).ok())
            .unwrap_or_default();
        self.stage_local_checkout_file(path, &contents, "dotenv")
    }

    /// Writes a startup fixture only inside the disposable checkout and records it for teardown.
    fn stage_local_checkout_file(
        &mut self,
        path: &str,
        contents: &[u8],
        kind: &str,
    ) -> Result<(), String> {
        let Runtime::Local {
            checkout_root,
            created_files,
            ..
        } = &mut self.runtime
        else {
            return Err("local startup-file staging requested for a Docker session".to_owned());
        };
        let root = checkout_root
            .canonicalize()
            .map_err(|error| format!("resolving local checkout root: {error}"))?;
        let target = std::path::PathBuf::from(path);
        let parent = target
            .parent()
            .ok_or_else(|| format!("startup-file path has no parent: {path}"))?
            .canonicalize()
            .map_err(|error| format!("resolving TLS parent for {path}: {error}"))?;
        if !parent.starts_with(&root) {
            return Err(format!(
                "refusing to stage {kind} outside the local checkout: {path}"
            ));
        }
        std::fs::write(&target, contents)
            .map_err(|error| format!("staging local {kind} at {path}: {error}"))?;
        created_files.push(target);
        Ok(())
    }

    fn run_local_app(
        &self,
        env: &[RequiredEnv],
        stub_missing_modules: bool,
        mongodb_callback_promises: bool,
        next_development: bool,
        scratch_dirs: &[String],
    ) -> Result<(), String> {
        let Runtime::Local {
            checkout_root,
            app_root,
            log,
            command,
            process,
            tool_dir,
            home_dir,
            ..
        } = &self.runtime
        else {
            return Err("local application requested for a Docker session".to_owned());
        };
        if let Some(mut previous) = process.borrow_mut().take() {
            stop_local_process(&mut previous);
        }
        for var in env {
            if var.directory {
                let value = localize_helper_paths(&var.value);
                std::fs::create_dir_all(&value)
                    .map_err(|error| format!("creating {value}: {error}"))?;
            }
        }
        for dir in scratch_dirs {
            let dir = localize_helper_paths(dir);
            std::fs::create_dir_all(&dir).map_err(|error| format!("creating {dir}: {error}"))?;
        }
        let config_home = home_dir.join(".config");
        let data_home = home_dir.join(".local/share");
        let cache_home = home_dir.join(".cache");
        for directory in [
            home_dir.as_path(),
            config_home.as_path(),
            data_home.as_path(),
            cache_home.as_path(),
        ] {
            std::fs::create_dir_all(directory).map_err(|error| {
                format!(
                    "creating private verifier home {}: {error}",
                    directory.display()
                )
            })?;
        }
        if self.run_as.is_some() {
            Self::make_local_run_as_accessible(
                checkout_root.as_path(),
                app_root,
                env,
                scratch_dirs,
                home_dir.as_path(),
            )?;
        }
        let stdout = std::fs::File::create(log)
            .map_err(|error| format!("creating local verifier log: {error}"))?;
        let stderr = stdout
            .try_clone()
            .map_err(|error| format!("opening local verifier log: {error}"))?;
        let next_command = next_development
            .then(|| next_development_command(app_root, self.port))
            .flatten();
        let command = next_command.as_ref().unwrap_or(command);
        let (program, args) = command
            .split_first()
            .ok_or_else(|| "generated start command is empty".to_owned())?;
        let mut child = Command::new(program);
        isolate_local_command(&mut child, home_dir, tool_dir.as_deref())?;
        // Package-manager launchers (`npm start`, `yarn …`) keep the application as a child
        // process. Give every launch its own process group so teardown removes that child too;
        // otherwise it can keep the HTTP port and the next finding is accidentally tested against
        // the preceding repository/service.
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            child.process_group(0);
            if let Some((uid, gid)) = self.run_as {
                let current = current_unix_identity().ok_or_else(|| {
                    "local verification could not determine its runtime user".to_owned()
                })?;
                if current == (0, 0) {
                    child.gid(gid).uid(uid);
                } else if current != (uid, gid) {
                    return Err(format!(
                        "local verification cannot run the application as uid {uid}, gid {gid}"
                    ));
                }
            }
        }
        child
            .args(args)
            .current_dir(app_root)
            .env("PORT", self.port.to_string())
            .env("HOST", "127.0.0.1")
            .env("NODE_ENV", "development")
            .env("HOME", home_dir.as_path())
            .env("XDG_CONFIG_HOME", config_home)
            .env("XDG_DATA_HOME", data_home)
            .env("XDG_CACHE_HOME", cache_home)
            .stdout(stdout)
            .stderr(stderr);
        if let Some(node_path) = &self.node_path {
            child.env("NODE_PATH", node_path);
        }
        let mut node_options = vec!["--require=/tmp/jss-sink-binding.js"];
        if self.node_sqlite {
            node_options.push("--experimental-sqlite");
        }
        if stub_missing_modules || mongodb_callback_promises {
            node_options.push("--require=/tmp/jss-launch-shim.js");
        }
        if self.electron_main {
            node_options.push("--require=/tmp/jss-electron-shim.js");
        }
        if stub_missing_modules && !self.guarded_modules.is_empty() {
            child.env("JSS_GUARDED_MODULES", self.guarded_modules.join(","));
        }
        if mongodb_callback_promises {
            child.env("JSS_MONGODB_CALLBACK_PROMISES", "1");
        }
        if !node_options.is_empty() {
            child.env("NODE_OPTIONS", node_options.join(" "));
        }
        for var in env {
            child.env(&var.name, localize_helper_paths(&var.value));
        }
        for (name, value) in self.db_env.iter().chain(&self.redis_env) {
            child.env(name, value);
        }
        let child = child
            .spawn()
            .map_err(|error| format!("starting local application: {error}"))?;
        process.replace(Some(child));
        Ok(())
    }

    /// A root-owned `mktemp -d` checkout is mode 0700, so an application deliberately launched as
    /// an unprivileged uid cannot even traverse to its entry file. Add read/traverse permission only
    /// to the disposable checkout chain and make verifier-created runtime directories writable. The
    /// application still runs without privileges and receives no access outside those fixtures.
    #[cfg(unix)]
    fn make_local_run_as_accessible(
        checkout_root: &std::path::Path,
        app_root: &std::path::Path,
        env: &[RequiredEnv],
        scratch_dirs: &[String],
        home_dir: &std::path::Path,
    ) -> Result<(), String> {
        use std::os::unix::fs::PermissionsExt;

        let boundary = checkout_root.parent().unwrap_or(checkout_root);
        let mut directories = app_root
            .ancestors()
            .take_while(|path| path.starts_with(boundary))
            .map(std::path::Path::to_path_buf)
            .collect::<Vec<_>>();
        directories.push(boundary.to_path_buf());
        directories.sort();
        directories.dedup();
        for directory in directories {
            let metadata = std::fs::metadata(&directory)
                .map_err(|error| format!("reading {} permissions: {error}", directory.display()))?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(permissions.mode() | 0o055);
            std::fs::set_permissions(&directory, permissions).map_err(|error| {
                format!("opening {} to the app uid: {error}", directory.display())
            })?;
        }
        for directory in env
            .iter()
            .filter(|var| var.directory)
            .map(|var| localize_helper_paths(&var.value))
            .chain(scratch_dirs.iter().map(|dir| localize_helper_paths(dir)))
            .chain(std::iter::once(home_dir.display().to_string()))
        {
            let metadata = std::fs::metadata(&directory)
                .map_err(|error| format!("reading {directory} permissions: {error}"))?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(permissions.mode() | 0o777);
            std::fs::set_permissions(&directory, permissions)
                .map_err(|error| format!("making {directory} writable to the app uid: {error}"))?;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn make_local_run_as_accessible(
        _checkout_root: &std::path::Path,
        _app_root: &std::path::Path,
        _env: &[RequiredEnv],
        _scratch_dirs: &[String],
        _home_dir: &std::path::Path,
    ) -> Result<(), String> {
        Ok(())
    }

    /// Starts the marker service and the app, and waits for the app to listen.
    fn boot(&mut self) -> Result<(), String> {
        // The marker service: records every path it is asked for. Reached only from inside the
        // private network, as `jss-marker`.
        let mut marker_args = vec![
            "run".to_owned(),
            "-d".to_owned(),
            "--name".to_owned(),
            self.marker.clone(),
            "--network".to_owned(),
            self.network.clone(),
            "--network-alias".to_owned(),
            "jss-marker".to_owned(),
        ];
        if let Some(host) = self.canary.callback_host() {
            marker_args.extend(["--network-alias".to_owned(), host.to_owned()]);
        }
        marker_args.extend([
            "--entrypoint".to_owned(),
            "node".to_owned(),
            self.tag.clone(),
            "/jss-marker.js".to_owned(),
        ]);
        let marker_args: Vec<&str> = marker_args.iter().map(String::as_str).collect();
        docker(&marker_args).map_err(|e| format!("could not start the marker service: {e}"))?;

        if self.db.is_some() {
            self.start_db()?;
            // Load the app's own shipped database seed (a `mongodump` in the repo) before launch, so
            // its startup initialization finds the configuration it reads out of its own collections.
            self.restore_db_dump();
        }
        if self.redis.is_some() {
            self.start_redis()?;
        }
        self.start_sql()?;

        // An app that refuses to start without an environment variable its deployment supplies
        // (`NOOBOT_WORKSPACE_ROOT is required`) is started again with it set to a neutral value
        // (see [`required_env`]), a few times at most.
        let mut env: Vec<RequiredEnv> = self.base_env.clone();
        let mut stub_missing_modules = false;
        let mut mongodb_callback_promises = false;
        // Directories the app tried to write into on startup before their parent existed
        // (see [`missing_write_dir`]); mounted as empty writable scratch on the next attempt.
        let mut scratch_dirs: Vec<String> = Vec::new();
        // TLS key/cert files the app reads to stand up an `https`/`tls` server before it listens
        // (see [`missing_tls_material`]); staged from the self-signed marker pair on the next
        // attempt so the server can bind. Each entry is (container path, is_key).
        let mut cert_files: Vec<(String, bool)> = Vec::new();
        // Service-account credential JSON files the app reads to initialize the Firebase Admin SDK
        // before it listens (see [`missing_service_account_json`]); staged from the inert placeholder
        // on the next attempt so the app can bind.
        let mut cred_files: Vec<String> = Vec::new();
        // Runtime configuration files the app refused to start without (see
        // [`missing_config_file_container`]); staged on the next attempt by copying the deployment's
        // own committed template to the path the loader expected.
        let mut config_files: Vec<ConfigStage> = Vec::new();
        let mut generated_config_retry = false;
        for _ in 0..5 {
            self.tls = !cert_files.is_empty();
            self.run_app(
                &env,
                stub_missing_modules,
                mongodb_callback_promises,
                &scratch_dirs,
                &StartupStaging {
                    cert_files: &cert_files,
                    cred_files: &cred_files,
                    config_files: &config_files,
                },
            )?;
            let err = match self.wait_until_listening() {
                Ok(port) => {
                    self.port = port;
                    self.seed_db();
                    return Ok(());
                }
                Err(err) => err,
            };
            let mut missing: Vec<RequiredEnv> = Vec::new();
            for wanted in required_env(&err)
                .into_iter()
                .chain(config_env(&err, &self.root))
            {
                if env.iter().all(|have| have.name != wanted.name)
                    && missing.iter().all(|have| have.name != wanted.name)
                {
                    missing.push(wanted);
                }
            }
            let enable_module_stub = !stub_missing_modules && missing_bare_module(&err);
            let enable_mongodb_callback_promises =
                !mongodb_callback_promises && missing_mongodb_collection_promise(&err);
            let new_dir = missing_write_dir(&err).filter(|dir| !scratch_dirs.contains(dir));
            let new_cert = missing_tls_material(&err)
                .filter(|(path, _)| cert_files.iter().all(|(have, _)| have != path));
            let new_cred = missing_service_account_json(&err, &self.root)
                .filter(|path| cred_files.iter().all(|have| have != path));
            let new_config = missing_config_file_container(&err, &self.root)
                .filter(|stage| config_files.iter().all(|have| have.target != stage.target));
            let retry_generated_config = !generated_config_retry && generated_startup_config(&err);
            if missing.is_empty()
                && !enable_module_stub
                && !enable_mongodb_callback_promises
                && new_dir.is_none()
                && new_cert.is_none()
                && new_cred.is_none()
                && new_config.is_none()
                && !retry_generated_config
            {
                return Err(err);
            }
            remove_container(&self.app);
            env.extend(missing);
            stub_missing_modules |= enable_module_stub;
            mongodb_callback_promises |= enable_mongodb_callback_promises;
            generated_config_retry |= retry_generated_config;
            if let Some(dir) = new_dir {
                scratch_dirs.push(dir);
            }
            if let Some(cert) = new_cert {
                cert_files.push(cert);
            }
            if let Some(cred) = new_cred {
                cred_files.push(cred);
            }
            if let Some(config) = new_config {
                config_files.push(config);
            }
        }
        Err("the app still could not start after five launch attempts".to_owned())
    }

    /// Starts the app container, with `env` on top of the variables every app gets, and
    /// `scratch_dirs` mounted as empty writable tmpfs (directories the app writes into on startup
    /// before creating them; see [`missing_write_dir`]).
    fn run_app(
        &self,
        env: &[RequiredEnv],
        stub_missing_modules: bool,
        mongodb_callback_promises: bool,
        scratch_dirs: &[String],
        staging: &StartupStaging,
    ) -> Result<(), String> {
        // The app: on the private network, hardened, its scratch space in tmpfs, no extra
        // privileges, bounded memory, CPUs and processes.
        let mut args: Vec<String> = [
            "run",
            "-d",
            "--name",
            &self.app,
            "--network",
            &self.network,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "256",
            "--memory",
            "1g",
            "--cpus",
            "2",
            "--tmpfs",
            "/tmp:exec",
            "-e",
            &format!("PORT={}", self.port),
            "-e",
            "HOST=0.0.0.0",
            "-e",
            "NODE_ENV=development",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        // Dependencies installed in a sibling package that bundles this module: point the module's
        // module resolution at that package's `node_modules`, the way the real app does for its
        // bundled code.
        if let Some(node_path) = &self.node_path {
            args.push("-e".to_owned());
            args.push(format!("NODE_PATH={node_path}"));
        }
        // An app that drops root at startup is run as the very uid/gid it drops to, so its
        // `setuid`/`setgid` are legal no-ops to the identity it already holds: the process ends up
        // unprivileged exactly as designed, with no capability added and nothing suppressed.
        if let Some((uid, gid)) = self.run_as {
            args.push("--user".to_owned());
            args.push(format!("{uid}:{gid}"));
        }
        // Node's built-in `node:sqlite` only loads with the `--experimental-sqlite` runtime flag; add
        // it only for an app that references that module, so its own database initialization succeeds
        // instead of throwing on an unavailable module. Adding it for an app that does not use the
        // module changes nothing. The missing-module stub is added only on the launch attempt that
        // needs it.
        // An app that hard-codes its backing service on `localhost`/`127.0.0.1` (a connection string
        // written inline, not read from the injected env) cannot reach the sidecar, which lives on the
        // private network under a service alias. The launch shim then runs a loopback->sidecar TCP
        // forwarder inside the app container so that hard-coded loopback connection reaches the very
        // same MongoDB/Redis/SQL instance the env-configured apps use. Empty (and inert) when no
        // backing service is running.
        let loopback_forward = self.loopback_forward_spec();
        let mut node_options: Vec<String> = vec!["--require=/jss-sink-binding.js".to_owned()];
        if self.node_sqlite {
            node_options.push("--experimental-sqlite".to_owned());
        }
        let load_launch_shim =
            stub_missing_modules || mongodb_callback_promises || !loopback_forward.is_empty();
        if load_launch_shim {
            node_options.push("--require=/jss-launch-shim.js".to_owned());
        }
        if self.electron_main {
            node_options.push("--require=/jss-electron-shim.js".to_owned());
        }
        // Modules the entry file `require`s inside a `try`/`catch` are ones it tolerates the absence
        // of: whenever the shim is active, let it re-throw their `MODULE_NOT_FOUND` so the app's own
        // fallback runs, instead of handing back an inert stub whose truthy value crashes that
        // fallback.
        if load_launch_shim && !self.guarded_modules.is_empty() {
            args.push("-e".to_owned());
            args.push(format!(
                "JSS_GUARDED_MODULES={}",
                self.guarded_modules.join(",")
            ));
        }
        if mongodb_callback_promises {
            args.push("-e".to_owned());
            args.push("JSS_MONGODB_CALLBACK_PROMISES=1".to_owned());
        }
        if !loopback_forward.is_empty() {
            args.push("-e".to_owned());
            args.push(format!("JSS_LOOPBACK_FORWARD={loopback_forward}"));
        }
        if !node_options.is_empty() {
            args.push("-e".to_owned());
            args.push(format!("NODE_OPTIONS={}", node_options.join(" ")));
        }
        for var in env {
            // A directory the app names by a variable: its own empty scratch space.
            if var.directory {
                args.push("--tmpfs".to_owned());
                args.push(var.value.clone());
            }
            args.push("-e".to_owned());
            args.push(format!("{}={}", var.name, var.value));
        }
        // A directory the app writes into at startup before ensuring it exists: its own empty,
        // writable scratch space, so the app's own state seeding succeeds instead of crashing.
        for dir in scratch_dirs {
            args.push("--tmpfs".to_owned());
            args.push(dir.clone());
        }
        for (name, value) in &self.db_env {
            args.push("-e".to_owned());
            args.push(format!("{name}={value}"));
        }
        for (name, value) in &self.redis_env {
            args.push("-e".to_owned());
            args.push(format!("{name}={value}"));
        }
        for (name, value) in &self.service_env {
            args.push("-e".to_owned());
            args.push(format!("{name}={value}"));
        }
        args.push(self.tag.clone());
        // A TLS server reads its key/cert off the filesystem before it listens; when those files are
        // absent the app exits on startup. Stage the self-signed marker pair (already baked into the
        // image, and trusted by the app through `NODE_EXTRA_CA_CERTS`) at the exact paths the app
        // read, then `exec` the app's own launch command unchanged. This satisfies a genuine runtime
        // precondition — a server needs a certificate to serve TLS — without altering the app, and
        // the key/cert are a matching pair so the handshake the driver performs is real.
        if let Some(command) = self.startup_staging_command(
            staging.cert_files,
            staging.cred_files,
            staging.config_files,
        ) {
            args.push("sh".to_owned());
            args.push("-c".to_owned());
            args.push(command);
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        docker(&args).map_err(|e| format!("could not start the app: {e}"))?;
        Ok(())
    }

    /// The `sh -c` launch wrapper that stages verifier and requested startup fixtures, then `exec`s
    /// the app's own launch command (the image `CMD`). Read canaries must be created here rather than
    /// only while building the image: the hardened runtime mounts `/tmp` as a fresh tmpfs.
    /// TLS key/cert files are copied from the self-signed marker pair (`/jss-marker.key`,
    /// `/jss-marker.crt`); service-account credential JSON files from the inert placeholder
    /// (`/jss-service-account.json`). The app's command is taken verbatim from its manifest/entry (see
    /// [`start_command`]); only a filesystem fixture is added ahead of it.
    fn startup_staging_command(
        &self,
        cert_files: &[(String, bool)],
        cred_files: &[String],
        config_files: &[ConfigStage],
    ) -> Option<String> {
        let argv: Vec<String> = serde_json::from_str(&self.start_command).ok()?;
        if argv.is_empty() {
            return None;
        }
        let exec = argv
            .iter()
            .map(|word| shell_quote(word))
            .collect::<Vec<_>>()
            .join(" ");
        let mut script = canary_staging_command(&self.canary);
        for (path, is_key) in cert_files {
            let source = if *is_key {
                "/jss-marker.key"
            } else {
                "/jss-marker.crt"
            };
            script.push_str(&format!("cp {} {} && ", source, shell_quote(path)));
        }
        for path in cred_files {
            script.push_str(&format!(
                "cp /jss-service-account.json {} && ",
                shell_quote(path)
            ));
        }
        // Reproduce the deployment's own first-run step: copy its committed config template to the
        // path the loader read (only when that template exists in the checkout; see
        // [`missing_config_file_container`]). The copy is skipped if the target already exists, so a
        // config the checkout did ship is never clobbered.
        for stage in config_files {
            script.push_str(&format!(
                "[ -f {target} ] || cp {template} {target} && ",
                target = shell_quote(&stage.target),
                template = shell_quote(&stage.template)
            ));
        }
        script.push_str(&format!("exec {exec}"));
        Some(script)
    }

    /// The `localport:sidecarhost:sidecarport` forwarding routes the launch shim installs on the app
    /// container's loopback, one per running backing service, so an application that hard-codes its
    /// database/cache on `localhost`/`127.0.0.1` still reaches the real sidecar (which only answers
    /// on the private network, under a service alias). The host of each route is the sidecar's own
    /// canonical network alias — the same name the injected connection env points at — so no traffic
    /// leaves the disposable sandbox and nothing about the query is fabricated: the app talks to the
    /// actual MongoDB/Redis/SQL server. Empty when no backing service runs (the shim then forwards
    /// nothing); an app that already connects by the alias is unaffected, since the forwarder only
    /// occupies the otherwise-unused loopback service ports.
    fn loopback_forward_spec(&self) -> String {
        let mut routes: Vec<String> = Vec::new();
        if self.db.is_some() {
            routes.push(format!("27017:{}:27017", DB_ALIASES[0]));
        }
        if self.redis.is_some() {
            routes.push(format!("6379:{}:6379", REDIS_ALIASES[0]));
        }
        for (_, sidecar) in &self.sql {
            if let Some(alias) = sidecar.aliases.first() {
                let port = sidecar.port();
                routes.push(format!("{port}:{alias}:{port}"));
            }
        }
        routes.join(",")
    }

    fn start_db(&self) -> Result<(), String> {
        let Some(db) = self.db.as_deref() else {
            return Ok(());
        };
        let mut args = vec![
            "run",
            "-d",
            "--name",
            db,
            "--network",
            &self.network,
            "--memory",
            "512m",
            "--tmpfs",
            "/data/db",
        ];
        // A name a SQL database answers to is not also MongoDB's (`db` may be Postgres).
        let taken: Vec<&str> = self
            .sql
            .iter()
            .flat_map(|(_, s)| s.aliases.iter().map(String::as_str))
            .collect();
        for alias in DB_ALIASES
            .iter()
            .copied()
            .chain(self.mongo_aliases.iter().map(String::as_str))
            .filter(|alias| !taken.contains(alias))
        {
            args.push("--network-alias");
            args.push(alias);
        }
        let image = self
            .mongo_image
            .clone()
            .unwrap_or_else(|| DB_IMAGE.to_owned());
        args.push(&image);
        // An older image a repository pins (`mongo:4.0.4`) may be published for amd64 only.
        if let Err(error) = docker(&args) {
            if !error.contains("no matching manifest") {
                return Err(format!("could not start the database sidecar: {error}"));
            }
            remove_container(db);
            args.splice(2..2, ["--platform", "linux/amd64"]);
            docker(&args)
                .map_err(|error| format!("could not start the database sidecar: {error}"))?;
        }
        for _ in 0..40 {
            let ping = self.exec(
                db,
                &[
                    self.mongo_shell(),
                    "--quiet",
                    "--eval",
                    "db.runCommand({ping:1}).ok",
                ],
            );
            if ping
                .ok()
                .filter(|output| output.status.success())
                .is_some_and(|output| String::from_utf8_lossy(&output.stdout).trim() == "1")
            {
                return Ok(());
            }
            if !self.container_running(db) {
                return Err(format!(
                    "the database sidecar exited before it was ready:\n{}",
                    self.tail_logs(db)
                ));
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        Err("the database sidecar did not become ready within 40s".to_owned())
    }

    /// Starts each SQL database the app needs (see [`super::services`]) on the private network, under
    /// the names the app connects to, with bounded memory and the repository's init scripts mounted
    /// read-only, and waits until it accepts TCP connections — which the official images only do once
    /// their initialization (users, database, init scripts) has finished.
    fn start_sql(&self) -> Result<(), String> {
        for (container, sidecar) in &self.sql {
            let mut args: Vec<String> = [
                "run",
                "-d",
                "--name",
                container,
                "--network",
                &self.network,
                "--memory",
                "512m",
            ]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
            // Official database images declare persistent VOLUME paths. Verification data is
            // disposable, so mount those paths as tmpfs instead of leaking anonymous Docker
            // volumes when a process is interrupted between `run` and teardown.
            args.push("--tmpfs".to_owned());
            args.push(sidecar.kind.data_dir(&sidecar.image).to_owned());
            for alias in &sidecar.aliases {
                args.push("--network-alias".to_owned());
                args.push(alias.clone());
            }
            for (name, value) in &sidecar.container_env {
                args.push("-e".to_owned());
                args.push(format!("{name}={value}"));
            }
            for (source, target) in &sidecar.mounts {
                args.push("-v".to_owned());
                args.push(format!("{}:{target}:ro", source.display()));
            }
            let run = |platform: Option<&str>| {
                let mut full = args.clone();
                if let Some(platform) = platform {
                    full.splice(2..2, ["--platform".to_owned(), platform.to_owned()]);
                }
                full.push(sidecar.image.clone());
                let refs: Vec<&str> = full.iter().map(String::as_str).collect();
                docker(&refs)
            };
            // An image published for amd64 only (`mysql:5.7`) runs emulated on an arm64 host.
            if let Err(error) = run(None) {
                if !error.contains("no matching manifest") {
                    return Err(format!(
                        "could not start the {} database sidecar: {error}",
                        sidecar.image
                    ));
                }
                remove_container(container);
                run(Some("linux/amd64")).map_err(|error| {
                    format!(
                        "could not start the {} database sidecar: {error}",
                        sidecar.image
                    )
                })?;
            }
            let port = sidecar.port().to_string();
            let password = format!("-p{}", sidecar.password);
            let user = format!("-u{}", sidecar.user);
            let probe: Vec<&str> = match sidecar.kind {
                super::services::SqlKind::Postgres => vec![
                    "pg_isready",
                    "-h",
                    "127.0.0.1",
                    "-p",
                    &port,
                    "-U",
                    &sidecar.user,
                ],
                super::services::SqlKind::Mysql => {
                    let mut probe = vec![
                        "mysqladmin",
                        "ping",
                        "--silent",
                        "--protocol=tcp",
                        "-h",
                        "127.0.0.1",
                        "-P",
                        &port,
                        &user,
                    ];
                    if !sidecar.password.is_empty() {
                        probe.push(&password);
                    }
                    probe
                }
            };
            let mut ready = false;
            for _ in 0..180 {
                if self
                    .exec(container, &probe)
                    .is_ok_and(|output| output.status.success())
                {
                    ready = true;
                    break;
                }
                if !self.container_running(container) {
                    return Err(format!(
                        "the {} database sidecar exited before it was ready:\n{}",
                        sidecar.image,
                        self.tail_logs(container)
                    ));
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
            if !ready {
                return Err(format!(
                    "the {} database sidecar did not become ready within 180s",
                    sidecar.image
                ));
            }
            if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
                eprintln!(
                    "[verify] sql sidecar {} ({}) ready as {:?}",
                    container, sidecar.image, sidecar.aliases
                );
            }
        }
        Ok(())
    }

    /// The MongoDB shell inside the database sidecar: `mongosh` (5.0 and later images) or the
    /// legacy `mongo` (older images a repository may pin). Looked up once per session.
    fn mongo_shell(&self) -> &'static str {
        if let Some(shell) = self.mongo_shell.get() {
            return shell;
        }
        let Some(db) = self.db.as_deref() else {
            return "mongosh";
        };
        let has_mongosh = self
            .exec(db, &["sh", "-c", "command -v mongosh"])
            .is_ok_and(|output| output.status.success());
        let shell = if has_mongosh { "mongosh" } else { "mongo" };
        // Only remember the answer once the container is up to give one.
        if self.container_running(db) {
            self.mongo_shell.set(Some(shell));
        }
        shell
    }

    fn start_redis(&self) -> Result<(), String> {
        let Some(redis) = self.redis.as_deref() else {
            return Ok(());
        };
        let mut args = vec![
            "run",
            "-d",
            "--name",
            redis,
            "--network",
            &self.network,
            "--memory",
            "256m",
        ];
        for alias in REDIS_ALIASES {
            args.push("--network-alias");
            args.push(alias);
        }
        args.push(REDIS_IMAGE);
        docker(&args).map_err(|error| format!("could not start the Redis sidecar: {error}"))?;
        for _ in 0..40 {
            let ping = self.exec(redis, &["redis-cli", "ping"]);
            if ping
                .ok()
                .filter(|output| output.status.success())
                .is_some_and(|output| String::from_utf8_lossy(&output.stdout).trim() == "PONG")
            {
                return Ok(());
            }
            if !self.container_running(redis) {
                return Err(format!(
                    "the Redis sidecar exited before it was ready:\n{}",
                    self.tail_logs(redis)
                ));
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        Err("the Redis sidecar did not become ready within 40s".to_owned())
    }

    /// Load the application's own database seed into the sidecar before launch, when the repository
    /// ships a `mongodump` (a directory of `<collection>.bson` files beside their `.metadata.json`).
    /// A real deployment restores this dump, so the app's startup initialization — which reads
    /// required configuration (a JWT signing secret, feature flags) out of its own collections and
    /// crashes when they are absent — finds the data it needs and the server reaches `listen`. The
    /// dump is restored into the verifier's application database, the one the app is pointed at, so
    /// the running server reads it exactly as it would in production. Best-effort: a repository with
    /// no dump, or a restore error, leaves the database empty — the same state as before.
    fn restore_db_dump(&self) {
        let Some(db) = self.db.as_deref() else {
            return;
        };
        let Some(dump) = mongodump_dir(&self.root) else {
            return;
        };
        let Some(dump_str) = dump.to_str() else {
            return;
        };
        let dest = format!("{db}:/jss-db-dump");
        if Command::new("docker")
            .args(["cp", dump_str, &dest])
            .output()
            .is_err()
        {
            return;
        }
        let output = self.exec(
            db,
            &["mongorestore", "--drop", "--db", DB_NAME, "/jss-db-dump"],
        );
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            let (code, message) = match output {
                Ok(output) => (
                    output.status.code(),
                    String::from_utf8_lossy(&output.stderr)
                        .lines()
                        .last()
                        .unwrap_or_default()
                        .to_owned(),
                ),
                Err(error) => (None, error),
            };
            eprintln!("[verify] db restore {dump_str} -> {code:?} {message}");
        }
    }

    fn seed_db(&self) {
        let Some(db) = self.db.as_deref() else {
            return;
        };
        let script = "db.getMongo().getDBNames().forEach(function(n){\
            if(['admin','local','config'].indexOf(n)>=0)return;\
            var d=db.getSiblingDB(n);\
            d.getCollectionNames().forEach(function(c){\
              try{if(d.getCollection(c).countDocuments({})===0)\
                d.getCollection(c).insertOne({jss_seed:1});}catch(e){}\
            });\
          });";
        let output = self.exec(db, &[self.mongo_shell(), "--quiet", "--eval", script]);
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            let (code, message) = match output {
                Ok(output) => (
                    output.status.code(),
                    String::from_utf8_lossy(&output.stderr).trim().to_owned(),
                ),
                Err(error) => (None, error),
            };
            let list = "db.getMongo().getDBNames().forEach(function(n){\
                if(['admin','local','config'].indexOf(n)>=0)return;\
                var d=db.getSiblingDB(n);\
                d.getCollectionNames().forEach(function(c){\
                  print(n+'.'+c+'='+d.getCollection(c).countDocuments({}));\
                });\
              });";
            let listing = self
                .exec(db, &[self.mongo_shell(), "--quiet", "--eval", list])
                .ok()
                .map(|o| {
                    String::from_utf8_lossy(&o.stdout)
                        .trim()
                        .replace('\n', " | ")
                })
                .unwrap_or_default();
            eprintln!("[verify] db seed -> {code:?} {message} || state: {listing}");
        }
    }

    /// Turn on full operation profiling on every application database. A read-only query sink
    /// (`Model.findOne(...)`) never creates its collection on a driver that does not auto-create on
    /// read (Mongoose 5's `autoCreate` defaults off), so the startup seed cannot know the collection
    /// exists and the match-all/match-none differential has no document to observe. Profiling records
    /// the namespace of every command the server receives, so a single benign request reveals exactly
    /// which collection(s) the sink reads — without guessing a name from the source. Enable it before
    /// the benign probe request; [`Session::seed_profiled_collections`] consumes the log afterwards.
    fn enable_db_profiling(&self) {
        let Some(db) = self.db.as_deref() else {
            return;
        };
        // Profile every database that already holds data (from `getDBNames()`), plus every database
        // the app names in its own connection string. A read-only sink's database is never created on
        // disk, so `getDBNames()` omits it and its query would go unrecorded; naming it (each name is
        // restricted to MongoDB-legal identifier characters, so it cannot break out of the script
        // literal) enables profiling on the exact database the sink queries. Enabling profiling on a
        // not-yet-existing named database creates it, which is also what lets the recorded collection
        // be seeded for the differential.
        let mut script = String::from(ENABLE_PROFILING_SCRIPT);
        for name in &self.mongo_databases {
            script.push_str(&format!(
                "try{{db.getSiblingDB('{name}').setProfilingLevel(2);}}catch(e){{}}"
            ));
        }
        let _ = self.exec(db, &[self.mongo_shell(), "--quiet", "--eval", &script]);
    }

    /// Read the profiler log written since [`Session::enable_db_profiling`], and for every collection
    /// a command targeted that is still empty, insert one seed document. This materializes exactly the
    /// collections the sink's request actually queried — including a read-only sink's collection the
    /// driver never auto-created — so a match-all operator (`{$ne}`) can return a record the match-none
    /// controls (`$eq`, `$in: []`) do not. Profiling is then disabled and its capped log dropped so the
    /// seeded documents are the only state the differential depends on.
    fn seed_profiled_collections(&self) {
        let Some(db) = self.db.as_deref() else {
            return;
        };
        let _ = self.exec(
            db,
            &[
                self.mongo_shell(),
                "--quiet",
                "--eval",
                SEED_PROFILED_SCRIPT,
            ],
        );
    }

    /// Plant a single record that a document-filtering NoSQL sink's own query selects, so the
    /// match-all/match-none differential has a pre-existing document to move. Profiling is turned on,
    /// one benign match-none request is sent — its injected field carries the per-run sentinel, so the
    /// recorded query filter contains it — and the observed filter is turned into a document: each
    /// scalar equality is copied verbatim (the `email` the handler ANDs in), and the one operator
    /// field that references the sentinel is set to a present value that the match-all `{$ne:<sentinel>}`
    /// selects while the match-none controls (`$eq`, `$in: []`) do not. Guard queries that do not
    /// reference the sentinel — an earlier `{verified:true}` pre-check that must *not* match for the
    /// sink to run — contribute no fields, so the planted record stays reachable. Every collection,
    /// field and value comes from the query the app actually ran; nothing is derived from a name.
    fn seed_nosql_lookup_record(&self, cases: &[payload::NosqlCase]) {
        let Some(db) = self.db.as_deref() else {
            return;
        };
        let Some(first) = cases.first() else {
            return;
        };
        self.enable_db_profiling();
        let _ = self.fetch(&first.match_none_eq);
        std::thread::sleep(std::time::Duration::from_secs(2));
        let script = nosql_lookup_seed_script(&first.absent);
        let output = self.exec(db, &[self.mongo_shell(), "--quiet", "--eval", &script]);
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            let (code, message) = match output {
                Ok(output) => (
                    output.status.code(),
                    String::from_utf8_lossy(&output.stdout).trim().to_owned(),
                ),
                Err(error) => (None, error),
            };
            eprintln!("[verify] nosql lookup seed -> {code:?} {message}");
        }
    }

    /// Polls from inside the app's own container until the app answers on a port, or the
    /// deadline passes, and returns that port.
    fn wait_until_listening(&self) -> Result<u16, String> {
        // Up to ~90s: `npm start` may build first. The probe is one Node connect attempt.
        // A local session shares its network namespace with its datastore sidecars. Their ports are
        // already listening before the application starts and must not be mistaken for a hard-coded
        // application HTTP port while `npm start` is still booting.
        let excluded = match &self.runtime {
            Runtime::Local { .. } => local_excluded_ports(
                &self.local_baseline_ports,
                self.local_marker_port,
                self.db.is_some(),
                self.redis.is_some(),
            ),
            Runtime::Docker => Vec::new(),
        };
        for _ in 0..90 {
            let candidates = if matches!(&self.runtime, Runtime::Local { .. }) {
                local_listening_ports()
                    .into_iter()
                    .filter(|port| !self.local_baseline_ports.contains(port))
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            let script = listening_probe_excluding_candidates(self.port, &excluded, &candidates);
            let probe = self.exec(&self.app, &["node", "-e", &script]);
            if let Some(port) = probe.ok().filter(|o| o.status.success()).and_then(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .trim()
                    .parse::<u16>()
                    .ok()
            }) {
                return Ok(port);
            }
            // Give up early if the app container has already exited.
            if !self.container_running(&self.app) {
                return Err(format!(
                    "the app exited before it listened:\n{}",
                    self.settled_tail_logs(&self.app)
                ));
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        Err(format!(
            "the app did not listen within 90s:\n{}",
            self.tail_logs(&self.app)
        ))
    }

    /// Sends every derived request for a probe and reports the first that reproduces, or that
    /// none did.
    /// Report an outcome observed in this session, accounting for any backing service the sandbox
    /// could not provide (see [`qualify_reduced_environment`]).
    pub fn qualify(&self, outcome: Outcome) -> Outcome {
        qualify_reduced_environment(outcome, &self.unavailable_services)
    }

    /// Whether the app can be relaunched with a changed file: always in Docker (its container is
    /// restarted), and in the local runtime once a launch has succeeded (the process is relaunched
    /// with the same settings).
    pub fn can_relaunch(&self) -> bool {
        matches!(self.runtime, Runtime::Docker) || self.local_launch.is_some()
    }

    /// The HTTP status the route gives the probe's own request carrying a plain, harmless value
    /// instead of the payload: the legitimate behavior a fix must leave unchanged.
    /// The benign status and whether a stored, second-order route returned the exact harmless
    /// value planted through its write route. The latter is a functional control strong enough to
    /// prove a fix that replaces an unnecessary dangerous sink instead of merely wrapping it.
    pub fn benign_status_and_value(&mut self, probe: &Probe) -> Option<(u16, bool)> {
        if let Some(write) = &probe.stored_write {
            return self.stored_benign_status(probe, write);
        }
        let status = self
            .fetch_meta(&payload::benign(probe))
            .and_then(|(_, status, _)| status)?;
        // A socket.io event the handler never acks (204) shows no behavior a change could keep or
        // break, so it gives no control at all, the same as a route that answers nothing.
        (!(probe.method == Method::Socket && status == 204)).then_some((status, false))
    }

    /// Exercises the legitimate two-request behavior of a stored finding. A plain value must be
    /// accepted by the write route and the authenticated read route must still answer after a fix.
    /// Checking only the read route anonymously would preserve an auth rejection (often HTTP 400)
    /// and could incorrectly call a change proven without demonstrating useful application
    /// behavior.
    fn stored_benign_status(
        &mut self,
        probe: &Probe,
        write: &super::plan::StoredWrite,
    ) -> Option<(u16, bool)> {
        let write_probe = Probe {
            method: write.method,
            path: write.path.clone(),
            entry: write.entry.clone(),
            stored_write: None,
            ..probe.clone()
        };
        let credential = self.credential_for(probe).ok()?;
        let value = format!("jss-benign-{}", self.canary.token);
        let plant = self.with_credential(
            &payload::benign_with_value(&write_probe, &value),
            credential.as_ref(),
        );
        let (_, write_status, cookies) = self.fetch_meta(&plant)?;
        let write_status = write_status?;
        if !(200..400).contains(&write_status) {
            return None;
        }

        let rotated = payload::session_cookie_pair(&cookies)
            .map(|pair| SessionCred::Cookie { pair })
            .or(credential);
        let read = self.with_credential(
            &Attempt {
                verb: probe.method.verb(&probe.entry),
                target: payload::fill_remaining(&probe.path, &[]),
                body: None,
                headers: Vec::new(),
                signal: Signal::InResponse,
            },
            rotated.as_ref(),
        );
        self.fetch_meta(&read)
            .and_then(|(body, status, _)| status.map(|status| (status, body.contains(&value))))
    }

    /// The status the route gives a plain `value` placed where a reflected-XSS payload rides, and
    /// whether it answers with an HTML page that shows the value, fetched without a browser: what a
    /// fix must keep serving. A page answered as `text/plain` or JSON shows nothing as HTML.
    pub fn reflected_benign(
        &self,
        probe: &super::plan::ReflectedXss,
        value: &str,
    ) -> Option<(u16, bool)> {
        let attempt = Attempt {
            verb: "GET",
            target: super::reflected::benign_target(probe, value),
            body: None,
            headers: Vec::new(),
            signal: Signal::InResponse,
        };
        let output = self.drive(&attempt).ok()?;
        let body = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let (status, _) = parse_driver_meta(&stderr);
        let html = driver_content_type(&stderr).is_none_or(|kind| is_html_content_type(&kind));
        Some((status?, html && body.contains(value)))
    }

    /// Binds this disposable session to the finding's exact source expression and relaunches the
    /// app with only that controller marker added.  The caller invokes this once, before any
    /// exploit request.  A failure is a skipped verification rather than permission to accept an
    /// effect from some other compatible sink on the route.
    pub fn activate_sink(&mut self, finding: &jss_core::Finding) -> Result<(), String> {
        let token = format!("{}-sink-{}", self.canary.token, finding.fingerprint);
        let callback = self.canary.service_url_for_token(&token);
        let mut binding = super::sink_binding::Binding::for_finding(finding, token, callback);
        let source = std::fs::read_to_string(self.root.join(&binding.file)).map_err(|error| {
            format!(
                "could not read {} for exact runtime binding: {error}",
                binding.file
            )
        })?;
        let instrumented = binding.instrument_original(&source)?;
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            let at = instrumented.find(&binding.token).unwrap_or(0);
            let start = instrumented[..at]
                .rfind('\n')
                .map_or(0, |newline| newline.saturating_add(1));
            let end = instrumented[at..]
                .find('\n')
                .map_or(instrumented.len(), |newline| at + newline);
            eprintln!(
                "[verify] exact-sink binding {}:{}:{} api={} source[{}]",
                binding.file,
                binding.line,
                binding.col,
                binding.api,
                instrumented[start..end]
                    .chars()
                    .take(800)
                    .collect::<String>()
            );
        }
        self.relaunch_raw(&[(binding.file.clone(), instrumented)])?;
        self.sink_binding = Some(binding);
        Ok(())
    }

    /// Replaces each `(path, content)` (relative to the repository root), runs the app's build step
    /// again when it has one, relaunches the app and waits until it listens: the very app the
    /// finding reproduced against, now with a candidate change. Datastore sidecars keep running.
    ///
    /// Docker copies the files into the running container and restarts it; the checkout on disk is
    /// never touched. The local runtime runs the app from the checkout itself, so it writes the
    /// files there, remembering each original for [`Self::restore_files`] (and teardown).
    /// Relaunches a fix candidate that may intentionally replace the selected sink. The caller may
    /// opt into an uninstrumented changed file only after establishing a strong functional benign
    /// control; vulnerable controls and ordinary candidates remain strictly bound.
    pub fn relaunch_with_files_allowing_removed_sink(
        &mut self,
        files: &[(String, String)],
        allow_removed_sink: bool,
    ) -> Result<(), String> {
        let files = self.instrument_changed_sink(files, allow_removed_sink)?;
        self.relaunch_raw(&files)
    }

    fn relaunch_raw(&mut self, files: &[(String, String)]) -> Result<(), String> {
        match &self.runtime {
            Runtime::Docker => self.relaunch_docker(files),
            Runtime::Local { .. } => self.relaunch_local(files),
        }
    }

    fn instrument_changed_sink(
        &self,
        files: &[(String, String)],
        allow_removed_sink: bool,
    ) -> Result<Vec<(String, String)>, String> {
        files
            .iter()
            .map(|(file, content)| {
                let content = match &self.sink_binding {
                    Some(binding) if binding.file == *file => match binding.instrument(content) {
                        Ok(instrumented) => instrumented,
                        Err(_) if allow_removed_sink && !binding.is_present(content) => {
                            content.clone()
                        }
                        Err(error) => return Err(error),
                    },
                    _ => content.clone(),
                };
                Ok((file.clone(), content))
            })
            .collect()
    }

    /// The build step that makes `files` take effect: the project's TypeScript compiler when one
    /// of them is TypeScript and the app runs the compiler's output, otherwise the app's own build.
    fn rebuild_for(&self, files: &[(String, String)]) -> Option<Rebuild> {
        let typescript_change = files.iter().any(|(rel, _)| {
            [".ts", ".tsx", ".mts", ".cts"]
                .iter()
                .any(|ext| rel.ends_with(ext) && !rel.ends_with(".d.ts"))
        });
        match (&self.typescript, &self.rebuild) {
            (Some(typescript), _) if typescript_change => Some(Rebuild {
                workdir: typescript.workdir.clone(),
                command: TSC_COMMAND.to_owned(),
                typescript: Some(typescript.no_emit_on_error),
            }),
            (_, Some((workdir, command))) => Some(Rebuild {
                workdir: workdir.clone(),
                command: command.clone(),
                typescript: None,
            }),
            _ => None,
        }
    }

    fn relaunch_docker(&mut self, files: &[(String, String)]) -> Result<(), String> {
        for (rel, content) in files {
            let target = container_dir(std::path::Path::new(rel))
                .ok_or_else(|| format!("unsupported path `{rel}`"))?;
            let staged = tempfile::NamedTempFile::new()
                .map_err(|e| format!("could not stage {rel}: {e}"))?;
            std::fs::write(staged.path(), content)
                .map_err(|e| format!("could not stage {rel}: {e}"))?;
            // Readable by the app whatever uid it runs as: the copy keeps the staged file's mode.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(staged.path(), std::fs::Permissions::from_mode(0o644))
                    .map_err(|e| format!("could not stage {rel}: {e}"))?;
            }
            let source = staged
                .path()
                .to_str()
                .ok_or_else(|| format!("could not stage {rel}: non-UTF-8 temp path"))?;
            docker(&["cp", source, &format!("{}:{target}", self.app)])
                .map_err(|e| format!("could not copy {rel} into the app: {e}"))?;
        }
        if let Some(build) = self.rebuild_for(files) {
            let output = self.exec(
                &self.app,
                &[
                    "sh",
                    "-c",
                    &format!("cd {} && {}", shell_quote(&build.workdir), build.command),
                ],
            )?;
            let mut log = String::from_utf8_lossy(&output.stdout).into_owned();
            log.push_str(&String::from_utf8_lossy(&output.stderr));
            build.check(output.status.success(), &log)?;
        }
        docker(&["restart", "-t", "2", &self.app])
            .map_err(|e| format!("could not restart the app: {e}"))?;
        self.port = self.wait_until_listening()?;
        Ok(())
    }

    fn relaunch_local(&mut self, files: &[(String, String)]) -> Result<(), String> {
        let launch = self
            .local_launch
            .clone()
            .ok_or_else(|| "the app has not launched successfully yet".to_owned())?;
        for (rel, content) in files {
            let path = self.local_path(rel)?;
            if self.overwritten.iter().all(|(seen, _)| seen != rel) {
                let original = std::fs::read_to_string(&path)
                    .map_err(|e| format!("could not read {rel}: {e}"))?;
                self.overwritten.push((rel.clone(), original));
            }
            std::fs::write(&path, content).map_err(|e| format!("could not write {rel}: {e}"))?;
        }
        if let (
            Some(build),
            Runtime::Local {
                tool_dir, home_dir, ..
            },
        ) = (self.rebuild_for(files), &self.runtime)
        {
            let mut command = Command::new("sh");
            isolate_local_command(&mut command, home_dir, tool_dir.as_deref())?;
            let output = command
                .args(["-c", &build.command])
                .current_dir(&build.workdir)
                .env("CI", "true")
                .output()
                .map_err(|e| format!("running the app's build step: {e}"))?;
            let mut log = String::from_utf8_lossy(&output.stdout).into_owned();
            log.push_str(&String::from_utf8_lossy(&output.stderr));
            build.check(output.status.success(), &log)?;
        }
        self.run_local_app(
            &launch.env,
            launch.stub_missing_modules,
            launch.mongodb_callback_promises,
            launch.next_development,
            &launch.scratch_dirs,
        )?;
        self.port = self.wait_until_listening()?;
        restore_local_read_canaries(&self.canary)?;
        Ok(())
    }

    /// The on-disk path of `rel` in the local checkout, refusing anything that would leave it.
    fn local_path(&self, rel: &str) -> Result<std::path::PathBuf, String> {
        let relative = std::path::Path::new(rel);
        if relative.is_absolute()
            || relative
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err(format!("unsupported path `{rel}`"));
        }
        Ok(self.root.join(relative))
    }

    /// Repository content before this session added its exact-sink marker or tried a fix.
    pub fn original_file(&self, rel: &str) -> Result<String, String> {
        original_file_content(&self.root, &self.overwritten, rel)
    }

    /// Writes back every file the local runtime overwrote to try a change. Nothing to do for
    /// Docker, whose changes live only in the disposable container.
    pub fn restore_files(&mut self) -> Result<(), String> {
        let mut failures = Vec::new();
        for (rel, original) in std::mem::take(&mut self.overwritten) {
            let written = self
                .local_path(&rel)
                .and_then(|path| std::fs::write(path, &original).map_err(|e| e.to_string()));
            if let Err(error) = written {
                failures.push(format!("{rel}: {error}"));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(format!("could not restore {}", failures.join(", ")))
        }
    }

    /// This session's private network name, unique per launch (see [`run_id`]). Test-only: proves
    /// a session was actually relaunched rather than reused, without depending on any other
    /// observable side effect.
    #[cfg(test)]
    pub(crate) fn network_name(&self) -> &str {
        &self.network
    }

    pub fn exercise(&mut self, probe: &Probe) -> Outcome {
        self.driver_errors.borrow_mut().clear();
        self.driver_successes.set(0);
        self.proof_sink_hit.set(false);
        self.unbound_effect.set(false);
        *self.last_verified_attempt.borrow_mut() = None;
        self.probe_setup.borrow_mut().clear();
        self.prepare_probe_resources(probe);
        // An MCP probe is aimed at the endpoint found for its own hints and resolved against the
        // server's own tool list: the tool and argument the source did not settle, and the other
        // arguments the tool requires, come from its schema, one concrete pair at a time.
        let outcome = if probe.method == Method::Mcp {
            match self.mcp_discover(probe) {
                Ok(discovery) => self.exercise_mcp(probe, &discovery),
                Err(reason) => Outcome::Skipped { reason },
            }
        } else {
            self.exercise_generic(probe)
        };
        let outcome = qualify_driver_health(
            outcome,
            self.driver_errors.borrow().as_slice(),
            self.driver_successes.get(),
        );
        let outcome = self.qualify_sink_binding(outcome);
        self.attach_exact_command_transcript(outcome)
    }

    /// Replays the single request that established the current finding. A fixed candidate should
    /// usually be disproved in one request; rerunning hundreds of alternate routes and payloads is
    /// both slower and semantically weaker than checking the exact exploit. If the original proof
    /// used a multi-request differential oracle, no single attempt is recorded and the caller falls
    /// back to the full probe.
    pub fn replay_verified_attempt(&mut self, probe: &Probe) -> Outcome {
        let Some(attempt) = self.last_verified_attempt.borrow().clone() else {
            return self.exercise(probe);
        };
        self.driver_errors.borrow_mut().clear();
        self.driver_successes.set(0);
        self.proof_sink_hit.set(false);
        self.unbound_effect.set(false);
        self.probe_setup.borrow_mut().clear();
        self.prepare_probe_resources(probe);
        let outcome = match self.send(&attempt) {
            Some(poc) => Outcome::Verified {
                how: format!("{} {}", poc.method, poc.target),
                poc,
            },
            None => Outcome::NotReproduced { tried: 1 },
        };
        let outcome = qualify_driver_health(
            outcome,
            self.driver_errors.borrow().as_slice(),
            self.driver_successes.get(),
        );
        self.qualify_sink_binding(outcome)
    }

    /// Some evaluator routes operate on an existing resource and honestly reject an empty store.
    /// When the route and request field explicitly identify a query/expression evaluator, create one
    /// harmless code-backed resource at the parent collection first. This is performed only inside
    /// the disposable verifier sandbox and is included in the reported reproduction command.
    fn prepare_probe_resources(&self, probe: &Probe) {
        // A conventional worker registration route is the honest public prerequisite for endpoints
        // keyed by a worker id. Register a disposable manager (no project row required) so `{id}=1`
        // exists in a fresh SQL sidecar before the selected worker route is exercised.
        if probe.path.contains("/workers/{id}/") {
            let setup = Attempt {
                verb: "POST",
                target: "/worker/register".to_owned(),
                body: Some(
                    serde_json::json!({
                        "hostname": "jsspector",
                        "pid": 1,
                        "mode": "verification",
                        "type": "manager"
                    })
                    .to_string(),
                ),
                // Verification fills token-like environment variables with this same neutral
                // secret when an app expects them. Some local collectors consequently protect
                // their otherwise-public registration route with that token. Authenticate the
                // disposable registration with the verifier-owned value so the prerequisite is
                // created instead of silently recording a 401 response as setup.
                headers: vec![
                    (
                        "Authorization".to_owned(),
                        format!("Bearer {STRONG_FILLER_SECRET}"),
                    ),
                    ("Content-Type".to_owned(), "application/json".to_owned()),
                ],
                signal: Signal::InResponse,
            };
            let registered = self.fetch_meta(&setup);
            if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
                let summary = registered
                    .as_ref()
                    .map(|(body, status, _)| (status, response_excerpt(body)));
                eprintln!("[verify] worker prerequisite response={summary:?}");
            }
            if registered
                .is_some_and(|(_, status, _)| status.is_some_and(|code| (200..300).contains(&code)))
            {
                self.probe_setup.borrow_mut().push(setup);
            } else if self.seed_worker_row() && std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
                eprintln!("[verify] worker prerequisite seeded in disposable SQL sidecar");
            }
        }

        if probe.class != jss_core::VulnClass::CodeInjection {
            return;
        }
        let Entry::Body(Some(field)) = &probe.entry else {
            return;
        };
        if !matches!(field.as_str(), "expression" | "query") {
            return;
        }
        let Some(parent) = probe.path.strip_suffix("/query") else {
            return;
        };
        if parent.is_empty() {
            return;
        }
        let body = serde_json::json!({
            "id": "jsspector_probe",
            "name": "jsspector_probe",
            "prompt": "verification prerequisite",
            "code": "export default ({ brep }) => brep.box(1, 1, 1);"
        })
        .to_string();
        let setup = Attempt {
            verb: "POST",
            target: parent.to_owned(),
            body: Some(body),
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            signal: Signal::InResponse,
        };
        let created = self.fetch_meta(&setup);
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            let summary = created
                .as_ref()
                .map(|(body, status, _)| (status, response_excerpt(body)));
            eprintln!("[verify] evaluator prerequisite target={parent} response={summary:?}");
        }
        if created
            .is_some_and(|(_, status, _)| status.is_some_and(|code| (200..300).contains(&code)))
        {
            self.probe_setup.borrow_mut().push(setup);
        }
    }

    /// Seed the minimum conventional worker row when the application's own registration endpoint
    /// cannot run against its checked-in schema (for example, the route expects a migration that
    /// the repository's bootstrap omitted). The route under test only requires an existing id; this
    /// disposable row supplies that ordinary state without changing application code or bypassing
    /// its request authentication.
    fn seed_worker_row(&self) -> bool {
        for (container, sidecar) in &self.sql {
            let output = match sidecar.kind {
                super::services::SqlKind::Postgres => self.exec(
                    container,
                    &[
                        "env",
                        &format!("PGPASSWORD={}", sidecar.password),
                        "psql",
                        "-v",
                        "ON_ERROR_STOP=1",
                        "-U",
                        &sidecar.user,
                        "-d",
                        &sidecar.database,
                        "-c",
                        "INSERT INTO workers (id, hostname, pid, status) VALUES (1, 'jsspector', 1, 'idle') ON CONFLICT (id) DO NOTHING;",
                    ],
                ),
                super::services::SqlKind::Mysql => {
                    let mut args = vec![
                        "mysql".to_owned(),
                        "--protocol=tcp".to_owned(),
                        "-h".to_owned(),
                        "127.0.0.1".to_owned(),
                        "-u".to_owned(),
                        sidecar.user.clone(),
                    ];
                    if !sidecar.password.is_empty() {
                        args.push(format!("-p{}", sidecar.password));
                    }
                    args.extend([
                        sidecar.database.clone(),
                        "-e".to_owned(),
                        "INSERT IGNORE INTO workers (id, hostname, pid, status) VALUES (1, 'jsspector', 1, 'idle');".to_owned(),
                    ]);
                    let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
                    self.exec(container, &refs)
                }
            };
            if output.is_ok_and(|result| result.status.success()) {
                return true;
            }
        }
        false
    }

    /// Differential oracles (SQL/NoSQL, traversal branch comparisons, and similar proofs) build
    /// their reproduction after several requests rather than through [`Self::send`]. Repeat the
    /// displayed positive command here so every HTTP proof has one common transcript contract.
    /// The transcript is accepted only when the command succeeds, its stdout repeats the already
    /// proved positive response, and the selected sink executes again during that exact command.
    fn attach_exact_command_transcript(&self, outcome: Outcome) -> Outcome {
        let Outcome::Verified { how, mut poc } = outcome else {
            return outcome;
        };
        if poc.output_safety.is_some()
            || poc.response.trim().is_empty()
            || !poc.command.contains("curl ")
            || matches!(poc.method.as_str(), "SOCKET" | "MCP" | "BROWSER")
        {
            return Outcome::Verified { how, poc };
        }

        let marker_before = self.begin_sink_observation();
        let output = self.exec(&self.app, &["sh", "-c", &poc.command]);
        self.finish_sink_observation(marker_before);
        let Ok(output) = output else {
            return Outcome::Verified { how, poc };
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let expected = poc.response.trim();
        let response_body = if poc.command.contains("--include") {
            included_http_body(&stdout)
        } else {
            &stdout
        };
        let repeats_positive_response = response_body.trim().starts_with(expected);
        let bound = self.sink_binding.is_none() || self.last_sink_hit.get();
        if output.status.success() && repeats_positive_response && bound {
            poc.stdout = Some(stdout.into_owned());
            poc.stderr = Some(String::from_utf8_lossy(&output.stderr).into_owned());
            poc.exit_code = output.status.code();
            poc.output_safety = Some("oracle-proof".to_owned());
        }
        Outcome::Verified { how, poc }
    }

    fn qualify_sink_binding(&self, outcome: Outcome) -> Outcome {
        let Some(binding) = &self.sink_binding else {
            return outcome;
        };
        match outcome {
            Outcome::Verified { how, mut poc } if self.proof_sink_hit.get() => {
                poc.evidence = format!("{}; {}", poc.evidence, binding.evidence());
                Outcome::Verified { how, poc }
            }
            Outcome::Verified { .. } if !self.proof_sink_hit.get() => Outcome::Skipped {
                reason: format!(
                    "an exploitation-shaped effect was observed, but the planned sink `{}:{}:{}` (`{}`) did not execute during that same request",
                    binding.file, binding.line, binding.col, binding.api
                ),
            },
            Outcome::NotReproduced { .. } if self.unbound_effect.get() => Outcome::Skipped {
                reason: format!(
                    "an exploitation-shaped effect was observed, but the planned sink `{}:{}:{}` (`{}`) did not execute during that same request",
                    binding.file, binding.line, binding.col, binding.api
                ),
            },
            other => other,
        }
    }

    fn accept_bound_effect(&self, effect: bool) -> bool {
        self.accept_bound_effect_with_hit(effect, self.last_sink_hit.get())
    }

    fn accept_bound_effect_with_hit(&self, effect: bool, hit: bool) -> bool {
        if !effect {
            return false;
        }
        if self.sink_binding.is_none() || hit {
            self.proof_sink_hit.set(true);
            true
        } else {
            self.unbound_effect.set(true);
            false
        }
    }

    /// Drives one concrete probe: every payload the class calls for, the oracles it needs, in the
    /// order that finds a reproduction soonest.
    fn exercise_generic(&mut self, probe: &Probe) -> Outcome {
        self.nonce += 1;
        // A second-order finding: the payload must be saved by a write request before the read
        // request named by `probe` loads it back into the sink. Checked first — the generic matrix
        // below assumes the one request that carries the payload is also the one that reaches the
        // sink, which does not hold here.
        if let Some(write) = &probe.stored_write {
            return self.exercise_stored(probe, write);
        }
        let base_attempts = payload::attempts(probe, &self.canary, self.nonce);
        let credential = match self.credential_for(probe) {
            Ok(credential) => credential,
            Err(outcome) => return *outcome,
        };
        if probe.class == jss_core::VulnClass::NosqlInjection {
            return self.exercise_nosql(probe, credential.as_ref());
        }
        if probe.class == jss_core::VulnClass::SqlInjection {
            return self.exercise_sql(probe, credential.as_ref());
        }
        // A nested-write prototype-pollution sink cannot be proved by reflected content: the written
        // value is the handler's own, not attacker data, so observing input in the write proves only
        // reachability. Prove it instead by reading the injected property back off a *fresh* object
        // through the handler — a property that object never had until `__proto__` was written — with
        // the pre-pollution read and an unpolluted-key read as negative controls.
        if probe.class == jss_core::VulnClass::PrototypePollution {
            return match self.verify_proto_pollution(probe, credential.as_ref()) {
                Some(poc) => Outcome::Verified {
                    how: format!("{} {}", poc.method, poc.target),
                    poc,
                },
                None => Outcome::NotReproduced { tried: 1 },
            };
        }
        // A traversal sink that deletes its argument cannot be proved by reflected content — a
        // successful delete echoes nothing — and the generic climbing attempts would consume the
        // planted canary before any differential ran. Prove it directly: plant a filesystem entry
        // outside the base directory, drive the handler to remove it by traversal, and confirm it
        // disappeared while a sibling control entry planted alongside it survived.
        if probe.class == jss_core::VulnClass::PathTraversal && probe.removes {
            return match self.verify_delete_oracle(probe, credential.as_ref()) {
                Some(poc) => Outcome::Verified {
                    how: format!("{} {}", poc.method, poc.target),
                    poc,
                },
                None => Outcome::NotReproduced { tried: 1 },
            };
        }
        if probe.class == jss_core::VulnClass::PathTraversal && probe.archive_upload {
            return match self.verify_archive_create_oracle(probe, credential.as_ref()) {
                Some(poc) => Outcome::Verified {
                    how: format!("{} {}", poc.method, poc.target),
                    poc,
                },
                None => Outcome::NotReproduced { tried: 1 },
            };
        }
        // A traversal sink that creates its argument (`fs.mkdir`, `fs.writeFile`, an upload move)
        // cannot be proved by reflected content either — a successful create echoes nothing. Prove it
        // directly: plant an empty directory outside the base, drive the handler to create an entry
        // inside it by traversal, and confirm the directory became non-empty while a sibling control
        // directory planted alongside it stayed empty.
        if probe.class == jss_core::VulnClass::PathTraversal && probe.creates {
            if let Some(poc) = self.verify_create_oracle(probe, credential.as_ref()) {
                return Outcome::Verified {
                    how: format!("{} {}", poc.method, poc.target),
                    poc,
                };
            }
            // A read-modify-write handler (`fs.writeFile` after opening the same path) never creates a
            // brand-new leaf: it reads the target first, so the create differential cannot fire. Prove
            // it instead by overwriting an attacker-selected *existing* file outside the base, with an
            // untouched sibling control.
            if let Some(poc) = self.verify_overwrite_oracle(probe, credential.as_ref()) {
                return Outcome::Verified {
                    how: format!("{} {}", poc.method, poc.target),
                    poc,
                };
            }
            return Outcome::NotReproduced { tried: 1 };
        }
        // A traversal *read* sink that appends a fixed segment after the tainted input reads
        // `<tainted-dir>/<suffix>`. Plant the canary file at that location so the climbing payloads,
        // completed by the handler's own appended segment, resolve to a real token file. A listing
        // sink is handled below: it needs a directory, not a file, at the appended segment.
        if probe.class == jss_core::VulnClass::PathTraversal
            && !probe.lists_dir
            && let Some(suffix) = &probe.read_suffix
        {
            self.plant_suffix_canary(suffix);
        }
        // A directory-listing traversal proves itself by a planted file name appearing in the
        // returned listing. Plant a token-named file inside the directory the handler enumerates:
        // under each accepted sibling value it appends from the route (`path.join(base, kind)`), so a
        // climb completed by an accepted slot value lands on a real planted directory; otherwise
        // directly in the climbed-to directory. The fixed-segment (`read_suffix`) case is planted as
        // a file above, only for a byte read — a listing sink reaches a planted value directory here.
        if probe.class == jss_core::VulnClass::PathTraversal && probe.lists_dir {
            match &probe.appended_param {
                Some(ap) => {
                    for value in &ap.values {
                        self.plant_listing_canary(value, self.nonce);
                    }
                }
                None => self.plant_listing_canary("", self.nonce),
            }
        }
        // Try the three-leg read differential before the broad reflected-content payload matrix for
        // every anonymous traversal read. Besides being stronger evidence for a blind read, this
        // keeps URL-sourced sinks tractable: a renderer can expose many query fields, and trying the
        // full filename/encoding matrix for every field may perform hundreds of expensive renders
        // before reaching the one field connected to the sink. The oracle follows the mined query
        // fields in data-flow order and normally reaches that field in a handful of requests. If it
        // cannot distinguish the found and missing branches, the broad matrix remains the fallback.
        let read_oracle_tried_early =
            probe.class == jss_core::VulnClass::PathTraversal && !probe.lists_dir;
        if read_oracle_tried_early
            && let Some(poc) = self.verify_read_oracle(probe, credential.as_ref())
        {
            return Outcome::Verified {
                how: format!("{} {}", poc.method, poc.target),
                poc,
            };
        }
        let attempts = self.credentialed_attempts(&base_attempts, credential.as_ref(), true);
        let tried = attempts.len();
        // First pass carries the synthetic forwarding header (rate-limit de-bucketing); if nothing
        // reproduces, retry once representing the request's true loopback origin (no forwarding
        // header). An app that gates its sink on genuine loopback trust — a management route that
        // treats any forwarding header as a remote proxy hop — refuses the de-bucketed request before
        // the sink, so the honest loopback request is the one that reaches it. The driver already
        // connects from loopback; this never grants access a non-loopback peer would be denied.
        // The forwarding-header retry is an HTTP idea: a socket.io event or MCP call has no such
        // header to drop, so a second pass would only repeat every request.
        let passes: &[bool] = if probe.method.is_remote_call() {
            &[true]
        } else {
            &[true, false]
        };
        for &forward in passes {
            self.omit_forwarding.set(!forward);
            let mut response_controls: std::collections::BTreeMap<String, (Attempt, String)> =
                std::collections::BTreeMap::new();
            for attempt in &attempts {
                if let Some(poc) =
                    self.send_with_response_control(probe, attempt, &mut response_controls)
                {
                    self.omit_forwarding.set(false);
                    return Outcome::Verified {
                        how: format!("{} {}", poc.method, poc.target),
                        poc,
                    };
                }
            }
        }
        self.omit_forwarding.set(false);
        // Fallback for a read sink that consumes the planted file but never echoes it (the handler
        // reads it and then crashes or renders without reflecting its bytes): prove the traversal by
        // a differential file-found/not-found oracle instead of by content in the response.
        if !read_oracle_tried_early
            && let Some(poc) = self.verify_read_oracle(probe, credential.as_ref())
        {
            return Outcome::Verified {
                how: format!("{} {}", poc.method, poc.target),
                poc,
            };
        }
        Outcome::NotReproduced { tried }
    }

    /// Mints and validates the real application session once, before any specialized oracle runs.
    /// Every leg of a differential is decorated from this same credential, so authentication cannot
    /// itself be the difference the oracle observes.
    fn credential_for(&self, probe: &Probe) -> Result<Option<SessionCred>, Box<Outcome>> {
        let Some(boot) = &probe.auth else {
            return Ok(None);
        };
        let mut anonymous = payload::benign(probe);
        if probe.stored_write.is_some() {
            // For a second-order finding the probe describes the read request, while its `entry`
            // describes only where the earlier write stores the payload. The read itself has no
            // body. Sending the benign payload as a GET body can be rejected by the HTTP client
            // before it reaches the application's auth gate, hiding a genuine challenge.
            anonymous.body = None;
            anonymous
                .headers
                .retain(|(name, _)| !name.eq_ignore_ascii_case("content-type"));
        }
        let challenged = self.auth_challenge(std::slice::from_ref(&anonymous));
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            eprintln!(
                "[verify] auth-precondition route-gate={} challenged={} login={:?} register={:?} cookie={}",
                boot.route_gate, challenged, boot.login_paths, boot.register_paths, boot.cookie
            );
        }
        // A route-level auth annotation describes the source deployment, not necessarily the
        // runtime selected for verification. Some packages ship an authenticated appliance start
        // mode and an explicitly open local/container start mode. Observe the concrete route before
        // requiring a session: if it does not challenge, drive it anonymously. Exact sink binding
        // still prevents an unrelated open response from becoming evidence.
        if boot.route_gate && !challenged {
            return Ok(None);
        }
        let gated = !boot.default_credentials || challenged;
        let credential = gated.then(|| self.obtain_session(boot)).flatten();
        if boot.route_gate && credential.is_none() {
            let reason = if boot.login_paths.is_empty() {
                "reaching it needs user authentication, and the running application challenged the request but no login route was found to mint a session".to_owned()
            } else {
                format!(
                    "reaching it needs user authentication; no session could be minted through the app's login route ({})",
                    boot.login_paths.join(", ")
                )
            };
            return Err(Box::new(Outcome::Skipped { reason }));
        }
        if let Some(credential) = credential.as_ref() {
            let authenticated = self.with_credential(&anonymous, Some(credential));
            if boot.route_gate
                && let Some((_, Some(before), _)) = self.fetch_meta(&anonymous)
                && let Some((_, Some(after), _)) = self.fetch_meta(&authenticated)
                && is_gate_refusal(before)
                && (after == before || after == 403)
            {
                let reason = if after == 403 && before != 403 {
                    "reaching it needs a role a self-registered account does not have; the session minted through the app's login route was refused on this route (HTTP 403)".to_owned()
                } else {
                    format!(
                        "reaching it needs user authentication; the session minted through the app's login route was refused on this route (HTTP {after})"
                    )
                };
                return Err(Box::new(Outcome::Skipped { reason }));
            }
        } else if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            eprintln!(
                "[verify] auth-bootstrap could not obtain a session (login={:?} register={:?} default-creds={})",
                boot.login_paths, boot.register_paths, boot.default_credentials
            );
        }
        Ok(credential)
    }

    fn with_credential(&self, attempt: &Attempt, credential: Option<&SessionCred>) -> Attempt {
        match credential {
            Some(SessionCred::Bearer { cookie, token }) => {
                payload::with_session(attempt, cookie, token)
            }
            Some(SessionCred::Cookie { pair }) => payload::with_cookie(attempt, pair),
            None => attempt.clone(),
        }
    }

    fn credentialed_attempts(
        &self,
        attempts: &[Attempt],
        credential: Option<&SessionCred>,
        forms: bool,
    ) -> Vec<Attempt> {
        let mut decorated =
            Vec::with_capacity(attempts.len() * usize::from(forms).saturating_add(1));
        for attempt in attempts {
            let with = self.with_credential(attempt, credential);
            if forms
                && credential.is_some()
                && let Some(form) = payload::urlencoded_twin(&with)
            {
                decorated.push(form);
            }
            decorated.push(with);
        }
        decorated
    }

    /// Drives a second-order finding (see [`super::plan::Probe::stored_write`]): sends each payload
    /// through the request that saves it, then fetches the request named by `probe` itself and checks
    /// *that* response for the canary — the write's own response proves nothing, since the sink runs
    /// only when the stored value is read back. Both requests carry the same minted session when the
    /// finding is login-gated, since account fields can require one session to save and load.
    fn exercise_stored(&mut self, probe: &Probe, write: &super::plan::StoredWrite) -> Outcome {
        let write_probe = Probe {
            method: write.method,
            path: write.path.clone(),
            entry: write.entry.clone(),
            ..probe.clone()
        };
        let write_attempts = payload::attempts(&write_probe, &self.canary, self.nonce);
        let read_target = payload::fill_remaining(&probe.path, &[]);
        let read_verb = probe.method.verb(&probe.entry);
        let cred = match self.credential_for(probe) {
            Ok(credential) => credential,
            Err(outcome) => return *outcome,
        };
        let with_cred = |attempt: &Attempt, credential: Option<&SessionCred>| match credential {
            Some(SessionCred::Bearer { cookie, token }) => {
                payload::with_session(attempt, cookie, token)
            }
            Some(SessionCred::Cookie { pair }) => payload::with_cookie(attempt, pair),
            None => attempt.clone(),
        };
        let tried = write_attempts.len();
        for write_attempt in &write_attempts {
            let decorated_write = with_cred(write_attempt, cred.as_ref());
            let mut read_credential = cred.clone();
            for plant in std::iter::once(decorated_write.clone())
                .chain(payload::urlencoded_twin(&decorated_write))
            {
                // Plants the payload; its own response is not the oracle for a stored value.
                if let Some((_, status, cookies)) = self.fetch_meta(&plant)
                    && status.is_some_and(|code| (200..400).contains(&code))
                    && let Some(pair) = payload::session_cookie_pair(&cookies)
                {
                    // A profile/account write can rotate its session token. Carry the genuine
                    // replacement cookie into the read-back request, otherwise the application
                    // correctly rejects the old session before the stored value reaches the sink.
                    read_credential = Some(SessionCred::Cookie { pair });
                }
            }
            let read_attempt = with_cred(
                &Attempt {
                    verb: read_verb,
                    target: read_target.clone(),
                    body: None,
                    headers: Vec::new(),
                    signal: write_attempt.signal.clone(),
                },
                read_credential.as_ref(),
            );
            if let Some(mut poc) = self.send(&read_attempt) {
                let command =
                    stored_reproduction_command(&decorated_write, &read_attempt, self.port);
                let transcript = self.exact_http_transcript(&read_attempt, &command);
                poc.command = command;
                poc.body = marker_normalized(&decorated_write).1;
                poc.stdout = transcript
                    .as_ref()
                    .map(|output| String::from_utf8_lossy(&output.stdout).into_owned());
                poc.stderr = transcript
                    .as_ref()
                    .map(|output| String::from_utf8_lossy(&output.stderr).into_owned());
                poc.exit_code = transcript.as_ref().and_then(|output| output.status.code());
                poc.output_safety = transcript.map(|_| "oracle-proof".to_owned());
                poc.evidence = format!(
                    "{} (the payload was saved first by {} {})",
                    poc.evidence, decorated_write.verb, decorated_write.target
                );
                return Outcome::Verified {
                    how: format!("{} {}", poc.method, poc.target),
                    poc,
                };
            }
        }
        Outcome::NotReproduced { tried }
    }

    /// Drives a server-reflected XSS: the live app has already been launched, so request its route
    /// with each context-breakout canary placed in the tainted URL input, load the rendered response
    /// in a headless browser, and confirm the injected script executed by finding the value the canary
    /// computes at runtime (the product of two factors) in the final DOM. A reflection the app escapes
    /// never computes that product, so a hit is unambiguous execution — the same thing a victim's
    /// browser would do. Runs in the local browser runtime; Docker reflected-XSS is skipped with a
    /// reason.
    pub fn exercise_reflected_xss(&mut self, probe: &super::plan::ReflectedXss) -> Outcome {
        self.nonce += 1;
        self.proof_sink_hit.set(false);
        self.unbound_effect.set(false);
        // Where each attempt is loaded: the host's Chromium against the local app, or a browser
        // container on the Docker app's private network.
        let (executable, origin) = match &self.runtime {
            Runtime::Local { .. } => match local_browser_executable() {
                Some(executable) => (Some(executable), format!("http://127.0.0.1:{}", self.port)),
                None => {
                    return Outcome::Skipped {
                        reason:
                            "reflected XSS verification needs a Chromium/Chrome browser on the \
                                 host; none was found"
                                .to_owned(),
                    };
                }
            },
            Runtime::Docker => {
                if let Err(error) = self.ensure_xss_browser() {
                    return Outcome::Skipped {
                        reason: format!("the reflected-XSS browser could not start: {error}"),
                    };
                }
                let scheme = if self.tls { "https" } else { "http" };
                (None, format!("{scheme}://{}:{}", self.app, self.port))
            }
        };
        let attempts = super::reflected::reflected_xss_attempts(probe, self.nonce);
        let tried = attempts.len();
        let helper_dir = std::env::temp_dir().join(format!("jss-reflected-{}", run_id()));
        if let Err(error) = std::fs::create_dir_all(&helper_dir) {
            return Outcome::Skipped {
                reason: format!("could not create the browser profile directory: {error}"),
            };
        }
        let mut outcome = Outcome::NotReproduced { tried };
        let mut failed_loads = 0usize;
        for attempt in &attempts {
            let url = format!("{origin}{}", attempt.request_target);
            let marker_before = self.begin_sink_observation();
            let loaded = match (&executable, &self.xss_browser) {
                (Some(executable), _) => run_local_browser_capture(executable, &url, &helper_dir),
                (None, Some(browser)) => docker_browser_capture(browser, &url),
                (None, None) => Err("no browser".to_owned()),
            };
            self.finish_sink_observation(marker_before);
            let dom = match loaded {
                Ok(dom) => dom,
                Err(error) => {
                    if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
                        eprintln!("[verify] reflected-xss browser load {url} failed: {error}");
                    }
                    failed_loads += 1;
                    continue;
                }
            };
            let hit = dom.contains(&attempt.exec_token);
            if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
                eprintln!(
                    "[verify] reflected-xss {} payload={} token={} hit={hit}",
                    attempt.context, attempt.payload, attempt.exec_token
                );
            }
            if self.accept_bound_effect(hit) {
                let target = attempt.request_target.clone();
                outcome = Outcome::Verified {
                    how: format!("browser load {target} ({})", attempt.context),
                    poc: Reproduction {
                        command: format!(
                            "open {}",
                            shell_quote(&format!("http://TARGET_HOST{target}"))
                        ),
                        command_redacted: false,
                        method: "BROWSER".to_owned(),
                        target,
                        headers: Vec::new(),
                        body: None,
                        evidence: format!(
                            "a headless browser rendered the application's HTTP response and executed \
                             the reflected payload `{}` (context: {}): the script computed and wrote \
                             `{}` into the page, which a correctly escaped reflection never does",
                            attempt.payload, attempt.context, attempt.exec_token
                        ),
                        response: reflected_dom_excerpt(&dom, &attempt.exec_token),
                        stdout: None,
                        stderr: None,
                        exit_code: None,
                        output_safety: None,
                        controls: Vec::new(),
                    },
                };
                break;
            }
        }
        let _ = std::fs::remove_dir_all(&helper_dir);
        self.qualify_sink_binding(with_failed_loads(outcome, failed_loads, tried))
    }

    /// The browser container for reflected-XSS probes, started once per session on the app's
    /// private network (it reaches the app by its container name).
    fn ensure_xss_browser(&mut self) -> Result<(), String> {
        if self.xss_browser.is_some() {
            return Ok(());
        }
        let tag = ensure_xss_browser_image()?;
        let name = format!("{}-xss-browser", self.app);
        docker(&[
            "run",
            "-d",
            "--name",
            &name,
            "--network",
            &self.network,
            "--security-opt",
            "no-new-privileges",
            "--shm-size",
            "512m",
            "--memory",
            "2g",
            "--entrypoint",
            "sleep",
            &tag,
            "infinity",
        ])?;
        self.xss_browser = Some(name);
        Ok(())
    }

    // Sink-specific differential oracles live in `sandbox/oracles.rs`.
    // Authentication bootstrap lives in `sandbox/auth.rs`.
    /// Runs one attempt through the driver of its transport — an HTTP request, a socket.io event or
    /// an MCP tool call — and returns the driver's output in the one shape every caller reads: the
    /// response body on stdout and the tagged `__JSS_META__` line on stderr (status, cookies,
    /// content type). The socket and MCP drivers synthesize a status from the call's outcome, so
    /// every oracle, differential and fix control built on a status or a body works over any of them.
    fn drive(&self, attempt: &Attempt) -> Result<Output, String> {
        let marker_before = self.begin_sink_observation();
        let result = (|| {
            if let Some(left) = self.attempt_budget.get() {
                if left == 0 {
                    return Err("the request budget for this candidate is spent".to_owned());
                }
                self.attempt_budget.set(Some(left - 1));
            }
            match attempt.verb {
                "MCP" => {
                    let endpoint = self.mcp_endpoint_or_discover()?;
                    let arguments: serde_json::Value = attempt
                        .body
                        .as_deref()
                        .and_then(|body| serde_json::from_str(body).ok())
                        .unwrap_or_else(|| serde_json::json!({}));
                    let spec = serde_json::json!({
                        "mode": "call", "port": self.port, "tls": self.tls,
                        "endpoint": {"transport": endpoint.transport, "path": endpoint.path},
                        "tool": attempt.target, "arguments": arguments,
                    })
                    .to_string();
                    let output = self.exec(&self.app, &["node", "/jss-mcp-driver.js", &spec])?;
                    self.note_mcp_call(&output);
                    Ok(output)
                }
                "SOCKET" => {
                    let spec =
                        socket_spec(attempt, self.port, self.tls, self.socket_ack_wait(attempt));
                    let output = self.exec(&self.app, &["node", "/jss-socket-driver.js", &spec])?;
                    let (status, _) = parse_driver_meta(&String::from_utf8_lossy(&output.stderr));
                    if status == Some(204) {
                        self.socket_unacked
                            .borrow_mut()
                            .insert(attempt.target.clone());
                    }
                    Ok(output)
                }
                _ => {
                    let spec =
                        request_spec(attempt, self.port, !self.omit_forwarding.get(), self.tls);
                    self.exec(&self.app, &["node", "/jss-driver.js", &spec])
                }
            }
        })();
        self.finish_sink_observation(marker_before);
        match &result {
            Ok(output) => {
                self.driver_successes
                    .set(self.driver_successes.get().saturating_add(1));
                super::emit_verify_progress("request_activity", None, None);
                let (status, _) = parse_driver_meta(&String::from_utf8_lossy(&output.stderr));
                if status.is_some_and(|status| (200..400).contains(&status)) {
                    super::emit_verify_progress("positive_evidence", None, Some("route_reachable"));
                }
            }
            Err(error) => {
                let mut errors = self.driver_errors.borrow_mut();
                if errors.len() < 5 {
                    errors.push(format!(
                        "{} {}: {}",
                        attempt.verb,
                        attempt.target,
                        error.chars().take(240).collect::<String>()
                    ));
                }
            }
        }
        result
    }

    fn begin_sink_observation(&self) -> usize {
        self.last_sink_hit.set(false);
        let Some(binding) = &self.sink_binding else {
            return 0;
        };
        let _ = self.exec(
            &self.app,
            &[
                "sh",
                "-c",
                &format!("rm -f {}", super::sink_binding::HIT_FILE),
            ],
        );
        self.binding_marker_count(binding)
    }

    fn finish_sink_observation(&self, marker_before: usize) {
        let Some(binding) = &self.sink_binding else {
            return;
        };
        for wait in 0..6 {
            let file_hit = self
                .exec(
                    &self.app,
                    &[
                        "sh",
                        "-c",
                        &format!(
                            "test -f {} && cat {} || true",
                            super::sink_binding::HIT_FILE,
                            super::sink_binding::HIT_FILE
                        ),
                    ],
                )
                .ok()
                .is_some_and(|output| {
                    String::from_utf8_lossy(&output.stdout)
                        .lines()
                        .any(|line| line.trim() == binding.token)
                });
            let callback_hit = self.binding_marker_count(binding) > marker_before;
            if file_hit || callback_hit {
                self.last_sink_hit.set(true);
                super::emit_verify_progress("positive_evidence", None, Some("sink_hit"));
                return;
            }
            if wait < 5 {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    }

    fn binding_marker_count(&self, binding: &super::sink_binding::Binding) -> usize {
        let logs = match &self.runtime {
            Runtime::Docker => Command::new("docker")
                .args(["logs", &self.marker])
                .output()
                .map(|output| {
                    let mut logs = String::from_utf8_lossy(&output.stdout).into_owned();
                    logs.push_str(&String::from_utf8_lossy(&output.stderr));
                    logs
                })
                .unwrap_or_default(),
            Runtime::Local { marker_log, .. } => {
                std::fs::read_to_string(marker_log).unwrap_or_default()
            }
        };
        logs.lines()
            .filter(|line| {
                line.split_once("MARKER ")
                    .and_then(|(_, payload)| serde_json::from_str::<MarkerHit>(payload.trim()).ok())
                    .is_some_and(|hit| hit.path.contains(&binding.token))
            })
            .count()
    }

    /// The endpoint MCP calls go to, discovering it with the conventional paths when no discovery
    /// has run yet (a concrete probe replayed cold, as a fix proof does after a relaunch).
    fn mcp_endpoint_or_discover(&self) -> Result<McpEndpoint, String> {
        if let Some(endpoint) = self.mcp_endpoint.borrow().clone() {
            return Ok(endpoint);
        }
        self.mcp_discover_paths(mcp::endpoint_paths(&[]))?;
        self.mcp_endpoint
            .borrow()
            .clone()
            .ok_or_else(|| "no MCP endpoint was discovered".to_owned())
    }

    /// Finds the MCP server a probe is about — at the paths its hints name, then the conventional
    /// ones — and reads its tools; the endpoint it found becomes the one calls are sent to.
    fn mcp_discover(&self, probe: &Probe) -> Result<McpDiscovery, String> {
        self.mcp_discover_paths(mcp::endpoint_paths(
            probe
                .mcp
                .as_ref()
                .map_or(&[][..], |hints| hints.endpoints.as_slice()),
        ))
    }

    /// Finds the MCP server at `paths` and reads its tools, once per set of paths; the endpoint it
    /// found becomes the one calls are sent to.
    fn mcp_discover_paths(&self, paths: Vec<String>) -> Result<McpDiscovery, String> {
        self.mcp_bridge_ready()?;
        let key = paths.join(",");
        let cached = self.mcp_discovery.borrow().get(&key).cloned();
        let found = match cached {
            Some(found) => found,
            None => {
                let spec = serde_json::json!({
                    "mode": "discover", "port": self.port, "tls": self.tls, "paths": paths,
                })
                .to_string();
                let output = self.exec(&self.app, &["node", "/jss-mcp-driver.js", &spec])?;
                let (status, _) = parse_driver_meta(&String::from_utf8_lossy(&output.stderr));
                let found = mcp::parse_discovery(&String::from_utf8_lossy(&output.stdout), status);
                self.mcp_discovery.borrow_mut().insert(key, found.clone());
                found
            }
        };
        if let Ok(discovery) = &found {
            *self.mcp_endpoint.borrow_mut() = Some(McpEndpoint {
                transport: discovery.transport.clone(),
                path: discovery.path.clone(),
                stdio: self.mcp_stdio.borrow().clone(),
            });
        }
        found
    }

    /// For a session launched through the stdio bridge: waits until the bridge has tried its candidate
    /// commands and says which started the server (kept for the reproduction), or why none did. A
    /// session that is the app itself has nothing to wait for.
    fn mcp_bridge_ready(&self) -> Result<(), String> {
        if !self.stdio_bridge || self.mcp_stdio.borrow().is_some() {
            return Ok(());
        }
        let spec = serde_json::json!({
            "mode": "bridge", "port": self.port, "tls": self.tls, "waitMs": 150_000,
        })
        .to_string();
        let output = self.exec(&self.app, &["node", "/jss-mcp-driver.js", &spec])?;
        let command = mcp::parse_bridge(&String::from_utf8_lossy(&output.stdout))?;
        *self.mcp_stdio.borrow_mut() = Some(command);
        Ok(())
    }

    /// Counts an MCP call's outcome toward the candidate being tried: a call the tool's input
    /// schema rejected (status 422) never reached the handler, which no verdict may mistake for the
    /// handler having been tried.
    fn note_mcp_call(&self, output: &Output) {
        let (status, _) = parse_driver_meta(&String::from_utf8_lossy(&output.stderr));
        let mut calls = self.mcp_calls.borrow_mut();
        calls.total += 1;
        if status == Some(422) {
            calls.rejected += 1;
            if calls.first_rejection.is_none() {
                let text = String::from_utf8_lossy(&output.stdout);
                calls.first_rejection = Some(text.trim().chars().take(200).collect());
            }
        }
    }

    /// The concrete (tool, argument) probe the last MCP exercise verified.
    pub fn resolved_mcp_probe(&self) -> Option<Probe> {
        self.mcp_resolved.borrow().clone()
    }

    /// Drives an MCP finding whose tool or argument is not known yet: finds the server, reads its
    /// tools, and tries each (tool, argument) pair that could carry the payload — the finding's own
    /// tool first when it names one — with a bounded number of requests each, so a server of a
    /// hundred tools is not hammered for the one the finding is about. Only a candidate that really
    /// ran its payloads counts as not reproduced: one whose schema rejected every payload, or whose
    /// budget ran out first, was not tested and is reported as skipped, with the reason.
    fn exercise_mcp(&mut self, probe: &Probe, discovery: &McpDiscovery) -> Outcome {
        *self.mcp_resolved.borrow_mut() = None;
        let candidates = match mcp::candidates(probe, &discovery.tools) {
            Ok(candidates) => candidates,
            Err(reason) => return Outcome::Skipped { reason },
        };
        let (mut tried, mut tested) = (0usize, false);
        let mut why: Option<String> = None;
        for candidate in candidates {
            self.attempt_budget.set(Some(mcp::ATTEMPTS_PER_CANDIDATE));
            *self.mcp_calls.borrow_mut() = McpCalls::default();
            let outcome = self.exercise_generic(&candidate);
            let spent = self.attempt_budget.get() == Some(0);
            self.attempt_budget.set(None);
            let calls = std::mem::take(&mut *self.mcp_calls.borrow_mut());
            match outcome {
                Outcome::Verified { .. } => {
                    *self.mcp_resolved.borrow_mut() = Some(candidate);
                    return outcome;
                }
                Outcome::NotReproduced { tried: n } => {
                    tried += n;
                    if calls.total > 0 && calls.rejected == calls.total {
                        why.get_or_insert(format!(
                            "the tool's input schema rejected every payload: {}",
                            calls.first_rejection.unwrap_or_default()
                        ));
                    } else if spent {
                        why.get_or_insert(format!(
                            "the request budget ({}) ran out before `{}` was fully tried",
                            mcp::ATTEMPTS_PER_CANDIDATE,
                            candidate.path
                        ));
                    } else {
                        tested = true;
                    }
                }
                Outcome::Skipped { reason } => {
                    why.get_or_insert(reason);
                }
            }
        }
        match (tested, why) {
            (false, Some(reason)) => Outcome::Skipped { reason },
            _ => Outcome::NotReproduced { tried },
        }
    }

    /// The command that reproduces `attempt` in a report: plain `curl` for an HTTP request, and for
    /// a socket.io event or an MCP call the client that speaks its protocol.
    fn poc_command(&self, attempt: &Attempt) -> String {
        reproduction_command(attempt, self.mcp_endpoint.borrow().as_ref(), self.port)
    }

    /// How long a socket.io emit waits for its ack. An event the handler never acks gives nothing to
    /// wait for, so once one such emit was seen the rest of that event's probes wait only long enough
    /// for their proof signal. A file write is synchronous; a callback started with `fetch` is not,
    /// so it gets a bounded second to reach the marker before the driver returns.
    fn socket_ack_wait(&self, attempt: &Attempt) -> u64 {
        if self.socket_unacked.borrow().contains(&attempt.target) {
            if attempt.signal.service_token().is_some() {
                1000
            } else {
                150
            }
        } else {
            3000
        }
    }

    /// Runs one request through the driver and returns its body, status and `Set-Cookie` headers,
    /// read from the driver's tagged metadata line.
    fn fetch_meta(&self, attempt: &Attempt) -> Option<(String, Option<u16>, Vec<String>)> {
        let output = self.drive(attempt).ok()?;
        let body = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr);
        let (status, cookies) = parse_driver_meta(&stderr);
        Some((body, status, cookies))
    }

    fn fetch(&self, attempt: &Attempt) -> Option<String> {
        let output = self.drive(attempt).ok()?;
        let body = String::from_utf8_lossy(&output.stdout).into_owned();
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            let authenticated = attempt
                .headers
                .iter()
                .any(|(name, _)| super::credential_header(name));
            let request_body = attempt.body.as_deref().map(super::redact_jwts);
            let response = if authenticated {
                format!("[redacted authenticated response: {} bytes]", body.len())
            } else {
                response_excerpt(&super::redact_jwts(&body))
            };
            let target = super::redact_jwts(&attempt.target);
            let stderr = if authenticated {
                "[redacted authenticated driver metadata]".to_owned()
            } else {
                super::redact_jwts(String::from_utf8_lossy(&output.stderr).trim())
            };
            let empty_response_logs = if !body.is_empty() {
                String::new()
            } else if authenticated {
                " app-logs[[redacted authenticated app logs]]".to_owned()
            } else {
                format!(
                    " app-logs[{}]",
                    super::redact_jwts(&self.tail_logs(&self.app))
                )
            };
            eprintln!(
                "[verify] {} {} request-body={:?} -> status {:?} stderr[{}] body[{}]{}",
                attempt.verb,
                target,
                request_body,
                output.status.code(),
                stderr,
                response,
                empty_response_logs
            );
        }
        Some(body)
    }

    /// A fixed response substring is not proof when the harmless form of the same route already
    /// contains it. This matters for `/etc/passwd` traversal and reflected `id` command proofs: a
    /// static/demo response must not be mistaken for execution. Out-of-band and secret-token
    /// signals are already self-authenticating and do not need this extra request.
    fn send_with_response_control(
        &self,
        probe: &Probe,
        attempt: &Attempt,
        cached: &mut std::collections::BTreeMap<String, (Attempt, String)>,
    ) -> Option<Reproduction> {
        let control = match attempt.signal.expected_response_text() {
            Some(expected) => {
                if !cached.contains_key(expected) {
                    let mut control = payload::response_control(probe);
                    for (name, value) in &attempt.headers {
                        if super::credential_header(name)
                            && control
                                .headers
                                .iter()
                                .all(|(existing, _)| !existing.eq_ignore_ascii_case(name))
                        {
                            control.headers.push((name.clone(), value.clone()));
                        }
                    }
                    let response = self.fetch_negative_control(&control)?;
                    cached.insert(expected.to_owned(), (control, response));
                }
                let (control, response) = cached.get(expected)?;
                if response.contains(expected) {
                    return None;
                }
                Some((control, response))
            }
            None => None,
        };
        let mut reproduction = self.send(attempt)?;
        if let Some((attempt, response)) = control {
            reproduction.controls.push(control_observation(
                "harmless input did not contain the proof substring",
                attempt,
                response,
            ));
        }
        Some(reproduction)
    }

    /// Drives a controller-owned negative control without charging it to the candidate's payload
    /// budget or MCP schema statistics. It is still a real request, and [`Self::drive`] still records
    /// transport success/failure: a failed control makes a negative verdict inconclusive. Keeping it
    /// out of `mcp_calls` is essential because an accepted harmless input must not hide that every
    /// exploit payload was rejected by the tool's schema.
    fn fetch_negative_control(&self, attempt: &Attempt) -> Option<String> {
        let budget = self.attempt_budget.replace(None);
        let calls = std::mem::take(&mut *self.mcp_calls.borrow_mut());
        let response = self.fetch(attempt);
        *self.mcp_calls.borrow_mut() = calls;
        self.attempt_budget.set(budget);
        response
    }

    /// Sends one request from inside the app container and checks its signal.
    fn send(&self, attempt: &Attempt) -> Option<Reproduction> {
        // Effect oracles are stateful. A fix replay must prove that *this* request produced a new
        // effect, not reuse the file/marker record left by the original exploit.
        let marker_before = attempt
            .signal
            .service_token()
            .map(|token| marker_hit_count(&self.tail_logs(&self.marker), token))
            .unwrap_or_default();
        if let Signal::FileWritten(path) = &attempt.signal {
            let _ = self.exec(&self.app, &["rm", "-f", path]);
        }
        let output = match self.drive(attempt) {
            Ok(output) => output,
            Err(_) => return None,
        };
        let body = String::from_utf8_lossy(&output.stdout);
        if !body.contains(&self.canary.token)
            && payload::response_contains_canary(&body, &self.canary.token)
        {
            super::emit_verify_progress("positive_evidence", None, Some("canary_partial"));
        }
        let mut captured_command_output = None;
        let reproduced = match &attempt.signal {
            Signal::InResponse
            | Signal::ResponseContains(_)
            | Signal::Base64FileRead { .. }
            | Signal::ComputedResponse { .. } => {
                payload::reproduced(attempt, &self.canary, &body, false, false)
            }
            Signal::FileWritten(path) => {
                let exists = self
                    .exec(&self.app, &["test", "-f", path])
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                payload::reproduced(attempt, &self.canary, &body, exists, false)
            }
            Signal::ServiceReached(token) => {
                let marker_after = self.tail_logs(&self.marker);
                let local_reached = marker_hit_count(&marker_after, token) > marker_before;
                if local_reached {
                    // The isolated marker hit is the exploitation proof. Mirroring that hit to
                    // the public callback only records metadata; a transient callback/API failure
                    // must not turn a reproduced vulnerability into a false negative.
                    self.relay_public_callback(token);
                }
                let public_reached = !local_reached
                    && self
                        .canary
                        .callback_host()
                        .is_some_and(|host| attempt_mentions_host(attempt, host))
                    && self.public_callback_reached(token);
                let reached = local_reached || public_reached;
                payload::reproduced(attempt, &self.canary, &body, false, reached)
            }
            Signal::CommandOutputReached(token) => {
                let marker_after = self.tail_logs(&self.marker);
                let fresh_hit = marker_hit_count(&marker_after, token) > marker_before;
                captured_command_output = fresh_hit
                    .then(|| captured_id_output(&marker_after, token))
                    .flatten();
                if captured_command_output.is_some() {
                    self.relay_public_callback(token);
                }
                payload::reproduced(
                    attempt,
                    &self.canary,
                    &body,
                    false,
                    captured_command_output.is_some(),
                )
            }
        };
        let reproduced = self.accept_bound_effect(reproduced);
        // `JSS_VERIFY_DEBUG=1` prints each request, its response, and the proof decision, to
        // diagnose whether a request reached the sink but failed to satisfy the intended oracle.
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            let authenticated = attempt
                .headers
                .iter()
                .any(|(name, _)| super::credential_header(name));
            let request_body = attempt.body.as_deref().map(super::redact_jwts);
            let response = if authenticated {
                format!("[redacted authenticated response: {} bytes]", body.len())
            } else {
                response_excerpt(&super::redact_jwts(&body))
            };
            let target = super::redact_jwts(&attempt.target);
            let stderr = if authenticated {
                "[redacted authenticated driver metadata]".to_owned()
            } else {
                super::redact_jwts(String::from_utf8_lossy(&output.stderr).trim())
            };
            let signal = match &attempt.signal {
                Signal::InResponse => "canary-in-response",
                Signal::ResponseContains(_) => "expected-substring-in-response",
                Signal::Base64FileRead { .. } => "base64-file-read-in-response",
                Signal::ComputedResponse { .. } => "interpreter-computed-response",
                Signal::FileWritten(_) => "canary-file-written",
                Signal::ServiceReached(_) => "callback-reached",
                Signal::CommandOutputReached(_) => "command-output-callback-reached",
            };
            eprintln!(
                "[verify] {} {} request-body={:?} -> status {:?} stderr[{}] body[{}] signal={} matched={} canary-exists={}",
                attempt.verb,
                target,
                request_body,
                output.status.code(),
                stderr,
                response,
                signal,
                reproduced,
                self.file_exists(&self.canary.planted_file()),
            );
        }
        reproduced.then(|| {
            *self.last_verified_attempt.borrow_mut() = Some(attempt.clone());
            let display = normalized_callback_attempt(attempt, self.canary.callback_host());
            let mut exploit_command = self.poc_command(&display);
            if matches!(&attempt.signal, Signal::InResponse)
                && !body.contains(&self.canary.token)
                && payload::response_contains_canary(&body, &self.canary.token)
            {
                exploit_command = decode_indexed_json_response(&exploit_command);
            }
            let command = self
                .probe_setup
                .borrow()
                .iter()
                .map(|setup| self.poc_command(setup))
                .chain(std::iter::once(exploit_command))
                .collect::<Vec<_>>()
                .join(" && ");
            // The report command replaces the private marker with CALLBACK_HOST. Re-run the same
            // request against the literal isolated marker so callback-based proofs can retain the
            // exact curl transcript without making the disposable app reach the public Internet.
            let executed_command = self
                .probe_setup
                .borrow()
                .iter()
                .map(|setup| literal_reproduction_command(setup, self.port))
                .chain(std::iter::once(literal_reproduction_command(
                    attempt, self.port,
                )))
                .collect::<Vec<_>>()
                .join(" && ");
            let transcript = self.exact_http_transcript(attempt, &executed_command);
            let stdout = transcript
                .as_ref()
                .map(|output| String::from_utf8_lossy(&output.stdout).into_owned());
            Reproduction {
                command,
                command_redacted: false,
                method: display.verb.to_owned(),
                target: display.target.clone(),
                headers: display
                    .headers
                    .iter()
                    .map(|(name, value)| format!("{name}: {value}"))
                    .collect(),
                body: display.body.clone(),
                evidence: observed_evidence(
                    &attempt.signal,
                    self.canary.callback_host(),
                    &body,
                    &self.canary.token,
                    captured_command_output.as_deref(),
                ),
                response: body.trim().to_owned(),
                stdout,
                stderr: transcript
                    .as_ref()
                    .map(|output| String::from_utf8_lossy(&output.stderr).into_owned()),
                exit_code: transcript.as_ref().and_then(|output| output.status.code()),
                output_safety: transcript.map(|_| "oracle-proof".to_owned()),
                controls: Vec::new(),
            }
        })
    }

    /// Execute the exact report command and accept its streams only when that same command repeats
    /// both halves of the proof: the response oracle and the runtime marker for the selected sink.
    /// Protocol helpers and side-effect-only oracles keep their legacy PoC until their reportable
    /// command can be made identical to the transport the verifier drives.
    fn exact_http_transcript(&self, attempt: &Attempt, command: &str) -> Option<Output> {
        if matches!(attempt.verb, "SOCKET" | "MCP")
            || !matches!(
                attempt.signal,
                Signal::InResponse
                    | Signal::ResponseContains(_)
                    | Signal::Base64FileRead { .. }
                    | Signal::ComputedResponse { .. }
                    | Signal::ServiceReached(_)
                    | Signal::CommandOutputReached(_)
            )
        {
            return None;
        }
        let service_marker_before = attempt
            .signal
            .service_token()
            .map(|token| marker_hit_count(&self.tail_logs(&self.marker), token))
            .unwrap_or_default();
        let sink_marker_before = self.begin_sink_observation();
        let output = self.exec(&self.app, &["sh", "-c", command]).ok()?;
        self.finish_sink_observation(sink_marker_before);
        if !output.status.success() {
            return None;
        }
        let body = String::from_utf8_lossy(&output.stdout);
        let service_reached = match &attempt.signal {
            Signal::ServiceReached(token) => {
                marker_hit_count(&self.tail_logs(&self.marker), token) > service_marker_before
            }
            Signal::CommandOutputReached(token) => {
                let logs = self.tail_logs(&self.marker);
                marker_hit_count(&logs, token) > service_marker_before
                    && captured_id_output(&logs, token).is_some()
            }
            _ => false,
        };
        let oracle = payload::reproduced(attempt, &self.canary, &body, false, service_reached);
        let bound = self.sink_binding.is_none() || self.last_sink_hit.get();
        (oracle && bound).then_some(output)
    }

    fn exec(&self, container: &str, cmd: &[&str]) -> Result<Output, String> {
        match &self.runtime {
            Runtime::Docker => exec_in(container, cmd),
            Runtime::Local { app_root, .. } if container == self.app => {
                let (program, args) = cmd
                    .split_first()
                    .ok_or_else(|| "empty local verifier command".to_owned())?;
                let args: Vec<String> = args
                    .iter()
                    .map(|argument| localize_helper_paths(argument))
                    .collect();
                Command::new(program)
                    .args(args)
                    .current_dir(app_root)
                    .output()
                    .map_err(|error| error.to_string())
            }
            Runtime::Local { app_root, .. }
                if self.db.as_deref() == Some(container)
                    || self.redis.as_deref() == Some(container) =>
            {
                let (program, args) = cmd
                    .split_first()
                    .ok_or_else(|| "empty local sidecar command".to_owned())?;
                let mut command = Command::new(program);
                if let Some(path) = &self.service_path {
                    command.env("PATH", path);
                }
                command
                    .args(args)
                    .current_dir(app_root)
                    .output()
                    .map_err(|error| error.to_string())
            }
            Runtime::Local { .. } => Err("unknown local verifier service".to_owned()),
        }
    }

    /// Mirror an isolated marker hit to the registered public callback from the verifier host.
    /// The untrusted application container remains on its `--internal` network; only this fixed,
    /// validated Satori hostname is contacted. The relay carries the target request's method and
    /// user agent as metadata, so the public interaction cannot be mistaken for a direct `curl`
    /// request from the verifier. This is best-effort telemetry: the isolated marker hit remains
    /// the authoritative exploitation signal.
    fn relay_public_callback(&self, token: &str) {
        let Some(host) = self.canary.callback_host() else {
            return;
        };
        let logs = self.tail_logs(&self.marker);
        let Some(hit) = marker_hit(&logs, token) else {
            return;
        };
        let url = format!("https://{host}{}", hit.path);
        let Ok(output) = Command::new("curl")
            .args(callback_relay_args(&url, &hit))
            .output()
        else {
            return;
        };
        let registered_token = host.split('.').next().unwrap_or_default();
        let confirmed = output.status.success()
            && String::from_utf8_lossy(&output.stdout)
                .contains(&format!("CANARY {registered_token}"));
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            eprintln!(
                "[verify] callback relay {} -> status {:?} confirmed={confirmed}",
                url,
                output.status.code()
            );
        }
    }

    fn public_callback_reached(&self, token: &str) -> bool {
        let Some(host) = self.canary.callback_host() else {
            return false;
        };
        let Some(callback_token) = host.strip_suffix(".callback.satori.ci") else {
            return false;
        };
        let Ok(auth) = std::env::var("SATORI_TOKEN") else {
            return false;
        };
        let url = format!("https://api-v2.satori.ci/callbacks/{callback_token}");
        for _ in 0..10 {
            let mut command = Command::new("curl");
            command.args([
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "10",
                "--header",
                &format!("Authorization: Bearer {auth}"),
            ]);
            if let Ok(org) = std::env::var("SATORI_ORGANIZATION") {
                command.args(["--header", &format!("X-Satori-Organization: {org}")]);
            }
            if let Ok(output) = command.arg(&url).output()
                && output.status.success()
                && callback_response_contains(&output.stdout, token)
            {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        false
    }
}

/// Returns the response body from curl's `--include` output. PoCs retain the original stdout so a
/// reviewer sees the status and headers, while exact-command qualification compares the same body
/// the in-process driver observed. Curl emits CRLF on the wire but a few test doubles use LF only.
fn included_http_body(output: &str) -> &str {
    output
        .split_once("\r\n\r\n")
        .or_else(|| output.split_once("\n\n"))
        .map_or(output, |(_, body)| body)
}

/// Reads `rel` as it existed before a local verifier session instrumented it. `overwritten` is
/// populated before every write; Docker sessions leave the checkout unchanged and naturally fall
/// back to disk. Keeping this lookup separate makes the trust boundary regression-testable.
pub(super) fn original_file_content(
    root: &std::path::Path,
    overwritten: &[(String, String)],
    rel: &str,
) -> Result<String, String> {
    let relative = std::path::Path::new(rel);
    if relative.is_absolute()
        || relative
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err(format!("unsupported path `{rel}`"));
    }
    if let Some((_, original)) = overwritten.iter().find(|(name, _)| name == rel) {
        return Ok(original.clone());
    }
    std::fs::read_to_string(root.join(relative))
        .map_err(|error| format!("could not read {rel}: {error}"))
}

/// Per-session fixtures are staged only when the disposable container starts. This keeps the
/// expensive application image reusable while preserving a fresh, valid-JSON canary for every
/// finding.
fn canary_staging_command(canary: &Canary) -> String {
    let marker_files = canary.planted_files().join(" ");
    format!(
        "for f in {marker_files}; do printf '\"CANARY %s\"' '{}' > \"$f\"; done && cp /jss-canary-img-fixture {} && ",
        canary.token,
        canary.planted_image_file()
    )
}

fn attempt_mentions_host(attempt: &Attempt, host: &str) -> bool {
    attempt.target.contains(host)
        || attempt
            .body
            .as_deref()
            .is_some_and(|body| body.contains(host))
        || attempt
            .headers
            .iter()
            .any(|(_, value)| value.contains(host))
}

fn callback_response_contains(body: &[u8], token: &str) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("interactions")
                .and_then(|value| value.as_array())
                .cloned()
        })
        .is_some_and(|interactions| {
            interactions.iter().any(|interaction| {
                interaction.get("protocol").and_then(|value| value.as_str()) == Some("http")
                    && interaction
                        .get("path")
                        .and_then(|value| value.as_str())
                        .is_some_and(|path| path.split('/').any(|segment| segment == token))
            })
        })
}

fn valid_container_workdir(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 512
        && !path.contains("..")
        && path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct MarkerHit {
    method: String,
    path: String,
    #[serde(rename = "userAgent")]
    user_agent: Option<String>,
}

/// The last structured marker record for this probe. The token must occur in the parsed path,
/// never merely elsewhere in a log line.
fn marker_hit(logs: &str, token: &str) -> Option<MarkerHit> {
    logs.lines().rev().find_map(|line| {
        let payload = line.split_once("MARKER ")?.1.trim();
        let hit: MarkerHit = serde_json::from_str(payload).ok()?;
        (hit.path.contains(token)).then_some(hit)
    })
}

/// Number of structured marker records for this token. Fix replays compare this value before and
/// after the request so an earlier callback can never prove a changed candidate exploitable.
fn marker_hit_count(logs: &str, token: &str) -> usize {
    logs.lines()
        .filter_map(|line| {
            let payload = line.split_once("MARKER ")?.1.trim();
            serde_json::from_str::<MarkerHit>(payload).ok()
        })
        .filter(|hit| hit.path.contains(token))
        .count()
}

/// Returns the real stdout transported by a blind command-injection probe. The payload places the
/// URL-encoded output of the read-only Linux `id` command after `/<token>/id/`. Requiring both the
/// per-run token and the shape of `id` output prevents a generic callback from being promoted into
/// command-execution evidence.
fn captured_id_output(logs: &str, token: &str) -> Option<String> {
    let prefix = format!("/{token}/id/");
    logs.lines().rev().find_map(|line| {
        let payload = line.split_once("MARKER ")?.1.trim();
        let hit: MarkerHit = serde_json::from_str(payload).ok()?;
        let encoded = hit.path.split(['?', '#']).next()?.strip_prefix(&prefix)?;
        if encoded.len() > 4_096 {
            return None;
        }
        let decoded = percent_decode_component(encoded)?;
        let output = decoded.trim();
        (output.starts_with("uid=")
            && output.contains(" gid=")
            && output.len() <= 2_048
            && output
                .chars()
                .all(|ch| ch == ' ' || ch == '\t' || !ch.is_control()))
        .then(|| output.to_owned())
    })
}

fn percent_decode_component(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = *bytes.get(index)?;
        if byte == b'%' {
            let high = hex_value(*bytes.get(index + 1)?)?;
            let low = hex_value(*bytes.get(index + 2)?)?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(byte);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn callback_relay_args(url: &str, hit: &MarkerHit) -> Vec<String> {
    let args = vec![
        "--fail".to_owned(),
        "--silent".to_owned(),
        "--show-error".to_owned(),
        "--max-time".to_owned(),
        "10".to_owned(),
        "--header".to_owned(),
        "X-Satori-Callback-Relay: isolated-target".to_owned(),
        "--header".to_owned(),
        format!(
            "X-Satori-Original-Method: {}",
            safe_method(&hit.method).unwrap_or("UNKNOWN")
        ),
        "--user-agent".to_owned(),
        safe_user_agent(hit.user_agent.as_deref()).unwrap_or_default(),
        url.to_owned(),
    ];
    args
}

fn safe_user_agent(value: Option<&str>) -> Option<String> {
    value
        .filter(|value| {
            value.len() <= 512 && !value.bytes().any(|byte| matches!(byte, b'\r' | b'\n'))
        })
        .map(str::to_owned)
}

fn safe_method(value: &str) -> Option<&str> {
    (!value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'-'))
    .then_some(value)
}

fn observed_evidence(
    signal: &Signal,
    callback_host: Option<&str>,
    response: &str,
    canary_token: &str,
    captured_command_output: Option<&str>,
) -> String {
    match signal {
        Signal::InResponse if response.contains(canary_token) => {
            format!(
                "the planted out-of-root file's exact contents `CANARY {canary_token}` appeared in the application response, proving local file content disclosure"
            )
        }
        Signal::InResponse => {
            format!(
                "the application serialized the planted out-of-root file's exact contents as ordered numeric JSON entries; reconstructing those entries produced `CANARY {canary_token}`, proving local file content disclosure"
            )
        }
        Signal::ResponseContains(expected) => {
            if expected == "uid=" {
                "the application response contained the output of the read-only `id` command (`uid=`)"
                    .to_owned()
            } else {
                format!("the application response contained known proof text `{expected}`")
            }
        }
        Signal::Base64FileRead { path, .. } => format!(
            "the injected JavaScript read `{path}` inside the disposable application container; the exact report command decoded the returned file bytes"
        ),
        Signal::ComputedResponse { expected, kind } => match kind {
            payload::ComputedResponseKind::ShellArithmetic => format!(
                "the application response contained `{expected}`, a per-run product computed by the injected shell arithmetic expression; the product was absent from the request and from the harmless same-route control"
            ),
            payload::ComputedResponseKind::JavaScriptArithmetic => format!(
                "the application response contained `{expected}`, a per-run product computed by the injected JavaScript expression; the product was absent from the request and from the harmless same-route control"
            ),
        },
        Signal::FileWritten(path) => {
            format!("the application created the canary file `{path}`")
        }
        Signal::ServiceReached(token) => {
            if callback_host.is_some() {
                format!(
                    "the isolated request carrying CANARY `{token}` was confirmed by the registered Satori callback"
                )
            } else {
                format!("the isolated marker service received CANARY `{token}`")
            }
        }
        Signal::CommandOutputReached(token) => format!(
            "the injected read-only OS command `id` executed; the isolated marker captured its exact stdout `{}` under the per-run token `{token}`",
            captured_command_output.unwrap_or("[missing command output]")
        ),
    }
}

/// Make an indexed JSON content disclosure human-readable in the exact reported transcript. The
/// target is a JavaScript application, so `node` is already present in the verifier container. The
/// decoder is static and reads only curl's stdout; no repository-controlled text enters the script.
fn decode_indexed_json_response(command: &str) -> String {
    format!(
        "{command} | node -e 'const fs=require(\"fs\");const v=JSON.parse(fs.readFileSync(0,\"utf8\"));const a=Array.isArray(v)?v:(v&&v.type===\"Buffer\"&&Array.isArray(v.data)?v.data:Object.keys(v).sort((a,b)=>Number(a)-Number(b)).map(k=>v[k]));process.stdout.write(Buffer.from(a.map(x=>typeof x===\"number\"?x:String(x).charCodeAt(0))))'"
    )
}

fn normalized_callback_attempt(attempt: &Attempt, callback_host: Option<&str>) -> Attempt {
    let Some(host) = callback_host else {
        return attempt.clone();
    };
    let replace = |value: &str| value.replace(host, "CALLBACK_HOST");
    Attempt {
        verb: attempt.verb,
        target: replace(&attempt.target),
        body: attempt.body.as_deref().map(replace),
        headers: attempt
            .headers
            .iter()
            .map(|(name, value)| (name.clone(), replace(value)))
            .collect(),
        signal: attempt.signal.clone(),
    }
}

fn configured_callback_host() -> Result<Option<String>, String> {
    let Some(value) = std::env::var_os("JSS_VERIFY_CALLBACK_URL") else {
        return Ok(None);
    };
    let value = value
        .into_string()
        .map_err(|_| "JSS_VERIFY_CALLBACK_URL is not UTF-8".to_owned())?;
    let host = value
        .strip_prefix("https://")
        .and_then(|rest| rest.strip_suffix('/').or(Some(rest)))
        .ok_or_else(|| "JSS_VERIFY_CALLBACK_URL must use https".to_owned())?;
    let Some(token) = host.strip_suffix(".callback.satori.ci") else {
        return Err("JSS_VERIFY_CALLBACK_URL must use callback.satori.ci".to_owned());
    };
    if token.len() != 32 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(
            "JSS_VERIFY_CALLBACK_URL must contain a 32-character hexadecimal token".to_owned(),
        );
    }
    Ok(Some(host.to_ascii_lowercase()))
}

/// The attempt's target and body with the marker service's address replaced by the placeholder a
/// report shows, so a reproduction never carries the verifier's private marker.
fn marker_normalized(attempt: &Attempt) -> (String, Option<String>) {
    let mut target = attempt.target.clone();
    let mut body = attempt.body.clone();
    if let Some(token) = attempt.signal.service_token() {
        let private = format!("http://jss-marker/{token}");
        let callback = "http://CALLBACK_HOST";
        target = target.replace(&private, callback).replace(
            &format!("http%3A%2F%2Fjss-marker%2F{token}"),
            "http%3A%2F%2FCALLBACK_HOST",
        );
        // Blind command-injection probes address the marker through Node's `{ hostname, path }`
        // options object rather than a literal URL. Normalize that hostname too, including after
        // the surrounding request has percent-encoded the payload. The verifier's literal replay
        // bypasses this function and continues to use the private `jss-marker` DNS alias.
        target = target.replace("jss-marker", "CALLBACK_HOST");
        target = replace_local_marker_url(&target, token, callback);
        body = body.map(|value| {
            replace_local_marker_url(
                &value
                    .replace(&private, callback)
                    .replace("jss-marker", "CALLBACK_HOST"),
                token,
                callback,
            )
        });
    }
    (target, body)
}

/// The command that reproduces `attempt`: for an MCP call, the one that speaks the transport the
/// server was found on; for anything else [`curl_command`].
fn reproduction_command(attempt: &Attempt, mcp: Option<&McpEndpoint>, port: u16) -> String {
    if attempt.verb == "MCP"
        && let Some(endpoint) = mcp
    {
        let (_, body) = marker_normalized(attempt);
        if let Some(command) = &endpoint.stdio {
            return mcp::stdio_poc_command(
                command,
                &attempt.target,
                body.as_deref().unwrap_or("{}"),
            );
        }
        return mcp::poc_command(
            &endpoint.transport,
            &endpoint.path,
            &attempt.target,
            body.as_deref().unwrap_or("{}"),
            port,
        );
    }
    curl_command(attempt, port)
}

/// The command the verifier itself can execute. Unlike the report-facing command, this keeps the
/// disposable marker address intact; it never leaves the private verification network.
fn literal_reproduction_command(attempt: &Attempt, port: u16) -> String {
    append_oracle_filter(raw_curl_command_with_marker(attempt, port, false), attempt)
}

fn curl_command(attempt: &Attempt, port: u16) -> String {
    let command = raw_curl_command(attempt, port);
    append_oracle_filter(command, attempt)
}

/// Builds the request without an output filter so callers that need extra curl options can
/// append them before the pipeline. This matters for stored, second-order reproductions: both
/// the cookie-capture options on the write and the replay cookie on the read must belong to curl,
/// not to the proof filter following it.
fn raw_curl_command(attempt: &Attempt, port: u16) -> String {
    raw_curl_command_with_marker(attempt, port, true)
}

fn raw_curl_command_with_marker(attempt: &Attempt, port: u16, normalize_marker: bool) -> String {
    let (target, body) = if normalize_marker {
        marker_normalized(attempt)
    } else {
        (attempt.target.clone(), attempt.body.clone())
    };
    if attempt.verb == "SOCKET" {
        return socket_command(&target, body.as_deref(), port);
    }
    let mut parts = vec![
        "TARGET_HOST=\"${TARGET_HOST:-127.0.0.1}\";".to_owned(),
        "curl -sS --max-time 15".to_owned(),
        format!("--request {}", attempt.verb),
    ];
    if attempt.signal.service_token().is_some() {
        // Callback proofs are often blind. Preserve the target application's HTTP status and
        // headers alongside its response body so a reviewer can see exactly what the PoC returned.
        parts.push("--include".to_owned());
    }
    if target.starts_with('/') {
        // The verifier sends the request target verbatim. curl otherwise normalizes dot
        // segments before sending them, which makes a copyable traversal PoC differ from the
        // request that was actually verified.
        parts.push("--path-as-is".to_owned());
        parts.push(format!(
            "--url \"http://${{TARGET_HOST}}:{port}{}\"",
            shell_double_quote_contents(&target)
        ));
    } else {
        // An absolute-form request target (`GET http://host/path HTTP/1.1`), sent as is.
        parts.push(format!("--url \"http://${{TARGET_HOST}}:{port}\""));
        parts.push(format!("--request-target {}", shell_quote(&target)));
    }
    let multipart = body
        .as_deref()
        .and_then(|body| curl_multipart(&attempt.headers, body));
    parts.extend(attempt.headers.iter().filter_map(|(name, value)| {
        if multipart.is_some() && name.eq_ignore_ascii_case("content-type") {
            None
        } else {
            Some(format!(
                "--header {}",
                shell_quote(&format!("{name}: {value}"))
            ))
        }
    }));
    if let Some(form) = &multipart {
        parts.extend(form.args.clone());
    } else if let Some(body) = body {
        parts.push(format!("--data-raw {}", shell_quote(&body)));
    }
    let command = parts.join(" \\\n  ");
    if multipart.as_ref().is_some_and(|form| form.has_file) {
        format!(
            "printf %s {} > /tmp/jsspector-upload.bin\n{command}",
            shell_quote("jsspector-upload")
        )
    } else {
        command
    }
}

fn append_oracle_filter(command: String, attempt: &Attempt) -> String {
    match &attempt.signal {
        Signal::ComputedResponse { expected, .. } => {
            format!("{command} | grep -F -m 1 -o -- {}", shell_quote(expected))
        }
        Signal::Base64FileRead { encoded_prefix, .. } => format!(
            "{command} | grep -E -m 1 -o -- {} | base64 -d",
            shell_quote(&format!("{encoded_prefix}[A-Za-z0-9+/=]*"))
        ),
        _ => command,
    }
}

/// A self-contained reproduction for a second-order HTTP finding. The write can rotate the
/// application's session cookie, so the shell captures the genuine replacement from `Set-Cookie`
/// and carries it into the read that reaches the sink. Only the read body is printed.
fn stored_reproduction_command(write: &Attempt, read: &Attempt, port: u16) -> String {
    let mut write_command = raw_curl_command(write, port);
    write_command.push_str(
        " \\\n  --dump-header /tmp/jsspector-stored-poc.headers \\\n  --output /dev/null",
    );
    let mut unauthenticated_read = read.clone();
    unauthenticated_read
        .headers
        .retain(|(name, _)| !super::credential_header(name));
    let mut read_command = raw_curl_command(&unauthenticated_read, port);
    read_command.push_str(" \\\n  --header \"Cookie: $JSS_COOKIE\"");
    let read_command = append_oracle_filter(read_command, &unauthenticated_read);
    format!(
        "{write_command}\n\
JSS_COOKIE=\"$(sed -n 's/^[Ss]et-[Cc]ookie:[[:space:]]*\\([^;]*\\).*/\\1/p' /tmp/jsspector-stored-poc.headers | tail -n 1)\"; \\\n  test -n \"$JSS_COOKIE\";\n\
{read_command}"
    )
}

fn shell_double_quote_contents(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('`', "\\`")
        .replace('$', "\\$")
}

/// Rewrites the ephemeral loopback marker URL used by the local verifier to the same public
/// placeholder emitted for Docker's `jss-marker` hostname. The port is intentionally discovered
/// from the generated value: it is reserved per run and must never leak into a reusable PoC.
fn replace_local_marker_url(value: &str, token: &str, replacement: &str) -> String {
    let mut out = value
        .replace(&format!("http://jss-marker/{token}"), replacement)
        .replace(
            &format!("http%3A%2F%2Fjss-marker%2F{token}"),
            "http%3A%2F%2FCALLBACK_HOST",
        );
    for (prefix, separator) in [
        ("http://0x7f000001:", "/"),
        ("http%3A%2F%2F0x7f000001%3A", "%2F"),
    ] {
        while let Some(start) = out.find(prefix) {
            let tail = &out[start + prefix.len()..];
            let Some(token_at) = tail.find(&format!("{separator}{token}")) else {
                break;
            };
            let end = start + prefix.len() + token_at + separator.len() + token.len();
            let encoded_replacement = if separator == "%2F" {
                "http%3A%2F%2FCALLBACK_HOST"
            } else {
                replacement
            };
            out.replace_range(start..end, encoded_replacement);
        }
    }
    out
}

struct CurlMultipart {
    args: Vec<String>,
    has_file: bool,
}

/// Convert the verifier's canonical multipart body back into readable, copyable curl form
/// arguments for advisory evidence. Malformed or external MIME bodies fall back to data-raw.
fn curl_multipart(headers: &[(String, String)], body: &str) -> Option<CurlMultipart> {
    let content_type = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))?
        .1
        .as_str();
    let boundary = content_type
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix("boundary="))?
        .trim_matches('"');
    if boundary.is_empty() || !content_type.starts_with("multipart/form-data") {
        return None;
    }
    let delimiter = format!("--{boundary}");
    let mut args = Vec::new();
    let mut has_file = false;
    for raw in body.split(&delimiter).skip(1) {
        let raw = raw.trim_start_matches("\r\n");
        if raw.starts_with("--") || raw.trim().is_empty() {
            continue;
        }
        let (head, contents) = raw.split_once("\r\n\r\n")?;
        let contents = contents.strip_suffix("\r\n").unwrap_or(contents);
        let disposition = head.lines().find(|line| {
            line.to_ascii_lowercase()
                .starts_with("content-disposition:")
        })?;
        let name = disposition_parameter(disposition, "name")?;
        if !safe_mime_parameter(&name) {
            return None;
        }
        if disposition_parameter(disposition, "filename").is_some() {
            has_file = true;
            let content_type = head
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(key, value)| {
                        key.eq_ignore_ascii_case("content-type")
                            .then(|| value.trim())
                    })
                })
                .unwrap_or("application/octet-stream");
            args.push(format!(
                "--form {}",
                shell_quote(&format!(
                    "{name}=@/tmp/jsspector-upload.bin;filename=jsspector-upload.bin;type={content_type}"
                ))
            ));
        } else {
            args.push(format!(
                "--form {}",
                shell_quote(&format!("{name}={contents}"))
            ));
        }
    }
    (!args.is_empty()).then_some(CurlMultipart { args, has_file })
}

fn disposition_parameter(line: &str, wanted: &str) -> Option<String> {
    line.split(';').skip(1).find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        key.eq_ignore_ascii_case(wanted)
            .then(|| value.trim().trim_matches('"').to_owned())
    })
}

fn safe_mime_parameter(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'[' | b']')
        })
}

pub(super) fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

impl Session {
    fn container_running(&self, name: &str) -> bool {
        match &self.runtime {
            Runtime::Docker => docker(&["inspect", "-f", "{{.State.Running}}", name])
                .map(|out| out.trim() == "true")
                .unwrap_or(false),
            Runtime::Local { process, .. } if name == self.app => {
                let mut process = process.borrow_mut();
                let Some(child) = process.as_mut() else {
                    return false;
                };
                let group = child.id();
                child.try_wait().is_ok_and(|status| status.is_none())
                    || local_process_group_running(group)
            }
            Runtime::Local { .. } => false,
        }
    }

    fn tail_logs(&self, name: &str) -> String {
        match &self.runtime {
            Runtime::Docker => tail_logs(name),
            Runtime::Local { log, .. } if name == self.app => std::fs::read_to_string(log)
                .map(|text| tail(&text, 50))
                .unwrap_or_default(),
            Runtime::Local { marker_log, .. } if name == self.marker => {
                std::fs::read_to_string(marker_log)
                    .map(|text| tail(&text, 50))
                    .unwrap_or_default()
            }
            Runtime::Local { .. } => String::new(),
        }
    }

    /// Reads a local process's final log only after its descendants have had a short opportunity to
    /// flush their stack trace. Package-manager launchers can exit a few milliseconds before the
    /// Node child finishes writing the error; classifying the partial log misses safe startup
    /// retries that depend on stack frames and makes the same checkout timing-dependent under load.
    fn settled_tail_logs(&self, name: &str) -> String {
        if matches!(&self.runtime, Runtime::Local { .. }) {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        self.tail_logs(name)
    }

    /// Removes the app, the marker service, the network and the image. Safe to call twice.
    pub fn teardown(&mut self) {
        if self.torn_down {
            return;
        }
        self.torn_down = true;
        // A fix attempt the caller did not get to undo must not leave the checkout changed.
        if let Err(error) = self.restore_files() {
            eprintln!("jsspector: {error}");
        }
        match &self.runtime {
            Runtime::Docker => {
                remove_container(&self.app);
                remove_container(&self.marker);
                if let Some(browser) = &self.xss_browser {
                    remove_container(browser);
                }
                if let Some(db) = &self.db {
                    remove_container(db);
                }
                if let Some(redis) = &self.redis {
                    remove_container(redis);
                }
                for (container, _) in &self.sql {
                    remove_container(container);
                }
                let _ = docker(&["network", "rm", &self.network]);
                let _ = docker(&["rmi", "-f", &self.tag]);
            }
            Runtime::Local {
                log,
                process,
                services,
                service_dirs,
                marker_log,
                created_files,
                ..
            } => {
                if let Some(mut child) = process.borrow_mut().take() {
                    stop_local_process(&mut child);
                }
                for mut child in services.borrow_mut().drain(..) {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                let _ = std::fs::remove_file(log);
                let _ = std::fs::remove_file(marker_log);
                for path in created_files {
                    let _ = std::fs::remove_file(path);
                }
                for dir in service_dirs.iter() {
                    let _ = std::fs::remove_dir_all(dir);
                }
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.teardown();
    }
}

// Runtime provisioning, launch discovery and controller helpers live in `sandbox/runtime.rs`.
#[cfg(test)]
mod tests;

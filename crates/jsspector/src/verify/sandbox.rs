//! The container side of `--verify`: build an image from the scanned repo, start the app with no
//! network reach beyond a marker service, drive the derived requests from inside the container,
//! and tear everything down. Everything here shells out to the `docker` CLI; no ports are
//! published and no Rust HTTP client is pulled in — requests are made by Node already present in
//! the image, so all traffic stays on a private network.

use super::payload::{self, Attempt, Canary, Signal};
use super::plan::Probe;
use super::{Outcome, Reproduction};
use serde::Deserialize;
use std::process::{Command, Output, Stdio};
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

/// Read the profiler log, seed one document into every (otherwise empty) collection a profiled command
/// targeted — resolving the collection from the command's own field first, falling back to the `ns` —
/// then disable profiling and drop its capped log so only the seeded documents remain.
const SEED_PROFILED_SCRIPT: &str = "db.getMongo().getDBNames().forEach(function(n){\
    if(['admin','local','config'].indexOf(n)>=0)return;\
    var d=db.getSiblingDB(n);\
    var names={};\
    try{d.getCollection('system.profile').find({}).forEach(function(e){\
      var c=null;\
      if(e.command){c=e.command.find||e.command.findAndModify||e.command.count||\
        e.command.aggregate||e.command.distinct||e.command.update||e.command.delete;}\
      if(!c&&e.ns){var p=e.ns.split('.');p.shift();c=p.join('.');}\
      if(typeof c==='string'&&c.indexOf('system.')!==0)names[c]=1;\
    });}catch(e){}\
    Object.keys(names).forEach(function(c){\
      try{if(d.getCollection(c).countDocuments({})===0)\
        d.getCollection(c).insertOne({jss_seed:1});}catch(e){}\
    });\
    try{d.setProfilingLevel(0);}catch(e){}\
    try{d.getCollection('system.profile').drop();}catch(e){}\
  });";
const REDIS_ALIASES: [&str; 2] = ["redis", "cache"];

/// Whether a Docker daemon is reachable. The CLI on some platforms exits 0 even when it cannot
/// connect, so this checks that `docker info` actually printed a server version, not an error.
pub fn available() -> bool {
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

/// A built image, a private network, a marker service and a running app — one per `scan --verify`
/// run, reused across findings. [`Self::teardown`] removes all of it; [`Drop`] is a backstop.
pub struct Session {
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
    /// fixes its own, the one port it is found listening on (see [`listening_probe`]).
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
    torn_down: bool,
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
        let id = run_id();
        let canary = Canary::new(format!("{id}{}", short_rand()))
            .with_callback_host(configured_callback_host()?);
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

        let mut session = Self {
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
            guarded_modules: entry_file
                .and_then(|entry| std::fs::read_to_string(root.join(entry)).ok())
                .map(|src| guarded_bare_requires(&src).into_iter().collect())
                .unwrap_or_default(),
            torn_down: false,
        };
        if let Err(err) = session.boot() {
            session.teardown();
            return Err(err);
        }
        Ok(session)
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
        }
        if self.redis.is_some() {
            self.start_redis()?;
        }

        // An app that refuses to start without an environment variable its deployment supplies
        // (`NOOBOT_WORKSPACE_ROOT is required`) is started again with it set to a neutral value
        // (see [`required_env`]), a few times at most.
        let mut env: Vec<RequiredEnv> = self.base_env.clone();
        let mut stub_missing_modules = false;
        // Directories the app tried to write into on startup before their parent existed
        // (see [`missing_write_dir`]); mounted as empty writable scratch on the next attempt.
        let mut scratch_dirs: Vec<String> = Vec::new();
        for _ in 0..5 {
            self.run_app(&env, stub_missing_modules, &scratch_dirs)?;
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
            let new_dir = missing_write_dir(&err).filter(|dir| !scratch_dirs.contains(dir));
            if missing.is_empty() && !enable_module_stub && new_dir.is_none() {
                return Err(err);
            }
            let _ = docker(&["rm", "-f", &self.app]);
            env.extend(missing);
            stub_missing_modules |= enable_module_stub;
            if let Some(dir) = new_dir {
                scratch_dirs.push(dir);
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
        scratch_dirs: &[String],
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
        let mut node_options: Vec<String> = Vec::new();
        if self.node_sqlite {
            node_options.push("--experimental-sqlite".to_owned());
        }
        if stub_missing_modules {
            node_options.push("--require=/jss-launch-shim.js".to_owned());
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
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        docker(&args).map_err(|e| format!("could not start the app: {e}"))?;
        Ok(())
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

    /// Polls from inside the app's own container until the app answers on a port, or the
    /// deadline passes, and returns that port.
    fn wait_until_listening(&self) -> Result<u16, String> {
        // Up to ~90s: `npm start` may build first. The probe is one Node connect attempt.
        let script = listening_probe(self.port);
        for _ in 0..90 {
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
                    self.tail_logs(&self.app)
                ));
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        Err("the app did not listen within 90s".to_owned())
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
        // A traversal sink that deletes its argument cannot be proved by reflected content — a
        // successful delete echoes nothing — and the generic climbing attempts would consume the
        // planted canary before any differential ran. Prove it directly: plant a file outside the
        // base directory, drive the handler to remove it by traversal, and confirm it disappeared
        // while a sibling control file planted alongside it survived.
        if probe.class == jss_core::VulnClass::PathTraversal && probe.removes {
            return match self.verify_delete_oracle(probe) {
                Some(poc) => Outcome::Verified {
                    how: format!("{} {}", poc.method, poc.target),
                    poc,
                },
                None => Outcome::NotReproduced { tried: 1 },
            };
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
        let attempts = payload::attempts(probe, &self.canary, self.nonce);
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
                        how: format!("{} {}", attempt.verb, attempt.target),
                        poc,
                    };
                }
            }
        }
        self.omit_forwarding.set(false);
        // Fallback for a read sink that consumes the planted file but never echoes it (the handler
        // reads it and then crashes or renders without reflecting its bytes): prove the traversal by
        // a differential file-found/not-found oracle instead of by content in the response.
        if let Some(poc) = self.verify_read_oracle(probe) {
            return Outcome::Verified {
                how: format!("{} {}", poc.method, poc.target),
                poc,
            };
        }
        Outcome::NotReproduced { tried }
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
        let present = self.fetch(&oracle.present)?;
        let absent = self.fetch(&oracle.absent)?;
        let absent_sub = self.fetch(&oracle.absent_sub)?;
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
        let plant = format!(
            "mkdir -p '{parent}' '{dir}' && : > '{target}' && : > '{control}'",
            dir = oracle.dir,
            target = oracle.target_path,
            control = oracle.control_path,
        );
        let _ = self.exec(&self.app, &["sh", "-c", &plant]);
        // Both planted files must exist before the request, or the differential proves nothing.
        if !self.file_exists(&oracle.target_path) || !self.file_exists(&oracle.control_path) {
            return None;
        }
        let _ = self.fetch(&oracle.present);
        // The target must be gone (the traversal reached it) and the control must survive (the
        // removal was directed by the attacker-controlled path, not an indiscriminate wipe).
        if self.file_exists(&oracle.target_path) || !self.file_exists(&oracle.control_path) {
            return None;
        }
        Some(Reproduction {
            command: curl_command(&oracle.present, self.port),
            method: oracle.present.verb.to_owned(),
            target: oracle.present.target.clone(),
            headers: Vec::new(),
            body: oracle.present.body.clone(),
            evidence:
                "a canary file planted outside the application's base directory was removed by \
                the traversal request while a sibling control file planted alongside it survived, \
                proving the removal opened the attacker-controlled path outside the base directory"
                    .to_owned(),
            response: String::new(),
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
        let Some(case) = payload::sql_cases(probe, &self.canary, self.nonce) else {
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
                        response: truthy.trim().to_owned(),
                    },
                };
            }
            return Outcome::NotReproduced { tried: 5 };
        }
        Outcome::NotReproduced { tried: 2 }
    }

    fn exercise_nosql(&self, probe: &Probe) -> Outcome {
        let cases = payload::nosql_cases(probe, &self.canary, self.nonce);
        let tried = cases.len();
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
                        evidence: format!(
                            concat!(
                                "a match-all operator (`{}: {{$ne}}`) returned a record that the ",
                                "match-none operators (`$eq`, `$in: []`) did not, proving the ",
                                "object was interpreted as a MongoDB query operator rather than ",
                                "a scalar"
                            ),
                            case.field
                        ),
                        response: match_all.trim().to_owned(),
                    },
                };
            }
        }
        Outcome::NotReproduced { tried }
    }

    fn fetch(&self, attempt: &Attempt) -> Option<String> {
        let spec = request_spec(attempt, self.port, !self.omit_forwarding.get());
        let output = self
            .exec(&self.app, &["node", "/jss-driver.js", &spec])
            .ok()?;
        let body = String::from_utf8_lossy(&output.stdout).into_owned();
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            eprintln!(
                "[verify] {} {} body={:?} -> status {:?} body[{}]",
                attempt.verb,
                attempt.target,
                attempt.body,
                output.status.code(),
                body.trim()
            );
        }
        Some(body)
    }

    /// Sends one request from inside the app container and checks its signal.
    fn send(&self, attempt: &Attempt) -> Option<Reproduction> {
        let spec = request_spec(attempt, self.port, !self.omit_forwarding.get());
        let output = match self.exec(&self.app, &["node", "/jss-driver.js", &spec]) {
            Ok(output) => output,
            Err(_) => return None,
        };
        let body = String::from_utf8_lossy(&output.stdout);
        // `JSS_VERIFY_DEBUG=1` prints each request and its response, to diagnose why a finding
        // did or did not reproduce.
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            eprintln!(
                "[verify] {} {} -> status {:?} stderr[{}] body[{}]",
                attempt.verb,
                attempt.target,
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim(),
                body.trim()
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
                let reached = self.tail_logs(&self.marker).contains(token)
                    && self.relay_public_callback(token);
                payload::reproduced(attempt, &self.canary, &body, false, reached)
            }
        };
        reproduced.then(|| Reproduction {
            command: curl_command(attempt, self.port),
            method: attempt.verb.to_owned(),
            target: attempt.target.clone(),
            headers: attempt
                .headers
                .iter()
                .map(|(name, value)| format!("{name}: {value}"))
                .collect(),
            body: attempt.body.clone(),
            evidence: observed_evidence(&attempt.signal, self.canary.callback_host()),
            response: body.trim().to_owned(),
        })
    }

    fn exec(&self, container: &str, cmd: &[&str]) -> Result<Output, String> {
        exec_in(container, cmd)
    }

    /// Mirror an isolated marker hit to the registered public callback from the verifier host.
    /// The untrusted application container remains on its `--internal` network; only this fixed,
    /// validated Satori hostname is contacted. The relay carries the target request's method and
    /// user agent as metadata, so the public interaction cannot be mistaken for a direct `curl`
    /// request from the verifier. A registered canary response is required.
    fn relay_public_callback(&self, token: &str) -> bool {
        let Some(host) = self.canary.callback_host() else {
            return true;
        };
        let logs = self.tail_logs(&self.marker);
        let Some(hit) = marker_hit(&logs, token) else {
            return false;
        };
        let url = format!("https://{host}{}", hit.path);
        let Ok(output) = Command::new("curl")
            .args(callback_relay_args(&url, &hit))
            .output()
        else {
            return false;
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
        confirmed
    }
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
            format!("the application response contained known file content `{expected}`")
        }
        Signal::FileWritten(path) => {
            format!("the application created the canary file `{path}`")
        }
        Signal::ServiceReached(token) => {
            if let Some(host) = callback_host {
                format!(
                    "the isolated request carrying `{token}` was confirmed by the registered Satori callback `{host}`"
                )
            } else {
                format!("the isolated marker service received callback token `{token}`")
            }
        }
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
        body = body.map(|value| value.replace(&private, callback));
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
    parts.extend(
        attempt
            .headers
            .iter()
            .map(|(name, value)| format!("--header {}", shell_quote(&format!("{name}: {value}")))),
    );
    if let Some(body) = body {
        parts.push(format!("--data-raw {}", shell_quote(&body)));
    }
    parts.join(" \\\n  ")
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

impl Session {
    fn container_running(&self, name: &str) -> bool {
        docker(&["inspect", "-f", "{{.State.Running}}", name])
            .map(|out| out.trim() == "true")
            .unwrap_or(false)
    }

    fn tail_logs(&self, name: &str) -> String {
        tail_logs(name)
    }

    /// Removes the app, the marker service, the network and the image. Safe to call twice.
    pub fn teardown(&mut self) {
        if self.torn_down {
            return;
        }
        self.torn_down = true;
        let _ = docker(&["rm", "-f", &self.app]);
        let _ = docker(&["rm", "-f", &self.marker]);
        if let Some(db) = &self.db {
            let _ = docker(&["rm", "-f", db]);
        }
        if let Some(redis) = &self.redis {
            let _ = docker(&["rm", "-f", redis]);
        }
        let _ = docker(&["network", "rm", &self.network]);
        let _ = docker(&["rmi", "-f", &self.tag]);
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.teardown();
    }
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
    let has_build = std::fs::read_to_string(app_root.join("package.json"))
        .is_ok_and(|manifest| has_build_script(&manifest));
    let dockerfile = dockerfile(
        &image,
        install_workdir,
        workdir,
        canary,
        start_command,
        port,
        pm,
        has_build,
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
    let host = DB_ALIASES[0];
    let url = format!("mongodb://{host}:27017/{DB_NAME}");
    [
        ("MONGODB_HOST", host.to_owned()),
        ("MONGO_HOST", host.to_owned()),
        ("MONGODB_PORT", "27017".to_owned()),
        ("MONGO_PORT", "27017".to_owned()),
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
    let host = REDIS_ALIASES[0];
    let url = format!("redis://{host}:6379");
    [
        ("REDIS_HOST", host.to_owned()),
        ("REDIS_PORT", "6379".to_owned()),
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
/// rather than a build error. The npm fallback accepts legacy peer dependencies, which the
/// ecosystem's strict default otherwise rejects.
fn install_command(pm: PackageManager) -> &'static str {
    match pm {
        PackageManager::Npm => {
            "npm ci --no-audit --no-fund || npm install --no-audit --no-fund --legacy-peer-deps || true"
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
fn build_command(pm: PackageManager) -> &'static str {
    match pm {
        PackageManager::Npm => "npm run build --if-present || true",
        PackageManager::Yarn => "yarn build || true",
        PackageManager::Pnpm => "pnpm run build || true",
    }
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
    has_build: bool,
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
    let canary_image_b64 = payload::PLANTED_IMAGE_PNG_BASE64;
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
    let build = if has_build {
        format!("RUN {}\n", build_command(pm))
    } else {
        String::new()
    };
    // Install and build in the directory that owns the manifest and lockfile, then move to the
    // launch directory so the app's `.env` seeding and `CMD` run with its own working directory.
    // When they coincide (an app launched from its own package) this is one directory throughout.
    format!(
        "FROM {image}\n\
         ENV CI=true\n\
         ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0\n\
         ENV TS_NODE_TRANSPILE_ONLY=true\n\
         WORKDIR /app\n\
         COPY . /app\n\
         WORKDIR {install_workdir}\n\
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
         RUN echo {} | base64 -d > /jss-express-host.mjs\n\
         RUN echo {} | base64 -d > /jss-lifecycle-host.mjs\n\
         RUN echo {} | base64 -d > /jss-route-host.mjs\n\
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
        base64(EXPRESS_HOST_JS.as_bytes()),
        base64(LIFECYCLE_HOST_JS.as_bytes()),
        base64(ROUTE_HOST_JS.as_bytes()),
    )
}

/// Strips `workspace:`-protocol dependency specifiers from the install directory's `package.json`
/// before an npm install, since npm cannot resolve that protocol and aborts the entire install on the
/// first one it sees. Edits in place and tolerates a missing or malformed manifest. Dependencies
/// removed here are development-only monorepo tools, never runtime dependencies.
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

/// Whether an environment variable name denotes an external-service credential the sandbox may set
/// to a filler to satisfy a configuration precondition: an `_`-delimited segment of `TOKEN`, `PAT`,
/// `SECRET`, `PASSWORD`, `CREDENTIAL` or `CREDENTIALS` (so `GITHUB_TOKEN`/`GH_TOKEN`/`GITHUB_PAT`
/// qualify but `PATH` does not). Never a variable the sandbox owns.
fn credential_name(name: &str) -> bool {
    const KINDS: [&str; 6] = [
        "TOKEN",
        "PAT",
        "SECRET",
        "PASSWORD",
        "CREDENTIAL",
        "CREDENTIALS",
    ];
    let upper = name.to_ascii_uppercase();
    if upper.starts_with("NODE_") || upper.starts_with("NPM_") {
        return false;
    }
    upper.split('_').any(|segment| KINDS.contains(&segment))
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
            && !word.starts_with("NPM_")
            && !matches!(word, "PORT" | "HOST" | "NODE_ENV")
    };
    let mut out: Vec<RequiredEnv> = Vec::new();
    for line in log.lines() {
        // ASCII lowercasing keeps byte offsets, and a word is ASCII, so offsets stay on
        // character boundaries.
        let lower = line.to_ascii_lowercase();
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
            let demanded = AFTER.iter().any(|p| after.starts_with(p))
                || BEFORE.iter().any(|p| before.ends_with(p));
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
    for rel in stack_app_files(log) {
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
    if name.starts_with("NODE_") || name.starts_with("NPM_") || name.starts_with("ERR_") {
        return false;
    }
    if matches!(name, "PORT" | "HOST" | "NODE_ENV" | "CI") {
        return false;
    }
    db_connection_env()
        .iter()
        .all(|(db_name, _)| db_name != name)
}

/// App-owned JavaScript files named by Node stack frames under the image's `/app` root.
fn stack_app_files(log: &str) -> Vec<String> {
    const PREFIX: &str = "/app/";
    let bytes = log.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut from = 0;
    while let Some(rel) = log[from..].find(PREFIX) {
        let start = from + rel + PREFIX.len();
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
/// runs there). Several candidates and none on `PORT` is ambiguous: not ready.
fn listening_probe(wanted: u16) -> String {
    format!(
        "const fs=require('fs'),net=require('net');const ports=new Set();\
         for(const f of ['/proc/net/tcp','/proc/net/tcp6']){{let t='';try{{t=fs.readFileSync(f,'utf8')}}catch{{}}\
         for(const l of t.split('\\n').slice(1)){{const c=l.trim().split(/\\s+/);\
         const [a,p]=(c[1]||'').split(':');\
         if(c[3]==='0A'&&p&&(/^0+$/.test(a)||a==='0100007F'||a==='00000000000000000000000001000000'))ports.add(parseInt(p,16))}}}}\
         const list=[...ports];const port=ports.has({wanted})||!list.length?{wanted}:(list.length===1?list[0]:0);\
         if(!port)process.exit(1);\
         const hosts=['127.0.0.1','::1'];let hi=0;\
         (function go(){{if(hi>=hosts.length)process.exit(1);\
         net.connect({{port,host:hosts[hi++]}}).on('connect',()=>{{console.log(port);process.exit(0)}}).on('error',()=>go());}})();"
    )
}

/// The app's launch command for the image `CMD`. A launchable package manifest
/// ([`manifest_start_command`]) is preferred; failing that, when the finding's own file
/// (`entry`, relative to `root`) is a self-contained server that constructs a listener and calls
/// `.listen`, it is run directly with `node`. This lets a repository of standalone scripts with no
/// `package.json` still be exercised.
fn start_command(root: &std::path::Path, entry: Option<&std::path::Path>) -> Option<String> {
    if let Some(command) = manifest_start_command(root) {
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
    let main = json?.get("main")?.as_str()?.to_owned();
    let main = package_file(root, &main)?;
    // A `main` that is a plug-in handler module — it registers an HTTP request handler on a
    // host-provided web-server service but never listens itself — would just evaluate and exit under
    // `node <main>`, never binding a port. Mount its registered handler(s) on a throwaway server
    // instead, so a genuinely reachable sink is still exercised.
    if is_plugin_handler(&root.join(&main)) {
        return Some(plugin_host_command(&main));
    }
    Some(format!("[\"node\",\"{main}\"]"))
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
    listens && constructs
}

/// A file of the package by a relative path its manifest gives (`./server.js`), when it exists
/// and its name is plain enough to place in the image `CMD` unquoted: never outside the package.
fn package_file(root: &std::path::Path, path: &str) -> Option<String> {
    let path = path.trim_start_matches("./");
    let safe = !path.is_empty()
        && !path.starts_with('/')
        && !path.split('/').any(|part| part == "..")
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/' | b'@'));
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
        return parent.to_path_buf();
    }
    std::path::PathBuf::new()
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
fn request_spec(attempt: &Attempt, port: u16, forward: bool) -> String {
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
        "{{\"port\":{port},\"method\":\"{}\",\"path\":\"{}\",\"headers\":{{{headers}}},\"body\":{body}}}",
        attempt.verb,
        esc(&attempt.target)
    )
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
const EXPRESS_HOST_JS: &str = r#"
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';

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
import path from 'node:path';
import { pathToFileURL } from 'node:url';

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

/// Sends one request to the app on localhost and prints the response body. Reads its spec from
/// argv[2]. Kept tiny and dependency-free (core `http`).
const DRIVER_JS: &str = r#"
const http = require('http');
const spec = JSON.parse(process.argv[2]);
// An app that binds `localhost` listens on a single loopback address, which may be IPv6 (`::1`)
// rather than IPv4. Try each loopback family in turn so the request reaches the server however it
// bound; a connection error (nothing listening on that family) falls through to the next.
const hosts = ['127.0.0.1','::1'];
let hi = 0;
function attempt(){
  if(hi>=hosts.length){process.exit(0);}
  const host = hosts[hi++];
  let sent = false;
  const done = (data)=>{if(sent){return;} sent=true; try{process.stdout.write(data,()=>process.exit(0));}catch(e){process.exit(0);}};
  const req = http.request({host,port:spec.port,method:spec.method,path:spec.path,headers:spec.headers,timeout:10000},(res)=>{
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
  req.on('error',()=>attempt());
  req.on('timeout',()=>{req.destroy();process.exit(0);});
  if(spec.body){req.write(spec.body);}
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
httpServer.listen(80, '0.0.0.0');
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

/// A self-signed certificate (and its key) for the host `jss-marker`, baked in as a verification
/// fixture — not a secret. The marker serves TLS with it and the app image trusts it as a CA
/// (`NODE_EXTRA_CA_CERTS`), so the app's own `https` verification accepts the marker without being
/// weakened. SAN is `DNS:jss-marker`, matching the network alias; validity runs to 2126.
const MARKER_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIDJDCCAgygAwIBAgIUftLDL4Vr1Ml5LgbJGBgAmUWw810wDQYJKoZIhvcNAQEL
BQAwFTETMBEGA1UEAwwKanNzLW1hcmtlcjAgFw0yNjExMDMyMTQwMjJaGA8yMTI2
MTAxMDIxNDAyMlowFTETMBEGA1UEAwwKanNzLW1hcmtlcjCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBANgmb3Seut5AAC+eYFshT1Mf9lpyRqC0VmGs22N4
a0OKWRVvZ7gUH0ZGK65t9jZ7DiP4vmKMFJnt4RGYoYnqUixhQoxy+weSLLLF1JBh
32sBW/iMy19bsWqmopaX1lAsQDS50oJEUil8Mbt58fyYHhb8dXpICA1x5duRuiUX
BD6KImDyNHCkeq3wkkpyMj1Q1c/lBAV8UVF+SHQn1eIcgExtkpRZzAMmfZHER+PI
NILtINMESEb0BfxnY3s4Kx+nZOoiajBHjNdmbWeolM9gzPUvGApkYz6VANjJwWUg
X2VLfvcHuaviwbkyXzZamSrsAVpd133loAGCLpDWBvnCew0CAwEAAaNqMGgwHQYD
VR0OBBYEFH6cydpB1sESWixE6OIqU2PCkv5gMB8GA1UdIwQYMBaAFH6cydpB1sES
WixE6OIqU2PCkv5gMA8GA1UdEwEB/wQFMAMBAf8wFQYDVR0RBA4wDIIKanNzLW1h
cmtlcjANBgkqhkiG9w0BAQsFAAOCAQEAu1Wrz3WoE2+zeijmE4k3+IPyV5cEfeJi
uNeaMcwcmBWTyvKxFhQJ4ePMCjUOaZFaif5tGvaOo3Vhd6OYZDGbJ24EPYS6fTEc
OrdGqWjIWTeunJ/Z9SUydx/QQZ3jywJFz29mLOwM7yMXqtGCXeW+ej47ga0wiHuJ
JmpJqEubm4VSpLP25/bxdyjj7pVQuNP3F4WdwvmLFO3h+8D+qM1R6aErvVmrf0bJ
IJYc03Nc2HAb8p+qFHZnkq42HuW8v6iBRci1nxu2JKAuYSzS/KOD28nNEXXI8WIG
1OqBPnwKyuYXWys+W2Y2nl1uFx+uFdgdZ+7RBVkJzBRtHkgcorG+nw==
-----END CERTIFICATE-----
"#;

/// The private key for [`MARKER_CERT`]. A throwaway key for an isolated, internal-only test
/// service; it secures nothing and is intentionally public.
const MARKER_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDYJm90nrreQAAv
nmBbIU9TH/ZackagtFZhrNtjeGtDilkVb2e4FB9GRiuubfY2ew4j+L5ijBSZ7eER
mKGJ6lIsYUKMcvsHkiyyxdSQYd9rAVv4jMtfW7FqpqKWl9ZQLEA0udKCRFIpfDG7
efH8mB4W/HV6SAgNceXbkbolFwQ+iiJg8jRwpHqt8JJKcjI9UNXP5QQFfFFRfkh0
J9XiHIBMbZKUWcwDJn2RxEfjyDSC7SDTBEhG9AX8Z2N7OCsfp2TqImowR4zXZm1n
qJTPYMz1LxgKZGM+lQDYycFlIF9lS373B7mr4sG5Ml82Wpkq7AFaXdd95aABgi6Q
1gb5wnsNAgMBAAECggEABTJseIPNOX9Ph6cGupul9z8L8TZoilGIyFeEcWe5hfVh
3yBWrxJDVGtPrQKbR4Pgo8vc/olmaWeYsdWFupi19xTWew3T8ghh+L5oZJll01Oh
UANga7D7JpirQV1POKVZLjb+SHRxWI11EWGzqyJ1imKruj57fIlzhowN+crdbJ95
ZFd+7WKn9JJFSOXJM93973OldCp9pe6Zw6RA2ZdpeDezh/iuV8W7iQcm6yG9yAzh
nlWDLXnzKaLGjlHc7ieSws9Wx54w9caH2tf28fFwAvFEywQpfaJWNorPuCVqIm6L
1NwViJX6IIVCfxPDdvXAAlZN3GeLUhFe9G7l+9YnJQKBgQDzP6JsfiCEY2t7809G
B9WavpgvpkA3xQu/+E1Wnfy0UjKXd5xivaZ5Yp6pHK9PEkxtgmOKxJXMVhvAcuQc
UhsMc37uQye7RAsExcpGahIo7KiF3vL+GYF1UT3SeyA3LrFVI26vQgCaz5MaBslg
bgI4CQB4mTGHEstVNwliv/rIDwKBgQDjeySvJ2JZsoE9tA4B7qFDyIojbyaJdl7w
ZG0bq8N9/trjD8RvTDFznWDazJo7cng6CXoFJKoQ8/p2Q/GjMHsydVKZWqjjpOW5
6D6yZnxUioaVm+fDpM01OKieEphTe77w5eGkjr0vrb4mixxdpcdg4hlxatkniyEV
HEsedPvPIwKBgBII5sb6dvi50k9HU9pSXGDzvp7RybMY1e0uwLUqU4EfEwct5Bdi
DkSzriXFra3EIox//VddiemzfK1BF26OG9lJeuC5c+mretGoxH2CAcSs/zWluQhj
5bhIBLhlTpcozBcO4Hb4Asl3mGV2mVmf7mQvLqzCVuy31QGFahm7OCG7AoGAfZ7A
SFVoc34m7ssivSBpP8RbvGuiDWEn1nqu4gv9XfPCLofDg27BFEaBePJp7ZAuImaf
Un3HyKri0jJ9GxAnyFqPrY4qG+Qw1HQTQ3NjD1CcN7wrxZeZlt1eCETeh6Obcu6P
p88HXHAGxMQnevOUYcUaJc7KcpLbRwwj04Lol58CgYBOU+E5XyTFENcfXQqmevqG
jHsK6ZuxTJBu3/ljnl/s4eDRdDQeWg9jxHjCIb+RZ+lzLDBrK72e8uGTAzy2bJOo
TMKYIU1ehZPUtYF64aOhLdUeKbibo7gMuVOuuNnQn/fQmDyQPv0MAfDeYp5BHMlY
TMvXfMFYx7ZXHLP5nQYIeQ==
-----END PRIVATE KEY-----
"#;

// ----- browser phase (DOM-source XSS and client-side redirects) ---------------------------------

/// The browser-phase base image: Playwright's, which carries Node, Chromium and its system
/// dependencies. Pinned.
const BROWSER_IMAGE: &str = "mcr.microsoft.com/playwright:v1.49.1-jammy";

/// A built browser-phase image, a private network, a marker service, a static file server for the
/// repo, and a browser container — one per `--verify` run that has DOM findings.
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
    torn_down: bool,
}

impl BrowserSession {
    /// Builds the browser-phase image from `root` and starts the marker service, the static file
    /// server and the browser, or returns why it could not.
    pub fn start(root: &std::path::Path) -> Result<Self, String> {
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
    pub fn exercise(&mut self, probe: &super::plan::BrowserProbe) -> Outcome {
        self.nonce += 1;
        let page = match self.find_page(&probe.file) {
            Ok(page) => page,
            Err(reason) => return Outcome::Skipped { reason },
        };
        let attempts = super::browser::browser_attempts(probe, &page, &self.canary, self.nonce);
        let referrer = super::browser::via_referrer(probe)
            .then(|| super::browser::referrer_payload(probe, &self.canary, self.nonce));
        let tried = attempts.len();
        for attempt in &attempts {
            let url = format!("http://jss-app:{}{}", self.port, attempt.url);
            let mut cmd = vec!["node".to_owned(), "/jss-browser.js".to_owned(), url.clone()];
            if let Some((payload, _)) = &referrer {
                cmd.push(payload.clone());
            }
            let args: Vec<&str> = cmd.iter().map(String::as_str).collect();
            let _ = exec_in(&self.browser, &args);
            let hit = referrer
                .as_ref()
                .map_or(attempt.token.as_str(), |(_, t)| t.as_str());
            if tail_logs(&self.marker).contains(hit) {
                return Outcome::Verified {
                    how: format!("browser load {}", attempt.url),
                    poc: Reproduction {
                        command: format!(
                            "Open {} in a browser",
                            shell_quote(&format!(
                                "http://TARGET_HOST:{}{}",
                                self.port, attempt.url
                            ))
                        ),
                        method: "BROWSER".to_owned(),
                        target: attempt.url.clone(),
                        headers: Vec::new(),
                        body: None,
                        evidence: format!(
                            "the isolated marker service received callback token `{hit}`"
                        ),
                        response: String::new(),
                    },
                };
            }
        }
        Outcome::NotReproduced { tried }
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

    pub fn teardown(&mut self) {
        if self.torn_down {
            return;
        }
        self.torn_down = true;
        let _ = docker(&["rm", "-f", &self.app]);
        let _ = docker(&["rm", "-f", &self.marker]);
        let _ = docker(&["rm", "-f", &self.browser]);
        let _ = docker(&["network", "rm", &self.network]);
        let _ = docker(&["rmi", "-f", &self.tag]);
    }
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

/// A static file server for the repo, dependency-free (core `http`).
const SERVE_JS: &str = r#"
const http = require('http');
const fs = require('fs');
const path = require('path');
const root = path.resolve(process.argv[2] || '/app');
const port = Number(process.argv[3] || 3000);
const types = {'.html':'text/html','.htm':'text/html','.js':'text/javascript','.mjs':'text/javascript','.cjs':'text/javascript','.css':'text/css','.json':'application/json','.svg':'image/svg+xml','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.gif':'image/gif','.webp':'image/webp','.ico':'image/x-icon','.map':'application/json','.woff2':'font/woff2','.woff':'font/woff','.ttf':'font/ttf'};
http.createServer((req, res) => {
  try {
    let p = decodeURIComponent(req.url.split('?')[0].split('#')[0]);
    let f = path.join(root, p);
    if (!f.startsWith(root)) { res.writeHead(403); return res.end('x'); }
    let st; try { st = fs.statSync(f); } catch (e) { res.writeHead(404); return res.end('x'); }
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
            s.contains("indexOf('system.')!==0"),
            "skips profiler/system collections"
        );
        assert!(
            s.contains("countDocuments({})===0") && s.contains("insertOne({jss_seed:1})"),
            "seeds only empty collections with the shared seed marker"
        );
        assert!(
            s.contains("setProfilingLevel(0)")
                && s.contains("system.profile').drop()")
                && ENABLE_PROFILING_SCRIPT.contains("setProfilingLevel(2)"),
            "enables then disables profiling and drops its log"
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

    /// Only external-service credential names are set to a filler, and only from the sink's import
    /// graph; the sandbox's own variables and non-credential names (including `PATH`) are left alone.
    #[test]
    fn credential_env_sets_only_credential_named_variables() {
        assert!(credential_name("GITHUB_TOKEN"));
        assert!(credential_name("GH_TOKEN"));
        assert!(credential_name("GITHUB_PAT"));
        assert!(credential_name("SESSION_SECRET"));
        assert!(credential_name("DB_PASSWORD"));
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
            ["NOOBOT_WORKSPACE_ROOT", "DATABASE_URL", "SESSION_SECRET"]
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
        assert_eq!(env[2].value, STRONG_FILLER_SECRET);
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
             if(process.env.ENABLE_PAYMENTS) start();",
        );
        let env = config_env(
            "Error: `key_id` is mandatory\n    at /app/config/razorpay.js:1:1",
            dir.path(),
        );
        let names: Vec<&str> = env.iter().map(|item| item.name.as_str()).collect();
        assert_eq!(names, ["RAZORPAY_KEY", "RAZORPAY_SECRET"]);
        assert!(env.iter().all(|item| item.value == STRONG_FILLER_SECRET));
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
        let spec = request_spec(&attempt, 3000, true);
        // Round-trips as JSON (the driver does the same parse).
        let value: serde_json::Value = serde_json::from_str(&spec).unwrap();
        assert_eq!(value["method"], "POST");
        assert_eq!(value["port"], 3000);
        assert_eq!(value["headers"]["Content-Type"], "application/json");
        assert_eq!(value["body"], "{\"url\":\"http://jss-marker/t\"}");
        // The forwarding header de-buckets a rate limiter by default, but is suppressed on the
        // loopback-origin retry so a genuine loopback request carries no forged proxy hop.
        assert!(value["headers"].get("X-Forwarded-For").is_some());
        let loopback = request_spec(&attempt, 3000, false);
        let loopback_value: serde_json::Value = serde_json::from_str(&loopback).unwrap();
        assert!(loopback_value["headers"].get("X-Forwarded-For").is_none());
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
    }

    fn write(root: &std::path::Path, rel: &str, text: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
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
            true,
        );
        assert!(file.contains("RUN corepack enable"), "{file}");
        assert!(file.contains("yarn build"), "{file}");
        // The canary is planted under its extension variants, so a handler that appends a known
        // extension to the tainted path (`input + '.md'`) still reads the token.
        assert!(file.contains("/jss-canary-read.md"), "{file}");
        // No build step emitted for a package without one.
        let no_build = dockerfile(
            "node:22-slim",
            "/app",
            "/app",
            &canary,
            r#"["npm","start"]"#,
            3000,
            PackageManager::Npm,
            false,
        );
        assert!(!no_build.contains("build"), "{no_build}");
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
            true,
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
            true,
        );
        assert!(!yarn.contains(NPM_WORKSPACE_FIXUP), "{yarn}");
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

        // Findings launched from a shared package manifest keep sharing one session: the directory
        // identifies the single server, and the entry file does not split it.
        write(
            root,
            "svc/package.json",
            r#"{"scripts":{"start":"node a.js"}}"#,
        );
        write(root, "svc/a.js", server);
        write(root, "svc/b.js", server);
        let svc = path("svc");
        assert_eq!(
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
            false,
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
            false,
        );
        assert!(file.contains(r#"printf '"%s"' 'cafed00d'"#), "{file}");
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
            .args(["-e", &listening_probe(port)])
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
            .args(["-e", &listening_probe(port)])
            .output()
            .unwrap();
        assert!(!out.status.success() || std::path::Path::new("/proc/net/tcp").exists());
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
            false,
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
            appended_param: None,
            path_fillers: Vec::new(),
            body_requires: Vec::new(),
            sql: None,
            array_element: false,
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
            appended_param: None,
            path_fillers: Vec::new(),
            body_requires: Vec::new(),
            sql: None,
            array_element: false,
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
            appended_param: None,
            path_fillers: Vec::new(),
            body_requires: Vec::new(),
            sql: None,
            array_element: false,
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
            appended_param: None,
            path_fillers: Vec::new(),
            body_requires: Vec::new(),
            sql: None,
            array_element: false,
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
                assert!(poc.command.contains("id%20%23"), "{}", poc.command);
                assert!(poc.response.contains("uid="), "{}", poc.response);
            }
            other => panic!("command injection should verify, got {other:?}"),
        }
        match &injected {
            Outcome::Verified { poc, .. } => {
                assert!(poc.command.contains("touch%20"), "{}", poc.command);
                assert!(poc.response.contains("done"), "{}", poc.response);
            }
            other => panic!("blind command injection should verify, got {other:?}"),
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

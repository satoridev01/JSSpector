//! The container side of `--verify`: build an image from the scanned repo, start the app with no
//! network reach beyond a marker service, drive the derived requests from inside the container,
//! and tear everything down. Everything here shells out to the `docker` CLI; no ports are
//! published and no Rust HTTP client is pulled in — requests are made by Node already present in
//! the image, so all traffic stays on a private network.

use super::payload::{self, Attempt, Canary, Signal};
use super::plan::Probe;
use super::{Outcome, Reproduction};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const BASE_IMAGE: &str = "node:22-slim";
const DEFAULT_NODE_MAJOR: u32 = 22;

const VERIFY_RUN_LABEL_KEY: &str = "ci.satori.jsspector.verify-run";

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
    canary: Canary,
    /// The container port the app listens on: the one we ask for via `PORT`, or, for an app that
    /// fixes its own, the one port it is found listening on (see [`listening_probe`]).
    port: u16,
    /// Bumped per probe, so one probe's write/service marker never confirms another's.
    nonce: u32,
    torn_down: bool,
}

impl Session {
    /// Builds the image from `root` and starts the app and marker service, or returns why it
    /// could not (no start script, build failure, app never listened). The caller turns an `Err`
    /// here into a skip reason for every drivable finding.
    #[cfg(test)]
    pub fn start(root: &std::path::Path) -> Result<Self, String> {
        Self::start_in(root, std::path::Path::new(""))
    }

    /// Like [`Self::start`], but launches the package at `app` (relative to `root`, as chosen by
    /// [`app_dir`]) while the whole repo stays in the image, so the app can still import files
    /// outside its own directory.
    pub fn start_in(root: &std::path::Path, app_path: &std::path::Path) -> Result<Self, String> {
        let id = run_id();
        let canary = Canary::new(format!("{id}{}", short_rand()))
            .with_callback_host(configured_callback_host()?);
        let tag = format!("jsspector-verify:{id}");
        let network = format!("jss-verify-net-{id}");
        let app = format!("jss-verify-app-{id}");
        let marker = format!("jss-verify-marker-{id}");
        let port = 3000;

        let app_root = root.join(app_path);
        let start_command = start_command(&app_root)
            .ok_or_else(|| "no `start` script in package.json to launch the app".to_owned())?;
        let workdir = container_dir(app_path)
            .ok_or_else(|| format!("unsupported app directory `{}`", app_path.display()))?;

        build_image(
            root,
            &app_root,
            &workdir,
            &tag,
            &canary,
            &start_command,
            port,
        )?;

        // An internal network: DNS between its members, no route to the internet.
        docker(&["network", "create", "--internal", &network])
            .map_err(|e| format!("could not create the private network: {e}"))?;

        let mut session = Self {
            tag,
            network,
            app,
            marker,
            canary,
            port,
            nonce: 0,
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

        // An app that refuses to start without an environment variable its deployment supplies
        // (`NOOBOT_WORKSPACE_ROOT is required`) is started again with it set to a neutral value
        // (see [`required_env`]), a few times at most.
        let mut env: Vec<RequiredEnv> = Vec::new();
        for _ in 0..4 {
            self.run_app(&env)?;
            let err = match self.wait_until_listening() {
                Ok(port) => {
                    self.port = port;
                    return Ok(());
                }
                Err(err) => err,
            };
            let missing: Vec<RequiredEnv> = required_env(&err)
                .into_iter()
                .filter(|wanted| env.iter().all(|have| have.name != wanted.name))
                .collect();
            if missing.is_empty() {
                return Err(err);
            }
            let _ = docker(&["rm", "-f", &self.app]);
            env.extend(missing);
        }
        Err("the app still exited for want of environment variables after four starts".to_owned())
    }

    /// Starts the app container, with `env` on top of the variables every app gets.
    fn run_app(&self, env: &[RequiredEnv]) -> Result<(), String> {
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
        for var in env {
            // A directory the app names by a variable: its own empty scratch space.
            if var.directory {
                args.push("--tmpfs".to_owned());
                args.push(var.value.clone());
            }
            args.push("-e".to_owned());
            args.push(format!("{}={}", var.name, var.value));
        }
        args.push(self.tag.clone());
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        docker(&args).map_err(|e| format!("could not start the app: {e}"))?;
        Ok(())
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
        let attempts = payload::attempts(probe, &self.canary, self.nonce);
        let tried = attempts.len();
        for attempt in &attempts {
            if let Some(poc) = self.send(attempt) {
                return Outcome::Verified {
                    how: format!("{} {}", attempt.verb, attempt.target),
                    poc,
                };
            }
        }
        Outcome::NotReproduced { tried }
    }

    /// Sends one request from inside the app container and checks its signal.
    fn send(&self, attempt: &Attempt) -> Option<Reproduction> {
        let spec = request_spec(attempt, self.port);
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
    /// validated Satori hostname is contacted. A registered canary response is required.
    fn relay_public_callback(&self, token: &str) -> bool {
        let Some(host) = self.canary.callback_host() else {
            return true;
        };
        let logs = self.tail_logs(&self.marker);
        let Some(path) = logs
            .lines()
            .rev()
            .find(|line| line.contains(token))
            .and_then(|line| line.split_once("MARKER ").map(|(_, path)| path.trim()))
        else {
            return false;
        };
        let url = format!("https://{host}{path}");
        let Ok(output) = Command::new("curl")
            .args([
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "10",
                &url,
            ])
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
fn build_image(
    root: &std::path::Path,
    app_root: &std::path::Path,
    workdir: &str,
    tag: &str,
    canary: &Canary,
    start_command: &str,
    port: u16,
) -> Result<(), String> {
    let context = root
        .to_str()
        .ok_or_else(|| "the repository path is not valid UTF-8".to_owned())?;
    let image = base_image(app_root);
    let dockerfile = dockerfile(&image, workdir, canary, start_command, port);
    build_from_dockerfile(&dockerfile, tag, context)
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
fn dockerfile(
    image: &str,
    workdir: &str,
    canary: &Canary,
    start_command: &str,
    port: u16,
) -> String {
    let marker_file = canary.planted_file();
    let token = &canary.token;
    format!(
        "FROM {image}\n\
         WORKDIR /app\n\
         COPY . /app\n\
         WORKDIR {workdir}\n\
         RUN npm ci --no-audit --no-fund || npm install --no-audit --no-fund || true\n\
         RUN for example in .env.example .env.sample .env.template; do \
         if [ ! -e .env ] && [ -f \"$example\" ]; then cp \"$example\" .env; fi; done\n\
         RUN printf '%s' '{token}' > {marker_file}\n\
         RUN echo {} | base64 -d > /jss-driver.js\n\
         RUN echo {} | base64 -d > /jss-marker.js\n\
         RUN echo {} | base64 -d > /jss-marker.crt\n\
         RUN echo {} | base64 -d > /jss-marker.key\n\
         ENV NODE_EXTRA_CA_CERTS=/jss-marker.crt\n\
         ENV PORT={port}\n\
         ENV HOST=0.0.0.0\n\
         CMD {start_command}\n",
        base64(DRIVER_JS.as_bytes()),
        base64(MARKER_JS.as_bytes()),
        base64(MARKER_CERT.as_bytes()),
        base64(MARKER_KEY.as_bytes()),
    )
}

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
                let last = word.rsplit('_').next().unwrap_or(word);
                let (value, directory) = match last {
                    "ROOT" | "DIR" | "DIRECTORY" | "PATH" | "HOME" | "FOLDER" => {
                        (format!("/jss-env/{}", word.to_ascii_lowercase()), true)
                    }
                    "URL" | "URI" => ("http://jss-filler.test/".to_owned(), false),
                    _ => ("jsspector".to_owned(), false),
                };
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
         net.connect({{port,host:'127.0.0.1'}}).on('connect',()=>{{console.log(port);process.exit(0)}}).on('error',()=>process.exit(1));"
    )
}

/// The app's launch command for the image `CMD`: `npm start` when the package has a start
/// script (explicit, and what most Node servers document); otherwise the package's own entry
/// point, its `main` file, run with `node` — what a service package without scripts is started
/// with. `None` when the package declares neither.
fn start_command(root: &std::path::Path) -> Option<String> {
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
    let main = json?.get("main")?.as_str()?.to_owned();
    package_file(root, &main).map(|main| format!("[\"node\",\"{main}\"]"))
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
/// ancestor with a start script, and the repo root when none has one.
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
        && start_command(&root.join(nearest)).is_some()
    {
        return nearest.clone();
    }
    packages
        .into_iter()
        .find(|dir| {
            std::fs::read_to_string(root.join(dir).join("package.json"))
                .is_ok_and(|manifest| has_start_script(&manifest))
        })
        .unwrap_or_default()
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
fn request_spec(attempt: &Attempt, port: u16) -> String {
    let headers = attempt
        .headers
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

/// Sends one request to the app on localhost and prints the response body. Reads its spec from
/// argv[2]. Kept tiny and dependency-free (core `http`).
const DRIVER_JS: &str = r#"
const http = require('http');
const spec = JSON.parse(process.argv[2]);
const req = http.request({host:'127.0.0.1',port:spec.port,method:spec.method,path:spec.path,headers:spec.headers,timeout:10000},(res)=>{
  let data='';
  res.on('data',(c)=>{data+=c; if(data.length>65536){res.destroy();}});
  res.on('end',()=>{process.stdout.write(data);process.exit(0);});
});
// An upgrade request completes with an 'upgrade' event instead of a response; the out-of-band
// marker signal is what confirms it, so just end the request once it is answered either way.
req.on('upgrade',(res,socket)=>{try{socket.destroy();}catch(e){}process.exit(0);});
req.on('error',()=>process.exit(0));
req.on('timeout',()=>{req.destroy();process.exit(0);});
if(spec.body){req.write(spec.body);}
req.end();
"#;

/// Records the path of every request it receives, on stdout, so a marker hit shows in the
/// container logs. Listens on HTTP port 80 and, when the planted certificate is present, HTTPS
/// port 443 — so an outbound request whose host (not whole URL) is attacker-controlled still
/// lands here even when the app uses `https`/`http.request` against a fixed port. The certificate
/// is trusted by the app through `NODE_EXTRA_CA_CERTS`, so TLS verification passes honestly
/// instead of being disabled.
const MARKER_JS: &str = r#"
const http = require('http');
const log = (req, res) => { console.log('MARKER ' + req.url); res.end('ok'); };
// An outbound request whose host is attacker-controlled may be forwarded with upgrade headers
// (a proxied WebSocket/upgrade request). Record those too, so a reached-service signal is seen
// however the request arrives, then drop the raw socket.
const logUpgrade = (req, socket) => { console.log('MARKER ' + req.url); try { socket.destroy(); } catch (e) {} };
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
        assert_eq!(env[2].value, "jsspector");
        assert!(required_env("the app did not listen within 90s").is_empty());
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
        assert!(command.contains("--url 'http://TARGET_HOST:8000/x?u=1'"));
        assert!(!command.contains("--request-target"));
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
        let spec = request_spec(&attempt, 3000);
        // Round-trips as JSON (the driver does the same parse).
        let value: serde_json::Value = serde_json::from_str(&spec).unwrap();
        assert_eq!(value["method"], "POST");
        assert_eq!(value["port"], 3000);
        assert_eq!(value["headers"]["Content-Type"], "application/json");
        assert_eq!(value["body"], "{\"url\":\"http://jss-marker/t\"}");
    }

    fn write(root: &std::path::Path, rel: &str, text: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
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
            start_command(&root.join("svc")).as_deref(),
            Some(r#"["node","index.js"]"#)
        );
        assert_eq!(start_command(root).as_deref(), Some(r#"["npm","start"]"#));
        assert_eq!(start_command(&root.join("lib/util")), None);
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
        assert_eq!(start_command(root).as_deref(), Some(r#"["npm","start"]"#));
        write(root, "scripts/start.js", "");
        assert_eq!(
            start_command(root).as_deref(),
            Some(r#"["node","scripts/start.js"]"#)
        );
        write(
            root,
            "package.json",
            r#"{"scripts":{"start":"node ../outside.js &"}}"#,
        );
        assert_eq!(start_command(root).as_deref(), Some(r#"["npm","start"]"#));
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
            assert_eq!(start_command(root), None, "main {main:?}");
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
            &canary,
            r#"["node","index.js"]"#,
            3000,
        );
        let copy = file.find("COPY . /app\n").unwrap();
        let workdir = file.find("WORKDIR /app/svc\n").unwrap();
        let install = file.find("RUN npm ci").unwrap();
        assert!(copy < workdir && workdir < install, "{file}");
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
        };
        let confined = Probe {
            method: Method::Get,
            path: "/safe".to_owned(),
            entry: Entry::Query("name".to_owned()),
            class: VulnClass::PathTraversal,
            siblings: Vec::new(),
            gate_paths: Vec::new(),
        };
        let command = Probe {
            method: Method::Get,
            path: "/ping".to_owned(),
            entry: Entry::Query("host".to_owned()),
            class: VulnClass::CommandInjection,
            siblings: Vec::new(),
            gate_paths: Vec::new(),
        };
        let ssrf = Probe {
            method: Method::Get,
            path: "/fetch".to_owned(),
            entry: Entry::Query("url".to_owned()),
            class: VulnClass::Ssrf,
            siblings: Vec::new(),
            gate_paths: Vec::new(),
        };
        let vulnerable = session.exercise(&traversal);
        let safe = session.exercise(&confined);
        let injected = session.exercise(&command);
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
        assert!(
            matches!(injected, Outcome::Verified { .. }),
            "command injection should verify, got {injected:?}"
        );
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
        });
        let safe = session.exercise(&BrowserProbe {
            file: "safe.html".to_owned(),
            vector: UrlVector::Search,
            sink: BrowserSink::Html,
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

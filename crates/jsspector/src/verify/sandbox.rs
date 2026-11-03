//! The container side of `--verify`: build an image from the scanned repo, start the app with no
//! network reach beyond a marker service, drive the derived requests from inside the container,
//! and tear everything down. Everything here shells out to the `docker` CLI; no ports are
//! published and no Rust HTTP client is pulled in — requests are made by Node already present in
//! the image, so all traffic stays on a private network.

use super::Outcome;
use super::payload::{self, Attempt, Canary, Signal};
use super::plan::Probe;
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

/// The base image. A pinned slim Node: present everywhere, has `node` for the driver, no app of
/// its own.
const BASE_IMAGE: &str = "node:20-slim";

/// An optional supervisor-supplied label lets a caller remove only this run's resources if
/// the scanner is interrupted before its normal teardown can run.
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
    /// The container port the app listens on (we set it, via `PORT`).
    port: u16,
    /// Bumped per probe, so one probe's write/service marker never confirms another's.
    nonce: u32,
    torn_down: bool,
}

impl Session {
    /// Builds the image from `root` and starts the app and marker service, or returns why it
    /// could not (no start script, build failure, app never listened). The caller turns an `Err`
    /// here into a skip reason for every drivable finding.
    pub fn start(root: &std::path::Path) -> Result<Self, String> {
        let id = run_id();
        let canary = Canary::new(format!("{id}{}", short_rand()));
        let tag = format!("jsspector-verify:{id}");
        let network = format!("jss-verify-net-{id}");
        let app = format!("jss-verify-app-{id}");
        let marker = format!("jss-verify-marker-{id}");
        let port = 3000;

        let start_command = start_command(root)
            .ok_or_else(|| "no `start` script in package.json to launch the app".to_owned())?;

        build_image(root, &tag, &canary, &start_command, port)?;

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
    fn boot(&self) -> Result<(), String> {
        // The marker service: records every path it is asked for. Reached only from inside the
        // private network, as `jss-marker`.
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

        // The app: on the private network, hardened, its scratch space in tmpfs, no extra
        // privileges, bounded memory, CPUs and processes.
        docker(&[
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
            &self.tag,
        ])
        .map_err(|e| format!("could not start the app: {e}"))?;

        self.wait_until_listening()
    }

    /// Polls the app's port from inside its own container until it answers or the deadline
    /// passes.
    fn wait_until_listening(&self) -> Result<(), String> {
        // Up to ~90s: `npm start` may build first. The probe is one Node connect attempt.
        for _ in 0..90 {
            let probe = self.exec(
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
            if self.send(attempt) {
                return Outcome::Verified {
                    how: format!("{} {}", attempt.verb, attempt.target),
                };
            }
        }
        Outcome::NotReproduced { tried }
    }

    /// Sends one request from inside the app container and checks its signal.
    fn send(&self, attempt: &Attempt) -> bool {
        let spec = request_spec(attempt, self.port);
        let output = match self.exec(&self.app, &["node", "/jss-driver.js", &spec]) {
            Ok(output) => output,
            Err(_) => return false,
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
        match &attempt.signal {
            Signal::InResponse => payload::reproduced(attempt, &self.canary, &body, false, false),
            Signal::FileWritten(path) => {
                let exists = self
                    .exec(&self.app, &["test", "-f", path])
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                payload::reproduced(attempt, &self.canary, &body, exists, false)
            }
            Signal::ServiceReached(token) => {
                let reached = self.tail_logs(&self.marker).contains(token);
                payload::reproduced(attempt, &self.canary, &body, false, reached)
            }
        }
    }

    fn exec(&self, container: &str, cmd: &[&str]) -> Result<Output, String> {
        exec_in(container, cmd)
    }

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
    tag: &str,
    canary: &Canary,
    start_command: &str,
    port: u16,
) -> Result<(), String> {
    let context = root
        .to_str()
        .ok_or_else(|| "the repository path is not valid UTF-8".to_owned())?;
    let dockerfile = dockerfile(canary, start_command, port);
    build_from_dockerfile(&dockerfile, tag, context)
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
fn dockerfile(canary: &Canary, start_command: &str, port: u16) -> String {
    let marker_file = canary.planted_file();
    let token = &canary.token;
    format!(
        "FROM {BASE_IMAGE}\n\
         WORKDIR /app\n\
         COPY . /app\n\
         RUN npm ci --no-audit --no-fund || npm install --no-audit --no-fund || true\n\
         RUN printf '%s' '{token}' > {marker_file}\n\
         RUN echo {} | base64 -d > /jss-driver.js\n\
         RUN echo {} | base64 -d > /jss-marker.js\n\
         ENV PORT={port}\n\
         ENV HOST=0.0.0.0\n\
         CMD {start_command}\n",
        base64(DRIVER_JS.as_bytes()),
        base64(MARKER_JS.as_bytes()),
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

/// The app's launch command for the image `CMD`. Only `npm start` in v1: explicit, and what most
/// Node servers document. `None` when there is no start script.
fn start_command(root: &std::path::Path) -> Option<String> {
    let manifest = std::fs::read_to_string(root.join("package.json")).ok()?;
    // A cheap check: a `"start"` key under a `"scripts"` object. Good enough to decide launch;
    // the real command runs through npm.
    let scripts = manifest.split("\"scripts\"").nth(1)?;
    let head = &scripts[..scripts.len().min(2000)];
    if head.contains("\"start\"") {
        Some("[\"npm\",\"start\"]".to_owned())
    } else {
        None
    }
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

/// Label resource creation only; probes, execution and teardown keep their original arguments.
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
req.on('error',()=>process.exit(0));
req.on('timeout',()=>{req.destroy();process.exit(0);});
if(spec.body){req.write(spec.body);}
req.end();
"#;

/// Records the path of every request it receives, on stdout, so a marker hit shows in the
/// container logs. Listens on port 80 on the private network.
const MARKER_JS: &str = r#"
const http = require('http');
http.createServer((req,res)=>{console.log('MARKER '+req.url);res.end('ok');}).listen(80,'0.0.0.0');
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
        };
        let confined = Probe {
            method: Method::Get,
            path: "/safe".to_owned(),
            entry: Entry::Query("name".to_owned()),
            class: VulnClass::PathTraversal,
        };
        let command = Probe {
            method: Method::Get,
            path: "/ping".to_owned(),
            entry: Entry::Query("host".to_owned()),
            class: VulnClass::CommandInjection,
        };
        let ssrf = Probe {
            method: Method::Get,
            path: "/fetch".to_owned(),
            entry: Entry::Query("url".to_owned()),
            class: VulnClass::Ssrf,
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

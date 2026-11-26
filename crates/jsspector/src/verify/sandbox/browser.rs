use super::*;
use crate::verify::{browser as browser_payload, plan, sink_binding};

/// The image the reflected-XSS browser container runs: the browser phase's Playwright browser
/// and driver, without the repository. Built once and kept, keyed by its content.
pub(super) fn ensure_xss_browser_image() -> Result<String, String> {
    use std::hash::{Hash, Hasher};
    let dockerfile = format!(
        "FROM {BROWSER_IMAGE}\n\
         RUN mkdir -p /opt/pw && cd /opt/pw && npm init -y >/dev/null 2>&1 && \
             PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm install playwright@1.49.1 --no-audit --no-fund\n\
         RUN echo {} | base64 -d > /jss-browser.js\n\
         ENV NODE_PATH=/opt/pw/node_modules\n",
        base64(BROWSER_JS.as_bytes()),
    );
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    dockerfile.hash(&mut hasher);
    let tag = format!("jsspector-verify-xss-browser:{:016x}", hasher.finish());
    if docker(&["image", "inspect", &tag]).is_ok() {
        return Ok(tag);
    }
    let context = tempfile::tempdir().map_err(|error| format!("build context: {error}"))?;
    let context_path = context
        .path()
        .to_str()
        .ok_or_else(|| "the build context path is not valid UTF-8".to_owned())?;
    build_from_dockerfile(&dockerfile, &tag, context_path)?;
    Ok(tag)
}

/// The framed page's DOM a harness load mirrored into its own (`m=1`), if it did.
pub(super) fn mirrored(dom: &str) -> Option<&str> {
    const MARK: &str = "__JSS_MIRROR__";
    let start = dom.find(MARK)? + MARK.len();
    let end = start + dom.get(start..)?.find(MARK)?;
    dom.get(start..end)
}

/// A browser-driven outcome with the loads that failed taken into account. An attempt the browser
/// never loaded was not tried: without a hit, a failed load leaves the finding undecided rather than
/// not reproduced, so a fix proof never mistakes a browser that could not load the changed page for
/// an exploit that stopped.
pub(super) fn with_failed_loads(outcome: Outcome, failed_loads: usize, tried: usize) -> Outcome {
    if failed_loads > 0 && matches!(outcome, Outcome::NotReproduced { .. }) {
        return Outcome::Skipped {
            reason: format!("the browser failed to load {failed_loads} of {tried} attempts"),
        };
    }
    outcome
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
    /// Files a fix candidate overwrote in the checkout, with their original content, written back by
    /// [`Self::restore_files`] (and teardown).
    overwritten: Vec<(String, String)>,
    sink_binding: Option<sink_binding::Binding>,
    last_sink_hit: std::cell::Cell<bool>,
    proof_sink_hit: std::cell::Cell<bool>,
    unbound_effect: std::cell::Cell<bool>,
    /// Set when `root` is a disposable working copy whose front end is bundled from source by a
    /// build step (esbuild/webpack/vite/...). The served page loads the built bundle, not the source
    /// module, so after instrumenting a source file the bundle is rebuilt so the change takes effect.
    web_build: Option<WebBuild>,
    /// Keeps the working copy alive for the session; dropped (and removed) on teardown.
    build_tempdir: Option<tempfile::TempDir>,
}

/// A front-end build that turns source modules into the bundle an HTML page actually loads. `root`
/// is a disposable copy of the repository (the original target is never written); `cmd` is the npm
/// run-script arguments, and `home` a private npm/HOME directory isolated from the scanner's.
struct WebBuild {
    cmd: Vec<String>,
    home: std::path::PathBuf,
}

impl BrowserSession {
    /// Whether a fix candidate can be tried: the static server reads each file on every request
    /// (the checkout itself locally, the image's copy in Docker), so a changed file takes effect on
    /// the next load.
    pub fn can_relaunch(&self) -> bool {
        !self.torn_down
    }

    /// Source content before the browser session added its exact-sink marker or tried a fix.
    pub fn original_file(&self, rel: &str) -> Result<String, String> {
        super::original_file_content(&self.root, &self.overwritten, rel)
    }

    /// Writes each `(path, content)` (relative to the repository root) where the static server
    /// serves it from — the checkout locally, the app container in Docker — remembering each
    /// original for [`Self::restore_files`]. The browser starts each load with a fresh profile,
    /// so the next load serves the change.
    pub fn relaunch_with_files(
        &mut self,
        files: &[(String, String)],
        allow_removed_sink: bool,
    ) -> Result<(), String> {
        for (rel, content) in files {
            if std::path::Path::new(rel)
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
            {
                return Err(format!("unsupported path `{rel}`"));
            }
            if !self.overwritten.iter().any(|(name, _)| name == rel) {
                let original = std::fs::read_to_string(self.root.join(rel))
                    .map_err(|error| format!("could not read {rel}: {error}"))?;
                self.overwritten.push((rel.clone(), original));
            }
            let content = match &self.sink_binding {
                Some(binding) if binding.file == *rel => match binding.instrument(content) {
                    Ok(instrumented) => instrumented,
                    Err(_) if allow_removed_sink => content.clone(),
                    Err(error) => return Err(error),
                },
                _ => content.clone(),
            };
            self.serve_file(rel, &content)?;
        }
        Ok(())
    }

    pub fn activate_sink(&mut self, finding: &jss_core::Finding) -> Result<(), String> {
        if self.sink_binding.is_some() || !self.overwritten.is_empty() {
            self.restore_files()?;
            self.sink_binding = None;
        }
        let token = format!("{}-sink-{}", self.canary.token, finding.fingerprint);
        let callback = self.canary.service_url_for_token(&token);
        let mut binding = sink_binding::Binding::for_finding(finding, token, callback);
        let source = std::fs::read_to_string(self.root.join(&binding.file)).map_err(|error| {
            format!(
                "could not read {} for exact runtime binding: {error}",
                binding.file
            )
        })?;
        let instrumented = binding.instrument_original(&source)?;
        self.overwritten.push((binding.file.clone(), source));
        if let Err(error) = self.serve_file(&binding.file, &instrumented) {
            self.overwritten.clear();
            return Err(error);
        }
        self.rebuild_bundle()?;
        self.sink_binding = Some(binding);
        Ok(())
    }

    /// Writes back every file a fix candidate overwrote.
    pub fn restore_files(&mut self) -> Result<(), String> {
        let mut failures = Vec::new();
        for (rel, original) in std::mem::take(&mut self.overwritten) {
            if let Err(error) = self.serve_file(&rel, &original) {
                failures.push(format!("{rel}: {error}"));
            }
        }
        if failures.is_empty() {
            self.rebuild_bundle()?;
            Ok(())
        } else {
            Err(format!(
                "could not restore files a fix candidate changed: {}",
                failures.join("; ")
            ))
        }
    }

    /// Rebuilds the front-end bundle from the (possibly instrumented) working-copy source and, for
    /// Docker, copies every file the build changed into the running static server. A no-op when the
    /// front end is loaded directly (no bundle step).
    fn rebuild_bundle(&self) -> Result<(), String> {
        if self.torn_down {
            return Ok(());
        }
        let Some(build) = &self.web_build else {
            return Ok(());
        };
        let before = std::time::SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(2))
            .unwrap_or(std::time::UNIX_EPOCH);
        run_npm(&self.root, &build.home, &build.cmd)
            .map_err(|error| format!("rebuilding the front-end bundle: {error}"))?;
        if let BrowserRuntime::Docker = self.runtime {
            for rel in files_modified_since(&self.root, before) {
                let source = self.root.join(&rel);
                let Some(src) = source.to_str() else {
                    continue;
                };
                docker(&["cp", src, &format!("{}:/app/{rel}", self.app)]).map_err(|e| {
                    format!("could not sync rebuilt {rel} into the static server: {e}")
                })?;
            }
        }
        Ok(())
    }

    /// Makes the static server serve `content` as `rel`.
    fn serve_file(&self, rel: &str, content: &str) -> Result<(), String> {
        // A bundled front end rebuilds from its working-copy source, so the instrumented/candidate
        // source must land on the host copy too (never the original target), not only in the
        // container, before the bundle is rebuilt.
        if matches!(self.runtime, BrowserRuntime::Docker) && self.web_build.is_some() {
            std::fs::write(self.root.join(rel), content)
                .map_err(|error| format!("could not write {rel}: {error}"))?;
        }
        match &self.runtime {
            BrowserRuntime::Local { .. } => std::fs::write(self.root.join(rel), content)
                .map_err(|error| format!("could not write {rel}: {error}")),
            BrowserRuntime::Docker => {
                let staged = tempfile::NamedTempFile::new()
                    .map_err(|e| format!("could not stage {rel}: {e}"))?;
                std::fs::write(staged.path(), content)
                    .map_err(|e| format!("could not stage {rel}: {e}"))?;
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
                docker(&["cp", source, &format!("{}:/app/{rel}", self.app)])
                    .map(|_| ())
                    .map_err(|e| format!("could not copy {rel} into the static server: {e}"))
            }
        }
    }

    /// The rendered DOM of `url` (a served path), or `None` when the page did not load.
    fn capture(&self, url: &str) -> Option<String> {
        match &self.runtime {
            BrowserRuntime::Local {
                executable,
                helper_dir,
                ..
            } => run_local_browser_capture(
                executable,
                &format!("http://127.0.0.1:{}{url}", self.port),
                helper_dir,
            )
            .ok(),
            BrowserRuntime::Docker => {
                docker_browser_capture(&self.browser, &format!("http://jss-app:{}{url}", self.port))
                    .ok()
            }
        }
    }

    /// The benign loads for `probe`, in a fixed order — the page the script ships in first, then
    /// the pages the harness pass hosts it in — each with whether it is hosted in the harness.
    /// `carried` is the value placed where the payload rides.
    fn benign_loads(&self, probe: &plan::BrowserProbe, carried: &str) -> Vec<(String, bool)> {
        let mut loads: Vec<(String, bool)> = self
            .find_page(&probe.file)
            .ok()
            .iter()
            .flat_map(|page| browser_payload::benign_urls(probe, page, carried))
            .map(|url| (url, false))
            .collect();
        let seeds = seeds_json(&self.local_storage_seeds());
        for host in self.find_pages(&probe.file).iter().take(MAX_HARNESS_PAGES) {
            for url in browser_payload::benign_urls(probe, host, carried)
                .iter()
                .take(MAX_HARNESS_ATTEMPTS_PER_PAGE)
            {
                // `m=1`: the harness mirrors the frame's DOM into its own, where the dump reads it.
                loads.push((format!("{}&m=1", harness_url(url, &seeds)), true));
            }
        }
        loads
    }

    /// The HTTP status of the page the script is served in, and which benign load (an index into
    /// [`Self::benign_loads`]) still shows the page's legitimate job with a benign value placed
    /// where the payload rides: an HTML sink shows the plain `value` in the rendered DOM; a
    /// navigation sink, given an ordinary `http` URL (the marker service's, under a fresh token),
    /// still navigates to it. `only` rechecks just the load that showed it before a change, so a
    /// candidate that drops the value is rejected after one load, not after every page. `None` when
    /// no page could be loaded at all (no host page, a browser that failed every load) or for a
    /// module-import sink.
    pub fn benign_shows(
        &mut self,
        probe: &plan::BrowserProbe,
        value: &str,
        only: Option<usize>,
    ) -> Option<(u16, Option<usize>)> {
        if !self.can_relaunch() || probe.sink == plan::BrowserSink::Import {
            return None;
        }
        let navigates = probe.sink == plan::BrowserSink::Navigation;
        let token = navigates.then(|| {
            self.nonce += 1;
            format!("{}-benign-{}", self.canary.token, self.nonce)
        });
        let carried = token.as_deref().map_or_else(
            || value.to_owned(),
            |token| self.canary.service_url_for_token(token),
        );
        let status = self
            .find_page(&probe.file)
            .ok()
            .into_iter()
            .chain(
                self.find_pages(&probe.file)
                    .into_iter()
                    .take(MAX_HARNESS_PAGES),
            )
            .find_map(|page| self.page_status(&page))?;
        if probe.vector == plan::UrlVector::Message {
            let page = self.find_page(&probe.file).ok()?;
            let messages = browser_payload::benign_messages(value);
            let mut loaded = false;
            for (index, message) in messages.iter().enumerate() {
                if only.is_some_and(|only| only != index) {
                    continue;
                }
                let dummy = format!("{}-benign-no-effect-{}", self.canary.token, index);
                match self.drive_with_message_origin(&page, &dummy, message, true) {
                    Some(_) if self.last_sink_hit.get() => return Some((status, Some(index))),
                    Some(_) => loaded = true,
                    None => {}
                }
            }
            return loaded.then_some((status, None));
        }
        let loads = self.benign_loads(probe, &carried);
        let mut loaded = false;
        for (index, (url, hosted)) in loads.iter().enumerate() {
            if only.is_some_and(|only| only != index) {
                continue;
            }
            let shows = match &token {
                Some(token) => self.drive(url, token, None, None),
                None => self.capture(url).map(|dom| {
                    // The harness page itself names the value in its frame's `src`: only what the
                    // framed page rendered counts.
                    let rendered = if *hosted {
                        mirrored(&dom)
                    } else {
                        Some(dom.as_str())
                    };
                    rendered.is_some_and(|rendered| rendered.contains(value))
                }),
            };
            match shows {
                Some(true) => return Some((status, Some(index))),
                Some(false) => loaded = true,
                None => {}
            }
        }
        loaded.then_some((status, None))
    }

    /// The HTTP status the static server answers `page` (a served path) with.
    fn page_status(&self, page: &str) -> Option<u16> {
        let path = if page.starts_with('/') {
            page.to_owned()
        } else {
            format!("/{page}")
        };
        match &self.runtime {
            BrowserRuntime::Local { .. } => {
                use std::io::{Read, Write};
                let mut stream = std::net::TcpStream::connect(("127.0.0.1", self.port)).ok()?;
                let timeout = Some(std::time::Duration::from_secs(5));
                stream.set_read_timeout(timeout).ok()?;
                stream.set_write_timeout(timeout).ok()?;
                write!(
                    stream,
                    "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
                )
                .ok()?;
                let mut head = [0u8; 64];
                let read = stream.read(&mut head).ok()?;
                let line = String::from_utf8_lossy(head.get(..read)?);
                line.split_whitespace().nth(1)?.parse().ok()
            }
            // The static server is reachable only inside the private network.
            BrowserRuntime::Docker => docker(&[
                "exec",
                &self.browser,
                "node",
                "-e",
                "require('http').get(process.argv[1], r => { process.stdout.write(String(r.statusCode)); \
                 r.resume(); r.on('end', () => process.exit(0)); }).on('error', () => process.exit(1));",
                &format!("http://jss-app:{}{path}", self.port),
            ])
            .ok()?
            .trim()
            .parse()
            .ok(),
        }
    }

    pub fn start(root: &std::path::Path) -> Result<Self, String> {
        if local_runtime_requested() {
            return Self::start_local(root);
        }
        let id = run_id();
        let canary = Canary::new(format!("{id}{}", short_rand()));
        let (served_root, web_build, build_tempdir) = prepare_web_root(root)?;
        let session = Self {
            tag: format!("jsspector-verify-browser:{id}"),
            network: format!("jss-verifyb-net-{id}"),
            app: format!("jss-verifyb-app-{id}"),
            marker: format!("jss-verifyb-marker-{id}"),
            browser: format!("jss-verifyb-br-{id}"),
            canary,
            port: 3000,
            nonce: 0,
            root: served_root,
            runtime: BrowserRuntime::Docker,
            torn_down: false,
            overwritten: Vec::new(),
            sink_binding: None,
            last_sink_hit: std::cell::Cell::new(false),
            proof_sink_hit: std::cell::Cell::new(false),
            unbound_effect: std::cell::Cell::new(false),
            web_build,
            build_tempdir,
        };
        build_browser_image(&session.root, &session.tag, session.port)?;
        docker(&["network", "create", "--internal", &session.network])
            .map_err(|e| format!("could not create the private network: {e}"))?;
        if let Err(err) = session.boot() {
            let mut session = session;
            session.teardown();
            return Err(err);
        }
        Ok(session)
    }

    pub(super) fn start_local(root: &std::path::Path) -> Result<Self, String> {
        let executable = local_browser_executable().ok_or_else(|| {
            "no Chromium/Chrome executable is available for local browser verification".to_owned()
        })?;
        let (served_root, web_build, build_tempdir) = prepare_web_root(root)?;
        let root = served_root.as_path();
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
            overwritten: Vec::new(),
            sink_binding: None,
            last_sink_hit: std::cell::Cell::new(false),
            proof_sink_hit: std::cell::Cell::new(false),
            unbound_effect: std::cell::Cell::new(false),
            web_build,
            build_tempdir,
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
    pub fn exercise(&mut self, probe: &plan::BrowserProbe) -> Outcome {
        self.nonce += 1;
        self.proof_sink_hit.set(false);
        self.unbound_effect.set(false);
        let page = match self.find_page(&probe.file) {
            Ok(page) => page,
            Err(reason) => {
                // A bookmarklet (a `javascript:` script) has no host page: the victim runs it on an
                // attacker-chosen page, so the attacker controls the URL the script reads. Drive it
                // as such — synthesize the host and carry the payload in the URL — before giving up.
                if let Some(source) = self.bookmarklet_source(&probe.file) {
                    return self.exercise_bookmarklet(probe, &source);
                }
                return Outcome::Skipped { reason };
            }
        };
        let attempts = browser_payload::browser_attempts(probe, &page, &self.canary, self.nonce);
        let referrer = browser_payload::via_referrer(probe)
            .then(|| browser_payload::referrer_payload(probe, &self.canary, self.nonce));
        let mut tried = 0usize;
        let mut failed = 0usize;
        for attempt in &attempts {
            let hit = referrer
                .as_ref()
                .map_or(attempt.token.as_str(), |(_, t)| t.as_str());
            tried += 1;
            match self.drive(
                &attempt.url,
                hit,
                referrer.as_ref(),
                attempt.message.as_deref(),
            ) {
                Some(true) if self.accept_browser_effect() => {
                    return self.qualify_browser_binding(browser_verified(
                        &attempt.url,
                        attempt.message.as_deref(),
                        hit,
                    ));
                }
                Some(true) => {}
                Some(false) => {}
                None => failed += 1,
            }
        }
        // Harness pass: only a URL-delivered HTML/navigation probe can be driven this way (a
        // referrer probe needs the header set per load, which the harness frame does not carry).
        if referrer.is_none() && probe.vector != plan::UrlVector::Message {
            let seeds = self.local_storage_seeds();
            let seeds_json = seeds_json(&seeds);
            let pages = self.find_pages(&probe.file);
            for host in pages.iter().take(MAX_HARNESS_PAGES) {
                let host_attempts =
                    browser_payload::browser_attempts(probe, host, &self.canary, self.nonce);
                for attempt in host_attempts.iter().take(MAX_HARNESS_ATTEMPTS_PER_PAGE) {
                    let url = harness_url(&attempt.url, &seeds_json);
                    tried += 1;
                    match self.drive(&url, &attempt.token, None, None) {
                        // The reproduction is the real page URL the victim opens, not our driver.
                        Some(true) if self.accept_browser_effect() => {
                            return self.qualify_browser_binding(browser_verified(
                                &attempt.url,
                                None,
                                &attempt.token,
                            ));
                        }
                        Some(true) => {}
                        Some(false) => {}
                        None => failed += 1,
                    }
                }
            }
        }
        self.qualify_browser_binding(with_failed_loads(
            Outcome::NotReproduced { tried },
            failed,
            tried,
        ))
    }

    /// The bookmarklet body of `script` if it is one: a script whose first non-space bytes are
    /// `javascript:`. Returns the full source (the leading `javascript:` is stripped server-side
    /// when the body is served). `None` for an ordinary script, which the normal host-page flow
    /// handles.
    fn bookmarklet_source(&self, script: &str) -> Option<String> {
        let text = std::fs::read_to_string(self.root.join(script)).ok()?;
        let trimmed = text.trim_start_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
        let lead: String = trimmed.chars().take("javascript:".len()).collect();
        lead.eq_ignore_ascii_case("javascript:").then_some(text)
    }

    /// Drives a bookmarklet: for each mined URL shape, loads the synthesized `/__jss/bm` host with
    /// the payload in the fragment and reports verified on the first marker hit. The reproduction is
    /// the attacker-crafted page URL the victim runs the bookmarklet on (the fragment), not the
    /// driver.
    fn exercise_bookmarklet(&self, probe: &plan::BrowserProbe, source: &str) -> Outcome {
        let attempts =
            browser_payload::bookmarklet_attempts(&probe.file, source, &self.canary, self.nonce);
        let mut tried = 0usize;
        let mut failed = 0usize;
        for attempt in attempts
            .iter()
            .take(MAX_HARNESS_PAGES * MAX_HARNESS_ATTEMPTS_PER_PAGE)
        {
            tried += 1;
            match self.drive(&attempt.url, &attempt.token, None, None) {
                Some(true) if self.accept_browser_effect() => {
                    return self.qualify_browser_binding(bookmarklet_verified(
                        &probe.file,
                        &attempt.url,
                        &attempt.token,
                    ));
                }
                Some(true) => {}
                Some(false) => {}
                None => failed += 1,
            }
        }
        self.qualify_browser_binding(with_failed_loads(
            Outcome::NotReproduced { tried },
            failed,
            tried,
        ))
    }

    /// Loads one URL (relative to the served app) in the browser and reports whether the canary
    /// reached the marker service with `hit`. `referrer`, when set, carries the payload as the
    /// Referer header for a referrer-sourced probe.
    /// Loads one attempt: `Some(true)` when the marker received `hit`, `Some(false)` when the page
    /// loaded without it, `None` when the local browser failed to load the page at all.
    fn drive(
        &self,
        attempt_url: &str,
        hit: &str,
        referrer: Option<&(String, String)>,
        message: Option<&str>,
    ) -> Option<bool> {
        self.drive_inner(attempt_url, hit, referrer, message, false)
    }

    fn drive_with_message_origin(
        &self,
        attempt_url: &str,
        hit: &str,
        message: &str,
        same_origin: bool,
    ) -> Option<bool> {
        self.drive_inner(attempt_url, hit, None, Some(message), same_origin)
    }

    fn drive_inner(
        &self,
        attempt_url: &str,
        hit: &str,
        referrer: Option<&(String, String)>,
        message: Option<&str>,
        same_origin: bool,
    ) -> Option<bool> {
        self.last_sink_hit.set(false);
        let binding_before = self.browser_binding_count();
        match &self.runtime {
            BrowserRuntime::Docker => {
                let url = format!("http://jss-app:{}{}", self.port, attempt_url);
                let mut cmd = vec!["node".to_owned(), "/jss-browser.js".to_owned(), url];
                if let Some((payload, _)) = referrer {
                    cmd.push(payload.clone());
                }
                if let Some(message) = message {
                    if referrer.is_none() {
                        cmd.push(String::new());
                    }
                    cmd.push(message.to_owned());
                    cmd.push(
                        if same_origin {
                            "same-origin"
                        } else {
                            "cross-origin"
                        }
                        .to_owned(),
                    );
                }
                let args: Vec<&str> = cmd.iter().map(String::as_str).collect();
                let _ = exec_in(&self.browser, &args);
                let logs = self.browser_marker_logs();
                self.last_sink_hit
                    .set(self.browser_binding_count_in(&logs) > binding_before);
                Some(marker_hit(&logs, hit).is_some())
            }
            BrowserRuntime::Local {
                executable,
                marker_log,
                helper_dir,
                ..
            } => {
                if message.is_some() {
                    return None;
                }
                let url = format!("http://127.0.0.1:{}{}", self.port, attempt_url);
                let referer = referrer.map(|(payload, _)| payload.as_str());
                let browser_result = run_local_browser(executable, &url, referer, helper_dir);
                let logs = std::fs::read_to_string(marker_log).unwrap_or_default();
                self.last_sink_hit
                    .set(self.browser_binding_count_in(&logs) > binding_before);
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
                (reached || browser_result.is_ok()).then_some(reached)
            }
        }
    }

    fn accept_browser_effect(&self) -> bool {
        if self.sink_binding.is_none() || self.last_sink_hit.get() {
            self.proof_sink_hit.set(true);
            true
        } else {
            self.unbound_effect.set(true);
            false
        }
    }

    fn qualify_browser_binding(&self, outcome: Outcome) -> Outcome {
        let Some(binding) = &self.sink_binding else {
            return outcome;
        };
        match outcome {
            Outcome::Verified { how, mut poc } if self.proof_sink_hit.get() => {
                poc.evidence = format!("{}; {}", poc.evidence, binding.evidence());
                Outcome::Verified { how, poc }
            }
            Outcome::Verified { .. } => Outcome::Skipped {
                reason: format!(
                    "the browser effect occurred, but the planned sink `{}:{}:{}` (`{}`) did not execute during that load",
                    binding.file, binding.line, binding.col, binding.api
                ),
            },
            Outcome::NotReproduced { .. } if self.unbound_effect.get() => Outcome::Skipped {
                reason: format!(
                    "a browser exploitation effect occurred, but the planned sink `{}:{}:{}` (`{}`) did not execute during that load",
                    binding.file, binding.line, binding.col, binding.api
                ),
            },
            other => other,
        }
    }

    fn browser_marker_logs(&self) -> String {
        match &self.runtime {
            BrowserRuntime::Docker => Command::new("docker")
                .args(["logs", &self.marker])
                .output()
                .map(|output| {
                    let mut logs = String::from_utf8_lossy(&output.stdout).into_owned();
                    logs.push_str(&String::from_utf8_lossy(&output.stderr));
                    logs
                })
                .unwrap_or_default(),
            BrowserRuntime::Local { marker_log, .. } => {
                std::fs::read_to_string(marker_log).unwrap_or_default()
            }
        }
    }

    fn browser_binding_count(&self) -> usize {
        self.browser_binding_count_in(&self.browser_marker_logs())
    }

    fn browser_binding_count_in(&self, logs: &str) -> usize {
        let Some(binding) = &self.sink_binding else {
            return 0;
        };
        logs.lines()
            .filter(|line| {
                line.split_once("MARKER ")
                    .and_then(|(_, payload)| serde_json::from_str::<MarkerHit>(payload.trim()).ok())
                    .is_some_and(|record| record.path.contains(&binding.token))
            })
            .count()
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
        if let Some(page) = best.map(|(_, page)| page) {
            return Ok(page);
        }
        // The script is not loaded directly by any page. When the front end is bundled, an HTML page
        // loads a built bundle whose source map names this source file; drive that page.
        if let Some(page) = self.bundled_pages(script).into_iter().next() {
            return Ok(page);
        }
        Err(format!(
            "no HTML page loads `{base}` with a <script> tag (it may be bundled or an ES \
             module behind the app entry; verify v1 drives directly-loadable pages)"
        ))
    }

    /// Served paths of every HTML page that loads a built bundle whose source map lists `script` in
    /// its `sources` (so the page runs that source module after bundling). First-seen, deduplicated.
    /// Empty unless the bundle and its `.map` have been built into the served root.
    fn bundled_pages(&self, script: &str) -> Vec<String> {
        let Ok(target) = self.root.join(script).canonicalize() else {
            return Vec::new();
        };
        let mut pages: Vec<String> = Vec::new();
        for html in html_files(&self.root) {
            let Ok(text) = std::fs::read_to_string(&html) else {
                continue;
            };
            let Some(page_dir) = html.parent() else {
                continue;
            };
            let mut hit = false;
            for src in script_sources(&text) {
                let bundle = resolve_served(&self.root, page_dir, &src);
                let map = bundle.with_extension(format!(
                    "{}.map",
                    bundle
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or_default()
                ));
                if source_map_lists(&map, &target) {
                    hit = true;
                    break;
                }
            }
            if !hit {
                continue;
            }
            let rel = html
                .strip_prefix(&self.root)
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_default();
            let page = format!("/{}", rel.trim_start_matches('/'));
            if !pages.contains(&page) {
                pages.push(page);
            }
        }
        pages
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
        let mut pages: Vec<String> = ranked.into_iter().map(|(_, page)| page).collect();
        // A bundled front end loads the source through a built bundle, not a direct `<script src>`;
        // add every page whose bundle's source map names this file, after the direct matches.
        for page in self.bundled_pages(script) {
            if !pages.contains(&page) {
                pages.push(page);
            }
        }
        pages
    }

    pub fn teardown(&mut self) {
        if self.torn_down {
            return;
        }
        self.torn_down = true;
        if let Err(error) = self.restore_files() {
            eprintln!("jsspector: {error}");
        }
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
        // Drop the front-end build working copy (if any), removing it from disk.
        drop(self.build_tempdir.take());
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
pub(super) fn run_local_browser_capture(
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
pub(super) fn reflected_dom_excerpt(dom: &str, token: &str) -> String {
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
pub(super) fn html_loads_script(text: &str, base: &str) -> bool {
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

/// A built bundle's source map, as far as the page linkage needs it: the list of source files the
/// bundle was produced from.
#[derive(serde::Deserialize)]
struct SourceMap {
    #[serde(default)]
    sources: Vec<String>,
}

/// Prepares the directory the static server serves. For a bundled front end — a `build` script, a
/// known bundler, and an HTML page that loads a build artifact which is not in the checkout — the
/// repository is copied into a disposable working directory, its dependencies installed and the
/// build run, so the served tree holds the bundle and its source map. Otherwise the checkout is
/// served unchanged. The original target is never written.
fn prepare_web_root(
    root: &std::path::Path,
) -> Result<
    (
        std::path::PathBuf,
        Option<WebBuild>,
        Option<tempfile::TempDir>,
    ),
    String,
> {
    let Some(cmd) = front_end_build_spec(root) else {
        return Ok((root.to_path_buf(), None, None));
    };
    let tempdir = tempfile::Builder::new()
        .prefix("jss-webbuild-")
        .tempdir()
        .map_err(|e| format!("creating the front-end build directory: {e}"))?;
    let work = tempdir.path().join("app");
    let home = tempdir.path().join("home");
    copy_tree(root, &work)?;
    run_npm(
        &work,
        &home,
        &[
            "install".to_owned(),
            "--no-audit".to_owned(),
            "--no-fund".to_owned(),
            "--no-save".to_owned(),
        ],
    )
    .map_err(|e| format!("installing front-end dependencies: {e}"))?;
    run_npm(&work, &home, &cmd).map_err(|e| format!("building the front end: {e}"))?;
    Ok((work, Some(WebBuild { cmd, home }), Some(tempdir)))
}

/// The npm run-script that builds a bundled front end, when the repository is one: a non-empty
/// `build` script, a known JavaScript bundler among the declared dependencies, and at least one HTML
/// page that loads a `.js`/`.mjs` script which does not exist in the checkout (a build artifact the
/// step produces). Returns the `npm` arguments to run it. Nothing here is tied to a repository.
fn front_end_build_spec(root: &std::path::Path) -> Option<Vec<String>> {
    let text = std::fs::read_to_string(root.join("package.json")).ok()?;
    let pkg: serde_json::Value = serde_json::from_str(&text).ok()?;
    let build = pkg.get("scripts")?.get("build")?.as_str()?;
    if build.trim().is_empty() {
        return None;
    }
    const BUNDLERS: [&str; 7] = [
        "esbuild",
        "webpack",
        "vite",
        "rollup",
        "parcel",
        "tsup",
        "@vercel/ncc",
    ];
    let has_bundler = ["dependencies", "devDependencies"].iter().any(|section| {
        pkg.get(section)
            .and_then(serde_json::Value::as_object)
            .is_some_and(|deps| BUNDLERS.iter().any(|name| deps.contains_key(*name)))
    });
    if !has_bundler || !loads_missing_bundle(root) {
        return None;
    }
    Some(vec!["run".to_owned(), "build".to_owned()])
}

/// Whether any HTML page loads a relative `.js`/`.mjs` script that is not present in the checkout —
/// the signature of a bundle produced by a build step rather than committed.
fn loads_missing_bundle(root: &std::path::Path) -> bool {
    for html in html_files(root) {
        let Ok(text) = std::fs::read_to_string(&html) else {
            continue;
        };
        let Some(dir) = html.parent() else {
            continue;
        };
        for src in script_sources(&text) {
            if src.contains("://") || src.starts_with("//") {
                continue;
            }
            let path = src.split(['?', '#']).next().unwrap_or(&src);
            if !(path.ends_with(".js") || path.ends_with(".mjs")) {
                continue;
            }
            if !resolve_served(root, dir, path).exists() {
                return true;
            }
        }
    }
    false
}

/// The `src` values of every `<script src=...>` tag in an HTML document, in document order.
fn script_sources(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(rel) = lower.get(i..).and_then(|t| t.find("<script")) {
        let start = i + rel;
        let end = lower
            .get(start..)
            .and_then(|t| t.find('>'))
            .map_or(text.len(), |e| start + e);
        if let Some(tag) = text.get(start..end)
            && let Some(src) = attr_value(tag, "src")
        {
            out.push(src);
        }
        i = end.saturating_add(1);
        if out.len() > 256 {
            break;
        }
    }
    out
}

/// The value of attribute `name` within a single start tag, matched only at an attribute boundary so
/// `data-src` or `nosrc` is not mistaken for `src`. Handles double, single and unquoted values.
fn attr_value(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut from = 0;
    loop {
        let at = from + lower.get(from..)?.find(name)?;
        from = at + name.len();
        let boundary = at == 0
            || bytes
                .get(at.wrapping_sub(1))
                .is_some_and(|b| b.is_ascii_whitespace());
        let rest_lower = lower.get(from..)?;
        if boundary && rest_lower.trim_start().starts_with('=') {
            let eq = from + rest_lower.find('=')?;
            let rest = tag.get(eq + 1..)?.trim_start();
            let value = if let Some(stripped) = rest.strip_prefix('"') {
                stripped.split('"').next()?
            } else if let Some(stripped) = rest.strip_prefix('\'') {
                stripped.split('\'').next()?
            } else {
                rest.split_whitespace().next()?
            };
            return Some(value.to_owned());
        }
    }
}

/// Resolves a page-relative or root-relative script URL to the file the static server would serve.
fn resolve_served(
    root: &std::path::Path,
    page_dir: &std::path::Path,
    src: &str,
) -> std::path::PathBuf {
    let path = src.split(['?', '#']).next().unwrap_or(src);
    let base = path
        .strip_prefix('/')
        .map_or_else(|| page_dir.join(path), |rooted| root.join(rooted));
    normalize_lexical(&base)
}

/// Whether `map` is a source map listing `target` (an already-canonicalized path) in its `sources`,
/// resolved relative to the map's own directory.
fn source_map_lists(map: &std::path::Path, target: &std::path::Path) -> bool {
    let Ok(text) = std::fs::read_to_string(map) else {
        return false;
    };
    let Ok(parsed) = serde_json::from_str::<SourceMap>(&text) else {
        return false;
    };
    let Some(map_dir) = map.parent() else {
        return false;
    };
    parsed.sources.iter().any(|source| {
        let path = source.split(['?', '#']).next().unwrap_or(source);
        normalize_lexical(&map_dir.join(path))
            .canonicalize()
            .is_ok_and(|resolved| resolved == *target)
    })
}

/// Resolves `.` and `..` components lexically, without touching the filesystem.
fn normalize_lexical(path: &std::path::Path) -> std::path::PathBuf {
    let mut out = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Copies a repository tree into `dst`, skipping `node_modules` and `.git` (dependencies are
/// reinstalled fresh; VCS metadata is irrelevant to the served app).
fn copy_tree(src: &std::path::Path, dst: &std::path::Path) -> Result<(), String> {
    fn walk(src: &std::path::Path, dst: &std::path::Path, depth: usize) -> Result<(), String> {
        if depth > 32 {
            return Ok(());
        }
        std::fs::create_dir_all(dst).map_err(|e| format!("creating {}: {e}", dst.display()))?;
        let entries =
            std::fs::read_dir(src).map_err(|e| format!("reading {}: {e}", src.display()))?;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str == "node_modules" || name_str == ".git" {
                continue;
            }
            let from = entry.path();
            let to = dst.join(&name);
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                walk(&from, &to, depth + 1)?;
            } else if file_type.is_file() {
                std::fs::copy(&from, &to)
                    .map_err(|e| format!("copying {}: {e}", from.display()))?;
            }
        }
        Ok(())
    }
    walk(src, dst, 0)
}

/// Runs `npm <args>` in `dir` with a private, credential-free environment and `HOME` (never the
/// scanner's), returning the tail of stderr on failure.
fn run_npm(dir: &std::path::Path, home: &std::path::Path, args: &[String]) -> Result<(), String> {
    let mut command = Command::new("npm");
    command
        .args(args)
        .current_dir(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    isolate_local_command(&mut command, home, None)?;
    let output = command
        .output()
        .map_err(|e| format!("running `npm {}`: {e}", args.join(" ")))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "`npm {}` failed:\n{}",
            args.join(" "),
            tail(&String::from_utf8_lossy(&output.stderr), 20)
        ))
    }
}

/// Repository-relative paths of files modified at or after `since`, skipping `node_modules`/`.git` —
/// the outputs a rebuild produced, to copy into the running static server.
fn files_modified_since(root: &std::path::Path, since: std::time::SystemTime) -> Vec<String> {
    fn walk(
        dir: &std::path::Path,
        root: &std::path::Path,
        since: std::time::SystemTime,
        out: &mut Vec<String>,
        depth: usize,
    ) {
        if depth > 32 || out.len() > 5000 {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str == "node_modules" || name_str == ".git" {
                continue;
            }
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                walk(&path, root, since, out, depth + 1);
            } else if file_type.is_file()
                && entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .is_ok_and(|modified| modified >= since)
                && let Ok(rel) = path.strip_prefix(root)
            {
                out.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, since, &mut out, 0);
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
fn browser_verified(attempt_url: &str, message: Option<&str>, hit: &str) -> Outcome {
    let public_url = replace_local_marker_url(attempt_url, hit, "http://CALLBACK_HOST");
    let target_url = format!("http://TARGET_HOST:3000{public_url}");
    let command = message.map_or_else(
        || format!("Open {} in a browser", shell_quote(&target_url)),
        |message| {
            let public_message =
                replace_local_marker_url(message, hit, "http://CALLBACK_HOST/CANARY");
            let target_literal =
                serde_json::to_string(&target_url).unwrap_or_else(|_| "\"\"".to_owned());
            let message_literal =
                serde_json::to_string(&public_message).unwrap_or_else(|_| "\"\"".to_owned());
            format!(
                "In a browser console on an attacker-controlled origin, run:\n\
                 const frame = document.body.appendChild(document.createElement('iframe'));\n\
                 frame.src = {target_literal};\n\
                 frame.onload = () => setTimeout(() => {{\n\
                   const data = JSON.parse({message_literal});\n\
                   for (const delay of [0, 150, 300]) setTimeout(() => frame.contentWindow.postMessage(data, '*'), delay);\n\
                 }}, 500);"
            )
        },
    );
    Outcome::Verified {
        how: if message.is_some() {
            format!("cross-origin postMessage to {public_url}")
        } else {
            format!("browser load {public_url}")
        },
        poc: Reproduction {
            command,
            command_redacted: false,
            method: "BROWSER".to_owned(),
            target: public_url,
            headers: Vec::new(),
            body: None,
            evidence: format!("the isolated marker service received CANARY `{hit}`"),
            response: String::new(),
            stdout: None,
            stderr: None,
            exit_code: None,
            output_safety: None,
            controls: Vec::new(),
        },
    }
}

/// The verified outcome for a bookmarklet whose canary reached the marker: the reproduction is the
/// attacker-crafted page URL the victim runs the bookmarklet on — the driver's fragment, not the
/// `/__jss/bm` driver page itself.
fn bookmarklet_verified(script: &str, attempt_url: &str, hit: &str) -> Outcome {
    let crafted = attempt_url
        .split_once('#')
        .map(|(_, fragment)| fragment)
        .unwrap_or(attempt_url);
    let public = replace_local_marker_url(crafted, hit, "http://CALLBACK_HOST");
    let victim_url = format!("http://TARGET_HOST:3000/{}", public.trim_start_matches('/'));
    Outcome::Verified {
        how: format!("bookmarklet {script} run on {victim_url}"),
        poc: Reproduction {
            command: format!(
                "Run the {} bookmarklet on a page whose URL is {}",
                script,
                shell_quote(&victim_url)
            ),
            command_redacted: false,
            method: "BROWSER".to_owned(),
            target: victim_url,
            headers: Vec::new(),
            body: None,
            evidence: format!("the isolated marker service received callback token `{hit}`"),
            response: String::new(),
            stdout: None,
            stderr: None,
            exit_code: None,
            output_safety: None,
            controls: Vec::new(),
        },
    }
}

/// The served URL that drives `attempt_url` through the harness, carrying the `localStorage` seeds.
/// Both values are whole-component percent-encoded so the harness recovers them exactly (the inner
/// payload keeps its own encoding, which the framed page decodes when it reads the parameter).
pub(super) fn harness_url(attempt_url: &str, seeds_json: &str) -> String {
    format!(
        "/__jss/harness?p={}&s={}",
        encode_component(attempt_url),
        encode_component(seeds_json)
    )
}

/// A JSON array of `[key, value]` pairs for the harness to replay into `localStorage`.
pub(super) fn seeds_json(seeds: &[(String, String)]) -> String {
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
pub(super) fn encode_component(text: &str) -> String {
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
pub(super) fn script_names_page(source: &str, stem: &str) -> bool {
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
pub(super) fn mine_local_storage_flags(text: &str, out: &mut Vec<(String, String)>) {
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
// A permissive, reflecting network shim for the bookmarklet host. Every fetch resolves
// successfully; property access on the parsed body yields a non-empty collection for list-like use
// (`.map`/`.forEach`) and, for scalars, reflects the request URL — so a value a bookmarklet
// round-trips through its own API (e.g. a handle it resolves to an id) still carries attacker input
// and reaches the sink. It installs only on the synthesized host, never changing how real pages load.
const BM_SHIM = `
(function(){
  function make(reflect){
    return new Proxy(function(){}, {
      get:function(t,p){
        if(p===Symbol.toPrimitive||p==='toString'||p==='valueOf')return function(){return reflect;};
        if(p==='length')return 1;
        if(p==='then'||p==='catch'||p==='finally')return undefined;
        if(p==='split')return function(){return [reflect];};
        if(p==='pop'||p==='shift'||p==='substring'||p==='slice'||p==='trim'||p==='toLowerCase'||p==='toUpperCase'||p==='toLocaleDateString'||p==='toLocaleString'||p==='toISOString')return function(){return reflect;};
        if(p==='map')return function(fn){return [fn(make(reflect),0,[make(reflect)])];};
        if(p==='forEach')return function(fn){fn(make(reflect),0,[make(reflect)]);};
        if(p==='filter')return function(){return [make(reflect)];};
        return make(reflect);
      },
      apply:function(){return make(reflect);},
      has:function(){return true;}
    });
  }
  function resp(reflect){
    return { ok:true, status:200, statusText:'OK', redirected:false, type:'basic', url:reflect,
      headers:{get:function(){return null;},has:function(){return false;}},
      clone:function(){return resp(reflect);},
      json:function(){return Promise.resolve(make(reflect));},
      text:function(){return Promise.resolve(reflect);},
      blob:function(){return Promise.resolve(make(reflect));},
      arrayBuffer:function(){return Promise.resolve(make(reflect));} };
  }
  try { window.fetch = function(u){ var s=''; try{ s=(typeof u==='string')?u:((u&&u.url)||String(u)); }catch(e){} return Promise.resolve(resp(s)); }; } catch(e){}
})();
`;
// After the bookmarklet runs, fire the handlers that reach a DOM sink only on interaction (an inline
// `onclick`) and re-dispatch route events, so a sink gated behind a click still executes. It only
// drives the app's own handlers; the canary is written into the DOM by the application, never by us.
const BM_DRIVER = `
(function(){
  var n=0;
  var iv=setInterval(function(){
    n++;
    try { document.querySelectorAll('[onclick]').forEach(function(e){ try{ e.click(); }catch(x){} try{ e.dispatchEvent(new MouseEvent('click',{bubbles:true,cancelable:true})); }catch(x){} }); } catch(e){}
    try { window.dispatchEvent(new Event('hashchange')); } catch(e){}
    if(n>8) clearInterval(iv);
  }, 300);
})();
`;
function bmQuery(url){ var qi = url.indexOf('?'); if (qi === -1) return ''; try { return new URLSearchParams(url.slice(qi+1)).get('s') || ''; } catch (e) { return ''; } }
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
  // m=1: mirror the framed page's DOM as text into this document, for a DOM dump to read.
  if (q.get('m') === '1') setTimeout(function(){
    try {
      var mirror = document.createElement('pre');
      mirror.hidden = true;
      var mark = '__JSS_' + 'MIRROR__';
      mirror.textContent = mark + f.contentDocument.documentElement.outerHTML + mark;
      document.body.appendChild(mirror);
    } catch (e) {}
  }, 2800);
})();
</script>`;
http.createServer((req, res) => {
  try {
    let p = decodeURIComponent(req.url.split('?')[0].split('#')[0]);
    if (p === '/__jss/harness') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(HARNESS); }
    if (p === '/__jss/bm') {
      let s = bmQuery(req.url);
      let html = '<!doctype html><meta charset="utf-8"><body>'
        + '<script>' + BM_SHIM + '</scr' + 'ipt>'
        + '<script src="/__jss/bmbody?s=' + encodeURIComponent(s) + '"></scr' + 'ipt>'
        + '<script>' + BM_DRIVER + '</scr' + 'ipt>';
      res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(html);
    }
    if (p === '/__jss/bmbody') {
      let s = bmQuery(req.url);
      let bf = path.join(root, s);
      if (!bf.startsWith(root)) { res.writeHead(403); return res.end('x'); }
      let code; try { code = fs.readFileSync(bf, 'utf8'); } catch (e) { res.writeHead(404); return res.end('x'); }
      code = code.replace(/^[﻿\s]*javascript:/i, '');
      res.writeHead(200, { 'Content-Type': 'text/javascript' }); return res.end(code);
    }
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
  const message = process.argv[4];
  const messageOrigin = process.argv[5];
  // JSS_DUMP=1: print the rendered DOM; a page that never loaded exits 2 instead.
  const dump = process.env.JSS_DUMP === '1';
  const browser = await chromium.launch({ args: ['--no-sandbox', '--disable-dev-shm-usage'] });
  const options = { ignoreHTTPSErrors: true };
  if (referer) options.extraHTTPHeaders = { Referer: referer };
  const context = await browser.newContext(options);
  const page = await context.newPage();
  page.on('dialog', d => { try { d.dismiss(); } catch (e) {} });
  page.on('pageerror', () => {});
  let loaded = true;
  if (message) {
    // A data: document is an opaque, distinct attacker origin. It frames the target and sends the
    // exact JSON-decoded value; the target page, not this harness, must evaluate the canary.
    try {
      const driverUrl = messageOrigin === 'same-origin'
        ? new URL('/__jss/harness', url).href
        : 'data:text/html,<title>attacker</title>';
      await page.goto(driverUrl, { waitUntil: 'load', timeout: 8000 });
      loaded = await page.evaluate(async ({ url, message }) => {
        const frame = document.createElement('iframe');
        frame.src = url;
        document.body.appendChild(frame);
        await new Promise((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error('frame timeout')), 8000);
          frame.onload = () => { clearTimeout(timer); resolve(); };
        });
        // Some plugin bridges set their ready flag only after an onload-triggered config XHR. Give
        // that honest initialization a moment, then repeat the same message a few times so the
        // result does not depend on racing the target's asynchronous setup.
        await new Promise(resolve => setTimeout(resolve, 500));
        const data = JSON.parse(message);
        for (let i = 0; i < 3; i++) {
          frame.contentWindow.postMessage(data, '*');
          await new Promise(resolve => setTimeout(resolve, 150));
        }
        return true;
      }, { url, message });
    } catch (e) { loaded = false; }
  } else {
    try { await page.goto(url, { waitUntil: 'load', timeout: 8000 }); } catch (e) { loaded = false; }
  }
  try { await page.waitForTimeout(dump ? 3500 : 1200); } catch (e) {}
  let code = 0;
  if (dump) {
    if (!loaded) code = 2;
    else { try { process.stdout.write(await page.content()); } catch (e) { code = 2; } }
  }
  try { await browser.close(); } catch (e) {}
  process.exit(code);
})();
"#;

#[cfg(test)]
mod bundled_tests {
    use super::*;

    #[test]
    fn script_sources_reads_every_src_at_an_attribute_boundary() {
        let html = r#"<script type="module" src="dist/web.js"></script>
            <script>inline()</script>
            <script defer src='app.js'></script>
            <div data-src="not-a-script.js"></div>"#;
        let found = script_sources(html);
        assert_eq!(found, vec!["dist/web.js".to_owned(), "app.js".to_owned()]);
    }

    #[test]
    fn a_postmessage_proof_includes_the_exact_reproduction_payload() {
        let token = "postmessage-token-1";
        let message =
            format!(r#"{{"type":"plugin_init","data":"fetch('http://jss-marker/{token}')"}}"#);
        let Outcome::Verified { how, poc } =
            browser_verified("/plugin.html", Some(&message), token)
        else {
            panic!("the browser proof should be verified");
        };

        assert!(how.contains("postMessage"));
        assert!(poc.command.contains("frame.contentWindow.postMessage"));
        assert!(poc.command.contains("plugin_init"));
        assert!(poc.command.contains("http://CALLBACK_HOST/CANARY"));
        assert!(!poc.command.contains("jss-marker"));
        assert!(poc.evidence.contains("received CANARY"));
        assert_eq!(poc.target, "/plugin.html");
    }

    #[test]
    fn a_bundled_page_is_linked_to_its_source_through_the_bundle_source_map() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("public/dist")).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("public/index.html"),
            r#"<!doctype html><script type="module" src="dist/web.js"></script>"#,
        )
        .unwrap();
        std::fs::write(root.join("public/dist/web.js"), "/*bundle*/").unwrap();
        std::fs::write(
            root.join("public/dist/web.js.map"),
            r#"{"version":3,"sources":["../../src/Editor.js","../../src/web.js"]}"#,
        )
        .unwrap();
        std::fs::write(root.join("src/Editor.js"), "el.innerHTML = x;").unwrap();
        std::fs::write(root.join("src/Other.js"), "noop();").unwrap();

        let page = root.join("public/index.html");
        let page_dir = page.parent().unwrap();
        let bundle = resolve_served(root, page_dir, "dist/web.js");
        let map = bundle.with_extension("js.map");

        let editor = root.join("src/Editor.js").canonicalize().unwrap();
        assert!(
            source_map_lists(&map, &editor),
            "the bundle maps to Editor.js"
        );

        let other = root.join("src/Other.js").canonicalize().unwrap();
        assert!(
            !source_map_lists(&map, &other),
            "a source the bundle does not include is not linked"
        );
    }

    #[test]
    fn front_end_build_is_detected_only_for_a_bundler_with_a_missing_artifact() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(
            root.join("package.json"),
            r#"{"scripts":{"build":"node build.js"},"devDependencies":{"esbuild":"^0.25.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            root.join("index.html"),
            r#"<script type="module" src="dist/web.js"></script>"#,
        )
        .unwrap();
        // The bundle is absent (gitignored build output): a build is needed.
        assert_eq!(
            front_end_build_spec(root),
            Some(vec!["run".to_owned(), "build".to_owned()])
        );

        // Once the artifact exists (directly loadable), no build step is inferred.
        std::fs::create_dir_all(root.join("dist")).unwrap();
        std::fs::write(root.join("dist/web.js"), "/*built*/").unwrap();
        assert_eq!(front_end_build_spec(root), None);
    }

    #[test]
    fn no_build_without_a_known_bundler() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(
            root.join("package.json"),
            r#"{"scripts":{"build":"tsc"},"devDependencies":{"typescript":"^5.0.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            root.join("index.html"),
            r#"<script src="dist/web.js"></script>"#,
        )
        .unwrap();
        assert_eq!(front_end_build_spec(root), None);
    }
}

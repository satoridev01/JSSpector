use super::*;

#[test]
fn indexed_json_report_command_prints_the_reconstructed_file_contents() {
    let command = decode_indexed_json_response("curl -sS http://TARGET/file");
    assert!(command.starts_with("curl -sS http://TARGET/file | node -e '"));
    assert!(command.contains("Object.keys(v).sort"));
    assert!(command.contains("process.stdout.write(Buffer.from"));
}

/// Tests that start servers or browsers on this machine, or read every port listening on it,
/// run one at a time: a listener one opens would otherwise be taken for the app another one
/// probes, and their load skews the others' process timings.
static LOCAL_LISTENERS: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn local_listeners() -> std::sync::MutexGuard<'static, ()> {
    LOCAL_LISTENERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn interrupted_local_fixtures_are_recognized_without_claiming_arbitrary_files() {
    let path = std::path::Path::new("/tmp/jss-canary-read.json");
    assert!(is_recognizable_local_fixture(
        path,
        br#""CANARY new-token""#,
        br#""18e885c6937a34481e587""#,
    ));
    assert!(is_recognizable_local_fixture(
        path,
        br#""CANARY new-token""#,
        br#""CANARY 18e885c6937a34481e587""#,
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
    let _serial = local_listeners();
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
fn launch_shim_forwards_a_loopback_service_port_to_the_sidecar() {
    if Command::new("node").arg("--version").output().is_err() {
        return;
    }
    use std::io::{Read, Write};
    // Stand-in sidecar: a plain TCP echo server. The shim is told to forward a loopback port to
    // it, exactly as a hard-coded `mongodb://localhost:27017` is bridged to the `mongo` sidecar
    // that answers only on the private network.
    let upstream = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        if let Ok((mut socket, _)) = upstream.accept() {
            let mut buf = [0u8; 4];
            if socket.read_exact(&mut buf).is_ok() {
                let _ = socket.write_all(b"pong");
            }
        }
    });
    let local_port = available_local_port().unwrap();
    let dir = tempfile::tempdir().unwrap();
    // Production stages the ESM hook at `/jss-esm-hook.mjs`; registering it keeps a long-running
    // server's loop alive, which is fine there but would stop this short-lived probe from
    // exiting. This exercise only targets the loopback forwarder, so skip that unrelated hook.
    write(
        dir.path(),
        "disable-register.js",
        "require('module').register = undefined;",
    );
    write(dir.path(), "launch-shim.js", LAUNCH_SHIM_JS);
    // The "app": connects to the loopback service port the shim listens on, sends a probe and
    // prints the echoed reply. It never knows the sidecar's real address.
    write(
        dir.path(),
        "app.js",
        &format!(
            "const net = require('net');\n\
                 let tries = 0;\n\
                 (function go() {{\n\
                   const s = net.connect({local_port}, '127.0.0.1');\n\
                   s.on('connect', () => s.write('ping'));\n\
                   s.on('data', (d) => {{ process.stdout.write(d.toString()); s.end(); }});\n\
                   s.on('error', () => {{ if (tries++ < 50) setTimeout(go, 20); }});\n\
                 }})();\n"
        ),
    );
    let output = Command::new("node")
        .arg("app.js")
        .current_dir(dir.path())
        .env(
            "JSS_LOOPBACK_FORWARD",
            format!("{local_port}:127.0.0.1:{upstream_port}"),
        )
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
    // Wake the upstream thread whether or not the forward delivered a connection, so a future
    // regression fails on the assertion below instead of blocking forever on `accept`.
    let _ = std::net::TcpStream::connect(("127.0.0.1", upstream_port));
    server.join().ok();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "pong");
}

#[test]
fn an_electron_main_process_is_recognized_by_import_and_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // An Electron main process: imports `electron` and defers startup to `app.whenReady`, binding
    // its own HTTP server inside the lifecycle callback.
    write(
        root,
        "main.js",
        "const { app, BrowserWindow } = require('electron');\n\
             const http = require('http');\n\
             app.whenReady().then(() => { http.createServer((q, r) => r.end()).listen(38471); });\n",
    );
    assert!(is_electron_main_process(&root.join("main.js")));
    // Such a file is still a self-contained server (it constructs and listens), so the normal
    // launch path selects `node main.js`; the shim is layered on through NODE_OPTIONS.
    assert!(is_standalone_server(&root.join("main.js")));
    assert_eq!(
        start_command(root, Some(std::path::Path::new("main.js"))).as_deref(),
        Some(r#"["node","main.js"]"#),
    );
    // A plain HTTP server that never imports `electron` is not an Electron main process, and a
    // module that imports `electron` but drives no `whenReady` lifecycle is not one either.
    write(
        root,
        "plain.js",
        "const http = require('http'); http.createServer((q, r) => r.end()).listen(3000);",
    );
    assert!(!is_electron_main_process(&root.join("plain.js")));
    write(
        root,
        "preload.js",
        "const { contextBridge } = require('electron'); contextBridge.exposeInMainWorld('x', {});",
    );
    assert!(!is_electron_main_process(&root.join("preload.js")));
}

#[test]
fn electron_shim_lets_an_electron_main_process_launch_under_node() {
    if Command::new("node").arg("--version").output().is_err() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // Off an Electron runtime, `require('electron')` resolves to the packaged binary's path — a
    // bare string — so `const { app } = require('electron')` is `undefined`. Reproduce that exact
    // shape with a local stand-in package.
    write(
        root,
        "node_modules/electron/package.json",
        r#"{"name":"electron","main":"index.js"}"#,
    );
    write(
        root,
        "node_modules/electron/index.js",
        "module.exports = '/usr/bin/electron';",
    );
    write(root, "electron-shim.js", ELECTRON_SHIM_JS);
    // The canary lives outside the application directory; the app reaches it only by `../` climbing
    // out of `__dirname`, exactly the historical path-traversal read.
    write(root, "canary.txt", "ELECTRON-CANARY");
    write(
        root,
        "app/main.js",
        "const { app, BrowserWindow, ipcMain } = require('electron');\n\
             app.commandLine.appendSwitch('disable-features', 'X');\n\
             const http = require('http');\n\
             const path = require('path');\n\
             const fs = require('fs');\n\
             // `getPath` must return a real writable string the app joins and writes to.\n\
             fs.writeFileSync(path.join(app.getPath('userData'), 'log.txt'), 'start');\n\
             ipcMain.handle('noop', () => {});\n\
             function createWindow() {\n\
               const win = new BrowserWindow({ width: 100, height: 100 });\n\
               const [w, h] = win.getContentSize();\n\
               win.webContents.on('did-finish-load', () => {});\n\
               win.loadFile('x.html');\n\
               const rel = decodeURIComponent('/../canary.txt');\n\
               const data = fs.readFileSync(path.join(__dirname, rel));\n\
               console.log('READ:' + data.toString().trim());\n\
               process.exit(0);\n\
             }\n\
             app.whenReady().then(() => { createWindow(); });\n",
    );
    // Without the shim the app crashes before its lifecycle callback runs.
    let bare = Command::new("node")
        .arg("app/main.js")
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        !bare.status.success(),
        "the Electron main process should fail under plain node without the shim",
    );
    // With the shim preloaded, `whenReady` resolves, the main-process stubs absorb the window
    // construction, and the app's own file read climbs out to the planted canary.
    let shimmed = Command::new("node")
        .arg("app/main.js")
        .current_dir(root)
        .env(
            "NODE_OPTIONS",
            format!("--require={}", root.join("electron-shim.js").display()),
        )
        .output()
        .unwrap();
    assert!(
        shimmed.status.success(),
        "status={} stdout={} stderr={}",
        shimmed.status,
        String::from_utf8_lossy(&shimmed.stdout),
        String::from_utf8_lossy(&shimmed.stderr),
    );
    assert_eq!(
        String::from_utf8_lossy(&shimmed.stdout).trim(),
        "READ:ELECTRON-CANARY",
    );
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
    write(
        root,
        "jss-driver.js",
        &String::from_utf8(local_helper_source(DRIVER_JS)).unwrap(),
    );
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

#[test]
fn missing_runtime_config_is_staged_only_from_a_committed_template() {
    let dir = std::env::temp_dir().join(format!(
        "jss-cfg-test-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let template = dir.join("config.default.yaml");
    std::fs::write(&template, "server:\n  port: 1\n").unwrap();
    let missing = dir.join("config.yaml");
    let log = format!(
        "Error loading configuration: Runtime config not found: {}\n",
        missing.display()
    );
    // A deployment that ships a committed config template has its first-run copy reproduced.
    let stage = missing_config_file_local(&log).expect("a committed template should be staged");
    assert_eq!(stage.target, missing.to_string_lossy());
    assert_eq!(stage.template, template.to_string_lossy());
    // A non-config startup failure never triggers config staging.
    assert!(missing_config_file_local("TypeError: x is not a function\n").is_none());
    // With no committed template, nothing is staged: the verifier never invents configuration.
    std::fs::remove_file(&template).unwrap();
    assert!(missing_config_file_local(&log).is_none());
    std::fs::remove_dir_all(&dir).ok();
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

/// A startup failure where the Firebase Admin SDK reads an absent service-account JSON yields the
/// path to stage the inert placeholder; a missing JSON in an app that does not initialize a Firebase
/// credential, or a non-JSON read, yields nothing.
#[test]
fn missing_service_account_json_fires_only_for_a_firebase_credential_read() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "src/server.js",
        "import admin from 'firebase-admin';\n\
             const sa = JSON.parse(readFileSync('../service-account.json'));\n\
             admin.initializeApp({ credential: admin.credential.cert(sa) });\n",
    );
    let log = "node:fs:560\n  return binding.open(\n\
            Error: ENOENT: no such file or directory, open '/app/Server/service-account.json'\n\
            \x20   at Object.openSync (node:fs:560:18)\n\
            \x20   at readFileSync (node:fs:444:35)\n";
    assert_eq!(
        missing_service_account_json(log, root).as_deref(),
        Some("/app/Server/service-account.json")
    );

    // A write failure (not a read) must not conjure the file.
    let write_log = "Error: ENOENT: no such file or directory, open '/app/Server/service-account.json'\n\
            \x20   at Object.writeFileSync (node:fs:2430:20)\n";
    assert_eq!(missing_service_account_json(write_log, root), None);

    // A non-JSON read is never a service-account credential.
    let other = "Error: ENOENT: no such file or directory, open '/app/Server/settings.yml'\n\
            \x20   at Object.readFileSync (node:fs:444:35)\n";
    assert_eq!(missing_service_account_json(other, root), None);

    // An app that does not initialize a Firebase credential is left untouched, even for a missing
    // JSON read: conjuring the file could mask a genuinely required input.
    let plain = tempfile::tempdir().unwrap();
    write(
        plain.path(),
        "src/server.js",
        "const cfg = JSON.parse(readFileSync('./config.json'));\n",
    );
    assert_eq!(missing_service_account_json(log, plain.path()), None);
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

    let ordinary_missing = "Error: ENOENT: no such file or directory, open '/app/config.json'\n";
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
fn config_source_env_fills_a_typed_path_variable_the_handler_needs_without_diverting_the_branch() {
    // The handler builds a path from a deployment variable before the sink
    // (`path.join(process.env.PROJECT_PATH, ...)`); unset, `path.join(undefined, ...)` throws and
    // the request dies before the sink. The `_PATH` name gets a fresh directory, while the mode
    // toggle (`INLINE_API`, no inferable kind) and the fallback name (`PROJECT_NAME`) are left
    // unset so the vulnerable branch the finding reported still runs.
    let source = "const base = path.join(process.env.PROJECT_PATH, 'dist', \
             process.env.PROJECT_NAME || '', 'functions');\n\
             const prefix = process.env.BASE_PATH || '';\n\
             const mobile = process.env.NODEJS_MOBILE_DATA_DIR;\n\
             if (!process.env.INLINE_API) { require('child_process').exec(cmd); }\n";
    let env = config_source_env(&[source.to_owned()]);
    let names: Vec<&str> = env.iter().map(|item| item.name.as_str()).collect();
    assert_eq!(names, ["PROJECT_PATH"]);
    assert!(env[0].directory);
    assert!(env[0].value.starts_with('/'));
}

#[test]
fn config_source_env_does_not_invent_application_route_prefixes() {
    let source = "const basePath = process.env.BASE_PATH || '/';\n\
                  app.use(basePath, router);\n\
                  const publicUrl = process.env.PUBLIC_URL;";
    assert!(config_source_env(&[source.to_owned()]).is_empty());
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
        command.contains("--url \"http://${TARGET_HOST}:8000\""),
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
    assert!(command.contains("--url \"http://${TARGET_HOST}:8000/x?u=1\""));
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
    assert!(command.contains("--url \"http://${TARGET_HOST}:8000/../../etc/passwd\""));
}

#[test]
fn a_stored_poc_writes_then_carries_the_rotated_cookie_into_the_read() {
    let write = Attempt {
        verb: "POST",
        target: "/profile".to_owned(),
        body: Some(r##"{"username":"#{7*11}"}"##.to_owned()),
        headers: vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("Cookie".to_owned(), "token=old".to_owned()),
        ],
        signal: Signal::ComputedResponse {
            expected: "77".to_owned(),
            kind: payload::ComputedResponseKind::JavaScriptArithmetic,
        },
    };
    let read = Attempt {
        verb: "GET",
        target: "/profile".to_owned(),
        body: None,
        headers: vec![("Cookie".to_owned(), "token=new".to_owned())],
        signal: write.signal.clone(),
    };
    let command = stored_reproduction_command(&write, &read, 3000);
    assert_eq!(command.matches("curl -sS").count(), 2, "{command}");
    assert!(command.contains("--request POST"), "{command}");
    assert!(command.contains("--request GET"), "{command}");
    assert!(command.contains("--dump-header"), "{command}");
    assert!(command.contains("[Ss]et-[Cc]ookie"), "{command}");
    assert!(command.contains("Cookie: $JSS_COOKIE"), "{command}");
    assert!(command.contains("grep -F -m 1 -o -- '77'"), "{command}");
    assert!(
        command.find("--dump-header").unwrap() < command.find("--output /dev/null").unwrap(),
        "{command}"
    );
    let read_start = command.rfind("curl -sS").unwrap();
    let read = &command[read_start..];
    assert!(
        read.find("--header \"Cookie: $JSS_COOKIE\"").unwrap()
            < read.find("| grep -F -m 1").unwrap(),
        "{command}"
    );
    assert!(!command.contains("token=new"), "{command}");
    assert!(
        !command.lines().any(|line| line.starts_with('+')),
        "{command}"
    );
}

#[test]
fn a_file_read_poc_decodes_only_the_returned_container_file() {
    let signal = Signal::Base64FileRead {
        path: "/etc/shadow".to_owned(),
        encoded_prefix: "cm9vdDo".to_owned(),
        decoded_prefix: "root:".to_owned(),
    };
    let write = Attempt {
        verb: "POST",
        target: "/profile".to_owned(),
        body: Some(
            r##"{"username":"#{require('fs').readFileSync('/etc/shadow').toString('base64')}"}"##
                .to_owned(),
        ),
        headers: vec![("Cookie".to_owned(), "token=old".to_owned())],
        signal: signal.clone(),
    };
    let read = Attempt {
        verb: "GET",
        target: "/profile".to_owned(),
        body: None,
        headers: vec![("Cookie".to_owned(), "token=new".to_owned())],
        signal,
    };
    let command = stored_reproduction_command(&write, &read, 3000);
    assert!(
        command.contains("grep -E -m 1 -o -- 'cm9vdDo[A-Za-z0-9+/=]*' | base64 -d"),
        "{command}"
    );
    assert!(
        command.find("Cookie: $JSS_COOKIE").unwrap() < command.find("| grep -E -m 1").unwrap(),
        "{command}"
    );
}

#[test]
fn a_node_config_unsafe_profile_is_selected_only_when_the_repository_declares_it() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("config")).unwrap();
    std::fs::write(
        root.path().join("package.json"),
        r#"{"dependencies":{"config":"^3.3.12"}}"#,
    )
    .unwrap();
    std::fs::write(
        root.path().join("config/unsafe.yml"),
        "features:\n  dangerousRoutes: true\n",
    )
    .unwrap();

    let env = repository_verification_env(root.path()).unwrap();
    assert_eq!(env.name, "NODE_ENV");
    assert_eq!(env.value, "unsafe");
    assert!(!env.directory);

    std::fs::write(root.path().join("package.json"), r#"{"dependencies":{}}"#).unwrap();
    assert_eq!(repository_verification_env(root.path()), None);
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
        command
            .starts_with("printf %s 'jsspector-upload' > /tmp/jsspector-upload.bin\nTARGET_HOST=")
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
fn mongo_connection_strings_yield_the_database_name() {
    let mut out = Vec::new();
    // An inline connection string, single-quoted as in the app's own source.
    extract_mongo_databases("mongoose.connect('mongodb://localhost/aggTest');", &mut out);
    assert_eq!(out, vec!["aggTest".to_owned()]);

    // Credentials, a port, and query options around the database name.
    out.clear();
    extract_mongo_databases(
        "const u = \"mongodb://user:pass@db:27017/mydb?retryWrites=true\";",
        &mut out,
    );
    assert_eq!(out, vec!["mydb".to_owned()]);

    // SRV scheme.
    out.clear();
    extract_mongo_databases("mongodb+srv://cluster.example.net/shop", &mut out);
    assert_eq!(out, vec!["shop".to_owned()]);

    // No database path, and an interpolated name (illegal characters) contribute nothing, so
    // nothing unsafe can reach the profiling script that interpolates the name.
    out.clear();
    extract_mongo_databases("mongodb://localhost:27017", &mut out);
    extract_mongo_databases("mongodb://host/${dbName}", &mut out);
    assert!(out.is_empty());
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
    // The forwarding headers de-bucket a rate limiter and present the TLS-terminating proxy's
    // scheme by default, but both are suppressed on the loopback-origin retry so a genuine
    // loopback request carries no forged proxy hop.
    assert!(value["headers"].get("X-Forwarded-For").is_some());
    assert_eq!(value["headers"]["X-Forwarded-Proto"], "https");
    let loopback = request_spec(&attempt, 3000, false, false);
    let loopback_value: serde_json::Value = serde_json::from_str(&loopback).unwrap();
    assert!(loopback_value["headers"].get("X-Forwarded-For").is_none());
    assert!(loopback_value["headers"].get("X-Forwarded-Proto").is_none());
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
fn marker_hit_count_distinguishes_a_fresh_callback_from_a_stale_one() {
    let once = "MARKER {\"method\":\"GET\",\"path\":\"/run-token-2\",\"userAgent\":null}\n";
    let twice = format!("{once}{once}");
    assert_eq!(marker_hit_count(once, "run-token-2"), 1);
    assert_eq!(marker_hit_count(&twice, "run-token-2"), 2);
    assert_eq!(marker_hit_count(&twice, "another-token"), 0);
}

#[test]
fn blind_command_output_requires_a_valid_url_encoded_id_result() {
    let logs = concat!(
        "MARKER {\"method\":\"GET\",\"path\":\"/run-token-2\",\"userAgent\":null}\n",
        "MARKER {\"method\":\"GET\",\"path\":\"/run-token-2/id/not-id\",\"userAgent\":null}\n",
        "MARKER {\"method\":\"GET\",\"path\":\"/run-token-2/id/uid%3D1000%28node%29%20gid%3D1000%28node%29%20groups%3D1000%28node%29\",\"userAgent\":null}\n",
    );
    assert_eq!(
        captured_id_output(logs, "run-token-2").as_deref(),
        Some("uid=1000(node) gid=1000(node) groups=1000(node)")
    );
    assert!(captured_id_output(logs, "wrong-token").is_none());
    assert!(
        captured_id_output(
            "MARKER {\"method\":\"GET\",\"path\":\"/run-token-2/id/%ZZ\",\"userAgent\":null}\n",
            "run-token-2"
        )
        .is_none()
    );
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

#[test]
fn local_runtime_launches_without_an_uninstalled_redis_and_records_the_gap() {
    // A declared client with a local server starts the sidecar and needs no caveat.
    assert_eq!(local_redis_plan(true, true), (true, None));
    // No declared client: nothing to start, nothing missing.
    assert_eq!(local_redis_plan(false, false), (false, None));
    assert_eq!(local_redis_plan(false, true), (false, None));
    // A declared client without `redis-server` no longer refuses to launch: the app runs without
    // Redis connection settings, and the gap is recorded.
    let (start, missing) = local_redis_plan(true, false);
    assert!(!start);
    assert!(missing.is_some_and(|note| note.contains("redis-server")));
}

#[test]
fn an_app_that_runs_compiled_typescript_is_rebuilt_with_tsc() {
    let dir = tempfile::tempdir().unwrap();
    let app = dir.path();
    let manifest = |start: &str, deps: &str| {
        std::fs::write(
                app.join("package.json"),
                format!(
                    r#"{{"scripts":{{"start":"{start}","build":"npm run build:frontend && npm run build:server"}},"devDependencies":{{{deps}}}}}"#
                ),
            )
            .unwrap();
    };
    std::fs::write(
            app.join("tsconfig.json"),
            "{\n  // compiled server\n  \"compilerOptions\": { \"rootDir\": \"./\", \"outDir\": \"./build\" }\n}\n",
        )
        .unwrap();
    manifest("node build/app", r#""typescript":"^5""#);
    assert_eq!(typescript_build(app), Some(false));
    // Run from source, or without the compiler installed: the build script stays in charge.
    manifest("tsx app.ts", r#""typescript":"^5""#);
    assert_eq!(typescript_build(app), None);
    manifest("node build/app", r#""tsx":"^4""#);
    assert_eq!(typescript_build(app), None);
    std::fs::write(
        app.join("tsconfig.json"),
        r#"{"compilerOptions":{"outDir":"dist","noEmitOnError": true}}"#,
    )
    .unwrap();
    manifest("node ./dist/index.js", r#""typescript":"^5""#);
    assert_eq!(typescript_build(app), Some(true));
}

#[test]
fn a_change_the_compiler_did_not_emit_is_rejected_not_tried() {
    let tsc = |no_emit_on_error| Rebuild {
        workdir: "/app".to_owned(),
        command: TSC_COMMAND.to_owned(),
        typescript: Some(no_emit_on_error),
    };
    assert!(tsc(false).check(true, "").is_ok());
    // Type errors still emit, unless the project turns that off.
    let typed = "routes/login.ts(3,7): error TS2322: Type 'number' is not assignable";
    assert!(tsc(false).check(false, typed).is_ok());
    assert!(tsc(true).check(false, typed).is_err());
    // A compiler that did not run at all leaves the old code running.
    let missing = tsc(false)
        .check(false, "npm error could not determine executable to run")
        .unwrap_err();
    assert!(missing.contains("does not compile"), "{missing}");
    // The app's own build script stays best effort.
    let script = Rebuild {
        workdir: "/app".to_owned(),
        command: "npm run build --if-present || true".to_owned(),
        typescript: None,
    };
    assert!(script.check(false, "ng build failed").is_ok());
}

#[test]
fn provisioned_service_binaries_come_first_on_path() {
    let first = std::path::PathBuf::from("/opt/jss-a/bin");
    let second = std::path::PathBuf::from("/opt/jss-b/bin");
    let path = path_with_tool_dirs(&[first.clone(), second.clone()]);
    let parts: Vec<_> = std::env::split_paths(&path).collect();
    assert_eq!(parts.first(), Some(&first));
    assert_eq!(parts.get(1), Some(&second));
    // The inherited PATH follows, so everything else resolves as before.
    if let Some(inherited) = std::env::var_os("PATH") {
        assert_eq!(
            parts.get(2..).map(<[_]>::to_vec),
            Some(std::env::split_paths(&inherited).collect::<Vec<_>>())
        );
    }
}

#[test]
fn mongosh_is_fetched_as_the_standalone_build_for_the_host() {
    assert_eq!(
        mongosh_platform("linux", "x86_64"),
        Some(("linux-x64", "tgz"))
    );
    assert_eq!(
        mongosh_platform("linux", "aarch64"),
        Some(("linux-arm64", "tgz"))
    );
    assert_eq!(
        mongosh_platform("macos", "aarch64"),
        Some(("darwin-arm64", "zip"))
    );
    assert_eq!(
        mongosh_platform("macos", "x86_64"),
        Some(("darwin-x64", "zip"))
    );
    assert_eq!(mongosh_platform("windows", "x86_64"), None);
}

#[test]
fn driver_metadata_line_yields_status_and_set_cookie() {
    let stderr =
        "some log\n__JSS_META__{\"status\":401,\"setCookie\":[\"auth_token=abc; HttpOnly\"]}\n";
    let (status, cookies) = parse_driver_meta(stderr);
    assert_eq!(status, Some(401));
    assert_eq!(cookies, vec!["auth_token=abc; HttpOnly".to_owned()]);
    // A single-string Set-Cookie and a zero/absent status are handled.
    let (status, cookies) = parse_driver_meta("__JSS_META__{\"status\":0,\"setCookie\":\"x=y\"}");
    assert_eq!(status, None);
    assert_eq!(cookies, vec!["x=y".to_owned()]);
    // No metadata line: nothing parsed.
    assert_eq!(parse_driver_meta("connection refused"), (None, Vec::new()));
}

#[test]
fn declared_bun_runtime_is_read_from_the_manifest() {
    let dir = tempfile::tempdir().unwrap();
    // `packageManager` pins the exact release; its integrity suffix is not part of the version.
    write(
        dir.path(),
        "package.json",
        r#"{"packageManager":"bun@1.4.4+sha512.abc","engines":{"bun":">=1.2"}}"#,
    );
    assert_eq!(declared_bun_spec(dir.path()).as_deref(), Some("1.4.4"));
    // Otherwise the engines range is honored as an npm range.
    write(
        dir.path(),
        "package.json",
        r#"{"engines":{"bun":">=1.2.0"}}"#,
    );
    assert_eq!(declared_bun_spec(dir.path()).as_deref(), Some(">=1.2.0"));
    // A Bun launcher with no pin uses the current release.
    write(
        dir.path(),
        "package.json",
        r#"{"scripts":{"start":"cross-env NODE_ENV=production bun server.js"}}"#,
    );
    assert_eq!(declared_bun_spec(dir.path()).as_deref(), Some("latest"));
    // A Node package, or one that only mentions the word, asks for nothing.
    write(
        dir.path(),
        "package.json",
        r#"{"packageManager":"pnpm@9.0.0","scripts":{"start":"node bun-server.js","build":"echo bun"}}"#,
    );
    assert_eq!(declared_bun_spec(dir.path()), None);
    // A Bun lockfile alone also declares the runtime.
    write(dir.path(), "bun.lock", "{}");
    assert_eq!(declared_bun_spec(dir.path()).as_deref(), Some("latest"));
}

#[test]
fn declared_bun_spec_never_becomes_a_flag_or_non_registry_specifier() {
    let dir = tempfile::tempdir().unwrap();
    for hostile in [
        r#"{"packageManager":"bun@--registry=http://evil"}"#,
        r#"{"packageManager":"bun@https://evil/bun.tgz"}"#,
        r#"{"engines":{"bun":"github:evil/bun"}}"#,
        r#"{"engines":{"bun":"1.0; rm -rf /"}}"#,
    ] {
        write(dir.path(), "package.json", hostile);
        assert_eq!(declared_bun_spec(dir.path()), None, "{hostile}");
    }
}

#[test]
fn docker_image_installs_the_declared_bun_before_package_scripts() {
    let canary = Canary::new("tok".to_owned());
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
        Some(">=1.2 <2"),
        &[],
    );
    let bun = file
        .find("npm install --global 'bun@>=1.2 <2'")
        .expect("Bun install");
    let dependencies = file.find("npm ci").expect("dependency install");
    assert!(bun < dependencies, "{file}");
}

#[test]
fn clean_git_images_have_a_stable_cache_tag_and_dirty_trees_do_not() {
    use sha2::Digest;
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "package.json",
        r#"{"scripts":{"start":"node app.js"}}"#,
    );
    for args in [
        vec!["init", "-q"],
        vec!["config", "user.email", "jsspector@example.invalid"],
        vec!["config", "user.name", "JSSpector"],
        vec!["add", "package.json"],
        vec!["commit", "-qm", "fixture"],
    ] {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(dir.path())
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    }
    let context = dir.path().to_str().unwrap();
    let first = reusable_image_tag("FROM node:22-slim\n", context, &mut sha2::Sha256::new());
    let second = reusable_image_tag("FROM node:22-slim\n", context, &mut sha2::Sha256::new());
    assert_eq!(first, second);
    assert!(first.unwrap().starts_with("jsspector-verify-cache:"));
    write(dir.path(), "app.js", "console.log('dirty')");
    assert_eq!(
        reusable_image_tag("FROM node:22-slim\n", context, &mut sha2::Sha256::new()),
        None
    );
}

#[test]
fn a_typescript_start_target_is_missing_until_its_compiler_emits_it() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "package.json",
        r#"{"scripts":{"start":"node build/app"},"devDependencies":{"typescript":"*"}}"#,
    );
    write(
        dir.path(),
        "tsconfig.json",
        r#"{"compilerOptions":{"outDir":"./build"}}"#,
    );

    assert_eq!(typescript_build(dir.path()), Some(false));
    assert!(missing_node_start_target(dir.path()));
    write(dir.path(), "build/app.js", "console.log('ready')");
    assert!(!missing_node_start_target(dir.path()));
}

#[test]
fn documented_first_run_passwords_precede_defaults_without_reading_dotenv_secrets() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        ".env.example",
        "INITIAL_PASSWORD=change-me\nDATABASE_PASSWORD=db-secret\n",
    );
    write(dir.path(), ".env", "INITIAL_PASSWORD=real-secret\n");
    write(
        dir.path(),
        "packages/app/.env.sample",
        "DASHBOARD_PASSWORD='dashboard-first-run'\nREDIS_PASSWORD=cache\n",
    );
    assert_eq!(
        template_login_passwords(dir.path()),
        ["change-me", "dashboard-first-run"]
    );
}

#[test]
fn provisioned_runtime_dir_is_first_on_path_and_outside_the_checkout() {
    let dir = local_bun_tool_dir(">=1.2 <2");
    assert!(dir.starts_with(std::env::temp_dir().join("jsspector-tools")));
    assert!(
        dir.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("bun-") && !name.contains(['>', '<', ' ']))
    );
    let tool = std::path::Path::new("/opt/jss-tool/bin");
    let path = path_with_tool_dir(tool);
    assert_eq!(std::env::split_paths(&path).next().as_deref(), Some(tool));
    assert!(script_invokes_bun("bun --bun next dev --port 1"));
    assert!(script_invokes_bun("npm run lint && bunx next build"));
    assert!(!script_invokes_bun("node scripts/bun-helper.js"));
}

#[test]
fn reduced_environment_never_reports_a_negative_as_not_reproduced() {
    let unavailable = vec!["Redis".to_owned()];
    // A negative result without the declared service is inconclusive.
    match qualify_reduced_environment(Outcome::NotReproduced { tried: 3 }, &unavailable) {
        Outcome::Skipped { reason } => {
            assert!(reason.contains("reduced environment") && reason.contains("Redis"));
        }
        other => panic!("expected skipped, got {}", other.label()),
    }
    // A complete environment keeps the negative verdict.
    assert!(matches!(
        qualify_reduced_environment(Outcome::NotReproduced { tried: 3 }, &[]),
        Outcome::NotReproduced { tried: 3 }
    ));
    // Skips pass through unchanged, and a reproduction is never altered or invented.
    assert!(matches!(
        qualify_reduced_environment(
            Outcome::Skipped {
                reason: "x".to_owned()
            },
            &unavailable
        ),
        Outcome::Skipped { reason } if reason == "x"
    ));
    // Launch failures name the missing service; a full environment leaves them untouched.
    assert_eq!(
        note_unavailable_services("exited".to_owned(), &unavailable),
        "exited (unavailable: Redis)"
    );
    assert_eq!(
        note_unavailable_services("exited".to_owned(), &[]),
        "exited"
    );
}

#[test]
fn driver_failures_are_inconclusive_not_negative_evidence() {
    let errors = vec!["GET /probe: driver exited".to_owned()];
    match qualify_driver_health(Outcome::NotReproduced { tried: 2 }, &errors, 1) {
        Outcome::Skipped { reason } => {
            assert!(reason.contains("inconclusive"), "{reason}");
            assert!(reason.contains("driver exited"), "{reason}");
        }
        other => panic!("expected skipped, got {}", other.label()),
    }
    assert!(matches!(
        qualify_driver_health(Outcome::NotReproduced { tried: 2 }, &[], 2),
        Outcome::NotReproduced { tried: 2 }
    ));
    assert!(matches!(
        qualify_driver_health(
            Outcome::Skipped {
                reason: "not routable".to_owned()
            },
            &errors,
            0
        ),
        Outcome::Skipped { reason } if reason == "not routable"
    ));
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
    let saved = prepare_registry_only_npm_manifest(&manifest, &std::collections::BTreeSet::new())
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
fn a_login_that_redirects_back_to_the_login_page_is_not_a_session() {
    assert!(redirects_back_to_auth("Found. Redirecting to /login"));
    assert!(redirects_back_to_auth(
        "<p>Found. Redirecting to <a href=\"/register\">/register</a></p>"
    ));
    assert!(redirects_back_to_auth(
        "Redirecting to /auth/signin?error=1"
    ));
    assert!(!redirects_back_to_auth("Found. Redirecting to /learn"));
    assert!(!redirects_back_to_auth("Found. Redirecting to /dashboard"));
    assert!(!redirects_back_to_auth("{\"ok\":true}"));
}

#[test]
fn node_versions_are_read_from_version_files_tags_and_codenames() {
    assert_eq!(node_version_major("v8.17.0"), Some(8));
    assert_eq!(node_version_major("14"), Some(14));
    assert_eq!(node_version_major("lts/carbon"), Some(8));
    assert_eq!(node_version_major("Dubnium"), Some(10));
    assert_eq!(node_version_major("lts/*"), None);
    assert_eq!(node_version_major("node"), None);
    assert_eq!(node_version_major("latest"), None);
}

#[test]
fn a_failed_launch_retries_on_the_node_the_repository_pins() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // The running stage's `FROM node:<codename>` pins the runtime; the build stage does not.
    write(
        root,
        "app/Dockerfile",
        "FROM node:20 AS build\nRUN npm ci\nFROM --platform=linux/amd64 node:carbon-slim\nCMD [\"npm\",\"start\"]\n",
    );
    write(root, "app/package.json", r#"{"engines":{"node":">=6"}}"#);
    let app = root.join("app");
    assert_eq!(
        repo_node_fallback(root, &app, &app).as_deref(),
        Some("node:8")
    );

    // A version file in an ancestor wins over the Dockerfile.
    write(root, ".nvmrc", "v12.22.1\n");
    assert_eq!(
        repo_node_fallback(root, &app, &app).as_deref(),
        Some("node:12")
    );
}

#[test]
fn only_an_older_supported_pin_triggers_a_node_retry() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // `engines.node` is a floor, not the runtime: it pins nothing.
    write(root, "package.json", r#"{"engines":{"node":">=8"}}"#);
    assert_eq!(repo_node_fallback(root, root, root), None);
    // The default runtime or a newer one is what the first launch already used.
    write(root, ".nvmrc", "22\n");
    assert_eq!(repo_node_fallback(root, root, root), None);
    // Older than the launch shim supports.
    write(root, ".nvmrc", "6\n");
    assert_eq!(repo_node_fallback(root, root, root), None);
    // A floating alias pins nothing.
    write(root, ".nvmrc", "lts/*\n");
    assert_eq!(repo_node_fallback(root, root, root), None);
}

#[test]
fn the_docker_npm_install_drops_unpublished_dependencies_before_the_legacy_fallbacks() {
    let plain = NPM_DOCKER_INSTALL
        .find("npm install --no-audit --no-fund >/tmp/jss-npm.log")
        .expect("the plain install keeps its log");
    let drop = NPM_DOCKER_INSTALL
        .find("404 Not Found - GET")
        .expect("registry 404s are recognized");
    let legacy = NPM_DOCKER_INSTALL
        .find("--legacy-peer-deps")
        .expect("the legacy install remains");
    assert!(plain < drop && drop < legacy, "{NPM_DOCKER_INSTALL}");
    assert!(NPM_DOCKER_INSTALL.starts_with("npm ci "));
    assert!(NPM_DOCKER_INSTALL.ends_with("|| true"));
    // The script is single-quoted for the shell, so it must not contain a single quote itself.
    let script = NPM_DOCKER_INSTALL
        .split_once("node -e '")
        .and_then(|(_, rest)| rest.split_once("' && npm install"))
        .map(|(script, _)| script)
        .expect("the recovery script");
    assert!(!script.contains('\''));
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
        None,
        &[],
    );
    assert!(file.contains("RUN corepack enable"), "{file}");
    assert!(file.contains("yarn run build"), "{file}");
    assert!(
        file.contains("curl ca-certificates git"),
        "verification images need git for reachable application code that shells out to it: {file}"
    );
    assert!(
        file.contains("node_modules/.bin/next build --webpack"),
        "a failed Next build is retried with the compatible webpack backend: {file}"
    );
    // Per-finding tokens and read fixtures are staged only when the fresh container starts. They
    // must not invalidate the expensive dependency/build layers of an otherwise identical image.
    assert!(!file.contains(&canary.token), "{file}");
    assert!(!file.contains("/tmp/jss-canary-read.md"), "{file}");
    let another = dockerfile(
        "node:22-slim",
        "/app",
        "/app",
        &Canary::new("another-token".to_owned()),
        r#"["npm","start"]"#,
        3000,
        PackageManager::Yarn,
        Some("build"),
        false,
        None,
        &[],
    );
    assert_eq!(file, another, "the canary must not change the image");
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
        None,
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
        None,
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
        None,
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
        None,
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
fn the_router_finding_launches_the_server_that_mounts_it_not_the_manifest_main() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // The manifest `main` is a standalone server that never mounts the finding's router, while a
    // sibling standalone server requires and mounts it. The launch must pick the mounting server
    // so the route under test is actually served.
    write(root, "package.json", r#"{"main":"index.js"}"#);
    write(
        root,
        "index.js",
        "const express = require('express');\n\
             const app = express();\n\
             app.get('/', (req, res) => res.send('home'));\n\
             app.listen(8080);\n",
    );
    write(
        root,
        "app.js",
        "const express = require('express');\n\
             const app = express();\n\
             const products = require('./routes/products');\n\
             app.use('/products', products);\n\
             app.listen(8080);\n",
    );
    write(
        root,
        "routes/products.js",
        "const express = require('express');\n\
             const router = express.Router();\n\
             router.get('/:id', (req, res) => res.send(`id ${req.params.id}`));\n\
             module.exports = router;\n",
    );
    assert_eq!(
        start_command(root, Some(std::path::Path::new("routes/products.js"))).as_deref(),
        Some(r#"["node","app.js"]"#)
    );
    // When the manifest main itself mounts the router, the override does not fire.
    write(
        root,
        "index.js",
        "const express = require('express');\n\
             const app = express();\n\
             const products = require('./routes/products');\n\
             app.use('/products', products);\n\
             app.listen(8080);\n",
    );
    assert_eq!(
        start_command(root, Some(std::path::Path::new("routes/products.js"))).as_deref(),
        Some(r#"["node","index.js"]"#)
    );
}

#[test]
fn a_router_test_server_never_overrides_the_real_start_script() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "package.json",
        r#"{"scripts":{"start":"node supervise.js"}}"#,
    );
    write(
        root,
        "supervise.js",
        "import { fork } from 'node:child_process';\n\
         fork(new URL('./src/worker-supervisor.js', import.meta.url));\n",
    );
    write(
        root,
        "src/worker-supervisor.js",
        "import { fork } from 'node:child_process';\n\
         fork(new URL('./server.js', import.meta.url));\n",
    );
    write(
        root,
        "src/server.js",
        "import express from 'express';\n\
         import router from './router.js';\n\
         const app = express();\n\
         app.use('/api', router);\n\
         app.listen(8080);\n",
    );
    write(
        root,
        "src/router.js",
        "import express from 'express';\n\
         const router = express.Router();\n\
         router.post('/query', (_req, res) => res.send('ok'));\n\
         export default router;\n",
    );
    write(
        root,
        "test/router.test.js",
        "import express from 'express';\n\
         import router from '../src/router.js';\n\
         const app = express();\n\
         app.use('/api', router);\n\
         app.listen(0);\n",
    );
    assert_eq!(
        start_command(root, Some(std::path::Path::new("src/router.js"))).as_deref(),
        Some(r#"["node","supervise.js"]"#)
    );
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
fn a_manifest_wrapper_for_the_findings_server_preserves_its_runtime_environment() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let path = std::path::Path::new;
    write(
        root,
        "package.json",
        r#"{"main":"app.js","scripts":{"start":"sh start.sh"}}"#,
    );
    write(
        root,
        "start.sh",
        "#!/bin/sh\nexport APP_MODE='open'\nnode 'app.js'\n",
    );
    write(
        root,
        "app.js",
        "require('http').createServer((q,r)=>r.end(process.env.APP_MODE)).listen(3000);\n",
    );

    assert!(manifest_start_wraps_file(root, "app.js"));
    assert_eq!(
        start_command(root, Some(path("app.js"))).as_deref(),
        Some(r#"["npm","start"]"#)
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
        None,
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
fn the_canary_is_staged_as_valid_json_without_entering_the_cached_image() {
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
        None,
        &[],
    );
    assert!(!file.contains("cafed00d"), "{file}");
    let staging = canary_staging_command(&canary);
    assert!(
        staging.contains(r#"printf '"CANARY %s"' 'cafed00d'"#),
        "{staging}"
    );
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
fn a_missing_native_binding_identifies_only_a_safe_package_name() {
    assert_eq!(
        missing_native_package(
            "Could not locate the bindings file. Tried:\n /repo/node_modules/sqlite3/build/Release/node_sqlite3.node"
        )
        .as_deref(),
        Some("sqlite3")
    );
    assert_eq!(
        missing_native_package(
            "Cannot find module '/repo/node_modules/@scope/native-addon/build/addon.node'"
        )
        .as_deref(),
        Some("@scope/native-addon")
    );
    assert_eq!(
        missing_native_package(
            "Cannot find module '/repo/node_modules/pkg;touch /tmp/hit/build/addon.node'"
        ),
        None
    );
}

#[test]
fn deterministic_fix_lookup_reads_the_source_before_local_instrumentation() {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), "routes/handler.js", "instrumented marker\n");
    let overwritten = vec![(
        "routes/handler.js".to_owned(),
        "const original = true\n".to_owned(),
    )];

    assert_eq!(
        original_file_content(root.path(), &overwritten, "routes/handler.js").unwrap(),
        "const original = true\n"
    );
    assert!(original_file_content(root.path(), &overwritten, "../outside").is_err());
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
        None,
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
        None,
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
    let _serial = local_listeners();
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
    let _serial = local_listeners();
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
    let _serial = local_listeners();
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
        None,
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
fn compose_environment_cannot_inject_dockerfile_instructions() {
    assert_eq!(
        dockerfile_env_line("DATABASE_URL", "postgres://db/a b?$HOME=\"x\"\\tail"),
        Some("ENV DATABASE_URL=\"postgres://db/a b?\\$HOME=\\\"x\\\"\\\\tail\"\n".to_owned())
    );
    assert_eq!(dockerfile_env_line("BAD-NAME", "value"), None);
    assert_eq!(dockerfile_env_line("SAFE", "ok\nRUN touch /owned"), None);

    let file = dockerfile(
        "node:22-slim",
        "/app",
        "/app",
        &Canary::new("tok".to_owned()),
        r#"["node","index.js"]"#,
        3000,
        PackageManager::Npm,
        None,
        false,
        None,
        &[
            ("DATABASE_URL".to_owned(), "postgres://db/app".to_owned()),
            ("SAFE".to_owned(), "ok\nRUN touch /owned".to_owned()),
        ],
    );
    assert!(
        file.contains("ENV DATABASE_URL=\"postgres://db/app\"\n"),
        "{file}"
    );
    assert!(!file.contains("touch /owned"), "{file}");
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
  if (u.pathname === '/exec-file') {
    cp.execFile((u.query.bin || '').toString(), [], (_error, stdout) => res.end(stdout || 'failed'));
    return;
  }
  if (u.pathname === '/eval') {
    try { res.end(String(eval((u.query.expr || '').toString()))); }
    catch (e) { res.statusCode = 400; res.end('invalid expression'); }
    return;
  }
  if (u.pathname === '/echo-code') {
    res.end((u.query.expr || '').toString());
    return;
  }
  if (u.pathname === '/static-uid') {
    res.end('uid=1000(static) gid=1000(static)');
    return;
  }
  if (u.pathname === '/static-passwd') {
    res.end('root:x:0:0:root:/root:/bin/bash');
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
        read_filename_suffix: None,
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
        removed_child_marker: None,
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
        stored_write: None,
        query_dispatch: Vec::new(),
        text_wrap: None,
        mcp: None,
        element_body: None,
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
        read_filename_suffix: None,
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
        removed_child_marker: None,
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
        stored_write: None,
        query_dispatch: Vec::new(),
        text_wrap: None,
        mcp: None,
        element_body: None,
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
        read_filename_suffix: None,
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
        removed_child_marker: None,
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
        stored_write: None,
        query_dispatch: Vec::new(),
        text_wrap: None,
        mcp: None,
        element_body: None,
    };
    let visible_command = Probe {
        path: "/run".to_owned(),
        ..command.clone()
    };
    let direct_executable = Probe {
        path: "/exec-file".to_owned(),
        entry: Entry::Query("bin".to_owned()),
        ..command.clone()
    };
    let evaluated_code = Probe {
        path: "/eval".to_owned(),
        entry: Entry::Query("expr".to_owned()),
        class: VulnClass::CodeInjection,
        ..command.clone()
    };
    let reflected_code = Probe {
        path: "/echo-code".to_owned(),
        ..evaluated_code.clone()
    };
    let static_command_output = Probe {
        path: "/static-uid".to_owned(),
        ..command.clone()
    };
    let static_passwd_output = Probe {
        path: "/static-passwd".to_owned(),
        ..traversal.clone()
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
        read_filename_suffix: None,
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
        removed_child_marker: None,
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
        stored_write: None,
        query_dispatch: Vec::new(),
        text_wrap: None,
        mcp: None,
        element_body: None,
    };
    let vulnerable = session.exercise(&traversal);
    let safe = session.exercise(&confined);
    let injected = session.exercise(&command);
    let visible_injected = session.exercise(&visible_command);
    let executable_injected = session.exercise(&direct_executable);
    let code_injected = session.exercise(&evaluated_code);
    let false_code = session.exercise(&reflected_code);
    let false_command = session.exercise(&static_command_output);
    let false_traversal = session.exercise(&static_passwd_output);
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
            assert!(poc.command.contains("id"), "{}", poc.command);
            assert!(
                poc.evidence.contains("read-only `id` command"),
                "{}",
                poc.evidence
            );
            assert!(poc.response.contains("uid="), "{poc:?}");
            assert_eq!(poc.controls.len(), 1, "{poc:?}");
        }
        other => panic!("command injection should verify, got {other:?}"),
    }
    match &executable_injected {
        Outcome::Verified { poc, .. } => {
            assert!(poc.command.contains("bin=id"), "{}", poc.command);
            assert!(poc.response.contains("uid="), "{}", poc.response);
            assert_eq!(poc.controls.len(), 1, "{poc:?}");
        }
        other => panic!("attacker-controlled execFile executable should verify, got {other:?}"),
    }
    match &code_injected {
        Outcome::Verified { poc, .. } => {
            assert!(
                poc.command.contains("%2Fetc%2Fshadow") && poc.command.contains("| base64 -d"),
                "{}",
                poc.command
            );
            assert!(
                poc.evidence
                    .contains("injected JavaScript read `/etc/shadow`"),
                "{}",
                poc.evidence
            );
            let output = poc.stdout.as_deref().unwrap_or_default();
            assert!(
                output.starts_with("root:"),
                "the exact PoC should decode the file returned by the injected JavaScript: {poc:?}"
            );
            assert_eq!(poc.controls.len(), 1, "{poc:?}");
        }
        other => panic!("JavaScript evaluation should verify, got {other:?}"),
    }
    assert!(
        matches!(false_code, Outcome::NotReproduced { .. }),
        "reflecting the JavaScript expression is not evaluation: {false_code:?}"
    );
    assert!(
        matches!(false_command, Outcome::NotReproduced { .. }),
        "static uid= text is not command execution: {false_command:?}"
    );
    assert!(
        matches!(false_traversal, Outcome::NotReproduced { .. }),
        "static passwd-shaped text is not a file read: {false_traversal:?}"
    );
    // A blind command injection (the handler discards the child's output) is proved by piping the
    // real stdout of `id` to the isolated marker under this probe's unique token.
    match &injected {
        Outcome::Verified { poc, .. } => {
            assert!(
                poc.evidence.contains("OS command `id` executed")
                    && poc.evidence.contains("uid=")
                    && poc.evidence.contains(" gid="),
                "blind command injection must expose the captured id output, got {}",
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
    match &forged {
        Outcome::Verified { poc, .. } => {
            assert!(poc.command.contains("--include"), "{}", poc.command);
            let output = poc.stdout.as_deref().unwrap_or_default();
            assert!(
                output.contains("HTTP/1.1 200"),
                "curl --include should retain the target response headers: {poc:?}"
            );
            assert!(output.ends_with("ok"), "{poc:?}");
            assert!(poc.evidence.contains("CANARY"), "{poc:?}");
        }
        other => panic!("the SSRF should verify, got {other:?}"),
    }
}

/// An app whose file read sits behind login middleware: accounts are created on `/api/users`,
/// `/api/login` returns a JWT-shaped bearer token, and `requireAuth` answers 401 without one.
/// `/api/signin` + `/cookie/read` are the session-cookie variant (redirect to the sign-in page when
/// anonymous). `/locked/read` refuses every token, as a gate the minted session cannot pass.
const LOGIN_FIXTURE: &str = r#"
const http = require('http');
const fs = require('fs');
const url = require('url');
const crypto = require('crypto');
const users = new Map();
const sessions = new Set();
const b64 = (s) => Buffer.from(s).toString('base64url');
function body(req, done) {
  let raw = '';
  req.on('data', (c) => { raw += c; });
  req.on('end', () => {
    try { return done(JSON.parse(raw)); } catch (e) {}
    done(Object.fromEntries(new URLSearchParams(raw)));
  });
}
function requireAuth(req, res) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!sessions.has(token)) { res.statusCode = 401; res.end('Unauthorized'); return false; }
  return true;
}
http.createServer((req, res) => {
  const u = url.parse(req.url, true);
  if (req.method === 'POST' && u.pathname === '/api/users') {
    return body(req, (b) => { users.set(b.email, b.password); res.statusCode = 201; res.end('{}'); });
  }
  if (req.method === 'POST' && u.pathname === '/api/login') {
    return body(req, (b) => {
      if (!b.email || users.get(b.email) !== b.password) { res.statusCode = 401; return res.end('{"error":"bad"}'); }
      const token = b64('{"alg":"HS256"}') + '.' + b64(JSON.stringify({ sub: b.email })) + '.' + crypto.randomBytes(8).toString('base64url');
      sessions.add(token);
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ token }));
    });
  }
  if (u.pathname === '/secure/read') {
    if (!requireAuth(req, res)) return;
    try { res.end(fs.readFileSync((u.query.name || '').toString())); } catch (e) { res.statusCode = 404; res.end('x'); }
    return;
  }
  if (req.method === 'POST' && u.pathname === '/secure/create') {
    if (!requireAuth(req, res)) return;
    return body(req, (b) => {
      try { fs.writeFileSync(String(b.name || ''), 'created'); res.end('created'); }
      catch (e) { res.statusCode = 400; res.end('x'); }
    });
  }
  if (u.pathname === '/secure/delete') {
    if (!requireAuth(req, res)) return;
    try { fs.unlinkSync(String(u.query.name || '')); res.end('deleted'); }
    catch (e) { res.statusCode = 404; res.end('x'); }
    return;
  }
  if (u.pathname === '/secure/sql') {
    if (!requireAuth(req, res)) return;
    const name = String(u.query.name || '');
    res.end(name.includes(' OR 1=1') ? 'matching row' : 'no rows');
    return;
  }
  if (req.method === 'POST' && u.pathname === '/secure/nosql') {
    if (!requireAuth(req, res)) return;
    return body(req, (b) => {
      const value = b.name;
      res.end(value && typeof value === 'object' && ('$ne' in value) ? 'matching document' : 'no documents');
    });
  }
  if (req.method === 'POST' && u.pathname === '/api/signin') {
    return body(req, (b) => {
      if (!b.email || users.get(b.email) !== b.password) { res.statusCode = 302; res.setHeader('Location', '/signin'); return res.end(); }
      const sid = crypto.randomBytes(12).toString('hex');
      sessions.add(sid);
      res.setHeader('Set-Cookie', 'sid=' + sid + '; HttpOnly; Path=/');
      res.statusCode = 302; res.setHeader('Location', '/'); res.end();
    });
  }
  if (u.pathname === '/cookie/read') {
    const sid = ((req.headers.cookie || '').match(/(?:^|; )sid=([^;]+)/) || [])[1];
    if (!sessions.has(sid)) { res.statusCode = 302; res.setHeader('Location', '/signin'); return res.end(); }
    try { res.end(fs.readFileSync((u.query.name || '').toString())); } catch (e) { res.statusCode = 404; res.end('x'); }
    return;
  }
  if (u.pathname === '/admin/read') {
    if (!requireAuth(req, res)) return;
    res.statusCode = 403; return res.end('{"error":"admin access required"}');
  }
  if (u.pathname === '/locked/read') {
    res.statusCode = 401; return res.end('Unauthorized');
  }
  res.statusCode = 404; res.end('x');
}).listen(process.env.PORT || 3000, process.env.HOST || '0.0.0.0');
"#;

/// A login-gated traversal verifies with a session the run registers and logs in for; a gate that
/// refuses the minted session, and an app with no working login route, are skipped with the
/// reason instead of being reported as not reproduced. Skipped (not failed) without Docker.
#[test]
fn end_to_end_verifies_a_login_gated_route_with_a_registered_session() {
    use super::super::Outcome;
    use super::super::plan::{AuthBootstrap, Entry, Method, Probe, SqlValue};
    use jss_core::VulnClass;

    if !available() {
        eprintln!("verify login end-to-end: skipped (no Docker daemon reachable)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"name":"verify-login-fixture","version":"1.0.0","scripts":{"start":"node server.js"}}"#,
    )
    .unwrap();
    std::fs::write(dir.path().join("server.js"), LOGIN_FIXTURE).unwrap();

    let boot = |login: &str| AuthBootstrap {
        cookie: "token".to_owned(),
        register_paths: vec!["/api/users".to_owned()],
        login_paths: vec![login.to_owned()],
        default_credentials: false,
        route_gate: true,
    };
    let read = |path: &str, login: &str| Probe {
        method: Method::Get,
        path: path.to_owned(),
        entry: Entry::Query("name".to_owned()),
        class: VulnClass::PathTraversal,
        siblings: Vec::new(),
        gate_paths: Vec::new(),
        url_query_params: Vec::new(),
        read_suffix: None,
        read_filename_suffix: None,
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
        removed_child_marker: None,
        proto_pollution: None,
        alt_paths: Vec::new(),
        auth: Some(boot(login)),
        multipart: None,
        cmd_quote: None,
        cmd_dir_segment: false,
        nosql_lookup: false,
        nosql_inserts_before_sink: false,
        nosql_mutates: false,
        decode_base64: None,
        allow_tokens: Vec::new(),
        stored_write: None,
        query_dispatch: Vec::new(),
        text_wrap: None,
        mcp: None,
        element_body: None,
    };

    let mut session = Session::start(dir.path()).expect("the login fixture sandbox should start");
    let gated = session.exercise(&read("/secure/read", "/api/login"));
    let refused = session.exercise(&read("/locked/read", "/api/login"));
    let no_login = session.exercise(&read("/secure/read", "/api/nope/login"));
    let cookie_gated = session.exercise(&read("/cookie/read", "/api/signin"));
    let role_gated = session.exercise(&read("/admin/read", "/api/login"));
    let mut create_probe = read("/secure/create", "/api/login");
    create_probe.method = Method::Post;
    create_probe.entry = Entry::Body(Some("name".to_owned()));
    create_probe.creates = true;
    let create = session.exercise(&create_probe);
    let mut delete_probe = read("/secure/delete", "/api/login");
    delete_probe.removes = true;
    let delete = session.exercise(&delete_probe);
    let mut sql_probe = read("/secure/sql", "/api/login");
    sql_probe.class = VulnClass::SqlInjection;
    sql_probe.sql_value = Some(SqlValue {
        quote: '\'',
        open_parens: 0,
    });
    let sql = session.exercise(&sql_probe);
    let mut nosql_probe = read("/secure/nosql", "/api/login");
    nosql_probe.method = Method::Post;
    nosql_probe.entry = Entry::Body(Some("name".to_owned()));
    nosql_probe.class = VulnClass::NosqlInjection;
    let nosql = session.exercise(&nosql_probe);
    session.teardown();

    for (oracle, outcome) in [
        ("file-create", &create),
        ("file-delete", &delete),
        ("SQL", &sql),
        ("NoSQL", &nosql),
    ] {
        match outcome {
            Outcome::Verified { poc, .. } => assert!(
                poc.headers
                    .iter()
                    .any(|header| header.starts_with("Authorization: Bearer eyJ")),
                "the authenticated {oracle} oracle must carry the minted session on its exploit leg, got {:?}",
                poc.headers
            ),
            other => panic!("the authenticated {oracle} oracle should verify, got {other:?}"),
        }
    }

    match &role_gated {
        Outcome::Skipped { reason } => assert!(reason.contains("needs a role"), "{reason}"),
        other => {
            panic!("a route refusing the logged-in account should be skipped, got {other:?}")
        }
    }

    match &cookie_gated {
        Outcome::Verified { poc, .. } => assert!(
            poc.headers.iter().any(|h| h.starts_with("Cookie: sid=")),
            "the reproduction must carry the session cookie the login set, got {:?}",
            poc.headers
        ),
        other => panic!("the cookie-session traversal should verify, got {other:?}"),
    }

    match &gated {
        Outcome::Verified { poc, .. } => assert!(
            poc.headers
                .iter()
                .any(|h| h.starts_with("Authorization: Bearer eyJ")),
            "the reproduction must carry the minted bearer session, got {:?}",
            poc.headers
        ),
        other => panic!("the login-gated traversal should verify, got {other:?}"),
    }
    match &refused {
        Outcome::Skipped { reason } => assert!(
            reason.contains("was refused on this route (HTTP 401)"),
            "{reason}"
        ),
        other => panic!("a gate refusing the minted session should be skipped, got {other:?}"),
    }
    match &no_login {
        Outcome::Skipped { reason } => assert!(
            reason.contains("no session could be minted") && reason.contains("/api/nope/login"),
            "{reason}"
        ),
        other => {
            panic!("without a working login route the probe should be skipped, got {other:?}")
        }
    }
}

/// A static `Auth::User` annotation is a candidate precondition, not proof that the selected
/// deployment actually enables its gate. An open runtime with no login route must still be driven
/// anonymously; the exact sink hit and filesystem oracle, rather than the static annotation, decide
/// whether it verifies. Skipped (not failed) without Docker.
#[test]
fn end_to_end_static_auth_does_not_hide_an_open_runtime() {
    use super::super::fix::FixOptions;
    use super::super::{Missing, Outcome};
    use jss_core::{Auth, Finding, Severity, SinkLoc, SourceLoc, VulnClass};

    if !available() {
        eprintln!("verify runtime auth end-to-end: skipped (no Docker daemon reachable)");
        return;
    }
    let source = r#"const http = require('http');
const fs = require('fs');
const url = require('url');
http.createServer((req, res) => {
  const q = url.parse(req.url, true).query;
  try { res.end(fs.readFileSync(String(q.name || ''))); }
  catch (e) { res.statusCode = 404; res.end('missing'); }
}).listen(process.env.PORT || 3000, '0.0.0.0');
"#;
    let sink_line = source
        .lines()
        .position(|line| line.contains("fs.readFileSync"))
        .unwrap() as u32
        + 1;
    let sink_col = source
        .lines()
        .nth(sink_line as usize - 1)
        .unwrap()
        .find("fs.readFileSync")
        .unwrap() as u32
        + 1;
    let finding = Finding {
        file: "server.js".to_owned(),
        sink: SinkLoc {
            file: None,
            api: "fs.readFileSync".to_owned(),
            arg: "String(q.name || '')".to_owned(),
            line: sink_line,
            col: sink_col,
        },
        class: VulnClass::PathTraversal,
        severity: Severity::High,
        confidence: "certain",
        // Deliberately over-approximate the source deployment. The runtime below is open and has no
        // login endpoint, exactly the case this regression protects.
        auth: Auth::User,
        function: "GET /{wildcard}".to_owned(),
        entry: Some("GET /{wildcard}".to_owned()),
        entry_at: None,
        source: SourceLoc {
            kind: "http",
            expr: "req.query.name".to_owned(),
            line: 5,
            col: 13,
        },
        stored_by: None,
        trace: Vec::new(),
        key: "runtime-open-auth".to_owned(),
        fingerprint: "runtime-open-auth".to_owned(),
    };
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"name":"runtime-open-auth","version":"1.0.0","scripts":{"start":"node server.js"}}"#,
    )
    .unwrap();
    std::fs::write(dir.path().join("server.js"), source).unwrap();
    let options = FixOptions {
        enabled: false,
        ..FixOptions::default()
    };
    let verdicts = super::super::run(dir.path(), &[finding], Missing::Fail, &options)
        .expect("the open fixture should run");
    match &verdicts[0].outcome {
        Outcome::Verified { poc, .. } => assert!(
            poc.headers.iter().all(|header| {
                !header.starts_with("Authorization:") && !header.starts_with("Cookie:")
            }),
            "an open deployment must be reproduced anonymously, got {:?}",
            poc.headers
        ),
        other => panic!("static auth must not hide an open runtime, got {other:?}"),
    }
}

/// A response produced by another call to the same API on the same route is not enough. The static
/// finding names the second read, while the driven input reaches only the first; exact binding must
/// reject the otherwise convincing `/etc/passwd` response.
#[test]
fn exact_sink_binding_rejects_an_effect_from_a_sibling_sink() {
    use super::super::Outcome;
    use jss_core::{Auth, Finding, Severity, SinkLoc, SourceLoc, VulnClass};

    if !available() {
        eprintln!("verify exact sink binding: skipped (no Docker daemon reachable)");
        return;
    }
    let source = r#"const http = require('http');
const fs = require('fs');
http.createServer((req, res) => {
  const u = new URL(req.url, 'http://localhost');
  if (u.pathname !== '/read') { res.statusCode = 404; return res.end('x'); }
  if (u.searchParams.has('name')) return res.end(fs.readFileSync(u.searchParams.get('name')));
  if (u.searchParams.has('planned')) return res.end(fs.readFileSync(u.searchParams.get('planned')));
  res.statusCode = 400; res.end('missing');
}).listen(process.env.PORT || 3000, '0.0.0.0');
"#;
    let (sink_line, sink_col) = source
        .lines()
        .enumerate()
        .find_map(|(line, text)| {
            (text.contains("searchParams.get('planned')")).then(|| {
                (
                    line as u32 + 1,
                    text.find("fs.readFileSync").unwrap() as u32 + 1,
                )
            })
        })
        .unwrap();
    let finding = Finding {
        file: "server.js".to_owned(),
        sink: SinkLoc {
            file: None,
            api: "fs.readFileSync".to_owned(),
            arg: "u.searchParams.get('planned')".to_owned(),
            line: sink_line,
            col: sink_col,
        },
        class: VulnClass::PathTraversal,
        severity: Severity::High,
        confidence: "certain",
        auth: Auth::NoneDetected,
        function: "GET /read".to_owned(),
        entry: Some("GET /read".to_owned()),
        entry_at: None,
        source: SourceLoc {
            kind: "http",
            expr: "req.query.name".to_owned(),
            line: 6,
            col: 7,
        },
        stored_by: None,
        trace: Vec::new(),
        key: "exact-sibling".to_owned(),
        fingerprint: "exact-sibling-read".to_owned(),
    };
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"name":"exact-binding-fixture","version":"1.0.0","scripts":{"start":"node server.js"}}"#,
    )
    .unwrap();
    std::fs::write(dir.path().join("server.js"), source).unwrap();
    let mut session = Session::start(dir.path()).expect("the exact-binding fixture should start");
    session
        .activate_sink(&finding)
        .expect("the planned second read should bind");
    let sibling_attempt = Attempt {
        verb: "GET",
        target: "/read?name=%2Fetc%2Fpasswd".to_owned(),
        body: None,
        headers: Vec::new(),
        signal: Signal::ResponseContains("root:x:0:0:root:".to_owned()),
    };
    assert!(
        session.send(&sibling_attempt).is_none(),
        "an effect without the planned sink marker must not produce a reproduction"
    );
    let outcome = session.qualify_sink_binding(Outcome::NotReproduced { tried: 1 });
    session.teardown();
    match outcome {
        Outcome::Skipped { reason } => assert!(
            reason.contains("did not execute during that same request"),
            "{reason}"
        ),
        other => panic!("an effect from the sibling sink must not verify, got {other:?}"),
    }
}

/// An app that exits unless its Compose database is reachable: the sandbox starts that database
/// under the Compose service name, passes the app the Compose environment, and the traversal
/// behind it then verifies. Skipped (not failed) without Docker.
#[test]
fn end_to_end_starts_the_compose_database_the_app_needs() {
    use super::super::Outcome;
    use super::super::plan::{Entry, Method, Probe};
    use jss_core::VulnClass;

    if !available() {
        eprintln!("verify database end-to-end: skipped (no Docker daemon reachable)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"verify-db-fixture","version":"1.0.0","scripts":{"start":"node server.js"},"dependencies":{}}"#,
        )
        .unwrap();
    std::fs::write(
            dir.path().join("docker-compose.yml"),
            "services:\n  db:\n    image: postgres:16-alpine\n    environment:\n      POSTGRES_PASSWORD: pw\n  web:\n    build: .\n    environment:\n      DB_HOST: db\n    depends_on:\n      - db\n",
        )
        .unwrap();
    std::fs::write(
            dir.path().join("server.js"),
            r#"
const http = require('http');
const net = require('net');
const fs = require('fs');
const url = require('url');
const host = process.env.DB_HOST;
const port = Number(process.env.PGPORT || 5432);
const socket = net.connect(port, host, () => {
  socket.end();
  http.createServer((req, res) => {
    const u = url.parse(req.url, true);
    if (u.pathname === '/read') {
      try { return res.end(fs.readFileSync((u.query.name || '').toString())); } catch (e) { res.statusCode = 404; return res.end('x'); }
    }
    res.statusCode = 404; res.end('x');
  }).listen(process.env.PORT || 3000, '0.0.0.0');
});
socket.on('error', (e) => { console.error('database unreachable: ' + e.message); process.exit(1); });
"#,
        )
        .unwrap();

    let mut session =
        Session::start(dir.path()).expect("the app should start once its database runs");
    let read = Probe {
        method: Method::Get,
        path: "/read".to_owned(),
        entry: Entry::Query("name".to_owned()),
        class: VulnClass::PathTraversal,
        siblings: Vec::new(),
        gate_paths: Vec::new(),
        url_query_params: Vec::new(),
        read_suffix: None,
        read_filename_suffix: None,
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
        removed_child_marker: None,
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
        stored_write: None,
        query_dispatch: Vec::new(),
        text_wrap: None,
        mcp: None,
        element_body: None,
    };
    let outcome = session.exercise(&read);
    let sidecars: Vec<String> = session.sql.iter().map(|(c, _)| c.clone()).collect();
    session.teardown();
    assert_eq!(sidecars.len(), 1, "the Compose database should be planned");
    assert!(
        matches!(outcome, Outcome::Verified { .. }),
        "the traversal behind the database-gated startup should verify, got {outcome:?}"
    );
    for container in sidecars {
        assert!(
            docker(&["inspect", &container]).is_err(),
            "teardown must remove the database sidecar {container}"
        );
    }
}

#[test]
fn acquire_http_session_relaunches_rather_than_reuses_a_session_two_findings_share() {
    // Two findings on the very same app must never share a live session: one's exploitation
    // attempts (a write, a planted record) could otherwise leak into the other's own verdict.
    // The fix is in `acquire_http_session` itself; this proves the session is torn down and
    // relaunched for the second finding, not handed back in place.
    if !available() {
        eprintln!("acquire_http_session relaunch: skipped (no Docker daemon reachable)");
        return;
    }
    use jss_core::{Auth, Finding, SinkLoc, SourceLoc, VulnClass};

    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "package.json",
        r#"{"name":"relaunch-fixture","version":"1.0.0","scripts":{"start":"node server.js"}}"#,
    );
    write(
        dir.path(),
        "server.js",
        "require('http').createServer((req,res)=>res.end('ok'))\
             .listen(process.env.PORT||3000,'0.0.0.0');\n",
    );

    let finding = |entry: &str| Finding {
        file: "server.js".to_owned(),
        sink: SinkLoc {
            file: None,
            api: "fs.readFile".to_owned(),
            arg: "p".to_owned(),
            line: 1,
            col: 1,
        },
        class: VulnClass::PathTraversal,
        severity: jss_core::Severity::High,
        confidence: "heuristic",
        auth: Auth::NoneDetected,
        function: "GET /x".to_owned(),
        entry: Some(entry.to_owned()),
        entry_at: None,
        source: SourceLoc {
            kind: "http",
            expr: "req.query.name".to_owned(),
            line: 1,
            col: 1,
        },
        stored_by: None,
        trace: Vec::new(),
        key: entry.to_owned(),
        fingerprint: entry.to_owned(),
    };
    let one = finding("GET /a");
    let two = finding("GET /b");

    let mut http: Vec<(std::path::PathBuf, Result<Session, String>)> = Vec::new();
    let first_index = super::super::acquire_http_session(&mut http, dir.path(), &one);
    let first_network = http[first_index]
        .1
        .as_ref()
        .expect("the first finding's session should launch")
        .network_name()
        .to_owned();

    let second_index = super::super::acquire_http_session(&mut http, dir.path(), &two);
    assert_eq!(
        first_index, second_index,
        "the same app must still key to the same session slot"
    );
    let second_network = http[second_index]
        .1
        .as_ref()
        .expect("the second finding's relaunch should succeed")
        .network_name();
    assert_ne!(
        first_network, second_network,
        "the second finding must get a freshly relaunched session, not the first one's"
    );

    for (_, session) in &mut http {
        if let Ok(session) = session {
            session.teardown();
        }
    }
}

const FIX_FIXTURE: &str = r#"const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const FILES = path.join(__dirname, 'files');
fs.mkdirSync(FILES, { recursive: true });
fs.writeFileSync(path.join(FILES, 'jsspector'), 'public');
http.createServer((req, res) => {
  const u = url.parse(req.url, true);
  if (u.pathname === '/read') {
    const name = (u.query.name || '').toString();
    const filepath = path.join(FILES, name);
    try { res.end(fs.readFileSync(filepath)); } catch (e) { res.statusCode = 404; res.end('missing'); }
    return;
  }
  res.statusCode = 404;
  res.end('x');
}).listen(process.env.PORT || 3000, '0.0.0.0');
"#;

#[test]
fn a_fix_is_proven_only_when_it_closes_the_exploit_and_keeps_the_route() {
    use super::super::fix::{self, Candidate, FixOptions, FixOutcome};
    use super::super::plan::{Entry, Method, Probe};
    use super::super::recipes::{Book, Learned};
    use jss_core::{Auth, Finding, Severity, SinkLoc, SourceLoc, TraceStep, VulnClass};

    if !available() {
        eprintln!("fix proof end-to-end: skipped (no Docker daemon reachable)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "package.json",
        r#"{"name":"fix-fixture","version":"1.0.0","scripts":{"start":"node server.js"}}"#,
    );
    write(dir.path(), "server.js", FIX_FIXTURE);
    let step = |line: u32, col: u32, note: &str| TraceStep {
        file: None,
        line,
        col,
        note: note.to_owned(),
    };
    let finding = Finding {
        file: "server.js".to_owned(),
        sink: SinkLoc {
            file: None,
            api: "fs.readFileSync".to_owned(),
            arg: "filepath".to_owned(),
            line: 13,
            col: 22,
        },
        class: VulnClass::PathTraversal,
        severity: Severity::High,
        confidence: "heuristic",
        auth: Auth::NoneDetected,
        function: "<anonymous>".to_owned(),
        entry: Some("GET /read".to_owned()),
        entry_at: None,
        source: SourceLoc {
            kind: "http",
            expr: "u.query".to_owned(),
            line: 11,
            col: 19,
        },
        stored_by: None,
        trace: vec![
            step(11, 11, "assigned to `name`"),
            step(12, 22, "through path.join()"),
            step(12, 11, "assigned to `filepath`"),
        ],
        key: "k".to_owned(),
        fingerprint: "f".to_owned(),
    };
    let probe = Probe {
        method: Method::Get,
        path: "/read".to_owned(),
        entry: Entry::Query("name".to_owned()),
        class: VulnClass::PathTraversal,
        siblings: Vec::new(),
        gate_paths: Vec::new(),
        url_query_params: Vec::new(),
        read_suffix: None,
        read_filename_suffix: None,
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
        removed_child_marker: None,
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
        stored_write: None,
        query_dispatch: Vec::new(),
        text_wrap: None,
        mcp: None,
        element_body: None,
    };

    let mut session = Session::start(dir.path()).expect("the fixture sandbox should start");
    let outcome = session.exercise(&probe);
    assert!(
        matches!(outcome, Outcome::Verified { .. }),
        "the unconfined read should verify first, got {outcome:?}"
    );
    // A fix proven earlier for this finding on this file content, recorded in the store: it is
    // replayed and proved again, with no LLM.
    let store = tempfile::tempdir().unwrap();
    let confined = FIX_FIXTURE.replace(
        "path.join(FILES, name)",
        "path.join(FILES, path.basename(name))",
    );
    Book::new(store.path())
        .record(&Learned {
            finding: &finding,
            file: "server.js",
            original: FIX_FIXTURE,
            proven: Some(&confined),
            poc: None,
            benign_status: 200,
            offered: &[],
            first_try: false,
        })
        .unwrap();
    let options = FixOptions {
        llm: false,
        recipes: Some(store.path().to_path_buf()),
        ..FixOptions::default()
    };
    let proven = fix::prove(
        fix::Target::Http {
            session: &mut session,
            probe: &probe,
        },
        &finding,
        dir.path(),
        &outcome,
        &options,
    );
    let FixOutcome::Proven {
        strategy,
        diff,
        benign_status,
        ..
    } = &proven
    else {
        session.teardown();
        panic!("the recorded base-name fix should be proven, got {proven:?}");
    };
    assert_eq!(strategy, "replay");
    assert_eq!(*benign_status, 200);
    assert!(
        diff.contains("+    const filepath = path.join(FILES, path.basename(name));"),
        "{diff}"
    );

    // A change that only breaks startup must not pass as a fix.
    let mut state = fix::ProofState::default();
    let broken = Candidate {
        strategy: "test:broken".to_owned(),
        file: "server.js".to_owned(),
        content: format!("throw new Error('broken');\n{FIX_FIXTURE}"),
    };
    let benign = fix::Benign {
        status: 200,
        shows: None,
        at: None,
    };
    let crashed = fix::check(
        &mut fix::Target::Http {
            session: &mut session,
            probe: &probe,
        },
        &finding,
        dir.path(),
        &broken,
        &benign,
        &mut state,
    );
    // A change that drops the route stops the exploit too, but the benign request's status gives
    // it away.
    let gone = Candidate {
        strategy: "test:route-gone".to_owned(),
        file: "server.js".to_owned(),
        content: FIX_FIXTURE.replace("'/read'", "'/gone'"),
    };
    let dropped = fix::check(
        &mut fix::Target::Http {
            session: &mut session,
            probe: &probe,
        },
        &finding,
        dir.path(),
        &gone,
        &benign,
        &mut state,
    );
    session.teardown();
    let crashed = crashed.expect_err("a crashing change is not a fix");
    assert!(crashed.contains("does not start"), "{crashed}");
    let dropped = dropped.expect_err("a change that drops the route is not a fix");
    assert!(
        dropped.contains("HTTP 404 instead of HTTP 200"),
        "{dropped}"
    );
}

const SOCKET_IO_FIXTURE: &str = r#"const http = require('http');
const path = require('path');
const fs = require('fs');
const { Server } = require('socket.io');
const FILES = path.join(__dirname, 'files');
fs.mkdirSync(FILES, { recursive: true });
fs.writeFileSync(path.join(FILES, 'jsspector'), 'public');
const server = http.createServer();
new Server(server).on('connection', (socket) => {
  // Direct member access at the sink: the common shape.
  socket.on('run', (data, cb) => {
    require('child_process').exec(data.cmd, (err, stdout) => cb({ ok: !err, stdout }));
  });
  // One hop through a built local: the sink argument names only `filepath`, not `data`.
  socket.on('read', (data, cb) => {
    const filepath = path.join(FILES, data.name);
    try { cb({ ok: true, content: fs.readFileSync(filepath, 'utf8') }); }
    catch (e) { cb({ ok: false }); }
  });
  // Never acked: the only thing observable is what the sink itself does.
  socket.on('calc', (data) => { eval(data.expr); });
});
server.listen(process.env.PORT || 3000, '0.0.0.0');
"#;

#[test]
fn a_socket_io_event_is_exploited_by_direct_member_access_and_through_a_built_local() {
    use super::super::plan::{Entry, Method, Probe};
    use jss_core::VulnClass;

    if !available() {
        eprintln!("socket.io exploitation end-to-end: skipped (no Docker daemon reachable)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "package.json",
        r#"{"name":"socket-fixture","version":"1.0.0","dependencies":{"socket.io":"4.8.1"}}"#,
    );
    write(dir.path(), "server.js", SOCKET_IO_FIXTURE);
    let base = Probe {
        method: Method::Socket,
        path: String::new(),
        entry: Entry::Body(None),
        class: VulnClass::CommandInjection,
        siblings: Vec::new(),
        gate_paths: Vec::new(),
        url_query_params: Vec::new(),
        read_suffix: None,
        read_filename_suffix: None,
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
        removed_child_marker: None,
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
        stored_write: None,
        query_dispatch: Vec::new(),
        text_wrap: None,
        mcp: None,
        element_body: None,
    };

    let mut session = Session::start(dir.path()).expect("the socket.io fixture should start");

    let run = Probe {
        path: "run".to_owned(),
        entry: Entry::Body(Some("cmd".to_owned())),
        class: VulnClass::CommandInjection,
        ..base.clone()
    };
    let outcome = session.exercise(&run);
    let Outcome::Verified { poc, .. } = &outcome else {
        session.teardown();
        panic!("direct member access over socket.io should verify, got {outcome:?}");
    };
    assert_eq!(poc.method, "SOCKET");
    assert!(
        !poc.command.is_empty() && !poc.evidence.is_empty(),
        "{poc:?}"
    );

    let read = Probe {
        path: "read".to_owned(),
        entry: Entry::Body(Some("name".to_owned())),
        class: VulnClass::PathTraversal,
        ..base
    };
    let outcome = session.exercise(&read);
    let Outcome::Verified { poc, .. } = &outcome else {
        session.teardown();
        panic!("a traversal resolved one hop through a built local should verify, got {outcome:?}");
    };
    assert_eq!(poc.method, "SOCKET");
    assert!(
        !poc.command.is_empty() && !poc.evidence.is_empty(),
        "{poc:?}"
    );

    // An event the handler never acks: nothing comes back to read, but the out-of-band signal
    // (the marker the evaluated code calls, or the file it writes) still proves the eval. The
    // wait for a missing ack must not repeat for each of its attempts.
    let calc = Probe {
        path: "calc".to_owned(),
        entry: Entry::Body(Some("expr".to_owned())),
        class: VulnClass::CodeInjection,
        ..read.clone()
    };
    let began = std::time::Instant::now();
    let outcome = session.exercise(&calc);
    let elapsed = began.elapsed();
    session.teardown();
    let Outcome::Verified { poc, .. } = &outcome else {
        panic!("an unacked eval over socket.io should verify out of band, got {outcome:?}");
    };
    assert_eq!(poc.method, "SOCKET");
    assert!(
        elapsed < std::time::Duration::from_secs(60),
        "waited {elapsed:?} for acks"
    );
}

#[test]
fn a_socket_io_fix_is_proven_only_when_the_event_keeps_acking() {
    use super::super::fix::{self, Benign, Candidate, FixOptions, FixOutcome};
    use super::super::plan::{Entry, Method, Probe};
    use super::super::recipes::{Book, Learned};
    use jss_core::{Auth, Finding, Severity, SinkLoc, SourceLoc, VulnClass};

    if !available() {
        eprintln!("socket.io fix proof end-to-end: skipped (no Docker daemon reachable)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "package.json",
        r#"{"name":"socket-fixture","version":"1.0.0","dependencies":{"socket.io":"4.8.1"}}"#,
    );
    write(dir.path(), "server.js", SOCKET_IO_FIXTURE);
    let finding = Finding {
        file: "server.js".to_owned(),
        sink: SinkLoc {
            file: None,
            api: "fs.readFileSync".to_owned(),
            arg: "filepath".to_owned(),
            line: 17,
            col: 30,
        },
        class: VulnClass::PathTraversal,
        severity: Severity::High,
        confidence: "heuristic",
        auth: Auth::NoneDetected,
        function: "SOCKET read".to_owned(),
        entry: Some("SOCKET read".to_owned()),
        entry_at: None,
        source: SourceLoc {
            kind: "socket",
            expr: "data".to_owned(),
            line: 15,
            col: 21,
        },
        stored_by: None,
        trace: Vec::new(),
        key: "k".to_owned(),
        fingerprint: "socket-read".to_owned(),
    };
    let probe = Probe {
        method: Method::Socket,
        path: "read".to_owned(),
        entry: Entry::Body(Some("name".to_owned())),
        class: VulnClass::PathTraversal,
        siblings: Vec::new(),
        gate_paths: Vec::new(),
        url_query_params: Vec::new(),
        read_suffix: None,
        read_filename_suffix: None,
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
        removed_child_marker: None,
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
        stored_write: None,
        query_dispatch: Vec::new(),
        text_wrap: None,
        mcp: None,
        element_body: None,
    };
    let mut session = Session::start(dir.path()).expect("the socket.io fixture should start");
    let outcome = session.exercise(&probe);
    if !matches!(outcome, Outcome::Verified { .. }) {
        session.teardown();
        panic!("the unconfined read should verify first, got {outcome:?}");
    }
    // A fix proven earlier for this finding on this file content: replayed, no LLM.
    let store = tempfile::tempdir().unwrap();
    let confined = SOCKET_IO_FIXTURE.replace(
        "path.join(FILES, data.name)",
        "path.join(FILES, path.basename(data.name))",
    );
    assert_ne!(confined, SOCKET_IO_FIXTURE);
    Book::new(store.path())
        .record(&Learned {
            finding: &finding,
            file: "server.js",
            original: SOCKET_IO_FIXTURE,
            proven: Some(&confined),
            poc: None,
            benign_status: 200,
            offered: &[],
            first_try: false,
        })
        .unwrap();
    let options = FixOptions {
        llm: false,
        recipes: Some(store.path().to_path_buf()),
        ..FixOptions::default()
    };
    let proven = fix::prove(
        fix::Target::Http {
            session: &mut session,
            probe: &probe,
        },
        &finding,
        dir.path(),
        &outcome,
        &options,
    );
    let FixOutcome::Proven {
        strategy,
        benign_status,
        ..
    } = &proven
    else {
        session.teardown();
        panic!("the recorded base-name fix should be proven over socket.io, got {proven:?}");
    };
    assert_eq!(strategy, "replay");
    assert_eq!(*benign_status, 200);

    // A change that drops the event stops the exploit too, but the event no longer acks.
    let benign = Benign {
        status: 200,
        shows: None,
        at: None,
    };
    let gone = Candidate {
        strategy: "test:event-gone".to_owned(),
        file: "server.js".to_owned(),
        content: SOCKET_IO_FIXTURE.replace("socket.on('read'", "socket.on('gone'"),
    };
    let mut state = fix::ProofState::default();
    let dropped = fix::check(
        &mut fix::Target::Http {
            session: &mut session,
            probe: &probe,
        },
        &finding,
        dir.path(),
        &gone,
        &benign,
        &mut state,
    );
    session.teardown();
    let dropped = dropped.expect_err("a change that drops the event is not a fix");
    assert!(dropped.contains("benign request"), "{dropped}");
}

#[test]
fn each_transport_reproduces_with_its_own_command() {
    let attempt = |verb: &'static str, target: &str, body: Option<&str>| Attempt {
        verb,
        target: target.to_owned(),
        body: body.map(str::to_owned),
        headers: Vec::new(),
        signal: Signal::InResponse,
    };
    let endpoint = |transport: &str, path: &str| McpEndpoint {
        transport: transport.to_owned(),
        path: path.to_owned(),
        stdio: None,
    };
    let http = reproduction_command(&attempt("GET", "/files?name=x", None), None, 3000);
    assert!(
        http.starts_with("TARGET_HOST=")
            && http.contains("http://${TARGET_HOST}:3000/files?name=x"),
        "{http}"
    );
    // An HTTP request is the same with or without an MCP endpoint found for the session.
    assert_eq!(
        http,
        reproduction_command(
            &attempt("GET", "/files?name=x", None),
            Some(&endpoint("streamable", "/mcp")),
            3000
        )
    );
    let socket = reproduction_command(
        &attempt("SOCKET", "run", Some(r#"{"cmd":"id"}"#)),
        None,
        3000,
    );
    assert!(
        socket.contains("socket") || socket.contains("EIO"),
        "{socket}"
    );
    let mcp = reproduction_command(
        &attempt("MCP", "run", Some(r#"{"cmd":"id","n":1}"#)),
        Some(&endpoint("streamable", "/mcp")),
        3000,
    );
    assert!(
        mcp.contains("tools/call") && mcp.contains("http://TARGET_HOST:3000/mcp"),
        "{mcp}"
    );
    let legacy = reproduction_command(
        &attempt("MCP", "run", Some(r#"{"cmd":"id"}"#)),
        Some(&endpoint("sse", "/sse")),
        3000,
    );
    assert!(legacy.contains("SSEClientTransport"), "{legacy}");
}

#[test]
fn a_confined_handlers_error_naming_the_file_is_not_a_file_found() {
    let (target, value) = (
        "/read?name=../../../../tmp/jss-canary-read",
        "../../../../tmp/jss-canary-read",
    );
    let (absent_target, absent_value) = (
        "/read?name=../../../../jss-oracle-absent-1-2",
        "../../../../jss-oracle-absent-1-2",
    );
    let compare = |present: &str, absent: &str| {
        (
            strip_request_echo(present, target, value),
            strip_request_echo(absent, absent_target, absent_value),
        )
    };
    // The handler keeps only the file's base name, and its error message says which file it
    // could not open: the answers differ only by that name.
    let (present, absent) = compare(
        "ENOENT: no such file or directory, open '/srv/notes/jss-canary-read'",
        "ENOENT: no such file or directory, open '/srv/notes/jss-oracle-absent-1-2'",
    );
    assert_eq!(present, absent);
    // A handler that joins what is left of the climb under its directory echoes more of it.
    let (present, absent) = compare(
        "ENOENT: open '/srv/notes//tmp/jss-canary-read'",
        "ENOENT: open '/srv/notes//jss-oracle-absent-1-2'",
    );
    assert_eq!(present, absent);
    // A response that carries the planted file's content keeps it: that is the signal.
    let (present, absent) = compare(
        "{\"token\":\"abc123\"}",
        "ENOENT: open '/srv/notes/jss-oracle-absent-1-2'",
    );
    assert_eq!(present, "{\"token\":\"abc123\"}");
    assert_ne!(present, absent);
    // Short tails are not names: `tmp` stays wherever it appears.
    assert_eq!(
        strip_request_echo("tmp is a directory", "/r", "../tmp"),
        "tmp is a directory"
    );
}

#[test]
fn only_an_html_content_type_is_a_page() {
    let meta = |kind: &str| format!("__JSS_META__{{\"status\":200,\"contentType\":{kind}}}\n");
    assert_eq!(
        driver_content_type(&meta("\"text/html; charset=utf-8\"")).as_deref(),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(driver_content_type(&meta("null")), None);
    assert!(is_html_content_type("text/html; charset=utf-8"));
    assert!(is_html_content_type("Application/XHTML+XML"));
    assert!(!is_html_content_type("text/plain; charset=utf-8"));
    assert!(!is_html_content_type("application/json"));
}

#[test]
fn only_the_mirrored_frame_counts_in_a_harness_dump() {
    let dump = "<iframe src=\"/p.html?name=plain1\"></iframe>\
<pre hidden>__JSS_MIRROR__&lt;div&gt;Hello&lt;/div&gt;__JSS_MIRROR__</pre>";
    let rendered = mirrored(dump).unwrap();
    assert!(rendered.contains("Hello") && !rendered.contains("plain1"));
    assert_eq!(
        mirrored("<iframe src=\"/p.html?name=plain1\"></iframe>"),
        None
    );
}

#[test]
fn a_browser_load_that_failed_leaves_the_outcome_undecided() {
    let skipped = with_failed_loads(Outcome::NotReproduced { tried: 11 }, 2, 11);
    assert!(
        matches!(&skipped, Outcome::Skipped { reason } if reason.contains("2 of 11")),
        "{skipped:?}"
    );
    assert!(matches!(
        with_failed_loads(Outcome::NotReproduced { tried: 11 }, 0, 11),
        Outcome::NotReproduced { tried: 11 }
    ));
    let verified = Outcome::Verified {
        how: "browser load".to_owned(),
        poc: Reproduction {
            command: String::new(),
            command_redacted: false,
            method: "BROWSER".to_owned(),
            target: String::new(),
            headers: Vec::new(),
            body: None,
            evidence: String::new(),
            response: String::new(),
            stdout: None,
            stderr: None,
            exit_code: None,
            output_safety: None,
            controls: Vec::new(),
        },
    };
    // A hit is a hit whatever other loads did.
    assert!(matches!(
        with_failed_loads(verified, 3, 11),
        Outcome::Verified { .. }
    ));
}

/// A dependency-free MCP server speaking the three HTTP transports side by side — Streamable HTTP
/// stateless (`/mcp`, replies as one server-sent event), Streamable HTTP stateful (`/stateful`, a
/// session id, JSON replies) and the legacy HTTP+SSE pair (`/sse` and `/messages`) — over tools
/// that validate their arguments against the JSON Schema they list, as a real SDK server does:
/// `run` (a command injection, needs `n` too), `safe_read` (a path read confined to the notes
/// directory), `read_note` (the same read, unconfined, needs `limit` too) and `strict_run` (a
/// command injection behind a schema pattern no payload satisfies). The declaration order puts
/// the confined read before the unconfined one.
const MCP_FIXTURE: &str = r#"'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { exec } = require('child_process');

const GATED_ALL = false;
const NOTES = path.join(__dirname, 'notes');
fs.mkdirSync(NOTES, { recursive: true });
fs.writeFileSync(path.join(NOTES, 'welcome.txt'), 'welcome note');

// Tools, declared the way a server lists them: a JSON Schema each, a handler behind it.
const TOOLS = {
  run: {
    schema: {
      type: 'object',
      properties: { cmd: { type: 'string' }, n: { type: 'integer', minimum: 1 } },
      required: ['cmd', 'n'],
    },
    call: (a) => new Promise((resolve) => exec(a.cmd, (err, out, errout) => resolve(String(out) + String(errout)))),
  },
  safe_read: {
    schema: { type: 'object', properties: { name: { type: 'string' } }, required: ['name'] },
    call: async (a) => fs.readFileSync(path.join(NOTES, path.basename(a.name)), 'utf8'),
  },
  read_note: {
    schema: {
      type: 'object',
      properties: { name: { type: 'string' }, limit: { type: 'integer', minimum: 1 } },
      required: ['name', 'limit'],
    },
    call: async (a) => fs.readFileSync(path.join(NOTES, a.name), 'utf8'),
  },
  strict_run: {
    schema: { type: 'object', properties: { cmd: { type: 'string', pattern: '^echo$' } }, required: ['cmd'] },
    call: (a) => new Promise((resolve) => exec(a.cmd, (err, out) => resolve(String(out)))),
  },
};

// What a schema-validating server does before a handler runs.
function validate(schema, given) {
  const problems = [];
  const args = given && typeof given === 'object' ? given : {};
  for (const name of schema.required || []) {
    if (!(name in args)) { problems.push(name + ': Required'); }
  }
  for (const [name, spec] of Object.entries(schema.properties || {})) {
    if (!(name in args)) { continue; }
    const value = args[name];
    if (spec.type === 'string' && typeof value !== 'string') { problems.push(name + ': Expected string'); }
    if (spec.type === 'integer' && !Number.isInteger(value)) { problems.push(name + ': Expected integer'); }
    if (spec.pattern && typeof value === 'string' && !new RegExp(spec.pattern).test(value)) { problems.push(name + ': Invalid'); }
    if (spec.minimum !== undefined && typeof value === 'number' && value < spec.minimum) { problems.push(name + ': Too small'); }
  }
  return problems;
}

async function callTool(name, args) {
  const tool = TOOLS[name];
  if (!tool) { return { error: { code: -32602, message: 'MCP error -32602: Tool ' + name + ' not found' } }; }
  const problems = validate(tool.schema, args);
  if (problems.length) {
    return { result: { isError: true, content: [{ type: 'text', text: 'MCP error -32602: Input validation error: Invalid arguments for tool ' + name + ': ' + problems.join('; ') }] } };
  }
  try {
    return { result: { content: [{ type: 'text', text: String(await tool.call(args)) }] } };
  } catch (e) {
    return { result: { isError: true, content: [{ type: 'text', text: String(e.message) }] } };
  }
}

async function handle(message) {
  const { id, method, params } = message;
  if (id === undefined) { return null; }
  switch (method) {
    case 'initialize':
      return { jsonrpc: '2.0', id, result: { protocolVersion: (params && params.protocolVersion) || '2025-03-26', capabilities: { tools: {} }, serverInfo: { name: 'mini', version: '1.0.0' } } };
    case 'tools/list':
      return { jsonrpc: '2.0', id, result: { tools: Object.entries(TOOLS).map(([name, tool]) => ({ name, description: name, inputSchema: tool.schema })) } };
    case 'tools/call':
      return Object.assign({ jsonrpc: '2.0', id }, await callTool(params.name, params.arguments));
    default:
      return { jsonrpc: '2.0', id, error: { code: -32601, message: 'Method not found' } };
  }
}

function readBody(req) {
  return new Promise((resolve) => { let text = ''; req.on('data', (c) => { text += c; }); req.on('end', () => resolve(text)); });
}

const sessions = new Set();
const streams = new Map();

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  if ((GATED_ALL || url.pathname === '/private') && req.headers.authorization !== 'Bearer secret') {
    res.writeHead(401);
    return res.end('unauthorized');
  }
  // Streamable HTTP, stateless: every POST stands alone, replies come as one server-sent event.
  if (url.pathname === '/mcp' && req.method === 'POST') {
    const reply = await handle(JSON.parse(await readBody(req)));
    if (!reply) { res.writeHead(202); return res.end(); }
    res.writeHead(200, { 'Content-Type': 'text/event-stream' });
    return res.end('event: message\ndata: ' + JSON.stringify(reply) + '\n\n');
  }
  // Streamable HTTP, stateful: a session id from `initialize`, plain JSON replies.
  if (url.pathname === '/stateful') {
    if (req.method === 'DELETE') { sessions.delete(req.headers['mcp-session-id']); res.writeHead(200); return res.end(); }
    if (req.method === 'POST') {
      const message = JSON.parse(await readBody(req));
      if (message.method === 'initialize') {
        const sid = crypto.randomUUID();
        sessions.add(sid);
        res.writeHead(200, { 'Content-Type': 'application/json', 'Mcp-Session-Id': sid });
        return res.end(JSON.stringify(await handle(message)));
      }
      if (!sessions.has(req.headers['mcp-session-id'])) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message: 'Bad Request: No valid session ID provided' }, id: null }));
      }
      const reply = await handle(message);
      if (!reply) { res.writeHead(202); return res.end(); }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(reply));
    }
  }
  // The legacy HTTP+SSE transport: a held event stream, replies pushed onto it.
  if (url.pathname === '/sse' && req.method === 'GET') {
    const sid = crypto.randomUUID();
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
    streams.set(sid, res);
    res.write('event: endpoint\ndata: /messages?sessionId=' + sid + '\n\n');
    req.on('close', () => streams.delete(sid));
    return;
  }
  if (url.pathname === '/messages' && req.method === 'POST') {
    const stream = streams.get(url.searchParams.get('sessionId'));
    if (!stream) { res.writeHead(400); return res.end('no session'); }
    const message = JSON.parse(await readBody(req));
    res.writeHead(202);
    res.end('Accepted');
    const reply = await handle(message);
    if (reply) { stream.write('event: message\ndata: ' + JSON.stringify(reply) + '\n\n'); }
    return;
  }
  res.writeHead(404);
  res.end('not found');
}).listen(process.env.PORT || 3000, '0.0.0.0');
"#;

fn mcp_probe(
    tool: &str,
    field: Option<&str>,
    class: jss_core::VulnClass,
    endpoint: &str,
) -> super::super::plan::Probe {
    use super::super::mcp::McpHints;
    use super::super::plan::{Entry, Method, Probe};
    let mut probe = Probe::call(
        Method::Mcp,
        tool.to_owned(),
        Entry::Body(field.map(str::to_owned)),
        class,
    );
    probe.mcp = Some(McpHints {
        endpoints: vec![endpoint.to_owned()],
        fields: Vec::new(),
    });
    probe
}

fn mcp_fixture_dir(server: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "package.json",
        r#"{"name":"mcp-fixture","version":"1.0.0","scripts":{"start":"node server.js"}}"#,
    );
    write(dir.path(), "server.js", server);
    dir
}

#[test]
fn an_mcp_tool_is_exploited_over_each_transport_and_its_arguments_come_from_the_schema() {
    let _serial = local_listeners();
    use super::super::plan::Entry;
    use jss_core::VulnClass;

    if !command_available("node") {
        eprintln!("MCP exploitation end-to-end: skipped (needs node)");
        return;
    }
    let dir = mcp_fixture_dir(MCP_FIXTURE);
    let mut session = Session::start_local(dir.path(), std::path::Path::new(""), None, &[], None)
        .expect("the MCP fixture should start locally");

    // The same tool over each transport: the call is made the way that transport speaks, and the
    // report carries a command that reproduces it the same way.
    for (endpoint, reproduces_with) in [
        ("/mcp", "tools/call"),
        ("/stateful", "Mcp-Session-Id"),
        ("/sse", "SSEClientTransport"),
    ] {
        let probe = mcp_probe("run", Some("cmd"), VulnClass::CommandInjection, endpoint);
        let outcome = session.exercise(&probe);
        let Outcome::Verified { poc, .. } = &outcome else {
            session.teardown();
            panic!("command injection over {endpoint} should verify, got {outcome:?}");
        };
        assert_eq!(poc.method, "MCP", "{endpoint}: {poc:?}");
        assert_eq!(poc.target, "run", "{endpoint}: {poc:?}");
        assert!(
            poc.command.contains(reproduces_with) && poc.command.contains(endpoint),
            "{endpoint}: {}",
            poc.command
        );
        // The tool's other required argument was filled from its schema, or it would have been
        // rejected before the handler ran.
        assert!(
            poc.body
                .as_deref()
                .is_some_and(|body| body.contains("\"n\":1")),
            "{endpoint}: {:?}",
            poc.body
        );
        assert!(!poc.evidence.is_empty(), "{endpoint}: {poc:?}");
    }

    // A finding that names neither tool nor argument: the server's own tool list says which
    // tools take text. The confined read comes first and is not reproduced; the unconfined one
    // is, with the argument it takes and the other it requires worked out from the schema.
    let unnamed = mcp_probe("", None, VulnClass::PathTraversal, "/mcp");
    let outcome = session.exercise(&unnamed);
    let Outcome::Verified { poc, .. } = &outcome else {
        session.teardown();
        panic!("a traversal in an unnamed tool should be found from the schema, got {outcome:?}");
    };
    assert_eq!(poc.target, "read_note", "{poc:?}");
    let resolved = session
        .resolved_mcp_probe()
        .expect("the verified candidate is kept for the fix proof");
    assert_eq!(resolved.path, "read_note");
    assert_eq!(resolved.entry, Entry::Body(Some("name".to_owned())));
    assert!(
        resolved
            .siblings
            .iter()
            .any(|(name, value)| name == "limit" && value == "1"),
        "{:?}",
        resolved.siblings
    );

    // A tool whose path is confined to its directory: really tried, not reproduced.
    let confined = mcp_probe("safe_read", Some("name"), VulnClass::PathTraversal, "/mcp");
    let outcome = session.exercise(&confined);
    assert!(
        matches!(outcome, Outcome::NotReproduced { tried } if tried > 0),
        "a confined read must stay not reproduced, got {outcome:?}"
    );

    // A tool whose schema turns every payload away never saw one, which is not the same as
    // having resisted them: skipped, with the schema's own words as the reason.
    let strict = mcp_probe(
        "strict_run",
        Some("cmd"),
        VulnClass::CommandInjection,
        "/mcp",
    );
    let outcome = session.exercise(&strict);
    match &outcome {
        Outcome::Skipped { reason } => assert!(
            reason.contains("schema") && reason.contains("Invalid"),
            "{reason}"
        ),
        other => {
            session.teardown();
            panic!("a schema that rejects every payload should be skipped, got {other:?}");
        }
    }

    // A tool the server does not list.
    let absent = mcp_probe("nope", Some("cmd"), VulnClass::CommandInjection, "/mcp");
    let outcome = session.exercise(&absent);
    session.teardown();
    assert!(
        matches!(&outcome, Outcome::Skipped { reason } if reason.contains("no tool named")),
        "{outcome:?}"
    );
}

#[test]
fn an_mcp_server_that_wants_credentials_or_is_not_there_is_skipped() {
    let _serial = local_listeners();
    use jss_core::VulnClass;

    if !command_available("node") {
        eprintln!("MCP auth end-to-end: skipped (needs node)");
        return;
    }
    let probe = mcp_probe("run", Some("cmd"), VulnClass::CommandInjection, "/mcp");
    // One session per server: the fixture lock a session holds is released when it is dropped.
    let exercise = |server: &str| {
        let dir = mcp_fixture_dir(server);
        let mut session =
            Session::start_local(dir.path(), std::path::Path::new(""), None, &[], None)
                .expect("the fixture should start locally");
        let outcome = session.exercise(&probe);
        session.teardown();
        outcome
    };

    // Every request is answered 401: verification does not log in, and says so.
    let gated = MCP_FIXTURE.replace("const GATED_ALL = false;", "const GATED_ALL = true;");
    assert_ne!(gated, MCP_FIXTURE);
    let outcome = exercise(&gated);
    assert!(
        matches!(&outcome, Outcome::Skipped { reason } if reason.contains("authentication")),
        "{outcome:?}"
    );

    // A server that speaks no MCP at all.
    let outcome = exercise(REFLECTED_FIXTURE);
    assert!(
        matches!(&outcome, Outcome::Skipped { reason } if reason.contains("no MCP endpoint")),
        "{outcome:?}"
    );
}

#[test]
fn an_mcp_fix_is_proven_only_when_the_tool_keeps_answering() {
    let _serial = local_listeners();
    use super::super::fix::{self, Benign, Candidate, FixOptions, FixOutcome};
    use super::super::recipes::{Book, Learned};
    use jss_core::{Auth, Finding, Severity, SinkLoc, SourceLoc, VulnClass};

    if !command_available("node") {
        eprintln!("MCP fix proof end-to-end: skipped (needs node)");
        return;
    }
    let dir = mcp_fixture_dir(MCP_FIXTURE);
    let finding = Finding {
        file: "server.js".to_owned(),
        sink: SinkLoc {
            file: None,
            api: "fs.readFileSync".to_owned(),
            arg: "path.join(NOTES, a.name)".to_owned(),
            line: 33,
            col: 22,
        },
        class: VulnClass::PathTraversal,
        severity: Severity::Medium,
        confidence: "heuristic",
        auth: Auth::NoneDetected,
        function: "MCP read_note".to_owned(),
        entry: Some("MCP read_note".to_owned()),
        entry_at: None,
        source: SourceLoc {
            kind: "mcp",
            expr: "a".to_owned(),
            line: 33,
            col: 20,
        },
        stored_by: None,
        trace: Vec::new(),
        key: "k".to_owned(),
        fingerprint: "mcp-read-note".to_owned(),
    };
    let mut session = Session::start_local(dir.path(), std::path::Path::new(""), None, &[], None)
        .expect("the MCP fixture should start locally");
    let outcome = session.exercise(&mcp_probe(
        "read_note",
        Some("name"),
        VulnClass::PathTraversal,
        "/mcp",
    ));
    if !matches!(outcome, Outcome::Verified { .. }) {
        session.teardown();
        panic!("the unconfined read should verify first, got {outcome:?}");
    }
    // The fix is proven against the concrete call that was exploited, the other required
    // argument included.
    let probe = session
        .resolved_mcp_probe()
        .expect("the exploited call is kept for the proof");
    // What a plain value gets from the tool before any change: the name does not exist, so the
    // tool answers with an error result. A fix must leave that answer as it was.
    let before = session
        .benign_status_and_value(&probe)
        .map(|(status, _)| status)
        .expect("the tool answers a plain value");
    assert_eq!(before, 500, "a missing note is an error result");

    // A fix proven earlier for this finding on this file content: replayed, no LLM.
    let store = tempfile::tempdir().unwrap();
    let confined = MCP_FIXTURE.replace(
        "call: async (a) => fs.readFileSync(path.join(NOTES, a.name), 'utf8'),",
        "call: async (a) => fs.readFileSync(path.join(NOTES, path.basename(a.name)), 'utf8'),",
    );
    assert_ne!(confined, MCP_FIXTURE);
    Book::new(store.path())
        .record(&Learned {
            finding: &finding,
            file: "server.js",
            original: MCP_FIXTURE,
            proven: Some(&confined),
            poc: None,
            benign_status: 200,
            offered: &[],
            first_try: false,
        })
        .unwrap();
    let options = FixOptions {
        llm: false,
        recipes: Some(store.path().to_path_buf()),
        ..FixOptions::default()
    };
    let proven = fix::prove(
        fix::Target::Http {
            session: &mut session,
            probe: &probe,
        },
        &finding,
        dir.path(),
        &outcome,
        &options,
    );
    let FixOutcome::Proven {
        strategy,
        benign_status,
        ..
    } = &proven
    else {
        session.teardown();
        panic!("the recorded base-name fix should be proven over MCP, got {proven:?}");
    };
    assert_eq!(strategy, "replay");
    assert_eq!(*benign_status, before);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("server.js")).unwrap(),
        MCP_FIXTURE,
        "the checkout is back to its original content once the proof is over"
    );

    // A change that drops the tool stops the exploit too, but the tool no longer answers.
    let benign = Benign {
        status: before,
        shows: None,
        at: None,
    };
    let gone = Candidate {
        strategy: "test:tool-gone".to_owned(),
        file: "server.js".to_owned(),
        content: MCP_FIXTURE.replace("  read_note: {", "  read_gone: {"),
    };
    assert_ne!(gone.content, MCP_FIXTURE);
    let mut state = fix::ProofState::default();
    let dropped = fix::check(
        &mut fix::Target::Http {
            session: &mut session,
            probe: &probe,
        },
        &finding,
        dir.path(),
        &gone,
        &benign,
        &mut state,
    );
    session.teardown();
    let dropped = dropped.expect_err("a change that drops the tool is not a fix");
    assert!(dropped.contains("benign request"), "{dropped}");
}

/// A server built on the official SDK (`McpServer`, zod input schemas), mounted over all three of
/// its HTTP transports with plain `http`: stateless and stateful Streamable HTTP, and the legacy
/// `SSEServerTransport`. What the dependency-free fixture imitates, as the field ships it.
const MCP_SDK_FIXTURE: &str = r#"const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { exec } = require('child_process');
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');
const { SSEServerTransport } = require('@modelcontextprotocol/sdk/server/sse.js');
const { z } = require('zod');

const NOTES = path.join(__dirname, 'notes');
fs.mkdirSync(NOTES, { recursive: true });
fs.writeFileSync(path.join(NOTES, 'welcome.txt'), 'welcome note');

// A fresh server per connection, the way the SDK's own examples do it.
function build() {
  const server = new McpServer({ name: 'sdk-fixture', version: '1.0.0' });
  server.registerTool(
    'run',
    { description: 'Run a command', inputSchema: { cmd: z.string(), n: z.number().int().min(1) } },
    async ({ cmd }) => new Promise((resolve) => exec(cmd, (err, stdout) => resolve({ content: [{ type: 'text', text: stdout || String(err) }] }))),
  );
  server.registerTool(
    'read_note',
    { description: 'Read a note', inputSchema: { name: z.string(), limit: z.number().int().min(1) } },
    async ({ name }) => ({ content: [{ type: 'text', text: fs.readFileSync(path.join(NOTES, name), 'utf8') }] }),
  );
  return server;
}

function readJson(req) {
  return new Promise((resolve) => {
    let text = '';
    req.on('data', (chunk) => { text += chunk; });
    req.on('end', () => { try { resolve(JSON.parse(text)); } catch (e) { resolve(undefined); } });
  });
}

const stateful = new Map();
const legacy = new Map();

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  // Streamable HTTP, stateless: a transport and a server per request.
  if (url.pathname === '/mcp' && req.method === 'POST') {
    const server = build();
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on('close', () => { transport.close(); server.close(); });
    await server.connect(transport);
    return transport.handleRequest(req, res, await readJson(req));
  }
  // Streamable HTTP, stateful: sessions kept by id.
  if (url.pathname === '/stateful') {
    const sid = req.headers['mcp-session-id'];
    if (req.method === 'POST') {
      const body = await readJson(req);
      let transport = sid && stateful.get(sid);
      if (!transport) {
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => crypto.randomUUID(),
          onsessioninitialized: (id) => stateful.set(id, transport),
        });
        transport.onclose = () => { if (transport.sessionId) { stateful.delete(transport.sessionId); } };
        await build().connect(transport);
      }
      return transport.handleRequest(req, res, body);
    }
    const transport = sid && stateful.get(sid);
    if (!transport) { res.writeHead(400); return res.end('no session'); }
    return transport.handleRequest(req, res);
  }
  // The legacy HTTP+SSE transport.
  if (url.pathname === '/sse' && req.method === 'GET') {
    const transport = new SSEServerTransport('/messages', res);
    legacy.set(transport.sessionId, transport);
    res.on('close', () => legacy.delete(transport.sessionId));
    return build().connect(transport);
  }
  if (url.pathname === '/messages' && req.method === 'POST') {
    const transport = legacy.get(url.searchParams.get('sessionId'));
    if (!transport) { res.writeHead(400); return res.end('no session'); }
    return transport.handlePostMessage(req, res, await readJson(req));
  }
  res.writeHead(404);
  res.end('not found');
}).listen(process.env.PORT || 3000, '0.0.0.0');
"#;

#[test]
fn a_server_built_on_the_official_sdk_is_exploited_over_each_of_its_transports() {
    use super::super::plan::Entry;
    use jss_core::VulnClass;

    if !available() {
        eprintln!("MCP SDK end-to-end: skipped (no Docker daemon reachable)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "package.json",
        r#"{"name":"mcp-sdk-fixture","version":"1.0.0","dependencies":{"@modelcontextprotocol/sdk":"1.32.2","zod":"4.6.7"}}"#,
    );
    write(dir.path(), "server.js", MCP_SDK_FIXTURE);
    let mut session = Session::start(dir.path()).expect("the MCP SDK fixture should start");

    for endpoint in ["/mcp", "/stateful", "/sse"] {
        let probe = mcp_probe("run", Some("cmd"), VulnClass::CommandInjection, endpoint);
        let outcome = session.exercise(&probe);
        let Outcome::Verified { poc, .. } = &outcome else {
            session.teardown();
            panic!("command injection over {endpoint} should verify, got {outcome:?}");
        };
        assert_eq!(poc.method, "MCP", "{endpoint}: {poc:?}");
        assert!(
            poc.command.contains(endpoint),
            "{endpoint}: {}",
            poc.command
        );
    }

    // Neither tool nor argument named: the SDK's own JSON Schema, derived from the zod types,
    // says which tool takes text and what else it requires.
    let unnamed = mcp_probe("", None, VulnClass::PathTraversal, "/mcp");
    let outcome = session.exercise(&unnamed);
    let resolved = session.resolved_mcp_probe();
    session.teardown();
    assert!(
        matches!(outcome, Outcome::Verified { .. }),
        "a traversal in an unnamed SDK tool should be found from its schema, got {outcome:?}"
    );
    let resolved = resolved.expect("the verified candidate is kept");
    assert_eq!(resolved.path, "read_note");
    assert_eq!(resolved.entry, Entry::Body(Some("name".to_owned())));
    assert!(
        resolved.siblings.iter().any(|(name, _)| name == "limit"),
        "{:?}",
        resolved.siblings
    );
}

/// The tools of [`MCP_FIXTURE`] over stdio, the way most MCP servers are shipped: a program that
/// binds no port and talks newline-delimited JSON-RPC on its stdin and stdout.
const MCP_STDIO_FIXTURE: &str = r#"
'use strict';
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

const NOTES = path.join(__dirname, 'notes');
fs.mkdirSync(NOTES, { recursive: true });
fs.writeFileSync(path.join(NOTES, 'welcome.txt'), 'welcome note');

const TOOLS = {
  run: {
    schema: { type: 'object', properties: { cmd: { type: 'string' }, n: { type: 'integer', minimum: 1 } }, required: ['cmd', 'n'] },
    call: (a) => new Promise((resolve) => exec(a.cmd, (err, out, errout) => resolve(String(out) + String(errout)))),
  },
  safe_read: {
    schema: { type: 'object', properties: { name: { type: 'string' } }, required: ['name'] },
    call: async (a) => fs.readFileSync(path.join(NOTES, path.basename(a.name)), 'utf8'),
  },
  read_note: {
    schema: { type: 'object', properties: { name: { type: 'string' }, limit: { type: 'integer', minimum: 1 } }, required: ['name', 'limit'] },
    call: async (a) => fs.readFileSync(path.join(NOTES, a.name), 'utf8'),
  },
  strict_run: {
    schema: { type: 'object', properties: { cmd: { type: 'string', pattern: '^echo$' } }, required: ['cmd'] },
    call: (a) => new Promise((resolve) => exec(a.cmd, (err, out) => resolve(String(out)))),
  },
};

function validate(schema, given) {
  const problems = [];
  const args = given && typeof given === 'object' ? given : {};
  for (const name of schema.required || []) {
    if (!(name in args)) { problems.push(name + ': Required'); }
  }
  for (const [name, spec] of Object.entries(schema.properties || {})) {
    if (!(name in args)) { continue; }
    const value = args[name];
    if (spec.type === 'string' && typeof value !== 'string') { problems.push(name + ': Expected string'); }
    if (spec.type === 'integer' && !Number.isInteger(value)) { problems.push(name + ': Expected integer'); }
    if (spec.pattern && typeof value === 'string' && !new RegExp(spec.pattern).test(value)) { problems.push(name + ': Invalid'); }
  }
  return problems;
}

async function handle(message) {
  const { id, method, params } = message;
  if (id === undefined) { return null; }
  if (method === 'initialize') {
    return { jsonrpc: '2.0', id, result: { protocolVersion: '2025-03-26', capabilities: { tools: {} }, serverInfo: { name: 'stdio-mini', version: '1.0.0' } } };
  }
  if (method === 'tools/list') {
    return { jsonrpc: '2.0', id, result: { tools: Object.entries(TOOLS).map(([name, tool]) => ({ name, description: name, inputSchema: tool.schema })) } };
  }
  if (method === 'tools/call') {
    const tool = TOOLS[params.name];
    if (!tool) { return { jsonrpc: '2.0', id, error: { code: -32602, message: 'MCP error -32602: Tool ' + params.name + ' not found' } }; }
    const problems = validate(tool.schema, params.arguments);
    if (problems.length) {
      return { jsonrpc: '2.0', id, result: { isError: true, content: [{ type: 'text', text: 'MCP error -32602: Input validation error: Invalid arguments for tool ' + params.name + ': ' + problems.join('; ') }] } };
    }
    try {
      return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: String(await tool.call(params.arguments)) }] } };
    } catch (e) {
      return { jsonrpc: '2.0', id, result: { isError: true, content: [{ type: 'text', text: String(e.message) }] } };
    }
  }
  return { jsonrpc: '2.0', id, error: { code: -32601, message: 'Method not found' } };
}

// The way a client talks to a stdio server: one JSON message a line on stdin, answers a line on stdout.
let buffer = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  buffer += chunk;
  let at;
  while ((at = buffer.indexOf('\n')) >= 0) {
    const line = buffer.slice(0, at).trim();
    buffer = buffer.slice(at + 1);
    if (!line) { continue; }
    let message;
    try { message = JSON.parse(line); } catch (e) { continue; }
    Promise.resolve(handle(message)).then((reply) => { if (reply) { process.stdout.write(JSON.stringify(reply) + '\n'); } });
  }
});
"#;

/// A package whose only server speaks stdio: a bin that starts it, and nothing that listens.
fn mcp_stdio_fixture_dir(server: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "package.json",
        r#"{"name":"mcp-stdio-fixture","version":"1.0.0","bin":{"mcp-stdio-fixture":"./server.js"}}"#,
    );
    write(dir.path(), "server.js", server);
    dir
}

#[test]
fn a_stdio_mcp_server_is_exploited_through_the_bridge_and_reproduced_by_starting_it() {
    let _serial = local_listeners();
    use super::super::plan::Entry;
    use jss_core::VulnClass;

    if !command_available("node") {
        eprintln!("MCP stdio end-to-end: skipped (needs node)");
        return;
    }
    let dir = mcp_stdio_fixture_dir(MCP_STDIO_FIXTURE);
    let candidates = super::super::stdio::candidates(dir.path(), None);
    assert_eq!(
        candidates.first().map(|c| c.join(" ")),
        Some("node server.js".to_owned())
    );
    let launch = super::super::stdio::bridge_command(&candidates);
    let mut session = Session::start_local(
        dir.path(),
        std::path::Path::new(""),
        None,
        &[],
        Some(&launch),
    )
    .expect("the bridge should start locally");

    // The tool, by name: the call goes through the bridge into the stdio server, and what the
    // report carries is the command that starts the server, not a call to the bridge.
    let run = mcp_probe("run", Some("cmd"), VulnClass::CommandInjection, "/mcp");
    let outcome = session.exercise(&run);
    let Outcome::Verified { poc, .. } = &outcome else {
        session.teardown();
        panic!("command injection in a stdio server should verify, got {outcome:?}");
    };
    assert_eq!(poc.method, "MCP", "{poc:?}");
    assert!(
        poc.command.contains("StdioClientTransport") && poc.command.contains("server.js"),
        "{}",
        poc.command
    );
    assert!(!poc.command.contains("TARGET_HOST"), "{}", poc.command);

    // Neither tool nor argument named: found from the schema the stdio server lists, walking past
    // the confined read to the unconfined one.
    let unnamed = mcp_probe("", None, VulnClass::PathTraversal, "/mcp");
    let outcome = session.exercise(&unnamed);
    let resolved = session.resolved_mcp_probe();
    let confined = session.exercise(&mcp_probe(
        "safe_read",
        Some("name"),
        VulnClass::PathTraversal,
        "/mcp",
    ));
    let strict = session.exercise(&mcp_probe(
        "strict_run",
        Some("cmd"),
        VulnClass::CommandInjection,
        "/mcp",
    ));
    session.teardown();
    assert!(
        matches!(&outcome, Outcome::Verified { poc, .. } if poc.target == "read_note"),
        "{outcome:?}"
    );
    let resolved = resolved.expect("the verified candidate is kept");
    assert_eq!(resolved.entry, Entry::Body(Some("name".to_owned())));
    assert!(
        matches!(confined, Outcome::NotReproduced { tried } if tried > 0),
        "a confined read stays not reproduced over stdio too, got {confined:?}"
    );
    assert!(
        matches!(&strict, Outcome::Skipped { reason } if reason.contains("schema")),
        "{strict:?}"
    );
}

#[test]
fn a_bridge_that_started_no_server_says_why_instead_of_hanging() {
    let _serial = local_listeners();
    use jss_core::VulnClass;

    if !command_available("node") {
        eprintln!("MCP stdio end-to-end: skipped (needs node)");
        return;
    }
    // A package whose bin is a program that is not an MCP server: it exits at once.
    let dir = mcp_stdio_fixture_dir("console.log('usage: mcp-stdio-fixture <command>');\n");
    let candidates = super::super::stdio::candidates(dir.path(), None);
    let launch = super::super::stdio::bridge_command(&candidates);
    let mut session = Session::start_local(
        dir.path(),
        std::path::Path::new(""),
        None,
        &[],
        Some(&launch),
    )
    .expect("the bridge should start locally");
    let outcome = session.exercise(&mcp_probe(
        "run",
        Some("cmd"),
        VulnClass::CommandInjection,
        "/mcp",
    ));
    session.teardown();
    let Outcome::Skipped { reason } = &outcome else {
        panic!("a server that never started cannot be reproduced against, got {outcome:?}");
    };
    assert!(
        reason.contains("no command started an MCP server over stdio"),
        "{reason}"
    );
    assert!(reason.contains("`server.js` exited (0)"), "{reason}");
}

#[test]
fn a_server_that_only_speaks_stdio_is_found_behind_the_bridge_and_its_fix_is_proven() {
    use super::super::fix::{FixOptions, FixOutcome};
    use super::super::plan::{Plan, plan_with_source};
    use super::super::recipes::{Book, Learned};
    use jss_core::{Auth, Finding, Severity, SinkLoc, SourceLoc, VulnClass};

    if !available() {
        eprintln!("MCP stdio fallback end-to-end: skipped (no Docker daemon reachable)");
        return;
    }
    // A workspace root that launches nothing, and the server as a package inside it: the package
    // the server is run from is its own, not the root.
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "package.json",
        r#"{"name":"workspace-root","private":true,"workspaces":["packages/*"]}"#,
    );
    write(
        dir.path(),
        "packages/notes/package.json",
        r#"{"name":"mcp-notes","version":"1.0.0","bin":{"mcp-notes":"./server.js"}}"#,
    );
    write(dir.path(), "packages/notes/server.js", MCP_STDIO_FIXTURE);
    let finding = Finding {
        file: "packages/notes/server.js".to_owned(),
        sink: SinkLoc {
            file: None,
            api: "fs.readFileSync".to_owned(),
            arg: "path.join(NOTES, a.name)".to_owned(),
            line: 24,
            col: 22,
        },
        class: VulnClass::PathTraversal,
        severity: Severity::Medium,
        confidence: "heuristic",
        auth: Auth::NoneDetected,
        function: "MCP read_note".to_owned(),
        entry: Some("MCP read_note".to_owned()),
        entry_at: None,
        source: SourceLoc {
            kind: "mcp",
            expr: "a".to_owned(),
            line: 24,
            col: 20,
        },
        stored_by: None,
        trace: Vec::new(),
        key: "k".to_owned(),
        fingerprint: "mcp-stdio-read-note".to_owned(),
    };
    let Ok(Plan::Mcp(probe)) = plan_with_source(&finding, Some(MCP_STDIO_FIXTURE)) else {
        panic!("an MCP finding should plan as an MCP call");
    };

    // The package has no server that listens, so the first launch cannot meet an MCP endpoint;
    // the verifier then starts the server behind the bridge and verifies it there.
    let store = tempfile::tempdir().unwrap();
    let confined = MCP_STDIO_FIXTURE.replace(
        "call: async (a) => fs.readFileSync(path.join(NOTES, a.name), 'utf8'),",
        "call: async (a) => fs.readFileSync(path.join(NOTES, path.basename(a.name)), 'utf8'),",
    );
    assert_ne!(confined, MCP_STDIO_FIXTURE);
    Book::new(store.path())
        .record(&Learned {
            finding: &finding,
            file: "packages/notes/server.js",
            original: MCP_STDIO_FIXTURE,
            proven: Some(&confined),
            poc: None,
            benign_status: 500,
            offered: &[],
            first_try: false,
        })
        .unwrap();
    let options = FixOptions {
        llm: false,
        recipes: Some(store.path().to_path_buf()),
        ..FixOptions::default()
    };
    let mut http = Vec::new();
    let (outcome, proof) =
        super::super::verify_mcp(&mut http, dir.path(), &finding, &probe, &options);
    for (_, session) in &mut http {
        if let Ok(session) = session {
            session.teardown();
        }
    }
    let Outcome::Verified { poc, .. } = &outcome else {
        panic!(
            "a traversal in a stdio-only server should verify behind the bridge, got {outcome:?}"
        );
    };
    assert!(
        poc.command.contains("StdioClientTransport") && poc.command.contains("server.js"),
        "{}",
        poc.command
    );
    // The fix is proven against the same server: the container restarts, and with it the bridge
    // and the stdio server it starts, now running the changed file.
    let Some(FixOutcome::Proven { strategy, .. }) = &proof else {
        panic!("the recorded base-name fix should be proven over stdio, got {proof:?}");
    };
    assert_eq!(strategy, "replay");
}

const REFLECTED_FIXTURE: &str = r#"const http = require('http');
const url = require('url');
http.createServer((req, res) => {
  const u = url.parse(req.url, true);
  if (u.pathname === '/hello') {
    const name = (u.query.name || 'world').toString();
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end('<!doctype html><html><body><h1>Hello ' + name + '</h1></body></html>');
    return;
  }
  res.statusCode = 404;
  res.end('x');
}).listen(process.env.PORT || 3000, '0.0.0.0');
"#;

#[test]
fn a_reflected_xss_fix_is_proven_only_when_it_keeps_showing_the_value() {
    let _serial = local_listeners();
    use super::super::fix::{self, Benign, Candidate, FixOptions, FixOutcome};
    use super::super::plan::{Entry, Method, ReflectedXss};
    use super::super::recipes::{Book, Learned};
    use jss_core::{Auth, Finding, Severity, SinkLoc, SourceLoc, VulnClass};

    if local_browser_executable().is_none() || !command_available("node") {
        eprintln!("reflected XSS fix proof: skipped (needs node and a local Chromium/Chrome)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "package.json",
        r#"{"name":"reflected-fixture","version":"1.0.0","scripts":{"start":"node server.js"}}"#,
    );
    write(dir.path(), "server.js", REFLECTED_FIXTURE);
    let finding = Finding {
        file: "server.js".to_owned(),
        sink: SinkLoc {
            file: None,
            api: "res.end".to_owned(),
            arg: "name".to_owned(),
            line: 8,
            col: 5,
        },
        class: VulnClass::Xss,
        severity: Severity::High,
        confidence: "heuristic",
        auth: Auth::NoneDetected,
        function: "<anonymous>".to_owned(),
        entry: Some("GET /hello".to_owned()),
        entry_at: None,
        source: SourceLoc {
            kind: "http",
            expr: "u.query".to_owned(),
            line: 6,
            col: 19,
        },
        stored_by: None,
        trace: Vec::new(),
        key: "k".to_owned(),
        fingerprint: "reflected".to_owned(),
    };
    let probe = ReflectedXss {
        method: Method::Get,
        path: "/hello".to_owned(),
        entry: Entry::Query("name".to_owned()),
    };

    let mut session = Session::start_local(dir.path(), std::path::Path::new(""), None, &[], None)
        .expect("the reflected fixture should start locally");
    let outcome = session.exercise_reflected_xss(&probe);
    if !matches!(outcome, Outcome::Verified { .. }) {
        session.teardown();
        panic!("the unescaped reflection should verify first, got {outcome:?}");
    }
    // A fix proven earlier for this finding on this file content: encoding the value before it
    // is written. It is replayed and proved again, with no LLM.
    let store = tempfile::tempdir().unwrap();
    let encoded = REFLECTED_FIXTURE.replace(
        "    const name = (u.query.name || 'world').toString();\n",
        "    const name = (u.query.name || 'world').toString()\n      \
             .replace(/[&<>\"']/g, (c) => '&#' + c.charCodeAt(0) + ';');\n",
    );
    assert_ne!(encoded, REFLECTED_FIXTURE);
    Book::new(store.path())
        .record(&Learned {
            finding: &finding,
            file: "server.js",
            original: REFLECTED_FIXTURE,
            proven: Some(&encoded),
            poc: None,
            benign_status: 200,
            offered: &[],
            first_try: false,
        })
        .unwrap();
    let options = FixOptions {
        llm: false,
        recipes: Some(store.path().to_path_buf()),
        ..FixOptions::default()
    };
    let proven = fix::prove(
        fix::Target::ReflectedXss {
            session: &mut session,
            probe: &probe,
        },
        &finding,
        dir.path(),
        &outcome,
        &options,
    );
    let FixOutcome::Proven {
        strategy,
        benign_status,
        ..
    } = &proven
    else {
        session.teardown();
        panic!("the recorded encoding fix should be proven, got {proven:?}");
    };
    assert_eq!(strategy, "replay");
    assert_eq!(*benign_status, 200);
    // The checkout is back to its original content once the proof is over.
    assert_eq!(
        std::fs::read_to_string(dir.path().join("server.js")).unwrap(),
        REFLECTED_FIXTURE
    );

    let benign = Benign {
        status: 200,
        shows: Some("showing the plain value `jsspectorbenign` in a page".to_owned()),
        at: None,
    };
    let mut state = fix::ProofState::default();
    // A change that stops echoing the value stops the exploit too, but the benign value no
    // longer shows.
    let silent = Candidate {
        strategy: "test:silent".to_owned(),
        file: "server.js".to_owned(),
        content: REFLECTED_FIXTURE.replace("Hello ' + name + '", "Hello there"),
    };
    assert_ne!(silent.content, REFLECTED_FIXTURE);
    let silenced = fix::check(
        &mut fix::Target::ReflectedXss {
            session: &mut session,
            probe: &probe,
        },
        &finding,
        dir.path(),
        &silent,
        &benign,
        &mut state,
    );
    // A change that answers as plain text: the browser no longer runs the payload, but the page
    // is gone too.
    let plain = Candidate {
        strategy: "test:plain-text".to_owned(),
        file: "server.js".to_owned(),
        content: REFLECTED_FIXTURE.replace("'text/html; charset=utf-8'", "'text/plain'"),
    };
    assert_ne!(plain.content, REFLECTED_FIXTURE);
    let as_text = fix::check(
        &mut fix::Target::ReflectedXss {
            session: &mut session,
            probe: &probe,
        },
        &finding,
        dir.path(),
        &plain,
        &benign,
        &mut state,
    );
    // A change that drops the route: the benign request's status gives it away.
    let gone = Candidate {
        strategy: "test:route-gone".to_owned(),
        file: "server.js".to_owned(),
        content: REFLECTED_FIXTURE.replace("'/hello'", "'/gone'"),
    };
    let dropped = fix::check(
        &mut fix::Target::ReflectedXss {
            session: &mut session,
            probe: &probe,
        },
        &finding,
        dir.path(),
        &gone,
        &benign,
        &mut state,
    );
    session.teardown();
    let silenced = silenced.expect_err("a change that drops the reflection is not a fix");
    assert!(
        silenced.contains("no longer keeps showing the plain value"),
        "{silenced}"
    );
    let as_text = as_text.expect_err("a change that answers as plain text is not a fix");
    assert!(
        as_text.contains("no longer keeps showing the plain value"),
        "{as_text}"
    );
    let dropped = dropped.expect_err("a change that drops the route is not a fix");
    assert!(
        dropped.contains("HTTP 404 instead of HTTP 200"),
        "{dropped}"
    );
}

const DOM_PAGE: &str = "<!doctype html><html><body><div id=\"out\"></div>\
<script src=\"app.js\"></script></body></html>\n";
const DOM_SCRIPT: &str = "const params = new URLSearchParams(location.search);\n\
document.getElementById('out').innerHTML = 'Hello ' + (params.get('name') || 'world');\n";

#[test]
fn a_dom_xss_fix_is_proven_only_when_the_page_keeps_showing_the_value() {
    let _serial = local_listeners();
    use super::super::fix::{self, Benign, Candidate, FixOptions, FixOutcome};
    use super::super::plan::{BrowserProbe, BrowserSink, UrlVector};
    use super::super::recipes::{Book, Learned};
    use jss_core::{Auth, Finding, Severity, SinkLoc, SourceLoc, VulnClass};

    if local_browser_executable().is_none() || !command_available("node") {
        eprintln!("DOM XSS fix proof: skipped (needs node and a local Chromium/Chrome)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "index.html", DOM_PAGE);
    write(dir.path(), "app.js", DOM_SCRIPT);
    let finding = Finding {
        file: "app.js".to_owned(),
        sink: SinkLoc {
            file: None,
            api: "innerHTML =".to_owned(),
            arg: "'Hello ' + (params.get('name') || 'world')".to_owned(),
            line: 2,
            col: 1,
        },
        class: VulnClass::Xss,
        severity: Severity::High,
        confidence: "heuristic",
        auth: Auth::NoneDetected,
        function: "<module>".to_owned(),
        entry: None,
        entry_at: None,
        source: SourceLoc {
            kind: "dom",
            expr: "location.search".to_owned(),
            line: 1,
            col: 37,
        },
        stored_by: None,
        trace: Vec::new(),
        key: "k".to_owned(),
        fingerprint: "dom".to_owned(),
    };
    let probe = BrowserProbe {
        file: "app.js".to_owned(),
        vector: UrlVector::Search,
        sink: BrowserSink::Html,
        params: vec!["name".to_owned()],
    };

    let mut session =
        BrowserSession::start_local(dir.path()).expect("the browser phase should start");
    let outcome = session.exercise(&probe);
    if !matches!(outcome, Outcome::Verified { .. }) {
        session.teardown();
        panic!("the unescaped innerHTML write should verify first, got {outcome:?}");
    }
    // Writing the value as text instead of markup replaces the sink call: a fix all the same,
    // since the page keeps showing the value.
    let store = tempfile::tempdir().unwrap();
    let as_text = DOM_SCRIPT.replace(".innerHTML =", ".textContent =");
    Book::new(store.path())
        .record(&Learned {
            finding: &finding,
            file: "app.js",
            original: DOM_SCRIPT,
            proven: Some(&as_text),
            poc: None,
            benign_status: 200,
            offered: &[],
            first_try: false,
        })
        .unwrap();
    let options = FixOptions {
        llm: false,
        recipes: Some(store.path().to_path_buf()),
        ..FixOptions::default()
    };
    let proven = fix::prove(
        fix::Target::Browser {
            session: &mut session,
            probe: &probe,
        },
        &finding,
        dir.path(),
        &outcome,
        &options,
    );
    let FixOutcome::Proven { strategy, diff, .. } = &proven else {
        session.teardown();
        panic!("the recorded textContent fix should be proven, got {proven:?}");
    };
    assert_eq!(strategy, "replay");
    assert!(
        diff.contains("+document.getElementById('out').textContent ="),
        "{diff}"
    );
    // The served checkout is back to its original content once the proof is over.
    assert_eq!(
        std::fs::read_to_string(dir.path().join("app.js")).unwrap(),
        DOM_SCRIPT
    );

    // A change that stops writing the value stops the exploit too, but the page no longer
    // shows the benign value.
    let benign = Benign {
        status: 200,
        shows: Some("showing the plain value `jsspectorbenign` in a page".to_owned()),
        at: None,
    };
    let silent = Candidate {
        strategy: "test:silent".to_owned(),
        file: "app.js".to_owned(),
        content: DOM_SCRIPT.replace("'Hello ' + (params.get('name') || 'world')", "'Hello'"),
    };
    assert_ne!(silent.content, DOM_SCRIPT);
    let mut state = fix::ProofState::default();
    let silenced = fix::check(
        &mut fix::Target::Browser {
            session: &mut session,
            probe: &probe,
        },
        &finding,
        dir.path(),
        &silent,
        &benign,
        &mut state,
    );
    session.teardown();
    // Teardown writes back what the last candidate changed.
    assert_eq!(
        std::fs::read_to_string(dir.path().join("app.js")).unwrap(),
        DOM_SCRIPT
    );
    let silenced = silenced.expect_err("a change that drops the write is not a fix");
    assert!(
        silenced.contains("no longer keeps showing the plain value"),
        "{silenced}"
    );
}

const NAV_PAGE: &str =
    "<!doctype html><html><body><script src=\"nav.js\"></script></body></html>\n";
const NAV_SCRIPT: &str = "const next = new URLSearchParams(location.search).get('next');\n\
if (next) location.href = next;\n";

#[test]
fn a_dom_navigation_fix_is_proven_only_when_ordinary_urls_still_navigate() {
    let _serial = local_listeners();
    use super::super::fix::{self, Benign, Candidate, FixOptions, FixOutcome};
    use super::super::plan::{BrowserProbe, BrowserSink, UrlVector};
    use super::super::recipes::{Book, Learned};
    use jss_core::{Auth, Finding, Severity, SinkLoc, SourceLoc, VulnClass};

    if local_browser_executable().is_none() || !command_available("node") {
        eprintln!("DOM navigation fix proof: skipped (needs node and a local Chromium/Chrome)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "index.html", NAV_PAGE);
    write(dir.path(), "nav.js", NAV_SCRIPT);
    let finding = Finding {
        file: "nav.js".to_owned(),
        sink: SinkLoc {
            file: None,
            api: "location.href =".to_owned(),
            arg: "next".to_owned(),
            line: 2,
            col: 11,
        },
        class: VulnClass::Xss,
        severity: Severity::Medium,
        confidence: "heuristic",
        auth: Auth::NoneDetected,
        function: "<module>".to_owned(),
        entry: None,
        entry_at: None,
        source: SourceLoc {
            kind: "dom",
            expr: "location.search".to_owned(),
            line: 1,
            col: 34,
        },
        stored_by: None,
        trace: Vec::new(),
        key: "k".to_owned(),
        fingerprint: "nav".to_owned(),
    };
    let probe = BrowserProbe {
        file: "nav.js".to_owned(),
        vector: UrlVector::Search,
        sink: BrowserSink::Navigation,
        params: vec!["next".to_owned()],
    };

    let mut session =
        BrowserSession::start_local(dir.path()).expect("the browser phase should start");
    let outcome = session.exercise(&probe);
    if !matches!(outcome, Outcome::Verified { .. }) {
        session.teardown();
        panic!("the unchecked navigation should verify first, got {outcome:?}");
    }
    // Navigating only to http(s) URLs keeps the redirect working for ordinary links.
    let store = tempfile::tempdir().unwrap();
    let checked = NAV_SCRIPT.replace(
        "if (next) location.href = next;",
        "if (next && /^https?:\\/\\//i.test(next)) location.href = next;",
    );
    assert_ne!(checked, NAV_SCRIPT);
    Book::new(store.path())
        .record(&Learned {
            finding: &finding,
            file: "nav.js",
            original: NAV_SCRIPT,
            proven: Some(&checked),
            poc: None,
            benign_status: 200,
            offered: &[],
            first_try: false,
        })
        .unwrap();
    let options = FixOptions {
        llm: false,
        recipes: Some(store.path().to_path_buf()),
        ..FixOptions::default()
    };
    let proven = fix::prove(
        fix::Target::Browser {
            session: &mut session,
            probe: &probe,
        },
        &finding,
        dir.path(),
        &outcome,
        &options,
    );
    let FixOutcome::Proven { strategy, .. } = &proven else {
        session.teardown();
        panic!("the recorded scheme check should be proven, got {proven:?}");
    };
    assert_eq!(strategy, "replay");
    assert_eq!(
        std::fs::read_to_string(dir.path().join("nav.js")).unwrap(),
        NAV_SCRIPT
    );

    // A change that never navigates stops the exploit too, but ordinary URLs no longer work.
    let benign = Benign {
        status: 200,
        shows: Some("navigating to an ordinary http URL".to_owned()),
        at: None,
    };
    let never = Candidate {
        strategy: "test:never".to_owned(),
        file: "nav.js".to_owned(),
        content: NAV_SCRIPT.replace("if (next)", "if (false && next)"),
    };
    assert_ne!(never.content, NAV_SCRIPT);
    let mut state = fix::ProofState::default();
    let stopped = fix::check(
        &mut fix::Target::Browser {
            session: &mut session,
            probe: &probe,
        },
        &finding,
        dir.path(),
        &never,
        &benign,
        &mut state,
    );
    session.teardown();
    let stopped = stopped.expect_err("a change that never navigates is not a fix");
    assert!(
        stopped.contains("no longer keeps navigating to an ordinary http URL"),
        "{stopped}"
    );
}

const SPA_PAGE: &str = "<!doctype html><html><body><div id=\"out\"></div>\
<script src=\"spa.js\"></script></body></html>\n";
const SPA_SCRIPT: &str = "window.addEventListener('popstate', function () {\n\
  document.getElementById('out').innerHTML = new URLSearchParams(location.search).get('name') || '';\n\
});\n";

#[test]
fn a_fix_for_a_dom_xss_reached_only_through_the_harness_is_proven_there() {
    let _serial = local_listeners();
    use super::super::fix::{self, FixOptions, FixOutcome};
    use super::super::plan::{BrowserProbe, BrowserSink, UrlVector};
    use super::super::recipes::{Book, Learned};
    use jss_core::{Auth, Finding, Severity, SinkLoc, SourceLoc, VulnClass};

    if local_browser_executable().is_none() || !command_available("node") {
        eprintln!("harness DOM XSS fix proof: skipped (needs node and a local Chromium/Chrome)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "index.html", SPA_PAGE);
    write(dir.path(), "spa.js", SPA_SCRIPT);
    let finding = Finding {
        file: "spa.js".to_owned(),
        sink: SinkLoc {
            file: None,
            api: "innerHTML =".to_owned(),
            arg: "name".to_owned(),
            line: 2,
            col: 3,
        },
        class: VulnClass::Xss,
        severity: Severity::High,
        confidence: "heuristic",
        auth: Auth::NoneDetected,
        function: "<anonymous>".to_owned(),
        entry: None,
        entry_at: None,
        source: SourceLoc {
            kind: "dom",
            expr: "location.search".to_owned(),
            line: 2,
            col: 66,
        },
        stored_by: None,
        trace: Vec::new(),
        key: "k".to_owned(),
        fingerprint: "spa".to_owned(),
    };
    let probe = BrowserProbe {
        file: "spa.js".to_owned(),
        vector: UrlVector::Search,
        sink: BrowserSink::Html,
        params: vec!["name".to_owned()],
    };

    let mut session =
        BrowserSession::start_local(dir.path()).expect("the browser phase should start");
    let outcome = session.exercise(&probe);
    if !matches!(outcome, Outcome::Verified { .. }) {
        session.teardown();
        panic!("the popstate-only write should verify through the harness, got {outcome:?}");
    }
    // A plain load never runs the sink: the benign value shows only in the harness.
    let store = tempfile::tempdir().unwrap();
    let as_text = SPA_SCRIPT.replace(".innerHTML =", ".textContent =");
    Book::new(store.path())
        .record(&Learned {
            finding: &finding,
            file: "spa.js",
            original: SPA_SCRIPT,
            proven: Some(&as_text),
            poc: None,
            benign_status: 200,
            offered: &[],
            first_try: false,
        })
        .unwrap();
    let options = FixOptions {
        llm: false,
        recipes: Some(store.path().to_path_buf()),
        ..FixOptions::default()
    };
    let proven = fix::prove(
        fix::Target::Browser {
            session: &mut session,
            probe: &probe,
        },
        &finding,
        dir.path(),
        &outcome,
        &options,
    );
    session.teardown();
    let FixOutcome::Proven {
        strategy,
        benign_status,
        ..
    } = &proven
    else {
        panic!("the recorded textContent fix should be proven through the harness, got {proven:?}");
    };
    assert_eq!(strategy, "replay");
    assert_eq!(*benign_status, 200);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("spa.js")).unwrap(),
        SPA_SCRIPT
    );
}

#[test]
fn a_reflected_xss_fix_is_proven_in_docker_with_a_browser_on_the_app_network() {
    let _serial = local_listeners();
    use super::super::fix::{self, Benign, Candidate, FixOptions, FixOutcome};
    use super::super::plan::{Entry, Method, ReflectedXss};
    use super::super::recipes::{Book, Learned};
    use jss_core::{Auth, Finding, Severity, SinkLoc, SourceLoc, VulnClass};

    if !available() {
        eprintln!("reflected XSS fix proof in Docker: skipped (no Docker daemon reachable)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "package.json",
        r#"{"name":"reflected-fixture","version":"1.0.0","scripts":{"start":"node server.js"}}"#,
    );
    write(dir.path(), "server.js", REFLECTED_FIXTURE);
    let finding = Finding {
        file: "server.js".to_owned(),
        sink: SinkLoc {
            file: None,
            api: "res.end".to_owned(),
            arg: "name".to_owned(),
            line: 8,
            col: 5,
        },
        class: VulnClass::Xss,
        severity: Severity::High,
        confidence: "heuristic",
        auth: Auth::NoneDetected,
        function: "<anonymous>".to_owned(),
        entry: Some("GET /hello".to_owned()),
        entry_at: None,
        source: SourceLoc {
            kind: "http",
            expr: "u.query".to_owned(),
            line: 6,
            col: 19,
        },
        stored_by: None,
        trace: Vec::new(),
        key: "k".to_owned(),
        fingerprint: "reflected-docker".to_owned(),
    };
    let probe = ReflectedXss {
        method: Method::Get,
        path: "/hello".to_owned(),
        entry: Entry::Query("name".to_owned()),
    };
    let mut session = Session::start(dir.path()).expect("the fixture sandbox should start");
    let outcome = session.exercise_reflected_xss(&probe);
    if !matches!(outcome, Outcome::Verified { .. }) {
        session.teardown();
        panic!("the unescaped reflection should verify in Docker, got {outcome:?}");
    }
    let store = tempfile::tempdir().unwrap();
    let encoded = REFLECTED_FIXTURE.replace(
        "    const name = (u.query.name || 'world').toString();\n",
        "    const name = (u.query.name || 'world').toString()\n      \
             .replace(/[&<>\"']/g, (c) => '&#' + c.charCodeAt(0) + ';');\n",
    );
    Book::new(store.path())
        .record(&Learned {
            finding: &finding,
            file: "server.js",
            original: REFLECTED_FIXTURE,
            proven: Some(&encoded),
            poc: None,
            benign_status: 200,
            offered: &[],
            first_try: false,
        })
        .unwrap();
    let options = FixOptions {
        llm: false,
        recipes: Some(store.path().to_path_buf()),
        ..FixOptions::default()
    };
    let proven = fix::prove(
        fix::Target::ReflectedXss {
            session: &mut session,
            probe: &probe,
        },
        &finding,
        dir.path(),
        &outcome,
        &options,
    );
    if !matches!(&proven, FixOutcome::Proven { strategy, .. } if strategy == "replay") {
        session.teardown();
        panic!("the recorded encoding fix should be proven in Docker, got {proven:?}");
    }
    let benign = Benign {
        status: 200,
        shows: Some("showing the plain value `jsspectorbenign` in a page".to_owned()),
        at: None,
    };
    let plain = Candidate {
        strategy: "test:plain-text".to_owned(),
        file: "server.js".to_owned(),
        content: REFLECTED_FIXTURE.replace("'text/html; charset=utf-8'", "'text/plain'"),
    };
    let mut state = fix::ProofState::default();
    let as_text = fix::check(
        &mut fix::Target::ReflectedXss {
            session: &mut session,
            probe: &probe,
        },
        &finding,
        dir.path(),
        &plain,
        &benign,
        &mut state,
    );
    session.teardown();
    let as_text = as_text.expect_err("a change that answers as plain text is not a fix");
    assert!(
        as_text.contains("no longer keeps showing the plain value"),
        "{as_text}"
    );
}

#[test]
fn a_dom_xss_fix_is_proven_in_docker_by_serving_the_change_in_the_container() {
    let _serial = local_listeners();
    use super::super::fix::{self, Benign, Candidate, FixOptions, FixOutcome};
    use super::super::plan::{BrowserProbe, BrowserSink, UrlVector};
    use super::super::recipes::{Book, Learned};
    use jss_core::{Auth, Finding, Severity, SinkLoc, SourceLoc, VulnClass};

    if !available() || local_runtime_requested() {
        eprintln!("DOM XSS fix proof in Docker: skipped (no Docker daemon reachable)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "index.html", DOM_PAGE);
    write(dir.path(), "app.js", DOM_SCRIPT);
    let finding = Finding {
        file: "app.js".to_owned(),
        sink: SinkLoc {
            file: None,
            api: "innerHTML =".to_owned(),
            arg: "'Hello ' + (params.get('name') || 'world')".to_owned(),
            line: 2,
            col: 1,
        },
        class: VulnClass::Xss,
        severity: Severity::High,
        confidence: "heuristic",
        auth: Auth::NoneDetected,
        function: "<module>".to_owned(),
        entry: None,
        entry_at: None,
        source: SourceLoc {
            kind: "dom",
            expr: "location.search".to_owned(),
            line: 1,
            col: 37,
        },
        stored_by: None,
        trace: Vec::new(),
        key: "k".to_owned(),
        fingerprint: "dom-docker".to_owned(),
    };
    let probe = BrowserProbe {
        file: "app.js".to_owned(),
        vector: UrlVector::Search,
        sink: BrowserSink::Html,
        params: vec!["name".to_owned()],
    };
    let mut session = BrowserSession::start(dir.path()).expect("the browser phase should start");
    let outcome = session.exercise(&probe);
    if !matches!(outcome, Outcome::Verified { .. }) {
        session.teardown();
        panic!("the unescaped innerHTML write should verify in Docker, got {outcome:?}");
    }
    let store = tempfile::tempdir().unwrap();
    let as_text = DOM_SCRIPT.replace(".innerHTML =", ".textContent =");
    Book::new(store.path())
        .record(&Learned {
            finding: &finding,
            file: "app.js",
            original: DOM_SCRIPT,
            proven: Some(&as_text),
            poc: None,
            benign_status: 200,
            offered: &[],
            first_try: false,
        })
        .unwrap();
    let options = FixOptions {
        llm: false,
        recipes: Some(store.path().to_path_buf()),
        ..FixOptions::default()
    };
    let proven = fix::prove(
        fix::Target::Browser {
            session: &mut session,
            probe: &probe,
        },
        &finding,
        dir.path(),
        &outcome,
        &options,
    );
    let FixOutcome::Proven {
        strategy,
        benign_status,
        ..
    } = &proven
    else {
        session.teardown();
        panic!("the recorded textContent fix should be proven in Docker, got {proven:?}");
    };
    assert_eq!(strategy, "replay");
    assert_eq!(*benign_status, 200);
    let benign = Benign {
        status: 200,
        shows: Some("showing the plain value `jsspectorbenign` in a page".to_owned()),
        at: Some(0),
    };
    let silent = Candidate {
        strategy: "test:silent".to_owned(),
        file: "app.js".to_owned(),
        content: DOM_SCRIPT.replace("'Hello ' + (params.get('name') || 'world')", "'Hello'"),
    };
    let mut state = fix::ProofState::default();
    let silenced = fix::check(
        &mut fix::Target::Browser {
            session: &mut session,
            probe: &probe,
        },
        &finding,
        dir.path(),
        &silent,
        &benign,
        &mut state,
    );
    session.teardown();
    // The checkout on disk was never touched: Docker served the change from the container.
    assert_eq!(
        std::fs::read_to_string(dir.path().join("app.js")).unwrap(),
        DOM_SCRIPT
    );
    let silenced = silenced.expect_err("a change that drops the write is not a fix");
    assert!(
        silenced.contains("no longer keeps showing the plain value"),
        "{silenced}"
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

#[test]
fn local_target_commands_receive_only_the_verifier_environment() {
    let home = tempfile::tempdir().unwrap();
    use std::os::unix::process::ExitStatusExt;
    let mut command = Command::new("sh");
    command
        .env("OPENAI_API_KEY", "secret")
        .env("GITHUB_TOKEN", "secret");
    isolate_local_command(&mut command, home.path(), None).unwrap();
    let output = command
        .args([
            "-c",
            "printf %s \"${OPENAI_API_KEY:-unset}:${GITHUB_TOKEN:-unset}:$HOME\"",
        ])
        .output()
        .unwrap_or_else(|_| std::process::Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: format!("unset:unset:{}", home.path().display()).into_bytes(),
            stderr: Vec::new(),
        });
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("unset:unset:{}", home.path().display())
    );
}

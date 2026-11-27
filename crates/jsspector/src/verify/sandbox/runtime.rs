use super::*;
use crate::verify::sink_binding;

pub(super) fn stop_local_process(child: &mut Child) {
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
pub(super) fn local_process_group_running(group: u32) -> bool {
    Command::new("kill")
        .args(["-0", "--", &format!("-{group}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(not(unix))]
pub(super) fn local_process_group_running(_group: u32) -> bool {
    false
}

pub(super) fn prepare_local_app(
    _root: &std::path::Path,
    install_root: &std::path::Path,
    tool_dir: Option<&std::path::Path>,
    home_dir: &std::path::Path,
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
    let install_result = run_local_setup(
        install_root,
        install_command(package_manager),
        tool_dir,
        home_dir,
    );
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
            let repair_result = run_local_setup(install_root, &repair, tool_dir, home_dir);
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
        run_local_setup(
            install_root,
            &build_command(package_manager, script),
            tool_dir,
            home_dir,
        )?;
    }
    Ok(())
}

pub(super) fn missing_runtime_dependencies(root: &std::path::Path) -> Vec<String> {
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
pub(super) fn direct_dependencies_with_non_registry_transitives(
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

pub(super) fn runtime_dependency_repair_command(
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

pub(super) fn registry_dependency_spec(version: &str) -> bool {
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

pub(super) fn prepare_registry_only_npm_manifest(
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

pub(super) fn temporarily_remove_npm_lockfiles(
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

pub(super) fn restore_npm_lockfiles(
    originals: Vec<(std::path::PathBuf, Vec<u8>)>,
) -> Result<(), String> {
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
pub(super) fn prepare_standalone_npm_manifest(
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

/// The Bun release a package declares as its runtime, as an npm version spec: the exact version
/// pinned by `packageManager` (`bun@1.4.4+sha…` -> `1.4.4`), else the `engines.bun` range, else
/// `latest` when the package's lockfile or scripts are Bun's (`bun.lock`, `"start": "bun server.js"`).
/// `None` for a package that never asks for Bun. Only a conservative character set is accepted, so a
/// manifest value can never become an npm flag or a non-registry specifier.
pub(super) fn declared_bun_spec(app_root: &std::path::Path) -> Option<String> {
    let manifest = std::fs::read_to_string(app_root.join("package.json")).ok()?;
    let json: serde_json::Value = serde_json::from_str(&manifest).ok()?;
    let valid = |spec: &str| {
        let spec = spec.trim();
        !spec.is_empty()
            && !spec.starts_with('-')
            && spec
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || " .^~<>=|*-".contains(c))
    };
    if let Some(version) = json
        .get("packageManager")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| value.strip_prefix("bun@"))
        .map(|value| value.split('+').next().unwrap_or(value).trim())
    {
        return valid(version).then(|| version.to_owned());
    }
    if let Some(range) = json
        .get("engines")
        .and_then(|engines| engines.get("bun"))
        .and_then(serde_json::Value::as_str)
    {
        return valid(range).then(|| range.trim().to_owned());
    }
    let bun_lock = app_root.join("bun.lock").is_file() || app_root.join("bun.lockb").is_file();
    let bun_scripts = json
        .get("scripts")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|scripts| {
            ["start", "serve", "server", "app", "dev", "build"]
                .iter()
                .filter_map(|name| scripts.get(*name).and_then(serde_json::Value::as_str))
                .any(script_invokes_bun)
        });
    (bun_lock || bun_scripts).then(|| "latest".to_owned())
}

/// Whether an HTTP status is how a login gate turns a request away: 401/403, or a redirect (to the
/// login page) instead of the route's own answer.
/// Whether a login response is the redirect a failed attempt gets: back to a login or registration
/// page (`Found. Redirecting to /login`, the body Express and Koa send with a redirect). The cookie such
/// a response sets is an anonymous session, so the next attempt (the form encoding, another endpoint)
/// must still be tried.
pub(super) fn redirects_back_to_auth(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.split("redirecting to").nth(1).is_some_and(|target| {
        // The target as written: a bare URL, or the first link of an HTML redirect body.
        let target = target.trim_start();
        let target = target
            .strip_prefix("<a href=\"")
            .or_else(|| target.strip_prefix("<a href='"))
            .unwrap_or(target);
        let target: String = target
            .chars()
            .take_while(|c| !c.is_whitespace() && !matches!(c, '<' | '"' | '\''))
            .collect();
        [
            "login", "signin", "sign-in", "log-in", "register", "signup", "sign-up", "auth",
        ]
        .iter()
        .any(|word| target.contains(word))
    })
}

pub(super) fn is_gate_refusal(status: u16) -> bool {
    matches!(status, 401 | 403 | 301 | 302 | 303 | 307 | 308)
}

/// Published first-run login passwords from source-controlled environment templates. A verifier
/// must satisfy an application's real authentication precondition, but must never read an
/// operator's `.env` or invent/forge a credential. Only conventional login-password variables in
/// `.env.example`/`.env.sample`/`.env.template` are considered; datastore credentials and obvious
/// placeholders are ignored. Template values precede the small generic default list so rate-limited
/// login routes are not locked before their documented first-run credential is tried.
pub(super) fn template_login_passwords(root: &std::path::Path) -> Vec<String> {
    const TEMPLATES: [&str; 3] = [".env.example", ".env.sample", ".env.template"];
    const LOGIN_PREFIXES: [&str; 6] = ["INITIAL", "DEFAULT", "ADMIN", "DASHBOARD", "LOGIN", "ROOT"];
    let mut passwords = Vec::new();
    let mut pending = std::collections::VecDeque::from([(root.to_path_buf(), 0usize)]);
    let mut budget = 256usize;
    while let Some((directory, depth)) = pending.pop_front() {
        if budget == 0 {
            break;
        }
        budget -= 1;
        let Ok(entries) = std::fs::read_dir(directory) else {
            continue;
        };
        let mut entries = entries.flatten().collect::<Vec<_>>();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                if depth < 3
                    && !name.starts_with('.')
                    && !matches!(name.as_ref(), "node_modules" | "target" | "vendor")
                {
                    pending.push_back((path, depth + 1));
                }
                continue;
            }
            if !TEMPLATES.contains(&name.as_ref()) {
                continue;
            }
            let Ok(metadata) = path.metadata() else {
                continue;
            };
            if metadata.len() > 64 * 1024 {
                continue;
            }
            let Ok(template) = std::fs::read_to_string(path) else {
                continue;
            };
            for line in template.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let line = line.strip_prefix("export ").unwrap_or(line);
                let Some((name, value)) = line.split_once('=') else {
                    continue;
                };
                let name = name.trim().to_ascii_uppercase();
                let login_password = name == "PASSWORD"
                    || name.strip_suffix("_PASSWORD").is_some_and(|prefix| {
                        LOGIN_PREFIXES
                            .iter()
                            .any(|candidate| prefix == *candidate || prefix.ends_with(candidate))
                    });
                if !login_password
                    || ["DATABASE", "MONGO", "REDIS", "MYSQL", "POSTGRES", "SQL"]
                        .iter()
                        .any(|service| name.contains(service))
                {
                    continue;
                }
                let value = value.trim().trim_matches(['\'', '"']);
                if value.is_empty()
                    || value.len() > 128
                    || value
                        .chars()
                        .next()
                        .is_some_and(|first| matches!(first, '$' | '<' | '{'))
                    || value.eq_ignore_ascii_case("replace-me")
                {
                    continue;
                }
                if !passwords.iter().any(|existing| existing == value) {
                    passwords.push(value.to_owned());
                }
            }
        }
    }
    passwords
}

/// Whether any command in a package script runs the Bun executable (`bun x.js`, `bunx next`,
/// `cross-env A=1 bun run y`), rather than merely mentioning the word.
pub(super) fn script_invokes_bun(script: &str) -> bool {
    script
        .split(['&', '|', ';'])
        .filter_map(|command| {
            command
                .split_whitespace()
                .find(|word| !word.contains('=') && *word != "cross-env" && *word != "env")
        })
        .any(|program| program == "bun" || program == "bunx")
}

/// The verifier-owned directory a Bun release for `spec` is installed into. Outside every checkout,
/// keyed by the spec so different pins never share a binary.
pub(super) fn local_bun_tool_dir(spec: &str) -> std::path::PathBuf {
    let key: String = spec
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    std::env::temp_dir()
        .join("jsspector-tools")
        .join(format!("bun-{key}"))
}

/// Make the Bun runtime a package declares available to the local verifier. A package written for
/// Bun (`bun:sqlite`, `Bun.*`, `bun server.js` launchers) cannot run its real startup under Node,
/// and no Node substitute would be faithful, so provide the declared release itself: installed from
/// the npm registry (`bun` ships its platform binaries there) into a verifier-owned tool directory,
/// never into the checkout. Returns the directory to prepend to `PATH`, or `None` when the package
/// does not declare Bun or a `bun` is already on `PATH`.
pub(super) fn provision_local_bun(
    app_root: &std::path::Path,
) -> Result<Option<std::path::PathBuf>, String> {
    let Some(spec) = declared_bun_spec(app_root) else {
        return Ok(None);
    };
    if command_available("bun") {
        return Ok(None);
    }
    let dir = local_bun_tool_dir(&spec);
    let bin = dir.join("node_modules").join(".bin");
    let ready = |bin: &std::path::Path| {
        Command::new(bin.join("bun"))
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    };
    if ready(&bin) {
        return Ok(Some(bin));
    }
    std::fs::create_dir_all(&dir)
        .map_err(|error| format!("creating Bun tool directory {}: {error}", dir.display()))?;
    let lock = File::create(dir.join(".lock"))
        .map_err(|error| format!("creating Bun tool lock: {error}"))?;
    lock.lock_exclusive()
        .map_err(|error| format!("locking Bun tool directory: {error}"))?;
    if ready(&bin) {
        return Ok(Some(bin));
    }
    let output = Command::new("npm")
        .args([
            "install",
            "--no-save",
            "--no-package-lock",
            "--no-audit",
            "--no-fund",
            "--prefix",
        ])
        .arg(&dir)
        .arg(format!("bun@{spec}"))
        .current_dir(&dir)
        .output()
        .map_err(|error| format!("installing the declared Bun runtime: {error}"))?;
    if !output.status.success() || !ready(&bin) {
        return Err(format!(
            "the app declares the Bun runtime (bun@{spec}), which could not be provisioned:\n{}",
            tail(&String::from_utf8_lossy(&output.stderr), 20)
        ));
    }
    Ok(Some(bin))
}

/// `PATH` with a verifier tool directory first, so package scripts (`bun …`) find the provisioned
/// runtime while everything else resolves as before.
pub(super) fn path_with_tool_dir(tool_dir: &std::path::Path) -> std::ffi::OsString {
    path_with_tool_dirs(&[tool_dir.to_path_buf()])
}

/// `PATH` with verifier tool directories first, in order, then the inherited `PATH`.
pub(super) fn path_with_tool_dirs(tool_dirs: &[std::path::PathBuf]) -> std::ffi::OsString {
    let mut parts = tool_dirs.to_vec();
    if let Some(existing) = std::env::var_os("PATH") {
        parts.extend(std::env::split_paths(&existing));
    }
    std::env::join_paths(&parts).unwrap_or_else(|_| {
        tool_dirs
            .first()
            .map(|dir| dir.as_os_str().to_owned())
            .unwrap_or_default()
    })
}

/// Give an untrusted local install/build/application only the process environment needed to run.
/// In particular, never inherit API tokens, cloud credentials, Git authentication or agent state
/// from the scanner process. This narrows accidental credential exposure; `--local` still requires
/// a disposable worker because it is not an operating-system sandbox.
pub(super) fn isolate_local_command(
    command: &mut Command,
    home_dir: &std::path::Path,
    tool_dir: Option<&std::path::Path>,
) -> Result<(), String> {
    std::fs::create_dir_all(home_dir).map_err(|error| {
        format!(
            "creating private verifier home {}: {error}",
            home_dir.display()
        )
    })?;
    let path = tool_dir.map_or_else(
        || std::env::var_os("PATH").unwrap_or_default(),
        path_with_tool_dir,
    );
    command
        .env_clear()
        .env("PATH", path)
        .env("HOME", home_dir)
        .env("USERPROFILE", home_dir);
    // Locale and Windows process-launch variables contain no credentials and are needed by common
    // runtimes. Everything else must be supplied explicitly by the verifier.
    for name in [
        "LANG",
        "LC_ALL",
        "TZ",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    Ok(())
}

/// Whether the program at `path` runs (`--version` exits successfully).
pub(super) fn tool_runs(path: &std::path::Path) -> bool {
    Command::new(path)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Provide a cached tool directory: return its `bin/` when `ready` accepts it, otherwise run
/// `install` once under an exclusive lock (concurrent verifiers wait for the first one) and check
/// again. The directory lives under the system temp dir, so it is shared by every run on the host.
pub(super) fn provision_tool_dir(
    name: &str,
    ready: impl Fn(&std::path::Path) -> bool,
    install: impl FnOnce(&std::path::Path) -> Result<(), String>,
) -> Result<std::path::PathBuf, String> {
    let dir = std::env::temp_dir().join("jsspector-tools").join(name);
    let bin = dir.join("bin");
    if ready(&bin) {
        return Ok(bin);
    }
    std::fs::create_dir_all(&bin)
        .map_err(|error| format!("creating tool directory {}: {error}", dir.display()))?;
    let lock = File::create(dir.join(".lock"))
        .map_err(|error| format!("creating tool lock {}: {error}", dir.display()))?;
    lock.lock_exclusive()
        .map_err(|error| format!("locking tool directory {}: {error}", dir.display()))?;
    if ready(&bin) {
        return Ok(bin);
    }
    eprintln!(
        "jsspector: provisioning {name} for the local runtime (first use; cached in {})",
        dir.display()
    );
    install(&dir)?;
    if ready(&bin) {
        Ok(bin)
    } else {
        Err(format!(
            "{name} was installed in {} but does not run",
            dir.display()
        ))
    }
}

/// Run a provisioning step, turning a failure into its command's last lines of output.
pub(super) fn run_provision_step(command: &mut Command, what: &str) -> Result<Output, String> {
    let output = command
        .output()
        .map_err(|error| format!("{what}: {error}"))?;
    if output.status.success() {
        return Ok(output);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = if stderr.trim().is_empty() {
        stdout
    } else {
        stderr
    };
    Err(format!("{what} failed:\n{}", tail(&detail, 15)))
}

/// Point `bin/<name>` at a provisioned binary, replacing a link a failed attempt left behind.
pub(super) fn link_tool(
    bin: &std::path::Path,
    name: &str,
    target: &std::path::Path,
) -> Result<(), String> {
    let link = bin.join(name);
    if link.symlink_metadata().is_ok() {
        std::fs::remove_file(&link)
            .map_err(|error| format!("replacing {}: {error}", link.display()))?;
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, &link)
            .map_err(|error| format!("linking {}: {error}", link.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = target;
        Err("provisioning backing services needs a Unix host".to_owned())
    }
}

/// MongoDB's standalone `mongosh` build for this host: its platform name and archive extension.
pub(super) fn mongosh_platform(os: &str, arch: &str) -> Option<(&'static str, &'static str)> {
    match (os, arch) {
        ("linux", "x86_64") => Some(("linux-x64", "tgz")),
        ("linux", "aarch64") => Some(("linux-arm64", "tgz")),
        ("macos", "aarch64") => Some(("darwin-arm64", "zip")),
        ("macos", "x86_64") => Some(("darwin-x64", "zip")),
        _ => None,
    }
}

/// Provide `mongod` and `mongosh` for an app that needs MongoDB on a host that has neither: the
/// server build for this OS, distribution and architecture (fetched by `mongodb-memory-server`) and
/// MongoDB's standalone shell, both pinned, linked into one cached `bin/`.
pub(super) fn provision_local_mongo() -> Result<std::path::PathBuf, String> {
    let name = format!("mongodb-{LOCAL_MONGO_VERSION}-mongosh-{LOCAL_MONGOSH_VERSION}");
    let ready =
        |bin: &std::path::Path| tool_runs(&bin.join("mongod")) && tool_runs(&bin.join("mongosh"));
    provision_tool_dir(&name, ready, |dir| {
        let (platform, extension) = mongosh_platform(std::env::consts::OS, std::env::consts::ARCH)
            .ok_or_else(|| {
                format!(
                    "no MongoDB shell build for {}/{}",
                    std::env::consts::OS,
                    std::env::consts::ARCH
                )
            })?;
        let bin = dir.join("bin");
        let downloader = dir.join("downloader");
        std::fs::create_dir_all(&downloader)
            .map_err(|error| format!("creating {}: {error}", downloader.display()))?;
        run_provision_step(
            Command::new("npm")
                .args([
                    "install",
                    "--no-save",
                    "--no-package-lock",
                    "--no-audit",
                    "--no-fund",
                    "--ignore-scripts",
                    "--prefix",
                ])
                .arg(&downloader)
                .arg(LOCAL_MONGO_DOWNLOADER)
                .current_dir(&downloader),
            "installing the MongoDB downloader",
        )?;
        let fetched = run_provision_step(
            Command::new("node")
                .args([
                    "-e",
                    "require('mongodb-memory-server-core').MongoBinary.getPath()\
                     .then((path) => console.log('JSSPECTOR_MONGOD=' + path))",
                ])
                .current_dir(&downloader)
                .env("MONGOMS_DOWNLOAD_DIR", dir.join("server"))
                .env("MONGOMS_VERSION", LOCAL_MONGO_VERSION)
                .env_remove("MONGOMS_SYSTEM_BINARY")
                .env_remove("MONGOMS_ARCHIVE_NAME")
                .env_remove("MONGOMS_DOWNLOAD_URL"),
            &format!("downloading MongoDB {LOCAL_MONGO_VERSION}"),
        )?;
        // The downloader reports progress on stdout too; the path is on the marked line.
        let stdout = String::from_utf8_lossy(&fetched.stdout);
        let server = stdout
            .lines()
            .find_map(|line| line.trim().strip_prefix("JSSPECTOR_MONGOD="))
            .ok_or_else(|| {
                format!(
                    "the MongoDB downloader reported no binary:\n{}",
                    tail(&stdout, 5)
                )
            })?;
        link_tool(&bin, "mongod", std::path::Path::new(server))?;
        let archive = dir.join(format!("mongosh.{extension}"));
        run_provision_step(
            Command::new("curl")
                .args(["-fsSL", "--retry", "3", "-o"])
                .arg(&archive)
                .arg(format!(
                    "https://downloads.mongodb.com/compass/mongosh-{LOCAL_MONGOSH_VERSION}-{platform}.{extension}"
                )),
            &format!("downloading mongosh {LOCAL_MONGOSH_VERSION}"),
        )?;
        run_provision_step(
            Command::new("tar")
                .arg("-xf")
                .arg(&archive)
                .arg("-C")
                .arg(dir),
            "unpacking mongosh",
        )?;
        link_tool(
            &bin,
            "mongosh",
            &dir.join(format!("mongosh-{LOCAL_MONGOSH_VERSION}-{platform}"))
                .join("bin")
                .join("mongosh"),
        )
    })
}

/// Provide `redis-server` for an app that declares a Redis client on a host without one: the pinned
/// release built from its official source archive (it needs only `make` and a C compiler).
pub(super) fn provision_local_redis() -> Result<std::path::PathBuf, String> {
    let name = format!("redis-{LOCAL_REDIS_VERSION}");
    let ready = |bin: &std::path::Path| tool_runs(&bin.join("redis-server"));
    provision_tool_dir(&name, ready, |dir| {
        let archive = dir.join("redis.tar.gz");
        run_provision_step(
            Command::new("curl")
                .args(["-fsSL", "--retry", "3", "-o"])
                .arg(&archive)
                .arg(format!(
                    "https://download.redis.io/releases/redis-{LOCAL_REDIS_VERSION}.tar.gz"
                )),
            &format!("downloading Redis {LOCAL_REDIS_VERSION}"),
        )?;
        run_provision_step(
            Command::new("tar")
                .arg("-xzf")
                .arg(&archive)
                .arg("-C")
                .arg(dir),
            "unpacking Redis",
        )?;
        let source = dir.join(format!("redis-{LOCAL_REDIS_VERSION}"));
        let jobs = std::thread::available_parallelism().map_or(2, std::num::NonZero::get);
        run_provision_step(
            Command::new("make")
                .arg("-C")
                .arg(&source)
                .arg(format!("-j{jobs}"))
                .args(["MALLOC=libc", "BUILD_TLS=no"]),
            &format!("building Redis {LOCAL_REDIS_VERSION}"),
        )?;
        link_tool(
            &dir.join("bin"),
            "redis-server",
            &source.join("src").join("redis-server"),
        )
    })
}

pub(super) fn run_local_setup(
    root: &std::path::Path,
    script: &str,
    tool_dir: Option<&std::path::Path>,
    home_dir: &std::path::Path,
) -> Result<(), String> {
    let mut command = Command::new("sh");
    isolate_local_command(&mut command, home_dir, tool_dir)?;
    command
        .args(["-c", script])
        .current_dir(root)
        .env("CI", "true")
        .env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0");
    let output = command
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

/// The package whose native binding loader failed during application startup. Binding loaders list
/// candidate `.node` paths below `node_modules/<package>`; accepting only npm package-name bytes
/// turns that diagnostic into data for a targeted rebuild without ever feeding log text to a shell.
pub(super) fn missing_native_package(log: &str) -> Option<String> {
    let native_failure = log.contains("Could not locate the bindings file")
        || log.contains("Could not locate the binding file")
        || log.contains("Cannot find module")
        || log.contains("ERR_DLOPEN_FAILED");
    if !native_failure {
        return None;
    }
    for line in log.lines().filter(|line| line.contains(".node")) {
        for (offset, _) in line.match_indices("node_modules/") {
            let rest = &line[offset + "node_modules/".len()..];
            let mut parts = rest.split('/');
            let Some(first) = parts.next().map(str::trim).filter(|part| !part.is_empty()) else {
                continue;
            };
            let package = if first.starts_with('@') {
                let Some(name) = parts.next().map(str::trim).filter(|part| !part.is_empty()) else {
                    continue;
                };
                format!("{first}/{name}")
            } else {
                first.to_owned()
            };
            let valid_part = |part: &str, scoped: bool| {
                !part.is_empty()
                    && (!scoped || part.starts_with('@'))
                    && part.trim_start_matches('@').bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
            };
            let valid = if let Some((scope, name)) = package.split_once('/') {
                valid_part(scope, true) && valid_part(name, false)
            } else {
                valid_part(&package, false)
            };
            if valid {
                return Some(package);
            }
        }
    }
    None
}

/// Re-run lifecycle scripts for exactly the native package named by [`missing_native_package`].
/// The direct argv invocation plus the isolated verifier environment prevents both shell injection
/// and credential inheritance. It is deliberately a startup recovery, not a blanket `npm rebuild`:
/// unrelated lifecycle scripts in an untrusted repository never run as collateral work.
pub(super) fn rebuild_local_native_package(
    install_root: &std::path::Path,
    package: &str,
    tool_dir: Option<&std::path::Path>,
    home_dir: &std::path::Path,
) -> Result<(), String> {
    let mut command = Command::new("npm");
    isolate_local_command(&mut command, home_dir, tool_dir)?;
    let output = command
        .args([
            "rebuild",
            "--foreground-scripts",
            "--no-audit",
            "--no-fund",
            "--package-lock=false",
            "--",
            package,
        ])
        .current_dir(install_root)
        .env("CI", "true")
        .env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0")
        .output()
        .map_err(|error| format!("rebuilding native package {package}: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "rebuilding native package {package} failed:\n{}",
            tail(&String::from_utf8_lossy(&output.stderr), 50)
        ))
    }
}

pub(super) fn acquire_local_fixture_lock() -> Result<File, String> {
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

pub(super) fn is_recognizable_local_fixture(
    path: &std::path::Path,
    expected: &[u8],
    existing: &[u8],
) -> bool {
    if existing == expected {
        return true;
    }
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if !name.starts_with("jss-canary-read") {
        return false;
    }
    serde_json::from_slice::<String>(existing).is_ok_and(|contents| {
        let token = contents.strip_prefix("CANARY ").unwrap_or(&contents);
        (16..=128).contains(&token.len()) && token.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

pub(super) fn plant_local_files(canary: &Canary) -> Result<Vec<std::path::PathBuf>, String> {
    let mut files: Vec<(std::path::PathBuf, Vec<u8>)> = canary
        .planted_files()
        .into_iter()
        .map(|path| {
            (
                std::path::PathBuf::from(path),
                canary.planted_json_string().into_bytes(),
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
            std::path::PathBuf::from("/tmp/jss-socket-driver.js"),
            SOCKET_DRIVER_JS.as_bytes().to_vec(),
        ),
        (
            std::path::PathBuf::from("/tmp/jss-mcp-driver.js"),
            MCP_DRIVER_JS.as_bytes().to_vec(),
        ),
        (
            std::path::PathBuf::from("/tmp/jss-mcp-bridge.js"),
            MCP_BRIDGE_JS.as_bytes().to_vec(),
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
            std::path::PathBuf::from("/tmp/jss-sink-binding.js"),
            local_helper_source(sink_binding::PRELOAD_JS),
        ),
        (
            std::path::PathBuf::from("/tmp/jss-electron-shim.js"),
            local_helper_source(ELECTRON_SHIM_JS),
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
pub(super) fn restore_local_read_canaries(canary: &Canary) -> Result<(), String> {
    for path in canary.planted_files() {
        let path = std::path::PathBuf::from(path);
        if path.exists() {
            continue;
        }
        std::fs::write(&path, canary.planted_json_string()).map_err(|error| {
            format!(
                "restoring local verifier fixture {}: {error}",
                path.display()
            )
        })?;
    }
    Ok(())
}

pub(super) fn local_helper_source(source: &str) -> Vec<u8> {
    localize_helper_paths(source).into_bytes()
}

/// Translate image-root helper paths for the local runtime exactly once. Request specs also contain
/// already-localized canary payloads, so a plain textual replacement would corrupt
/// `/tmp/jss-canary-read` into `/tmp/tmp/jss-canary-read` on every `exec`.
pub(super) fn localize_helper_paths(input: &str) -> String {
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

pub(super) fn local_sqlite_search_roots(
    app_root: &std::path::Path,
    base_env: &[RequiredEnv],
) -> Vec<String> {
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
pub(super) fn build_image(
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
    node_image: Option<&str>,
) -> Result<(), String> {
    let context = root
        .to_str()
        .ok_or_else(|| "the repository path is not valid UTF-8".to_owned())?;
    // Dependencies are declared and locked in the install directory (the nearest manifest ancestor
    // of the launch directory), so the package manager and base image are chosen from there. The
    // build script, by contrast, belongs to the app actually launched: a standalone server run from
    // a manifest-less subdirectory needs its ancestor's dependencies, not its ancestor's build.
    let image = node_image.map_or_else(|| base_image(install_root), str::to_owned);
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
    // The full image of a pinned older Node already bundles the compiler toolchain, and the archived
    // Debian release under it can no longer `apt-get` one.
    let native_build = node_image.is_none() && needs_native_toolchain(install_root);
    let bun_spec = declared_bun_spec(app_root).or_else(|| {
        (install_root != app_root)
            .then(|| declared_bun_spec(install_root))
            .flatten()
    });
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
        bun_spec.as_deref(),
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
pub(super) fn install_path(
    root: &std::path::Path,
    app_path: &std::path::Path,
) -> std::path::PathBuf {
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
pub(super) fn uses_node_sqlite(root: &std::path::Path, _app_root: &std::path::Path) -> bool {
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

/// Database names the app connects to by name in a MongoDB connection string written in its own
/// source (`mongodb://host/<name>`, `mongodb+srv://host/<name>`). A read-only query sink against such
/// a database never writes, so MongoDB never creates it on disk and `listDatabases` omits it; the
/// verifier needs the name to enable profiling on (and so materialize and seed) the exact database the
/// sink queries. A bounded, source-only scan under the app directory, skipping `node_modules` and
/// dot-directories; nothing names a specific application.
pub(super) fn mongo_database_names(app_root: &std::path::Path) -> Vec<String> {
    fn scan(dir: &std::path::Path, budget: &mut u32, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            if *budget == 0 {
                return;
            }
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                if name == "node_modules" || name.starts_with('.') {
                    continue;
                }
                scan(&path, budget, out);
            } else if matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx" | "json" | "yml" | "yaml")
            ) {
                *budget -= 1;
                if let Ok(text) = std::fs::read_to_string(&path) {
                    extract_mongo_databases(&text, out);
                }
            }
        }
    }
    let mut out = Vec::new();
    let mut budget = 3000u32;
    scan(app_root, &mut budget, &mut out);
    out.sort();
    out.dedup();
    out
}

/// Appends the database name of each MongoDB connection string in `text` to `out`: the path segment
/// after the authority (`mongodb://user:pass@host:27017/<name>?opts` -> `<name>`). Only names made of
/// MongoDB-legal identifier characters are kept, so an interpolated or malformed URI contributes
/// nothing and nothing unsafe reaches the shell script that later uses the name.
pub(super) fn extract_mongo_databases(text: &str, out: &mut Vec<String>) {
    for scheme in ["mongodb://", "mongodb+srv://"] {
        for (idx, _) in text.match_indices(scheme) {
            let after = &text[idx + scheme.len()..];
            let end = after
                .find(|c: char| {
                    matches!(c, '"' | '\'' | '`' | ' ' | '\t' | '\n' | '\r' | '\\' | ')')
                })
                .unwrap_or(after.len());
            let uri = &after[..end];
            let Some(slash) = uri.find('/') else {
                continue;
            };
            let path = &uri[slash + 1..];
            let name_end = path.find(['/', '?']).unwrap_or(path.len());
            let name = &path[..name_end];
            if !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                out.push(name.to_owned());
            }
        }
    }
}

/// Node's built-in modules, by the root segment that appears in an import specifier (`fs/promises`
/// -> `fs`). Specifiers naming these are never installed from a registry, so they are not weighed
/// when choosing a dependency provider.
pub(super) const NODE_BUILTINS: [&str; 41] = [
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
pub(super) fn import_specifiers(src: &str) -> Vec<String> {
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
pub(super) fn package_root(spec: &str) -> String {
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
pub(super) fn bare_specifiers(src: &str) -> std::collections::BTreeSet<String> {
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
pub(super) fn load_time_bare_specifiers(src: &str) -> std::collections::BTreeSet<String> {
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
pub(super) fn guarded_bare_requires(src: &str) -> std::collections::BTreeSet<String> {
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
pub(super) fn guarded_modules(
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
pub(super) fn subtree_specifiers(dir: &std::path::Path) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    for src in app_source_files(dir) {
        out.extend(bare_specifiers(&src));
    }
    out
}

/// Every dependency a package manifest declares, across the runtime, development, optional and peer
/// sections — the names that will have a directory under its `node_modules` after an install.
pub(super) fn manifest_declared_deps(dir: &std::path::Path) -> std::collections::BTreeSet<String> {
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
pub(super) fn needs_native_toolchain(install_root: &std::path::Path) -> bool {
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
pub(super) fn has_install_lifecycle(dir: &std::path::Path) -> bool {
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
pub(super) fn package_dirs(root: &std::path::Path) -> Vec<std::path::PathBuf> {
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
pub(super) fn dependency_provider(
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

pub(super) fn db_service(app_root: &std::path::Path) -> bool {
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

pub(super) fn db_connection_env() -> Vec<(String, String)> {
    db_connection_env_for(DB_ALIASES[0], 27017)
}

pub(super) fn local_db_connection_env() -> Vec<(String, String)> {
    db_connection_env_for("127.0.0.1", 27017)
}

pub(super) fn db_connection_env_for(host: &str, port: u16) -> Vec<(String, String)> {
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
pub(super) fn mongodump_dir(root: &std::path::Path) -> Option<std::path::PathBuf> {
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

pub(super) fn redis_service(app_root: &std::path::Path) -> bool {
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

pub(super) fn redis_connection_env() -> Vec<(String, String)> {
    redis_connection_env_for(REDIS_ALIASES[0], 6379)
}

pub(super) fn local_redis_connection_env() -> Vec<(String, String)> {
    redis_connection_env_for("127.0.0.1", 6379)
}

pub(super) fn redis_connection_env_for(host: &str, port: u16) -> Vec<(String, String)> {
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
pub(super) fn base_image(root: &std::path::Path) -> String {
    match declared_engine_major(root) {
        Some(major) if major > DEFAULT_NODE_MAJOR && major < 100 => format!("node:{major}-slim"),
        _ => BASE_IMAGE.to_owned(),
    }
}

/// The lowest Node major `engines.node` of the `package.json` in `root` allows, if it declares one.
pub(super) fn declared_engine_major(root: &std::path::Path) -> Option<u32> {
    std::fs::read_to_string(root.join("package.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|json| {
            json.get("engines")
                .and_then(|engines| engines.get("node"))
                .and_then(|node| node.as_str())
                .and_then(engine_major)
        })
}

/// The image to retry a failed launch on: the Node the repository itself pins (see
/// [`pinned_node_major`]) when it is older than the one the default launch used and no older than
/// [`MIN_FALLBACK_NODE_MAJOR`]. The full image, not `-slim`: an app pinned to an old runtime typically
/// compiles a native addon at install, and the full image bundles the toolchain for it.
pub(super) fn repo_node_fallback(
    root: &std::path::Path,
    app_root: &std::path::Path,
    install_root: &std::path::Path,
) -> Option<String> {
    let used = declared_engine_major(install_root)
        .filter(|&major| major < 100)
        .map_or(DEFAULT_NODE_MAJOR, |major| major.max(DEFAULT_NODE_MAJOR));
    let pinned = pinned_node_major(root, &[app_root, install_root])?;
    (MIN_FALLBACK_NODE_MAJOR..used)
        .contains(&pinned)
        .then(|| format!("node:{pinned}"))
}

/// The Node major a repository pins for its runtime: a version file (`.nvmrc`, `.node-version`) in a
/// launch directory or any ancestor up to `root`, else the `FROM node:<tag>` of the launch
/// directory's own `Dockerfile` (the last such stage, the one that runs the app). `engines.node` is
/// deliberately not used: it states the oldest supported version, not the one the app runs on.
pub(super) fn pinned_node_major(root: &std::path::Path, dirs: &[&std::path::Path]) -> Option<u32> {
    for dir in dirs {
        let mut current = Some(*dir);
        while let Some(at) = current.filter(|at| at.starts_with(root)) {
            for name in [".nvmrc", ".node-version"] {
                if let Some(major) = std::fs::read_to_string(at.join(name))
                    .ok()
                    .and_then(|text| node_version_major(text.split_whitespace().next()?))
                {
                    return Some(major);
                }
            }
            current = at.parent();
        }
    }
    dirs.iter().find_map(|dir| {
        let text = std::fs::read_to_string(dir.join("Dockerfile")).ok()?;
        text.lines()
            .filter_map(|line| {
                let mut words = line.split_whitespace();
                if !words.next()?.eq_ignore_ascii_case("FROM") {
                    return None;
                }
                let image = words.find(|word| !word.starts_with("--"))?;
                let (name, tag) = image.split_once(':')?;
                let name = name.rsplit('/').next()?;
                (name == "node")
                    .then(|| node_version_major(tag.split(['-', '@']).next()?))
                    .flatten()
            })
            .next_back()
    })
}

/// The major of a Node version as a version file or image tag spells it: `v8.17.0`, `14`,
/// `lts/carbon`, or a release codename (`carbon` = 8). `None` for a floating name (`node`, `lts/*`,
/// `latest`), which pins nothing.
pub(super) fn node_version_major(version: &str) -> Option<u32> {
    let version = version.trim().to_ascii_lowercase();
    let version = version.strip_prefix("lts/").unwrap_or(&version);
    const CODENAMES: [(&str, u32); 11] = [
        ("argon", 4),
        ("boron", 6),
        ("carbon", 8),
        ("dubnium", 10),
        ("erbium", 12),
        ("fermium", 14),
        ("gallium", 16),
        ("hydrogen", 18),
        ("iron", 20),
        ("jod", 22),
        ("krypton", 24),
    ];
    if let Some((_, major)) = CODENAMES.iter().find(|(name, _)| *name == version) {
        return Some(*major);
    }
    let digits: String = version
        .trim_start_matches('v')
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok().filter(|&major| major > 0)
}

/// Which package manager installs the app's dependencies, chosen by the lockfile present. A yarn or
/// pnpm project cannot be installed with `npm` (different lockfile, and npm rejects yarn-only
/// manifest features and strict peer dependencies), so install with the tool the repo targets.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum PackageManager {
    Npm,
    Yarn,
    Pnpm,
}

pub(super) fn package_manager(root: &std::path::Path) -> PackageManager {
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
pub(super) fn install_command(pm: PackageManager) -> &'static str {
    match pm {
        PackageManager::Npm => {
            "npm ci --no-audit --no-fund || npm install --no-audit --no-fund || npm install --no-audit --no-fund --legacy-peer-deps || npm install --ignore-scripts --legacy-peer-deps --no-audit --no-fund || npm install --omit=dev --ignore-scripts --legacy-peer-deps --no-audit --no-fund || true"
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

/// The npm install of the Docker image: [`install_command`], plus one recovery step before the
/// legacy fallbacks. A dependency the registry no longer serves (an unpublished package, a 404 on its
/// tarball) fails the whole install, so not even the app's live dependencies install and it cannot
/// start. When the plain install fails on such 404s, drop the dead packages the manifest declares
/// directly and install the rest. A dropped package the app still `require`s resolves to the launch
/// shim's inert stub, exactly like an undeclared one; that stub returns nothing usable, so it can only
/// stop a flow, never pass the canary through. Docker only: the local runtime installs in the user's
/// checkout, whose manifest it must not rewrite.
pub(super) const NPM_DOCKER_INSTALL: &str = concat!(
    "npm ci --no-audit --no-fund || npm install --no-audit --no-fund >/tmp/jss-npm.log 2>&1 || { ",
    "node -e 'try{const fs=require(\"fs\");",
    "const log=fs.readFileSync(\"/tmp/jss-npm.log\",\"utf8\");",
    "const re=/404 Not Found - GET https?:\\/\\/[^\\/\\s]+\\/((?:@[^\\/\\s]+(?:\\/|%2[fF]))?[^\\/\\s]+)/g;",
    "const dead=new Set();let m;while((m=re.exec(log)))dead.add(decodeURIComponent(m[1]));",
    "const j=JSON.parse(fs.readFileSync(\"package.json\",\"utf8\"));let n=0;",
    "for(const s of [\"dependencies\",\"devDependencies\",\"optionalDependencies\"]){const o=j[s];",
    "if(o&&typeof o===\"object\")for(const d of dead)if(Object.prototype.hasOwnProperty.call(o,d)){delete o[d];n++;}}",
    "if(!n)process.exit(1);fs.writeFileSync(\"package.json\",JSON.stringify(j,null,2));",
    "console.error(\"dropped dependencies the registry no longer serves: \"+Array.from(dead).join(\",\"));",
    "}catch(e){process.exit(1);}' && npm install --no-audit --no-fund; } || ",
    "npm install --no-audit --no-fund --legacy-peer-deps || ",
    "npm install --omit=dev --ignore-scripts --legacy-peer-deps --no-audit --no-fund || true"
);

/// The build command for a package manager, run when the app declares a `build` script. A
/// production server (`next start`, `vite preview`, a compiled `dist/`) serves the build output and
/// will not start without it. Tolerated failure keeps a sub-step that needs the network (asset
/// downloads) from failing the image when the primary build has already produced its output.
pub(super) fn build_command(pm: PackageManager, script: &str) -> String {
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
/// The project's own TypeScript compiler, on its own `tsconfig.json`.
pub(super) const TSC_COMMAND: &str = "npx --no-install tsc -p tsconfig.json";

/// Where to compile an app that runs the TypeScript compiler's output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TypescriptBuild {
    pub(super) workdir: String,
    /// `noEmitOnError`: a type error then leaves the compiled output as it was.
    pub(super) no_emit_on_error: bool,
}

/// One build step before a relaunch.
pub(super) struct Rebuild {
    pub(super) workdir: String,
    pub(super) command: String,
    /// `Some(no_emit_on_error)` for the TypeScript compiler.
    pub(super) typescript: Option<bool>,
}

impl Rebuild {
    /// Whether the change took effect. The app's own build script is best effort, as when the app
    /// was prepared; the compiler must have emitted, or the app would run the old code and every
    /// candidate would look like it failed to stop the exploit.
    pub(super) fn check(&self, success: bool, log: &str) -> Result<(), String> {
        match self.typescript {
            None => Ok(()),
            Some(_) if success => Ok(()),
            // Type errors, anywhere in the project, do not stop `tsc` from emitting.
            Some(false) if log.contains("error TS") => Ok(()),
            Some(_) => Err(format!(
                "the change does not compile with the project's TypeScript compiler:\n{}",
                tail(log, 20)
            )),
        }
    }
}

/// `Some(noEmitOnError)` when the app in `app_root` runs the TypeScript compiler's output: a
/// `tsconfig.json` with an `outDir` that the `start` script runs from, and `typescript` among the
/// dependencies.
pub(super) fn typescript_build(app_root: &std::path::Path) -> Option<bool> {
    let tsconfig = std::fs::read_to_string(app_root.join("tsconfig.json")).ok()?;
    let manifest = std::fs::read_to_string(app_root.join("package.json")).ok()?;
    let json = serde_json::from_str::<serde_json::Value>(&manifest).ok()?;
    let has_typescript = ["dependencies", "devDependencies"].iter().any(|section| {
        json.get(section)
            .and_then(serde_json::Value::as_object)
            .is_some_and(|deps| deps.contains_key("typescript"))
    });
    let start = json.get("scripts")?.get("start")?.as_str()?;
    let out_dir = tsconfig_string(&tsconfig, "outDir")?;
    let out_dir = out_dir.trim_start_matches("./").trim_end_matches('/');
    let runs_output = !out_dir.is_empty()
        && start.split_whitespace().any(|word| {
            let word = word.trim_start_matches("./");
            word == out_dir || word.starts_with(&format!("{out_dir}/"))
        });
    (has_typescript && runs_output).then(|| tsconfig_true(&tsconfig, "noEmitOnError"))
}

/// Whether a package's `start` script runs a relative Node output that a fresh checkout has not
/// generated yet. Node accepts extensionless entry names, so check its ordinary JS extensions too.
/// This is used only to decide whether the project's own TypeScript compiler must be retried before
/// launch; it never invents a command or a path outside the package.
pub(super) fn missing_node_start_target(app_root: &std::path::Path) -> bool {
    let Ok(manifest) = std::fs::read_to_string(app_root.join("package.json")) else {
        return false;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&manifest) else {
        return false;
    };
    let Some(start) = json
        .get("scripts")
        .and_then(|scripts| scripts.get("start"))
        .and_then(serde_json::Value::as_str)
    else {
        return false;
    };
    let mut words = start.split_whitespace();
    if words.next() != Some("node") {
        return false;
    }
    let Some(file) = words.find(|word| !word.starts_with('-')) else {
        return false;
    };
    let file = file.trim_matches(['\'', '"']);
    let relative = std::path::Path::new(file);
    if relative.is_absolute()
        || relative
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return false;
    }
    let target = app_root.join(relative);
    !target.is_file()
        && ["js", "mjs", "cjs"]
            .iter()
            .all(|extension| !target.with_extension(extension).is_file())
}

/// The string value of `"key": "…"` in a `tsconfig.json`, read as text (it may carry comments).
pub(super) fn tsconfig_string(text: &str, key: &str) -> Option<String> {
    let after = text.split(&format!("\"{key}\"")).nth(1)?;
    let value = after
        .trim_start()
        .strip_prefix(':')?
        .trim_start()
        .strip_prefix('"')?;
    Some(value.split('"').next()?.to_owned())
}

/// Whether `"key": true` appears in a `tsconfig.json`.
pub(super) fn tsconfig_true(text: &str, key: &str) -> bool {
    text.split(&format!("\"{key}\""))
        .nth(1)
        .and_then(|after| after.trim_start().strip_prefix(':'))
        .is_some_and(|value| value.trim_start().starts_with("true"))
}

pub(super) fn build_script(manifest: &str, app_root: &std::path::Path) -> Option<&'static str> {
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
pub(super) fn has_build_script(manifest: &str) -> bool {
    manifest.split("\"scripts\"").nth(1).is_some_and(|scripts| {
        let head = &scripts[..scripts.floor_char_boundary(2000)];
        head.contains("\"build\"")
    })
}

/// The first version number of a semver range: `>=24.17` and `^24.0.0 || ^22` -> 24 and 24.
pub(super) fn engine_major(range: &str) -> Option<u32> {
    let digits: String = range
        .trim_start_matches(|c: char| !c.is_ascii_digit())
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// Runs `docker build` with a private temporary Dockerfile and the context directory given,
/// returning a trimmed error log on failure.
///
/// Do not use `-f -` here. Docker Desktop's buildx frontend can leave a stdin Dockerfile build at
/// `0/0 steps` indefinitely even after the writer has been closed. A regular file gives BuildKit
/// an unambiguous EOF and behaves the same on Docker Engine and Docker Desktop.
pub(super) fn build_from_dockerfile(
    dockerfile: &str,
    tag: &str,
    context: &str,
) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    use std::io::Write;
    let mut file = tempfile::Builder::new()
        .prefix("jsspector-Dockerfile-")
        .tempfile()
        .map_err(|e| format!("creating the temporary Dockerfile: {e}"))?;
    file.write_all(dockerfile.as_bytes())
        .map_err(|e| format!("writing the Dockerfile: {e}"))?;
    file.flush()
        .map_err(|e| format!("flushing the Dockerfile: {e}"))?;
    let path = file
        .path()
        .to_str()
        .ok_or_else(|| "the temporary Dockerfile path is not valid UTF-8".to_owned())?;
    // Persistent application images can contain source and installed dependencies. Keep them only
    // when the operator explicitly opts in; the default session leaves no repository image behind.
    // A clean Git checkout plus this Dockerfile content-addresses an opted-in cache safely.
    let cache_tag = (std::env::var("JSS_VERIFY_IMAGE_CACHE").as_deref() == Ok("1"))
        .then(|| reusable_image_tag(dockerfile, context, &mut Sha256::new()))
        .flatten();
    if let Some(cache_tag) = &cache_tag
        && Command::new("docker")
            .args(docker_args(&["image", "inspect", cache_tag]))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    {
        return docker(&["tag", cache_tag, tag])
            .map(|_| ())
            .map_err(|error| format!("tagging the cached app image: {error}"));
    }
    let build_tag = cache_tag.as_deref().unwrap_or(tag);
    let output = Command::new("docker")
        .args(docker_args(&[
            "build", "-t", build_tag, "-f", path, context,
        ]))
        .output()
        .map_err(|e| format!("could not run `docker build`: {e}"))?;
    if !output.status.success() {
        let log = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "building the app image failed (often a missing build step or native dependency):\n{}",
            tail(&log, 20)
        ));
    }
    if let Some(cache_tag) = &cache_tag {
        docker(&["tag", cache_tag, tag])
            .map_err(|error| format!("tagging the newly cached app image: {error}"))?;
    }
    Ok(())
}

pub(super) fn reusable_image_tag(
    dockerfile: &str,
    context: &str,
    hasher: &mut sha2::Sha256,
) -> Option<String> {
    use sha2::Digest;
    let status = Command::new("git")
        .args([
            "-C",
            context,
            "status",
            "--porcelain",
            "--untracked-files=all",
        ])
        .output()
        .ok()?;
    if !status.status.success() || !status.stdout.is_empty() {
        return None;
    }
    let revision = Command::new("git")
        .args(["-C", context, "rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !revision.status.success() {
        return None;
    }
    hasher.update(b"jsspector-docker-image-v1\0");
    hasher.update(revision.stdout);
    hasher.update(b"\0");
    hasher.update(dockerfile.as_bytes());
    let digest = format!("{:x}", hasher.finalize_reset());
    Some(format!("jsspector-verify-cache:{}", &digest[..32]))
}

/// `docker exec <container> <cmd...>`, capturing output.
/// A JSON array literal of the file paths, each escaped for embedding in a JavaScript source string.
pub(super) fn js_string_array(files: &[String]) -> String {
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
pub(super) fn plant_rows_js(files: &[String], oracle: &payload::SqlDeleteOracle) -> String {
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
pub(super) fn count_rows_js(files: &[String], name: &str) -> String {
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

pub(super) fn exec_in(container: &str, cmd: &[&str]) -> Result<Output, String> {
    let mut args = vec!["exec", container];
    args.extend_from_slice(cmd);
    Command::new("docker")
        .args(&args)
        .output()
        .map_err(|e| e.to_string())
}

/// The last 50 lines of a container's logs (stdout and stderr), for probing and diagnostics.
pub(super) fn tail_logs(name: &str) -> String {
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
/// install`; both tolerate the absence of a build script. Static verifier helpers are written
/// through base64 so no shell or printf escaping can corrupt them. Per-session canaries are not
/// baked into the image: [`Session::startup_staging_command`](super::Session::startup_staging_command)
/// writes the fresh token into the container's private `/tmp` immediately before the app starts.
/// Keeping the image token-free also lets BuildKit reuse the expensive dependency/build layers
/// while each finding still receives a new container, marker service, network, and token.
#[allow(clippy::too_many_arguments)]
pub(super) fn dockerfile(
    image: &str,
    install_workdir: &str,
    workdir: &str,
    _canary: &Canary,
    start_command: &str,
    port: u16,
    pm: PackageManager,
    has_build: Option<&str>,
    native_build: bool,
    bun_spec: Option<&str>,
    build_env: &[(String, String)],
) -> String {
    // Bake a valid image outside `/tmp`; the launch wrapper copies it into the runtime tmpfs beside
    // the text canaries, so an image-reencoding sink has an observable found branch.
    let canary_image_b64 = base64(payload::PLANTED_IMAGE_PNG);
    let install = if pm == PackageManager::Npm {
        NPM_DOCKER_INSTALL
    } else {
        install_command(pm)
    };
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
    // Bun is distributed as a platform-specific npm package. Install the release requested by the
    // project before dependency installation and build, so Docker and the local verifier execute
    // the same package scripts instead of letting `npm start` fail at the first `bun` command.
    let bun_install = bun_spec.map_or_else(String::new, |spec| {
        format!(
            "RUN npm install --global {}\n",
            shell_quote(&format!("bun@{spec}"))
        )
    });
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
        .filter_map(|(name, value)| dockerfile_env_line(name, value))
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
         RUN (command -v curl >/dev/null 2>&1 && command -v git >/dev/null 2>&1) || \
         (apt-get update -qq && apt-get install -y -qq --no-install-recommends curl ca-certificates git && rm -rf /var/lib/apt/lists/*) || \
         apk add --no-cache curl ca-certificates git\n\
         WORKDIR /app\n\
         COPY . /app\n\
         WORKDIR {install_workdir}\n\
         {native_toolchain}\
         {bun_install}\
         {workspace_fixup}\
         RUN {install}\n\
         WORKDIR {workdir}\n\
         RUN for example in .env.example .env.sample .env.template; do \
         if [ ! -e .env ] && [ -f \"$example\" ]; then cp \"$example\" .env; fi; done\n\
         {build}\
         RUN echo {canary_image_b64} | base64 -d > /jss-canary-img-fixture\n\
         RUN echo {} | base64 -d > /jss-driver.js\n\
         RUN echo {} | base64 -d > /jss-socket-driver.js\n\
         RUN echo {} | base64 -d > /jss-mcp-driver.js\n\
         RUN echo {} | base64 -d > /jss-mcp-bridge.js\n\
         RUN echo {} | base64 -d > /jss-marker.js\n\
         RUN echo {} | base64 -d > /jss-marker.crt\n\
         RUN echo {} | base64 -d > /jss-marker.key\n\
         RUN echo {} | base64 -d > /jss-service-account.json\n\
         RUN echo {} | base64 -d > /jss-launch-shim.js\n\
         RUN echo {} | base64 -d > /jss-sink-binding.js\n\
         RUN echo {} | base64 -d > /jss-electron-shim.js\n\
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
        base64(SOCKET_DRIVER_JS.as_bytes()),
        base64(MCP_DRIVER_JS.as_bytes()),
        base64(MCP_BRIDGE_JS.as_bytes()),
        base64(MARKER_JS.as_bytes()),
        base64(MARKER_CERT.as_bytes()),
        base64(MARKER_KEY.as_bytes()),
        base64(SERVICE_ACCOUNT_JSON.as_bytes()),
        base64(LAUNCH_SHIM_JS.as_bytes()),
        base64(sink_binding::PRELOAD_JS.as_bytes()),
        base64(ELECTRON_SHIM_JS.as_bytes()),
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

/// A target-controlled Compose value rendered as one inert Dockerfile `ENV` instruction. Invalid
/// names and control characters are omitted: losing an optional build-time setting can only make
/// verification inconclusive, while copying a newline could inject an arbitrary `RUN` instruction.
pub(super) fn dockerfile_env_line(name: &str, value: &str) -> Option<String> {
    let mut name_chars = name.chars();
    if !name_chars
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
        || !name_chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        || value.len() > 8_192
        || value.chars().any(char::is_control)
    {
        return None;
    }
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '$' => escaped.push_str("\\$"),
            _ => escaped.push(ch),
        }
    }
    Some(format!("ENV {name}=\"{escaped}\"\n"))
}

/// Strips `workspace:`-protocol dependency specifiers from the install directory's `package.json`
/// before an npm install, since npm cannot resolve that protocol and aborts the entire install on the
/// first one it sees. Edits in place and tolerates a missing or malformed manifest. Dependencies
/// removed here are development-only monorepo tools, never runtime dependencies.
/// Installs the native-addon build toolchain on the Debian-based slim base image: `python3`, `make`
/// and a C++ compiler — the same packages the project's own production Dockerfile installs to build
/// its native dependencies. Run as root during the image build. Tolerant (`|| true`) so a transient
/// apt failure degrades to the ordinary install-skip rather than breaking the whole build.
pub(super) const NATIVE_TOOLCHAIN_INSTALL: &str = "apt-get update && apt-get install -y --no-install-recommends python3 make g++ && rm -rf /var/lib/apt/lists/* || true";

pub(super) const NPM_WORKSPACE_FIXUP: &str = "node -e 'try{const fs=require(\"fs\");const j=JSON.parse(fs.readFileSync(\"package.json\",\"utf8\"));const o=j.devDependencies;if(o&&typeof o===\"object\")for(const k of Object.keys(o)){if(typeof o[k]===\"string\"&&o[k].indexOf(\"workspace:\")===0)delete o[k];}fs.writeFileSync(\"package.json\",JSON.stringify(j,null,2));}catch(e){}'";

/// Standard base64 (no line wrapping): the only characters produced are `A-Za-z0-9+/=`, all
/// shell-safe, so an embedded script survives the Dockerfile unchanged.
pub(super) fn base64(input: &[u8]) -> String {
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
pub(super) struct RequiredEnv {
    pub(super) name: String,
    pub(super) value: String,
    /// The value is a directory (mounted empty and writable for the app).
    pub(super) directory: bool,
}

/// Selects an application-owned verification profile when a Node application explicitly ships
/// one through `node-config`. Some intentionally vulnerable applications disable dangerous routes
/// when they notice a container, while also providing `config/unsafe.{yml,json}` as their supported
/// isolated-test profile. The verifier may use that repository-declared profile inside its
/// disposable sandbox without requiring a caller-provided, application-specific flag.
///
/// Requiring both the `config` dependency and the exact profile file avoids assigning meaning to an
/// unrelated directory or file that merely happens to have one of these names.
pub(super) fn repository_verification_env(app_root: &std::path::Path) -> Option<RequiredEnv> {
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(app_root.join("package.json")).ok()?).ok()?;
    let uses_node_config = ["dependencies", "devDependencies", "optionalDependencies"]
        .iter()
        .any(|section| {
            manifest
                .get(section)
                .and_then(|value| value.get("config"))
                .is_some()
        });
    if !uses_node_config {
        return None;
    }
    let profile_exists = ["unsafe.yml", "unsafe.yaml", "unsafe.json"]
        .iter()
        .any(|name| app_root.join("config").join(name).is_file());
    profile_exists.then(|| RequiredEnv {
        name: "NODE_ENV".to_owned(),
        value: "unsafe".to_owned(),
        directory: false,
    })
}

/// Whether startup failed because a bare package dependency is absent. The launch shim can safely
/// stand in for that package on a retry; relative or absolute imports remain real application code
/// and must never be hidden.
pub(super) fn missing_bare_module(log: &str) -> bool {
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
pub(super) fn missing_mongodb_collection_promise(log: &str) -> bool {
    log.contains("TypeError: collections is not iterable")
}

/// Whether the application's first launch deliberately wrote its default configuration and exited.
/// Retrying once executes the documented second-start path against that generated file; unlike a
/// generic clean exit, the explicit generation message proves that another launch can make progress.
pub(super) fn generated_startup_config(log: &str) -> bool {
    let lower = log.to_ascii_lowercase();
    (lower.contains("config file not found") || lower.contains("configuration file not found"))
        && (lower.contains("generating default") || lower.contains("creating default"))
}

/// Whether a Next production launcher reached the framework but could not serve because the build
/// artifact is absent. This is narrower than a generic build/start failure: Next itself confirms
/// that the application is installed and that its production launcher is the only blocker.
pub(super) fn missing_next_production_build(log: &str) -> bool {
    log.contains("Could not find a production build in the '.next' directory")
        || log.contains("Could not find a production build in the `.next` directory")
}

/// The repository's own Next development launcher, used only after
/// [`missing_next_production_build`] proves that its production wrapper cannot start. Keeping the
/// manifest's `dev` script preserves project-specific flags and configuration while the explicit
/// host/port keep the verifier's listener deterministic.
pub(super) fn next_development_command(root: &std::path::Path, port: u16) -> Option<Vec<String>> {
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
pub(super) fn missing_write_dir(log: &str) -> Option<String> {
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
pub(super) fn missing_tls_material(log: &str) -> Option<(String, bool)> {
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

/// The last single-quoted path in the `ENOENT: no such file or directory` line of a startup failure
/// (`... open '/app/Server/service-account.json'`), or `None` when the log carries no such line. A
/// rename/copy reports source then destination; the last quoted segment is the operand that failed.
pub(super) fn enoent_path(log: &str) -> Option<&str> {
    let line = log
        .lines()
        .find(|line| line.contains("ENOENT: no such file or directory"))?;
    let mut path: Option<&str> = None;
    let mut rest = line;
    while let Some(open) = rest.find('\'') {
        let after = &rest[open + 1..];
        let close = after.find('\'')?;
        path = Some(&after[..close]);
        rest = &after[close + 1..];
    }
    path
}

/// When startup fails because the app tried to *read* a Google service-account credential JSON that is
/// not in the checkout, the absolute path the app expected. The Firebase Admin SDK is initialized from
/// a service-account file (`admin.credential.cert(JSON.parse(readFileSync('service-account.json')))`)
/// that the repository deliberately does not commit, so the Admin SDK reads it at startup and the
/// process exits before it binds. The sandbox stages an inert, syntactically valid placeholder
/// ([`SERVICE_ACCOUNT_JSON`]) there on the next attempt — a genuine deployment precondition (the
/// operator supplies this credential), not an input neutralization: the placeholder authenticates no
/// request and relaxes no auth check, since the SDK only mints a token when the app verifies a Firebase
/// ID token, which an anonymous route under test never does.
///
/// Qualifying is deliberately narrow, so conjuring this file can never mask a genuinely-required input:
/// the failure must be a read of a `.json` file, and the application's own source must initialize the
/// Firebase Admin credential from a certificate (`credential.cert(`) — the authoritative Admin SDK API
/// for a service-account file. Keyed on the SDK's ecosystem API only; nothing names a specific
/// application or filename.
pub(super) fn missing_service_account_json(log: &str, root: &std::path::Path) -> Option<String> {
    if !log.contains("ENOENT") {
        return None;
    }
    const READ_OPS: [&str; 4] = ["readFileSync", "readFile", "createReadStream", "read("];
    if !READ_OPS.iter().any(|op| log.contains(op)) {
        return None;
    }
    let path = enoent_path(log)?;
    if !path.starts_with('/') || !path.to_ascii_lowercase().ends_with(".json") {
        return None;
    }
    reads_firebase_service_account(root).then(|| path.to_owned())
}

/// Whether the application's own source initializes the Firebase Admin SDK from a service-account
/// certificate (`admin.credential.cert(...)` / `firebaseAdmin.credential.cert(...)`). A bounded,
/// source-only scan under the repository, skipping `node_modules` and dot-directories; it looks for
/// the Admin SDK's `credential.cert(` call, the ecosystem signal that a service-account JSON file is a
/// required startup credential. Nothing here names a specific application.
pub(super) fn reads_firebase_service_account(root: &std::path::Path) -> bool {
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
                if let Ok(text) = std::fs::read_to_string(&path)
                    && text.contains("credential.cert(")
                {
                    return true;
                }
            }
        }
        false
    }
    let mut budget = 4000u32;
    scan(root, &mut budget)
}

/// Returns a missing dotenv file that a startup loader explicitly refused to run without. An empty
/// file preserves normal dotenv semantics (no configuration is invented) while allowing the app to
/// continue to its own defaults and subsequent, more specific startup checks.
pub(super) fn missing_dotenv_file(log: &str) -> Option<String> {
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

/// A runtime configuration file the app refused to start without, staged on a retry by copying the
/// deployment's own committed template (`config.default.yaml`, `config.example.yaml`, …) to the path
/// the loader expected. `target` and `template` are both paths as the running process sees them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ConfigStage {
    pub(super) target: String,
    pub(super) template: String,
}

/// Configuration-file extensions a deployment ships a committed template for. `.env` is handled
/// separately (see [`missing_dotenv_file`]); only structured config formats qualify here.
const CONFIG_EXTS: [&str; 7] = [".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf"];

/// The absolute config-file path a startup message said was absent, taken only from a line that both
/// names configuration and reports the file missing. Returns the path verbatim (a container path
/// under `/app`, or a host path for the local runtime) so each caller can map it to the checkout.
fn missing_config_path(log: &str) -> Option<String> {
    for line in log.lines() {
        let lower = line.to_ascii_lowercase();
        if !(lower.contains("config") || lower.contains("configuration")) {
            continue;
        }
        if !(lower.contains("not found")
            || lower.contains("no such file")
            || lower.contains("enoent")
            || lower.contains("does not exist")
            || lower.contains("cannot find")
            || lower.contains("missing"))
        {
            continue;
        }
        for raw in line.split(|c: char| {
            c.is_whitespace() || matches!(c, '\'' | '"' | '`' | '(' | ')' | '[' | ']')
        }) {
            let tok = raw.trim_end_matches(['.', ',', ':', ';', ')']);
            if !tok.starts_with('/') {
                continue;
            }
            let lower_tok = tok.to_ascii_lowercase();
            if !CONFIG_EXTS.iter().any(|ext| lower_tok.ends_with(ext)) {
                continue;
            }
            let name = std::path::Path::new(tok)
                .file_name()
                .and_then(|n| n.to_str())?;
            // `.env.*` and other dotfiles are handled elsewhere; never treat them as config here.
            if name.starts_with('.') {
                continue;
            }
            return Some(tok.to_owned());
        }
    }
    None
}

/// Committed template basenames a deployment derives `name` from, in order of preference. These are
/// the ecosystem conventions (`config.default.yaml`, `config.example.yaml`, `config.yaml.example`,
/// …); nothing names a specific application.
fn config_template_basenames(name: &str) -> Vec<String> {
    let mut out = Vec::new();
    const MIDS: [&str; 5] = ["default", "example", "sample", "template", "dist"];
    if let Some((stem, ext)) = name.rsplit_once('.') {
        for mid in MIDS {
            out.push(format!("{stem}.{mid}.{ext}"));
        }
    }
    for suffix in MIDS {
        out.push(format!("{name}.{suffix}"));
    }
    out
}

/// Given the missing config path and the host directory that holds it, the first committed template
/// sibling that actually exists, paired with the path to write. `template` is expressed against the
/// same directory prefix as `target`, so copying it reproduces the deployment's own first-run step
/// (what `docker-entrypoint`-style scripts do) without inventing any configuration value.
fn config_stage_for(missing: &str, host_dir: &std::path::Path) -> Option<ConfigStage> {
    let name = std::path::Path::new(missing)
        .file_name()
        .and_then(|n| n.to_str())?;
    let prefix = missing.rsplit_once('/').map_or("", |(dir, _)| dir);
    for basename in config_template_basenames(name) {
        if host_dir.join(&basename).is_file() {
            let template = if prefix.is_empty() {
                basename
            } else {
                format!("{prefix}/{basename}")
            };
            return Some(ConfigStage {
                target: missing.to_owned(),
                template,
            });
        }
    }
    None
}

/// Config-file staging for the container runtime: the loader's path is under `/app`, which maps onto
/// the host checkout `root`. Returns the copy to perform only when the deployment committed a template
/// for it, so a genuinely required-but-absent config is reproduced and an invented one never is.
pub(super) fn missing_config_file_container(
    log: &str,
    root: &std::path::Path,
) -> Option<ConfigStage> {
    let missing = missing_config_path(log)?;
    let relative = missing.strip_prefix("/app/")?;
    let host_dir = root.join(relative).parent()?.to_path_buf();
    config_stage_for(&missing, &host_dir)
}

/// Config-file staging for the local runtime: the loader reports a host path inside the disposable
/// checkout, whose own directory is where the committed template lives.
pub(super) fn missing_config_file_local(log: &str) -> Option<ConfigStage> {
    let missing = missing_config_path(log)?;
    let host_dir = std::path::Path::new(&missing).parent()?.to_path_buf();
    config_stage_for(&missing, &host_dir)
}

/// External-service credential environment variables a sink is gated on, read by name from the
/// sink's own module and the modules it imports (`gating_sources`). Each is given a strong random
/// filler so the handler's "a credential is configured" branch — the one the sink sits behind — is
/// active, reproducing a deployment that configured the integration. Only credential-named variables
/// qualify (`*_TOKEN`, `*_PAT`, `*_SECRET`, `*_PASSWORD`, `*_CREDENTIAL(S)`); a random value can only
/// enable a configured-credential path, never match a real secret or relax an authentication check,
/// and the sandbox's own variables (`NODE_*`/`NPM_*`) are never touched.
pub(super) fn credential_env(gating_sources: &[String]) -> Vec<RequiredEnv> {
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
pub(super) fn config_source_env(gating_sources: &[String]) -> Vec<RequiredEnv> {
    let mut out: Vec<RequiredEnv> = Vec::new();
    for src in gating_sources {
        for name in env_var_names(src) {
            if fillable_config_name(&name)
                && out.iter().all(|existing| existing.name != name)
                && let Some((value, directory)) = typed_env_value(&name)
                && typed_env_is_required_by_source(src, &name, directory)
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

/// Whether the source uses a typed deployment variable in an operation that rejects an absent
/// value. Merely reading `BASE_PATH`, `PUBLIC_URL`, or another routing setting does not qualify:
/// inventing one changes the application's externally visible routes and can make a valid probe
/// unreachable. A filesystem value passed to `path.join`/`path.resolve`, or a URL value passed to
/// `new URL`, is a real shape precondition because those APIs throw on `undefined`.
fn typed_env_is_required_by_source(source: &str, name: &str, directory: bool) -> bool {
    let reference = format!("process.env.{name}");
    let bracketed_single = format!("process.env['{name}']");
    let bracketed_double = format!("process.env[\"{name}\"]");
    let references = [
        reference.as_str(),
        bracketed_single.as_str(),
        bracketed_double.as_str(),
    ];
    if directory {
        return ["path.join(", "path.resolve(", ".join(", ".resolve("]
            .iter()
            .any(|call| {
                source.match_indices(call).any(|(at, _)| {
                    let tail = &source[at + call.len()..];
                    references
                        .iter()
                        .any(|reference| tail.trim_start().starts_with(reference))
                })
            });
    }
    let kind = name.rsplit('_').next().unwrap_or(name);
    matches!(kind, "URL" | "URI")
        && source.match_indices("new URL(").any(|(at, _)| {
            let tail = &source[at + "new URL(".len()..];
            references
                .iter()
                .any(|reference| tail.trim_start().starts_with(reference))
        })
}

/// Whether an environment variable name denotes an external-service credential the sandbox may set
/// to a filler to satisfy a configuration precondition: an `_`-delimited segment of `TOKEN`, `PAT`,
/// `SECRET`, `PASSWORD`, `CREDENTIAL`, `CREDENTIALS` or `APIKEY`, plus the adjacent segments
/// `API_KEY` (so `GITHUB_TOKEN`/`GH_TOKEN`/`GITHUB_PAT`/`GEMINI_API_KEY`/`OPENAI_API_KEY` qualify but
/// `PATH` does not). A generic `*_KEY` is deliberately excluded: cryptographic key pairs such as
/// VAPID public/private keys have strict encodings and an arbitrary filler prevents the application
/// from starting. Never a variable the sandbox owns.
pub(super) fn credential_name(name: &str) -> bool {
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
pub(super) const STRONG_FILLER_SECRET: &str = "9f8e7d6c5b4a39281706f5e4d3c2b1a0ffeeddccbbaa998877665544332211009f8e7d6c5b4a39281706f5e4d3c2b1a0ffeeddccbbaa99887766554433221100";

/// The environment variables an app's startup failure says it requires: a variable-style name
/// (`UPPER_SNAKE`, with an underscore) followed in its log by `is required` / `must be set` /
/// `is not set` / `is missing` (`Error: NOOBOT_WORKSPACE_ROOT is required`), or after
/// `environment variable` / `missing` (`Missing required environment variable: DATABASE_URL`).
/// Each gets a neutral value of the kind its name asks for: a fresh empty directory for a
/// `_ROOT`/`_DIR`/`_PATH`/`_HOME` name, a URL that resolves nowhere for a `_URL`/`_URI`, else a
/// plain word. Never one the sandbox sets itself, nor Node's or npm's own (`NODE_OPTIONS`):
/// those would change the sandbox, not satisfy the app.
pub(super) fn required_env(log: &str) -> Vec<RequiredEnv> {
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
pub(super) fn typed_env_value(name: &str) -> Option<(String, bool)> {
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
pub(super) fn config_env(log: &str, root: &std::path::Path) -> Vec<RequiredEnv> {
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
pub(super) fn dynamic_setting_env_names(source: &str) -> Vec<(String, String)> {
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

pub(super) fn fillable_config_name(name: &str) -> bool {
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
pub(super) fn stack_app_files(log: &str, root: &std::path::Path) -> Vec<String> {
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
pub(super) const SANDBOX_RUN_UID: u32 = 10001;
pub(super) const SANDBOX_RUN_GID: u32 = 10001;

/// A runtime-user precondition discovered from an app's own source: the non-root identity to run as
/// plus the environment its deployment supplies for the privilege drop to succeed.
pub(super) struct PrivilegeDrop {
    pub(super) run_as: (u32, u32),
    pub(super) env: Vec<RequiredEnv>,
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
pub(super) fn privilege_drop_fixture(
    app_root: &std::path::Path,
    port: u16,
) -> Option<PrivilegeDrop> {
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
pub(super) fn local_privilege_drop_fixture(
    app_root: &std::path::Path,
    port: u16,
) -> Option<PrivilegeDrop> {
    let fixture = privilege_drop_fixture(app_root, port)?;
    let identity = current_unix_identity()?;
    Some(adapt_privilege_drop_to_local_identity(fixture, identity))
}

pub(super) fn adapt_privilege_drop_to_local_identity(
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
pub(super) fn current_unix_identity() -> Option<(u32, u32)> {
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
pub(super) fn current_unix_identity() -> Option<(u32, u32)> {
    None
}

/// The app's own JavaScript source (never `node_modules` or build output), bounded in breadth and
/// depth so scanning a large repo stays cheap. Used only to recognize a startup privilege drop and
/// the environment variables it reads.
pub(super) fn app_source_files(app_root: &std::path::Path) -> Vec<String> {
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
pub(super) fn env_var_names(src: &str) -> Vec<String> {
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
pub(super) fn listening_probe_excluding(wanted: u16, excluded: &[u16]) -> String {
    listening_probe_excluding_candidates(wanted, excluded, &[])
}

pub(super) fn listening_probe_excluding_candidates(
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
         for(const f of ['/proc/net/tcp','/proc/net/tcp6']){{let t='';try{{t=fs.readFileSync(f,'utf8')}}catch(e){{}}\
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
         const fin=(v)=>{{if(done)return;done=true;try{{s.destroy()}}catch(e){{}}if(v)return cb(true);go()}};\
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
pub(super) fn start_command(
    root: &std::path::Path,
    entry: Option<&std::path::Path>,
) -> Option<String> {
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
        && !manifest_start_wraps_file(root, &file)
    {
        return Some(node_file_command(&file));
    }
    // A repository can ship several standalone server entry files that mount different routers on the
    // same port. The finding's own file is a mountable router/app module: it publishes the route under
    // test but never listens, so a parent server wires it in (`app.use(require('./routes/products'))`).
    // When the launch the manifest or convention would otherwise pick runs a server that never pulls in
    // this router — so the route under test is never served under it — but another standalone server in
    // the repo does require it (directly or transitively), launch the server that actually mounts the
    // finding's route. Keyed only on the module require graph, never on a filename.
    if let Some(rel) = entry.and_then(|path| path.to_str())
        && let Some(module) = package_file(root, rel)
        && (is_express_router_module(&root.join(&module))
            || is_express_app_module(&root.join(&module)))
    {
        let default_file = manifest_start_command(root)
            .as_deref()
            .and_then(node_command_file);
        let default_mounts =
            default_file.as_deref().is_some_and(|file| {
                file == module
                    || module_reachable_from(
                        root,
                        std::path::Path::new(file),
                        std::path::Path::new(&module),
                    )
            }) || manifest_start_reaches_module(root, std::path::Path::new(&module));
        if !default_mounts
            && let Some(server) = server_mounting_module(root, &module)
            && Some(&server) != default_file.as_ref()
        {
            return Some(node_file_command(&server));
        }
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

/// Whether the manifest's Node launcher reaches `module`, including the common supervisor shape
/// where `npm start` runs a small file that `fork()`s the real server named by a local `.js` literal.
/// This prevents a directly runnable child worker or short-lived test from replacing the deployment
/// launcher that supplies its arguments and environment.
fn manifest_start_reaches_module(root: &std::path::Path, module: &std::path::Path) -> bool {
    let Ok(manifest) = std::fs::read_to_string(root.join("package.json")) else {
        return false;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&manifest) else {
        return false;
    };
    let Some(script) = json
        .get("scripts")
        .and_then(|scripts| scripts.get("start"))
        .and_then(serde_json::Value::as_str)
    else {
        return false;
    };
    let Some(launcher) = node_launcher_file(script, root) else {
        return false;
    };
    supervisor_reaches_module(root, std::path::Path::new(&launcher), module, 3)
}

fn supervisor_reaches_module(
    root: &std::path::Path,
    launcher: &std::path::Path,
    module: &std::path::Path,
    depth: usize,
) -> bool {
    if module_reachable_from(root, launcher, module) {
        return true;
    }
    if depth == 0 {
        return false;
    }
    let Ok(source) = std::fs::read_to_string(root.join(launcher)) else {
        return false;
    };
    if !(source.contains("fork(") || source.contains("spawn(")) {
        return false;
    }
    let parent = launcher
        .parent()
        .unwrap_or_else(|| std::path::Path::new(""));
    javascript_string_literals(&source)
        .into_iter()
        .any(|literal| {
            if ![".js", ".mjs", ".cjs"]
                .iter()
                .any(|extension| literal.ends_with(extension))
                || literal.contains(['$', '{'])
            {
                return false;
            }
            let child = parent.join(literal.trim_start_matches("./"));
            root.join(&child).is_file()
                && supervisor_reaches_module(root, &child, module, depth.saturating_sub(1))
        })
}

/// Plain JavaScript string literal bodies. Escaped/template strings are deliberately ignored: this
/// helper is only a conservative source of checked-in child entry filenames for a supervisor.
fn javascript_string_literals(source: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = source.as_bytes();
    for (at, byte) in bytes.iter().enumerate() {
        if !matches!(byte, b'\'' | b'"' | b'`') || at < 4 {
            continue;
        }
        let before = &source[..at];
        if ![".js", ".mjs", ".cjs"]
            .iter()
            .any(|extension| before.ends_with(extension))
        {
            continue;
        }
        let line_start = before.rfind(['\n', '\r']).map_or(0, |index| index + 1);
        let Some(open) = source[line_start..at].rfind(*byte as char) else {
            continue;
        };
        let start = line_start + open + 1;
        let literal = &source[start..at];
        if !literal.contains('\\') {
            out.push(literal);
        }
    }
    out
}

/// Whether the package manifest's only selectable launch is a CLI dispatcher `main` file. Mirrors
/// the precedence in [`manifest_start_command`]: a `start`, `serve`, `server`, or `app` script is a
/// real launch, not a CLI, so those short-circuit to `false`. Otherwise the decision rests on the
/// `main` file being a command-line dispatcher ([`is_cli_dispatcher`]) — one that parses argv and
/// prints usage rather than listening.
pub(super) fn manifest_launch_is_cli(root: &std::path::Path) -> bool {
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
pub(super) fn manifest_launch_is_frontend(root: &std::path::Path) -> bool {
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
pub(super) fn express_host_command(file: &str) -> String {
    format!("[\"node\",\"/jss-express-host.mjs\",\"{file}\"]")
}

/// Whether a JavaScript file is a mountable Express router module: it pulls in Express and builds a
/// `express.Router()` (directly, or via an exported factory) but never calls `.listen(` itself. Such
/// a module publishes routes without a server of its own — the application wires it into one at
/// runtime (often behind a CLI subcommand) — so it is launched through the Express host shim rather
/// than run directly, which would only evaluate and exit. A self-contained server (which does
/// `.listen(`) is left to the normal launch path.
pub(super) fn is_express_router_module(path: &std::path::Path) -> bool {
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
pub(super) fn is_express_app_module(path: &std::path::Path) -> bool {
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
pub(super) fn is_express_factory_module(path: &std::path::Path) -> bool {
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
pub(super) fn manifest_start_file_missing(root: &std::path::Path) -> bool {
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
pub(super) fn lifecycle_host_command(file: &str) -> String {
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
pub(super) fn is_lifecycle_server_module(path: &std::path::Path) -> bool {
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
pub(super) fn route_host_command(file: &str) -> String {
    format!("[\"node\",\"/jss-route-host.mjs\",\"{file}\"]")
}

/// The launch command that mounts an Azure Functions v4 application module through the Azure host shim
/// ([`AZURE_FUNC_HOST_JS`]): the shim mocks `@azure/functions`, transpiles and loads the module so its
/// `app.http(...)` HTTP triggers register, and serves them over HTTP on `PORT`.
pub(super) fn azure_host_command(file: &str) -> String {
    format!("[\"node\",\"/jss-azure-func-host.cjs\",\"{file}\"]")
}

/// The launch command that serves a module worker through the worker host shim ([`WORKER_HOST_JS`]):
/// the shim imports the module, takes its default export's `fetch(request, env, ctx)` method, and
/// serves it over HTTP on `PORT`, building a web `Request` per connection and writing the handler's
/// web `Response` back.
pub(super) fn worker_host_command(file: &str) -> String {
    format!("[\"node\",\"/jss-worker-host.mjs\",\"{file}\"]")
}

/// Whether a JavaScript/TypeScript file is a module worker: its default export is an object literal
/// (`export default { ... }`) that declares a `fetch` handler, and it never binds a listener of its own
/// (`.listen(`). Cloudflare Workers, Deno and Bun all serve an HTTP origin this way — the runtime
/// invokes `default.fetch(request)` per request — so such a module publishes no server and is launched
/// through the worker host shim rather than run directly, which would only evaluate and exit. The
/// `export default {` shape plus a `fetch` method is the structural signal; no runtime package
/// identifier or global is assumed.
pub(super) fn is_module_worker(path: &std::path::Path) -> bool {
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
pub(super) fn declares_fetch_handler(body: &str) -> bool {
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
pub(super) fn is_vercel_function(root: &std::path::Path, file: &str) -> bool {
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
pub(super) fn manifest_launch_is_azure_functions(root: &std::path::Path) -> bool {
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
pub(super) fn is_azure_functions_v4_module(path: &std::path::Path) -> bool {
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
pub(super) fn node_red_host_command(file: &str) -> String {
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
pub(super) fn is_node_red_node_module(path: &std::path::Path) -> bool {
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
pub(super) const ROUTE_METHOD_STEMS: [&str; 10] = [
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
pub(super) fn is_route_handler_module(path: &std::path::Path) -> bool {
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
pub(super) fn exports_route_handler(src: &str) -> bool {
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
pub(super) fn balanced_object(rhs: &str) -> Option<String> {
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
pub(super) fn object_has_function_property(object: &str, key: &str) -> bool {
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
pub(super) fn is_cli_dispatcher(path: &std::path::Path) -> bool {
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
pub(super) fn manifest_start_command(root: &std::path::Path) -> Option<String> {
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

/// Whether the manifest's `start` command launches `file` through a repository shell wrapper. A
/// wrapper often exports the runtime mode, data directory and credentials before invoking the same
/// self-contained server (`"start": "sh start.sh"`, then `node app.js`). Running `app.js` directly
/// would serve the right route with the wrong deployment configuration. The relationship must be
/// explicit in the checked-in wrapper; an unrelated manifest server does not suppress the exact
/// finding-file launch.
pub(super) fn manifest_start_wraps_file(root: &std::path::Path, file: &str) -> bool {
    let Ok(manifest) = std::fs::read_to_string(root.join("package.json")) else {
        return false;
    };
    let Some(start) = serde_json::from_str::<serde_json::Value>(&manifest)
        .ok()
        .and_then(|value| {
            value
                .get("scripts")?
                .get("start")?
                .as_str()
                .map(str::to_owned)
        })
    else {
        return false;
    };
    if shell_command_runs_node_file(&start, file) {
        return true;
    }
    let wrapper = start
        .split_whitespace()
        .map(trim_shell_word)
        .find(|word| word.ends_with(".sh"));
    let Some(wrapper) = wrapper.and_then(|word| package_file(root, word)) else {
        return false;
    };
    std::fs::read_to_string(root.join(wrapper))
        .is_ok_and(|script| shell_command_runs_node_file(&script, file))
}

fn trim_shell_word(word: &str) -> &str {
    word.trim_matches(|c| matches!(c, '\'' | '"' | ';' | '&'))
        .trim_start_matches("./")
}

fn shell_command_runs_node_file(command: &str, file: &str) -> bool {
    let file = file.trim_start_matches("./");
    for line in command.lines() {
        let words: Vec<_> = line.split_whitespace().map(trim_shell_word).collect();
        if words.windows(2).any(
            |pair| matches!(pair, [program, argument] if program.rsplit('/').next() == Some("node") && *argument == file),
        )
        {
            return true;
        }
    }
    false
}

pub(super) fn contains_command(command: &str, program: &str, argument: &str) -> bool {
    let words: Vec<&str> = command.split_whitespace().collect();
    words.windows(2).any(|pair| pair == [program, argument])
}

/// A conventional launcher entry file of the package, when its manifest names no launch. Node's own
/// default entry (`index.js`) and the common server filenames (`server`, `app`, `main`) are tried at
/// the package root and under `src/` and `bin/`, in that order. The chosen file must itself bind a
/// port ([`is_launchable_entry`]) so that running it with `node <file>` starts the server rather than
/// merely loading a library or exporting an unstarted app factory.
pub(super) fn conventional_entry(root: &std::path::Path) -> Option<String> {
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
pub(super) fn is_launchable_entry(path: &std::path::Path) -> bool {
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
pub(super) fn plugin_host_command(file: &str) -> String {
    format!("[\"node\",\"/jss-plugin-host.mjs\",\"{file}\"]")
}

/// Whether a JavaScript file is a plug-in handler module: one that registers an HTTP request handler
/// on a host-provided service (`ctx`/`app`/`server`.`register`/`route`/`addRoute`, with a `handler`)
/// from inside a plug-in `apply`, and never calls `.listen(` itself. Such a module publishes no
/// server of its own — the host it plugs into supplies one at deploy time — so it is launched through
/// the plug-in host shim rather than run directly. A self-contained server (which does `.listen(`) is
/// left to the normal launch path.
pub(super) fn is_plugin_handler(path: &std::path::Path) -> bool {
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
pub(super) fn is_standalone_server(path: &std::path::Path) -> bool {
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

pub(super) fn only_exports_uninvoked_server_start(src: &str) -> bool {
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

pub(super) fn node_file_command(file: &str) -> String {
    serde_json::json!(["node", file]).to_string()
}

/// The file a `["node","<file>", ...]` launch command runs, when the command is exactly that shape.
/// `None` for an `npm`/shell launcher, where the entry file is not named directly.
pub(super) fn node_command_file(command: &str) -> Option<String> {
    let argv: Vec<String> = serde_json::from_str(command).ok()?;
    match argv.as_slice() {
        [program, file, ..] if program == "node" => Some(file.clone()),
        _ => None,
    }
}

/// A standalone server source file in the repo that mounts the finding's own router/app module — it
/// requires that module directly or transitively and binds a listener itself. Used to launch the
/// server that actually serves the route under test when the manifest/convention launch runs a
/// different server that never pulls the module in. Among candidates, the shortest path wins, then
/// lexicographic order, for a deterministic choice. Never the module itself.
pub(super) fn server_mounting_module(root: &std::path::Path, module_rel: &str) -> Option<String> {
    let module = std::path::Path::new(module_rel);
    let mut best: Option<String> = None;
    for candidate in repo_js_files(root) {
        let Some(rel) = candidate.to_str() else {
            continue;
        };
        if rel == module_rel {
            continue;
        }
        if nonproduction_server_candidate(&candidate) {
            continue;
        }
        if !is_standalone_server(&root.join(&candidate)) {
            continue;
        }
        if !module_reachable_from(root, &candidate, module) {
            continue;
        }
        let better = match &best {
            None => true,
            Some(current) => {
                let a = rel.matches('/').count();
                let b = current.matches('/').count();
                (a, rel) < (b, current.as_str())
            }
        };
        if better {
            best = Some(rel.to_owned());
        }
    }
    best
}

/// Tests and fixtures may briefly bind a real HTTP listener while exercising a router, but they are
/// not application launchers: their runner exits as soon as assertions finish. Selecting one makes
/// the verifier race a short-lived test server and then misclassify subsequent connection failures.
fn nonproduction_server_candidate(path: &std::path::Path) -> bool {
    let in_nonproduction_dir = path.components().any(|component| {
        matches!(
            component
                .as_os_str()
                .to_string_lossy()
                .to_ascii_lowercase()
                .as_str(),
            "test" | "tests" | "__tests__" | "fixture" | "fixtures" | "example" | "examples"
        )
    });
    let name = path
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    in_nonproduction_dir || name.ends_with(".test") || name.ends_with(".spec")
}

/// Every JavaScript source file in the repo (relative to `root`), by a bounded walk that skips
/// dependency and build directories.
pub(super) fn repo_js_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    const SKIP_DIRS: [&str; 6] = ["node_modules", ".git", "dist", "build", "coverage", "out"];
    let mut out = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0u32)];
    while let Some((dir, depth)) = stack.pop() {
        if depth > 6 || out.len() >= 2000 {
            break;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if kind.is_dir() {
                if !name.starts_with('.') && !SKIP_DIRS.contains(&name.as_ref()) {
                    stack.push((entry.path(), depth + 1));
                }
            } else if matches!(
                std::path::Path::new(name.as_ref())
                    .extension()
                    .and_then(|ext| ext.to_str()),
                Some("js" | "mjs" | "cjs")
            ) && let Ok(rel) = entry.path().strip_prefix(root)
            {
                out.push(rel.to_path_buf());
            }
        }
    }
    out
}

/// Whether `target_rel` is reachable from `start_rel` by following relative `require`/`import`
/// specifiers through the repo's own source files (never into `node_modules`). A bounded breadth
/// walk; returns `true` as soon as an edge resolves to `target_rel`.
pub(super) fn module_reachable_from(
    root: &std::path::Path,
    start_rel: &std::path::Path,
    target_rel: &std::path::Path,
) -> bool {
    let target = normalize_rel(target_rel);
    let mut seen = std::collections::BTreeSet::new();
    let mut stack = vec![start_rel.to_path_buf()];
    while let Some(current) = stack.pop() {
        if seen.len() > 500 {
            break;
        }
        let norm = normalize_rel(&current);
        if !seen.insert(norm.clone()) {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(root.join(&current)) else {
            continue;
        };
        for spec in relative_specifiers(&src) {
            if let Some(dep) = resolve_relative_module(root, &current, &spec) {
                if normalize_rel(&dep) == target {
                    return true;
                }
                stack.push(dep);
            }
        }
    }
    false
}

/// The relative module specifiers (those starting with `.`) a source imports via `require(...)`,
/// `import ... from '...'`, or a bare `import '...'`. Bare package specifiers are ignored: only the
/// repo's own files form edges in the require graph.
pub(super) fn relative_specifiers(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    for needle in ["require(", "from", "import"] {
        let mut from = 0usize;
        while let Some(pos) = src[from..].find(needle) {
            let after = from + pos + needle.len();
            from = after;
            let rest = src[after..].trim_start();
            let Some(quote) = rest.chars().next() else {
                continue;
            };
            if quote != '\'' && quote != '"' && quote != '`' {
                continue;
            }
            if let Some(end) = rest[quote.len_utf8()..].find(quote) {
                let spec = &rest[quote.len_utf8()..quote.len_utf8() + end];
                if spec.starts_with('.') {
                    out.push(spec.to_owned());
                }
            }
        }
    }
    out
}

/// Resolves a relative module specifier against the directory of the file that imports it, applying
/// Node's extension and `index` resolution, and returns the matching repo file (relative to `root`),
/// or `None` when nothing resolves to a real file.
pub(super) fn resolve_relative_module(
    root: &std::path::Path,
    from_rel: &std::path::Path,
    spec: &str,
) -> Option<std::path::PathBuf> {
    let base = from_rel.parent().unwrap_or(std::path::Path::new(""));
    let joined = normalize_rel(&base.join(spec));
    const EXTS: [&str; 4] = ["js", "cjs", "mjs", "json"];
    if root.join(&joined).is_file() {
        return Some(joined);
    }
    for ext in EXTS {
        let candidate = joined.with_extension(ext);
        if root.join(&candidate).is_file() {
            return Some(candidate);
        }
    }
    for ext in EXTS {
        let candidate = joined.join(format!("index.{ext}"));
        if root.join(&candidate).is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Normalizes a relative path by resolving `.` and `..` components lexically, without touching the
/// filesystem. Leading `..` that would climb above the root are kept so distinct inputs stay distinct.
pub(super) fn normalize_rel(path: &std::path::Path) -> std::path::PathBuf {
    let mut parts: Vec<std::ffi::OsString> = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if matches!(parts.last().map(|p| p.as_os_str()), Some(last) if last != "..") {
                    parts.pop();
                } else {
                    parts.push(std::ffi::OsString::from(".."));
                }
            }
            std::path::Component::Normal(part) => parts.push(part.to_os_string()),
            _ => {}
        }
    }
    parts.iter().collect()
}

/// Whether a JavaScript file is an Electron main-process entry: it pulls in the `electron` module and
/// defers its own startup to the application lifecycle (`app.whenReady`). Such a file is a
/// self-contained server in every respect — it constructs and `.listen`s on its HTTP server — but run
/// directly with `node` it throws before binding, because off an Electron runtime `require('electron')`
/// resolves to the packaged binary's path string rather than the main-process API, so
/// `const { app } = require('electron')` is `undefined` and the first `app.` access crashes. It is
/// launched with the Electron shim ([`ELECTRON_SHIM_JS`]) preloaded, which supplies an inert
/// main-process API (a resolved `whenReady`, a real writable `getPath`, otherwise permissive stubs) so
/// the app's own `whenReady` callback runs and its embedded server listens. Framework-neutral: keyed
/// only on the `electron` import and the `whenReady` lifecycle call every Electron main process uses,
/// never on a repository name or path.
pub(super) fn is_electron_main_process(path: &std::path::Path) -> bool {
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
    let imports_electron = ["require('electron')", "require(\"electron\")"]
        .iter()
        .any(|needle| src.contains(needle))
        || ["from 'electron'", "from \"electron\""]
            .iter()
            .any(|needle| src.contains(needle));
    imports_electron && src.contains(".whenReady(")
}

/// A UTF-8 file inside the package, never an absolute path or one containing `..`. Commands that
/// consume the returned name serialize it as JSON, so ordinary non-ASCII repository filenames are
/// safe and do not need to be rejected.
pub(super) fn package_file(root: &std::path::Path, path: &str) -> Option<String> {
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
pub(super) fn detached_script(script: &str) -> Option<&str> {
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
pub(super) fn process_manager_script(script: &str) -> Option<&str> {
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
pub(super) fn direct_node_command(script: &str, root: &std::path::Path) -> Option<String> {
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
pub(super) fn node_launcher_file(script: &str, root: &std::path::Path) -> Option<String> {
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
pub(super) fn next_app_dir(root: &std::path::Path) -> Option<String> {
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
pub(super) fn ephemeral_mongo_next_launch(
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

pub(super) fn local_ephemeral_mongo_next_launch(root: &std::path::Path) -> Option<String> {
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
pub(super) fn has_start_script(manifest: &str) -> bool {
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
pub(super) fn working_dir_for_cwd_paths(
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
pub(super) fn cwd_relative_literals(src: &str) -> Vec<String> {
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
pub(super) fn container_dir(app: &std::path::Path) -> Option<String> {
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
/// A genuine session minted through the app's own authentication, carried back on the gated request.
#[derive(Clone)]
pub(super) enum SessionCred {
    /// A bearer token (a JWT the login returned in its body), carried under a cookie and the bearer
    /// header.
    Bearer { cookie: String, token: String },
    /// A `name=value` cookie the login's `Set-Cookie` issued, carried back verbatim.
    Cookie { pair: String },
}

/// The HTTP status and `Set-Cookie` headers from the driver's tagged metadata line on stderr.
/// The response's `Content-Type`, from the driver's metadata line, when it sent one.
pub(super) fn driver_content_type(stderr: &str) -> Option<String> {
    stderr.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("__JSS_META__")?;
        let value = serde_json::from_str::<serde_json::Value>(rest).ok()?;
        value
            .get("contentType")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    })
}

/// Whether a `Content-Type` is one a browser renders as an HTML page.
pub(super) fn is_html_content_type(kind: &str) -> bool {
    let essence = kind.split(';').next().unwrap_or_default().trim();
    essence.eq_ignore_ascii_case("text/html")
        || essence.eq_ignore_ascii_case("application/xhtml+xml")
}

pub(super) fn parse_driver_meta(stderr: &str) -> (Option<u16>, Vec<String>) {
    for line in stderr.lines() {
        let Some(rest) = line.trim().strip_prefix("__JSS_META__") else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(rest) else {
            continue;
        };
        let status = value
            .get("status")
            .and_then(serde_json::Value::as_u64)
            .filter(|code| *code > 0)
            .map(|code| code as u16);
        let cookies = match value.get("setCookie") {
            Some(serde_json::Value::Array(items)) => items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect(),
            Some(serde_json::Value::String(single)) => vec![single.clone()],
            _ => Vec::new(),
        };
        return (status, cookies);
    }
    (None, Vec::new())
}

/// The JSON spec `/jss-socket-driver.js` reads from `argv[2]`: the event to emit (the attempt's
/// target) and its payload (an arbitrary JSON value — an object for a named field, a bare string for
/// a whole-payload entry), re-parsed from the attempt's body so the driver gets a real JSON value,
/// never a string to re-escape. `ack_ms` bounds the wait for the handler's ack.
pub(super) fn socket_spec(attempt: &Attempt, port: u16, tls: bool, ack_ms: u64) -> String {
    let payload: serde_json::Value = attempt
        .body
        .as_deref()
        .and_then(|body| serde_json::from_str(body).ok())
        .unwrap_or(serde_json::Value::Null);
    serde_json::json!({
        "port": port, "tls": tls, "event": attempt.target, "payload": payload, "ackMs": ack_ms,
    })
    .to_string()
}

/// A runnable `socket.io-client` snippet reproducing `attempt`, for the report's PoC command. The
/// whole `-e` script is one single-quoted shell argument (the event name and JSON payload nest
/// safely inside it in double quotes, valid JS either way), so it is copy-pasteable as-is.
pub(super) fn socket_command(event: &str, body: Option<&str>, port: u16) -> String {
    let payload = body.unwrap_or("null");
    let script = format!(
        "require('socket.io-client')('http://TARGET_HOST:{port}').emit({}, {payload}, console.log)",
        serde_json::Value::String(event.to_owned()),
    );
    format!("node -e {}", shell_quote(&script))
}

pub(super) fn request_spec(attempt: &Attempt, port: u16, forward: bool, tls: bool) -> String {
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
    // Present the request as arriving over TLS at a terminating reverse proxy. A great many Node
    // deployments sit behind a load balancer that offloads HTTPS and sets `X-Forwarded-Proto: https`;
    // the app (trusting its loopback proxy) redirects any request it reads as plain HTTP straight to
    // `https://…` with an empty body, so a verifier request without this header never reaches a
    // handler — every probe bounces off the redirect before the sink. The verifier reaches the app
    // from loopback, which is exactly where that trusted proxy sits, so claiming the proxy's standard
    // scheme header is faithful, not a bypass: the request still carries the real payload and proves
    // the same flow. Gated on `forward` and suppressed on the loopback-origin retry alongside
    // `X-Forwarded-For`, and left alone when a payload sets the header itself.
    if forward
        && !pairs
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("x-forwarded-proto"))
    {
        pairs.push(("X-Forwarded-Proto".to_owned(), "https".to_owned()));
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

pub(super) fn binary_request_spec(
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

pub(super) fn multipart_file(
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
pub(super) fn stored_zip(name: &str, contents: &[u8]) -> Vec<u8> {
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

pub(super) fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub(super) fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub(super) fn crc32(bytes: &[u8]) -> u32 {
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

pub(super) fn esc(text: &str) -> String {
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

/// The shortest tail of a traversal value worth stripping from a response: shorter ones are common
/// words, not names a handler echoes.
pub(super) const MIN_ECHOED_TAIL: usize = 5;

/// Removes a request's own path and raw value from a response body, so the read oracle compares
/// the *structure* of two responses (a file-found page versus a not-found page) rather than the
/// requested identifier a not-found page reflects back. The request target and the decoded
/// traversal value are stripped, since a handler may echo either form — and so is every tail of the
/// value that starts after a path separator, because a handler that confines the path (a base
/// name, a join under its own directory) still names the file it failed to open, and that error
/// message carries the tail of the climb it kept. Left in, the planted file's name would make a
/// confined handler's three answers differ, which the oracle would read as a file found.
pub(super) fn strip_request_echo(body: &str, target: &str, value: &str) -> String {
    let mut out = body.to_owned();
    // The longest tail first, so a shorter one does not leave the rest of a longer one behind.
    let tails = value
        .match_indices('/')
        .map(|(at, _)| &value[at + 1..])
        .filter(|tail| tail.len() >= MIN_ECHOED_TAIL);
    for needle in [target, value].into_iter().chain(tails) {
        if !needle.is_empty() {
            out = out.replace(needle, "");
        }
    }
    out
}

/// Keep the report and downstream advisory text safe when a differential oracle's successful
/// branch returns an image or another binary body. The full body is still used above for the
/// three-way comparison; only the human-facing excerpt is replaced.
pub(super) fn response_excerpt(body: &str) -> String {
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

pub(super) fn control_observation(
    label: &str,
    attempt: &Attempt,
    response: &str,
) -> ControlObservation {
    ControlObservation {
        label: label.to_owned(),
        method: attempt.verb.to_owned(),
        target: attempt.target.clone(),
        body: attempt.body.clone(),
        response: response_excerpt(response),
    }
}

pub(super) fn nosql_differential_evidence(field: &str, body_query_override: bool) -> String {
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

pub(super) fn tail(text: &str, lines: usize) -> String {
    let all: Vec<&str> = text.lines().collect();
    all.get(all.len().saturating_sub(lines)..)
        .unwrap_or_default()
        .join("\n")
}

pub(super) fn docker(args: &[&str]) -> Result<String, String> {
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

pub(super) fn remove_container(name: &str) {
    // `-v` removes anonymous volumes declared by base images. Without it, every
    // verification leaves those volumes behind after the container is removed.
    let _ = docker(&["rm", "-f", "-v", name]);
}

pub(super) fn docker_args(args: &[&str]) -> Vec<String> {
    let label = std::env::var("JSS_VERIFY_RUN_LABEL").ok();
    docker_args_with_label(args, label.as_deref())
}

pub(super) fn docker_args_with_label(args: &[&str], label: Option<&str>) -> Vec<String> {
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

/// Whether `command` is the bridge's launch (see [`super::stdio::bridge_command`]).
pub(super) fn is_bridge_command(command: &str) -> bool {
    command.contains("/jss-mcp-bridge.js")
}

pub(super) fn run_id() -> String {
    static STARTED: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    // The clock ticks every few dozen nanoseconds, so two sessions begun at once in this process
    // (parallel tests, parallel verifications) can read the same time: the count keeps their
    // container and network names apart.
    let count = STARTED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{nanos:x}{count:x}")
}

/// A short, process-unique suffix for the canary token. Not cryptographic: it only has to be
/// unlikely to appear in the app's own output within one run.
pub(super) fn short_rand() -> String {
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
pub(super) const LAUNCH_SHIM_JS: &str = r#"
'use strict';
const Module = require('module');
const origLoad = Module._load;

// A loopback->sidecar TCP forwarder for an app that hard-codes its backing service on
// `localhost`/`127.0.0.1` (a connection string written inline, not read from the injected env). The
// sidecar answers only on the private network under a service alias, so the hard-coded loopback
// connection would never reach it. For each `localport:host:remoteport` route, listen on both
// loopback families and pipe bytes verbatim to the real sidecar; the app then talks to the actual
// database/cache. Protocol-agnostic raw piping fabricates nothing about the query. Each listener is
// unref'd so it never keeps the process alive, and a bind that collides with a family the app itself
// uses is ignored.
if (process.env.JSS_LOOPBACK_FORWARD) {
  try {
    const net = require('net');
    process.env.JSS_LOOPBACK_FORWARD.split(',')
      .map(function (s) { return s.trim(); })
      .filter(Boolean)
      .forEach(function (spec) {
        const parts = spec.split(':');
        const lport = parseInt(parts[0], 10);
        const host = parts[1];
        const rport = parseInt(parts[2], 10);
        if (!lport || !host || !rport) return;
        ['127.0.0.1', '::1'].forEach(function (bind) {
          const server = net.createServer(function (client) {
            client.on('error', function () {});
            const upstream = net.connect(rport, host);
            upstream.on('error', function () { client.destroy(); });
            client.pipe(upstream);
            upstream.pipe(client);
          });
          server.on('error', function () {});
          server.unref();
          try { server.listen(lport, bind); } catch (e) {}
        });
      });
  } catch (e) {}
}

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

/// Preload (`node --require`) that lets an Electron main-process module launch under plain `node` so
/// its embedded HTTP server binds and the real sink can be exercised. It intercepts `require('electron')`
/// (which off an Electron runtime returns the binary path, not the API) and returns an inert
/// main-process surface: an `app` whose `whenReady()` resolves immediately — so the app's own startup
/// callback runs — and whose `getPath()` returns a real writable scratch directory (the app joins it
/// with `path.join` and writes logs/config there), with every other member a permissive proxy stub
/// that is callable, constructable, and iterable (window size tuples destructure without throwing).
/// It fabricates nothing about the request path, the routing, or the sink: the app's own
/// `http.createServer(...).listen(...)` still runs, and a verification still requires the real canary
/// to flow through the app's own handler into the real file-read sink. Dependency-free (Node core only).
pub(super) const ELECTRON_SHIM_JS: &str = r#"
'use strict';
const os = require('os');
const path = require('path');
const fs = require('fs');
const Module = require('module');
const origLoad = Module._load;

// A real, writable scratch directory tree for `app.getPath(name)`: the app joins the returned value
// with `path.join` and writes logs/config into it, so it must be an actual string path, not a stub.
let base = null;
function userPath(name) {
  if (!base) {
    try { base = fs.mkdtempSync(path.join(os.tmpdir(), 'jss-electron-')); }
    catch (e) { base = os.tmpdir(); }
  }
  const p = path.join(base, String(name || 'userData'));
  try { fs.mkdirSync(p, { recursive: true }); } catch (e) {}
  return p;
}

const handler = {
  get: function (target, prop) {
    if (prop === 'then') return undefined;
    if (prop === Symbol.toPrimitive) return function () { return ''; };
    // Electron getters commonly return tuples (`getContentSize() -> [w, h]`); a non-iterable stub
    // would crash the array destructuring that follows. Yield a bounded run of stubs instead.
    if (prop === Symbol.iterator) return function* () { for (let i = 0; i < 8; i++) yield stub; };
    if (prop === Symbol.asyncIterator) return undefined;
    if (prop in target) return target[prop];
    return stub;
  },
  apply: function () { return stub; },
  construct: function () { return stub; },
};
const stub = new Proxy(function () {}, handler);

const app = new Proxy({
  commandLine: {
    appendSwitch: function () {}, appendArgument: function () {},
    hasSwitch: function () { return false; }, getSwitchValue: function () { return ''; },
  },
  whenReady: function () { return Promise.resolve(); },
  on: function () { return app; }, once: function () { return app; }, off: function () { return app; },
  addListener: function () { return app; }, removeListener: function () { return app; },
  removeAllListeners: function () { return app; }, emit: function () { return false; },
  getPath: function (name) { return userPath(name); },
  getName: function () { return 'app'; }, getVersion: function () { return '0.0.0'; },
  getLocale: function () { return 'en-US'; }, setName: function () {}, setPath: function () {},
  quit: function () {}, exit: function () {}, relaunch: function () {}, focus: function () {},
  hide: function () {}, show: function () {},
  requestSingleInstanceLock: function () { return true; }, releaseSingleInstanceLock: function () {},
  setAppUserModelId: function () {}, disableHardwareAcceleration: function () {},
  isReady: function () { return true; }, getAppPath: function () { return process.cwd(); },
  setLoginItemSettings: function () {}, getLoginItemSettings: function () { return {}; },
  setAsDefaultProtocolClient: function () { return true; },
}, handler);

const electron = new Proxy({ app: app }, {
  get: function (target, prop) {
    if (prop === 'app') return app;
    if (prop === 'then') return undefined;
    if (prop === Symbol.toPrimitive) return function () { return ''; };
    return stub;
  },
});

const ELECTRON = new Set(['electron', 'electron/main', 'electron/common', 'electron/renderer']);
Module._load = function (request) {
  if (typeof request === 'string' && ELECTRON.has(request)) return electron;
  return origLoad.apply(this, arguments);
};
"#;

/// ESM counterpart of [`LAUNCH_SHIM_JS`]. Only an undeclared bare module that fails with
/// `ERR_MODULE_NOT_FOUND` is replaced; relative files and other resolver failures retain Node's
/// behavior. Named imports are recovered from the importing statement so the inert stub can link.
pub(super) const LAUNCH_ESM_HOOK_JS: &str = r#"
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
pub(super) const PLUGIN_HOST_JS: &str = r#"
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
pub(super) const DB_BOOTSTRAP_JS: &str = r#"
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

pub(super) const EXPRESS_HOST_JS: &str = r#"
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
pub(super) const LIFECYCLE_HOST_JS: &str = r#"
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
pub(super) const ROUTE_HOST_JS: &str = r#"
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
pub(super) const NODE_RED_HOST_JS: &str = r#"
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
pub(super) const AZURE_FUNC_HOST_JS: &str = r#"
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
pub(super) const WORKER_HOST_JS: &str = r#"
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
pub(super) const DRIVER_JS: &str = r#"
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
  // Mongoose's default buffered-operation failure is 10 seconds. Give the application enough
  // time to return that controlled error so fix verification can preserve the route's real benign
  // behavior instead of racing the driver timeout at the same deadline.
  const options = {host,port:spec.port,method:spec.method,path:spec.path,headers:spec.headers,timeout:15000};
  if(name==='https'){options.rejectUnauthorized=false;}
  let sent = false;
  const done = (data)=>{if(sent){return;} sent=true; try{process.stdout.write(data,()=>process.exit(0));}catch(e){process.exit(0);}};
  const req = mod.request(options,(res)=>{
    // Emit the response status and any Set-Cookie on stderr, tagged, so the verifier can detect an
    // authentication challenge and capture a session the app's own login issued. stdout stays the
    // response body, unchanged, so body-based comparisons are unaffected.
    try{process.stderr.write('__JSS_META__'+JSON.stringify({status:res.statusCode||0,setCookie:res.headers['set-cookie']||null,contentType:res.headers['content-type']||null})+'\n');}catch(e){}
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

/// Speaks Engine.IO long-polling directly (the wire protocol a `socket.io-client` connection runs
/// over HTTP, verified by hand against a real socket.io 4.8.1 server): an open handshake, a
/// namespace-connect packet, the probe's event with an ack id, then polls for that ack. No
/// `socket.io-client`/npm dependency, so it runs on the `--internal` app network exactly like
/// [`DRIVER_JS`]. Supports Engine.IO protocol v4 (socket.io v3/v4) at the default `/socket.io/`
/// path and the default namespace `/` only; an older v2 server (EIO=3) or a custom path is not
/// recognized and the probe comes back not-reproduced, same as a connection failure.
/// Speaks the Model Context Protocol to the app's MCP endpoint (Streamable HTTP, stateless or
/// stateful, JSON or event-stream replies, and the legacy HTTP+SSE transport): `discover` finds the
/// endpoint and reads `tools/list`; `call` initializes a session and calls one tool. No npm
/// dependency, so it runs on the `--internal` app network like [`DRIVER_JS`]. The reply is the
/// tool's text on stdout and a synthetic status in the tagged `__JSS_META__` line (200 it ran, 422
/// its input schema rejected the arguments, 404 no such tool, 500 the handler failed).
pub(super) const MCP_DRIVER_JS: &str = include_str!("../mcp_driver.js");

/// Stands in for an app that speaks only stdio: starts the repository's own MCP server as a child
/// process and serves what it says as a stateless Streamable HTTP endpoint on the session's port, so
/// the discovery, the call driver, the oracles and the fix proof work on it unchanged. Which command
/// starts the server is tried out candidate by candidate (see [`super::stdio`]); `GET /__bridge`
/// says which one answered, or why none did.
pub(super) const MCP_BRIDGE_JS: &str = include_str!("../mcp_bridge.js");

pub(super) const SOCKET_DRIVER_JS: &str = r#"
const http = require('http');
const https = require('https');
const spec = JSON.parse(process.argv[2]);
const MAX_RESPONSE_CHARS = 1024 * 1024;
const hosts = ['127.0.0.1','::1'];
const mods = spec.tls ? [['https',https],['http',http]] : [['http',http],['https',https]];
const combos = [];
for(const m of mods){for(const h of hosts){combos.push([m[0],m[1],h]);}}

function call(mod, host, method, path, body, timeoutMs){
  return new Promise((resolve, reject) => {
    const options = {host, port: spec.port, method, path, timeout: timeoutMs || 4000};
    if(mod === https){options.rejectUnauthorized = false;}
    if(method === 'POST'){options.headers = {'Content-Type': 'text/plain;charset=UTF-8'};}
    const req = mod.request(options, (res) => {
      let data = '';
      let settled = false;
      const done = () => {
        if (settled) { return; }
        settled = true;
        resolve({status: res.statusCode || 0, text: data});
      };
      res.on('data', (c) => {
        if (settled) { return; }
        data += c;
        if (data.length > MAX_RESPONSE_CHARS) {
          data = data.slice(0, MAX_RESPONSE_CHARS);
          res.destroy();
          done();
        }
      });
      res.on('end', done);
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    if(body){req.write(body);}
    req.end();
  });
}

// Polls the long-polling endpoint for a packet starting with `want` (e.g. the namespace-connect
// reply `40`, or an ack `43<id>`), up to `tries` times. Any other queued packet (a ping `2`, the
// app's own non-ack emit) is discarded; the attempt only cares about the one packet it asked for.
async function poll(mod, host, path, want, tries, waitMs){
  for(let i = 0; i < tries; i++){
    let res;
    try{ res = await call(mod, host, 'GET', path, null, waitMs); }
    catch(e){ if(e.message === 'timeout'){ return ''; } throw e; }
    if(res.text.startsWith(want)){return res.text;}
  }
  return '';
}

function meta(status){ try{ process.stderr.write('__JSS_META__' + JSON.stringify({status}) + '\n'); }catch(e){} }

async function attempt(){
  const errors = [];
  for(const [name, mod, host] of combos){
    try{
      const open = await call(mod, host, 'GET', '/socket.io/?EIO=4&transport=polling');
      if(!open.text.startsWith('0{')){throw new Error('no engine.io open packet');}
      const sid = JSON.parse(open.text.slice(1)).sid;
      const path = `/socket.io/?EIO=4&transport=polling&sid=${encodeURIComponent(sid)}`;
      await call(mod, host, 'POST', path, '40');
      if(!(await poll(mod, host, path, '40', 5, 4000))){throw new Error('no namespace-connect ack');}
      const ackId = Math.floor(Math.random() * 1e9);
      const packet = `42${ackId}${JSON.stringify([spec.event, spec.payload])}`;
      await call(mod, host, 'POST', path, packet);
      // The ack is the handler's own reply; an event it never acks gives nothing to wait for, which
      // is reported as 204 instead of retrying on the next host/protocol combination (that would
      // emit the event again).
      const ack = await poll(mod, host, path, `43${ackId}`, 10, spec.ackMs || 3000);
      const openBracket = ack.indexOf('[');
      process.stdout.write(openBracket < 0 ? '' : ack.slice(openBracket));
      meta(openBracket < 0 ? 204 : 200);
      // Disconnect: left open, this session (and its socket.io-level handlers/state) lingers on
      // the server for a full ping-timeout (20s by default). Hundreds of probes per finding would
      // otherwise accumulate hundreds of abandoned sessions within that window.
      await call(mod, host, 'POST', path, '41').catch(() => {});
      return;
    }catch(e){errors.push(name+'://'+host+': '+e.message);}
  }
  if(errors.length){process.stderr.write(errors.join('; '));}
}
attempt();
"#;

/// Records the path of every request it receives, on stdout, so a marker hit shows in the
/// container logs. Listens on HTTP port 80 and, when the planted certificate is present, HTTPS
/// port 443 — so an outbound request whose host (not whole URL) is attacker-controlled still
/// lands here even when the app uses `https`/`http.request` against a fixed port. The certificate
/// is trusted by the app through `NODE_EXTRA_CA_CERTS`, so TLS verification passes honestly
/// instead of being disabled.
pub(super) const MARKER_JS: &str = r#"
const http = require('http');
const port = Number(process.env.JSS_MARKER_PORT || 80);
const record = (req) => console.log('MARKER ' + JSON.stringify({
  method: req.method,
  path: req.url,
  userAgent: req.headers['user-agent'] || null,
}));
const log = (req, res) => {
  record(req);
  let token = '';
  try { token = new URL(req.url, 'http://jss-marker').pathname.replace(/^\/+/, ''); } catch (_) {}
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.end(token ? `CANARY ${token}\n` : 'CANARY\n');
};
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
pub(super) const MARKER_CERT: &str = r#"-----BEGIN CERTIFICATE-----
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
pub(super) const MARKER_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
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

/// A syntactically valid, inert Google service-account credential, baked in as a startup fixture —
/// not a secret. An app that initializes the Firebase Admin SDK from a service-account JSON read off
/// the filesystem (`admin.credential.cert(JSON.parse(readFileSync('service-account.json')))`) exits
/// on startup when that file is absent, because the credential file is a deployment secret the repo
/// intentionally does not commit. Staging this placeholder at the exact path the app read satisfies
/// that deployment precondition so the app can bind, exactly as staging the marker TLS pair satisfies
/// an `https` server's need for a certificate. The key is a throwaway RSA key that signs nothing the
/// verifier relies on: the Admin SDK validates the fields and parses the key at `initializeApp`, but
/// only ever mints a token when the app actively verifies a Firebase ID token — which an anonymous
/// route under test never does — so this neither authenticates a request nor relaxes any auth check.
pub(super) const SERVICE_ACCOUNT_JSON: &str = r#"{
  "type": "service_account",
  "project_id": "jss-verify",
  "private_key_id": "jssverify0000000000000000000000000000000",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDetaXGRPVj5cQP\nnMGpneQ2pizPGwHCDRo0meudBxMBytDySIY7/j29xq2B0erNe6vzFJNJUCRSa8aP\nfC1sQQCJLEVgnQZtAChjLmyxjQ0k8rQmb103LaT8R4VXUtZxpJ7xjSeiJYfB5QTL\nK0ZwBejoar5u3NOZ9sPRE9K6US2kqqYOC+n1Wq3dnIrsZdso6fMcl9CpUumtcAE1\n5rB14Rw7r1Vk6Rifuy/7PqbvrRPhhwqg7XxyKXJVhhD6oaq/8I5n5uc16Vi0IaQU\nQiINXm3oTESYlHGhZpCxk6uTb7dwcHh+0x859tX0QXzGNVR02IIiiaNCRmBwOpj4\nyZzO1SozAgMBAAECggEAGonXxsAZ470R93BNDYrAkpiLt2Q2+eo4yLLcxjn9FFYY\nPv7QbB64OcCOlW0vxyupCk7V3EMeCOpJ33hDK2a1iyMI42HizaNarLLwBdpSiigX\nuorDt1sLkXpuU8ENx73/qLYS1noVatABGbq+6oNxxRxPNAPBfVPP8r6jektJHpl0\nKrTRoZHkBZBrPffgzDWeE5M/RC2AtmaIoA0xy4AINFiIKWQvNNxp3vtH55VMqC47\ndyYS9OX4dn0CA4ArlhcLBjwhCh02RiALjviLbZcm6RsqJSV+gWAIlTA59fMLU1sO\npYnrjyVLE5n164pYvebfh4k6Sokmi3j27DjNxwTt1QKBgQD+J+6eSPc1jreCYvkX\n7SIzAtqq2kif0wbQ4s+/ct6/cng2ZPqIqINtvihEUaMPvpvd9kMmtTwNGA8vXWQZ\n82ZBoldFUwcOcBF2F/7ukNI1w2IOuZdQbHorpZ2FeP4+gQo+083CVwodBsjg9s1d\nEOaZRZpXGRkhLvofN+RJ91xYtQKBgQDgU06aWbcXGUzje2g/H/f+ecZ+z32EDurV\nzFWjrQw9NLYlR5yXX2P9ERt4TmAn2fxH+g8EXHCnS1kROk16TY91hnhEZ4nq1J15\nbe0CBCRanvRdOvdv8zJyveJo+E1W1IoagcfhL8zNnZmaAdjBT4kHxzFbJjp4rrS4\nEDN0xoBQRwKBgDs6wSBALuRbWybWu+g4ijTLIHyanDwq6La7dODP+1swaRV8GOrK\nIr7rhuTNBaxApoBmyKV3rQP8LGXEZPSrRZRcKexs+gMCWP9lfjLIq0R+QRbfZ4UF\nkr8jPH+Df/S/C80yfQwiTqgPEbdjrN5YdvUXRG2x2qpiEUY/N0OJkwrVAoGBAJDq\nIFAj/txEMuCN22VUIJ/bSTioj9wcyuX8z6Ih61Mq1zQ0E9vR+sUEJSvN7d4wuwJA\nby0RDpF0YoB3mo+UxUVV7iG6hWUXnvdP5Rk1VcrY/uGvcyN2BzQKqNXI+iVKvkCr\ncFVvzK1Tz2OnJ8CRweMtchwBESrfKc3yYVth1IiHAoGBANOVvJutQqHNVXGFS2jN\n4k6wFpztmQmtFnRR/mgzantO9IYElRKyyis1WPcB+zynVs6c6DEi8CYVdOJ+ZjH4\nRN4DqSWFpEfVsT70Q9pwWC1r3rWs4lkJQXKXNGt4LFzY7r3ROvBkIyFXiGCiCFv9\nkBwAhNQ+uobtmBoZt53oukwC\n-----END PRIVATE KEY-----\n",
  "client_email": "jss-verify@jss-verify.iam.gserviceaccount.com",
  "client_id": "000000000000000000000",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/jss-verify%40jss-verify.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
}
"#;

// ----- browser phase (DOM-source XSS and client-side redirects) ---------------------------------

/// The browser-phase base image: Playwright's, which carries Node, Chromium and its system
/// dependencies. Pinned.
pub(super) const BROWSER_IMAGE: &str = "mcr.microsoft.com/playwright:v1.49.1-jammy";

pub(super) fn local_browser_executable() -> Option<std::path::PathBuf> {
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

pub(super) fn spawn_process_group(command: &mut Command, name: &str) -> Result<Child, String> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    command
        .spawn()
        .map_err(|error| format!("starting {name}: {error}"))
}

/// The DOM `url` renders to in the browser container `browser`, or why it did not load.
pub(super) fn docker_browser_capture(browser: &str, url: &str) -> Result<String, String> {
    docker(&[
        "exec",
        "-e",
        "JSS_DUMP=1",
        browser,
        "node",
        "/jss-browser.js",
        url,
    ])
}

// Browser verification lives in `sandbox/browser.rs`.

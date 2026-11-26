use super::*;

#[test]
fn patch_release_updates_only_the_workspace_version() -> Result<()> {
    let manifest = "[workspace]\nmembers = []\n\n[workspace.package]\nversion = \"1.2.9\"\nedition = \"2024\"\n\n[profile.release]\ndebug = true\n";
    let (updated, version) = next_patch_manifest(manifest)?;
    assert_eq!(version, "1.2.10");
    assert!(updated.contains("[workspace.package]\nversion = \"1.2.10\"\n"));
    assert!(updated.contains("[profile.release]\ndebug = true\n"));
    Ok(())
}

#[test]
fn patch_release_rejects_prerelease_or_missing_versions() {
    assert!(next_patch_manifest("[workspace.package]\nversion = \"1.2.3-alpha.1\"\n").is_err());
    assert!(next_patch_manifest("[package]\nversion = \"1.2.3\"\n").is_err());
}

#[cfg(unix)]
#[test]
fn timeout_stops_descendant_processes() -> Result<()> {
    if Command::new("node").arg("--version").output().is_err() {
        return Ok(());
    }
    let directory = tempfile::tempdir()?;
    let ready = directory.path().join("ready");
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    let script = format!(
        "node -e 'require(\"http\").createServer((q,s)=>s.end(\"ok\")).listen({port},\"127.0.0.1\",()=>require(\"fs\").writeFileSync({},\"ready\"))' & wait",
        serde_json::to_string(&ready.display().to_string())?
    );
    let error = status_with_timeout(
        Command::new("sh").args(["-c", &script]),
        Duration::from_secs(1),
    )
    .expect_err("the server tree should exceed the timeout");
    assert!(error.to_string().contains("wall-clock timeout"));
    assert!(ready.is_file(), "the descendant started before teardown");

    for _ in 0..50 {
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(20));
    }
    bail!("the timed-out descendant kept port {port} open")
}

fn repair_workspace() -> Result<(tempfile::TempDir, RepairWorkspace)> {
    let directory = tempfile::tempdir()?;
    command_ok(
        Command::new("git")
            .current_dir(directory.path())
            .args(["init", "-q"]),
        "initialize repair test repository".to_owned(),
    )?;
    std::fs::create_dir_all(directory.path().join("crates/jss-frontend/src"))?;
    std::fs::create_dir_all(directory.path().join("crates/jsspector/src/verify"))?;
    std::fs::create_dir_all(directory.path().join("xtask"))?;
    std::fs::write(
        directory.path().join("crates/jss-frontend/src/scan.rs"),
        "base\n",
    )?;
    std::fs::write(
        directory
            .path()
            .join("crates/jsspector/src/verify/sandbox.rs"),
        "trusted oracle\n",
    )?;
    std::fs::write(directory.path().join("xtask/controller.rs"), "trusted\n")?;
    command_ok(
        Command::new("git").current_dir(directory.path()).args([
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@localhost.invalid",
            "add",
            ".",
        ]),
        "stage repair test repository".to_owned(),
    )?;
    command_ok(
        Command::new("git").current_dir(directory.path()).args([
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@localhost.invalid",
            "commit",
            "-qm",
            "base",
        ]),
        "commit repair test repository".to_owned(),
    )?;
    let base = git_output(directory.path(), &["rev-parse", "HEAD"])?
        .trim()
        .to_owned();
    let workspace = RepairWorkspace {
        path: directory.path().to_path_buf(),
        branch: "main".to_owned(),
        base,
    };
    Ok((directory, workspace))
}

#[test]
fn staged_controller_edits_and_agent_created_commits_are_rejected() -> Result<()> {
    let (_directory, workspace) = repair_workspace()?;
    std::fs::write(
        workspace.path.join("crates/jss-frontend/src/scan.rs"),
        "repair\n",
    )?;
    std::fs::write(workspace.path.join("xtask/controller.rs"), "bypass\n")?;
    command_ok(
        Command::new("git")
            .current_dir(&workspace.path)
            .args(["add", "xtask/controller.rs"]),
        "stage forbidden controller edit".to_owned(),
    )?;
    assert!(validate_repair_paths(&workspace).is_err());

    command_ok(
        Command::new("git")
            .current_dir(&workspace.path)
            .args(["reset", "--hard", "HEAD"]),
        "reset repair test repository".to_owned(),
    )?;
    std::fs::write(
        workspace.path.join("crates/jss-frontend/src/scan.rs"),
        "committed\n",
    )?;
    command_ok(
        Command::new("git").current_dir(&workspace.path).args([
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@localhost.invalid",
            "commit",
            "-am",
            "agent commit",
        ]),
        "create unauthorized repair commit".to_owned(),
    )?;
    assert!(validate_repair_history(&workspace).is_err());
    Ok(())
}

#[test]
fn repair_agent_cannot_change_the_dynamic_proof_oracle() -> Result<()> {
    let (_directory, workspace) = repair_workspace()?;
    std::fs::write(
        workspace
            .path
            .join("crates/jsspector/src/verify/sandbox.rs"),
        "always verified\n",
    )?;
    assert!(validate_repair_paths(&workspace).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn benchmark_tree_permissions_are_restored_after_agent_access() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir()?;
    let nested = directory.path().join("src/app.js");
    std::fs::create_dir_all(nested.parent().context("nested parent")?)?;
    std::fs::write(&nested, "source\n")?;
    let original = std::fs::metadata(&nested)?.permissions().mode();
    {
        let _guard = ReadOnlyTree::new(directory.path())?;
        assert_eq!(std::fs::metadata(&nested)?.permissions().mode() & 0o222, 0);
        assert_eq!(
            std::fs::metadata(nested.parent().context("nested parent")?)?
                .permissions()
                .mode()
                & 0o222,
            0
        );
    }
    assert_eq!(std::fs::metadata(&nested)?.permissions().mode(), original);
    Ok(())
}

#[test]
fn parallel_integration_fast_forwards_before_applying_a_repair() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let remote = directory.path().join("remote.git");
    let writer = directory.path().join("writer");
    let worker = directory.path().join("worker");
    command_ok(
        Command::new("git").args(["init", "--bare"]).arg(&remote),
        "initialize test remote".to_owned(),
    )?;
    command_ok(
        Command::new("git")
            .args(["clone"])
            .arg(&remote)
            .arg(&writer),
        "clone test writer".to_owned(),
    )?;
    for (key, value) in [
        ("user.name", "JSSpector test"),
        ("user.email", "test@localhost.invalid"),
    ] {
        command_ok(
            Command::new("git")
                .current_dir(&writer)
                .args(["config", key, value]),
            format!("configure test writer {key}"),
        )?;
    }
    std::fs::write(writer.join("version"), "one\n")?;
    command_ok(
        Command::new("git")
            .current_dir(&writer)
            .args(["add", "version"]),
        "stage initial test revision".to_owned(),
    )?;
    command_ok(
        Command::new("git")
            .current_dir(&writer)
            .args(["commit", "-m", "initial"]),
        "commit initial test revision".to_owned(),
    )?;
    command_ok(
        Command::new("git")
            .current_dir(&writer)
            .args(["push", "-u", "origin", "HEAD:main"]),
        "push initial test revision".to_owned(),
    )?;
    command_ok(
        Command::new("git")
            .args(["clone", "--branch", "main"])
            .arg(&remote)
            .arg(&worker),
        "clone parallel test worker".to_owned(),
    )?;
    std::fs::write(writer.join("version"), "two\n")?;
    command_ok(
        Command::new("git")
            .current_dir(&writer)
            .args(["commit", "-am", "advance"]),
        "commit concurrent test revision".to_owned(),
    )?;
    command_ok(
        // Name the branch: the writer's local branch is whatever `init.defaultBranch` says,
        // and a bare `git push` refuses when it differs from `main`.
        Command::new("git")
            .current_dir(&writer)
            .args(["push", "origin", "HEAD:main"]),
        "push concurrent test revision".to_owned(),
    )?;

    synchronize_integration_checkout(&worker, true)?;

    assert_eq!(
        git_output(&worker, &["rev-parse", "HEAD"])?,
        git_output(&writer, &["rev-parse", "HEAD"])?
    );
    assert_eq!(std::fs::read_to_string(worker.join("version"))?, "two\n");
    Ok(())
}

fn case() -> Case {
    Case {
        finding_id: "finding-1".to_owned(),
        repository: "owner/repo".to_owned(),
        revision: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        class: "ssrf".to_owned(),
        file: Some("src/app.js".to_owned()),
        title: "custom advisory title".to_owned(),
        expected_exploitability: "exploitable".to_owned(),
        scanner_fingerprint: None,
        scanner_identity: None,
    }
}

#[test]
fn semantic_identity_recovers_a_missing_fingerprint() {
    let issue = json!({"snapshot": {
        "ruleId": "ssrf", "filePath": "src/app.js", "lineNumber": 12,
        "code": "req.query.url", "title": "SSRF in GET /proxy"
    }});
    let report = json!({"findings": [{
        "fingerprint": "new-fingerprint", "class": "ssrf", "file": "src/app.js",
        "title": "SSRF in GET /proxy",
        "source": {"kind": "http", "expr": "req.query.url", "line": 4},
        "sink": {"file": "src/app.js", "line": 12, "api": "fetch"}
    }]});

    let matches = matching_candidates(&case(), &issue, &report);

    assert_eq!(matches.len(), 1);
    assert_eq!(at(matches[0], &["fingerprint"]), "new-fingerprint");
}

#[test]
fn semantic_identity_rejects_a_different_flow_in_the_same_file() {
    let issue = json!({"snapshot": {
        "ruleId": "ssrf", "filePath": "src/app.js", "lineNumber": 12,
        "code": "req.query.url", "title": "SSRF in GET /proxy"
    }});
    let report = json!({"findings": [{
        "fingerprint": "other", "class": "ssrf", "file": "src/app.js",
        "title": "SSRF in POST /import",
        "source": {"kind": "http", "expr": "req.body.source", "line": 30},
        "sink": {"file": "src/app.js", "line": 40, "api": "fetch"}
    }]});

    assert!(matching_candidates(&case(), &issue, &report).is_empty());
}

#[test]
fn a_known_semantic_identity_never_degrades_to_heuristic_matching() {
    let issue = json!({"snapshot": {
        "ruleId": "ssrf", "filePath": "src/app.js", "lineNumber": 12,
        "code": "req.query.url", "title": "SSRF in GET /proxy"
    }});
    let report = json!({"findings": [{
        "fingerprint": "same-old-fingerprint", "identity": "jss1-different",
        "class": "ssrf", "file": "src/app.js", "title": "SSRF in GET /proxy",
        "source": {"kind": "http", "expr": "req.query.url", "line": 4},
        "sink": {"file": "src/app.js", "line": 12, "api": "fetch"}
    }]});
    let mut known = case();
    known.scanner_fingerprint = Some("same-old-fingerprint".to_owned());
    known.scanner_identity = Some("jss1-expected".to_owned());

    assert!(matching_candidates(&known, &issue, &report).is_empty());
}

#[test]
fn persisting_an_identity_migrates_a_schema_one_index() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("targets.json");
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "targets": [{
                "repository": "owner/repo",
                "revision": "0123456789abcdef0123456789abcdef01234567",
                "fingerprints": ["old-fingerprint"],
                "cases": [{"finding_id": "finding-1", "fingerprint": "old-fingerprint"}]
            }]
        }))?,
    )?;

    persist_identity(&path, &case(), "new-fingerprint", "jss1-new-identity")?;

    let migrated: Value = read_json(&path)?;
    assert_eq!(migrated["schema_version"], 2);
    let target = &migrated["targets"][0];
    assert_eq!(
        target["fingerprints"],
        json!(["new-fingerprint", "old-fingerprint"])
    );
    assert_eq!(target["identities"], json!(["jss1-new-identity"]));
    assert_eq!(target["cases"][0]["fingerprint"], "new-fingerprint");
    assert_eq!(target["cases"][0]["identity"], "jss1-new-identity");
    Ok(())
}

#[test]
fn verified_requires_a_structured_poc() {
    let incomplete = json!({"exploitation": {"outcome": "verified"}});
    let complete = json!({
        "exploitation": {"outcome": "verified"},
        "poc": {"command": "curl http://TARGET_HOST", "evidence": "callback observed"}
    });

    assert!(!has_dynamic_proof(&incomplete));
    assert!(has_dynamic_proof(&complete));
}

#[test]
fn repository_selection_accepts_head_full_revision_and_prefix() {
    let case = case();
    assert!(repository_selection_matches("OWNER/REPO", &case));
    assert!(repository_selection_matches(
        "owner/repo@0123456789abcdef0123456789abcdef01234567",
        &case
    ));
    assert!(repository_selection_matches("owner/repo@012345", &case));
    assert!(!repository_selection_matches("owner/other", &case));
    assert!(!repository_selection_matches("owner/repo@abcdef", &case));
}

#[test]
fn benchmark_identity_fields_cannot_escape_controller_paths_or_git_arguments() {
    assert!(validate_case(&case()).is_ok());

    let mut traversal = case();
    traversal.finding_id = "../../outside".to_owned();
    assert!(validate_case(&traversal).is_err());

    let mut revision = case();
    revision.revision = "--upload-pack=malicious".to_owned();
    assert!(validate_case(&revision).is_err());

    let mut source = case();
    source.file = Some("../outside.js".to_owned());
    assert!(validate_case(&source).is_err());
}

#[cfg(unix)]
#[test]
fn private_artifacts_replace_symlinks_and_protect_their_directory() -> Result<()> {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let root = tempfile::tempdir()?;
    let artifacts = root.path().join("artifacts");
    let outside = root.path().join("outside");
    std::fs::create_dir(&artifacts)?;
    std::fs::write(&outside, "keep")?;
    let artifact = artifacts.join("diagnostic.json");
    symlink(&outside, &artifact)?;

    atomic_private_write(&artifact, b"diagnostic")?;

    assert_eq!(std::fs::read_to_string(&outside)?, "keep");
    assert_eq!(std::fs::read_to_string(&artifact)?, "diagnostic");
    assert!(
        !std::fs::symlink_metadata(&artifact)?
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        std::fs::metadata(&artifacts)?.permissions().mode() & 0o777,
        0o700
    );
    Ok(())
}

#[test]
fn agent_transcripts_are_bounded_but_the_pipe_is_fully_drained() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let transcript = directory.path().join("agent.jsonl");
    copy_bounded(std::io::Cursor::new(vec![b'x'; 128]), &transcript, 16)?;

    let output = std::fs::read(&transcript)?;
    assert_eq!(output.get(..16), Some([b'x'; 16].as_slice()));
    assert!(output.ends_with(b"[jsspector: transcript truncated]\n"));
    Ok(())
}

use super::*;

impl Session {
    /// Confirms a path-traversal read whose content is not reflected, by a differential oracle. A
    /// real sensitive OS file is preferred; a crafted out-of-root fixture is used only when the
    /// handler's filename constraints prevent naming that file. Two equivalent missing paths must
    /// agree, while the positive path must take a distinct file-found branch. URL reflection is
    /// neutralized before comparing, so a handler that confines all three paths yields no signal.
    pub(super) fn verify_read_oracle(
        &self,
        probe: &Probe,
        credential: Option<&SessionCred>,
    ) -> Option<Reproduction> {
        // The climbed path may enter the request several ways (the entry, or a parsed query parameter
        // under a gate) and the found canary has two shapes (text, image); try each until one shows
        // the file-found/not-found differential.
        payload::read_oracle(probe, &self.canary, self.nonce)
            .iter()
            .find_map(|oracle| self.try_read_oracle(oracle, credential))
    }

    /// Runs one read-oracle candidate's three-request differential; see [`Self::verify_read_oracle`].
    pub(super) fn try_read_oracle(
        &self,
        oracle: &payload::ReadOracle,
        credential: Option<&SessionCred>,
    ) -> Option<Reproduction> {
        let present_attempt = self.with_credential(&oracle.present, credential);
        let absent_attempt = self.with_credential(&oracle.absent, credential);
        let absent_sub_attempt = self.with_credential(&oracle.absent_sub, credential);
        // Establish both controls before touching the planted path. Some vulnerable handlers enter
        // the file-found branch and then crash in downstream processing of the loaded fixture; its
        // response is still valid evidence, but sending it first would kill the process before the
        // not-found controls can be observed.
        let absent = self.fetch(&absent_attempt)?;
        let absent_sub = self.fetch(&absent_sub_attempt)?;
        let present = self.fetch(&present_attempt)?;
        let sink_hit = self.last_sink_hit.get();
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
        let differential =
            present_n != absent_n && present_n != absent_sub_n && absent_n == absent_sub_n;
        if !self.accept_bound_effect_with_hit(differential, sink_hit) {
            return None;
        }
        // The read oracle runs before the broad reflected-content matrix, so it must preserve the
        // stronger result when its positive leg actually returns the planted bytes. JavaScript
        // commonly serializes a string/Buffer spread as numeric JSON keys; that is content
        // disclosure, even though the literal token is not contiguous in the raw response. Export
        // the same decoder used by the normal response path so the copyable PoC prints the bytes a
        // reviewer needs to see instead of an opaque object.
        if payload::response_contains_canary(&present, &self.canary.token) {
            let mut command = self.poc_command(&present_attempt);
            if !present.contains(&self.canary.token) {
                command = decode_indexed_json_response(&command);
            }
            let transcript = self.exact_http_transcript(&present_attempt, &command);
            return Some(Reproduction {
                command,
                command_redacted: false,
                method: present_attempt.verb.to_owned(),
                target: present_attempt.target.clone(),
                headers: present_attempt
                    .headers
                    .iter()
                    .map(|(name, value)| format!("{name}: {value}"))
                    .collect(),
                body: present_attempt.body.clone(),
                evidence: observed_evidence(
                    &Signal::InResponse,
                    self.canary.callback_host(),
                    &present,
                    &self.canary.token,
                    None,
                ),
                response: response_excerpt(&present),
                stdout: transcript
                    .as_ref()
                    .map(|output| String::from_utf8_lossy(&output.stdout).into_owned()),
                stderr: transcript
                    .as_ref()
                    .map(|output| String::from_utf8_lossy(&output.stderr).into_owned()),
                exit_code: transcript.as_ref().and_then(|output| output.status.code()),
                output_safety: transcript.map(|_| "oracle-proof".to_owned()),
                controls: Vec::new(),
            });
        }
        let evidence = match &oracle.proof {
            payload::ReadOracleProof::SensitiveFile { path } => format!(
                "the traversal reached the real operating-system file `{path}`: the handler took its \
                file-found path for `{path}` but its not-found path for two equivalent nonexistent \
                siblings under `/etc`, proving path traversal and disclosure of the target file's \
                existence outside the application base directory; the response did not return the \
                file bytes, so this is an existence oracle, not local file content disclosure"
            ),
            payload::ReadOracleProof::CraftedFixture {
                effective_path,
                constraint,
            } => {
                let why = constraint
                    .as_deref()
                    .unwrap_or("the handler requires a crafted verifier fixture");
                format!(
                    "{why}, so an exact `/etc/shadow` or `/etc/passwd` target is not representable; \
                    a verifier-created file outside the application base directory was placed at \
                    `{effective_path}`, and the traversal took its file-found path only for that file \
                    while two equivalent unplanted controls took its not-found path; the response \
                    did not return the file bytes, so this proves an existence oracle rather than \
                    local file content disclosure"
                )
            }
        };
        Some(Reproduction {
            command: self.poc_command(&present_attempt),
            command_redacted: false,
            method: present_attempt.verb.to_owned(),
            target: present_attempt.target.clone(),
            headers: present_attempt
                .headers
                .iter()
                .map(|(name, value)| format!("{name}: {value}"))
                .collect(),
            body: present_attempt.body.clone(),
            evidence,
            response: response_excerpt(&present),
            stdout: None,
            stderr: None,
            exit_code: None,
            output_safety: None,
            controls: Vec::new(),
        })
    }

    /// Confirms a path-traversal removal (`fs.unlink`, `fs.rm`, …) by a destructive differential: a
    /// `target` file is planted outside the application's base directory, and a `control` file is
    /// planted alongside it that the request never names. The present request climbs to `target` and
    /// asks the handler to remove it. A vulnerable handler opens the attacker-controlled path and
    /// removes `target` (it disappears) while `control` survives; a handler that confines the path
    /// reaches neither. The planting and the request both stay inside the isolated app container.
    pub(super) fn verify_delete_oracle(
        &self,
        probe: &Probe,
        credential: Option<&SessionCred>,
    ) -> Option<Reproduction> {
        let oracle = payload::delete_oracle(probe, &self.canary, self.nonce)?;
        let present = self.with_credential(&oracle.present, credential);
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
                present.verb, present.target, oracle.target_path, oracle.control_path
            );
        }
        let response = self.fetch(&present);
        let sink_hit = self.last_sink_hit.get();
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            eprintln!(
                "[verify] delete oracle response={response:?} target-exists={} control-exists={}",
                self.file_exists(&oracle.target_path),
                self.file_exists(&oracle.control_path)
            );
        }
        // The target must be gone (the traversal reached it) and the control must survive (the
        // removal was directed by the attacker-controlled path, not an indiscriminate wipe).
        let removed =
            !self.file_exists(&oracle.target_path) && self.file_exists(&oracle.control_path);
        if !self.accept_bound_effect_with_hit(removed, sink_hit) {
            return None;
        }
        let entry_kind = if probe.removes_dir {
            "directory"
        } else {
            "file"
        };
        Some(Reproduction {
            command: self.poc_command(&present),
            command_redacted: false,
            method: present.verb.to_owned(),
            target: present.target.clone(),
            headers: present
                .headers
                .iter()
                .map(|(name, value)| format!("{name}: {value}"))
                .collect(),
            body: present.body.clone(),
            evidence: format!(
                "a canary {entry_kind} planted outside the application's base directory was removed \
                 by the traversal request while a sibling control {entry_kind} planted alongside it \
                 survived, proving the removal opened the attacker-controlled path outside the base \
                 directory"
            ),
            response: String::new(),
            stdout: None,
            stderr: None,
            exit_code: None,
            output_safety: None,
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
    pub(super) fn verify_create_oracle(
        &self,
        probe: &Probe,
        credential: Option<&SessionCred>,
    ) -> Option<Reproduction> {
        let oracle = payload::create_oracle(probe, &self.canary, self.nonce)?;
        // A sink that case-normalizes the attacker's path before the write (`id.toUpperCase()`,
        // `name.toLowerCase()`) sends the create to a differently-cased path than the one planted — on a
        // case-sensitive filesystem `/tmp/jss-canary-read.d/..` and `/TMP/JSS-CANARY-READ.D/..` are
        // distinct directories, so the write misses the planted canary and the differential never fires.
        // Plant the canary (and the control) at every case variant of its path; whichever case the sink
        // emits then has a matching planted directory, and a case-preserving sink still lands in the
        // original. On a case-insensitive filesystem the variants collapse to one, so this is inert
        // there. The control is planted in the same variants and must stay empty in all of them.
        let dirs = path_case_variants(&oracle.dir);
        let controls = path_case_variants(&oracle.control);
        // The create runs as the app process, which may be a dropped non-root user; make the planted
        // directories writable so a genuine traversal is not masked by a permission error.
        let all = dirs.iter().chain(controls.iter());
        let quoted = all
            .map(|path| format!("'{path}'"))
            .collect::<Vec<_>>()
            .join(" ");
        let plant = format!("rm -rf {quoted} && mkdir -p {quoted} && chmod 777 {quoted}");
        let _ = self.exec(&self.app, &["sh", "-c", &plant]);
        // Every planted directory must exist and be empty before the request, or the differential
        // proves nothing.
        if dirs
            .iter()
            .chain(controls.iter())
            .any(|p| !self.dir_empty(p))
        {
            return None;
        }
        // Stop at the exact request that creates the entry so the exported PoC independently
        // reproduces the observed effect. Different sinks need different shapes: `mkdir` commonly
        // needs the fresh leaf, while an upload move may populate the existing directory itself.
        let mut witness = None;
        for attempt in &oracle.present {
            let attempt = self.with_credential(attempt, credential);
            let _ = self.fetch(&attempt);
            let sink_hit = self.last_sink_hit.get();
            let created = dirs.iter().any(|p| !self.dir_empty(p))
                && controls.iter().all(|p| self.dir_empty(p));
            if self.accept_bound_effect_with_hit(created, sink_hit) {
                witness = Some(attempt);
                break;
            }
        }
        let cleanup = format!("rm -rf {quoted}");
        let _ = self.exec(&self.app, &["sh", "-c", &cleanup]);
        let witness = witness?;
        Some(Reproduction {
            command: self.poc_command(&witness),
            command_redacted: false,
            method: witness.verb.to_owned(),
            target: witness.target.clone(),
            headers: witness
                .headers
                .iter()
                .map(|(name, value)| format!("{name}: {value}"))
                .collect(),
            body: witness.body.clone(),
            evidence:
                "an empty directory planted outside the application's base directory received a new \
                entry created by the traversal request while a sibling control directory planted \
                alongside it stayed empty, proving the create opened the attacker-controlled path \
                outside the base directory"
                    .to_owned(),
            response: String::new(),
            stdout: None,
            stderr: None,
            exit_code: None,
            output_safety: None,
            controls: Vec::new(),
        })
    }

    /// Confirms an archive-entry traversal by uploading a one-file ZIP whose entry climbs into an
    /// empty canary directory outside the extraction base. The sibling control directory stays
    /// empty, so a hit proves the archive entry name controlled the write path rather than merely
    /// exercising the upload endpoint.
    pub(super) fn verify_archive_create_oracle(
        &self,
        probe: &Probe,
        credential: Option<&SessionCred>,
    ) -> Option<Reproduction> {
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
        let request = self.with_credential(
            &Attempt {
                verb,
                target: target.clone(),
                body: None,
                headers: vec![(
                    "Content-Type".to_owned(),
                    format!("multipart/form-data; boundary={boundary}"),
                )],
                signal: Signal::FileWritten(format!("{dir}/jss-zip-leaf")),
            },
            credential,
        );
        let spec = binary_request_spec(
            self.port,
            verb,
            &target,
            &request.headers,
            &multipart,
            self.tls,
        );
        let marker_before = self.begin_sink_observation();
        let output = self
            .exec(&self.app, &["node", "/jss-driver.js", &spec])
            .ok()?;
        self.finish_sink_observation(marker_before);
        let sink_hit = self.last_sink_hit.get();
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
        if !self.accept_bound_effect_with_hit(reproduced, sink_hit) {
            return None;
        }
        let archive_b64 = base64(&archive);
        // The binary driver needs our explicit boundary for the exact request it sends. The
        // copyable curl PoC must let curl choose the boundary generated by `--form`; retaining the
        // controller boundary would advertise bytes that curl never emits. Preserve only auth and
        // other application headers in the exported request.
        let poc_request = Attempt {
            headers: request
                .headers
                .iter()
                .filter(|(name, _)| !name.eq_ignore_ascii_case("content-type"))
                .cloned()
                .collect(),
            ..request.clone()
        };
        let command = format!(
            "printf %s {} | base64 -d > /tmp/jsspector.zip\n{} \\\n  --form {}",
            shell_quote(&archive_b64),
            curl_command(&poc_request, self.port,),
            shell_quote("file=@/tmp/jsspector.zip;filename=jsspector.zip;type=application/zip")
        );
        Some(Reproduction {
            command,
            command_redacted: false,
            method: verb.to_owned(),
            target,
            headers: poc_request
                .headers
                .iter()
                .map(|(name, value)| format!("{name}: {value}"))
                .collect(),
            body: None,
            evidence: "a ZIP entry containing traversal segments created a canary file outside the extraction directory while a sibling control directory stayed empty"
                .to_owned(),
            response: response_excerpt(&response),
            stdout: None,
            stderr: None,
            exit_code: None,
            output_safety: None,
            controls: Vec::new(),
        })
    }

    /// Whether a path exists, is a directory, and holds no entries inside the running app container.
    /// Used by the create oracle to observe, out of band from the HTTP response, that a planted
    /// directory went from empty to holding an entry created by a traversal request.
    pub(super) fn dir_empty(&self, path: &str) -> bool {
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
    pub(super) fn verify_overwrite_oracle(
        &self,
        probe: &Probe,
        credential: Option<&SessionCred>,
    ) -> Option<Reproduction> {
        let oracle = payload::overwrite_oracle(probe, &self.canary, self.nonce)?;
        let document = base64(oracle.planted.as_bytes());
        for attempt in &oracle.present {
            let attempt = self.with_credential(attempt, credential);
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
            let _ = self.fetch(&attempt);
            let sink_hit = self.last_sink_hit.get();
            // The target must have been rewritten (content changed) and the control left untouched: the
            // write was directed by the attacker-controlled path, not an indiscriminate rewrite.
            let changed = self
                .file_contents(&oracle.target_path)
                .is_some_and(|after| after != oracle.planted);
            let control_intact = self.file_contents(&oracle.control_path).as_deref()
                == Some(oracle.planted.as_str());
            if self.accept_bound_effect_with_hit(changed && control_intact, sink_hit) {
                let _ = self.exec(
                    &self.app,
                    &["sh", "-c", &format!("rm -rf '{}'", oracle.dir)],
                );
                return Some(Reproduction {
                    command: self.poc_command(&attempt),
                    command_redacted: false,
                    method: attempt.verb.to_owned(),
                    target: attempt.target.clone(),
                    headers: attempt
                        .headers
                        .iter()
                        .map(|(name, value)| format!("{name}: {value}"))
                        .collect(),
                    body: attempt.body.clone(),
                    evidence:
                        "a canary file planted outside the application's base directory with known \
                        content was overwritten by the traversal request while a sibling control file \
                        planted alongside it kept its content, proving the write opened the \
                        attacker-controlled path outside the base directory"
                            .to_owned(),
                    response: String::new(),
                    stdout: None,
                    stderr: None,
                    exit_code: None,
                    output_safety: None,
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
    pub(super) fn file_contents(&self, path: &str) -> Option<String> {
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
    pub(super) fn verify_proto_pollution(
        &self,
        probe: &Probe,
        credential: Option<&SessionCred>,
    ) -> Option<Reproduction> {
        // The finding's entry may carry a mount prefix the isolated verifier drops (it mounts the
        // handler's own router at the root). Try the full path and each router-relative variant; a
        // wrong base only 404s identically for every request, so it cannot fabricate a reproduction.
        for base in payload::proto_base_candidates(&probe.path) {
            if let Some(poc) = self.try_proto_pollution(probe, &base, credential) {
                return Some(poc);
            }
        }
        None
    }

    /// Run the read-back prototype-pollution differential for one candidate route base.
    pub(super) fn try_proto_pollution(
        &self,
        probe: &Probe,
        base: &str,
        credential: Option<&SessionCred>,
    ) -> Option<Reproduction> {
        let oracle = payload::proto_pollution_oracle(probe, &self.canary, self.nonce, base)?;
        let baseline_attempt = self.with_credential(&oracle.baseline, credential);
        let pollute_attempt = self.with_credential(&oracle.pollute, credential);
        let probe_attempt = self.with_credential(&oracle.probe, credential);
        let control_attempt = self.with_credential(&oracle.control, credential);
        let baseline = self.fetch(&baseline_attempt)?;
        let _ = self.fetch(&pollute_attempt);
        let pollute_hit = self.last_sink_hit.get();
        let after = self.fetch(&probe_attempt)?;
        let control = self.fetch(&control_attempt)?;
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
        let reproduced = !a.is_empty() && a != b && a != c && b == c;
        if !self.accept_bound_effect_with_hit(reproduced, pollute_hit) {
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
                self.poc_command(&pollute_attempt).replacen(
                    "curl -i -sS",
                    "curl -i -sS --max-time 2",
                    1,
                ),
                self.poc_command(&probe_attempt),
            ),
            command_redacted: false,
            method: probe_attempt.verb.to_owned(),
            target: probe_attempt.target.clone(),
            headers: probe_attempt
                .headers
                .iter()
                .map(|(name, value)| format!("{name}: {value}"))
                .collect(),
            body: probe_attempt.body.clone(),
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
            stdout: None,
            stderr: None,
            exit_code: None,
            output_safety: None,
            controls: Vec::new(),
        })
    }

    /// Whether a path exists inside the running app container. Used by the removal oracle to observe,
    /// out of band from the HTTP response, that a planted file was deleted by a traversal request.
    pub(super) fn file_exists(&self, path: &str) -> bool {
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
    pub(super) fn plant_suffix_canary(&self, suffix: &str) {
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
    /// one) holding a single token-named directory inside the running app container, so a directory-
    /// listing traversal that climbs to it enumerates an entry name carrying the token. A directory
    /// is used because some listing handlers deliberately return only child directories. `subdir` is
    /// already
    /// validated filesystem-safe by the planner; the token is alphanumeric. The write stays inside the
    /// isolated container, and the proof is the token name surfacing, nothing weaker.
    pub(super) fn plant_listing_canary(&self, subdir: &str, nonce: u32) {
        let base = self.canary.planted_dir();
        let dir = if subdir.is_empty() {
            base
        } else {
            format!("{base}/{subdir}")
        };
        let entry = format!("{dir}/{}", self.canary.listing_token(nonce));
        let script = format!("mkdir -p '{entry}'");
        let _ = self.exec(&self.app, &["sh", "-c", &script]);
    }

    /// Confirms a table-identifier SQL injection by a response differential: the tainted identifier is
    /// replaced with a sub-select that the database must evaluate, returning a value it can only produce
    /// by concatenating two string literals (absent from the request text). A plain-identifier control
    /// request is sent too. The injection is proved only when the computed value surfaces in the
    /// injecting response but not the control's — a bound parameter can never introduce a computed
    /// column, so this is a genuine change to the statement's meaning, not mere taint reachability.
    pub(super) fn exercise_sql(&self, probe: &Probe, credential: Option<&SessionCred>) -> Outcome {
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
            return match self.verify_sql_destructive_oracle(probe, credential) {
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
                return self.exercise_sql_value(probe, credential);
            }
            return Outcome::Skipped {
                reason:
                    "the tainted value is not interpolated in a SQL table-identifier position that \
                    verify v1 drives"
                        .to_owned(),
            };
        };
        let positive_attempt = self.with_credential(&case.positive, credential);
        let negative_attempt = self.with_credential(&case.negative, credential);
        let Some(positive) = self.fetch(&positive_attempt) else {
            return Outcome::NotReproduced { tried: 2 };
        };
        let positive_hit = self.last_sink_hit.get();
        let Some(negative) = self.fetch(&negative_attempt) else {
            return Outcome::NotReproduced { tried: 2 };
        };
        let reproduced = positive.contains(&case.computed) && !negative.contains(&case.computed);
        if self.accept_bound_effect_with_hit(reproduced, positive_hit) {
            let attempt = &positive_attempt;
            return Outcome::Verified {
                how: format!("{} {}", attempt.verb, attempt.target),
                poc: Reproduction {
                    command: self.poc_command(attempt),
                    command_redacted: false,
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
                    stdout: None,
                    stderr: None,
                    exit_code: None,
                    output_safety: None,
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
            let truthy_attempt = self.with_credential(&blind.truthy, credential);
            let falsy_a_attempt = self.with_credential(&blind.falsy_a, credential);
            let falsy_b_attempt = self.with_credential(&blind.falsy_b, credential);
            if let Some(truthy) = self.fetch(&truthy_attempt) {
                let truthy_hit = self.last_sink_hit.get();
                if let (Some(falsy_a), Some(falsy_b)) =
                    (self.fetch(&falsy_a_attempt), self.fetch(&falsy_b_attempt))
                {
                    let reproduced =
                        payload::sql_blind_reproduced(&truthy, &falsy_a, &falsy_b, &blind.volatile);
                    if self.accept_bound_effect_with_hit(reproduced, truthy_hit) {
                        let attempt = &truthy_attempt;
                        return Outcome::Verified {
                    how: format!("{} {}", attempt.verb, attempt.target),
                    poc: Reproduction {
                        command: self.poc_command(attempt),
                        command_redacted: false,
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
                        stdout: None,
                        stderr: None,
                        exit_code: None,
                        output_safety: None,
                        controls: vec![
                            control_observation(
                                "non-matching fabricated row A",
                                &falsy_a_attempt,
                                &falsy_a,
                            ),
                            control_observation(
                                "non-matching fabricated row B",
                                &falsy_b_attempt,
                                &falsy_b,
                            ),
                        ],
                    },
                };
                    }
                }
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
    pub(super) fn exercise_sql_value(
        &self,
        probe: &Probe,
        credential: Option<&SessionCred>,
    ) -> Outcome {
        // Each boolean-differential case is tried as sent (JSON body for a body source) and, for a
        // body source, also as its form-urlencoded twin: an Express app that mounts only
        // `express.urlencoded` before the route never parses a JSON body, so the tainted value would
        // never reach the sink in JSON form. The twin carries the same fields as a form submission so
        // such a form-only route is still reached; a route with a JSON parser ignores the extra legs.
        let cases: Vec<payload::SqlValueCase> = payload::sql_value_cases(probe, &self.canary)
            .into_iter()
            .flat_map(|case| {
                let twin = payload::sql_value_case_twin(&case);
                std::iter::once(case).chain(twin)
            })
            .collect();
        let tried = cases.len() * 3;
        for case in &cases {
            let truthy_attempt = self.with_credential(&case.truthy, credential);
            let falsy_a_attempt = self.with_credential(&case.falsy_a, credential);
            let falsy_b_attempt = self.with_credential(&case.falsy_b, credential);
            let Some(truthy) = self.fetch(&truthy_attempt) else {
                continue;
            };
            let truthy_hit = self.last_sink_hit.get();
            let (Some(falsy_a), Some(falsy_b)) =
                (self.fetch(&falsy_a_attempt), self.fetch(&falsy_b_attempt))
            else {
                continue;
            };
            let reproduced = payload::sql_blind_reproduced(&truthy, &falsy_a, &falsy_b, &[]);
            if self.accept_bound_effect_with_hit(reproduced, truthy_hit) {
                let attempt = &truthy_attempt;
                return Outcome::Verified {
                    how: format!("{} {}", attempt.verb, attempt.target),
                    poc: Reproduction {
                        command: self.poc_command(attempt),
                        command_redacted: false,
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
                        stdout: None,
                        stderr: None,
                        exit_code: None,
                        output_safety: None,
                        controls: vec![
                            control_observation(
                                "always-false boolean 1=2",
                                &falsy_a_attempt,
                                &falsy_a,
                            ),
                            control_observation(
                                "always-false boolean 1=3",
                                &falsy_b_attempt,
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
    pub(super) fn verify_sql_destructive_oracle(
        &self,
        probe: &Probe,
        credential: Option<&SessionCred>,
    ) -> Option<Reproduction> {
        let oracle = payload::sql_delete_oracle(probe, &self.canary, self.nonce)?;
        let benign = self.with_credential(&oracle.benign, credential);
        let breakout = self.with_credential(&oracle.breakout, credential);
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
        let _ = self.fetch(&benign);
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
        let _ = self.fetch(&breakout);
        let breakout_hit = self.last_sink_hit.get();
        let (t2, s2) = (
            self.count_table_rows(&files, &oracle.table)?,
            self.count_table_rows(&files, &oracle.sibling)?,
        );
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            eprintln!(
                "[verify] SQL delete oracle rows before={t0}/{s0} control={t1}/{s1} exploit={t2}/{s2}"
            );
        }
        if self.accept_bound_effect_with_hit(t2 < t1 && s2 == s1, breakout_hit) {
            let attempt = &breakout;
            return Some(Reproduction {
                command: self.poc_command(attempt),
                command_redacted: false,
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
                stdout: None,
                stderr: None,
                exit_code: None,
                output_safety: None,
                controls: Vec::new(),
            });
        }
        None
    }

    /// SQLite database files owned by the isolated application. Docker's `/tmp` belongs to the
    /// sandbox; local mode instead searches only the app tree and generated directory-valued
    /// fixtures, never the host's shared temporary root.
    pub(super) fn discover_sqlite_files(&self) -> Vec<String> {
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
    pub(super) fn count_table_rows(&self, files: &[String], name: &str) -> Option<i64> {
        let out = self.run_node(&count_rows_js(files, name))?;
        out.lines()
            .rev()
            .find_map(|line| line.trim().parse::<i64>().ok())
    }

    /// Runs a Node script (with `node:sqlite` enabled) inside the app container, passing it through a
    /// base64 temp file so no shell escaping can corrupt it, mirroring how the image's helper scripts
    /// are planted. `NODE_OPTIONS` is set to exactly the sqlite flag so a launch-time require shim is
    /// not inherited. Returns the script's stdout.
    pub(super) fn run_node(&self, js: &str) -> Option<String> {
        let b64 = base64(js.as_bytes());
        let script = format!(
            "f=$(mktemp) && echo {b64} | base64 -d > \"$f\" && \
             NODE_OPTIONS=--experimental-sqlite node \"$f\"; rc=$?; rm -f \"$f\"; exit $rc"
        );
        let output = self.exec(&self.app, &["sh", "-c", &script]).ok()?;
        Some(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    pub(super) fn exercise_nosql(
        &self,
        probe: &Probe,
        credential: Option<&SessionCred>,
    ) -> Outcome {
        let cases: Vec<payload::NosqlCase> = payload::nosql_cases(probe, &self.canary, self.nonce)
            .into_iter()
            .map(|mut case| {
                case.match_all = self.with_credential(&case.match_all, credential);
                case.match_none_eq = self.with_credential(&case.match_none_eq, credential);
                case.match_none_in = self.with_credential(&case.match_none_in, credential);
                case
            })
            .collect();
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
            let Some((match_all, match_all_status, match_all_cookies)) =
                self.fetch_meta(&case.match_all)
            else {
                continue;
            };
            let match_all_hit = self.last_sink_hit.get();
            let (
                Some((match_none_eq, match_none_eq_status, match_none_eq_cookies)),
                Some((match_none_in, match_none_in_status, match_none_in_cookies)),
            ) = (
                self.fetch_meta(&case.match_none_eq),
                self.fetch_meta(&case.match_none_in),
            )
            else {
                continue;
            };
            let reproduced = nosql_response_proves_impact(
                &probe.path,
                (&match_all, match_all_status, &match_all_cookies),
                (&match_none_eq, match_none_eq_status, &match_none_eq_cookies),
                (&match_none_in, match_none_in_status, &match_none_in_cookies),
                &case.absent,
            );
            if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
                eprintln!(
                    "[verify] nosql differential field={} match-all-status={match_all_status:?} match-all-cookies={match_all_cookies:?} match-none-eq-status={match_none_eq_status:?} match-none-eq-cookies={match_none_eq_cookies:?} match-none-in-status={match_none_in_status:?} match-none-in-cookies={match_none_in_cookies:?} reproduced={reproduced}",
                    case.field,
                );
            }
            if self.accept_bound_effect_with_hit(reproduced, match_all_hit) {
                let attempt = &case.match_all;
                let command = include_response_headers(self.poc_command(attempt));
                let operator_siblings: Vec<&str> = probe
                    .siblings
                    .iter()
                    .filter_map(|(name, value)| {
                        (value == payload::NOSQL_OPERATOR_PLACEHOLDER).then_some(name.as_str())
                    })
                    .collect();
                let mut evidence = nosql_differential_evidence(
                    &case.field,
                    &operator_siblings,
                    probe.body_query_override.is_some(),
                );
                if authentication_endpoint(&probe.path) {
                    evidence.push_str(
                        "; the match-all response issued an authentication credential that neither match-none control received",
                    );
                }
                return Outcome::Verified {
                    how: format!("{} {} ({}[$ne])", attempt.verb, attempt.target, case.field),
                    poc: Reproduction {
                        command,
                        command_redacted: false,
                        method: attempt.verb.to_owned(),
                        target: attempt.target.clone(),
                        headers: attempt
                            .headers
                            .iter()
                            .map(|(name, value)| format!("{name}: {value}"))
                            .collect(),
                        body: attempt.body.clone(),
                        evidence,
                        response: response_excerpt(&match_all),
                        stdout: None,
                        stderr: None,
                        exit_code: None,
                        output_safety: None,
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
    pub(super) fn nosql_inserted_document_differential(
        &self,
        cases: &[payload::NosqlCase],
    ) -> Option<Outcome> {
        for case in cases {
            let [all_id, eq_id, in_id] = case.identity.as_slice() else {
                continue;
            };
            let _ = self.fetch(&case.match_all);
            let match_all_hit = self.last_sink_hit.get();
            let all = self.nosql_identity_document_digest(all_id, &case.identity)?;
            let _ = self.fetch(&case.match_none_eq);
            let eq = self.nosql_identity_document_digest(eq_id, &case.identity)?;
            let _ = self.fetch(&case.match_none_in);
            let in_empty = self.nosql_identity_document_digest(in_id, &case.identity)?;
            let reproduced =
                !all.trim().is_empty() && !eq.trim().is_empty() && eq == in_empty && all != eq;
            if !self.accept_bound_effect_with_hit(reproduced, match_all_hit) {
                continue;
            }
            let attempt = &case.match_all;
            return Some(Outcome::Verified {
                how: format!(
                    "{} {} ({}[$ne], inserted-document differential)",
                    attempt.verb, attempt.target, case.field
                ),
                poc: Reproduction {
                    command: self.poc_command(attempt),
                    command_redacted: false,
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
                    stdout: None,
                    stderr: None,
                    exit_code: None,
                    output_safety: None,
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
    pub(super) fn nosql_identity_document_digest(
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
            .exec(db, &[self.mongo_shell(), "--quiet", "--eval", &script])
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
    pub(super) fn nosql_state_differential(&self, cases: &[payload::NosqlCase]) -> Option<Outcome> {
        for case in cases {
            let exclude = &case.identity;
            let before_all = self.nosql_state_digest(exclude)?;
            let _ = self.fetch(&case.match_all);
            let match_all_hit = self.last_sink_hit.get();
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
            if !self.accept_bound_effect_with_hit(true, match_all_hit) {
                continue;
            }
            let attempt = &case.match_all;
            return Some(Outcome::Verified {
                how: format!(
                    "{} {} ({}[$ne], database-state differential)",
                    attempt.verb, attempt.target, case.field
                ),
                poc: Reproduction {
                    command: self.poc_command(attempt),
                    command_redacted: false,
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
                    stdout: None,
                    stderr: None,
                    exit_code: None,
                    output_safety: None,
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
    pub(super) fn nosql_state_digest(&self, exclude: &[String]) -> Option<String> {
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
            .exec(db, &[self.mongo_shell(), "--quiet", "--eval", &script])
            .ok()?;
        if !output.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

type HttpObservation<'a> = (&'a str, Option<u16>, &'a [String]);

/// A response differential proves an exploitable read only when the positive request completed
/// successfully. A 5xx/4xx split can be manufactured by a schema-incomplete document planted in
/// the disposable database: the operator selects it, then unrelated downstream code crashes while
/// reading a required field. That proves operator semantics, not confidentiality, integrity or
/// authentication impact.
///
/// Login-like endpoints are stricter still. A 2xx body difference is not an authentication bypass;
/// the operator leg must actually receive a bearer token or session cookie that neither match-none
/// control receives.
fn nosql_response_proves_impact(
    path: &str,
    match_all: HttpObservation<'_>,
    match_none_eq: HttpObservation<'_>,
    match_none_in: HttpObservation<'_>,
    absent: &str,
) -> bool {
    if !payload::nosql_reproduced(match_all.0, match_none_eq.0, match_none_in.0, absent) {
        return false;
    }
    let authentication = authentication_endpoint(path);
    // Successful form logins commonly answer with a 302 and set their session cookie on that
    // redirect. Treat that as success only for an authentication endpoint and only when the
    // credential oracle below confirms a newly issued session; ordinary read differentials remain
    // restricted to 2xx responses.
    let completed = match_all.1.is_some_and(|status| {
        (200..300).contains(&status) || (authentication && (300..400).contains(&status))
    });
    if !completed {
        return false;
    }
    if !authentication {
        return true;
    }
    issued_session(match_all.0, match_all.2)
        && !issued_session(match_none_eq.0, match_none_eq.2)
        && !issued_session(match_none_in.0, match_none_in.2)
}

fn authentication_endpoint(path: &str) -> bool {
    path.split(['?', '#'])
        .next()
        .unwrap_or(path)
        .split('/')
        .any(|segment| {
            matches!(
                segment.to_ascii_lowercase().as_str(),
                "login" | "log-in" | "signin" | "sign-in" | "authenticate"
            )
        })
}

fn issued_session(body: &str, cookies: &[String]) -> bool {
    payload::extract_bearer_token(body).is_some() || payload::session_cookie_pair(cookies).is_some()
}

fn include_response_headers(command: String) -> String {
    if command.contains(" --include") {
        command
    } else {
        command.replacen("curl -sS", "curl -sS --include", 1)
    }
}

/// The distinct case variants of a filesystem path a case-normalizing sink might write to: the path as
/// given, fully upper-cased, and fully lower-cased, de-duplicated (an all-lowercase path yields two, an
/// already-mixed one up to three). A sink that applies `.toUpperCase()` / `.toLowerCase()` to the
/// attacker's path sends the operation to the variant it produces, so planting every variant keeps the
/// canary reachable whatever the transform; on a case-insensitive filesystem the variants name the same
/// directory, leaving the single-planted behaviour unchanged.
fn path_case_variants(path: &str) -> Vec<String> {
    let mut variants = vec![path.to_owned()];
    for candidate in [path.to_ascii_uppercase(), path.to_ascii_lowercase()] {
        if !variants.contains(&candidate) {
            variants.push(candidate);
        }
    }
    variants
}

#[cfg(test)]
mod oracle_tests {
    use super::{include_response_headers, nosql_response_proves_impact, path_case_variants};

    const NO_COOKIES: &[String] = &[];

    #[test]
    fn nosql_crash_differential_is_not_security_impact() {
        assert!(!nosql_response_proves_impact(
            "/api/auth/login",
            (
                r#"{"message":"Server error during login"}"#,
                Some(500),
                NO_COOKIES
            ),
            (
                r#"{"message":"Invalid credentials"}"#,
                Some(400),
                NO_COOKIES
            ),
            (
                r#"{"message":"Invalid credentials"}"#,
                Some(400),
                NO_COOKIES
            ),
            "18ebdf4eae3bee68012fb800",
        ));
    }

    #[test]
    fn nosql_login_differential_requires_an_issued_session() {
        let controls = (
            r#"{"message":"Invalid credentials"}"#,
            Some(401),
            NO_COOKIES,
        );
        assert!(!nosql_response_proves_impact(
            "/api/auth/login",
            (
                r#"{"message":"different but unauthenticated"}"#,
                Some(200),
                NO_COOKIES
            ),
            controls,
            controls,
            "absent",
        ));

        let authenticated = r#"{"token":"eyJhbGci.eyJzdWIiOiIxIn0.c2ln"}"#;
        assert!(nosql_response_proves_impact(
            "/api/auth/login",
            (authenticated, Some(200), NO_COOKIES),
            controls,
            controls,
            "absent",
        ));

        let redirect_cookie = ["uid=6b62d; Path=/; HttpOnly".to_owned()];
        assert!(nosql_response_proves_impact(
            "/user/login",
            ("Found. Redirecting to /", Some(302), &redirect_cookie),
            controls,
            controls,
            "absent",
        ));
        assert!(!nosql_response_proves_impact(
            "/user/login",
            ("Found. Redirecting to /", Some(302), NO_COOKIES),
            controls,
            controls,
            "absent",
        ));
    }

    #[test]
    fn nosql_read_differential_needs_a_successful_positive_response() {
        let controls = (r#"{"items":[]}"#, Some(200), NO_COOKIES);
        assert!(nosql_response_proves_impact(
            "/api/users/search",
            (r#"{"items":[{"id":1}]}"#, Some(200), NO_COOKIES),
            controls,
            controls,
            "absent",
        ));
        assert!(!nosql_response_proves_impact(
            "/api/users/search",
            (r#"{"error":"query crashed"}"#, Some(500), NO_COOKIES),
            controls,
            controls,
            "absent",
        ));
    }

    #[test]
    fn nosql_report_command_includes_response_headers_once() {
        let command = include_response_headers("curl -sS --request POST /login".to_owned());
        assert_eq!(command.matches("--include").count(), 1);
        assert_eq!(include_response_headers(command.clone()), command);
    }

    #[test]
    fn case_variants_cover_a_normalizing_sink_without_duplicates() {
        // A lowercase canary path (the planted default) must also offer the fully upper-cased path a
        // `.toUpperCase()` sink writes to — and nothing else, so the planting stays minimal.
        let lower = "/tmp/jss-canary-read.d/jss-mk-18ea66-1/jss-mk-leaf";
        let variants = path_case_variants(lower);
        assert!(variants.contains(&lower.to_owned()));
        assert!(
            variants.contains(&"/TMP/JSS-CANARY-READ.D/JSS-MK-18EA66-1/JSS-MK-LEAF".to_owned())
        );
        assert_eq!(variants.len(), 2);

        // A mixed-case path yields the original plus both pure-case forms, de-duplicated.
        let mixed = path_case_variants("/Tmp/Canary");
        assert_eq!(mixed.len(), 3);

        // An all-caps path collapses with its own upper-cased form, leaving two.
        let upper = path_case_variants("/TMP/CANARY");
        assert_eq!(upper.len(), 2);
    }
}

//! Finding the commands that may start an MCP server which speaks only stdio.
//!
//! A stdio MCP server binds no port: whatever uses it (an editor, `npx`) starts it as a child process
//! and talks over its pipes. The verifier drives a server over HTTP, so it runs the HTTP-to-stdio
//! bridge ([`super::sandbox`]'s `mcp_bridge.js`) in the app's place, and the bridge starts the
//! server. What it needs from here is commands to try.
//!
//! Nothing here has to be right. The bridge shakes hands with each candidate in turn and keeps the
//! first that answers `initialize`, so this only has to make the right command likely, put it early,
//! and stay bounded. The sources are the package's own files: `bin` and `main`, a `start`-style
//! script that is a plain `node <file>`, the sub-commands its CLI defines (a `bin` that dispatches
//! to `server start` or `mcp:serve` prints its usage and exits when run bare), and the source files
//! that construct the stdio transport, mapped to the output the compiler writes.

use std::path::Path;

use serde_json::Value;

/// One command line: the program and its arguments, run from the package directory.
pub type Command = Vec<String>;

/// The most candidates handed to the bridge, so a package with a wide CLI cannot make a launch that
/// finds nothing spend minutes confirming it.
const MAX_CANDIDATES: usize = 16;

/// Script names that commonly start a server, likeliest first.
const SCRIPTS: [&str; 7] = [
    "start:mcp",
    "mcp",
    "mcp:start",
    "serve",
    "start",
    "start:stdio",
    "dev:mcp",
];

/// The sub-command words that mean "start the MCP server" (a CLI's `mcp`, `serve`, `mcp:serve`).
const STRONG: [&str; 4] = ["mcp", "mcp:serve", "mcp-server", "stdio"];
/// Words that start something when combined with a server word (`server start`).
const SERVER: [&str; 3] = ["server", "serve", "mcp"];
const START: [&str; 3] = ["start", "run", "serve"];

/// The commands that may start the stdio MCP server of the package at `app_root`, likeliest first.
/// `entry` is the finding's own file (relative to `app_root`), used to prefer the transport module
/// it belongs to.
pub fn candidates(app_root: &Path, entry: Option<&Path>) -> Vec<Command> {
    let manifest: Value = std::fs::read_to_string(app_root.join("package.json"))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or(Value::Null);
    let mut out: Vec<Command> = Vec::new();
    let mut add = |command: Command| {
        if !command.is_empty() && !out.contains(&command) {
            out.push(command);
        }
    };

    let bins = bin_files(&manifest);
    let words = cli_words(app_root);

    // A bin that is the server itself (most single-purpose servers): run it bare.
    for file in &bins {
        add(node(file));
    }
    if let Some(main) = manifest.get("main").and_then(Value::as_str)
        && is_script_file(main)
    {
        add(node(main));
    }
    // A `start`-style script that is nothing but `node <file> [literal args]`.
    for name in SCRIPTS {
        if let Some(script) = manifest
            .get("scripts")
            .and_then(|scripts| scripts.get(name))
            .and_then(Value::as_str)
            && let Some(command) = plain_node_script(script)
        {
            add(command);
        }
    }
    // A bin that dispatches sub-commands: the ones the CLI defines for starting a server.
    for file in &bins {
        for tail in subcommand_tails(&words) {
            let mut command = node(file);
            command.extend(tail);
            add(command);
        }
    }
    // The module that constructs the stdio transport, run as the output the compiler writes for it.
    for source in transport_modules(app_root, entry) {
        for built in built_paths(app_root, &source) {
            add(node(&built));
        }
    }
    out.truncate(MAX_CANDIDATES);
    out
}

/// The exec-form launch command (a JSON array, as `CMD` and the local launcher take it) that runs
/// the bridge over `candidates`.
pub fn bridge_command(candidates: &[Command]) -> String {
    let spec = serde_json::json!({ "candidates": candidates, "startupMs": 20000 }).to_string();
    serde_json::to_string(&["node", "/jss-mcp-bridge.js", spec.as_str()])
        .unwrap_or_else(|_| "[]".to_owned())
}

fn node(file: &str) -> Command {
    vec!["node".to_owned(), file.trim_start_matches("./").to_owned()]
}

fn is_script_file(path: &str) -> bool {
    [".js", ".mjs", ".cjs"]
        .iter()
        .any(|extension| path.ends_with(extension))
}

/// The files `bin` names (a string, or a name-to-file map), as relative paths.
fn bin_files(manifest: &Value) -> Vec<String> {
    let files: Vec<&str> = match manifest.get("bin") {
        Some(Value::String(file)) => vec![file.as_str()],
        Some(Value::Object(map)) => map.values().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    let mut out: Vec<String> = Vec::new();
    for file in files {
        let file = file.trim_start_matches("./");
        if is_script_file(file) && !file.contains("..") && !out.iter().any(|seen| seen == file) {
            out.push(file.to_owned());
        }
    }
    out
}

/// `node <file> [literal args]` when `script` is nothing more; shell syntax is not a command here.
fn plain_node_script(script: &str) -> Option<Command> {
    let mut words = script.split_whitespace();
    if words.next()? != "node" {
        return None;
    }
    let file = words.next()?;
    if !is_script_file(file) || file.contains("..") || file.starts_with('/') {
        return None;
    }
    let mut command = node(file);
    for word in words {
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
        command.push(word.to_owned());
    }
    Some(command)
}

/// Source files under the package, excluding dependencies, build output and tests.
fn source_files(app_root: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![app_root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.is_dir() {
                let skip = matches!(
                    name.as_str(),
                    "node_modules" | "dist" | "build" | "out" | ".git" | "coverage" | "__tests__"
                ) || name.starts_with('.');
                if !skip && out.len() < 4000 {
                    stack.push(path);
                }
            } else if [".ts", ".mts", ".cts", ".js", ".mjs", ".cjs"]
                .iter()
                .any(|extension| name.ends_with(extension))
                && !name.ends_with(".d.ts")
                && !name.contains(".test.")
                && !name.contains(".spec.")
                && std::fs::metadata(&path).is_ok_and(|meta| meta.len() < 400_000)
            {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// The sub-command names the package's CLI defines: the string literal of each `.command('name')`
/// (commander), `command: 'name'` (yargs object form), and `case 'name'` of a dispatcher whose
/// name looks like it starts a server. Only words that could start one are kept.
fn cli_words(app_root: &Path) -> Vec<String> {
    let mut words: Vec<String> = Vec::new();
    for file in source_files(app_root) {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        // `.command('x')` and `command: 'x'` define a sub-command; so does a group made with
        // `new Command('x')` (commander) and a dispatcher's `case 'x'`.
        for marker in [".command(", "new Command(", "command:", "case "] {
            let mut rest = text.as_str();
            while let Some(at) = rest.find(marker) {
                rest = &rest[at + marker.len()..];
                let Some(word) = leading_literal(rest) else {
                    continue;
                };
                // `command("server <name>")` defines `server`; arguments follow the first word.
                let word = word.split_whitespace().next().unwrap_or("").to_owned();
                let interesting = STRONG.contains(&word.as_str())
                    || SERVER.contains(&word.as_str())
                    || START.contains(&word.as_str())
                    || word.starts_with("mcp");
                if interesting && !words.contains(&word) {
                    words.push(word);
                }
            }
        }
    }
    words
}

/// The string literal at the start of `text` (after spaces, an optional `[` or `(`), unquoted.
fn leading_literal(text: &str) -> Option<String> {
    let trimmed = text.trim_start_matches([' ', '\t', '\n', '\r', '(', '[']);
    let quote = trimmed
        .chars()
        .next()
        .filter(|c| matches!(c, '\'' | '"' | '`'))?;
    let inner = &trimmed[1..];
    let end = inner.find(quote)?;
    let literal = &inner[..end];
    (!literal.is_empty() && literal.len() <= 40 && !literal.contains('\n'))
        .then(|| literal.to_owned())
}

/// The argument tails to try after a bin: a strong word alone (`mcp`, `mcp:serve`), a strong word
/// with `--stdio`, and a server word followed by a start word (`server start`), in that order.
fn subcommand_tails(words: &[String]) -> Vec<Vec<String>> {
    let has = |word: &str| words.iter().any(|seen| seen == word);
    let mut out: Vec<Vec<String>> = Vec::new();
    for strong in STRONG.iter().chain(&["mcp"]) {
        if has(strong) && *strong != "stdio" {
            out.push(vec![(*strong).to_owned()]);
            out.push(vec![(*strong).to_owned(), "--stdio".to_owned()]);
        }
    }
    for server in SERVER {
        for start in START {
            if server != start && has(server) && has(start) {
                out.push(vec![server.to_owned(), start.to_owned()]);
            }
        }
    }
    for single in ["serve", "server", "start"] {
        if has(single) {
            out.push(vec![single.to_owned()]);
        }
    }
    if has("stdio") {
        out.push(vec!["--stdio".to_owned()]);
    }
    let mut seen: Vec<Vec<String>> = Vec::new();
    out.retain(|tail| {
        let fresh = !seen.contains(tail);
        seen.push(tail.clone());
        fresh
    });
    out
}

/// Source files that construct the stdio transport, the finding's own module's package first.
fn transport_modules(app_root: &Path, entry: Option<&Path>) -> Vec<String> {
    let mut modules: Vec<String> = Vec::new();
    for file in source_files(app_root) {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        // A module that builds the transport *and* runs at load time starts a server when executed;
        // one that only exports a starter does nothing when run, which the handshake would reveal,
        // so it is tried only after those that call it.
        if text.contains("new StdioServerTransport(")
            && let Ok(relative) = file.strip_prefix(app_root)
        {
            modules.push(relative.to_string_lossy().into_owned());
        }
    }
    let entry = entry.map(|path| path.to_string_lossy().into_owned());
    modules.sort_by_key(|module| {
        let near = entry.as_ref().is_some_and(|entry| {
            Path::new(entry)
                .parent()
                .is_some_and(|dir| Path::new(module).starts_with(dir))
        });
        (!near, module.clone())
    });
    modules.truncate(4);
    modules
}

/// Where the compiler writes the output for a TypeScript `source` (`src/x.ts` -> `dist/x.js`),
/// from the package's `tsconfig.json`; the source itself when it is already JavaScript.
fn built_paths(app_root: &Path, source: &str) -> Vec<String> {
    if is_script_file(source) {
        return vec![source.to_owned()];
    }
    let tsconfig = std::fs::read_to_string(app_root.join("tsconfig.json")).unwrap_or_default();
    let value = |key: &str| {
        let after = tsconfig.split(&format!("\"{key}\"")).nth(1)?;
        let literal = leading_literal(after.trim_start().strip_prefix(':')?)?;
        Some(
            literal
                .trim_start_matches("./")
                .trim_end_matches('/')
                .to_owned(),
        )
    };
    let out_dir = value("outDir").unwrap_or_else(|| "dist".to_owned());
    let root_dir = value("rootDir").unwrap_or_else(|| "src".to_owned());
    let stem = source
        .rsplit_once('.')
        .map_or(source, |(stem, _)| stem)
        .to_owned();
    let below_root = stem
        .strip_prefix(&format!("{root_dir}/"))
        .map(str::to_owned)
        .unwrap_or_else(|| stem.clone());
    let mut out = vec![format!("{out_dir}/{below_root}.js")];
    // A module compiled to ES modules may carry the `.mjs` extension.
    if source.ends_with(".mts") {
        out = vec![format!("{out_dir}/{below_root}.mjs")];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (relative, text) in files {
            let path = dir.path().join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        dir
    }

    fn strings(command: &[&str]) -> Command {
        command.iter().map(|word| (*word).to_owned()).collect()
    }

    #[test]
    fn a_single_purpose_server_is_its_own_bin_run_bare() {
        let dir = package(&[(
            "package.json",
            r#"{"name":"mcp-server-notes","bin":{"mcp-server-notes":"./dist/index.js"},"scripts":{"build":"tsc"}}"#,
        )]);
        assert_eq!(
            candidates(dir.path(), None).first(),
            Some(&strings(&["node", "dist/index.js"]))
        );
    }

    #[test]
    fn a_cli_that_dispatches_sub_commands_is_tried_with_the_ones_that_start_a_server() {
        let dir = package(&[
            (
                "package.json",
                r#"{"bin":{"tasks-adapter":"./dist/cli/index.js"},"main":"dist/index.js"}"#,
            ),
            (
                "src/cli/commands/server.ts",
                "const cmd = new Command(\"server\").description(\"Server management\");\n\
                 cmd.command(\"start\").description(\"Start the MCP server (stdio)\");\n",
            ),
            (
                "src/cli/program.ts",
                "program.command(\"ask\"); program.command(\"auth\");",
            ),
        ]);
        let found = candidates(dir.path(), None);
        // The bare bin first (it may be the server), then the sub-command that starts one.
        assert_eq!(found[0], strings(&["node", "dist/cli/index.js"]));
        assert!(
            found.contains(&strings(&["node", "dist/cli/index.js", "server", "start"])),
            "{found:?}"
        );
        // Commands that start nothing (`ask`, `auth`) are never offered.
        assert!(
            found
                .iter()
                .all(|command| !command.contains(&"ask".to_owned()))
        );
    }

    #[test]
    fn an_mcp_serve_command_is_tried_alone_and_with_the_stdio_flag() {
        let dir = package(&[
            ("package.json", r#"{"bin":{"tool":"dist/cli.js"}}"#),
            (
                "src/cli.ts",
                "switch (command) {\n  case \"mcp:serve\":\n    return handleMcpServe();\n}\n",
            ),
        ]);
        let found = candidates(dir.path(), None);
        assert!(
            found.contains(&strings(&["node", "dist/cli.js", "mcp:serve"])),
            "{found:?}"
        );
        assert!(
            found.contains(&strings(&["node", "dist/cli.js", "mcp:serve", "--stdio"])),
            "{found:?}"
        );
    }

    #[test]
    fn a_plain_node_start_script_is_a_candidate_and_shell_syntax_is_not() {
        let dir = package(&[(
            "package.json",
            r#"{"scripts":{"start":"node build/server.js --stdio","serve":"NODE_ENV=production node a.js && echo x"}}"#,
        )]);
        let found = candidates(dir.path(), None);
        assert_eq!(
            found,
            vec![strings(&["node", "build/server.js", "--stdio"])]
        );
    }

    #[test]
    fn the_module_that_builds_the_transport_is_run_as_the_compiler_writes_it() {
        let dir = package(&[
            ("package.json", r#"{"name":"x"}"#),
            (
                "tsconfig.json",
                "{\n // build\n \"compilerOptions\": { \"outDir\": \"./build\", \"rootDir\": \"./src\" }\n}\n",
            ),
            (
                "src/index.ts",
                "const transport = new StdioServerTransport();\nawait server.connect(transport);\n",
            ),
            ("src/util.ts", "export const x = 1;\n"),
        ]);
        assert_eq!(
            candidates(dir.path(), None),
            vec![strings(&["node", "build/index.js"])]
        );
    }

    #[test]
    fn the_module_nearest_the_finding_comes_first_and_the_list_is_bounded() {
        let mut files: Vec<(String, String)> = (0..30)
            .map(|n| {
                (
                    format!("src/m{n}/server.js"),
                    "new StdioServerTransport();".to_owned(),
                )
            })
            .collect();
        files.push(("package.json".to_owned(), "{}".to_owned()));
        let refs: Vec<(&str, &str)> = files
            .iter()
            .map(|(path, text)| (path.as_str(), text.as_str()))
            .collect();
        let dir = package(&refs);
        let found = candidates(dir.path(), Some(Path::new("src/m17/tools.ts")));
        assert_eq!(
            found.first(),
            Some(&strings(&["node", "src/m17/server.js"]))
        );
        assert!(found.len() <= MAX_CANDIDATES);
    }

    #[test]
    fn nothing_is_offered_for_a_package_without_a_stdio_server() {
        let dir = package(&[
            (
                "package.json",
                r#"{"name":"web","scripts":{"start":"vite"}}"#,
            ),
            ("src/app.js", "export const x = 1;\n"),
        ]);
        assert!(candidates(dir.path(), None).is_empty());
    }

    #[test]
    fn the_bridge_command_is_an_exec_form_array_carrying_the_candidates() {
        let command = bridge_command(&[strings(&["node", "dist/index.js"])]);
        let parsed: Vec<String> = serde_json::from_str(&command).unwrap();
        assert_eq!(parsed[0], "node");
        assert_eq!(parsed[1], "/jss-mcp-bridge.js");
        let spec: Value = serde_json::from_str(&parsed[2]).unwrap();
        assert_eq!(spec["candidates"][0][1], "dist/index.js");
        assert_eq!(spec["startupMs"], 20000);
    }
}

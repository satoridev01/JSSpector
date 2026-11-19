//! Proven fixes kept as data, so later fixes come faster and some need no LLM at all.
//!
//! A **recipe** is one fix pattern: the vulnerability class, the sink's callee, what the change
//! introduced (`String`, `basename`, …), a short before/after taken from the first fix that proved
//! it, and counters. Recipes of the finding's class are shown to the LLM as fixes already proven
//! elsewhere; they are never applied by themselves.
//!
//! An **example** is one proven fix as a deterministic reproduction case: the finding's and the
//! original file's fingerprints, the repository and commit it was proven on, the exact change, the
//! request that reproduced the exploit (credentials redacted) and the status a benign request kept. When the same finding shows up again on the same file content, the
//! example's change is replayed — and proved again by the same three controls — without an LLM.
//!
//! The default store is the JSSpector checkout the binary was built from, and it publishes
//! itself: after a fix is proven and recorded, the new files are committed and pushed, so what one
//! run learned reaches the next without anyone doing anything.
//!
//! The store is a directory: `recipes/<class>/<id>.json` and `examples/<finding>-<file>.json`.
//! Reads take no lock (every write is a rename); each write takes `.lock` once, for one
//! read-modify-write, and calls nothing else that locks.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use fs2::FileExt;
use jss_core::Finding;
use jss_core::finding::fingerprint;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::fix::{Op, line_ops};

/// Recipes shown to the LLM per finding.
const OFFERED: usize = 3;
/// Lines and characters kept of each side of a recipe's before/after.
const SNIPPET_LINES: usize = 12;
const SNIPPET_CHARS: usize = 800;
/// Tokens kept of what a change introduced.
const INTRODUCED: usize = 8;

/// Recipes that ship with JSSpector: the fix patterns it used to apply by itself, now guidance only.
const SEEDS: &str = include_str!("fix-recipes.json");

/// One fix pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recipe {
    pub id: String,
    /// The vulnerability class (`nosql-injection`).
    pub class: String,
    /// The sink's callee (`findOne`), or empty for a pattern that applies to any sink of the class.
    pub sink: String,
    /// Calls, members and keywords the change introduced.
    #[serde(default)]
    pub introduces: Vec<String>,
    /// A sentence on the pattern (shipped recipes carry one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub before: String,
    pub after: String,
    /// Fixes proven with this pattern.
    #[serde(default)]
    pub proven: u32,
    /// Times this recipe was shown to the LLM.
    #[serde(default)]
    pub offered: u32,
    /// Of those, the times the LLM's first candidate was proven.
    #[serde(default)]
    pub first_try: u32,
}

/// One proven fix, replayable on the same finding and file content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Example {
    pub recipe: String,
    /// The finding's fingerprint.
    pub finding: String,
    pub file: String,
    /// The repository the fix was proven in (the scanned checkout's `origin`), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    /// The commit the fix was proven on, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    /// The fingerprint of the file content the change applies to.
    pub original_fingerprint: String,
    pub hunks: Vec<Hunk>,
    /// The request that reproduced the exploit before the change, without credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poc: Option<String>,
    /// The status a benign request got before and after the change.
    pub benign_status: u16,
}

/// One contiguous change: the lines at `line` (1-based) that must read `old`, replaced by `new`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hunk {
    pub line: usize,
    pub old: Vec<String>,
    pub new: Vec<String>,
}

/// What one fix search leaves for the store.
pub struct Learned<'a> {
    pub finding: &'a Finding,
    pub file: &'a str,
    pub original: &'a str,
    /// The scanned checkout's repository and commit, when known.
    pub repository: Option<&'a str>,
    pub revision: Option<&'a str>,
    /// The content an LLM candidate was proven with, when one was.
    pub proven: Option<&'a str>,
    pub poc: Option<&'a str>,
    pub benign_status: u16,
    /// The recipes shown to the LLM.
    pub offered: &'a [String],
    /// Whether the LLM's first candidate was the proven one.
    pub first_try: bool,
}

/// A recipe store.
pub struct Book {
    dir: PathBuf,
}

impl Book {
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
        }
    }

    /// The change proven before for this very finding on this very file content, applied.
    pub fn replay(&self, finding: &Finding, file: &str, original: &str) -> Option<String> {
        let example: Example = read_json(&self.example_path(finding, original))?;
        (example.file == file && example.original_fingerprint == fingerprint(original))
            .then(|| apply(original, &example.hunks))
            .flatten()
    }

    /// The recipes to show the LLM for `finding`: its class only, the same sink first, then the
    /// best first-try rate, then the most proven.
    pub fn lookup(&self, finding: &Finding) -> Vec<Recipe> {
        let class = finding.class.name();
        let sink = sink_callee(finding);
        let mut recipes: Vec<Recipe> = std::fs::read_dir(self.dir.join("recipes").join(class))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| read_json::<Recipe>(&entry.path()))
            .filter(|recipe| recipe.class == class)
            .collect();
        for seed in seeds() {
            if seed.class == class && !recipes.iter().any(|recipe| recipe.id == seed.id) {
                recipes.push(seed);
            }
        }
        recipes.sort_by(|a, b| {
            let same = |recipe: &Recipe| recipe.sink == sink;
            same(b)
                .cmp(&same(a))
                .then_with(|| rate(b).total_cmp(&rate(a)))
                .then_with(|| b.proven.cmp(&a.proven))
                .then_with(|| a.id.cmp(&b.id))
        });
        recipes.truncate(OFFERED);
        recipes
    }

    /// Records what a fix search learned: the offered recipes' counters, and for a fix an LLM
    /// candidate proved, its recipe (new or merged) and its example.
    pub fn record(&self, learned: &Learned) -> Result<(), String> {
        let class = learned.finding.class.name();
        let new = learned
            .proven
            .map(|proven| pattern(learned.finding, learned.original, proven));
        if learned.offered.is_empty() && new.is_none() {
            return Ok(());
        }
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| format!("creating {}: {e}", self.dir.display()))?;
        let lock = std::fs::File::create(self.dir.join(".lock"))
            .map_err(|e| format!("creating the recipe lock: {e}"))?;
        lock.lock_exclusive()
            .map_err(|e| format!("locking {}: {e}", self.dir.display()))?;
        for id in learned.offered {
            if let Some(mut recipe) = self.load(class, id) {
                recipe.offered += 1;
                if learned.first_try {
                    recipe.first_try += 1;
                }
                self.save_recipe(&recipe)?;
            }
        }
        if let (Some(proven), Some(found)) = (learned.proven, new) {
            let mut recipe = self.load(class, &found.id).unwrap_or(found);
            recipe.proven += 1;
            self.save_recipe(&recipe)?;
            let example = Example {
                recipe: recipe.id,
                finding: learned.finding.fingerprint.clone(),
                file: learned.file.to_owned(),
                repository: learned.repository.map(str::to_owned),
                revision: learned.revision.map(str::to_owned),
                original_fingerprint: fingerprint(learned.original),
                hunks: hunks(learned.original, proven),
                poc: learned.poc.map(redact),
                benign_status: learned.benign_status,
            };
            write_json(
                &self.example_path(learned.finding, learned.original),
                &example,
            )?;
        }
        Ok(())
    }

    /// Commits what a recorded fix added or changed, in the git checkout the store is in, and
    /// pushes it. A push the remote rejects is rebased once and retried, never forced.
    pub fn publish(&self) -> Result<String, String> {
        let lock = std::fs::File::create(self.dir.join(".lock"))
            .map_err(|e| format!("creating the recipe lock: {e}"))?;
        lock.lock_exclusive()
            .map_err(|e| format!("locking {}: {e}", self.dir.display()))?;
        let git = |args: &[&str]| -> Result<std::process::Output, String> {
            std::process::Command::new("git")
                .arg("-C")
                .arg(&self.dir)
                .args(args)
                .env("GIT_TERMINAL_PROMPT", "0")
                .stdin(std::process::Stdio::null())
                .output()
                .map_err(|e| format!("running git: {e}"))
        };
        let run = |args: &[&str]| -> Result<(), String> {
            let output = git(args)?;
            if output.status.success() {
                Ok(())
            } else {
                Err(format!(
                    "git {}: {}",
                    args.first().unwrap_or(&""),
                    String::from_utf8_lossy(&output.stderr).trim()
                ))
            }
        };
        run(&["add", "--", "recipes", "examples"])?;
        if git(&["diff", "--cached", "--quiet", "--", "recipes", "examples"])?
            .status
            .success()
        {
            return Ok("nothing new to publish".to_owned());
        }
        run(&[
            "commit",
            "-q",
            "-m",
            "Record proven fixes",
            "--",
            "recipes",
            "examples",
        ])?;
        if run(&["push", "-q"]).is_err() {
            if let Err(error) = run(&["pull", "--rebase", "--autostash", "-q"]) {
                let _ = run(&["rebase", "--abort"]);
                return Err(format!("the remote moved and the rebase failed: {error}"));
            }
            run(&["push", "-q"])?;
        }
        Ok("committed and pushed".to_owned())
    }

    fn load(&self, class: &str, id: &str) -> Option<Recipe> {
        read_json(&self.recipe_path(class, id))
            .or_else(|| seeds().into_iter().find(|seed| seed.id == id))
    }

    fn save_recipe(&self, recipe: &Recipe) -> Result<(), String> {
        write_json(&self.recipe_path(&recipe.class, &recipe.id), recipe)
    }

    fn recipe_path(&self, class: &str, id: &str) -> PathBuf {
        self.dir
            .join("recipes")
            .join(file_name(class))
            .join(format!("{}.json", file_name(id)))
    }

    fn example_path(&self, finding: &Finding, original: &str) -> PathBuf {
        self.dir.join("examples").join(format!(
            "{}-{}.json",
            file_name(&finding.fingerprint),
            fingerprint(original)
        ))
    }
}

/// The recipes JSSpector ships.
fn seeds() -> Vec<Recipe> {
    serde_json::from_str(SEEDS).unwrap_or_default()
}

/// The first-try rate, smoothed so an untried recipe ranks between a good and a bad one.
fn rate(recipe: &Recipe) -> f64 {
    (f64::from(recipe.first_try) + 1.0) / (f64::from(recipe.offered) + 2.0)
}

/// The sink's callee: `findOne` for `User.findOne`.
pub fn sink_callee(finding: &Finding) -> String {
    finding
        .sink
        .api
        .trim_end_matches(" =")
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned()
}

/// The recipe a proven change belongs to. Two fixes that introduce the same calls at the same
/// kind of sink are one pattern.
fn pattern(finding: &Finding, original: &str, proven: &str) -> Recipe {
    let ops = line_ops(original, proven);
    let removed: Vec<&str> = ops
        .iter()
        .filter(|(op, _)| *op == Op::Removed)
        .map(|(_, line)| *line)
        .collect();
    let added: Vec<&str> = ops
        .iter()
        .filter(|(op, _)| *op == Op::Added)
        .map(|(_, line)| *line)
        .collect();
    let class = finding.class.name();
    let sink = sink_callee(finding);
    let introduces = introduced(&removed, &added);
    let shape = if introduces.is_empty() {
        added
            .iter()
            .flat_map(|line| line.split_whitespace())
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        introduces.join(",")
    };
    Recipe {
        id: fingerprint(&format!("{class}|{sink}|{shape}")),
        class: class.to_owned(),
        sink,
        introduces,
        note: None,
        before: snippet(&removed),
        after: snippet(&added),
        proven: 0,
        offered: 0,
        first_try: 0,
    }
}

/// Calls, member accesses and guard keywords in `added` that `removed` did not have, leaving out
/// names the change itself declares.
fn introduced(removed: &[&str], added: &[&str]) -> Vec<String> {
    const KEYWORDS: [&str; 5] = ["typeof", "instanceof", "throw", "return", "new"];
    // Followed by `(` without being calls.
    const CONTROL: [&str; 6] = ["if", "for", "while", "switch", "catch", "function"];
    let had: BTreeSet<String> = removed
        .iter()
        .flat_map(|line| identifiers(line))
        .map(|(name, _, _)| name)
        .collect();
    let mut declared: BTreeSet<String> = BTreeSet::new();
    let mut found: BTreeSet<String> = BTreeSet::new();
    for line in added {
        let mut previous: Option<String> = None;
        for (name, before, after) in identifiers(line) {
            if matches!(
                previous.as_deref(),
                Some("const" | "let" | "var" | "function")
            ) {
                declared.insert(name.clone());
            }
            let api = (after == Some('(') || before == Some('.') || KEYWORDS.contains(&&*name))
                && !CONTROL.contains(&&*name);
            if api && !had.contains(&name) {
                found.insert(name.clone());
            }
            previous = Some(name);
        }
    }
    found
        .into_iter()
        .filter(|name| !declared.contains(name))
        .take(INTRODUCED)
        .collect()
}

/// The identifiers in `line`, each with the nearest non-space characters before and after it.
fn identifiers(line: &str) -> Vec<(String, Option<char>, Option<char>)> {
    let chars: Vec<char> = line.chars().collect();
    let mut out = Vec::new();
    let mut index = 0;
    while let Some(&c) = chars.get(index) {
        if c.is_alphabetic() || c == '_' || c == '$' {
            let start = index;
            while chars
                .get(index)
                .is_some_and(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
            {
                index += 1;
            }
            let name: String = chars.get(start..index).unwrap_or_default().iter().collect();
            let before = chars
                .get(..start)
                .unwrap_or_default()
                .iter()
                .rev()
                .find(|c| !c.is_whitespace())
                .copied();
            let after = chars
                .get(index..)
                .unwrap_or_default()
                .iter()
                .find(|c| !c.is_whitespace())
                .copied();
            out.push((name, before, after));
        } else if c.is_numeric() {
            while chars.get(index).is_some_and(|c| c.is_alphanumeric()) {
                index += 1;
            }
        } else {
            index += 1;
        }
    }
    out
}

/// Lines for a recipe's before/after: whole-line comments dropped, common indentation removed,
/// capped.
fn snippet(lines: &[&str]) -> String {
    let kept: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|line| {
            let line = line.trim_start();
            !(line.is_empty() || line.starts_with("//") || line.starts_with("/*"))
                && !line.starts_with('*')
        })
        .take(SNIPPET_LINES)
        .collect();
    let indent = kept
        .iter()
        .map(|line| line.len() - line.trim_start().len())
        .min()
        .unwrap_or(0);
    let text = kept
        .iter()
        .map(|line| line.get(indent..).unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n");
    match text.char_indices().nth(SNIPPET_CHARS) {
        Some((cut, _)) => format!("{}…", text.get(..cut).unwrap_or_default()),
        None => text,
    }
}

/// The change from `original` to `changed` as hunks.
pub fn hunks(original: &str, changed: &str) -> Vec<Hunk> {
    let mut out: Vec<Hunk> = Vec::new();
    let mut line = 1;
    let mut open = false;
    for (op, text) in line_ops(original, changed) {
        match op {
            Op::Same => {
                open = false;
                line += 1;
            }
            Op::Removed | Op::Added => {
                if !open {
                    out.push(Hunk {
                        line,
                        old: Vec::new(),
                        new: Vec::new(),
                    });
                    open = true;
                }
                if let Some(hunk) = out.last_mut() {
                    if op == Op::Removed {
                        hunk.old.push(text.to_owned());
                    } else {
                        hunk.new.push(text.to_owned());
                    }
                }
                if op == Op::Removed {
                    line += 1;
                }
            }
        }
    }
    out
}

/// `original` with `hunks` applied, or `None` when a hunk's old lines are not where it says.
pub fn apply(original: &str, hunks: &[Hunk]) -> Option<String> {
    let mut lines: Vec<String> = original.lines().map(str::to_owned).collect();
    // Apply from the bottom up, so the line numbers of the hunks above stay valid.
    let mut ordered: Vec<&Hunk> = hunks.iter().collect();
    ordered.sort_by_key(|hunk| std::cmp::Reverse(hunk.line));
    for hunk in ordered {
        let start = hunk.line.checked_sub(1)?;
        let end = start.checked_add(hunk.old.len())?;
        if lines.get(start..end)? != hunk.old.as_slice() {
            return None;
        }
        lines.splice(start..end, hunk.new.iter().cloned());
    }
    let newline = if original.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut out = lines.join(newline);
    if original.ends_with('\n') {
        out.push_str(newline);
    }
    Some(out)
}

/// A store path component: anything but ASCII letters, digits, `-` and `_` becomes `_`.
fn file_name(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Option<T> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

/// Writes `value` to `path` through a temporary file and a rename, so a reader never sees half.
/// Headers whose values are credentials.
const CREDENTIAL_HEADERS: [&str; 9] = [
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-access-token",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "x-session-token",
];
/// What a redacted value reads.
const REDACTED: &str = "REDACTED";

/// `poc` without credentials: the values of credential headers and anything shaped like a JWT. A
/// store may be shared or committed, and a PoC carries the test user's session.
fn redact(poc: &str) -> String {
    poc.split_inclusive('\n')
        .map(|line| redact_jwts(&redact_header(line)))
        .collect()
}

/// A `--header 'Name: value'` line with the value redacted when `Name` is a credential header.
fn redact_header(line: &str) -> String {
    const FLAG: &str = "--header '";
    let Some(start) = line.find(FLAG).map(|at| at + FLAG.len()) else {
        return line.to_owned();
    };
    let (Some(head), Some(rest)) = (line.get(..start), line.get(start..)) else {
        return line.to_owned();
    };
    let Some((name, _)) = rest.split_once(':') else {
        return line.to_owned();
    };
    let credential = CREDENTIAL_HEADERS
        .iter()
        .any(|header| name.trim().eq_ignore_ascii_case(header));
    match rest.rfind('\'').and_then(|end| rest.get(end..)) {
        Some(tail) if credential => format!("{head}{name}: {REDACTED}{tail}"),
        _ => line.to_owned(),
    }
}

/// `text` with every JWT (`eyJ….….…`) replaced.
fn redact_jwts(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("eyJ") {
        let (before, candidate) = rest.split_at(at);
        out.push_str(before);
        let (kept, length) = match jwt_length(candidate) {
            Some(length) => (REDACTED, length),
            None => ("eyJ", 3),
        };
        out.push_str(kept);
        rest = candidate.get(length..).unwrap_or_default();
    }
    out.push_str(rest);
    out
}

/// The length of the JWT `text` starts with: three dot-separated base64url segments, the first two
/// non-empty (the signature is empty for `alg: none`).
fn jwt_length(text: &str) -> Option<usize> {
    let segment = |from: usize| {
        let tail = text.get(from..).unwrap_or_default();
        tail.find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
            .unwrap_or(tail.len())
    };
    let mut end = segment(0);
    for required in [true, false] {
        if text.get(end..=end) != Some(".") {
            return None;
        }
        let length = segment(end + 1);
        if required && length == 0 {
            return None;
        }
        end += 1 + length;
    }
    Some(end)
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent", path.display()))?;
    std::fs::create_dir_all(parent).map_err(|e| format!("creating {}: {e}", parent.display()))?;
    let text = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("recipe"),
        std::process::id()
    ));
    std::fs::write(&temporary, format!("{text}\n"))
        .map_err(|e| format!("writing {}: {e}", temporary.display()))?;
    std::fs::rename(&temporary, path).map_err(|e| format!("writing {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jss_core::{Auth, Severity, SinkLoc, SourceLoc, VulnClass};

    fn finding(class: VulnClass, api: &str, fingerprint: &str) -> Finding {
        Finding {
            file: "routes/auth.js".to_owned(),
            sink: SinkLoc {
                file: None,
                api: api.to_owned(),
                arg: "x".to_owned(),
                line: 4,
                col: 1,
            },
            class,
            severity: Severity::High,
            confidence: "heuristic",
            auth: Auth::NoneDetected,
            function: "f".to_owned(),
            entry: None,
            entry_at: None,
            source: SourceLoc {
                kind: "http",
                expr: "req.body".to_owned(),
                line: 3,
                col: 1,
            },
            stored_by: None,
            trace: Vec::new(),
            key: "k".to_owned(),
            fingerprint: fingerprint.to_owned(),
        }
    }

    const LOGIN: &str = "const { User } = require('../db');\n\
router.post('/login', async (req, res) => {\n\
    const { username, password } = req.body;\n\
    const user = await User.findOne({ username, password });\n\
    res.json(user);\n\
});\n";

    fn coerced() -> String {
        LOGIN.replace(
            "User.findOne({ username, password })",
            "User.findOne({ username: String(username), password: String(password) })",
        )
    }

    #[test]
    fn hunks_reapply_to_the_same_content_exactly() {
        let changed = coerced();
        let found = hunks(LOGIN, &changed);
        assert_eq!(found.len(), 1);
        assert_eq!(found.first().map(|hunk| hunk.line), Some(4));
        assert_eq!(apply(LOGIN, &found).as_deref(), Some(changed.as_str()));

        // Insertions, deletions, several hunks and CRLF line ends round-trip too.
        let original = "a\r\nb\r\nc\r\nd\r\ne\r\n";
        let changed = "a\r\nguard\r\nb\r\nd\r\nE\r\n";
        assert_eq!(
            apply(original, &hunks(original, changed)).as_deref(),
            Some(changed)
        );
        // Without a final newline, none is added.
        assert_eq!(
            apply("x\ny", &hunks("x\ny", "x\nz")).as_deref(),
            Some("x\nz")
        );
    }

    #[test]
    fn a_hunk_applies_only_where_its_old_lines_are() {
        let found = hunks(LOGIN, &coerced());
        let edited = LOGIN.replace("res.json(user)", "res.json({ user })");
        // An edit elsewhere leaves the hunk's own lines in place.
        assert!(apply(&edited, &found).is_some());
        let moved = format!("// header\n{LOGIN}");
        assert_eq!(apply(&moved, &found), None);
    }

    #[test]
    fn a_pattern_is_what_the_change_introduced() {
        assert_eq!(
            introduced(
                &["const user = await User.findOne({ username, password });"],
                &[
                    "const user = await User.findOne({ username: String(username), password: String(password) });"
                ]
            ),
            ["String"]
        );
        assert_eq!(
            introduced(
                &["const filepath = path.join(FILES, name);"],
                &[
                    "const safe = path.basename(name);",
                    "const filepath = path.join(FILES, safe);"
                ]
            ),
            ["basename"]
        );
        assert_eq!(
            introduced(
                &["exec('ls ' + dir);"],
                &[
                    "if (typeof dir !== 'string') return res.status(400).end();",
                    "execFile('ls', [dir]);"
                ]
            ),
            ["end", "execFile", "return", "status", "typeof"]
        );
    }

    #[test]
    fn a_proven_fix_replays_only_on_the_same_finding_and_content() {
        let store = tempfile::tempdir().unwrap();
        let book = Book::new(store.path());
        let login = finding(VulnClass::NosqlInjection, "User.findOne", "aaaa");
        let changed = coerced();
        book.record(&Learned {
            finding: &login,
            file: "routes/auth.js",
            original: LOGIN,
            repository: None,
            revision: None,
            proven: Some(&changed),
            poc: Some("curl -X POST /login"),
            benign_status: 401,
            offered: &[],
            first_try: false,
        })
        .unwrap();

        assert_eq!(
            book.replay(&login, "routes/auth.js", LOGIN).as_deref(),
            Some(changed.as_str())
        );
        // Another finding, another file, or changed content: no replay.
        let other = finding(VulnClass::NosqlInjection, "User.findOne", "bbbb");
        assert_eq!(book.replay(&other, "routes/auth.js", LOGIN), None);
        assert_eq!(book.replay(&login, "routes/other.js", LOGIN), None);
        let edited = LOGIN.replace("res.json(user)", "res.json({ user })");
        assert_eq!(book.replay(&login, "routes/auth.js", &edited), None);

        // The fix became a recipe of its class, offered first for the same sink.
        let offered = book.lookup(&other);
        let first = offered.first().unwrap();
        assert_eq!(first.sink, "findOne");
        assert_eq!(first.introduces, ["String"]);
        assert_eq!(first.proven, 1);
        assert!(first.after.contains("String(username)"));
        assert!(offered.len() <= OFFERED);
        // No recipe of another class is offered.
        let traversal = finding(VulnClass::PathTraversal, "fs.readFile", "cccc");
        assert!(
            book.lookup(&traversal)
                .iter()
                .all(|recipe| recipe.class == "path-traversal")
        );
    }

    #[test]
    fn an_example_names_where_it_was_proven_and_keeps_no_credentials() {
        let store = tempfile::tempdir().unwrap();
        let book = Book::new(store.path());
        let login = finding(VulnClass::NosqlInjection, "User.findOne", "aaaa");
        let changed = coerced();
        let jwt = "eyJ0eXAiOiJKV1QifQ.eyJpZCI6MjZ9.c2lnbmF0dXJl";
        let poc = format!(
            "curl -i -sS \\\n  --url 'http://TARGET_HOST:3000/profile?token={jwt}' \\\n  \
             --header 'Cookie: token={jwt}; lang=en' \\\n  \
             --header 'authorization: Bearer opaque-secret' \\\n  \
             --header 'Content-Type: application/json' \\\n  \
             --data-raw '{{\"note\":\"eyJ is not a token\"}}'"
        );
        book.record(&Learned {
            finding: &login,
            file: "routes/auth.js",
            original: LOGIN,
            repository: Some("https://github.com/owner/app.git"),
            revision: Some("64c34c5"),
            proven: Some(&changed),
            poc: Some(&poc),
            benign_status: 401,
            offered: &[],
            first_try: false,
        })
        .unwrap();

        let example: Example = read_json(&book.example_path(&login, LOGIN)).unwrap();
        assert_eq!(
            example.repository.as_deref(),
            Some("https://github.com/owner/app.git")
        );
        assert_eq!(example.revision.as_deref(), Some("64c34c5"));
        let kept = example.poc.unwrap();
        assert!(
            !kept.contains(jwt) && !kept.contains("opaque-secret"),
            "{kept}"
        );
        assert!(kept.contains("--header 'Cookie: REDACTED' \\\n"), "{kept}");
        assert!(
            kept.contains("--header 'authorization: REDACTED'"),
            "{kept}"
        );
        assert!(kept.contains("profile?token=REDACTED'"), "{kept}");
        assert!(
            kept.contains("--header 'Content-Type: application/json'"),
            "{kept}"
        );
        assert!(kept.contains("eyJ is not a token"), "{kept}");
        // The redaction is stable: redacting again changes nothing.
        assert_eq!(redact(&kept), kept);
    }

    fn git(dir: &Path, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args([
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@localhost.invalid",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success(), "git {args:?}: {output:?}");
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    fn learn(book: &Book, fingerprint_: &str) {
        let login = finding(VulnClass::NosqlInjection, "User.findOne", fingerprint_);
        let changed = coerced();
        book.record(&Learned {
            finding: &login,
            file: "routes/auth.js",
            original: LOGIN,
            repository: None,
            revision: None,
            proven: Some(&changed),
            poc: None,
            benign_status: 401,
            offered: &[],
            first_try: false,
        })
        .unwrap();
    }

    #[test]
    fn a_store_that_is_a_git_checkout_publishes_what_it_learned() {
        let dir = tempfile::tempdir().unwrap();
        let remote = dir.path().join("remote.git");
        let clone = dir.path().join("clone");
        git(
            dir.path(),
            &[
                "init",
                "-q",
                "--bare",
                "-b",
                "main",
                remote.to_str().unwrap(),
            ],
        );
        git(
            dir.path(),
            &[
                "clone",
                "-q",
                remote.to_str().unwrap(),
                clone.to_str().unwrap(),
            ],
        );
        std::fs::write(clone.join("README"), "store\n").unwrap();
        git(&clone, &["add", "."]);
        git(&clone, &["commit", "-qm", "initial"]);
        git(&clone, &["push", "-q", "-u", "origin", "HEAD:main"]);

        let book = Book::new(&clone);
        learn(&book, "aaaa");
        assert_eq!(book.publish().unwrap(), "committed and pushed");
        assert_eq!(book.publish().unwrap(), "nothing new to publish");
        assert_eq!(
            git(&remote, &["log", "-1", "--format=%s", "main"]),
            "Record proven fixes"
        );
        assert!(git(&remote, &["ls-tree", "-r", "--name-only", "main"]).contains("examples/"));
        // The lock file never reaches the remote.
        assert!(!git(&remote, &["ls-tree", "-r", "--name-only", "main"]).contains(".lock"));

        // The remote moves on; the next publish rebases onto it and still pushes.
        let other = dir.path().join("other");
        git(
            dir.path(),
            &[
                "clone",
                "-q",
                remote.to_str().unwrap(),
                other.to_str().unwrap(),
            ],
        );
        std::fs::write(other.join("NOTES"), "more\n").unwrap();
        git(&other, &["add", "."]);
        git(&other, &["commit", "-qm", "elsewhere"]);
        git(&other, &["push", "-q"]);
        learn(&book, "bbbb");
        assert_eq!(book.publish().unwrap(), "committed and pushed");
        let files = git(&remote, &["ls-tree", "-r", "--name-only", "main"]);
        assert!(
            files.contains("NOTES") && files.matches("examples/").count() == 2,
            "{files}"
        );
    }

    #[test]
    fn offered_recipes_count_their_first_try_wins() {
        let store = tempfile::tempdir().unwrap();
        let book = Book::new(store.path());
        let login = finding(VulnClass::NosqlInjection, "User.findOne", "aaaa");
        let seed = book.lookup(&login).first().unwrap().id.clone();
        let changed = coerced();
        book.record(&Learned {
            finding: &login,
            file: "routes/auth.js",
            original: LOGIN,
            repository: None,
            revision: None,
            proven: Some(&changed),
            poc: None,
            benign_status: 401,
            offered: std::slice::from_ref(&seed),
            first_try: true,
        })
        .unwrap();
        book.record(&Learned {
            finding: &login,
            file: "routes/auth.js",
            original: LOGIN,
            repository: None,
            revision: None,
            proven: None,
            poc: None,
            benign_status: 401,
            offered: std::slice::from_ref(&seed),
            first_try: false,
        })
        .unwrap();
        let recipe = book.load("nosql-injection", &seed).unwrap();
        assert_eq!((recipe.offered, recipe.first_try), (2, 1));
    }

    #[test]
    fn shipped_recipes_parse_and_cover_their_classes() {
        let seeds = seeds();
        assert!(seeds.iter().any(|seed| seed.class == "nosql-injection"));
        assert!(seeds.iter().any(|seed| seed.class == "path-traversal"));
        assert!(seeds.iter().all(|seed| seed.note.is_some()));
        let ids: BTreeSet<&str> = seeds.iter().map(|seed| seed.id.as_str()).collect();
        assert_eq!(ids.len(), seeds.len());
    }
}

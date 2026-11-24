//! `.jsspector.yml`: per-project settings, read from the scan root (or `--config`).
//!
//! ```yaml
//! min_severity: high            # report findings at or above this severity
//! fail_on: high                 # exit 1 when a reported finding is at or above this
//! include: [tests]              # file classes to scan besides source
//! exclude: ["scripts/**", "*.min.js"]   # paths not to scan (globs, relative to the root)
//! baseline: .jsspector-baseline.json    # findings accepted earlier (see --write-baseline)
//! disable: [xss]                # vulnerability classes not to report
//! packs: [security/orm.yaml]    # extra packs, same schema as the built-in ones
//! auth:
//!   require: [mustBeLoggedIn]   # middleware or guards that require a login
//!   admin: [mustBeAdmin]        # ... or an admin
//! ```
//!
//! Command-line options win over the file; relative paths in the file are relative to it.

use std::path::{Path, PathBuf};

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use jss_core::{Severity, VulnClass};
use serde::Deserialize;

use crate::rules;

/// The file looked for in the scan root.
pub const FILE_NAME: &str = ".jsspector.yml";

/// The file, as written.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, alias = "min-severity")]
    pub min_severity: Option<String>,
    #[serde(default, alias = "fail-on")]
    pub fail_on: Option<String>,
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub baseline: Option<PathBuf>,
    #[serde(default)]
    pub disable: Vec<String>,
    #[serde(default)]
    pub packs: Vec<PathBuf>,
    #[serde(default)]
    pub auth: AuthConfig,
}

/// Project authentication conventions.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// Names (or parts of names) of middleware and guards that require a logged-in user.
    #[serde(default)]
    pub require: Vec<String>,
    /// ... that require an admin.
    #[serde(default)]
    pub admin: Vec<String>,
}

/// A config file and the directory its relative paths start from.
#[derive(Debug, Default)]
pub struct Loaded {
    /// The file read, if any.
    pub path: Option<PathBuf>,
    pub config: Config,
}

impl Loaded {
    /// Reads `explicit`, or else `.jsspector.yml` in the directory scanned (`target`, or the
    /// directory of a single file), unless `disabled`.
    pub fn load(target: &Path, explicit: Option<&Path>, disabled: bool) -> Result<Self, String> {
        let path = match explicit {
            Some(path) => path.to_path_buf(),
            None if disabled => return Ok(Self::default()),
            None => {
                let dir = if target.is_dir() {
                    target
                } else {
                    target.parent().unwrap_or(Path::new("."))
                };
                let candidate = dir.join(FILE_NAME);
                if !candidate.is_file() {
                    return Ok(Self::default());
                }
                candidate
            }
        };
        let text = std::fs::read_to_string(&path)
            .map_err(|err| format!("cannot read {}: {err}", path.display()))?;
        let config = if text.trim().is_empty() {
            Config::default()
        } else {
            serde_norway::from_str(&text).map_err(|err| format!("{}: {err}", path.display()))?
        };
        Ok(Self {
            path: Some(path),
            config,
        })
    }

    /// `relative` resolved against the config file's directory.
    pub fn resolve(&self, relative: &Path) -> PathBuf {
        match self.path.as_deref().and_then(Path::parent) {
            Some(dir) if relative.is_relative() => dir.join(relative),
            _ => relative.to_path_buf(),
        }
    }

    pub fn min_severity(&self) -> Result<Option<Severity>, String> {
        self.config
            .min_severity
            .as_deref()
            .map(|s| rules::parse_severity(s).map_err(|err| self.context(&err)))
            .transpose()
    }

    pub fn fail_on(&self) -> Result<Option<Severity>, String> {
        self.config
            .fail_on
            .as_deref()
            .map(|s| rules::parse_severity(s).map_err(|err| self.context(&err)))
            .transpose()
    }

    /// The classes in `disable`.
    pub fn disabled(&self) -> Result<Vec<VulnClass>, String> {
        self.config
            .disable
            .iter()
            .map(|name| {
                rules::by_name(name)
                    .map(|rule| rule.class)
                    .ok_or_else(|| self.context(&format!("unknown class `{name}` in disable")))
            })
            .collect()
    }

    /// The extra packs (name, YAML text): the files in `packs`, then a pack made of `auth`.
    pub fn packs(&self) -> Result<Vec<(String, String)>, String> {
        let mut packs = Vec::new();
        for file in &self.config.packs {
            let path = self.resolve(file);
            let text = std::fs::read_to_string(&path).map_err(|err| {
                self.context(&format!("cannot read pack {}: {err}", path.display()))
            })?;
            packs.push((path.display().to_string(), text));
        }
        let auth = &self.config.auth;
        if !auth.require.is_empty() || !auth.admin.is_empty() {
            // Names are matched lowercased, as parts of middleware names.
            let lower = |names: &[String]| -> Vec<String> {
                names.iter().map(|n| n.to_ascii_lowercase()).collect()
            };
            // JSON is YAML, and serde_json quotes every name safely.
            let pack = serde_json::json!({
                "name": FILE_NAME,
                "auth": { "middleware": lower(&auth.require), "admin": lower(&auth.admin) },
            });
            packs.push((format!("{FILE_NAME} auth"), pack.to_string()));
        }
        Ok(packs)
    }

    fn context(&self, message: &str) -> String {
        match &self.path {
            Some(path) => format!("{}: {message}", path.display()),
            None => message.to_owned(),
        }
    }
}

/// Paths excluded from a scan, from globs relative to the root. Like `.gitignore`: a pattern
/// without a `/` matches at any depth, and a pattern that names a directory excludes everything
/// in it. `*` stays inside one path segment; `**` crosses them.
#[derive(Debug)]
pub struct Excludes {
    set: GlobSet,
    empty: bool,
}

impl Excludes {
    pub fn new(patterns: &[String]) -> Result<Self, String> {
        let mut builder = GlobSetBuilder::new();
        for pattern in patterns {
            let trimmed = pattern.trim();
            let anchored = trimmed.starts_with('/');
            let mut base = trimmed
                .trim_start_matches("./")
                .trim_start_matches('/')
                .trim_end_matches('/')
                .to_owned();
            if base.is_empty() {
                continue;
            }
            if !anchored && !base.contains('/') {
                base = format!("**/{base}");
            }
            for glob in [base.clone(), format!("{base}/**")] {
                let glob = GlobBuilder::new(&glob)
                    .literal_separator(true)
                    .build()
                    .map_err(|err| format!("bad exclude pattern `{pattern}`: {err}"))?;
                builder.add(glob);
            }
        }
        let set = builder
            .build()
            .map_err(|err| format!("bad exclude patterns: {err}"))?;
        Ok(Self {
            empty: set.is_empty(),
            set,
        })
    }

    /// Whether `rel_path` (relative to the root) is excluded.
    pub fn matches(&self, rel_path: &str) -> bool {
        !self.empty && self.set.is_match(rel_path.replace('\\', "/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excludes_work_like_gitignore() {
        let ex = Excludes::new(&[
            "scripts/".to_owned(),
            "*.min.js".to_owned(),
            "/legacy".to_owned(),
            "src/**/fixtures/*.ts".to_owned(),
        ])
        .unwrap();
        assert!(ex.matches("scripts/build.js"));
        assert!(ex.matches("pkg/scripts/build.js"));
        assert!(ex.matches("public/app.min.js"));
        assert!(ex.matches("legacy/a/b.js"));
        assert!(!ex.matches("src/legacy/b.js"));
        assert!(ex.matches("src/a/b/fixtures/x.ts"));
        assert!(!ex.matches("src/a/b/fixtures/deep/x.ts"));
        assert!(!ex.matches("src/app.js"));
        assert!(!Excludes::new(&[]).unwrap().matches("a.js"));
    }

    #[test]
    fn a_config_file_is_read_and_checked() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(FILE_NAME),
            "min_severity: medium\nfail-on: high\ndisable: [xss]\nexclude: [vendor]\n\
             auth:\n  require: [mustBeLoggedIn]\n",
        )
        .unwrap();
        let loaded = Loaded::load(dir.path(), None, false).unwrap();
        assert_eq!(loaded.min_severity().unwrap(), Some(Severity::Medium));
        assert_eq!(loaded.fail_on().unwrap(), Some(Severity::High));
        assert_eq!(loaded.disabled().unwrap(), vec![VulnClass::Xss]);
        let packs = loaded.packs().unwrap();
        assert_eq!(packs.len(), 1);
        assert!(packs[0].1.contains("mustbeloggedin"), "{}", packs[0].1);
        assert!(Loaded::load(dir.path(), None, true).unwrap().path.is_none());

        std::fs::write(dir.path().join(FILE_NAME), "min_severity: urgent\n").unwrap();
        let loaded = Loaded::load(dir.path(), None, false).unwrap();
        assert!(loaded.min_severity().is_err());
        std::fs::write(dir.path().join(FILE_NAME), "severity: high\n").unwrap();
        assert!(Loaded::load(dir.path(), None, false).is_err());
    }
}

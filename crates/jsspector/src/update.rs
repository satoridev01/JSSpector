//! Updating a wheel-installed JSSpector with the Python interpreter that owns it.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

const PACKAGE: &str = "jsspector";
const VERSION_SCRIPT: &str = "from importlib.metadata import version; print(version('jsspector'))";

pub(crate) fn run() -> Result<(), String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("locate the running jsspector binary: {error}"))?;
    let candidates = python_candidates(&executable, std::env::var_os("JSSPECTOR_PYTHON"));
    let Some((python, before)) = candidates
        .into_iter()
        .find_map(|candidate| installed_version(&candidate).map(|version| (candidate, version)))
    else {
        return Err(
            "this binary is not owned by a Python environment containing the `jsspector` package; \
             install or update it with `python3 -m pip install --upgrade jsspector` (or set \
             JSSPECTOR_PYTHON to that environment's interpreter)"
                .to_owned(),
        );
    };

    eprintln!(
        "jsspector: checking PyPI from {} (installed {before}, running {})",
        python.display(),
        env!("CARGO_PKG_VERSION")
    );
    let status = Command::new(&python)
        .args([
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--upgrade",
            PACKAGE,
        ])
        .status()
        .map_err(|error| format!("start {} -m pip: {error}", python.display()))?;
    if !status.success() {
        return Err(format!("pip exited with {status}"));
    }

    let after = installed_version(&python).ok_or_else(|| {
        format!(
            "pip completed but {} can no longer find the `jsspector` package",
            python.display()
        )
    })?;
    if after == before {
        eprintln!("jsspector: {after} is already the newest available version");
    } else {
        eprintln!("jsspector: updated {before} -> {after}");
    }
    Ok(())
}

fn python_candidates(executable: &Path, override_python: Option<OsString>) -> Vec<PathBuf> {
    if let Some(override_python) = override_python.filter(|value| !value.is_empty()) {
        return vec![PathBuf::from(override_python)];
    }

    let mut candidates = Vec::new();
    if let Some(directory) = executable.parent() {
        push_unique(&mut candidates, directory.join("python3"));
        push_unique(&mut candidates, directory.join("python"));
    }
    push_unique(&mut candidates, PathBuf::from("python3"));
    push_unique(&mut candidates, PathBuf::from("python"));
    candidates
}

fn push_unique(candidates: &mut Vec<PathBuf>, candidate: PathBuf) {
    if !candidates.iter().any(|existing| existing == &candidate) {
        candidates.push(candidate);
    }
}

fn installed_version(python: &Path) -> Option<String> {
    let output = Command::new(python)
        .args(["-c", VERSION_SCRIPT])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let version = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (!version.is_empty()).then_some(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_python_is_the_only_candidate() {
        let candidates = python_candidates(
            Path::new("/environment/bin/jsspector"),
            Some(OsString::from("/chosen/python")),
        );
        assert_eq!(candidates, vec![PathBuf::from("/chosen/python")]);
    }

    #[test]
    fn environment_interpreters_come_before_path_fallbacks() {
        let candidates = python_candidates(Path::new("/environment/bin/jsspector"), None);
        assert_eq!(
            candidates,
            vec![
                PathBuf::from("/environment/bin/python3"),
                PathBuf::from("/environment/bin/python"),
                PathBuf::from("python3"),
                PathBuf::from("python"),
            ]
        );
    }
}

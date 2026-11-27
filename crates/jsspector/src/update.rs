//! Updating a wheel-installed JSSpector with the tool that owns it: `pipx upgrade` for a pipx
//! installation, otherwise pip run by the Python interpreter whose environment holds the package.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

const PACKAGE: &str = "jsspector";
const VERSION_SCRIPT: &str = "from importlib.metadata import version; print(version('jsspector'))";
/// Prints `1` when pip would refuse to install into this interpreter's environment (PEP 668): a
/// distribution-managed interpreter that is not running inside a virtual environment.
const EXTERNALLY_MANAGED_SCRIPT: &str = "import os, sys, sysconfig; \
print(int(sys.prefix == sys.base_prefix and \
os.path.isfile(os.path.join(sysconfig.get_path('stdlib'), 'EXTERNALLY-MANAGED'))))";
/// File pipx writes into every virtual environment it manages.
const PIPX_METADATA: &str = "pipx_metadata.json";

pub(crate) fn run() -> Result<(), String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("locate the running jsspector binary: {error}"))?;
    let executable = executable.canonicalize().unwrap_or(executable);
    if std::env::var_os("JSSPECTOR_PYTHON").is_none_or(|value| value.is_empty())
        && let Some(venv) = pipx_venv(&executable)
    {
        return pipx_upgrade(&venv);
    }

    let candidates = python_candidates(&executable, std::env::var_os("JSSPECTOR_PYTHON"));
    let Some((python, before)) = candidates
        .into_iter()
        .find_map(|candidate| installed_version(&candidate).map(|version| (candidate, version)))
    else {
        return Err(
            "this binary is not owned by a Python environment containing the `jsspector` package; \
             install or update it with `pipx install jsspector` (or `python3 -m pip install \
             --upgrade jsspector` inside a virtual environment), or set JSSPECTOR_PYTHON to the \
             interpreter of the environment that holds it"
                .to_owned(),
        );
    };

    if externally_managed(&python) {
        return Err(format!(
            "{} is managed by the operating system (PEP 668), so pip will not upgrade it; \
             reinstall JSSpector as an isolated CLI with `pipx install jsspector` and update it \
             from then on with `jsspector update`",
            python.display()
        ));
    }

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

/// The pipx-managed virtual environment that owns `executable`, if any: pipx installs the binary
/// at `<venv>/bin/jsspector` and marks `<venv>` with its metadata file.
fn pipx_venv(executable: &Path) -> Option<PathBuf> {
    let venv = executable.parent()?.parent()?;
    venv.join(PIPX_METADATA)
        .is_file()
        .then(|| venv.to_path_buf())
}

/// Upgrades through pipx so its own records stay in step with the installed version.
fn pipx_upgrade(venv: &Path) -> Result<(), String> {
    let python = venv.join("bin").join("python3");
    let before = installed_version(&python);
    eprintln!(
        "jsspector: upgrading the pipx installation in {} (installed {}, running {})",
        venv.display(),
        before.as_deref().unwrap_or("unknown"),
        env!("CARGO_PKG_VERSION")
    );
    let mut command = Command::new("pipx");
    command.args(["upgrade", PACKAGE]);
    // A pipx home outside the default must be named for pipx to find this installation.
    if let Some(home) = venv.parent().and_then(Path::parent) {
        command.env("PIPX_HOME", home);
    }
    let status = command.status().map_err(|error| {
        format!(
            "start pipx: {error}; this JSSpector was installed with pipx, so update it with \
             `pipx upgrade jsspector`"
        )
    })?;
    if !status.success() {
        return Err(format!("pipx exited with {status}"));
    }

    match (before, installed_version(&python)) {
        (Some(before), Some(after)) if before == after => {
            eprintln!("jsspector: {after} is already the newest available version");
        }
        (Some(before), Some(after)) => eprintln!("jsspector: updated {before} -> {after}"),
        _ => {}
    }
    Ok(())
}

fn externally_managed(python: &Path) -> bool {
    Command::new(python)
        .args(["-c", EXTERNALLY_MANAGED_SCRIPT])
        .output()
        .is_ok_and(|output| output.status.success() && output.stdout.trim_ascii() == b"1")
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
    fn pipx_venv_requires_pipx_metadata() {
        let root = std::env::temp_dir().join(format!("jsspector-update-{}", std::process::id()));
        let venv = root.join("venvs").join("jsspector");
        let bin = venv.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let executable = bin.join("jsspector");

        assert_eq!(pipx_venv(&executable), None);
        std::fs::write(venv.join(PIPX_METADATA), "{}").unwrap();
        assert_eq!(pipx_venv(&executable), Some(venv.clone()));

        std::fs::remove_dir_all(&root).unwrap();
    }

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

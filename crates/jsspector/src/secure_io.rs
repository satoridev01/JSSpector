//! Atomic writes for user-visible artifacts.
//!
//! Reports, baselines and learned recipes can be written inside an untrusted checkout. Writing a
//! named path directly would follow a repository-controlled symlink and could overwrite a file
//! outside that checkout. A temporary regular file in the destination directory followed by an
//! atomic rename replaces the directory entry itself instead.

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

/// Atomically replace `path` with the bytes emitted by `write`.
pub fn atomic_write(
    path: &Path,
    write: impl FnOnce(&mut File) -> io::Result<()>,
) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    write(temporary.as_file_mut())?;
    temporary.as_file_mut().flush()?;
    temporary
        .persist(path)
        .map(|_| ())
        .map_err(|error| error.error)
}

/// Atomically replace `path` with `bytes`.
pub fn write_bytes(path: &Path, bytes: &[u8]) -> io::Result<()> {
    atomic_write(path, |output| output.write_all(bytes))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[cfg(unix)]
    #[test]
    fn an_output_path_replaces_a_symlink_without_following_it() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let outside = directory.path().join("outside");
        let output = directory.path().join("report.json");
        std::fs::write(&outside, "keep").unwrap();
        symlink(&outside, &output).unwrap();

        write_bytes(&output, b"report").unwrap();

        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "keep");
        assert_eq!(std::fs::read_to_string(&output).unwrap(), "report");
        assert!(
            !std::fs::symlink_metadata(&output)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}

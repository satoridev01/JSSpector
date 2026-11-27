use std::fs;
use std::path::{Path, PathBuf};

fn main() -> std::io::Result<()> {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default());
    let workspace = manifest
        .parent()
        .and_then(Path::parent)
        .unwrap_or(&manifest);
    let store = workspace.join(".satori/fix-recipes");
    let recipes = store.join("recipes");
    println!("cargo:rerun-if-changed={}", recipes.display());

    let mut files = Vec::new();
    collect_json(&recipes, &mut files)?;
    files.sort();

    let mut generated = String::from("pub static EMBEDDED_FIX_FILES: &[(&str, &str)] = &[\n");
    for path in files {
        let relative = path
            .strip_prefix(&store)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        generated.push_str(&format!(
            "    ({relative:?}, include_str!({absolute:?})),\n",
            absolute = path.to_string_lossy()
        ));
    }
    generated.push_str("];\n");
    let output = PathBuf::from(std::env::var_os("OUT_DIR").unwrap_or_default())
        .join("embedded_fix_store.rs");
    fs::write(output, generated)
}

fn collect_json(directory: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let path = entry?.path();
        if path.is_dir() {
            collect_json(&path, files)?;
        } else if path.extension().and_then(|value| value.to_str()) == Some("json") {
            files.push(path);
        }
    }
    Ok(())
}

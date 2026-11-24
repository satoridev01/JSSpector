use std::fs;
use std::path::{Path, PathBuf};

fn main() -> std::io::Result<()> {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default());
    let store = manifest.join("../..").join(".satori").join("fix-recipes");
    println!("cargo:rerun-if-changed={}", store.display());

    let mut files = Vec::new();
    collect_json(&store.join("examples"), &store, &mut files);
    collect_json(&store.join("recipes"), &store, &mut files);
    files.sort();

    let mut generated = String::from("pub static EMBEDDED_FIX_FILES: &[(&str, &str)] = &[\n");
    for relative in files {
        let relative = relative.to_string_lossy().replace('\\', "/");
        generated.push_str(&format!(
            "    ({relative:?}, include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/../../.satori/fix-recipes/{relative}\"))),\n"
        ));
    }
    generated.push_str("];\n");

    let output = PathBuf::from(std::env::var_os("OUT_DIR").unwrap_or_default())
        .join("embedded_fix_store.rs");
    fs::write(output, generated)
}

fn collect_json(directory: &Path, root: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_json(&path, root, files);
        } else if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            println!("cargo:rerun-if-changed={}", path.display());
            if let Ok(relative) = path.strip_prefix(root) {
                files.push(relative.to_path_buf());
            }
        }
    }
}

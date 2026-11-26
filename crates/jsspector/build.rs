use std::fs;
use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    let output = PathBuf::from(std::env::var_os("OUT_DIR").unwrap_or_default())
        .join("embedded_fix_store.rs");
    fs::write(
        output,
        "pub static EMBEDDED_FIX_FILES: &[(&str, &str)] = &[];\n",
    )
}

use std::fs;
use std::path::{Path, PathBuf};

fn resolve_profile_dir_from_out_dir(out_dir: &Path) -> Option<PathBuf> {
    // Supports both classic Cargo (`<target>/<profile>/build/<pkg>-<hash>/out`) and
    // Cargo 1.9x+ (`<target>/<profile>/build/<pkg>/<hash>/out`).
    let build_dir = out_dir
        .ancestors()
        .find(|p| p.file_name().and_then(|n| n.to_str()) == Some("build"))?;
    build_dir.parent().map(Path::to_path_buf)
}

fn sync_runtime_dll(src: &Path, dst: &Path) {
    if !src.is_file() {
        return;
    }
    let Ok(src_meta) = fs::metadata(src) else {
        return;
    };
    let needs_copy = match fs::metadata(dst) {
        Ok(dst_meta) => {
            dst_meta.len() != src_meta.len()
                || src_meta
                    .modified()
                    .ok()
                    .zip(dst_meta.modified().ok())
                    .is_some_and(|(s, d)| s > d)
        }
        Err(_) => true,
    };
    if needs_copy {
        if let Err(err) = fs::copy(src, dst) {
            println!(
                "cargo:warning=failed staging {} -> {}: {err}",
                src.display(),
                dst.display()
            );
        }
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../assets/bin/tunnel.dll");
    println!("cargo:rerun-if-changed=../assets/bin/wireguard.dll");

    if std::env::var_os("CARGO_CFG_WINDOWS").is_none() {
        return;
    }

    let Some(manifest_dir) = std::env::var_os("CARGO_MANIFEST_DIR").map(PathBuf::from) else {
        return;
    };
    let Some(out_dir) = std::env::var_os("OUT_DIR").map(PathBuf::from) else {
        return;
    };
    let Some(profile_dir) = resolve_profile_dir_from_out_dir(&out_dir) else {
        return;
    };

    let assets_bin = manifest_dir.join("..").join("assets").join("bin");
    for dll in ["tunnel.dll", "wireguard.dll"] {
        sync_runtime_dll(&assets_bin.join(dll), &profile_dir.join(dll));
    }
}

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

#[cfg(feature = "llvm")]
use std::process::Command;
#[cfg(feature = "llvm")]
use which::which;

#[cfg(feature = "llvm")]
fn find_clang_with_bpf() -> Result<String> {
    let package_paths: Vec<&str> = if cfg!(target_os = "macos") {
        vec![
            "/opt/homebrew/opt/llvm@17/bin/clang",
            "/usr/local/opt/llvm@17/bin/clang",
            "/opt/homebrew/opt/llvm/bin/clang",
            "/usr/local/opt/llvm/bin/clang",
        ]
    } else {
        vec!["/usr/bin/clang-17", "/usr/bin/clang"]
    };

    for path in package_paths {
        if std::path::Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }

    let path = which("clang")?.to_string_lossy().into_owned();
    Ok(path)
}

#[cfg(feature = "llvm")]
fn verify_bpf_support(clang_path: &str) -> Result<()> {
    let output = Command::new(clang_path)
        .arg("--print-targets")
        .output()
        .with_context(|| "Failed to check clang targets")?;

    if !output.status.success() {
        anyhow::bail!("Failed to check clang targets");
    }

    let targets = String::from_utf8_lossy(&output.stdout);
    if !targets.contains("bpf") {
        anyhow::bail!("Installed clang does not support BPF target");
    }

    Ok(())
}

#[cfg(feature = "llvm")]
pub async fn build_bpf_program(
    source: &Path,
    output: Option<&Path>,
    opt_level: u8,
) -> Result<PathBuf> {
    let output_path = output.map(|p| p.to_path_buf()).unwrap_or_else(|| {
        let mut out = source.to_path_buf();
        out.set_extension("o");
        out
    });

    let clang = find_clang_with_bpf()?;
    verify_bpf_support(&clang)?;

    let mut cmd = Command::new(&clang);
    cmd.arg(format!("-O{opt_level}"))
        .arg("-target")
        .arg("bpf")
        .arg("-c")
        .arg("-g")
        .arg("-I")
        .arg("include")
        .arg("-D__KERNEL__")
        .arg("-D__BPF_TRACING__")
        .arg("-Wno-unused-value")
        .arg("-Wno-pointer-sign")
        .arg("-Wno-compare-distinct-pointer-types")
        .arg("-Wno-gnu-variable-sized-type-not-at-end")
        .arg("-Wno-address-of-packed-member")
        .arg("-Wno-tautological-compare")
        .arg("-Wno-unknown-warning-option")
        .arg(source)
        .arg("-o")
        .arg(&output_path);

    let status = cmd
        .status()
        .with_context(|| format!("Failed to execute clang for {}", source.display()))?;

    if !status.success() {
        anyhow::bail!("Compilation failed for {}", source.display());
    }

    Ok(output_path)
}

#[cfg(not(feature = "llvm"))]
pub async fn build_bpf_program(
    _source: &Path,
    _output: Option<&Path>,
    _opt_level: u8,
) -> Result<PathBuf> {
    anyhow::bail!(
        "Building eBPF programs requires the 'llvm' feature. Install with default features enabled."
    )
}

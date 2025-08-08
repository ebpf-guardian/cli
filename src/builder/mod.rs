use anyhow::{Result, Context};
use std::path::{Path, PathBuf};
use std::process::Command;
use llvm_sys::target_machine::LLVMCodeGenOptLevel;
use which::which;

/// Builds an eBPF program from C source to object file
/// Finds clang with BPF support in standard system locations
fn find_clang_with_bpf() -> Result<String> {
    // First try standard package manager locations
    let package_paths = if cfg!(target_os = "macos") {
        vec![
            "/usr/local/opt/llvm/bin/clang",  // Intel Homebrew
            "/opt/homebrew/opt/llvm/bin/clang",  // M1 Homebrew
        ]
    } else {
        vec![
            "/usr/bin/clang",  // Standard Linux
            "/usr/local/bin/clang",  // Custom install
        ]
    };

    // Check package manager paths first
    for path in package_paths {
        if Path::new(path).exists() {
            if let Ok(output) = Command::new(path)
                .arg("--version")
                .output()
            {
                if output.status.success() {
                    return Ok(path.to_string());
                }
            }
        }
    }

    // Fall back to PATH search
    if let Ok(path) = which("clang") {
        if let Ok(output) = Command::new(&path)
            .arg("--version")
            .output()
        {
            if output.status.success() {
                return Ok(path.to_string_lossy().into_owned());
            }
        }
    }

    anyhow::bail!("Could not find clang. Please install LLVM/Clang with BPF support:\n\
                  - On macOS: brew install llvm\n\
                  - On Ubuntu/Debian: sudo apt install llvm clang\n\
                  - On Fedora/RHEL: sudo dnf install llvm clang")
}

/// Verifies that clang has BPF target support
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
        anyhow::bail!("Installed clang does not support BPF target.\n\
                      Please ensure you have LLVM/Clang installed with BPF support.")
    }

    Ok(())
}

pub async fn build_bpf_program(source: &Path, output: Option<&Path>, opt_level: u8) -> Result<PathBuf> {
    // Determine output path
    let output_path = if let Some(out) = output {
        out.to_path_buf()
    } else {
        let mut out = source.to_path_buf();
        out.set_extension("o");
        out
    };

    // Find clang with BPF support
    let clang_path = find_clang_with_bpf()?;
    
    // Verify BPF target support
    verify_bpf_support(&clang_path)?;
    
    let mut cmd = Command::new(clang_path);
    cmd.arg(format!("-O{}", opt_level))
        .arg("-target")
        .arg("bpf")  // BPF target
        .arg("-c")
        .arg("-g")  // Include debug info
        .arg("-I")
        .arg("include")  // Add our include directory
        .arg("-D__KERNEL__")  // Define kernel compilation
        .arg("-D__BPF_TRACING__")  // Enable BPF tracing
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

    // Run compilation
    let status = cmd.status()
        .with_context(|| format!("Failed to execute clang for {}", source.display()))?;

    if !status.success() {
        anyhow::bail!("Compilation failed for {}", source.display());
    }

    Ok(output_path)
}
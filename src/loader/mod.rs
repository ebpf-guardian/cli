//! Module for loading eBPF programs from various sources

pub mod bpftool;
pub mod elf_parser;

/// Common error type for loader operations
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
#[allow(clippy::enum_variant_names)]
pub enum LoaderError {
    #[error("ELF parsing error: {0}")]
    ElfError(String),

    #[error("BPF tool error: {0}")]
    BpfToolError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Invalid format: {0}")]
    FormatError(String),
}

/// Result type for loader operations
#[allow(dead_code)]
pub type Result<T> = std::result::Result<T, LoaderError>;

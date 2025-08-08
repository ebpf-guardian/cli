//! Module for loading eBPF programs from various sources

pub mod elf_parser;
pub mod bpftool;

/// Common error type for loader operations
#[derive(Debug, thiserror::Error)]
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
pub type Result<T> = std::result::Result<T, LoaderError>;

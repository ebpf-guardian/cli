// Library entry point to reuse analyzer functionality programmatically
// Expose key modules used by the demo server and potential integrations

pub mod analyzer;
pub mod builder;
pub mod cli;
pub mod loader;
pub mod output;
pub mod utils;

pub use analyzer::{analyze_bpf_program, ScanSummary};

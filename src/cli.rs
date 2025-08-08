use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// CLI arguments for ebpf-guardian
#[derive(Parser, Debug)]
#[command(author, version, about = "Static analyzer for eBPF programs")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
    
    /// Verbosity level (-v = debug, -vv = trace)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
    
    /// Suppress all output except errors
    #[arg(short, long)]
    pub quiet: bool,
}

/// Available subcommands
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Scan eBPF programs from object files or live system
    Scan(ScanArgs),
    /// Build and optionally scan eBPF programs
    Build(BuildArgs),
}

/// Arguments for the build command
#[derive(Parser, Debug)]
pub struct BuildArgs {
    /// Path to the eBPF source file (.c)
    #[arg(required = true)]
    pub source: PathBuf,

    /// Output path for object file (default: source_name.o)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Optimization level (0-3, default: 2)
    #[arg(short = 'O', long, default_value = "2")]
    pub opt_level: u8,

    /// Run scan after building
    #[arg(short, long)]
    pub scan: bool,

    /// Custom rules file for scanning
    #[arg(short, long)]
    pub rules: Option<PathBuf>,
}

/// Output format options
#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable table format
    Table,
    /// JSON format for machine consumption
    Json,
}

/// Arguments for the scan command
#[derive(Parser, Debug)]
pub struct ScanArgs {
    /// Path to the eBPF source (.c) or object (.o) file
    #[arg(long, required_unless_present_any = ["dir", "glob"])]
    pub file: Option<PathBuf>,

    /// Build source file before scanning (if .c file)
    #[arg(long)]
    pub build: bool,

    /// Scan all .o files in a directory (non-recursive)
    #[arg(long, conflicts_with = "file")]
    pub dir: Option<PathBuf>,

    /// Glob pattern to match object files (e.g., "**/*.o")
    #[arg(long, conflicts_with = "file")]
    pub glob: Option<String>,
    
    /// Path to custom rules file
    #[arg(short, long)]
    pub rules: Option<PathBuf>,
    
    /// Output format (table or json)
    #[arg(short = 'f', long, value_enum, default_value = "table")]
    pub format: OutputFormat,
    
    /// Generate detailed Markdown report
    #[arg(short = 'R', long)]
    pub report: Option<PathBuf>,

    /// Emit CFG in DOT format to this file
    #[arg(long)]
    pub cfg_dot_out: Option<PathBuf>,

    /// Emit CFG in ASCII (adjacency) to this file
    #[arg(long)]
    pub cfg_ascii_out: Option<PathBuf>,

    /// Print CFG in ASCII (adjacency) to stdout
    #[arg(long)]
    pub print_cfg_ascii: bool,
    
    /// Exit with code 1 if any high-severity rules are violated
    #[arg(long)]
    pub strict: bool,
    
    /// Skip scanning if file hasn't changed (uses SHA256 cache)
    #[arg(long)]
    pub use_cache: bool,
    
    /// Cache directory location
    #[arg(long, default_value = ".ebpf-guardian-cache")]
    pub cache_dir: PathBuf,
}

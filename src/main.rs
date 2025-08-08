mod cli;
mod analyzer;
mod loader;
mod output;
mod utils;
mod builder;

use anyhow::{Result, Context};
use clap::Parser;
use cli::{Cli, Commands, OutputFormat};
use colored::*;
use env_logger::Env;
use std::process;
use utils::cache::Cache;
use std::path::{Path, PathBuf};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logger based on verbosity
    setup_logging(cli.verbose, cli.quiet);
    
    // Execute the appropriate subcommand
    match cli.command {
        Commands::Scan(args) => {
            match scan_command(args).await {
                Ok(exit_code) => process::exit(exit_code),
                Err(e) => {
                    eprintln!("{}: {:#}", "Error".red().bold(), e);
                    log::debug!("Detailed error: {:#?}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Build(args) => {
            match build_command(args).await {
                Ok(exit_code) => process::exit(exit_code),
                Err(e) => {
                    eprintln!("{}: {:#}", "Error".red().bold(), e);
                    log::debug!("Detailed error: {:#?}", e);
                    process::exit(1);
                }
            }
        }
    }
}

/// Sets up logging with appropriate filters
fn setup_logging(verbosity: u8, quiet: bool) {
    if quiet {
        env_logger::Builder::from_env(Env::default().default_filter_or("error"))
            .init();
        return;
    }

    let default_level = match verbosity {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    
    env_logger::Builder::from_env(Env::default().default_filter_or(default_level))
        .init();
}

/// Handles the scan command
async fn build_command(args: cli::BuildArgs) -> Result<i32> {
    // Build the program
    let output_path = builder::build_bpf_program(&args.source, args.output.as_deref(), args.opt_level).await?;
    println!("Successfully built {}", output_path.display());

    // Optionally scan the built program
    if args.scan {
        let scan_args = cli::ScanArgs {
            file: Some(output_path),
            rules: args.rules,
            format: cli::OutputFormat::Table,
            report: None,
            cfg_dot_out: None,
            cfg_ascii_out: None,
            print_cfg_ascii: false,
            strict: false,
            use_cache: false,
            cache_dir: PathBuf::from(".ebpf-guardian-cache"),
            dir: None,
            glob: None,
            build: false,  // Already built
        };
        scan_command(scan_args).await?;
    }

    Ok(0)
}

async fn scan_command(args: cli::ScanArgs) -> Result<i32> {
    // Initialize cache if requested
    let cache = if args.use_cache {
        Some(Cache::new(args.cache_dir)?)
    } else {
        None
    };
    
    // Multi-target scanning aggregation via helper

    let summary = if let Some(file_path) = args.file.as_ref() {
        // Build if source file and build flag is set
        let target_path = if args.build && file_path.extension().and_then(|e| e.to_str()) == Some("c") {
            let output = builder::build_bpf_program(file_path, None, 2).await
                .with_context(|| format!("Failed to build {}", file_path.display()))?;
            println!("Successfully built {}", output.display());
            output
        } else {
            file_path.clone()
        };
        
        // Check cache first if enabled
        analyze_one(&target_path, args.rules.as_deref(), &cache).await?
    } else if let Some(dir) = args.dir.as_ref() {
        let mut summaries = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("o") {
                let s = analyze_one(&path, args.rules.as_deref(), &cache).await?;
                summaries.push(s);
            }
        }
        // Print aggregated output per summary
        for s in &summaries {
            let out = output::formatter::format_output(s, &args.format)?;
            println!("{}\n{}", "==>".bold(), out);
        }
        return Ok(0);
    } else if let Some(pattern) = args.glob.as_ref() {
        // Best-effort simple glob using glob crate semantics; avoid dep by minimal expansion
        // For now, support "*.o" in current dir
        let mut summaries = Vec::new();
        let cwd = std::env::current_dir()?;
        if pattern == "*.o" {
            for entry in std::fs::read_dir(cwd)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("o") {
                    let s = analyze_one(&path, args.rules.as_deref(), &cache).await?;
                    summaries.push(s);
                }
            }
        } else {
            anyhow::bail!("Unsupported glob pattern: {}", pattern);
        }
        for s in &summaries {
            let out = output::formatter::format_output(s, &args.format)?;
            println!("{}\n{}", "==>".bold(), out);
        }
        return Ok(0);
    } else {
        unreachable!("Either file or live must be specified");
    };
    
    // Format and display results
    let output = output::formatter::format_output(&summary, &args.format)?;
    println!("{}", output);
    
    // Emit CFG outputs if requested
    if let Some(dot_path) = args.cfg_dot_out.as_ref() {
        if let Some(dot) = summary.cfg_dot.as_ref() {
            std::fs::write(dot_path, dot).with_context(|| format!("Failed to write DOT to {}", dot_path.display()))?;
            println!("Wrote CFG DOT: {}", dot_path.display());
        }
    }
    if let Some(ascii_path) = args.cfg_ascii_out.as_ref() {
        if let Some(ascii) = summary.cfg_ascii.as_ref() {
            std::fs::write(ascii_path, ascii).with_context(|| format!("Failed to write ASCII CFG to {}", ascii_path.display()))?;
            println!("Wrote CFG ASCII: {}", ascii_path.display());
        }
    }
    if args.print_cfg_ascii {
        if let Some(ascii) = summary.cfg_ascii.as_ref() {
            println!("\nCFG (ASCII)\n{}", ascii);
        }
    }

    // Generate report if requested
    if let Some(report_path) = args.report {
        output::formatter::generate_report(&summary, &report_path)
            .with_context(|| format!("Failed to generate report at {}", report_path.display()))?;
        println!("\nReport generated: {}", report_path.display());
    }
    
    // Check for high severity violations in strict mode
    if args.strict {
        let has_high_severity = summary.violations.iter()
            .any(|v| v.severity.to_lowercase() == "high");
            
        if has_high_severity {
            eprintln!("{}: High severity violations found", "Error".red().bold());
            return Ok(1);
        }
    }
    
    Ok(0)
}

async fn analyze_one(
    path: &PathBuf,
    rules: Option<&Path>,
    cache: &Option<Cache>,
) -> anyhow::Result<analyzer::ScanSummary> {
    if let Some(cache) = cache {
        if let Some(entry) = cache.get(path)? {
            log::info!("Using cached results for {}", path.display());
            return Ok(entry.scan_results);
        }
    }
    let summary = analyzer::analyze_bpf_program(path, rules)
        .await
        .with_context(|| format!("Failed to analyze {}", path.display()))?;
    if let Some(cache) = cache {
        cache.store(path, &summary)?;
    }
    Ok(summary)
}

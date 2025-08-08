mod analyzer;
mod builder;
mod cli;
mod loader;
mod output;
mod repl;
mod utils;
mod samples {
    pub const DEFAULT_RULES: &str = include_str!("./../rules.yaml");
}

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Commands, OutputFormat};
use colored::*;
use env_logger::Env;
use futures::stream::{FuturesUnordered, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};
use std::process;
use utils::cache::Cache;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logger based on verbosity
    setup_logging(cli.verbose, cli.quiet);

    // Execute the appropriate subcommand
    match cli.command {
        Commands::Scan(args) => match scan_command(args).await {
            Ok(exit_code) => process::exit(exit_code),
            Err(e) => {
                eprintln!("{}: {:#}", "Error".red().bold(), e);
                log::debug!("Detailed error: {:#?}", e);
                process::exit(1);
            }
        },
        Commands::Build(args) => match build_command(args).await {
            Ok(exit_code) => process::exit(exit_code),
            Err(e) => {
                eprintln!("{}: {:#}", "Error".red().bold(), e);
                log::debug!("Detailed error: {:#?}", e);
                process::exit(1);
            }
        },
        Commands::ValidateRules { file } => match validate_rules_command(file).await {
            Ok(_) => process::exit(0),
            Err(e) => {
                eprintln!("{}: {:#}", "Error".red().bold(), e);
                process::exit(1);
            }
        },
        Commands::InitRules { out } => match init_rules_command(out).await {
            Ok(path) => {
                println!("Sample rules written to {}", path.display());
                process::exit(0)
            }
            Err(e) => {
                eprintln!("{}: {:#}", "Error".red().bold(), e);
                process::exit(1)
            }
        },
        Commands::Repl => {
            if let Err(e) = repl::run_repl(None) {
                eprintln!("{}: {:#}", "Error".red().bold(), e);
                process::exit(1)
            }
            process::exit(0)
        }
    }
}

/// Sets up logging with appropriate filters
fn setup_logging(verbosity: u8, quiet: bool) {
    if quiet {
        env_logger::Builder::from_env(Env::default().default_filter_or("error")).init();
        return;
    }

    let default_level = match verbosity {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };

    env_logger::Builder::from_env(Env::default().default_filter_or(default_level)).init();
}

/// Handles the scan command
async fn build_command(args: cli::BuildArgs) -> Result<i32> {
    // Build the program
    let output_path =
        builder::build_bpf_program(&args.source, args.output.as_deref(), args.opt_level).await?;
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
            build: false, // Already built
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
        let target_path =
            if args.build && file_path.extension().and_then(|e| e.to_str()) == Some("c") {
                let output = builder::build_bpf_program(file_path, None, 2)
                    .await
                    .with_context(|| format!("Failed to build {}", file_path.display()))?;
                println!("Successfully built {}", output.display());
                output
            } else {
                file_path.clone()
            };

        // Check cache first if enabled
        analyze_one(&target_path, args.rules.as_deref(), &cache).await?
    } else if let Some(dir) = args.dir.as_ref() {
        let entries: Vec<_> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("o"))
            .collect();
        let pb = ProgressBar::new(entries.len() as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}",
            )
            .unwrap()
            .progress_chars("=>-"),
        );

        let mut tasks = FuturesUnordered::new();
        for path in entries.clone() {
            let rules = args.rules.clone();
            let cache = cache.clone();
            tasks.push(async move {
                (
                    path.clone(),
                    analyze_one(&path, rules.as_deref(), &cache).await,
                )
            });
        }

        let mut summaries = Vec::with_capacity(entries.len());
        while let Some((path, res)) = tasks.next().await {
            pb.set_message(path.display().to_string());
            match res {
                Ok(s) => summaries.push(s),
                Err(e) => eprintln!("{}: {}: {:#}", "Error".red().bold(), path.display(), e),
            }
            pb.inc(1);
        }
        pb.finish_with_message("Scan complete");
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
            let entries: Vec<_> = std::fs::read_dir(cwd)?
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("o"))
                .collect();
            let pb = ProgressBar::new(entries.len() as u64);
            pb.set_style(
                ProgressStyle::with_template(
                    "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}",
                )
                .unwrap()
                .progress_chars("=>-"),
            );
            let mut tasks = FuturesUnordered::new();
            for path in entries.clone() {
                let rules = args.rules.clone();
                let cache = cache.clone();
                tasks.push(async move {
                    (
                        path.clone(),
                        analyze_one(&path, rules.as_deref(), &cache).await,
                    )
                });
            }
            while let Some((path, res)) = tasks.next().await {
                pb.set_message(path.display().to_string());
                match res {
                    Ok(s) => summaries.push(s),
                    Err(e) => eprintln!("{}: {}: {:#}", "Error".red().bold(), path.display(), e),
                }
                pb.inc(1);
            }
            pb.finish_with_message("Scan complete");
        } else {
            anyhow::bail!("Unsupported glob pattern: {}", pattern);
        }
        for s in &summaries {
            let out = output::formatter::format_output(s, &args.format)?;
            println!("{}\n{}", "==>".bold(), out);
        }
        return Ok(0);
    } else {
        anyhow::bail!("No input specified. Use --file, --dir, or --glob.");
    };

    // Format and display results
    let output = output::formatter::format_output(&summary, &args.format)?;
    println!("{}", output);

    // Emit CFG outputs if requested
    if let Some(dot_path) = args.cfg_dot_out.as_ref() {
        if let Some(dot) = summary.cfg_dot.as_ref() {
            std::fs::write(dot_path, dot)
                .with_context(|| format!("Failed to write DOT to {}", dot_path.display()))?;
            println!("Wrote CFG DOT: {}", dot_path.display());
        }
    }
    if let Some(ascii_path) = args.cfg_ascii_out.as_ref() {
        if let Some(ascii) = summary.cfg_ascii.as_ref() {
            std::fs::write(ascii_path, ascii).with_context(|| {
                format!("Failed to write ASCII CFG to {}", ascii_path.display())
            })?;
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
        let has_high_severity = summary
            .violations
            .iter()
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

// Helper used by REPL (sync wrapper over async path)
pub fn main_analyze_file(path: &Path) -> anyhow::Result<analyzer::ScanSummary> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move { analyze_one(&path.to_path_buf(), None, &None).await })
}

async fn validate_rules_command(file: PathBuf) -> anyhow::Result<()> {
    let content = std::fs::read_to_string(&file)
        .with_context(|| format!("Failed to read {}", file.display()))?;
    let _: Vec<analyzer::rule_engine::Rule> = serde_yaml::from_str(&content)
        .with_context(|| format!("Failed to parse YAML in {}", file.display()))?;
    println!("Rules OK: {}", file.display());
    Ok(())
}

async fn init_rules_command(out: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    let path = out.unwrap_or_else(|| PathBuf::from("rules.sample.yaml"));
    if path.exists() {
        anyhow::bail!("{} already exists", path.display());
    }
    std::fs::write(&path, samples::DEFAULT_RULES)
        .with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(path)
}

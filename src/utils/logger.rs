use anyhow::Result;
use colored::*;
use env_logger::{Builder, Env};
use log::LevelFilter;
use std::io::Write;

/// Initializes the logger with custom formatting
#[allow(dead_code)]
pub fn init() -> Result<()> {
    Builder::from_env(Env::default().default_filter_or("info"))
        .format(|buf, record| {
            let level = match record.level() {
                log::Level::Error => "ERROR".red(),
                log::Level::Warn => "WARN".yellow(),
                log::Level::Info => "INFO".green(),
                log::Level::Debug => "DEBUG".blue(),
                log::Level::Trace => "TRACE".purple(),
            };

            writeln!(
                buf,
                "{:>5} [{}] {}",
                level,
                record.target().blue(),
                record.args()
            )
        })
        .init();
    Ok(())
}

/// Sets the global maximum log level
#[allow(dead_code)]
pub fn set_max_level(level: LevelFilter) {
    log::set_max_level(level);
}

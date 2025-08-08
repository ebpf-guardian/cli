use crate::analyzer::ScanSummary;
use anyhow::{Context, Result};
use colored::*;
use prettytable::{format, Cell, Row, Table};
use serde_json;
use std::fs;
use std::path::Path;

/// Formats scan results based on the specified output format
pub fn format_output(summary: &ScanSummary, format: &crate::cli::OutputFormat) -> Result<String> {
    match format {
        crate::cli::OutputFormat::Table => format_table(summary),
        crate::cli::OutputFormat::Json => format_json(summary),
    }
}

/// Formats scan results as a human-readable table
fn format_table(summary: &ScanSummary) -> Result<String> {
    let mut output = String::new();

    // Program info
    output.push_str(&format!("\n{}\n", "eBPF Program Analysis".bold()));
    output.push_str(&format!("File: {}\n", summary.program_path));
    output.push_str(&format!("Type: {}\n", summary.program_type));
    output.push_str(&format!("Instructions: {}\n", summary.instructions.len()));
    output.push_str("\nControl Flow\n");
    let mut cf_table = Table::new();
    cf_table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    cf_table.add_row(Row::new(vec![
        Cell::new("Metric").style_spec("b"),
        Cell::new("Value").style_spec("b"),
    ]));
    cf_table.add_row(Row::new(vec![
        Cell::new("Cyclomatic Complexity"),
        Cell::new(&summary.cyclomatic_complexity.to_string()),
    ]));
    cf_table.add_row(Row::new(vec![
        Cell::new("Conditional Branches"),
        Cell::new(&summary.conditional_branch_count.to_string()),
    ]));
    cf_table.add_row(Row::new(vec![
        Cell::new("Path Count (estimate)"),
        Cell::new(&summary.path_count_estimate.to_string()),
    ]));
    cf_table.add_row(Row::new(vec![
        Cell::new("Path Count (exact, capped)"),
        Cell::new(
            &summary
                .path_count_exact
                .map(|v| v.to_string())
                .unwrap_or_else(|| "n/a".to_string()),
        ),
    ]));
    cf_table.add_row(Row::new(vec![
        Cell::new("Max Stack Depth (bytes)"),
        Cell::new(&summary.max_stack_depth.to_string()),
    ]));
    cf_table.add_row(Row::new(vec![
        Cell::new("CFG Entry Offset"),
        Cell::new(&summary.cfg_entry_offset.to_string()),
    ]));
    cf_table.add_row(Row::new(vec![
        Cell::new("CFG Exit Offsets"),
        Cell::new(&format!("{:?}", summary.cfg_exit_offsets)),
    ]));
    cf_table.add_row(Row::new(vec![
        Cell::new("Unreachable Blocks"),
        Cell::new(&format!("{:?}", summary.cfg_unreachable_blocks)),
    ]));
    cf_table.add_row(Row::new(vec![
        Cell::new("CFG Max Depth"),
        Cell::new(&summary.cfg_max_depth.to_string()),
    ]));
    cf_table.add_row(Row::new(vec![
        Cell::new("CFG Avg Out-Degree"),
        Cell::new(&format!("{:.2}", summary.cfg_avg_out_degree)),
    ]));
    cf_table.add_row(Row::new(vec![
        Cell::new("CFG Max Out-Degree"),
        Cell::new(&summary.cfg_max_out_degree.to_string()),
    ]));
    output.push_str(&cf_table.to_string());

    // Maps overview
    output.push_str(&format!("\n{}\n", "Maps".bold()));
    let mut map_table = Table::new();
    map_table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    map_table.add_row(Row::new(vec![
        Cell::new("Name").style_spec("b"),
        Cell::new("Type").style_spec("b"),
        Cell::new("Key/Value Size").style_spec("b"),
        Cell::new("Max Entries").style_spec("b"),
        Cell::new("Access").style_spec("b"),
    ]));

    for map in &summary.maps {
        map_table.add_row(Row::new(vec![
            Cell::new(&map.name),
            Cell::new(&map.map_type),
            Cell::new(&format!("{}/{}", map.key_size, map.value_size)),
            Cell::new(&map.max_entries.to_string()),
            Cell::new(if map.writable { "RW" } else { "RO" }),
        ]));
    }
    output.push_str(&map_table.to_string());

    // Rule violations
    if !summary.violations.is_empty() {
        output.push_str(&format!("\n{}\n", "Rule Violations".bold()));
        let mut rule_table = Table::new();
        rule_table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
        rule_table.add_row(Row::new(vec![
            Cell::new("Severity").style_spec("b"),
            Cell::new("Rule").style_spec("b"),
            Cell::new("Location").style_spec("b"),
            Cell::new("Description").style_spec("b"),
        ]));

        for violation in &summary.violations {
            rule_table.add_row(Row::new(vec![
                Cell::new(&format_severity(&violation.severity)),
                Cell::new(&violation.rule_id),
                Cell::new(&violation.location),
                Cell::new(&violation.description),
            ]));
        }
        output.push_str(&rule_table.to_string());
    } else {
        output.push_str(&format!("\n{}\n", "✓ No rule violations found".green()));
    }

    Ok(output)
}

/// Formats scan results as JSON with pretty printing and colors
fn format_json(summary: &ScanSummary) -> Result<String> {
    let json_str = serde_json::to_string_pretty(summary)
        .context("Failed to serialize scan results to JSON")?;

    // Color different parts of the JSON
    let mut colored_json = String::new();
    let lines: Vec<&str> = json_str.lines().collect();

    for line in lines {
        let trimmed = line.trim();

        if trimmed.is_empty() {
            colored_json.push_str("\n");
            continue;
        }

        // Color the indentation
        let spaces: String = line.chars().take_while(|c| c.is_whitespace()).collect();
        colored_json.push_str(&spaces);

        // Color different parts
        let content = line.trim();
        if content.ends_with('{') || content.ends_with('[') {
            // Opening brackets
            colored_json.push_str(&content.blue().to_string());
        } else if content.starts_with('}') || content.starts_with(']') {
            // Closing brackets
            colored_json.push_str(&content.blue().to_string());
        } else if content.contains(":") {
            // Key-value pairs
            let parts: Vec<&str> = content.splitn(2, ':').collect();
            let key = parts[0];
            let value = parts.get(1).map_or("", |s| s.trim());

            colored_json.push_str(&format!("{}: ", key.green()));

            // Color values based on type
            if value.starts_with('"') {
                colored_json.push_str(&value.yellow().to_string());
            } else if value.parse::<f64>().is_ok() || value.parse::<i64>().is_ok() {
                colored_json.push_str(&value.cyan().to_string());
            } else if value == "true" || value == "false" {
                colored_json.push_str(&value.purple().to_string());
            } else {
                colored_json.push_str(value);
            }
        } else {
            colored_json.push_str(content);
        }
        colored_json.push_str("\n");
    }

    Ok(colored_json)
}

/// Generates a detailed Markdown report
pub fn generate_report(summary: &ScanSummary, output_path: &Path) -> Result<()> {
    let mut report = String::new();

    // Header
    report.push_str("# eBPF Program Analysis Report\n\n");
    report.push_str(&format!("## Program Information\n\n"));
    report.push_str(&format!("- **File:** {}\n", summary.program_path));
    report.push_str(&format!("- **Type:** {}\n", summary.program_type));
    report.push_str(&format!(
        "- **Instructions:** {}\n",
        summary.instructions.len()
    ));
    report.push_str(&format!("- **Analysis Time:** {}\n", summary.timestamp));

    // Maps
    report.push_str("\n## Maps\n\n");
    report.push_str("| Name | Type | Key/Value Size | Max Entries | Access |\n");
    report.push_str("|------|------|---------------|-------------|--------|\n");
    for map in &summary.maps {
        report.push_str(&format!(
            "| {} | {} | {}/{} | {} | {} |\n",
            map.name,
            map.map_type,
            map.key_size,
            map.value_size,
            map.max_entries,
            if map.writable { "RW" } else { "RO" }
        ));
    }

    // Rule Violations
    report.push_str("\n## Rule Violations\n\n");
    if summary.violations.is_empty() {
        report.push_str("✓ No rule violations found\n");
    } else {
        for violation in &summary.violations {
            report.push_str(&format!(
                "### {} - {}\n\n",
                violation.rule_id,
                format_severity_md(&violation.severity)
            ));
            report.push_str(&format!("**Description:** {}\n\n", violation.description));
            report.push_str(&format!("**Location:** {}\n\n", violation.location));
            report.push_str(&format!("**Context:** {}\n\n", violation.context));
        }

        // Recommendations
        report.push_str("\n## Recommendations\n\n");
        generate_recommendations(summary, &mut report);
    }

    fs::write(output_path, report).context("Failed to write Markdown report")
}

/// Formats severity level with color
fn format_severity(severity: &str) -> ColoredString {
    match severity.to_lowercase().as_str() {
        "high" => severity.red(),
        "medium" => severity.yellow(),
        "low" => severity.blue(),
        _ => severity.normal(),
    }
}

/// Formats severity level for Markdown
fn format_severity_md(severity: &str) -> String {
    match severity.to_lowercase().as_str() {
        "high" => "🔴 High",
        "medium" => "🟡 Medium",
        "low" => "🔵 Low",
        _ => severity,
    }
    .to_string()
}

/// Generates improvement recommendations based on violations
fn generate_recommendations(summary: &ScanSummary, report: &mut String) {
    let mut recommendations = Vec::new();

    // Group violations by type
    let mut map_issues = false;
    let mut security_issues = false;
    let mut performance_issues = false;

    for violation in &summary.violations {
        match violation.rule_id.as_str() {
            "no-shared-writable-map" | "map-size-limit" => map_issues = true,
            "restricted-helper-funcs" | "no-raw-tracepoint" => security_issues = true,
            "proper-error-handling" => performance_issues = true,
            _ => {}
        }
    }

    if map_issues {
        recommendations.push("- Review map sharing and access patterns. Consider using read-only maps where possible.");
    }
    if security_issues {
        recommendations.push("- Audit use of privileged helper functions and raw tracepoints.");
    }
    if performance_issues {
        recommendations.push("- Improve error handling and bounds checking.");
    }

    if !recommendations.is_empty() {
        report.push_str("Consider the following improvements:\n\n");
        for rec in recommendations {
            report.push_str(&format!("{}\n", rec));
        }
    }
}

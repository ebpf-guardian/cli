pub mod formatter;

#[cfg(test)]
mod tests {
    use super::formatter;
    use crate::analyzer::{InstructionInfo, MapInfo, RuleViolation, ScanSummary};
    use crate::cli::OutputFormat;
    use tempfile::NamedTempFile;

    fn create_test_summary() -> ScanSummary {
        ScanSummary {
            program_path: "test.o".to_string(),
            program_type: "XDP".to_string(),
            instructions: vec![InstructionInfo {
                offset: 0,
                opcode: 0xb7,
                src_reg: 0,
                dst_reg: 0,
                imm: 0,
                class: "ALU64".to_string(),
                disassembly: "mov r0, 0".to_string(),
            }],
            maps: vec![MapInfo {
                name: "test_map".to_string(),
                map_type: "HASH".to_string(),
                key_size: 4,
                value_size: 4,
                max_entries: 1024,
                flags: 0,
                writable: true,
                accessed_by: vec!["test_prog".to_string()],
            }],
            violations: vec![RuleViolation {
                rule_id: "test-rule".to_string(),
                description: "Test violation".to_string(),
                severity: "high".to_string(),
                location: "test_map".to_string(),
                context: "Test context".to_string(),
            }],
            cyclomatic_complexity: 1,
            conditional_branch_count: 0,
            path_count_estimate: 1,
            path_count_exact: Some(1),
            max_stack_depth: 0,
            cfg_entry_offset: 0,
            cfg_exit_offsets: vec![],
            cfg_unreachable_blocks: vec![],
            cfg_max_depth: 0,
            cfg_avg_out_degree: 0.0,
            cfg_max_out_degree: 0,
            cfg_dot: None,
            cfg_ascii: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    #[test]
    fn test_table_output() {
        let summary = create_test_summary();
        let result = formatter::format_output(&summary, &OutputFormat::Table);
        assert!(result.is_ok());

        let output = result.unwrap();
        assert!(output.contains("eBPF Program Analysis"));
        assert!(output.contains("test_map"));
        assert!(output.contains("Rule Violations"));
    }

    #[test]
    fn test_json_output() {
        let summary = create_test_summary();
        let result = formatter::format_output(&summary, &OutputFormat::Json);
        assert!(result.is_ok());

        let output = result.unwrap();
        println!("JSON output: {}", output);
        assert!(output.contains("program_path"));
        assert!(output.contains("test.o"));
        assert!(output.contains("rule_id"));
        assert!(output.contains("test-rule"));
    }

    #[test]
    fn test_markdown_report() {
        let summary = create_test_summary();
        let report_file = NamedTempFile::new().unwrap();

        let result = formatter::generate_report(&summary, report_file.path());
        assert!(result.is_ok());

        let report_content = std::fs::read_to_string(report_file.path()).unwrap();
        assert!(report_content.contains("# eBPF Program Analysis Report"));
        assert!(report_content.contains("test_map"));
        assert!(report_content.contains("🔴 High"));
    }
}

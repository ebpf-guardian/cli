//! Module for analyzing eBPF programs and building control/data flow graphs.

use serde::{Deserialize, Serialize};

use std::path::Path;

pub mod disassembler; // Handles converting bytecode into readable ops
pub mod map_tracker; // Analyzes maps defined/used in the program
pub mod program_graph; // Builds control/data flow graphs
pub mod rule_engine; // Applies rules against the extracted behavior

/// Common error type for analyzer operations
#[derive(Debug, thiserror::Error)]
pub enum AnalyzerError {
    #[error("Disassembly error: {0}")]
    DisassemblyError(String),

    #[error("Invalid instruction: {0}")]
    InvalidInstruction(String),

    #[error("Map analysis error: {0}")]
    MapAnalysisError(String),

    #[error("Rule engine error: {0}")]
    RuleEngineError(String),

    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

/// Result type for analyzer operations
pub type Result<T> = std::result::Result<T, AnalyzerError>;

/// Represents a single eBPF instruction with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionInfo {
    /// Offset in the program
    pub offset: usize,
    /// Instruction opcode
    pub opcode: u8,
    /// Source register
    pub src_reg: u8,
    /// Destination register
    pub dst_reg: u8,
    /// Immediate value
    pub imm: i32,
    /// Instruction class (e.g., ALU, JMP, MEM)
    pub class: String,
    /// Human readable representation
    pub disassembly: String,
}

/// Information about an eBPF map
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapInfo {
    /// Map name or identifier
    pub name: String,
    /// Map type (e.g., HASH, ARRAY)
    pub map_type: String,
    /// Key size in bytes
    pub key_size: u32,
    /// Value size in bytes
    pub value_size: u32,
    /// Maximum number of entries
    pub max_entries: u32,
    /// Map flags
    pub flags: u32,
    /// Whether the map is writable
    pub writable: bool,
    /// Programs accessing this map
    pub accessed_by: Vec<String>,
}

/// Represents a rule violation found during analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleViolation {
    /// Rule identifier
    pub rule_id: String,
    /// Rule description
    pub description: String,
    /// Violation severity (high, medium, low)
    pub severity: String,
    /// Location of the violation
    pub location: String,
    /// Additional context about the violation
    pub context: String,
}

/// Summary of the eBPF program analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    /// Path to the analyzed program
    pub program_path: String,
    /// Program type (e.g., XDP, kprobe)
    pub program_type: String,
    /// List of instructions
    pub instructions: Vec<InstructionInfo>,
    /// Maps used by the program
    pub maps: Vec<MapInfo>,
    /// Rule violations found
    pub violations: Vec<RuleViolation>,
    /// Control flow: cyclomatic complexity (McCabe)
    pub cyclomatic_complexity: usize,
    /// Control flow: number of conditional branches
    pub conditional_branch_count: usize,
    /// Control flow: estimated path count (upper bound)
    pub path_count_estimate: usize,
    /// Control flow: exact simple path count (capped)
    pub path_count_exact: Option<usize>,
    /// Control flow: maximum stack depth in bytes
    pub max_stack_depth: usize,
    /// CFG entry basic block start offset
    pub cfg_entry_offset: usize,
    /// CFG exit basic block start offsets
    pub cfg_exit_offsets: Vec<usize>,
    /// CFG unreachable basic block start offsets
    pub cfg_unreachable_blocks: Vec<usize>,
    /// CFG maximum depth from entry to any exit (in basic blocks)
    pub cfg_max_depth: usize,
    /// CFG average out-degree
    pub cfg_avg_out_degree: f32,
    /// CFG maximum out-degree
    pub cfg_max_out_degree: usize,
    /// Control flow graph rendering in DOT format
    pub cfg_dot: Option<String>,
    /// Control flow graph rendering in ASCII adjacency form
    pub cfg_ascii: Option<String>,
    /// Analysis timestamp
    pub timestamp: String,
}

/// Analyzes an eBPF program file and returns a summary
pub async fn analyze_bpf_program(path: &Path, rules_path: Option<&Path>) -> Result<ScanSummary> {
    // Load and disassemble the program
    let instructions = disassembler::disassemble(path)?;

    // Analyze maps
    let maps = map_tracker::analyze_maps(path)?;

    // Load and evaluate rules
    let mut violations = Vec::new();
    if let Some(rules_file) = rules_path {
        violations = rule_engine::evaluate_rules(rules_file, &instructions, &maps)?;
    }

    // Build and analyze control flow graph
    let graph = program_graph::build_graph(&instructions)?;
    let analysis = program_graph::analyze_program(&graph, &instructions)?;

    // Add violations based on analysis
    if analysis.max_stack_depth > 512 {
        violations.push(RuleViolation {
            rule_id: "stack-depth-limit".to_string(),
            description: format!(
                "Stack depth {} exceeds recommended limit of 512 bytes",
                analysis.max_stack_depth
            ),
            severity: "medium".to_string(),
            location: format!("Program uses {} bytes of stack", analysis.max_stack_depth),
            context: "Large stack usage may cause issues with concurrent programs".to_string(),
        });
    }

    // Check for unbounded loops
    for loop_info in &analysis.loops {
        if !loop_info.has_static_bound {
            violations.push(RuleViolation {
                rule_id: "unbounded-loop".to_string(),
                description: "Loop without static bound detected".to_string(),
                severity: "high".to_string(),
                location: format!("Loop at offset {}", loop_info.start_offset),
                context: "Loops must have verifiable bounds for kernel verifier".to_string(),
            });
        }
    }

    // Check map access patterns
    for access in &analysis.map_accesses {
        if access.in_loop && !access.has_bounds_check {
            violations.push(RuleViolation {
                rule_id: "unsafe-map-access".to_string(),
                description: format!("Unchecked map access in loop for {}", access.map_id),
                severity: "high".to_string(),
                location: format!(
                    "Map {} accessed in loop without bounds check",
                    access.map_id
                ),
                context: "Map accesses in loops must check bounds to prevent hangs".to_string(),
            });
        }
    }

    // Check helper function usage
    for helper in &analysis.helper_calls {
        // Example: Check for privileged helpers
        if helper.helper_id >= 100 {
            violations.push(RuleViolation {
                rule_id: "privileged-helper".to_string(),
                description: format!("Use of privileged helper function {}", helper.helper_id),
                severity: "medium".to_string(),
                location: format!("Helper call at offset {}", helper.offset),
                context: "Privileged helpers may require additional capabilities".to_string(),
            });
        }
    }

    // Path complexity warning
    if analysis.cyclomatic_complexity > 200
        || analysis.path_count > 1000
        || analysis.conditional_branch_count > 12
    {
        violations.push(RuleViolation {
            rule_id: "verifier-scaling-risk".to_string(),
            description: format!(
                "Potential verifier scalability issue: cyclomatic {}, est paths ~{}, cond branches {}",
                analysis.cyclomatic_complexity, analysis.path_count, analysis.conditional_branch_count
            ),
            severity: "medium".to_string(),
            location: "Program-wide".to_string(),
            context: "Complex control flow can cause long verification times or rejection.".to_string(),
        });
    }

    let program_type = detect_program_type(path).unwrap_or_else(|| "unknown".to_string());

    Ok(ScanSummary {
        program_path: path.display().to_string(),
        program_type,
        instructions,
        maps,
        violations,
        cyclomatic_complexity: analysis.cyclomatic_complexity,
        conditional_branch_count: analysis.conditional_branch_count,
        path_count_estimate: analysis.path_count,
        path_count_exact: analysis.path_count_exact,
        max_stack_depth: analysis.max_stack_depth,
        cfg_entry_offset: analysis.entry_offset,
        cfg_exit_offsets: analysis.exit_offsets,
        cfg_unreachable_blocks: analysis.unreachable_blocks,
        cfg_max_depth: analysis.max_depth,
        cfg_avg_out_degree: analysis.avg_out_degree,
        cfg_max_out_degree: analysis.max_out_degree,
        cfg_dot: analysis.cfg_dot,
        cfg_ascii: analysis.cfg_ascii,
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
}

/// Naive program type detection from ELF section names
fn detect_program_type(path: &Path) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    let elf = goblin::elf::Elf::parse(&data).ok()?;

    // Check section names used by LLVM/Clang for BPF: .text/<name> with prefix indicating type
    for sh in elf.section_headers.iter() {
        let name = match elf.shdr_strtab.get_at(sh.sh_name) {
            Some(n) => n,
            None => continue,
        };

        // Strict matches
        if name == "xdp"
            || name.starts_with("xdp/")
            || name.starts_with(".text/xdp")
            || name == ".text.xdp"
        {
            return Some("XDP".to_string());
        }
        if name == "socket" || name.starts_with(".text/socket") {
            return Some("socket_filter".to_string());
        }
        if name.starts_with(".text/tc") || name == "tc" || name == "cls" {
            return Some("TC".to_string());
        }
        if name.starts_with(".text/kprobe") || name == "kprobe" || name == "kretprobe" {
            return Some("kprobe".to_string());
        }
        if name.starts_with(".text/tracepoint") || name.starts_with("tracepoint/") {
            return Some("tracepoint".to_string());
        }
        if name.starts_with(".text/raw_tracepoint") || name.starts_with("raw_tracepoint/") {
            return Some("raw_tracepoint".to_string());
        }
        if name.starts_with(".text/uprobe") || name == "uprobe" || name == "uretprobe" {
            return Some("uprobe".to_string());
        }
        if name.starts_with(".text/cgroup/") || name.starts_with("cgroup/") {
            return Some("cgroup".to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::NamedTempFile;

    fn create_test_rule_file() -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        use std::io::Write;
        writeln!(
            file,
            r#"
- id: map-size-limit
  description: Limit map size
  severity: high
  rule_type: map_policy
  config:
    max_entries: 1
"#
        )
        .unwrap();
        file
    }

    #[tokio::test]
    async fn test_analyze_simple_program() {
        let test_file = PathBuf::from("tests/data/simple.o");
        let result = analyze_bpf_program(&test_file, None).await;
        assert!(result.is_ok());

        let summary = result.unwrap();
        assert!(!summary.instructions.is_empty());
        assert_eq!(summary.program_type, "unknown"); // TODO: Update when type detection is implemented
    }

    #[tokio::test]
    async fn test_analyze_program_with_maps() {
        let test_file = PathBuf::from("tests/data/simple.o");
        let result = analyze_bpf_program(&test_file, None).await;
        assert!(result.is_ok());

        let summary = result.unwrap();
        assert!(!summary.maps.is_empty());

        let map = &summary.maps[0];
        assert_eq!(map.map_type, "HASH");
        assert_eq!(map.max_entries, 10000);
    }

    #[tokio::test]
    async fn test_analyze_with_rules() {
        let test_file = PathBuf::from("tests/data/simple.o");
        let rules_file = create_test_rule_file();

        let result = analyze_bpf_program(&test_file, Some(rules_file.path())).await;
        assert!(result.is_ok());

        let summary = result.unwrap();
        assert!(!summary.violations.is_empty());

        let violation = &summary.violations[0];
        assert_eq!(violation.rule_id, "map-size-limit");
        assert_eq!(violation.severity, "high");
    }
}

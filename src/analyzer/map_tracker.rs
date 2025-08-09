use super::{MapInfo, Result};
use crate::loader::elf_parser;
use std::fmt;
use std::path::Path;

/// Map types as defined in linux/bpf.h
#[derive(Debug, Clone, Copy)]
pub enum BpfMapType {
    Hash = 1,
    Array = 2,
    ProgArray = 3,
    PerfEventArray = 4,
    // Add more as needed
}

impl BpfMapType {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(BpfMapType::Hash),
            2 => Some(BpfMapType::Array),
            3 => Some(BpfMapType::ProgArray),
            4 => Some(BpfMapType::PerfEventArray),
            _ => None,
        }
    }
}

impl fmt::Display for BpfMapType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BpfMapType::Hash => write!(f, "HASH"),
            BpfMapType::Array => write!(f, "ARRAY"),
            BpfMapType::ProgArray => write!(f, "PROG_ARRAY"),
            BpfMapType::PerfEventArray => write!(f, "PERF_EVENT_ARRAY"),
        }
    }
}

/// Analyzes maps defined and used in an eBPF program
pub fn analyze_maps(path: &Path) -> Result<Vec<MapInfo>> {
    // Delegate to loader's ELF parser for consistent map extraction
    let maps = elf_parser::parse_maps(path)
        .map_err(|e| super::AnalyzerError::MapAnalysisError(e.to_string()))?;

    let mut result = Vec::with_capacity(maps.len());
    for m in maps {
        let map_type_str = match crate::analyzer::map_tracker::BpfMapType::from_u32(m.map_type) {
            Some(t) => t.to_string(),
            None => format!("UNKNOWN({})", m.map_type),
        };

        // Writable heuristic: if map flags indicate RDONLY for prog, mark RO
        // These constants mirror BPF_F_RDONLY_PROG / BPF_F_WRONLY_PROG when available.
        const BPF_F_RDONLY_PROG: u32 = 1 << 3; // 8
        let writable = (m.flags & BPF_F_RDONLY_PROG) == 0;

        result.push(MapInfo {
            name: m.name,
            map_type: map_type_str,
            key_size: m.key_size,
            value_size: m.value_size,
            max_entries: m.max_entries,
            flags: m.flags,
            writable,
            accessed_by: if m.section.is_empty() {
                vec![]
            } else {
                vec![m.section]
            },
        });
    }

    Ok(result)
}

/// Extract map access patterns from instructions
#[allow(dead_code)]
pub fn analyze_map_access(_instructions: &[super::InstructionInfo]) -> Result<Vec<MapAccess>> {
    let accesses = Vec::new();

    // TODO: Implement map access pattern analysis
    // This would look for:
    // - map_fd_idx in instructions
    // - read vs write operations
    // - key/value access patterns

    Ok(accesses)
}

/// Represents a map access operation
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct MapAccess {
    /// Map identifier
    pub map_id: String,
    /// Access type (read/write)
    pub access_type: AccessType,
    /// Instruction offset where access occurs
    pub instruction_offset: usize,
}

/// Type of map access
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum AccessType {
    Read,
    Write,
}

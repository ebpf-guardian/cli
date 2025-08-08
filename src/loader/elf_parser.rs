use anyhow::{Context, Result};
use goblin::elf::Elf;
use std::fs;
use std::path::Path;

/// Information about a BPF map
#[derive(Debug, Clone)]
pub struct BpfMap {
    /// Map name
    pub name: String,
    /// Map type (e.g., HASH, ARRAY)
    pub map_type: u32,
    /// Key size in bytes
    pub key_size: u32,
    /// Value size in bytes
    pub value_size: u32,
    /// Maximum number of entries
    pub max_entries: u32,
    /// Map flags
    pub flags: u32,
    /// Section containing the map
    pub section: String,
}

/// Parses an ELF file and extracts BPF maps
pub fn parse_maps(path: &Path) -> Result<Vec<BpfMap>> {
    let buffer =
        fs::read(path).with_context(|| format!("Failed to read file: {}", path.display()))?;

    let elf = Elf::parse(&buffer).with_context(|| "Failed to parse ELF file")?;

    let mut maps = Vec::new();

    // Find maps section and extract BPF map definitions by parsing struct bpf_map_def
    for section in elf.section_headers.iter() {
        let Some(name) = elf.shdr_strtab.get_at(section.sh_name) else {
            continue;
        };
        if name == ".maps" || name == "maps" {
            let start = section.sh_offset as usize;
            let size = section.sh_size as usize;
            let end = start.saturating_add(size);
            if end > buffer.len() || start >= buffer.len() {
                continue;
            }
            let data = &buffer[start..end];

            // struct bpf_map_def layout (classic):
            // u32 type; u32 key_size; u32 value_size; u32 max_entries; u32 map_flags; (optionally: u32 id; u32 pinning;)
            // We do not rely on BTF here; just read 5 u32s per entry and derive name from symtab
            let entry_size = 5 * 4; // bytes

            // Build an address->name map from symbols to attach names to map objects
            let mut sym_name_by_addr = std::collections::HashMap::new();
            for sym in elf.syms.iter() {
                if sym.st_value == 0 {
                    continue;
                }
                if let Some(sname) = elf.strtab.get_at(sym.st_name) {
                    sym_name_by_addr.insert(sym.st_value as usize, sname.to_string());
                }
            }

            let base_addr = section.sh_addr as usize;
            for (idx, chunk) in data.chunks_exact(entry_size).enumerate() {
                let r32 = |off: usize| -> u32 {
                    let bytes = &chunk[off..off + 4];
                    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
                };

                let map_type = r32(0);
                let key_size = r32(4);
                let value_size = r32(8);
                let max_entries = r32(12);
                let flags = r32(16);

                // Try to resolve name via symbol that points into this struct
                let obj_addr = base_addr + idx * entry_size;
                let name = sym_name_by_addr
                    .get(&obj_addr)
                    .cloned()
                    .unwrap_or_else(|| format!("map_{}", idx));

                maps.push(BpfMap {
                    name,
                    map_type,
                    key_size,
                    value_size,
                    max_entries,
                    flags,
                    section: ".maps".to_string(),
                });
            }
        }
    }

    // Find program sections to annotate access context (best-effort)
    for section in elf.section_headers.iter() {
        let Some(name) = elf.shdr_strtab.get_at(section.sh_name) else {
            continue;
        };
        if name.starts_with(".text/") || name == "xdp" || name.starts_with("xdp/") {
            // We could parse relocations here to link maps per program.
            // Leave as-is for now; map names are already captured above.
            let _program_name = if name.starts_with(".text/") {
                &name[6..]
            } else {
                name
            };
            let _ = _program_name; // suppress unused for now
        }
    }

    // No more dummy maps; return exactly what we parsed.

    Ok(maps)
}

// Note: We intentionally avoid a separate parse_maps_section helper to keep symbol resolution simple.

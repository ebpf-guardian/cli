use super::{AnalyzerError, InstructionInfo, MapInfo, Result, RuleViolation};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// Rule definition loaded from YAML
#[derive(Debug, Serialize, Deserialize)]
pub struct Rule {
    /// Unique rule identifier
    pub id: String,
    /// Human readable description
    pub description: String,
    /// Rule severity level
    pub severity: String,
    /// Rule type (e.g., map_policy, instruction_policy)
    pub rule_type: String,
    /// Rule-specific configuration
    #[serde(flatten)]
    pub config: serde_yaml::Value,
    /// Optional regex on instruction disassembly
    #[serde(default)]
    pub instr_regex: Option<String>,
    /// Optional scripting condition (rhai), enabled via `scripting` feature
    #[serde(default)]
    pub script: Option<String>,
}

/// Evaluates rules against an eBPF program
pub fn evaluate_rules(
    rules_path: &Path,
    instructions: &[InstructionInfo],
    maps: &[MapInfo],
) -> Result<Vec<RuleViolation>> {
    // Load rules from YAML (with better error context)
    let rules_content = fs::read_to_string(rules_path).map_err(AnalyzerError::IoError)?;
    let rules: Vec<Rule> = match serde_yaml::from_str(&rules_content) {
        Ok(r) => r,
        Err(e) => {
            let loc = e
                .location()
                .map(|l| format!("line {}, column {}", l.line(), l.column()))
                .unwrap_or_else(|| "unknown location".to_string());
            return Err(AnalyzerError::RuleEngineError(format!(
                "Failed to parse rules at {loc}: {e}"
            )));
        }
    };

    let mut violations = Vec::new();

    // Evaluate each rule
    for rule in rules {
        match rule.rule_type.as_str() {
            "map_policy" => {
                evaluate_map_rule(&rule, maps, &mut violations)?;
            }
            "instruction_policy" => {
                evaluate_instruction_rule(&rule, instructions, &mut violations)?;
            }
            _ => {
                return Err(AnalyzerError::RuleEngineError(format!(
                    "Unknown rule type: {}",
                    rule.rule_type
                )));
            }
        }
    }

    Ok(violations)
}

/// Evaluates a map-related rule
fn evaluate_map_rule(
    rule: &Rule,
    maps: &[MapInfo],
    violations: &mut Vec<RuleViolation>,
) -> Result<()> {
    if rule.id == "no-shared-writable-map" {
        for map in maps {
            if map.writable && map.accessed_by.len() > 1 {
                violations.push(RuleViolation {
                    rule_id: rule.id.clone(),
                    description: rule.description.clone(),
                    severity: rule.severity.clone(),
                    location: format!("map:{}", map.name),
                    context: format!(
                        "Map is writable and accessed by multiple programs: {:?}",
                        map.accessed_by
                    ),
                });
            }
        }
        return Ok(());
    }
    if rule.id == "map-size-limit" {
        let max_entries_limit = rule
            .config
            .get("config")
            .and_then(|c| c.get("max_entries"))
            .and_then(|v| v.as_u64())
            .unwrap_or(10_000_000);
        for map in maps {
            if (map.max_entries as u64) > max_entries_limit {
                violations.push(RuleViolation {
                    rule_id: rule.id.clone(),
                    description: rule.description.clone(),
                    severity: rule.severity.clone(),
                    location: format!("map:{}", map.name),
                    context: format!(
                        "max_entries={} exceeds limit {}",
                        map.max_entries, max_entries_limit
                    ),
                });
            }
        }
        return Ok(());
    }

    Ok(())
}

/// Evaluates an instruction-related rule
fn evaluate_instruction_rule(
    rule: &Rule,
    instructions: &[InstructionInfo],
    violations: &mut Vec<RuleViolation>,
) -> Result<()> {
    // Regex-based matching
    if let Some(pat) = rule.instr_regex.as_deref() {
        let re =
            regex::Regex::new(pat).map_err(|e| AnalyzerError::RuleEngineError(e.to_string()))?;
        for inst in instructions {
            if re.is_match(&inst.disassembly) {
                violations.push(RuleViolation {
                    rule_id: rule.id.clone(),
                    description: rule.description.clone(),
                    severity: rule.severity.clone(),
                    location: format!("offset:{}", inst.offset),
                    context: format!("matches regex: {pat}"),
                });
            }
        }
    }

    // Scripting (rhai) optional
    #[cfg(feature = "scripting")]
    if let Some(script) = rule.script.as_deref() {
        let mut engine = rhai::Engine::new();
        let mut scope = rhai::Scope::new();
        scope.push("num_instructions", instructions.len() as i64);
        // Add more context bindings as needed
        let ok: bool = engine
            .eval_with_scope(&mut scope, script)
            .map_err(|e| AnalyzerError::RuleEngineError(format!("rhai error: {e}")))?;
        if ok {
            violations.push(RuleViolation {
                rule_id: rule.id.clone(),
                description: rule.description.clone(),
                severity: rule.severity.clone(),
                location: "program-wide".into(),
                context: "script condition matched".into(),
            });
        }
    }
    if rule.id == "restricted-helper-funcs" {
        // Expect list of helper names
        let restricted: HashSet<String> = rule
            .config
            .get("config")
            .and_then(|c| c.get("restricted_helpers"))
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|e| e.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        for inst in instructions {
            // Heuristic: helper call has opcode 0x85 (BPF_CALL). imm holds helper id.
            if inst.opcode == 0x85 {
                if let Some(helper_name) = helper_name_from_id(inst.imm as i64) {
                    if restricted.contains(helper_name) {
                        violations.push(RuleViolation {
                            rule_id: rule.id.clone(),
                            description: rule.description.clone(),
                            severity: rule.severity.clone(),
                            location: format!("offset:{}", inst.offset),
                            context: format!("uses helper {} (id {} )", helper_name, inst.imm),
                        });
                    }
                }
            }
        }
        return Ok(());
    }
    if rule.id == "no-raw-tracepoint" {
        // This rule is better applied at program level; we don't have attach type here.
        // Leave to analyzer to attach a violation later if program_type == raw_tracepoint.
        return Ok(());
    }
    Ok(())
}

/// Minimal helper id→name mapping for common restricted helpers
fn helper_name_from_id(id: i64) -> Option<&'static str> {
    match id {
        // These ids are stable across kernels
        36 => Some("bpf_probe_write_user"),
        59 => Some("bpf_override_return"),
        _ => None,
    }
}

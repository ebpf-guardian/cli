use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::NamedTempFile;

#[test]
fn test_version() {
    Command::cargo_bin("ebpf-guardian")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn test_scan_missing_file() {
    Command::cargo_bin("ebpf-guardian")
        .unwrap()
        .arg("scan")
        .arg("--file")
        .arg("nonexistent.o")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error"));
}

#[test]
fn test_scan_simple_program() {
    Command::cargo_bin("ebpf-guardian")
        .unwrap()
        .arg("scan")
        .arg("--file")
        .arg("tests/data/simple.o")
        .assert()
        .success();
}

#[test]
fn test_scan_with_json_output() {
    let output = Command::cargo_bin("ebpf-guardian")
        .unwrap()
        .arg("scan")
        .arg("--file")
        .arg("tests/data/simple.o")
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(serde_json::from_str::<serde_json::Value>(&stdout).is_ok());
}

#[test]
fn test_scan_with_rules() {
    let rules_file = NamedTempFile::new().unwrap();
    std::fs::write(
        &rules_file,
        r#"
- id: map-size-limit
  description: Limit map size
  severity: high
  rule_type: map_policy
  config:
    max_entries: 1
"#,
    )
    .unwrap();

    Command::cargo_bin("ebpf-guardian")
        .unwrap()
        .arg("scan")
        .arg("--file")
        .arg("tests/data/simple.o")
        .arg("--rules")
        .arg(rules_file.path())
        .assert()
        .success();
}

#[test]
fn test_scan_with_report() {
    let report_file = NamedTempFile::new().unwrap();

    Command::cargo_bin("ebpf-guardian")
        .unwrap()
        .arg("scan")
        .arg("--file")
        .arg("tests/data/simple.o")
        .arg("--report")
        .arg(report_file.path())
        .assert()
        .success();

    let report_content = std::fs::read_to_string(report_file.path()).unwrap();
    assert!(report_content.contains("# eBPF Program Analysis Report"));
}

#[test]
fn test_scan_strict_mode() {
    let rules_file = NamedTempFile::new().unwrap();
    std::fs::write(
        &rules_file,
        r#"
- id: map-size-limit
  description: Limit map size
  severity: high
  rule_type: map_policy
  config:
    max_entries: 1
"#,
    )
    .unwrap();

    Command::cargo_bin("ebpf-guardian")
        .unwrap()
        .arg("scan")
        .arg("--file")
        .arg("tests/data/simple.o")
        .arg("--rules")
        .arg(rules_file.path())
        .arg("--strict")
        .assert()
        .failure()
        .stderr(predicate::str::contains("High severity violations found"));
}

#[test]
fn test_scan_with_cache() {
    let cache_dir = tempfile::tempdir().unwrap();

    // First scan
    Command::cargo_bin("ebpf-guardian")
        .unwrap()
        .arg("scan")
        .arg("--file")
        .arg("tests/data/simple.o")
        .arg("--use-cache")
        .arg("--cache-dir")
        .arg(cache_dir.path())
        .assert()
        .success();

    // Second scan should use cache
    let output = Command::cargo_bin("ebpf-guardian")
        .unwrap()
        .arg("scan")
        .arg("--file")
        .arg("tests/data/simple.o")
        .arg("--use-cache")
        .arg("--cache-dir")
        .arg(cache_dir.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stderr).unwrap();
    assert!(stdout.contains("Using cached results"));
}

//! Milestone 5 Challenger 2 Adversarial Stress Tests for Spec Drift & Schema Engine.
//!
//! Empirically tests:
//! 1. Spec drift tamper tests: Mutate every schema/lexicon file and verify `./scripts/sync_specs.sh --verify` fails with exit code 1.
//! 2. Missing schema file detection: Delete schema files or corrupt manifest hashes and verify failure.
//! 3. Offline sync safety: Verify `--sync` under network failures and malformed upstream responses never corrupts local schemas.
//! 4. CLI flag handling and manifest idempotence.
//! 5. Runtime AST schema validator fuzzing and boundary stress testing.

#![allow(
    clippy::all,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{json, Value};

static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

const MANAGED_FILES: &[&str] = &[
    "lexicons/com/atproto/identity/resolveHandle.json",
    "lexicons/com/atproto/server/createSession.json",
    "lexicons/com/atproto/server/refreshSession.json",
    "schemas/rfc8414_authorization_server.json",
    "schemas/rfc9728_protected_resource.json",
    "schemas/rfc9449_dpop_proof.json",
    "schemas/atproto_client_metadata.json",
];

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(test_name: &str) -> Self {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let target_tmp = manifest_dir
            .join("target")
            .join("tmp_m5_challenger")
            .join(format!("{}_{}_{}", test_name, pid, id));

        if target_tmp.exists() {
            let _ = fs::remove_dir_all(&target_tmp);
        }
        fs::create_dir_all(&target_tmp).expect("Failed to create sandbox dir");

        let src_lex = manifest_dir.join("lexicons");
        let dst_lex = target_tmp.join("lexicons");
        copy_dir_recursive(&src_lex, &dst_lex);

        let src_schemas = manifest_dir.join("schemas");
        let dst_schemas = target_tmp.join("schemas");
        copy_dir_recursive(&src_schemas, &dst_schemas);

        let src_scripts = manifest_dir.join("scripts");
        let dst_scripts = target_tmp.join("scripts");
        copy_dir_recursive(&src_scripts, &dst_scripts);

        let script_file = dst_scripts.join("sync_specs.sh");
        if script_file.exists() {
            let mut perms = fs::metadata(&script_file).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&script_file, perms).unwrap();
        }

        Self { root: target_tmp }
    }

    fn run_script(&self, args: &[&str], envs: &[(&str, &str)]) -> std::process::Output {
        let script_path = self.root.join("scripts").join("sync_specs.sh");
        let mut cmd = Command::new(&script_path);
        cmd.args(args);
        cmd.current_dir(&self.root);
        for (k, v) in envs {
            cmd.env(k, v);
        }
        cmd.output().expect("Failed to execute sync_specs.sh")
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn copy_dir_recursive(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("Failed to create destination dir");
    for entry in fs::read_dir(src).expect("Failed to read src dir") {
        let entry = entry.expect("Valid entry");
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path);
        } else {
            fs::copy(&src_path, &dst_path).expect("Failed to copy file");
        }
    }
}

#[test]
fn test_tamper_every_single_managed_schema_file_caught_by_verify() {
    let sandbox = Sandbox::new("tamper_each_file");

    let out = sandbox.run_script(&["--verify"], &[]);
    assert!(
        out.status.success(),
        "Clean sandbox must pass --verify. stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    for &rel_path in MANAGED_FILES {
        let full_path = sandbox.root.join(rel_path);
        assert!(full_path.exists(), "Managed file must exist: {}", rel_path);

        let original_content = fs::read_to_string(&full_path).unwrap();

        let mut parsed: Value = serde_json::from_str(&original_content).unwrap();
        if let Value::Object(ref mut map) = parsed {
            map.insert("__tampered_field__".to_string(), json!("malicious_drift"));
        }
        let tampered_content = serde_json::to_string_pretty(&parsed).unwrap();
        fs::write(&full_path, tampered_content).unwrap();

        let out = sandbox.run_script(&["--verify"], &[]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let combined = format!("{}\n{}", stdout, stderr);

        assert_eq!(
            out.status.code(),
            Some(1),
            "Tampered file {} MUST cause --verify to exit with code 1. Output: {}",
            rel_path,
            combined
        );
        assert!(
            combined.contains("DRIFT DETECTED")
                || combined.contains("Specification drift check FAILED"),
            "Output must state DRIFT DETECTED for {}. Output: {}",
            rel_path,
            combined
        );

        let out_check = sandbox.run_script(&["--check"], &[]);
        assert_eq!(
            out_check.status.code(),
            Some(1),
            "--check alias MUST also exit with code 1 on tampered {}",
            rel_path
        );

        fs::write(&full_path, original_content).unwrap();

        let out_clean = sandbox.run_script(&["--verify"], &[]);
        assert!(
            out_clean.status.success(),
            "Restored file {} must return --verify to exit code 0",
            rel_path
        );
    }
}

#[test]
fn test_tamper_single_byte_drift_detection() {
    let sandbox = Sandbox::new("single_byte_drift");

    for &rel_path in MANAGED_FILES {
        let full_path = sandbox.root.join(rel_path);
        let original_bytes = fs::read(&full_path).unwrap();

        let mut tampered_bytes = original_bytes.clone();
        tampered_bytes.push(b' ');
        fs::write(&full_path, &tampered_bytes).unwrap();

        let out = sandbox.run_script(&["--verify"], &[]);
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );

        assert_eq!(
            out.status.code(),
            Some(1),
            "Single trailing whitespace byte in {} MUST trigger drift rejection (exit 1)",
            rel_path
        );
        assert!(
            combined.contains("DRIFT DETECTED"),
            "Must report DRIFT DETECTED for single-byte whitespace tampering in {}",
            rel_path
        );

        fs::write(&full_path, &original_bytes).unwrap();
    }
}

#[test]
fn test_tamper_json_syntax_corruption_rejection() {
    let sandbox = Sandbox::new("syntax_corruption");

    for &rel_path in MANAGED_FILES {
        let full_path = sandbox.root.join(rel_path);
        let original_content = fs::read_to_string(&full_path).unwrap();

        fs::write(&full_path, "{ \"invalid_json\": [ unclosed array ").unwrap();

        let out = sandbox.run_script(&["--verify"], &[]);
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );

        assert_eq!(
            out.status.code(),
            Some(1),
            "Corrupt JSON syntax in {} MUST exit with code 1",
            rel_path
        );
        assert!(
            combined.contains("Malformed JSON") || combined.contains("DRIFT DETECTED"),
            "Must report Malformed JSON or DRIFT DETECTED. Got: {}",
            combined
        );

        fs::write(&full_path, &original_content).unwrap();
    }
}

#[test]
fn test_missing_each_schema_file_detection() {
    let sandbox = Sandbox::new("missing_files");

    for &rel_path in MANAGED_FILES {
        let full_path = sandbox.root.join(rel_path);
        let original_content = fs::read_to_string(&full_path).unwrap();

        fs::remove_file(&full_path).unwrap();

        let out = sandbox.run_script(&["--verify"], &[]);
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );

        assert_eq!(
            out.status.code(),
            Some(1),
            "Deleting {} MUST cause --verify to exit with code 1",
            rel_path
        );
        assert!(
            combined.contains("Missing required specification")
                || combined.contains("Manifest references missing file"),
            "Error output must identify missing file {}. Got: {}",
            rel_path,
            combined
        );

        fs::write(&full_path, &original_content).unwrap();
    }
}

#[test]
fn test_manifest_checksum_tamper_detection() {
    let sandbox = Sandbox::new("manifest_tamper");
    let manifest_path = sandbox.root.join("schemas/.checksums.sha256");

    let original_manifest = fs::read_to_string(&manifest_path).unwrap();

    let lines: Vec<&str> = original_manifest.lines().collect();
    assert!(!lines.is_empty());
    let mut modified_lines = lines.clone();
    let first_line = lines[0];
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    let corrupted_first = format!(
        "0000000000000000000000000000000000000000000000000000000000000000  {}",
        parts[1]
    );
    modified_lines[0] = &corrupted_first;
    fs::write(&manifest_path, modified_lines.join("\n") + "\n").unwrap();

    let out = sandbox.run_script(&["--verify"], &[]);
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "Corrupted manifest checksum MUST fail --verify with exit code 1"
    );
    assert!(
        combined.contains("DRIFT DETECTED"),
        "Must flag DRIFT DETECTED when checksum in manifest is invalid"
    );

    let with_ghost_file = format!(
        "{}\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  schemas/ghost_schema.json\n",
        original_manifest.trim()
    );
    fs::write(&manifest_path, with_ghost_file).unwrap();

    let out_ghost = sandbox.run_script(&["--verify"], &[]);
    assert_eq!(
        out_ghost.status.code(),
        Some(1),
        "Manifest referencing nonexistent file MUST exit with code 1"
    );

    fs::write(&manifest_path, original_manifest).unwrap();
    let out_clean = sandbox.run_script(&["--verify"], &[]);
    assert!(
        out_clean.status.success(),
        "Restoring manifest must restore exit code 0"
    );
}

#[test]
fn test_missing_manifest_triggers_initial_creation_safely() {
    let sandbox = Sandbox::new("missing_manifest");
    let manifest_path = sandbox.root.join("schemas/.checksums.sha256");

    fs::remove_file(&manifest_path).unwrap();
    assert!(!manifest_path.exists());

    let out = sandbox.run_script(&["--verify"], &[]);
    assert!(
        out.status.success(),
        "Missing manifest triggers auto-generation and passes"
    );
    assert!(
        manifest_path.exists(),
        "Manifest must be regenerated on disk"
    );

    let new_manifest = fs::read_to_string(&manifest_path).unwrap();
    for &file in MANAGED_FILES {
        assert!(
            new_manifest.contains(file),
            "Regenerated manifest must contain {}",
            file
        );
    }
}

#[test]
fn test_offline_sync_network_failure_fallback_preserves_files() {
    let sandbox = Sandbox::new("offline_sync_netfail");

    let mock_bin_dir = sandbox.root.join("mock_bin");
    fs::create_dir_all(&mock_bin_dir).unwrap();
    let mock_curl = mock_bin_dir.join("curl");
    fs::write(
        &mock_curl,
        "#!/bin/sh\necho 'curl: (7) Failed to connect to host' >&2\nexit 7\n",
    )
    .unwrap();
    let mut perms = fs::metadata(&mock_curl).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&mock_curl, perms).unwrap();

    let mut original_contents = std::collections::HashMap::new();
    for &rel_path in MANAGED_FILES {
        let full_path = sandbox.root.join(rel_path);
        let content = fs::read_to_string(&full_path).unwrap();
        assert!(!content.is_empty());
        original_contents.insert(rel_path, content);
    }

    let current_path = std::env::var("PATH").unwrap_or_default();
    let new_path = format!("{}:{}", mock_bin_dir.display(), current_path);

    let out = sandbox.run_script(&["--sync"], &[("PATH", &new_path)]);
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    println!("Mock netfail sync output:\n{}", combined);

    assert!(
        combined.contains("Network request failed") || combined.contains("fallback"),
        "Must inform user that network request failed and fallback was used"
    );

    for &rel_path in MANAGED_FILES {
        let full_path = sandbox.root.join(rel_path);
        let current_content = fs::read_to_string(&full_path).unwrap();
        assert_eq!(
            &current_content,
            original_contents.get(rel_path).unwrap(),
            "File {} must be preserved exactly under network failure",
            rel_path
        );
    }

    let out_verify = sandbox.run_script(&["--verify"], &[]);
    assert!(
        out_verify.status.success(),
        "--verify must pass after offline sync fallback"
    );
}

#[test]
fn test_offline_sync_malformed_upstream_response_rejection() {
    let sandbox = Sandbox::new("offline_sync_malformed");

    let mock_bin_dir = sandbox.root.join("mock_bin");
    fs::create_dir_all(&mock_bin_dir).unwrap();
    let mock_curl = mock_bin_dir.join("curl");
    fs::write(
        &mock_curl,
        r#"#!/bin/sh
# If -o is passed, write HTML error to destination file
while [ "$#" -gt 0 ]; do
    if [ "$1" = "-o" ]; then
        echo "<html><head><title>502 Bad Gateway</title></head><body>502 Bad Gateway</body></html>" > "$2"
        exit 0
    fi
    shift
done
exit 0
"#,
    )
    .unwrap();
    let mut perms = fs::metadata(&mock_curl).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&mock_curl, perms).unwrap();

    let mut original_contents = std::collections::HashMap::new();
    for &rel_path in MANAGED_FILES {
        let full_path = sandbox.root.join(rel_path);
        let content = fs::read_to_string(&full_path).unwrap();
        original_contents.insert(rel_path, content);
    }

    let current_path = std::env::var("PATH").unwrap_or_default();
    let new_path = format!("{}:{}", mock_bin_dir.display(), current_path);

    let out = sandbox.run_script(&["--sync"], &[("PATH", &new_path)]);
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    println!("Mock malformed response output:\n{}", combined);

    assert!(
        combined.contains("invalid JSON") || combined.contains("preserving existing local version"),
        "Must detect malformed upstream response and preserve local version"
    );

    for &rel_path in MANAGED_FILES {
        let full_path = sandbox.root.join(rel_path);
        let current_content = fs::read_to_string(&full_path).unwrap();
        assert_eq!(
            &current_content,
            original_contents.get(rel_path).unwrap(),
            "File {} must not be overwritten by malformed upstream HTML",
            rel_path
        );
    }

    let out_verify = sandbox.run_script(&["--verify"], &[]);
    assert!(
        out_verify.status.success(),
        "--verify must succeed with preserved valid schemas"
    );
}

#[test]
fn test_manifest_with_comments_and_blank_lines() {
    let sandbox = Sandbox::new("manifest_comments");
    let manifest_path = sandbox.root.join("schemas/.checksums.sha256");

    let original_manifest = fs::read_to_string(&manifest_path).unwrap();

    let mut modified = String::new();
    modified.push_str("# Canonical Checksum Manifest for ATProto OAuth\n");
    modified.push_str("# Automatically generated - DO NOT EDIT MANUALLY\n\n");
    for line in original_manifest.lines() {
        modified.push_str(line);
        modified.push_str("\n\n");
    }
    modified.push_str("# End of manifest\n");

    fs::write(&manifest_path, &modified).unwrap();

    let out = sandbox.run_script(&["--verify"], &[]);
    assert!(
        out.status.success(),
        "--verify must gracefully ignore comments and blank lines in manifest"
    );
}

#[test]
fn test_manifest_tab_and_whitespace_formatting_handling() {
    let sandbox = Sandbox::new("manifest_whitespace");
    let manifest_path = sandbox.root.join("schemas/.checksums.sha256");

    let original_manifest = fs::read_to_string(&manifest_path).unwrap();

    let mut whitespace_manifest = String::new();
    for line in original_manifest.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 2 {
            whitespace_manifest.push_str(&format!("{}\t\t{}\n", parts[0], parts[1]));
        }
    }
    fs::write(&manifest_path, &whitespace_manifest).unwrap();

    let out = sandbox.run_script(&["--verify"], &[]);
    assert!(
        out.status.success(),
        "--verify must handle tabs and irregular whitespace in manifest"
    );
}

#[test]
fn test_multiple_simultaneous_file_corruptions_reported() {
    let sandbox = Sandbox::new("multiple_corruptions");

    let file1 = sandbox.root.join(MANAGED_FILES[0]);
    let file2 = sandbox.root.join(MANAGED_FILES[3]);

    fs::write(&file1, "{\"corrupted\": 1}").unwrap();
    fs::write(&file2, "{\"corrupted\": 2}").unwrap();

    let out = sandbox.run_script(&["--verify"], &[]);
    assert_eq!(out.status.code(), Some(1));

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(
        combined.contains(MANAGED_FILES[0]),
        "Error output must identify first corrupted file {}",
        MANAGED_FILES[0]
    );
    assert!(
        combined.contains(MANAGED_FILES[3]),
        "Error output must identify second corrupted file {}",
        MANAGED_FILES[3]
    );
}

#[test]
fn test_cli_argument_handling_and_exit_codes() {
    let sandbox = Sandbox::new("cli_args");

    let out_help = sandbox.run_script(&["--help"], &[]);
    assert!(out_help.status.success());
    let out_h = sandbox.run_script(&["-h"], &[]);
    assert!(out_h.status.success());

    let out_invalid = sandbox.run_script(&["--nonexistent-flag"], &[]);
    assert_eq!(out_invalid.status.code(), Some(1));

    let out_bogus = sandbox.run_script(&["bogus_command"], &[]);
    assert_eq!(out_bogus.status.code(), Some(1));
}

#[test]
fn test_generate_manifest_idempotence_and_hash_stability() {
    let sandbox = Sandbox::new("manifest_idempotence");
    let manifest_path = sandbox.root.join("schemas/.checksums.sha256");

    let out1 = sandbox.run_script(&["--generate-manifest"], &[]);
    assert!(out1.status.success());
    let content1 = fs::read_to_string(&manifest_path).unwrap();

    let out2 = sandbox.run_script(&["--generate-manifest"], &[]);
    assert!(out2.status.success());
    let content2 = fs::read_to_string(&manifest_path).unwrap();

    assert_eq!(
        content1, content2,
        "Manifest generation must be deterministic and idempotent"
    );
}

#[test]
fn test_runtime_ast_validator_deep_nesting_and_unusual_types() {
    let sample_lexicon = json!({
        "lexicon": 1,
        "id": "com.example.testProcedure",
        "defs": {
            "main": {
                "type": "procedure",
                "input": {
                    "schema": {
                        "type": "object",
                        "required": ["nested_record", "custom_open_field"],
                        "properties": {
                            "nested_record": {
                                "type": "object",
                                "properties": {
                                    "inner_data": { "type": "string" }
                                }
                            },
                            "custom_open_field": {
                                "type": "unknown"
                            },
                            "array_of_open": {
                                "type": "array",
                                "items": {
                                    "type": "unknown"
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    fn normalize_lex(val: &Value) -> Value {
        match val {
            Value::Object(map) => {
                let mut new_map = serde_json::Map::new();
                for (k, v) in map {
                    if k == "type" && v == "unknown" {
                        continue;
                    }
                    new_map.insert(k.clone(), normalize_lex(v));
                }
                Value::Object(new_map)
            }
            Value::Array(arr) => Value::Array(arr.iter().map(normalize_lex).collect()),
            other => other.clone(),
        }
    }

    let input_schema = &sample_lexicon["defs"]["main"]["input"]["schema"];
    let normalized = normalize_lex(input_schema);
    let validator = jsonschema::validator_for(&normalized).unwrap();

    let valid_instances = vec![
        json!({
            "nested_record": { "inner_data": "ok" },
            "custom_open_field": "any string",
            "array_of_open": [1, "two", true, null, {"k": "v"}]
        }),
        json!({
            "nested_record": {},
            "custom_open_field": { "arbitrary_nested": { "deep": 42 } },
            "array_of_open": []
        }),
        json!({
            "nested_record": { "inner_data": "hello" },
            "custom_open_field": 123456
        }),
    ];

    for instance in valid_instances {
        assert!(
            validator.is_valid(&instance),
            "Instance should pass validation: {:?}",
            instance
        );
    }

    let invalid_missing = json!({
        "nested_record": { "inner_data": "ok" }
    });
    assert!(!validator.is_valid(&invalid_missing));

    let invalid_type = json!({
        "nested_record": 999,
        "custom_open_field": true
    });
    assert!(!validator.is_valid(&invalid_type));
}

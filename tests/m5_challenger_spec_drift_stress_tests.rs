//! Deterministic specification integrity and upstream drift tests.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

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

const UPSTREAM_FILES: &[&str] = &[
    "lexicons/com/atproto/identity/resolveHandle.json",
    "lexicons/com/atproto/server/createSession.json",
    "lexicons/com/atproto/server/refreshSession.json",
];

const LIVE_DERIVED_PATH: &str = "schemas/atproto_client_metadata.json";
const LIVE_SOURCE_FIXTURE: &[u8] = b"authoritative AT Protocol OAuth page fixture\n";

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> Self {
        let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let unique = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let root = repository
            .join("target/tmp-spec-tests")
            .join(format!("{name}-{}-{unique}", std::process::id()));
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }
        fs::create_dir_all(&root).unwrap();
        for directory in ["lexicons", "schemas", "scripts"] {
            copy_tree(&repository.join(directory), &root.join(directory));
        }
        Self { root }
    }

    fn run(&self, argument: &str, environment: &[(&str, &Path)]) -> Output {
        let mut command = Command::new("bash");
        command
            .arg(self.root.join("scripts/sync_specs.sh"))
            .arg(argument)
            .current_dir(&self.root);
        for (name, value) in environment {
            command.env(name, value);
        }
        command.output().unwrap()
    }

    fn run_with_path_prefix(&self, argument: &str, prefix: &Path) -> Output {
        let current_path = env::var_os("PATH").unwrap_or_default();
        let path = env::join_paths(
            std::iter::once(prefix.to_path_buf()).chain(env::split_paths(&current_path)),
        )
        .unwrap();
        Command::new("bash")
            .arg(self.root.join("scripts/sync_specs.sh"))
            .arg(argument)
            .current_dir(&self.root)
            .env("PATH", path)
            .output()
            .unwrap()
    }

    fn fixture(&self) -> PathBuf {
        let fixture = self.root.join("upstream-fixture");
        for path in UPSTREAM_FILES {
            let destination = fixture.join(path);
            fs::create_dir_all(destination.parent().unwrap()).unwrap();
            fs::copy(self.root.join(path), destination).unwrap();
        }
        let source = fixture.join(format!("{LIVE_DERIVED_PATH}.source"));
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::write(source, LIVE_SOURCE_FIXTURE).unwrap();
        update_provenance_digest(
            &self.root,
            LIVE_DERIVED_PATH,
            "upstream_sha256",
            &sha256_hex(LIVE_SOURCE_FIXTURE),
        );
        fixture
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.path().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    skyauth::crypto::sha256_digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn update_provenance_digest(root: &Path, path: &str, field: &str, digest: &str) {
    let provenance_path = root.join("schemas/provenance.json");
    let mut provenance: Value =
        serde_json::from_slice(&fs::read(&provenance_path).unwrap()).unwrap();
    let artifact = provenance["artifacts"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|artifact| artifact["local_path"] == path)
        .unwrap();
    artifact[field] = Value::String(digest.to_string());
    fs::write(
        provenance_path,
        serde_json::to_vec_pretty(&provenance).unwrap(),
    )
    .unwrap();
}

fn output_diagnostics(output: &Output) -> String {
    format!(
        "status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_success(output: &Output) {
    assert!(output.status.success(), "{}", output_diagnostics(output));
}

fn assert_status(output: &Output, expected: i32) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "{}",
        output_diagnostics(output)
    );
}

#[test]
fn local_verify_is_offline_and_passes_clean_copy() {
    let sandbox = Sandbox::new("offline-verify");
    let bin = sandbox.root.join("offline-bin");
    fs::create_dir_all(&bin).unwrap();
    let curl = bin.join("curl");
    fs::write(&curl, "#!/usr/bin/env bash\nexit 99\n").unwrap();
    #[cfg(unix)]
    fs::set_permissions(&curl, fs::Permissions::from_mode(0o755)).unwrap();
    let output = sandbox.run_with_path_prefix("--verify", &bin);
    assert_success(&output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("local specification integrity"));
}

#[test]
fn every_managed_artifact_tamper_is_rejected() {
    let sandbox = Sandbox::new("tamper");
    for path in MANAGED_FILES {
        let file = sandbox.root.join(path);
        let original = fs::read(&file).unwrap();
        let mut value: Value = serde_json::from_slice(&original).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("fixtureChange".to_string(), json!(true));
        fs::write(&file, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        let output = sandbox.run("--verify", &[]);
        assert_status(&output, 1);
        fs::write(file, original).unwrap();
    }
}

#[test]
fn every_missing_artifact_is_rejected() {
    let sandbox = Sandbox::new("missing");
    for path in MANAGED_FILES {
        let file = sandbox.root.join(path);
        let original = fs::read(&file).unwrap();
        fs::remove_file(&file).unwrap();
        let output = sandbox.run("--verify", &[]);
        assert_status(&output, 1);
        fs::write(file, original).unwrap();
    }
}

#[test]
fn missing_or_corrupt_manifest_is_not_regenerated_by_verify() {
    let sandbox = Sandbox::new("manifest");
    let manifest = sandbox.root.join("schemas/.checksums.sha256");
    fs::write(
        &manifest,
        format!("{}  {}\n", "0".repeat(64), MANAGED_FILES[0]),
    )
    .unwrap();
    let corrupt = sandbox.run("--verify", &[]);
    assert_status(&corrupt, 1);
    fs::remove_file(&manifest).unwrap();
    let missing = sandbox.run("--verify", &[]);
    assert_status(&missing, 1);
    assert!(!manifest.exists());
}

#[test]
fn controlled_upstream_fixture_detects_freshness_drift() {
    let sandbox = Sandbox::new("freshness");
    let fixture = sandbox.fixture();
    let clean = sandbox.run(
        "--check-upstream",
        &[("SKYAUTH_UPSTREAM_FIXTURE_DIR", &fixture)],
    );
    assert_success(&clean);

    let changed = fixture.join(UPSTREAM_FILES[0]);
    let mut value: Value = serde_json::from_slice(&fs::read(&changed).unwrap()).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("upstreamChange".to_string(), json!(true));
    fs::write(changed, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    let drift = sandbox.run(
        "--check-upstream",
        &[("SKYAUTH_UPSTREAM_FIXTURE_DIR", &fixture)],
    );
    assert_status(&drift, 1);
}

#[test]
fn live_derived_source_digest_detects_page_drift() {
    let sandbox = Sandbox::new("live-source-freshness");
    let fixture = sandbox.fixture();
    fs::write(
        fixture.join(format!("{LIVE_DERIVED_PATH}.source")),
        b"changed authoritative page fixture\n",
    )
    .unwrap();

    let output = sandbox.run(
        "--check-upstream",
        &[("SKYAUTH_UPSTREAM_FIXTURE_DIR", &fixture)],
    );
    assert_status(&output, 1);
    assert!(String::from_utf8_lossy(&output.stderr).contains("live specification source drift"));
}

#[test]
fn failed_sync_preserves_all_managed_state_atomically() {
    let sandbox = Sandbox::new("atomic-sync");
    let fixture = sandbox.fixture();
    fs::write(fixture.join(UPSTREAM_FILES[1]), b"not json").unwrap();
    let watched = MANAGED_FILES
        .iter()
        .copied()
        .chain(["schemas/provenance.json", "schemas/.checksums.sha256"])
        .map(|path| (path, fs::read(sandbox.root.join(path)).unwrap()))
        .collect::<BTreeMap<_, _>>();

    let output = sandbox.run("--sync", &[("SKYAUTH_UPSTREAM_FIXTURE_DIR", &fixture)]);
    assert!(!output.status.success(), "{}", output_diagnostics(&output));
    for (path, contents) in watched {
        assert_eq!(fs::read(sandbox.root.join(path)).unwrap(), contents);
    }
}

#[test]
fn manifest_generation_is_deterministic() {
    let sandbox = Sandbox::new("manifest-idempotence");
    let committed = fs::read(sandbox.root.join("schemas/.checksums.sha256")).unwrap();
    let first_run = sandbox.run("--generate-manifest", &[]);
    assert_success(&first_run);
    let first = fs::read(sandbox.root.join("schemas/.checksums.sha256")).unwrap();
    assert_eq!(first, committed);
    let second_run = sandbox.run("--generate-manifest", &[]);
    assert_success(&second_run);
    let second = fs::read(sandbox.root.join("schemas/.checksums.sha256")).unwrap();
    assert_eq!(first, second);
    let verified = sandbox.run("--verify", &[]);
    assert_success(&verified);
}

#[test]
fn manifest_generation_fails_without_replacing_a_valid_manifest() {
    let sandbox = Sandbox::new("manifest-failure");
    let manifest = sandbox.root.join("schemas/.checksums.sha256");
    let original = fs::read(&manifest).unwrap();
    fs::remove_file(sandbox.root.join(MANAGED_FILES[0])).unwrap();

    let output = sandbox.run("--generate-manifest", &[]);
    assert_status(&output, 1);
    assert_eq!(fs::read(manifest).unwrap(), original);
}

#[test]
fn generated_manifest_lists_exact_content_digests() {
    let sandbox = Sandbox::new("manifest-content");
    let output = sandbox.run("--generate-manifest", &[]);
    assert_success(&output);
    let contents = fs::read_to_string(sandbox.root.join("schemas/.checksums.sha256")).unwrap();
    let entries = contents
        .lines()
        .map(|line| {
            let (digest, path) = line.split_once("  ").unwrap();
            (path.to_string(), digest.to_string())
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(entries.len(), MANAGED_FILES.len());
    for path in MANAGED_FILES {
        let actual = sha256_hex(&fs::read(sandbox.root.join(path)).unwrap());
        assert_eq!(entries.get(*path), Some(&actual), "path={path}");
    }
}

#[test]
fn upstream_comparison_normalizes_both_documents() {
    let sandbox = Sandbox::new("normalized-upstream");
    let fixture = sandbox.fixture();
    let path = UPSTREAM_FILES[0];
    let file = sandbox.root.join(path);
    let value: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    let compact = serde_json::to_vec(&value).unwrap();
    fs::write(&file, &compact).unwrap();
    update_provenance_digest(&sandbox.root, path, "local_sha256", &sha256_hex(&compact));
    let generated = sandbox.run("--generate-manifest", &[]);
    assert_success(&generated);

    let checked = sandbox.run(
        "--check-upstream",
        &[("SKYAUTH_UPSTREAM_FIXTURE_DIR", &fixture)],
    );
    assert_success(&checked);
}

#[test]
fn commit_phase_failure_rolls_back_every_installed_file() {
    let sandbox = Sandbox::new("commit-rollback");
    let fixture = sandbox.fixture();
    let changed = fixture.join(UPSTREAM_FILES[0]);
    let mut value: Value = serde_json::from_slice(&fs::read(&changed).unwrap()).unwrap();
    value["description"] = Value::String("valid fixture update".to_string());
    fs::write(changed, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    let watched = MANAGED_FILES
        .iter()
        .copied()
        .chain(["schemas/provenance.json", "schemas/.checksums.sha256"])
        .map(|path| (path, fs::read(sandbox.root.join(path)).unwrap()))
        .collect::<BTreeMap<_, _>>();

    let output = sandbox.run(
        "--sync",
        &[
            ("SKYAUTH_UPSTREAM_FIXTURE_DIR", &fixture),
            ("SKYAUTH_SYNC_FAIL_AFTER_INSTALLS", Path::new("1")),
        ],
    );
    assert_status(&output, 1);
    for (path, contents) in watched {
        assert_eq!(
            fs::read(sandbox.root.join(path)).unwrap(),
            contents,
            "path={path}"
        );
    }
}

#[test]
fn command_line_contract_has_distinct_error_status() {
    let sandbox = Sandbox::new("cli");
    let help = sandbox.run("--help", &[]);
    assert_success(&help);
    let unknown = sandbox.run("--unknown", &[]);
    assert_status(&unknown, 2);
}

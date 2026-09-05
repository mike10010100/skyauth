//! Anti-Vacuity Tag Inventory Meta-Test.
//!
//! Parses the proof-harness source at test time and enforces a **bidirectional
//! exact match** between:
//!
//! 1. every `kani::cover!` / `anti_vacuity_cover!` tag literal present in the
//!    harness sources, and
//! 2. the required-tag lists consumed by `assert_all_covered` in the m6
//!    stress suite.
//!
//! This closes the drift class the independent reviews called out ("25 tags"
//! claimed in docs, ~13 live sites, several inside dead code): the tag count
//! is now a *generated, machine-checked* number — adding a cover to a proof
//! without adding it to the enforced inventory fails this test, and so does
//! listing a tag that no proof carries.
//!
//! Source files parsed (single source of truth):
//! - `src/verification/kani_harnesses.rs`

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    rust_2018_idioms
)]

use std::collections::BTreeSet;
use std::path::Path;

/// The harness sources scanned for cover-tag literals.
const HARNESS_SOURCES: &[&str] = &["src/verification/kani_harnesses.rs"];

/// The m6 test file that consumes `assert_all_covered` tag lists.
const M6_SOURCE: &str = "tests/m6_challenger_formal_verification_and_race_stress_tests.rs";

/// Extracts all string-literal tags in `cover!("tag"` or
/// `cover!(cond, "tag"` invocations (both `kani::cover!` and the
/// `anti_vacuity_cover!` wrapper, which expands to the former).
///
/// Implementation: find every `cover!(` occurrence and take the first
/// identifier-shaped string literal among its arguments (tags are the first
/// string in either argument order used by this codebase).
fn extract_cover_tags(source: &str) -> BTreeSet<String> {
    let mut tags = BTreeSet::new();
    let mut search_from = 0usize;
    while let Some(rel) = source[search_from..].find("cover!(") {
        let open = search_from + rel + "cover!(".len();
        // Paren-depth scan to the matching close: cover args contain nested
        // parens (e.g. `kani::cover!((s0 & 0xfe00) == 0xfc00, "tag")`).
        let bytes = source.as_bytes();
        let mut depth = 1usize;
        let mut close = open;
        while close < bytes.len() && depth > 0 {
            match bytes[close] {
                b'(' => depth += 1,
                b')' => depth -= 1,
                _ => {}
            }
            close += 1;
        }
        let args = &source[open..close.saturating_sub(1)];
        for part in args.split(',') {
            let part_trim = part.trim();
            if let Some(stripped) = part_trim
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
            {
                if is_tag_shaped(stripped) {
                    tags.insert(stripped.to_string());
                }
            }
        }
        search_from = close;
    }
    tags
}

/// Returns `true` for identifier-shaped tags (lowercase/digit/underscore).
fn is_tag_shaped(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Reads a repo-relative file, panicking with a clear message if missing.
fn read_repo_file(rel: &str) -> String {
    // CARGO_MANIFEST_DIR = crate root when running integration tests.
    let root = env!("CARGO_MANIFEST_DIR");
    let path = Path::new(root).join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read {rel} (resolved to {}): {e}", path.display()))
}

#[test]
fn test_cover_tag_inventory_matches_enforced_required_tags_exactly() {
    // 1. Inventory: every tag literal in the harness sources.
    let mut inventory: BTreeSet<String> = BTreeSet::new();
    for rel in HARNESS_SOURCES {
        inventory.extend(extract_cover_tags(&read_repo_file(rel)));
    }
    assert!(
        !inventory.is_empty(),
        "tag inventory is empty — parser or source layout changed; update HARNESS_SOURCES"
    );

    // 2. Enforced: every string literal in the m6 required-tag list arrays.
    let m6 = read_repo_file(M6_SOURCE);
    let enforced = extract_all_string_literals_in_required_tag_lists(&m6);
    assert!(
        !enforced.is_empty(),
        "required-tag lists not found in {M6_SOURCE} — parser or test layout changed"
    );

    // 3. Bidirectional exact match.
    let orphan: Vec<_> = inventory.difference(&enforced).cloned().collect();
    let missing: Vec<_> = enforced.difference(&inventory).cloned().collect();

    assert!(
        orphan.is_empty(),
        "cover tags present in proofs but NOT enforced by the m6 assert_all_covered lists \
         (unenforced reachability — add them to the required-tag arrays): {orphan:?}"
    );
    assert!(
        missing.is_empty(),
        "tags enforced by m6 assert_all_covered lists but NOT present in any proof harness \
         (stale inventory — remove them or restore the proof): {missing:?}"
    );
    assert_eq!(inventory, enforced, "tag inventory drift");
}

/// Extracts string literals from the `all_required_tags`-style arrays in the
/// m6 source: all `"..."` literals between `let all_required_tags` and the
/// closing `];`.
fn extract_all_string_literals_in_required_tag_lists(m6_source: &str) -> BTreeSet<String> {
    let mut tags = BTreeSet::new();
    let mut rest = m6_source;
    while let Some(start) = rest.find("let all_required_tags") {
        let after = &rest[start..];
        let Some(array_start) = after.find('[') else {
            break;
        };
        // Find the terminating `];` for this array.
        let Some(array_end_rel) = after[array_start..].find("];") else {
            break;
        };
        let array_body = &after[array_start..array_start + array_end_rel];
        let mut segment = array_body;
        while let Some(q) = segment.find('"') {
            let after_q = &segment[q + 1..];
            let Some(close) = after_q.find('"') else {
                break;
            };
            let literal = &after_q[..close];
            if literal
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                && !literal.is_empty()
            {
                tags.insert(literal.to_string());
            }
            segment = &after_q[close + 1..];
        }
        rest = &after[array_start + array_end_rel..];
    }
    tags
}

#[test]
fn test_inventory_parser_finds_known_tag() {
    // Parser self-check: a synthetic source must yield exactly its tags, in
    // either argument position, and skip non-tag string literals.
    let src = r#"
        kani::cover!(cond_a, "alpha_tag");
        kani::cover!("beta_tag");
        anti_vacuity_cover!("delta_tag", cond_b);
        let unrelated = "gamma_not_a_tag";
    "#;
    let tags = extract_cover_tags(src);
    assert_eq!(
        tags,
        BTreeSet::from([
            "alpha_tag".to_string(),
            "beta_tag".to_string(),
            "delta_tag".to_string(),
        ])
    );
}

#[test]
fn test_inventory_count_is_recorded_for_docs() {
    // The tag count that docs may quote — this test pins the number so any
    // change in proof coverage is a visible, reviewed diff.
    let mut inventory: BTreeSet<String> = BTreeSet::new();
    for rel in HARNESS_SOURCES {
        inventory.extend(extract_cover_tags(&read_repo_file(rel)));
    }
    // Pinned as of the Phase 3 expansion (docs reference this number). The
    // harnesses define tags in BOTH cfg branches (kani + deterministic), and
    // the inventory intentionally counts the union.
    assert_eq!(
        inventory.len(),
        57,
        "cover-tag count changed — update README/docs and this pin"
    );
}

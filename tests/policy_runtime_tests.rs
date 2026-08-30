#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used, missing_docs)]

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, SystemTime};

use proptest::prelude::*;
use skyauth::client::StoredStateEntry;
use skyauth::dpop::DPoPKey;
use skyauth::policy::{
    ipv4_is_restricted, ipv6_is_restricted, pkce_byte_allowed, pkce_length_allowed,
};
use skyauth::ssrf::{is_restricted_ipv4, is_restricted_ipv6};
use skyauth::store::{OAuthStateStore, OAuthStore};

fn state_entry(state: &str) -> StoredStateEntry {
    StoredStateEntry::builder(state, DPoPKey::generate())
        .client_id("https://app.example.com/client-metadata.json")
        .code_verifier("a".repeat(43))
        .issuer("https://issuer.example.com")
        .identity(Some("did:plc:abcdefgh".to_string()), None)
        .redirect_uri("https://app.example.com/callback")
        .pds_endpoint("https://pds.example.com")
        .token_endpoint("https://issuer.example.com/token")
        .scopes("atproto")
        .lifetime(SystemTime::now(), 300)
        .build()
        .unwrap()
}

proptest! {
    #[test]
    fn ipv4_adapter_matches_policy(a: u8, b: u8, c: u8, d: u8) {
        let address = Ipv4Addr::new(a, b, c, d);
        prop_assert_eq!(is_restricted_ipv4(&address), ipv4_is_restricted(a, b, c, d));
    }

    #[test]
    fn ipv6_adapter_matches_policy(segments: [u16; 8]) {
        let address = Ipv6Addr::new(
            segments[0], segments[1], segments[2], segments[3],
            segments[4], segments[5], segments[6], segments[7],
        );
        prop_assert_eq!(
            is_restricted_ipv6(&address),
            ipv6_is_restricted(
                segments[0], segments[1], segments[2], segments[3],
                segments[4], segments[5], segments[6], segments[7],
            )
        );
    }

    #[test]
    fn pkce_primitive_boundaries_match_ascii(byte: u8, len in 0usize..180) {
        prop_assert_eq!(
            pkce_byte_allowed(byte),
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
        );
        prop_assert_eq!(pkce_length_allowed(len), (43..=128).contains(&len));
    }
}

#[test]
fn state_store_has_exactly_one_concurrent_consumer() {
    let store = Arc::new(OAuthStateStore::new(Duration::from_secs(300)));
    store
        .insert_state_sync(
            "single-use".to_string(),
            state_entry("single-use"),
            Duration::from_secs(300),
        )
        .unwrap();
    let barrier = Arc::new(Barrier::new(200));
    let handles = (0..200)
        .map(|_| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                store.take_state_sync("single-use").is_some()
            })
        })
        .collect::<Vec<_>>();
    let winners = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .filter(|won| *won)
        .count();
    assert_eq!(winners, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_state_store_has_exactly_one_consumer() {
    let store = Arc::new(OAuthStateStore::new(Duration::from_secs(300)));
    store
        .insert_state(
            "async-single-use".to_string(),
            state_entry("async-single-use"),
            Duration::from_secs(300),
        )
        .await
        .unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(200));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..200 {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        tasks.spawn(async move {
            barrier.wait().await;
            store
                .take_state("async-single-use")
                .await
                .unwrap()
                .is_some()
        });
    }
    let mut winners = 0;
    while let Some(result) = tasks.join_next().await {
        if result.unwrap() {
            winners += 1;
        }
    }
    assert_eq!(winners, 1);
}

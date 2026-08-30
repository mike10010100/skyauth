//! Comprehensive Integration and Stress Tests for 64-Shard Partitioned OAuthStateStore.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, SystemTime};

use skyauth::client::StoredStateEntry;
use skyauth::dpop::DPoPKey;
use skyauth::store::{OAuthStateStore, OAuthStore, DEFAULT_STATE_TTL, NUM_SHARDS};
use tokio_util::sync::CancellationToken;

fn create_test_state(state: &str, ttl_secs: u64) -> StoredStateEntry {
    StoredStateEntry::builder(state, DPoPKey::generate())
        .client_id("https://feed.example.com/client-metadata.json")
        .code_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        .issuer("https://auth.bsky.social")
        .identity(
            Some("did:plc:ragtjsm2j2vknq6tfur4vg6u".to_string()),
            Some("alice.bsky.social".to_string()),
        )
        .redirect_uri("https://feed.example.com/oauth/callback")
        .pds_endpoint("https://morel.us-east.host.bsky.network")
        .token_endpoint("https://auth.bsky.social/oauth/token")
        .scopes("atproto transition:generic")
        .lifetime(SystemTime::now(), ttl_secs.max(1))
        .build()
        .unwrap()
}

#[test]
fn test_sharded_store_shard_count_is_strictly_64() {
    let store = OAuthStateStore::default();
    assert_eq!(NUM_SHARDS, 64);
    assert_eq!(store.default_ttl(), DEFAULT_STATE_TTL);
    assert_eq!(store.total_entries(), 0);
    assert!(store.is_empty());
}

#[test]
fn test_deterministic_shard_distribution_across_64_shards() {
    let store = OAuthStateStore::default();
    let num_samples = 2000;
    let mut shard_hits = vec![0usize; NUM_SHARDS];
    let mut hit_shards = HashSet::new();

    for i in 0..num_samples {
        let key = format!("state_sample_key_{i}_{}", i * 17);
        let idx = store.shard_index(&key);
        assert!(idx < 64);
        shard_hits[idx] += 1;
        hit_shards.insert(idx);
    }

    // Assert that at least 60 of the 64 shards received items
    assert!(
        hit_shards.len() >= 60,
        "Expected at least 60/64 shards hit, but got {}",
        hit_shards.len()
    );

    // Assert that no single shard received an extreme overload (e.g. > 15% of all keys)
    let max_in_shard = *shard_hits.iter().max().unwrap_or(&0);
    let max_fraction = (max_in_shard as f64) / (num_samples as f64);
    assert!(
        max_fraction < 0.10,
        "Shard distribution too skewed: max shard had fraction {max_fraction:.3}"
    );
}

#[test]
fn test_single_use_atomic_consumption_50_threads() {
    let store = Arc::new(OAuthStateStore::default());
    let state_token = "single_use_race_target_token";
    let entry = create_test_state(state_token, 300);

    store
        .insert_state_sync(state_token.to_string(), entry, Duration::from_secs(300))
        .unwrap();
    assert_eq!(store.total_entries(), 1);

    let winner_count = Arc::new(AtomicUsize::new(0));
    let start_barrier = Arc::new(Barrier::new(50));
    let mut thread_handles = Vec::with_capacity(50);

    for thread_id in 0..50 {
        let s = Arc::clone(&store);
        let w = Arc::clone(&winner_count);
        let b = Arc::clone(&start_barrier);
        let key = state_token.to_string();

        thread_handles.push(
            std::thread::Builder::new()
                .name(format!("race-worker-{thread_id}"))
                .spawn(move || {
                    b.wait();
                    let res = s.take_state_sync(&key);
                    if res.is_some() {
                        w.fetch_add(1, Ordering::SeqCst);
                    }
                })
                .unwrap(),
        );
    }

    for h in thread_handles {
        h.join().unwrap();
    }

    assert_eq!(
        winner_count.load(Ordering::SeqCst),
        1,
        "CRITICAL INVARIANT: Exactly 1 out of 50 racing threads must successfully consume the state token"
    );
    assert_eq!(store.total_entries(), 0);
    assert!(store.take_state_sync(state_token).is_none());
}

#[test]
fn test_concurrent_multishard_high_throughput_100_threads() {
    let store = Arc::new(OAuthStateStore::default());
    let num_threads = 100;
    let ops_per_thread = 50;
    let start_barrier = Arc::new(Barrier::new(num_threads));
    let mut handles = Vec::with_capacity(num_threads);

    for t in 0..num_threads {
        let s = Arc::clone(&store);
        let b = Arc::clone(&start_barrier);
        handles.push(std::thread::spawn(move || {
            b.wait();
            for i in 0..ops_per_thread {
                let key = format!("state_thread_{t}_op_{i}");
                let state = create_test_state(&key, 60);

                // Insert
                s.insert_state_sync(key.clone(), state, Duration::from_secs(60))
                    .unwrap();

                // Contains check
                assert!(s.contains_state_sync(&key));

                // Take
                let consumed = s.take_state_sync(&key);
                assert!(consumed.is_some());
                assert_eq!(consumed.unwrap().state(), key);

                // Re-take must fail
                assert!(s.take_state_sync(&key).is_none());
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(store.total_entries(), 0);
}

#[test]
fn test_ttl_validation_and_pruning() {
    let store = OAuthStateStore::default();

    // Insert 10 active states
    for i in 0..10 {
        let key = format!("active_state_{i}");
        store
            .insert_state_sync(
                key.clone(),
                create_test_state(&key, 300),
                Duration::from_secs(300),
            )
            .unwrap();
    }

    // Zero-lifetime entries are rejected.
    for i in 0..15 {
        let key = format!("expired_state_{i}");
        assert!(store
            .insert_state_sync(key.clone(), create_test_state(&key, 300), Duration::ZERO,)
            .is_err());
    }

    assert_eq!(store.total_entries(), 10);

    // Active entries remain after pruning.
    let pruned = store.prune_expired_sync();
    assert_eq!(pruned, 0);
    assert_eq!(store.total_entries(), 10);

    // Second prune should evict 0
    assert_eq!(store.prune_expired_sync(), 0);
    assert_eq!(store.total_entries(), 10);

    // Clear store
    store.clear();
    assert_eq!(store.total_entries(), 0);
    assert!(store.is_empty());
}

#[tokio::test]
async fn test_oauth_store_trait_async_lifecycle() {
    let store = OAuthStateStore::default();
    let key = "async_trait_key_999";
    let entry = create_test_state(key, 120);

    // 1. Insert state
    store
        .insert_state(key.to_string(), entry.clone(), Duration::from_secs(120))
        .await
        .unwrap();

    // 2. Contains state
    assert!(store.contains_state(key).await.unwrap());
    assert!(!store.contains_state("non_existent_key").await.unwrap());

    // 3. Take state
    let taken = store.take_state(key).await.unwrap();
    assert!(taken.is_some());
    assert_eq!(taken.unwrap().state(), key);

    // 4. Repeated take returns None
    assert!(store.take_state(key).await.unwrap().is_none());
    assert!(!store.contains_state(key).await.unwrap());

    // 5. Prune on empty returns 0
    assert_eq!(store.prune_expired().await.unwrap(), 0);
}

#[tokio::test(start_paused = true)]
async fn test_background_pruner_task_lifecycle_and_cancellation() {
    let store = Arc::new(OAuthStateStore::default());
    let cancel_token = CancellationToken::new();

    // Insert expired items
    for i in 0..20 {
        let key = format!("bg_exp_{i}");
        store
            .insert_state_sync(
                key.clone(),
                create_test_state(&key, 1),
                Duration::from_millis(1),
            )
            .unwrap();
    }
    assert_eq!(store.total_entries(), 20);
    tokio::time::advance(Duration::from_millis(5)).await;

    // Spawn background pruner with short interval
    let mut pruner_handle =
        store.spawn_pruning_task(Duration::from_millis(15), cancel_token.clone());

    tokio::time::advance(Duration::from_millis(20)).await;
    tokio::task::yield_now().await;
    assert_eq!(store.total_entries(), 0);

    // Cancel token and join
    cancel_token.cancel();
    let res = pruner_handle.shutdown().await;
    assert!(res.is_ok());
}

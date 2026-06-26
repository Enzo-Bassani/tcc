//! HAIP §6.1 (FMT-6): a credential's status-list index must be **unique AND
//! unpredictable**. This test pins the verifiable invariants of
//! [`db::allocate_status_index`] — every allocated index is in `[0, size_bits)`
//! and pairwise-unique across many allocations. It deliberately does NOT assert
//! "not sequential" or any probabilistic property, which would be flaky.
//!
//! Requires `TEST_DATABASE_URL`; otherwise it skips cleanly (mirrors the other
//! DB-backed issuer tests).

mod common;

use std::collections::HashSet;

use issuer_backend::db;
use serde_json::json;
use uuid::Uuid;

const STATUS_LIST_SIZE_BITS: i32 = 131_072;

#[tokio::test]
async fn status_indices_are_unique_and_in_range() {
    let Some(app) = common::spawn().await else {
        return; // TEST_DATABASE_URL not set — harness printed a SKIP notice.
    };
    assert!(app.base.starts_with("http"), "app booted with a base URL");
    let pool = app.db;

    // A fresh, test-local status list so we never collide with app-issued credentials.
    let list_id = format!("test-status-{}", Uuid::new_v4());
    let vct = "https://example.test/diploma";

    // A real student is required for the issued_credentials FK.
    let student = db::student_by_sub(&pool, "alice")
        .await
        .unwrap()
        .expect("seeded student 'alice'");

    const N: usize = 300;
    let mut seen = HashSet::new();
    for _ in 0..N {
        let idx = db::allocate_status_index(&pool, &list_id, vct)
            .await
            .unwrap();
        assert!(
            (0..STATUS_LIST_SIZE_BITS).contains(&idx),
            "index {idx} out of range [0, {STATUS_LIST_SIZE_BITS})"
        );
        assert!(seen.insert(idx), "index {idx} was allocated twice");
        // Record the allocation so subsequent draws see it as taken (this is what
        // the real issuance path does via `insert_issued_credential`).
        db::insert_issued_credential(
            &pool,
            Uuid::new_v4(),
            student.id,
            vct,
            &list_id,
            idx,
            &json!({}),
        )
        .await
        .unwrap();
    }
    assert_eq!(seen.len(), N, "expected {N} distinct indices");
}

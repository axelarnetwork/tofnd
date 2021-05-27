#[cfg(feature = "malicious")]
use super::malicious_test_cases::MaliciousTestCase;
use crate::tests::TestCase;
use crate::tests::{run_test_cases, run_test_cases_with_restart};

use tracing_test::traced_test; // logs for tests

#[traced_test]
#[tokio::test]
async fn honest_test_cases() {
    run_test_cases(&generate_honest_cases()).await;
}

#[traced_test]
#[tokio::test]
async fn honest_test_cases_with_restart() {
    run_test_cases_with_restart(&generate_honest_cases()).await;
}

impl TestCase {
    pub(super) fn new(
        uid_count: usize,
        share_counts: Vec<u32>,
        threshold: usize,
        signer_indices: Vec<usize>,
    ) -> TestCase {
        let expected_crimes = vec![vec![]; uid_count];
        TestCase {
            uid_count,
            share_counts,
            threshold,
            signer_indices,
            expected_crimes,
        }
    }
}

#[rustfmt::skip] // skip formatting to make file more readable
pub(super) fn generate_honest_cases() -> Vec<TestCase> {
    vec![
        TestCase::new(4, vec![], 0, vec![0, 1, 2, 3]), // should initialize share_counts into [1,1,1,1,1]
        TestCase::new(5, vec![1, 1, 1, 1, 1], 3, vec![1, 4, 2, 3]), // 1 share per uid
        TestCase::new(5, vec![1, 2, 1, 3, 2], 6, vec![1, 4, 2, 3]), // multiple shares per uid
        TestCase::new(1, vec![1], 0, vec![0]),         // trivial case
        // TestCase::new(5, vec![1,2,3,4,20], 27, vec![0, 1, 4, 3, 2]), // Create a malicious party
    ]
}
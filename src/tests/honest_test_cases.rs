use crate::tests::TestCase;
use crate::tests::{run_restart_recover_test_cases, run_restart_test_cases, run_test_cases};

#[cfg(feature = "malicious")]
use super::malicious::MaliciousData;

use crate::proto::message_out::CriminalList;

use tracing_test::traced_test; // logs for tests

fn set_up_logs() {
    use tracing::Level;
    // set up environment variable for log level
    // set up an event subscriber for logs
    tracing_subscriber::fmt()
        // .with_env_filter("tofnd=info,[Keygen]=info")
        .with_max_level(Level::DEBUG)
        // .json()
        // .with_ansi(atty::is(atty::Stream::Stdout))
        // .without_time()
        // .with_target(false)
        // .with_current_span(false)
        .init();
}

// #[traced_test]
#[tokio::test]
async fn honest_test_cases() {
    set_up_logs();
    run_test_cases(&generate_honest_cases()).await;
}

#[traced_test]
#[tokio::test]
async fn honest_test_cases_with_restart() {
    run_restart_test_cases(&generate_honest_cases()).await;
}

#[traced_test]
#[tokio::test]
async fn honest_test_cases_with_restart_recover() {
    run_restart_recover_test_cases(&generate_honest_cases()).await;
}

impl TestCase {
    pub(super) fn new(
        uid_count: usize,
        share_counts: Vec<u32>,
        threshold: usize,
        signer_indices: Vec<usize>,
    ) -> TestCase {
        TestCase {
            uid_count,
            share_counts,
            threshold,
            signer_indices,
            expected_keygen_faults: CriminalList::default(),
            expected_sign_faults: CriminalList::default(),
            #[cfg(feature = "malicious")]
            malicious_data: MaliciousData::empty(uid_count),
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

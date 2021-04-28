pub(super) struct TestCase {
    pub(super) uid_count: usize,
    pub(super) share_counts: Vec<u32>,
    pub(super) threshold: usize,
    pub(super) signer_indices: Vec<usize>,
    pub(super) criminal_list: Vec<usize>,
}

impl TestCase {
    pub(super) fn new(
        uid_count: usize,
        share_counts: Vec<u32>,
        threshold: usize,
        signer_indices: Vec<usize>,
    ) -> TestCase {
        let criminal_list = vec![];
        TestCase {
            uid_count,
            share_counts,
            threshold,
            signer_indices,
            criminal_list,
        }
    }
}

#[rustfmt::skip] // skip formatting to make file more readable
pub(super) fn generate_test_cases() -> Vec<TestCase> {
    vec![
        TestCase::new(4, vec![], 0, vec![0, 1, 2, 3]), // should initialize share_counts into [1,1,1,1,1]
        TestCase::new(5, vec![1, 1, 1, 1, 1], 3, vec![1, 4, 2, 3]), // 1 share per uid
        TestCase::new(5, vec![1, 2, 1, 3, 2], 6, vec![1, 4, 2, 3]), // multiple shares per uid
        TestCase::new(1, vec![1], 0, vec![0]),         // trivial case
        // TestCase::new(5, vec![1,2,3,4,20], 27, vec![0, 1, 4, 3, 2]), // Create a malicious party
    ]
}

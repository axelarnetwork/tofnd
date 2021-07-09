use super::map_tofnd_to_tofn_idx;

// KeygenInitSanitized is also needed by recovery module
pub struct KeygenInitSanitized {
    pub new_key_uid: String,
    pub party_uids: Vec<String>,
    pub party_share_counts: Vec<usize>,
    pub my_index: usize,
    pub threshold: usize,
}

impl KeygenInitSanitized {
    pub(super) fn my_shares_count(&self) -> usize {
        self.party_share_counts[self.my_index] as usize
    }
}

pub struct Context {
    pub uids: Vec<String>,
    pub share_counts: Vec<usize>,
    pub threshold: usize,
    pub tofnd_index: usize,
    pub tofnd_subindex: usize,
    pub nonce: String,
}

impl Context {
    // TODO: tofn_index = my_starting_tofn_index + my_tofnd_subindex,
    pub fn new(
        keygen_init: &KeygenInitSanitized,
        tofnd_index: usize,
        tofnd_subindex: usize,
    ) -> Self {
        Context {
            uids: keygen_init.party_uids.clone(),
            share_counts: keygen_init.party_share_counts.clone(),
            threshold: keygen_init.threshold,
            tofnd_index,
            tofnd_subindex,
            nonce: keygen_init.new_key_uid.clone(),
        }
    }

    pub fn tofn_index(&self) -> usize {
        map_tofnd_to_tofn_idx(self.tofnd_index, self.tofnd_subindex, &self.share_counts)
    }

    pub fn total_share_count(&self) -> usize {
        self.share_counts.iter().sum()
    }

    pub fn nonce(&self) -> &[u8] {
        self.nonce.as_bytes()
    }

    pub fn log_info(&self) -> String {
        format!(
            "[{}] [uid:{}, share:{}/{}]",
            self.nonce,
            self.uids[self.tofnd_index],
            self.tofnd_subindex + 1,
            self.total_share_count(),
        )
    }
}

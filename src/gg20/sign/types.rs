use super::MessageDigest;
pub(super) struct SignInitSanitized {
    pub(super) new_sig_uid: String, // this is only used for logging
    // pub(super) key_uid: String,
    pub(super) participant_uids: Vec<String>,
    pub(super) participant_indices: Vec<usize>,
    pub(super) message_to_sign: MessageDigest,
}

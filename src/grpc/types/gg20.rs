use crate::grpc::types::common::TofndInfo;
use tofn::gg20::keygen::{GroupPublicInfo, SecretKeyShare, ShareSecretInfo};

use serde::{Deserialize, Serialize};
use tracing::{info, span, Level, Span};

/// `KeyShareKv` record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartyInfo {
    pub common: GroupPublicInfo,
    pub shares: Vec<ShareSecretInfo>,
    pub tofnd: TofndInfo,
}

impl PartyInfo {
    /// Get GroupPublicInfo and ShareSecretInfo from tofn to create PartyInfo
    /// Also needed in recovery
    pub fn get_party_info(
        secret_key_shares: Vec<SecretKeyShare>,
        uids: Vec<String>,
        share_counts: Vec<usize>,
        tofnd_index: usize,
    ) -> Self {
        // grap the first share to acquire common data
        let common = secret_key_shares[0].group().clone();

        // aggregate share data into a vector
        let shares = secret_key_shares
            .into_iter()
            .map(|share| share.share().clone())
            .collect();

        // add tofnd data
        let tofnd = TofndInfo {
            party_uids: uids,
            share_counts,
            index: tofnd_index,
        };

        PartyInfo {
            common,
            shares,
            tofnd,
        }
    }

    /// log PartyInfo state
    pub fn log_info(&self, session_id: &str, sign_span: Span) {
        let init_span = span!(parent: &sign_span, Level::INFO, "init");
        let _enter = init_span.enter();

        info!(
            "[uid:{}, shares:{}] starting Sign with [key: {}, (t,n)=({},{}), participants:{:?}",
            self.tofnd.party_uids[self.tofnd.index],
            self.tofnd.share_counts[self.tofnd.index],
            session_id,
            self.common.threshold(),
            self.tofnd.share_counts.iter().sum::<usize>(),
            self.tofnd.party_uids,
        );
    }
}

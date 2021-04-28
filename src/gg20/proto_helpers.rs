use tofn::protocol::{gg20::sign::SignOutput, CrimeType, Criminal};

use crate::proto;
use proto::message_out::criminal_list::criminal::CrimeType as ProtoCrimeType;
use proto::message_out::criminal_list::Criminal as ProtoCriminal;
use proto::message_out::sign_result::SignResultData::Criminals as ProtoCriminals;
use proto::message_out::sign_result::SignResultData::Signature as ProtoSignature;
use proto::message_out::CriminalList as ProtoCriminalList;

use super::protocol::map_tofn_to_tofnd_idx;

// convenience constructors
impl proto::MessageOut {
    pub(super) fn new_bcast(bcast: &[u8]) -> Self {
        Self::new_traffic("", bcast, true)
    }
    pub(super) fn new_p2p(receiver_id: &str, p2p: &[u8]) -> Self {
        Self::new_traffic(receiver_id, p2p, false)
    }
    pub(super) fn new_traffic(receiver_id: &str, msg: &[u8], is_broadcast: bool) -> Self {
        proto::MessageOut {
            data: Some(proto::message_out::Data::Traffic(proto::TrafficOut {
                to_party_uid: receiver_id.to_string(),
                payload: msg.to_vec(),
                is_broadcast,
            })),
        }
    }
    pub(super) fn new_keygen_result(result: &[u8]) -> Self {
        proto::MessageOut {
            data: Some(proto::message_out::Data::KeygenResult(result.to_vec())),
        }
    }
    pub(super) fn new_sign_result(
        participant_uids: &[String],
        all_share_counts: &[usize],
        result: SignOutput,
    ) -> Self {
        let result = match result {
            Ok(signature) => ProtoSignature(signature),
            Err(criminals) => ProtoCriminals(ProtoCriminalList::from(
                criminals,
                participant_uids,
                all_share_counts,
            )),
        };

        proto::MessageOut {
            data: Some(proto::message_out::Data::SignResult(
                proto::message_out::SignResult {
                    sign_result_data: Some(result),
                },
            )),
        }
    }
}

impl ProtoCriminalList {
    // can't impl From<Vec<Criminal>> because we need participant_uids :(
    fn from(
        criminals: Vec<Criminal>,
        participant_uids: &[String],
        participant_share_counts: &[usize],
    ) -> Self {
        // the Criminal::index inside `criminals` is the index of tofn sign participants.
        // tofnd keygen participants:           [A, B, C, D]
        // tofnd keygen share_counts:           [1, 2, 3, 4]
        // tofnd sign   participants:           [B, C, D], where C is a Criminal; this is given as [1, 2, 3] (indices to tofnd keygen participants)
        // tofn  sign   participants:           [B, B, C, C, C, D, D, D, D], tofn finds criminal indices [2, 3, 4]. We need to return `C`.
        //                                             ^  ^  ^
        // To convert tofn criminal indices into tofnd uids, we need to have a vec containing all share counts for sign participants
        // so that we can map `tofn_sign_index` to `tofnd_uid`
        let mut criminals: Vec<ProtoCriminal> = criminals
            .into_iter()
            .map(|c| {
                // TODO panic
                // TODO refactor so that map_tofn_to_tofnd_idx never fails
                let (criminal_index, _) = map_tofn_to_tofnd_idx(c.index, participant_share_counts)
                    .expect("failure to recover tofnd party index from tofn share index");
                ProtoCriminal {
                    party_uid: participant_uids[criminal_index].clone(),
                    crime_type: ProtoCrimeType::from(c.crime_type) as i32, // why `as i32`? https://github.com/danburkert/prost#enumerations
                }
            })
            .collect();
        criminals.dedup();
        Self { criminals }
    }
}

impl From<CrimeType> for ProtoCrimeType {
    fn from(crime_type: CrimeType) -> Self {
        match crime_type {
            CrimeType::Malicious => Self::Malicious,
            CrimeType::NonMalicious => Self::NonMalicious,
        }
    }
}

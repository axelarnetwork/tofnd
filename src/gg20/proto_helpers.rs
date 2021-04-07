use tofn::protocol::{gg20::sign::SignOutput, CrimeType, Criminal};

use crate::proto;
use proto::message_out::criminal_list::criminal::CrimeType as ProtoCrimeType;
use proto::message_out::criminal_list::Criminal as ProtoCriminal;
use proto::message_out::sign_result::SignResultData::Criminals as ProtoCriminals;
use proto::message_out::sign_result::SignResultData::Signature as ProtoSignature;
use proto::message_out::CriminalList as ProtoCriminalList;

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
    pub(super) fn new_sign_result(participant_uids: &[String], result: SignOutput) -> Self {
        let result = match result {
            Ok(signature) => ProtoSignature(signature),
            Err(criminals) => ProtoCriminals(ProtoCriminalList::from(criminals, participant_uids)),
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
    fn from(criminals: Vec<Criminal>, participant_uids: &[String]) -> Self {
        Self {
            criminals: criminals
                .into_iter()
                .map(|c| ProtoCriminal {
                    party_uid: participant_uids[c.index].clone(),
                    crime_type: ProtoCrimeType::from(c.crime_type) as i32, // why `as i32`? https://github.com/danburkert/prost#enumerations
                })
                .collect(),
        }
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

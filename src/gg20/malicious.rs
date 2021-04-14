use crate::config::CONFIG;
use tofn::protocol::gg20::{keygen::SecretKeyShare, sign::ParamsError};

use tofn::protocol::gg20::sign::malicious::{BadSign, MaliciousType};

// get user sign
pub fn get_sign(
    my_secret_key_share: &SecretKeyShare,
    participant_indices: &[usize],
    msg_to_sign: &[u8],
) -> Result<BadSign, ParamsError> {
    let behaviour: &str = &CONFIG.behaviour;
    let victim = CONFIG.victim;

    // TODO: add all behaviours from MaliciousType
    let behaviour = match behaviour {
        "R1BadProof" => MaliciousType::R1BadProof { victim },
        _ => panic!("undefined behaviour"),
    };

    BadSign::new(
        my_secret_key_share,
        participant_indices,
        msg_to_sign,
        behaviour,
    )
}

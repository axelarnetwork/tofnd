use tofn::protocol::gg20::keygen::{validate_params, ECPoint, Keygen, SecretKeyShare};

use super::{proto, protocol, KeySharesKv};
use crate::TofndError;

// tonic cruft
use tokio::sync::mpsc;

pub(super) async fn execute_keygen(
    channel: mpsc::Receiver<Option<proto::TrafficIn>>,
    mut msg_sender: mpsc::Sender<Result<proto::MessageOut, tonic::Status>>,
    keygen_init: KeygenInitSanitized,
    mut kv: KeySharesKV,
    log_prefix: String,
) -> Result<(), TofndError> {

    // reserve new_key_uid in the KV store
    let key_uid_reservation = kv.reserve_key(keygen_init.new_key_uid).await?;

    // keygen execute
    let mut keygen = Keygen::new(
        keygen_init.party_uids.len(),
        keygen_init.threshold,
        keygen_init.my_index,
    )?;
    // unreserve new_key_uid on failure
    // too bad try blocks are not yet stable in Rust https://doc.rust-lang.org/nightly/unstable-book/language-features/try-blocks.html
    // instead I'll use the less-readable `and_then` https://doc.rust-lang.org/std/result/enum.Result.html#method.and_then
    let secret_key_share = protocol::execute_protocol(
        &mut keygen,
        channel,
        &mut msg_sender,
        &keygen_init.party_uids,
        &log_prefix,
    )
    .await
    .and_then(|_| {
        keygen
            .get_result()
            .ok_or_else(|| From::from("keygen output is `None`"))
    });
    if let Err(e) = secret_key_share {
        kv.unreserve_key(key_uid_reservation).await;
        return Err(e);
    }
    let secret_key_share = secret_key_share.unwrap();

    // store output in KV store
    let kv_data: (SecretKeyShare, Vec<String>) = (secret_key_share.clone(), keygen_init.party_uids);
    kv.put(key_uid_reservation, kv_data).await?;

    // serialize generated public key and send to client
    let pubkey = secret_key_share.ecdsa_public_key.get_element();
    let pubkey = pubkey.serialize(); // bitcoin-style serialization
    msg_sender
        .send(Ok(proto::MessageOut::new_keygen_result(&pubkey)))
        .await?;
    Ok(())
}

#[derive(Clone)]
pub struct KeygenInitSanitized {
    pub new_key_uid: String,
    pub party_uids: Vec<String>,
    pub my_index: usize,
    pub threshold: usize,
}

impl KeygenInitSanitized {
    // TODO: return actual share here
    pub fn my_shares(&self) -> usize {
        // self.party_uids[self.my_index]
        1
    }
}

pub fn keygen_sanitize_args(
    mut args: proto::KeygenInit,
) -> Result<KeygenInitSanitized, TofndError> {
    use std::convert::TryFrom;
    let my_index = usize::try_from(args.my_party_index)?;
    let threshold = usize::try_from(args.threshold)?;
    validate_params(args.party_uids.len(), threshold, my_index)?;

    // sort party ids to get a deterministic ordering
    // find my_index in the newly sorted list
    // check for duplicate party ids
    let old_len = args.party_uids.len();
    let my_uid = args.party_uids[my_index].clone();
    args.party_uids.sort_unstable();
    args.party_uids.dedup();
    if args.party_uids.len() != old_len {
        return Err(From::from("duplicate party ids detected"));
    }
    let my_index = args
        .party_uids
        .iter()
        .enumerate()
        .find(|(_index, id)| **id == my_uid)
        .ok_or("lost my uid after sorting uids")?
        .0;
    Ok(KeygenInitSanitized {
        new_key_uid: args.new_key_uid,
        party_uids: args.party_uids,
        my_index,
        threshold,
    })
}

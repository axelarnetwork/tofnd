//! This module handles the initialization of the Keygen protocol.

use futures_util::StreamExt;
use tracing::{info, span, Level, Span};

use tofn::protocol::gg20::keygen::validate_params;

use super::{proto, types::KeygenInitSanitized, Gg20Service, TofndError};
use crate::kv_manager::KeyReservation;

impl Gg20Service {
    // makes all needed assertions on incoming data, and create structures that are
    // needed to execute the protocol
    pub(super) async fn handle_keygen_init(
        &mut self,
        stream: &mut tonic::Streaming<proto::MessageIn>,
        keygen_span: Span,
    ) -> Result<(KeygenInitSanitized, KeyReservation), TofndError> {
        // receive message
        let msg_type = stream
            .next()
            .await
            .ok_or("keygen: stream closed by client without sending a message")??
            .data
            .ok_or("keygen: missing `data` field in client message")?;

        // check if message is of expected type
        let keygen_init = match msg_type {
            proto::message_in::Data::KeygenInit(k) => k,
            _ => return Err(From::from("Expected keygen init message")),
        };

        // sanitize arguments and reserve key
        let keygen_init = Self::keygen_sanitize_args(keygen_init)?;
        let key_uid_reservation = self
            .shares_kv
            .reserve_key(keygen_init.new_key_uid.clone())
            .await?;

        let init_span = span!(parent: &keygen_span, Level::INFO, "init");
        let _enter = init_span.enter();

        info!(
            "[uid:{}, shares:{}] starting Keygen with [key: {}, (t,n)=({},{}), participants:{:?}",
            keygen_init.party_uids[keygen_init.my_index],
            keygen_init.party_share_counts[keygen_init.my_index],
            keygen_init.new_key_uid,
            keygen_init.threshold,
            keygen_init.party_share_counts.iter().sum::<usize>(),
            keygen_init.party_uids,
        );

        Ok((keygen_init, key_uid_reservation))
    }

    // This function is pub(crate) because it is also needed in handle_recover
    // sanitize arguments of incoming message.
    // Example:
    // input for party 'a':
    //   args.party_uids = [c, b, a]
    //   args.party_share_counts = [1, 2, 3]
    //   args.my_party_index = 2
    //   args.threshold = 1
    // output for party 'a':
    //   keygen_init.party_uids = [a, b, c]           <- sorted array
    //   keygen_init.party_share_counts = [3, 2, 1] . <- sorted with respect to party_uids
    //   keygen_init.my_party_index = 0 .             <- index inside sorted array
    //   keygen_init.threshold = 1                    <- same as in input
    pub(crate) fn keygen_sanitize_args(
        args: proto::KeygenInit,
    ) -> Result<KeygenInitSanitized, TofndError> {
        // convert `u32`s to `usize`s
        use std::convert::TryFrom;
        let my_index = usize::try_from(args.my_party_index)?;
        let threshold = usize::try_from(args.threshold)?;
        let mut party_share_counts = args
            .party_share_counts
            .iter()
            .map(|i| usize::try_from(*i))
            .collect::<Result<Vec<usize>, _>>()?;

        // if share_counts are not provided, fall back to 1 share per party
        if party_share_counts.is_empty() {
            party_share_counts = vec![1; args.party_uids.len()];
        }

        // assert that uids and party shares are alligned
        if args.party_uids.len() != party_share_counts.len() {
            return Err(From::from(format!(
                "uid vector and share counts vector not alligned: {:?}, {:?}",
                args.party_uids, party_share_counts,
            )));
        }

        // sort uids and share counts
        // we need to sort uids and shares because the caller (axelar-core) does not
        // necessarily send the same vectors (in terms of order) to all tofnd instances.
        let (my_new_index, sorted_uids, sorted_share_counts) =
            sort_uids_and_shares(my_index, args.party_uids, party_share_counts)?;

        // get total number of shares of all parties
        let total_shares = sorted_share_counts.iter().sum();

        // invoke tofn validation
        validate_params(total_shares, threshold, my_index)?;

        Ok(KeygenInitSanitized {
            new_key_uid: args.new_key_uid,
            party_uids: sorted_uids,
            party_share_counts: sorted_share_counts,
            my_index: my_new_index,
            threshold,
        })
    }
}

// co-sort uids and shares with respect to uids an find new index
fn sort_uids_and_shares(
    my_index: usize,
    uids: Vec<String>,
    share_counts: Vec<usize>,
) -> Result<(usize, Vec<String>, Vec<usize>), TofndError> {
    // save my uid
    let my_uid = uids[my_index].clone();

    // create a vec of (uid, share_count) and sort it
    let mut pairs: Vec<(String, usize)> = uids.into_iter().zip(share_counts.into_iter()).collect();
    pairs.sort();

    // unzip vec and search for duplicates in uids
    let (mut sorted_uids, sorted_share_counts): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
    let old_len = sorted_uids.len();
    sorted_uids.dedup();
    if old_len != sorted_uids.len() {
        return Err(From::from("Error: party_uid vector contained a duplicate"));
    }

    // find my new index
    let my_index = sorted_uids
        .iter()
        .position(|x| x == &my_uid)
        .ok_or("Lost my uid after sorting uids")?;

    Ok((my_index, sorted_uids, sorted_share_counts))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sort_uids_and_shares() {
        let in_pairs = vec![
            ("c".to_owned(), 1),
            ("b".to_owned(), 2),
            ("a".to_owned(), 3),
        ];
        let out_pairs = vec![
            ("a".to_owned(), 3),
            ("b".to_owned(), 2),
            ("c".to_owned(), 1),
        ];

        let (in_keys, in_values): (Vec<String>, Vec<usize>) = in_pairs.into_iter().unzip();
        let (out_keys, out_values): (Vec<String>, Vec<usize>) = out_pairs.into_iter().unzip();

        let res = sort_uids_and_shares(0, in_keys.clone(), in_values.clone()).unwrap();
        assert_eq!((2, out_keys.clone(), out_values.clone()), res);
        let res = sort_uids_and_shares(1, in_keys.clone(), in_values.clone()).unwrap();
        assert_eq!((1, out_keys.clone(), out_values.clone()), res);
        let res = sort_uids_and_shares(2, in_keys, in_values).unwrap();
        assert_eq!((0, out_keys, out_values), res);

        let err_pairs = vec![("a".to_owned(), 1), ("a".to_owned(), 2)];
        let (err_keys, err_values): (Vec<String>, Vec<usize>) = err_pairs.into_iter().unzip();
        assert!(sort_uids_and_shares(0, err_keys.clone(), err_values.clone()).is_err());
        assert!(sort_uids_and_shares(1, err_keys, err_values).is_err());
    }
}

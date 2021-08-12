//! This module handles the initialization of the Keygen protocol.
//! A [KeygenInitSanitized] struct is created out of the raw incoming [proto::KeygenInit] message and a key is reserved inside the KvStore
//! If [proto::KeygenInit] fails to be parsed, a [TofndError] is returned

// tonic cruft
use futures_util::StreamExt;

// spans for logging
use tracing::Span;

// use tofn::protocol::gg20::keygen::validate_params;

use super::{
    proto,
    types::{KeygenInitSanitized, MAX_PARTY_SHARE_COUNT, MAX_TOTAL_SHARE_COUNT},
    Gg20Service, TofndError,
};
use crate::kv_manager::KeyReservation;

impl Gg20Service {
    /// Receives a message from the stream and tries to handle keygen init operations.
    /// On success, it reserves a key in the KVStrore and returns a sanitized struct ready to be used by the protocol.
    /// On failure, returns a TofndError and no changes are been made in the KvStore.
    pub(super) async fn handle_keygen_init(
        &self,
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

        // try to process incoming message
        let (keygen_init, key_reservation) = self.process_keygen_init(keygen_init).await?;

        // log keygen init state
        keygen_init.log_info(keygen_span);

        // return sanitized key and its KvStore reservation
        Ok((keygen_init, key_reservation))
    }

    // makes all needed assertions on incoming data, and create structures that are
    // needed for the execution of the protocol
    pub(super) async fn process_keygen_init(
        &self,
        keygen_init: proto::KeygenInit,
    ) -> Result<(KeygenInitSanitized, KeyReservation), TofndError> {
        // sanitize arguments
        let keygen_init = Self::keygen_sanitize_args(keygen_init)?;
        // reserve key
        let key_uid_reservation = match self
            .shares_kv
            .reserve_key(keygen_init.new_key_uid.clone())
            .await
        {
            Ok(reservation) => reservation,
            Err(err) => return Err(From::from(format!("Error: failed to reseve key: {}", err))),
        };

        // return sanitized keygen init and key reservation
        Ok((keygen_init, key_uid_reservation))
    }

    /// This function is pub(crate) because it is also needed in handle_recover
    /// sanitize arguments of incoming message.
    /// Example:
    /// input for party 'a':
    ///   args.party_uids = [c, b, a]
    ///   args.party_share_counts = [1, 2, 3]
    ///   args.my_party_index = 2
    ///   args.threshold = 1
    /// output for party 'a':
    ///   keygen_init.party_uids = [a, b, c]           <- sorted array
    ///   keygen_init.party_share_counts = [3, 2, 1] . <- sorted with respect to party_uids
    ///   keygen_init.my_party_index = 0 .             <- index inside sorted array
    ///   keygen_init.threshold = 1                    <- same as in input
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

        // check if my_index is inside party_uids
        if my_index >= args.party_uids.len() {
            return Err(From::from(format!(
                "my index is {}, but there are only {} parties.",
                my_index,
                args.party_uids.len(),
            )));
        }

        // if party's shares are above max, return error
        for party_share_count in &party_share_counts {
            if *party_share_count > MAX_PARTY_SHARE_COUNT {
                return Err(From::from(format!(
                    "party {} has {} shares, but maximum number of shares per party is {}.",
                    args.party_uids[my_index],
                    args.party_share_counts[my_index],
                    MAX_PARTY_SHARE_COUNT,
                )));
            }
        }

        let total_shares = party_share_counts.iter().sum::<usize>();
        if total_shares <= threshold {
            return Err(From::from(format!(
                "threshold is not satisfied: t = {}, total number of shares = {}",
                threshold, total_shares,
            )));
        } else if total_shares > MAX_TOTAL_SHARE_COUNT {
            return Err(From::from(format!(
                "total shares count is {}, but maximum number of share count is {}.",
                total_shares, MAX_PARTY_SHARE_COUNT,
            )));
        }

        // sort uids and share counts
        // we need to sort uids and shares because the caller does not necessarily
        // send the same vectors (in terms of order) to all tofnd instances.
        let (my_new_index, sorted_uids, sorted_share_counts) =
            sort_uids_and_shares(my_index, args.party_uids, party_share_counts)?;

        Ok(KeygenInitSanitized {
            new_key_uid: args.new_key_uid,
            party_uids: sorted_uids,
            party_share_counts: sorted_share_counts,
            my_index: my_new_index,
            threshold,
        })
    }
}

// helper function to co-sort uids and shares with respect to uids an find new index
fn sort_uids_and_shares(
    my_index: usize,
    uids: Vec<String>,
    share_counts: Vec<usize>,
) -> Result<(usize, Vec<String>, Vec<usize>), TofndError> {
    // save my uid
    let my_uid = uids
        .get(my_index)
        .ok_or("Error: Index out of bounds")?
        .clone();

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
        .ok_or("Error: Lost my uid after sorting uids")?;

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
        let res = sort_uids_and_shares(2, in_keys.clone(), in_values.clone()).unwrap();
        assert_eq!((0, out_keys, out_values), res);
        assert!(sort_uids_and_shares(3, in_keys, in_values).is_err()); // index out of bounds

        let err_pairs = vec![("a".to_owned(), 1), ("a".to_owned(), 2)];
        let (err_keys, err_values): (Vec<String>, Vec<usize>) = err_pairs.into_iter().unzip();
        assert!(sort_uids_and_shares(0, err_keys.clone(), err_values.clone()).is_err());
        assert!(sort_uids_and_shares(1, err_keys, err_values).is_err());
    }

    #[test]
    fn test_ok_keygen_sanitize_args() {
        // check sorting of parties and shares
        let raw_keygen_init = proto::KeygenInit {
            new_key_uid: "test_uid".to_owned(),
            party_uids: vec!["party_2".to_owned(), "party_1".to_owned()], // unsorted parties
            party_share_counts: vec![2, 1],                               // unsorted shares
            my_party_index: 1,                                            // index of "party_1"
            threshold: 1,
        };
        let sanitized_keygen_init = KeygenInitSanitized {
            new_key_uid: "test_uid".to_owned(), // should be same as in raw keygen init
            party_uids: vec!["party_1".to_owned(), "party_2".to_owned()], // parties should be sorted
            party_share_counts: vec![1, 2], // shares should be sorted with respect to parties
            my_index: 0,                    // index should track "party_1" in the sorted party_uids
            threshold: 1,                   // threshold should be the same
        };
        let res = Gg20Service::keygen_sanitize_args(raw_keygen_init).unwrap();
        assert_eq!(&res.new_key_uid, &sanitized_keygen_init.new_key_uid);
        assert_eq!(&res.party_uids, &sanitized_keygen_init.party_uids);
        assert_eq!(
            &res.party_share_counts,
            &sanitized_keygen_init.party_share_counts
        );
        assert_eq!(&res.my_index, &sanitized_keygen_init.my_index);
        assert_eq!(&res.threshold, &sanitized_keygen_init.threshold);

        // check empty share counts
        let raw_keygen_init = proto::KeygenInit {
            new_key_uid: "test_uid".to_owned(),
            party_uids: vec!["party_1".to_owned(), "party_2".to_owned()],
            party_share_counts: vec![], // empty share counts; should default to [1, 1]
            my_party_index: 0,
            threshold: 1,
        };
        let res = Gg20Service::keygen_sanitize_args(raw_keygen_init).unwrap();
        assert_eq!(&res.party_share_counts, &vec![1, 1]);

        let raw_keygen_init = proto::KeygenInit {
            new_key_uid: "test_uid".to_owned(),
            party_uids: vec!["party_1".to_owned()],
            party_share_counts: vec![MAX_PARTY_SHARE_COUNT as u32], // should be ok
            my_party_index: 0,
            threshold: 1,
        };
        let res = Gg20Service::keygen_sanitize_args(raw_keygen_init).unwrap();
        assert_eq!(&res.party_share_counts, &vec![MAX_PARTY_SHARE_COUNT]);

        let raw_keygen_init = proto::KeygenInit {
            new_key_uid: "test_uid".to_owned(),
            party_uids: vec!["party_1".to_owned(), "party_2".to_owned()],
            party_share_counts: vec![MAX_TOTAL_SHARE_COUNT as u32 - 1, 1], // should be ok
            my_party_index: 0,
            threshold: 1,
        };
        let res = Gg20Service::keygen_sanitize_args(raw_keygen_init).unwrap();
        assert_eq!(&res.party_share_counts, &vec![MAX_TOTAL_SHARE_COUNT - 1, 1]);
    }

    #[test]
    fn test_fail_keygen_sanitize_args() {
        let raw_keygen_init = proto::KeygenInit {
            new_key_uid: "test_uid".to_owned(),
            party_uids: vec!["party_1".to_owned(), "party_2".to_owned()],
            party_share_counts: vec![1, 1, 1], // counts are not the same number as parties
            my_party_index: 0,
            threshold: 1,
        };
        assert!(Gg20Service::keygen_sanitize_args(raw_keygen_init).is_err());

        let raw_keygen_init = proto::KeygenInit {
            new_key_uid: "test_uid".to_owned(),
            party_uids: vec!["party_1".to_owned(), "party_2".to_owned()],
            party_share_counts: vec![1, 1],
            my_party_index: 0,
            threshold: 2, // incorrect threshold
        };
        assert!(Gg20Service::keygen_sanitize_args(raw_keygen_init).is_err());

        let raw_keygen_init = proto::KeygenInit {
            new_key_uid: "test_uid".to_owned(),
            party_uids: vec!["party_1".to_owned(), "party_2".to_owned()],
            party_share_counts: vec![1, 1],
            my_party_index: 2, // index out of bounds
            threshold: 1,
        };
        assert!(Gg20Service::keygen_sanitize_args(raw_keygen_init).is_err());

        let raw_keygen_init = proto::KeygenInit {
            new_key_uid: "test_uid".to_owned(),
            party_uids: vec!["party_1".to_owned()],
            party_share_counts: vec![(MAX_PARTY_SHARE_COUNT + 1) as u32], // party has more than max number of shares
            my_party_index: 0,
            threshold: 1,
        };
        assert!(Gg20Service::keygen_sanitize_args(raw_keygen_init).is_err());

        let raw_keygen_init = proto::KeygenInit {
            new_key_uid: "test_uid".to_owned(),
            party_uids: vec!["party_1".to_owned(), "party_2".to_owned()],
            party_share_counts: vec![MAX_TOTAL_SHARE_COUNT as u32, 1], // total share count is more than max total shares
            my_party_index: 0,
            threshold: 1,
        };
        assert!(Gg20Service::keygen_sanitize_args(raw_keygen_init).is_err());
    }
}

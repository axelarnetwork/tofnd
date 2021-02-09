use super::*;

use mock::Party;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::Arc;
use tofnd_party::TofndParty;

// #[test]
#[tokio::test]
async fn start_servers() {
    let (share_count, threshold) = (3, 2);

    // prepare keygen init message
    let mut init = proto::KeygenInit {
        new_key_uid: "Gus-test-key".to_string(),
        party_uids: (0..share_count)
            .map(|i| format!("{}", (b'A' + i as u8) as char))
            .collect(),
        my_party_index: 0,
        threshold,
    };

    let mut tx_map: mock::MutexPartyMap = HashMap::with_capacity(share_count);

    // create parties and populate tx_map
    let mut parties = Vec::with_capacity(share_count);
    for i in 0..share_count {
        init.my_party_index = i32::try_from(i).unwrap();
        let new_party = TofndParty::new(&init).await;
        tx_map.insert(init.party_uids[i].clone(), new_party.get_tx().clone());
        parties.push(new_party);
    }
    let tx_map = Arc::new(tx_map);

    // execute parties and shut down
    let mut join_handles = Vec::<_>::with_capacity(parties.len());
    for mut p in parties {
        let tx_map = Arc::clone(&tx_map);
        p.set_party_map(tx_map);
        let handle = tokio::spawn(async move {
            p.execute().await;
            p.close().await;
        });
        join_handles.push(handle);
    }
    for h in join_handles {
        h.await.unwrap();
    }
}

mod mock;
mod tofnd_party;

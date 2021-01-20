use super::*;

use mock::{close_all, execute_all};
use tssd_party::TssdParty;

use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::Arc;
use tokio::sync::Mutex;

// #[test]
#[tokio::test]
async fn start_servers() {
    let (share_count, threshold) = (1, 0);
    let mut init = proto::KeygenInit {
        new_key_uid: "Gus-test-key".to_string(),
        party_uids: (0..share_count)
            .map(|i| format!("{}", (b'A' + i as u8) as char))
            .collect(),
        my_party_index: 0,
        threshold,
    };

    // let party_map = Arc::new(Mutex::new(HashMap::with_capacity(share_count)));
    let mut party_map: mock::MutexPartyMap = HashMap::with_capacity(share_count);

    for i in 0..share_count {
        init.my_party_index = i32::try_from(i).unwrap();
        let new_party = TssdParty::new(&init).await;
        party_map.insert(init.party_uids[i].clone(), Arc::new(Mutex::new(new_party)));
    }

    let party_map = Arc::new(party_map);
    for (_id, party) in party_map.iter() {
        party.lock().await.set_party_map(Arc::downgrade(&party_map));
    }

    // Arc::downgrade(&party_map)

    execute_all(Arc::clone(&party_map)).await;
    close_all(Arc::clone(&party_map)).await;

    // let mut party = tssd_party::TssdParty::new(&init, Arc::downgrade(&party_map)).await;

    // party.execute().await;

    // party.close().await;
}

mod mock;
mod tssd_party;

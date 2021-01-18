use super::*;

use mock::Party;

// #[test]
#[tokio::test]
async fn start_servers() {
    let transport = mock::TestDeliverer {};
    let init = proto::KeygenInit {
        new_key_uid: "test-key".to_string(),
        party_uids: vec!["Gus".to_string()],
        my_party_index: 0,
        threshold: 0,
    };
    let party = tssd_party::TssdParty::new(&init, &transport).await;

    println!("sleep for 2 secs...");
    tokio::time::delay_for(std::time::Duration::from_secs(2)).await;

    party.close().await;
}

mod mock;
mod tssd_party;

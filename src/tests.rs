use super::*;

use mock::{Party, Transport};

// #[test]
#[tokio::test]
async fn start_servers() {
    let (share_count, threshold) = (1, 0);
    let mut init = proto::KeygenInit {
        new_key_uid: "Gus's-test-key".to_string(),
        party_uids: (0..share_count)
            .map(|i| format!("{}", (b'A' + i as u8) as char))
            .collect(),
        my_party_index: 0,
        threshold,
    };

    let mut transport = mock::DefaultTransport::new();

    // for i in 0..share_count {
    //     init.my_party_index = i;
    //     transport.add_party(Box::new(
    //         tssd_party::TssdParty::new(&init, &transport).await,
    //     ));
    // }

    let mut party = tssd_party::TssdParty::new(&init, &transport).await;

    party.execute().await;

    party.close().await;
}

mod mock;
mod tssd_party;

//! mnemonic tests at the TofndParty level

use crate::mnemonic::Cmd;
use testdir::testdir;

use super::{tofnd_party::TofndParty, InitParty};

fn dummy_init_party() -> InitParty {
    InitParty::new(0)
}

#[should_panic]
#[tokio::test]
async fn mnemonic_existing() {
    let dir = testdir!();
    // dummy init data
    let init_party = dummy_init_party();
    // Existing should panic
    let _ = TofndParty::new(init_party, Cmd::Existing, &dir).await;
}

#[tokio::test]
async fn mnemonic_create() {
    let dir = testdir!();
    // dummy init data
    let init_party = dummy_init_party();
    // Create should succeed
    let _ = TofndParty::new(init_party, Cmd::Create, &dir).await;
}

#[should_panic]
#[tokio::test]
async fn mnemonic_export_panic() {
    let dir = testdir!();
    // dummy init data
    let init_party = dummy_init_party();
    // Export should fail
    let _ = TofndParty::new(init_party, Cmd::Export, &dir).await;
}

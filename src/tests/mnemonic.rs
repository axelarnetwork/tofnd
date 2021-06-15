//! mnemonic tests at the TofndParty level

use std::path::Path;

use super::{InitParty, MaliciousData, TofndParty};
use crate::{gg20::mnemonic::Cmd, tests::mock::Party};
use testdir::testdir;
use tracing_test::traced_test;

fn dummy_init_party() -> InitParty {
    InitParty::new(
        0,
        #[cfg(feature = "malicious")]
        &MaliciousData::empty(1),
    )
}

// copy "export" file to "import" file.
// File "export" constains the mnemonic created when the party was instantiated.
// Now that we restart the party, we need to import the mnemonic from "import" file.
fn copy_export_to_import(dir: &Path, party_index: usize) {
    let p = format!("test-key-{:02}", party_index);
    let path = dir.to_path_buf();
    let path = path.join(p);
    let export_path = format!("{}/export", path.to_str().unwrap());
    let import_path = format!("{}/import", path.to_str().unwrap());
    println!("Copying {} to {}", export_path, import_path);
    std::fs::copy(export_path, import_path).unwrap();
}

// check if export, export_2 and export_3 files exist and are the same
fn compare_export_files(dir: &Path, party_index: usize) -> bool {
    let p = format!("test-key-{:02}", party_index);
    let path = dir.to_path_buf();
    let path = path.join(p);

    let export_filename = format!("{}/export", path.to_str().unwrap());
    let export_2_filename = format!("{}/export_2", path.to_str().unwrap());
    let export_3_filename = format!("{}/export_3", path.to_str().unwrap());
    let export =
        std::fs::read_to_string(export_filename).expect("Something went wrong reading the file");
    let export_2 =
        std::fs::read_to_string(export_2_filename).expect("Something went wrong reading the file");
    let export_3 =
        std::fs::read_to_string(export_3_filename).expect("Something went wrong reading the file");
    export == export_2 && export_2 == export_3
}

#[tokio::test]
async fn mnemonic_noop() {
    let dir = testdir!();
    // dummy init data
    let init_party = dummy_init_party();
    // Noop should succeed
    let _ = TofndParty::new(init_party, Cmd::Noop, &dir).await;
}

#[tokio::test]
async fn mnemonic_create() {
    let dir = testdir!();
    // dummy init data
    let init_party = dummy_init_party();
    // Create should succeed
    let _ = TofndParty::new(init_party, Cmd::Create, &dir).await;
}

#[traced_test]
#[tokio::test]
async fn mnemonic_create_update_export() {
    let dir = testdir!();
    // create a mnemonic in "export" file
    {
        let p = TofndParty::new(dummy_init_party(), Cmd::Create, &dir).await;
        p.shutdown().await;
    }
    // copy "export" to "import"
    copy_export_to_import(&dir, 0);
    // update from "import" file, save existing to "export_1" file
    {
        let p = TofndParty::new(dummy_init_party(), Cmd::Update, &dir).await;
        p.shutdown().await;
    }
    // export to "export_3" file
    {
        let p = TofndParty::new(dummy_init_party(), Cmd::Export, &dir).await;
        p.shutdown().await;
    }

    assert!(compare_export_files(&dir, 0));
}

#[should_panic]
#[tokio::test]
async fn mnemonic_import_panic() {
    let dir = testdir!();
    // dummy init data
    let init_party = dummy_init_party();
    // import should fail
    let _ = TofndParty::new(init_party, Cmd::Import, &dir).await;
}

#[should_panic]
#[tokio::test]
async fn mnemonic_update_panic() {
    let dir = testdir!();
    // dummy init data
    let init_party = dummy_init_party();
    // update should fail
    let _ = TofndParty::new(init_party, Cmd::Update, &dir).await;
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

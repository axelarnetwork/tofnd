use crate::encrypted_sled::open;
use crate::password::Password;
use testdir::testdir;

#[test]
fn test_encrypted_sled() {
    let db_path = testdir!("encrypted_db");
    let db = open(
        &db_path,
        &Password("an example very very secret key.".to_string()),
    )
    .unwrap();

    // insert <key: value> -> returns None
    let res = db.insert("key", "value").unwrap();
    assert!(res.is_none());

    // get <key> -> returns <value>
    let res = db.get("key").unwrap();
    assert_eq!(res, Some(sled::IVec::from("value")));

    // insert <key: value2> -> returns old value <value>
    let res = db.insert("key", "value2").unwrap();
    assert!(res.is_some());

    // get <key: value2> -> returns new value <value2>
    let res = db.get("key").unwrap();
    assert_eq!(res, Some(sled::IVec::from("value2")));

    // get <key1: value2> -> returns None because key1 does not exist
    let res = db.get("key1").unwrap();
    assert!(res.is_none());

    // contains <key> -> returns Some(true) because key exists
    let res = db.contains_key("key").unwrap();
    assert!(res);

    // contains <key1> -> returns None because key1 does not exist
    let res = db.contains_key("key1").unwrap();
    assert!(!res);

    // remove <key> -> returns <value2> because key exists
    let res = db.remove("key").unwrap();
    assert_eq!(res, Some(sled::IVec::from("value2")));

    // remove <key> again -> returns None because key does not exist
    let res = db.remove("key").unwrap();
    assert_eq!(res, None);
}

#[test]
fn test_password() {
    let db_path = testdir!("test_password");

    let db = open(
        &db_path,
        &Password("an example very very secret key.".to_string()),
    );
    assert!(db.is_ok());
    drop(db);

    // try to open the kv store using a different password
    let db = open(
        &db_path,
        &Password("an example very very secret key!".to_string()), // replace '.' with '!'
    );
    assert!(matches!(
        db,
        Err(super::result::EncryptedDbError::WrongPassword)
    ));
}

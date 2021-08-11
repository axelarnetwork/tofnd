use super::*;

// testdir creates a test directory at $TMPDIR.
// Mac: /var/folders/v4/x_j3jj7d6ql4gjdf7b7jvjhm0000gn/T/testdir-of-$(USER)
// Linux: /tmp
// Windows: /data/local/tmp
// https://doc.rust-lang.org/std/env/fn.temp_dir.html#unix
use testdir::testdir;

fn clean_up(kv_name: &str, kv: sled::Db) {
    assert!(kv.flush().is_ok());
    std::fs::remove_dir_all(kv_name).unwrap();
}

impl PartialEq for KeyReservation {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

#[test]
fn reserve_success() {
    let kv_name = testdir!("reserve_success");
    let kv = sled::open(&kv_name).unwrap();

    let key: String = "key".to_string();
    assert_eq!(
        handle_reserve(&kv, key.clone()).unwrap(),
        KeyReservation { key: key.clone() }
    );

    // check if default value was stored
    // get bytes
    let default_reserv = kv.get(&key).unwrap().unwrap();
    // convert to value type
    assert!(default_reserv == DEFAULT_RESERV);

    clean_up(kv_name.to_str().unwrap(), kv);
}

#[test]
fn reserve_failure() {
    let kv_name = testdir!();
    let kv = sled::open(&kv_name).unwrap();

    let key: String = "key".to_string();
    handle_reserve(&kv, key.clone()).unwrap();
    // try reserving twice
    assert!(handle_reserve(&kv, key).is_err());

    clean_up(kv_name.to_str().unwrap(), kv);
}

#[test]
fn put_success() {
    let kv_name = testdir!();
    let kv = sled::open(&kv_name).unwrap();

    let key: String = "key".to_string();
    handle_reserve(&kv, key.clone()).unwrap();

    let value: String = "value".to_string();
    assert!(handle_put(&kv, KeyReservation { key }, value).is_ok());

    clean_up(kv_name.to_str().unwrap(), kv);
}

#[test]
fn put_failure_no_reservation() {
    let kv_name = testdir!();
    let kv = sled::open(&kv_name).unwrap();

    let key: String = "key".to_string();

    let value: String = "value".to_string();
    // try to add put a key without reservation and get an error
    assert!(handle_put(&kv, KeyReservation { key: key.clone() }, value).is_err());
    // check if key was inserted
    assert!(!kv.contains_key(&key).unwrap());

    clean_up(kv_name.to_str().unwrap(), kv);
}

#[test]
fn put_failure_put_twice() {
    let kv_name = testdir!();
    let kv = sled::open(&kv_name).unwrap();

    let key: String = "key".to_string();
    let value = "value";
    let value2 = "value2";

    handle_reserve(&kv, key.clone()).unwrap();
    handle_put(&kv, KeyReservation { key: key.clone() }, value).unwrap();

    assert!(handle_put(&kv, KeyReservation { key: key.clone() }, value2).is_err());

    // check if value was changed
    // get bytes
    let bytes = kv.get(&key).unwrap().unwrap();
    // convert to value type
    let v: &str = bincode::deserialize(&bytes).unwrap();
    // check current value with first assigned value
    assert!(v == value);

    clean_up(kv_name.to_str().unwrap(), kv);
}

#[test]
fn get_success() {
    let kv_name = testdir!();
    let kv = sled::open(&kv_name).unwrap();

    let key: String = "key".to_string();
    let value = "value";
    handle_reserve(&kv, key.clone()).unwrap();
    handle_put(&kv, KeyReservation { key: key.clone() }, value).unwrap();
    let res = handle_get::<String>(&kv, key);
    assert!(res.is_ok());
    let res = res.unwrap();
    assert_eq!(res, value);

    clean_up(kv_name.to_str().unwrap(), kv);
}

#[test]
fn get_failure() {
    let kv_name = testdir!();
    let kv = sled::open(&kv_name).unwrap();

    let key: String = "key".to_string();
    let res = handle_get::<String>(&kv, key);
    assert!(res.is_err());

    clean_up(kv_name.to_str().unwrap(), kv);
}

#[test]
fn test_exists() {
    let kv_name = testdir!();
    let kv = sled::open(&kv_name).unwrap();
    let key: String = "key".to_string();
    let value: String = "value".to_string();

    // exists should fail
    let exists = handle_exists(&kv, &key);
    assert!(exists.is_ok());
    assert!(!exists.unwrap()); // assert that the result is false

    // reserve key
    let reservation = handle_reserve(&kv, key.clone()).unwrap();

    // exists should succeed
    let exists = handle_exists(&kv, &key);
    assert!(exists.is_ok());
    assert!(exists.unwrap()); // check that the result is true

    // put key
    handle_put(&kv, reservation, value).unwrap();

    // exists should succeed
    let exists = handle_exists(&kv, &key);
    assert!(exists.is_ok());
    assert!(exists.unwrap()); // check that the result is true

    // remove key
    let _ = handle_remove::<String>(&kv, key.clone()).unwrap();

    // exists should fail
    let exists = handle_exists(&kv, &key);
    assert!(exists.is_ok());
    assert!(!exists.unwrap()); // check that the result is false
}

#[test]
fn remove_success() {
    let kv_name = testdir!();
    let kv = sled::open(&kv_name).unwrap();

    let key: String = "key".to_string();
    let value = "value";
    handle_reserve(&kv, key.clone()).unwrap();
    handle_put(&kv, KeyReservation { key: key.clone() }, value).unwrap();
    let res = handle_remove::<String>(&kv, key).unwrap();
    assert_eq!(res, value);
    clean_up(kv_name.to_str().unwrap(), kv);
}

#[test]
fn remove_failure() {
    let kv_name = testdir!();
    let kv = sled::open(&kv_name).unwrap();

    let key: String = "key".to_string();
    let res = handle_remove::<String>(&kv, key);
    assert!(res.is_err());

    clean_up(kv_name.to_str().unwrap(), kv);
}

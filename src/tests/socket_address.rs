//! socket address convertion tests

use crate::addr;

#[test]
fn test_ips() {
    let valid_ips = ["0.0.0.0", "127.0.0.1"];
    let invalid_ips = ["256.0.0.0"];
    let ports = [0, 65535]; // no need to check for invalid ports because 0 <= u16 <= 65535

    valid_ips.map(|a| ports.map(|p| assert!(addr(a, p).is_ok())));
    invalid_ips.map(|a| ports.map(|p| assert!(addr(a, p).is_err())));
}

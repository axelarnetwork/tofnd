mod mnemonic;
mod socket_address;
mod tofnd_party;

lazy_static::lazy_static! {
    static ref MSG_TO_SIGN: Vec<u8> = vec![42; 32];
}

const SLEEP_TIME: u64 = 1;
const MAX_TRIES: u32 = 3;
pub const DEFAULT_TEST_IP: &str = "0.0.0.0";
pub const DEFAULT_TEST_PORT: u16 = 0; // use port 0 and let the OS decide

// Struct to pass in TofndParty constructor.
struct InitParty {
    party_index: usize,
}

impl InitParty {
    fn new(party_index: usize) -> Self {
        Self { party_index }
    }
}

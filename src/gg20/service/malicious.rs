use tofn::gg20::{
    keygen::malicious::Behaviour as KeygenBehaviour, sign::malicious::Behaviour as SignBehaviour,
};

/// Behaviours are pub because config mod needs access
#[derive(Clone, Debug)]
pub struct Behaviours {
    pub keygen: KeygenBehaviour,
    pub sign: SignBehaviour,
}

use tonic;
// Go-style usage idiom:
// prefer `use tonic;` to `use tonic::Request;`
// so that we write `tonic::Request` instead of `Request`

use super::grpc as grpc;
// use grpc::gg20_server::{Gg20, Gg20Server};

use super::multi_party_ecdsa_common as multi_party_ecdsa_common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::convert::TryInto;
use uuid::Uuid;
use bincode;

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i as multi_party_ecdsa;

// baggage from multi_party_ecdsa
// use curv::{
//     arithmetic::traits::Converter,
//     cryptographic_primitives::{
//         proofs::sigma_dlog::DLogProof, secret_sharing::feldman_vss::VerifiableSS,
//     },
//     elliptic::curves::traits::{ECPoint, ECScalar},
//     BigInt, FE, GE,
// };
use curv;
use curv::elliptic::curves::traits::ECPoint; // see if you can figure out how to use fully qualified syntax to get rid of this use

const MAX_SHARE_COUNT : u16 = 10;

#[derive(Debug, PartialEq)]
enum KeygenStatus {
    Round1Done,
    Round2Done,
    Round3Done,
    // Round4Done,
}

// keygen state persisted to disk in the multi-party-ecdsa library
// TODO there's probably lots of duplication here; multi-party-ecdsa is a mess
#[derive(Debug)]
struct ZengoState {
    tn: multi_party_ecdsa::Parameters, // tn: threshold (t), share_count (n)

    // set in keygen_round1
    my_keys: multi_party_ecdsa::Keys,
    my_commit: multi_party_ecdsa::KeyGenBroadcastMessage1,
    my_reveal: multi_party_ecdsa::KeyGenDecommitMessage1,

    // set in keygen_round2
    other_commits: Vec<multi_party_ecdsa::KeyGenBroadcastMessage1>,
    // tn.share_count

    // set in keygen_round3
    other_reveals: Vec<multi_party_ecdsa::KeyGenDecommitMessage1>,
    other_ss_aes_keys: Vec<Vec<u8>>,
    my_secret_share: Option<curv::FE>,
    my_vss_scheme: Option<curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS>,
    // tn.threshold
}

#[derive(Debug)]
struct KeygenSessionState {
    status: KeygenStatus,
    state: ZengoState,
}

#[derive(Debug, Default)]
pub struct GG20Service {
    // TODO for now be conservative wrt thread safety
    // see https://tokio.rs/tokio/tutorial/shared-state
    keygen_sessions: Arc<Mutex<HashMap<Uuid, KeygenSessionState>>>,
}

#[tonic::async_trait]
impl grpc::gg20_server::Gg20 for GG20Service {
    async fn keygen_round1(
        &self,
        request: tonic::Request<grpc::KeygenRound1Request>,
    ) -> Result<tonic::Response<grpc::KeygenRound1Response>, tonic::Status> {
        println!("Got a request: {:?}", request);

        // do as much work as possible before locking self.keygen_sessions
        // TODO inserting a new session requires a lock on the whole HashMap
        //   by contrast, updating an existing session requires only a lock on that portion of the HashMap
        //   should we split session creation into another (faster) gRPC call?

        let session_id = Uuid::parse_str(&request.get_ref().session_id).unwrap(); // string
        // let session_id = Uuid::from_slice( &request.get_ref().session_id ).unwrap(); // bytes

        // create new key material, get responses for rounds 1, 2
        let my_keys = multi_party_ecdsa::Keys::create(0); // we don't use party index
        // TODO use create_safe_prime in production
        // let my_keys = multi_party_ecdsa::Keys::create_safe_prime(0);
        let (my_commit, my_reveal) =
            my_keys.phase1_broadcast_phase3_proof_of_correct_key_proof_of_correct_h1h2();

        let response = grpc::KeygenRound1Response {
            my_commit: bincode::serialize(&my_commit).unwrap(),
            my_paillier_key: bincode::serialize(&my_keys.ek).unwrap(),
        };

        // lock state
        let mut keygen_sessions = self.keygen_sessions.lock().unwrap();

        // session_id should be brand new
        if keygen_sessions.contains_key(&session_id) {
            return Err(tonic::Status::already_exists(format!(
                "session_id {:?} already exists",
                session_id
            )));
        }

        // save state
        keygen_sessions.insert(
            session_id,
            KeygenSessionState {
                status: KeygenStatus::Round1Done,
                state: ZengoState {
                    tn: multi_party_ecdsa::Parameters{ share_count: 0, threshold: 0}, // wish I had a Default...
                    my_keys: my_keys,
                    my_commit: my_commit,
                    my_reveal: my_reveal,
                    other_commits: Vec::default(), // wish I had a Default...
                    other_reveals: Vec::default(), // wish I had a Default...
                    other_ss_aes_keys: Vec::default(), // wish I had a Default...
                    my_secret_share: None, // wish I had a Default...
                    my_vss_scheme: None // wish I had a Default...
                },
            },
        );

        Ok(tonic::Response::new(response))
    }

    async fn keygen_round2(
        &self,
        request: tonic::Request<grpc::KeygenRound2Request>,
    ) -> Result<tonic::Response<grpc::KeygenRound2Response>, tonic::Status> {
        println!("Got a request: {:?}", request);

        let session_id = Uuid::parse_str(&request.get_ref().session_id).unwrap(); // string
        // let session_id = Uuid::from_slice( &request.get_ref().session_id ).unwrap(); // bytes

        // TODO the number and order of parties is dictated by whatever we find in request_commits
        // it's the responsibility of the caller to maintain this order in subsequent rounds

        // deserialize request_commits
        let request_commits = &request.get_ref().other_commits;
        let num_other_parties : u16 = request_commits.len().try_into().unwrap(); 
        if num_other_parties < 1 || num_other_parties >= MAX_SHARE_COUNT {
            return Err(tonic::Status::invalid_argument(format!("invalid number of parties: {:?}", num_other_parties+1)));
        }
        // TODO there should be a way to do this using unwrap_or_else
        // let other_commits : Vec<multi_party_ecdsa::KeyGenBroadcastMessage1> = request_commits.iter().map(|c| bincode::deserialize(&c).unwrap()).collect::<Vec<_>>();
        let mut other_commits : Vec<multi_party_ecdsa::KeyGenBroadcastMessage1> = Vec::with_capacity(num_other_parties.into());
        for request_commit in request_commits.iter() {
            other_commits.push(
                match bincode::deserialize(request_commit) {
                    Ok(r) => r,
                    Err(e) => {
                        return Err(tonic::Status::invalid_argument(format!("deserialization failure for other_commits: {:?}", e)));
                    }
                }
            );
        }

        // lock state
        let mut keygen_sessions = self.keygen_sessions.lock().unwrap();

        // session_id should exist and be in state Round1Done
        let mut keygen_session = match keygen_sessions.get_mut(&session_id) {
            Some(s) => s,
            None => {return Err(tonic::Status::not_found(format!("session_id {:?} not found", session_id)))},
        };
        if keygen_session.status != KeygenStatus::Round1Done {
            return Err(tonic::Status::failed_precondition(format!("incorrect status for session_id {:?}", session_id)));
        }

        let response = grpc::KeygenRound2Response {
            my_reveal: bincode::serialize(&keygen_session.state.my_reveal).unwrap(),
        };

        keygen_session.state.other_commits = other_commits;
        keygen_session.state.tn.share_count = num_other_parties + 1;
        keygen_session.status = KeygenStatus::Round2Done;

        Ok(tonic::Response::new(response))
    }

    async fn keygen_round3(
        &self,
        request: tonic::Request<grpc::KeygenRound3Request>,
    ) -> Result<tonic::Response<grpc::KeygenRound3Response>, tonic::Status> {
        println!("Got a request: {:?}", request);

        let session_id = Uuid::parse_str(&request.get_ref().session_id).unwrap(); // string
        // let session_id = Uuid::from_slice( &request.get_ref().session_id ).unwrap(); // bytes
        
        // deserialize request_reveals
        let request_reveals = &request.get_ref().other_reveals;
        if request_reveals.len() >= MAX_SHARE_COUNT.into() {
            return Err(tonic::Status::invalid_argument(format!("too many other_reveals: {:?}", request_reveals.len())));
        }
        // TODO repeated code from keygen_round2
        let mut other_reveals : Vec<multi_party_ecdsa::KeyGenDecommitMessage1> = Vec::with_capacity(request_reveals.len());
        for request_reveal in request_reveals.iter() {
            other_reveals.push(
                match bincode::deserialize(request_reveal) {
                    Ok(r) => r,
                    Err(e) => {
                        return Err(tonic::Status::invalid_argument(format!("deserialization failure for other_reveals: {:?}", e)));
                    }
                }
            );
        }

        // lock state
        let mut keygen_sessions = self.keygen_sessions.lock().unwrap();

        // TODO is it possible to get read-only access to session state?

        // ---
        // begin: check parameters

        // session_id should exist and be in state Round2Done
        let mut keygen_session = match keygen_sessions.get_mut(&session_id) {
            Some(s) => s,
            None => {return Err(tonic::Status::not_found(format!("session_id {:?} not found", session_id)))},
        };
        if keygen_session.status != KeygenStatus::Round2Done {
            return Err(tonic::Status::failed_precondition(format!("incorrect status for session_id {:?}", session_id)));
        }

        // verify correct number of parties
        let num_other_parties = other_reveals.len();
        if num_other_parties != keygen_session.state.other_commits.len() {
            return Err(tonic::Status::failed_precondition(format!("incorrect number of parties: {:?}", num_other_parties)));
        }

        // verify a reasonable threshold
        let threshold : u16 = request.get_ref().threshold.try_into().unwrap();
        // TODO do you need threshold+1 parties or threshold parties to sign?
        if threshold <= 0 || threshold >= keygen_session.state.tn.share_count {
            return Err(tonic::Status::failed_precondition(format!("invalid threshold: {:?}", threshold)));
        }

        // end: check parameters
        // ---

        // ---
        // begin: compute response

        // get secret shares

        // TODO zengo API should not need my_commit, my_reveal
        // TODO fix horrible Vec copying
        let mut all_reveals = other_reveals.clone();
        all_reveals.push(keygen_session.state.my_reveal.clone());
        let mut all_commits = keygen_session.state.other_commits.clone();
        all_commits.push(keygen_session.state.my_commit.clone());

        let (my_vss_scheme, mut all_secret_shares, _index) // zengo API should not return _index
            = match keygen_session.state.my_keys
            .phase1_verify_com_phase3_verify_correct_key_verify_dlog_phase2_distribute(
                &multi_party_ecdsa::Parameters{
                    share_count: keygen_session.state.tn.share_count,
                    threshold: threshold,
                },
                &all_reveals,
                &all_commits,
            )
            {
                Ok(r) => r,
                Err(e) => {
                    return Err(tonic::Status::failed_precondition(format!("{:?}", e)));
                }
            };
        
        let my_secret_share = all_secret_shares.pop().unwrap();
        let other_secret_shares = all_secret_shares;
        
        // encrypt secret shares

        let mut other_ss_aes_keys : Vec<Vec<u8>> = Vec::with_capacity(num_other_parties);
        let mut other_encrypted_secret_shares : Vec<Vec<u8>> = Vec::with_capacity(num_other_parties);
        for i in 0..num_other_parties {

            // use a Diffie-Hellman for symmetric encryption as per
            // https://github.com/ZenGo-X/multi-party-ecdsa/blob/10d37b89561d95f68fe94baf95fc14226dadfa80/examples/gg18_keygen_client.rs#L133
            // except use bincode::serialize instead of BigInt::to_vec
            other_ss_aes_keys.push(

                bincode::serialize(
                    &(other_reveals[i].y_i.clone() * keygen_session.state.my_keys.u_i).x_coor().unwrap()
                ).unwrap()

            );
            other_encrypted_secret_shares.push(
                bincode::serialize(
                    &multi_party_ecdsa_common::aes_encrypt(
                        &other_ss_aes_keys[i],
                        &bincode::serialize( &other_secret_shares[i] ).unwrap()
                    )
                ).unwrap()
            )
        }

        let response = grpc::KeygenRound3Response {
            my_vss_scheme: bincode::serialize(&my_vss_scheme).unwrap(),
            other_encrypted_secret_shares: other_encrypted_secret_shares,
        };

        // end: compute response
        // ---

        // ---
        // begin: update session state

        // TODO this is the only place we need write acces to keygen_session

        keygen_session.state.tn.threshold = threshold;
        keygen_session.state.other_reveals = other_reveals;
        keygen_session.state.other_ss_aes_keys = other_ss_aes_keys;
        keygen_session.state.my_secret_share = Some(my_secret_share);
        keygen_session.state.my_vss_scheme = Some(my_vss_scheme);
        keygen_session.status = KeygenStatus::Round3Done;

        // end: update session state
        // ---

        Ok(tonic::Response::new(response))
    }
}
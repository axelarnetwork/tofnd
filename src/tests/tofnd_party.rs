use super::{InitParty, DEFAULT_TEST_IP, DEFAULT_TEST_PORT, MAX_TRIES};
use crate::{
    addr,
    config::Config,
    encrypted_sled::{get_test_password, PasswordMethod},
    kv_manager::KvManager,
    mnemonic::Cmd,
    multisig, proto,
    tests::SLEEP_TIME,
};

use std::path::Path;
use std::path::PathBuf;
use tokio::time::{sleep, Duration};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use tokio_stream::wrappers::TcpListenerStream;

use tracing::{info, warn};

// I tried to keep this struct private and return `impl Party` from new() but ran into so many problems with the Rust compiler
// I also tried using Box<dyn Party> but ran into this: https://github.com/rust-lang/rust/issues/63033
#[allow(dead_code)]
pub(super) struct TofndParty {
    tofnd_path: PathBuf,
    client: proto::multisig_client::MultisigClient<tonic::transport::Channel>,
    server_handle: JoinHandle<()>,
    server_shutdown_sender: oneshot::Sender<()>,
    server_port: u16,
}

impl TofndParty {
    pub(super) async fn new(init_party: InitParty, mnemonic_cmd: Cmd, testdir: &Path) -> Self {
        let tofnd_path = format!("test-key-{:02}", init_party.party_index);
        let tofnd_path = testdir.join(tofnd_path);

        // start server
        let (server_shutdown_sender, shutdown_receiver) = oneshot::channel::<()>();

        let incoming = TcpListener::bind(addr(DEFAULT_TEST_IP, DEFAULT_TEST_PORT).unwrap())
            .await
            .unwrap();
        let server_addr = incoming.local_addr().unwrap();
        let server_ip = server_addr.ip();
        let server_port = server_addr.port();
        info!("new party bound to port [{:?}]", server_port);

        let cfg = Config {
            mnemonic_cmd,
            ip: server_ip.to_string(),
            port: server_port,
            safe_keygen: false,
            tofnd_path,
            password_method: PasswordMethod::NoPassword,
        };

        // start service
        // sled does not support to rapidly open/close databases.
        // Unfortunately, for our restarts/recover tests we need to open
        // a database right after it is closed. We get around with that by
        // attempting to open the kv with some artificial delay.
        // https://github.com/spacejam/sled/issues/1234#issuecomment-754769425
        let mut tries = 0;
        let kv_manager = loop {
            match KvManager::new(cfg.tofnd_path.clone(), get_test_password()) {
                Ok(kv_manager) => break kv_manager,
                Err(err) => {
                    tries += 1;
                    warn!("({}/3) unable to start kv manager: {}", tries, err);
                }
            };
            sleep(Duration::from_secs(SLEEP_TIME)).await;
            if tries == MAX_TRIES {
                panic!("could not start kv manager");
            }
        };
        let kv_manager = kv_manager.handle_mnemonic(&cfg.mnemonic_cmd).await.unwrap();

        let my_service = multisig::service::new_service(kv_manager);

        let proto_service = proto::multisig_server::MultisigServer::new(my_service);
        // let (startup_sender, startup_receiver) = tokio::sync::oneshot::channel::<()>();
        let server_handle = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(proto_service)
                .serve_with_incoming_shutdown(TcpListenerStream::new(incoming), async {
                    shutdown_receiver.await.unwrap();
                })
                .await
                .unwrap();
            // startup_sender.send(()).unwrap();
        });

        // TODO get the server to notify us after it's started, or perhaps just "yield" here
        // println!(
        //     "new party [{}] TODO sleep waiting for server to start...",
        //     server_port
        // );
        // tokio::time::delay_for(std::time::Duration::from_millis(100)).await;
        // startup_receiver.await.unwrap();
        // println!("party [{}] server started!", init.party_uids[my_id_index]);

        info!("new party [{}] connect to server...", server_port);
        let client =
            proto::multisig_client::MultisigClient::connect(format!("http://{}", server_addr))
                .await
                .unwrap();

        TofndParty {
            tofnd_path: cfg.tofnd_path,
            client,
            server_handle,
            server_shutdown_sender,
            server_port,
        }
    }
}

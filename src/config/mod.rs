use clap::{App, Arg};

// error handling
use crate::{encrypted_sled::PasswordMethod, mnemonic::Cmd, TofndResult};
use anyhow::anyhow;

// TODO: move these into constants.rs
const DEFAULT_PATH_ROOT: &str = ".tofnd";
const TOFND_HOME_ENV_VAR: &str = "TOFND_HOME";
const DEFAULT_MNEMONIC_CMD: &str = "existing";
const DEFAULT_GG20_PORT: &str = "50051";
const DEFAULT_MULTISIG_PORT: &str = "50052";
const AVAILABLE_MNEMONIC_CMDS: [&str; 4] = ["existing", "create", "import", "export"];

#[cfg(feature = "malicious")]
mod malicious;
#[cfg(feature = "malicious")]
use malicious::*;

// TODO: move to types.rs
#[derive(Clone, Debug)]
pub struct Config {
    pub gg20_port: u16,
    pub multisig_port: u16,
    pub safe_keygen: bool,
    pub mnemonic_cmd: Cmd,
    pub tofnd_path: String,
    pub password_method: PasswordMethod,
    #[cfg(feature = "malicious")]
    pub behaviours: Behaviours,
}
impl Default for Config {
    fn default() -> Self {
        Config {
            gg20_port: 50051,
            multisig_port: 50052,
            safe_keygen: true,
            mnemonic_cmd: Cmd::Existing,
            tofnd_path: DEFAULT_PATH_ROOT.to_string(),
            password_method: PasswordMethod::Prompt,
            #[cfg(feature = "malicious")]
            behaviours: Behaviours::default(),
        }
    }
}

pub fn parse_args() -> TofndResult<Config> {
    let app = App::new("tofnd")
        .about("A threshold signature scheme daemon")
        .arg(
            Arg::with_name("gg20-port")
                .long("gg20-port")
                .short("g")
                .required(false)
                .default_value(DEFAULT_GG20_PORT),
        )
        .arg(
            Arg::with_name("multisig-port")
                .long("multisig-port")
                .short("s")
                .required(false)
                .default_value(DEFAULT_MULTISIG_PORT),
        )
        .arg(
            // TODO: change to something like `--unsafe-primes`
            Arg::with_name("unsafe")
                .help(
                    "Use unsafe primes for generation of Pailler encryption keys. (default: deactivated) **Security warning:** This option is intented for use only in tests.  Do not use this option to secure real value.",
                )
                .long("unsafe")
                .required(false)
                .takes_value(false)
                .display_order(0),
        )
        .arg(
            Arg::with_name("no-password")
                .help(
                    "Skip providing a password. (default: disabled) **Security warning:** If this option is set then on-disk storage is encrypted with a default (and insecure) password.",
                )
                .long("no-password")
                .required(false)
                .takes_value(false)
                .display_order(0),
        )
        .arg(
            Arg::with_name("mnemonic")
                .long("mnemonic")
                .short("m")
                .required(false)
                .default_value(DEFAULT_MNEMONIC_CMD)
                .possible_values(&AVAILABLE_MNEMONIC_CMDS),
        )
        .arg(
            Arg::with_name("directory")
                .long("directory")
                .short("d")
                .required(false)
                .env(TOFND_HOME_ENV_VAR)
                .default_value(DEFAULT_PATH_ROOT),
        );

    #[cfg(feature = "malicious")]
    let app = app.subcommand(
        SubCommand::with_name("malicious")
            .about("Select malicious behaviour")
            .arg(
                Arg::with_name("behaviour")
                    .required(true)
                    .possible_values(&AVAILABLE_BEHAVIOURS)
                    .help("malicious behaviour"),
            )
            .arg(Arg::with_name("victim").required(true).help("victim")),
    );
    #[cfg(feature = "malicious")]
    let behaviours = get_behaviour_matches(app.clone())?;

    let matches = app.get_matches();
    let gg20_port = matches
        .value_of("gg20-port")
        .ok_or_else(|| anyhow!("port value"))?
        .parse::<u16>()?;
    let multisig_port = matches
        .value_of("multisig-port")
        .ok_or_else(|| anyhow!("port value"))?
        .parse::<u16>()?;
    let safe_keygen = !matches.is_present("unsafe");
    let mnemonic_cmd = matches
        .value_of("mnemonic")
        .ok_or_else(|| anyhow!("cmd value"))?
        .to_string();
    let mnemonic_cmd = Cmd::from_string(&mnemonic_cmd)?;

    let tofnd_path = matches
        .value_of("directory")
        .ok_or_else(|| anyhow!("directory value"))?
        .to_string();

    let password_method = match matches.is_present("no-password") {
        true => PasswordMethod::NoPassword,
        false => PasswordMethod::Prompt,
    };

    Ok(Config {
        gg20_port,
        multisig_port,
        safe_keygen,
        mnemonic_cmd,
        tofnd_path,
        password_method,
        #[cfg(feature = "malicious")]
        behaviours,
    })
}

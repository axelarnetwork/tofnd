use std::path::PathBuf;

use clap::{crate_version, App, Arg};

// error handling
use crate::{encrypted_sled::PasswordMethod, mnemonic::Cmd, TofndResult};
use anyhow::anyhow;

// TODO: move these into constants.rs
const DEFAULT_PATH_ROOT: &str = ".tofnd";
const TOFND_HOME_ENV_VAR: &str = "TOFND_HOME";
const DEFAULT_MNEMONIC_CMD: &str = "existing";
const DEFAULT_IP: &str = "localhost";
const DEFAULT_PORT: u16 = 50051;
const AVAILABLE_MNEMONIC_CMDS: &[&str] = &["existing", "create", "import", "export", "rotate"];

#[cfg(feature = "malicious")]
mod malicious;
#[cfg(feature = "malicious")]
use malicious::*;

// default path is ~/.tofnd
fn default_tofnd_dir() -> TofndResult<PathBuf> {
    Ok(dirs::home_dir()
        .ok_or_else(|| anyhow!("no home dir"))?
        .join(DEFAULT_PATH_ROOT))
}

// TODO: move to types.rs
#[derive(Clone, Debug)]
pub struct Config {
    pub ip: String,
    pub port: u16,
    pub safe_keygen: bool,
    pub mnemonic_cmd: Cmd,
    pub tofnd_path: PathBuf,
    pub password_method: PasswordMethod,
    #[cfg(feature = "malicious")]
    pub behaviours: Behaviours,
}

pub fn parse_args() -> TofndResult<Config> {
    // need to use let to avoid dropping temporary value
    let ip = &DEFAULT_IP.to_string();
    let port = &DEFAULT_PORT.to_string();
    let default_dir = default_tofnd_dir()?;
    let default_dir = default_dir
        .to_str()
        .ok_or_else(|| anyhow!("can't convert default dir to str"))?;

    let app = App::new("tofnd")
        .about("A threshold signature scheme daemon")
        .version(crate_version!())
        .arg(
            Arg::new("ip")
                .long("address")
                .short('a')
                .required(false)
                .default_value(ip),
        )
        .arg(
            Arg::new("port")
                .long("port")
                .short('p')
                .required(false)
                .default_value(port),
        )
        .arg(
            // TODO: change to something like `--unsafe-primes`
            Arg::new("unsafe")
                .help(
                    "Use unsafe primes for generation of Pailler encryption keys. (default: deactivated) **Security warning:** This option is intented for use only in tests.  Do not use this option to secure real value.",
                )
                .long("unsafe")
                .required(false)
                .takes_value(false)
                .display_order(0),
        )
        .arg(
            Arg::new("no-password")
                .help(
                    "Skip providing a password. (default: disabled) **Security warning:** If this option is set then on-disk storage is encrypted with a default (and insecure) password.",
                )
                .long("no-password")
                .required(false)
                .takes_value(false)
                .display_order(0),
        )
        .arg(
            Arg::new("mnemonic")
                .long("mnemonic")
                .short('m')
                .required(false)
                .default_value(DEFAULT_MNEMONIC_CMD)
                .possible_values(AVAILABLE_MNEMONIC_CMDS),
        )
        .arg(
            Arg::new("directory")
                .long("directory")
                .short('d')
                .required(false)
                .env(TOFND_HOME_ENV_VAR)
                .default_value(default_dir),
        );

    #[cfg(feature = "malicious")]
    let app = app.subcommand(
        App::new("malicious")
            .about("Select malicious behaviour")
            .arg(
                Arg::new("behaviour")
                    .required(true)
                    .possible_values(&AVAILABLE_BEHAVIOURS)
                    .help("malicious behaviour"),
            )
            .arg(Arg::new("victim").required(true).help("victim")),
    );
    #[cfg(feature = "malicious")]
    let behaviours = get_behaviour_matches(app.clone())?;

    let matches = app.get_matches();

    let ip = matches
        .value_of("ip")
        .ok_or_else(|| anyhow!("ip value"))?
        .to_string();
    let port = matches
        .value_of("port")
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
        .into();
    let password_method = match matches.is_present("no-password") {
        true => PasswordMethod::NoPassword,
        false => PasswordMethod::Prompt,
    };

    Ok(Config {
        ip,
        port,
        safe_keygen,
        mnemonic_cmd,
        tofnd_path,
        password_method,
        #[cfg(feature = "malicious")]
        behaviours,
    })
}

use std::path::PathBuf;

use clap::{builder::PossibleValuesParser, crate_version, Arg, Command};

// error handling
use crate::{encrypted_sled::PasswordMethod, mnemonic::Cmd, TofndResult};
use anyhow::anyhow;

// TODO: move these into constants.rs
const DEFAULT_PATH_ROOT: &str = ".tofnd";
const TOFND_HOME_ENV_VAR: &str = "TOFND_HOME";
const DEFAULT_MNEMONIC_CMD: &str = "existing";
const DEFAULT_IP: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 50051;
const AVAILABLE_MNEMONIC_CMDS: &[&str] = &["existing", "create", "import", "export", "rotate"];

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
    pub mnemonic_cmd: Cmd,
    pub tofnd_path: PathBuf,
    pub password_method: PasswordMethod,
}

pub fn parse_args() -> TofndResult<Config> {
    // need to use let to avoid dropping temporary value
    let ip = &DEFAULT_IP.to_string();
    let port = &DEFAULT_PORT.to_string();
    let default_dir = default_tofnd_dir()?;
    let default_dir = default_dir
        .to_str()
        .ok_or_else(|| anyhow!("can't convert default dir to str"))?;

    let app = Command::new("tofnd")
        .about("A cryptographic signing service")
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
                .value_parser(PossibleValuesParser::new(AVAILABLE_MNEMONIC_CMDS))
                .takes_value(true),
        )
        .arg(
            Arg::new("directory")
                .long("directory")
                .short('d')
                .required(false)
                .env(TOFND_HOME_ENV_VAR)
                .default_value(default_dir),
        );

    let matches = app.get_matches();

    let ip = matches
        .get_one::<String>("ip")
        .ok_or_else(|| anyhow!("ip value"))?
        .clone();
    let port = matches
        .get_one::<String>("port")
        .ok_or_else(|| anyhow!("port value"))?
        .parse::<u16>()?;
    let mnemonic_cmd = Cmd::from_string(
        matches
            .get_one::<String>("mnemonic")
            .ok_or_else(|| anyhow!("cmd value"))?,
    )?;
    let tofnd_path = matches
        .get_one::<String>("directory")
        .ok_or_else(|| anyhow!("directory value"))?
        .into();
    let password_method = match matches.contains_id("no-password") {
        true => PasswordMethod::NoPassword,
        false => PasswordMethod::Prompt,
    };

    Ok(Config {
        ip,
        port,
        mnemonic_cmd,
        tofnd_path,
        password_method,
    })
}

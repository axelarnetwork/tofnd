use clap::{App, Arg};

// error handling
use crate::TofndResult;
use anyhow::anyhow;

use crate::gg20::mnemonic::Cmd;

const DEFAULT_PATH_ROOT: &str = ".tofnd";
const TOFND_HOME_ENV_VAR: &str = "TOFND_HOME";

#[cfg(feature = "malicious")]
mod malicious;
#[cfg(feature = "malicious")]
use malicious::*;

#[derive(Clone, Debug)]
pub struct Config {
    pub port: u16,
    pub safe_keygen: bool,
    pub mnemonic_cmd: Cmd,
    pub tofnd_path: String,
    #[cfg(feature = "malicious")]
    pub behaviours: Behaviours,
}
// TODO: add chain calls: with_port(), with_safe_keygen() etc
impl Default for Config {
    fn default() -> Self {
        Config {
            port: 50051,
            safe_keygen: true,
            mnemonic_cmd: Cmd::Noop,
            tofnd_path: DEFAULT_PATH_ROOT.to_string(),
            #[cfg(feature = "malicious")]
            behaviours: Behaviours::default(),
        }
    }
}

pub fn parse_args() -> TofndResult<Config> {
    // Note that we want lower-case letters as impot, as enum type start with capitals
    let available_mnemonic_cmds = vec!["stored", "create", "import", "update", "export"];
    let default_mnemonic_cmd = "create";
    let default_port = "50051";

    let app = App::new("tofnd")
        .about("A threshold signature scheme daemon")
        .arg(
            Arg::with_name("port")
                .long("port")
                .short("p")
                .required(false)
                .default_value(default_port),
        )
        .arg(
            Arg::with_name("unsafe")
                .long("unsafe")
                .required(false)
                .takes_value(false),
        )
        .arg(
            Arg::with_name("mnemonic")
                .long("mnemonic")
                .short("m")
                .required(false)
                .default_value(default_mnemonic_cmd)
                .possible_values(&available_mnemonic_cmds),
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
        .to_string();

    Ok(Config {
        port,
        safe_keygen,
        mnemonic_cmd,
        tofnd_path,
        #[cfg(feature = "malicious")]
        behaviours,
    })
}

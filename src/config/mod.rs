use clap::{App, Arg};

// error handling
use crate::{gg20::mnemonic::Cmd, TofndResult};
use anyhow::anyhow;

const DEFAULT_PATH_ROOT: &str = ".tofnd";
const TOFND_HOME_ENV_VAR: &str = "TOFND_HOME";
const DEFAULT_MNEMONIC_CMD: &str = "create";
const DEFAULT_PORT: &str = "50051";
const AVAILABLE_MNEMONIC_CMDS: [&str; 5] = ["stored", "create", "import", "update", "export"];

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
    let app = App::new("tofnd")
        .about("A threshold signature scheme daemon")
        .arg(
            Arg::with_name("port")
                .long("port")
                .short("p")
                .required(false)
                .default_value(DEFAULT_PORT),
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

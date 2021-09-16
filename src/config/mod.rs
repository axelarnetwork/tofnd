use clap::{App, Arg};

// error handling
use crate::{TofndResult, DEFAULT_PATH_ROOT};
use anyhow::anyhow;

use crate::gg20::mnemonic::Cmd;

const TOFND_HOME_ENV_VAR: &str = "TOFND_HOME";

// TODO: examine if using a config file can replace commandline args

#[derive(Clone)]
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

#[cfg(not(feature = "malicious"))]
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
    })
}

#[cfg(feature = "malicious")]
use super::gg20::service::malicious::Behaviours;
#[cfg(feature = "malicious")]
use clap::SubCommand;
#[cfg(feature = "malicious")]
use tofn::{
    collections::TypedUsize,
    gg20::{
        keygen::malicious::Behaviour as KeygenBehaviour,
        sign::malicious::Behaviour as SignBehaviour,
    },
};

#[cfg(feature = "malicious")]
pub fn parse_args() -> TofndResult<Config> {
    let available_mnemonic_cmds = vec!["stored", "create", "import", "update", "export"];
    let default_mnemonic_cmd = "create";

    // TODO: if we want to read all available behaviours from tofn automatically,
    // we should add strum (https://docs.rs/strum) to iterate over enums and
    // print their names, but it has to be imported in tofn.
    let available_behaviours = [
        "Honest",
        "R1BadProof ",
        "R1BadGammaI",
        "R2FalseAccusation ",
        "R2BadMta ",
        "R2BadMtaWc ",
        "R3BadSigmaI",
        "R3FalseAccusationMta ",
        "R3FalseAccusationMtaWc ",
        "R3BadProof",
        "R3BadDeltaI",
        "R3BadKI",
        "R3BadAlpha ",
        "R3BadBeta ",
        "R4BadReveal",
        "R5BadProof ",
        "R6FalseAccusation ",
        "R6BadProof",
        "R6FalseFailRandomizer",
        "R7BadSI",
    ];

    // TODO: some of the behaviours do not demand a victim. In the future, more
    // will be added that potentially need different set of arguments.
    // Adjust this as needed to support that.
    let matches = App::new("tofnd")
        .about("A threshold signature scheme daemon")
        .arg(
            Arg::with_name("port")
                .long("port")
                .short("p")
                .required(false)
                .default_value("50051"),
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
        )
        .subcommand(
            SubCommand::with_name("malicious")
                .about("Select malicious behaviour")
                .arg(
                    Arg::with_name("behaviour")
                        .required(true)
                        .possible_values(&available_behaviours)
                        .help("malicious behaviour"),
                )
                .arg(Arg::with_name("victim").required(true).help("victim")),
        )
        .get_matches();

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

    // Set a default behaviour
    let mut sign_behaviour = "Honest";
    let mut victim = 0;
    if let Some(matches) = matches.subcommand_matches("malicious") {
        sign_behaviour = matches
            .value_of("behaviour")
            .ok_or_else(|| anyhow!("behaviour value"))?;
        victim = matches
            .value_of("victim")
            .ok_or_else(|| anyhow!("victim value"))?
            .parse::<usize>()?;
    }

    // TODO: parse keygen malicious types aswell
    let keygen = KeygenBehaviour::R1BadCommit;
    let sign = match_string_to_behaviour(sign_behaviour, victim);
    let behaviours = Behaviours { keygen, sign };

    Ok(Config {
        port,
        safe_keygen,
        mnemonic_cmd,
        tofnd_path,
        behaviours,
    })
}

#[cfg(feature = "malicious")]
fn match_string_to_behaviour(behaviour: &str, victim: usize) -> SignBehaviour {
    use SignBehaviour::*;
    let victim = TypedUsize::from_usize(victim);
    // TODO: some of the behaviours do not demand a victim. In the future, more
    // will be added that potentially need different set of arguments.
    // Adjust this as needed to support that.
    match behaviour {
        "Honest" => Honest,
        "R1BadProof " => R1BadProof { victim },
        "R1BadGammaI" => R1BadGammaI,
        "R2FalseAccusation " => R2FalseAccusation { victim },
        "R2BadMta " => R2BadMta { victim },
        "R2BadMtaWc " => R2BadMtaWc { victim },
        "R3BadSigmaI" => R3BadSigmaI,
        "R3FalseAccusationMta " => R3FalseAccusationMta { victim },
        "R3FalseAccusationMtaWc " => R3FalseAccusationMtaWc { victim },
        "R3BadProof" => R3BadProof,
        "R3BadDeltaI" => R3BadDeltaI,
        "R3BadKI" => R3BadKI,
        "R3BadAlpha " => R3BadAlpha { victim },
        "R3BadBeta " => R3BadBeta { victim },
        "R4BadReveal" => R4BadReveal,
        "R5BadProof " => R5BadProof { victim },
        "R6FalseAccusation " => R6FalseAccusation { victim },
        "R6BadProof" => R6BadProof,
        "R6FalseFailRandomizer" => R6FalseType5Claim,
        "R7BadSI" => R7BadSI,
        "R7FalseFailRandomizer" => R7FalseType7Claim,
        _ => Honest,
    }
}

use crate::TofndError;
use clap::{App, Arg};

use crate::gg20::mnemonic::Cmd;

#[cfg(not(feature = "malicious"))]
pub fn parse_args() -> Result<(u16, Cmd), TofndError> {
    // TODO: check if this can be automated with strum.
    // Note that we want lower-case letters as impot, as enum type start with capitals
    let available_mnemonic_cmds = vec!["stored", "create", "import", "update", "export"];
    let default_mnemonic_cmd = "create";

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
            Arg::with_name("mnemonic")
                .long("mnemonic")
                .short("m")
                .required(false)
                .default_value(default_mnemonic_cmd)
                .possible_values(&available_mnemonic_cmds),
        )
        .get_matches();

    let port = matches.value_of("port").unwrap().parse::<u16>()?;
    let mnemonic_cmd = matches.value_of("mnemonic").unwrap().to_string();
    let mnemonic_cmd = Cmd::from_string(&mnemonic_cmd)?;
    Ok((port, mnemonic_cmd))
}

#[cfg(feature = "malicious")]
use clap::SubCommand;
#[cfg(feature = "malicious")]
use tofn::protocol::gg20::keygen::malicious::Behaviour as KeygenBehaviour;
#[cfg(feature = "malicious")]
use tofn::protocol::gg20::sign::malicious::Behaviour as SignBehaviour;

#[cfg(feature = "malicious")]
pub fn parse_args() -> Result<(u16, Cmd, KeygenBehaviour, SignBehaviour), TofndError> {
    // TODO: check if this can be automated with strum.
    // Note that we want lower-case letters as impot, as enum type start with capitals
    let available_mnemonic_cmds = vec!["stored", "create", "import", "update", "export"];
    let default_mnemonic_cmd = "create";

    // TODO: if we want to read all available behaviours from tofn automatically,
    // we should add strum (https://docs.rs/strum) to iterate over enums and
    // print their names, but it has to be imported in tofn.
    let available_behaviours = [
        "Honest",
        "R1BadProof",
        "R2FalseAccusation",
        "R2BadMta",
        "R2BadMtaWc",
        "R3FalseAccusationMta",
        "R3FalseAccusationMtaWc",
        "R3BadProof",
        "R4BadReveal",
        "R5BadProof",
        "R6BadProof",
        "R6FalseAccusation",
        "R7BadSigSummand",
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
            Arg::with_name("mnemonic")
                .long("mnemonic")
                .short("m")
                .required(false)
                .default_value(default_mnemonic_cmd)
                .possible_values(&available_mnemonic_cmds),
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

    let port = matches.value_of("port").unwrap().parse::<u16>()?;
    let mnemonic_cmd = matches.value_of("mnemonic").unwrap().to_string();
    let mnemonic_cmd = Cmd::from_string(&mnemonic_cmd)?;

    // Set a default behaviour
    let mut sign_behaviour = "Honest";
    let mut victim = 0;
    if let Some(matches) = matches.subcommand_matches("malicious") {
        sign_behaviour = matches.value_of("behaviour").unwrap();
        victim = matches.value_of("victim").unwrap().parse::<usize>()?;
    }

    // TODO: parse keygen malicious types
    let keygen_behaviour = KeygenBehaviour::R1BadCommit;
    let sign_behaviour = match_string_to_behaviour(sign_behaviour, victim);
    Ok((port, mnemonic_cmd, keygen_behaviour, sign_behaviour))
}

#[cfg(feature = "malicious")]
// TODO can be eliminated if we use strum (https://docs.rs/strum) in tofn
fn match_string_to_behaviour(behaviour: &str, victim: usize) -> SignBehaviour {
    match behaviour {
        "Honest" => SignBehaviour::Honest,
        "R1BadProof" => SignBehaviour::R1BadProof { victim },
        "R2FalseAccusation" => SignBehaviour::R2FalseAccusation { victim },
        "R2BadMta" => SignBehaviour::R2BadMta { victim },
        "R2BadMtaWc" => SignBehaviour::R2BadMtaWc { victim },
        "R3FalseAccusationMta" => SignBehaviour::R3FalseAccusationMta { victim },
        "R3FalseAccusationMtaWc" => SignBehaviour::R3FalseAccusationMtaWc { victim },
        "R3BadProof" => SignBehaviour::R3BadProof,
        "R4BadReveal" => SignBehaviour::R4BadReveal,
        "R5BadProof" => SignBehaviour::R5BadProof { victim },
        "R6BadProof" => SignBehaviour::R6BadProof,
        "R6FalseAccusation" => SignBehaviour::R6FalseAccusation { victim },
        "R7BadSI" => SignBehaviour::R7BadSI,
        _ => panic!("Unknown behaviour"),
    }
}

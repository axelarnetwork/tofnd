use crate::TofndError;
use clap::{App, Arg};

#[cfg(not(feature = "malicious"))]
pub fn parse_args() -> Result<u16, TofndError> {
    let matches = App::new("tofnd")
        .about("A threshold signature scheme daemon")
        .arg(
            Arg::with_name("port")
                .long("port")
                .short("p")
                .required(false)
                .default_value("50051"),
        )
        .get_matches();

    let port = matches.value_of("port").unwrap().parse::<u16>()?;
    Ok(port)
}

#[cfg(feature = "malicious")]
use clap::SubCommand;
#[cfg(feature = "malicious")]
use tofn::protocol::gg20::keygen::malicious::Behaviour;
#[cfg(feature = "malicious")]
use tofn::protocol::gg20::sign::malicious::MaliciousType;

#[cfg(feature = "malicious")]
pub fn parse_args() -> Result<(u16, Behaviour, MaliciousType), TofndError> {
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

    // Set a default behaviour
    let mut sign_behaviour = "Honest";
    let mut victim = 0;
    if let Some(matches) = matches.subcommand_matches("malicious") {
        sign_behaviour = matches.value_of("behaviour").unwrap();
        victim = matches.value_of("victim").unwrap().parse::<usize>()?;
    }

    // TODO: parse keygen malicious types
    let keygen_behaviour = Behaviour::R1BadCommit;
    let sign_behaviour = match_string_to_behaviour(sign_behaviour, victim);
    Ok((port, keygen_behaviour, sign_behaviour))
}

#[cfg(feature = "malicious")]
// TODO can be eliminated if we use strum (https://docs.rs/strum) in tofn
fn match_string_to_behaviour(behaviour: &str, victim: usize) -> MaliciousType {
    match behaviour {
        "Honest" => MaliciousType::Honest,
        "R1BadProof" => MaliciousType::R1BadProof { victim },
        "R2FalseAccusation" => MaliciousType::R2FalseAccusation { victim },
        "R2BadMta" => MaliciousType::R2BadMta { victim },
        "R2BadMtaWc" => MaliciousType::R2BadMtaWc { victim },
        "R3FalseAccusationMta" => MaliciousType::R3FalseAccusationMta { victim },
        "R3FalseAccusationMtaWc" => MaliciousType::R3FalseAccusationMtaWc { victim },
        "R3BadProof" => MaliciousType::R3BadProof,
        "R4BadReveal" => MaliciousType::R4BadReveal,
        "R5BadProof" => MaliciousType::R5BadProof { victim },
        "R6BadProof" => MaliciousType::R6BadProof,
        "R6FalseAccusation" => MaliciousType::R6FalseAccusation { victim },
        "R7BadSigSummand" => MaliciousType::R7BadSigSummand,
        _ => panic!("Unknown behaviour"),
    }
}

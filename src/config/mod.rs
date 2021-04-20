use clap::{App, Arg};

#[cfg(not(feature = "malicious"))]
pub fn parse_args() -> u16 {
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

    let port = matches.value_of("port").unwrap().parse::<u16>().unwrap();
    port
}

#[cfg(feature = "malicious")]
use clap::SubCommand;
#[cfg(feature = "malicious")]
use tofn::protocol::gg20::sign::malicious::MaliciousType::{self, *};

#[cfg(feature = "malicious")]
pub fn parse_args() -> (u16, MaliciousType) {
    // TODO: if we want to read all available behaviours from tofn automatically,
    // we should add strum (https://docs.rs/strum) to iterate over enums and
    // print their names, but it has to be imported in tofn.
    let available_behaviours = [
        "Honest",
        "R1BadProof",
        "R1FalseAccusation",
        "R2BadMta",
        "R2BadMtaWc",
        "R2FalseAccusationMta",
        "R2FalseAccusationMtaWc",
        "R3BadProof",
        "R3FalseAccusation",
        "R4BadReveal",
        "R4FalseAccusation",
        "R5BadProof",
        "R5FalseAccusation",
        "R6BadProof",
        "R6FalseAccusation",
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

    let port = matches.value_of("port").unwrap().parse::<u16>().unwrap();

    // Set a default behaviour
    let mut behaviour = "Honest";
    let mut victim = 0;
    if let Some(matches) = matches.subcommand_matches("malicious") {
        behaviour = matches.value_of("behaviour").unwrap();
        victim = matches
            .value_of("victim")
            .unwrap()
            .parse::<usize>()
            .unwrap();
    }

    let behaviour = match_string_to_behaviour(behaviour, victim);
    (port, behaviour)
}

#[cfg(feature = "malicious")]
// TODO can be eliminated if we use strum (https://docs.rs/strum) in tofn
fn match_string_to_behaviour(behaviour: &str, victim: usize) -> MaliciousType {
    match behaviour {
        "Honest" => Honest,
        "R1BadProof" => R1BadProof { victim },
        "R1FalseAccusation" => R1FalseAccusation { victim },
        "R2BadMta" => R2BadMta { victim },
        "R2BadMtaWc" => R2BadMtaWc { victim },
        "R2FalseAccusationMta" => R2FalseAccusationMta { victim },
        "R2FalseAccusationMtaWc" => R2FalseAccusationMtaWc { victim },
        "R3BadProof" => R3BadProof,
        "R3FalseAccusation" => R3FalseAccusation { victim },
        "R4BadReveal" => R4BadReveal,
        "R4FalseAccusation" => R4FalseAccusation { victim },
        "R5BadProof" => R5BadProof { victim },
        "R5FalseAccusation" => R5FalseAccusation { victim },
        "R6BadProof" => R6BadProof,
        "R6FalseAccusation" => R6FalseAccusation { victim },
        _ => panic!("Unknown behaviour"),
    }
}

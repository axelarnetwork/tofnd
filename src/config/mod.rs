use clap::{App, Arg, SubCommand};
use lazy_static::lazy_static;

// init config
lazy_static! {
    pub static ref CONFIG: Config = Config::new();
}

pub struct Config {
    pub behaviour: String,
    pub victim: usize,
}

impl Config {
    pub fn new() -> Config {
        let (behaviour, victim) = parse_args();
        Config { behaviour, victim }
    }
}

pub fn parse_args() -> (String, usize) {
    // TODO: if we want to read all available behaviours from tofn automatically,
    // we should add strum (https://docs.rs/strum) to iterate over enums and
    // print their names. But it has to be imported from tofn.
    let available_behaviours = [
        "R1BadProof",
        "R1FalseAccusation",
        "R2BadMta",
        "R2BadMtaWc",
        "R2FalseAccusationMta",
        "R2FalseAccusationMtaWc",
    ];

    let matches = App::new("tofnd")
        .version("A threshold signature scheme daemon")
        .subcommand(
            SubCommand::with_name("behaviour")
                .arg(
                    Arg::with_name("name")
                        .required(true)
                        .possible_values(&available_behaviours),
                )
                .arg(Arg::with_name("victim").required(true)),
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("behaviour") {
        let name = matches.value_of("name").unwrap();
        let victim = matches
            .value_of("victim")
            .unwrap()
            .parse::<usize>()
            .unwrap();
        (name.to_owned(), victim)
    } else {
        ("honest".to_owned(), 0)
    }
}
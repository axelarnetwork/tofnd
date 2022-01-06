// error handling
use crate::TofndResult;
use anyhow::anyhow;

use tofn::{
    collections::TypedUsize,
    gg20::{
        keygen::malicious::Behaviour as KeygenBehaviour,
        sign::malicious::Behaviour as SignBehaviour,
    },
};

use clap::App;

pub(super) type Behaviours = crate::gg20::service::malicious::Behaviours;

pub(super) const AVAILABLE_BEHAVIOURS: [&str; 20] = [
    "Honest",
    "R1BadProof",
    "R1BadGammaI",
    "R2FalseAccusation",
    "R2BadMta",
    "R2BadMtaWc",
    "R3BadSigmaI",
    "R3FalseAccusationMta",
    "R3FalseAccusationMtaWc",
    "R3BadProof",
    "R3BadDeltaI",
    "R3BadKI",
    "R3BadAlpha",
    "R3BadBeta",
    "R4BadReveal",
    "R5BadProof",
    "R6FalseAccusation",
    "R6BadProof",
    "R6FalseFailRandomizer",
    "R7BadSI",
];

pub fn get_behaviour_matches(app: App) -> TofndResult<Behaviours> {
    // TODO: if we want to read all available behaviours from tofn automatically,
    // we should add strum (https://docs.rs/strum) to iterate over enums and
    // print their names, but it has to be imported in tofn.

    let matches = app.get_matches();

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

    // TODO: parse keygen malicious types as well
    let keygen = KeygenBehaviour::R1BadCommit;
    let sign = match_string_to_behaviour(sign_behaviour, victim);
    Ok(Behaviours { keygen, sign })
}

fn match_string_to_behaviour(behaviour: &str, victim: usize) -> SignBehaviour {
    use SignBehaviour::*;
    let victim = TypedUsize::from_usize(victim);
    // TODO: some of the behaviours do not demand a victim. In the future, more
    // will be added that potentially need different set of arguments.
    // Adjust this as needed to support that.
    match behaviour {
        "Honest" => Honest,
        "R1BadProof" => R1BadProof { victim },
        "R1BadGammaI" => R1BadGammaI,
        "R2FalseAccusation" => R2FalseAccusation { victim },
        "R2BadMta" => R2BadMta { victim },
        "R2BadMtaWc" => R2BadMtaWc { victim },
        "R3BadSigmaI" => R3BadSigmaI,
        "R3FalseAccusationMta" => R3FalseAccusationMta { victim },
        "R3FalseAccusationMtaWc" => R3FalseAccusationMtaWc { victim },
        "R3BadProof" => R3BadProof,
        "R3BadDeltaI" => R3BadDeltaI,
        "R3BadKI" => R3BadKI,
        "R3BadAlpha" => R3BadAlpha { victim },
        "R3BadBeta" => R3BadBeta { victim },
        "R4BadReveal" => R4BadReveal,
        "R5BadProof" => R5BadProof { victim },
        "R6FalseAccusation" => R6FalseAccusation { victim },
        "R6BadProof" => R6BadProof,
        "R6FalseFailRandomizer" => R6FalseType5Claim,
        "R7BadSI" => R7BadSI,
        "R7FalseFailRandomizer" => R7FalseType7Claim,
        _ => Honest,
    }
}

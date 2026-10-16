//! `bifrost-icone <repertoire>`: ecrit dans le repertoire donne les icones
//! hicolor (`bifrost-<cote>.png`), le `.ico` Windows (`bifrost.ico`) et les PNG
//! de tray (`bifrost-tray-<teinte>-16.png`), imprime chaque chemin, et sort 0.
//!
//! Il REFUSE un chemin sous `gui/` ou `crates/`: aucun binaire d'icone ne doit
//! entrer dans l'arbre versionne (gardes `la_coquille_n_embarque_aucun_binaire`
//! et `sources_ascii`). Le repertoire de sortie est donc toujours hors depot.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: bifrost-icone <repertoire>");
        return ExitCode::from(2);
    }
    let repertoire = std::path::Path::new(&args[1]);
    match bifrost_icone::ecrire_icones(repertoire) {
        Ok(chemins) => {
            for chemin in chemins {
                println!("{}", chemin.display());
            }
            ExitCode::SUCCESS
        }
        Err(erreur) => {
            eprintln!("bifrost-icone: {erreur}");
            ExitCode::FAILURE
        }
    }
}

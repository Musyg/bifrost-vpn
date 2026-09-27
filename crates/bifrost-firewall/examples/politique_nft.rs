//! Outil du banc jetable: rendu produit sans appliquer une seule regle.
//! Le second argument choisit le JSON de reference, sinon le script nft.

#[cfg(target_os = "linux")]
fn main() {
    let mut args = std::env::args().skip(1);
    let fichier = args.next().expect("fichier de politique du banc");
    let v = serde_json::from_slice(&std::fs::read(fichier).unwrap()).unwrap();
    let p = bifrost_firewall::politique_nft::Politique::lire(v).unwrap();
    if args.next().as_deref() == Some("json") {
        println!("{}", p.reference().unwrap());
    } else {
        print!(
            "{}",
            bifrost_firewall::linux::ruleset::render(&p.firewall_policy().unwrap())
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("Banc nft Linux uniquement");
    std::process::exit(2);
}

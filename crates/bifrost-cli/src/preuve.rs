//! Mesure locale, sans IPC, reseau, elevation ni modification du fichier.
//! Une empreinte fournie par l'utilisateur n'authentifie pas un editeur.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha2::{Digest, Sha256};

const MAX_OCTETS: u64 = 512 * 1024 * 1024;
const LIMITE: &str =
    "L'egalite des empreintes ne prouve ni l'origine du fichier, ni la securite du VPN.";

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Verdict {
    Match,
    Mismatch,
    Unmeasured,
}

#[derive(Debug, Serialize)]
pub struct Rapport {
    schema_version: u32,
    scope: &'static str,
    verdict: Verdict,
    started_at_unix_ms: Option<u128>,
    completed_at_unix_ms: Option<u128>,
    duration_ms: u128,
    expected_sha256: String,
    observed_sha256: Option<String>,
    bytes_read: Option<u64>,
    reference_source: &'static str,
    provenance: &'static str,
    network_security: &'static str,
    reason: &'static str,
    limitation: &'static str,
}

impl Rapport {
    fn terminer(mut self, debut: Instant) -> Self {
        self.completed_at_unix_ms = horodatage();
        self.duration_ms = debut.elapsed().as_millis();
        self
    }

    pub fn code(&self) -> i32 {
        match self.verdict {
            Verdict::Match => 0,
            Verdict::Mismatch => 1,
            Verdict::Unmeasured => 2,
        }
    }

    pub fn texte(&self) -> String {
        let verdict = match self.verdict {
            Verdict::Match => "MATCH",
            Verdict::Mismatch => "MISMATCH",
            Verdict::Unmeasured => "UNMEASURED",
        };
        format!(
            "{verdict}  file-sha256\n{}\nattendu: {}\nobserve: {}\n\n{}\n",
            self.reason,
            self.expected_sha256,
            self.observed_sha256.as_deref().unwrap_or("non mesure"),
            self.limitation
        )
    }
}

fn horodatage() -> Option<u128> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis())
}

/// Le parseur clap rejette une reference mal formee AVANT toute lecture.
pub fn empreinte(valeur: &str) -> Result<String, String> {
    if valeur.len() != 64 || !valeur.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("SHA-256 attendu: exactement 64 caracteres hexadecimaux".to_owned());
    }
    Ok(valeur.to_ascii_lowercase())
}

fn mesurer(mut lecteur: impl Read, limite: u64) -> Result<(String, u64), &'static str> {
    let mut hash = Sha256::new();
    let mut total = 0_u64;
    let mut tampon = [0_u8; 64 * 1024];
    loop {
        let n = match lecteur.read(&mut tampon) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err("lecture interrompue: aucune empreinte partielle acceptee"),
        };
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > limite {
            return Err("fichier trop grand: limite de 512 Mio");
        }
        hash.update(&tampon[..n]);
    }
    Ok((format!("{:x}", hash.finalize()), total))
}

fn lire(chemin: &Path) -> Result<(String, u64), &'static str> {
    let avant = std::fs::symlink_metadata(chemin).map_err(|_| "fichier absent ou inaccessible")?;
    if !avant.file_type().is_file() {
        return Err("seul un fichier regulier est accepte, sans lien symbolique");
    }
    if avant.len() > MAX_OCTETS {
        return Err("fichier trop grand: limite de 512 Mio");
    }
    let mut fichier = File::open(chemin).map_err(|_| "ouverture du fichier impossible")?;
    let debut = fichier.metadata().map_err(|_| "metadonnees illisibles")?;
    if !debut.is_file() || debut.len() > MAX_OCTETS {
        return Err("fichier non regulier ou trop grand a l'ouverture");
    }
    // Le meme descripteur est garde jusqu'au bout. La borne de lecture reste
    // necessaire si le fichier grossit apres l'ouverture.
    let mesure = mesurer((&mut fichier).take(MAX_OCTETS + 1), MAX_OCTETS)?;
    let fin = fichier
        .metadata()
        .map_err(|_| "metadonnees finales illisibles")?;
    let stable = debut.len() == fin.len()
        && fin.len() == mesure.1
        && matches!((debut.modified(), fin.modified()), (Ok(a), Ok(b)) if a == b);
    if !stable {
        return Err("fichier modifie pendant la lecture, ou stabilite non mesurable");
    }
    Ok(mesure)
}

pub fn verifier(chemin: &Path, reference: &str) -> Rapport {
    let debut = Instant::now();
    let mut rapport = Rapport {
        schema_version: 1,
        scope: "file-sha256",
        verdict: Verdict::Unmeasured,
        started_at_unix_ms: horodatage(),
        completed_at_unix_ms: None,
        duration_ms: 0,
        expected_sha256: reference.to_owned(),
        observed_sha256: None,
        bytes_read: None,
        reference_source: "user-supplied",
        provenance: "not-verified",
        network_security: "not-evaluated",
        reason: "reference SHA-256 invalide",
        limitation: LIMITE,
    };
    let Ok(reference) = empreinte(reference) else {
        return rapport.terminer(debut);
    };
    rapport.expected_sha256.clone_from(&reference);
    match lire(chemin) {
        Ok((observe, taille)) => {
            if observe == reference {
                rapport.verdict = Verdict::Match;
                rapport.reason = "les octets lus correspondent a la reference fournie";
            } else {
                rapport.verdict = Verdict::Mismatch;
                rapport.reason = "les octets lus different de la reference fournie";
            }
            rapport.observed_sha256 = Some(observe);
            rapport.bytes_read = Some(taille);
        }
        Err(raison) => rapport.reason = raison,
    }
    rapport.terminer(debut)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vecteur_sha256_connu_et_limite_exacte() {
        assert_eq!(
            mesurer(&b"abc"[..], 3).unwrap(),
            (
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
                3
            )
        );
        assert!(mesurer(&b"abcd"[..], 3).is_err());
    }

    #[test]
    fn erreur_apres_lecture_ne_rend_pas_une_empreinte_partielle() {
        let erreur = io::Error::other("temoin");
        struct Refus(Option<io::Error>);
        impl Read for Refus {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(self.0.take().unwrap())
            }
        }
        let lecteur = (&b"abc"[..]).chain(Refus(Some(erreur)));
        assert!(mesurer(lecteur, 4).is_err());
    }

    #[test]
    fn reference_stricte_sans_troncature_ni_espaces() {
        assert_eq!(empreinte(&"A".repeat(64)).unwrap(), "a".repeat(64));
        for invalide in [
            "a".repeat(63),
            "a".repeat(65),
            "g".repeat(64),
            format!(" {}", "a".repeat(64)),
        ] {
            assert!(empreinte(&invalide).is_err());
        }
    }
}

//! Kill switch Linux: nftables famille `inet`, policy drop, couple au fwmark.

pub mod ruleset;

use std::io::Write;
use std::process::{Command, Stdio};

use bifrost_core::ports::{FirewallPolicy, KillSwitch};
use bifrost_core::{Error, Result};

/// Emplacements ou chercher `nft`. Sur Debian et Ubuntu il est dans `/usr/sbin`,
/// qui n'est pas dans le PATH d'un shell non privilegie.
const NFT_CANDIDATES: &[&str] = &["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "nft"];

pub struct NftablesKillSwitch {
    nft: String,
}

impl Default for NftablesKillSwitch {
    fn default() -> Self {
        Self::new()
    }
}

impl NftablesKillSwitch {
    pub fn new() -> Self {
        Self {
            nft: find_nft().unwrap_or_else(|| "nft".to_owned()),
        }
    }

    /// Applique un fichier de regles. `nft` traite un fichier en une seule
    /// transaction noyau: soit tout est pose, soit rien ne change.
    fn apply(&self, script: &str) -> Result<()> {
        let mut child = Command::new(&self.nft)
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                Error::Firewall(format!(
                    "impossible de lancer {}: {e}. nftables est-il installe ?",
                    self.nft
                ))
            })?;

        child
            .stdin
            .take()
            .expect("stdin demande a la creation")
            .write_all(script.as_bytes())
            .map_err(|e| Error::Firewall(format!("ecriture vers nft: {e}")))?;

        let out = child
            .wait_with_output()
            .map_err(|e| Error::Firewall(format!("attente de nft: {e}")))?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(Error::Firewall(format!(
                "nft a echoue ({}): {}",
                out.status,
                stderr.trim()
            )));
        }
        Ok(())
    }

    /// Valide la syntaxe sans rien appliquer. Utilise par les tests.
    pub fn check(&self, script: &str) -> Result<()> {
        let mut child = Command::new(&self.nft)
            .args(["--check", "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::Firewall(format!("impossible de lancer nft: {e}")))?;
        child
            .stdin
            .take()
            .expect("stdin demande a la creation")
            .write_all(script.as_bytes())
            .map_err(|e| Error::Firewall(format!("ecriture vers nft: {e}")))?;
        let out = child
            .wait_with_output()
            .map_err(|e| Error::Firewall(format!("attente de nft: {e}")))?;
        if !out.status.success() {
            return Err(Error::Firewall(
                String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            ));
        }
        Ok(())
    }
}

impl KillSwitch for NftablesKillSwitch {
    fn engage(&mut self, policy: &FirewallPolicy) -> Result<()> {
        // `TunnelConfig::validate` refuse deja fwmark 0, mais la validation
        // porte sur la CONFIGURATION et une `FirewallPolicy` se construit aussi
        // directement: les recettes le font, et le vecteur veille l'a fait. Or
        // le ruleset rend alors `meta mark 0x0 accept`, qui matche tout paquet
        // non marque, c'est-a-dire tout le trafic. Le kill switch devient un
        // laissez-passer tout en journalisant "kill switch arme". Constate le
        // 17 aout 2026: sonde connectee, kill switch pretendument arme.
        //
        // La garde est donc reposee ici, la ou le mal se produit, et elle
        // refuse d'armer plutot que d'armer un leurre.
        // `None` est legitime depuis qu'un coeur peut porter le trafic: le
        // ruleset n'emet alors aucun permit de marque. C'est `Some(0)` qui
        // reste interdit, et la nuance est tout l'interet du type optionnel.
        if policy.fwmark == Some(0) {
            return Err(Error::Config(
                "fwmark 0 rendrait 'meta mark 0x0 accept', qui laisse passer \
                 tout le trafic non marque: le kill switch serait un \
                 laissez-passer. Pour un tunnel sans marque, ecrire None. \
                 Refus d'armer."
                    .to_owned(),
            ));
        }
        let script = ruleset::render(policy);
        tracing::debug!(bytes = script.len(), "application du ruleset nftables");
        self.apply(&script)?;
        tracing::info!(
            interface = ?policy.tunnel_interface,
            fwmark = policy
                .fwmark
                .map_or_else(|| "aucun".to_owned(), |m| format!("{m:#x}")),
            allow_lan = policy.allow_lan,
            "kill switch arme"
        );
        Ok(())
    }

    fn disengage(&mut self) -> Result<()> {
        // Si la table n'existe pas, `delete table` echoue. On considere que
        // l'objectif (aucun filtre Bifrost en place) est atteint.
        match self.is_engaged() {
            Ok(false) => {
                tracing::debug!("kill switch deja desarme");
                return Ok(());
            }
            Ok(true) => {}
            Err(e) => tracing::warn!(error = %e, "etat du kill switch indeterminable"),
        }
        self.apply(&ruleset::render_teardown())?;
        tracing::info!("kill switch desarme");
        Ok(())
    }

    fn is_engaged(&self) -> Result<bool> {
        let out = Command::new(&self.nft)
            .args(["list", "table", "inet", ruleset::TABLE])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| Error::Firewall(format!("impossible de lancer nft: {e}")))?;
        Ok(out.status.success())
    }

    fn backend(&self) -> &'static str {
        "nftables"
    }
}

fn find_nft() -> Option<String> {
    NFT_CANDIDATES
        .iter()
        .find(|p| p.starts_with('/') && std::path::Path::new(p).exists())
        .map(|p| (*p).to_owned())
        .or_else(|| {
            // Dernier recours: laisser le PATH decider.
            Command::new("nft")
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .ok()
                .filter(|s| s.success())
                .map(|_| "nft".to_owned())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn policy() -> FirewallPolicy {
        FirewallPolicy {
            tunnel_interface: Some("wg0".into()),
            tunnel_luid: None,
            fwmark: Some(0xca6c),
            dns_resolver: IpAddr::V4(Ipv4Addr::LOCALHOST),
            allow_lan: false,
            coeur_uid: None,
            coeur_executable: None,
            resolveur_uid: None,
            resolveur_executable: None,
            resolveur_sid: None,
            resolveur_embarque: false,
        }
    }

    /// Un fwmark nul rend `meta mark 0x0 accept`, qui matche tout paquet non
    /// marque: le ruleset laisse alors passer tout le trafic tout en
    /// s'annoncant arme. `TunnelConfig::validate` refuse deja ce cas, mais une
    /// `FirewallPolicy` se construit aussi sans passer par une configuration,
    /// et c'est ce chemin qui a produit un faux vert le 17 aout 2026.
    ///
    /// Le test n'a pas besoin de `nft`: le refus doit tomber AVANT tout appel
    /// au systeme, sans quoi une machine sans `nft` le verrait passer.
    #[test]
    fn armer_avec_un_fwmark_nul_est_refuse() {
        let mut ks = NftablesKillSwitch::new();
        let nulle = FirewallPolicy {
            fwmark: Some(0),
            ..policy()
        };
        let e = ks
            .engage(&nulle)
            .expect_err("armer avec fwmark 0 doit echouer");
        let message = e.to_string();
        assert!(
            message.contains("laissez-passer"),
            "le message doit dire POURQUOI c'est refuse: {message}"
        );
    }

    /// Valide la syntaxe du ruleset contre le vrai binaire nft.
    ///
    /// `nft --check` analyse et resout les regles sans les appliquer, mais il a
    /// besoin de parler au noyau: sans privileges il echoue avec EPERM. Le test
    /// se declare alors SKIPPED plutot que de passer sans rien verifier.
    #[test]
    fn le_ruleset_est_syntaxiquement_valide_pour_nft() {
        let ks = NftablesKillSwitch::new();
        if find_nft().is_none() {
            eprintln!("SKIPPED: nft absent de cette machine");
            return;
        }
        for p in [
            policy(),
            FirewallPolicy {
                tunnel_interface: None,
                tunnel_luid: None,
                ..policy()
            },
            FirewallPolicy {
                allow_lan: true,
                ..policy()
            },
            // L'exemption du coeur passe par `meta skuid`, une syntaxe que
            // seul `nft` peut valider. Un test de chaine ne dirait rien d'une
            // regle malformee, qui ferait echouer l'armement en production.
            FirewallPolicy {
                coeur_uid: Some(977),
                ..policy()
            },
            // Le cas d'un tunnel par coeur: aucun permit de marque, et le
            // coeur sort par son identite. C'est le rendu le plus recent et
            // celui dont l'absence d'une ligne pourrait laisser une chaine
            // vide ou une accolade orpheline - ce qu'un test de chaine ne
            // verrait pas et que nft, lui, refuserait a l'armement.
            FirewallPolicy {
                fwmark: None,
                coeur_uid: Some(977),
                ..policy()
            },
        ] {
            match ks.check(&ruleset::render(&p)) {
                Ok(()) => {}
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("Operation not permitted") || msg.contains("Permission denied")
                    {
                        eprintln!("SKIPPED: nft --check exige des privileges ({msg})");
                        return;
                    }
                    panic!("ruleset invalide: {msg}\n{}", ruleset::render(&p));
                }
            }
        }
    }
}

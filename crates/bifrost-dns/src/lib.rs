//! Gestion du resolveur systeme pendant la duree du tunnel.
//!
//! Le kill switch fait le gros du travail: sa `policy drop` interdit tout :53
//! sortant qui n'irait pas vers le resolveur de loopback ou vers le tunnel. Ce
//! crate s'occupe du reste, empecher le systeme d'interroger un resolveur
//! pousse par DHCP, ce qui produirait des requetes bloquees et une resolution
//! cassee plutot qu'une fuite.

use std::net::IpAddr;

use bifrost_core::Result;
use bifrost_core::config::DnsPolicy;
use bifrost_core::ports::DnsManager;

#[cfg(target_os = "linux")]
pub mod linux;

/// Le resolveur chiffre embarque. Compile partout: sa configuration est de la
/// donnee, et ses tests n'ont besoin d'aucune plateforme particuliere.
pub mod resolveur;

/// Ce que le resolveur embarque refuse de resoudre. Compile partout, et
/// deliberement: la liste vise des endpoints Windows, mais c'est le resolveur
/// qui l'applique, et il tourne des deux cotes. Une machine Linux qui heberge
/// un poste Windows derriere elle a exactement le meme besoin.
pub mod telemetrie;

#[cfg(windows)]
pub mod windows;

/// Construit le gestionnaire DNS de la plateforme courante.
pub fn new() -> Result<Box<dyn DnsManager>> {
    #[cfg(target_os = "linux")]
    {
        Ok(linux::detect())
    }
    #[cfg(windows)]
    {
        Ok(Box::new(windows::NetshDns::new()))
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        Err(bifrost_core::Error::Unsupported(format!(
            "aucun gestionnaire DNS pour {}",
            std::env::consts::OS
        )))
    }
}

/// Qui le systeme doit interroger, selon qu'un resolveur chiffre est embarque.
///
/// ICI, a la racine du crate, et la raison est datee. Cette fonction vivait
/// dans `linux.rs`, ou sa documentation affirmait deja etre "la seule fonction
/// qui tranche cette question" et que "les deux backends DNS doivent repondre
/// pareil". Windows ne l'appelait pas: `NetshDns::apply` parcourait
/// `policy.upstream` sans jamais regarder `embarque`.
///
/// Mesure du 22/08/2026 par `scripts/service-windows.ps1`, sur un profil
/// demandant `embarque = true` avec `local_resolver = 127.0.0.1`: l'interface
/// du tunnel s'est retrouvee pointee sur `9.9.9.9`, c'est-a-dire sur une
/// destination que le kill switch REFUSE - `block-dns` ne laisse passer le :53
/// que vers le resolveur local. Un resolveur chiffre qui demarre, qui ecoute,
/// et que plus rien n'interroge: la machine perd la resolution de noms au lieu
/// de la chiffrer, et rien dans les journaux ne le dit.
///
/// Une intention ecrite dans un commentaire n'est pas une garantie. Une
/// fonction compilee sur les deux hotes en est une - meme raisonnement que
/// `service::spec::ligne_de_commande`, sorti de `scm.rs` pour la meme raison.
pub fn serveurs_a_interroger(policy: &DnsPolicy) -> Vec<IpAddr> {
    if policy.embarque {
        // Un seul serveur, sur la boucle locale. Y ajouter les amonts en
        // secours annulerait tout: au premier hoquet du resolveur chiffre, le
        // systeme basculerait sur une resolution en clair, silencieusement, et
        // justement le jour ou le chiffrement servait.
        vec![policy.local_resolver]
    } else {
        policy.upstream.clone()
    }
}

/// Adresse par defaut du resolveur local selon la plateforme.
///
/// Sur une Ubuntu moderne, systemd-resolved ecoute sur le stub 127.0.0.53 et
/// `/etc/resolv.conf` pointe dessus. Ailleurs, on retombe sur 127.0.0.1.
pub fn default_local_resolver() -> std::net::IpAddr {
    #[cfg(target_os = "linux")]
    {
        if linux::resolved_is_active() {
            return std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 53));
        }
    }
    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn politique(embarque: bool) -> DnsPolicy {
        DnsPolicy {
            local_resolver: IpAddr::V4(Ipv4Addr::LOCALHOST),
            upstream: vec![
                IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            ],
            embarque,
            anti_telemetrie: bifrost_core::config::ProfilTelemetrie::Aucun,
        }
    }

    /// Le defaut mesure le 22/08/2026 sur essai-windows, en une ligne: un
    /// profil qui embarque un resolveur ne doit designer QUE la boucle locale.
    #[test]
    fn un_resolveur_embarque_se_designe_par_la_boucle_locale() {
        assert_eq!(
            serveurs_a_interroger(&politique(true)),
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
        );
    }

    /// Et le temoin negatif: sans resolveur embarque, la boucle locale n'a
    /// rien a faire la, il n'y a personne pour repondre.
    #[test]
    fn sans_resolveur_embarque_ce_sont_les_amonts() {
        let vus = serveurs_a_interroger(&politique(false));
        assert_eq!(vus, politique(false).upstream);
        assert!(
            !vus.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "la boucle locale ne doit pas apparaitre: rien n y ecoute"
        );
    }

    /// Le point qui a coute la mesure: aucun amont en SECOURS derriere le
    /// resolveur chiffre. Au premier hoquet, le systeme basculerait en clair
    /// sans rien dire, le jour meme ou le chiffrement servait.
    #[test]
    fn le_resolveur_embarque_n_a_aucun_secours_en_clair() {
        let vus = serveurs_a_interroger(&politique(true));
        assert_eq!(vus.len(), 1, "un seul serveur, et pas de repli: {vus:?}");
        for amont in politique(true).upstream {
            assert!(!vus.contains(&amont), "{amont} ne doit pas servir de repli");
        }
    }
}

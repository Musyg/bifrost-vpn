//! Collecte Linux strictement passive de `prove dns`: fichiers du systeme,
//! `/proc`, rtnetlink et le bus systeme D-Bus, en lecture, sans elevation,
//! sans shell, sans programme externe.
//!
//! # Le bus systeme
//!
//! L'adresse est celle que la specification D-Bus fixe au bus systeme,
//! `unix:path=/var/run/dbus/system_bus_socket`. `DBUS_SYSTEM_BUS_ADDRESS`
//! n'est pas lue: la preuve juge le bus que le systeme utilise, pas celui que
//! l'environnement de l'appelant designe. Chaque appel porte `NO_AUTO_START`:
//! un service absent n'est jamais demarre par activation, la preuve le dit
//! absent. Aucun appel ne change d'etat: `Hello`, `GetNameOwner`,
//! `GetConnectionUnixUser`, `Properties.Get`, `Manager.ListDelegates`,
//! `Manager.GetLink`. Les appels a systemd-resolved vont a son nom unique, lu
//! une fois: toutes les reponses d'une lecture viennent de la meme instance.
//!
//! `Properties.GetAll` n'est pas utilise: il rendrait toutes les proprietes du
//! Manager, donc des signatures (`(tt)`, `as`, `a(iiay)`...) que la preuve ne
//! lit pas et qu'un lecteur strict devrait decoder ou refuser.
//!
//! Chaque echange est borne: 2 s, 1 Mio par message.

use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::preuve_dns::dbus::{self, Appel, Attente, Corps, Forme, Issue, Propriete, Valeur};
use crate::preuve_dns::{
    Backend, EtatResolved, Inode, Intention, Lien, Observation, ecoutes_udp, mdns_non_minimal,
    mode_resolv_conf, sources_hosts,
};

/// Le bus systeme, a l'adresse que la specification lui fixe.
const BUS_SYSTEME: &str = "/var/run/dbus/system_bus_socket";
const DELAI: Duration = Duration::from_secs(2);
/// Borne d'un fichier du systeme lu.
const MAX_FICHIER: u64 = 4 * 1024 * 1024;

const NSSWITCH: &str = "/etc/nsswitch.conf";
const MDNS_ALLOW: &str = "/etc/mdns.allow";
const RESOLV_CONF: &str = "/etc/resolv.conf";
/// Les fichiers de systemd-resolved que `resolv_conf_mode()` compare a
/// `/etc/resolv.conf` (`resolved-resolv-conf.h`, systemd v255; le statique
/// est sous `LIBEXECDIR`, `/usr/lib/systemd` sur les distributions mesurees).
const UPLINK: &str = "/run/systemd/resolve/resolv.conf";
const STUB: &str = "/run/systemd/resolve/stub-resolv.conf";
const STATIQUE: &str = "/usr/lib/systemd/resolv.conf";

const CHEMIN_BUS: &str = "/org/freedesktop/DBus";
const RESOLVE1: &str = "org.freedesktop.resolve1";
const CHEMIN_RESOLVE1: &str = "/org/freedesktop/resolve1";
const MANAGER: &str = "org.freedesktop.resolve1.Manager";
const LINK: &str = "org.freedesktop.resolve1.Link";
const PROPRIETES: &str = "org.freedesktop.DBus.Properties";

const SANS_PROPRIETAIRE: &str = "org.freedesktop.DBus.Error.NameHasNoOwner";
const METHODE_INCONNUE: &str = "org.freedesktop.DBus.Error.UnknownMethod";
const LIEN_INCONNU: &str = "org.freedesktop.resolve1.NoSuchLink";

/// Lecture bornee d'un fichier regulier du systeme, liens symboliques suivis
/// comme glibc et systemd-resolved les suivent. `None` s'il n'existe pas.
fn lire_systeme(chemin: &str, erreur: &'static str) -> Result<Option<Vec<u8>>, &'static str> {
    let f = match std::fs::File::open(chemin) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(erreur),
    };
    if !f.metadata().map_err(|_| erreur)?.is_file() {
        return Err(erreur);
    }
    let mut octets = Vec::new();
    f.take(MAX_FICHIER + 1)
        .read_to_end(&mut octets)
        .map_err(|_| erreur)?;
    if octets.len() as u64 > MAX_FICHIER {
        return Err(erreur);
    }
    Ok(Some(octets))
}

/// L'inode d'un fichier, lien symbolique suivi comme `stat()`; `None` s'il
/// n'existe pas. Une autre erreur est fatale pour `/etc/resolv.conf`
/// (resolved rend alors un mode vide), et fait passer le fichier pour les
/// fichiers de resolved, comme resolved le fait.
fn inode(chemin: &str, strict: bool) -> Result<Option<Inode>, &'static str> {
    match std::fs::metadata(chemin) {
        Ok(m) => Ok(Some((m.dev(), m.ino()))),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(_) if !strict => Ok(None),
        Err(_) => Err("mode de /etc/resolv.conf illisible"),
    }
}

/// Le compte effectif du processus, lu dans `/proc/self/status` (`Uid:` porte
/// les comptes reel, effectif, sauve et de systeme de fichiers): c'est lui que
/// le bus lit par SO_PEERCRED, et la bibliotheque n'appelle pas `geteuid`
/// faute de code `unsafe`.
fn uid_effectif() -> Result<u32, &'static str> {
    const ERREUR: &str = "compte du processus illisible";
    compte_effectif(&lire_systeme("/proc/self/status", ERREUR)?.ok_or(ERREUR)?)
}

/// Le compte effectif d'un `/proc/<pid>/status`: la deuxieme colonne de
/// l'unique ligne `Uid:`.
fn compte_effectif(statut: &[u8]) -> Result<u32, &'static str> {
    const ERREUR: &str = "compte du processus illisible";
    let mut lignes = statut
        .split(|&c| c == b'\n')
        .filter(|l| l.starts_with(b"Uid:"));
    let (Some(ligne), None) = (lignes.next(), lignes.next()) else {
        return Err(ERREUR);
    };
    let comptes: Vec<u32> = std::str::from_utf8(&ligne[4..])
        .map_err(|_| ERREUR)?
        .split_ascii_whitespace()
        .map(|t| t.parse().map_err(|_| ERREUR))
        .collect::<Result<_, _>>()?;
    match comptes.as_slice() {
        [_, effectif, _, _] => Ok(*effectif),
        _ => Err(ERREUR),
    }
}

/// Une connexion au bus, apres authentification et `Hello`.
struct Bus {
    flux: UnixStream,
    /// Recu et pas encore consomme.
    recu: Vec<u8>,
    serie: u32,
}

/// Le motif d'un refus rendu par le bus lui-meme.
fn refus(nom: &str) -> &'static str {
    match nom {
        "org.freedesktop.DBus.Error.AccessDenied" => "bus systeme: appel refuse par sa politique",
        "org.freedesktop.DBus.Error.ServiceUnknown" | SANS_PROPRIETAIRE => {
            "systemd-resolved a quitte le bus pendant la lecture"
        }
        _ => "bus systeme: appel refuse",
    }
}

impl Bus {
    fn ouvrir(chemin: &str) -> Result<Self, &'static str> {
        let flux = UnixStream::connect(chemin).map_err(|e| {
            if e.kind() == ErrorKind::PermissionDenied {
                "bus systeme refuse a ce compte"
            } else {
                "bus systeme injoignable"
            }
        })?;
        flux.set_write_timeout(Some(DELAI))
            .map_err(|_| "bus systeme injoignable")?;
        let mut bus = Bus {
            flux,
            recu: Vec::new(),
            serie: 0,
        };
        bus.ecrire(&dbus::requete_authentification(uid_effectif()?))?;
        let debut = Instant::now();
        let n = loop {
            if let Some(n) = dbus::lire_accord(&bus.recu)? {
                break n;
            }
            bus.recevoir(debut)?;
        };
        if bus.recu.len() != n {
            return Err("donnees D-Bus avant la fin de l'authentification");
        }
        bus.recu.clear();
        bus.ecrire(dbus::DEBUT)?;
        match bus.appeler(
            dbus::BUS,
            CHEMIN_BUS,
            dbus::BUS,
            "Hello",
            Corps::Vide,
            Forme::Chaine,
        )? {
            Issue::Retour(Valeur::Chaine(nom)) if dbus::nom_unique_valide(&nom) => Ok(bus),
            _ => Err("bus systeme: Hello refuse"),
        }
    }

    fn ecrire(&mut self, octets: &[u8]) -> Result<(), &'static str> {
        self.flux
            .write_all(octets)
            .map_err(|_| "ecriture sur le bus systeme impossible")
    }

    /// Ajoute a `recu` ce que le bus a envoye, dans le delai restant.
    fn recevoir(&mut self, debut: Instant) -> Result<(), &'static str> {
        const EXPIRE: &str = "delai du bus systeme depasse";
        let reste = DELAI.checked_sub(debut.elapsed()).ok_or(EXPIRE)?;
        if reste.is_zero() {
            return Err(EXPIRE);
        }
        // Une reponse et les signaux qui la precedent: au-dela, refus.
        if self.recu.len() > 2 * dbus::MAX_MESSAGE {
            return Err(dbus::HORS_BORNE);
        }
        self.flux
            .set_read_timeout(Some(reste))
            .map_err(|_| "lecture sur le bus systeme impossible")?;
        let mut tampon = [0_u8; 16 * 1024];
        match self.flux.read(&mut tampon) {
            Ok(0) => Err("bus systeme ferme pendant l'echange"),
            Ok(n) => {
                self.recu.extend_from_slice(&tampon[..n]);
                Ok(())
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => Ok(()),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                Err(EXPIRE)
            }
            Err(_) => Err("lecture sur le bus systeme impossible"),
        }
    }

    fn appeler(
        &mut self,
        destination: &str,
        chemin: &str,
        interface: &str,
        membre: &str,
        corps: Corps,
        forme: Forme,
    ) -> Result<Issue, &'static str> {
        self.serie = self.serie.checked_add(1).ok_or(dbus::HORS_BORNE)?;
        let appel = Appel {
            destination: destination.to_owned(),
            chemin: chemin.to_owned(),
            interface: interface.to_owned(),
            membre: membre.to_owned(),
            corps,
        };
        let trame = dbus::encoder_appel(&appel, self.serie, dbus::ORDRE_NATIF)?;
        self.ecrire(&trame)?;
        let attente = Attente {
            serie: self.serie,
            emetteur: destination,
            forme,
            ordre: dbus::ORDRE_NATIF,
        };
        let debut = Instant::now();
        loop {
            if let Some((issue, n)) = dbus::lire_reponse(&self.recu, &attente)? {
                self.recu.drain(..n);
                return Ok(issue);
            }
            self.recevoir(debut)?;
        }
    }

    /// `Properties.Get` d'une propriete de systemd-resolved.
    fn propriete(
        &mut self,
        service: &str,
        chemin: &str,
        interface: &str,
        nom: &str,
        p: Propriete,
    ) -> Result<Valeur, &'static str> {
        let corps = Corps::DeuxChaines(interface.to_owned(), nom.to_owned());
        match self.appeler(
            service,
            chemin,
            PROPRIETES,
            "Get",
            corps,
            Forme::Variante(p),
        )? {
            Issue::Retour(v) => Ok(v),
            Issue::Erreur(_) => Err("propriete de systemd-resolved refusee"),
            Issue::RefusDuBus(n) => Err(refus(&n)),
        }
    }
}

/// L'etat de systemd-resolved, lu sur le bus a `chemin`, avec, pour chaque
/// lien du namespace courant, `DefaultRoute`, `ScopesMask` et `DNSEx`.
fn lire_resolved(chemin: &str, liens: &[(u32, Vec<u8>)]) -> Result<EtatResolved, &'static str> {
    const FORME: &str = "reponse de systemd-resolved d'une forme inattendue";
    let mut bus = Bus::ouvrir(chemin)?;
    let corps = Corps::Chaine(RESOLVE1.to_owned());
    let proprietaire = match bus.appeler(
        dbus::BUS,
        CHEMIN_BUS,
        dbus::BUS,
        "GetNameOwner",
        corps,
        Forme::Chaine,
    )? {
        Issue::Retour(Valeur::Chaine(n)) if dbus::nom_unique_valide(&n) => n,
        Issue::Erreur(n) if n == SANS_PROPRIETAIRE => {
            return Err("systemd-resolved absent du bus systeme");
        }
        Issue::Erreur(n) | Issue::RefusDuBus(n) => return Err(refus(&n)),
        Issue::Retour(_) => return Err(FORME),
    };
    let corps = Corps::Chaine(proprietaire.clone());
    let uid = match bus.appeler(
        dbus::BUS,
        CHEMIN_BUS,
        dbus::BUS,
        "GetConnectionUnixUser",
        corps,
        Forme::Entier32NonSigne,
    )? {
        Issue::Retour(Valeur::Entier32NonSigne(u)) => u,
        Issue::Erreur(n) | Issue::RefusDuBus(n) => return Err(refus(&n)),
        Issue::Retour(_) => return Err(FORME),
    };
    let p = &proprietaire;
    let Valeur::Serveurs(serveurs) =
        bus.propriete(p, CHEMIN_RESOLVE1, MANAGER, "DNSEx", Propriete::Serveurs)?
    else {
        return Err(FORME);
    };
    let Valeur::Domaines(domaines) =
        bus.propriete(p, CHEMIN_RESOLVE1, MANAGER, "Domains", Propriete::Domaines)?
    else {
        return Err(FORME);
    };
    let Valeur::Chaine(mode) = bus.propriete(
        p,
        CHEMIN_RESOLVE1,
        MANAGER,
        "ResolvConfMode",
        Propriete::Chaine,
    )?
    else {
        return Err(FORME);
    };
    let delegues = match bus.appeler(
        p,
        CHEMIN_RESOLVE1,
        MANAGER,
        "ListDelegates",
        Corps::Vide,
        Forme::ListeDeDelegues,
    )? {
        Issue::Retour(Valeur::Delegues(d)) => d,
        // Avant systemd 258, ni la methode ni les delegues n'existent.
        Issue::Erreur(n) if n == METHODE_INCONNUE => false,
        Issue::Erreur(_) => return Err("liste des delegues DNS refusee"),
        Issue::RefusDuBus(n) => return Err(refus(&n)),
        Issue::Retour(_) => return Err(FORME),
    };
    let mut vus = Vec::with_capacity(liens.len());
    for (index, nom) in liens {
        let index_dbus = i32::try_from(*index).map_err(|_| FORME)?;
        let objet = match bus.appeler(
            p,
            CHEMIN_RESOLVE1,
            MANAGER,
            "GetLink",
            Corps::Entier32(index_dbus),
            Forme::Chemin,
        )? {
            Issue::Retour(Valeur::Chemin(o)) => o,
            Issue::Erreur(n) if n == LIEN_INCONNU => {
                return Err(
                    "systemd-resolved ne connait pas un lien de ce namespace: resolved d'un autre namespace, ou lien trop recent",
                );
            }
            Issue::Erreur(_) => return Err("lien refuse par systemd-resolved"),
            Issue::RefusDuBus(n) => return Err(refus(&n)),
            Issue::Retour(_) => return Err(FORME),
        };
        let Valeur::Booleen(route_par_defaut) =
            bus.propriete(p, &objet, LINK, "DefaultRoute", Propriete::Booleen)?
        else {
            return Err(FORME);
        };
        let Valeur::Entier64(portees) =
            bus.propriete(p, &objet, LINK, "ScopesMask", Propriete::Entier64)?
        else {
            return Err(FORME);
        };
        let Valeur::ServeursDuLien(serveurs) =
            bus.propriete(p, &objet, LINK, "DNSEx", Propriete::ServeursDuLien)?
        else {
            return Err(FORME);
        };
        vus.push(Lien {
            index: *index,
            nom: nom.clone(),
            route_par_defaut,
            portees,
            serveurs,
        });
    }
    Ok(EtatResolved {
        proprietaire,
        uid,
        mode,
        serveurs,
        domaines,
        delegues,
        liens: vus,
    })
}

/// Une lecture complete du systeme, pour l'intention donnee.
pub(crate) fn lire_une_fois(i: &Intention) -> Result<Observation, &'static str> {
    let nsswitch = lire_systeme(NSSWITCH, "nsswitch.conf illisible")?
        .ok_or("nsswitch.conf absent: sources par defaut de glibc, non lues")?;
    let hosts = sources_hosts(&nsswitch)?;
    let mdns_allow = if hosts.iter().any(|s| mdns_non_minimal(s)) {
        Some(
            Path::new(MDNS_ALLOW)
                .try_exists()
                .map_err(|_| "presence de /etc/mdns.allow illisible")?,
        )
    } else {
        None
    };
    const UDP: &str = "/proc/net/udp illisible";
    let mut ecoutes = ecoutes_udp(&lire_systeme("/proc/net/udp", UDP)?.ok_or(UDP)?, false)?;
    if i.embarque && i.local_resolver.is_ipv6() {
        const UDP6: &str = "/proc/net/udp6 illisible";
        ecoutes.extend(ecoutes_udp(
            &lire_systeme("/proc/net/udp6", UDP6)?.ok_or(UDP6)?,
            true,
        )?);
    }
    let mut obs = Observation {
        hosts,
        mdns_allow,
        ecoutes,
        mode: None,
        resolv_conf: lire_systeme(RESOLV_CONF, "/etc/resolv.conf illisible")?,
        tunnel: None,
        resolved: None,
    };
    match i.backend {
        Backend::ResolvConf => {}
        Backend::Resolved => {
            obs.mode = Some(mode_resolv_conf(
                inode(RESOLV_CONF, true)?,
                inode(UPLINK, false)?,
                inode(STUB, false)?,
                inode(STATIQUE, false)?,
            ));
            let liens = crate::preuve_routes_linux::liens()?;
            obs.tunnel = liens
                .iter()
                .find(|(_, n)| n.as_slice() == i.plan.interface.as_bytes())
                .map(|(x, _)| *x);
            obs.resolved = Some(lire_resolved(BUS_SYSTEME, &liens)?.normaliser());
        }
    }
    Ok(obs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    /// Sans privilege, sans bus et sans fichier DNS: les liens et les ecoutes
    /// UDP du namespace courant se lisent, et la boucle locale y est.
    #[test]
    fn liens_et_ecoutes_du_namespace_courant_se_lisent() {
        let liens = crate::preuve_routes_linux::liens().expect("dump des liens");
        assert!(
            liens.iter().any(|(i, n)| *i == 1 && n == b"lo"),
            "{liens:?}"
        );
        let udp = lire_systeme("/proc/net/udp", "illisible")
            .expect("lecture")
            .expect("present");
        ecoutes_udp(&udp, false).expect("en-tete et lignes du noyau");
        assert_eq!(lire_systeme("/proc/absent-9z", "x"), Ok(None));
    }

    /// Le compte lu est celui du processus: proprietaire de `/proc/self`.
    #[test]
    fn le_compte_effectif_est_celui_du_processus() {
        let m = std::fs::metadata("/proc/self").expect("/proc/self");
        assert_eq!(uid_effectif(), Ok(m.uid()));
    }

    /// Le bus lit le compte effectif (SO_PEERCRED): c'est lui que
    /// l'authentification doit porter, pas le compte reel.
    #[test]
    fn le_compte_lu_est_la_deuxieme_colonne_de_uid() {
        let statut = b"Name:\tx\nUid:\t1000\t65534\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(compte_effectif(statut), Ok(65534));
        for illisible in [
            &b"Name:\tx\n"[..],
            b"Uid:\t1000\t65534\t1000\n",
            b"Uid:\t1000\t65534\t1000\t1000\nUid:\t0\t0\t0\t0\n",
            b"Uid:\t1000\t-1\t1000\t1000\n",
        ] {
            assert!(compte_effectif(illisible).is_err(), "{illisible:?}");
        }
    }

    /// Un faux bus, sur un socket d'un repertoire temporaire: le client
    /// complet (authentification, Hello, appels, signaux sautes) sans jamais
    /// joindre le bus systeme. `repondre` recoit la serie et rend la trame.
    fn faux_bus(
        nom: &str,
        accord: &'static [u8],
        repondre: impl Fn(u32) -> Option<Vec<u8>> + Send + 'static,
    ) -> (String, std::thread::JoinHandle<()>) {
        let dossier =
            std::env::temp_dir().join(format!("bifrost-preuve-dns-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir(&dossier).expect("dossier");
        let chemin = dossier.join("bus");
        let ecoute = UnixListener::bind(&chemin).expect("socket");
        let fil = std::thread::spawn(move || {
            let (mut c, _) = ecoute.accept().expect("accept");
            // Le chemin ne sert plus: le dossier part des que le client est la.
            let _ = std::fs::remove_dir_all(&dossier);
            c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut recu = Vec::new();
            let mut t = [0_u8; 4096];
            while !recu.windows(2).any(|w| w == b"\r\n") {
                let n = c.read(&mut t).unwrap_or(0);
                if n == 0 {
                    return;
                }
                recu.extend_from_slice(&t[..n]);
            }
            if c.write_all(accord).is_err() || !accord.starts_with(b"OK") {
                return;
            }
            // Chaque appel: un en-tete de 16 octets, puis ses champs et son
            // corps; la serie est a l'octet 8.
            let mut recu: Vec<u8> = Vec::new();
            let mut commence = false;
            loop {
                if !commence && recu.starts_with(b"BEGIN\r\n") {
                    recu.drain(..7);
                    commence = true;
                }
                while commence && recu.len() >= 16 {
                    let u = |a: usize| u32::from_ne_bytes(recu[a..a + 4].try_into().unwrap());
                    let champs = u(12) as usize;
                    let total = (16 + champs).div_ceil(8) * 8 + u(4) as usize;
                    if recu.len() < total {
                        break;
                    }
                    let serie = u(8);
                    recu.drain(..total);
                    match repondre(serie) {
                        Some(r) => {
                            if c.write_all(&r).is_err() {
                                return;
                            }
                        }
                        None => return,
                    }
                }
                let n = c.read(&mut t).unwrap_or(0);
                if n == 0 {
                    return;
                }
                recu.extend_from_slice(&t[..n]);
            }
        });
        (chemin.to_string_lossy().into_owned(), fil)
    }

    const GUID: &[u8] = b"OK 0123456789abcdef0123456789abcdef\r\n";
    const RESOLVED: &str = ":1.7";

    fn r(serie: u32, emetteur: &str, erreur: Option<&str>, v: Option<(Forme, Valeur)>) -> Vec<u8> {
        dbus::encoder_reponse(
            1000 + serie,
            serie,
            emetteur,
            erreur,
            v.as_ref().map(|(f, v)| (*f, v)),
            dbus::ORDRE_NATIF,
        )
    }

    fn variante(p: Propriete, v: Valeur) -> Option<(Forme, Valeur)> {
        Some((Forme::Variante(p), v))
    }

    /// Les reponses d'un resolved v255 a un lien `lo` (index 1): Hello, puis
    /// un signal, puis GetNameOwner, GetConnectionUnixUser, DNSEx, Domains,
    /// ResolvConfMode, ListDelegates (inconnue), GetLink, DefaultRoute,
    /// ScopesMask, DNSEx du lien. Chaque recette en change une seule.
    fn resolved_v255(serie: u32) -> Option<Vec<u8>> {
        let s = |v: &str| Some((Forme::Chaine, Valeur::Chaine(v.into())));
        Some(match serie {
            1 => {
                let mut v = r(1, dbus::BUS, None, s(":1.9"));
                v.extend(signal_name_acquired());
                v
            }
            2 => r(2, dbus::BUS, None, s(RESOLVED)),
            3 => r(
                3,
                dbus::BUS,
                None,
                Some((Forme::Entier32NonSigne, Valeur::Entier32NonSigne(991))),
            ),
            4 => r(
                4,
                RESOLVED,
                None,
                variante(
                    Propriete::Serveurs,
                    Valeur::Serveurs(vec![dbus::Serveur {
                        index: 1,
                        famille: 2,
                        adresse: vec![192, 0, 2, 1],
                        port: 0,
                        nom: String::new(),
                    }]),
                ),
            ),
            5 => r(
                5,
                RESOLVED,
                None,
                variante(
                    Propriete::Domaines,
                    Valeur::Domaines(vec![dbus::Domaine {
                        index: 1,
                        nom: ".".into(),
                        route_seule: true,
                    }]),
                ),
            ),
            6 => r(
                6,
                RESOLVED,
                None,
                variante(Propriete::Chaine, Valeur::Chaine("stub".into())),
            ),
            7 => r(7, RESOLVED, Some(METHODE_INCONNUE), None),
            8 => r(
                8,
                RESOLVED,
                None,
                Some((
                    Forme::Chemin,
                    Valeur::Chemin("/org/freedesktop/resolve1/link/_31".into()),
                )),
            ),
            9 => r(
                9,
                RESOLVED,
                None,
                variante(Propriete::Booleen, Valeur::Booleen(true)),
            ),
            10 => r(
                10,
                RESOLVED,
                None,
                variante(Propriete::Entier64, Valeur::Entier64(1)),
            ),
            11 => r(
                11,
                RESOLVED,
                None,
                variante(
                    Propriete::ServeursDuLien,
                    Valeur::ServeursDuLien(vec![dbus::Serveur {
                        index: 0,
                        famille: 2,
                        adresse: vec![192, 0, 2, 1],
                        port: 0,
                        nom: String::new(),
                    }]),
                ),
            ),
            _ => return None,
        })
    }

    /// `NameAcquired`, tel que le bus l'envoie apres `Hello`: un signal, que
    /// le lecteur saute.
    fn signal_name_acquired() -> Vec<u8> {
        // Type 4, champs PATH, INTERFACE, MEMBER, SENDER, SIGNATURE; corps `s`.
        let mut v = vec![dbus::ORDRE_NATIF, 4, 0, 1];
        let mut champs = Vec::new();
        let ajouter = |champs: &mut Vec<u8>, code: u8, genre: u8, s: &str| {
            while !champs.len().is_multiple_of(8) {
                champs.push(0);
            }
            champs.extend_from_slice(&[code, 1, genre, 0]);
            if genre == b'g' {
                champs.push(s.len() as u8);
            } else {
                champs.extend_from_slice(&(s.len() as u32).to_ne_bytes());
            }
            champs.extend_from_slice(s.as_bytes());
            champs.push(0);
        };
        ajouter(&mut champs, 1, b'o', "/org/freedesktop/DBus");
        ajouter(&mut champs, 2, b's', "org.freedesktop.DBus");
        ajouter(&mut champs, 3, b's', "NameAcquired");
        ajouter(&mut champs, 7, b's', "org.freedesktop.DBus");
        ajouter(&mut champs, 8, b'g', "s");
        let corps_nom = ":1.9";
        let mut corps = (corps_nom.len() as u32).to_ne_bytes().to_vec();
        corps.extend_from_slice(corps_nom.as_bytes());
        corps.push(0);
        v.extend_from_slice(&(corps.len() as u32).to_ne_bytes());
        v.extend_from_slice(&77_u32.to_ne_bytes());
        v.extend_from_slice(&(champs.len() as u32).to_ne_bytes());
        v.extend_from_slice(&champs);
        while !v.len().is_multiple_of(8) {
            v.push(0);
        }
        v.extend_from_slice(&corps);
        v
    }

    #[test]
    fn le_client_lit_un_resolved_complet_sur_un_faux_bus() {
        let (chemin, fil) = faux_bus("complet", GUID, resolved_v255);
        let e = lire_resolved(&chemin, &[(1, b"lo".to_vec())]).expect("lecture");
        fil.join().unwrap();
        assert_eq!(e.proprietaire, RESOLVED);
        assert_eq!(e.uid, 991);
        assert_eq!(e.mode, "stub");
        assert!(!e.delegues);
        assert_eq!(e.serveurs.len(), 1);
        assert_eq!(e.domaines.len(), 1);
        assert_eq!(
            e.liens,
            vec![Lien {
                index: 1,
                nom: b"lo".to_vec(),
                route_par_defaut: true,
                portees: 1,
                serveurs: vec![dbus::Serveur {
                    index: 0,
                    famille: 2,
                    adresse: vec![192, 0, 2, 1],
                    port: 0,
                    nom: String::new(),
                }],
            }]
        );
    }

    #[test]
    fn un_refus_d_authentification_n_est_pas_une_mesure() {
        let (chemin, fil) = faux_bus("rejet", b"REJECTED EXTERNAL\r\n", |_| None);
        assert_eq!(lire_resolved(&chemin, &[]).unwrap_err(), dbus::REFUSEE);
        fil.join().unwrap();
    }

    #[test]
    fn un_bus_absent_n_est_pas_une_mesure() {
        assert_eq!(
            lire_resolved("/proc/absent-9z/bus", &[]).unwrap_err(),
            "bus systeme injoignable"
        );
    }

    /// La politique du bus refuse l'appel: le bus repond lui-meme.
    #[test]
    fn un_refus_de_politique_n_est_pas_une_mesure() {
        let (chemin, fil) = faux_bus("politique", GUID, |s| match s {
            4 => Some(r(
                4,
                dbus::BUS,
                Some("org.freedesktop.DBus.Error.AccessDenied"),
                None,
            )),
            s => resolved_v255(s),
        });
        assert_eq!(
            lire_resolved(&chemin, &[(1, b"lo".to_vec())]).unwrap_err(),
            "bus systeme: appel refuse par sa politique"
        );
        drop(fil);
    }

    /// Une propriete d'une autre signature que celle attendue.
    #[test]
    fn une_signature_inconnue_n_est_pas_une_mesure() {
        let (chemin, fil) = faux_bus("signature", GUID, |s| match s {
            6 => Some(r(
                6,
                RESOLVED,
                None,
                variante(Propriete::Booleen, Valeur::Booleen(true)),
            )),
            s => resolved_v255(s),
        });
        assert_eq!(
            lire_resolved(&chemin, &[(1, b"lo".to_vec())]).unwrap_err(),
            dbus::SIGNATURE
        );
        drop(fil);
    }

    /// resolved sans proprietaire: absent, jamais demarre par activation.
    #[test]
    fn resolved_absent_du_bus_n_est_pas_une_mesure() {
        let (chemin, fil) = faux_bus("absent", GUID, |s| match s {
            2 => Some(r(2, dbus::BUS, Some(SANS_PROPRIETAIRE), None)),
            s => resolved_v255(s),
        });
        assert_eq!(
            lire_resolved(&chemin, &[]).unwrap_err(),
            "systemd-resolved absent du bus systeme"
        );
        drop(fil);
    }

    /// Un lien d'ici que resolved ne connait pas.
    #[test]
    fn un_lien_inconnu_de_resolved_n_est_pas_une_mesure() {
        let (chemin, fil) = faux_bus("lien", GUID, |s| match s {
            8 => Some(r(8, RESOLVED, Some(LIEN_INCONNU), None)),
            s => resolved_v255(s),
        });
        assert!(
            lire_resolved(&chemin, &[(1, b"lo".to_vec())])
                .unwrap_err()
                .starts_with("systemd-resolved ne connait pas un lien")
        );
        drop(fil);
    }

    /// Des delegues DNS sont lus comme presents.
    #[test]
    fn des_delegues_presents_sont_lus() {
        let (chemin, fil) = faux_bus("delegues", GUID, |s| match s {
            7 => Some(r(
                7,
                RESOLVED,
                None,
                Some((Forme::ListeDeDelegues, Valeur::Delegues(true))),
            )),
            s => resolved_v255(s),
        });
        let e = lire_resolved(&chemin, &[(1, b"lo".to_vec())]).expect("lecture");
        assert!(e.delegues);
        fil.join().unwrap();
    }

    /// Seule une methode inconnue dit qu'il n'y a pas de delegues: une autre
    /// erreur de resolved ne le dit pas.
    #[test]
    fn une_autre_erreur_de_list_delegates_n_est_pas_une_mesure() {
        let (chemin, fil) = faux_bus("delegues-refus", GUID, |s| match s {
            7 => Some(r(
                7,
                RESOLVED,
                Some("org.freedesktop.DBus.Error.AccessDenied"),
                None,
            )),
            s => resolved_v255(s),
        });
        assert_eq!(
            lire_resolved(&chemin, &[(1, b"lo".to_vec())]).unwrap_err(),
            "liste des delegues DNS refusee"
        );
        drop(fil);
    }

    /// Une reponse a l'appel venue d'un autre emetteur que resolved.
    #[test]
    fn une_reponse_d_un_autre_emetteur_n_est_pas_une_mesure() {
        let (chemin, fil) = faux_bus("emetteur", GUID, |s| match s {
            4 => Some(r(
                4,
                ":1.99",
                None,
                variante(Propriete::Serveurs, Valeur::Serveurs(Vec::new())),
            )),
            s => resolved_v255(s),
        });
        assert_eq!(
            lire_resolved(&chemin, &[(1, b"lo".to_vec())]).unwrap_err(),
            dbus::INATTENDUE
        );
        drop(fil);
    }
}

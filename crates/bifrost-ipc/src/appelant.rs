//! Ce qu'un appelant admis par le canal peut demander au daemon.
//!
//! L'acceptation dit QUI ouvre le canal (`SO_PEERCRED` sous Linux, DACL du
//! pipe sous Windows). Elle ne suffit pas a dire ce qu'il peut y demander: un
//! groupe ouvre le canal a des comptes qui ne sont pas administrateurs (le
//! groupe `bifrost` du socket sous Linux, le groupe d'acces du pipe sous
//! Windows, `groupe::GroupeDAcces`), et ceux-la n'ont que trois commandes. La
//! regle, en une phrase, la meme sur les deux plateformes: un appelant admis
//! SEULEMENT parce qu'il est membre du groupe n'a que `status`,
//! `connect-stored` et `disconnect`; un administrateur garde tout le canal.
//! Sous Linux, l'administrateur est un appelant admis par son uid (root, ou
//! un uid de `allowed_uids`); sous Windows, SYSTEM ou un jeton aux
//! Administrateurs actifs. C'est la separation de l'option
//! `LimitedOperatorUI` de WireGuard pour Windows: les membres demarrent et
//! arretent un tunnel enregistre, ils n'en ajoutent ni n'en modifient aucun;
//! sous Windows sur un groupe local cree pour Bifrost, jamais sur un groupe
//! predefini.
//!
//! Trois pieces, separees pour etre jugees chacune:
//!
//! - [`decider`], fonction pure du niveau de l'appelant et de la commande,
//!   commune aux deux plateformes. Chaque commande y est classee par un bras
//!   a elle, sans bras joker: une commande ajoutee au protocole ne compile
//!   pas tant qu'elle n'est pas classee ici.
//! - sous Linux, le niveau tire de la raison de l'admission
//!   ([`niveau_admis`], depuis [`crate::auth::Admission`]): l'appelant est
//!   identifie a l'acceptation, par `SO_PEERCRED`, une fois par connexion.
//! - sous Windows, l'identification de l'appelant, par requete, sur le jeton
//!   que le canal presente au daemon (`identifier`). Elle est SURE PAR
//!   DEFAUT: une identification impossible range l'appelant au niveau
//!   [`NiveauDAppelant::Restreint`], jamais au niveau complet.
//!
//! Le transport applique la decision a chaque requete lue, avant de la rendre
//! au serveur (`Connection::recv`), sur les deux plateformes: une commande
//! refusee recoit sa reponse de refus et ne sort jamais du transport, donc le
//! daemon n'en execute rien.

use crate::auth::Admission;
use crate::protocol::Command;

/// Ce qu'un appelant admis peut demander au daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NiveauDAppelant {
    /// Tout le canal. Sous Windows: un jeton de SYSTEM, ou dont les
    /// Administrateurs sont actifs (une console elevee, le service). Sous
    /// Linux: un appelant que le socket admet par son uid (root, ou un uid
    /// de `allowed_uids`).
    Complet,
    /// `status`, `connect-stored` et `disconnect`, et rien d'autre. Sous
    /// Windows: un appelant admis seulement comme membre du groupe d'acces,
    /// et tout appelant que le daemon n'a pas su identifier. Sous Linux: un
    /// appelant admis seulement par le groupe `bifrost` (gid primaire ou
    /// groupe supplementaire).
    Restreint,
}

impl NiveauDAppelant {
    /// Le nom du niveau, pour le journal.
    pub fn nom(self) -> &'static str {
        match self {
            NiveauDAppelant::Complet => "complet",
            NiveauDAppelant::Restreint => "restreint",
        }
    }
}

/// Le refus d'une commande reservee aux administrateurs, tel que le daemon le
/// rend a l'appelant (`Response::Error`). Il nomme la commande, dit a qui
/// elle est reservee sur cette plateforme (Windows: SYSTEM ou Administrateurs
/// actifs; Linux: root), et ce que ce compte peut demander.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(
    windows,
    error(
        "commande {commande} refusee: reservee aux administrateurs (SYSTEM ou \
         Administrateurs actifs); ce compte n'a sur ce canal que status, \
         connect-stored et disconnect"
    )
)]
#[cfg_attr(
    unix,
    error(
        "commande {commande} refusee: reservee a root; ce compte n'a sur ce \
         canal que status, connect-stored et disconnect"
    )
)]
pub struct CommandeReservee {
    /// Le nom de la commande, celui du protocole (`Command::name`).
    pub commande: &'static str,
}

/// La decision: la commande est-elle admise pour un appelant de ce niveau?
///
/// Fonction pure, sans bras joker, ni ici ni dans
/// [`reservee_aux_administrateurs`]; une recette lit son texte et rougit sur
/// tout bras qui ne nomme pas sa commande.
pub fn decider(niveau: NiveauDAppelant, commande: &Command) -> Result<(), CommandeReservee> {
    match (niveau, reservee_aux_administrateurs(commande)) {
        (NiveauDAppelant::Complet, false | true) => Ok(()),
        (NiveauDAppelant::Restreint, false) => Ok(()),
        (NiveauDAppelant::Restreint, true) => Err(CommandeReservee {
            commande: commande.name(),
        }),
    }
}

/// Le niveau que vaut une admission par le socket (Linux): l'uid admet au
/// niveau complet, le groupe seul au niveau restreint. Pure et commune aux
/// deux plateformes, pour etre jugee sur chacune; seul le transport Unix
/// l'appelle, a l'acceptation.
pub fn niveau_admis(admission: Admission) -> NiveauDAppelant {
    match admission {
        Admission::ParUid => NiveauDAppelant::Complet,
        Admission::ParGroupe => NiveauDAppelant::Restreint,
    }
}

/// La commande est-elle reservee aux administrateurs? Un bras par commande,
/// chacun sur une ligne `Command::<Variante> => true|false,`, et rien
/// d'autre: la forme qu'exige la garde `la_decision_n_a_pas_de_bras_joker`.
///
/// Ouvertes au niveau restreint: l'etat, et les deux gestes de la coquille,
/// `connect-stored` (le profil que le DAEMON detient, enregistre par un
/// administrateur, jamais un profil fourni par l'appelant) et `disconnect`.
/// Tout le reste change ce que le daemon fera ou expose ce qu'il a pose: un
/// profil fourni (`connect`), la suite des sondes (`check`), le verdict
/// d'inspection TLS, la reprise apres veille, les trois declarations.
fn reservee_aux_administrateurs(commande: &Command) -> bool {
    match commande {
        Command::Status => false,
        Command::ConnectStored => false,
        Command::Disconnect => false,
        Command::Connect { .. } => true,
        Command::Check => true,
        Command::VerdictInspectionTls { .. } => true,
        Command::Reprise => true,
        Command::DeclarationPareFeu => true,
        Command::DeclarationRoutage => true,
        Command::DeclarationDns => true,
    }
}

/// L'etape de l'identification qui n'a pas abouti.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtapeDIdentification {
    /// `ImpersonateNamedPipeClient`.
    Imitation,
    /// `OpenThreadToken`: un client qui a ouvert le canal en
    /// `SECURITY_ANONYMOUS` echoue ici (`ERROR_CANT_OPEN_ANONYMOUS`).
    Jeton,
    /// `CheckTokenMembership` pour SYSTEM.
    Systeme,
    /// `CheckTokenMembership` pour les Administrateurs.
    Administrateurs,
}

#[cfg(windows)]
impl EtapeDIdentification {
    /// Le nom de l'etape, pour le journal.
    pub fn nom(self) -> &'static str {
        match self {
            EtapeDIdentification::Imitation => "ImpersonateNamedPipeClient",
            EtapeDIdentification::Jeton => "OpenThreadToken",
            EtapeDIdentification::Systeme => "CheckTokenMembership(SYSTEM)",
            EtapeDIdentification::Administrateurs => "CheckTokenMembership(Administrateurs)",
        }
    }
}

/// Ce que le daemon a lu du jeton sous lequel l'appelant a ouvert le canal.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Identification {
    /// Le jeton est lu: SYSTEM y est-il present, les Administrateurs y
    /// sont-ils actifs. Les deux reponses viennent du systeme
    /// (`CheckTokenMembership`), jamais d'une comparaison de chaines.
    Lue {
        systeme: bool,
        administrateurs: bool,
    },
    /// Le jeton n'a pas pu etre lu: l'etape, et le code du systeme.
    Impossible {
        etape: EtapeDIdentification,
        code: u32,
    },
}

/// Le compte sous lequel l'appelant a ouvert le canal, pour le journal et
/// pour lui seul: son SID, lu sur le jeton meme que l'identification
/// (`GetTokenInformation(TokenUser)`), ou l'etape qui ne l'a pas rendu.
/// Aucune decision ne le lit; la decision reste [`niveau_lu`] de
/// l'[`Identification`].
#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompteDuClient {
    /// La forme canonique du SID (`S-1-5-...`), rendue par le systeme
    /// (`ConvertSidToStringSidW`).
    Lu(String),
    /// Le SID n'a pas ete lu: l'etape qui a echoue, et le code du systeme.
    NonLu { etape: &'static str, code: u32 },
}

#[cfg(windows)]
impl std::fmt::Display for CompteDuClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompteDuClient::Lu(sid) => f.write_str(sid),
            CompteDuClient::NonLu { etape, code } => write!(f, "non lu ({etape}, code {code})"),
        }
    }
}

/// Le niveau que vaut une identification. Sure par defaut: seul un jeton LU,
/// ou SYSTEM est present ou les Administrateurs actifs, vaut le niveau
/// complet; une identification impossible vaut le niveau restreint.
#[cfg(windows)]
pub fn niveau_lu(identification: Identification) -> NiveauDAppelant {
    match identification {
        Identification::Lue {
            systeme: true,
            administrateurs: false | true,
        } => NiveauDAppelant::Complet,
        Identification::Lue {
            systeme: false,
            administrateurs: true,
        } => NiveauDAppelant::Complet,
        Identification::Lue {
            systeme: false,
            administrateurs: false,
        } => NiveauDAppelant::Restreint,
        Identification::Impossible { .. } => NiveauDAppelant::Restreint,
    }
}

#[cfg(windows)]
pub(crate) use imp::identifier;

#[cfg(windows)]
mod imp {
    //! L'identification de l'appelant, par le jeton que le canal presente.
    //!
    //! # Pourquoi l'imitation du client, et pas le jeton de son processus
    //!
    //! Mesure du 16/10/2026 sur dev-windows (sonde hors du depot, compte non
    //! eleve, Windows 10 19045), sur un pipe a ce compte:
    //!
    //! - `ImpersonateNamedPipeClient` aboutit avant comme apres la lecture
    //!   d'une premiere requete; le jeton du fil est alors un jeton
    //!   d'imitation au niveau qu'a demande le client (`SecurityIdentification`
    //!   pour le client de ce depot), et `CheckTokenMembership` le lit;
    //! - un client en `SECURITY_ANONYMOUS` passe l'imitation, puis
    //!   `OpenThreadToken` echoue (1347, `ERROR_CANT_OPEN_ANONYMOUS`): il
    //!   n'est pas identifiable, et ne vaut donc que le niveau restreint;
    //! - apres `RevertToSelf`, le fil n'a plus de jeton (`OpenThreadToken`
    //!   rend 1008, `ERROR_NO_TOKEN`);
    //! - 1000 identifications prennent 13 ms (sonde non optimisee).
    //!
    //! L'autre moyen, `GetNamedPipeClientProcessId` puis le jeton primaire de
    //! ce processus, est ecarte: un numero de processus se reutilise (la
    //! poignee du pipe peut survivre au processus qui l'a ouvert, dans un
    //! autre processus du meme compte), et le jeton primaire n'est pas
    //! forcement celui sous lequel le client a ouvert le canal, un fil qui
    //! emprunte une autre identite y presentant la sienne. Le jeton d'imitation
    //! est exactement celui que le canal a capture a l'ouverture.
    //!
    //! # Le fil rendu a son jeton, sur tous les chemins
    //!
    //! L'imitation change le jeton du FIL qui l'appelle: un fil du runtime,
    //! qui sert ensuite d'autres taches. Elle ne dure que le temps d'ouvrir le
    //! jeton du fil (`OpenThreadToken`), sans aucun `await` entre les deux; la
    //! garde [`Emprunt`], creee AVANT l'appel, appelle `RevertToSelf` a sa
    //! destruction, panique comprise. Si `RevertToSelf` echouait, le fil
    //! continuerait sous l'identite du client: la documentation de la fonction
    //! demande alors d'arreter le processus, et la garde le fait (`abort`).
    //! Le daemon s'arrete avec son kill switch dans l'etat ou il est, comme
    //! sur toute mort du processus.

    use super::{CompteDuClient, EtapeDIdentification, Identification};
    use std::os::windows::io::RawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
    use windows_sys::Win32::Security::{
        CheckTokenMembership, CreateWellKnownSid, GetTokenInformation, PSID, RevertToSelf,
        SECURITY_MAX_SID_SIZE, TOKEN_QUERY, TOKEN_USER, TokenUser, WELL_KNOWN_SID_TYPE,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
    use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

    fn derniere_erreur() -> u32 {
        // SAFETY: GetLastError ne lit que l'etat du fil courant.
        unsafe { GetLastError() }
    }

    /// Le fil courant rendu a son propre jeton a la destruction de la garde.
    struct Emprunt;

    impl Drop for Emprunt {
        fn drop(&mut self) {
            // SAFETY: sans argument; rend au fil courant le jeton du processus.
            // Sans imitation en cours, il n'a rien a rendre et aboutit.
            if unsafe { RevertToSelf() } == 0 {
                // Le fil agirait sous l'identite du client: rien ne doit plus
                // tourner dans ce processus.
                std::process::abort();
            }
        }
    }

    /// Un jeton ouvert, ferme a la destruction.
    struct Jeton(HANDLE);

    impl Drop for Jeton {
        fn drop(&mut self) {
            // SAFETY: la poignee vient d'un OpenThreadToken reussi et n'est
            // fermee qu'ici.
            unsafe { CloseHandle(self.0) };
        }
    }

    /// Le SID est-il present et actif dans le jeton, selon le systeme?
    fn present(jeton: &Jeton, genre: WELL_KNOWN_SID_TYPE) -> Result<bool, u32> {
        // Aligne sur 4 octets, comme un SID.
        let mut sid = [0u32; (SECURITY_MAX_SID_SIZE as usize).div_ceil(4)];
        let mut taille = (sid.len() * 4) as u32;
        // SAFETY: le tampon fait au moins SECURITY_MAX_SID_SIZE octets et sa
        // taille est passee; ni SYSTEM ni les Administrateurs n'exigent de SID
        // de domaine.
        let cree = unsafe {
            CreateWellKnownSid(
                genre,
                std::ptr::null_mut(),
                sid.as_mut_ptr() as PSID,
                &mut taille,
            )
        };
        if cree == 0 {
            return Err(derniere_erreur());
        }
        let mut est = 0;
        // SAFETY: `jeton.0` est un jeton d'imitation ouvert en TOKEN_QUERY et
        // vivant; le SID vient d'etre cree dans un tampon vivant; `est` est
        // une variable locale.
        let lu = unsafe { CheckTokenMembership(jeton.0, sid.as_mut_ptr() as PSID, &mut est) };
        if lu == 0 {
            return Err(derniere_erreur());
        }
        Ok(est != 0)
    }

    /// Le SID du compte du jeton, sous sa forme canonique: `TokenUser`, puis
    /// la conversion du systeme. Pour le journal: rien ne le compare a quoi
    /// que ce soit.
    fn compte(jeton: &Jeton) -> CompteDuClient {
        const ETAPE: &str = "GetTokenInformation(TokenUser)";
        let mut taille = 0u32;
        // SAFETY: sonde de taille, tampon nul de longueur zero; le systeme
        // n'ecrit que `taille`, une variable locale.
        unsafe { GetTokenInformation(jeton.0, TokenUser, std::ptr::null_mut(), 0, &mut taille) };
        if taille == 0 {
            return CompteDuClient::NonLu {
                etape: ETAPE,
                code: derniere_erreur(),
            };
        }
        // Aligne sur 8 octets: un TOKEN_USER commence par un pointeur.
        let mut tampon = vec![0u64; (taille as usize).div_ceil(8)];
        // SAFETY: `jeton.0` est un jeton ouvert en TOKEN_QUERY et vivant; le
        // tampon, vivant, fait au moins `taille` octets, et sa taille est
        // passee.
        let lu = unsafe {
            GetTokenInformation(
                jeton.0,
                TokenUser,
                tampon.as_mut_ptr().cast(),
                taille,
                &mut taille,
            )
        };
        if lu == 0 {
            return CompteDuClient::NonLu {
                etape: ETAPE,
                code: derniere_erreur(),
            };
        }
        // SAFETY: le tampon commence par le TOKEN_USER que le systeme vient
        // d'y ecrire, et son SID pointe dans ce meme tampon.
        let sid = unsafe { (*tampon.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        // SAFETY: SID valide, dans le tampon vivant jusqu'a la fin de l'appel.
        match unsafe { crate::groupe::forme_canonique(sid) } {
            Ok(texte) => CompteDuClient::Lu(texte),
            Err(code) => CompteDuClient::NonLu {
                etape: "ConvertSidToStringSidW",
                code,
            },
        }
    }

    /// Identifie le client de l'instance `pipe`: le jeton sous lequel il a
    /// ouvert le canal, lu par le systeme. Ne panique pas; toute etape qui
    /// echoue rend [`Identification::Impossible`]. Le fil courant est rendu a
    /// son jeton avant le retour, quel que soit le chemin.
    ///
    /// Rend aussi le compte de ce jeton ([`CompteDuClient`]), pour le
    /// journal: lu sur le jeton deja ouvert, apres l'imitation, et sans effet
    /// sur l'identification. Un compte illisible laisse l'identification
    /// telle quelle; une identification impossible avant l'ouverture du jeton
    /// rend un compte non lu, a la meme etape et au meme code.
    pub(crate) fn identifier(pipe: RawHandle) -> (Identification, CompteDuClient) {
        let emprunt = Emprunt;
        // SAFETY: `pipe` est la poignee d'une instance serveur que l'appelant
        // tient pendant l'appel; la fonction ne lit ni n'ecrit la memoire de
        // ce processus. Le fil emprunte l'identite du client jusqu'a la
        // destruction d'`emprunt`, quelques lignes plus bas.
        if unsafe { ImpersonateNamedPipeClient(pipe as HANDLE) } == 0 {
            let code = derniere_erreur();
            drop(emprunt);
            return impossible(EtapeDIdentification::Imitation, code);
        }
        let mut poignee: HANDLE = std::ptr::null_mut();
        // SAFETY: pseudo-poignee du fil courant, toujours valide; `poignee`
        // est une variable locale qui recoit un jeton, ferme par `Jeton`.
        // OpenAsSelf: l'acces au jeton du fil est juge sous l'identite du
        // processus, et non sous celle, d'identification seulement, du client.
        let ouvert = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut poignee) };
        let code = if ouvert == 0 { derniere_erreur() } else { 0 };
        drop(emprunt);
        if ouvert == 0 {
            return impossible(EtapeDIdentification::Jeton, code);
        }
        let jeton = Jeton(poignee);
        let compte = compte(&jeton);
        let systeme = match present(&jeton, WinLocalSystemSid) {
            Ok(oui) => oui,
            Err(code) => {
                return (
                    Identification::Impossible {
                        etape: EtapeDIdentification::Systeme,
                        code,
                    },
                    compte,
                );
            }
        };
        let administrateurs = match present(&jeton, WinBuiltinAdministratorsSid) {
            Ok(oui) => oui,
            Err(code) => {
                return (
                    Identification::Impossible {
                        etape: EtapeDIdentification::Administrateurs,
                        code,
                    },
                    compte,
                );
            }
        };
        (
            Identification::Lue {
                systeme,
                administrateurs,
            },
            compte,
        )
    }

    /// Une identification impossible avant que le jeton soit ouvert: aucun
    /// compte a lire, et le compte dit pourquoi, par la meme etape.
    fn impossible(etape: EtapeDIdentification, code: u32) -> (Identification, CompteDuClient) {
        (
            Identification::Impossible { etape, code },
            CompteDuClient::NonLu {
                etape: etape.nom(),
                code,
            },
        )
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Une commande de chaque sorte, et ce que la decision doit en dire au
    /// niveau restreint (`true`: admise). Le niveau complet les admet toutes.
    /// Partagee avec les recettes du transport.
    pub(crate) fn une_de_chaque() -> Vec<(Command, bool)> {
        let config = serde_json::from_value(serde_json::json!({
            "interface": "wg0",
            "private_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA=",
            "addresses": ["10.2.0.2/32"],
            "peer": {
                "public_key": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbA=",
                "endpoint": { "addr": "203.0.113.7:51820" },
                "allowed_ips": ["0.0.0.0/0"]
            },
            "dns": { "local_resolver": "127.0.0.1", "upstream": ["10.2.0.1"] }
        }))
        .expect("profil de recette");
        vec![
            (Command::Status, true),
            (Command::ConnectStored, true),
            (Command::Disconnect, true),
            (
                Command::Connect {
                    config: Box::new(config),
                },
                false,
            ),
            (Command::Check, false),
            (Command::VerdictInspectionTls { intercepte: true }, false),
            (Command::Reprise, false),
            (Command::DeclarationPareFeu, false),
            (Command::DeclarationRoutage, false),
            (Command::DeclarationDns, false),
        ]
    }

    /// Les variantes de `Command`, lues dans le texte de `protocol.rs`: les
    /// lignes de l'enum indentees de quatre espaces qui commencent par une
    /// majuscule.
    fn variantes_du_protocole() -> BTreeSet<String> {
        let source = include_str!("protocol.rs");
        let debut = source
            .find("\npub enum Command {\n")
            .expect("pub enum Command dans protocol.rs");
        let mut variantes = BTreeSet::new();
        for ligne in source[debut..].lines().skip(2) {
            if ligne == "}" {
                break;
            }
            if let Some(reste) = ligne.strip_prefix("    ")
                && reste.starts_with(|c: char| c.is_ascii_uppercase())
            {
                let nom: String = reste
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                assert!(variantes.insert(nom.clone()), "variante en double: {nom}");
            }
        }
        variantes
    }

    /// Chaque commande, a chaque niveau: le niveau complet les admet toutes;
    /// le niveau restreint admet `status`, `connect-stored` et `disconnect`,
    /// et refuse chacune des autres par un refus qui la nomme. La table
    /// couvre toutes les variantes du protocole: une commande ajoutee sans
    /// ligne ici rougit.
    #[test]
    fn la_decision_classe_chaque_commande_pour_chaque_niveau() {
        let table = une_de_chaque();
        let noms: BTreeSet<&str> = table.iter().map(|(c, _)| c.name()).collect();
        assert_eq!(noms.len(), table.len(), "deux lignes pour une commande");
        assert_eq!(
            table.len(),
            variantes_du_protocole().len(),
            "la table ne couvre pas toutes les commandes du protocole: {noms:?}"
        );
        let mut admises = Vec::new();
        for (commande, admise) in &table {
            assert_eq!(
                decider(NiveauDAppelant::Complet, commande),
                Ok(()),
                "niveau complet, {}",
                commande.name()
            );
            let issue = decider(NiveauDAppelant::Restreint, commande);
            if *admise {
                assert_eq!(issue, Ok(()), "niveau restreint, {}", commande.name());
                admises.push(commande.name());
            } else {
                let refus = issue.expect_err(commande.name());
                assert_eq!(refus.commande, commande.name());
                assert_eq!(refus.to_string(), refus_attendu(commande.name()));
            }
        }
        assert_eq!(admises, ["status", "connect-stored", "disconnect"]);
    }

    /// Le texte du refus sous Windows, tel qu'il etait avant la regle Linux,
    /// octet pour octet.
    #[cfg(windows)]
    pub(crate) fn refus_attendu(commande: &str) -> String {
        format!(
            "commande {} refusee: reservee aux administrateurs (SYSTEM ou \
             Administrateurs actifs); ce compte n'a sur ce canal que status, \
             connect-stored et disconnect",
            commande
        )
    }

    /// Le texte du refus sous Linux: reservee a root.
    #[cfg(unix)]
    pub(crate) fn refus_attendu(commande: &str) -> String {
        format!(
            "commande {} refusee: reservee a root; ce compte n'a sur ce canal \
             que status, connect-stored et disconnect",
            commande
        )
    }

    /// Le refus nomme la regle de SA plateforme, et seulement elle: sous
    /// Windows le texte d'avant, inchange, qui nomme SYSTEM et les
    /// Administrateurs actifs; sous Linux root, sans rien de Windows.
    #[test]
    fn le_refus_nomme_la_regle_de_sa_plateforme() {
        let texte = CommandeReservee { commande: "check" }.to_string();
        #[cfg(windows)]
        assert_eq!(
            texte,
            "commande check refusee: reservee aux administrateurs (SYSTEM ou Administrateurs \
             actifs); ce compte n'a sur ce canal que status, connect-stored et disconnect"
        );
        #[cfg(unix)]
        {
            assert_eq!(
                texte,
                "commande check refusee: reservee a root; ce compte n'a sur ce canal que \
                 status, connect-stored et disconnect"
            );
            assert!(
                !texte.contains("SYSTEM") && !texte.contains("Administrateurs"),
                "{texte}"
            );
        }
    }

    /// La raison de l'admission par le socket vaut son niveau: l'uid le
    /// niveau complet, le groupe seul le niveau restreint; et ce niveau-la
    /// refuse chacune des sept commandes reservees.
    #[test]
    fn l_admission_par_le_groupe_seul_vaut_le_niveau_restreint() {
        assert_eq!(niveau_admis(Admission::ParUid), NiveauDAppelant::Complet);
        assert_eq!(
            niveau_admis(Admission::ParGroupe),
            NiveauDAppelant::Restreint
        );
        let refusees: Vec<&str> = une_de_chaque()
            .iter()
            .filter(|(c, _)| decider(niveau_admis(Admission::ParGroupe), c).is_err())
            .map(|(c, _)| c.name())
            .collect();
        assert_eq!(
            refusees,
            [
                "connect",
                "check",
                "verdict-inspection-tls",
                "reprise",
                "declaration-pare-feu",
                "declaration-routage",
                "declaration-dns"
            ]
        );
        assert!(
            une_de_chaque()
                .iter()
                .all(|(c, _)| decider(niveau_admis(Admission::ParUid), c).is_ok())
        );
    }

    /// Le corps d'une fonction de `appelant.rs`, de sa signature a la ligne
    /// `}` qui la ferme (indentation nulle), commentaires retires.
    fn corps(signature: &str) -> Vec<String> {
        let source = include_str!("appelant.rs");
        let debut = source
            .find(&format!("\n{signature}\n"))
            .unwrap_or_else(|| panic!("`{signature}` dans appelant.rs"));
        source[debut..]
            .lines()
            .skip(2)
            .take_while(|l| *l != "}")
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with("//"))
            .map(str::to_owned)
            .collect()
    }

    /// Aucun bras joker dans la decision.
    ///
    /// `reservee_aux_administrateurs` n'est qu'un `match commande`, et chaque
    /// ligne de ce `match` est `Command::<Variante> => true,` ou `=> false,`
    /// (`{ .. }` apres une variante a champs): un `_`, une liaison
    /// (`autre =>`), une alternative (`A | B`) ou un bras sur plusieurs lignes
    /// n'ont pas cette forme, et la garde les nomme. Les variantes nommees
    /// sont exactement celles de l'enum, une fois chacune. `decider` n'a que
    /// des bras qui nomment le niveau, sans `_` ni `..`.
    #[test]
    fn la_decision_n_a_pas_de_bras_joker() {
        let lignes = corps("fn reservee_aux_administrateurs(commande: &Command) -> bool {");
        assert_eq!(
            lignes.first().map(String::as_str),
            Some("match commande {"),
            "le corps doit etre un seul match sur la commande: {lignes:?}"
        );
        assert_eq!(
            lignes.last().map(String::as_str),
            Some("}"),
            "rien apres le match: {lignes:?}"
        );
        let mut hors_forme = Vec::new();
        let mut nommees = Vec::new();
        for ligne in &lignes[1..lignes.len() - 1] {
            let forme = ligne
                .strip_prefix("Command::")
                .and_then(|reste| {
                    let nom: String = reste
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric())
                        .collect();
                    let suite = &reste[nom.len()..];
                    let suite = suite.strip_prefix(" { .. }").unwrap_or(suite);
                    matches!(suite, " => true," | " => false,").then_some(nom)
                })
                .filter(|nom| !nom.is_empty());
            match forme {
                Some(nom) => nommees.push(nom),
                None => hors_forme.push(ligne.clone()),
            }
        }
        assert!(
            hors_forme.is_empty(),
            "bras hors de la forme `Command::<Variante> => true|false,`: {hors_forme:?}"
        );
        let uniques: BTreeSet<String> = nommees.iter().cloned().collect();
        assert_eq!(uniques.len(), nommees.len(), "variante classee deux fois");
        assert_eq!(
            uniques,
            variantes_du_protocole(),
            "les bras ne nomment pas exactement les variantes de Command"
        );

        let decision = corps(
            "pub fn decider(niveau: NiveauDAppelant, commande: &Command) -> Result<(), CommandeReservee> {",
        );
        for ligne in decision.iter().filter(|l| l.contains("=>")) {
            assert!(
                ligne.starts_with("(NiveauDAppelant::"),
                "bras de decider qui ne nomme pas le niveau: {ligne}"
            );
        }
        let texte = decision.join(" ");
        assert!(!texte.contains(".."), "`..` dans decider: {texte}");
        let octets = texte.as_bytes();
        for (rang, octet) in octets.iter().enumerate() {
            let voisin = |i: Option<usize>| {
                i.and_then(|i| octets.get(i))
                    .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
            };
            assert!(
                *octet != b'_' || voisin(rang.checked_sub(1)) || voisin(Some(rang + 1)),
                "`_` seul dans decider: {texte}"
            );
        }
    }

    /// Une identification impossible, a chaque etape et quel que soit le
    /// code, vaut le niveau restreint; un jeton lu vaut le niveau complet
    /// seulement avec SYSTEM ou les Administrateurs actifs.
    #[cfg(windows)]
    #[test]
    fn une_identification_impossible_vaut_le_niveau_restreint() {
        use EtapeDIdentification::{Administrateurs, Imitation, Jeton, Systeme};
        for etape in [Imitation, Jeton, Systeme, Administrateurs] {
            for code in [0, 5, 1347, u32::MAX] {
                assert_eq!(
                    niveau_lu(Identification::Impossible { etape, code }),
                    NiveauDAppelant::Restreint,
                    "{etape:?} {code}"
                );
            }
        }
        for (systeme, administrateurs, niveau) in [
            (false, false, NiveauDAppelant::Restreint),
            (false, true, NiveauDAppelant::Complet),
            (true, false, NiveauDAppelant::Complet),
            (true, true, NiveauDAppelant::Complet),
        ] {
            assert_eq!(
                niveau_lu(Identification::Lue {
                    systeme,
                    administrateurs
                }),
                niveau,
                "systeme={systeme} administrateurs={administrateurs}"
            );
        }
    }
}

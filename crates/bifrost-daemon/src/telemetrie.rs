//! Le versant impur de [`bifrost_telemetrie`]: ce qui touche vraiment la
//! machine.
//!
//! Tout le jugement vit dans le crate pur - quoi poser, pourquoi, comment le
//! defaire. Ici il n'y a que des acces: le registre, le gestionnaire de taches,
//! et le jeton du processus courant. Meme partage que
//! [`bifrost_evasion::carnet`] et [`crate::carnet`], et meme benefice: le
//! catalogue et la reversibilite se verifient sur les deux hotes, seule la pose
//! demande Windows.
//!
//! # Ce que ce module refuse de faire
//!
//! **Poser un reglage de ruche utilisateur quand il tourne sous SYSTEM.** Le
//! daemon tourne en service; `HKEY_CURRENT_USER` y designe la ruche de SYSTEM,
//! pas celle de la personne devant l'ecran. Un reglage de vie privee pose la ne
//! protege personne et se lirait pourtant comme une protection. Le piege est
//! deja documente en tete de [`crate::checks::doh_registre`], ou il touchait la
//! LECTURE; ici il toucherait l'ECRITURE, ce qui est pire: on laisserait des
//! traces dans une ruche de service en croyant proteger un utilisateur.
//! [`Issue::Refuse`] dit la raison; c'est une mesure qui n'a pas eu lieu, pas
//! un echec, et surtout pas un succes.
//!
//! **Supprimer une cle qui n'est pas vide.** `RegDeleteKeyW` efface une cle
//! avec toutes ses valeurs; seules ses sous-cles l'en empechent. Rendre la
//! machine a son etat d'avant ne doit pas emporter ce qu'un autre outil aurait
//! ecrit entre-temps sous la meme cle. Le retour en arriere compte donc valeurs
//! et sous-cles avant de supprimer, et s'abstient s'il en reste.
//!
//! # Ce qu'il fait apres avoir ecrit
//!
//! Il relit. Toujours. Winhance, defaut 281 du 29 decembre 2025: un
//! interrupteur intitule "Disable" qui ecrivait 1, sur Windows 11 Enterprise
//! 24H2. L'outil affichait le bon etat parce qu'il affichait SON etat, pas
//! celui de la machine. [`Issue::Echoue`] est reserve a ce cas-la: ecrit, puis
//! relu different.

use std::path::Path;
use std::process::Command;

use bifrost_telemetrie::catalogue::{Cible, Profil, Reglage, Ruche};
use bifrost_telemetrie::journal::{Avant, Entree, Issue, Journal};
use bifrost_telemetrie::taches;
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SUCCESS};
use windows_sys::Win32::Security::{
    GetSidIdentifierAuthority, GetSidSubAuthority, GetSidSubAuthorityCount, TOKEN_QUERY,
    TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_SET_VALUE, REG_DWORD, REG_OPTION_NON_VOLATILE,
    RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegDeleteValueW, RegQueryInfoKeyW, RegSetValueExW,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::checks::doh_registre::{cle_existe, lire_dword};

/// La ruche des services. Leur `Start` s'y lit et s'y ecrit, ce qui contourne
/// les refus d'acces que le document 03 releve sur `sc config` pour DoSvc.
const SERVICES: &str = r"SYSTEM\CurrentControlSet\Services";

/// Une ligne de rapport: ce qui a ete tente, sur quoi, et ce que ca a donne.
#[derive(Debug, Clone)]
pub struct Ligne {
    pub id: &'static str,
    pub cible: String,
    pub issue: Issue,
}

/// Ce qu'une commande a fait, ligne par ligne.
#[derive(Debug, Clone, Default)]
pub struct Rapport {
    pub lignes: Vec<Ligne>,
}

impl Rapport {
    pub fn compte(&self, mot: &str) -> usize {
        self.lignes.iter().filter(|l| l.issue.mot() == mot).count()
    }

    /// Le code de sortie: 1 des qu'une seule ligne est en ECHEC.
    ///
    /// SANS OBJET et REFUSE n'y entrent pas: ce sont des mesures qui n'ont pas
    /// eu lieu et qui le disent, pas des defauts de la machine.
    pub fn code(&self) -> i32 {
        i32::from(self.lignes.iter().any(|l| l.issue.est_un_echec()))
    }

    pub fn imprimer(&self) {
        for l in &self.lignes {
            match l.issue.raison() {
                None => println!("{:<11} {:<40} {}", l.issue.mot(), l.id, l.cible),
                Some(r) => println!(
                    "{:<11} {:<40} {}\n            {}",
                    l.issue.mot(),
                    l.id,
                    l.cible,
                    r
                ),
            }
        }
    }
}

/// Chaine UTF-16 terminee par un zero, comme l'attend l'API Win32.
fn w(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Vrai si le processus courant tourne sous `S-1-5-18`, LocalSystem.
///
/// Le SID est compare a la main plutot que converti en chaine: c'est la meme
/// lecture que [`bifrost_firewall::wfp_plan::est_sid_de_service`], elle ne
/// demande aucune fonctionnalite supplementaire, et elle ne depend d'aucune
/// mise en forme.
pub fn tourne_sous_systeme() -> bool {
    // SAFETY: bloc d'appels Win32 sur le jeton du processus courant.
    // GetCurrentProcess rend une pseudo-poignee valide; `jeton` est ferme sur
    // chaque chemin de sortie. Le premier GetTokenInformation ne renseigne que
    // `taille`, le second remplit `tampon` de `taille` octets. Le TOKEN_USER lu au
    // debut de `tampon` fournit `sid`, verifie non nul avant chaque
    // dereferencement; la sous-autorite 0 n'est lue qu'apres avoir verifie que le
    // compte vaut 1.
    unsafe {
        let mut jeton = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut jeton) == 0 {
            return false;
        }
        let mut taille: u32 = 0;
        // Premier appel sans tampon: il ne fait que renseigner la taille.
        windows_sys::Win32::Security::GetTokenInformation(
            jeton,
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut taille,
        );
        if taille == 0 {
            windows_sys::Win32::Foundation::CloseHandle(jeton);
            return false;
        }
        let mut tampon = vec![0u8; taille as usize];
        let ok = windows_sys::Win32::Security::GetTokenInformation(
            jeton,
            TokenUser,
            tampon.as_mut_ptr().cast(),
            taille,
            &mut taille,
        );
        windows_sys::Win32::Foundation::CloseHandle(jeton);
        if ok == 0 {
            return false;
        }
        let info: *const TOKEN_USER = tampon.as_ptr().cast();
        let sid = (*info).User.Sid;
        if sid.is_null() {
            return false;
        }
        let autorite = GetSidIdentifierAuthority(sid);
        if autorite.is_null() || (*autorite).Value != [0, 0, 0, 0, 0, 5] {
            return false;
        }
        let compte = GetSidSubAuthorityCount(sid);
        if compte.is_null() || *compte != 1 {
            return false;
        }
        *GetSidSubAuthority(sid, 0) == 18
    }
}

/// Le numero de build complet, tel que le registre le porte.
///
/// Le registre et non `GetVersionEx`, qui ment selon le manifeste de
/// l'executable qui l'appelle. `CurrentBuild` est une chaine, `UBR` un DWORD:
/// les deux ensemble donnent le numero que `ver` affiche.
///
/// Le journal le garde parce que le moteur de derive en aura besoin: une mise a
/// jour de fonctionnalite change ce numero ET remet DiagTrack en automatique.
pub fn build_du_systeme() -> String {
    const CLE: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    match (
        crate::checks::doh_registre::lire_chaine(HKEY_LOCAL_MACHINE, CLE, "CurrentBuild"),
        lire_dword(HKEY_LOCAL_MACHINE, CLE, "UBR"),
    ) {
        (Some(b), Some(u)) => format!("10.0.{b}.{u}"),
        (Some(b), None) => format!("10.0.{b}"),
        (None, _) => "build inconnue".to_owned(),
    }
}

/// Ce qu'on a trouve sur la machine avant d'y toucher.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Observation {
    Dword(u32),
    ValeurAbsente,
    CleAbsente,
    Tache {
        activee: bool,
    },
    /// La cible n'existe pas sur cette machine, avec la raison.
    SansObjet(String),
}

impl Observation {
    fn en_clair(&self) -> String {
        match self {
            Observation::Dword(v) => format!("valeur {v}"),
            Observation::ValeurAbsente => "valeur absente".into(),
            Observation::CleAbsente => "cle absente".into(),
            Observation::Tache { activee: true } => "tache active".into(),
            Observation::Tache { activee: false } => "tache desactivee".into(),
            Observation::SansObjet(r) => format!("sans objet: {r}"),
        }
    }

    /// Vrai si l'observation correspond deja a ce que la cible veut.
    fn conforme_a(&self, cible: &Cible) -> bool {
        match (self, cible) {
            (Observation::Dword(v), Cible::Dword { voulu, .. }) => v == voulu,
            (Observation::Dword(v), Cible::Service { voulu, .. }) => v == voulu,
            (Observation::Tache { activee }, Cible::Tache { .. }) => !activee,
            _ => false,
        }
    }

    fn en_avant(&self) -> Option<Avant> {
        match self {
            Observation::Dword(v) => Some(Avant::Dword { valeur: *v }),
            Observation::ValeurAbsente => Some(Avant::ValeurAbsente),
            Observation::CleAbsente => Some(Avant::CleEtValeurAbsentes),
            Observation::Tache { activee } => Some(Avant::Tache { activee: *activee }),
            Observation::SansObjet(_) => None,
        }
    }
}

fn racine(ruche: Ruche) -> HKEY {
    match ruche {
        Ruche::Machine => HKEY_LOCAL_MACHINE,
        Ruche::Utilisateur => HKEY_CURRENT_USER,
    }
}

fn observer(cible: &Cible) -> Observation {
    match cible {
        Cible::Dword {
            ruche, cle, valeur, ..
        } => {
            let r = racine(*ruche);
            if !cle_existe(r, cle) {
                return Observation::CleAbsente;
            }
            match lire_dword(r, cle, valeur) {
                Some(v) => Observation::Dword(v),
                None => Observation::ValeurAbsente,
            }
        }
        Cible::Service { nom, .. } => {
            let cle = format!("{SERVICES}\\{nom}");
            if !cle_existe(HKEY_LOCAL_MACHINE, &cle) {
                return Observation::SansObjet(format!(
                    "le service {nom} n'existe pas sur cette machine. Le \
                     compter comme desactive annoncerait une protection qui \
                     n'a pas eu lieu"
                ));
            }
            match lire_dword(HKEY_LOCAL_MACHINE, &cle, "Start") {
                Some(v) => Observation::Dword(v),
                None => Observation::ValeurAbsente,
            }
        }
        Cible::Tache { chemin } => match lire_tache(chemin) {
            Some(activee) => Observation::Tache { activee },
            None => Observation::SansObjet(format!(
                "la tache {chemin} n'existe pas sous ce nom sur cette machine. \
                 Le releve du 22/08/2026 sur la build 26200 en a trouve deux \
                 dans ce cas parmi celles que le document 03 nomme"
            )),
        },
    }
}

/// L'etat d'une tache, lu dans le XML de `schtasks` et jamais dans sa prose.
fn lire_tache(chemin: &str) -> Option<bool> {
    let sortie = Command::new("schtasks")
        .args(["/query", "/tn", chemin, "/xml", "ONE"])
        .output()
        .ok()?;
    // Le code de retour ne suffit pas: on veut le XML de toute facon, et une
    // sortie vide se distingue mal d'une sortie traduite. C'est le contenu qui
    // tranche.
    let texte = taches::decoder_sortie(&sortie.stdout);
    taches::tache_activee(&texte)
}

fn changer_tache(chemin: &str, desactiver: bool) -> Result<(), String> {
    let verbe = if desactiver { "/Disable" } else { "/Enable" };
    let sortie = Command::new("schtasks")
        .args(["/Change", "/TN", chemin, verbe])
        .output()
        .map_err(|e| format!("schtasks introuvable ou non lancable: {e}"))?;
    if sortie.status.success() {
        return Ok(());
    }
    // La sortie est traduite; on ne la lit pas, on la rend telle quelle a
    // l'operateur en disant qu'elle est brute.
    Err(format!(
        "schtasks {verbe} a rendu {:?}. Sortie brute, dans la langue de la \
         machine: {}",
        sortie.status.code(),
        taches::decoder_sortie(&sortie.stderr).trim()
    ))
}

/// Ecrit une valeur `REG_DWORD`, en creant la cle si besoin.
fn ecrire_dword(r: HKEY, cle: &str, valeur: &str, donnee: u32) -> Result<(), String> {
    let (sc, v) = (w(cle), w(valeur));
    let mut poignee: HKEY = std::ptr::null_mut();
    // SAFETY: `sc` est une chaine large NUL-terminee vivante pendant l'appel; les
    // null sont la classe et les attributs, optionnels; `poignee` est une sortie.
    let code = unsafe {
        RegCreateKeyExW(
            r,
            sc.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            std::ptr::null(),
            &mut poignee,
            std::ptr::null_mut(),
        )
    };
    if code != ERROR_SUCCESS {
        return Err(erreur_registre(code, "creation ou ouverture de la cle"));
    }
    let octets = donnee.to_le_bytes();
    // SAFETY: `poignee` est valide (RegCreateKeyExW a rendu ERROR_SUCCESS); `v` est
    // une chaine large NUL-terminee et `octets` fait `octets.len()` octets, la
    // longueur passee.
    let code = unsafe {
        RegSetValueExW(
            poignee,
            v.as_ptr(),
            0,
            REG_DWORD,
            octets.as_ptr(),
            octets.len() as u32,
        )
    };
    // SAFETY: `poignee` a ete ouverte ci-dessus et n'est plus utilisee apres;
    // fermee une seule fois.
    unsafe { RegCloseKey(poignee) };
    if code != ERROR_SUCCESS {
        return Err(erreur_registre(code, "ecriture de la valeur"));
    }
    Ok(())
}

fn supprimer_valeur(r: HKEY, cle: &str, valeur: &str) -> Result<(), String> {
    let (sc, v) = (w(cle), w(valeur));
    let mut poignee: HKEY = std::ptr::null_mut();
    // SAFETY: `sc` est une chaine large NUL-terminee vivante pendant l'appel;
    // `poignee` est une sortie.
    let code = unsafe {
        windows_sys::Win32::System::Registry::RegOpenKeyExW(
            r,
            sc.as_ptr(),
            0,
            KEY_SET_VALUE,
            &mut poignee,
        )
    };
    if code != ERROR_SUCCESS {
        // La cle a deja disparu: il n'y a plus rien a supprimer, et c'est bien
        // l'etat vise.
        return Ok(());
    }
    // SAFETY: `poignee` est valide (ouverte ci-dessus); `v` est une chaine large
    // NUL-terminee.
    let code = unsafe { RegDeleteValueW(poignee, v.as_ptr()) };
    // SAFETY: `poignee` a ete ouverte ci-dessus et n'est plus utilisee apres;
    // fermee une seule fois.
    unsafe { RegCloseKey(poignee) };
    // ERROR_FILE_NOT_FOUND: la valeur n'y est plus. Meme raisonnement.
    if code != ERROR_SUCCESS && code != windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND {
        return Err(erreur_registre(code, "suppression de la valeur"));
    }
    Ok(())
}

/// Nombre de sous-cles et de valeurs d'une cle, ou `None` si elle n'existe pas.
fn contenu_cle(r: HKEY, cle: &str) -> Option<(u32, u32)> {
    let sc = w(cle);
    let mut poignee: HKEY = std::ptr::null_mut();
    // SAFETY: `sc` est une chaine large NUL-terminee vivante pendant l'appel;
    // `poignee` est une sortie.
    let code = unsafe {
        windows_sys::Win32::System::Registry::RegOpenKeyExW(
            r,
            sc.as_ptr(),
            0,
            windows_sys::Win32::System::Registry::KEY_READ,
            &mut poignee,
        )
    };
    if code != ERROR_SUCCESS {
        return None;
    }
    let (mut sous_cles, mut valeurs) = (0u32, 0u32);
    // SAFETY: `poignee` est valide (ouverte ci-dessus); `sous_cles` et `valeurs`
    // sont des sorties u32, les autres champs sont null (non demandes).
    let code = unsafe {
        RegQueryInfoKeyW(
            poignee,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sous_cles,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut valeurs,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    // SAFETY: `poignee` a ete ouverte ci-dessus et n'est plus utilisee apres;
    // fermee une seule fois.
    unsafe { RegCloseKey(poignee) };
    (code == ERROR_SUCCESS).then_some((sous_cles, valeurs))
}

/// Supprime une cle **uniquement si elle est vide**.
///
/// Rend `Ok(true)` si elle a ete supprimee, `Ok(false)` si on s'est abstenu.
/// `RegDeleteKeyW` emporterait toutes les valeurs de la cle sans broncher: un
/// retour en arriere ne doit pas emporter ce qu'un autre outil y aurait ecrit
/// entre-temps.
fn supprimer_cle_si_vide(r: HKEY, cle: &str) -> Result<bool, String> {
    match contenu_cle(r, cle) {
        None => Ok(false),
        Some((sous_cles, valeurs)) if sous_cles > 0 || valeurs > 0 => Ok(false),
        Some(_) => {
            let sc = w(cle);
            // SAFETY: `r` est une HKEY racine valide, `sc` une chaine large NUL-terminee,
            // et la cle a ete verifiee vide juste au-dessus.
            let code = unsafe { RegDeleteKeyW(r, sc.as_ptr()) };
            if code != ERROR_SUCCESS {
                return Err(erreur_registre(code, "suppression de la cle vide"));
            }
            Ok(true)
        }
    }
}

fn erreur_registre(code: u32, quoi: &str) -> String {
    if code == ERROR_ACCESS_DENIED {
        format!(
            "{quoi}: acces refuse. Cette commande demande les droits \
             d'administrateur"
        )
    } else {
        format!("{quoi}: erreur Windows {code}")
    }
}

/// Pose une cible. Ne relit pas: c'est l'appelant qui relit.
fn poser(cible: &Cible) -> Result<(), String> {
    match cible {
        Cible::Dword {
            ruche,
            cle,
            valeur,
            voulu,
        } => ecrire_dword(racine(*ruche), cle, valeur, *voulu),
        Cible::Service { nom, voulu } => ecrire_dword(
            HKEY_LOCAL_MACHINE,
            &format!("{SERVICES}\\{nom}"),
            "Start",
            *voulu,
        ),
        Cible::Tache { chemin } => changer_tache(chemin, true),
    }
}

/// Rend une cible a l'etat que le journal a garde.
fn rendre(cible: &Cible, avant: &Avant) -> Result<(), String> {
    match (cible, avant) {
        (
            Cible::Dword {
                ruche, cle, valeur, ..
            },
            Avant::Dword { valeur: v },
        ) => ecrire_dword(racine(*ruche), cle, valeur, *v),
        (
            Cible::Dword {
                ruche, cle, valeur, ..
            },
            Avant::ValeurAbsente,
        ) => supprimer_valeur(racine(*ruche), cle, valeur),
        (
            Cible::Dword {
                ruche, cle, valeur, ..
            },
            Avant::CleEtValeurAbsentes,
        ) => {
            let r = racine(*ruche);
            supprimer_valeur(r, cle, valeur)?;
            supprimer_cle_si_vide(r, cle)?;
            Ok(())
        }
        (Cible::Service { nom, .. }, Avant::Dword { valeur: v }) => ecrire_dword(
            HKEY_LOCAL_MACHINE,
            &format!("{SERVICES}\\{nom}"),
            "Start",
            *v,
        ),
        (Cible::Tache { chemin }, Avant::Tache { activee }) => changer_tache(chemin, !activee),
        (cible, avant) => Err(format!(
            "le journal garde {avant:?} pour une cible {}, ce qui ne va pas \
             ensemble. Rien n'a ete touche",
            cible.en_clair()
        )),
    }
}

/// Lit l'etat de chaque reglage d'un profil, sans rien ecrire.
pub fn etat(profil: Profil) -> Rapport {
    let sous_systeme = tourne_sous_systeme();
    let mut rapport = Rapport::default();
    for r in bifrost_telemetrie::reglages(profil) {
        let observation = observer(&r.cible);
        let issue = match &observation {
            Observation::SansObjet(raison) => Issue::SansObjet(raison.clone()),
            _ if r.cible.ruche() == Some(Ruche::Utilisateur) && sous_systeme => {
                Issue::Refuse(refus_systeme())
            }
            o if o.conforme_a(&r.cible) => Issue::DejaConforme,
            o => Issue::APoser(format!("actuellement: {}", o.en_clair())),
        };
        rapport.lignes.push(Ligne {
            id: r.id,
            cible: r.cible.en_clair(),
            issue,
        });
    }
    rapport
}

fn refus_systeme() -> String {
    "ruche utilisateur, et ce processus tourne sous SYSTEM: HKEY_CURRENT_USER y \
     designe la ruche de SYSTEM et non celle de la personne devant l'ecran. \
     Poser ici ne protegerait personne et se lirait comme une protection. \
     Relancer la commande depuis une session d'administrateur"
        .to_owned()
}

/// Applique un profil, en journalisant l'etat d'origine AVANT chaque ecriture.
///
/// Le journal est ecrit sur le disque a la fin, et aussi apres chaque ecriture
/// reussie: un arret brutal au milieu doit laisser de quoi tout defaire, pas un
/// journal vide et une machine modifiee.
pub fn appliquer(
    profil: Profil,
    chemin: &Path,
    pose_le: &str,
    build: &str,
) -> Result<Rapport, String> {
    let sous_systeme = tourne_sous_systeme();
    let mut journal = match lire_journal(chemin) {
        Ok(Some(j)) => j,
        Ok(None) => Journal::neuf(profil, pose_le, build),
        Err(e) => return Err(e),
    };
    let mut rapport = Rapport::default();

    for r in bifrost_telemetrie::reglages(profil) {
        let ligne = appliquer_un(r, &mut journal, sous_systeme, chemin);
        rapport.lignes.push(ligne);
    }
    ecrire_journal(chemin, &journal)?;
    Ok(rapport)
}

fn appliquer_un(r: &Reglage, journal: &mut Journal, sous_systeme: bool, chemin: &Path) -> Ligne {
    let clair = r.cible.en_clair();
    let ligne = |issue| Ligne {
        id: r.id,
        cible: clair.clone(),
        issue,
    };

    let observation = observer(&r.cible);
    if let Observation::SansObjet(raison) = &observation {
        return ligne(Issue::SansObjet(raison.clone()));
    }
    if r.cible.ruche() == Some(Ruche::Utilisateur) && sous_systeme {
        return ligne(Issue::Refuse(refus_systeme()));
    }
    if observation.conforme_a(&r.cible) {
        return ligne(Issue::DejaConforme);
    }

    // Journaliser AVANT d'ecrire, et rendre le journal durable avant l'ecriture
    // elle-meme: entre les deux, une coupure de courant laisserait une machine
    // modifiee et rien pour la defaire.
    if let Some(avant) = observation.en_avant() {
        journal.noter(r.id, &clair, avant);
        if let Err(e) = ecrire_journal(chemin, journal) {
            return ligne(Issue::Refuse(format!(
                "rien n'a ete pose: le journal n'a pas pu etre ecrit, et poser \
                 sans pouvoir defaire n'est pas acceptable. {e}"
            )));
        }
    }

    if let Err(e) = poser(&r.cible) {
        return ligne(if e.contains("acces refuse") {
            Issue::Refuse(e)
        } else {
            Issue::Echoue(e)
        });
    }

    // La relecture. C'est elle qui distingue "j'ai ecrit" de "c'est ecrit".
    let apres = observer(&r.cible);
    if apres.conforme_a(&r.cible) {
        ligne(Issue::Applique)
    } else {
        ligne(Issue::Echoue(format!(
            "ecrit, puis relu: {}. C'est le defaut Winhance 281: un reglage qui \
             se croit pose",
            apres.en_clair()
        )))
    }
}

/// Rend la machine a l'etat que le journal a garde, puis efface le journal.
///
/// Le journal n'est efface que si TOUT a ete rendu. Une restauration partielle
/// qui perdrait son journal laisserait une machine a moitie modifiee et plus
/// rien pour finir.
pub fn restaurer(chemin: &Path) -> Result<Rapport, String> {
    let journal = match lire_journal(chemin)? {
        Some(j) => j,
        None => {
            return Err(format!(
                "{} n'existe pas: il n'y a rien a defaire. Ce n'est pas une \
                 erreur de la machine",
                chemin.display()
            ));
        }
    };
    let sous_systeme = tourne_sous_systeme();
    let mut rapport = Rapport::default();
    let mut restantes: Vec<Entree> = Vec::new();

    for entree in journal.a_defaire() {
        let reglage = bifrost_telemetrie::catalogue::tous()
            .iter()
            .find(|r| r.id == entree.id);
        let Some(reglage) = reglage else {
            restantes.push(entree.clone());
            rapport.lignes.push(Ligne {
                id: "inconnu",
                cible: entree.cible.clone(),
                issue: Issue::Refuse(format!(
                    "le journal porte le reglage {}, que ce binaire ne connait \
                     pas. Il est laisse dans le journal plutot que devine",
                    entree.id
                )),
            });
            continue;
        };
        if reglage.cible.ruche() == Some(Ruche::Utilisateur) && sous_systeme {
            restantes.push(entree.clone());
            rapport.lignes.push(Ligne {
                id: reglage.id,
                cible: entree.cible.clone(),
                issue: Issue::Refuse(refus_systeme()),
            });
            continue;
        }
        match rendre(&reglage.cible, &entree.avant) {
            Ok(()) => rapport.lignes.push(Ligne {
                id: reglage.id,
                cible: entree.cible.clone(),
                issue: Issue::Applique,
            }),
            Err(e) => {
                restantes.push(entree.clone());
                rapport.lignes.push(Ligne {
                    id: reglage.id,
                    cible: entree.cible.clone(),
                    issue: if e.contains("acces refuse") {
                        Issue::Refuse(e)
                    } else {
                        Issue::Echoue(e)
                    },
                });
            }
        }
    }

    if restantes.is_empty() {
        std::fs::remove_file(chemin)
            .map_err(|e| format!("{} non supprimable: {e}", chemin.display()))?;
    } else {
        // Ce qui n'a pas pu etre rendu reste journalise, dans l'ordre de pose.
        restantes.reverse();
        let mut reste = Journal::neuf(journal.profil, &journal.pose_le, &journal.build);
        for e in restantes {
            reste.noter(&e.id, &e.cible, e.avant);
        }
        ecrire_journal(chemin, &reste)?;
    }
    Ok(rapport)
}

pub fn lire_journal(chemin: &Path) -> Result<Option<Journal>, String> {
    match std::fs::read_to_string(chemin) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{} illisible: {e}", chemin.display())),
        Ok(texte) => Journal::depuis_texte(&texte).map(Some),
    }
}

/// Ecrit le journal par un fichier temporaire puis un renommage, comme
/// [`crate::carnet::ecrire`]: une ecriture en place interrompue laisserait un
/// journal tronque, donc illisible, donc une machine modifiee sans moyen de la
/// defaire.
fn ecrire_journal(chemin: &Path, journal: &Journal) -> Result<(), String> {
    let texte = journal.en_texte()?;
    if let Some(parent) = chemin.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("{} non creable: {e}", parent.display()))?;
    }
    let provisoire = chemin.with_extension("json.tmp");
    std::fs::write(&provisoire, texte)
        .map_err(|e| format!("{} non ecrivable: {e}", provisoire.display()))?;
    std::fs::rename(&provisoire, chemin).map_err(|e| {
        let _ = std::fs::remove_file(&provisoire);
        format!(
            "{} non renommable en {}: {e}",
            provisoire.display(),
            chemin.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Le rapport doit distinguer ce qui est un echec de ce qui est une mesure
    /// qui n'a pas eu lieu. Confondre les deux donne soit une machine saine
    /// declaree rouge, soit une machine non protegee declaree verte.
    #[test]
    fn seul_un_echec_change_le_code_de_sortie() {
        let mut r = Rapport::default();
        r.lignes.push(Ligne {
            id: "a",
            cible: "x".into(),
            issue: Issue::SansObjet("service inconnu".into()),
        });
        r.lignes.push(Ligne {
            id: "b",
            cible: "y".into(),
            issue: Issue::Refuse("sous SYSTEM".into()),
        });
        r.lignes.push(Ligne {
            id: "c",
            cible: "z".into(),
            issue: Issue::Applique,
        });
        assert_eq!(r.code(), 0);
        r.lignes.push(Ligne {
            id: "d",
            cible: "w".into(),
            issue: Issue::Echoue("relu 1".into()),
        });
        assert_eq!(r.code(), 1);
    }

    #[test]
    fn le_rapport_compte_par_mot() {
        let mut r = Rapport::default();
        for issue in [Issue::Applique, Issue::Applique, Issue::DejaConforme] {
            r.lignes.push(Ligne {
                id: "a",
                cible: "x".into(),
                issue,
            });
        }
        assert_eq!(r.compte("POSE"), 2);
        assert_eq!(r.compte("DEJA"), 1);
        assert_eq!(r.compte("ECHEC"), 0);
    }

    #[test]
    fn la_conformite_se_juge_par_type_de_cible() {
        let dword = Cible::Dword {
            ruche: Ruche::Machine,
            cle: "c",
            valeur: "v",
            voulu: 0,
        };
        assert!(Observation::Dword(0).conforme_a(&dword));
        assert!(!Observation::Dword(1).conforme_a(&dword));
        assert!(!Observation::ValeurAbsente.conforme_a(&dword));
        assert!(!Observation::CleAbsente.conforme_a(&dword));

        let tache = Cible::Tache { chemin: r"\A" };
        assert!(Observation::Tache { activee: false }.conforme_a(&tache));
        assert!(!Observation::Tache { activee: true }.conforme_a(&tache));

        // Une observation de tache face a une cible de registre ne doit JAMAIS
        // passer pour conforme.
        assert!(!Observation::Tache { activee: false }.conforme_a(&dword));
        assert!(!Observation::Dword(0).conforme_a(&tache));
    }

    /// Une cible sans objet ne produit pas d'entree de journal: il n'y a rien a
    /// defaire, et une entree vide ferait croire a un passage.
    #[test]
    fn une_cible_sans_objet_ne_se_journalise_pas() {
        assert_eq!(Observation::SansObjet("absent".into()).en_avant(), None);
        assert_eq!(
            Observation::CleAbsente.en_avant(),
            Some(Avant::CleEtValeurAbsentes)
        );
        assert_eq!(
            Observation::ValeurAbsente.en_avant(),
            Some(Avant::ValeurAbsente)
        );
        assert_eq!(
            Observation::Dword(2).en_avant(),
            Some(Avant::Dword { valeur: 2 })
        );
    }

    /// Un journal qui garde un etat d'un autre genre que la cible est un
    /// journal abime. Rendre au hasard serait pire que refuser.
    #[test]
    fn un_journal_incoherent_est_refuse_sans_rien_toucher() {
        let e = rendre(&Cible::Tache { chemin: r"\A" }, &Avant::Dword { valeur: 3 })
            .expect_err("une tache ne se rend pas depuis un DWORD");
        assert!(e.contains("Rien n'a ete touche"), "{e}");
    }

    #[test]
    fn les_observations_se_lisent_en_clair() {
        assert_eq!(Observation::Dword(4).en_clair(), "valeur 4");
        assert_eq!(Observation::CleAbsente.en_clair(), "cle absente");
        assert_eq!(
            Observation::Tache { activee: true }.en_clair(),
            "tache active"
        );
    }

    #[test]
    fn le_refus_sous_systeme_dit_quoi_faire() {
        let r = refus_systeme();
        assert!(r.contains("SYSTEM"), "{r}");
        assert!(
            r.contains("Relancer la commande depuis une session"),
            "un refus qui ne dit pas comment avancer est un mur: {r}"
        );
    }

    #[test]
    fn le_journal_fait_l_aller_retour_par_le_disque() {
        let dossier =
            std::env::temp_dir().join(format!("bifrost-telemetrie-{}", std::process::id()));
        let chemin = dossier.join("journal.json");
        let _ = std::fs::remove_dir_all(&dossier);

        assert_eq!(
            lire_journal(&chemin).expect("absence n'est pas une erreur"),
            None,
            "un journal absent doit se lire comme absent et non comme illisible"
        );

        let mut j = Journal::neuf(Profil::Equilibre, "2026-08-22T18:00:00Z", "26200");
        j.noter(
            "service-diagtrack",
            "service DiagTrack",
            Avant::Dword { valeur: 2 },
        );
        ecrire_journal(&chemin, &j).expect("ecrivable");
        assert_eq!(lire_journal(&chemin).unwrap().as_ref(), Some(&j));
        assert!(
            !chemin.with_extension("json.tmp").exists(),
            "le provisoire doit avoir ete renomme, pas laisse derriere"
        );
        let _ = std::fs::remove_dir_all(&dossier);
    }
}

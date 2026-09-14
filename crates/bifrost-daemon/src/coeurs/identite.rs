//! Qui est le coeur: une seule reponse, pour le pare-feu comme pour le
//! lancement.
//!
//! Le kill switch exempte le coeur par son identite, et le superviseur de
//! coeurs le lance sous une identite. Tant que ce sont deux champs distincts,
//! rien n'empeche qu'ils divergent, et une divergence ne se voit nulle part:
//! le pare-feu ouvre une sortie a un compte sous lequel rien ne tourne, le
//! coeur tourne sous un compte que le pare-feu ne connait pas, et le kill
//! switch etrangle en silence le composant qui porte le trafic. Le mode
//! d'echec est un tunnel qui ne monte pas, avec un pare-feu qui a l'air
//! correct et un coeur qui a l'air correct.
//!
//! D'ou ce module: les deux bouts lisent la MEME valeur. Ils ne peuvent plus
//! diverger, non pas parce qu'on y fait attention, mais parce qu'il n'y a plus
//! qu'une chose a lire.
//!
//! Les deux plateformes ne designent pas un processus de la meme facon, et ce
//! n'est pas une incoherence a masquer. Sous Linux, `meta skuid` compare l'UID
//! proprietaire du socket: l'identite EST le compte, et le chemin du binaire
//! n'entre nulle part. Sous Windows, WFP combine `ALE_APP_ID` et
//! `ALE_USER_ID`, et l'installateur connait le chemin du binaire, pas un
//! compte dedie. Les deux champs sont donc renseignes independamment, chacun
//! par ce que sa plateforme sait reellement fournir.

use std::path::PathBuf;

use bifrost_core::ports::FirewallPolicy;

use super::lancement::{Lancement, Utilisateur};

/// L'identite du coeur anti-censure, telle que l'exploitation la declare.
///
/// Vide par defaut, et c'est le comportement d'aujourd'hui: aucune exemption
/// n'est posee, aucun compte n'est impose au lancement. Declarer une identite
/// est une decision explicite de l'exploitation, parce qu'elle ouvre une
/// sortie en clair, fut-elle etroite.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IdentiteCoeur {
    /// Compte dedie. Renseigne l'exemption `meta skuid` sous Linux ET le
    /// compte de lancement: c'est le point entier de ce type.
    pub utilisateur: Option<Utilisateur>,
    /// Executable du coeur, pour `ALE_APP_ID` sous Windows.
    pub executable: Option<PathBuf>,
}

impl IdentiteCoeur {
    /// Rien n'est declare: le kill switch reste sans exemption.
    pub fn est_vide(&self) -> bool {
        self.utilisateur.is_none() && self.executable.is_none()
    }

    /// Inscrit l'identite dans une politique de pare-feu.
    ///
    /// Appele a CHAQUE armement, et non une fois pour toutes. Le premier
    /// armement precede la montee du tunnel, donc precede tout lancement de
    /// coeur: un coeur demarre plus tard trouve son exemption deja posee. La
    /// propriete qui compte n'est pas que l'exemption finisse par arriver,
    /// c'est qu'il n'existe aucun instant ou le coeur tourne sans elle, et
    /// aucun instant ou on baisse le kill switch pour la lui donner.
    pub fn exempter(&self, politique: &mut FirewallPolicy) {
        politique.coeur_uid = self.utilisateur.map(|u| u.uid);
        politique.coeur_executable = self.executable.clone();
    }

    /// Impose l'identite a un lancement de coeur.
    ///
    /// Lit le meme champ que [`IdentiteCoeur::exempter`]. C'est ce qui rend la
    /// divergence impossible plutot qu'improbable.
    pub fn appliquer(&self, lancement: &mut Lancement) {
        lancement.utilisateur = self.utilisateur;
    }
}

/// Identite du resolveur chiffre embarque.
///
/// Le pendant exact de [`IdentiteCoeur`], et son contraire. Meme mecanique,
/// meme UID, meme moment: seul le SENS change. Le coeur est exempte pour
/// pouvoir sortir hors du tunnel, parce qu'il EST le transport. Le resolveur
/// n'est exempte de rien; declarer son identite FERME le :53 pour tout le
/// monde, y compris a l'interieur du tunnel, en ne laissant que lui.
///
/// Deux types distincts plutot qu'un champ de plus dans le premier, parce que
/// confondre les deux roles est le seul defaut vraiment grave de ce coin du
/// code: un resolveur qui recevrait l'exemption du coeur pourrait emettre du
/// DNS en clair hors tunnel, et le vecteur `dns-leak` resterait vert puisque
/// cette sortie serait autorisee. Le compilateur ne laissera pas passer la
/// confusion.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IdentiteResolveur {
    pub utilisateur: Option<Utilisateur>,
    /// Executable du resolveur, pour `ALE_APP_ID` sous Windows.
    ///
    /// Meme partage des roles que dans [`IdentiteCoeur`], et pour la meme
    /// raison: Linux compare l'UID proprietaire du socket, Windows compare le
    /// chemin du binaire. Depuis 11b-1, Windows fait AUSSI tourner le resolveur
    /// sous un compte de service dedie: le chemin ne suffit plus a le NOMMER,
    /// le SID de ce compte s'y ajoute (voir `compte` et `sid`).
    pub executable: Option<PathBuf>,
    /// Compte de service Windows demande par l'exploitation, tel qu'il a ete
    /// ecrit sur la ligne de commande (`--resolveur-utilisateur`).
    ///
    /// Le NOM, pas le SID: c'est lui que `LogonUserW` et `CreateProcessAsUserW`
    /// consomment au lancement. Sa forme recommandee est `LocalService`
    /// (arbitrage 11b, forme alpha, tranchee le 06/09/2026). `None` = le
    /// comportement d'avant 11b-1, le resolveur tourne sous le compte du
    /// daemon. Absent hors Windows: Linux nomme un compte par son UID, pas par
    /// un nom de compte de service.
    #[cfg(windows)]
    pub compte: Option<String>,
    /// SID resolu de `compte`, sous sa forme textuelle (`S-1-5-19` pour
    /// `LocalService`).
    ///
    /// Resolu UNE fois au demarrage, par `LookupAccountNameW`, pour que
    /// `restreindre` n'ait pas a refaire un appel systeme a chaque armement.
    /// C'est ce SID que `restreindre` pose dans `FirewallPolicy::resolveur_sid`,
    /// et que `permit-resolveur-dns` nomme dans `ALE_USER_ID`.
    #[cfg(windows)]
    pub sid: Option<String>,
}

impl IdentiteResolveur {
    /// Rien n'est declare: le :53 continue de circuler dans le tunnel.
    ///
    /// C'est le seul comportement correct tant qu'aucun resolveur n'ecoute sur
    /// la boucle locale. Fermer le :53 sans rien mettre en face ne durcirait
    /// rien, cela retirerait simplement la resolution de noms a la machine.
    pub fn est_vide(&self) -> bool {
        self.utilisateur.is_none() && self.executable.is_none()
    }

    /// Inscrit la restriction dans une politique de pare-feu.
    ///
    /// Le nom dit le sens: `restreindre`, quand celui du coeur dit `exempter`.
    /// Ils ecrivent des champs differents et ne peuvent pas se substituer l'un
    /// a l'autre.
    ///
    /// Il faut DEUX conditions, et l'asymetrie avec le coeur est le point.
    /// L'exemption du coeur ne depend que de l'exploitation: un compte declare
    /// suffit, parce qu'ouvrir une sortie a un compte qui ne s'en sert pas ne
    /// casse rien. La restriction, elle, depend AUSSI du profil: fermer le :53
    /// alors que le profil ne route pas le DNS par la boucle locale ne durcit
    /// rien, cela retire la resolution de noms a la machine. Un compte declare
    /// une fois pour toutes au demarrage du daemon ne peut donc pas decider
    /// seul; c'est le profil, qui change a chaque connexion, qui tranche.
    pub fn restreindre(&self, politique: &mut FirewallPolicy) {
        if !politique.resolveur_embarque {
            // Effacer et non rendre la main: une politique reutilisee d'un
            // armement a l'autre garderait sinon la restriction du profil
            // precedent, sur un profil qui ne route plus le DNS par la boucle
            // locale. Le :53 resterait ferme sans que rien n'ecoute en face.
            politique.resolveur_uid = None;
            politique.resolveur_executable = None;
            // Le SID suit la MEME discipline (11b-1): efface quand le profil
            // n'embarque plus de resolveur, sinon `permit-resolveur-dns`
            // nommerait un compte pour un resolveur qui n'ecoute plus.
            politique.resolveur_sid = None;
            return;
        }
        politique.resolveur_uid = self.utilisateur.map(|u| u.uid);
        politique.resolveur_executable = self.executable.clone();
        // Le SID du compte de service, sous Windows uniquement. Sans compte
        // declare, `self.sid` est `None` et le permit garde `Identity::Current`
        // (le comportement d'avant 11b-1). Le champ `resolveur_sid` existe sur
        // les deux plateformes, mais rien ne l'ecrit hors Windows: Linux
        // restreint le :53 par l'UID, jamais par un SID.
        #[cfg(windows)]
        {
            politique.resolveur_sid = self.sid.clone();
        }
    }
}

/// Resout un compte de service Windows en son SID textuel (`S-1-5-19` pour
/// `LocalService`).
///
/// `LookupAccountNameW` d'abord, une table des SID bien connus en repli. La
/// mesure du 06/09/2026 sur essai-windows a montre que la forme alpha du
/// resolveur est `NT AUTHORITY\LocalService` (SID `S-1-5-19`), obtenue sans
/// mot de passe; `NetworkService` est `S-1-5-20`. Coder ces deux SID en dur
/// comme SEULE voie interdirait tout autre compte de service, d'ou l'appel
/// systeme en premier: un compte cree par l'installateur (11b-2) reste
/// possible. La table sert de repli - et de temoin de test, la ou une recette
/// veut un SID connu sans dependre de l'etat de la base des comptes.
///
/// Accepte `LocalService` comme `NT AUTHORITY\LocalService`: `LookupAccountNameW`
/// resout les deux, et la table normalise le prefixe de domaine avant de
/// comparer.
#[cfg(windows)]
pub fn resoudre_sid_compte(nom: &str) -> anyhow::Result<String> {
    match sid_par_lookup(nom) {
        Ok(sid) => Ok(sid),
        Err(e) => sid_bien_connu(nom).ok_or_else(|| {
            anyhow::anyhow!(
                "compte de service {nom:?}: introuvable ({e}) et hors de la table \
                 des comptes bien connus. L'installateur doit le creer, ou la \
                 forme recommandee est LocalService"
            )
        }),
    }
}

/// SID d'un compte via l'annuaire du systeme.
///
/// `LookupAccountNameW` rend le SID sous forme binaire; `ConvertSidToStringSidW`
/// le met en texte. Deux appels a taille croissante, comme partout ailleurs
/// avec les API Win32 a tampon: le premier dit combien il faut, le second
/// remplit.
#[cfg(windows)]
fn sid_par_lookup(nom: &str) -> anyhow::Result<String> {
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::LookupAccountNameW;

    let nom_utf16: Vec<u16> = nom.encode_utf16().chain(std::iter::once(0)).collect();

    // Premier appel a vide: il echoue en ERROR_INSUFFICIENT_BUFFER et rend les
    // deux tailles a allouer (le SID et le nom de domaine, dont on ne fait
    // rien mais que l'API remplit quand meme).
    let mut taille_sid: u32 = 0;
    let mut taille_domaine: u32 = 0;
    let mut usage = 0i32;
    // SAFETY: `nom_utf16` est une chaine UTF-16 terminee par zero; les pointeurs
    // de sortie sont nuls pour la sonde de taille, les compteurs vivent ici.
    unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            nom_utf16.as_ptr(),
            std::ptr::null_mut(),
            &mut taille_sid,
            std::ptr::null_mut(),
            &mut taille_domaine,
            &mut usage,
        );
    }
    // SAFETY: lecture d'une valeur par thread, sans effet de bord.
    let err = unsafe { GetLastError() };
    if err != ERROR_INSUFFICIENT_BUFFER || taille_sid == 0 {
        return Err(anyhow::anyhow!(
            "LookupAccountNameW({nom:?}) sonde de taille: erreur Win32 {err}"
        ));
    }

    let mut tampon_sid = vec![0u8; taille_sid as usize];
    let mut domaine = vec![0u16; taille_domaine.max(1) as usize];
    // SAFETY: les tampons sont dimensionnes par la sonde ci-dessus et vivent
    // pendant l'appel; `nom_utf16` reste une chaine terminee par zero.
    let ok = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            nom_utf16.as_ptr(),
            tampon_sid.as_mut_ptr() as *mut core::ffi::c_void,
            &mut taille_sid,
            domaine.as_mut_ptr(),
            &mut taille_domaine,
            &mut usage,
        )
    };
    if ok == 0 {
        // SAFETY: lecture d'une valeur par thread, sans effet de bord.
        let err = unsafe { GetLastError() };
        return Err(anyhow::anyhow!(
            "LookupAccountNameW({nom:?}): erreur Win32 {err}"
        ));
    }

    let mut texte: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: `tampon_sid` contient un SID valide rendu par LookupAccountNameW;
    // `texte` recoit une allocation liberee par LocalFree juste apres lecture.
    let sid = unsafe {
        if ConvertSidToStringSidW(tampon_sid.as_ptr() as *mut core::ffi::c_void, &mut texte) == 0
            || texte.is_null()
        {
            let err = GetLastError();
            return Err(anyhow::anyhow!(
                "ConvertSidToStringSidW: erreur Win32 {err}"
            ));
        }
        let mut len = 0usize;
        while *texte.add(len) != 0 {
            len += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(texte, len));
        LocalFree(texte as windows_sys::Win32::Foundation::HLOCAL);
        s
    };
    Ok(sid)
}

/// Table des SID de compte de service bien connus.
///
/// Repli quand l'annuaire ne repond pas, et temoin pour les recettes. Normalise
/// le prefixe de domaine: `LocalService` et `NT AUTHORITY\LocalService`
/// designent le meme compte.
#[cfg(windows)]
fn sid_bien_connu(nom: &str) -> Option<String> {
    let sans_domaine = nom
        .rsplit('\\')
        .next()
        .unwrap_or(nom)
        .trim()
        .to_ascii_lowercase();
    match sans_domaine.as_str() {
        "localservice" => Some("S-1-5-19".to_owned()),
        "networkservice" => Some("S-1-5-20".to_owned()),
        _ => None,
    }
}

/// Lit un compte declare sur la ligne de commande.
///
/// Deux formes, parce que deux usages. `uid:gid` sert aux bancs, qui
/// travaillent sous `nobody` et n'ont aucun compte a creer. Un NOM sert a
/// l'exploitation reelle, ou l'empaquetage cree `bifrost-coeur` et ou son
/// numero varie d'une machine a l'autre: y ecrire un nombre en dur donnerait
/// une exemption qui designe le mauvais compte sur la machine suivante, ce
/// qu'aucun message d'erreur ne signalerait.
#[cfg(unix)]
pub fn lire_compte(specification: &str) -> anyhow::Result<Utilisateur> {
    if let Some((uid, gid)) = specification.split_once(':') {
        return Ok(Utilisateur {
            uid: uid.parse()?,
            gid: gid.parse()?,
        });
    }
    resoudre_nom(specification)
}

/// Traduit un nom de compte en couple uid/gid.
///
/// `getpwnam_r` plutot que la lecture de `/etc/passwd`: les comptes peuvent
/// venir de LDAP, de SSSD ou d'ailleurs, et un daemon qui ne saurait lire que
/// le fichier local refuserait de demarrer sur une machine d'entreprise pour
/// une raison sans rapport avec ce qu'il fait.
#[cfg(unix)]
fn resoudre_nom(nom: &str) -> anyhow::Result<Utilisateur> {
    use std::ffi::CString;

    let c_nom = CString::new(nom)?;
    // 16 Kio: `sysconf(_SC_GETPW_R_SIZE_MAX)` peut rendre -1, auquel cas il
    // faut choisir. Une entree passwd tient tres largement dedans.
    let mut tampon = vec![0_i8; 16 * 1024];
    // SAFETY: `libc::passwd` n'est fait que de pointeurs et d'entiers pour lesquels
    // tout-a-zero est une valeur initiale valide; getpwnam_r le remplit ensuite.
    let mut entree: libc::passwd = unsafe { std::mem::zeroed() };
    let mut trouve: *mut libc::passwd = std::ptr::null_mut();

    // SAFETY: `c_nom` est un C-string valide, le tampon est possede et
    // dimensionne, et `trouve` recoit un pointeur vers `entree` ou null.
    let code = unsafe {
        libc::getpwnam_r(
            c_nom.as_ptr(),
            &mut entree,
            tampon.as_mut_ptr().cast(),
            tampon.len(),
            &mut trouve,
        )
    };
    // POSIX dit qu'un compte absent se signale par un retour 0 et un resultat
    // nul. glibc n'en fait rien: selon les modules `nsswitch` interroges, elle
    // rend ENOENT, ESRCH ou EBADF pour dire exactement la meme chose. Mesure
    // du 17/08/2026 sur essai-linux: `ENOENT`. Traiter ces codes comme des pannes
    // ferait dire "annuaire illisible" la ou il fallait dire "ce compte
    // n'existe pas", et l'exploitation chercherait la panne au mauvais
    // endroit. Tout autre code est, lui, une vraie panne de l'annuaire.
    const ABSENT: [i32; 4] = [libc::ENOENT, libc::ESRCH, libc::EBADF, libc::EPERM];
    if code != 0 && !ABSENT.contains(&code) {
        return Err(anyhow::anyhow!(
            "lecture du compte {nom:?}: {}",
            std::io::Error::from_raw_os_error(code)
        ));
    }
    if code != 0 || trouve.is_null() {
        return Err(anyhow::anyhow!(
            "compte {nom:?} inconnu. L'empaquetage doit le creer avant que le \
             daemon puisse exempter le coeur, sans quoi l'exemption designerait \
             un compte inexistant et le kill switch etranglerait le coeur"
        ));
    }
    Ok(Utilisateur {
        uid: entree.pw_uid,
        gid: entree.pw_gid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn politique() -> FirewallPolicy {
        FirewallPolicy {
            tunnel_interface: None,
            tunnel_luid: None,
            fwmark: Some(0xca6c),
            dns_resolver: "127.0.0.1".parse::<IpAddr>().unwrap(),
            allow_lan: false,
            coeur_uid: None,
            coeur_executable: None,
            resolveur_uid: None,
            resolveur_executable: None,
            resolveur_sid: None,
            resolveur_embarque: false,
        }
    }

    fn lancement() -> Lancement {
        Lancement {
            programme: PathBuf::from("/opt/bifrost/coeurs/sing-box"),
            arguments: vec![],
            configuration: PathBuf::from("/var/lib/bifrost/sing-box.json"),
            api_clash: None,
            utilisateur: None,
        }
    }

    /// La raison d'etre du module. Si un jour ces deux valeurs peuvent
    /// differer, le pare-feu exemptera un compte sous lequel rien ne tourne.
    #[test]
    fn le_compte_exempte_est_celui_qui_lance() {
        let identite = IdentiteCoeur {
            utilisateur: Some(Utilisateur { uid: 977, gid: 977 }),
            executable: None,
        };
        let mut p = politique();
        let mut l = lancement();
        identite.exempter(&mut p);
        identite.appliquer(&mut l);
        assert_eq!(p.coeur_uid, l.utilisateur.map(|u| u.uid));
        assert_eq!(p.coeur_uid, Some(977));
    }

    /// Le groupe suit l'utilisateur jusqu'au lancement. Ne baisser que l'UID
    /// laisserait le coeur avec le GID 0.
    #[test]
    fn le_groupe_accompagne_le_compte_jusqu_au_lancement() {
        let identite = IdentiteCoeur {
            utilisateur: Some(Utilisateur { uid: 977, gid: 978 }),
            executable: None,
        };
        let mut l = lancement();
        identite.appliquer(&mut l);
        assert_eq!(l.utilisateur.unwrap().gid, 978);
    }

    /// Rien de declare, rien d'ouvert: c'est le comportement d'avant ce
    /// module, et il doit le rester quand l'exploitation ne declare rien.
    #[test]
    fn une_identite_vide_n_ouvre_rien_et_n_impose_rien() {
        let identite = IdentiteCoeur::default();
        assert!(identite.est_vide());
        let mut p = politique();
        let mut l = lancement();
        identite.exempter(&mut p);
        identite.appliquer(&mut l);
        assert_eq!(p.coeur_uid, None);
        assert_eq!(p.coeur_executable, None);
        assert_eq!(l.utilisateur, None);
    }

    /// `exempter` ECRASE, il n'ajoute pas. Une politique reutilisee d'un
    /// armement a l'autre ne doit pas garder l'exemption d'une configuration
    /// precedente.
    #[test]
    fn exempter_efface_ce_qui_precedait() {
        let mut p = politique();
        p.coeur_uid = Some(1234);
        p.coeur_executable = Some(PathBuf::from("/ancien"));
        IdentiteCoeur::default().exempter(&mut p);
        assert_eq!(p.coeur_uid, None);
        assert_eq!(p.coeur_executable, None);
    }

    /// Le pendant Windows de `le_compte_exempte_est_celui_qui_lance`, pour le
    /// resolveur. Windows ne nomme pas un compte, il nomme un BINAIRE, et c'est
    /// ce binaire que `ALE_APP_ID` compare.
    #[test]
    fn le_binaire_restreint_est_celui_qui_est_lance() {
        let identite = IdentiteResolveur {
            utilisateur: None,
            executable: Some(PathBuf::from(r"C:\Bifrost\dnscrypt-proxy.exe")),
            #[cfg(windows)]
            compte: None,
            #[cfg(windows)]
            sid: None,
        };
        let mut p = politique();
        p.resolveur_embarque = true;
        identite.restreindre(&mut p);
        assert_eq!(
            p.resolveur_executable,
            Some(PathBuf::from(r"C:\Bifrost\dnscrypt-proxy.exe"))
        );
    }

    /// Meme condition que pour l'UID, et pour la meme raison: un profil qui ne
    /// route pas le DNS par la boucle locale n'a aucun resolveur en face.
    #[test]
    fn sans_profil_qui_embarque_le_binaire_n_est_pas_inscrit() {
        let identite = IdentiteResolveur {
            utilisateur: None,
            executable: Some(PathBuf::from(r"C:\Bifrost\dnscrypt-proxy.exe")),
            #[cfg(windows)]
            compte: None,
            #[cfg(windows)]
            sid: None,
        };
        let mut p = politique();
        assert!(!p.resolveur_embarque);
        identite.restreindre(&mut p);
        assert_eq!(p.resolveur_executable, None);
    }

    /// Le profil CESSE d'embarquer un resolveur, et la restriction doit tomber
    /// avec lui.
    ///
    /// C'est le cas qu'un simple retour anticipe manquerait: si `restreindre`
    /// rendait la main sans rien ecrire quand le profil n'embarque rien, une
    /// politique reutilisee d'un armement a l'autre garderait la restriction du
    /// profil precedent. Le :53 resterait ferme alors que plus rien n'ecoute
    /// sur la boucle locale, et la machine perdrait la resolution de noms.
    #[test]
    fn un_profil_qui_cesse_d_embarquer_rouvre_le_53() {
        let identite = IdentiteResolveur {
            utilisateur: Some(Utilisateur { uid: 981, gid: 981 }),
            executable: Some(PathBuf::from(r"C:\Bifrost\dnscrypt-proxy.exe")),
            #[cfg(windows)]
            compte: None,
            #[cfg(windows)]
            sid: None,
        };
        let mut p = politique();
        p.resolveur_embarque = true;
        identite.restreindre(&mut p);
        assert_eq!(p.resolveur_uid, Some(981));

        // Meme politique, profil suivant: il ne route plus le DNS par la
        // boucle locale.
        p.resolveur_embarque = false;
        identite.restreindre(&mut p);
        assert_eq!(p.resolveur_uid, None);
        assert_eq!(p.resolveur_executable, None);
    }

    /// `restreindre` ECRASE, comme `exempter`. Une politique reutilisee d'un
    /// armement a l'autre ne doit pas garder le binaire d'un profil precedent.
    #[test]
    fn restreindre_efface_ce_qui_precedait() {
        let mut p = politique();
        p.resolveur_embarque = true;
        p.resolveur_executable = Some(PathBuf::from(r"C:\ancien.exe"));
        p.resolveur_uid = Some(1234);
        IdentiteResolveur::default().restreindre(&mut p);
        assert_eq!(p.resolveur_executable, None);
        assert_eq!(p.resolveur_uid, None);
    }

    #[cfg(unix)]
    #[test]
    fn un_couple_numerique_est_lu_tel_quel() {
        let u = lire_compte("977:978").unwrap();
        assert_eq!((u.uid, u.gid), (977, 978));
    }

    #[cfg(unix)]
    #[test]
    fn le_compte_root_se_resout_par_son_nom() {
        // `root` est le seul compte dont l'existence et le numero soient
        // garantis partout ou ce test tourne.
        let u = lire_compte("root").unwrap();
        assert_eq!(u.uid, 0);
    }

    #[cfg(unix)]
    #[test]
    fn un_compte_inconnu_est_refuse_et_dit_pourquoi() {
        let e = lire_compte("bifrost-compte-qui-n-existe-pas").unwrap_err();
        let texte = format!("{e}");
        assert!(texte.contains("inconnu"), "message inattendu: {texte}");
        assert!(
            texte.contains("etranglerait"),
            "le message doit dire la consequence: {texte}"
        );
    }

    /// 11b-1. Le pendant Windows de la discipline `resolveur_uid`: `restreindre`
    /// pose le SID du compte dans la politique quand un compte est declare ET
    /// que le profil embarque un resolveur, et l'EFFACE quand le profil cesse
    /// d'en embarquer. Falsification: si le second `restreindre` n'effacait pas
    /// le SID (retour anticipe sans ecriture), la derniere assertion rougit -
    /// `permit-resolveur-dns` nommerait un compte pour un resolveur qui
    /// n'ecoute plus.
    #[cfg(windows)]
    #[test]
    fn restreindre_pose_le_sid_sous_compte_et_l_efface_sans_profil() {
        let identite = IdentiteResolveur {
            utilisateur: None,
            executable: Some(PathBuf::from(r"C:\Bifrost\dnscrypt-proxy.exe")),
            compte: Some("LocalService".to_owned()),
            sid: Some("S-1-5-19".to_owned()),
        };
        let mut p = politique();
        p.resolveur_embarque = true;
        identite.restreindre(&mut p);
        assert_eq!(p.resolveur_sid, Some("S-1-5-19".to_owned()));

        // Profil suivant: il ne route plus le DNS par la boucle locale.
        p.resolveur_embarque = false;
        identite.restreindre(&mut p);
        assert_eq!(
            p.resolveur_sid, None,
            "le SID doit tomber avec le resolveur qu'il nommait"
        );
    }

    /// 11b-1. La resolution nom -> SID rend le SID bien connu de LocalService,
    /// que le nom porte ou non son prefixe de domaine. La forme alpha tranchee
    /// le 06/09/2026 est `NT AUTHORITY\LocalService`, SID `S-1-5-19`.
    /// `LookupAccountNameW` resout les deux formes; a defaut la table de repli
    /// les normalise. `#[cfg(windows)]` parce que `LookupAccountNameW` n'existe
    /// pas ailleurs.
    #[cfg(windows)]
    #[test]
    fn la_resolution_du_compte_local_service_rend_son_sid() {
        assert_eq!(resoudre_sid_compte("LocalService").unwrap(), "S-1-5-19");
        assert_eq!(
            resoudre_sid_compte(r"NT AUTHORITY\LocalService").unwrap(),
            "S-1-5-19"
        );
        // 11b-2: un nom absent de l'annuaire ET de la table de repli doit
        // ECHOUER, jamais rendre un SID par defaut. C'est ce sur quoi
        // `scm::install` s'appuie pour refuser un compte inconnu a
        // l'installation plutot qu'au premier demarrage du service.
        assert!(
            resoudre_sid_compte("bifrost-compte-inexistant-11b2").is_err(),
            "un compte inexistant doit echouer a la resolution"
        );
    }
}

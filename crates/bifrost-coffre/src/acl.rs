//! Qui peut remplacer le profil, sous Windows.
//!
//! # Le meme risque que sous Linux, par un autre mecanisme
//!
//! Le module principal refuse deja un repertoire ou d'autres peuvent ecrire: un
//! profil parfaitement protege dans un repertoire ouvert peut etre REMPLACE, et
//! le remplacant designe le serveur vers lequel le tunnel monte. C'est une
//! redirection complete du trafic obtenue sans jamais lire le moindre secret.
//! Sous Windows ce controle etait un `Ok(())`, au motif que le durcissement de
//! `C:\ProgramData\Bifrost` appartenait a l'installateur. Il n'y a pas
//! d'installateur.
//!
//! # Mesure sur dev-windows, le 19 aout 2026
//!
//! `C:\ProgramData` porte une ACE `CREATOR OWNER` en controle total, heritee par
//! les conteneurs et les objets, et une ACE `Users` en ecriture heritee par les
//! conteneurs. Consequence mesuree: un repertoire cree la par un utilisateur
//! ORDINAIRE, sans elevation, lui appartient - le descripteur rendu commence par
//! `O:S-1-5-21-...-1001` - et lui donne le controle total dessus et sur ce qu'il
//! contiendra.
//!
//! `C:\ProgramData\Bifrost` n'existait pas sur cette machine. Le premier a le
//! creer le possede. Un utilisateur ordinaire peut donc le creer, attendre qu'un
//! administrateur y installe un profil, puis le remplacer par le sien. C'est la
//! mecanique exacte de CVE-2026-35603, ou quatre outils de developpement
//! chargeaient leur configuration depuis un sous-repertoire de `ProgramData` que
//! personne n'avait cree ni restreint a l'installation.
//!
//! Le scellement DPAPI ne rattrape pas cela: le proprietaire du repertoire peut
//! SUPPRIMER le fichier scelle et laisser un profil en clair a la place, que
//! [`crate::ouvrir`] lira faute de mieux.
//!
//! # Pourquoi le PROPRIETAIRE, et pas la liste de controle
//!
//! Parce que le proprietaire d'un objet detient implicitement `WRITE_DAC`, quoi
//! que dise la liste - la documentation Microsoft l'ecrit explicitement. Une
//! liste parfaite sur un repertoire possede par un tiers ne protege donc de
//! rien: il la reecrit quand il veut. Le proprietaire n'est pas un indice de la
//! propriete cherchee, il en est la racine. La liste, elle, demanderait de
//! parcourir des ACE heritees et de resoudre des appartenances de groupe, avec
//! le risque de refuser une installation correcte.
//!
//! # L'elevation change le proprietaire, pas la regle
//!
//! La mesure ci-dessus a ete faite SANS elevation. Sous elevation, Windows
//! n'attribue pas l'objet cree au compte mais au groupe Administrateurs: le
//! proprietaire par defaut du jeton, `TokenOwner`, vaut alors `S-1-5-32-544`.
//! La regle n'a rien a en faire, elle accepte deja ce SID. La recette
//! `un_repertoire_a_moi_est_accepte`, elle, l'ignorait et tombait sur toute
//! machine elevee; le detail de ce qui a ete mesure est en tete de cette
//! recette.
//!
//! # Et pourquoi des SID, jamais des noms
//!
//! La meme mesure a rendu `VORDEFINIERT\Benutzer` et `NT-AUTORITAT\SYSTEM`:
//! cette machine est en allemand. Les noms de comptes sont traduits, les SID
//! non.

use anyhow::{Result, bail};
use std::path::Path;
use windows_sys::Win32::Security::TOKEN_INFORMATION_CLASS;

use crate::texte::{large_chemin, lire_et_liberer};

/// Le compte de service du systeme.
///
/// Microsoft documente ce SID comme identique sur toutes les machines, ce qui
/// est aussi ce que rendrait `CreateWellKnownSid` - en une constante plutot
/// qu'en un appel de plus qui peut echouer.
const SYSTEM: &str = "S-1-5-18";

/// Le groupe Administrateurs local.
///
/// Un administrateur peut de toute facon s'approprier n'importe quel objet:
/// l'accepter comme proprietaire n'ouvre rien qui ne le soit deja.
const ADMINISTRATEURS: &str = "S-1-5-32-544";

/// `TrustedInstaller`, qui possede `C:\Program Files`.
///
/// Un profil range la n'est pas moins sur, et le refuser enverrait un conseil
/// faux - la reponse serait alors de DESSERRER un repertoire correct.
const TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

/// Le SID du proprietaire d'un fichier ou d'un repertoire.
pub fn proprietaire(chemin: &Path) -> Result<String> {
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};

    let large = large_chemin(chemin);
    let mut sid: PSID = std::ptr::null_mut();
    let mut descripteur: PSECURITY_DESCRIPTOR = std::ptr::null_mut();

    // SAFETY: `large` est une chaine large NUL-terminee (large_chemin), vivante
    // pendant l'appel. `sid` et `descripteur` sont des sorties initialisees a null;
    // a ERROR_SUCCESS l'API alloue `descripteur` et y fait pointer `sid`. Les trois
    // null_mut demandent ni DACL, ni SACL, ni groupe.
    let code = unsafe {
        GetNamedSecurityInfoW(
            large.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut sid,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descripteur,
        )
    };
    if code != ERROR_SUCCESS {
        bail!(
            "impossible de lire le proprietaire de {} (erreur {code})",
            chemin.display()
        );
    }

    let mut texte: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid` pointe dans `descripteur`, encore alloue a ce point, et
    // l'appel precedent a rendu ERROR_SUCCESS donc le SID est valide. `texte`
    // recoit un tampon large alloue par LocalAlloc.
    let ok = unsafe { ConvertSidToStringSidW(sid, &mut texte) };
    // Le SID pointe DANS le descripteur: le liberer avant la conversion
    // laisserait un pointeur pendant.
    // SAFETY: `descripteur` a ete alloue par GetNamedSecurityInfoW;
    // ConvertSidToStringSidW a fini de lire `sid` (qui pointe dedans), plus rien
    // ne le reference. Libere une seule fois.
    unsafe {
        LocalFree(descripteur as HLOCAL);
    }
    if ok == 0 {
        return Err(anyhow::Error::from(std::io::Error::last_os_error()));
    }
    // SAFETY: `texte` a ete alloue par ConvertSidToStringSidW (ok != 0) et pointe
    // une chaine large NUL-terminee; lire_et_liberer la lit puis la libere une
    // fois par LocalFree.
    Ok(unsafe { lire_et_liberer(texte) })
}

/// Le SID du compte qui execute ce processus.
pub fn moi() -> Result<String> {
    sid_du_jeton(windows_sys::Win32::Security::TokenUser)
}

/// Le SID que porte une classe d'information du jeton de ce processus.
///
/// La classe est un parametre parce que deux d'entre elles servent ici et
/// qu'elles ne disent pas la meme chose. `TokenUser` designe le COMPTE.
/// `TokenOwner` designe le proprietaire par defaut, celui que Windows inscrit
/// dans le descripteur des objets crees sans en fournir un, et les deux
/// different des que le jeton est eleve.
///
/// Une seule lecture les sert toutes les deux: `TOKEN_USER` commence par un
/// `SID_AND_ATTRIBUTES` et `TOKEN_OWNER` par un `PSID` nu, donc dans les deux
/// cas le POINTEUR de SID occupe le debut de la structure.
fn sid_du_jeton(classe: TOKEN_INFORMATION_CLASS) -> Result<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, PSID, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut jeton: HANDLE = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess rend un pseudo-handle toujours valide; `jeton` est
    // une sortie initialisee a null qui recoit le handle a la reussite.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut jeton) } == 0 {
        return Err(anyhow::Error::from(std::io::Error::last_os_error()));
    }

    // Deux appels: le premier pour la taille, le second pour le contenu. La
    // taille depend de la longueur du SID, qui n'est pas fixe.
    let mut taille = 0u32;
    // SAFETY: `jeton` est un handle ouvert avec TOKEN_QUERY; l'appel de mesure
    // passe un tampon nul et une taille 0, licite pour ne recuperer que la taille
    // requise dans `taille`.
    unsafe { GetTokenInformation(jeton, classe, std::ptr::null_mut(), 0, &mut taille) };
    let mut tampon = vec![0u8; taille as usize];
    // SAFETY: `jeton` est valide (TOKEN_QUERY); `tampon` fait `taille` octets,
    // exactement la taille rendue par l'appel de mesure precedent, et `taille`
    // decrit sa capacite.
    let ok = unsafe {
        GetTokenInformation(
            jeton,
            classe,
            tampon.as_mut_ptr() as *mut std::ffi::c_void,
            taille,
            &mut taille,
        )
    };
    // SAFETY: `jeton` a ete ouvert par OpenProcessToken et n'est plus utilise
    // ensuite; ferme une seule fois.
    unsafe {
        CloseHandle(jeton);
    }
    if ok == 0 {
        return Err(anyhow::Error::from(std::io::Error::last_os_error()));
    }

    // SAFETY: `tampon` a ete rempli par GetTokenInformation pour TokenUser ou
    // TokenOwner; dans les deux structures le pointeur de SID occupe le debut (voir
    // la doc de `sid_du_jeton`), donc lire un PSID au debut du tampon est valide.
    let sid = unsafe { *(tampon.as_ptr().cast::<PSID>()) };
    let mut texte: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid` pointe dans `tampon`, encore vivant a ce point; `texte` recoit
    // un tampon large alloue par l'API.
    if unsafe { ConvertSidToStringSidW(sid, &mut texte) } == 0 {
        return Err(anyhow::Error::from(std::io::Error::last_os_error()));
    }
    // SAFETY: `texte` a ete alloue par ConvertSidToStringSidW et pointe une chaine
    // large NUL-terminee; lire_et_liberer la lit puis la libere une fois.
    Ok(unsafe { lire_et_liberer(texte) })
}

/// Ce proprietaire a-t-il le droit de detenir le profil?
///
/// Pure et separee de tout appel systeme: c'est la REGLE, elle se lit d'un coup
/// d'oeil et elle s'eprouve sans toucher au disque ni fabriquer de compte.
pub fn proprietaire_legitime(sid: &str, moi: &str) -> bool {
    sid == SYSTEM || sid == ADMINISTRATEURS || sid == TRUSTED_INSTALLER || sid == moi
}

/// Refuse un chemin possede par un tiers.
///
/// `quoi` nomme ce dont il s'agit - "le repertoire", "le profil" - pour que le
/// message dise lequel des deux est en cause.
pub fn exiger_proprietaire_sur(chemin: &Path, quoi: &str) -> Result<()> {
    let Ok(moi) = moi() else {
        return Ok(());
    };
    exiger(chemin, quoi, |sid| proprietaire_legitime(sid, &moi))
}

/// Le coeur, avec la regle en parametre.
///
/// Injectee pour une raison de MESURE et non de souplesse: fabriquer un
/// repertoire qui appartient a quelqu'un d'autre demanderait un second compte
/// sur la machine, donc une recette qui ne s'ecrirait jamais - et un refus
/// jamais eprouve est un refus qu'on croit avoir. Avec la regle en parametre, le
/// refus se mesure sur un vrai repertoire, dont le vrai proprietaire est
/// vraiment lu.
fn exiger(chemin: &Path, quoi: &str, legitime: impl Fn(&str) -> bool) -> Result<()> {
    // Illisible ou absent: la lecture qui suit dira laquelle des deux, avec un
    // message plus utile que celui-ci. Meme choix que sous Unix.
    let Ok(sid) = proprietaire(chemin) else {
        return Ok(());
    };
    if legitime(&sid) {
        return Ok(());
    }
    bail!(
        "{quoi} {} appartient a {sid}, qui n'est ni vous, ni SYSTEM, ni les \
         Administrateurs.\n    \
         Son proprietaire peut en reecrire les droits quand il veut, donc y \
         remplacer le profil,\n    \
         donc choisir le serveur vers lequel le tunnel monte. Reprendre la main \
         dessus:\n    \
         icacls \"{}\" /setowner \"*S-1-5-32-544\" /T /C\n    \
         icacls \"{}\" /inheritance:r /grant \"*S-1-5-18:(OI)(CI)F\" \
         \"*S-1-5-32-544:(OI)(CI)F\"",
        chemin.display(),
        chemin.display(),
        chemin.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOI: &str = "S-1-5-21-111-222-333-1001";

    /// La regle, sans rien toucher: elle vaut d'etre lue seule.
    ///
    /// # Les SID sont ecrits EN TOUTES LETTRES, et pas repris des constantes
    ///
    /// Cette recette passait `SYSTEM`, `ADMINISTRATEURS` et `TRUSTED_INSTALLER`
    /// a la regle qui consomme ces MEMES constantes. Elle ne verifiait donc que
    /// la forme de la regle - quatre comparaisons reliees par des `ou` - et pas
    /// la valeur des SID, alors que c'est la valeur qui decide qui peut detenir
    /// le profil.
    ///
    /// Mesure du 23 aout 2026 sur dev-windows: en remplacant
    /// `ADMINISTRATEURS` par `S-1-5-32-573`, la suite du crate restait
    /// ENTIEREMENT VERTE. La regle aurait alors accepte
    /// n'importe quel membre du groupe Utilisateurs comme proprietaire
    /// legitime du repertoire du profil - exactement la redirection de tunnel
    /// que ce module existe pour refuser - et rien ne l'aurait dit.
    ///
    /// En donnant le SID LITTERAL en entree, la garde mord dans les deux sens:
    /// une constante qui derive de sa valeur documentee fait rendre `false` a
    /// la regle, donc rougir la recette. Les trois valeurs viennent de la
    /// documentation Microsoft des SID connus, la quatrieme est celle du
    /// `TrustedInstaller` qui possede `C:\Program Files`.
    #[test]
    fn la_regle_accepte_les_proprietaires_privilegies_et_moi() {
        assert!(proprietaire_legitime("S-1-5-18", MOI), "SYSTEM");
        assert!(
            proprietaire_legitime("S-1-5-32-544", MOI),
            "le groupe Administrateurs local"
        );
        assert!(
            proprietaire_legitime(
                "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
                MOI
            ),
            "TrustedInstaller"
        );
        assert!(proprietaire_legitime(MOI, MOI));

        // Et les constantes portent bien ces valeurs-la, dit franchement
        // plutot que deduit du fait que les assertions ci-dessus passent.
        assert_eq!(SYSTEM, "S-1-5-18");
        assert_eq!(ADMINISTRATEURS, "S-1-5-32-544");
        assert_eq!(
            TRUSTED_INSTALLER,
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        );
    }

    /// Le compte du voisin, qui est exactement le cas de CVE-2026-35603.
    #[test]
    fn la_regle_refuse_un_autre_compte_de_la_machine() {
        const VOISIN: &str = "S-1-5-21-111-222-333-1002";
        assert!(!proprietaire_legitime(VOISIN, MOI));
        // Et pas davantage le groupe Utilisateurs, ni Tout le monde.
        assert!(!proprietaire_legitime("S-1-5-32-545", MOI));
        assert!(!proprietaire_legitime("S-1-1-0", MOI));
    }

    #[test]
    fn mon_propre_sid_se_lit() {
        let s = moi().expect("le SID du processus doit se lire");
        assert!(s.starts_with("S-1-"), "{s}");
    }

    /// Un repertoire que je viens de creer est ACCEPTE, eleve ou non.
    ///
    /// # Ce que l'assertion comparait, et pourquoi c'etait trop strict
    ///
    /// Elle comparait le proprietaire a `moi()`, c'est-a-dire au COMPTE. Elle
    /// est tombee des la premiere execution reelle de la CI, le 22 aout 2026:
    /// `left: "S-1-5-32-544"`, `right: "S-1-5-21-...-500"`. Le runner GitHub
    /// tourne ELEVE.
    ///
    /// La regle, elle, n'etait pas en cause: [`proprietaire_legitime`] accepte
    /// deja `ADMINISTRATEURS`, donc [`exiger_proprietaire_sur`] aurait laisse
    /// passer ce repertoire. C'est l'assertion qui etait plus stricte que la
    /// regle qu'elle pretendait eprouver, et une recette plus stricte que sa
    /// regle mesure autre chose que ce qu'elle annonce.
    ///
    /// # Ce qu'elle compare maintenant
    ///
    /// Le proprietaire d'un objet cree sans descripteur explicite vient du
    /// proprietaire par defaut du JETON, `TokenOwner`, et non de son
    /// utilisateur: [MS-DTYP] 2.5.3.4.1 pose `NewDescriptor.Owner` a
    /// `Token.SIDs[Token.OwnerIndex]`. Sous elevation ce champ vaut le groupe
    /// Administrateurs; sans elevation il vaut le SID du compte. La comparaison
    /// porte donc sur ce champ-la, et elle vaut dans les deux etats sans avoir
    /// a les distinguer.
    ///
    /// Quatre mesures du 23 aout 2026, deux machines:
    ///
    /// - dev-windows, jeton filtre: `TokenOwner` = SID du compte, repertoire
    ///   cree = SID du compte.
    /// - dev-windows, jeton LIE de la meme ouverture de session, lu par
    ///   `TokenLinkedToken`: `TokenOwner` = `S-1-5-32-544`. Meme machine, meme
    ///   compte, meme session: seule l'elevation change.
    /// - essai-windows, session elevee: `TokenOwner` = `S-1-5-32-544` et
    ///   repertoire cree = `S-1-5-32-544`, alors que son PARENT appartient au
    ///   compte. Le proprietaire vient donc du jeton et non d'un heritage
    ///   depuis le conteneur.
    /// - essai-windows, MEME session sous jeton restreint: les deux
    ///   redeviennent le SID du compte.
    ///
    /// L'egalite reste EXACTE. Accepter au choix l'un ou l'autre SID serait
    /// plus court et ne verifierait plus que le proprietaire lu est bien celui
    /// que le jeton designe.
    #[test]
    fn un_repertoire_a_moi_est_accepte() {
        use windows_sys::Win32::Security::TokenOwner;

        let rep = std::env::temp_dir().join(format!("bifrost-acl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&rep);
        std::fs::create_dir_all(&rep).unwrap();

        let sid = proprietaire(&rep).expect("le proprietaire doit se lire");
        let par_defaut =
            sid_du_jeton(TokenOwner).expect("le proprietaire par defaut du jeton doit se lire");
        assert_eq!(
            sid, par_defaut,
            "un repertoire que je cree appartient au proprietaire par defaut de mon jeton"
        );

        // Et ce proprietaire-la est l'un des deux que la regle admet pour un
        // objet que je cree, jamais un troisieme: sans elevation le compte,
        // avec elevation le groupe Administrateurs.
        let moi = moi().expect("le SID du compte doit se lire");
        assert!(
            sid == moi || sid == ADMINISTRATEURS,
            "hors elevation le proprietaire est le mien, sous elevation le groupe Administrateurs, et rien d'autre: {sid}"
        );

        exiger_proprietaire_sur(&rep, "le repertoire").expect("et doit donc etre accepte");

        let _ = std::fs::remove_dir_all(&rep);
    }

    /// Un repertoire qui appartient a un tiers est refuse, et le dit.
    ///
    /// Le pendant Windows de `un_repertoire_ou_d_autres_ecrivent_est_refuse`.
    /// Le proprietaire lu est le VRAI, celui du repertoire qui vient d'etre
    /// cree; seule la regle est remplacee, faute d'un second compte sur la
    /// machine.
    #[test]
    fn un_repertoire_qui_appartient_a_un_tiers_est_refuse() {
        let rep = std::env::temp_dir().join(format!("bifrost-acl-tiers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&rep);
        std::fs::create_dir_all(&rep).unwrap();
        let sien = proprietaire(&rep).expect("le proprietaire doit se lire");

        let e = exiger(&rep, "le repertoire", |_| false)
            .expect_err("un repertoire qui appartient a un tiers doit etre refuse");
        let e = e.to_string();
        assert!(
            e.contains(&sien),
            "le proprietaire fautif doit etre nomme: {e}"
        );
        assert!(
            e.contains("serveur"),
            "et la consequence dite: c'est le choix du serveur qui est en jeu. {e}"
        );
        assert!(
            e.contains("/setowner"),
            "et la commande qui reprend la main donnee: {e}"
        );

        // Ce conseil a d'abord dit `takeown /f ... /r /d o`. L'option `/d` de
        // takeown attend la reponse OUI/NON dans la LANGUE DE L'APPELANT: `o`
        // pour un compte francais, `y` pour un compte anglais. Mesure du
        // 22/08/2026, la meme commande dans `install-windows.ps1` a fait
        // echouer une installation sous SYSTEM - "'o' value is not allowed for
        // '/d' option". Un conseil qui ne marche que dans une langue est un
        // conseil faux, et `icacls` prend un SID sans rien demander.
        assert!(
            !e.contains("takeown"),
            "aucune commande attendant une reponse LOCALISEE ne doit etre \
             conseillee: {e}"
        );

        // Le temoin negatif.
        exiger(&rep, "le repertoire", |_| true).expect("une regle qui accepte doit passer");
        let _ = std::fs::remove_dir_all(&rep);
    }

    /// Le temoin que la lecture rend bien autre chose que le jeton: sans lui,
    /// une fonction qui repondrait toujours le SID du jeton passerait la
    /// recette precedente sans jamais toucher au disque.
    ///
    /// Les DEUX SID du jeton sont ecartes, pas seulement le compte, et cette
    /// seconde comparaison vient d'une mesure du 23 aout 2026. Tant qu'elle ne
    /// portait que sur `moi()`, un `proprietaire` remplace par
    /// `sid_du_jeton(TokenOwner)` faisait bien tomber ce temoin sur
    /// dev-windows, non elevee, mais laissait les six recettes VERTES sur
    /// essai-windows, elevee. Donc vertes sur le runner de la CI, eleve lui
    /// aussi: le module entier aurait pu cesser de lire le disque sans que
    /// l'integration continue le voie.
    #[test]
    fn un_repertoire_du_systeme_ne_m_appartient_pas_et_passe_quand_meme() {
        use windows_sys::Win32::Security::TokenOwner;

        let sys = Path::new(r"C:\Windows");
        if !sys.is_dir() {
            println!("SKIPPED: C:\\Windows absent");
            return;
        }
        let sid = proprietaire(sys).expect("le proprietaire doit se lire");
        assert_ne!(sid, moi().unwrap(), "C:\\Windows ne m'appartient pas");
        assert_ne!(
            sid,
            sid_du_jeton(TokenOwner).unwrap(),
            "C:\\Windows n'appartient pas davantage au proprietaire par defaut de mon jeton, y compris sous elevation"
        );
        exiger_proprietaire_sur(sys, "le repertoire")
            .expect("un repertoire du systeme doit etre accepte");
    }
}

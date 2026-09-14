//! Le versant Windows de [`super::doh`]: la lecture des configurations.
//!
//! Tout le jugement vit dans [`super::doh`], qui se teste partout. Ce module ne
//! fait que produire la liste de clients a juger, et il est donc reduit au
//! minimum: trois acces au registre et quatre assemblages.
//!
//! # Ou sont lues les politiques, et pourquoi la
//!
//! Les politiques sont lues sous `HKEY_LOCAL_MACHINE` UNIQUEMENT, jamais sous
//! `HKEY_CURRENT_USER`. Ce n'est pas un oubli: c'est la definition meme du
//! pincage. Chrome et Edge font primer la politique machine sur celle de
//! l'utilisateur, donc une politique posee sous HKCU est precisement ce que
//! l'utilisateur peut defaire, et la compter reviendrait a appeler verrou ce
//! qui s'ouvre de l'interieur.
//!
//! La PRESENCE d'un navigateur, elle, se lit dans les deux ruches: une
//! installation par utilisateur, la forme par defaut de Chrome et de Firefox,
//! n'ecrit rien sous HKLM. Ne regarder que HKLM ferait passer un Chrome
//! installe pour un Chrome absent, donc un contournement pour un succes.
//!
//! Concretement, la presence est cherchee sous HKLM puis dans chaque ruche
//! d'utilisateur reel chargee sous `HKEY_USERS`. Pas sous
//! `HKEY_CURRENT_USER`: `check` passe par le daemon, qui tourne en service
//! sous SYSTEM, et HKCU y designerait la ruche de SYSTEM. Un Chrome installe
//! par l'utilisateur y serait invisible, donc rapporte absent, donc compte
//! comme un succes. C'est exactement l'erreur qui rassure a tort.
//!
//! # Deux angles morts, nommes
//!
//! Un navigateur portable, lance depuis un repertoire quelconque, n'apparait
//! dans aucune ruche et sort de la portee de ce vecteur.
//!
//! Et la ruche d'un utilisateur n'est chargee sous `HKEY_USERS` que pendant sa
//! session. Une machine ou personne n'est connecte ne montrerait que les
//! installations pour tous. `check` est lance par quelqu'un, donc le cas
//! normal est couvert, mais l'hypothese est ici ecrite plutot que supposee.

use std::net::{IpAddr, Ipv4Addr};

use bifrost_core::checks::{CheckOutcome, CheckVector};
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegCloseKey,
    RegEnumKeyExW, RegGetValueW, RegOpenKeyExW,
};

use super::doh::{self, Client, Verdict};

/// Le client DNS de Windows, qui peut promouvoir en DoH de son propre chef.
const DNSCACHE: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";

/// Ou Windows enregistre les executables installes, quelle que soit la ruche.
const APP_PATHS: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths";

/// Chaine UTF-16 terminee par un zero, comme l'attend l'API Win32.
fn w(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Valeur `REG_SZ`, ou `None` si la cle ou la valeur n'existe pas.
pub(crate) fn lire_chaine(racine: HKEY, sous_cle: &str, valeur: &str) -> Option<String> {
    let (sc, v) = (w(sous_cle), w(valeur));
    let mut octets: u32 = 0;
    // Premier appel sans tampon: il ne fait que renseigner la taille.
    // SAFETY: sc et v sont des chaines UTF-16 terminees par un zero, valides
    // le temps de l'appel; le tampon de sortie est nul, l'API ne fait donc
    // que renseigner octets, un u32 valide.
    let r = unsafe {
        RegGetValueW(
            racine,
            sc.as_ptr(),
            v.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut octets,
        )
    };
    if r != ERROR_SUCCESS || octets == 0 {
        return None;
    }
    let mut tampon = vec![0u8; octets as usize];
    // SAFETY: tampon fait octets octets, la taille rendue par l'appel
    // precedent, et sc et v restent des chaines UTF-16 terminees par un
    // zero, valides ici.
    let r = unsafe {
        RegGetValueW(
            racine,
            sc.as_ptr(),
            v.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            tampon.as_mut_ptr().cast(),
            &mut octets,
        )
    };
    if r != ERROR_SUCCESS {
        return None;
    }
    tampon.truncate(octets as usize);
    let unites: Vec<u16> = tampon
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u16::from_le_bytes(*p))
        .collect();
    // `RegGetValueW` garantit le zero final et le compte dans la taille. Le
    // garder dans la chaine ferait echouer toute comparaison, en silence.
    let utiles = unites.split(|c| *c == 0).next().unwrap_or(&[]);
    Some(String::from_utf16_lossy(utiles))
}

/// Valeur `REG_DWORD`, ou `None` si la cle ou la valeur n'existe pas.
pub(crate) fn lire_dword(racine: HKEY, sous_cle: &str, valeur: &str) -> Option<u32> {
    let (sc, v) = (w(sous_cle), w(valeur));
    let mut donnee: u32 = 0;
    let mut octets: u32 = std::mem::size_of::<u32>() as u32;
    // SAFETY: sc et v sont des chaines UTF-16 terminees par un zero; donnee
    // est un u32 dont le pointeur porte octets = 4 octets, la taille attendue.
    let r = unsafe {
        RegGetValueW(
            racine,
            sc.as_ptr(),
            v.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            std::ptr::from_mut(&mut donnee).cast(),
            &mut octets,
        )
    };
    (r == ERROR_SUCCESS).then_some(donnee)
}

/// Vrai si la cle existe et se laisse ouvrir en lecture.
pub(crate) fn cle_existe(racine: HKEY, sous_cle: &str) -> bool {
    let sc = w(sous_cle);
    let mut poignee: HKEY = std::ptr::null_mut();
    // SAFETY: sc est une chaine UTF-16 terminee par un zero, valide le temps
    // de l'appel; poignee est un HKEY de sortie, renseigne en cas de succes.
    let r = unsafe { RegOpenKeyExW(racine, sc.as_ptr(), 0, KEY_READ, &mut poignee) };
    if r != ERROR_SUCCESS {
        return false;
    }
    // Une poignee laissee ouverte a chaque `check` finirait par se voir.
    // SAFETY: poignee vient du RegOpenKeyExW rendu ERROR_SUCCESS juste
    // au-dessus, donc ouverte, et elle n'est fermee qu'ici.
    unsafe { RegCloseKey(poignee) };
    true
}

/// Noms des sous-cles directes, dans l'ordre ou le registre les rend.
fn sous_cles(racine: HKEY, sous_cle: &str) -> Vec<String> {
    let sc = w(sous_cle);
    let mut poignee: HKEY = std::ptr::null_mut();
    // SAFETY: sc est une chaine UTF-16 terminee par un zero; poignee est un
    // HKEY de sortie, renseigne seulement en cas de succes.
    if unsafe { RegOpenKeyExW(racine, sc.as_ptr(), 0, KEY_READ, &mut poignee) } != ERROR_SUCCESS {
        return Vec::new();
    }
    let mut noms = Vec::new();
    let mut i = 0u32;
    loop {
        // 256 unites: une cle de registre en fait au plus 255.
        let mut tampon = [0u16; 256];
        let mut unites = tampon.len() as u32;
        // SAFETY: poignee est ouverte au-dessus et pas encore fermee; tampon
        // fait 256 unites et unites porte cette capacite; les autres
        // pointeurs de sortie sont nuls, ce que l'API accepte.
        let r = unsafe {
            RegEnumKeyExW(
                poignee,
                i,
                tampon.as_mut_ptr(),
                &mut unites,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if r != ERROR_SUCCESS {
            break;
        }
        noms.push(String::from_utf16_lossy(&tampon[..unites as usize]));
        i += 1;
    }
    // SAFETY: poignee vient du RegOpenKeyExW reussi plus haut - la fonction
    // est sortie tot sinon - donc ouverte, et fermee une seule fois.
    unsafe { RegCloseKey(poignee) };
    noms
}

/// SID d'un compte d'utilisateur reel, par opposition aux comptes de service
/// et aux ruches de classes que Windows charge a cote.
fn est_utilisateur_reel(sid: &str) -> bool {
    sid.starts_with("S-1-5-21-") && !sid.ends_with("_Classes")
}

/// Cherche l'executable pour tous, puis dans chaque ruche d'utilisateur reel.
/// Voir la note du module: s'arreter a HKLM ferait passer une installation par
/// utilisateur pour une absence, donc un contournement pour un succes.
pub(crate) fn installe(exe: &str) -> bool {
    let chemin = format!(r"{APP_PATHS}\{exe}");
    if cle_existe(HKEY_LOCAL_MACHINE, &chemin) {
        return true;
    }
    sous_cles(HKEY_USERS, "")
        .iter()
        .filter(|sid| est_utilisateur_reel(sid))
        .any(|sid| cle_existe(HKEY_USERS, &format!(r"{sid}\{chemin}")))
}

fn chromium(nom: &'static str, exe: &str, politique: &str, resolveur: IpAddr) -> Client {
    let mode = lire_chaine(HKEY_LOCAL_MACHINE, politique, "DnsOverHttpsMode");
    let gabarit = lire_chaine(HKEY_LOCAL_MACHINE, politique, "DnsOverHttpsTemplates");
    Client {
        nom,
        etat: doh::interpreter_chromium(
            installe(exe),
            mode.as_deref(),
            gabarit.as_deref(),
            resolveur,
        ),
    }
}

fn firefox(resolveur: IpAddr) -> Client {
    const POLITIQUE: &str = r"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS";
    Client {
        nom: "firefox",
        etat: doh::interpreter_firefox(
            installe("firefox.exe"),
            lire_dword(HKEY_LOCAL_MACHINE, POLITIQUE, "Enabled"),
            lire_dword(HKEY_LOCAL_MACHINE, POLITIQUE, "Locked"),
            lire_chaine(HKEY_LOCAL_MACHINE, POLITIQUE, "ProviderURL").as_deref(),
            resolveur,
        ),
    }
}

/// Les clients DoH de cette machine, dans l'etat ou le registre les decrit.
///
/// Le resolveur de reference est la boucle locale v4, ce que `windows::armer`
/// exige deja d'une politique. Un resolveur DoH pose sur `[::1]` serait donc
/// rapporte comme externe: l'erreur va dans le sens qui sur-signale, jamais
/// dans celui qui rassure a tort.
pub fn clients() -> Vec<Client> {
    let resolveur = IpAddr::V4(Ipv4Addr::LOCALHOST);
    vec![
        Client {
            nom: "client-dns-windows",
            etat: doh::interpreter_windows(lire_dword(
                HKEY_LOCAL_MACHINE,
                DNSCACHE,
                "EnableAutoDoh",
            )),
        },
        chromium(
            "chrome",
            "chrome.exe",
            r"SOFTWARE\Policies\Google\Chrome",
            resolveur,
        ),
        chromium(
            "edge",
            "msedge.exe",
            r"SOFTWARE\Policies\Microsoft\Edge",
            resolveur,
        ),
        firefox(resolveur),
    ]
}

/// Le vecteur, pret a entrer dans le rapport.
pub fn vecteur() -> CheckOutcome {
    let v = CheckVector::DohBypass;
    let clients = clients();
    // L'etat de CHAQUE client, y compris les pinces: c'est ce qui permet de
    // relire un rapport sans avoir la machine sous la main.
    let releve: Vec<String> = clients
        .iter()
        .map(|c| format!("{}: {}", c.nom, doh::decrire(&c.etat)))
        .collect();
    match doh::juger(&clients) {
        Verdict::Pince(raison) => CheckOutcome::passed(v, raison),
        Verdict::Indecis(raison) => CheckOutcome::skipped(v, raison),
        Verdict::Contournable(raison) => CheckOutcome::failed(v, raison, releve),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ce filtre decide quels navigateurs sont VUS. Trop large, il fait lire
    /// des ruches de service qui n'ont pas de navigateur et ne coute rien;
    /// trop etroit, il rend invisible une installation reelle et transforme un
    /// contournement en succes.
    #[test]
    fn seuls_les_comptes_reels_sont_retenus() {
        assert!(est_utilisateur_reel(
            "S-1-5-21-1234567890-987654321-1111111111-1001"
        ));
        // Comptes integres: SYSTEM, service local, service reseau.
        assert!(!est_utilisateur_reel("S-1-5-18"));
        assert!(!est_utilisateur_reel("S-1-5-19"));
        assert!(!est_utilisateur_reel("S-1-5-20"));
        // La ruche de classes double chaque ruche d'utilisateur et n'a pas
        // d'App Paths: la lire ne servirait qu'a doubler le travail.
        assert!(!est_utilisateur_reel(
            "S-1-5-21-1234567890-987654321-1111111111-1001_Classes"
        ));
        assert!(!est_utilisateur_reel(".DEFAULT"));
    }
}

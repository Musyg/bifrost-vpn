//! Le versant Windows de [`super::doh_pose`]: l'ecriture dans le registre.
//!
//! Symetrique de [`super::doh_registre`], qui lit les memes valeurs, et les
//! decisions sont les memes que sous Linux: on n'ecrase jamais une valeur qu'on
//! n'a pas posee, et on ne retire que ce qu'on reconnait.
//!
//! # Ce que cette commande touche VRAIMENT
//!
//! Trois des quatre cibles sont des politiques de navigateur sous
//! `HKLM\SOFTWARE\Policies`, sans effet sur le reste du systeme.
//!
//! La quatrieme ne l'est pas. `EnableAutoDoh` vit sous
//! `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters`, c'est-a-dire
//! dans la configuration du SERVICE DNS de la machine. La poser a 0 empeche le
//! client DNS de Windows de promouvoir de lui-meme une resolution en DoH. Ce
//! n'est pas une modification anodine et elle est annoncee comme telle: la
//! commande la nomme dans son compte rendu, et le retrait la defait.
//!
//! # Pourquoi les clefs ne sont pas supprimees au retrait
//!
//! Seules les VALEURS sont retirees. Une clef de politique vide ne porte aucune
//! politique, donc ne coute rien, tandis que supprimer une clef sous
//! `SOFTWARE\Policies` emporterait tout ce qu'elle contient. `RegDeleteKeyW`
//! efface les valeurs de la clef visee, y compris celles que d'autres y
//! auraient mises: le residu d'une clef vide est de loin le moindre risque.

use bifrost_core::checks::CheckVector;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_DWORD, REG_OPTION_NON_VOLATILE,
    REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteKeyValueW, RegSetValueExW,
};

use super::doh_pose::Pose;
use super::doh_registre;

/// Ce qu'une valeur doit contenir pour que le DoH soit coupe.
enum Valeur {
    Chaine(&'static str),
    Entier(u32),
}

/// Une valeur a poser, et le navigateur dont elle depend.
struct Cible {
    nom: &'static str,
    /// `None` pour ce qui est toujours present, comme le client DNS.
    exe: Option<&'static str>,
    cle: &'static str,
    valeur: &'static str,
    voulu: Valeur,
}

const CIBLES: &[Cible] = &[
    Cible {
        nom: "chrome",
        exe: Some("chrome.exe"),
        cle: r"SOFTWARE\Policies\Google\Chrome",
        valeur: "DnsOverHttpsMode",
        voulu: Valeur::Chaine("off"),
    },
    Cible {
        nom: "edge",
        exe: Some("msedge.exe"),
        cle: r"SOFTWARE\Policies\Microsoft\Edge",
        valeur: "DnsOverHttpsMode",
        voulu: Valeur::Chaine("off"),
    },
    Cible {
        nom: "firefox-enabled",
        exe: Some("firefox.exe"),
        cle: r"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS",
        valeur: "Enabled",
        voulu: Valeur::Entier(0),
    },
    Cible {
        nom: "firefox-locked",
        exe: Some("firefox.exe"),
        cle: r"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS",
        valeur: "Locked",
        voulu: Valeur::Entier(1),
    },
    Cible {
        nom: "client-dns-windows",
        exe: None,
        cle: r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
        valeur: "EnableAutoDoh",
        voulu: Valeur::Entier(0),
    },
];

fn w(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Ce que la cible porte aujourd'hui, decrit pour un humain, ou `None` si rien.
fn actuel(c: &Cible) -> Option<String> {
    match c.voulu {
        Valeur::Chaine(_) => doh_registre::lire_chaine(HKEY_LOCAL_MACHINE, c.cle, c.valeur),
        Valeur::Entier(_) => {
            doh_registre::lire_dword(HKEY_LOCAL_MACHINE, c.cle, c.valeur).map(|v| v.to_string())
        }
    }
}

fn voulu_en_texte(c: &Cible) -> String {
    match c.voulu {
        Valeur::Chaine(s) => s.to_owned(),
        Valeur::Entier(n) => n.to_string(),
    }
}

fn ecrire(c: &Cible) -> Result<(), String> {
    let cle = w(c.cle);
    let mut poignee: HKEY = std::ptr::null_mut();
    // SAFETY: cle est une chaine UTF-16 terminee par un zero, valide le temps
    // de l'appel; poignee est un HKEY de sortie, la classe est nulle.
    let r = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            cle.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | KEY_QUERY_VALUE,
            std::ptr::null(),
            &mut poignee,
            std::ptr::null_mut(),
        )
    };
    if r != ERROR_SUCCESS {
        return Err(format!(
            "{} non ouvrable en ecriture (code {r}): les droits d'administrateur sont-ils la?",
            c.cle
        ));
    }

    let nom = w(c.valeur);
    let (typ, donnees) = match c.voulu {
        // Le zero final fait partie de la valeur: sans lui, la chaine relue
        // emporterait ce qui la suit dans la ruche.
        Valeur::Chaine(s) => (REG_SZ, {
            let unites = w(s);
            unites.iter().flat_map(|u| u.to_le_bytes()).collect()
        }),
        Valeur::Entier(n) => (REG_DWORD, n.to_le_bytes().to_vec()),
    };
    // SAFETY: poignee vient du RegCreateKeyExW rendu ERROR_SUCCESS au-dessus;
    // nom est une chaine UTF-16 terminee par un zero; donnees.as_ptr() porte
    // exactement donnees.len() octets.
    let r = unsafe {
        RegSetValueExW(
            poignee,
            nom.as_ptr(),
            0,
            typ,
            donnees.as_ptr(),
            u32::try_from(donnees.len()).expect("une valeur de registre tient sur 32 bits"),
        )
    };
    // SAFETY: poignee ouverte par le RegCreateKeyExW reussi plus haut, fermee
    // ici une seule fois.
    unsafe { RegCloseKey(poignee) };
    if r != ERROR_SUCCESS {
        return Err(format!("{}\\{} non ecrivable (code {r})", c.cle, c.valeur));
    }
    Ok(())
}

fn effacer(c: &Cible) -> Result<(), String> {
    let (cle, nom) = (w(c.cle), w(c.valeur));
    // SAFETY: cle et nom sont des chaines UTF-16 terminees par un zero,
    // valides le temps de l'appel; HKEY_LOCAL_MACHINE est une racine
    // predefinie.
    let r = unsafe { RegDeleteKeyValueW(HKEY_LOCAL_MACHINE, cle.as_ptr(), nom.as_ptr()) };
    if r == ERROR_SUCCESS {
        return Ok(());
    }
    Err(format!(
        "{}\\{} non supprimable (code {r})",
        c.cle, c.valeur
    ))
}

/// Ecrit les politiques. Ne touche a rien de ce qu'il n'a pas ecrit.
pub fn poser() -> Vec<(String, Pose)> {
    CIBLES
        .iter()
        .map(|c| {
            let pose = match c.exe {
                // Un navigateur absent n'a pas besoin d'etre bride, et poser sa
                // politique laisserait une clef sans objet dans la ruche.
                Some(exe) if !doh_registre::installe(exe) => {
                    Pose::HorsObjet("non installe".to_owned())
                }
                _ => match actuel(c) {
                    Some(v) if v == voulu_en_texte(c) => {
                        Pose::DejaPose(format!("{}\\{} vaut deja {v}", c.cle, c.valeur))
                    }
                    Some(v) => Pose::Refus(format!(
                        "{}\\{} vaut deja '{v}' et non '{}': quelqu'un l'a pose, et Bifrost n'ecrase pas une configuration qu'il n'a pas faite",
                        c.cle,
                        c.valeur,
                        voulu_en_texte(c)
                    )),
                    None => match ecrire(c) {
                        Err(e) => Pose::Refus(e),
                        Ok(()) => Pose::Posee(format!(
                            "{}\\{} = {}",
                            c.cle,
                            c.valeur,
                            voulu_en_texte(c)
                        )),
                    },
                },
            };
            (c.nom.to_owned(), pose)
        })
        .collect()
}

/// Retire ce que [`poser`] a ecrit, et rien d'autre.
///
/// Seules les valeurs EGALES aux notres sont effacees. Limite assumee, la meme
/// que sous Linux: une valeur identique posee par quelqu'un d'autre part avec
/// les notres. Le cas reste visible, le vecteur `doh-bypass` repasse au rouge.
pub fn retirer() -> Vec<(String, Pose)> {
    CIBLES
        .iter()
        .map(|c| {
            let pose = match actuel(c) {
                None => Pose::HorsObjet("rien a retirer".to_owned()),
                Some(v) if v != voulu_en_texte(c) => Pose::HorsObjet(format!(
                    "{}\\{} vaut '{v}', ce n'est pas ce que Bifrost pose: laisse en place",
                    c.cle, c.valeur
                )),
                Some(_) => match effacer(c) {
                    Err(e) => Pose::Refus(e),
                    Ok(()) => Pose::Retiree(format!("{}\\{}", c.cle, c.valeur)),
                },
            };
            (c.nom.to_owned(), pose)
        })
        .collect()
}

/// Rappel affiche avant d'ecrire: cette commande ne touche pas que des
/// navigateurs.
pub fn avertissement() -> String {
    format!(
        "{} touche aussi le service DNS de Windows ({}), pas seulement des politiques de navigateur.",
        CheckVector::DohBypass.id(),
        CIBLES
            .iter()
            .find(|c| c.exe.is_none())
            .map_or("", |c| c.cle)
    )
}

//! Les chaines, entre Rust et l'API Windows.
//!
//! Deux conversions dont `dpapi` et `acl` ont tous les deux besoin. Les
//! dupliquer reviendrait a relire deux fois le meme `unsafe`, ce qui est
//! precisement ce qu'il ne faut pas multiplier.

/// Un chemin termine par un zero, tel que l'API le veut.
///
/// Passe par `OsStr` et non par `str`: un chemin Windows n'est pas garanti
/// convertible en UTF-8, et le convertir avec pertes designerait un AUTRE
/// fichier que celui qu'on croit verifier.
pub fn large_chemin(p: &std::path::Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    p.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Une chaine terminee par un zero, telle que l'API la veut.
pub fn large(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Lit une chaine large rendue par l'API, puis la libere.
///
/// # Securite
///
/// `p` doit etre une chaine terminee par un zero, allouee par `LocalAlloc`, ce
/// que garantissent `CryptUnprotectData` pour la description qu'il rend et
/// `ConvertSidToStringSidW` pour le SID.
pub unsafe fn lire_et_liberer(p: *mut u16) -> String {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};

    if p.is_null() {
        return String::new();
    }
    let mut fin = 0usize;
    // SAFETY: `p` n'est pas nul (teste au-dessus) et pointe une chaine large
    // NUL-terminee (contrat de la fonction), donc `p.add(fin)` reste dans la chaine
    // jusqu'au zero final.
    while unsafe { *p.add(fin) } != 0 {
        fin += 1;
    }
    // SAFETY: `fin` est l'index du zero terminal trouve ci-dessus, donc `p` couvre
    // `fin` u16 valides et initialises.
    let vu = unsafe { std::slice::from_raw_parts(p, fin) };
    let s = std::ffi::OsString::from_wide(vu)
        .to_string_lossy()
        .into_owned();
    // SAFETY: `p` a ete alloue par LocalAlloc (contrat de la fonction) et n'est
    // plus lu apres la copie; libere une seule fois.
    unsafe {
        LocalFree(p as HLOCAL);
    }
    s
}

//! Ce que les recettes Windows des politiques d'attenuation attendent de
//! relire, et la lecture elle-meme, partages par `attenuation_windows.rs` et
//! `attenuation_daemon_windows.rs`.
//!
//! Inclus par `#[path = "commun/attenuation.rs"]`: un fichier sous
//! `tests/commun/` n'est pas une cible de test pour cargo, et les deux
//! recettes lisent une seule table.
//!
//! La table est ecrite ici, avec les constantes de `windows-sys`, et non tiree
//! de `attenuation::POSEES`: une entree omise ou mal parametree dans la liste
//! du daemon ne se relirait pas, et ces recettes rougiraient.

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows_sys::Win32::System::Threading::{
    GetProcessMitigationPolicy, OpenProcess, PROCESS_QUERY_INFORMATION,
    ProcessControlFlowGuardPolicy, ProcessDynamicCodePolicy, ProcessExtensionPointDisablePolicy,
    ProcessImageLoadPolicy, ProcessStrictHandleCheckPolicy,
};

/// Chaque politique attendue, et les bits de `Flags` qui doivent s'y relire.
pub const ATTENDUES: &[(&str, i32, u32)] = &[
    ("ProcessImageLoadPolicy", ProcessImageLoadPolicy, 0b111),
    (
        "ProcessExtensionPointDisablePolicy",
        ProcessExtensionPointDisablePolicy,
        0b1,
    ),
    (
        "ProcessStrictHandleCheckPolicy",
        ProcessStrictHandleCheckPolicy,
        0b11,
    ),
    (
        "ProcessControlFlowGuardPolicy",
        ProcessControlFlowGuardPolicy,
        0b100,
    ),
    ("ProcessDynamicCodePolicy", ProcessDynamicCodePolicy, 0b1),
];

/// Les politiques attendues qui manquent au processus `pid`, chacune avec ce
/// qui a ete lu. Une lecture refusee compte comme une absence. Rend le code
/// systeme si le processus ne s'ouvre pas en `PROCESS_QUERY_INFORMATION`.
pub fn manquantes(pid: u32) -> Result<Vec<String>, u32> {
    // SAFETY: aucun pointeur; une poignee nulle dit l'echec.
    let poignee = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid) };
    if poignee.is_null() {
        // SAFETY: lecture de l'etat du fil courant.
        return Err(unsafe { GetLastError() });
    }
    let manque = ATTENDUES
        .iter()
        .filter_map(|&(nom, valeur, bits)| match lire(poignee, valeur) {
            Ok(lu) if lu & bits == bits => None,
            Ok(lu) => Some(format!("{nom}: lu 0x{lu:x}, attendu 0x{bits:x}")),
            Err(code) => Some(format!("{nom}: lecture refusee, code systeme {code}")),
        })
        .collect();
    // SAFETY: poignee rendue par OpenProcess ci-dessus, fermee une seule fois.
    unsafe { CloseHandle(poignee) };
    Ok(manque)
}

/// Le mot `Flags` d'une politique, par `GetProcessMitigationPolicy`. Chaque
/// structure lue ici est une union d'un seul `DWORD`.
fn lire(poignee: HANDLE, valeur: i32) -> Result<u32, u32> {
    let mut drapeaux: u32 = 0;
    // SAFETY: `drapeaux` vit jusqu'a la fin de l'appel et la taille annoncee
    // est la sienne; `poignee` est ouverte par `manquantes` et pas encore
    // fermee.
    let ok = unsafe {
        GetProcessMitigationPolicy(
            poignee,
            valeur,
            (&raw mut drapeaux).cast(),
            std::mem::size_of::<u32>(),
        )
    };
    if ok == 0 {
        // SAFETY: lecture de l'etat du fil courant.
        return Err(unsafe { GetLastError() });
    }
    Ok(drapeaux)
}

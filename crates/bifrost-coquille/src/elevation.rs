//! La coquille graphique refuse de demarrer elevee.
//!
//! Le document 06 le pose (partie 1.2): << ne pas lancer le GUI en admin
//! (sinon toute la surface WebView tourne en admin) >>. Une WebView qui rend du
//! HTML et parle a un daemon n'a aucune raison d'avoir les droits de ce
//! daemon; l'inverse annulerait la separation privilegie / non privilegie que
//! tout Bifrost defend.
//!
//! La DECISION est une fonction pure d'un booleen ([`refuser_si_eleve`]),
//! testee dans les deux sens. La MESURE de ce booleen ([`est_eleve`]) touche a
//! l'OS et reste minuscule et isolee: `TokenElevation` sur Windows, `euid == 0`
//! sur Linux.

/// Ce que la coquille affiche avant de refuser de demarrer.
pub const MESSAGE_REFUS: &str = "Bifrost ne doit pas etre lance en administrateur (ou root). \
     La fenetre n'a besoin d'aucun privilege: elle commande le service par l'IPC. \
     Relance-la depuis une session utilisateur ordinaire.";

/// La decision, pure: refuse si et seulement si le processus est eleve.
///
/// Separee de la mesure pour se tester dans les deux sens sans dependre du
/// contexte d'execution: le runner CI Windows tourne eleve, une machine de
/// developpement non; une recette qui ne saurait forcer que l'un des deux ne
/// garderait que la moitie de la regle.
pub fn refuser_si_eleve(est_eleve: bool) -> Result<(), &'static str> {
    if est_eleve {
        Err(MESSAGE_REFUS)
    } else {
        Ok(())
    }
}

/// Vrai si CE processus est eleve. `euid == 0` sur Unix.
#[cfg(unix)]
pub fn est_eleve() -> bool {
    // SAFETY: geteuid ne prend aucun argument, ne touche aucune memoire et ne
    // peut pas echouer.
    unsafe { libc::geteuid() == 0 }
}

/// Vrai si CE processus porte un jeton eleve (le groupe Administrateurs actif),
/// mesure par `TokenElevation`.
///
/// C'est le meme critere que Windows applique lui-meme a l'UAC: un jeton filtre
/// (compte administrateur non eleve) rend `TokenIsElevated == 0`.
#[cfg(windows)]
pub fn est_eleve() -> bool {
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    // OpenProcessToken vit sous System::Threading dans windows-sys 0.61 (il est
    // exporte par advapi32 mais range la), verifie dans la source du crate.
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess rend une pseudo-poignee qui n'a pas a etre
    // fermee; OpenProcessToken ecrit dans `token` une poignee de jeton valide
    // en cas de succes (retour non nul), qu'on ferme plus bas.
    let ouvert = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if ouvert == 0 {
        // Sans jeton lisible, on ne peut pas PROUVER l'elevation. On repond
        // << non eleve >> plutot que de refuser de demarrer sur une incertitude:
        // cette garde protege d'un lancement administrateur par megarde, elle
        // n'est pas censee bloquer un utilisateur ordinaire sur un OS recalcitrant.
        return false;
    }

    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut taille = 0u32;
    // SAFETY: `token` est une poignee valide ouverte juste au-dessus; on passe
    // un TOKEN_ELEVATION de la taille declaree et un pointeur pour recevoir la
    // longueur ecrite.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast::<c_void>(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut taille,
        )
    };
    // SAFETY: `token` a ete ouvert par OpenProcessToken et n'est ferme qu'ici.
    unsafe {
        CloseHandle(token);
    }
    ok != 0 && elevation.TokenIsElevated != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eleve_refuse_de_demarrer() {
        let r = refuser_si_eleve(true);
        assert!(r.is_err());
        let message = r.unwrap_err();
        assert!(message.contains("administrateur"));
        assert!(message.contains("IPC"));
    }

    #[test]
    fn non_eleve_demarre() {
        assert!(refuser_si_eleve(false).is_ok());
    }

    /// La mesure et la decision sont cablees ensemble, quel que soit l'hote:
    /// une machine ordinaire rend `false` (donc Ok), le runner Windows eleve
    /// rend `true` (donc Err). Le test ne prejuge pas de l'hote, il verifie que
    /// les deux morceaux se rejoignent.
    #[test]
    fn la_mesure_et_la_decision_sont_coherentes() {
        let eleve = est_eleve();
        assert_eq!(refuser_si_eleve(eleve).is_err(), eleve);
    }
}

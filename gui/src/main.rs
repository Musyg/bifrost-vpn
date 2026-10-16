//! Bifrost GUI: coquille Tauri v2 NON privilegiee.
//!
//! Trois modes (connecter, deconnecter, voir l'etat du kill switch) et un tray,
//! qui commandent le daemon par l'IPC. Elle ne lit jamais une cle
//! (`ConnectStored`: le daemon monte SON profil), elle refuse de demarrer
//! elevee (document 06, partie 1.2), et toute sa logique testable vit dans
//! `bifrost-coquille`, hors de cette coquille que Tauri ne compile pas partout.
//! Le poste de commande (`Commande`) n'ouvre le canal qu'apres avoir exige du
//! serveur l'identite du daemon.
//!
//! La coquille se limite au cablage: elle traduit une [`Vue`] en pixels et en
//! entrees de menu, elle interroge l'etat toutes les deux secondes, et elle
//! relaie les clics vers le poste de commande. Aucune decision n'est prise ici.

// En release, pas de console: une GUI non privilegiee n'a rien a y afficher. En
// debug (le lancement de mesure), la console reste, ce qui aide a l'observer.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod icone;

use std::time::Duration;

use bifrost_coquille::elevation;
use bifrost_coquille::vue::Vue;
use bifrost_coquille::{Commande, ErreurCommande};
use bifrost_core::state::TunnelStatus;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager, WindowEvent, Wry};

/// Identifiant du tray, pour le retrouver depuis la boucle de fond.
const ID_TRAY: &str = "principal";
/// Etiquette de l'unique fenetre.
const ETIQUETTE_FENETRE: &str = "main";
/// Periode d'interrogation de l'etat.
const INTERVALLE: Duration = Duration::from_secs(2);
/// Nom de l'evenement emis vers le front a chaque rafraichissement.
const EVENEMENT_MAJ: &str = "maj-etat";

/// Ce que la coquille garde: le poste de commande et les poignees des entrees
/// du menu qu'elle repeint a chaque rafraichissement: le texte de << Etat >>,
/// et l'activation de << Connecter >> et << Deconnecter >>.
struct Contexte {
    commande: Commande,
    item_etat: MenuItem<Wry>,
    item_connecter: MenuItem<Wry>,
    item_deconnecter: MenuItem<Wry>,
}

/// Les entrees << Connecter >> et << Deconnecter >> du menu du tray actives
/// pour une Vue: les MEMES champs que les boutons de la page
/// (`vue.peut_connecter`, `vue.peut_deconnecter`), sans autre regle. Une action
/// n'est offerte, dans le menu comme dans la fenetre, que quand elle a un sens
/// dans l'etat courant; dans aucun etat d'erreur, << compte non admis par le
/// canal >> compris.
fn entrees_actives(vue: &Vue) -> (bool, bool) {
    (vue.peut_connecter, vue.peut_deconnecter)
}

/// La Vue d'une reponse du poste de commande, pure: l'etat rendu par le daemon,
/// ou une Vue d'erreur (jamais << connecte >>, jamais verte), pas une panique.
fn vue_de(reponse: Result<TunnelStatus, ErreurCommande>) -> Vue {
    match reponse {
        Ok(status) => Vue::depuis_status(&status),
        Err(e) => Vue::depuis_erreur(&e),
    }
}

/// L'info-bulle du tray pour une Vue.
fn info_bulle(vue: &Vue) -> String {
    format!("Bifrost - {}", vue.texte_etat)
}

/// Interroge le daemon et rend la Vue, qu'il reponde ou non.
async fn vue_courante(commande: &Commande) -> Vue {
    vue_de(commande.etat().await)
}

/// Applique une action mutante puis rend la Vue resultante: celle de l'etat
/// relu si l'action a reussi, celle de son erreur sinon.
async fn appliquer_action(commande: &Commande, resultat: Result<(), ErreurCommande>) -> Vue {
    match resultat {
        Ok(()) => vue_courante(commande).await,
        Err(e) => vue_de(Err(e)),
    }
}

#[tauri::command]
async fn etat(ctx: tauri::State<'_, Contexte>) -> Result<Vue, String> {
    let commande = ctx.commande.clone();
    Ok(vue_courante(&commande).await)
}

#[tauri::command]
async fn connecter(ctx: tauri::State<'_, Contexte>) -> Result<Vue, String> {
    let commande = ctx.commande.clone();
    let r = commande.connecter().await;
    Ok(appliquer_action(&commande, r).await)
}

#[tauri::command]
async fn deconnecter(ctx: tauri::State<'_, Contexte>) -> Result<Vue, String> {
    let commande = ctx.commande.clone();
    let r = commande.deconnecter().await;
    Ok(appliquer_action(&commande, r).await)
}

/// Peint une Vue: icone et info-bulle du tray, texte de l'entree << Etat >>,
/// activation de << Connecter >> et << Deconnecter >>, et un evenement vers le
/// front.
fn appliquer_vue(app: &AppHandle, vue: &Vue) {
    if let Some(tray) = app.tray_by_id(ID_TRAY) {
        let _ = tray.set_icon(Some(icone::image_pour(vue.couleur)));
        let _ = tray.set_tooltip(Some(info_bulle(vue)));
    }
    if let Some(ctx) = app.try_state::<Contexte>() {
        let _ = ctx.item_etat.set_text(&vue.texte_menu_etat);
        let (connecter, deconnecter) = entrees_actives(vue);
        let _ = ctx.item_connecter.set_enabled(connecter);
        let _ = ctx.item_deconnecter.set_enabled(deconnecter);
    }
    // Le front rend ce qu'on lui envoie; s'il n'ecoute pas encore, l'echec est
    // sans consequence, le prochain tour reessaiera.
    let _ = app.emit(EVENEMENT_MAJ, vue.clone());
}

/// Amene la fenetre au premier plan.
fn afficher(app: &AppHandle) {
    if let Some(fenetre) = app.get_webview_window(ETIQUETTE_FENETRE) {
        let _ = fenetre.show();
        let _ = fenetre.set_focus();
    }
}

/// Une action mutante lancee depuis le menu du tray: on la joue en tache de
/// fond puis on repeint. On extrait le poste de commande de l'etat AVANT toute
/// attente pour ne pas tenir le verrou de l'etat a travers un `await`.
fn lancer_depuis_menu(app: &AppHandle, connecter_et_pas_deconnecter: bool) {
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let commande = match handle.try_state::<Contexte>() {
            Some(ctx) => ctx.commande.clone(),
            None => return,
        };
        let resultat = if connecter_et_pas_deconnecter {
            commande.connecter().await
        } else {
            commande.deconnecter().await
        };
        let vue = appliquer_action(&commande, resultat).await;
        appliquer_vue(&handle, &vue);
    });
}

fn gerer_menu(app: &AppHandle, id: &str) {
    match id {
        "connecter" => lancer_depuis_menu(app, true),
        "deconnecter" => lancer_depuis_menu(app, false),
        "afficher" => afficher(app),
        "quitter" => app.exit(0),
        _ => {}
    }
}

fn main() {
    // Avant toute chose: une GUI elevee est refusee (document 06, partie 1.2).
    // La decision est pure et testee dans bifrost-coquille; ici on la mesure et
    // on s'arrete si elle vaut refus.
    if let Err(message) = elevation::refuser_si_eleve(elevation::est_eleve()) {
        eprintln!("{message}");
        std::process::exit(3);
    }

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![etat, connecter, deconnecter])
        .on_window_event(|fenetre, evenement| {
            // Fermer la fenetre la CACHE: l'application vit dans le tray. Seul
            // << Quitter >> quitte.
            if let WindowEvent::CloseRequested { api, .. } = evenement {
                api.prevent_close();
                let _ = fenetre.hide();
            }
        })
        .setup(|app| {
            let commande = Commande::default();

            // Le menu du tray. << Etat >> est inactif: c'est un afficheur, pas
            // une action. Son texte est repeint a chaque tour. << Connecter >>
            // et << Deconnecter >> naissent inactifs, comme les boutons de la
            // page, et chaque tour les active selon la Vue (`appliquer_vue`).
            let item_etat = MenuItem::with_id(app, "etat", "Etat: demarrage", false, None::<&str>)?;
            let sep1 = PredefinedMenuItem::separator(app)?;
            let item_connecter =
                MenuItem::with_id(app, "connecter", "Connecter", false, None::<&str>)?;
            let item_deconnecter =
                MenuItem::with_id(app, "deconnecter", "Deconnecter", false, None::<&str>)?;
            let sep2 = PredefinedMenuItem::separator(app)?;
            let item_afficher = MenuItem::with_id(app, "afficher", "Afficher", true, None::<&str>)?;
            let item_quitter = MenuItem::with_id(app, "quitter", "Quitter", true, None::<&str>)?;
            let menu = Menu::with_items(
                app,
                &[
                    &item_etat,
                    &sep1,
                    &item_connecter,
                    &item_deconnecter,
                    &sep2,
                    &item_afficher,
                    &item_quitter,
                ],
            )?;

            TrayIconBuilder::with_id(ID_TRAY)
                .icon(icone::image_pour(bifrost_coquille::vue::CouleurTray::Gris))
                .tooltip("Bifrost")
                .menu(&menu)
                .show_menu_on_left_click(true)
                .on_menu_event(|app, evenement| gerer_menu(app, evenement.id.as_ref()))
                .build(app)?;

            app.manage(Contexte {
                commande: commande.clone(),
                item_etat,
                item_connecter,
                item_deconnecter,
            });

            // La boucle de fond: interroge l'etat toutes les deux secondes et
            // repeint. Elle possede sa propre copie du poste de commande.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    let vue = vue_courante(&commande).await;
                    appliquer_vue(&handle, &vue);
                    tokio::time::sleep(INTERVALLE).await;
                }
            });

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("erreur fatale au demarrage de Bifrost");
}

/// Une erreur du poste de commande de chaque sorte, et de chaque cause du
/// serveur non admis. Le `match` est exhaustif: une sorte ajoutee a
/// `ErreurCommande` ou une cause ajoutee a `ServerIdentityError` ne compile
/// plus ici tant qu'elle n'est pas dans la liste, donc dans les recettes de la
/// coquille.
#[cfg(test)]
fn une_erreur_de_chaque_sorte() -> Vec<ErreurCommande> {
    use bifrost_ipc::transport::ServerIdentityError;
    let erreurs = vec![
        ErreurCommande::DaemonInjoignable("canal absent".into()),
        ErreurCommande::CompteNonAdmis("acces refuse a l'ouverture".into()),
        ErreurCommande::DaemonSansReponse("canal occupe".into()),
        ErreurCommande::ServeurNonAdmis(ServerIdentityError::Refused),
        ErreurCommande::ServeurNonAdmis(ServerIdentityError::Unreadable),
        ErreurCommande::Refuse("acces refuse pour uid=1000".into()),
        ErreurCommande::Autre("profil absent".into()),
    ];
    for e in &erreurs {
        match e {
            ErreurCommande::DaemonInjoignable(_)
            | ErreurCommande::CompteNonAdmis(_)
            | ErreurCommande::DaemonSansReponse(_)
            | ErreurCommande::ServeurNonAdmis(
                ServerIdentityError::Refused | ServerIdentityError::Unreadable,
            )
            | ErreurCommande::Refuse(_)
            | ErreurCommande::Autre(_) => {}
        }
    }
    erreurs
}

#[cfg(test)]
mod tests {
    use super::*;
    use bifrost_coquille::vue::{CouleurTray, EtatVue};
    use bifrost_core::state::State;

    fn status(state: State) -> TunnelStatus {
        TunnelStatus {
            state,
            kill_switch_engaged: true,
            firewall_backend: "nftables".into(),
            interface: Some("wg0".into()),
            endpoint: Some("203.0.113.7:51820".into()),
            last_handshake_secs_ago: Some(12),
            rx_bytes: 2048,
            tx_bytes: 1024,
        }
    }

    /// Une erreur, de chaque sorte, ne se lit jamais comme connecte dans la
    /// coquille: ni dans son etat, ni dans sa couleur, ni dans l'info-bulle du
    /// tray, l'entree << Etat >> du menu ou le texte de la page. Et aucune
    /// action n'y est proposee.
    #[test]
    fn une_erreur_ne_se_lit_jamais_comme_connecte_dans_la_coquille() {
        for e in une_erreur_de_chaque_sorte() {
            let vue = vue_de(Err(e.clone()));
            assert_ne!(
                vue.etat,
                EtatVue::Connecte,
                "erreur {e:?} lue comme connecte"
            );
            assert_ne!(vue.couleur, CouleurTray::Vert, "erreur {e:?} rendue verte");
            for texte in [
                info_bulle(&vue),
                vue.texte_menu_etat.clone(),
                vue.texte_etat.clone(),
            ] {
                assert!(
                    !texte.to_lowercase().contains("connecte"),
                    "erreur {e:?}: `{texte}`"
                );
            }
            assert!(
                !vue.peut_connecter && !vue.peut_deconnecter,
                "erreur {e:?}: une action proposee sans savoir a quoi elle repond"
            );
        }
    }

    /// Chaque erreur est peinte telle que `bifrost-coquille` la derive, a
    /// l'identique: la coquille ne decide rien.
    #[test]
    fn chaque_erreur_est_peinte_telle_que_la_vue_la_derive() {
        for e in une_erreur_de_chaque_sorte() {
            assert_eq!(vue_de(Err(e.clone())), Vue::depuis_erreur(&e), "{e:?}");
        }
    }

    /// Les entrees << Connecter >> et << Deconnecter >> du menu du tray, etat
    /// par etat, ecrites en clair: celles qu'active la page pour ses boutons
    /// (`peut_connecter`, `peut_deconnecter`), et aucune autre. Connecter n'a
    /// de sens que deconnecte ou en echec, deconnecter que hors de
    /// << deconnecte >>; aucune des deux dans un etat d'erreur, << compte non
    /// admis par le canal >> compris.
    #[test]
    fn le_menu_du_tray_n_offre_que_ce_qu_offrent_les_boutons() {
        for (state, attendu) in [
            (State::Connected, (false, true)),
            (State::Connecting { attempt: 1 }, (false, true)),
            (State::Reconnecting { attempt: 2 }, (false, true)),
            (
                State::Error {
                    reason: "handshake perime".into(),
                },
                (true, true),
            ),
            (State::Disconnected, (true, false)),
        ] {
            let vue = vue_de(Ok(status(state.clone())));
            assert_eq!(entrees_actives(&vue), attendu, "{state:?}");
            assert_eq!(
                entrees_actives(&vue),
                (vue.peut_connecter, vue.peut_deconnecter),
                "{state:?}: le menu et les boutons divergent"
            );
        }
        for e in une_erreur_de_chaque_sorte() {
            let vue = vue_de(Err(e.clone()));
            assert_eq!(entrees_actives(&vue), (false, false), "{e:?}");
            assert_eq!(
                entrees_actives(&vue),
                (vue.peut_connecter, vue.peut_deconnecter),
                "{e:?}: le menu et les boutons divergent"
            );
        }
    }

    /// Un etat rendu par le daemon est peint tel quel, et seul `Connected`
    /// est vert.
    #[test]
    fn un_etat_du_daemon_est_peint_tel_que_la_vue_le_derive() {
        for state in [
            State::Connected,
            State::Connecting { attempt: 1 },
            State::Reconnecting { attempt: 2 },
            State::Error {
                reason: "handshake perime".into(),
            },
            State::Disconnected,
        ] {
            let s = status(state.clone());
            let vue = vue_de(Ok(s.clone()));
            assert_eq!(vue, Vue::depuis_status(&s), "{state:?}");
            assert_eq!(
                vue.couleur == CouleurTray::Vert,
                state == State::Connected,
                "{state:?}"
            );
            assert_eq!(info_bulle(&vue), format!("Bifrost - {}", vue.texte_etat));
        }
    }
}

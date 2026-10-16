// Front statique de Bifrost. Aucun framework, aucun npm. Il ne fait que peindre
// la Vue que le backend Rust lui envoie et relayer les deux boutons.
//
// withGlobalTauri expose ces deux entrees; on ne charge aucun script externe
// (la CSP est default-src 'self').

"use strict";

const invoke = window.__TAURI__.core.invoke;
const listen = window.__TAURI__.event.listen;

// La note de chaque etat de la Vue, par le nom que le backend emet (`EtatVue`,
// en kebab-case). Un etat rendu par le daemon n'a pas de note: son texte
// suffit. Un etat d'erreur dit ce que la coquille sait, et rien de plus; aucun
// ne laisse croire que le tunnel est etabli. La recette `gui_conf.rs` du crate
// bifrost-coquille exige une entree par etat de la Vue.
const NOTES = {
  "connecte": "",
  "connexion-en-cours": "",
  "reprise": "",
  "echec": "",
  "deconnecte": "",
  "daemon-injoignable":
    "Le service Bifrost est injoignable: il ne tourne pas, ou l'echange a ete coupe.",
  "compte-non-admis":
    "Le canal du service Bifrost n'admet pas ce compte: il n'est pas membre du groupe d'acces du service. Un administrateur l'y ajoute; l'appartenance vaut a la prochaine ouverture de session.",
  "daemon-sans-reponse":
    "Le canal du service est occupe et n'a pas repondu dans le delai. Rien ne dit que le service soit arrete.",
  "serveur-non-admis":
    "Le canal est tenu par un processus qui n'a pas l'identite du service Bifrost: rien ne lui a ete envoye.",
  "refuse":
    "Le service a refuse la commande, ou rendu une erreur: le detail est dans l'etat.",
};

// Tailles lisibles, sans dependance.
function octets(n) {
  const unites = ["o", "Kio", "Mio", "Gio"];
  let v = Number(n) || 0;
  let i = 0;
  while (v >= 1024 && i < unites.length - 1) {
    v /= 1024;
    i += 1;
  }
  return i === 0 ? v + " o" : v.toFixed(1) + " " + unites[i];
}

function texte(id, valeur) {
  document.getElementById(id).textContent = valeur;
}

function rendre(vue) {
  if (!vue) {
    return;
  }
  texte("etat", vue.texte_etat);
  texte("kill-switch", vue.texte_kill_switch);
  texte("interface", vue.interface || "-");
  texte("endpoint", vue.endpoint || "-");

  if (vue.rx_bytes || vue.tx_bytes) {
    texte("transfert", "recu " + octets(vue.rx_bytes) + ", emis " + octets(vue.tx_bytes));
  } else {
    texte("transfert", "-");
  }

  const pastille = document.getElementById("pastille");
  // La classe de la pastille est la couleur de la Vue (serialisation
  // kebab-case de CouleurTray), telle quelle: la page ne choisit aucune
  // couleur.
  pastille.className = "pastille " + vue.couleur;

  document.getElementById("connecter").disabled = !vue.peut_connecter;
  document.getElementById("deconnecter").disabled = !vue.peut_deconnecter;

  // Un etat que cette page ne connait pas est dit tel quel, jamais tu.
  const connu = Object.prototype.hasOwnProperty.call(NOTES, vue.etat);
  texte("note", connu ? NOTES[vue.etat] : "Etat inconnu de cette page: " + vue.etat);
}

async function rafraichir() {
  try {
    rendre(await invoke("etat"));
  } catch (e) {
    document.getElementById("note").textContent = "Erreur interne: " + e;
  }
}

async function agir(commande) {
  try {
    rendre(await invoke(commande));
  } catch (e) {
    document.getElementById("note").textContent = "Erreur interne: " + e;
  }
}

window.addEventListener("DOMContentLoaded", () => {
  document.getElementById("connecter").addEventListener("click", () => agir("connecter"));
  document.getElementById("deconnecter").addEventListener("click", () => agir("deconnecter"));

  // La boucle de fond du backend emet cet evenement toutes les deux secondes.
  listen("maj-etat", (evenement) => rendre(evenement.payload));

  // Premier rendu sans attendre le prochain tour de la boucle.
  rafraichir();
});

# Etat de Bifrost

Bifrost est un VPN auto-heberge pour Windows 11 et Linux. Trois objectifs, dans
cet ordre: ne pas fuir (kill switch de niveau noyau, fail-closed), ne pas etre
bloque (resistance active au DPI et a la censure), ne pas laisser le systeme
d'exploitation parler (blocage de la telemetrie avant le tunnel). Le MVP de
l'objectif 1 est implemente; l'objectif 2 avance; l'objectif 3 est au stade de
la conception. Daemon et CLI, pas d'interface graphique.

Cette page tient sur un ecran et se met a jour a chaque tranche. Ce qui est
mesure et ce qui ne l'est pas est detaille dans le README et dans les documents
du plan `docs/01..07`. La suite de fuite couvre dix vecteurs; le compte des
recettes cargo est pris par `scripts/recettes-strict.sh`, jamais par le compte
de `cargo test`, qui presente comme verte une recette abstenue.

Chaque mesure nomme l'hote qui l'a produite. Les hotes sont designes par leur
role: `dev-windows` (Windows 10 build 19045, ou vit et compile le depot),
`essai-linux` (Ubuntu 24.04, chaine outillee cargo-deny et cargo-audit) et
`essai-windows` (Windows 11, session de mesure sans chaine Rust).

## Comptes de recettes

Compte honnete des recettes cargo, par hote. La colonne `reelles` est ce qui a
verifie quelque chose: `annoncees` moins `abstentions` moins `rouges`.

| Hote | Annoncees | Abstentions | Rouges | Reelles |
|---|---|---|---|---|
| dev-windows | 1225 | 19 | 0 | 1206 |
| essai-linux | 1222 | 22 | 0 | 1200 |

Les deux lignes sont prises sur cet arbre par `scripts/recettes-strict.sh`, chacune
sur son hote. Sur `essai-linux` une recette de plus est ignoree par construction
(elle pose une route et ne tourne qu'en espace de noms reseau), et la garde des
modes de scripts s'y abstient parce que la copie mesuree n'a pas de `.git` (elle
lit l'index; dans un clone elle mesure).

## Ce qui est ouvert, document par document

Les sept documents du plan `docs/01..07`, leur etat et, pour un chantier ouvert,
la prochaine action. Une cellule vide signalerait une tranche non finie.

| Chantier | Etat et derniere mesure | Prochaine action |
|---|---|---|
| 01 | Architecture technique. Cadre du plan, redige; ce n'est pas un livrable | - |
| 02 | Kill switch WFP et nftables. Specification de reference, a jour | - |
| 03 | Anti-telemetrie OS. Couche DNS livree; couches Windows registre et WFP par service a finir | Finir les couches Windows registre et WFP par service |
| 04 | Anti-censure DPI. Tableau de survie a jour | - |
| 05 | Anonymat et chainage. Document redige; le chainage Tor et Nym n'est pas commence, et le document lui-meme le place apres les trois objectifs | Chainage Tor ou Nym, apres les objectifs 1 a 3 |
| 06 | Architecture logicielle et packaging. Daemon, IPC authentifie, machine a etats et scripts d'installation faits (Linux et Windows, comptes dedies, ACL); ni interface graphique, ni MSI, ni .deb/.rpm, ni mise a jour TUF, ni provisioning; SBOM en CI | Interface graphique en jalon propre apres J2; paquets signes et mise a jour TUF |
| 07 | Programme de securite produit. fmt, clippy, recettes, suite de fuite, cargo audit, cargo deny et SBOM en CI; politique de divulgation publiee (SECURITY.md, security.txt); inventaire unsafe ferme; cargo vet et fuzz absents, aucune cle PGP | Publier une cle PGP (champ Encryption); ajouter cargo vet et un harnais fuzz |

## Scripts

Chaque banc et outil du depot, avec sa ligne d'usage. Un banc que personne ne
sait lancer n'est pas un banc.

Sous `scripts/`:

| Script | Usage |
|---|---|
| recettes-strict.sh | Compte honnete des recettes cargo (vertes, abstentions, rouges); `--strict` echoue aussi sur abstention |
| abstentions-budget.sh | Exige que chaque abstention de la CI figure dans la liste attendue du job |
| check-strict.sh | Exige que les dix vecteurs de fuite soient PASSED |
| check-cibles.sh | Construit et verifie les cibles sur l'hote courant |
| e2e-linux.sh | Bout en bout Linux: daemon reel, capture, montee du tunnel et etancheite |
| banc-coeur-e2e.sh | Banc bout en bout d'un coeur anti-censure |
| banc-bascule-en-session.sh | Banc de bascule DNS en session, avec temoin de l'etat DNS de l'hote |
| banc-cdn-linux.sh | Banc CDN Linux (httpupgrade, edge) |
| mort-daemon-systemd-linux.sh | Banc de mort brutale du daemon sous systemd, etancheite mesuree |
| resolveur-linux.sh | Banc du resolveur chiffre embarque, Linux |
| resolveur-systemd-linux.sh | Banc du resolveur sous l'unite systemd |
| service-systemd-linux.sh | Banc du service Linux (cycle connect/disconnect par l'unite) |
| service-windows-pair.sh | Pilote la paire de bancs de service Windows depuis Linux |
| quic-chronologie.py | Chronologie des evenements QUIC pour l'analyse d'une capture |
| banc-coeur-windows.ps1 | Banc d'un coeur anti-censure, Windows |
| banc-jeton-filtre-windows.ps1 | Banc du jeton de filtre WFP, Windows |
| jetons-compare-windows.ps1 | Compare les jetons de filtre entre deux mesures Windows |
| service-windows.ps1 | Banc du service Windows |
| packaging-linux.sh | Fabrique les paquets Linux |
| packaging-windows.ps1 | Fabrique le paquet Windows |
| telemetrie-windows.ps1 | Banc de la couche anti-telemetrie Windows |
| telemetrie-reseau-windows.ps1 | Mesure la telemetrie reseau Windows |
| telemetrie-effet-windows.ps1 | Mesure l'effet d'un filtre de telemetrie |
| telemetrie-conditions-windows.ps1 | Etablit les conditions de mesure de telemetrie |
| telemetrie-cibles-windows.ps1 | Enumere les cibles de telemetrie |
| telemetrie-cause-windows.ps1 | Impute une sortie de telemetrie a sa cause |
| telemetrie-cause-binaire-windows.ps1 | Impute une sortie a un binaire precis |
| telemetrie-svchost-windows.ps1 | Analyse les sorties de telemetrie hebergees dans svchost |
| telemetrie-jeton-capture-windows.ps1 | Lit l'utilisateur du jeton capture a la creation de socket |
| telemetrie-w32time-windows.ps1 | Banc temoin sur W32Time, service qui, lui, se laisse bloquer |
| telemetrie-regle-microsoft-windows.ps1 | Rejoue une regle de blocage de Microsoft et mesure son effet |

Sous `packaging/`:

| Script | Usage |
|---|---|
| comptes.sh | Verifie la coherence des comptes systeme declares par le packaging |
| install-linux.sh | Installe le daemon, cree les comptes et l'unite systemd |
| install-windows.ps1 | Installe le service Windows et pose les ACL du resolveur |
| systemd/system-sleep/bifrost-reprise | Hook de reprise apres veille, cote systemd |

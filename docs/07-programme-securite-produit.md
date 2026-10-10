# Programme de securite du logiciel - Bifrost

## TL;DR
- Bifrost est un produit important de classe I au sens du CRA (les VPN sont listes explicitement en Annexe III) : l'auto-evaluation (Module A) n'est ouverte que si une norme harmonisee est appliquee integralement ; or aucune norme harmonisee CRA n'est encore citee au Journal officiel au 4 juin 2026, donc au lancement il faut soit attendre une citation au JO, soit passer par un notified body (Module B+C ou H).
- Le programme minimum viable au lancement tient en : modele de menace STRIDE+LINDDUN en threat-model-as-code (Threagile), CI de securite Rust/Go (clippy, cargo-audit, cargo-deny, cargo-vet, gosec, govulncheck), fuzzing cargo-fuzz sur les 4 parseurs a risque, security.txt RFC 9116, politique CVD, SBOM CycloneDX, et un premier audit externe finance via OTF Security Lab ou NLnet/NGI (potentiellement gratuit).
- Deux echeances reglementaires structurent le calendrier : 11 septembre 2026 (obligation de reporting Article 14 via la plateforme ENISA SRP) et 11 decembre 2027 (application pleine du CRA).

## Key Findings

1. **Le daemon privilegie est la surface critique.** Toute vulnerabilite memoire dans le daemon Rust tournant en SYSTEM/root est une escalade de privileges locale. Les exemples reels le confirment : selon le blog Mullvad (mullvad.net, 2024-12-11), "Four people from X41 D-Sec performed a penetration test and source code audit ... for a total of 30 person-days. The audit was performed between 23rd October 2024 and 28th November 2024 ... A total of six vulnerabilities ... None ... critical severity, three as high, two as medium, and one as low." L'une d'elles etait une PE Windows : selon l'audit publie (github.com/mullvad/mullvadvpn-app), "The Windows installer ... executed a binary named taskkill.exe placed next to the installer ... Since the installer runs with administrator privileges, this vulnerability allows for privilege escalation" (corrige en version 2024.8, PR #7225). X41 a aussi releve des race conditions dans le signal-handler pouvant mener a de la corruption memoire. Mullvad a par ailleurs eu une PE local-user-vers-SYSTEM sur Windows (avant 2023.6-beta1) par permissions de repertoire insuffisantes.

2. **Rust ne dispense pas d'audit.** Les blocs `unsafe` seront inevitables aux frontieres FFI (WFP via windows-rs, netlink, appels systeme). cargo-geiger compte le unsafe, miri detecte l'UB (mais ne traverse pas la FFI reelle), kani/creusot restent des efforts lourds reserves aux fonctions critiques.

3. **Le fuzzing est accessible sans infrastructure lourde.** cargo-fuzz (libFuzzer) + `arbitrary` couvrent les 4 parseurs prioritaires (profils, IPC, metadonnees de mise a jour, deserialisation). OSS-Fuzz est gratuit mais exige que le projet "serve a critical purpose to global infrastructure" ; a defaut, ClusterFuzzLite auto-heberge en CI est la solution.

4. **Un premier audit peut etre gratuit.** OTF Security Lab audite gratuitement les outils de liberte sur Internet (anti-censure, VPN) : selon l'OTF Application Guidebook (docs.opentech.fund), "the Security Lab has supported more than 170 audits, resulting in the identification and patching of over 2,000 privacy and security vulnerabilities." NLnet/NGI Zero finance des audits pour projets ayant recu une subvention NGI. Sovereign Tech Resilience finance des audits via OSTIF mais ne finance pas explicitement les applications end-user (un composant/bibliotheque sous-jacent serait un meilleur fit).

5. **CRA Article 14 : delais 24h/72h/14j.** Early warning 24h, notification 72h, rapport final 14j apres correctif (1 mois pour incident grave), via la plateforme ENISA SRP (Single Reporting Platform), obligatoire des le 11 septembre 2026. S'applique meme aux editeurs hors UE (dont un editeur suisse) des lors que les utilisateurs sont dans l'UE.

## Details

### PARTIE 1 - MODELE DE MENACE

**1.1 Cartographie de la surface d'attaque**

| Composant | Frontiere de confiance | Menaces STRIDE dominantes | Impact max |
|---|---|---|---|
| Daemon privilegie (Rust, SYSTEM/root) | Manipule pare-feu/routes/interfaces | Elevation of Privilege, Tampering | PE locale complete |
| IPC GUI<->daemon | Parsing, autorisation, deserialisation | Spoofing, Tampering, EoP | Contournement d'autorisation, PE |
| Parseur de profils/config | Entree non fiable (import, lien subscription) | Tampering, DoS, RCE | Corruption memoire, exec |
| Client de mise a jour | Parsing metadonnees, verif signature, ecriture privilegiee | Tampering, EoP | Persistance privilegiee |
| Processus tiers supervises (sing-box, Xray) | Binaires sur disque, IPC | Tampering, EoP | Substitution de binaire |
| Module de provisioning | Cles API hebergeur, cloud-init, SSH | Info Disclosure, Tampering | Compromission infra |
| GUI Tauri (WebView) | Surface web, capabilities v2 | Spoofing, Info Disclosure | XSS -> abus IPC |
| Installeur/desinstalleur | Execution privilegiee | EoP | PE (cf. Mullvad taskkill.exe) |
| Secrets au repos | Cles, config | Info Disclosure | Vol de cles |

**1.2 Adversaires et scenarios** - L'adversaire local non privilegie vise SYSTEM/root via IPC mal autorise, permissions de fichiers/repertoires laxistes (cf. Mullvad Windows PE), ou binaire plante a cote de l'installeur. Le serveur VPN malveillant : le client ne doit PAS faire confiance au serveur - toute donnee recue (routes poussees, DNS, config) est une entree non fiable a valider. Le profil malveillant est le vecteur le plus sous-estime, surtout via lien de subscription (parsing = RCE potentielle). L'attaquant reseau peut tenter TunnelVision (CVE-2024-3661) et TunnelCrack LocalNet (CVE-2023-36672, CVE-2023-35838) pour router du trafic hors tunnel via un faux serveur DHCP ; Mullvad desktop a mitige via des regles de pare-feu bloquant le trafic public hors tunnel. La supply chain : une crate/module Go trojanise s'execute avec les privileges du build puis du daemon.

**1.3 Methodologie** - Recommandation : **STRIDE** pour la securite + **LINDDUN** pour la vie privee (logiciel VPN), documentes en **threat-model-as-code**.

| Outil | Maintenu 2026 | Format | As-code / CI | Verdict |
|---|---|---|---|---|
| Microsoft TMT | Oui mais lent (v7.3.51110.1, 10 nov 2025, apres ~2 ans sans release) | .tm7 XML | Non / faible | A eviter (Windows-only, pas git-friendly) |
| OWASP Threat Dragon | Oui, actif (v2.x) | JSON | Semi (JSON diffable + GitHub) | Bon si equipe prefere diagrammes |
| pytm (OWASP) | Oui mais lent | Python | Oui | Bon si stack Python |
| Threagile | Oui, actif (repo mis a jour nov 2025) | YAML | Oui, GitHub Action officielle | **Recommande (stack Go, CI natif)** |

Garder le modele vivant : le fichier YAML Threagile vit dans le repo, tourne en CI a chaque PR touchant un composant sensible, et est revu a chaque changement d'architecture. Note d'interoperabilite : pytm et Threat Dragon participent a l'effort de format standardise CycloneDX TMBOM ; les formats des trois outils as-code sont actuellement mutuellement incompatibles.

### PARTIE 2 - DURCISSEMENT DU CODE

**2.1 Rust unsafe** - Isoler tout `unsafe` dans des modules FFI dedies avec invariants documentes (`// SAFETY:`), envelopper dans des API safe. cargo-geiger pour l'inventaire (indique aussi la presence de `#![forbid(unsafe_code)]`), miri pour l'UB (limite : ne traverse pas la FFI reelle), cargo-careful en test. kani/creusot : reserver aux fonctions cryptographiques ou de parsing les plus critiques, effort d'integration eleve. Pieges FFI classiques : validation de pointeurs/longueurs cote C, gestion de la propriete memoire a la frontiere, absence de panique traversant la FFI (UB).

**2.2 Analyse statique - config CI reelle**

`deny.toml` (cargo-deny) :
```toml
[advisories]
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
yanked = "deny"
[bans]
multiple-versions = "warn"
deny = []
[licenses]
allow = ["MPL-2.0", "Apache-2.0", "MIT", "BSD-3-Clause", "ISC"]
confidence-threshold = 0.9
[sources]
unknown-registry = "deny"
unknown-git = "deny"
```

Workflow GitHub Actions Rust :
```yaml
name: security
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with: { components: clippy }
      - run: cargo clippy --all-targets -- -D warnings -W clippy::all
      - uses: taiki-e/install-action@v2
        with: { tool: "cargo-audit,cargo-deny,cargo-vet" }
      - run: cargo audit -D warnings
      - run: cargo deny check
      - run: cargo vet --locked
```

Cote Go (sing-box, Xray, go-rosenpass eventuel) : `gosec ./...` et `govulncheck ./...` en CI. cargo-vet reserve aux exigences supply-chain strictes (adopter incrementalement via `cargo vet suggest` pour les exemptions) ; cargo-deny suffit comme baseline. Eviter la fatigue d'alerte : faire echouer la CI sur cargo-audit (`-D warnings`) pour maintenir le taux d'alertes non traitees a 0, et ne mettre en `warn` que multiple-versions.

**Ce que la CI reelle epingle, et ce qui reste flottant** (02/10/2026). Le bloc ci-dessus est un
modele. `.github/workflows/ci.yml` epingle chaque action par empreinte de commit et chaque outil a
une version exacte: `cargo-audit@0.22.2`, `cargo-deny@0.20.2` et `cargo-cyclonedx@0.5.9` par
`taiki-e/install-action` (manifeste de la v2.86.5; `fallback: none`, une version absente du
manifeste fait echouer l'etape au lieu de se rabattre sur cargo-binstall), `cargo-fuzz` 0.13.2 et
`cargo-vet` 0.10.2 par `cargo install --locked --version` (le manifeste de l'action, a l'empreinte
epinglee, ne connait de cargo-vet que la 0.10.0: les 0.10.1 et 0.10.2 n'ont aucun binaire publie
dans les releases GitHub de cargo-vet). Chacune etait la derniere publiee sur crates.io au
02/10/2026, cargo-vet encore au 07/10/2026, et les commandes de la CI passent avec elle; monter
une version est un changement a part entiere.
Les jobs tournent sur `ubuntu-24.04` et `windows-2025-vs2026`, pas sur `-latest`, qui change d'OS
ou de chaine MSVC sans un commit du depot (`ubuntu-latest` passe a Ubuntu 26.04 du 19/10 au
19/11/2026). Restent flottants: la revision hebdomadaire de l'image (noyau, outils, paquets
preinstalles), que le depot ne choisit pas et que l'en-tete de chaque job releve; les paquets apt
du job de fuite (nftables, tcpdump, iproute2, jq), deja presents dans l'image et non epingles, car
les index d'Ubuntu ne gardent que la version de sortie et la derniere mise a jour: un
`paquet=version` casserait l'etape a la mise a jour suivante.

**cargo vet sur l'espace de travail racine** (07/10/2026). `supply-chain/` porte la configuration de
cargo-vet (`config.toml`), le verrou des audits importes (`imports.lock`) et le fichier des audits
du depot (`audits.toml`). Aucun ensemble d'audits publies n'est importe, par choix: un import
recopie dans `imports.lock`, donc dans ce depot public, le nom et l'adresse de courriel de chaque
auditeur dont un audit sert. `config.toml` n'a donc aucune section `[imports]`, et `imports.lock`
ne porte que l'en-tete que `cargo vet init` ecrit (vet refuse de tourner sans ce fichier, et refuse
un fichier vide). `audits.toml` est VIDE: le depot ne certifie aucun paquet lui-meme. Les 299
dependances tierces du verrou racine, toutes plateformes et toutes fonctionnalites confondues, sont
donc toutes exemptees, chacune a sa version exacte (270 au critere `safe-to-deploy`, 29 a
`safe-to-run`). Les criteres sont ceux de cargo-vet par defaut: `safe-to-deploy` pour les
dependances normales et de construction de chaque paquet du depot, `safe-to-run` pour celles qui ne
servent qu'aux recettes. Le seul paquet du depot qui n'est pas livre, le temoin de diagnostic
`bifrost-temoin-svchost`, ne tire rien que le daemon ne tire deja. Les onze paquets du depot sont
declares de premiere partie (`audit-as-crates-io = false`): aucun n'existe sur crates.io, et la
declaration empeche vet de les confondre un jour avec un paquet homonyme du registre.

La CI le verifie dans le job `dependances`: `cargo vet --locked`, puis `git diff --exit-code` sur
`supply-chain/`. Sous `--locked`, vet ne va chercher aucun audit. L'etape echoue, en nommant le
paquet, sa version et le critere qui lui manque, sur une dependance nouvelle, sur une autre version
d'une dependance exemptee et sur une exemption retiree. Elle echoue aussi sur un `imports.lock`
absent ou vide, et sur un fichier hors de la forme canonique de vet, lignes vides finales comprises:
apres un succes, vet reecrit les trois fichiers a sa forme, et le `git diff` voit tout octet qu'il
a change. Ajouter une dependance, ou en changer la version, demande donc de lancer `cargo vet` hors
de la CI, qui dit ce qui manque, puis de l'exempter ou de l'auditer et de committer
`supply-chain/`.

`supply-chain/` est aussi sous la garde ASCII du depot, dans le job `controles`: la recette
`crates/bifrost-evasion/tests/sources_ascii.rs` en lit tous les fichiers, dans un lot a part et
sous la meme regle que les sources, et rougit sur un caractere hors ASCII comme sur un repertoire
absent ou un des trois fichiers de vet manquant. `caracteres_de_controle.rs` y lit les `.toml` et
le `.lock` comme partout ailleurs dans le depot.

Ce que cela ne dit pas:
- une exemption n'est pas un audit: les 299 dependances ne sont couvertes que par la decision de les
  accepter telles quelles, prise a la mise en place; l'etape dit seulement qu'aucune n'entre ni ne
  change de version sans un commit de `supply-chain/`;
- le harnais `fuzz/`, espace de travail separe, n'est pas couvert: 266 dependances tierces dans son
  verrou, dont 2 absentes du verrou racine (`arbitrary`, `libfuzzer-sys`).

**2.3 Fuzzing** - Priorite : parseur de profils > parseur IPC > metadonnees de mise a jour > deserialisation. Outils : cargo-fuzz (libFuzzer) + `arbitrary` en premier choix ; AFL++/honggfuzz en complement (tous trois supportes par OSS-Fuzz/ClusterFuzz).

**Ce qui est pose.** Le harnais vit dans `fuzz/` (cargo-fuzz 0.13, libFuzzer,
sanitizer d'adresses). C'est un espace de travail cargo SEPARE: son
`Cargo.lock` et sa politique de dependances (`fuzz/deny.toml`, celle de la
racine plus une exception nominative pour `libfuzzer-sys`, sous licence NCSA)
ne touchent ni le verrou ni les binaires du logiciel. Chaque cible appelle la
fonction de PRODUCTION du parseur par son chemin public. Les douze premieres
n'ont demande d'exposer aucun symbole. Les cinq cibles des lecteurs de la CLI
passent par la bibliotheque du paquet `bifrost-cli` (`src/lib.rs`): elle porte
les modules des preuves. Le binaire y appelle leurs points d'entree comme
avant, publics dans la bibliotheque pour lui; les cibles y appellent leurs
lecteurs, rendus publics pour elles (le lecteur JSON strict, le comparateur
nft hors ligne sans ses lectures de fichier, les lecteurs d'intention de
routage et ceux de la declaration du daemon). Le paquet n'est pas publie sur
crates.io: la bibliotheque n'a pour consommateurs que le binaire et le
harnais. Au-dela de l'absence de
panique, chacune verifie une propriete: lecture deterministe, aller-retour
par l'encodeur de production, issue exacte du cadrage, ou, pour les lecteurs
de la CLI, coherence du rapport et accord de deux chemins qui lisent les
memes valeurs.

| Cible | Parseur | Qui fournit l'octet, et qui le lit |
|---|---|---|
| `lien_colle` | `bifrost_amorce::colle::lire`, sans phrase | un lien colle, venu d'un inconnu; la CLI, avant toute signature |
| `lien_colle_chiffre` | `colle::lire` avec phrase: en-tete age, scrypt, clair | le meme lien, chiffre; la CLI |
| `moisson` | `bifrost_amorce::recuperer` | les canaux (miroirs HTTP, fichier, lien); la CLI |
| `signature_profil` | `bifrost_coffre::signature::{lire_cle_de_confiance, verifier}` | fichier de cle, profil et signature d'un canal; la CLI |
| `reponses_reseau` | `quic::lire_reponse`, `tls::decouper`, `coeurs::socks`, `coeurs::clash` | hotes distants et coeur tiers; le daemon (root) |
| `lien_profil` | `bifrost_core::profil::Profil::depuis_lien` | lien `vless://` ou `hysteria2://` d'un tiers (aucun appelant de production a ce jour) |
| `ipc_trame` | `IpcServer::accept` puis `Connection::recv`, sur un vrai socket Unix | tout client admis sur le socket; le daemon (root) |
| `ipc_json` | `Request`, `Response`, `TunnelConfig::validate` | client admis (requete lue en root); daemon (reponse lue par la CLI) |
| `profil_toml` | `toml::from_str::<TunnelConfig>` puis `validate` | profil du daemon (root), ou designe a `connect --config` |
| `politique_nft` | `politique_nft::Politique::lire`, `reference` | intention de `prove nft --politique`, declaration du daemon; la CLI |
| `politique_wfp` | `politique_wfp::PolitiqueWfp::lire`, `reference` | declaration du daemon; la CLI |
| `instantane_wfp` | `instantane_wfp::{Sid::lire_texte, Sid::lire_octets, lire_dacl}` | moteur WFP; la CLI |
| `capture_nft` | `bifrost_cli::preuve_nft::verifier_avec`: lecteur JSON strict, analyseur de capture et objets nommes, comparaison | deux captures `nft -j` designees a `prove nft --attendu --observe`, l'observe pouvant venir d'un autre poste; la CLI. Le meme analyseur lit la sortie de `nft` sous `--actif` |
| `politique_nft_cli` | `preuve_nft::Unique`, `Politique::lire`, `reference`, puis le comparateur de la CLI | intention de `prove nft --politique`; la CLI |
| `intention_routes` | `Unique` et `preuve_routes::plan_de_l_intention`; pour les memes valeurs, `declaration::analyser_routage` et `plan_de_la_declaration` | intention de `prove routes --intention` sous Linux; la CLI |
| `intention_routes_windows` | `Unique` et `preuve_routes_windows::plan_de_l_intention`; pour les memes valeurs, `analyser_routage_windows` et `plan_de_la_declaration` | intention de `prove routes --intention` sous Windows (lecteur pur, compile partout); la CLI |
| `declaration_daemon` | `declaration::{analyser, analyser_routage, analyser_routage_windows}` | reponse du daemon (root, LocalSystem) que `prove nft`, `prove wfp` et `prove routes` prennent pour attendu; la CLI, une fois l'identite du serveur admise |
| `trames_dbus` | `bifrost_cli::preuve_dns::dbus::{lire_accord, lire_reponse}` | trames que le bus systeme relaie a `prove dns` (tout pair que le bus relaie), lues sous le compte de l'utilisateur; la CLI |

Les graines (`fuzz/graines/<cible>`) viennent des recettes et des exemples du
depot: litteraux recopies, ou produits par les encodeurs de production a
partir des valeurs des recettes. Aucune n'est inventee, aucune ne porte de
secret: les paires minisign qui les signent ont ete engendrees pour l'occasion
et leur cle privee jetee.

**Lancer** (Linux, chaine nightly et `cargo-fuzz`): `./scripts/fuzz-linux.sh`
rejoue toutes les graines puis fuzze chaque cible 30 s; `--duree N` change le
temps par cible, `--rejouer` s'arrete apres la relecture, `--cible NOM`
restreint (option repetable). Les binaires sont construits la ou cargo les
mettrait (`CARGO_TARGET_DIR`, sinon `fuzz/target/`) et lus au meme endroit; le
corpus de travail et les entrees qui font tomber une cible restent sous
`fuzz/target/`. La CI fait de meme a chaque PR (job `fuzz`, nightly datee) et
passe `cargo deny` sur le verrou du harnais.
Le script donne aux cibles un repertoire temporaire a lui et le retire a sa
sortie, quelle qu'elle soit: `ipc_trame` y ecoute sur un socket Unix,
`signature_profil` y ecrit une cle publique, et rien n'en reste.

**Campagne initiale**, le 01/10/2026 sur essai-linux (canal `nightly` de
l'hote, rustc 1.95.0-nightly c78a29473 du 22/02/2026, une cible a la fois,
2 Gio par processus): 5 a 15 minutes par cible, de 70 000 executions
(`lien_colle_chiffre`, qui paie un scrypt par en-tete valide) a 155 millions
(`instantane_wfp`). Une seule cible est tombee: `lien_profil`, en moins d'une
seconde, sur une etiquette a caractere de controle venue de l'hote d'un lien
sans fragment. La classe etait plus large que l'hote: brut ou encode
(`%0A`), un caractere de controle du lien ressortait aussi dans la
configuration du coeur (`sni`, `host`, `path`) et dans les messages d'erreur
qui recitent le schema, le port ou un parametre refuse. `Profil::depuis_lien`
refuse desormais tout caractere de controle (C0, DEL, C1) avant tout usage et
sans le reciter, sauf dans la valeur de `obfs-password`, un secret jamais
recite; U+00A0, premier caractere apres C1, reste admis (recettes
`un_hote_a_caractere_de_controle_est_refuse`,
`un_caractere_de_controle_du_lien_ne_ressort_nulle_part`,
`del_et_c1_sont_refuses_comme_c0` et
`le_premier_caractere_apres_c1_reste_hors_de_la_classe`). La cible verifie
maintenant le refus et chaque champ en clair: sur le code qui ne corrigeait
que l'hote, elle trouve la classe en 25 executions. Les entrees sont devenues
des graines; une campagne de 15 minutes apres la correction de l'hote, puis
de 10 minutes apres celle de la classe, n'ont plus rien trouve. En tout,
2 h 09 de calcul pour les campagnes.

**Cibles des lecteurs de la CLI**, le 01/10/2026 sur essai-linux (meme
chaine, une cible a la fois, 2 Gio par processus): 10 minutes par cible, de
6,7 millions d'executions (`capture_nft`, qui analyse et compare deux
captures) a 31,8 millions (`intention_routes_windows`). Aucune n'est tombee.

**Ce que prouvent les plantages semes.** Chaque cible a ete eprouvee par une
ligne `panic!` semee dans le parseur qu'elle vise, puis retiree. Les douze
cibles sont tombees en moins d'une minute, chaque fois sur une entree mutee:
aucune graine telle quelle ne remplissait la condition. Trois entrees
etaient a une ou deux mutations d'une graine, neuf d'une entree que la
campagne avait deja derivee. Cela prouve que chaque cible atteint le code de
son parseur et que la mutation y produit des entrees voisines du corpus; pas
que le fuzzing trouve une condition eloignee. Les egalites de chaine trouvees
etaient a un chiffre d'une graine: `wg1` depuis le `wg0` des graines (un
changement d'entier ASCII ou d'un bit), `S-1-5-18` depuis `S-1-5-19`. Une
egalite sur `wg7` dans `profil_toml` n'a pas ete trouvee en 300 s (6,9
millions d'executions), pas plus, en 300 s chacun, qu'un entier ecrit en
decimal (`mtu == 1337`, une marque ou un LUID `4242`) ni deux longueurs a la
fois. Une condition que l'on veut voir eprouvee demande une graine qui
l'approche. Les cinq cibles des lecteurs de la CLI ont ete eprouvees de meme, par sept
plantages (un par lecteur que `declaration_daemon` donne a lire): elles sont
tombees en moins de deux secondes (1,2 s au plus a la premiere mesure, 1,6 s
a la contre-verification), chaque fois sur une entree a une valeur d'une
graine (une priorite de chaine, une marque, une table, une MTU, un numero
d'application).

**Ce qui manque.**
- Dans la CLI, ce qui entoure ses lecteurs: la lecture bornee du fichier, la
  reception de la declaration du daemon (identite du serveur, socket Unix ou
  pipe nomme) et le protocole qui l'encadre. Les cibles donnent leurs octets
  aux lecteurs, ni un fichier ni un serveur.
- Les trames rtnetlink que `prove routes` lit sous Linux
  (`preuve_routes::trames`): un decodeur pur, sans cible; sa source est le
  noyau.
- Le pipe nomme de Windows, lu par LocalSystem, et tout ce qui ne compile que
  sous Windows (DPAPI): le harnais ne tourne que sous Linux.
- Le cadrage HTTP du canal web (ureq): une cible n'a pas acces au reseau.
- Les lecteurs dont la source est le noyau ou le systeme (netlink, `/proc`,
  PktMon) ou un fichier du daemon (carnet).
- Aucune mesure de couverture par ligne (`cargo fuzz coverage` demande
  `llvm-tools`); les compteurs de libFuzzer en tiennent lieu.
- ClusterFuzzLite et OSS-Fuzz, ci-dessous.

Integration continue : OSS-Fuzz est gratuit mais reserve aux projets critiques pour l'infrastructure mondiale (decision au cas par cas via PR, avec score de criticite) ; si refuse, deployer **ClusterFuzzLite** en CI (auto-heberge, base sur ClusterFuzz).

**2.4 Durcissement compilation/execution** - Rust : ASLR et DEP sont poses par defaut, la
protection de pile ne l'est pas (`-Z stack-protector`, nightly) ; activer explicitement CFG sur
Windows (`-C control-flow-guard`), RELRO complet et PIE sur Linux (defauts de rustc). Cote Windows
execution : `SetProcessMitigationPolicy` avec `ProcessDynamicCodePolicy` (ACG -
`PROCESS_MITIGATION_DYNAMIC_CODE_POLICY.ProhibitDynamicCode = 1`), `ProcessSignaturePolicy`
(bloque l'injection de DLL non signee Microsoft), `ProcessControlFlowGuardPolicy`,
`ProcessImageLoadPolicy`. Le service Windows doit avoir une ACL restrictive et un SID de service
dedie.

**Ce qui etait deja la, mesure le 01/10/2026** sur `bifrost-daemon` et `bifrost-cli` construits
en `--release`, avant toute modification. Sous Windows (dev-windows, `dumpbin`): ASLR 64 bits et
DEP (DYNAMIC_BASE, HIGH_ENTROPY_VA, NX_COMPAT), poses par l'editeur de liens; aucun Control Flow
Guard: ni GUARD_CF, ni table des cibles, et les seuls controles etaient ceux de la bibliotheque C
de Microsoft. GuardFlags y valait pourtant 0x100, << CF instrumented >>: la Load Config vient de
cette bibliotheque, deja compilee avec /guard:cf, et ce drapeau seul ne prouve rien. Sous Linux
(essai-linux, `readelf`): executable PIE, RELRO complet (PT_GNU_RELRO et liaison immediate), pile
non executable, sans rien demander; la chaine gcc d'Ubuntu ajoute meme `-z now` d'elle-meme, si
bien que `-C relro-level=partial` seul y laisse un RELRO complet.

**Ce qui est pose.** `.cargo/config.toml` demande `-C control-flow-guard=checks` pour les cibles
Windows MSVC, et rien d'autre; sous Linux le fichier ne change rien (memes empreintes des
binaires). Mesure apres, binaires `--release` de dev-windows: GUARD_CF, 1758 cibles CFG pour le
daemon et 2332 pour la CLI, 4201 et 4476 appels indirects qui passent par le controle (3 et 3
avant); il reste 198 et 209 appels indirects nus, surtout dans le code precompile de la
bibliotheque standard. LTO (`thin`) garde CFG. Cout: +0,65 % de taille pour le daemon, +0,84 %
pour la CLI; temps de construction `--release` inchange a l'echantillon (291,5 s puis 289,4 s).

**Ce qui l'annule sans un mot, mesure.** cargo ne lit cette table que s'il est lance depuis le
depot (pas avec `--manifest-path` depuis un autre repertoire, pas par `cargo install` sans
`--path`), et `RUSTFLAGS` ou `CARGO_ENCODED_RUSTFLAGS`, meme definis a vide, la remplacent au lieu
de s'y ajouter.

**La garde.** `crates/bifrost-daemon/tests/durcissement_binaire.rs` lit les en-tetes de son
propre executable, sans outil externe. Sous Windows: les trois bits d'ASLR et de DEP, GUARD_CF
avec une table de cibles non vide, et un appel par pointeur ecrit dans ce fichier qui doit passer
par le pointeur de controle que l'image declare; ce dernier point separe `checks` de `nochecks`,
qui pose la table sans emettre un seul controle. Sous Linux: PIE, RELRO complet, pile non
executable. Partout: la table de `.cargo/config.toml`, seule partie que la CI automatique,
Linux, execute pour Windows. Chaque recette a ete vue rouge: drapeau retire, `nochecks`,
`RUSTFLAGS` vide ou autre, `CARGO_ENCODED_RUSTFLAGS` vide, cargo lance hors du depot, chacun des
trois bits ASLR/DEP; relocation statique, RELRO coupe ou paresseux, pile executable.
Elle lit un binaire de recette (profil de test, sans LTO), pas les binaires `--release`: les
drapeaux de cible sont les memes, et l'effet de LTO n'est mesure que par la mesure ci-dessus.

**CET et les binaires livres, 02/10/2026.** `.cargo/config.toml` ajoute `-C link-arg=/CETCOMPAT`
pour la cible MSVC x86_64, dans une table a part: Microsoft ne donne l'option que pour x64, et
rustc 1.98.0 n'en a pas d'equivalent. L'image se declare compatible avec la pile fantome (bit
CET_COMPAT des caracteristiques etendues, entree de type 20 du repertoire de debogage). Mesure sur
dev-windows: le bit est pose sur le daemon, la CLI et chaque executable de recette, tailles et
temps de construction `--release` inchanges; la suite complete et les deux binaires livres
tournent sous ce marquage. Une etape de la CI (`controles` sous Linux, `windows` sur demande)
construit en `--release` les binaires que les installeurs copient, et la recette ignoree
`les_binaires_livres_portent_le_durcissement` lit leurs en-tetes avec les lectures de la suite:
ASLR 64 bits et DEP, GUARD_CF et une table de cibles non vide, au moins 100 lectures des cases de
controle CFG dans le code (4 sans controle emis, celles de la bibliotheque C de Microsoft; 4783
pour le daemon et 5483 pour la CLI), le marquage CET; sous Linux, PIE, RELRO complet et pile non
executable. Elle refuse un repertoire qui n'est pas `release` et une copie de son propre
executable, et une autre recette confronte la liste des binaires lus aux scripts d'installation.
Cout mesure: 286 s de construction et 3 s de lecture sur dev-windows, 27 s et 0,3 s sur
essai-linux, sans recompiler la recette; sur le runner, non mesure. Chaque lecture a ete vue
rouge: binaires construits avec `CARGO_ENCODED_RUSTFLAGS` vide ou hors du depot (CFG, controles et
CET), sans `/CETCOMPAT` (CET seul), avec `control-flow-guard=nochecks` (le seul compte des
controles: GUARD_CF et la table restent poses), pile executable, RELRO coupe ou paresseux,
relocation statique; lecture d'un mauvais champ ou d'un mauvais bit; propriete retiree de la
lecture; repertoire absent, vide ou de profil de test; copie de la recette a la place d'un livre.

**Politiques d'execution Windows, 02/10/2026.** Le daemon se pose cinq politiques par
`SetProcessMitigationPolicy` (module `attenuation`), comme premiere instruction de `main` et
avant la lecture de sa ligne de commande, en service comme en console: `ProcessImageLoadPolicy`
(aucune image depuis un peripherique distant ni d'etiquette d'integrite basse, System32 d'abord
pour une image chargee par son nom), `ProcessExtensionPointDisablePolicy` (ni DLL AppInit, ni
fournisseur Winsock en couche, ni crochet global, ni ancien editeur de methode d'entree),
`ProcessStrictHandleCheckPolicy` (une reference a une poignee invalide leve une exception; les deux
bits, que le systeme exige ensemble), `ProcessControlFlowGuardPolicy` en `StrictMode` (toute DLL
chargee ensuite doit porter CFG) et `ProcessDynamicCodePolicy` (ACG, sans retrait par fil ni par
un autre processus). Une pose refusee est journalisee avec la politique, ses champs et le code
systeme, et le daemon continue: une politique absente est un durcissement en moins, pas une raison
de laisser la machine sans kill switch. Documentation Microsoft lue le 02/10/2026:
`SetProcessMitigationPolicy` (mise a jour le 07/01/2026), les structures `PROCESS_MITIGATION_*`
(22/02/2024), l'enumeration `PROCESS_MITIGATION_POLICY` (17/06/2026).

**Ce qui est ecarte.** `ProcessSignaturePolicy`: `MicrosoftSignedOnly` fait echouer le chargement
de wintun.dll et de wireguard.dll, signees par leur editeur (erreur 577 sous le service reel), donc
tout tunnel; `StoreSignedOnly` et `MitigationOptIn` exigent une signature qu'elles ne portent pas
non plus. `ProcessSystemCallDisablePolicy` (Win32k): le daemon importe user32, dont il emploie
quatre fonctions pour la window-station et le bureau du compte du resolveur, et la pose est alors
refusee (code 19, mesure sur dev-windows). `ProcessChildProcessPolicy`: le daemon lance les coeurs
et le resolveur (creation refusee, code 367, mesure sur dev-windows).

**Ce qui est mesure.** Sur dev-windows: seule `ProcessImageLoadPolicy` passe aux processus crees
apres la pose. Sur essai-windows, sous le service reel installe par le mecanisme du depot, binaires
`--release`: les cinq politiques se relisent de l'exterieur du processus du service
(`GetProcessMitigationPolicy` et `Get-ProcessMitigation` concordent), le coeur et le resolveur
lances ne portent que la premiere. Le service fait la meme chose avec et sans elles: statut par
l'IPC, kill switch arme puis desarme avec `allow_lan` (le LAN repond pendant l'armement),
adaptateur WireGuardNT, coeur sous son TUN Wintun, resolveur lance sous son compte, meme processus
du debut a la fin, arret propre et code de sortie 0, aucune erreur nouvelle au journal.
wintun.dll et wireguard.dll portent GUARD_CF et se chargent sous `StrictMode`.

**Les gardes.** Les recettes du module tiennent la liste posee (nom, valeur, bits, ordre), l'ecart
entre posees et ecartees, le refus nomme, et la place de la pose: premiere instruction de `main`,
bilan journalise juste apres l'ouverture du journal. `tests/attenuation_windows.rs` relit les
politiques dans son propre processus apres la pose; `tests/attenuation_daemon_windows.rs` les
relit de l'exterieur dans un daemon lance, depuis un processus qui n'en porte aucune, puisque la
premiere passe aux enfants. Les deux lisent une table ecrite a part. Chaque recette a ete vue
rouge: politique omise, mauvais bit, mauvaise valeur, un seul bit des poignees, mauvaise taille,
pose apres le journal ou apres la lecture de la ligne de commande, journal retire, lecture
toujours pleine, refus sans nom, politique ecartee posee, lanceur qui se pose les politiques.

**Ce qui manque.**
- La bibliotheque standard n'est pas instrumentee: elle est livree precompilee sans CFG, et seul
  `-Z build-std`, sur une chaine nightly, la recompilerait.
- L'effet a l'execution: aucun appel vers une cible invalide n'a ete fait tomber; la mesure
  statique compte les controles, pas leur effet. Un temoin d'execution devra empecher
  l'optimiseur de rendre l'appel direct (`std::hint::black_box`), sans quoi il ne prouve rien:
  c'est la cause de rust-lang/rust#135963, fermee le 24/01/2025 comme comportement attendu.
- L'effet de la pile fantome: le processeur de dev-windows ne la porte pas, et le processus y
  tourne sans elle; le marquage est mesure, pas son effet. wintun.dll et wireguard.dll ne sont
  pas marquees; en mode de compatibilite, seule une violation dans un module marque est fatale
  (documentation de PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY), ce qu'aucune mesure sous le
  service reel n'a encore confirme.
- La protection de pile de rustc (`-Z stack-protector`) n'existe que sur une chaine nightly
  (rustc 1.98.0 refuse toute option `-Z`): non posee. Le seul `__stack_chk_fail` des binaires
  Linux vient du code C d'une dependance de la CLI.
- Les binaires tiers que les installeurs deposent (dnscrypt-proxy, wireguard.dll) ne sont pas
  lus par la recette des binaires livres.
- Les politiques d'execution Windows ne couvrent pas ce que le chargeur a deja charge quand
  `main` commence: les DLL importees statiquement. Les poser avant ce point demande un reglage du
  systeme (options d'execution de l'image), hors du daemon.
- La signature reste ecartee tant que wintun.dll et wireguard.dll ne portent pas de signature
  Microsoft, et Win32k tant que le daemon emploie user32 pour le compte du resolveur.
- Le resolveur sous les politiques n'est mesure qu'a son lancement: sans pair vivant il ne repond
  pas, avec ou sans elles. Aucune chute sur une poignee invalide n'a ete provoquee.

### PARTIE 3 - AUDIT EXTERNE

**3.1 Marche des auditeurs**

| Auditeur | Region | Specialite | Rapports VPN/privacy publics |
|---|---|---|---|
| Cure53 | Berlin, DE | Web, crypto, VPN, apps | Mullvad, Nym, ExpressVPN, Psiphon |
| X41 D-Sec | DE | Pentest, code audit desktop | Mullvad app 2024 |
| Radically Open Security | NL | Infra, reseau | Mullvad infra (3e audit) |
| Trail of Bits | US | Crypto, systemes, fuzzing | Multiples (via OSTIF/OTF) |
| Assured AB | SE | Crypto, appsec | Projets OSS |
| 7ASecurity | Intl | Apps mobiles/desktop | Via OSTIF |
| Quarkslab | FR | Crypto, reverse | OpenSSL, Paramiko (via OSTIF) |
| NCC Group | UK/US | Large spectre, MASA | Mullvad Android MASA (fev 2025) |
| Least Authority | Berlin, DE | Crypto, protocoles | Projets privacy |

Audits publics comparables :
- **Mullvad app** : X41 D-Sec, 30 jours-homme, 23 oct - 28 nov 2024, 6 vulns (3 high, 2 medium, 1 low), rapport public.
- **Mullvad infra** : Cure53, 3-14 juin 2024, 4e audit, 2 issues (1 low, 1 medium), rapport public.
- **Nym** : Cure53, juillet 2024 - selon Nym Trust Center (nym.com), "Spanning 56 working days, the audit involved a team of six senior cybersecurity experts ... identifying 43 findings, including 7 security vulnerabilities - comprising critical and high-severity issues - and 24 general weaknesses" ; ex. NYM-01-013 "No integrity protection for Sphinx packets" (Medium).
- **Tailscale** : audits en continu via Latacora + SOC 2 Type II (Aprio).

**Couts** - Un audit d'app VPN desktop se situe generalement dans une fourchette de plusieurs dizaines de milliers d'euros ; l'audit Mullvad de 30 jours-homme (4 personnes) donne l'ordre de grandeur d'un audit client cible. Les no-logs audits type Deloitte/PwC sont cites a 50 000-100 000 USD par evaluation. **Fraicheur incertaine : ces couts varient fortement selon perimetre et auditeur ; demander des devis fermes.**

Fourchettes indicatives par perimetre : audit protocole/crypto seul (le plus cher au jour-homme) ; audit client desktop (perimetre le plus rentable pour un premier audit) ; audit infrastructure (separe) ; audit complet (somme des trois).

**3.2 Conduire un audit** - Perimetre premier audit a budget limite : cibler le daemon privilegie + IPC + parseurs (la ou l'impact est maximal). Fournir a l'auditeur : modele de menace Threagile, doc d'architecture, acces code source complet (white-box), environnement de test type staging (comme Mullvad, configure a l'identique de la production mais sans clients), points d'attention (blocs unsafe, FFI). Publier le rapport integralement : c'est ce que font Mullvad (audits/README.md sur GitHub, historique des audits depuis 2020) et Nym (trust center) - le benefice de credibilite depasse le risque d'exposition. Cadence : audit initial, puis biannuel (modele Mullvad), plus audit hors cycle a chaque changement majeur d'architecture ou de crypto.

**3.3 Financement d'audit gratuit**

| Programme | Eligibilite | Montant | Pour Bifrost |
|---|---|---|---|
| OTF Security Lab | Outils liberte Internet (anti-censure, VPN) ; projets non finances par OTF mais pertinents peuvent postuler | Audit gratuit (170+ audits soutenus) | **Tres bon fit (volet anti-censure)** |
| NLnet/NGI Zero | Projet ayant recu une subvention NGI ; audit inclus pour projets > 50k EUR | Audit inclus ; subventions 5k-50k EUR (jusqu'a 150-200k selon fonds) | Bon si subvention NGI obtenue |
| OSTIF | Facilite audits via financeurs (Alpha-Omega, Sovereign Tech) | Variable | Via un financeur tiers |
| Sovereign Tech Resilience | FOSS "base technologique", PAS applications end-user | Audits via OSTIF ; challenges jusqu'a 300k EUR/round de 4 mois | Fit limite (client = app end-user) |

Note : OTF est finance par l'USAGM (gouvernement US) - risque politique/budgetaire a noter. Sovereign Tech Fund a abaisse son minimum de 150k a 50k EUR mais "n'est actuellement pas a la recherche d'applications end-user" - un composant/bibliotheque sous-jacent serait un meilleur candidat.

### PARTIE 4 - DIVULGATION ET BUG BOUNTY

**4.1 Politique CVD** - Doit contenir : canal de contact, cle de chiffrement PGP, delai de reponse, delai de divulgation, safe harbor juridique, perimetre.

`/.well-known/security.txt` (RFC 9116, servi obligatoirement en HTTPS) :
```
Contact: mailto:security@bifrost.example
Contact: https://bifrost.example/security
Encryption: https://bifrost.example/pgp-key.txt
Policy: https://bifrost.example/security-policy
Acknowledgments: https://bifrost.example/hall-of-fame
Preferred-Languages: fr, en
Canonical: https://bifrost.example/.well-known/security.txt
Expires: 2027-07-25T00:00:00.000Z
```
Champs obligatoires : **Contact** (au moins un) et **Expires** (unique, date future, < 1 an recommande). Optionnels : Encryption, Canonical, Policy, Acknowledgments, Preferred-Languages, Hiring. Chemin exact : `/.well-known/security.txt` (fallback legacy `/security.txt`). Le fichier peut etre signe OpenPGP.

Modeles reutilisables : disclose.io (safe harbor), politiques Mullvad et Tor. **CVE/CNA** : un petit editeur n'a pas besoin de devenir CNA ; passer par un CNA existant (GitHub Security Advisories est CNA pour l'open source, ou MITRE en Root CNA). Devenir CNA n'exige qu'une politique de divulgation publique + un point de contact + l'acceptation des CVE Terms of Use, mais implique une charge continue peu justifiee pour une equipe de 1-3 personnes.

**4.2 Bug bounty**

| Plateforme | Region | Frais plateforme | Fit |
|---|---|---|---|
| HackerOne | US | 20 000 - 200 000+ USD/an | Trop cher au demarrage |
| Bugcrowd | US | des 5 000 USD (pentest ponctuel) | Triage gere |
| Intigriti | EU (BE) | 20-40% moins cher que HackerOne | **Bon fit EU** |
| YesWeHack | EU (FR) | Budget-friendly, triage gere | **Bon fit EU** |
| Immunefi | Web3 uniquement | - | Hors sujet |

Recommandation : commencer par une **VDP simple** (politique + security.txt + remerciements, sans prime), puis un programme **prive sur invitation**. Modele Nym : selon le Nym Trust Center, "As of December 2024, NymVPN is planning a vulnerability disclosure program for security researchers to report issues to be launched in 2025. This program will go live once the Cure53 audit findings have been addressed and released." Mullvad n'a PAS de bug bounty paye - juste un canal de report dans l'app avec remerciements. Un programme public est difficilement gerable pour une petite equipe (bruit, rapports LLM de faible qualite - plusieurs programmes rejettent desormais explicitement les rapports LLM low-effort).

Grille de primes indicative (si programme prive) : Critical (RCE daemon, PE vers SYSTEM) 2000-5000+ EUR ; High (contournement kill switch, fuite trafic) 1000-2000 EUR ; Medium 300-1000 EUR ; Low/recognition.

**4.3 Obligations CRA** - **Annexe I partie II** impose : (1) identifier et documenter vulnerabilites et composants, y compris un **SBOM** machine-lisible (CycloneDX ou SPDX) couvrant au moins les dependances de premier niveau ; (2) remedier "sans delai" via security updates, separees des mises a jour fonctionnelles si techniquement possible ; (3) tests et revues reguliers de la securite ; (4) publication d'infos sur les vulns corrigees une fois le correctif disponible ; (5) politique CVD ; (6) point de contact unique ; report des vulns de composants tiers a leurs mainteneurs.

**Article 14** (applicable 11 septembre 2026) : early warning 24h, notification detaillee 72h, rapport final 14j apres correctif disponible (1 mois pour incident grave), via la plateforme **ENISA SRP**. Ne sont reportables que les vulnerabilites **activement exploitees** et les incidents graves (un PoC sur GitHub ne compte pas). Editeur suisse vendant dans l'UE : soumis, car le CRA s'applique selon la localisation des utilisateurs. Une seule notification atteint simultanement le CSIRT coordinateur et ENISA. Deux obligations restent hors plateforme : informer les utilisateurs affectes (Art. 14(8)) et reporter la vuln d'un composant tiers a son mainteneur (Art. 13(6)).

Sanctions : selon le Reglement (UE) 2024/2847, Article 64(2), "Non-compliance with the essential cybersecurity requirements set out in Annex I and the obligations set out in Articles 13 and 14 shall be subject to administrative fines of up to EUR 15 000 000 or, if the offender is an undertaking, up to 2,5 % of its total worldwide annual turnover for the preceding financial year, whichever is higher."

**Fraicheur incertaine : au 29 juin 2026 la plateforme SRP n'etait pas encore live alors que l'obligation demarre le 11 septembre 2026 ; une periode de test est prevue.** NIS2 : ne s'applique pas a un editeur de logiciel en tant que fabricant de produit (le CRA est la lex specialis pour le logiciel) sauf si l'entite est elle-meme entite essentielle/importante au sens NIS2 par son activite.

Organisation : designer plusieurs reporters autorises (l'exploitation peut etre decouverte un week-end), definir triggers et chaine d'escalade, preparer des templates alignes SRP, mettre en place une astreinte informelle. S'abonner aux flux CVE de chaque composant du SBOM + EUVD (European Vulnerability Database) pour detecter l'exploitation active dans les 24h.

### PARTIE 5 - REVUE CRYPTOGRAPHIQUE

Points d'attention : integration **Rosenpass** (PQ), generation/stockage des cles, source d'aleatoire (`getrandom`/getrandom(2) sur Linux, `BCryptGenRandom` sur Windows - ne jamais reimplementer un PRNG), derivation de cles, chiffrement des secrets au repos.

Erreurs classiques reelles a eviter :
- **CVE-2021-46873** (WireGuard/wireguard-windows) : le protocole ne tient pas compte d'un adversaire reglant l'horloge systeme via NTP non authentifie, ce qui peut rendre une cle privee statique definitivement inutilisable (DoS/state disruption). Lecon : le client ne doit pas dependre d'une horloge non authentifiee pour la protection anti-rejeu.
- **CVE-2024-34446** (Mullvad Android) : en cas d'echec de creation du tunnel, aucun serveur DNS n'etait fixe dans l'etat de blocage, laissant fuiter le DNS (fail-open). Lecon : le blocage doit etre **fail-closed** (kill switch qui ferme par defaut).

Rosenpass : verification symbolique **ProVerif** publiee (repertoire analysis) ; preuve cryptographique **CryptoVerif** et papier scientifique en cours (non finalises) ; utilise Classic McEliece (authenticite/confidentialite) + Kyber (forward secrecy) ; injecte une PSK dans WireGuard toutes les 2 minutes. **go-rosenpass n'est pas audite** (mention explicite du projet) - ne pas l'utiliser en production sans revue. Faire auditer specifiquement la partie crypto par Cure53, Quarkslab, Least Authority ou Trail of Bits.

### PARTIE 6 - CERTIFICATIONS

| Label | Pertinence VPN | Cout/delai petite structure | Verdict |
|---|---|---|---|
| EUCC (Common Criteria EU) | Volontaire, base SOG-IS CC (Reglement 2024/482, dispo vendeurs depuis 27 fev 2025) | Eleve, plusieurs mois | Hors de portee au lancement |
| Common Criteria classique | Idem | Tres eleve | Hors de portee |
| ISO 27001 | Management securite (hausse de cout ~20% prevue 2026) | Moyen | Optionnel, apres traction |
| SOC 2 Type II | Marche US (modele Tailscale) | Moyen-eleve | Optionnel si clients US |

**CRA pour classe I : trancher precisement.** Le self-assessment (Module A) est ouvert **uniquement** si une norme harmonisee (ou specification commune, ou schema de certification) est appliquee integralement ; sinon third-party via notified body (Module B+C ou H). **Etat au 25 juillet 2026 : aucune norme harmonisee CRA n'est citee au Journal officiel (constat au 4 juin 2026 selon craevidence.com), donc la presomption de conformite de l'Article 27 n'est disponible pour aucune categorie de produit.** Les series EN 18031 et EN 40000 sont en cours ; le standard horizontal de vulnerability handling est vise pour le 30 aout 2026 et les standards produits (type C, importants/critiques) pour le 30 octobre 2026, mais la citation au JO n'est pas confirmee et suit un calendrier non arrete par la Commission. **Fraicheur incertaine.**

Consequence operationnelle : au lancement, pour un produit classe I, la voie Module A "documenter soi-meme les ecarts" n'est PAS ouverte sans norme harmonisee integralement appliquee ; il faut soit attendre la citation d'une norme au JO, soit engager un notified body (backlogs de demande attendus avant sept 2026 - engager tot). Un audit public credible (modele Mullvad/Nym) apporte plus de credibilite qu'une certification formelle couteuse.

### PARTIE 7 - PROGRAMME DE MISE EN OEUVRE

**Indispensable au lancement :** modele de menace Threagile en CI ; CI securite (clippy/audit/deny/vet, gosec/govulncheck) ; fuzzing cargo-fuzz des parseurs (pose: dix-huit cibles, lecteurs de fichiers de la CLI compris, section 2.3) ; security.txt + politique CVD ; SBOM CycloneDX a chaque build ; durcissement compilation + verification winchecksec/checksec ; process interne Article 14.
**Ensuite :** audit externe (viser OTF/NLnet gratuit) ; VDP puis bug bounty prive ; ClusterFuzzLite continu ; audit crypto dedie ; ISO 27001/SOC 2 a envisager.

**Calendrier :**
- **Avant le 11 sept 2026 :** process de reporting Article 14 operationnel, reporters designes, templates SRP, security.txt et politique CVD publies, SBOM automatise, monitoring CVE des dependances (flux + EUVD).
- **Avant le 11 dec 2027 :** conformite CRA complete (Annexe I parties I et II), technical documentation Annexe VII, EU Declaration of Conformity, marquage CE, premier audit externe publie, support period definie (min 5 ans, security updates disponibles min 10 ans ou duree du support si superieure).

**Effort/budget annuel (equipe 1-3 personnes) :**
- Outillage CI + fuzzing : integration initiale ~10-15 jours-homme, maintenance faible, cout logiciel quasi nul (open source).
- Audit externe : viser gratuit (OTF Security Lab / NLnet NGI) ; sinon budgeter plusieurs dizaines de milliers d'EUR (ordre de grandeur : audit client cible ~30 jours-homme).
- Bug bounty : VDP gratuite au depart ; si Intigriti/YesWeHack prive, prevoir frais de plateforme + budget primes selon la grille.
- Assurance cyber, certification : optionnel, differable.

**Qui fait quoi (1-3 pers) :** un responsable de la securite du logiciel (modele de menace, triage des vulns, decisions Article 14) ; un dev responsable CI/fuzzing/SBOM ; contact CVD partage avec astreinte informelle. En equipe de 1, le fondateur cumule, avec templates et automatisation maximale.

**Indicateurs :** couverture de fuzzing (% code des parseurs) ; nombre de blocs unsafe (cargo-geiger, tendance decroissante) ; delai median de remediation ; taux d'alertes cargo-audit non traitees (doit rester 0) ; delai de reponse aux reports CVD ; presence des mitigations dans le binaire (winchecksec/checksec pass/fail) ; delai de production du SBOM (automatise a chaque build).

**Reutilisable tel quel :** `deny.toml`, workflow CI ci-dessus, harnais de fuzzing, `security.txt`, structure de politique CVD (base disclose.io), fichier de modele Threagile.

## Recommendations

1. **Immediat (0-1 mois) :** publier security.txt + politique CVD (base disclose.io), mettre en place le workflow CI de securite et le SBOM CycloneDX. Cout quasi nul, satisfait deja plusieurs exigences de l'Annexe I partie II.
2. **Court terme (1-3 mois) :** ecrire le modele de menace Threagile en CI ; implementer les 4 harnais cargo-fuzz ; activer CFG/ACG/signature policy Windows et verifier via winchecksec ; monter le process Article 14 (reporters, templates SRP, flux CVE+EUVD) avant le 11 septembre 2026.
3. **Moyen terme (3-9 mois) :** candidater a OTF Security Lab (fit anti-censure fort) et/ou NLnet/NGI pour un audit gratuit ; a defaut demander des devis a Cure53 et X41 D-Sec pour le perimetre daemon+IPC+parseurs ; publier le rapport integralement.
4. **Avant mise sur le marche de l'UE :** trancher la voie CRA classe I - si aucune norme harmonisee n'est citee au JO, engager un notified body (backlog attendu) OU retarder le placement si une citation est imminente. Surveiller mensuellement le tracker du Journal officiel.
5. **Apres traction :** VDP -> bug bounty prive (Intigriti/YesWeHack) ; audit crypto dedie de l'integration Rosenpass ; envisager ISO 27001/SOC 2.

**Seuils qui changent la decision :** si une norme harmonisee CRA couvrant les VPN est citee au JO -> bascule vers Module A self-assessment (economie majeure, plus besoin de notified body). Si le volume de reports CVD depasse la capacite de triage manuel -> passer a une plateforme geree (Intigriti/YesWeHack). Si cargo-fuzz trouve des crashs recurrents -> prioriser ClusterFuzzLite continu et anticiper l'audit externe.

## Caveats
- **Couts d'audit :** fourchettes indicatives, forte variance selon perimetre/auditeur, fraicheur incertaine - obtenir des devis fermes ; le repere fiable est l'audit Mullvad de 30 jours-homme (4 personnes).
- **Etat des normes harmonisees CRA :** aucune citee au JO au 4 juin 2026 ; les dates cibles (aout/octobre 2026) ne sont pas confirmees et la citation au JO peut suivre bien plus tard. C'est le point le plus determinant pour la voie de conformite - le verifier avant toute decision.
- **Plateforme ENISA SRP :** non live au 29 juin 2026 alors que l'obligation demarre le 11 septembre 2026 - preparer une procedure de report de secours (contact direct du CSIRT coordinateur).
- **Eligibilite des programmes de financement (OTF, NLnet, Sovereign Tech) :** conditions susceptibles d'evoluer ; OTF est finance par l'USAGM (risque politique/budgetaire) ; Sovereign Tech ne finance pas les applications end-user, ce qui limite le fit pour un client VPN (mais une bibliotheque/composant sous-jacent pourrait etre eligible).
- **go-rosenpass** n'est pas audite a ce jour ; ne pas l'utiliser en production sans revue independante.
- Le chiffre "170+ audits" d'OTF et les grilles de prix bug bounty proviennent de sources datees 2025-2026 ; les verifier au moment de la candidature/contractualisation.
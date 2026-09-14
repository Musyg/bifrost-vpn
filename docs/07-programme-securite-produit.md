# Programme de securite produit - Bifrost

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

**1.3 Methodologie** - Recommandation : **STRIDE** pour la securite + **LINDDUN** pour la vie privee (produit VPN), documentes en **threat-model-as-code**.

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

**2.3 Fuzzing** - Priorite : parseur de profils > parseur IPC > metadonnees de mise a jour > deserialisation. Outils : cargo-fuzz (libFuzzer) + `arbitrary` en premier choix ; AFL++/honggfuzz en complement (tous trois supportes par OSS-Fuzz/ClusterFuzz).

Harnais type (`fuzz/fuzz_targets/profile_parser.rs`) :
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use bifrost_core::profil::Profil;
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = Profil::depuis_lien(s);
    }
});
```
Harnais avec `arbitrary` pour l'IPC :
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
// Illustratif: aucun module `ipc` de cette forme n'existe encore dans le
// depot. Le nom reste fictif A DESSEIN - le renommer en `bifrost_core::ipc`
// donnerait une reference precise a un symbole absent, ce qui se recopie sans
// se verifier. A reecrire le jour ou le harnais est vraiment pose.
use vpn_fictif::ipc::IpcMessage;
fuzz_target!(|msg: IpcMessage| {
    let _ = vpn_fictif::ipc::handle(&msg);
});
```

Le premier harnais, lui, vise des symboles qui EXISTENT
(`bifrost_core::profil::Profil::depuis_lien`), verifies le 21/08/2026. Aucun
repertoire `fuzz/` n'est encore pose dans le depot.
Integration continue : OSS-Fuzz est gratuit mais reserve aux projets critiques pour l'infrastructure mondiale (decision au cas par cas via PR, avec score de criticite) ; si refuse, deployer **ClusterFuzzLite** en CI (auto-heberge, base sur ClusterFuzz).

**2.4 Durcissement compilation/execution** - Rust : ASLR/DEP/stack protector actifs par defaut ; activer explicitement CFG sur Windows (`-C control-flow-guard`), RELRO complet et PIE sur Linux (souvent defaut). Verification : winchecksec (Windows), checksec/hardening-check (Linux) en CI post-build. Cote Windows execution : `SetProcessMitigationPolicy` avec `ProcessDynamicCodePolicy` (ACG - `PROCESS_MITIGATION_DYNAMIC_CODE_POLICY.ProhibitDynamicCode = 1`), `ProcessSignaturePolicy` (bloque l'injection de DLL non signee Microsoft), `ProcessControlFlowGuardPolicy`, `ProcessImageLoadPolicy`. Le service Windows doit avoir une ACL restrictive et un SID de service dedie.

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

**Fraicheur incertaine : au 29 juin 2026 la plateforme SRP n'etait pas encore live alors que l'obligation demarre le 11 septembre 2026 ; une periode de test est prevue.** NIS2 : ne s'applique pas a un editeur de logiciel en tant que fabricant de produit (le CRA est la lex specialis pour le produit) sauf si l'entite est elle-meme entite essentielle/importante au sens NIS2 par son activite.

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

**Indispensable au lancement :** modele de menace Threagile en CI ; CI securite (clippy/audit/deny/vet, gosec/govulncheck) ; fuzzing cargo-fuzz sur les 4 parseurs ; security.txt + politique CVD ; SBOM CycloneDX a chaque build ; durcissement compilation + verification winchecksec/checksec ; process interne Article 14.
**Ensuite :** audit externe (viser OTF/NLnet gratuit) ; VDP puis bug bounty prive ; ClusterFuzzLite continu ; audit crypto dedie ; ISO 27001/SOC 2 a envisager.

**Calendrier :**
- **Avant le 11 sept 2026 :** process de reporting Article 14 operationnel, reporters designes, templates SRP, security.txt et politique CVD publies, SBOM automatise, monitoring CVE des dependances (flux + EUVD).
- **Avant le 11 dec 2027 :** conformite CRA complete (Annexe I parties I et II), technical documentation Annexe VII, EU Declaration of Conformity, marquage CE, premier audit externe publie, support period definie (min 5 ans, security updates disponibles min 10 ans ou duree du support si superieure).

**Effort/budget annuel (equipe 1-3 personnes) :**
- Outillage CI + fuzzing : integration initiale ~10-15 jours-homme, maintenance faible, cout logiciel quasi nul (open source).
- Audit externe : viser gratuit (OTF Security Lab / NLnet NGI) ; sinon budgeter plusieurs dizaines de milliers d'EUR (ordre de grandeur : audit client cible ~30 jours-homme).
- Bug bounty : VDP gratuite au depart ; si Intigriti/YesWeHack prive, prevoir frais de plateforme + budget primes selon la grille.
- Assurance cyber, certification : optionnel, differable.

**Qui fait quoi (1-3 pers) :** un lead securite produit (modele de menace, triage des vulns, decisions Article 14) ; un dev responsable CI/fuzzing/SBOM ; contact CVD partage avec astreinte informelle. En equipe de 1, le fondateur cumule, avec templates et automatisation maximale.

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
# Bifrost - Document d'architecture logicielle, packaging, signature, mise a jour et provisioning

Etat de l'art au 25 juillet 2026. Termes techniques en anglais conserves. Client sous MPL-2.0, produit important de classe I au sens du Cyber Resilience Act (CRA).

## TL;DR
- Stack tranchee: **daemon Rust** (workspace multi-crates a la Mullvad, dont les paquets 2026.x reposent sur cargo/rustup + go + electron39) exposant une interface de gestion, avec **GUI Tauri v2** (coeur sub-600 KB, backend Rust) plutot qu'Electron; separation stricte daemon privilegie / GUI non privilegiee via IPC authentifie (named pipe ACL + verification du peer sur Windows, socket Unix + SO_PEERCRED/polkit sur Linux).
- Packaging: **WiX (MSI) sur Windows** comme Tailscale (qui distribue des .msi par architecture), MSIX ecarte pour la desinstallation des filtres WFP et la gestion de service; **.deb + .rpm heberges dans un depot signe GPG** sur Linux, Flatpak/Snap ecartes pour le daemon privilegie. Signature via certificat OV sur token/HSM (EV ne donne plus de reputation SmartScreen instantanee depuis 2024) ou Azure Artifact Signing si l'entite suisse devient eligible.
- Mise a jour: **The Update Framework (TUF)** pour la resilience anti-rollback/anti-freeze, implemente avec `tough` (AWS, Rust) ou le mecanisme Ed25519/minisign de `tauri-plugin-updater`; provisioning serveur en un clic via **API REST des hebergeurs (Vultr, DigitalOcean, Hetzner, SporeStack pour Monero)** + cloud-init durci. Le CRA impose des mises a jour de securite sur toute la duree de support et le reporting des vulnerabilites exploitees (early warning 24h, notification 72h) des le 11 septembre 2026.

## Key Findings

1. **Rust est la stack de reference des VPN serieux en 2026.** Mullvad implemente son daemon entierement en Rust, decoupe en crates `talpid-*` (generiques, VPN-agnostiques) et `mullvad-*` (specifiques), avec une interface de gestion gRPC et un GUI Electron+React. Le paquet Arch `mullvad-vpn-daemon` 2026.x liste `cargo (rust, rustup)`, `go`, `electron39`, `dbus`, `protobuf` comme dependances de build. C'est le modele a copier, en remplacant Electron par Tauri.

2. **La separation daemon privilegie / GUI non privilegiee est non negociable.** Le composant qui manipule WFP, nftables, routes et interfaces a besoin de root/admin; le GUI ne doit jamais l'avoir. Mullvad decrit son daemon comme un "long-running system service implemented in Rust" qui "exposes a gRPC management interface for frontends". Le risque cote IPC est concret: sur Windows, un named pipe mal ACL-ise permet l'impersonation (`ImpersonateNamedPipeClient`) et l'escalade SYSTEM (famille "Potato"); sur Linux, polkit a eu des CVE d'escalade (CVE-2021-3560, CVE-2021-4034 pkexec).

3. **Les regles de signature de code ont durci et EV a perdu son avantage.** Depuis le 1er juin 2023, la cle privee de tout certificat OV ou EV doit etre generee et stockee sur un module materiel FIPS 140-2 niveau 2 ou Common Criteria EAL 4+ non exportable (CA/Browser Forum, ballots CSC-13/CSC-17). Depuis 2024, Microsoft a retire le traitement special des certificats EV pour SmartScreen (section 3.D.3 du Trusted Root Program, aout 2024: "All EV Code Signing OIDs will be removed from existing roots, and all Code Signing certificates will be treated equally"). Depuis le 1er mars 2026, la validite maximale des certificats de signature tombe a 460 jours (~15 mois) via ballot CSC-31.

4. **TUF reste la reference pour un canal de mise a jour resistant a la compromission.** Projet CNCF gradue depuis le 18 decembre 2019, il protege contre le rollback et le freeze via roles de cles separes (root, targets, snapshot, timestamp). Les attaques 3CX (mars 2023, installeur signe trojanise via pipeline compromis) et SolarWinds (2020, backdoor signee avec le certificat legitime) montrent que la signature seule ne suffit pas: il faut la separation des roles et la verification cote client que TUF apporte.

5. **Le provisioning en un clic est realisable via les API REST des hebergeurs.** Vultr (API v2, cheapest $2.50-3.50/mo, ~$0.003/hr, Terraform officiel), DigitalOcean (API v2, droplet $4/mo, facturation a la seconde depuis le 1er janvier 2026, Terraform officiel), Hetzner (cloud API, CX23 a 5.49 EUR/mo ou 0.0088 EUR/hr), et surtout SporeStack (API-first, paiement Monero, sans KYC ni email) permettent de creer/detruire un serveur par programme avec image Debian 12 / Ubuntu 24.04.

## Details

### PARTIE 1 - ARCHITECTURE DE L'APPLICATION

#### 1.1 Choix du langage et du framework

Comparatif operationnel 2026:

| Stack | API systeme privilegiees | Binaire | RAM | Demarrage | Maturite VPN | Signature/packaging | Verdict |
|---|---|---|---|---|---|---|---|
| **Rust + windows-rs / netlink** | Excellent (FFI direct WFP, netlink) | Petit | Faible | Rapide | Mullvad, cloudflared | Bon (single binary) | **Retenu pour le daemon** |
| **Rust + Tauri v2 (GUI)** | via daemon | coeur sub-600 KB | Faible | Rapide | croissante | Bon | **Retenu pour le GUI** |
| Go + Wails | Bon (WireGuard officiel en Go) | ~8-15 MB | ~10 MB | <0.5s | Tailscale, WireGuard | Bon | Alternative credible |
| Go + Fyne | Bon | moyen | moyen | rapide | rare | moyen | Non |
| C++ + Qt | Excellent | gros | moyen | moyen | Amnezia | lourd | Non (surface, cout maintenance) |
| Electron | via daemon | ~150 MB+ (Chromium) | eleve | lent | Mullvad (UI) | Bon mais lourd | GUI seulement, ecarte |
| .NET MAUI | moyen sur Linux | gros | eleve | moyen | rare | moyen | Non |
| Flutter desktop | faible pour reseau bas niveau | gros | moyen | moyen | rare | moyen | Non |

Ce que font les projets comparables:
- **Mullvad**: daemon Rust (crates `talpid-*` + `mullvad-*`), GUI Electron+React, CLI Rust `mullvad`. Interface de gestion gRPC.
- **WireGuard officiel sur Windows**: implementation Go (wireguard-go) + driver Wintun (WireGuard LLC), distribue en MSI/MSM.
- **Tailscale**: `tailscaled` en Go, client Windows MSI par architecture (`tailscale-setup-1.76.3-amd64.msi`), utilise Wintun ("MSI is the only supported method of installing Wintun").
- **Amnezia**: C++/Qt.

Tauri v2 compare a Wails: Tauri a un ecosysteme plus grand (plus de 70 000 stars GitHub), un modele de securite par capabilities, et un binaire plus petit (app d'exemple sub-1 MB contre ~8 MB pour Wails Windows x64 selon le comparatif Elanis/web-to-desktop-framework-comparison). Wails produit des binaires ~15 MB, ~10 MB RAM, demarrage sub-0.5s selon ses propres docs (a verifier independamment).

**Decision:** Daemon en **Rust** (workspace multi-crates), GUI en **Tauri v2** (backend Rust unifie avec le reste, WebView systeme au lieu de Chromium embarque). Cela evite le poids d'Electron (que Mullvad traine dans ses paquets via `electron39`) tout en gardant une UI web moderne. Un fork Go/Wails est l'alternative si l'equipe est plus forte en Go, car WireGuard et Tailscale prouvent que Go accede correctement aux API reseau privilegiees.

#### 1.2 Architecture privilegiee: separation daemon et interface

Modele: un **service Windows** (SYSTEM) ou un **daemon systemd** (root, capacites reduites) tourne en privilegie; le GUI Tauri tourne en session utilisateur non privilegiee; ils communiquent par IPC.

Choix du canal IPC:

| Canal | Windows | Linux | Securite peer | Verdict |
|---|---|---|---|---|
| gRPC sur socket local | oui | oui | via TLS mutuel ou verif OS | Retenu (Mullvad l'utilise) |
| Named pipe | oui | non | ACL + verif du peer | Retenu cote Windows |
| Unix domain socket | non | oui | SO_PEERCRED | Retenu cote Linux |
| D-Bus | non | oui | polkit | Complement Linux |
| JSON-RPC sur TCP | oui | oui | faible (port ouvert) | Ecarte |

Authentification et autorisation de l'IPC:
- **Windows**: creer le named pipe avec un descripteur de securite restrictif (DACL limitant aux membres du groupe attendu), refuser `SECURITY_IMPERSONATION` non desire, et verifier cote serveur le PID/token du client. Le risque documente (HackTricks, Elastic Security): un pipe mal ACL-ise permet a un processus bas privilege de piloter le daemon, et l'impersonation de pipe est un primitive d'escalade SYSTEM connue.

```rust
// Cote serveur Windows: creation d'un named pipe avec DACL restrictive
// (pseudo-code windows-rs). On refuse l'acces au public, on autorise
// uniquement Administrators + le compte de service, et on verifie le client.
use windows::Win32::Security::*;
use windows::Win32::System::Pipes::*;

// SDDL: autoriser SYSTEM (SY) et Administrators (BA) en Full,
// refuser tout le monde d'autre. Pas d'ACE pour "Everyone".
let sddl = w!("D:(A;;GA;;;SY)(A;;GA;;;BA)");
// ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, ...)
// -> SECURITY_ATTRIBUTES passe a CreateNamedPipeW
// A la connexion: GetNamedPipeClientProcessId -> OpenProcessToken
// -> verifier le SID / l'integrite du client avant d'accepter les commandes.
```

- **Linux**: socket Unix dans `/run/bifrost/daemon.sock` avec permissions `0660` et groupe dedie `bifrost`; cote serveur, lire `SO_PEERCRED` pour obtenir uid/gid/pid du client et autoriser selon une ACL applicative; pour les actions sensibles declenchees par un utilisateur, deleguer l'autorisation a **polkit**.

```rust
// Cote serveur Linux: verification du peer via SO_PEERCRED
use std::os::unix::net::UnixStream;
use std::os::unix::io::AsRawFd;

fn check_peer(stream: &UnixStream) -> std::io::Result<()> {
    let fd = stream.as_raw_fd();
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void, &mut len)
    };
    if rc != 0 { return Err(std::io::Error::last_os_error()); }
    // Autoriser uniquement uid 0 ou membres du groupe bifrost.
    if cred.uid != 0 && !user_in_group(cred.uid, "bifrost") {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "peer refuse"));
    }
    Ok(())
}
```

Elevation a l'installation et a l'execution:
- **Windows**: l'installeur MSI declenche UAC une fois; le service tourne ensuite en SYSTEM et le GUI n'a plus jamais besoin d'elever. Piege: ne pas lancer le GUI en admin (sinon toute la surface WebView tourne en admin).
- **Linux**: `pkexec`/polkit pour les actions ponctuelles; le daemon systemd demarre au boot sans intervention. Pieges connus: CVE-2021-4034 (pkexec, escalade locale) et CVE-2021-3560 (polkit) imposent de garder polkit a jour et d'ecrire des regles polkit minimales.

Ce que font les projets existants: `mullvad-daemon` (service central, gRPC), `tailscaled` (daemon Go), le service WireGuard sur Windows (tunnel par service). Tous isolent le composant privilegie du frontend.

#### 1.3 Structuration en modules

Decoupage propose en crates Rust (inspire de talpid):

| Crate | Responsabilite | Depend de |
|---|---|---|
| `hyper-daemon` | binaire du service/daemon, boucle d'evenements, IPC serveur | toutes ci-dessous |
| `hyper-core` | machine a etats du tunnel (Disconnected/Connecting/Connected/Error) | `hyper-firewall`, `hyper-proc` |
| `hyper-firewall` | kill switch: WFP user-mode (Windows), nftables+fwmark (Linux) | `hyper-platform` |
| `hyper-proc` | supervision des process sing-box et Xray, restart, health | - |
| `hyper-profiles` | gestion des profils, import/export, validation | `hyper-secrets` |
| `hyper-secrets` | chiffrement au repos (DPAPI Windows, libsecret/keyring Linux) | - |
| `hyper-antitelemetry` | couche anti-telemetrie | `hyper-firewall` |
| `hyper-ipc` | schema gRPC/protobuf partage daemon <-> GUI | - |
| `hyper-updater` | client de mise a jour TUF/Ed25519 | `hyper-secrets` |
| `hyper-provision` | provisioning serveur (clients API hebergeurs, cloud-init) | `hyper-secrets` |

La **machine a etats du tunnel** vit dans `hyper-core`; le **kill switch** dans `hyper-firewall`; la **gestion des profils** dans `hyper-profiles`; la **supervision sing-box/Xray** dans `hyper-proc`; l'**anti-telemetrie** dans `hyper-antitelemetry`.

Configuration et secrets:
- Format: TOML pour la config, secrets separes.
- Emplacement: `%ProgramData%\Bifrost\` (Windows), `/etc/bifrost/` + `/var/lib/bifrost/` (Linux).
- Permissions: config lisible, secrets `0600` root.
- Chiffrement au repos: **DPAPI** (machine scope) sur Windows; **libsecret/keyring** ou fichier chiffre + cle dans le keyring sur Linux.

### PARTIE 2 - PACKAGING ET SIGNATURE WINDOWS

#### 2.1 Format de paquet

| Format | Installe un service | Driver | Desinstalle filtres WFP | Verdict |
|---|---|---|---|---|
| **WiX v5 (MSI)** | oui (ServiceInstall) | oui (via MSM) | oui (custom action) | **Retenu** |
| MSIX | oui depuis Win10 2004, admin requis | tres limite | non (sandbox) | Ecarte |
| Inno Setup / NSIS | oui (scripts) | oui | oui | Alternative |

MSIX gere les services depuis Windows 10 2004 (janvier 2020, MSIX Packaging Tool 1.2019.1220.0) mais avec des limites lourdes documentees par Microsoft: chemin de l'executable de service non editable, pas de dependances hors package, admin obligatoire, et le modele de virtualisation/sandbox est inadapte a un produit qui installe des filtres WFP persistants et un driver reseau. **MSIX est donc ecarte pour Bifrost.**

Ce que font les acteurs: Tailscale distribue des `.msi` par architecture plus un `.exe` self-extracting; le driver Wintun n'est installable que par MSI/MSM ("MSI is the only supported method of installing Wintun"). Mullvad et Proton utilisent des installeurs classiques avec service. **Decision: WiX v5, MSI, avec un merge module (MSM) pour l'eventuel driver.**

Squelette WiX (extrait ServiceInstall + retrait WFP a la desinstallation):

```xml
<!-- Product.wxs (WiX v5) -->
<Package Name="Bifrost" Manufacturer="Bifrost Sarl"
         Version="1.0.0" UpgradeCode="PUT-GUID-HERE"
         Scope="perMachine">
  <MajorUpgrade DowngradeErrorMessage="Une version plus recente est installee." />
  <MediaTemplate EmbedCab="yes" />

  <Feature Id="Main">
    <ComponentGroupRef Id="DaemonComponents" />
  </Feature>

  <ComponentGroup Id="DaemonComponents" Directory="INSTALLFOLDER">
    <Component Id="DaemonExe" Guid="*">
      <File Id="hyperdaemon.exe" Source="hyper-daemon.exe" KeyPath="yes" />
      <ServiceInstall Id="HyperSvc" Name="BifrostDaemon"
                      DisplayName="Bifrost Daemon"
                      Type="ownProcess" Start="auto" ErrorControl="normal"
                      Account="LocalSystem" />
      <ServiceControl Id="HyperSvcCtl" Name="BifrostDaemon"
                      Start="install" Stop="both" Remove="uninstall" Wait="yes" />
    </Component>
  </ComponentGroup>

  <!-- Custom action a la desinstallation: purge des filtres WFP -->
  <CustomAction Id="PurgeWfp" FileRef="hyperdaemon.exe"
                ExeCommand="--cleanup-firewall" Execute="deferred"
                Impersonate="no" Return="ignore" />
  <InstallExecuteSequence>
    <Custom Action="PurgeWfp" Before="RemoveFiles" Condition="REMOVE=&quot;ALL&quot;" />
  </InstallExecuteSequence>
</Package>
```

Le compte de service doit etre pleinement qualifie (`LocalSystem`, ou `NT AUTHORITY\LocalService` pour LocalService), sinon l'erreur classique "Service could not be installed. Verify that you have sufficient privileges to install system services" (issues WiX #5603, dotnet/docs #51175).

#### 2.2 Signature de code

Etat exact du marche 2026:
- **HSM/token obligatoire** depuis le 1er juin 2023 (CA/B Forum, FIPS 140-2 niveau 2 / CC EAL 4+, cle non exportable), pour OV **et** EV.
- **Validite max 460 jours** depuis le 1er mars 2026 (ballot CSC-31); GlobalSign a arrete les multi-annees le 26 decembre 2025, DigiCert apres fevrier 2026.
- **EV ne court-circuite plus SmartScreen** depuis 2024: la reputation se construit desormais organiquement par volume de telechargements, pour OV comme EV. Microsoft ne publie pas de seuil. Un nouveau hash de fichier repart de zero; la reputation se rattache au certificat, donc signer chaque build avec le meme certificat est essentiel.

Types de certificats:
- **OV**: verifie l'identite de l'organisation. Suffisant en 2026 pour la plupart des editeurs.
- **EV**: validation plus stricte, exige pour la signature de drivers kernel-mode. N'apporte plus la reputation SmartScreen instantanee.

Couts 2026 (fourchettes, a re-verifier car volatils):

| CA / revendeur | OV /an | EV /an | Cloud signing |
|---|---|---|---|
| Sectigo (via revendeur) | ~$216-226 | ~$290-500 | oui |
| Comodo (= Sectigo) | ~$219 | - | - |
| DigiCert | ~$400-409 | ~$685 | KeyLocker |
| SSL.com | - | - | eSigner des $180/an (240 signatures) |
| GlobalSign | ~$434 (HSM, historique) | - | Cloud HSM |
| Certum | des $99/an (via My-SSL) | - | SimplySign |

**Microsoft Trusted Signing (Azure Artifact Signing, ex-Azure Code Signing):**
- Des **$9.99/mois**, pas de token a acheter, cles en FIPS 140-2 niveau 3.
- **Signe uniquement des fichiers Authenticode Windows.**
- Eligibilite 2026: organisations et self-employed des **US, Canada, UE et UK**. La regle historique des 3 ans d'anciennete a ete levee pour les individus en public preview; Microsoft prevoyait de l'etendre aux organisations de moins de 3 ans.
- **Une entreprise suisse est hors de la liste** (US/Canada/UE/UK) tant que la Suisse n'y est pas ajoutee. C'est un point bloquant a re-verifier: si l'editeur est suisse, il devra passer par un CA (OV sur token/HSM) ou etablir une entite UE.

SmartScreen: la reputation se construit par volume de telechargements sur le certificat; pas de seuil publie; EV ne raccourcit plus l'attente depuis 2024. Piege documente (Microsoft Q&A): le renouvellement d'un certificat (meme organisation, nouveau thumbprint) **reinitialise** la reputation SmartScreen, sans procedure de transfert.

Signature en CI sans exposer la cle:

```yaml
# .github/workflows/sign.yml - exemple avec Azure Artifact Signing (Trusted Signing)
# La cle ne quitte jamais le HSM Azure; seul le digest est signe.
name: build-and-sign
on: { push: { tags: ["v*"] } }
jobs:
  build:
    runs-on: windows-latest
    permissions: { id-token: write, contents: read }
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: cargo build --release --locked
      - name: Azure login (OIDC, sans secret long-vivant)
        uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
      - name: Trusted Signing
        uses: azure/trusted-signing-action@v0
        with:
          endpoint: https://weu.codesigning.azure.net/
          trusted-signing-account-name: bifrost
          certificate-profile-name: bifrost-oveoc
          files-folder: target/release
          files-folder-filter: exe,msi
```

Alternatives sans exposer la cle: SignPath (service de signing avec HSM et politique), Azure Key Vault + signtool avec digest signing, ou eSigner (SSL.com) qui signe cote cloud.

#### 2.3 Cas particulier du driver

Si un callout driver kernel est ajoute plus tard (au-dela du WFP user-mode et de Wintun qui est deja signe Microsoft): il faut un compte **Microsoft Partner Center** (Hardware/Windows Dev), l'**attestation signing** ou l'EV pour soumettre, et le driver doit passer par le portail pour recevoir la signature Microsoft (WHQL ou attestation). Impact pipeline: une etape supplementaire hors GitHub Actions (soumission Partner Center), un certificat EV obligatoire pour l'authentification au portail, et des delais de validation. Recommandation: rester en **WFP user-mode + Wintun** (signe par WireGuard LLC/Microsoft) pour eviter cette chaine.

### PARTIE 3 - PACKAGING ET DISTRIBUTION LINUX

Formats:

| Format | Daemon systemd privilegie | nftables | Verdict |
|---|---|---|---|
| **.deb / .rpm** | oui | oui | **Retenu** |
| tarball | oui (script) | oui | complement |
| AUR | oui | oui | communautaire |
| AppImage | non (pas de service) | difficile | GUI seulement |
| Flatpak | non (sandbox) | non | Ecarte pour le daemon |
| Snap | partiel (confinement) | limite | Ecarte pour le daemon |

Flatpak et Snap sont concus pour des applications utilisateur sandboxees; ils ne conviennent pas a un daemon root qui manipule nftables, les routes et les interfaces reseau. Le sandbox casse precisement les capacites dont le VPN a besoin (CAP_NET_ADMIN, acces netlink, modification du firewall hote). Ce que font les acteurs: Mullvad distribue `.deb`/`.rpm` et un depot APT/RPM signe; Tailscale distribue via son propre depot APT/RPM par distribution; ProtonVPN distribue un paquet `.deb`/`.rpm` qui ajoute son depot. **Decision: .deb + .rpm dans un depot maison signe GPG, plus un GUI eventuellement en Flatpak si separe du daemon.**

Depot APT/RPM maison:
- **APT**: `reprepro` (simple, mono-version) ou `aptly` (snapshots, multi-version). Structure `dists/<suite>/main/binary-amd64/`, signature GPG du `Release` (`InRelease`).
- **RPM**: `createrepo_c` + signature GPG des paquets (`rpm --addsign`) et du repomd.
- Hebergement: bucket S3/CDN ou VPS statique; cout marginal (quelques EUR/mois de stockage + CDN).

Unite systemd durcie (fichier complet et commente):

```ini
# /etc/systemd/system/bifrost-daemon.service
[Unit]
Description=Bifrost privileged daemon
Documentation=https://bifrost.example/docs
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/bin/hyper-daemon --system
Restart=on-failure
RestartSec=2

# --- Durcissement ---
# Le daemon a besoin de configurer nftables, routes et interfaces tun.
# On garde UNIQUEMENT les capacites reellement necessaires.
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
# Empeche tout gain de privilege via setuid/setcap.
NoNewPrivileges=yes
# Systeme de fichiers en lecture seule sauf chemins explicites.
ProtectSystem=strict
ReadWritePaths=/var/lib/bifrost /run/bifrost /var/log/bifrost
# /home, /root, /run/user inaccessibles.
ProtectHome=yes
# /tmp prive.
PrivateTmp=yes
# Protege le noyau et les cgroups.
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
# Familles d'adresses: AF_NETLINK indispensable pour nftables/routes.
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@keyring @debug @mount @swap
# /proc masque les autres process.
ProtectProc=invisible
ProcSubset=pid
UMask=0077

[Install]
WantedBy=multi-user.target
```

Chaque directive: `CapabilityBoundingSet` limite l'ensemble des capacites au strict necessaire (CAP_NET_ADMIN pour nftables/tun/routes, CAP_NET_RAW pour les sockets raw); `NoNewPrivileges` neutralise setuid; `ProtectSystem=strict` monte tout le FS en lecture seule sauf `ReadWritePaths`; `RestrictAddressFamilies` doit inclure `AF_NETLINK` sinon le daemon ne peut plus programmer nftables. On verifie le score avec `systemd-analyze security bifrost-daemon.service`.

Integration NetworkManager et systemd-resolved:
- **systemd-resolved**: pousser le DNS du tunnel via `resolvectl dns <iface> <ip>` et `resolvectl domain <iface> ~.`; ne pas ecraser `/etc/resolv.conf` a la main si resolved gere le lien symbolique.
- **NetworkManager**: marquer l'interface tun comme non geree (`nmcli device set <iface> managed no`) ou utiliser les hooks dispatcher; ne pas casser la connexion physique existante.

Matrice de support raisonnable pour un petit editeur: Ubuntu 24.04 LTS et superieur, Debian 12+, et par extension Fedora/RHEL via `.rpm`. Eviter de promettre toutes les distributions; documenter le tarball generique pour le reste.

### PARTIE 4 - MISE A JOUR AUTOMATIQUE SECURISEE

Attaques connues sur les canaux de mise a jour (cas reels documentes):
- **SolarWinds (2020)**: backdoor SUNBURST injectee dans le pipeline de build, distribuee signee avec le certificat legitime SolarWinds. Selon les depots SEC de SolarWinds (8-K du 14 decembre 2020), **jusqu'a ~18 000** clients sur ~33 000 ont installe les versions Orion trojanisees (2019.4 a 2020.2.1, publiees mars-juin 2020); l'entreprise a ensuite revise a **"fewer than 100"** le nombre de clients reellement compromis au second stade. Lecon: une mise a jour signee et largement diffusee peut n'infecter reellement qu'une fraction ciblee, mais le canal atteint tout le parc.
- **3CX (mars 2023)**: installeur Electron signe et distribue via le canal de mise a jour officiel (Update 7, **versions 18.12.407 et 18.12.416**, signees par 3CX), DLLs malveillantes (d3dcompiler.dll, ffmpeg) injectees apres compromission du pipeline. 3CX declare **plus de 600 000 clients et 12 millions d'utilisateurs** (attribution Mandiant a UNC4736 / acteur lie a la Coree du Nord, campagne MITRE ATT&CK C0057).
- **ASUS Live Update (Operation ShadowHammer)**: cle de signature exploitee sur le serveur d'update. Selon Kaspersky (Securelist), la version backdooree a ete distribuee a possiblement **plus d'un million d'utilisateurs**, avec ~57 000 installations confirmees cote clients Kaspersky, mais seulement **~600 adresses MAC** etaient reellement ciblees pour le payload de second stade.

Lecon commune: la signature seule ne protege pas si le pipeline ou la cle sont compromis. Il faut separation des roles et verification cote client (TUF).

The Update Framework (TUF): projet CNCF gradue depuis le 18 decembre 2019. Roles de cles separes:
- **root**: ancre de confiance, delegue les autres roles.
- **targets**: signe les hashes des artefacts.
- **snapshot**: garantit la coherence de l'ensemble des metadonnees.
- **timestamp**: horodatage frequent, protege contre le **freeze** (empeche l'attaquant de servir une vieille version en pretendant qu'elle est a jour).
- Protection **rollback**: le client refuse une version de metadonnees inferieure a celle deja vue.

Implementations 2026:

| Implementation | Langage | Maturite | Verdict |
|---|---|---|---|
| python-tuf | Python | reference, maintenue | outillage cote serveur |
| go-tuf | Go | mature, refonte inspiree de python-tuf | si stack Go |
| **tough** (AWS) | Rust | production (Bottlerocket) | **retenu si TUF complet** |
| rust-tuf | Rust | "under active development, may not be suitable for production", API instable | a surveiller |

Alternatives et complements: **Sigstore/cosign** (signature keyless, transparence via Rekor), **tauri-plugin-updater** (verification Ed25519/minisign integree, ne peut pas etre desactivee), **Velopack** (delta updates, multi-langage, gratuit open source), **cargo-dist**, Omaha (Google), Sparkle (macOS), Squirrel.

**Comparatif honnete pour un editeur avec peu de moyens mais serieux:**
- Le plus rigoureux: **TUF (tough)** pour les metadonnees + artefacts signes, servis en statique sur CDN. Cout d'implementation eleve mais protection maximale (rollback, freeze, compromission partielle).
- Le pragmatique: **tauri-plugin-updater** (Ed25519/minisign, cle privee jamais partagee, signature obligatoire) pour demarrer, en gardant la cle hors CI (secret chiffre), puis migration vers TUF quand les moyens suivent.
- **Recommandation Bifrost**: demarrer avec la signature Ed25519 de tauri-updater pour le GUI, mais adosser le **canal du daemon a TUF (tough)** car c'est le composant privilegie ou une compromission est catastrophique.

Architecture du serveur de mise a jour:
- **Statique** (fichiers + metadonnees TUF sur CDN) plutot que dynamique: moins de surface d'attaque.
- Canaux **stable** et **beta** (repertoires distincts, metadonnees TUF separees).
- **Rollback** applicatif: garder N-1 disponible, mais TUF empeche le rollback malveillant des metadonnees.
- **Mise a jour differentielle**: possible (Velopack delta) mais optionnelle.

Gestion des cles:
- Cles **root** et **targets** hors ligne (HSM/token, coffre); **timestamp** en ligne (rotation frequente).
- **Rotation**: TUF permet la rotation de tout role sauf necessite de re-signer root avec quorum.
- **Compromission**: revoquer via nouvelle metadonnee root signee par le quorum root hors ligne; les clients rejettent l'ancienne.

Cas Windows: mettre a jour un service en cours sans casser le tunnel ni ouvrir de fenetre de fuite:
- Ne pas arreter le service avant d'avoir bascule; utiliser un schema **stage-then-swap**: telecharger et verifier la nouvelle version, puis redemarrage controle du service pendant que le kill switch WFP reste actif (les filtres WFP persistent tant qu'ils ne sont pas explicitement retires), de sorte qu'aucun trafic ne fuit pendant le redemarrage.
- Le kill switch doit etre concu pour rester en place pendant la breve indisponibilite du daemon.

Obligations CRA: le Cyber Resilience Act (Regulation (EU) 2024/2847) impose des **mises a jour de securite pendant toute la duree de support**, un traitement des vulnerabilites, un SBOM, et le reporting des vulnerabilites activement exploitees et incidents graves des le **11 septembre 2026** (Art. 14): **early warning sous 24h** de la prise de connaissance, **notification complete sous 72h**, et **rapport final sous 14 jours** a ENISA/CSIRT via la CRA Single Reporting Platform. Conformite complete et marquage CE au 11 decembre 2027. Concretement pour le mecanisme d'update: canal securise obligatoire, capacite a pousser un correctif rapidement, tracabilite des versions, documentation. Sanctions maximales: **jusqu'a 15 M EUR ou 2,5% du CA mondial** (le plus eleve) pour manquement aux exigences essentielles; le reporting tardif d'une vulnerabilite activement exploitee expose specifiquement a **jusqu'a 10 M EUR ou 2% du CA mondial**.

### PARTIE 5 - BUILDS REPRODUCTIBLES ET CHAINE D'APPROVISIONNEMENT

Pourquoi indispensable: pour un produit de securite open source, un tiers doit pouvoir verifier que le binaire distribue correspond au code publie (defense contre la compromission du pipeline, type SolarWinds/3CX).

Etat de l'art 2026:
- **Rust**: definir `SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)`, `CARGO_INCREMENTAL=0`, `--remap-path-prefix` pour effacer les chemins de build, `--locked`. Depuis rustc 1.69, `/Brepro` est passe automatiquement a link.exe sur PE quand `SOURCE_DATE_EPOCH` est defini (efface le timestamp PE).

```powershell
# Windows MSVC, build reproductible Rust
$env:SOURCE_DATE_EPOCH = (git log -1 --pretty=%ct)
$cwd = (Get-Location).Path
$env:RUSTFLAGS = "--remap-path-prefix=$cwd=/build/bifrost --remap-path-prefix=$env:USERPROFILE\.cargo=/cargo"
$env:CARGO_INCREMENTAL = "0"
cargo build --workspace --release --locked --target x86_64-pc-windows-msvc
# Verification: builder deux fois dans des repertoires distincts, comparer les digests.
```

- **Go**: `-trimpath` (supprime les chemins du module cache et du repertoire de travail des donnees DWARF), `GOFLAGS=-mod=readonly`, `GOPROXY` fige. Go embarque des builds reproductibles comme propriete de premier ordre.

Ce que font les acteurs: le projet Debian reproductible atteint plus de 95% des paquets reproductibles en trixie (2026) via `rebuilderd`; Tor Browser, Mullvad et Signal publient des builds verifiables. Ces retours publics confirment la faisabilite et l'importance de fixer toolchain + dependances + timestamp.

SBOM: formats **SPDX** et **CycloneDX**; outils `syft`, `cargo-sbom`/`cargo-cyclonedx`, `cyclonedx-gomod`; integration CI a chaque release. Le CRA impose un SBOM dans la documentation technique.

SLSA: niveaux 1 a 4. Realiste avec GitHub Actions: **SLSA niveau 3** atteignable via les attestations de provenance signees (GitHub Artifact Attestations / provenance generateur), avec runners isoles et build parametre. Viser L3 (provenance non falsifiable) est un objectif concret pour un petit editeur.

Securisation du pipeline CI:
- Secrets: OIDC plutot que secrets long-vivants; pas de cle de signature en clair.
- Runners: epingler les actions par SHA, pas par tag.
- Dependances: `Cargo.lock`/`go.sum` verrouilles, images Docker par digest.
- Audit: `cargo-audit`, `cargo-vet`, `govulncheck`, `dependabot`.

### PARTIE 6 - PROVISIONING SERVEUR EN UN CLIC

Objectif: depuis le client, l'utilisateur fournit une cle API d'hebergeur et obtient un serveur VPN configure, durci, cles generees et profil client importe automatiquement.

Outil IaC a embarquer: **ne pas embarquer Terraform** (binaire lourd, etat a gerer). Preferer des **appels API REST directs** depuis `hyper-provision` (Rust) + **cloud-init** pour la configuration du serveur. Terraform/OpenTofu reste pertinent en interne pour les tests, mais dans un produit desktop, l'appel API + cloud-init est plus simple et sans dependance externe. Ansible est trop lourd cote client.

API des hebergeurs pertinents (2026):

| Hebergeur | API REST | Creation par programme | Image Debian 12 / Ubuntu 24.04 | Cout min /mois | Cout horaire | Terraform |
|---|---|---|---|---|---|---|
| **Hetzner Cloud** | oui | oui | oui | 5.49 EUR (CX23) | 0.0088 EUR/hr | officiel |
| **Vultr** | oui (v2) | oui | oui | $2.50 (IPv6) / $3.50 (IPv4) | ~$0.003/hr | officiel |
| **DigitalOcean** | oui (v2) | oui | oui | $4.00 | ~$0.006/hr (a la seconde depuis 01/01/2026) | officiel |
| **OVHcloud** | oui (OVH + OpenStack) | oui | oui | 8.98 EUR (D2-2) | 0.0123 EUR/hr | officiel |
| **Exoscale** | oui | oui | oui | ~5 EUR (Micro) | a la seconde | officiel |
| **Infomaniak** | oui (OpenStack) | oui | oui | ~CHF 11 (1vCPU/2GB) | horaire | via OpenStack |
| **SporeStack** | oui (API-first) | oui | oui (debian-12) | paiement a la duree, Monero | serveur ephemere a la journee | non |
| **Njalla** | JSON-RPC | oui (classe Server) | oui | ~15 EUR | non (mensuel) | non |
| **AlexHost** | non trouve | non | oui (a la commande) | ~4 EUR entree | non | non |

**SporeStack** (particulierement pertinent, API-first, Monero, sans KYC ni email): fonds sur un "token", CLI et API pour lancer/gerer des serveurs. Exemples reels:

```bash
# SporeStack: creer un token finance en Monero, puis lancer un serveur Debian 12
sporestack token create --dollars 20 --currency xmr
sporestack token list
sporestack server launch --hostname hv-node --operating-system debian-12 --days 1
# --region pour fixer la region; autorenouvellement:
sporestack server autorenew-enable --hostname hv-node
sporestack server list
sporestack server delete --hostname hv-node
# Communication via Tor: SPORESTACK_USE_TOR_ENDPOINT=1
```

SporeStack revend en fait des serveurs sur des providers comme DigitalOcean et Vultr, avec un systeme de token anonyme. C'est l'option privacy par defaut d'Bifrost pour les utilisateurs qui veulent payer en Monero sans identite. Note AUP: activite malveillante interdite (port scanning, brute forcing), a documenter aux utilisateurs.

cloud-init complet et commente pour deployer le serveur VPN:

```yaml
#cloud-config
# Deploiement d'un noeud Bifrost durci: SSH hardening, pare-feu nftables,
# WireGuard + sing-box, generation de cles, exposition securisee du profil.
package_update: true
package_upgrade: true
packages:
  - wireguard-tools
  - nftables
  - curl
  - ca-certificates

users:
  - name: hyper
    groups: [sudo]
    shell: /bin/bash
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    ssh_authorized_keys:
      - ssh-ed25519 AAAA...   # cle publique poussee par le client

write_files:
  # Durcissement SSH: pas de root, pas de mot de passe.
  - path: /etc/ssh/sshd_config.d/99-hyper.conf
    content: |
      PermitRootLogin no
      PasswordAuthentication no
      KbdInteractiveAuthentication no
      AllowUsers hyper
  # Pare-feu nftables minimal: SSH + port WireGuard uniquement.
  - path: /etc/nftables.conf
    content: |
      #!/usr/sbin/nft -f
      flush ruleset
      table inet filter {
        chain input {
          type filter hook input priority 0; policy drop;
          ct state established,related accept
          iif lo accept
          tcp dport 22 accept
          udp dport 51820 accept
          ip protocol icmp accept
        }
        chain forward { type filter hook forward priority 0; policy drop; }
        chain output { type filter hook output priority 0; policy accept; }
      }

runcmd:
  # Generation de la cle WireGuard serveur.
  - umask 077; wg genkey | tee /etc/wireguard/server.key | wg pubkey > /etc/wireguard/server.pub
  # Activation du forwarding.
  - sysctl -w net.ipv4.ip_forward=1
  - echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-hyper.conf
  # Application du pare-feu et SSH.
  - systemctl enable --now nftables
  - systemctl restart ssh
  # Installation de sing-box (binaire officiel, verifie par hash).
  - curl -fsSLo /usr/local/bin/sing-box https://example/sing-box && chmod +x /usr/local/bin/sing-box
  # Le profil client (cle publique serveur + endpoint) est recupere par le
  # client via SSH sur un canal ephemere; ne jamais exposer la cle privee.
  - wg genkey | tee /etc/wireguard/peer.key | wg pubkey > /etc/wireguard/peer.pub
```

Provisioning RAM-only: realiste sur les providers qui supportent un boot netboot/rescue en RAM (ex. via image custom ou iPXE), mais pas universel. Pour Bifrost, c'est un mode avance optionnel; la plupart des providers ne l'exposent pas simplement par API. A documenter comme "best effort" sur Hetzner (mode rescue) et non garanti ailleurs.

Cycle de vie: rotation d'IP (detruire/recreer via API, cout horaire minime), destruction/recreation automatique (les serveurs ephemeres factures a l'heure/seconde rendent cela peu couteux: DigitalOcean facture a la seconde depuis le 1er janvier 2026, minimum 60s/$0.01; Vultr facture a l'heure avec un plafond mensuel de 672h), sauvegarde/restauration de la config (chiffree cote client), facturation suivie via l'API.

Le probleme de la cle API cote client (risque majeur): une cle API d'hebergeur permet de creer/detruire des serveurs et engage des couts. Mesures:
- **Stocker la cle chiffree** (DPAPI/keyring), jamais en clair.
- **Limiter la portee**: utiliser des cles API a permissions reduites (projet dedie chez Hetzner, token scope chez DigitalOcean/Vultr) et un projet/compte isole.
- **Duree de vie courte**: encourager la revocation apres provisioning.
- Idealement, ne pas garder la cle apres creation si l'utilisateur n'en a plus besoin.

### PARTIE 7 - SUPPORT, DIAGNOSTIC ET CRASH REPORTING SANS TELEMETRIE

Le paradoxe: un produit qui bloque la telemetrie ne peut pas en emettre. Modele Mullvad (a copier, documente dans `docs/logging-and-telemetry.md`):
- Logs ecrits **localement** par le service et le GUI, **jamais envoyes automatiquement**.
- Envoi **uniquement** via le formulaire "Report a problem"; les logs sont **anonymises** avant envoi (l'utilisateur peut les visualiser via "View app logs"), et l'email est optionnel.
- Ne jamais logger: numero de compte, device id, device name, cle WireGuard. Redaction automatique de: tout nombre a 16 chiffres, repertoire home (pour masquer le username), IP et adresses MAC, UUID v4 (IDs de compte/device, GUID d'interface sur Windows).
- Sur Windows, un `DAEMON.DMP` est genere au crash de `mullvad-daemon.exe`, **stocke localement** dans le meme repertoire que les logs, jamais envoye.
- Transport chiffre (TLS) avec **certificate pinning** quand l'utilisateur envoie.

Outils crash reporting auto-heberge et opt-in: **Sentry auto-heberge** ou **GlitchTip** (plus leger, compatible SDK Sentry) pour l'ingestion opt-in; **crashpad**/**breakpad** pour generer les minidumps cote client. **Recommandation**: minidump local (crashpad) + envoi **opt-in explicite** vers un **GlitchTip auto-heberge** (empreinte serveur faible), avec redaction cote client avant envoi.

Conception d'un rapport de diagnostic utile sans reveler d'information sensible:
- Inclure: version app/daemon, OS, etat de la machine a etats du tunnel, codes d'erreur, logs applicatifs anonymises, config non secrete.
- Caviarder automatiquement: IP/MAC, UUID, numeros a 16 chiffres, chemin home/username, cles et secrets, endpoints serveur si sensibles.
- Envoi manuel apres consultation par l'utilisateur, transport TLS + pinning.

### PARTIE 8 - PLAN DE MISE EN OEUVRE

Architecture de bout en bout (resume): daemon Rust privilegie (service Windows / systemd durci) exposant gRPC; GUI Tauri v2 non privilegie; IPC authentifie (named pipe ACL + verif peer / Unix socket SO_PEERCRED + polkit); kill switch WFP/nftables; sing-box + Xray supervises; secrets chiffres (DPAPI/keyring); packaging MSI (WiX) + .deb/.rpm (depot signe GPG); signature OV sur token/HSM (ou Trusted Signing si eligible); mise a jour TUF (tough) pour le daemon + Ed25519 pour le GUI; builds reproductibles + SBOM + provenance SLSA L3; provisioning via API hebergeurs + cloud-init durci; diagnostic local opt-in facon Mullvad.

Jalons avec critere de validation objectif:

| Jalon | Livrable | Critere de validation |
|---|---|---|
| J1 Prototype daemon | daemon Rust + IPC + machine a etats | connexion WireGuard etablie, kill switch actif, CLI pilote le daemon |
| J2 Securite IPC | ACL named pipe, SO_PEERCRED, polkit | un process non privilegie ne peut pas piloter le daemon (test d'intrusion) |
| GUI (jalon propre, apres J2) | GUI Tauri v2 non privilegiee | GUI Tauri non privilegiee pilote le daemon sans elargir le public de disconnect; prealable: le test d'intrusion J2 passe |
| J3 Packaging | MSI signe + .deb/.rpm + depot | installation/desinstallation propre, filtres WFP retires, service demarre |
| J4 Update | canal TUF + signature | un artefact non signe ou rollback est rejete par le client |
| J5 Reproductibilite | build reproductible + SBOM + provenance | deux builds independants -> digests identiques; SBOM genere en CI |
| J6 Provisioning | hyper-provision + cloud-init | un clic cree un serveur durci et importe le profil, sur 3 providers |
| J7 Diagnostic | rapport local anonymise opt-in | aucun secret/IP/UUID dans le rapport (audit du contenu) |
| J8 Conformite CRA | SBOM, politique de divulgation, canal update | documentation technique + processus de reporting 24h/72h en place |

Note du 05/09/2026 (arbitrage 4): le critere de J1 a ete amende. Il portait "GUI Tauri pilote le daemon"; il porte desormais "CLI pilote le daemon", et la GUI Tauri devient un jalon propre place apres J2 (polkit, reauthentification, DACL du tube nomme). Motif: les documents 01 et 06 ne disaient pas la meme chose du MVP. Le document 01, AXE 7, decrit la phase 0 (MVP) comme "WireGuard + kill switch + DNS local + client CLI" et place l'UI Tauri en phase 1; le README dit deja "Daemon et CLI uniquement, pas d'interface graphique". Le MVP est une ligne de commande; la GUI suppose J2 et son test d'intrusion.

Estimation d'effort par composant (jours-homme, calibree sur la taille/complexite des projets etudies; a affiner):

| Composant | Effort (j-h) | Reference |
|---|---|---|
| Daemon Rust + machine a etats | 40-60 | talpid-core (Mullvad) est un gros module multi-crates |
| IPC securise (Win + Linux) | 15-25 | named pipe ACL + SO_PEERCRED + polkit |
| Kill switch (deja specifie ailleurs) | - | hors perimetre |
| GUI Tauri v2 | 25-40 | UI complete multi-plateforme |
| Packaging MSI + WiX | 10-15 | ServiceInstall + custom action WFP |
| Packaging .deb/.rpm + depot | 8-12 | reprepro/createrepo + GPG |
| Signature + CI | 5-10 | workflow + HSM/Trusted Signing |
| Update TUF (tough) | 20-30 | integration serveur + client + rotation cles |
| Builds reproductibles + SBOM + SLSA | 10-15 | flags + verification + provenance |
| Provisioning (API + cloud-init) | 25-40 | N providers + cloud-init durci + cycle de vie |
| Diagnostic/crash reporting | 10-15 | crashpad + GlitchTip + redaction |
| **Total indicatif** | **~180-260 j-h** | hors couches deja specifiees |

Budget non salarial annuel estime:

| Poste | Cout annuel |
|---|---|
| Certificat OV code signing (Sectigo via revendeur) | ~$216-226 |
| Token HSM / eSigner cloud (si pas de token) | eSigner des $180/an, ou Trusted Signing ~$120/an ($9.99/mo) |
| Hebergement depot APT/RPM + serveur update (statique + CDN) | ~100-300 EUR |
| CDN | inclus/faible |
| Serveur(s) de test provisioning | ~50-150 EUR (ephemeres) |
| Compte Microsoft Partner Center (seulement si driver kernel) | $19 (one-time) |
| **Total** | **~600-900 EUR/an** (sans driver kernel) |

Reutilisable tel quel / a forker / a ecrire:
- **Reutilisable**: Wintun (signe Microsoft, WireGuard LLC), tauri-plugin-updater (Ed25519), tough (Apache-2.0), syft/cyclonedx (SBOM), sing-box/Xray (deja specifies), SporeStack CLI/lib (MIT). Verifier compatibilite MPL-2.0.
- **A forker**: rien d'essentiel; eventuellement des exemples WiX/cloud-init.
- **A ecrire de zero**: daemon, IPC securise, machine a etats, hyper-provision, couche diagnostic, packaging specifique.

Pieges connus (issues GitHub des projets etudies):
- **WiX/service**: "Service could not be installed. Verify that you have sufficient privileges" quand le compte de service n'est pas pleinement qualifie (`NT AUTHORITY\LocalService`).
- **Wintun**: ne jamais distribuer un driver nomme "Wintun" generique ni un MSI tiers (les projets se desinstallent mutuellement via le reference counting MSM); construire et distribuer son propre MSI.
- **SmartScreen**: le renouvellement de certificat reinitialise la reputation; signer chaque build avec le meme certificat et anticiper la periode de warnings.
- **Trusted Signing**: migration silencieuse d'intermediate CA (vers "Microsoft ID Verified CS EOC CA 03" vers le 26 mars 2026) a declenche des warnings SmartScreen meme pour des publishers deja trusted.
- **rust-tuf**: marque "may not be suitable for production, API unstable"; preferer `tough`.
- **systemd**: oublier `AF_NETLINK` dans `RestrictAddressFamilies` casse la programmation de nftables.

## Recommandations

**Etape 1 (immediat, J1-J2):** Construire le daemon Rust en workspace multi-crates (modele talpid), avec IPC gRPC et securite du peer des le depart (named pipe ACL + verif token cote Windows, SO_PEERCRED + polkit cote Linux). Benchmark de validation: un binaire non privilegie ne doit pas pouvoir emettre une commande de connexion/deconnexion acceptee par le daemon.

**Etape 2 (J3-J4):** Packaging MSI (WiX v5) et .deb/.rpm avec depot signe GPG; signature OV sur token/HSM. Ne pas payer pour EV (plus d'avantage SmartScreen depuis 2024) sauf besoin de signer un driver kernel. Mettre en place le canal de mise a jour avec TUF (tough) pour le daemon. Seuil de decision: si la Suisse est ajoutee a la liste Trusted Signing, basculer vers Azure Artifact Signing ($9.99/mo, signature en CI sans token).

**Etape 3 (J5-J6):** Builds reproductibles (Rust + Go), SBOM CycloneDX en CI, provenance SLSA L3 via GitHub Artifact Attestations. Implementer hyper-provision avec au minimum Hetzner, Vultr/DigitalOcean, et SporeStack (Monero). Valider le provisioning en un clic sur les trois.

**Etape 4 (J7-J8):** Diagnostic local opt-in facon Mullvad (redaction automatique: 16 chiffres, home, IP/MAC, UUID) + crashpad/GlitchTip auto-heberge. Mettre en place la documentation technique et le processus de reporting CRA (early warning 24h, notification 72h, rapport final 14 jours) avant le 11 septembre 2026, et viser la conformite complete + CE avant le 11 decembre 2027.

Seuils qui changent les recommandations: si le produit ajoute un driver kernel -> EV + Partner Center + attestation signing obligatoires. Si le volume de telechargements est faible -> anticiper des warnings SmartScreen prolonges (pas de raccourci EV). Si l'equipe est plus forte en Go qu'en Rust -> Wails + wireguard-go est une alternative validee par Tailscale/WireGuard.

## Caveats

- **Fraicheur des tarifs de certificats**: les prix OV/EV varient fortement selon revendeur et periode; les fourchettes (Sectigo ~$216-226 OV, DigiCert ~$400-409 OV / ~$685 EV, SSL.com eSigner des $180/an, Certum des $99/an) sont a re-verifier sur les grilles officielles avant achat.
- **CA/Browser Forum 2026**: la validite max de 460 jours (ballot CSC-31, 1er mars 2026) et l'arret des multi-annees (GlobalSign 26 decembre 2025, DigiCert apres fevrier 2026) sont bien documentes mais evoluent; confirmer avant engagement pluriannuel.
- **Eligibilite Trusted Signing pour une entite suisse**: la liste 2026 est US/Canada/UE/UK. La Suisse n'y figure pas explicitement dans les sources; **point bloquant a confirmer directement aupres de Microsoft** avant de baser la strategie de signature dessus.
- **Prix hebergeurs volatils**: Exoscale aurait repricie le compute +74% (mai 2026) et OVH ~+25% (2026) selon un tracker tiers (eucloudcost.com); re-verifier sur les pages officielles. Les prix Njalla/AlexHost proviennent partiellement de comparateurs tiers, et AlexHost n'a pas d'API publique de provisioning (inadapte au un-clic).
- **Chiffres d'impact des attaques**: les nombres SolarWinds ("up to 18,000" installes, "fewer than 100" reellement compromis) et ASUS ShadowHammer (~1M distribue, ~57 000 installs confirmes, ~600 cibles) proviennent respectivement des depots SEC de SolarWinds et de Securelist/Kaspersky; ils illustrent que la portee du canal excede largement la cible reelle.
- **rust-tuf** n'est pas production-ready (aveu du projet); `tough` (AWS) est l'implementation Rust recommandee.
- Certaines sources tarifaires et de comparaison de stacks proviennent de blogs; les chiffres structurants (Mullvad Rust, CA/B Forum HSM, SmartScreen EV 2024, dates et sanctions CRA, APIs hebergeurs) sont ancres sur documentation officielle, code source public ou textes reglementaires.
# Document d'implementation: composant "etancheite absolue" (kill switch + anti-fuite) client VPN WireGuard multi-plateforme

Etat de l'art au 25 juillet 2026. Style ingenierie. Termes/API en anglais conserves.

## TL;DR
- Sur Windows, la seule approche de production est WFP user-mode via fwpuclnt.dll (BFE), avec un FWPM_SUBLAYER dedie de poids maximal 0xFFFF et un filtre "block all" de poids 0, exactement comme WireGuard for Windows (tunnel/firewall/) et le winfw de Mullvad; un callout driver kernel n'est requis que pour le split tunneling par paquet et coute un compte Partner Center + certificat EV.
- Sur Linux, le kill switch se fait en nftables family inet (policy drop) couple au mecanisme fwmark/suppress_prefixlength de wg-quick; pour un proxy local (sing-box) on exempte le trafic via `socket cgroupv2` (kernel >= 5.13, correct en namespaces seulement >= 6.12), pas via net_cls (qui n'existe pas en cgroup v2).
- Le DNS doit etre force vers un resolveur local unique (dnscrypt-proxy recommande) plus un filtre WFP/nftables bloquant tout :53 sortant sauf vers ce resolveur; a l'interieur du tunnel le DNS chiffre est redondant mais utile contre les applications a resolveur DoH embarque, qu'il faut bloquer explicitement.

## Key Findings

### 1. Windows: WFP user-mode suffit pour le kill switch; le kernel callout n'est utile que pour le split tunneling par paquet
Le code de reference (WireGuard for Windows, MIT) pose tous ses filtres via l'API user-mode `fwpuclnt.dll` (FwpmEngineOpen0, FwpmProviderAdd0, FwpmSubLayerAdd0, FwpmFilterAdd0) avec de simples droits administrateur. Aucun driver n'est requis pour "block all sauf le tunnel".

### 2. Arbitrage WFP: sublayer de poids maximal + hard permit/block via FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT
Une faille documentee (simplewall issue #689) montre qu'un filtre concurrent sur un sublayer de poids 0xFFFF/0xFFFE avec hard permit peut ecraser un block. La parade, adoptee par simplewall (commit 2b7a4a8), est le flag FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT sur les filtres de blocage (veto).

### 3. Linux: fwmark + suppress_prefixlength, nftables inet, exemption proxy via cgroup v2
La methode wg-quick est la reference. Pour sing-box, l'exemption se fait par `socket cgroupv2`, avec une limite majeure de fraicheur (comportement namespace correct seulement en kernel >= 6.12).

### 4. Fuites au boot: boot-time ET persistant, les deux depuis l'espace utilisateur; cote Linux, unite systemd tres precoce
**Corrige le 21/08/2026 apres mesure.** Ce paragraphe affirmait que le WFP boot-time filter (FWPM_FILTER_FLAG_BOOTTIME) n'etait settable que par un driver kernel, donc hors de portee sans budget de certificat EV. C'est faux: un simple processus utilisateur eleve en pose un, et il est enregistre dans le magasin que `tcpip.sys` lit avant le demarrage de BFE. Mesure sur essai-windows le 17/08/2026, par mutation dans les deux sens, puis cycle de vie complet le 18/08. Voir la section detaillee plus bas.

Les deux drapeaux etant exclusifs sur un meme filtre, la couverture sans trou demande DEUX jeux: boot-time pour la fenetre pre-BFE, persistant pour la suite.

---

## Details

### PARTIE 1 - KILL SWITCH WINDOWS VIA WFP

#### 1.1 Hierarchie WFP appliquee au kill switch

Objets WFP, du haut vers le bas: **provider** (identite, namespace des filtres) -> **sublayer** (groupe de filtres, possede un poids UINT16) -> **filter** (regle: layer + conditions + action + poids UINT8/UINT64) -> **callout** (logique kernel custom, optionnel). Les **layers** sont fixes par Windows.

Layers exacts a utiliser pour un kill switch orient connexion (ALE, stateful, evalue une fois par connexion):
- `FWPM_LAYER_ALE_AUTH_CONNECT_V4` / `_V6`: autorisation des connexions sortantes (TCP connect, premier paquet UDP). C'est le layer central du kill switch sortant.
- `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4` / `_V6`: autorisation des connexions entrantes.

WireGuard for Windows n'utilise que ces quatre layers ALE pour l'ensemble permit/block (voir rules.go ci-dessous). Il utilise en plus, en option commentee, `FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE` / `FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE` (layer 2) pour Hyper-V, desactive par defaut. Les layers `FWPM_LAYER_OUTBOUND_IPPACKET_V4/V6` (couche paquet, apres routage) ne sont PAS utilises par WireGuard car le filtrage par LUID d'interface au layer ALE suffit et est plus simple.

Systeme de poids et arbitrage. La doc Microsoft (FWPM_SUBLAYER0, fwpmtypes.h) precise: "Higher-weighted sublayers are invoked first". Au sein d'un sublayer, les filtres sont tries par poids decroissant. Regle d'arbitrage finale (Project Zero, Google): un **hard block** > **hard permit** > **soft block** > **soft permit**. Un filtre est "hard" s'il porte FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT.

Types de poids de filtre: `FWP_EMPTY` (auto-weight, BFE choisit), `FWP_UINT8` (0-15, plage courte), `FWP_UINT64` (plage complete). WireGuard convertit un uint8 en FWP_VALUE0 de type **FWP_UINT8** (et non FWP_UINT64) via le helper `filterWeight` situe dans tunnel/firewall/helpers.go:

```go
func filterWeight(weight uint8) wtFwpValue0 {
	return wtFwpValue0{
		_type: cFWP_UINT8,
		value: uintptr(weight),
	}
}
```

Sublayer dedie. WireGuard cree son propre sublayer avec le **poids maximal `^uint16(0)` = 0xFFFF = 65535 (MAXUINT16)** dans registerBaseObjects (blocker.go):

```go
sublayer := wtFwpmSublayer0{
	subLayerKey: bo.filters,
	displayData: *displayData,
	providerKey: &bo.provider,
	weight:      ^uint16(0),
}
err = fwpmSubLayerAdd0(session, &sublayer, 0)
```

Valeurs reelles observees dans les projets:
- **WireGuard for Windows**: sublayer 0xFFFF; filtres permit aux poids 12-15, block-all au poids 0.
- **Mullvad libwfp** (exemple): `sublayer.weight(MAXUINT16)` (0xFFFF).
- **Mullvad winfw**: design a plusieurs sublayers, un "baseline" de poids le plus eleve voyant tout le trafic en premier (permit-filters de poids haut, blocking-filter catch-all de poids bas), plus des sublayers specialises (ex: DNS) de poids legerement inferieur.
- Le sample Microsoft msnfilter.cpp utilise 0x100 (valeur "on ne se soucie pas de l'ordre").

Recommandation: sublayer a 0xFFFF, filtres permit a poids eleve, block-all a poids 0, ET flag CLEAR_ACTION_RIGHT sur les filtres de blocage pour empecher qu'un antivirus/autre VPN sur un sublayer concurrent 0xFFFF n'ecrase le block via hard permit.

Transactions WFP. WireGuard englobe l'installation de tous les objets dans une transaction (runTransaction), ce qui evite toute fenetre de fuite pendant la reconfiguration: les filtres apparaissent atomiquement. La doc Mullvad confirme: "All changes to the rules are applied as atomic transactions. This means that there is no time window of inconsistent or invalid rules during changes." Sequence: FwpmTransactionBegin0 -> Fwpm*Add0/Delete0... -> FwpmTransactionCommit0 (ou FwpmTransactionAbort0 sur erreur).

Persistant vs boot-time.
- **FWPM_FILTER_FLAG_PERSISTENT** (filtre) + **FWPM_PROVIDER_FLAG_PERSISTENT** / **FWPM_SUBLAYER_FLAG_PERSISTENT**: les objets survivent au redemarrage de BFE et sont re-ajoutes quand BFE demarre. Settable en user-mode.
- **FWPM_FILTER_FLAG_BOOTTIME** (filtre): applique des le demarrage du driver TCP/IP (tcpip.sys), AVANT que BFE ne demarre; retire quand BFE finit son initialisation. Il ne peut pas etre combine avec FWPM_FILTER_FLAG_PERSISTENT.

**Ce document a affirme que ce drapeau n'etait settable que par un driver kernel-mode, et c'est faux.** Mesure sur essai-windows le 17/08/2026 par `--boot-filtres`, depuis un processus utilisateur eleve, sans driver et sans certificat: le filtre est enregistre dans `BFE\Parameters\Policy\BootTime\Filter`, le magasin que `tcpip.sys` consulte avant le demarrage de BFE, au meme endroit et sous la meme forme que les 16 filtres boot-time natifs de Windows. Verifie par mutation dans les deux sens: 16 -> 17 a la pose, 17 -> 16 au retrait. Cycle de vie complet le 18/08, redemarrage reel compris.

Ce qui EST mesure et ce qui ne l'est pas, a ne pas confondre: on a la PRESENCE du filtre dans le magasin pre-BFE, pas l'observation d'un rejet dans cette fenetre. La fermer vraiment demanderait un temoin d'audit (evenement 5152) horodate avant le demarrage de BFE.

Deux pieges mesures au passage. Un filtre boot-time n'est pas enumerable dans le moteur en cours d'execution: sans GUID connu d'avance il n'est joignable par aucun chemin, retient son sublayer indefiniment, et la machine reste a moitie coupee - c'est arrive une fois, et c'est pourquoi Mullvad ecrit ses GUID en dur. Et `FWP_E_FILTER_NOT_FOUND` (0x80320003) est DISTINCT de `FWP_E_NOT_FOUND` (0x80320002): ne pas le tolerer fait avorter toute la transaction de retrait sur un filtre simplement deja absent.

Pour un blocage effectif DES LE BOOT: la voie PERSISTENT reste active des que BFE demarre (tot dans le boot, mais pas avant tcpip.sys), et c'est ce que fait Mullvad en mode "lockdown"/auto-connect. Comportement du moteur boot-time (Microsoft Learn, basic-operation.md): les boot-time filters sont appliques des le demarrage de tcpip.sys et **desactives quand BFE demarre**, moment ou les persistants prennent le relais - il n'y a donc pas de trou entre les deux si l'on combine les deux jeux, ce que ce depot peut faire SANS driver.

#### 1.2 BFE user-mode vs callout driver kernel

Faisable en user-mode (droits admin, `fwpuclnt.dll`): tout le kill switch "block all sauf tunnel/DNS/DHCP/NDP/loopback", incluant le split tunneling par processus grossier via ALE_APP_ID.

Split tunneling par processus en user-mode: **OUI**, partiellement. On peut filtrer par executable au layer ALE via `FWPM_CONDITION_ALE_APP_ID` et `FwpmGetAppIdFromFileName0` (qui convertit un chemin DOS en chemin NT `\device\harddiskvolume...`). WireGuard l'utilise pour s'auto-autoriser (permitWireGuardService). Limites: c'est une decision permit/block a l'etablissement de connexion, PAS une redirection de socket ni un routage par processus; on ne peut pas envoyer le trafic d'un processus dans le tunnel et celui d'un autre hors tunnel au niveau routage sans manipuler la table de routage ou un callout. Mullvad l'illustre: leur split tunneling Windows par processus utilise un **callout driver WFP dediee (mullvad-winfw / split tunnel driver)** qui inspecte et devie les paquets.

Exige un callout driver kernel: split tunneling par paquet (redirection selon le processus), inspection/modification de paquets, redirection de socket (bind redirect via FWPM_LAYER_ALE_BIND_REDIRECT_V4/V6 et FWPM_LAYER_ALE_CONNECT_REDIRECT_V4/V6, layers reserves aux callouts kernel).

Signature 2026 d'un callout driver (source Microsoft Learn, code-signing-reqs, a jour 2026):
- Un driver kernel-mode DOIT etre signe par le Microsoft Hardware Dev Center (Partner Center). Depuis Windows 10, l'auto-signature ne charge plus (hors test mode).
- Prerequis absolu: un **certificat EV code signing** enregistre sur le compte Partner Center. "To submit binaries for attestation signing, your Hardware Dev Center dashboard account must have at least one EV certificate associated with it."
- **Attestation signing**: Microsoft contresigne apres verifications automatisees, SANS test HLK complet. Fonctionne sur Windows 10/11 Desktop. Limite: les drivers attestation-signed ne peuvent PAS etre distribues via Windows Update aux audiences retail.
- **WHCP/HLK**: requis seulement pour publier via Windows Update ou obtenir la certification WHQL. Non necessaire pour un editeur qui distribue son driver avec son propre installeur.
- Couts 2026: certificat EV code signing. Prix DigiCert 2026 verifie chez revendeurs: environ 519-625 USD/an en direct (comparecheapssl.com), environ 419-524 USD/an via revendeurs (codesigningstore.com: "DigiCert EV Code Signing Certificate at $524.67/year"). **Point important CA/B Forum: depuis le 15 fevrier 2026 les certificats code signing sont limites a 1 an maximum (plus de multi-annuel)**, ce qui augmente le cout recurrent.
- **Microsoft Trusted Signing** (ex-Azure Code Signing, rebaptise Azure Artifact Signing en 2026): tier Basic a 9,99 USD/mois pour jusqu'a 5 000 signatures/mois (overage 0,005 USD/signature), tier Premium a 99,99 USD/mois (100 000 signatures). Cependant il **ne supporte pas encore la registration Hardware Program EV** (source Microsoft Q&A): pour signer un driver kernel et enregistrer un compte Hardware Program, il faut toujours un certificat EV classique.
- Commande de signature (Microsoft Learn): `SignTool sign /s MY /n "Company Name" /fd sha256 /tr http://timestamp... /td sha256 /v fichier.cab`, puis soumission du .cab dans Partner Center.

Verdict pour ce produit: implementer le kill switch et le split tunneling grossier (par processus, permit/block) en **user-mode pur**, ce qui evite entierement le cout/delai de signature driver. Reserver le callout driver a une phase ulterieure si un split tunneling par paquet est demande.

#### 1.3 Code de reference

**WireGuard for Windows** (git.zx2c4.com/wireguard-windows, mirror github.com/WireGuard/wireguard-windows), Go, licence **MIT**. Repertoire tunnel/firewall/. Le kill switch complet tient dans blocker.go (~188 lignes, ~3,99 KB) + rules.go (~33 KB, ~900-1000 lignes) + helpers.go (~3,48 KB) + types_windows.go (~14,8 KB). Directement reutilisable.

Sequence d'installation (blocker.go, EnableFirewall):
```go
err = permitWireGuardService(session, baseObjects, 15)   // le service lui-meme (poids 15)
if len(restrictToDNSServers) > 0 {
	err = blockDNS(restrictToDNSServers, session, baseObjects, 15, 14) // permit DNS 15, block DNS 14
}
err = permitLoopback(session, baseObjects, 13)           // loopback (13)
err = permitTunInterface(session, baseObjects, 12, luid) // trafic sur l'interface tun (12)
err = permitDHCPIPv4(session, baseObjects, 12)
err = permitDHCPIPv6(session, baseObjects, 12)
err = permitNdp(session, baseObjects, 12)
err = blockAll(session, baseObjects, 0)                  // catch-all block (0)
```

permitWireGuardService: filtre a DEUX conditions - `FWPM_CONDITION_ALE_APP_ID` (chemin exe) ET `FWPM_CONDITION_ALE_USER_ID` (SECURITY_DESCRIPTOR du process courant), ce qui empeche un autre process hebergant le meme exe de matcher. C'est la resolution du probleme oeuf-poule: le service WireGuard peut sortir vers l'endpoint car il est autorise par identite de process, pas par IP.

blockDNS (extrait, montre le OR logique par repetition de condition et le decoupage permit/deny):
```go
denyConditions := []wtFwpmFilterCondition0{
	{fieldKey: cFWPM_CONDITION_IP_REMOTE_PORT, matchType: cFWP_MATCH_EQUAL,
	 conditionValue: wtFwpConditionValue0{_type: cFWP_UINT16, value: uintptr(53)}},
	{fieldKey: cFWPM_CONDITION_IP_PROTOCOL, matchType: cFWP_MATCH_EQUAL,
	 conditionValue: wtFwpConditionValue0{_type: cFWP_UINT8, value: uintptr(cIPPROTO_UDP)}},
	// Repeat the condition type for logical OR.
	{fieldKey: cFWPM_CONDITION_IP_PROTOCOL, matchType: cFWP_MATCH_EQUAL,
	 conditionValue: wtFwpConditionValue0{_type: cFWP_UINT8, value: uintptr(cIPPROTO_TCP)}},
}
```
La contrainte de conception clef (Mullvad, docs): "WFP doesn't support AND for same-type conditions" - deux conditions de meme fieldKey sont combinees en OR. blockDNS exige que le poids allow (15) soit strictement superieur au poids deny (14): `if weightDeny >= weightAllow { return errors.New("The allow weight must be greater than the deny weight") }`.

permitDHCPIPv4 cible precisement: UDP, local port 68, remote port 67, remote address 255.255.255.255 (0xffffffff). permitDHCPIPv6 cible les multicast link-local (FF02::1:2) et site-local (FF05::1:3), ports 546/547. permitNdp autorise ICMPv6 types 133-137 avec adresses link-local/router-multicast. Ce sont exactement les protocoles a laisser passer.

**Mullvad** (github.com/mullvad/mullvadvpn-app), licence **GPLv3**. Cote Windows: shim Rust `talpid-core/src/firewall/windows.rs` (FFI, quelques centaines de lignes) qui appelle la lib C++ **windows/winfw/** (winfw.dll, module multi-fichiers de plusieurs milliers de lignes ou reside la vraie logique WFP). GUID de sublayer/filtres persistants observes: filtre persistant `{a81c5411-0fd0-43a9-a9be-313f299de64f}`, filtre temporaire `{79860c64-9a5e-48a3-b5f3-d64b41659aa5}`. Egalement la lib autonome **mullvad/libwfp** (C++, wrapper WFP reutilisable) et **mullvad/wireguard-nt**. Le crate Rust `windows-rs`, ou les crates communautaires `wfp` (github.com/dlon/wfp-rs) et `windows-wfp` peuvent servir de base si on choisit Rust.

**simplewall** (github.com/henrypp/simplewall), C, licence **GPLv3**. Exemple de filtrage WFP user-mode par processus (ALE_APP_ID). Interet principal pour ce projet: l'issue #689 documente et corrige (commit 2b7a4a8) la faille d'ecrasement de block par hard permit d'un sublayer concurrent, via CLEAR_ACTION_RIGHT. A etudier pour la robustesse, pas a forker.

**WinDivert** (reqrypt.org, github.com/basil00/WinDivert), driver WDF/WFP + DLL user-mode, licence **LGPLv3**. Permet capture/drop/reinjection de paquets en user-mode. **Mauvais choix pour un kill switch de production**: (1) c'est un mecanisme de capture/reinjection, pas une politique de filtrage declarative - le blocage depend d'un process user-mode qui lit/reinjecte; si ce process meurt (kill -9, crash), la protection tombe, contrairement a un filtre WFP declaratif qui reste applique par le kernel; (2) le driver WinDivert.sys doit etre signe - les variantes A/B/C different par la signature, et "Commercial users of WinDivert ought to sign the driver with their own certificate"; (3) latence et races (paquets "impostor", boucles de reinjection) documentees. WinDivert est adapte au DPI-bypass (GoodbyeDPI), pas a une garantie d'etancheite.

#### 1.4 Cas limites Windows

- **Endpoint VPN (oeuf-poule)**: autoriser par IDENTITE de process (permitWireGuardService: ALE_APP_ID + ALE_USER_ID), pas par IP. Ainsi seul le daemon VPN sort vers n'importe quelle IP (dont l'endpoint), sans ouvrir de trou pour les autres process.
- **Endpoint par nom de domaine**: resoudre le nom AVANT d'activer le block-all (comme WireGuard qui fait resolveHostname avec retries accrus si StartedAtBoot). Une fois l'IP obtenue, le kill switch autorise le daemon a sortir; la resolution ulterieure passe par le resolveur local autorise. Pour autoriser la resolution DNS de l'endpoint sans ouvrir tout le DNS: filtre permit :53 uniquement vers le resolveur local (127.0.0.1 ou l'IP du resolveur embarque), comme blockDNS restreint aux serveurs specifies.
- **Fenetre de fuite boot / veille (S3/S4/Modern Standby) / changement de reseau / reconnexion**: filtres PERSISTENT actifs des BFE; la reconfiguration de tunnel se fait en transaction (pas de fenetre). Au reveil et au changement de reseau, garder les filtres en place et ne reconfigurer que l'interface. WireGuard gere les races SCM au boot par retries (jusqu'a 15 tentatives, tunnel/service.go).
- **IPv6**: soit router IPv6 dans le tunnel (permit sur l'interface tun V6 + block-all V6), soit bloquer completement IPv6 si le serveur ne le supporte pas. WireGuard pose systematiquement les blockAll V6 -> pas de fuite IPv6 possible meme si l'endpoint est IPv4-only. NE PAS se contenter de desactiver IPv6 par registre; bloquer au niveau WFP.
- **DHCP, NDP**: a autoriser (permitDHCPIPv4/v6, permitNdp). **ARP**: layer 2, non gere par les filtres L3 ALE (fonctionne independamment). **mDNS (5353), LLMNR (5355), NetBIOS (137-139), SSDP (1900), WPAD (port 80 vers wpad)**: bloques par le block-all sortant (aucun permit). Si un acces LAN optionnel est active, ajouter des permits cibles vers les prefixes RFC1918/link-local uniquement.
- **Captive portal (hotel/aeroport)**: Mullvad n'ouvre PAS de "mode portail" cassant la garantie; leur kill switch reste actif. La strategie recommandee est un mode "LAN access"/pause explicite et temporaire (equivalent du "Allowing LAN" de Mullvad), l'utilisateur decidant en connaissance de cause. Mullvad et Proton ne desactivent pas le kill switch pour un portail: l'utilisateur passe par un etat "bloque mais LAN autorise". NCSI (voir Partie 3) declenche la detection de portail; ne pas le bloquer si on veut la detection.
- **Interaction Defender / AV tiers / autre VPN**: chacun pose ses filtres sur ses propres sublayers. Le risque est qu'un hard permit d'un sublayer concurrent de poids >= le notre ecrase notre block. Parade: CLEAR_ACTION_RIGHT (veto) sur nos blocks + sublayer 0xFFFF.
- **Services SYSTEM / telemetrie**: les filtres ALE en user-mode s'appliquent a TOUT le trafic, y compris SYSTEM (svchost, telemetrie), car le filtrage est fait dans le kernel par BFE - un process SYSTEM ne contourne pas un filtre WFP. Le block-all les couvre.
- **SeDebugPrivilege / SYSTEM**: un process SYSTEM ou disposant de SeDebugPrivilege peut MODIFIER/SUPPRIMER nos filtres WFP (appeler FwpmFilterDeleteById0), injecter dans notre daemon, ou desactiver BFE. C'est la surface reelle: WFP protege contre le trafic non privilegie, pas contre un attaquant deja SYSTEM. La securisation du daemon (DPAPI pour la conf comme WireGuard qui chiffre C:\Program Files\WireGuard\Data, DACL sur les objets WFP, protection du service) est la seule mitigation.

### PARTIE 2 - KILL SWITCH LINUX

#### 2.1 nftables complet + fwmark

Mecanisme wg-quick (source wireguard.com/netns, man wg-quick(8)):
```sh
wg set wg0 fwmark 51820
ip -4 route add 0.0.0.0/0 dev wg0 table 51820
ip -4 rule add not fwmark 51820 table 51820
ip -4 rule add table main suppress_prefixlength 0
# equivalents IPv6 avec ip -6 et ::/0
```
Explication: WireGuard marque tous ses paquets chiffres sortants avec fwmark 51820 (0xca6c). La regle `not fwmark 51820 table 51820` envoie tout paquet NON marque (donc non encore chiffre) dans la table 51820 dont la route par defaut est wg0 -> il repart chiffre. Les paquets deja chiffres (marques) echappent a cette regle et suivent la table main -> sortent sur l'interface physique vers l'endpoint. `suppress_prefixlength 0` sur la table main fait ignorer UNIQUEMENT la route par defaut (/0) de main, tout en gardant les routes LAN specifiques (prefixe > 0) -> acces LAN preserve sans fuite Internet. `Table = off` dans le .conf desactive la gestion auto de la table par wg-quick quand on gere soi-meme le routage.

Fichier nftables kill switch strict (family inet, IPv4+IPv6 unifie, policy drop). Remplacer `WG_MARK`, `WG_IF`, etc:
```
#!/usr/sbin/nft -f
flush ruleset

define WG_MARK   = 0xca6c
define WG_IF     = "wg0"
table inet killswitch {
    chain output {
        type filter hook output priority filter; policy drop;

        # loopback
        oif "lo" accept

        # trafic deja chiffre par WireGuard (marque) -> sort vers l'endpoint
        meta mark $WG_MARK accept

        # trafic a l'interieur du tunnel
        oifname $WG_IF accept

        # DHCPv4 client
        udp sport 68 udp dport 67 accept
        # DHCPv6 client
        ip6 daddr fe80::/10 udp sport 546 udp dport 547 accept

        # NDP / ICMPv6 indispensables
        icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit,
                      nd-neighbor-advert, nd-redirect } accept

        # DNS uniquement vers le resolveur local (voir Partie 3)
        ip daddr 127.0.0.1 udp dport 53 accept
        ip daddr 127.0.0.1 tcp dport 53 accept

        # tout le reste est droppe (policy drop)
    }
    chain input {
        type filter hook input priority filter; policy drop;
        iif "lo" accept
        ct state established,related accept
        iifname $WG_IF accept
        udp dport 68 udp sport 67 accept
        ip6 saddr fe80::/10 udp dport 546 udp sport 547 accept
        icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit,
                      nd-neighbor-advert, nd-redirect } accept
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
        oifname $WG_IF accept
        iifname $WG_IF accept
    }
}
```
Note: on n'autorise PAS ici l'endpoint par IP en clair car le trafic vers l'endpoint est deja couvert par `meta mark $WG_MARK accept` (WireGuard kernel marque ses paquets). Si on n'utilise pas fwmark (cas endpoint via proxy), voir "Cas proxy local" ci-dessous.

Anti-fuite specifiques: mDNS/LLMNR/NetBIOS/SSDP droppes par policy drop (aucun accept). RA/NDP autorises via icmpv6 type. Multicast/broadcast droppes sauf DHCP/NDP cibles. LAN access optionnel: ajouter `ip daddr 192.168.0.0/16 accept` (et 10/8, 172.16/12) sous garde d'une option activable.

Cas proxy local (sing-box en TCP/443, PAS WireGuard direct). Le trafic du process proxy doit sortir en clair vers l'endpoint :443, mais rien d'autre ne doit fuir. On exempte le CGROUP du proxy:
```
# lancer sing-box dans une scope systemd delegue, ex: vpnproxy.service
# puis dans la chain output du killswitch:
socket cgroupv2 level 1 "system.slice/vpnproxy.service" accept
```
IMPORTANT (fraicheur incertaine, a valider sur la cible): `socket cgroupv2` exige kernel >= 5.13 (commit e0bb96db96f8, "netfilter: nft_socket: add support for cgroupsv2"); le matching CORRECT en namespaces/conteneurs n'existe qu'a partir du kernel 6.12 (commit 7f3287db654395f9c5ddd246325ff7889f550286, "netfilter: nft_socket: make cgroupsv2 matching work with namespaces", Florian Westphal, PR netfilter nf-24-09-12 mergee le 12 septembre 2024, signalee par Nadia Pinaeva), backporte dans les stables Linux 6.1.112, 6.6.53, 6.10.12, 6.11.1. Sur Ubuntu 24.04 (kernel 6.8), le matching host fonctionne mais le comportement namespace peut differer. Piege documente (SUSE, Red Hat, Oracle): la regle `socket cgroupv2` matche un ID numerique de cgroup, pas le path; si le service redemarre, l'ID change et la regle ne matche plus - il faut re-appliquer les regles au (re)demarrage du service (outil: systemd `NFTSet=` en systemd 255+, ou mk-fg/systemd-cgroup-nftables-policy-manager). Alternative plus robuste: marquer le trafic du proxy avec `meta mark` via une regle qui matche `socket cgroupv2`, ou lancer le proxy sous un UID dedie et matcher `meta skuid <uid>` (skuid ne marche qu'en output). Ne pas exempter par IP de destination :443 (exploitable par n'importe quel process).

#### 2.2 Network namespaces et cgroup v2

Pattern netns (wireguard.com/netns, adapte). wg-quick ne fonctionne pas ici car il gere lui-meme routage/regles dans le namespace initial. Sequence: creer l'interface dans le namespace initial puis la deplacer (elle garde son socket UDP dans le namespace d'origine, ce qui permet le "magic" de sortie):
```sh
ip netns add vpn
ip link add wg0 type wireguard
wg setconf wg0 /etc/wireguard/wg0.conf
ip link set wg0 netns vpn
ip -n vpn addr add 10.2.0.2/32 dev wg0
ip -n vpn link set wg0 up
ip -n vpn route add default dev wg0
# DNS du namespace:
mkdir -p /etc/netns/vpn && echo "nameserver 127.0.0.1" > /etc/netns/vpn/resolv.conf
ip netns exec vpn <application>
```
Outils: **wg-netns** (github.com/dadevel/wg-netns, Python, profils YAML/JSON, unite `wg-netns@.service`); wg-quick ne s'applique pas. Un process lance dans le namespace ne peut PHYSIQUEMENT pas sortir hors tunnel (pas d'interface physique dans le namespace) -> kill switch structurel, superieur au filtrage.

Integration systemd:
```ini
# netns@.service : cree un namespace nomme
[Unit]
Description=%I network namespace
Before=network.target
[Service]
Type=oneshot
RemainAfterExit=yes
PrivateNetwork=yes
ExecStart=/bin/ip netns add %I
ExecStop=/bin/ip netns del %I
```
```ini
# application confinee au namespace VPN
[Unit]
BindsTo=wg.service
After=wg.service
JoinsNamespaceOf=wg.service
[Service]
PrivateNetwork=yes
NetworkNamespacePath=/run/netns/vpn
ExecStart=/usr/bin/monapp
```
`BindsTo=` garantit l'arret de l'app si le namespace tombe; `JoinsNamespaceOf=`/`NetworkNamespacePath=` place l'app dans le meme namespace; `PrivateNetwork=yes` isole.

Split tunneling par cgroup v2 sur Ubuntu 24.04 (cgroup v2 unifie). **net_cls n'existe pas en cgroup v2** - c'est un controleur v1. Methodes correctes 2026:
1. **nftables `socket cgroupv2`** (kernel >= 5.13): matcher le cgroup du process et poser mark/accept (voir 2.1). C'est ce que fait Mullvad (talpid-core/src/split_tunnel/linux.rs + firewall/linux.rs `add_split_tunneling_rules` qui utilise `nft_expr!(meta cgroup)` + `cmp` sur NET_CLS_CLASSID + `immediate data MARK`).
2. **systemd `NFTSet=`** (systemd 255, publie le 6 decembre 2023): declare un set nftables peuple automatiquement avec le cgroup de l'unite - evite le probleme d'ID qui change. Note de version systemd 255: "A new option NFTSet= provides a method for integrating dynamic cgroup IDs into firewall rules with NFT sets... NFT rules for cgroup matching use numeric cgroup IDs, which change every time a service is restarted, making them hard to use in systemd environment." Limite confirmee (doc systemd-cgroup-nftables-policy-manager): "its use is limited to system units (can't be used in ~/.config/systemd/user session units)."
3. **eBPF cgroup/connect4** ou **cgroup/sock_create**: attacher un programme BPF au cgroup pour marquer/rediriger - plus complexe, mais robuste et dynamique.
4. **systemd `IPAddressAllow=`/`IPAddressDeny=`** (base sur BPF cgroup/skb) et **SocketBindAllow=**: filtrage par IP/bind par unite; utile pour un allowlist grossier, pas pour du routage.

Mullvad utilise l'approche cgroup: un binaire `mullvad-exclude` place le process dans un cgroup d'exclusion (SPLIT_TUNNEL_CGROUP_NAME) puis exec l'application; nftables marque ce cgroup pour bypass le tunnel.

#### 2.3 Gestionnaires de reseau

- **NetworkManager**: peut reecrire routes et DNS. Le forcer a ne pas gerer l'interface wg (`nmcli device set wg0 managed no`) ou utiliser `Table=off` + gestion manuelle. Risque de fuite: NM restaure le DNS du FAI a la reconnexion.
- **systemd-resolved**: piege par defaut = split DNS avec requetes envoyees sur TOUTES les interfaces (multihomed). Forcer tout le DNS dans le tunnel:
```sh
resolvectl dns wg0 127.0.0.1
resolvectl domain wg0 '~.'      # '~.' = route toutes les requetes via ce lien
resolvectl dnsovertls wg0 yes
resolvectl flush-caches
```
`~.` (domaine "route-only" universel) donne priorite au DNS de wg0 sur les DNS link-local pousses par DHCP. Depuis NetworkManager 1.26.6, `~.` n'est configure que pour un VPN "privacy"; verifier avec `resolvectl status`. Desactiver le DNS FAI recu par DHCP: `resolvectl dns <phys_if> ""` ou empecher NM de l'appliquer (`ipv4.ignore-auto-dns yes`).
- **resolv.conf statique vs stub**: pour router tout via resolved, `/etc/resolv.conf` doit etre le symlink `../run/systemd/resolve/stub-resolv.conf` (stub 127.0.0.53). Un `/etc/resolv.conf` statique ou pointant sur `resolv.conf` (au lieu de `stub-resolv.conf`) contourne le stub et fuit. Pour notre resolveur local embarque, on pointe directement `nameserver 127.0.0.1`.

#### 2.4 Cas limites Linux

- **Fuite au boot avant demarrage du service VPN**: poser les regles nftables au plus tot via une unite systemd:
```ini
[Unit]
Description=killswitch (early)
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/killswitch.nft
[Install]
WantedBy=multi-user.target
```
`DefaultDependencies=no` + `Before=network-pre.target` garantit que le drop est en place avant toute config reseau.
- **Suspend/resume, roaming WiFi**: les regles nftables persistent en RAM; au resume, ne rien flusher, seulement reetablir le tunnel. Le fwmark/route reste valide.
- **Contournement de Netfilter (man wg-quick(8))**: le client DHCP utilisant des sockets **PF_PACKET/AF_PACKET** contourne les hooks Netfilter (donc nftables) - c'est pourquoi wg-quick note ce cas. Autres voies contournant (partiellement) Netfilter: **AF_PACKET** (raw L2), **XDP** (avant Netfilter), **raw sockets** (restent en general soumis au hook output). Surface reelle: faible mais reelle - un client DHCP AF_PACKET peut emettre des trames non filtrees par nftables. Mitigation: confiner via network namespace (pas d'interface physique) plutot que par filtrage seul, ou controler quel client DHCP tourne.
- **Conteneurs (Docker/Podman) et VMs**: Docker cree ses propres chaines iptables/nftables et un bridge docker0 pouvant contourner le killswitch si priorite/ordre mal geres. Mitigation: hook `forward` en policy drop (voir fichier ci-dessus, `oifname $WG_IF accept` seulement), et placer nos regles dans une table dediee de priorite superieure. Les VMs (bridge/TAP) sortent via l'interface physique - couvertes par le drop output/forward.
- **IPv6**: desactivation par sysctl (`net.ipv6.conf.all.disable_ipv6=1`) vs blocage nftables. Preferer le blocage nftables (family inet couvre v6): si IPv6 est desactive par sysctl mais qu'une application demande explicitement de l'IPv6, elle echoue proprement (pas de fuite), mais certaines apps se comportent mal. Le blocage nftables laisse la pile v6 active (link-local pour NDP) tout en dropant la sortie -> plus sur.

### PARTIE 3 - ELIMINATION DES FUITES DNS

#### 3.1 Architecture DNS anti-fuite

Comparatif 2026 (a embarquer dans le client):
- **dnscrypt-proxy** (Go, ISC license): proxy DoH/DoT/DNSCrypt, leger, cache integre, gestion bootstrap, anonymized relays. **Recommande pour un client VPN**: un seul binaire, config simple, forwarder pur (pas de recursion). Empreinte memoire faible (ordre de grandeur de quelques dizaines de Mo).
- **Unbound** (C, BSD): resolveur recursif+cache+DNSSEC. Avantage: pas de tiers (recursion depuis les roots), reduit la surface de confiance a votre propre machine. Inconvenient pour un VPN: la recursion revele le pattern de requetes aux TLD/roots; plus lourd a configurer. A l'interieur d'un tunnel, la recursion locale est moins pertinente.
- **stubby** (C): stub DoT minimaliste, moins de fonctionnalites que dnscrypt-proxy.
- **AdGuard Home** (Go): trop lourd (serveur complet avec UI) pour embarquer.
- **systemd-resolved**: pratique (deja present) mais fuit par defaut (split DNS multihomed); utilisable si strictement configure (`~.`, DoT), mais moins controlable qu'un binaire embarque.

Verdict: **dnscrypt-proxy** embarque, ecoutant sur 127.0.0.1:53, avec le kill switch autorisant :53 uniquement vers 127.0.0.1.

DoH vs DoT vs DoQ (2026). A l'INTERIEUR d'un tunnel WireGuard, le DNS est deja chiffre et achemine vers le resolveur du serveur -> le DNS chiffre est **redondant du point de vue confidentialite sur le reseau local**. MAIS il reste utile: (1) contre un resolveur intermediaire non fiable cote sortie; (2) pour forcer un resolveur specifique et empecher le detournement; (3) surtout, pour uniformiser le comportement quel que soit le mode (WireGuard direct vs proxy sing-box). Choix: **DoT** (port 853, simple a filtrer) ou **DoH** (443, indistinguable du trafic web, meilleur contre le blocage). DoQ (QUIC/UDP) coherent avec Hysteria2. Pour un client generaliste: DoH via dnscrypt-proxy.

Config dnscrypt-proxy commentee (dnscrypt-proxy.toml, extraits clefs):
```toml
listen_addresses = ['127.0.0.1:53']
max_clients = 250
# resolveurs DoH/DNSCrypt, DNSSEC obligatoire, pas de log, pas de filtre
require_dnssec = true
require_nolog = true
require_nofilter = true
# bootstrap: resoudre le serveur DoH lui-meme via ces IP (pas via le DNS systeme)
bootstrap_resolvers = ['9.9.9.9:53', '1.1.1.1:53']
ignore_system_dns = true
# cache pour eviter les requetes repetees (pas d'empoisonnement: DNSSEC valide)
cache = true
cache_min_ttl = 2400
cache_max_ttl = 86400
[sources.'public-resolvers']
urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md']
```
Le bootstrap resout le hostname du serveur DoH une seule fois via `bootstrap_resolvers` (IP en dur), evitant la dependance circulaire; ces IP doivent etre autorisees par le kill switch le temps du bootstrap ou routees dans le tunnel.

Windows: DoH natif et Dnscache. Windows 11 resout le DNS via le service `Dnscache`. Pour forcer TOUT le DNS a passer par le resolveur local: configurer les serveurs DNS de l'interface tun sur 127.0.0.1 et bloquer :53 sortant sauf vers 127.0.0.1 en WFP (blockDNS). Le probleme: **les navigateurs a DoH embarque (Chrome, Firefox, Edge) ignorent l'OS**. Ils font leur propre DoH en TCP/443 vers un resolveur public, indistinguable du trafic web -> le filtre :53 ne les arrete pas. Solutions:
1. Desactiver le DoH navigateur par **policy registre** (HKLM, verrouille):
```
Chrome:  HKLM\SOFTWARE\Policies\Google\Chrome\DnsOverHttpsMode = "off"
Edge:    HKLM\SOFTWARE\Policies\Microsoft\Edge\DnsOverHttpsMode = "off"
Firefox: HKLM\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS\Enabled = 0 (DWORD)
```
2. Desactiver le DoH natif de Windows si on veut tout centraliser sur le resolveur local.
3. Pour les applications a resolveur DoH embarque non gouvernable par policy: les detecter/bloquer au niveau WFP/nftables en bloquant les IP connues des resolveurs DoH publics (Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9 9.9.9.9...) en TCP/443 - mais c'est un jeu du chat et de la souris (canary domains, listes). Le blocage complet des resolveurs DoH tiers est imparfait; la seule garantie forte est la policy d'entreprise + routage de tout le trafic dans le tunnel.

#### 3.2 Autres vecteurs de fuite

- **WebRTC**: neutraliser au niveau navigateur par policy. Firefox: `media.peerconnection.ice.default_address_only = true` (ou `media.peerconnection.enabled = false`). Chrome/Edge: policy `WebRtcIPHandling` = `disable_non_proxied_udp`. Au niveau OS: le kill switch empeche de toute facon la sortie hors tunnel, donc une IP locale revelee par WebRTC reste une IP de tunnel.
- **IPv6**: recap - bloquer/router au niveau WFP (blockAll V6) et nftables (family inet); desactiver Teredo/6to4/ISATAP (voir ci-dessous).
- **mDNS/LLMNR/NetBIOS/SSDP/WPAD/Teredo/6to4/ISATAP** - desactivation:
  - Windows: `netsh interface teredo set state disabled`, `netsh interface 6to4 set state disabled`, `netsh interface isatap set state disabled`. LLMNR: policy `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast = 0`. NetBIOS: desactiver sur l'interface. WPAD: `WinHttpAutoProxySvc` desactive.
  - Linux: pas de Teredo/6to4/ISATAP par defaut; mDNS via avahi (`systemctl disable avahi-daemon`); LLMNR via resolved (`LLMNR=no` dans resolved.conf); tous droppes par le kill switch nftables de toute facon.
- **NTP / sondes de connectivite**:
  - **NCSI (Windows)**: sonde `www.msftconnecttest.com` (HTTP) + DNS `dns.msftncsi.com`. Depuis Windows 11, NCSI est heberge dans le service Network List Manager (netprofm). Les serveurs de sonde publics sont heberges par Akamai depuis le 20 juin 2023. Bloquer NCSI casse la detection de captive portal. Recommandation: laisser NCSI sondre A TRAVERS le tunnel (il sortira via wg -> pas de fuite), ou le desactiver par policy `Computer Configuration\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off Windows Network Connectivity Status Indicator active tests` si la detection de portail n'est pas voulue. Ne pas bloquer si on veut le portail.
  - **connectivity-check (Ubuntu/NetworkManager)**: `http://connectivity-check.ubuntu.com` / NetworkManager `connectivity` check. Idem: laisser passer dans le tunnel ou desactiver (`[connectivity] enabled=false` dans NetworkManager.conf).
- **Hostname dans DHCP/mDNS**: le client DHCP envoie souvent le hostname (option 12), et mDNS annonce `hostname.local`. Fuite d'identite. Mitigation: desactiver l'envoi du hostname DHCP (`dhcp-send-hostname=false` dans NetworkManager, ou config dhclient `send host-name ""`), desactiver mDNS/avahi.

### PARTIE 4 - SUITE DE TESTS DE FUITES EN CI

Objectif: assertion "zero paquet non chiffre vers une destination hors endpoint VPN" sur l'interface physique, plus verification IP de sortie/DNS/IPv6/WebRTC et comportement du kill switch sous defaillance.

Architecture de test (Linux, reproductible en CI via namespaces imbriques):
```sh
# namespace "physique" simule un LAN + une passerelle
ip netns add phys
# namespace "client" contient le kill switch + le tunnel
ip netns add client
# veth entre les deux
ip link add veth-c type veth peer name veth-p
ip link set veth-c netns client
ip link set veth-p netns phys
```
Capture pcap sur l'interface physique (cote phys/passerelle) et assertion. Exemple d'assertion (Python/scapy) - aucun paquet en clair vers une destination autre que l'endpoint:
```python
from scapy.all import rdpcap, IP, UDP
ENDPOINT_IP = "203.0.113.7"
WG_PORT = 51820
pkts = rdpcap("phys.pcap")
leaks = []
for p in pkts:
    if IP in p:
        dst = p[IP].dst
        # autorise: WireGuard chiffre vers l'endpoint, DHCP, multicast link-local
        if dst == ENDPOINT_IP:
            continue
        if dst.startswith(("224.", "239.", "255.255.255.255")):
            continue
        leaks.append((dst, p.summary()))
assert not leaks, f"FUITE detectee: {leaks[:10]}"
```
Equivalent tshark en one-liner (pour CI):
```sh
tshark -r phys.pcap -Y "ip.dst != 203.0.113.7 && !(udp.port==67||udp.port==68) && ip.dst < 224.0.0.0" -T fields -e ip.dst | sort -u
# la sortie DOIT etre vide
```
Un equivalent gopacket (Go) peut etre integre directement au produit pour un test embarque.

Simulation des defaillances (kill switch doit tenir):
```sh
# 1. tunnel tombe brutalement
ip netns exec client kill -9 $(pgrep -n wireguard-go)   # ou sing-box
ip netns exec client ip link del wg0
# 2. coupure reseau
ip netns exec phys ip link set veth-p down
# 3. perte/latence pour simuler DPI/instabilite (tc/netem)
ip netns exec client tc qdisc add dev veth-c root netem loss 100%
# 4. DPI qui coupe: dropper les paquets WireGuard
ip netns exec phys nft add rule inet t c udp dport 51820 drop
```
Apres chaque injection, relancer la capture + assertion "zero paquet en clair". Tester aussi la fenetre de reconnexion (le block-all doit rester actif pendant que le handshake se refait), le boot (poser le killswitch AVANT le tunnel et verifier qu'aucun paquet ne sort avant handshake) et le resume (suspend puis reprise).

Outils/API de reference:
- **Mullvad connection check**: API `https://am.i.mullvad.net/json` (renvoie IP, pays, `mullvad_exit_ip: true/false`, blacklist). Page interactive `mullvad.net/check` (l'ancienne `am.i.mullvad.net` sert toujours l'API JSON). Utilisable en CI pour verifier l'IP de sortie et l'absence de fuite. Exemple: `curl -s https://am.i.mullvad.net/json | jq .mullvad_exit_ip`.
- **Mullvad** publie ses tests dans mullvadvpn-app (Rust integration tests avec test-manager) - a etudier pour la structure.
- **IVPN**, projets open source de leak testing; sites de reference: browserleaks.com, dnsleaktest.com (test etendu via sous-domaines aleatoires), ipleak.net (API JSON), Mullvad check.
- **mullpy** (github.com/franccesco/mullpy, MIT): CLI Python exemple qui interroge l'API Mullvad + test DNS leak.

Tests Windows en CI. GitHub Actions `windows-latest` NE PERMET PAS de charger un driver kernel ni de manipuler WFP de facon fiable (pas toujours admin/interactif, pas de vraie interface reseau manipulable). Limites et contournements: (1) tests unitaires de la logique de construction de filtres (comme `types_windows_test.go` de WireGuard) executables sur windows-latest; (2) tests d'integration WFP reels sur une **VM dediee auto-hebergee** (self-hosted runner) avec droits admin et une interface reseau virtuelle (Hyper-V); (3) verifier l'application effective des filtres via `netsh wfp show filters` et parser le XML. La capture pcap se fait avec Npcap/tshark sur la VM.

### PARTIE 5 - SYNTHESE ET PLAN

#### Architecture logicielle recommandee

Interface commune (trait/interface) abstraisant les deux OS:
```
trait KillSwitch {
    fn enable(&mut self, endpoints: &[Endpoint], dns: &[IpAddr], allow_lan: bool) -> Result;
    fn allow_endpoint(&mut self, ep: Endpoint) -> Result;   // proxy sing-box
    fn set_tunnel_interface(&mut self, luid_or_ifname: IfId) -> Result;
    fn disable(&mut self) -> Result;
    fn is_engaged(&self) -> bool;
}
```
- **Windows**: **Rust avec le crate `windows-rs`** recommande (memoire sure, ecosysteme moderne, crates WFP existants `wfp`/`windows-wfp` comme base), OU Go avec `golang.zx2c4.com/wireguard/windows/tunnel/firewall` (reutilisable tel quel, MIT, deja teste en production). Choisir Go si on reutilise le code WireGuard quasi tel quel; Rust si on veut un socle unifie avec le reste. Eviter le C++ direct sauf pour reutiliser libwfp/winfw de Mullvad.
- **Linux**: **Rust** avec les crates `nftnl`/`mnl` (comme talpid-core) ou `rustables`, generation des regles nftables + gestion fwmark/ip rule (crate `rtnetlink`), gestion netns.
- Abstraction: un crate `killswitch` avec `#[cfg(windows)]` / `#[cfg(unix)]`, exposant le trait ci-dessus. Recommandation forte: **Rust unifie** pour partager le trait, la machine a etats (deconnecte/connexion/connecte/bloque) et les tests, en s'inspirant directement de la machine a etats de talpid-core (tunnel_state_machine).

#### Decoupage en modules
1. `wfp` (Windows): wrapper WFP (provider/sublayer/filter/transaction). Responsabilite: poser/retirer les filtres.
2. `nft` (Linux): generation/application des regles nftables + fwmark + ip rule.
3. `dns`: gestion du resolveur local (dnscrypt-proxy embarque), config resolved/registre, blocage :53.
4. `netns` (Linux, optionnel): mode namespace pour confinement structurel.
5. `split-tunnel`: par process (ALE_APP_ID / cgroup v2), phase ulterieure.
6. `state-machine`: orchestration des transitions, garantit qu'aucune transition ne cree de fenetre.
7. `leaktest`: suite CI (scapy/gopacket + API Mullvad-like).

#### Ordre d'implementation et criteres de validation
1. Windows WFP block-all + permit tunnel/loopback/DHCP/NDP (portage direct de blocker.go/rules.go). Critere: `netsh wfp show filters` montre les filtres; zero paquet en clair quand tunnel down.
2. Linux nftables inet + fwmark. Critere: assertion pcap "zero fuite" apres `ip link del wg0`.
3. DNS: dnscrypt-proxy + blockDNS/nftables :53. Critere: dnsleaktest ne montre que le resolveur attendu; DoH navigateur desactive par policy.
4. Machine a etats + transactions. Critere: aucune fuite pendant reconnexion (test netem loss 100%).
5. Boot/resume. Critere: unite systemd early + filtres PERSISTENT; capture au boot vide avant handshake.
6. Proxy sing-box (exemption cgroup v2/UID). Critere: seul le process proxy sort en :443, verifie par pcap.
7. Split tunneling par process (phase ulterieure). Critere: process exclu sort hors tunnel, tous les autres dans le tunnel.
8. Suite CI complete sur namespaces + VM Windows self-hosted.

#### Estimation d'effort (jours-homme), justifiee par la taille du code equivalent
- **Windows WFP core**: le module de reference (WireGuard tunnel/firewall/) fait ~83 KB de Go sur 10 fichiers, dont rules.go ~33 KB (~900-1000 lignes) qui contient tous les constructeurs de filtres, plus blocker.go ~188 lignes et helpers.go ~3,5 KB. Portage/adaptation + tests: **10-15 j-h** (le gros du travail est la reproduction fidele des conditions DHCP/NDP et la gestion des transactions/erreurs, deja resolue par WireGuard donc largement reutilisable).
- **Linux nftables + fwmark + netns**: talpid-core/src/firewall/linux.rs est un module de l'ordre de plusieurs centaines a ~1000 lignes (contient toute la construction des chaines/regles + split tunneling; deja ~400 lignes en 2019 selon la PR #1797, largement grossi depuis). Avec la generation nftables et la gestion ip rule/netns: **8-12 j-h**.
- **DNS anti-fuite (les deux OS)**: integration dnscrypt-proxy + policies registre + resolved + blocage :53: **6-10 j-h**.
- **Machine a etats + abstraction commune**: inspiree de talpid-core tunnel_state_machine (module consequent): **8-12 j-h**.
- **Split tunneling par process (cgroup v2 + ALE_APP_ID)**: complexite elevee (Mullvad y consacre plusieurs modules split_tunnel/{linux,windows}, dont un driver Windows): user-mode par process **5-8 j-h**; version driver kernel Windows **+20-40 j-h** (dev + signature + tests HLK-like), a reporter a une phase ulterieure.
- **Suite de tests CI**: namespaces + scapy/gopacket + VM Windows self-hosted: **8-12 j-h**.
Total socle (sans driver kernel): **~45-70 j-h**. Ces chiffres sont ancres sur la taille reelle des modules equivalents cites; ils excluent l'UI et le packaging.

#### Reutilisable / a forker / a ecrire
- **Reutilisable tel quel**: WireGuard tunnel/firewall/ (Go, MIT) pour le kill switch Windows; wg-quick fwmark/suppress_prefixlength (Linux); dnscrypt-proxy embarque (ISC); crates `windows-rs`, `nftnl`; wg-netns (Python) comme reference netns.
- **A forker/adapter**: mullvad/libwfp (C++, GPLv3) si on reste en C++; simplewall (GPLv3) pour la logique CLEAR_ACTION_RIGHT (etude, pas fork). Attention licences GPLv3: le lien avec du code GPLv3 impose la GPL sur l'ensemble - preferer MIT (WireGuard) et l'implementation propre pour le client MPL-2.0.
- **A ecrire de zero**: la machine a etats unifiee, l'abstraction cross-OS, la suite de tests de fuite, l'integration DoH navigateur, la gestion proxy sing-box (exemption cgroup).

#### Pieges connus (issues GitHub des projets)
- WFP: un hard permit sur un sublayer concurrent de poids 0xFFFF/0xFFFE ecrase un block sans CLEAR_ACTION_RIGHT (simplewall #689, Windscribe #44). TOUJOURS poser le veto.
- Mullvad Windows: "Initiate WFP transaction: The call timed out while waiting to acquire the transaction lock" quand un AV/pare-feu tiers bloque WFP - gerer le timeout et le retry.
- Mullvad Linux: "Expected 'mullvad' netfilter table to be set, but it is not" / "kernel might be terribly out of date or missing nftables" (#8620) - verifier la presence de nftables et du support kernel.
- nftables cgroupv2: la regle matche un ID numerique, pas le path; l'ID change au redemarrage du service (Red Hat, Oracle, libcgroup #432) - re-appliquer au (re)demarrage.
- WireGuard netquirk: le kill switch WFP n'est active que si un peer a AllowedIPs /0; sinon utiliser 0.0.0.0/1+128.0.0.0/1 (et ::/1+8000::/1) pour eviter la semantique kill-switch.
- Chemin ALE_APP_ID: il faut le chemin NT (`\device\harddiskvolume...`), pas DOS, sinon le filtre ne matche jamais (crate windows-wfp le documente explicitement).

## Recommendations
1. **Immediat**: porter le kill switch Windows depuis WireGuard tunnel/firewall/ (MIT) en user-mode WFP avec sublayer 0xFFFF, filtres permit 12-15, block-all 0, ET flag CLEAR_ACTION_RIGHT sur les blocks. Critere de passage: `netsh wfp show filters` + assertion pcap zero fuite tunnel down.
2. **Immediat**: Linux nftables family inet policy drop + fwmark/suppress_prefixlength; unite systemd early-boot (DefaultDependencies=no, Before=network-pre.target).
3. **Ensuite**: embarquer dnscrypt-proxy sur 127.0.0.1:53, bloquer :53 sortant sauf vers lui, desactiver DoH navigateur par policy registre.
4. **Proxy sing-box**: exempter par `socket cgroupv2` OU UID dedie (pas par IP). Valider le kernel cible pour le comportement namespace (>= 6.12 pour correction complete).
5. **Phase ulterieure**: split tunneling par process user-mode d'abord (ALE_APP_ID / cgroup v2); driver kernel + signature EV/Partner Center seulement si le split par paquet est requis.
6. **CI**: suite de tests namespaces + assertion pcap + API am.i.mullvad.net/json; VM Windows self-hosted pour les tests WFP reels.

Seuils qui changent ces recommandations: si le produit doit distribuer via Windows Update -> WHCP/HLK requis (change le budget signature); si la cible Linux est un kernel < 6.12 -> preferer le confinement netns au split cgroup pour le proxy; si les clients exigent le split tunneling par paquet -> driver kernel obligatoire (+20-40 j-h + EV cert).

## Caveats
- **Fraicheur cgroup v2 / Ubuntu 24.04 (signale explicitement)**: `socket cgroupv2` fonctionne en host des kernel 5.13, mais le matching CORRECT en namespaces n'est fiable qu'a partir de 6.12 (commit 7f3287db6543, PR mergee le 12 sept. 2024, backporte 6.1.112/6.6.53/6.10.12/6.11.1). Ubuntu 24.04 tourne sur kernel 6.8 par defaut - tester le comportement namespace sur la version exacte deployee. La regle matche un ID numerique de cgroup qui change au redemarrage du service: re-appliquer (ou utiliser systemd NFTSet= sur unites systeme).
- **Signature driver Windows 2026 (signale explicitement)**: les prix des certificats EV (~419-625 USD/an DigiCert selon canal) sont issus de revendeurs et doivent etre reverifies aupres des CA; noter la limite CA/B Forum du 15 fev. 2026 (validite max 1 an, plus de multi-annuel). L'exigence EV pour Partner Center et l'incapacite de Trusted Signing (Azure Artifact Signing, 9,99 USD/mois Basic / 99,99 USD/mois Premium) a couvrir la registration Hardware Program sont confirmees par Microsoft Learn/Q&A. Verifier l'etat du programme au moment du dev.
- Le helper `filterWeight` de WireGuard produit un FWP_VALUE0 de type **FWP_UINT8** (poids 0-15), pas FWP_UINT64; la plage 0-15 suffit pour ce kill switch. Pour des priorites fines entre nombreux filtres, utiliser FWP_UINT64.
- Les tailles de fichiers WireGuard sont des comptes d'octets (cgit), les lignes sont estimees (~30-40 octets/ligne). Les tailles exactes des modules Mullvad (linux.rs, winfw/) n'ont pas pu etre verifiees en ligne dans cette session (paths et architecture confirmes) - les estimations d'effort en tiennent compte avec une marge.
- Les licences GPLv3 (Mullvad, simplewall) sont incompatibles avec le client MPL-2.0 par simple lien; privilegier le code MIT (WireGuard) et une implementation propre.
- WebRTC/DoH navigateur: le blocage complet des resolveurs DoH tiers embarques est imparfait (chat et souris); la seule garantie forte reste la policy d'entreprise + routage integral dans le tunnel.
- **NCSI/connectivity-check**: laisser ces sondes sortir dans le tunnel (pas de fuite) plutot que les bloquer, sinon la detection de captive portal casse. Elles ne constituent une fuite que si elles sortent hors tunnel - ce que le kill switch empeche deja.
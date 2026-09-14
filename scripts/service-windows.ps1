<#
.SYNOPSIS
Cycle connect/disconnect COMPLET par le service Windows reellement installe.
COUPE LE RESEAU DE LA MACHINE.

.DESCRIPTION
Le pendant de scripts/service-systemd-linux.sh, et il pose les memes questions:
le service que l'empaquetage installe SERT-il, le vrai resolveur chiffre
demarre-t-il avec le tunnel, la machine resout-elle par lui, rien ne sort-il en
clair sur le :53, et le resolveur s'arrete-t-il avec le tunnel.

`packaging-windows.ps1` etablissait que l'installation POSE ce qu'il faut: les
binaires, les droits, la ligne du service. Il ne pouvait rien dire de ce qui se
passe quand on demarre ce service, et c'etait ecrit noir sur blanc dans le
depot. Ce banc-ci comble exactement ce trou.

# Ce qu'il faut en face, et pourquoi

Un vrai pair WireGuard avec un VRAI acces a Internet, monte par
`scripts/service-windows-pair.sh` sur essai-linux. Sans Internet au bout du
tunnel, dnscrypt-proxy ne demarre pas: le banc ne mesurerait alors plus rien du
resolveur, c'est-a-dire plus rien de ce qu'il est venu mesurer.

# Pourquoi il ne se lance pas depuis une session distante

Le profil porte une route par defaut et `allow_lan = false`. Armer le kill
switch coupe donc tout trafic hors tunnel, la session de pilotage comprise, et
un processus lance en enfant d'une session SSH meurt AVEC elle: le demontage
n'aurait jamais lieu et les filtres resteraient poses. Ce banc se lance en
TACHE PLANIFIEE SYSTEM detachee, et on lit son journal apres coup.

# Les deux filets, et pourquoi deux

Une tache planifiee `--cleanup-firewall` armee AVANT, a echeance de quelques
minutes: si ce script meurt entre l'armement et le demontage, la machine se
desarme seule. Et un redemarrage programme derriere, annule a la sortie: les
filtres WFP ne sont pas persistants, donc un redemarrage rend toujours la
machine, meme si la tache de nettoyage echouait elle aussi.

Le filet est VERIFIE et pas seulement cree, et deux mesures du 22/08/2026 ont
montre pourquoi. `schtasks /sc once /st HH:MM` sans `/sd` planifie pour
AUJOURD'HUI: passe l'heure, la tache est creee avec un simple avertissement et
n'a plus de prochaine execution - un filet qui n'existait que de nom. Donner
`/sd` ne suffit pas non plus: `22.08.2026` passe depuis la session SSH
interactive et se fait refuser sous SYSTEM avec "Date should be in mm/dd/yyyy
format". Deux comptes, deux formats acceptes, sur la meme machine.

La tache est donc posee par le module ScheduledTasks, qui prend un DateTime au
lieu d'une chaine, avec le compte designe par son SID `S-1-5-18` - sur une
machine allemande, SYSTEM s'appelle NT-AUTORITAT\SYSTEM. Et `NextRunTime` est
relu par `Get-ScheduledTaskInfo`, qui rend lui aussi un DateTime, la sortie de
`schtasks /query` etant traduite. Le banc refuse de continuer si cette date est
vide ou deja passee: sans filet, une mort du banc laisserait la machine coupee.

# Usage

  powershell -ExecutionPolicy Bypass -File service-windows.ps1 -Profil <TOML>

Le profil vient du pair et porte une cle privee: il n'est PAS versionne.
#>

param(
    # La racine du banc: le repertoire du script (via -File), ou BIFROST_BANC si pose.
    [string]$Banc = $(if ($env:BIFROST_BANC) { $env:BIFROST_BANC } else { $PSScriptRoot }),
    [string]$Racine = (Join-Path $Banc 'empaquetage'),
    [string]$Profil = (Join-Path $Banc 'service\profil-client.toml'),
    [string]$Resolveur = (Join-Path $Banc 'dnscrypt\win64\dnscrypt-proxy.exe'),
    # wireguard.dll, que le depot ne distribue pas. Sans elle aucun tunnel ne
    # monte: le banc rend SKIPPED avec sa raison plutot que d'accuser le
    # produit d'un echec de connexion.
    [string]$Pilote = (Join-Path $Banc 'wireguard.dll'),
    [string]$Journal = (Join-Path $Banc 'service-windows.log'),
    # L'adresse du pair, joignable par le SEUL tunnel. Verifiee muette avant le
    # montage: sans ce controle, ce qu'elle repond ensuite ne dirait rien du
    # chemin emprunte.
    [string]$BanniereHote = "10.98.0.1",
    [int]$BannierePort = 7100,
    [string]$BanniereAttendue = "BIFROST-SERVICE-OK",
    # Un nom que le resolveur chiffre devra resoudre. Public, stable, et jamais
    # une machine de la maison.
    [string]$NomReel = "example.com",
    [int]$FiletMinutes = 12,
    # Les deux fichiers du filet: le .cmd de nettoyage arme en tache planifiee
    # et le .log ou il ecrit. Mis en parametre par l'arbitrage 8 (option A) et
    # derives de $Banc par l'option B (arbitrage 8B, 06/09/2026): un editeur qui
    # installe le service ailleurs que sur le banc les veut ailleurs, et la
    # valeur par defaut suit la racine du banc, donc le comportement par defaut
    # ne change pas.
    [string]$FiletCmd = (Join-Path $Banc 'service-filet.cmd'),
    [string]$FiletLog = (Join-Path $Banc 'service-filet.log'),
    # Garder l'installation en place a la sortie. Par defaut le service est
    # retire: enregistre en demarrage AUTOMATIQUE, il repartirait au prochain
    # redemarrage d'une machine d'essai sans que personne l'ait demande.
    [switch]$Garder
)

# La racine du banc doit etre connue. Lance autrement que par -File et sans
# BIFROST_BANC, $Banc est vide et les chemins derives seraient faux.
if ([string]::IsNullOrEmpty($Banc)) {
    throw "Banc introuvable: lancer ce script par -File depuis la racine du banc (le repertoire qui contient les binaires), ou poser BIFROST_BANC sur ce repertoire."
}

$ErrorActionPreference = "Continue"

$Installation = Join-Path $env:ProgramFiles "Bifrost"
$Daemon = Join-Path $Installation "bifrost-daemon.exe"
$Cli = Join-Path $Installation "bifrost-cli.exe"
$Installateur = Join-Path $Racine "packaging\install-windows.ps1"
$Binaires = Join-Path $Racine "target\release"
$NomService = "BifrostDaemon"
$CleService = "HKLM:\SYSTEM\CurrentControlSet\Services\$NomService"
$TacheFilet = "bifrost-service-filet"

# Le banc tient son PROPRE journal. Lance en tache planifiee il n'a pas de
# console ou se plaindre, et une redirection mal ecrite emporte alors la seule
# trace de ce qui s'est passe.
try { Start-Transcript -Path $Journal -Force | Out-Null } catch {}

function Dire($texte) { Write-Host $texte }
function Saute($raison) { Dire "SKIPPED: $raison"; exit 0 }

# Verdict differe: un echec ne doit pas sauter le demontage, sans quoi le banc
# laisserait la machine coupee pour la raison meme qu'il devait mesurer.
$script:Griefs = @()
function Ok($m) { Dire "   ok    $m" }
function Grief($m) { Dire "   ECHEC $m"; $script:Griefs += $m }

# Un GET en socket brute. `Invoke-WebRequest` passerait par les reglages de
# proxy de la machine, ce qui ferait de ce banc une mesure du proxy plutot que
# du tunnel.
function Lire-Banniere($hote, $port, $delaiMs) {
    $client = New-Object Net.Sockets.TcpClient
    try {
        if (-not $client.ConnectAsync($hote, $port).Wait($delaiMs)) { return "" }
        $flux = $client.GetStream()
        $flux.ReadTimeout = $delaiMs
        $requete = [Text.Encoding]::ASCII.GetBytes("GET /index.txt HTTP/1.0`r`nHost: $hote`r`n`r`n")
        $flux.Write($requete, 0, $requete.Length)
        $tout = (New-Object IO.StreamReader($flux)).ReadToEnd()
        $corps = $tout -split "`r`n`r`n", 2
        if ($corps.Count -lt 2) { return "" }
        return $corps[1].Trim()
    } catch {
        return ""
    } finally { $client.Dispose() }
}

function Filtres-Bifrost {
    (netsh wfp show filters file=- | Select-String -SimpleMatch "bifrost").Count
}

function Service-Pid {
    $s = Get-CimInstance Win32_Service -Filter "Name='$NomService'" -ErrorAction SilentlyContinue
    if ($s) { return [int]$s.ProcessId }
    return 0
}

function Processus-Resolveur {
    Get-CimInstance Win32_Process -Filter "Name='dnscrypt-proxy.exe'" -ErrorAction SilentlyContinue
}

# L'empreinte DNS de la MACHINE, tunnel exclu. Relevee avant, relue PENDANT la
# connexion: une restauration fidele rendrait le controle muet s'il n'etait fait
# qu'a la fin.
function Empreinte-Dns {
    $lignes = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceAlias -ne "bifrost-svc" -and $_.ServerAddresses } |
        ForEach-Object { "$($_.InterfaceAlias)=$($_.ServerAddresses -join ',')" }
    return (($lignes | Sort-Object) -join " | ")
}

function Demonter {
    Dire ""
    Dire "== 12. demontage"
    & $Cli disconnect 2>&1 | Out-Null
    # Sans condition et sans se fier au disconnect: c'est la commande qui rend
    # la machine, et elle doit passer meme si tout le reste a echoue.
    & $Daemon --cleanup-firewall 2>&1 | Out-Null
    $restants = Filtres-Bifrost
    if ($restants -gt 0) { Dire "   ATTENTION: $restants filtre(s) subsistent" }
    else { Dire "   filtres=0" }
    if (-not $Garder) {
        Stop-Service $NomService -Force -ErrorAction SilentlyContinue
        & $Daemon --uninstall-service 2>&1 | Out-Null
        Dire "   service retire (les binaires restent dans $Installation)"
    } else {
        Dire "   installation gardee (-Garder)"
    }
    Unregister-ScheduledTask -TaskName $TacheFilet -Confirm:$false -ErrorAction SilentlyContinue
    shutdown /a 2>&1 | Out-Null
    Dire "   filet et redemarrage de secours annules"
}

# --- 0. premisses -----------------------------------------------------------

Dire "== 0. premisses"
$identite = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identite)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Saute "installer un service et poser des filtres WFP demande l'elevation, ce processus ne l'a pas"
}
Dire "   compte: $($identite.Name), eleve"

foreach ($f in $Installateur, $Profil, $Resolveur, $Pilote,
               (Join-Path $Binaires "bifrost-daemon.exe"),
               (Join-Path $Binaires "bifrost-cli.exe")) {
    if (-not (Test-Path -LiteralPath $f)) { Saute "$f absent" }
}
Dire "   installateur, binaires, pilote, resolveur et profil en place"

if (Get-Service -Name $NomService -ErrorAction SilentlyContinue) {
    Saute "un service $NomService existe deja: ce banc en installe un et le retire, il ne doit jamais defaire une installation reelle"
}
if ((Filtres-Bifrost) -gt 0) {
    Saute "des filtres WFP de Bifrost sont deja poses. Rendre la machine d'abord: bifrost-daemon --cleanup-firewall"
}
if (Processus-Resolveur) {
    Saute "un dnscrypt-proxy traine d'un passage precedent"
}
Dire "   ni service, ni filtre, ni resolveur residuels"

# La banniere doit etre HORS D'ATTEINTE avant le montage. Le pair est sur le
# meme lien, mais 10.98.0.1 est son adresse DE TUNNEL: aucune route ne mene la
# depuis ici tant que le tunnel n'est pas monte.
if (Lire-Banniere $BanniereHote $BannierePort 3000) {
    Dire "FAILED: ${BanniereHote}:${BannierePort} repond sans tunnel, la recette ne prouverait rien"
    exit 1
}
Dire "   temoin: la banniere est injoignable en direct"

$DnsAvant = Empreinte-Dns
Dire "   DNS de la machine avant: $DnsAvant"

# --- 1. les deux filets -----------------------------------------------------

Dire ""
Dire "== 1. filets, armes AVANT tout le reste"
$echeance = (Get-Date).AddMinutes($FiletMinutes)
$cmdFilet = $FiletCmd
Set-Content -Path $cmdFilet -Encoding ascii -Value @(
    "@echo off",
    "`"$Daemon`" --cleanup-firewall >> `"$FiletLog`" 2>&1"
)
# Par le module ScheduledTasks et non par `schtasks`, qui ne prend la date que
# sous forme de CHAINE et dans le format de l'appelant. Mesure du 22/08/2026:
# `/sd 22.08.2026` passe depuis la session SSH interactive et se fait refuser
# sous SYSTEM avec "Date should be in mm/dd/yyyy format" - deux comptes, deux
# formats, sur la meme machine. `New-ScheduledTaskTrigger` prend un DateTime,
# donc la question ne se pose plus. Le compte est donne par son SID pour la
# meme raison: sur une machine allemande, SYSTEM s'appelle NT-AUTORITAT\SYSTEM.
$action = New-ScheduledTaskAction -Execute $cmdFilet
$declencheur = New-ScheduledTaskTrigger -Once -At $echeance
$compteTache = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $TacheFilet -Action $action -Trigger $declencheur `
    -Principal $compteTache -Force -ErrorAction SilentlyContinue | Out-Null
$prochaine = (Get-ScheduledTaskInfo -TaskName $TacheFilet -ErrorAction SilentlyContinue).NextRunTime
if (-not $prochaine -or $prochaine -le (Get-Date)) {
    Dire "FAILED: le filet $TacheFilet n'a pas de prochaine execution ($prochaine). Sans lui, une mort du banc laisserait la machine coupee."
    Unregister-ScheduledTask -TaskName $TacheFilet -Confirm:$false -ErrorAction SilentlyContinue
    exit 1
}
Dire "   filet ${TacheFilet}: desarmera la machine a $prochaine"
shutdown /r /t 900 | Out-Null
Dire "   redemarrage de secours dans 900 s, annule a la sortie"

# --- 2. installation --------------------------------------------------------

Dire ""
Dire "== 2. installation par packaging/install-windows.ps1"
& powershell -NoProfile -ExecutionPolicy Bypass -File $Installateur `
    -Binaires $Binaires -Resolveur $Resolveur -Pilote $Pilote 2>&1 |
    ForEach-Object { Dire "   | $_" }
if ($LASTEXITCODE -ne 0) {
    Dire "FAILED: l'installateur a rendu $LASTEXITCODE"
    Unregister-ScheduledTask -TaskName $TacheFilet -Confirm:$false -ErrorAction SilentlyContinue
    shutdown /a | Out-Null
    exit 1
}

# Dans le REGISTRE et non par `sc qc`, dont la sortie est traduite. C'est la
# ligne que le gestionnaire de services lancera vraiment.
$ligne = (Get-ItemProperty -Path $CleService -Name ImagePath).ImagePath
Dire "   ImagePath: $ligne"
$ResolveurInstalle = Join-Path $Installation "dnscrypt-proxy.exe"
if ($ligne -like "*--resolveur-binaire*" -and $ligne -like "*$ResolveurInstalle*") {
    Ok "la ligne du service NOMME le resolveur chiffre"
} else {
    Grief "la ligne du service ne nomme pas le resolveur: il ne pourra pas en lancer un"
}
# 11b-2: la ligne porte aussi le compte de service sous lequel le daemon lance
# le resolveur. Sans lui, l'enfant tournerait sous le compte du service.
if ($ligne -like "*--resolveur-utilisateur*") {
    Ok "la ligne du service NOMME le compte du resolveur"
} else {
    Grief "la ligne du service ne nomme aucun compte pour le resolveur: il tournerait sous celui du service"
}
# Le pilote, lui, n'est nomme nulle part: il est resolu par le repertoire du
# binaire qui tourne. C'est donc sa PRESENCE ICI qui compte, et rien d'autre.
if (Test-Path -LiteralPath (Join-Path $Installation "wireguard.dll")) {
    Ok "wireguard.dll est a cote du daemon installe"
} else {
    Grief "wireguard.dll absente de $Installation : aucun tunnel ne montera"
}

# --- 3. le service demarre --------------------------------------------------

Dire ""
Dire "== 3. le service demarre"
Start-Service $NomService
Start-Sleep -Seconds 2
$etatService = (Get-Service $NomService).Status
$PidService = Service-Pid
if ($etatService -eq "Running" -and $PidService -gt 0) {
    Ok "service $etatService, pid $PidService"
} else {
    Grief "service $etatService (pid $PidService)"
}

$pret = $false
foreach ($i in 1..40) {
    Start-Sleep -Milliseconds 250
    if (Test-Path "\\.\pipe\bifrost-daemon") { $pret = $true; break }
}
if ($pret) { Ok "tube nomme ouvert par le service" } else { Grief "le service n'a pas ouvert son tube nomme" }

# --- 4. connect -------------------------------------------------------------

Dire ""
Dire "== 4. connect"
& $Cli connect --config $Profil 2>&1 | ForEach-Object { Dire "   | $_" }
if ($LASTEXITCODE -eq 0) { Ok "connect a repondu sans erreur" } else { Grief "connect a rendu $LASTEXITCODE" }

$etat = $null
try { $etat = & $Cli --json status 2>$null | ConvertFrom-Json } catch {}
if ($etat) {
    # `State` est un enum serde INTERNALLY TAGGED - `#[serde(tag = "state")]` -
    # donc le JSON porte `{"state":{"state":"connected"}}` et non
    # `{"state":"connected"}`. La version Linux greppe la chaine et ne voit pas
    # la difference; `ConvertFrom-Json`, si: `$etat.state` y est un objet.
    $nomEtat = if ($etat.state -is [string]) { $etat.state } else { $etat.state.state }
    Dire "   etat: state=$nomEtat kill_switch=$($etat.kill_switch_engaged) tx=$($etat.tx_bytes) rx=$($etat.rx_bytes)"
    if ($nomEtat -eq "connected") { Ok "status: connected" } else { Grief "status n'est pas connected: $nomEtat" }
    if ($etat.kill_switch_engaged) { Ok "kill switch arme" } else { Grief "kill switch non arme" }
} else {
    Grief "status illisible"
}

# --- 5. le tunnel transporte VRAIMENT ---------------------------------------

Dire ""
Dire "== 5. le tunnel transporte vraiment"
# Et non `tx_bytes > 0`: un endpoint MORT fait monter ce compteur, ce sont ses
# tentatives de poignee de main. La lecon est datee du 18/08/2026 sur `exit-ip`.
# La banniere, elle, ne peut venir que du pair, et elle etait muette a l'etape 0.
$vu = ""
foreach ($essai in 1..3) {
    $vu = Lire-Banniere $BanniereHote $BannierePort 6000
    Dire "   essai ${essai}: '$vu'"
    if ($vu) { break }
    Start-Sleep -Seconds 2
}
if ($vu -eq $BanniereAttendue) {
    Ok "'$vu' lue a travers le tunnel, inobtenable hors de lui"
} else {
    Grief "la banniere du pair n'a pas ete lue a travers le tunnel (vu: '$vu')"
}

# --- 6. le VRAI resolveur chiffre tourne, enfant du service -----------------

Dire ""
Dire "== 6. le VRAI resolveur chiffre tourne, enfant du service"
$resolveurProc = $null
foreach ($i in 1..40) {
    $resolveurProc = Processus-Resolveur | Select-Object -First 1
    if ($resolveurProc) { break }
    Start-Sleep -Milliseconds 500
}
if ($resolveurProc) {
    $PidResolveur = [int]$resolveurProc.ProcessId
    Ok "dnscrypt-proxy en service (pid $PidResolveur)"
    if ($resolveurProc.ExecutablePath -eq $ResolveurInstalle) {
        Ok "c'est le binaire que la ligne du service nomme"
    } else {
        Grief "il tourne depuis $($resolveurProc.ExecutablePath), pas $ResolveurInstalle"
    }
    if ([int]$resolveurProc.ParentProcessId -eq $PidService) {
        Ok "il est bien l'enfant du service (ppid $($resolveurProc.ParentProcessId))"
    } else {
        Grief "ppid $($resolveurProc.ParentProcessId), le service est $PidService"
    }
    # 11b-2: mesure, pas supposition. Sous Linux il tourne sous
    # bifrost-resolveur; ici sous NT AUTHORITY\LocalService (S-1-5-19), un
    # compte integre non administrateur, depuis que la ligne du service porte
    # --resolveur-utilisateur. La decision se prend sur le SID (GetOwnerSid),
    # jamais sur le nom (GetOwner), qui est traduit d'une machine a l'autre;
    # le nom n'est affiche que pour la lecture.
    $proprio = Invoke-CimMethod -InputObject $resolveurProc -MethodName GetOwner -ErrorAction SilentlyContinue
    if ($proprio) { Dire "   proprietaire affiche: $($proprio.Domain)\$($proprio.User)" }
    $proprioSid = Invoke-CimMethod -InputObject $resolveurProc -MethodName GetOwnerSid -ErrorAction SilentlyContinue
    if ($proprioSid -and $proprioSid.Sid -eq 'S-1-5-19') {
        Ok "il tourne sous S-1-5-19 (LocalService), pas sous le compte du service"
    } elseif ($proprioSid -and $proprioSid.Sid) {
        Grief "il tourne sous $($proprioSid.Sid), attendu S-1-5-19 (LocalService)"
    } else {
        Grief "SID du proprietaire de dnscrypt-proxy illisible"
    }
} else {
    $PidResolveur = 0
    Grief "aucun dnscrypt-proxy: le profil en demandait un"
}

# --- 7. la machine resout par lui -------------------------------------------

Dire ""
Dire "== 7. la machine resout par lui"
$dnsTun = Get-DnsClientServerAddress -InterfaceAlias "bifrost-svc" -AddressFamily IPv4 -ErrorAction SilentlyContinue
if ($dnsTun -and $dnsTun.ServerAddresses -contains "127.0.0.1") {
    Ok "l'interface du tunnel pointe le resolveur local (127.0.0.1)"
} else {
    Grief "l'interface du tunnel ne pointe pas 127.0.0.1: $($dnsTun.ServerAddresses -join ',')"
}

# La mesure qui compte: un vrai nom, demande EXPLICITEMENT au resolveur local,
# donc chiffre jusqu'au serveur public. `-DnsOnly` ecarte LLMNR et NetBIOS, qui
# repondraient sans que le resolveur ait rien fait.
$adresse = $null
try {
    $adresse = (Resolve-DnsName -Name $NomReel -Type A -Server 127.0.0.1 -DnsOnly `
        -QuickTimeout -ErrorAction Stop | Where-Object { $_.IPAddress } |
        Select-Object -First 1).IPAddress
} catch {
    Dire "   $($_.Exception.Message)"
}
if ($adresse) {
    Ok "$NomReel resout en $adresse, par le resolveur local"
} else {
    Grief "$NomReel ne resout pas par le resolveur local"
}

# --- 8. rien ne sort en clair sur le :53 ------------------------------------

Dire ""
Dire "== 8. rien ne sort en clair sur le :53"
# Le pendant du `nft list ruleset` de la version Linux, et un temoin vivant en
# plus. Le balayage rend 150000 lignes: il est fait UNE fois et relu ensuite.
#
# On cherche NOS PROPRES noms de filtres dans la sortie brute, et surtout pas
# les lignes contenant "bifrost". Mesure du 22/08/2026: le nom d'un filtre WFP
# est `"{nom} ({couche})"`, donc `block-dns (FWPM_LAYER_ALE_AUTH_CONNECT_V4)`,
# et le mot "Bifrost" n'apparait que sur les lignes du FOURNISSEUR. Filtrer sur
# lui d'abord jetait justement les lignes qu'on venait lire, et le banc a
# conclu a l'absence de filtres qui etaient bel et bien poses. Chercher nos
# noms est aussi le seul choix insensible a la langue: le reste de cette sortie
# est traduit.
$brut = netsh wfp show filters file=-
foreach ($attendu in "permit-resolveur-dns", "block-dns", "block-all") {
    if (($brut | Select-String -SimpleMatch $attendu).Count -gt 0) {
        Ok "$attendu est pose"
    } else {
        Grief "aucun $attendu dans les filtres vivants"
    }
}

# Le temoin vivant: la meme question posee a un resolveur PUBLIC doit echouer.
# Sans lui, "le filtre est pose" ne dirait pas qu'il mord.
$fuite = $null
try {
    $fuite = (Resolve-DnsName -Name $NomReel -Type A -Server 9.9.9.9 -DnsOnly `
        -QuickTimeout -ErrorAction Stop | Where-Object { $_.IPAddress } |
        Select-Object -First 1).IPAddress
} catch {}
if ($fuite) {
    Grief "une requete en clair vers 9.9.9.9:53 a abouti ($fuite): le :53 fuit"
} else {
    Ok "une requete en clair vers 9.9.9.9:53 n'aboutit pas"
}

# --- 9. le DNS de la machine n'a pas bouge ----------------------------------

Dire ""
Dire "== 9. le DNS de la machine n'a pas bouge"
$DnsPendant = Empreinte-Dns
if ($DnsPendant -eq $DnsAvant) {
    Ok "intact pendant la connexion ($DnsPendant)"
} else {
    Grief "modifie: '$DnsAvant' devenu '$DnsPendant'"
}

# --- 10. disconnect ---------------------------------------------------------

Dire ""
Dire "== 10. disconnect"
& $Cli disconnect 2>&1 | ForEach-Object { Dire "   | $_" }
if ($LASTEXITCODE -eq 0) { Ok "disconnect a repondu sans erreur" } else { Grief "disconnect a rendu $LASTEXITCODE" }
Start-Sleep -Seconds 3

# Sans resolveur au depart, "il s'est arrete" ne prouve rien: le temoin resterait
# vert dans le cas meme ou le produit n'en aurait jamais lance.
if ($PidResolveur -eq 0) {
    Grief "aucun resolveur n'avait demarre: son arret ne peut pas etre constate"
} elseif (Processus-Resolveur) {
    Grief "le resolveur survit a la deconnexion"
} else {
    Ok "le resolveur (pid $PidResolveur) s'est arrete avec le tunnel"
}

if ((Filtres-Bifrost) -eq 0) { Ok "le kill switch est retire" } else { Grief "des filtres restent en place" }
if (Get-NetAdapter -Name "bifrost-svc" -ErrorAction SilentlyContinue) {
    Grief "l'adaptateur du tunnel survit a la deconnexion"
} else {
    Ok "l'adaptateur du tunnel a disparu"
}

# --- 11. le service a tenu tout du long -------------------------------------

Dire ""
Dire "== 11. le service a tenu tout du long"
$etatFin = (Get-Service $NomService).Status
$PidFin = Service-Pid
if ($etatFin -eq "Running") { Ok "service toujours Running" } else { Grief "le service n'est plus Running: $etatFin" }
if ($PidFin -eq $PidService -and $PidFin -gt 0) {
    Ok "meme pid qu'au depart ($PidFin): aucun redemarrage"
} else {
    Grief "pid $PidFin au lieu de ${PidService}: le daemon est tombe et a redemarre"
}

# --- 12. demontage, puis verdict ------------------------------------------

Demonter

Dire ""
if ($script:Griefs.Count -eq 0) {
    Dire "service Windows, cycle complet: tout est passe"
    exit 0
} else {
    Dire "service Windows, cycle complet: $($script:Griefs.Count) controle(s) en echec"
    $script:Griefs | ForEach-Object { Dire "   - $_" }
    exit 1
}

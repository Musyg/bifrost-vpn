<#
.SYNOPSIS
Installe Bifrost sur une machine Windows: repertoires, binaires, service.

.DESCRIPTION
Le pendant de packaging/install-linux.sh. Meme parti pris, et la meme phrase
en tete: ce script N'ACTIVE NI NE DEMARRE le service. Poser un kill switch
coupe tout trafic qui ne passe pas par le tunnel, y compris la session distante
depuis laquelle on installe. Le demarrage reste une decision explicite, prise
par quelqu'un qui sait ou il se trouve.

Une divergence avec Linux, et il faut la dire: le service Windows est
enregistre en demarrage AUTOMATIQUE (service::spec::Demarrage::Automatique),
donc il partira au prochain redemarrage sans qu'on le lui demande. L'unite
systemd, elle, n'est pas activee par install-linux.sh. Sur Windows le reglage
vit dans la specification du service, pas dans l'installateur.

Idempotent: rejouable sur une installation existante. Le service est retire
puis recree, parce que sa ligne de commande NOMME le resolveur chiffre et
change donc avec lui.

.PARAMETER Binaires
Repertoire contenant bifrost-daemon.exe et bifrost-cli.exe. Par defaut
target\release a la racine du depot.

.PARAMETER Resolveur
Chemin du resolveur chiffre (dnscrypt-proxy.exe). Ce binaire tiers n'est pas
dans le depot: il se recupere et se verifie separement, a la cle publiee du
projet. Sans ce parametre tout le reste s'installe, et un profil demandant
`embarque` echouera avec un message clair plutot que de se rabattre en silence
sur du DNS en clair.

.PARAMETER Pilote
Chemin de wireguard.dll (WireGuardNT amd64). Troisieme binaire tiers, et le
seul SANS lequel aucun tunnel ne monte du tout: `WireGuardNt::load` cherche la
DLL A COTE DU BINAIRE QUI TOURNE - `current_exe().parent()` - donc une copie
posee ailleurs sur la machine est invisible pour un service qui s'execute
depuis %ProgramFiles%\Bifrost. Sans equivalent Linux: la, WireGuard est un
module du noyau et install-linux.sh n'a rien a deposer.

.EXAMPLE
.\packaging\install-windows.ps1

.EXAMPLE
.\packaging\install-windows.ps1 -Resolveur C:\telechargements\dnscrypt-proxy.exe -Pilote C:\telechargements\wireguard.dll
#>
[CmdletBinding()]
param(
    [string] $Binaires,
    [string] $Resolveur,
    [string] $Pilote
)

$ErrorActionPreference = 'Stop'

$Racine = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
if (-not $Binaires) { $Binaires = Join-Path $Racine 'target\release' }

# Program Files pour les binaires, ProgramData pour ce qui s'ecrit. Le meme
# partage que /usr/bin et /var/lib sous Linux, et il n'est pas cosmetique: le
# premier n'est pas accessible en ecriture aux comptes ordinaires, le second
# l'est par defaut - voir l'etape qui le durcit.
$Installation = Join-Path $env:ProgramFiles 'Bifrost'
$Donnees      = Join-Path $env:ProgramData 'Bifrost'
$ResolveurInstalle = Join-Path $Installation 'dnscrypt-proxy.exe'
$PiloteInstalle    = Join-Path $Installation 'wireguard.dll'
$Daemon       = Join-Path $Installation 'bifrost-daemon.exe'
$NomService   = 'BifrostDaemon'

# Des SID, jamais des noms. La mesure du 19 aout 2026 sur une machine allemande
# a rendu 'VORDEFINIERT\Benutzer' et 'NT-AUTORITAT\SYSTEM': les noms de comptes
# sont traduits, les SID non. Meme regle que dans bifrost-coffre/src/acl.rs.
$SID_SYSTEM = '*S-1-5-18'
$SID_ADMINS = '*S-1-5-32-544'
# 11b-2: le compte de service du resolveur chiffre, NT AUTHORITY\LocalService.
$SID_LOCALSERVICE = '*S-1-5-19'
# Le seul NOM que l'installateur passe au daemon, et sous sa forme CANONIQUE.
# Mesure du 06/09/2026 sur essai-windows, locale francaise: LookupAccountNameW
# resout 'LocalService' (et 'NT AUTHORITY\LocalService'); le nom AFFICHE
# localise, lui, ne se resout pas. Ne jamais passer un nom affiche: il change
# avec la langue de la machine. Le daemon le resout a l'installation et refuse
# un nom inconnu (scm::install).
$CompteResolveur = 'LocalService'

function Ok    ([string] $m) { Write-Host ('  OK    {0}' -f $m) }
function Info  ([string] $m) { Write-Host ('  ..    {0}' -f $m) }
function Etape ([string] $m) { Write-Host ''; Write-Host ('== {0}' -f $m) }

# Interroger un binaire TIERS ne doit jamais faire echouer l'installation.
# `install-linux.sh` l'ecrit en une fois avec `|| echo 'version illisible'`;
# PowerShell 5.1 ne pardonne pas autant. Deux pieges se cumulent ici, mesures
# le 22 aout 2026: rediriger le stderr d'un executable natif enveloppe chaque
# ligne dans un ErrorRecord, et avec $ErrorActionPreference a 'Stop' cet
# ErrorRecord devient terminant. Un binaire qui ne connait pas -version - ce
# qu'un tiers a parfaitement le droit d'etre - suffisait donc a interrompre
# l'installation apres la copie des binaires.
function Sans-Bruit ([scriptblock] $bloc) {
    $ancienne = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $bloc 2>&1 | Out-Null } finally { $ErrorActionPreference = $ancienne }
}

function Version-De ([string] $exe) {
    $ancienne = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $sortie = (& $exe -version 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -eq 0 -and $sortie) { return $sortie }
    } catch {
    } finally {
        $ErrorActionPreference = $ancienne
    }
    return 'version illisible'
}

function Est-Administrateur {
    $identite = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identite)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Est-Administrateur)) {
    throw "ce script doit tourner avec les droits administrateur: il ecrit dans Program Files et cree un service"
}

# Toutes les verifications d'entree AVANT la premiere ecriture. Un -Resolveur
# mal orthographie refuse a l'etape 3 laisserait derriere lui des repertoires
# crees et des binaires copies, c'est-a-dire une installation a moitie faite
# dont rien ne dit qu'elle l'est.
foreach ($f in 'bifrost-daemon.exe', 'bifrost-cli.exe') {
    $chemin = Join-Path $Binaires $f
    if (-not (Test-Path -LiteralPath $chemin -PathType Leaf)) {
        throw "binaire introuvable: $chemin"
    }
}
if ($Resolveur -and -not (Test-Path -LiteralPath $Resolveur -PathType Leaf)) {
    throw "-Resolveur $Resolveur n'existe pas"
}
if ($Pilote -and -not (Test-Path -LiteralPath $Pilote -PathType Leaf)) {
    throw "-Pilote $Pilote n'existe pas"
}

Etape 'Repertoires'
foreach ($d in $Installation, $Donnees) {
    if (Test-Path -LiteralPath $d -PathType Container) {
        Info "$d existe deja"
    } else {
        New-Item -ItemType Directory -Path $d | Out-Null
        Ok "$d cree"
    }
}

# Le durcissement de ProgramData n'est pas un detail de confort. Mesure du
# 19 aout 2026: C:\ProgramData porte une ACE CREATOR OWNER en controle total,
# heritee. Un repertoire cree la par un utilisateur ORDINAIRE lui appartient, et
# le proprietaire detient implicitement WRITE_DAC quoi que dise la liste. Il
# peut donc attendre qu'un administrateur y installe un profil, puis le
# remplacer par le sien - et le profil designe le serveur vers lequel le tunnel
# monte. C'est la mecanique exacte de CVE-2026-35603.
#
# La propriete d'abord: si un tiers a pris les devants, changer la liste sans
# la reprendre ne servirait a rien, il la reecrirait.
#
# Par `icacls /setowner` et non par `takeown /r /d o`, retire le 22/08/2026.
# L'option `/d` de takeown attend la reponse OUI/NON dans la LANGUE DE
# L'APPELANT: `o` passe depuis un compte francais et se fait refuser sous
# SYSTEM, dont l'interface est en anglais - "'o' value is not allowed for '/d'
# option", et l'installation s'arretait la. Meme piege que les noms de comptes
# traduits et que la sortie de `sc qc`: ne jamais passer ni attendre une chaine
# localisee depuis un script. `icacls` prend un SID et ne demande rien.
Sans-Bruit { & icacls.exe $Donnees /setowner $SID_ADMINS /T /C }
if ($LASTEXITCODE -ne 0) { throw "reprise de propriete impossible sur $Donnees (code $LASTEXITCODE)" }
Sans-Bruit { & icacls.exe $Donnees /inheritance:r /grant "$($SID_SYSTEM):(OI)(CI)F" "$($SID_ADMINS):(OI)(CI)F" }
if ($LASTEXITCODE -ne 0) { throw "icacls a echoue sur $Donnees (code $LASTEXITCODE)" }
Ok "$Donnees restreint a SYSTEM et aux administrateurs, heritage coupe"

# 11b-2 (ecart 2 du 13/09/2026): le repertoire DU RESOLVEUR et son
# sous-repertoire d'ETAT, ouverts au compte de service. Le repertoire du
# resolveur ($Donnees\resolveur) recoit la configuration et la liste
# anti-telemetrie, que le daemon y ecrit en place a chaque connexion; il est
# ouvert en LECTURE + traversee heritable (RX), jamais en ecriture: la
# configuration et la liste doivent rester non modifiables par le resolveur
# (meme but que "il ne peut pas reecrire son binaire"). Pourquoi le repertoire
# et non les deux fichiers: dnscrypt-proxy change lui-meme de repertoire
# courant vers celui de sa configuration au chargement, et sans acces au
# repertoire il sort en 255 ("chdir ...: Access is denied.", mesure sous
# SYSTEM sur essai-windows le 13/09/2026). Le sous-repertoire d'etat
# ($Donnees\resolveur\etat) est le seul que le compte peut ecrire (cache de la
# liste des serveurs): Modify heritable, en plus de la lecture heritee du
# parent. Les ACE sont posees sur CES deux repertoires et JAMAIS sur $Donnees
# lui-meme, qui porte le profil (cle privee WireGuard), les configurations des
# coeurs, le carnet et le journal: l'invariant "seuls SYSTEM et les
# administrateurs ont des droits sur $Donnees" reste tel quel, et
# scripts/packaging-windows.ps1 le garde, avec "aucun bit d'ecriture pour
# S-1-5-19 sur $Donnees\resolveur". Le daemon repose les memes ACE a chaque
# lancement (demarrer_sous_compte): il ne suppose pas l'installateur. Rejouer
# l'installation ne doit pas faire grossir le compte d'ACE S-1-5-19 de ces
# repertoires: c'est scripts/packaging-windows.ps1 qui le MESURE (deux passes
# dans le bac a sable), ce n'est pas suppose ici.
$RepResolveur = Join-Path $Donnees 'resolveur'
$Etat = Join-Path $RepResolveur 'etat'
foreach ($rep in $RepResolveur, $Etat) {
    if (-not (Test-Path -LiteralPath $rep -PathType Container)) {
        New-Item -ItemType Directory -Path $rep | Out-Null
    }
}
Sans-Bruit { & icacls.exe $RepResolveur /grant "$($SID_LOCALSERVICE):(OI)(CI)RX" }
if ($LASTEXITCODE -ne 0) { throw "icacls a echoue sur $RepResolveur (code $LASTEXITCODE)" }
Sans-Bruit { & icacls.exe $Etat /grant "$($SID_LOCALSERVICE):(OI)(CI)M" }
if ($LASTEXITCODE -ne 0) { throw "icacls a echoue sur $Etat (code $LASTEXITCODE)" }
Ok "$RepResolveur ouvert en lecture heritable et $Etat en ecriture heritable au compte du resolveur (S-1-5-19), rien sur $Donnees"

Etape 'Binaires'
foreach ($f in 'bifrost-daemon.exe', 'bifrost-cli.exe') {
    $source = Join-Path $Binaires $f
    $cible  = Join-Path $Installation $f
    try {
        Copy-Item -LiteralPath $source -Destination $cible -Force
    } catch {
        throw ("copie de $f impossible: $($_.Exception.Message)`n" +
               "    Un executable en cours d'utilisation est verrouille par Windows. " +
               "Arreter le service $NomService avant de reinstaller.")
    }
    Ok $cible
}

Etape 'Pilote WireGuardNT'
# Le seul des trois tiers sans lequel AUCUN tunnel ne monte, et le plus facile
# a oublier parce que rien ne le reclame avant la premiere connexion.
# `WireGuardNt::load` resout la DLL par `current_exe().parent()`: c'est le
# repertoire du BINAIRE QUI TOURNE, donc %ProgramFiles%\Bifrost des lors que le
# service est en place. Une copie posee dans un repertoire d'essai, ou a cote
# d'une construction de developpement, n'y change rien - le service ne la voit
# pas et rend "wireguard.dll introuvable" au premier connect.
if ($Pilote) {
    $memePilote = $false
    if (Test-Path -LiteralPath $PiloteInstalle -PathType Leaf) {
        $a = (Get-Item -LiteralPath $Pilote).FullName
        $b = (Get-Item -LiteralPath $PiloteInstalle).FullName
        $memePilote = ($a -eq $b)
    }
    if ($memePilote) {
        Info "$PiloteInstalle est deja la cible, rien a copier"
    } else {
        try {
            Copy-Item -LiteralPath $Pilote -Destination $PiloteInstalle -Force
        } catch {
            throw ("copie de wireguard.dll impossible: $($_.Exception.Message)`n" +
                   "    Une DLL chargee est verrouillee par Windows. " +
                   "Arreter le service $NomService avant de reinstaller.")
        }
    }
    Ok $PiloteInstalle
} elseif (Test-Path -LiteralPath $PiloteInstalle -PathType Leaf) {
    Ok "$PiloteInstalle deja en place, conserve"
} else {
    Info 'aucun pilote WireGuardNT installe (-Pilote non donne)'
    Info 'aucun tunnel ne montera tant qu il manque'
}

Etape 'Resolveur chiffre'
if ($Resolveur) {
    # Son existence a ete verifiee en tete, avant la premiere ecriture.
    $memeFichier = $false
    if (Test-Path -LiteralPath $ResolveurInstalle -PathType Leaf) {
        $a = (Get-Item -LiteralPath $Resolveur).FullName
        $b = (Get-Item -LiteralPath $ResolveurInstalle).FullName
        $memeFichier = ($a -eq $b)
    }
    if ($memeFichier) {
        Info "$ResolveurInstalle est deja la cible, rien a copier"
    } else {
        Copy-Item -LiteralPath $Resolveur -Destination $ResolveurInstalle -Force
    }
    Ok "$ResolveurInstalle ($(Version-De $ResolveurInstalle))"
} elseif (Test-Path -LiteralPath $ResolveurInstalle -PathType Leaf) {
    Ok "$ResolveurInstalle deja en place, conserve"
} else {
    Info 'aucun resolveur chiffre installe (-Resolveur non donne)'
    Info 'un profil demandant `embarque` echouera tant qu il manque'
}

# Les defauts Windows du daemon pointent sous %ProgramData%\Bifrost\resolveur
# (configuration, liste, sous-repertoire d'etat), que l'etape ProgramData vient
# de creer et d'ouvrir au compte de service (11b-2). La configuration du
# resolveur et sa liste anti-telemetrie ne sont PAS creees ici: le daemon les
# ecrit en place a chaque connexion (ecrire_configuration); elles heritent de
# la lecture du repertoire, que le daemon repose a chaque lancement
# (demarrer_sous_compte).

Etape 'Service'
$existant = Get-Service -Name $NomService -ErrorAction SilentlyContinue
if ($existant) {
    if ($existant.Status -ne 'Stopped') {
        throw ("le service $NomService tourne. L'arreter avant de reinstaller: " +
               "Stop-Service $NomService. Ses filtres SUBSISTENT a l'arret, " +
               "c'est voulu; --cleanup-firewall est la commande qui les retire.")
    }
    # Retire puis recree, et non laisse en place: la ligne de commande du
    # service NOMME le resolveur chiffre, donc elle change des que le resolveur
    # apparait ou disparait. Un service laisse tel quel garderait la ligne de
    # l'installation precedente sans que rien ne le signale.
    & $Daemon --uninstall-service | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "retrait du service $NomService impossible (code $LASTEXITCODE)" }
    Ok "ancien service $NomService retire"
}

$arguments = @('--install-service')
if (Test-Path -LiteralPath $ResolveurInstalle -PathType Leaf) {
    # 11b-2: le binaire ET le compte sous lequel le daemon le lance. Le daemon
    # resout le compte a l'installation et refuse un nom inconnu, plutot que de
    # laisser le service echouer a son premier demarrage.
    $arguments += @('--resolveur-binaire', $ResolveurInstalle, '--resolveur-utilisateur', $CompteResolveur)
}
& $Daemon @arguments
if ($LASTEXITCODE -ne 0) { throw "installation du service impossible (code $LASTEXITCODE)" }

Write-Host ''
Write-Host 'Installation terminee. Le service n est pas demarre.'
Write-Host ''
Write-Host "  sc.exe qc $NomService        # relire la ligne enregistree"
Write-Host "  Start-Service $NomService    # demarrer maintenant"
Write-Host ''
Write-Host 'Il est enregistre en demarrage AUTOMATIQUE: il partira de lui-meme au'
Write-Host 'prochain redemarrage. Armer le kill switch coupe tout trafic hors tunnel,'
Write-Host 'session distante comprise.'
if (-not (Test-Path -LiteralPath $PiloteInstalle -PathType Leaf)) {
    Write-Host ''
    Write-Host 'ATTENTION: wireguard.dll manque dans le repertoire d installation, donc'
    Write-Host 'AUCUN tunnel ne montera. Le service demarrera quand meme et repondra a'
    Write-Host 'tout, jusqu au premier connect. La recuperer sur'
    Write-Host 'https://download.wireguard.com/wireguard-nt/, verifier sa signature'
    Write-Host 'Authenticode, et reinstaller avec -Pilote.'
}
if (Test-Path -LiteralPath $ResolveurInstalle -PathType Leaf) {
    Write-Host ''
    Write-Host 'Le resolveur chiffre tourne sous NT AUTHORITY\LocalService (S-1-5-19): un'
    Write-Host 'compte integre, non administrateur, qui ne peut pas reecrire son propre'
    Write-Host 'binaire (mesure du 06/09/2026). Contrairement a bifrost-resolveur sous'
    Write-Host 'Linux, ce compte n est pas propre a Bifrost: d autres services de Windows'
    Write-Host 'le partagent. Cette installation lui accorde la lecture de son'
    Write-Host 'repertoire, %ProgramData%\Bifrost\resolveur (configuration et liste, que'
    Write-Host 'le daemon y ecrit et qu il ne peut pas modifier), et l ecriture de son'
    Write-Host 'seul etat, %ProgramData%\Bifrost\resolveur\etat; le daemon repose ces'
    Write-Host 'deux droits a chaque lancement. Rien n est ouvert sur'
    Write-Host '%ProgramData%\Bifrost lui-meme: le profil reste a SYSTEM et aux'
    Write-Host 'administrateurs. L exemption WFP du :53 nomme ce SID et le chemin du'
    Write-Host 'binaire.'
}

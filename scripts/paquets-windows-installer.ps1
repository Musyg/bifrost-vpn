<#
.SYNOPSIS
Installe, repare et desinstalle REELLEMENT le MSI de Bifrost, et mesure ce que
le systeme porte. Runner jetable seulement.

.DESCRIPTION
Ce script modifie la machine: le MSI enregistre un service, cree le groupe
local Bifrost et durcit des repertoires. Il refuse de tourner sans
BIFROST_RUNNER_JETABLE=1, que seul le job paquets-windows de la CI pose, sur un
runner jetable, et il exige une machine vierge (aucun service BifrostDaemon,
aucun groupe local Bifrost, ni %ProgramFiles%\Bifrost ni %ProgramData%\Bifrost):
il ne retire jamais une installation reelle.

Ce qu'il mesure (OK ou ECHEC par controle, code non nul s'il y a un ECHEC):
  1. msiexec /i: les deux binaires a la version du workspace, aucun binaire
     tiers; %ProgramData%\Bifrost aux Administrateurs, heritage coupe, SYSTEM et
     Administrateurs seuls; resolveur en lecture et etat en modification pour
     LocalService, rien de plus; le groupe local Bifrost cree vide, avec le
     commentaire de packaging/install-windows.ps1; le service enregistre comme
     spec.rs le declare (LocalSystem, BFE, SID propre, redemarrage sur echec,
     demarrage automatique) et NON demarre; sa ligne, relue au registre, est
     exactement << "<exe>" --service --group "<SID du groupe>" >>, la ligne que
     le script ecrit sur la meme machine; MSI non signe;
  2. msiexec /fa (reparation): code 0, ligne du service et groupe inchanges;
  3. msiexec /x: service, binaires, %ProgramFiles%\Bifrost et entree de
     Programmes et fonctionnalites retires, groupe conserve, journal nommant
     --cleanup-firewall et --uninstall-service;
  4. le resolveur deja pose: un dnscrypt-proxy.exe factice dans
     %ProgramFiles%\Bifrost avant msiexec /i, et la ligne nomme le resolveur et
     le compte LocalService avant le groupe, comme le script; puis msiexec /x,
     et le factice retire par son nom.
A la fin, le groupe cree par la recette est retire (il n'existait pas avant).

Le service n'est jamais demarre: sur le runner, un kill switch arme couperait
la liaison vers GitHub.

.PARAMETER RepertoireMsi
Repertoire du MSI (bifrost-<version>-x64.msi). Par defaut target\msi.

.EXAMPLE
$env:BIFROST_RUNNER_JETABLE = '1'; .\scripts\paquets-windows-installer.ps1
#>
[CmdletBinding()]
param(
    [string] $RepertoireMsi
)

$ErrorActionPreference = 'Stop'

$Racine = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
if (-not $RepertoireMsi) { $RepertoireMsi = Join-Path $Racine 'target\msi' }
$NomService   = 'BifrostDaemon'
$CleService   = "HKLM:\SYSTEM\CurrentControlSet\Services\$NomService"
$NomGroupe    = 'Bifrost'
$Commentaire  = "Acces sans elevation au canal de $NomService"
$Installation = Join-Path $env:ProgramFiles 'Bifrost'
$Donnees      = Join-Path $env:ProgramData 'Bifrost'
$Exe          = Join-Path $Installation 'bifrost-daemon.exe'
$Factice      = Join-Path $Installation 'dnscrypt-proxy.exe'

$script:Echecs = 0
function Ok    ([string] $m) { Write-Host ('  OK    {0}' -f $m) }
function Fail  ([string] $m) { Write-Host ('  ECHEC {0}' -f $m); $script:Echecs++ }
function Etape ([string] $m) { Write-Host ''; Write-Host ('== {0}' -f $m) }
function Refus ([string] $m) { Write-Host ('REFUS: {0}' -f $m); exit 1 }

function Est-Administrateur {
    $identite = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identite)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Des SID, jamais des noms: les noms de comptes sont traduits.
function Sid-DeLaRegle ($regle) {
    try { return $regle.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }
    catch { return $regle.IdentityReference.Value }
}
function Regles-PourSid ([string] $chemin, [string] $sid) {
    $regles = @()
    foreach ($regle in (Get-Acl -LiteralPath $chemin).Access) {
        if ((Sid-DeLaRegle $regle) -eq $sid) { $regles += $regle }
    }
    return ,$regles
}

function Version-Workspace {
    $dans = $false
    foreach ($ligne in (Get-Content -LiteralPath (Join-Path $Racine 'Cargo.toml'))) {
        $t = $ligne.Trim()
        if ($t.StartsWith('[')) { $dans = ($t -eq '[workspace.package]'); continue }
        if (-not $dans) { continue }
        if ($t -match '^version\s*=\s*"([^"]+)"') { return $Matches[1] }
    }
    return $null
}

function Propriete-Msi ([string] $msi, [string] $nom) {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $db = $installer.OpenDatabase($msi, 0)
    $vue = $db.OpenView("SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = '$nom'")
    $null = $vue.Execute()
    $rec = $vue.Fetch()
    if ($null -eq $rec) { return $null }
    return $rec.StringData(1)
}

function Msiexec ([string[]] $arguments) {
    $p = Start-Process -FilePath 'msiexec.exe' -ArgumentList $arguments -Wait -PassThru
    return $p.ExitCode
}

function Ligne-DuService {
    if (-not (Test-Path -LiteralPath $CleService)) { return $null }
    return (Get-ItemProperty -LiteralPath $CleService).ImagePath
}

# --------------------------------------------------------------- garde-fous
if ($env:BIFROST_RUNNER_JETABLE -ne '1') {
    Refus 'ce script installe un service et cree un groupe local: runner jetable seulement (BIFROST_RUNNER_JETABLE=1).'
}
if (-not (Est-Administrateur)) { Refus 'droits administrateur exiges (msiexec, service, ACL).' }

$fichierMsi = @(Get-ChildItem -LiteralPath $RepertoireMsi -Filter 'bifrost-*-x64.msi' -File -ErrorAction SilentlyContinue)
if ($fichierMsi.Count -ne 1) { Refus "il faut exactement un bifrost-*-x64.msi sous $RepertoireMsi ($($fichierMsi.Count) trouve(s))" }
$Msi = $fichierMsi[0].FullName
$Version = Version-Workspace
if (-not $Version) { Refus 'version illisible dans Cargo.toml [workspace.package]' }
$ProductCode = Propriete-Msi $Msi 'ProductCode'
if (-not $ProductCode) { Refus 'ProductCode illisible dans le MSI' }
Write-Host "MSI: $Msi"
Write-Host "version: $Version, ProductCode: $ProductCode"
$CleArp = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode"
$JournalInstallation = Join-Path $RepertoireMsi 'installation.log'
$JournalReparation   = Join-Path $RepertoireMsi 'reparation.log'
$JournalRetrait      = Join-Path $RepertoireMsi 'desinstallation.log'
$JournalInstallationResolveur = Join-Path $RepertoireMsi 'installation-resolveur.log'
$JournalRetraitResolveur      = Join-Path $RepertoireMsi 'desinstallation-resolveur.log'

Etape 'Machine vierge'
if (Get-Service -Name $NomService -ErrorAction SilentlyContinue) { Refus "un service $NomService existe deja" }
if (Get-LocalGroup -Name $NomGroupe -ErrorAction SilentlyContinue) { Refus "un groupe local $NomGroupe existe deja" }
if (Get-LocalUser -Name $NomGroupe -ErrorAction SilentlyContinue) { Refus "un compte local $NomGroupe existe deja" }
if (Test-Path -LiteralPath $Installation) { Refus "$Installation existe deja" }
if (Test-Path -LiteralPath $Donnees) { Refus "$Donnees existe deja" }
Ok 'ni service, ni groupe, ni repertoire Bifrost'

$GroupeSid = $null
try {
    # ---------------------------------------------------------- installation
    Etape 'msiexec /i'
    $code = Msiexec @('/i', "`"$Msi`"", '/qn', '/norestart', '/l*v', "`"$JournalInstallation`"")
    if ($code -eq 0) { Ok 'msiexec /i a rendu 0' } else { Fail "msiexec /i a rendu $code" }

    Etape 'Binaires'
    foreach ($b in 'bifrost-daemon.exe', 'bifrost-cli.exe') {
        if (Test-Path -LiteralPath (Join-Path $Installation $b) -PathType Leaf) { Ok "$b pose" }
        else { Fail "$b absent de $Installation" }
    }
    $cli = Join-Path $Installation 'bifrost-cli.exe'
    if (Test-Path -LiteralPath $cli -PathType Leaf) {
        $texteVersion = (& $cli --version 2>&1 | Out-String).Trim()
        if ($texteVersion -match [regex]::Escape($Version)) { Ok "bifrost-cli --version porte $Version" }
        else { Fail "bifrost-cli --version rend << $texteVersion >>" }
    }
    foreach ($tiers in 'wireguard.dll', 'dnscrypt-proxy.exe') {
        if (Test-Path -LiteralPath (Join-Path $Installation $tiers)) { Fail "$tiers distribue par le MSI" }
        else { Ok "$tiers absent (binaire tiers non distribue)" }
    }

    Etape '%ProgramData%\Bifrost: proprietaire, heritage, droits'
    if (Test-Path -LiteralPath $Donnees -PathType Container) {
        $acl = Get-Acl -LiteralPath $Donnees
        $proprietaire = try { $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { '?' }
        if ($proprietaire -eq 'S-1-5-32-544') { Ok 'proprietaire: Administrateurs (S-1-5-32-544)' }
        else { Fail "proprietaire: $proprietaire au lieu de S-1-5-32-544" }
        if ($acl.AreAccessRulesProtected) { Ok 'heritage coupe' } else { Fail 'heritage non coupe' }
        $intrus = @()
        foreach ($regle in $acl.Access) {
            $sid = Sid-DeLaRegle $regle
            if (@('S-1-5-18', 'S-1-5-32-544') -notcontains $sid) { $intrus += $sid }
        }
        if ($intrus.Count -eq 0) { Ok 'seuls SYSTEM et les Administrateurs y ont des droits' }
        else { Fail ("droits tiers: {0}" -f ($intrus -join ', ')) }
    } else {
        Fail "$Donnees absent"
    }
    $RepResolveur = Join-Path $Donnees 'resolveur'
    $Etat = Join-Path $RepResolveur 'etat'
    $oi = [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $ci = [Security.AccessControl.InheritanceFlags]::ContainerInherit
    $rx = [int][Security.AccessControl.FileSystemRights]::ReadAndExecute
    $modify = [int][Security.AccessControl.FileSystemRights]::Modify
    $bitsEcriture = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x40000000 -bor 0x10000000
    if (Test-Path -LiteralPath $RepResolveur -PathType Container) {
        $aceRep = Regles-PourSid $RepResolveur 'S-1-5-19'
        $lecture = @($aceRep | Where-Object {
            $_.AccessControlType -eq 'Allow' -and
            (([int]$_.FileSystemRights -band $rx) -eq $rx) -and
            (($_.InheritanceFlags -band $oi) -eq $oi) -and
            (($_.InheritanceFlags -band $ci) -eq $ci)
        })
        if ($lecture.Count -ge 1) { Ok 'resolveur: lecture et traversee heritables pour S-1-5-19' }
        else { Fail 'resolveur: aucune ACE S-1-5-19 en lecture heritable' }
        $ecriture = @($aceRep | Where-Object {
            $_.AccessControlType -eq 'Allow' -and (([int]$_.FileSystemRights -band $bitsEcriture) -ne 0)
        })
        if ($ecriture.Count -eq 0) { Ok 'resolveur: aucun bit d''ecriture pour S-1-5-19' }
        else { Fail ("resolveur: inscriptible par S-1-5-19 ({0})" -f $ecriture[0].FileSystemRights) }
    } else {
        Fail "$RepResolveur absent"
    }
    if (Test-Path -LiteralPath $Etat -PathType Container) {
        $aceEtat = Regles-PourSid $Etat 'S-1-5-19'
        $bonne = @($aceEtat | Where-Object {
            $_.AccessControlType -eq 'Allow' -and
            (([int]$_.FileSystemRights -band $modify) -eq $modify) -and
            (($_.InheritanceFlags -band $oi) -eq $oi) -and
            (($_.InheritanceFlags -band $ci) -eq $ci)
        })
        if ($bonne.Count -ge 1) { Ok 'etat: modification heritable pour S-1-5-19' }
        else { Fail 'etat: aucune ACE S-1-5-19 en modification heritable' }
    } else {
        Fail "$Etat absent"
    }

    Etape 'Groupe local Bifrost'
    $groupe = Get-LocalGroup -Name $NomGroupe -ErrorAction SilentlyContinue
    if ($groupe) {
        $GroupeSid = $groupe.SID.Value
        Ok "groupe $NomGroupe cree (SID $GroupeSid)"
        $membres = @(Get-LocalGroupMember -Group $NomGroupe -ErrorAction SilentlyContinue)
        if ($membres.Count -eq 0) { Ok 'vide' } else { Fail "$($membres.Count) membre(s)" }
        if ($groupe.Description -ceq $Commentaire) { Ok 'commentaire de install-windows.ps1' }
        else { Fail "commentaire << $($groupe.Description) >> au lieu de << $Commentaire >>" }
    } else {
        Fail "le groupe local $NomGroupe n'a pas ete cree"
    }

    Etape 'Service enregistre, non demarre'
    $service = Get-Service -Name $NomService -ErrorAction SilentlyContinue
    if (-not $service) {
        Fail "service $NomService absent"
    } else {
        if ($service.Status -eq 'Stopped') { Ok 'Stopped: le MSI ne demarre pas le service' }
        else { Fail "etat $($service.Status): le MSI ne doit rien demarrer" }
        $cle = Get-ItemProperty -LiteralPath $CleService
        Write-Host ("        ligne: {0}" -f $cle.ImagePath)
        $attendue = "`"$Exe`" --service --group `"$GroupeSid`""
        if ($cle.ImagePath -ceq $attendue) { Ok 'ligne identique a celle du script sur cette machine, SID du groupe en dernier' }
        else { Fail "ligne << $($cle.ImagePath) >> au lieu de << $attendue >>" }
        if ($cle.Start -eq 2) { Ok 'demarrage automatique (spec.rs), au prochain redemarrage' } else { Fail "Start = $($cle.Start)" }
        if ($cle.ObjectName -eq 'LocalSystem') { Ok 'LocalSystem' } else { Fail "compte $($cle.ObjectName)" }
        if (@($cle.DependOnService) -contains 'BFE') { Ok 'depend de BFE' } else { Fail 'ne depend pas de BFE' }
        if ($cle.ServiceSidType -eq 1) { Ok 'SID de service propre (SERVICE_SID_TYPE_UNRESTRICTED)' }
        else { Fail "ServiceSidType = $($cle.ServiceSidType)" }
        if ($cle.FailureActions) { Ok 'actions sur echec enregistrees' } else { Fail 'aucune action sur echec' }
    }

    Etape 'Programmes et fonctionnalites'
    if (Test-Path -LiteralPath $CleArp) {
        $arp = Get-ItemProperty -LiteralPath $CleArp
        if ($arp.DisplayName -eq 'Bifrost') { Ok 'DisplayName = Bifrost' } else { Fail "DisplayName = $($arp.DisplayName)" }
        if ($arp.DisplayVersion -eq $Version) { Ok "DisplayVersion = $Version" } else { Fail "DisplayVersion = $($arp.DisplayVersion)" }
    } else {
        Fail "entree absente: $CleArp"
    }

    Etape 'Journal et signature'
    $journal = if (Test-Path -LiteralPath $JournalInstallation) { Get-Content -LiteralPath $JournalInstallation -Raw } else { '' }
    if ($journal -match '--install-service') { Ok 'le journal nomme --install-service (action Return=check, msiexec a rendu 0)' }
    else { Fail 'le journal ne nomme pas --install-service' }
    $signature = (Get-AuthenticodeSignature -LiteralPath $Msi).Status
    if ($signature -eq 'NotSigned') { Ok 'MSI non signe' } else { Fail "signature: $signature" }

    # ------------------------------------------------------------ reparation
    Etape 'msiexec /fa (reparation)'
    $avant = Ligne-DuService
    $code = Msiexec @('/fa', $ProductCode, '/qn', '/norestart', '/l*v', "`"$JournalReparation`"")
    if ($code -eq 0) { Ok 'msiexec /fa a rendu 0' } else { Fail "msiexec /fa a rendu $code" }
    if ((Ligne-DuService) -ceq $avant) { Ok 'ligne du service inchangee' } else { Fail "ligne changee: << $(Ligne-DuService) >>" }
    $apres = Get-LocalGroup -Name $NomGroupe -ErrorAction SilentlyContinue
    if ($apres -and $apres.SID.Value -eq $GroupeSid) { Ok 'groupe inchange' } else { Fail 'groupe change par la reparation' }

    # --------------------------------------------------------- desinstallation
    Etape 'msiexec /x'
    $code = Msiexec @('/x', $ProductCode, '/qn', '/norestart', '/l*v', "`"$JournalRetrait`"")
    if ($code -eq 0) { Ok 'msiexec /x a rendu 0' } else { Fail "msiexec /x a rendu $code" }
    if (Get-Service -Name $NomService -ErrorAction SilentlyContinue) { Fail "service $NomService encore present" }
    else { Ok 'service retire' }
    if (Test-Path -LiteralPath $CleService) { Fail "cle $CleService encore presente" } else { Ok 'cle du service retiree' }
    if (Test-Path -LiteralPath $Installation) { Fail "$Installation encore present" } else { Ok "$Installation retire" }
    if (Test-Path -LiteralPath $CleArp) { Fail 'entree de Programmes et fonctionnalites encore presente' } else { Ok 'entree retiree' }
    if (Get-LocalGroup -Name $NomGroupe -ErrorAction SilentlyContinue) { Ok "groupe $NomGroupe conserve" }
    else { Fail "groupe $NomGroupe retire par la desinstallation" }
    if (Test-Path -LiteralPath $Donnees) {
        $restants = @(Get-ChildItem -LiteralPath $Donnees -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
        Ok ("$Donnees garde, {0} entree(s): {1}" -f $restants.Count, ($restants -join ', '))
    } else {
        Ok "$Donnees retire (vide: le service n'a jamais tourne)"
    }
    $journal = if (Test-Path -LiteralPath $JournalRetrait) { Get-Content -LiteralPath $JournalRetrait -Raw } else { '' }
    if ($journal -match '--cleanup-firewall') { Ok 'le journal nomme --cleanup-firewall' } else { Fail 'le journal ne nomme pas --cleanup-firewall' }
    if ($journal -match '--uninstall-service') { Ok 'le journal nomme --uninstall-service' } else { Fail 'le journal ne nomme pas --uninstall-service' }

    # ------------------------------------------- le resolveur deja pose
    Etape 'Resolveur deja pose: msiexec /i'
    # Le daemon n'exige du resolveur qu'un chemin absolu qui existe: une copie
    # de n'importe quel executable du systeme sert de factice.
    New-Item -ItemType Directory -Path $Installation | Out-Null
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -Destination $Factice
    $code = Msiexec @('/i', "`"$Msi`"", '/qn', '/norestart', '/l*v', "`"$JournalInstallationResolveur`"")
    if ($code -eq 0) { Ok 'msiexec /i a rendu 0' } else { Fail "msiexec /i a rendu $code" }
    $groupe = Get-LocalGroup -Name $NomGroupe -ErrorAction SilentlyContinue
    if ($groupe -and $groupe.SID.Value -eq $GroupeSid) { Ok 'groupe existant repris tel quel (meme SID)' }
    else { Fail 'le groupe a change entre les deux installations' }
    $attendue = "`"$Exe`" --service --resolveur-binaire `"$Factice`" --resolveur-utilisateur `"LocalService`" --group `"$GroupeSid`""
    $ligne = Ligne-DuService
    Write-Host ("        ligne: {0}" -f $ligne)
    if ($ligne -ceq $attendue) { Ok 'ligne identique a celle du script avec un resolveur pose' }
    else { Fail "ligne << $ligne >> au lieu de << $attendue >>" }
    $code = Msiexec @('/x', $ProductCode, '/qn', '/norestart', '/l*v', "`"$JournalRetraitResolveur`"")
    if ($code -eq 0) { Ok 'msiexec /x a rendu 0' } else { Fail "msiexec /x a rendu $code" }
    if (Get-Service -Name $NomService -ErrorAction SilentlyContinue) { Fail 'service encore present' } else { Ok 'service retire' }
    if (Test-Path -LiteralPath $Factice -PathType Leaf) { Ok 'le resolveur pose a la main reste en place (le MSI ne l''a pas pose)' }
    else { Fail 'le MSI a retire un fichier qu''il n''avait pas pose' }
} finally {
    # Filet: ne rien laisser de ce que la recette a cree. Un service subsistant
    # est retire par le daemon s'il est encore la; le factice et le repertoire
    # vide par leur nom; le groupe, qui n'existait pas avant la recette.
    if ((Get-Service -Name $NomService -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $Exe)) {
        & $Exe --uninstall-service 2>&1 | Out-Null
    }
    if (Test-Path -LiteralPath $Factice -PathType Leaf) { Remove-Item -LiteralPath $Factice -Force }
    if ((Test-Path -LiteralPath $Installation) -and @(Get-ChildItem -LiteralPath $Installation -Force).Count -eq 0) {
        Remove-Item -LiteralPath $Installation -Force
    }
    if (Get-LocalGroup -Name $NomGroupe -ErrorAction SilentlyContinue) { Remove-LocalGroup -Name $NomGroupe }
}

Etape 'Rien ne reste de la recette'
if (Get-Service -Name $NomService -ErrorAction SilentlyContinue) { Fail 'service residuel' } else { Ok 'aucun service' }
if (Get-LocalGroup -Name $NomGroupe -ErrorAction SilentlyContinue) { Fail 'groupe residuel' } else { Ok 'aucun groupe' }
if (Test-Path -LiteralPath $Installation) { Fail "$Installation residuel" } else { Ok "aucun $Installation" }

Write-Host ''
if ($script:Echecs -gt 0) {
    Write-Host ("installation reelle du MSI: {0} controle(s) en echec" -f $script:Echecs)
    exit 1
}
Write-Host 'installation reelle du MSI: tout est passe'

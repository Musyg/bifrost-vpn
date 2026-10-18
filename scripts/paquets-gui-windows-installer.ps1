<#
.SYNOPSIS
Installe et desinstalle REELLEMENT le MSI de la coquille graphique de Bifrost,
la lance sous la session elevee, et mesure ce que le systeme porte. Runner
jetable seulement.

.DESCRIPTION
Ce script modifie la machine: le MSI pose bifrost-gui.exe sous
%ProgramFiles%\Bifrost et un raccourci au Menu Demarrer. Il refuse de tourner
sans BIFROST_RUNNER_JETABLE=1, que seul le job paquets-gui-windows de la CI
pose, sur un runner jetable. Il exige une machine vierge pour la coquille
(aucun bifrost-gui.exe, aucun raccourci, aucun marqueur, aucune entree de
Programmes et fonctionnalites pour ce MSI); le dossier %ProgramFiles%\Bifrost,
partage avec le MSI du daemon, peut exister: il doit alors rester. Il ne touche
jamais au MSI du daemon.

Ce qu'il mesure (OK ou ECHEC par controle, code non nul s'il y a un ECHEC):
  1. msiexec /i: bifrost-gui.exe pose, a la version du workspace; le raccourci
     Bifrost a la racine du Menu Demarrer commun, vers l'exe pose; le marqueur
     HKCU du raccourci; l'entree de Programmes et fonctionnalites; aucun service,
     le groupe local Bifrost dans son etat d'avant; aucune valeur nouvelle sous
     Run ou RunOnce (HKLM, HKLM WOW6432Node, HKCU), aucune entree nouvelle dans
     les dossiers Demarrage, aucune tache planifiee nouvelle; MSI non signe;
     journal sans action de service;
  2. un lancement sous la session de ce script, elevee: la coquille refuse et
     sort en 3, avec son message sur stderr;
  3. msiexec /x: exe, raccourci, marqueur et entree retires; le dossier
     %ProgramFiles%\Bifrost retire s'il n'existait pas avant, garde sinon;
     groupe dans son etat d'avant; journal sans action de service.

Un lancement non eleve n'est pas joue: le runner tourne sous le compte
Administrateur predefini, dont le jeton n'est pas filtre, et rien sur la
machine n'offre un jeton ordinaire sans creer de compte.

.PARAMETER SortieMsi
Repertoire du MSI (bifrost-gui-<version>-x64.msi). Par defaut target\msi-gui.

.EXAMPLE
$env:BIFROST_RUNNER_JETABLE = '1'; .\scripts\paquets-gui-windows-installer.ps1
#>
[CmdletBinding()]
param(
    [string] $SortieMsi
)

$ErrorActionPreference = 'Stop'

$Racine = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
if (-not $SortieMsi) { $SortieMsi = Join-Path $Racine 'target\msi-gui' }
$NomService   = 'BifrostDaemon'
$NomGroupe    = 'Bifrost'
$Installation = Join-Path $env:ProgramFiles 'Bifrost'
$Exe          = Join-Path $Installation 'bifrost-gui.exe'
$Raccourci    = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Bifrost.lnk'
$CleMarqueur  = 'HKCU:\Software\Bifrost\GUI'
$ClesRun      = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
$DossiersDemarrage = @(
    (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup'),
    (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup')
)

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

# Ce qui fait demarrer un programme a l'ouverture de session ou plus tard: les
# valeurs sous Run et RunOnce, les entrees des dossiers Demarrage, les taches
# planifiees. Un releve avant, un apres, compares.
function Demarrages {
    $releve = @()
    foreach ($cle in $ClesRun) {
        if (-not (Test-Path -LiteralPath $cle)) { continue }
        $item = Get-Item -LiteralPath $cle
        foreach ($nom in $item.GetValueNames()) { $releve += ('{0}\{1}' -f $cle, $nom) }
    }
    foreach ($dossier in $DossiersDemarrage) {
        if (-not (Test-Path -LiteralPath $dossier)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $dossier -Force)) { $releve += $f.FullName }
    }
    foreach ($tache in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        $releve += ('tache {0}{1}' -f $tache.TaskPath, $tache.TaskName)
    }
    return ,($releve | Sort-Object)
}

# --------------------------------------------------------------- garde-fous
if ($env:BIFROST_RUNNER_JETABLE -ne '1') {
    Refus 'ce script installe et lance la coquille: runner jetable seulement (BIFROST_RUNNER_JETABLE=1).'
}
if (-not (Est-Administrateur)) { Refus 'droits administrateur exiges (msiexec).' }

$fichierMsi = @(Get-ChildItem -LiteralPath $SortieMsi -Filter 'bifrost-gui-*-x64.msi' -File -ErrorAction SilentlyContinue)
if ($fichierMsi.Count -ne 1) { Refus "il faut exactement un bifrost-gui-*-x64.msi sous $SortieMsi ($($fichierMsi.Count) trouve(s))" }
$Msi = $fichierMsi[0].FullName
$Version = Version-Workspace
if (-not $Version) { Refus 'version illisible dans Cargo.toml [workspace.package]' }
$ProductCode = Propriete-Msi $Msi 'ProductCode'
if (-not $ProductCode) { Refus 'ProductCode illisible dans le MSI' }
Write-Host "MSI: $Msi"
Write-Host "version: $Version, ProductCode: $ProductCode"
$CleArp = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode"
$JournalInstallation = Join-Path $SortieMsi 'installation.log'
$JournalRetrait      = Join-Path $SortieMsi 'desinstallation.log'
$ErreurEleve         = Join-Path $SortieMsi 'lancement-eleve.log'

Etape 'Machine vierge pour la coquille'
if (Test-Path -LiteralPath $CleArp) { Refus "une entree de Programmes et fonctionnalites existe deja pour $ProductCode" }
if (Test-Path -LiteralPath $Exe) { Refus "$Exe existe deja" }
if (Test-Path -LiteralPath $Raccourci) { Refus "$Raccourci existe deja" }
if (Test-Path -LiteralPath $CleMarqueur) { Refus "$CleMarqueur existe deja" }
$DossierAvant = Test-Path -LiteralPath $Installation
$GroupeAvant = [bool] (Get-LocalGroup -Name $NomGroupe -ErrorAction SilentlyContinue)
$ServiceAvant = [bool] (Get-Service -Name $NomService -ErrorAction SilentlyContinue)
$DemarragesAvant = Demarrages
Ok "ni exe, ni raccourci, ni marqueur, ni entree; $Installation present: $DossierAvant; groupe $NomGroupe present: $GroupeAvant; service $NomService present: $ServiceAvant"

try {
    # ---------------------------------------------------------- installation
    Etape 'msiexec /i'
    $code = Msiexec @('/i', "`"$Msi`"", '/qn', '/norestart', '/l*v', "`"$JournalInstallation`"")
    if ($code -eq 0) { Ok 'msiexec /i a rendu 0' } else { Fail "msiexec /i a rendu $code" }

    Etape 'Binaire'
    if (Test-Path -LiteralPath $Exe -PathType Leaf) {
        Ok "bifrost-gui.exe pose"
        $vi = (Get-Item -LiteralPath $Exe).VersionInfo
        if ($vi.ProductVersion -match ('^' + [regex]::Escape($Version))) { Ok "ProductVersion $($vi.ProductVersion)" }
        else { Fail "ProductVersion << $($vi.ProductVersion) >> sans $Version" }
    } else {
        Fail "bifrost-gui.exe absent de $Installation"
    }
    $autres = @(Get-ChildItem -LiteralPath $Installation -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'bifrost-gui.exe' } | ForEach-Object { $_.Name })
    Write-Host ("        autres entrees de {0}: {1}" -f $Installation, ($autres -join ', '))

    Etape 'Raccourci et marqueur'
    if (Test-Path -LiteralPath $Raccourci -PathType Leaf) {
        $lien = (New-Object -ComObject WScript.Shell).CreateShortcut($Raccourci)
        if ($lien.TargetPath -eq $Exe) { Ok "$Raccourci vers $Exe" } else { Fail "le raccourci vise $($lien.TargetPath)" }
    } else {
        Fail "raccourci absent: $Raccourci"
    }
    $marqueur = Get-ItemProperty -LiteralPath $CleMarqueur -Name 'installed' -ErrorAction SilentlyContinue
    if ($marqueur -and $marqueur.installed -eq 1) { Ok "$CleMarqueur installed=1 (KeyPath du raccourci)" }
    else { Fail "marqueur $CleMarqueur absent" }
    $bureau = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'Bifrost.lnk'
    if (Test-Path -LiteralPath $bureau) { Fail "raccourci sur le Bureau: $bureau" } else { Ok 'aucun raccourci sur le Bureau' }

    Etape 'Programmes et fonctionnalites'
    if (Test-Path -LiteralPath $CleArp) {
        $arp = Get-ItemProperty -LiteralPath $CleArp
        if ($arp.DisplayName -eq 'Bifrost GUI') { Ok 'DisplayName = Bifrost GUI' } else { Fail "DisplayName = $($arp.DisplayName)" }
        if ($arp.DisplayVersion -eq $Version) { Ok "DisplayVersion = $Version" } else { Fail "DisplayVersion = $($arp.DisplayVersion)" }
        if ($arp.Publisher -eq 'Bifrost') { Ok 'Publisher = Bifrost' } else { Fail "Publisher = $($arp.Publisher)" }
    } else {
        Fail "entree absente: $CleArp"
    }

    Etape 'Ni service, ni groupe, ni demarrage automatique'
    if ([bool] (Get-Service -Name $NomService -ErrorAction SilentlyContinue) -eq $ServiceAvant) { Ok "service $NomService dans son etat d'avant (present: $ServiceAvant)" }
    else { Fail "le MSI de la coquille a change la presence du service $NomService" }
    if ([bool] (Get-LocalGroup -Name $NomGroupe -ErrorAction SilentlyContinue) -eq $GroupeAvant) { Ok "groupe $NomGroupe dans son etat d'avant (present: $GroupeAvant)" }
    else { Fail "le MSI de la coquille a change la presence du groupe $NomGroupe" }
    $nouveaux = @((Demarrages) | Where-Object { $DemarragesAvant -notcontains $_ })
    if ($nouveaux.Count -eq 0) { Ok 'aucune valeur Run ou RunOnce, aucune entree Demarrage, aucune tache planifiee de plus' }
    else { Fail ("demarrage automatique ajoute: {0}" -f ($nouveaux -join ', ')) }

    Etape 'Journal et signature'
    $journal = if (Test-Path -LiteralPath $JournalInstallation) { Get-Content -LiteralPath $JournalInstallation -Raw } else { '' }
    if ($journal -match 'BifrostDaemon' -or $journal -match '--install-service') { Fail 'le journal d''installation nomme une action de service' }
    else { Ok 'le journal d''installation ne nomme aucune action de service' }
    $signature = (Get-AuthenticodeSignature -LiteralPath $Msi).Status
    if ($signature -eq 'NotSigned') { Ok 'MSI non signe' } else { Fail "signature: $signature" }

    # ------------------------------------------------------ lancement eleve
    Etape 'Lancement sous la session elevee: refus, code 3'
    if (Test-Path -LiteralPath $Exe -PathType Leaf) {
        # Process.Start garde la poignee du processus: son code de sortie se lit
        # meme s'il sort aussitot. L'objet que rend Start-Process -PassThru peut
        # ne pas la tenir, et son code de sortie est alors vide.
        $info = New-Object System.Diagnostics.ProcessStartInfo
        $info.FileName = $Exe
        $info.UseShellExecute = $false
        $info.RedirectStandardError = $true
        $info.CreateNoWindow = $true
        $p = [System.Diagnostics.Process]::Start($info)
        $lecture = $p.StandardError.ReadToEndAsync()
        if ($p.WaitForExit(15000)) {
            $p.WaitForExit()
            if ($p.ExitCode -eq 3) { Ok 'code 3' } else { Fail "code $($p.ExitCode) au lieu de 3" }
        } else {
            Stop-Process -Id $p.Id -Force
            Fail "aucune sortie en 15 s, processus $($p.Id) arrete par son PID (attendu: refus, code 3)"
        }
        $erreur = if ($lecture.Wait(5000)) { $lecture.Result } else { '' }
        Set-Content -LiteralPath $ErreurEleve -Value $erreur -Encoding ascii
        if ($erreur -match 'ne doit pas etre lance en administrateur') { Ok "message de refus sur stderr: $($erreur.Trim())" }
        else { Fail "message de refus absent de stderr: << $erreur >>" }
    } else {
        Fail 'pas de binaire a lancer'
    }

    # --------------------------------------------------------- desinstallation
    Etape 'msiexec /x'
    $code = Msiexec @('/x', $ProductCode, '/qn', '/norestart', '/l*v', "`"$JournalRetrait`"")
    if ($code -eq 0) { Ok 'msiexec /x a rendu 0' } else { Fail "msiexec /x a rendu $code" }
    if (Test-Path -LiteralPath $Exe) { Fail "$Exe encore present" } else { Ok 'bifrost-gui.exe retire' }
    if (Test-Path -LiteralPath $Raccourci) { Fail "$Raccourci encore present" } else { Ok 'raccourci retire' }
    if (Test-Path -LiteralPath $CleMarqueur) { Fail "$CleMarqueur encore present" } else { Ok 'marqueur retire' }
    if (Test-Path -LiteralPath $CleArp) { Fail 'entree de Programmes et fonctionnalites encore presente' } else { Ok 'entree retiree' }
    if ($DossierAvant) {
        if (Test-Path -LiteralPath $Installation) { Ok "$Installation garde (il existait avant)" } else { Fail "$Installation retire alors qu'il existait avant" }
    } else {
        if (Test-Path -LiteralPath $Installation) {
            $restants = @(Get-ChildItem -LiteralPath $Installation -Force | ForEach-Object { $_.Name })
            Fail ("$Installation reste, {0} entree(s): {1}" -f $restants.Count, ($restants -join ', '))
        } else {
            Ok "$Installation retire (cree par ce MSI, vide)"
        }
    }
    if ([bool] (Get-LocalGroup -Name $NomGroupe -ErrorAction SilentlyContinue) -eq $GroupeAvant) { Ok "groupe $NomGroupe dans son etat d'avant" }
    else { Fail "la desinstallation a change la presence du groupe $NomGroupe" }
    $journal = if (Test-Path -LiteralPath $JournalRetrait) { Get-Content -LiteralPath $JournalRetrait -Raw } else { '' }
    if ($journal -match 'BifrostDaemon' -or $journal -match '--uninstall-service' -or $journal -match '--cleanup-firewall') {
        Fail 'le journal de desinstallation nomme une action de service'
    } else {
        Ok 'le journal de desinstallation ne nomme aucune action de service'
    }
} finally {
    # Filet: ne rien laisser de la recette. Une coquille encore installee est
    # desinstallee par son ProductCode.
    if (Test-Path -LiteralPath $CleArp) {
        $null = Msiexec @('/x', $ProductCode, '/qn', '/norestart')
    }
}

Etape 'Rien ne reste de la recette'
if (Test-Path -LiteralPath $CleArp) { Fail 'entree residuelle' } else { Ok 'aucune entree de la coquille' }
if (Test-Path -LiteralPath $Exe) { Fail "$Exe residuel" } else { Ok 'aucun bifrost-gui.exe' }

Write-Host ''
if ($script:Echecs -gt 0) {
    Write-Host ("installation reelle du MSI de la coquille: {0} controle(s) en echec" -f $script:Echecs)
    exit 1
}
Write-Host 'installation reelle du MSI de la coquille: tout est passe'

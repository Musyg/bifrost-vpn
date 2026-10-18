<#
.SYNOPSIS
Construit et verifie le MSI de la coquille graphique de Bifrost
(bifrost-gui.exe). Pendant Windows de scripts/paquets-gui-linux.sh.

.DESCRIPTION
Dans l'ordre:
  1. lit la version du workspace (Cargo.toml, [workspace.package]) et refuse si
     gui/Cargo.toml ou gui/tauri.conf.json en annoncent une autre; lit
     l'editeur dans gui/tauri.conf.json (bundle.publisher) et refuse s'il
     manque;
  2. exige WiX 5.x dans le PATH (dotnet tool install --global wix --version
     5.0.2); sans lui, refuse. Aucune extension: ce MSI n'a aucune action
     personnalisee;
  3. exige gui\target\release\bifrost-gui.exe et
     target\release\bifrost-icone.exe, et que la ressource de version de la
     coquille porte la version du workspace et l'editeur (CompanyName);
  4. lit l'UpgradeCode des deux sources WiX, celle-ci et celle du daemon, et
     refuse s'ils sont egaux: chacun des deux MSI prendrait l'autre pour une
     version precedente de lui-meme et le retirerait;
  5. ecrit les icones par bifrost-icone.exe (bifrost.ico, hors de l'arbre
     versionne);
  6. construit le MSI (wix build -arch x64) et le valide par les ICE (wix msi
     validate), bloquant sur tout code non nul, borne par un delai;
  7. lit le MSI construit par COM, base ouverte en lecture seule, sans le
     service Windows Installer: un seul fichier (bifrost-gui.exe), les
     proprietes (Manufacturer: l'editeur), un seul raccourci, a la racine du
     Menu Demarrer et vers l'exe pose, une seule valeur de registre (le
     marqueur HKCU du raccourci), aucune action personnalisee, aucun service,
     aucun dossier Demarrage ni Bureau, ni %ProgramData%, et la condition sur
     la WebView2 (a cote de celle que WiX engendre pour MajorUpgrade);
  8. lit aussi ce qui regit la mise a niveau, comme scripts/paquets-windows.ps1
     pour le MSI du daemon: la table Upgrade (meme version comprise, plus
     recente refusee) et RemoveExistingProducts dans la transaction de la
     nouvelle version;
  9. ecrit l'empreinte SHA256 du MSI a cote.

Le MSI n'est pas signe: aucun certificat n'existe, et l'installation de
l'etape suivante (scripts/paquets-gui-windows-installer.ps1) verifie qu'il ne
l'est pas.

Le repertoire de sortie, target\msi-gui, doit etre neuf: le script refuse un
repertoire qui n'est pas vide plutot que d'y melanger deux constructions.

.PARAMETER Coquille
Repertoire de bifrost-gui.exe. Par defaut gui\target\release a la racine du
depot.

.PARAMETER Binaires
Repertoire de bifrost-icone.exe. Par defaut target\release a la racine du
depot.

.EXAMPLE
.\scripts\paquets-gui-windows.ps1
#>
[CmdletBinding()]
param(
    [string] $Coquille,
    [string] $Binaires
)

$ErrorActionPreference = 'Stop'

$Racine = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
if (-not $Coquille) { $Coquille = Join-Path $Racine 'gui\target\release' }
if (-not $Binaires) { $Binaires = Join-Path $Racine 'target\release' }
$Wxs = Join-Path $Racine 'packaging\msi\bifrost-gui.wxs'
$WxsDaemon = Join-Path $Racine 'packaging\msi\bifrost.wxs'
$SortieMsi = Join-Path $Racine 'target\msi-gui'
$Icones = Join-Path $SortieMsi 'icones'

$script:Echecs = 0
function Ok    ([string] $m) { Write-Host ('  OK    {0}' -f $m) }
function Fail  ([string] $m) { Write-Host ('  ECHEC {0}' -f $m); $script:Echecs++ }
function Etape ([string] $m) { Write-Host ''; Write-Host ('== {0}' -f $m) }
function Saut  ([string] $m) { Write-Host ('  SKIPPED: {0}' -f $m) }
function Refus ([string] $m) { Write-Host ('REFUS: {0}' -f $m); exit 1 }

# La version de la section [section] d'un Cargo.toml.
function Version-DansSection ([string] $fichier, [string] $section) {
    $dans = $false
    foreach ($ligne in (Get-Content -LiteralPath $fichier)) {
        $t = $ligne.Trim()
        if ($t.StartsWith('[')) { $dans = ($t -eq $section); continue }
        if (-not $dans) { continue }
        if ($t -match '^version\s*=\s*"([^"]+)"') { return $Matches[1] }
    }
    return $null
}

function UpgradeCode-De ([string] $wxs) {
    $contenu = Get-Content -LiteralPath $wxs -Raw
    if ($contenu -match 'UpgradeCode="([0-9A-Fa-f-]{36})"') { return $Matches[1] }
    return $null
}

# Les lignes d'une requete sur le MSI, base ouverte en lecture seule (mode 0).
# $null = devant Execute: la valeur rendue par une methode COM non capturee
# entrerait dans la sortie de la fonction.
function Lignes-Msi ([string] $msi, [string] $requete, [int] $colonnes) {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $db = $installer.OpenDatabase($msi, 0)
    $vue = $db.OpenView($requete)
    $null = $vue.Execute()
    $lignes = @()
    while ($true) {
        $rec = $vue.Fetch()
        if ($null -eq $rec) { break }
        $champs = @()
        for ($i = 1; $i -le $colonnes; $i++) { $champs += $rec.StringData($i) }
        $lignes += ,$champs
    }
    $null = $vue.Close()
    return ,$lignes
}

function Table-Existe ([string] $msi, [string] $table) {
    $lignes = Lignes-Msi $msi ("SELECT ``Name`` FROM ``_Tables`` WHERE ``Name`` = '{0}'" -f $table) 1
    return ($lignes.Count -gt 0)
}

# Le nombre de lignes d'une table, 0 si elle n'existe pas.
function Lignes-DeTable ([string] $msi, [string] $table, [string] $colonne) {
    if (-not (Table-Existe $msi $table)) { return 0 }
    return (Lignes-Msi $msi ("SELECT ``{0}`` FROM ``{1}``" -f $colonne, $table) 1).Count
}

Etape 'Version et editeur'
$Version = Version-DansSection (Join-Path $Racine 'Cargo.toml') '[workspace.package]'
if (-not $Version) { Refus 'version illisible dans Cargo.toml [workspace.package]' }
$VersionGui = Version-DansSection (Join-Path $Racine 'gui\Cargo.toml') '[package]'
if ($VersionGui -ne $Version) { Refus "gui/Cargo.toml annonce $VersionGui, le workspace $Version" }
$conf = Get-Content -LiteralPath (Join-Path $Racine 'gui\tauri.conf.json') -Raw | ConvertFrom-Json
if ($conf.version -ne $Version) { Refus "gui/tauri.conf.json annonce $($conf.version), le workspace $Version" }
Ok "version: $Version (gui/Cargo.toml et gui/tauri.conf.json concordent)"
# L'editeur n'a qu'une source, bundle.publisher: tauri-build l'ecrit dans le
# CompanyName de l'executable (absent, il y ecrit le deuxieme element de
# l'identifiant), et le MSI doit porter le meme en Manufacturer.
$Editeur = $conf.bundle.publisher
if (-not $Editeur) { Refus 'gui/tauri.conf.json sans bundle.publisher: tauri-build ecrirait dans CompanyName le deuxieme element de l''identifiant' }
Ok "editeur: $Editeur (gui/tauri.conf.json, bundle.publisher)"

Etape 'WiX 5'
$wix = Get-Command wix -ErrorAction SilentlyContinue
if (-not $wix) { Refus 'wix introuvable (dotnet tool install --global wix --version 5.0.2)' }
$wixVersion = ((& wix --version) | Out-String).Trim()
if (-not $wixVersion.StartsWith('5.')) {
    Refus "WiX ${wixVersion}: la serie 5 est exigee (dotnet tool install --global wix --version 5.0.2)"
}
Ok "wix $wixVersion"

Etape 'Binaires'
$Exe = Join-Path $Coquille 'bifrost-gui.exe'
if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) {
    Refus "binaire introuvable: $Exe (cargo build --release --manifest-path gui/Cargo.toml --locked)"
}
$IconeExe = Join-Path $Binaires 'bifrost-icone.exe'
if (-not (Test-Path -LiteralPath $IconeExe -PathType Leaf)) {
    Refus "binaire introuvable: $IconeExe (cargo build --release --locked -p bifrost-icone)"
}
# La coquille n'a pas de --version: sa ressource de version, que tauri-build
# compile depuis gui/tauri.conf.json, porte la version et l'editeur.
$vi = (Get-Item -LiteralPath $Exe).VersionInfo
if ($vi.ProductVersion -notmatch ('^' + [regex]::Escape($Version))) {
    Refus "ressource de version de bifrost-gui.exe: ProductVersion << $($vi.ProductVersion) >>, sans la version du workspace ($Version)"
}
if ($vi.CompanyName -cne $Editeur) {
    Refus "ressource de version de bifrost-gui.exe: CompanyName << $($vi.CompanyName) >>, l'editeur de gui/tauri.conf.json est << $Editeur >>"
}
Ok "bifrost-gui.exe: ProductVersion $($vi.ProductVersion), FileVersion $($vi.FileVersion), CompanyName $($vi.CompanyName)"

Etape 'UpgradeCode distinct de celui du daemon'
$Upgrade = UpgradeCode-De $Wxs
$UpgradeDaemon = UpgradeCode-De $WxsDaemon
if (-not $Upgrade -or -not $UpgradeDaemon) { Refus "UpgradeCode illisible dans $Wxs ou $WxsDaemon" }
if ($Upgrade -eq $UpgradeDaemon) {
    Refus "le MSI de la coquille reprend l'UpgradeCode du daemon ($Upgrade): chacun retirerait l'autre"
}
Ok "coquille $Upgrade, daemon $UpgradeDaemon"

Etape 'Repertoire de sortie'
if (Test-Path -LiteralPath $SortieMsi) {
    if (@(Get-ChildItem -LiteralPath $SortieMsi -Force).Count -gt 0) {
        Refus "$SortieMsi n'est pas vide (le vider, ou construire dans un arbre neuf)"
    }
} else {
    New-Item -ItemType Directory -Path $SortieMsi | Out-Null
}
New-Item -ItemType Directory -Path $Icones | Out-Null
Ok $SortieMsi

Etape 'Icones (bifrost-icone)'
& $IconeExe $Icones | Out-Null
if ($LASTEXITCODE -ne 0) { Refus "bifrost-icone a rendu $LASTEXITCODE" }
$Ico = Join-Path $Icones 'bifrost.ico'
if (-not (Test-Path -LiteralPath $Ico -PathType Leaf)) { Refus "bifrost.ico absent de $Icones" }
Ok $Ico

Etape 'Construction du MSI (wix build)'
$Msi = Join-Path $SortieMsi ("bifrost-gui-{0}-x64.msi" -f $Version)
& wix build -arch x64 `
    -d "Version=$Version" `
    -d "Binaires=$Coquille" `
    -d "Icone=$Ico" `
    -o $Msi `
    $Wxs
if ($LASTEXITCODE -ne 0) { Refus "wix build a rendu $LASTEXITCODE" }
if (-not (Test-Path -LiteralPath $Msi -PathType Leaf)) { Refus "wix build n'a produit aucun MSI: $Msi" }
Ok $Msi

Etape 'Validation ICE (wix msi validate)'
# Bornee comme pour le MSI du daemon: terminee dans le delai, son code fait foi
# et un code non nul arrete le script; depassee, l'arbre du processus est tue
# par son PID (jamais par son nom) et le depassement est dit (SKIPPED).
$DelaiIce = 300
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $wix.Source
$psi.Arguments = 'msi validate "{0}"' -f $Msi
$psi.UseShellExecute = $false
$proc = [System.Diagnostics.Process]::Start($psi)
if ($proc.WaitForExit($DelaiIce * 1000)) {
    if ($proc.ExitCode -ne 0) { Refus "wix msi validate a rendu $($proc.ExitCode) (au moins une ICE en echec)" }
    Ok 'ICE: aucune erreur (code 0)'
} else {
    & taskkill /PID $proc.Id /T /F | Out-Null
    Saut "validation ICE non terminee en ${DelaiIce} s, processus $($proc.Id) arrete par son PID"
}

Etape 'Fichiers du MSI (table File)'
# FileName porte << court|long >>: le nom long suit la barre.
$noms = @()
foreach ($l in (Lignes-Msi $Msi 'SELECT `FileName` FROM `File`' 1)) {
    $brut = $l[0]
    if ($brut.Contains('|')) { $brut = $brut.Substring($brut.IndexOf('|') + 1) }
    $noms += $brut.ToLowerInvariant()
}
$lus = ($noms | Sort-Object) -join ', '
if ($lus -eq 'bifrost-gui.exe') { Ok "le MSI porte exactement: $lus" }
else { Fail "table File: [$lus] au lieu de [bifrost-gui.exe]" }

Etape 'Proprietes du MSI'
$attendues = [ordered]@{
    'ProductName'     = 'Bifrost GUI'
    'Manufacturer'    = $Editeur
    'ProductVersion'  = $Version
    'UpgradeCode'     = ('{{{0}}}' -f $Upgrade)
    'ARPURLINFOABOUT' = 'https://github.com/Musyg/bifrost-vpn'
}
foreach ($nom in $attendues.Keys) {
    $lignes = Lignes-Msi $Msi ("SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = '{0}'" -f $nom) 1
    if ($lignes.Count -eq 0) { Fail "propriete $nom absente"; continue }
    $lu = $lignes[0][0]
    if ($lu.ToUpperInvariant() -eq $attendues[$nom].ToUpperInvariant()) { Ok "$nom = $lu" }
    else { Fail "$nom = << $lu >> au lieu de << $($attendues[$nom]) >>" }
}

Etape 'Raccourci (table Shortcut)'
$raccourcis = Lignes-Msi $Msi 'SELECT `Directory_`, `Name`, `Target` FROM `Shortcut`' 3
if ($raccourcis.Count -ne 1) {
    Fail "$($raccourcis.Count) raccourci(s) au lieu d'un"
} else {
    $r = $raccourcis[0]
    Write-Host ('        {0} | {1} | {2}' -f $r[0], $r[1], $r[2])
    if ($r[0] -eq 'ProgramMenuFolder') { Ok 'a la racine du Menu Demarrer commun' } else { Fail "dans $($r[0]) au lieu de ProgramMenuFolder" }
    if ($r[2] -eq '[INSTALLFOLDER]bifrost-gui.exe') { Ok 'vers [INSTALLFOLDER]bifrost-gui.exe, non annonce' }
    else { Fail "cible << $($r[2]) >> au lieu de [INSTALLFOLDER]bifrost-gui.exe" }
}

Etape 'Registre (table Registry): le seul marqueur HKCU du raccourci'
# Root: 1 = HKCU, 2 = HKLM. Aucune valeur sous Run ou RunOnce.
$valeurs = @()
if (Table-Existe $Msi 'Registry') {
    $valeurs = Lignes-Msi $Msi 'SELECT `Root`, `Key`, `Name`, `Value` FROM `Registry`' 4
}
foreach ($v in $valeurs) { Write-Host ('        racine {0} | {1} | {2} = {3}' -f $v[0], $v[1], $v[2], $v[3]) }
$autostart = @($valeurs | Where-Object { $_[1] -match '\\CurrentVersion\\Run' })
if ($autostart.Count -eq 0) { Ok 'aucune valeur sous CurrentVersion\Run ni RunOnce' } else { Fail "$($autostart.Count) valeur(s) de demarrage automatique" }
if ($valeurs.Count -eq 1 -and $valeurs[0][0] -eq '1' -and $valeurs[0][1] -eq 'Software\Bifrost\GUI' -and $valeurs[0][2] -eq 'installed') {
    Ok 'une seule valeur: HKCU Software\Bifrost\GUI installed'
} else {
    Fail "$($valeurs.Count) valeur(s) de registre, attendu le seul marqueur HKCU Software\Bifrost\GUI installed"
}

Etape 'Ni action, ni service, ni dossier Demarrage, Bureau ou ProgramData'
foreach ($t in @(@('CustomAction', 'Action'), @('ServiceInstall', 'ServiceInstall'), @('ServiceControl', 'ServiceControl'))) {
    $n = Lignes-DeTable $Msi $t[0] $t[1]
    if ($n -eq 0) { Ok "table $($t[0]) absente ou vide" } else { Fail "table $($t[0]): $n ligne(s)" }
}
$repertoires = @((Lignes-Msi $Msi 'SELECT `Directory` FROM `Directory`' 1) | ForEach-Object { $_[0] })
$interdits = @($repertoires | Where-Object { @('StartupFolder', 'DesktopFolder', 'CommonAppDataFolder') -contains $_ })
if ($interdits.Count -eq 0) { Ok ("repertoires: {0}" -f ($repertoires -join ', ')) } else { Fail ("repertoires interdits: {0}" -f ($interdits -join ', ')) }

Etape 'Condition sur la WebView2 (table LaunchCondition)'
# Deux lignes: la condition sur la WebView2 du .wxs, et celle que WiX engendre
# pour MajorUpgrade (DowngradeErrorMessage), sur WIX_DOWNGRADE_DETECTED.
$conditions = @((Lignes-Msi $Msi 'SELECT `Condition` FROM `LaunchCondition`' 1) | ForEach-Object { $_[0] })
foreach ($c in $conditions) { Write-Host "        $c" }
$webview = @($conditions | Where-Object { $_.StartsWith('Installed OR') -and $_.Contains('WEBVIEW2HKLM') -and $_.Contains('WEBVIEW2HKCU') })
$autres = @($conditions | Where-Object { -not ($_.StartsWith('Installed OR') -and $_.Contains('WEBVIEW2HKLM')) })
if ($webview.Count -eq 1) { Ok 'une condition sur la WebView2 (HKLM ou HKCU), levee si deja installe' }
else { Fail "conditions sur la WebView2: $($webview.Count) au lieu de 1" }
$inattendues = @($autres | Where-Object { -not $_.Contains('WIX_DOWNGRADE_DETECTED') })
if ($inattendues.Count -eq 0) { Ok "aucune autre condition que celle de MajorUpgrade ($($autres.Count))" }
else { Fail ("condition(s) inattendue(s): {0}" -f ($inattendues -join ' ; ')) }

Etape 'Mise a niveau: meme version comprise'
# Ce que WiX a ecrit, pas ce que le .wxs demande, comme pour le MSI du daemon.
# Deux lignes Upgrade et pas d'autre: la premiere retire toute version
# anterieure OU EGALE (Attributes 513 = VersionMaxInclusive 0x200 +
# MigrateFeatures 0x1, que l'ICE61 signale en avertissement), la seconde
# detecte une version plus recente, que la condition de lancement refuse.
# Sans la borne inclusive, deux MSI de la meme version seraient deux
# installations distinctes.
$attenduesUpgrade = @(
    ('{{{0}}}||{1}|513|WIX_UPGRADE_DETECTED' -f $Upgrade, $Version).ToUpperInvariant(),
    ('{{{0}}}|{1}||2|WIX_DOWNGRADE_DETECTED' -f $Upgrade, $Version).ToUpperInvariant()
) | Sort-Object
$luesUpgrade = @()
foreach ($l in (Lignes-Msi $Msi 'SELECT `UpgradeCode`, `VersionMin`, `VersionMax`, `Attributes`, `ActionProperty` FROM `Upgrade`' 5)) {
    $luesUpgrade += ($l -join '|').ToUpperInvariant()
}
$luesUpgrade = @($luesUpgrade | Sort-Object)
if (($luesUpgrade -join ';') -ceq ($attenduesUpgrade -join ';')) {
    Ok 'table Upgrade: version anterieure ou egale retiree (513), plus recente refusee (2)'
} else {
    Fail "table Upgrade: [$($luesUpgrade -join '; ')] au lieu de [$($attenduesUpgrade -join '; ')]"
}
# L'ancienne version est retiree dans la transaction de la nouvelle
# (afterInstallInitialize): un echec de la nouvelle la restaure.
$sequence = @{}
foreach ($l in (Lignes-Msi $Msi 'SELECT `Action`, `Sequence`, `Condition` FROM `InstallExecuteSequence`' 3)) {
    $sequence[$l[0]] = $l
}
$rep = $sequence['RemoveExistingProducts']
if ($null -ne $rep -and
    [int]$sequence['InstallInitialize'][1] -lt [int]$rep[1] -and
    [int]$rep[1] -lt [int]$sequence['ProcessComponents'][1]) {
    Ok "RemoveExistingProducts ($($rep[1])) entre InstallInitialize et ProcessComponents"
} else {
    Fail "RemoveExistingProducts hors de la transaction de la nouvelle version: $($rep -join ' | ')"
}

Etape 'Empreinte SHA256 du MSI'
$hash = (Get-FileHash -LiteralPath $Msi -Algorithm SHA256).Hash.ToLowerInvariant()
$fichierHash = "$Msi.sha256"
Set-Content -LiteralPath $fichierHash -Value ("{0}  {1}" -f $hash, (Split-Path -Leaf $Msi)) -Encoding ascii -NoNewline
Ok "$fichierHash ($hash)"

Write-Host ''
if ($script:Echecs -gt 0) {
    Write-Host ("MSI de la coquille: {0} controle(s) en echec" -f $script:Echecs)
    exit 1
}
Write-Host "MSI de la coquille: tout est conforme (sortie: $SortieMsi)"

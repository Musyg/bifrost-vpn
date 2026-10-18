<#
.SYNOPSIS
Construit et verifie le MSI de Bifrost (daemon et client). Pendant Windows de
scripts/paquets-linux.sh.

.DESCRIPTION
Dans l'ordre:
  1. lit la version du workspace (Cargo.toml, [workspace.package]);
  2. exige WiX 5.x dans le PATH (dotnet tool install --global wix --version
     5.0.2) et l'extension util de la meme version; sans eux, refuse;
  3. exige target\release\bifrost-daemon.exe, bifrost-cli.exe et
     bifrost-icone.exe, et que le --version des deux premiers porte la version
     du workspace;
  4. ecrit les icones par bifrost-icone.exe (bifrost.ico, hors de l'arbre
     versionne);
  5. construit le MSI (wix build -arch x64) et le valide par les ICE (wix msi
     validate), bloquant sur tout code non nul, borne par un delai;
  6. lit le MSI construit par COM, base ouverte en lecture seule, sans le
     service Windows Installer: les fichiers (exactement les deux binaires), les
     proprietes, les actions personnalisees (la ligne qui enregistre le service
     et celle qui cree le groupe d'acces, les memes que
     packaging/install-windows.ps1), et l'absence de ServiceInstall;
  7. lit aussi ce qui regit la mise a niveau: la table Upgrade (meme version
     comprise, plus recente refusee), RemoveExistingProducts dans la
     transaction de la nouvelle version, et les conditions qui gardent le
     service existant;
  8. ecrit l'empreinte SHA256 du MSI a cote.

Le MSI n'est pas signe: aucun certificat n'existe, et l'installation de
l'etape suivante (scripts/paquets-windows-installer.ps1) verifie qu'il ne l'est
pas.

Le repertoire de sortie, target\msi, doit etre neuf: le script refuse un
repertoire qui n'est pas vide plutot que d'y melanger deux constructions.

.PARAMETER Binaires
Repertoire de bifrost-daemon.exe, bifrost-cli.exe et bifrost-icone.exe. Par
defaut target\release a la racine du depot.

.EXAMPLE
.\scripts\paquets-windows.ps1
#>
[CmdletBinding()]
param(
    [string] $Binaires
)

$ErrorActionPreference = 'Stop'

$Racine = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
if (-not $Binaires) { $Binaires = Join-Path $Racine 'target\release' }
$Wxs = Join-Path $Racine 'packaging\msi\bifrost.wxs'
# Les noms de variables PowerShell ignorent la casse: aucune autre variable de
# ce script ne s'appelle RepertoireMsi, sous aucune casse.
$RepertoireMsi = Join-Path $Racine 'target\msi'
$Icones = Join-Path $RepertoireMsi 'icones'

$script:Echecs = 0
function Ok    ([string] $m) { Write-Host ('  OK    {0}' -f $m) }
function Fail  ([string] $m) { Write-Host ('  ECHEC {0}' -f $m); $script:Echecs++ }
function Etape ([string] $m) { Write-Host ''; Write-Host ('== {0}' -f $m) }
function Saut  ([string] $m) { Write-Host ('  SKIPPED: {0}' -f $m) }
function Refus ([string] $m) { Write-Host ('REFUS: {0}' -f $m); exit 1 }

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

function UpgradeCode-DuWxs {
    $contenu = Get-Content -LiteralPath $Wxs -Raw
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

Etape 'Version du workspace'
$Version = Version-Workspace
if (-not $Version) { Refus 'version illisible dans Cargo.toml [workspace.package]' }
Ok "version: $Version"

Etape 'WiX 5'
$wix = Get-Command wix -ErrorAction SilentlyContinue
if (-not $wix) { Refus 'wix introuvable (dotnet tool install --global wix --version 5.0.2)' }
$wixVersion = ((& wix --version) | Out-String).Trim()
if (-not $wixVersion.StartsWith('5.')) {
    Refus "WiX ${wixVersion}: la serie 5 est exigee (dotnet tool install --global wix --version 5.0.2)"
}
Ok "wix $wixVersion"
$extensions = ((& wix extension list -g) | Out-String)
if ($extensions -notmatch 'WixToolset\.Util\.wixext\s+5\.') {
    Refus "extension WixToolset.Util.wixext 5.x absente (wix extension add -g WixToolset.Util.wixext/5.0.2): $($extensions.Trim())"
}
Ok 'extension WixToolset.Util.wixext 5.x'

Etape 'Binaires'
foreach ($b in 'bifrost-daemon.exe', 'bifrost-cli.exe', 'bifrost-icone.exe') {
    $chemin = Join-Path $Binaires $b
    if (-not (Test-Path -LiteralPath $chemin -PathType Leaf)) {
        Refus "binaire introuvable: $chemin (cargo build --release -p bifrost-daemon -p bifrost-cli -p bifrost-icone --locked)"
    }
}
foreach ($b in 'bifrost-daemon.exe', 'bifrost-cli.exe') {
    $exe = Join-Path $Binaires $b
    $ancienne = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $texteVersion = (& $exe --version 2>&1 | Out-String).Trim() } finally { $ErrorActionPreference = $ancienne }
    if ($texteVersion -notmatch [regex]::Escape($Version)) {
        Refus "$b --version rend << $texteVersion >>, sans la version du workspace ($Version)"
    }
    Ok "$b --version porte $Version"
}

Etape 'Repertoire de sortie'
if (Test-Path -LiteralPath $RepertoireMsi) {
    if (@(Get-ChildItem -LiteralPath $RepertoireMsi -Force).Count -gt 0) {
        Refus "$RepertoireMsi n'est pas vide (le vider, ou construire dans un arbre neuf)"
    }
} else {
    New-Item -ItemType Directory -Path $RepertoireMsi | Out-Null
}
New-Item -ItemType Directory -Path $Icones | Out-Null
Ok $RepertoireMsi

Etape 'Icones (bifrost-icone)'
& (Join-Path $Binaires 'bifrost-icone.exe') $Icones | Out-Null
if ($LASTEXITCODE -ne 0) { Refus "bifrost-icone a rendu $LASTEXITCODE" }
$Ico = Join-Path $Icones 'bifrost.ico'
if (-not (Test-Path -LiteralPath $Ico -PathType Leaf)) { Refus "bifrost.ico absent de $Icones" }
Ok $Ico

Etape 'Construction du MSI (wix build)'
$Msi = Join-Path $RepertoireMsi ("bifrost-{0}-x64.msi" -f $Version)
& wix build -arch x64 `
    -d "Version=$Version" `
    -d "Binaires=$Binaires" `
    -d "Icone=$Ico" `
    -ext WixToolset.Util.wixext `
    -o $Msi `
    $Wxs
if ($LASTEXITCODE -ne 0) { Refus "wix build a rendu $LASTEXITCODE" }
if (-not (Test-Path -LiteralPath $Msi -PathType Leaf)) { Refus "wix build n'a produit aucun MSI: $Msi" }
Ok $Msi

Etape 'Validation ICE (wix msi validate)'
# Les ICE sont jouees par le moteur Windows Installer. Elles peuvent ne jamais
# rendre la main sous un compte de service sans bureau: la validation est donc
# bornee. Terminee dans le delai, son code fait foi et un code non nul arrete
# le script. Depassee, l'arbre du processus est tue par son PID (jamais par son
# nom) et le depassement est dit (SKIPPED), sans masquer le reste.
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
if ($lus -eq 'bifrost-cli.exe, bifrost-daemon.exe') { Ok "le MSI porte exactement: $lus" }
else { Fail "table File: [$lus] au lieu de [bifrost-cli.exe, bifrost-daemon.exe]" }

Etape 'Proprietes du MSI'
$upgrade = UpgradeCode-DuWxs
if (-not $upgrade) { Fail 'UpgradeCode illisible dans le .wxs' }
$attendues = [ordered]@{
    'ProductName'     = 'Bifrost'
    'Manufacturer'    = 'Bifrost'
    'ProductVersion'  = $Version
    'UpgradeCode'     = ('{{{0}}}' -f $upgrade)
    'ARPURLINFOABOUT' = 'https://github.com/Musyg/bifrost-vpn'
}
foreach ($nom in $attendues.Keys) {
    $lignes = Lignes-Msi $Msi ("SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = '{0}'" -f $nom) 1
    if ($lignes.Count -eq 0) { Fail "propriete $nom absente"; continue }
    $lu = $lignes[0][0]
    if ($lu.ToUpperInvariant() -eq $attendues[$nom].ToUpperInvariant()) { Ok "$nom = $lu" }
    else { Fail "$nom = << $lu >> au lieu de << $($attendues[$nom]) >>" }
}

Etape 'Le service est enregistre par le daemon, pas par une table ServiceInstall'
if (Table-Existe $Msi 'ServiceInstall') {
    $n = (Lignes-Msi $Msi 'SELECT `ServiceInstall` FROM `ServiceInstall`' 1).Count
    if ($n -eq 0) { Ok 'table ServiceInstall vide' } else { Fail "table ServiceInstall: $n ligne(s)" }
} else {
    Ok 'aucune table ServiceInstall'
}

Etape 'Actions personnalisees (table CustomAction)'
$actions = @{}
foreach ($l in (Lignes-Msi $Msi 'SELECT `Action`, `Type`, `Source`, `Target` FROM `CustomAction`' 4)) {
    $actions[$l[0]] = $l
    Write-Host ('        {0} type {1} source {2}: {3}' -f $l[0], $l[1], $l[2], $l[3])
}
$cibles = [ordered]@{
    'BifrostServiceInstall'          = '--install-service --group Bifrost'
    'BifrostServiceInstallResolveur' = '--install-service --resolveur-binaire "[INSTALLFOLDER]dnscrypt-proxy.exe" --resolveur-utilisateur LocalService --group Bifrost'
    'BifrostServiceRollback'         = '--uninstall-service'
    'BifrostCleanupFirewall'         = '--cleanup-firewall'
    'BifrostServiceUninstall'        = '--uninstall-service'
}
foreach ($nom in $cibles.Keys) {
    if (-not $actions.ContainsKey($nom)) { Fail "action $nom absente"; continue }
    if ($actions[$nom][3] -ceq $cibles[$nom]) { Ok "$nom lance le daemon avec << $($cibles[$nom]) >>" }
    else { Fail "${nom}: << $($actions[$nom][3]) >> au lieu de << $($cibles[$nom]) >>" }
}
# La ligne net.exe est la cible de l'action immediate que WiX engendre pour la
# SetProperty du groupe: la valeur que l'action differee recoit.
$groupe = @($actions.Values | Where-Object { $_[3] -like '*net.exe*localgroup Bifrost /add*' })
$commentaire = "/comment:`"Acces sans elevation au canal de BifrostDaemon`""
if ($groupe.Count -eq 1 -and $groupe[0][3].EndsWith($commentaire)) {
    Ok 'le groupe local Bifrost est cree par net.exe, avec le commentaire de install-windows.ps1'
} else {
    Fail "aucune action unique ne cree le groupe local Bifrost avec le commentaire attendu ($($groupe.Count) trouvee(s))"
}

Etape 'Mise a niveau: meme version comprise, service garde'
# Ce que WiX a ecrit, pas ce que le .wxs demande. Deux lignes Upgrade et pas
# d'autre: la premiere retire toute version anterieure OU EGALE (Attributes
# 513 = VersionMaxInclusive 0x200 + MigrateFeatures 0x1, que l'ICE61 signale
# en avertissement), la seconde detecte une version plus recente, que la
# condition de lancement refuse.
$attenduesUpgrade = @(
    ('{{{0}}}||{1}|513|WIX_UPGRADE_DETECTED' -f $upgrade, $Version).ToUpperInvariant(),
    ('{{{0}}}|{1}||2|WIX_DOWNGRADE_DETECTED' -f $upgrade, $Version).ToUpperInvariant()
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
# Le service de l'ancienne version n'est ni retire par sa desinstallation
# pendant une mise a niveau, ni par le retour arriere s'il existait avant.
$conditions = [ordered]@{
    'BifrostServiceRollback'  = 'NOT Installed AND NOT BIFROSTSERVICEEXISTANT'
    'BifrostCleanupFirewall'  = 'REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE'
    'BifrostServiceUninstall' = 'REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE'
}
foreach ($nom in $conditions.Keys) {
    if (-not $sequence.ContainsKey($nom)) { Fail "action $nom absente de la sequence"; continue }
    if ($sequence[$nom][2] -ceq $conditions[$nom]) { Ok "$nom sous << $($conditions[$nom]) >>" }
    else { Fail "${nom}: condition << $($sequence[$nom][2]) >> au lieu de << $($conditions[$nom]) >>" }
}
# BIFROSTSERVICEEXISTANT vient de la cle du service (ImagePath, vue 64 bits,
# brute) et passe a la phase serveur (SecureCustomProperties).
$recherche = @()
if (Table-Existe $Msi 'RegLocator') {
    foreach ($l in (Lignes-Msi $Msi 'SELECT `Signature_`, `Root`, `Key`, `Name`, `Type` FROM `RegLocator`' 5)) {
        if ($l[0] -ceq 'RechercheService') { $recherche += ($l -join '|') }
    }
}
$appSearch = @()
foreach ($l in (Lignes-Msi $Msi 'SELECT `Property`, `Signature_` FROM `AppSearch`' 2)) {
    if ($l[0] -ceq 'BIFROSTSERVICEEXISTANT') { $appSearch += ($l -join '|') }
}
$attendueRecherche = 'RechercheService|2|SYSTEM\CurrentControlSet\Services\BifrostDaemon|ImagePath|18'
if ($recherche.Count -eq 1 -and $recherche[0] -ceq $attendueRecherche -and
    $appSearch.Count -eq 1 -and $appSearch[0] -ceq 'BIFROSTSERVICEEXISTANT|RechercheService') {
    Ok 'BIFROSTSERVICEEXISTANT lit la cle du service (RegLocator 64 bits, brut)'
} else {
    Fail "recherche de BIFROSTSERVICEEXISTANT: RegLocator [$($recherche -join '; ')], AppSearch [$($appSearch -join '; ')]"
}
$securisees = @()
foreach ($l in (Lignes-Msi $Msi "SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = 'SecureCustomProperties'" 1)) {
    $securisees += $l[0].Split(';')
}
if ($securisees -ccontains 'BIFROSTSERVICEEXISTANT') { Ok 'BIFROSTSERVICEEXISTANT est dans SecureCustomProperties' }
else { Fail "SecureCustomProperties sans BIFROSTSERVICEEXISTANT: $($securisees -join ';')" }

Etape 'Empreinte SHA256 du MSI'
$hash = (Get-FileHash -LiteralPath $Msi -Algorithm SHA256).Hash.ToLowerInvariant()
$fichierHash = "$Msi.sha256"
Set-Content -LiteralPath $fichierHash -Value ("{0}  {1}" -f $hash, (Split-Path -Leaf $Msi)) -Encoding ascii -NoNewline
Ok "$fichierHash ($hash)"

Write-Host ''
if ($script:Echecs -gt 0) {
    Write-Host ("MSI: {0} controle(s) en echec" -f $script:Echecs)
    exit 1
}
Write-Host "MSI: tout est conforme (sortie: $RepertoireMsi)"

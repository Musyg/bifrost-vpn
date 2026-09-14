# Banc de la couche 2 anti-telemetrie: pose, verification, retrait.
#
# A lancer sur essai-windows, en administrateur. Il POSE de vrais filtres WFP
# persistants puis les retire; ne pas le lancer sur une machine de travail.
#
# L'instrument est `netsh wfp show filters`, de Microsoft, et non le binaire
# eprouve. La raison est celle du defaut Winhance 281, deja rencontre a la
# couche 1: un binaire qui se relit lui-meme confirme sa propre erreur. Ici
# c'est pire encore, parce qu'un filtre WFP peut etre parfaitement present dans
# le moteur et ne rien bloquer.
#
# Ce que le banc prouve: les filtres sont poses, ils portent le SID de DiagTrack
# et PAS celui de wuauserv, ils disparaissent entierement au retrait, et le kill
# switch n'a jamais ete touche.
#
# Ce qu'il ne prouve PAS: que la connexion de DiagTrack est effectivement
# refusee. Ca demande un audit WFP 5157 confronte au FilterRTID, et ce n'est pas
# fait ici. Ne pas lire ce banc comme une mesure d'efficacite.

param(
    # La racine du banc: le repertoire du script (via -File), ou BIFROST_BANC si pose.
    [string]$Banc = $(if ($env:BIFROST_BANC) { $env:BIFROST_BANC } else { $PSScriptRoot }),
    [string]$Binaire = (Join-Path $Banc 'bifrost-daemon.exe'),
    [string]$Profil = 'strict'
)

# La racine du banc doit etre connue. Lance autrement que par -File et sans
# BIFROST_BANC, $Banc est vide et les chemins derives seraient faux.
if ([string]::IsNullOrEmpty($Banc)) {
    throw "Banc introuvable: lancer ce script par -File depuis la racine du banc (le repertoire qui contient les binaires), ou poser BIFROST_BANC sur ce repertoire."
}

$ErrorActionPreference = 'Stop'
$script:Echecs = 0

# GUID du provider de la couche 2, tel que le code le declare. Ecrit ici A LA
# MAIN: si le banc le lisait du binaire, les deux se tromperaient ensemble.
$ProviderTelemetrie = '3ac9d180-5e42-4b77-9d61-8e05f3a27c40'
$ProviderKillSwitch = '0bd4f5a1-6c1e-4f8d-9a3e-2f7b41c9e510'

# SID releves par `sc showsid` le 22/08/2026, recopies a la main pour la meme
# raison. wuauserv est le temoin negatif: c'est le service qu'il ne faut PAS
# casser.
$SidDiagTrack = 'S-1-5-80-2620808479-2171380039-3191355562-2070425692-3097948119'
$SidWuauserv  = 'S-1-5-80-1014140700-3308905587-3330345912-272242898-93311788'

function Etape($t) { Write-Host ''; Write-Host "== $t" }
function Ok($t)    { Write-Host "  OK      $t" }
function Fail($t)  { Write-Host "  ECHEC   $t"; $script:Echecs++ }
function Skip($t)  { Write-Host "  SKIPPED $t" }

# Le dump WFP, par netsh. Rend le texte brut.
function Dump-Wfp {
    $f = Join-Path $env:SystemRoot 'Temp\bifrost-wfp-dump.xml'
    if (Test-Path $f) { Remove-Item $f -Force }
    $anc = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $null = & netsh wfp show filters file="$f" 2>&1
    $ErrorActionPreference = $anc
    if (-not (Test-Path $f)) { return '' }
    $t = Get-Content $f -Raw
    Remove-Item $f -Force
    return $t
}

# Combien de filtres portent ce provider. Les GUID sortent de netsh en
# minuscules et entre accolades; on compare sur la forme nue, insensible a la
# casse, ce qui est correct pour de l'hexadecimal.
function Compte-Filtres($dump, $provider) {
    if (-not $dump) { return -1 }
    return ([regex]::Matches($dump, [regex]::Escape($provider), 'IgnoreCase')).Count
}

function Lance-Binaire($arguments) {
    $anc = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $sortie = & $Binaire @arguments 2>&1 | Out-String
    $code = $LASTEXITCODE
    $ErrorActionPreference = $anc
    return @{ texte = $sortie; code = $code }
}

Write-Host "Binaire : $Binaire"
Write-Host "Profil  : $Profil"

if (-not (Test-Path $Binaire)) {
    Write-Host "ECHEC: binaire introuvable"
    exit 1
}

# ---------------------------------------------------------------------------
Etape 'Le moteur ne porte aucun filtre de la couche 2 au depart'
$avant = Dump-Wfp
if (-not $avant) {
    Skip 'netsh n''a rien rendu: le banc ne peut pas mesurer sans son instrument'
    exit 1
}
$nAvant = Compte-Filtres $avant $ProviderTelemetrie
$killAvant = Compte-Filtres $avant $ProviderKillSwitch
if ($nAvant -eq 0) {
    Ok 'zero filtre de telemetrie'
} else {
    Fail "$nAvant reference(s) au provider de telemetrie avant la pose: etat sale, le banc s'arrete"
    exit 1
}
Write-Host "  (references au provider du kill switch avant: $killAvant)"

# ---------------------------------------------------------------------------
Etape 'Lire ne pose rien'
$etat = Lance-Binaire @('--telemetrie-reseau-etat', '--telemetrie-profil', $Profil)
$apresLecture = Compte-Filtres (Dump-Wfp) $ProviderTelemetrie
if ($apresLecture -eq 0) {
    Ok '--telemetrie-reseau-etat n''a rien pose'
} else {
    Fail "une commande de LECTURE a laisse $apresLecture reference(s) dans le moteur"
}
$posables = 0
if ($etat.texte -match '(\d+) cible\(s\) posable\(s\) sur (\d+)') {
    $posables = [int]$Matches[1]
    Ok ("l'etat annonce {0} cible(s) posable(s) sur {1}" -f $Matches[1], $Matches[2])
} else {
    Fail 'l''etat des lieux ne rend pas de compte lisible'
}

# ---------------------------------------------------------------------------
Etape 'Pose'
$pose = Lance-Binaire @('--telemetrie-reseau-appliquer', '--telemetrie-profil', $Profil)
Write-Host ($pose.texte.TrimEnd())
$dumpPose = Dump-Wfp
$nPose = Compte-Filtres $dumpPose $ProviderTelemetrie

# Chaque cible posable donne DEUX filtres, un par famille d'adresses. Le dump
# nomme le provider une fois par filtre, plus une fois pour le provider
# lui-meme: la borne basse suffit a distinguer "pose" de "rien pose".
$attendu = $posables * 2
if ($nPose -ge $attendu -and $attendu -gt 0) {
    Ok "$nPose reference(s) au provider, pour $posables cible(s) sur deux familles d'adresses"
} else {
    Fail "$nPose reference(s) au provider, attendu au moins $attendu"
}

# ---------------------------------------------------------------------------
Etape 'La promesse differenciante: DiagTrack vise, Windows Update epargne'
if ($dumpPose -match [regex]::Escape($SidDiagTrack)) {
    Ok 'un filtre porte le SID de DiagTrack'
} else {
    Fail 'aucun filtre ne porte le SID de DiagTrack: la couche ne vise pas sa cible principale'
}
if ($dumpPose -match [regex]::Escape($SidWuauserv)) {
    Fail 'un filtre porte le SID de wuauserv: la couche casse Windows Update, ce que le document 03 promet de ne pas faire'
} else {
    Ok 'aucun filtre ne porte le SID de wuauserv'
}
if ($dumpPose -match 'compattelrunner') {
    Ok 'un filtre porte le chemin de CompatTelRunner'
} else {
    Fail 'aucun filtre ne porte le chemin de CompatTelRunner'
}
# Et jamais svchost par le chemin, l'erreur que le document interdit nommement.
$svchostVises = ([regex]::Matches($dumpPose, 'svchost\.exe', 'IgnoreCase')).Count
Write-Host "  (mentions de svchost.exe dans le dump entier: $svchostVises, tous produits confondus)"

# ---------------------------------------------------------------------------
Etape 'Le kill switch n''a pas ete touche'
$killPose = Compte-Filtres $dumpPose $ProviderKillSwitch
if ($killAvant -eq 0) {
    # Un temoin qui passe de zero a zero ne discrimine RIEN: un defaut qui
    # supprimerait les filtres du kill switch rendrait exactement la meme
    # mesure. Le dire SKIPPED plutot que de le compter vert.
    Skip 'le kill switch n''etait pas arme: 0 -> 0 ne prouve pas l''independance des deux jeux. Relancer ce banc tunnel leve pour que l''etape morde'
} elseif ($killPose -eq $killAvant) {
    Ok "le provider du kill switch garde ses $killAvant reference(s): les deux jeux d'objets sont bien independants"
} else {
    Fail "le kill switch est passe de $killAvant a $killPose reference(s): les deux jeux se marchent dessus"
}

# ---------------------------------------------------------------------------
Etape 'Retrait, la sortie de secours'
$retrait = Lance-Binaire @('--telemetrie-reseau-retirer')
Write-Host ($retrait.texte.TrimEnd())
if ($retrait.code -eq 0) {
    Ok 'le retrait rend zero'
} else {
    Fail "le retrait rend $($retrait.code): il reste quelque chose"
}
$dumpApres = Dump-Wfp
$nApres = Compte-Filtres $dumpApres $ProviderTelemetrie
if ($nApres -eq 0) {
    Ok 'plus une seule reference au provider de telemetrie: provider, sublayer et filtres ont disparu'
} else {
    Fail "$nApres reference(s) restent apres le retrait: une machine filtree par un logiciel absent"
}
if ($dumpApres -match [regex]::Escape($SidDiagTrack)) {
    Fail 'le SID de DiagTrack figure encore dans le moteur apres le retrait'
} else {
    Ok 'le SID de DiagTrack a disparu du moteur'
}
$killApres = Compte-Filtres $dumpApres $ProviderKillSwitch
if ($killAvant -eq 0) {
    Skip 'le kill switch n''etait pas arme: son etat apres retrait ne prouve rien non plus'
} elseif ($killApres -eq $killAvant) {
    Ok "le kill switch est intact apres le retrait: $killApres reference(s)"
} else {
    Fail "le retrait de la couche 2 a change le kill switch: $killAvant -> $killApres"
}

# ---------------------------------------------------------------------------
Etape 'Un retrait sur un moteur deja propre ne casse pas'
$retrait2 = Lance-Binaire @('--telemetrie-reseau-retirer')
if ($retrait2.code -eq 0) {
    Ok 'le retrait est idempotent: rejouer la suite de cles tolere les absentes'
} else {
    Fail "un second retrait rend $($retrait2.code)"
}

Write-Host ''
if ($script:Echecs -eq 0) {
    Write-Host "== TOUT VERT: aller-retour complet de la couche 2, mesure par netsh =="
    exit 0
} else {
    Write-Host "== $($script:Echecs) echec(s) =="
    exit 1
}

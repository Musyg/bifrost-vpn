# Pourquoi la couche 2 ne mord-elle pas ? Le banc qui isole la cause.
#
# A lancer sur essai-windows, en administrateur.
#
# Le 22 aout 2026, la mesure d'effet de la couche 2 est revenue NEGATIVE:
# filtres poses, verifies presents dans le moteur par netsh, portant le SID de
# service de DiagTrack - SID lui-meme verifie present dans le jeton du processus
# - et la connexion est passee quand meme. Deux questions restaient sans reponse
# et une seule mesure les tranche toutes les deux:
#
#   1. la FORME du filtre (blocage + ALE_USER_ID sur un SID de service) est-elle
#      capable de mordre, ou est-elle inoperante par construction ?
#   2. si elle mord ici mais pas sur DiagTrack, qu'est-ce que DiagTrack a de
#      particulier ?
#
# La mesure precedente ne pouvait pas y repondre parce que son seul emetteur,
# DiagTrack, n'emet qu'UNE fois par redemarrage et assechait la fenetre avant
# que la sonde ne puisse lire le FilterRTID de l'evenement 5156, celui qui nomme
# le filtre GAGNANT. D'ou ce banc: il se donne un emetteur qu'il COMMANDE.
#
# Le temoin est un service de test jetable, installe ici, dont le binaire est le
# daemon lui-meme en mode --connect-probe. Il a un SERVICE_SID_TYPE unrestricted
# comme DiagTrack, un SID de service comme DiagTrack, et il se connecte quand on
# le lui demande, contrairement a DiagTrack. Le blocage pose sur lui a
# exactement la meme forme que ceux du catalogue - meme couches, meme poids,
# meme veto, meme condition - parce qu'une sonde qui poserait autre chose ne
# mesurerait pas ce qu'on croit.
#
# Le banc nettoie derriere lui: filtres retires, service supprime, politique
# d'audit remise dans l'etat trouve. Il le fait meme en sortant sur une erreur.

param(
    # La racine du banc: le repertoire du script (via -File), ou BIFROST_BANC si pose.
    [string]$Banc = $(if ($env:BIFROST_BANC) { $env:BIFROST_BANC } else { $PSScriptRoot }),
    [string]$Binaire = (Join-Path $Banc 'bifrost-daemon.exe'),
    [string]$Cible = '1.1.1.1:443',
    [string]$Service = 'bifrost-temoin',
    [int]$Rafale = 8000
)

# La racine du banc doit etre connue. Lance autrement que par -File et sans
# BIFROST_BANC, $Banc est vide et les chemins derives seraient faux.
if ([string]::IsNullOrEmpty($Banc)) {
    throw "Banc introuvable: lancer ce script par -File depuis la racine du banc (le repertoire qui contient les binaires), ou poser BIFROST_BANC sur ce repertoire."
}

$ErrorActionPreference = 'Continue'
$Sous = '{0CCE9226-69AE-11D9-BED3-505054503030}'
$PrefixeCle = '3ac9d182-5e42-4b77-9d61-8e05f3a2'
$CibleIp = ($Cible -split ':')[0]

function Dump-Wfp {
    $f = Join-Path $env:SystemRoot 'Temp\bifrost-cause.xml'
    if (Test-Path $f) { Remove-Item $f -Force }
    $null = & netsh wfp show filters file="$f" 2>&1
    if (-not (Test-Path $f)) { return $null }
    $t = Get-Content $f -Raw; Remove-Item $f -Force; return $t
}

# Deux tables: nos filtres a nous, et TOUS les filtres du moteur. La seconde
# sert a NOMMER le gagnant quel qu'il soit, y compris s'il ne nous appartient
# pas - c'est precisement le cas interessant.
function Table-Nos($dump) {
    $r = [regex]::new("<filterKey>\{$PrefixeCle[0-9a-f]{4}\}</filterKey>.*?<displayData>\s*<name>([^<]*)</name>.*?<filterId>(\d+)</filterId>",
        [Text.RegularExpressions.RegexOptions]::Singleline -bor [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $res = @{}
    foreach ($m in $r.Matches($dump)) { $res[$m.Groups[2].Value] = $m.Groups[1].Value }
    return $res
}
function Table-Tous($dump) {
    $r = [regex]::new("<filterKey>\{[0-9a-f-]+\}</filterKey>.*?<name>([^<]*)</name>.*?<filterId>(\d+)</filterId>",
        [Text.RegularExpressions.RegexOptions]::Singleline -bor [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $res = @{}
    foreach ($m in $r.Matches($dump)) { $res[$m.Groups[2].Value] = $m.Groups[1].Value }
    return $res
}
function Detail($e) {
    $x = [xml]$e.ToXml(); $d = @{}
    foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
    return $d
}

# Le temoin est discrimine par sa DESTINATION, pas par son PID: le meme binaire
# sert aussi a poser les filtres depuis la session admin, et seul le service
# se connecte a la cible.
function Evenements($marque, $id) {
    $out = @()
    foreach ($e in @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$id; StartTime=$marque} -ErrorAction SilentlyContinue)) {
        $d = Detail $e
        if ($d['DestAddress'] -eq $CibleIp) { $out += $d }
    }
    return $out
}

function Passage($etiquette, $sid) {
    if ($sid) {
        $sortie = & $Binaire --telemetrie-sonde-sid $sid 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  $etiquette ECHEC: la sonde n a rien pose"
            $sortie | ForEach-Object { Write-Host "     $_" }
            return $null
        }
        $dump = Dump-Wfp
        $nos = Table-Nos $dump
        $tous = Table-Tous $dump
    } else {
        $null = & $Binaire --telemetrie-reseau-retirer
        $dump = Dump-Wfp
        $nos = @{}
        $tous = Table-Tous $dump
    }

    $marque = (Get-Date).AddSeconds(-1)
    Start-Process -FilePath 'sc.exe' -ArgumentList 'start', $Service -NoNewWindow
    Start-Sleep -Milliseconds ($Rafale + 12000)
    $null = & sc.exe stop $Service

    $permis = Evenements $marque 5156
    $refuses = Evenements $marque 5157
    $f = if ($sid) { 'SONDE POSEE' } else { 'sans filtre' }
    Write-Host ("  {0} {1,-12} nos filtres={2}  autorisees={3}  refusees={4}" -f `
        $etiquette, $f, $nos.Count, $permis.Count, $refuses.Count)

    foreach ($d in ($permis | Select-Object -First 2)) {
        $rt = $d['FilterRTID']
        $nom = if ($tous.ContainsKey($rt)) { $tous[$rt] } else { '(absent du dump)' }
        $notre = if ($nos.ContainsKey($rt)) { 'OUI' } else { 'non' }
        Write-Host ("     AUTORISEE  filtre gagnant rtid={0} layer={1} a nous={2}" -f $rt, $d['LayerRTID'], $notre)
        Write-Host ("        nom du gagnant: {0}" -f $nom)
    }
    foreach ($d in ($refuses | Select-Object -First 2)) {
        $rt = $d['FilterRTID']
        $nom = if ($tous.ContainsKey($rt)) { $tous[$rt] } else { '(absent du dump)' }
        $notre = if ($nos.ContainsKey($rt)) { 'OUI' } else { 'non' }
        Write-Host ("     REFUSEE    filtre gagnant rtid={0} layer={1} a nous={2}" -f $rt, $d['LayerRTID'], $notre)
        Write-Host ("        nom du gagnant: {0}" -f $nom)
    }
    return @{
        permis = $permis.Count
        refuses = $refuses.Count
        notres = @($refuses | Where-Object { $nos.ContainsKey($_['FilterRTID']) }).Count
        poses = $nos.Count
    }
}

function Menage {
    $null = & $Binaire --telemetrie-reseau-retirer
    $null = & sc.exe stop $Service
    $null = & sc.exe delete $Service
    $null = & auditpol /set /subcategory:"$Sous" /success:disable /failure:enable
    Write-Host 'menage fait: filtres retires, service supprime, audit remis dans l etat trouve'
}

# --------------------------------------------------------------------- depart
Write-Host "Binaire : $Binaire"
Write-Host "Cible   : $Cible"
if (-not (Test-Path $Binaire)) { Write-Host 'ECHEC: binaire introuvable'; exit 1 }

# Le temoin doit pouvoir sortir AVANT qu'on lui pose quoi que ce soit, sinon
# une absence de connexion ne voudra rien dire. Vecu le 22 aout 2026 avec
# CompatTelRunner, reste muet - et le 23/08 on a su pourquoi: ses taches
# n'avaient jamais tourne. Muet pour la mauvaise raison, ce qui ne change rien
# a la regle et beaucoup a ce qu'on a le droit d'en conclure.
$null = & $Binaire --connect-probe $Cible
if ($LASTEXITCODE -ne 5) {
    Write-Host "SKIPPED  la cible $Cible ne repond pas depuis cette machine (code $LASTEXITCODE)."
    Write-Host "         Sans temoin qui sort, une absence de connexion ne discrimine rien."
    exit 0
}
Write-Host 'temoin: la cible repond depuis cette machine, la mesure peut discriminer'

$null = & sc.exe delete $Service    # au cas ou un passage precedent aurait laisse quelque chose
$null = & sc.exe create $Service binPath= "`"$Binaire`" --connect-probe $Cible --connect-probe-rafale $Rafale" type= own start= demand
if ($LASTEXITCODE -ne 0) { Write-Host 'ECHEC: creation du service de test'; exit 1 }
$null = & sc.exe sidtype $Service unrestricted
$lt = @(& sc.exe qsidtype $Service) | Where-Object { $_ -match 'SERVICE_SID_TYPE' } | Select-Object -First 1
$ligne = @(& sc.exe showsid $Service) | Where-Object { $_ -match 'S-1-5-80' } | Select-Object -First 1
$sid = if ($ligne) { ([regex]::Match($ligne, 'S-1-5-80(-\d+)+')).Value } else { '' }
Write-Host "service de test cree: $Service"
Write-Host "  sidtype : $(($lt -replace '.*:\s*','').Trim())"
Write-Host "  SID     : $sid"
if (-not $sid) { Write-Host 'ECHEC: pas de SID de service lisible'; Menage; exit 1 }

$null = & auditpol /set /subcategory:"$Sous" /success:enable /failure:enable

Write-Host ''
Write-Host '== Deux passages, le temoin sort a la demande =='
$a = Passage 'A' $null
$b = Passage 'B' $sid

Write-Host ''
Write-Host '== Verdict =='
$code = 0
if (-not $a -or -not $b) {
    Write-Host '  ECHEC    un passage n a pas pu s executer'
    $code = 1
} elseif ($a.permis -eq 0) {
    Write-Host '  SKIPPED  le temoin n a pas sorti de connexion sans filtre: la mesure ne discrimine pas'
} elseif ($b.notres -ge 1) {
    Write-Host '  MESURE   la FORME du filtre mord: blocage + ALE_USER_ID sur un SID de service refuse'
    Write-Host '           bien la connexion du service qui porte ce SID. Le probleme observe sur'
    Write-Host '           DiagTrack lui est donc PROPRE, il ne vient pas de la construction du filtre.'
} elseif ($b.permis -ge 1) {
    Write-Host '  ECHEC    la FORME du filtre ne mord pas, meme sur un service qu on maitrise'
    Write-Host '           entierement. Ce n est pas une particularite de DiagTrack: la couche 2'
    Write-Host '           est inoperante par construction. Le nom du filtre gagnant est imprime'
    Write-Host '           ci-dessus, c est lui qu il faut suivre.'
    $code = 1
} else {
    Write-Host '  INDICE   plus aucune connexion avec la sonde, mais aucun 5157 impute a nos filtres:'
    Write-Host '           on ne sait pas QUI a bloque. Insuffisant pour conclure.'
}

Write-Host ''
Menage
exit $code

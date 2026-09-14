<#
.SYNOPSIS
Eprouve l'aller-retour de la couche 1 anti-telemetrie: etat, pose, retour.

.DESCRIPTION
La couche 1 touche des politiques, des services et des taches planifiees. Le
document 03 pose la reversibilite comme obligatoire, et une reversibilite qui
n'est pas mesuree n'est qu'une intention. Cette recette la mesure de la seule
facon qui vaille: elle releve l'etat BRUT de chaque cible avant de commencer,
fait poser, fait defaire, releve a nouveau, et exige que les deux releves
soient identiques cible par cible.

Le releve est fait ici, en PowerShell, et non par le binaire qu'on eprouve. Un
binaire qui se relit lui-meme confirmerait sa propre erreur; c'est exactement
le defaut Winhance 281 que la couche 1 existe pour ne pas reproduire.

Trois proprietes en plus de l'aller-retour:

 1. Une cle CREEE par la pose doit avoir DISPARU apres le retour. Sur la build
    26200, `WindowsAI`, `CloudContent`, `AdvertisingInfo` et
    `InputPersonalization` n'existent pas sous Policies: la pose les cree. Un
    retour qui se contenterait de supprimer la valeur laisserait une cle de
    politique vide.
 2. Une cible absente de la machine doit etre dite SANS OBJET, jamais posee.
 3. Le journal doit disparaitre quand, et seulement quand, tout a ete rendu.

Regle non negociable, comme partout ici: ce qui ne peut pas s'executer rend
SKIPPED avec sa raison. Jamais PASSED par defaut.

.PARAMETER Binaire
Chemin de bifrost-daemon.exe. Par defaut target\debug a la racine du depot.

.PARAMETER Profil
aucun, equilibre ou strict. Par defaut strict, qui couvre le catalogue entier.

.EXAMPLE
.\scripts\telemetrie-windows.ps1

.EXAMPLE
.\scripts\telemetrie-windows.ps1 -Binaire .\bifrost-daemon.exe -Profil equilibre
#>
[CmdletBinding()]
param(
    # La racine du banc: le repertoire du script (via -File), ou BIFROST_BANC si pose.
    [string]$Banc = $(if ($env:BIFROST_BANC) { $env:BIFROST_BANC } else { $PSScriptRoot }),
    [string] $Binaire,
    [ValidateSet('aucun', 'equilibre', 'strict')]
    [string] $Profil = 'strict'
)

# La racine du banc doit etre connue. Sous [CmdletBinding()], $PSScriptRoot est
# vide quand la valeur par defaut est evaluee (mesure PS 5.1 sur dev-windows):
# on la retrouve ici, dans le corps, ou $PSScriptRoot est disponible. Sans racine
# du tout (lance autrement que par -File et sans BIFROST_BANC), on s'arrete.
if ([string]::IsNullOrEmpty($Banc)) { $Banc = $PSScriptRoot }
if ([string]::IsNullOrEmpty($Banc)) {
    throw "Banc introuvable: lancer ce script par -File depuis la racine du banc (le repertoire qui contient les binaires), ou poser BIFROST_BANC sur ce repertoire."
}

$ErrorActionPreference = 'Stop'

$Racine = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
if (-not $Binaire) { $Binaire = Join-Path $Racine 'target\debug\bifrost-daemon.exe' }
$Journal = Join-Path $env:TEMP 'bifrost-telemetrie-banc.json'

$script:Echecs = 0
$script:Sautes = 0
function Ok    ([string] $m) { Write-Host ('  OK    {0}' -f $m) }
function Fail  ([string] $m) { Write-Host ('  ECHEC {0}' -f $m); $script:Echecs++ }
function Skip  ([string] $m) { Write-Host ('  SKIPPED {0}' -f $m); $script:Sautes++ }
function Etape ([string] $m) { Write-Host ''; Write-Host ('== {0}' -f $m) }

# ---------------------------------------------------------------- prealables
if (-not (Test-Path $Binaire)) {
    Skip ("bifrost-daemon.exe absent de {0}: rien a eprouver" -f $Binaire)
    Write-Host ''
    Write-Host 'SKIPPED: le binaire manque.'
    exit 3
}
$estAdmin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $estAdmin) {
    Skip 'session non elevee: poser sous HKLM et changer un service exigent les droits administrateur'
    Write-Host ''
    Write-Host 'SKIPPED: session non elevee.'
    exit 3
}
if (Test-Path $Journal) { Remove-Item $Journal -Force }

# ------------------------------------------------- le releve brut des cibles
# Les memes cibles que le catalogue, ecrites ici a la main et EXPRES: si le
# banc les lisait du binaire, les deux se tromperaient ensemble.
$CiblesRegistre = @(
    @{ Chemin = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Valeurs = @('AllowTelemetry', 'AllowDeviceNameInTelemetry', 'DoNotShowFeedbackNotifications') },
    @{ Chemin = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo'; Valeurs = @('DisabledByGroupPolicy') },
    @{ Chemin = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Valeurs = @('DisableTailoredExperiencesWithDiagnosticData', 'DisableWindowsConsumerFeatures') },
    @{ Chemin = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'; Valeurs = @('AllowRecallEnablement', 'DisableAIDataAnalysis') },
    @{ Chemin = 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization'; Valeurs = @('AllowInputPersonalization') },
    @{ Chemin = 'HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack'; Valeurs = @('Start') },
    @{ Chemin = 'HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice'; Valeurs = @('Start') },
    @{ Chemin = 'HKLM:\SYSTEM\CurrentControlSet\Services\DoSvc'; Valeurs = @('Start') },
    @{ Chemin = 'HKLM:\SYSTEM\CurrentControlSet\Services\WerSvc'; Valeurs = @('Start') },
    @{ Chemin = 'HKLM:\SYSTEM\CurrentControlSet\Services\CDPSvc'; Valeurs = @('Start') },
    @{ Chemin = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo'; Valeurs = @('Enabled') },
    @{ Chemin = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy'; Valeurs = @('TailoredExperiencesWithDiagnosticDataEnabled') },
    @{ Chemin = 'HKCU:\Software\Microsoft\InputPersonalization'; Valeurs = @('RestrictImplicitInkCollection', 'RestrictImplicitTextCollection') },
    @{ Chemin = 'HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy'; Valeurs = @('HasAccepted') }
)

$CiblesTaches = @(
    '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator',
    '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip',
    '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser',
    '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser Exp',
    '\Microsoft\Windows\Application Experience\ProgramDataUpdater',
    '\Microsoft\Windows\Application Experience\PcaPatchDbTask',
    '\Microsoft\Windows\Application Experience\StartupAppTask',
    '\Microsoft\Windows\Feedback\Siuf\DmClient',
    '\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload',
    '\Microsoft\Windows\Autochk\Proxy',
    '\Microsoft\Windows\Windows Error Reporting\QueueReporting'
)

function Releve {
    $etat = [ordered]@{}
    foreach ($c in $CiblesRegistre) {
        if (-not (Test-Path $c.Chemin)) {
            $etat[$c.Chemin] = 'CLE-ABSENTE'
            foreach ($v in $c.Valeurs) { $etat[($c.Chemin + '::' + $v)] = 'CLE-ABSENTE' }
            continue
        }
        $etat[$c.Chemin] = 'CLE-PRESENTE'
        foreach ($v in $c.Valeurs) {
            $p = Get-ItemProperty -Path $c.Chemin -Name $v -ErrorAction SilentlyContinue
            if ($null -eq $p) { $etat[($c.Chemin + '::' + $v)] = 'VALEUR-ABSENTE' }
            else { $etat[($c.Chemin + '::' + $v)] = ('valeur=' + $p.$v) }
        }
    }
    foreach ($t in $CiblesTaches) {
        $dossier = Split-Path $t
        $nom = Split-Path $t -Leaf
        # L'etat est une enumeration, jamais une phrase traduite.
        $tache = Get-ScheduledTask -TaskPath ($dossier + '\') -TaskName $nom -ErrorAction SilentlyContinue
        if ($null -eq $tache) { $etat[('tache::' + $t)] = 'TACHE-ABSENTE' }
        else { $etat[('tache::' + $t)] = ('etat=' + [int]$tache.State) }
    }
    return $etat
}

function Comparer ([hashtable] $a, [hashtable] $b, [string] $quoi) {
    $ecarts = @()
    foreach ($k in $a.Keys) {
        if ($a[$k] -ne $b[$k]) { $ecarts += ('{0}: avant {1}, apres {2}' -f $k, $a[$k], $b[$k]) }
    }
    if ($ecarts.Count -eq 0) {
        Ok ("{0}: les {1} cibles sont identiques" -f $quoi, $a.Count)
    } else {
        Fail ("{0}: {1} ecart(s)" -f $quoi, $ecarts.Count)
        foreach ($e in $ecarts) { Write-Host ('        ' + $e) }
    }
}

Etape 'Releve d''origine, lu par le banc et non par le binaire'
$avant = Releve
Ok ("{0} cibles relevees" -f $avant.Count)
$clesAbsentes = @($avant.Keys | Where-Object { $_ -notlike '*::*' -and $avant[$_] -eq 'CLE-ABSENTE' })
Write-Host ("        dont {0} cle(s) de politique qui n'existent pas encore" -f $clesAbsentes.Count)

Etape 'Etat avant pose'
$sortie = & $Binaire --telemetrie-etat --telemetrie-profil $Profil 2>&1
$code = $LASTEXITCODE
$sortie | ForEach-Object { Write-Host ('        ' + $_) }
if ($code -eq 0) { Ok '--telemetrie-etat rend 0 et n''ecrit rien' } else { Fail ("--telemetrie-etat a rendu {0}" -f $code) }
$apresLecture = Releve
Comparer $avant $apresLecture 'lire l''etat ne modifie rien'

Etape 'Pose'
$sortie = & $Binaire --telemetrie-appliquer --telemetrie-profil $Profil --telemetrie-journal $Journal 2>&1
$codePose = $LASTEXITCODE
$sortie | ForEach-Object { Write-Host ('        ' + $_) }
$texte = ($sortie | Out-String)
if ($codePose -eq 0) { Ok 'la pose ne rapporte aucun ECHEC' } else { Fail ("la pose a rendu {0}" -f $codePose) }
# -cmatch et pas -match: `-match` est INSENSIBLE A LA CASSE en PowerShell, et
# mordait sur la ligne de resume << 0 echec(s) >>. Le banc rougissait donc sur
# une pose parfaite. Ancre en debut de ligne, parce que seule une ligne de
# verdict commence par ce mot.
if ($texte -cmatch '(?m)^ECHEC') { Fail 'une ligne au moins est en ECHEC' } else { Ok 'aucune ligne en ECHEC' }
if (Test-Path $Journal) { Ok 'le journal a ete ecrit' } else { Fail 'aucun journal ecrit: rien ne pourrait etre defait' }

Etape 'Ce que la pose a change'
$apresPose = Releve
$changes = @($avant.Keys | Where-Object { $avant[$_] -ne $apresPose[$_] })
if ($changes.Count -gt 0) {
    Ok ("{0} cible(s) ont bouge" -f $changes.Count)
    foreach ($k in $changes) { Write-Host ('        {0}: {1} -> {2}' -f $k, $avant[$k], $apresPose[$k]) }
} else {
    Fail 'aucune cible n''a bouge: soit la machine etait deja conforme, soit rien n''a ete pose'
}

Etape 'Le journal decrit ce qu''il faut defaire'
if (Test-Path $Journal) {
    $j = Get-Content $Journal -Raw | ConvertFrom-Json
    Ok ("journal en version {0}, profil {1}, {2} entree(s)" -f $j.version, $j.profil, $j.entrees.Count)
    $avecCleAbsente = @($j.entrees | Where-Object { $_.avant.etait -eq 'cle_et_valeur_absentes' })
    if ($clesAbsentes.Count -gt 0 -and $avecCleAbsente.Count -eq 0) {
        Fail 'le journal ne distingue aucune cle absente alors que la machine en avait: le retour laisserait des cles vides'
    } elseif ($avecCleAbsente.Count -gt 0) {
        Ok ("{0} entree(s) se souviennent que la CLE n'existait pas" -f $avecCleAbsente.Count)
    } else {
        Skip 'aucune cle de politique n''etait absente sur cette machine: la propriete des cles creees n''est pas eprouvee ici'
    }
} else {
    Skip 'pas de journal a relire'
}

Etape 'Etat apres pose: plus rien a poser'
$sortie = & $Binaire --telemetrie-etat --telemetrie-profil $Profil 2>&1
$texte = ($sortie | Out-String)
if ($texte -cmatch '(?m)^A POSER') {
    Fail 'des cibles restent A POSER apres la pose'
    $sortie | Where-Object { $_ -cmatch '^A POSER' } | ForEach-Object { Write-Host ('        ' + $_) }
} else {
    Ok 'aucune cible ne reste A POSER'
}

Etape 'Retour en arriere'
$sortie = & $Binaire --telemetrie-restaurer --telemetrie-journal $Journal 2>&1
$codeRetour = $LASTEXITCODE
$sortie | ForEach-Object { Write-Host ('        ' + $_) }
if ($codeRetour -eq 0) { Ok 'le retour ne rapporte aucun ECHEC' } else { Fail ("le retour a rendu {0}" -f $codeRetour) }
if (Test-Path $Journal) {
    Fail 'le journal survit au retour: ou bien tout n''a pas ete rendu, ou bien il n''est pas efface'
    Remove-Item $Journal -Force
} else {
    Ok 'le journal a disparu, ce qui n''arrive que si tout a ete rendu'
}

Etape 'La machine est-elle rendue'
$apresRetour = Releve
Comparer $avant $apresRetour 'aller-retour complet'

Etape 'Les cles creees ont-elles disparu'
$restantes = @($clesAbsentes | Where-Object { $apresRetour[$_] -ne 'CLE-ABSENTE' })
if ($clesAbsentes.Count -eq 0) {
    Skip 'aucune cle de politique n''etait absente: rien n''a ete cree, donc rien a verifier ici'
} elseif ($restantes.Count -eq 0) {
    Ok ("les {0} cle(s) creees par la pose ont ete supprimees" -f $clesAbsentes.Count)
} else {
    Fail ("{0} cle(s) de politique restent apres le retour" -f $restantes.Count)
    foreach ($k in $restantes) { Write-Host ('        ' + $k) }
}

Etape 'Restaurer sans journal se dit, et ne rend pas 0'
# `$ErrorActionPreference = 'Stop'` plus `2>&1` sur un executable natif tue le
# script des que celui-ci ecrit une ligne sur sa sortie d'erreur: PowerShell
# l'emballe en ErrorRecord. Or c'est exactement ce qu'on veut provoquer ici. On
# desarme donc le temps de l'appel, et on le rearme aussitot.
$avantPref = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$sortie = & $Binaire --telemetrie-restaurer --telemetrie-journal $Journal 2>&1
$code = $LASTEXITCODE
$ErrorActionPreference = $avantPref
$sortie | ForEach-Object { Write-Host ('        ' + $_) }
if ($code -ne 0) { Ok ("un retour sans journal rend {0} et dit pourquoi" -f $code) }
else { Fail 'un retour sans journal a rendu 0: rien n''a ete fait et ca ressemble a un succes' }

Etape 'Sous SYSTEM, la ruche utilisateur est refusee et non ecrite dans le vide'
# Le daemon tourne en service. HKEY_CURRENT_USER y designe la ruche de SYSTEM,
# pas celle de la personne devant l'ecran. Sans refus, le moteur ecrirait cinq
# valeurs qui ne protegent personne et annoncerait cinq protections. La seule
# facon de le mesurer est de le faire tourner VRAIMENT sous SYSTEM, donc par une
# tache planifiee. La commande est en lecture seule: elle n'ecrit rien.
$NomTache = 'bifrost-telemetrie-systeme'
# Sous %SystemRoot%\Temp et non sous %TEMP%: %TEMP% pointe dans le profil de
# l'utilisateur courant, ou SYSTEM n'ecrit pas. Mesure du 22/08/2026: la tache
# tournait, rendait 1, et ne laissait aucun fichier - une abstention qui
# ressemblait a une limite du procede alors que c'etait un chemin mal choisi.
$TempMachine = Join-Path $env:SystemRoot 'Temp'
$Lanceur = Join-Path $TempMachine 'bifrost-telemetrie-systeme.cmd'
$SortieSysteme = Join-Path $TempMachine 'bifrost-telemetrie-systeme.txt'
if (Test-Path $SortieSysteme) { Remove-Item $SortieSysteme -Force }
# En ASCII et par un FICHIER: passer la ligne a `schtasks /TR` demanderait un
# niveau de guillemets de plus, et c'est la que les chemins se perdent.
$lignes = @(
    '@echo off',
    ('"' + $Binaire + '" --telemetrie-etat --telemetrie-profil ' + $Profil + ' > "' + $SortieSysteme + '" 2>&1')
)
Set-Content -Path $Lanceur -Value $lignes -Encoding ascii

$null = & schtasks /Create /TN $NomTache /TR $Lanceur /SC ONCE /ST 23:59 /RU SYSTEM /RL HIGHEST /F 2>&1
if ($LASTEXITCODE -ne 0) {
    Skip 'la tache SYSTEM n''a pas pu etre creee: le refus sous SYSTEM n''est pas mesure ici'
} else {
    $null = & schtasks /Run /TN $NomTache 2>&1
    $attendu = 20
    while ($attendu -gt 0 -and -not (Test-Path $SortieSysteme)) { Start-Sleep -Seconds 1; $attendu-- }
    if (-not (Test-Path $SortieSysteme)) {
        Skip 'la tache SYSTEM n''a rien ecrit dans le delai: le refus sous SYSTEM n''est pas mesure ici'
    } else {
        $texteSysteme = Get-Content $SortieSysteme -Raw
        # -cmatch: `-match` est insensible a la casse et mordrait sur la prose.
        $refuses = @([regex]::Matches($texteSysteme, '(?m)^REFUSE')).Count
        $attenduRefuses = @([regex]::Matches($texteSysteme, '(?m)^\S.*HKCU\\')).Count
        if ($refuses -ge 5) {
            Ok ("sous SYSTEM, {0} reglage(s) de ruche utilisateur sont REFUSES" -f $refuses)
        } else {
            Fail ("sous SYSTEM, seulement {0} REFUSE alors que {1} cible(s) HKCU sont au catalogue: le reste a ete ecrit dans la ruche de SYSTEM" -f $refuses, $attenduRefuses)
        }
        if ($texteSysteme -match 'designe la ruche de SYSTEM') {
            Ok 'le refus dit pourquoi, et ou relancer la commande'
        } else {
            Fail 'le refus ne dit pas sa raison'
        }
    }
    $null = & schtasks /Delete /TN $NomTache /F 2>&1
}
if (Test-Path $Lanceur) { Remove-Item $Lanceur -Force }
if (Test-Path $SortieSysteme) { Remove-Item $SortieSysteme -Force }

Write-Host ''
if ($script:Echecs -eq 0) {
    Write-Host ('OK: aller-retour complet, {0} abstention(s).' -f $script:Sautes)
    exit 0
} else {
    Write-Host ('ECHEC: {0} propriete(s) non tenue(s), {1} abstention(s).' -f $script:Echecs, $script:Sautes)
    exit 1
}

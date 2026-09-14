param(
    [Parameter(Mandatory = $true)][string]$Cible,
    [ValidateSet('redemarrage', 'resync')][string]$Declencheur = 'redemarrage',
    [int]$Port = 0,
    [int]$Attente = 70
)

# LE BANC QUI EXONERE NOTRE FILTRE.
#
# Notre blocage ALE_USER_ID mord sur W32Time et sur trois services temoins, et
# n a jamais mordu sur DiagTrack ni DoSvc. Une explication restait debout et
# elle etait la plus genante: NOTRE filtre est mal construit, et ce qui se
# bloque se bloque par chance.
#
# Ce banc ne construit rien. Il demande a Windows de poser LUI-MEME la
# politique - New-NetFirewallRule -Service <nom> -Direction Outbound -Action
# Block - puis lit qui gagne. Si la regle de Microsoft echoue la ou la notre
# echoue, notre implementation est hors de cause et la limite est celle de la
# plateforme.
#
# Il se lance sur DEUX cibles, et les deux comptent:
#   -Cible W32Time -Declencheur resync -Port 123   doit MORDRE
#   -Cible DoSvc   -Declencheur redemarrage        mesure du 23/08: ECHOUE
# Sans le premier passage, le second ne dit rien: une regle qui ne mord sur
# RIEN - profil reseau qui ne correspond pas, outil qui ne pose pas - rendrait
# exactement la meme sortie qu une regle qui ne mord pas sur cette cible-la.
#
# Le profil actif et le profil de CHAQUE filtre pose sont releves, pour que
# l objection soit fermee par la mesure et non par une supposition.
#
# Un service en WIN32_SHARE_PROCESS partage son svchost: compter les connexions
# du PID seul melangerait les services. Le verdict ne s appuie donc QUE sur les
# refus dont le filtre gagnant porte le nom de notre regle - ceux-la sont a nous
# sans ambiguite. -Port restreint en plus a un port de destination connu.

$ErrorActionPreference = 'Stop'
$Sous = '{0CCE9226-69AE-11D9-BED3-505054503030}'
$Regle = 'bifrost-essai-regle-microsoft'

function Titre($t) { Write-Host ''; Write-Host ('== ' + $t) }

$sid = ((& sc.exe showsid $Cible) -join ' ')
if ($sid -match '(S-1-5-80-[0-9-]+)') { $sid = $Matches[1] } else { throw "SID de $Cible illisible" }
$compte = (Get-CimInstance Win32_Service -Filter ("Name='" + $Cible + "'")).StartName
Write-Host ("cible  : {0}" -f $Cible)
Write-Host ("compte : {0}" -f $compte)
Write-Host ("SID    : {0}" -f $sid)

# profil reseau actif: 1 = Domaine, 2 = Prive, 4 = Public
$profils = @{}
foreach ($p in Get-NetConnectionProfile) {
    $n = switch ($p.NetworkCategory) { 'DomainAuthenticated' { 1 } 'Private' { 2 } 'Public' { 4 } default { 0 } }
    $profils[$n] = "$($p.NetworkCategory) sur $($p.InterfaceAlias)"
}
foreach ($k in $profils.Keys) { Write-Host ("profil actif : {0} ({1})" -f $k, $profils[$k]) }

$auditAvant = ((& auditpol /get /subcategory:"$Sous") -join ' ') -replace '\s+', ' '
Write-Host ("audit avant : {0}" -f $auditAvant)

Get-NetFirewallRule -DisplayName $Regle -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue

function Table-Filtres {
    $dump = Join-Path $env:TEMP 'regle-microsoft.xml'
    & netsh wfp show filters file="$dump" | Out-Null
    $xml = New-Object System.Xml.XmlDocument
    $xml.Load($dump)
    $map = @{}
    $notres = @()
    foreach ($item in $xml.SelectNodes('//item[filterKey]')) {
        $id = "$($item.filterId)"
        $nom = "$($item.displayData.name)"
        if ($id) { $map[$id] = $nom }
        if ($nom -eq $Regle) { $notres += $item }
    }
    Remove-Item $dump -ErrorAction SilentlyContinue
    return @{ Map = $map; Notres = $notres }
}

$res = $null
try {
    & auditpol /set /subcategory:"$Sous" /success:enable /failure:enable | Out-Null

    Titre ('A - REGLE MICROSOFT PAR NOM DE SERVICE SUR ' + $Cible)
    New-NetFirewallRule -DisplayName $Regle -Direction Outbound -Action Block `
        -Service $Cible -Enabled True -Profile Any | Out-Null

    $t = Table-Filtres
    Write-Host ("  filtres produits par la regle : {0}" -f $t.Notres.Count)
    if ($t.Notres.Count -eq 0) { throw 'la regle ne produit aucun filtre WFP' }

    $couvreProfilActif = $false
    foreach ($f in $t.Notres) {
        $prof = ''
        $porteSid = $false
        foreach ($c in $f.filterCondition.item) {
            if ($c.fieldKey -eq 'FWPM_CONDITION_ORIGINAL_PROFILE_ID') { $prof = "$($c.conditionValue.uint32)" }
            if ($c.fieldKey -eq 'FWPM_CONDITION_ALE_USER_ID' -and $c.conditionValue.sd -match [regex]::Escape($sid)) { $porteSid = $true }
        }
        $marque = ''
        if ($profils.ContainsKey([int]$prof)) { $marque = '  <== profil actif'; if ($porteSid) { $couvreProfilActif = $true } }
        Write-Host ("    rtid={0,-8} couche={1,-32} profil={2} sid={3}{4}" -f `
                $f.filterId, $f.layerKey, $prof, $porteSid, $marque)
    }
    Write-Host ("  un filtre portant le SID couvre le profil actif : {0}" -f $couvreProfilActif)
    if (-not $couvreProfilActif) { throw 'aucun filtre portant le SID ne couvre le profil actif: la mesure ne dirait rien' }

    $t0 = Get-Date
    if ($Declencheur -eq 'redemarrage') {
        & sc.exe stop $Cible | Out-Null
        Start-Sleep -Seconds 4
        & sc.exe start $Cible | Out-Null
        Start-Sleep -Seconds 4
    }
    else {
        & sc.exe start $Cible 2>&1 | Out-Null
        Start-Sleep -Seconds 3
    }
    $svc = Get-CimInstance Win32_Service -Filter ("Name='" + $Cible + "'")
    $pidC = $svc.ProcessId
    if (-not $pidC -or $pidC -eq 0) { throw "$Cible n a pas de processus" }
    $proc = Get-Process -Id $pidC -ErrorAction SilentlyContinue
    Write-Host ("  PID au depart : {0}  cree {1}" -f $pidC, $proc.StartTime.ToString('HH:mm:ss.fff'))

    if ($Declencheur -eq 'resync') {
        for ($i = 1; $i -le 5; $i++) {
            $sortie = (& w32tm /resync /force 2>&1) -join ' '
            Write-Host ("  resync {0} : {1}" -f $i, ($sortie -replace '\s+', ' '))
            Start-Sleep -Seconds 3
        }
    }
    Start-Sleep -Seconds $Attente

    $svc2 = Get-CimInstance Win32_Service -Filter ("Name='" + $Cible + "'")
    $proc2 = Get-Process -Id $svc2.ProcessId -ErrorAction SilentlyContinue
    if ($svc2.ProcessId -ne $pidC -or $proc2.StartTime -ne $proc.StartTime) {
        throw 'MESURE INVALIDE: le processus a change pendant la fenetre'
    }
    Write-Host ("  PID au releve : {0} (inchange)" -f $svc2.ProcessId)

    $t = Table-Filtres
    $ev = @(Get-WinEvent -FilterHashtable @{LogName = 'Security'; Id = 5156, 5157; StartTime = $t0 } -ErrorAction SilentlyContinue)
    $aut = 0; $ref = 0; $refNotre = 0
    $vus = @{}
    foreach ($e in $ev) {
        $x = [xml]$e.ToXml(); $d = @{}
        foreach ($c in $x.Event.EventData.Data) { $d[$c.Name] = $c.'#text' }
        if ($d['ProcessID'] -ne [string]$pidC) { continue }
        if ($Port -ne 0 -and $d['DestPort'] -ne [string]$Port) { continue }
        if ($e.Id -eq 5156) { $aut++ } else {
            $ref++
            if ($t.Map["$($d['FilterRTID'])"] -eq $Regle) { $refNotre++ }
        }
        $cle = "{0}|{1}" -f $e.Id, $d['FilterRTID']
        if (-not $vus.ContainsKey($cle)) {
            $vus[$cle] = $true
            $verdict = if ($e.Id -eq 5156) { 'AUTORISEE' } else { 'REFUSEE  ' }
            $nom = $t.Map["$($d['FilterRTID'])"]
            if (-not $nom) { $nom = '(nom introuvable dans le dump)' }
            Write-Host ("  {0} rtid={1} layer={2} dst={3}:{4}  filtre={5}" -f `
                    $verdict, $d['FilterRTID'], $d['LayerRTID'], $d['DestAddress'], $d['DestPort'], $nom)
        }
    }
    if ($Port -ne 0) { Write-Host ("  (restreint au port de destination {0})" -f $Port) }
    Write-Host ("  autorisees={0}  refusees={1}  dont refusees PAR NOTRE REGLE={2}" -f $aut, $ref, $refNotre)
    if ($aut -eq 0 -and $ref -eq 0) { Write-Host '  TEMOIN MUET: aucun evenement, la mesure ne dit rien.' }
    $res = @{ Aut = $aut; Ref = $ref; RefNotre = $refNotre }
}
finally {
    Titre 'menage'
    $r = Get-NetFirewallRule -DisplayName $Regle -ErrorAction SilentlyContinue
    if ($r) { $r | Remove-NetFirewallRule; Write-Host '  regle retiree' } else { Write-Host '  aucune regle a retirer' }
    $t = Table-Filtres
    Write-Host ("  filtres residuels portant le nom de la regle : {0}" -f $t.Notres.Count)
    & auditpol /set /subcategory:"$Sous" /success:disable /failure:enable | Out-Null
    $auditApres = ((& auditpol /get /subcategory:"$Sous") -join ' ') -replace '\s+', ' '
    Write-Host ("  audit apres : {0}" -f $auditApres)
    $svc = Get-CimInstance Win32_Service -Filter ("Name='" + $Cible + "'")
    Write-Host ("  {0} : {1}" -f $Cible, $svc.State)
}

Titre 'VERDICT'
if ($null -eq $res) { Write-Host '  passage invalide ou abandonne' }
elseif ($res.Aut -eq 0 -and $res.Ref -eq 0) { Write-Host ("  SANS OBJET: {0} n a rien emis." -f $Cible) }
elseif ($res.RefNotre -gt 0 -and $res.Aut -eq 0) { Write-Host ("  LA REGLE MICROSOFT MORD sur {0}." -f $Cible) }
elseif ($res.RefNotre -gt 0) { Write-Host ("  FUITE: notre regle a refuse {0} fois mais {1} connexions sont passees." -f $res.RefNotre, $res.Aut) }
elseif ($res.Ref -gt 0) { Write-Host ("  ECHEC de notre regle: les {0} refus viennent d AUTRES filtres." -f $res.Ref) }
else { Write-Host ("  LA REGLE MICROSOFT ECHOUE sur {0}." -f $Cible) }

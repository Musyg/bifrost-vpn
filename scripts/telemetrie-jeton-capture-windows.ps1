param([int]$Attente = 45)

# CE BANC MESURE L USURPATION D IDENTITE AU MOMENT DE LA CREATION DE LA SOCKET.
#
# Un blocage WFP par SID de service mord sur W32Time et sur trois services de
# test, et n a jamais mordu sur DiagTrack ni DoSvc - pas davantage quand c est
# New-NetFirewallRule -Service qui le pose, cf.
# telemetrie-regle-microsoft-windows.ps1. La cause documentee est que
# FWPM_CONDITION_ALE_USER_ID n est pas une comparaison de SID mais un CONTROLE
# D ACCES contre le jeton capture A LA CREATION DE LA SOCKET: si le thread
# usurpe l identite d un client a cet instant, le SID de service n est pas dans
# le jeton compare.
#
# CE QU IL LIT. L en-tete d un net event WFP porte <userId>: l utilisateur du
# jeton capture. Il n est renseigne que sur un REFUS. On force donc un refus par
# une regle qui ne depend d AUCUNE identite - adresse ou port de destination -
# et on lit le champ.
#
# PREDICTION, ET ELLE EST FALSIFIABLE.
#   W32Time (se bloque) -> userId = S-1-5-19, son propre compte
#   DoSvc   (echappe)   -> userId != S-1-5-20, donc pas son compte
# Si DoSvc rend S-1-5-20, l usurpation est REFUTEE et il faut chercher ailleurs.
# Le passage W32Time n est pas decoratif: sans lui, un banc qui ne lirait RIEN
# rendrait la meme sortie qu un banc qui lit un jeton non usurpe.
#
# QUATRE DEFAUTS DE LECTURE ONT ETE TRAVERSES AVANT D OBTENIR LE CHIFFRE, et
# chacun est garde par une ligne de ce script:
#
# 1. Le tamis rendait zero et le banc accusait l instrument. Il compte
#    desormais a CHAQUE etage, et son diagnostic propose MA lecture en premier.
# 2. Sur 25H2 le type est FWPM_NET_EVENT_TYPE_PUBLIC_CLASSIFY_DROP, pas
#    FWPM_NET_EVENT_TYPE_CLASSIFY_DROP comme le montrent les sources de 2019.
#    Une egalite stricte ecartait les 100 refus en silence; on accepte les deux
#    formes et on compte les types vus, pour qu une TROISIEME se voie.
# 3. [datetime]::TryParseExact avec une liste de formats: en PowerShell, @(...)
#    est un Object[] et non un String[], la surcharge se lie mal, et 90
#    horodates sur 90 deviennent illisibles. TryParse en culture invariante lit
#    l ISO sans qu on ait a deviner un format, et evite la culture francaise de
#    la machine d essai, qui refuse la forme ISO.
# 4. Un net event ne porte PAS de PID, et son appId vaut svchost.exe, partage
#    par des dizaines de services. Attribuer un jeton a une cible etait une
#    INFERENCE. On joint desormais le 5157, qui porte le PID, au net event, qui
#    porte le jeton, par le triplet port local + adresse distante + port
#    distant. Mesure du 23/08: sur 10 refus imputes a la regle, 4 seulement
#    etaient de la cible.
#
# La fenetre de temps n est pas un confort: show netevents est un TAMPON
# CIRCULAIRE et les rtid sont REUTILISES quand un filtre est retire, donc un
# evenement perime peut porter l identifiant aujourd hui attribue a notre regle.
#
# ETAT REMIS COMME TROUVE: l option netevents et la politique d audit sont
# relues au depart et restaurees, les regles posees sont retirees.

$ErrorActionPreference = 'Stop'
$Sous = '{0CCE9226-69AE-11D9-BED3-505054503030}'
$Regle = 'bifrost-essai-jeton'

function Titre($t) { Write-Host ''; Write-Host ('== ' + $t) }

function Etat-Netevents {
    $s = ((& netsh wfp show options optionsFor=NETEVENTS) -join ' ') -replace '\s+', ' '
    if ($s -match '(?i)NETEVENTS\s*=\s*(on|off)') { return $Matches[1].ToLower() }
    return "inconnu ($s)"
}

function Ids-De-Notre-Regle {
    $dump = Join-Path $env:TEMP 'jeton-filtres.xml'
    & netsh wfp show filters file="$dump" | Out-Null
    $xml = New-Object System.Xml.XmlDocument
    $xml.Load($dump)
    $ids = @{}
    foreach ($item in $xml.SelectNodes('//item[filterKey]')) {
        if ("$($item.displayData.name)" -eq $Regle) { $ids["$($item.filterId)"] = $true }
    }
    Remove-Item $dump -ErrorAction SilentlyContinue
    return $ids
}

# Compte a chaque etage du tamis. Un zero au bout ne dit rien; un zero situe dit
# tout. On lit l en-tete par le DOM, jamais par un decoupage sur <item>: <item>
# sert aussi aux elements imbriques.
function Bilan-Netevents($ids, $depuis, $parConnexion) {
    $dump = Join-Path $env:TEMP 'jeton-netevents.xml'
    & netsh wfp show netevents file="$dump" | Out-Null
    if (-not (Test-Path $dump)) { return @{ Erreur = 'netsh n a produit aucun fichier' } }
    $taille = (Get-Item $dump).Length
    $xml = New-Object System.Xml.XmlDocument
    $xml.Load($dump)

    $b = @{
        Octets = $taille; Total = 0; Drops = 0; Datables = 0; Illisibles = 0
        DansFenetre = 0; ANous = 0; Trouves = @(); IdsVus = @{}; Types = @{}
    }
    # PAS de TryParseExact avec une liste de formats: en PowerShell, @(...) est
    # un Object[] et non un String[], la surcharge se lie mal et TOUTES les
    # horodates deviennent illisibles - mesure du 23/08, 90 sur 90. TryParse en
    # culture invariante lit l ISO sans qu on ait a deviner le format, et evite
    # au passage la culture francaise de cette machine, qui refuse la forme ISO.
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    $limite = $depuis.ToUniversalTime()

    foreach ($ev in $xml.SelectNodes('//item[header]')) {
        $b.Total++
        # 25H2 rend PUBLIC_CLASSIFY_DROP la ou les sources de 2019 montrent
        # CLASSIFY_DROP. On accepte les deux, et on compte les types vus pour
        # qu une TROISIEME forme se voie au lieu de disparaitre.
        $ty = "$($ev.type)"
        $b.Types[$ty] = 1 + [int]$b.Types[$ty]
        if ($ty -notlike '*CLASSIFY_DROP') { continue }
        $b.Drops++
        $fid = "$($ev.classifyDrop.filterId)"
        $quand = [datetime]::MinValue
        if ([datetime]::TryParse("$($ev.header.timeStamp)", $inv, $styles, [ref]$quand)) { $b.Datables++ }
        else { $b.Illisibles++; continue }
        if ($quand -lt $limite) { continue }
        $b.DansFenetre++
        $b.IdsVus[$fid] = $true
        if (-not $ids.ContainsKey($fid)) { continue }
        $b.ANous++
        $cleJointure = "{0}|{1}|{2}" -f "$($ev.header.localPort)", `
            "$($ev.header.remoteAddrV4)$($ev.header.remoteAddrV6)", "$($ev.header.remotePort)"
        $pidJoint = $parConnexion[$cleJointure]
        if (-not $pidJoint) { $pidJoint = 'non joint' }
        $b.Trouves += [pscustomobject]@{
            FilterId = $fid
            Pid      = $pidJoint
            Drapeaux = (($ev.header.flags.item) -join ' ')
            UserId   = "$($ev.header.userId)"
            AppId    = ("$($ev.header.appId.asString)" -replace '\.', '')
            Remote   = "$($ev.header.remoteAddrV4)$($ev.header.remoteAddrV6)"
            RemPort  = "$($ev.header.remotePort)"
            Quand    = $quand
        }
    }
    Remove-Item $dump -ErrorAction SilentlyContinue
    return $b
}

# Second instrument, independant: le journal de securite. On sait par mesure du
# 23/08 qu il enregistre les refus de ces regles.
function Bilan-Audit($ids, $depuis) {
    $ev = @(Get-WinEvent -FilterHashtable @{LogName = 'Security'; Id = 5157; StartTime = $depuis } -ErrorAction SilentlyContinue)
    $anous = 0; $autres = 0
    # Table de jointure: triplet de connexion -> PID. Le net event n a pas de
    # PID, le 5157 n a pas de jeton; c est ce triplet qui les recolle.
    $parConnexion = @{}
    foreach ($e in $ev) {
        $x = [xml]$e.ToXml(); $d = @{}
        foreach ($c in $x.Event.EventData.Data) { $d[$c.Name] = $c.'#text' }
        if ($ids.ContainsKey("$($d['FilterRTID'])")) {
            $anous++
            $cle = "{0}|{1}|{2}" -f $d['SourcePort'], $d['DestAddress'], $d['DestPort']
            $parConnexion[$cle] = $d['ProcessID']
        }
        else { $autres++ }
    }
    return @{ ANous = $anous; Autres = $autres; Total = $ev.Count; ParConnexion = $parConnexion }
}

function Passe($titre, $cible, $parametres, $declencheur) {
    Titre $titre
    $compte = (Get-CimInstance Win32_Service -Filter ("Name='" + $cible + "'")).StartName
    Write-Host ("  {0} tourne sous {1}" -f $cible, $compte)

    Get-NetFirewallRule -DisplayName $Regle -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
    $arg = @{ DisplayName = $Regle; Direction = 'Outbound'; Action = 'Block'; Enabled = 'True'; Profile = 'Any' }
    foreach ($k in $parametres.Keys) { $arg[$k] = $parametres[$k] }
    New-NetFirewallRule @arg | Out-Null
    $ids = Ids-De-Notre-Regle
    Write-Host ("  filtres produits : {0}  (rtid {1})" -f $ids.Count, (($ids.Keys | Sort-Object) -join ' '))
    if ($ids.Count -eq 0) { Write-Host '  ABANDON: aucun filtre.'; return }

    $t0 = (Get-Date).AddSeconds(-2)
    & $declencheur
    Start-Sleep -Seconds $Attente

    $a = Bilan-Audit $ids $t0
    Write-Host ("  AUDIT 5157   : {0} refus dont {1} par notre regle" -f $a.Total, $a.ANous)

    $b = Bilan-Netevents $ids $t0 $a.ParConnexion
    if ($b.Erreur) { Write-Host ("  NETEVENTS    : ECHEC - {0}" -f $b.Erreur); return }
    Write-Host ("  NETEVENTS    : fichier {0} octets, {1} evenements, {2} refus," -f $b.Octets, $b.Total, $b.Drops)
    Write-Host ("                 {0} datables, {1} horodates illisibles, {2} dans la fenetre, {3} a nous" -f `
            $b.Datables, $b.Illisibles, $b.DansFenetre, $b.ANous)
    foreach ($k in ($b.Types.Keys | Sort-Object)) { Write-Host ("                 type {0} : {1}" -f $k, $b.Types[$k]) }
    if ($b.DansFenetre -gt 0 -and $b.ANous -eq 0) {
        Write-Host ("                 rtid vus dans la fenetre : {0}" -f (($b.IdsVus.Keys | Sort-Object) -join ' '))
    }

    if ($b.ANous -eq 0) {
        if ($a.ANous -gt 0 -and $b.Drops -eq 0) {
            Write-Host '  DIAGNOSTIC: la regle MORD (5157 le dit) et le dump ne contient AUCUN refus'
            Write-Host '              d aucune sorte. Suspecter MA LECTURE avant l instrument:'
            Write-Host ("              types vus dans le dump : {0}" -f (($b.Types.Keys | Sort-Object) -join ', '))
        }
        elseif ($a.ANous -gt 0) {
            Write-Host '  DIAGNOSTIC: la regle MORD (5157 le dit), le dump porte des refus, mais aucun'
            Write-Host '              a nous dans la fenetre. Suspecter la fenetre ou les identifiants.'
        }
        elseif ($a.Total -eq 0) {
            Write-Host '  DIAGNOSTIC: aucun refus nulle part. Le service n a probablement pas emis.'
        }
        else {
            Write-Host '  DIAGNOSTIC: des refus existent mais aucun ne vient de notre regle.'
        }
    }
    else {
        $pidCible = (Get-CimInstance Win32_Service -Filter ("Name='" + $cible + "'")).ProcessId
        Write-Host ("  PID de {0} au moment du releve : {1}" -f $cible, $pidCible)
        $vus = @{}
        foreach ($r in $b.Trouves) {
            $cle = "{0}|{1}|{2}" -f $r.UserId, $r.Remote, $r.RemPort
            if ($vus.ContainsKey($cle)) { continue }
            $vus[$cle] = $true
            $marque = if ($r.Pid -eq [string]$pidCible) { "  <== C EST BIEN $cible" } else { '' }
            Write-Host ("    pid={0,-8} userId={1,-46} dst={2}:{3}{4}" -f $r.Pid, $r.UserId, $r.Remote, $r.RemPort, $marque)
            Write-Host ("    appId ={0}" -f $r.AppId)
            Write-Host ("    flags ={0}" -f $r.Drapeaux)
        }
        # Le verdict ne retient QUE les refus joints au PID de la cible. Les
        # autres appartiennent a d autres processus tombes dans la meme regle;
        # les melanger rendrait une mesure qui ne parle de personne.
        $aLaCible = @($b.Trouves | Where-Object { $_.Pid -eq [string]$pidCible })
        $nonJoints = @($b.Trouves | Where-Object { $_.Pid -eq 'non joint' })
        Write-Host ("  refus joints au PID de la cible : {0} sur {1}  (non joints: {2})" -f `
                $aLaCible.Count, $b.Trouves.Count, $nonJoints.Count)
        if ($aLaCible.Count -eq 0) {
            Write-Host '  SANS OBJET: aucun refus ne se rattache au processus de la cible.'
            Write-Host '  La mesure ne dit rien du jeton de ce service.'
        }
        else {
            $comptes = @{}
            foreach ($r in $aLaCible) { $comptes[$r.UserId] = $true }
            Write-Host ("  UTILISATEUR DU JETON CAPTURE : {0}" -f (($comptes.Keys | Sort-Object) -join ', '))
            Write-Host ("  COMPTE D EXECUTION DU SERVICE : {0}" -f $compte)
        }
    }

    Get-NetFirewallRule -DisplayName $Regle -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Write-Host '  regle retiree'
}

$neAvant = Etat-Netevents
Write-Host ("netevents avant : {0}" -f $neAvant)

try {
    & netsh wfp set options netevents=on | Out-Null
    & auditpol /set /subcategory:"$Sous" /success:enable /failure:enable | Out-Null

    Passe 'TEMOIN - W32Time, refuse par port de destination' 'W32Time' `
    @{ Protocol = 'UDP'; RemotePort = 123 } `
    {
        for ($i = 1; $i -le 4; $i++) {
            $s = ((& w32tm /resync /force 2>&1) -join ' ') -replace '\s+', ' '
            Write-Host ("    resync {0} : {1}" -f $i, $s)
            Start-Sleep -Seconds 3
        }
    }

    Passe 'CAS - DoSvc, refuse par plage de destination' 'DoSvc' `
    @{ RemoteAddress = '72.153.0.0/16' } `
    {
        & sc.exe stop DoSvc | Out-Null; Start-Sleep -Seconds 4
        & sc.exe start DoSvc | Out-Null; Start-Sleep -Seconds 4
        $p = (Get-CimInstance Win32_Service -Filter "Name='DoSvc'").ProcessId
        Write-Host ("    DoSvc redemarre, pid {0}" -f $p)
    }
}
finally {
    Titre 'menage'
    $r = Get-NetFirewallRule -DisplayName $Regle -ErrorAction SilentlyContinue
    if ($r) { $r | Remove-NetFirewallRule; Write-Host '  regle residuelle retiree' } else { Write-Host '  aucune regle residuelle' }
    switch ($neAvant) {
        'off' { & netsh wfp set options netevents=off | Out-Null; Write-Host '  netevents remis a off, comme trouve' }
        'on' { Write-Host '  netevents laisse a on, comme trouve' }
        default { Write-Host ("  ETAT INITIAL ILLISIBLE ({0}): a verifier a la main" -f $neAvant) }
    }
    & auditpol /set /subcategory:"$Sous" /success:disable /failure:enable | Out-Null
    Write-Host ("  audit apres : {0}" -f (((& auditpol /get /subcategory:"$Sous") -join ' ') -replace '\s+', ' '))
    foreach ($s in @('W32Time', 'DoSvc')) {
        Write-Host ("  {0} : {1}" -f $s, (Get-CimInstance Win32_Service -Filter ("Name='" + $s + "'")).State)
    }
}

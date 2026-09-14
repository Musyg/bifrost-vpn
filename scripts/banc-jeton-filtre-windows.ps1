# Un jeton FILTRE echappe-t-il au blocage ALE_USER_ID ? La question a reponse
# binaire, et le banc qui la tranche.
#
# A lancer sur essai-windows, en administrateur, shell cmd, depuis la racine du
# banc (le repertoire qui contient les binaires) ou avec BIFROST_BANC pose:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\banc-jeton-filtre-windows.ps1
#
# CONTEXTE. La couche 2 bloque un service par son SID de service, via un filtre
# WFP portant FWPM_CONDITION_ALE_USER_ID. Cette condition n'est pas un SID mais
# un DESCRIPTEUR DE SECURITE: WFP fait un controle d'acces du jeton du processus
# contre D:(A;;0x1;;;<SID>). Trois mesures ont ete faites, toutes avec la meme
# forme de filtre:
#
#   1. sur un service de test fabrique, le blocage MORD: 0 autorisee,
#      569 refusees, le 5157 nommant notre filtre;
#   2. sur DiagTrack, le blocage ne mord pas: 2 connexions autorisees avec les
#      8 filtres verifies presents, et le 5156 nommant un filtre d'autorisation
#      qui n'est pas a nous. Chez WFP un blocage bat une autorisation: si une
#      autorisation gagne, c'est que notre filtre n'a PAS MATCHE;
#   3. la comparaison des deux jetons n'a laisse subsister qu'UNE difference:
#      TokenHasRestrictions vaut 1 pour DiagTrack et 0 pour le temoin. Le SID de
#      service est present et ENABLED dans les deux, attributs identiques au bit
#      pres, aucun USE_FOR_DENY_ONLY, aucun SID restreignant.
#
# La cause de cet etat est connue: DiagTrack declare une valeur
# RequiredPrivileges dans la base de registre, donc le SCM construit son jeton
# en FILTRANT celui de LocalSystem. Ce que PERSONNE ne sait, c'est si cet etat
# change quoi que ce soit au controle d'acces.
#
# CE QUE CE BANC MESURE. Il fabrique DEUX services de test identiques en tout
# sauf l'etat filtre de leur jeton - meme binaire, memes arguments, meme
# SERVICE_SID_TYPE unrestricted, meme compte - et mesure sur chacun si le
# blocage de la couche 2 mord. La liste RequiredPrivileges du second est LUE
# dans la base de registre du service de reference, jamais recopiee en dur: si
# elle change, le banc suit.
#
# CE QUI REND LA MESURE VALIDE, ET SANS QUOI ELLE NE VAUT RIEN.
#
#   - Le temoin doit SORTIR avant qu'on mesure qu'on l'arrete. Chaque service
#     fait donc un passage SANS sonde. Zero connexion autorisee a ce passage et
#     le banc se declare SKIPPED: une absence de connexion ne discriminerait
#     rien. Vecu le 22 aout 2026 avec CompatTelRunner, reste muet parce que ses
#     taches planifiees n'avaient jamais tourne - mesure le 23/08/2026.
#   - Les deux jetons doivent VRAIMENT differer: TokenHasRestrictions 0 d'un
#     cote, 1 de l'autre. Sinon la comparaison ne compare rien, et le banc se
#     declare SKIPPED avant meme de poser un filtre.
#   - Un PID cueilli au vol peut appartenir a un autre processus: les deux
#     services portent le meme binaire et les memes arguments. On releve donc
#     les PID vivants AVANT de demarrer, on n'accepte qu'un PID absent de ce
#     releve, et on verifie a chaque passage que le jeton lu porte bien le SID
#     de service du service demande. Vecu: PID 1836 lu deux fois, le jeton du
#     second temoin portant le SID du premier, et la mesure fausse se lisait
#     exactement comme une vraie.
#   - Les evenements sont discrimines par la DESTINATION autant que par le PID:
#     le meme binaire sert aussi a poser les filtres depuis la session admin.
#
# CE QUE CE BANC REMET EN ETAT, y compris en sortant sur une erreur: filtres
# retires, les DEUX services supprimes, politique d'audit remise a
# /success:disable /failure:enable. Un service dont le binaire ne dialogue pas
# avec le SCM ne repond pas a sc stop, et sc delete ne fait que le MARQUER tant
# que le processus vit: on attend et on reverifie en boucle.
#
# CE QUE CE BANC NE FAIT PAS. Il ne touche a aucun service existant: le service
# de reference n'est que LU, dans la base de registre. Il ne lance aucun
# autotest bloquant.

param(
    # La racine du banc: le repertoire du script (via -File), ou BIFROST_BANC si pose.
    [string]$Banc = $(if ($env:BIFROST_BANC) { $env:BIFROST_BANC } else { $PSScriptRoot }),
    # Le daemon, qui sert de binaire aux deux services de test.
    [string]$Binaire = (Join-Path $Banc 'bifrost-daemon.exe'),
    [string]$Cible = '1.1.1.1:443',
    [int]$Rafale = 8000,
    # Le service dont le jeton n'est PAS filtre.
    [string]$ServiceLibre = 'bifrost-jetonlibre',
    # Le meme, plus les RequiredPrivileges du service de reference.
    [string]$ServiceFiltre = 'bifrost-jetonfiltre',
    # Le service dont le blocage ne mord pas. LU seulement.
    [string]$ServiceReference = 'DiagTrack',
    # Le lecteur de jeton deja eprouve. On lui reprend sa partie C# plutot que
    # d'en ecrire une seconde: deux implementations qui divergent rendraient
    # deux mesures qu'on ne pourrait pas comparer.
    [string]$LecteurJeton = (Join-Path $Banc 'jetons-compare-windows.ps1')
)

# La racine du banc doit etre connue. Lance autrement que par -File et sans
# BIFROST_BANC, $Banc est vide et les chemins derives seraient faux.
if ([string]::IsNullOrEmpty($Banc)) {
    throw "Banc introuvable: lancer ce script par -File depuis la racine du banc (le repertoire qui contient les binaires), ou poser BIFROST_BANC sur ce repertoire."
}

$ErrorActionPreference = 'Continue'

# Object Access / Filtering Platform Connection: la sous-categorie qui porte les
# 5156 et 5157. Designee par son GUID, jamais par son nom: sur une machine en
# locale francaise le nom est traduit.
$Sous = '{0CCE9226-69AE-11D9-BED3-505054503030}'
# Le prefixe des cles de filtre de la couche 2 (cf. la constante BASE dans
# crates/bifrost-firewall/src/windows/mod.rs). Ce qui porte ce prefixe est a
# nous, le reste ne l'est pas.
$PrefixeCle = '3ac9d182-5e42-4b77-9d61-8e05f3a2'
$CibleIp = ($Cible -split ':')[0]
$NomImage = Split-Path -Leaf $Binaire

$script:servicesCrees = @()
$script:auditTouche = $false

# --------------------------------------------------------------- lecture WFP

function Dump-Wfp {
    $f = Join-Path $env:SystemRoot 'Temp\bifrost-jeton-filtre.xml'
    if (Test-Path $f) { Remove-Item $f -Force }
    $null = & netsh wfp show filters file="$f" 2>&1
    if (-not (Test-Path $f)) { return $null }
    $t = Get-Content $f -Raw
    Remove-Item $f -Force
    return $t
}

# Nos filtres a nous.
function Table-Nos($dump) {
    $r = [regex]::new("<filterKey>\{$PrefixeCle[0-9a-f]{4}\}</filterKey>.*?<displayData>\s*<name>([^<]*)</name>.*?<filterId>(\d+)</filterId>",
        [Text.RegularExpressions.RegexOptions]::Singleline -bor [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $res = @{}
    foreach ($m in $r.Matches($dump)) { $res[$m.Groups[2].Value] = $m.Groups[1].Value }
    return $res
}

# TOUS les filtres du moteur. Sert a NOMMER le gagnant quel qu'il soit, y
# compris s'il ne nous appartient pas: c'est precisement le cas interessant.
function Table-Tous($dump) {
    $r = [regex]::new("<filterKey>\{[0-9a-f-]+\}</filterKey>.*?<name>([^<]*)</name>.*?<filterId>(\d+)</filterId>",
        [Text.RegularExpressions.RegexOptions]::Singleline -bor [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $res = @{}
    foreach ($m in $r.Matches($dump)) { $res[$m.Groups[2].Value] = $m.Groups[1].Value }
    return $res
}

# ------------------------------------------------------- lecture des journaux

function Detail($e) {
    $x = [xml]$e.ToXml()
    $d = @{}
    foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
    return $d
}

# Deux discriminants, pas un: la destination ET le PID. La destination seule
# laisserait passer les tentatives de la session admin; le PID seul ferait
# confiance a une cueillette au vol.
function Evenements($marque, $id, $idproc) {
    $out = @()
    foreach ($e in @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$id; StartTime=$marque} -ErrorAction SilentlyContinue)) {
        $d = Detail $e
        if ($d['DestAddress'] -ne $CibleIp) { continue }
        if ("$($d['ProcessID'])" -ne "$idproc") { continue }
        $out += $d
    }
    return $out
}

function Nommer-Gagnants($etiquette, $liste, $nos, $tous, $combien) {
    foreach ($d in ($liste | Select-Object -First $combien)) {
        $rt = $d['FilterRTID']
        $nom = '(absent du dump)'
        if ($tous.ContainsKey($rt)) { $nom = $tous[$rt] }
        $notre = 'non'
        if ($nos.ContainsKey($rt)) { $notre = 'OUI' }
        Write-Host ("      {0}  rtid={1} layer={2} a nous={3}" -f $etiquette, $rt, $d['LayerRTID'], $notre)
        Write-Host ("         nom du gagnant  : {0}" -f $nom)
        Write-Host ("         FilterOrigin    : {0}" -f $d['FilterOrigin'])
    }
}

# ------------------------------------------------------- lecture des jetons
#
# La partie C# vient telle quelle de jetons-compare-windows.ps1: on extrait le
# here-string qui la porte et on la compile ici. On ne recopie pas ce code, et
# on n'en ecrit pas un second: le marshalling de TOKEN_GROUPS a deja coute
# assez de fautes silencieuses pour qu'on n'en entretienne qu'une version.

function Charger-Lecteur {
    if ('BifrostJeton' -as [type]) { return '' }
    if (-not (Test-Path $LecteurJeton)) { return "lecteur de jeton introuvable: $LecteurJeton" }
    $lignes = @(Get-Content -LiteralPath $LecteurJeton)
    $debut = -1
    $fin = -1
    for ($i = 0; $i -lt $lignes.Count; $i++) {
        if ($debut -lt 0) {
            if ($lignes[$i] -eq "`$source = @'") { $debut = $i + 1 }
            continue
        }
        if ($lignes[$i] -eq "'@") { $fin = $i - 1; break }
    }
    if ($debut -lt 0) { return "pas de here-string C# dans $LecteurJeton" }
    if ($fin -lt $debut) { return "here-string C# non termine dans $LecteurJeton" }
    $src = ($lignes[$debut..$fin] -join [Environment]::NewLine)
    Add-Type -TypeDefinition $src -Language CSharp
    if (-not ('BifrostJeton' -as [type])) { return 'Add-Type n a pas defini BifrostJeton' }
    return ''
}

# Rend l'etat du jeton d'un PID: l'etat filtre, le nombre de privileges, le SID
# de service, et les lignes brutes, qui sont ce qu'on cite dans un rapport.
function Lire-Jeton($idproc) {
    $lignes = @([BifrostJeton]::Decrire([uint32]$idproc))
    $o = New-Object psobject
    $o | Add-Member NoteProperty Brut       $lignes
    $o | Add-Member NoteProperty Ouverture  ''
    $o | Add-Member NoteProperty HasRestr   ''
    $o | Add-Member NoteProperty Restreint  ''
    $o | Add-Member NoteProperty NbPriv     0
    $o | Add-Member NoteProperty Privileges @()
    $o | Add-Member NoteProperty SidService ''
    $o | Add-Member NoteProperty Groupes    @()
    foreach ($l in $lignes) {
        $p = $l -split '\|'
        switch ($p[0]) {
            'OUVERTURE'              { $o.Ouverture = ($p[1..($p.Count - 1)] -join ' ') }
            'TOKEN_HAS_RESTRICTIONS' { $o.HasRestr = $p[1] }
            'IS_TOKEN_RESTRICTED'    { $o.Restreint = $p[1] }
            'SID_SERVICE_TROUVE'     { $o.SidService = $p[1] }
            'PRIVILEGE'              { $o.NbPriv = $o.NbPriv + 1; $o.Privileges = @($o.Privileges) + @($p[2]) }
            'GROUPE'                 { $o.Groupes = @($o.Groupes) + @($p[2]) }
        }
    }
    return $o
}

# ------------------------------------------------------------- contexte SCM

# Le PID se prend par CIM, jamais en analysant "sc queryex": un Select-String
# sur une chaine multiligne rend un seul MatchInfo qui porte tout le texte, ce
# qui a deja produit un PID de vingt chiffres.
function Pid-De-Service($nom) {
    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$nom'" -ErrorAction SilentlyContinue
    if ($svc -eq $null) { return 0 }
    return [int]$svc.ProcessId
}

# Le SID que le SCM derive du nom. Le SID est insensible a la locale, seule
# l'etiquette autour ne l'est pas: on ne garde que le SID.
function Sid-De-Service($nom) {
    foreach ($l in @(& sc.exe showsid $nom)) {
        $m = [regex]::Match("$l", 'S-1-5-80(-\d+)+')
        if ($m.Success) { return $m.Value }
    }
    return ''
}

# Le SERVICE_SID_TYPE se lit dans la base de registre, pas dans la sortie de
# "sc qsidtype": sur une machine en locale francaise la VALEUR est traduite, et
# on ne compare jamais une chaine traduite. 0 = none, 1 = unrestricted,
# 3 = restricted.
function SidType-De-Service($nom) {
    $cle = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $nom
    $v = Get-ItemProperty -Path $cle -Name 'ServiceSidType' -ErrorAction SilentlyContinue
    if ($v -eq $null) { return '(absent de la base de registre, donc 0 = none)' }
    $n = [int]$v.ServiceSidType
    $etiq = 'valeur inattendue'
    if ($n -eq 0) { $etiq = 'SERVICE_SID_TYPE_NONE' }
    elseif ($n -eq 1) { $etiq = 'SERVICE_SID_TYPE_UNRESTRICTED' }
    elseif ($n -eq 3) { $etiq = 'SERVICE_SID_TYPE_RESTRICTED' }
    return "$n ($etiq)"
}

# La liste RequiredPrivileges, LUE. Jamais recopiee en dur: si le service de
# reference change sa liste, le banc doit suivre, pas mesurer une liste morte.
function RequiredPrivileges-De-Service($nom) {
    $cle = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $nom
    $w = Get-ItemProperty -Path $cle -Name 'RequiredPrivileges' -ErrorAction SilentlyContinue
    if ($w -eq $null) { return @() }
    return @(@($w.RequiredPrivileges) | Where-Object { "$_" -ne '' })
}

function Recenser-Temoins {
    return @(Get-CimInstance -ClassName Win32_Process -Filter "Name='$NomImage'" -ErrorAction SilentlyContinue |
        Where-Object { "$($_.CommandLine)" -like '*--connect-probe-rafale*' } |
        Select-Object -ExpandProperty ProcessId)
}

# --------------------------------------------------------------- fabrication

# Deux services identiques en tout sauf l'etat filtre de leur jeton. $privs,
# s'il est non vide, est pose par "sc privs": le SCM construit alors le jeton du
# service en FILTRANT celui de LocalSystem pour n'y laisser que ces privileges.
function Creer-Service($nom, $privs) {
    # Garde-fou. Ces bancs appellent `sc delete` sur le nom qu'on leur donne, et
    # un nom passe en parametre peut etre celui d'un VRAI service: DiagTrack est
    # deja un parametre de l'un d'eux. On refuse donc tout nom qui ne porte pas
    # le prefixe reserve aux temoins. Ce n'est pas de la paranoia: supprimer un
    # service systeme par une faute de frappe ne se repare pas d'un `sc create`,
    # la configuration d'origine etant perdue.
    if ($nom -notlike 'bifrost-*') {
        Write-Host ("REFUS: {0} ne porte pas le prefixe bifrost-. Ce banc ne fabrique et ne supprime que ses propres temoins." -f $nom)
        throw "nom de service de test refuse: $nom"
    }
    $null = & sc.exe delete $nom    # au cas ou un passage precedent aurait laisse quelque chose
    $null = & sc.exe create $nom binPath= "`"$Binaire`" --connect-probe $Cible --connect-probe-rafale $Rafale" type= own start= demand
    if ($LASTEXITCODE -ne 0) {
        Write-Host ("ECHEC: creation du service {0}" -f $nom)
        return $false
    }
    $script:servicesCrees = @($script:servicesCrees) + @($nom)
    $null = & sc.exe sidtype $nom unrestricted
    if ($LASTEXITCODE -ne 0) {
        Write-Host ("ECHEC: sc sidtype {0} unrestricted a rendu {1}" -f $nom, $LASTEXITCODE)
        return $false
    }
    if (@($privs).Count -gt 0) {
        $arg = (@($privs) -join '/')
        $null = & sc.exe privs $nom $arg
        if ($LASTEXITCODE -ne 0) {
            Write-Host ("ECHEC: sc privs {0} a rendu {1}, le jeton ne serait pas filtre" -f $nom, $LASTEXITCODE)
            return $false
        }
    }
    return $true
}

# ------------------------------------------------------------ un passage

# Un passage = un etat de filtre, un demarrage du service, une lecture des
# journaux. $sidPose vide veut dire: aucune sonde, on etablit que le temoin sort.
function Passage($service, $sidAttendu, $sidPose, $etiquette) {
    Write-Host ''
    Write-Host ("-- {0} --" -f $etiquette)

    if ("$sidPose" -ne '') {
        $sortie = & $Binaire --telemetrie-sonde-sid $sidPose 2>&1
        $rc = $LASTEXITCODE
        foreach ($l in @($sortie)) { Write-Host ("      {0}" -f $l) }
        if ($rc -ne 0) {
            Write-Host ("   ECHEC: la sonde n a rien pose (code {0})" -f $rc)
            return $null
        }
    } else {
        $sortie = & $Binaire --telemetrie-reseau-retirer 2>&1
        foreach ($l in @($sortie)) { Write-Host ("      {0}" -f $l) }
    }

    $dump = Dump-Wfp
    if ($dump -eq $null) {
        Write-Host '   ECHEC: netsh wfp show filters n a rien rendu, le gagnant serait innommable'
        return $null
    }
    $nos = Table-Nos $dump
    $tous = Table-Tous $dump
    Write-Host ("   filtres a nous dans le moteur : {0}" -f $nos.Count)
    foreach ($k in @($nos.Keys)) { Write-Host ("      pose  id={0}  {1}" -f $k, $nos[$k]) }

    # Les PID vivants AVANT le demarrage. Sans ce releve, le second temoin se
    # lit sur le processus du premier, encore vivant pour la duree de sa rafale.
    $avant = @(Recenser-Temoins)
    if ($avant.Count -gt 0) {
        Write-Host ("   {0} processus temoin encore vivant(s), on attend leur fin: {1}" -f $avant.Count, ($avant -join ', '))
        for ($w = 0; $w -lt 300; $w++) {
            Start-Sleep -Milliseconds 100
            if (@(Recenser-Temoins).Count -eq 0) { $avant = @(); break }
        }
        if ($avant.Count -gt 0) {
            Write-Host ("   ils n ont pas fini, ils restent exclus du releve: {0}" -f ($avant -join ', '))
        }
    }

    $marque = (Get-Date).AddSeconds(-1)
    $depart = Get-Date
    # sc start ne rend la main que si le binaire dialogue avec le SCM, ce que
    # --connect-probe ne fait pas: on lance sans bloquer et on cueille le PID au
    # vol pendant la rafale. Une fois le handle ouvert, le jeton reste lisible.
    Start-Process -FilePath 'sc.exe' -ArgumentList 'start', $service -NoNewWindow

    $idproc = 0
    for ($i = 0; $i -lt 200; $i++) {
        Start-Sleep -Milliseconds 100
        $p = Pid-De-Service $service
        if ($p -gt 0 -and ($avant -notcontains $p)) { $idproc = $p; break }
        # Repli: si le SCM ne publie pas encore le PID, on retrouve le processus
        # par sa ligne de commande. Filtre sur le nom d'image, sinon on enumere
        # tous les processus a chaque tour et la rafale s acheve avant.
        $pr = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='$NomImage'" -ErrorAction SilentlyContinue |
            Where-Object { "$($_.CommandLine)" -like '*--connect-probe-rafale*' } |
            Where-Object { $avant -notcontains $_.ProcessId })
        if ($pr.Count -ge 1) { $idproc = [int]$pr[0].ProcessId; break }
    }
    if ($idproc -le 0) {
        Write-Host ("   SKIPPED  {0} n a pas expose de PID pendant la rafale de {1} ms." -f $service, $Rafale)
        Write-Host '            Sans PID il n y a ni jeton a lire ni evenement a attribuer.'
        return $null
    }
    Write-Host ("   PID retenu : {0}" -f $idproc)

    # Le jeton se lit a CHAQUE passage, pas une fois pour toutes: c'est lui qui
    # porte la garde. Un PID cueilli au vol peut appartenir a l autre temoin, et
    # une mesure faite sur le mauvais processus se lit comme une vraie.
    $o = Lire-Jeton $idproc
    if (@($o.Groupes) -notcontains $sidAttendu) {
        Write-Host ("   ECHEC DE GARDE: le jeton du PID {0} ne porte pas {1}" -f $idproc, $sidAttendu)
        Write-Host ("                   SID de service lu dans ce jeton: {0}" -f $o.SidService)
        Write-Host ("                   ouverture: {0}" -f $o.Ouverture)
        Write-Host '                   mauvais processus, mesure jetee.'
        return $null
    }
    Write-Host ("   jeton      : TokenHasRestrictions={0}  IsTokenRestricted={1}  privileges={2}  SID={3}" -f `
        $o.HasRestr, $o.Restreint, $o.NbPriv, $o.SidService)

    # On laisse la rafale s achever. Le temps deja consomme par la cueillette du
    # PID compte: sans ca on attendrait deux fois.
    $ecoule = ((Get-Date) - $depart).TotalMilliseconds
    $reste = ($Rafale + 12000) - $ecoule
    if ($reste -gt 0) { Start-Sleep -Milliseconds ([int]$reste) }
    $null = & sc.exe stop $service

    $permis = @(Evenements $marque 5156 $idproc)
    $refuses = @(Evenements $marque 5157 $idproc)
    $notres = @($refuses | Where-Object { $nos.ContainsKey($_['FilterRTID']) }).Count
    Write-Host ("   RESULTAT   autorisees={0}  refusees={1}  dont par nos filtres={2}" -f `
        $permis.Count, $refuses.Count, $notres)
    Nommer-Gagnants 'AUTORISEE' $permis $nos $tous 2
    Nommer-Gagnants 'REFUSEE  ' $refuses $nos $tous 2

    $r = New-Object psobject
    $r | Add-Member NoteProperty Permis   $permis.Count
    $r | Add-Member NoteProperty Refuses  $refuses.Count
    $r | Add-Member NoteProperty Notres   $notres
    $r | Add-Member NoteProperty Poses    $nos.Count
    $r | Add-Member NoteProperty Idproc   $idproc
    $r | Add-Member NoteProperty Jeton    $o
    $r | Add-Member NoteProperty Gagnants (@($permis) + @($refuses))
    return $r
}

# ------------------------------------------------------------------- menage

function Menage {
    Write-Host ''
    Write-Host '== menage =='
    $sortie = & $Binaire --telemetrie-reseau-retirer 2>&1
    foreach ($l in @($sortie)) { Write-Host ("   {0}" -f $l) }

    foreach ($nom in @($script:servicesCrees)) {
        $null = & sc.exe stop $nom
        $null = & sc.exe delete $nom
        $parti = $false
        # sc delete ne fait que MARQUER le service tant que son processus vit,
        # et ce binaire ne repond pas a sc stop. On attend, et on reverifie.
        for ($k = 0; $k -lt 80; $k++) {
            Start-Sleep -Milliseconds 500
            $a = Get-CimInstance -ClassName Win32_Service -Filter "Name='$nom'" -ErrorAction SilentlyContinue
            $b = Get-Service -Name $nom -ErrorAction SilentlyContinue
            if (($a -eq $null) -and ($b -eq $null)) { $parti = $true; break }
            if (($k % 6) -eq 5) { $null = & sc.exe delete $nom }
        }
        if ($parti) {
            Write-Host ("   service {0} supprime (Win32_Service et Get-Service ne le trouvent plus)" -f $nom)
        } else {
            Write-Host ("   ATTENTION: le service {0} est encore present apres 40 s, le supprimer a la main" -f $nom)
        }
    }
    if (@($script:servicesCrees).Count -eq 0) { Write-Host '   aucun service de test n avait ete cree' }

    if ($script:auditTouche) {
        $null = & auditpol /set /subcategory:"$Sous" /success:disable /failure:enable
        Write-Host '   politique d audit remise a /success:disable /failure:enable'
    } else {
        Write-Host '   politique d audit non touchee'
    }
    # Le dernier mot est une RELECTURE, pas une affirmation sur soi-meme.
    Write-Host '   relecture:'
    $d = Dump-Wfp
    if ($d -eq $null) {
        Write-Host '      netsh n a rien rendu, verifier a la main'
    } else {
        Write-Host ("      filtres portant notre prefixe encore dans le moteur : {0}" -f ([regex]::Matches($d, $PrefixeCle)).Count)
    }
    foreach ($l in @(& auditpol /get /subcategory:"$Sous")) { Write-Host ("      {0}" -f $l) }
}

# --------------------------------------------------------------------- depart

Write-Host ('=' * 78)
Write-Host 'Un jeton FILTRE echappe-t-il au blocage ALE_USER_ID ?'
Write-Host ("hote          : {0}" -f $env:COMPUTERNAME)
Write-Host ("windows       : {0}" -f (Get-CimInstance Win32_OperatingSystem).Version)
Write-Host ("powershell    : {0}" -f $PSVersionTable.PSVersion)
Write-Host ("date          : {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
$ident = [Security.Principal.WindowsIdentity]::GetCurrent()
$princ = New-Object Security.Principal.WindowsPrincipal($ident)
Write-Host ("session admin : {0}" -f $princ.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
Write-Host ("binaire       : {0}" -f $Binaire)
Write-Host ("cible         : {0}" -f $Cible)
Write-Host ('=' * 78)

if (-not (Test-Path $Binaire)) { Write-Host "ECHEC: binaire introuvable: $Binaire"; exit 1 }

$err = Charger-Lecteur
if ($err -ne '') {
    Write-Host ("SKIPPED  {0}" -f $err)
    Write-Host '         Sans lecteur de jeton, l etat filtre n est pas verifiable et la'
    Write-Host '         comparaison ne pourrait pas se declarer discriminante.'
    exit 0
}
Write-Host ("SeDebugPrivilege : {0}" -f [BifrostJeton]::ActiverDebug())

# Le temoin doit pouvoir sortir AVANT qu'on lui pose quoi que ce soit, sinon une
# absence de connexion ne voudra rien dire.
$null = & $Binaire --connect-probe $Cible
if ($LASTEXITCODE -ne 5) {
    Write-Host ("SKIPPED  la cible {0} ne repond pas depuis cette machine (code {1})." -f $Cible, $LASTEXITCODE)
    Write-Host '         Sans temoin qui sort, une absence de connexion ne discrimine rien.'
    exit 0
}
Write-Host 'temoin: la cible repond depuis cette machine, la mesure peut discriminer'

# La liste des privileges du service de reference, LUE.
$reqpriv = @(RequiredPrivileges-De-Service $ServiceReference)
Write-Host ''
Write-Host ("== reference LUE: {0} ==" -f $ServiceReference)
Write-Host ("   ServiceSidType     : {0}" -f (SidType-De-Service $ServiceReference))
Write-Host ("   RequiredPrivileges : {0} valeur(s)" -f $reqpriv.Count)
foreach ($p in $reqpriv) { Write-Host ("      {0}" -f $p) }
if ($reqpriv.Count -eq 0) {
    Write-Host ("SKIPPED  {0} ne declare aucune valeur RequiredPrivileges." -f $ServiceReference)
    Write-Host '         Il n y a alors pas d etat filtre a reproduire, et les deux services'
    Write-Host '         seraient identiques: la comparaison ne discriminerait rien.'
    exit 0
}

$code = 0
$resultats = @{}
$sids = @{}

try {
    # ---- fabrication des deux services
    Write-Host ''
    Write-Host '== fabrication =='
    $ok = $true
    if (-not (Creer-Service $ServiceLibre @())) { $ok = $false }
    if ($ok -and -not (Creer-Service $ServiceFiltre $reqpriv)) { $ok = $false }
    if (-not $ok) {
        Write-Host 'ECHEC    les deux services de test n ont pas pu etre fabriques'
        $code = 1
    } else {
        foreach ($nom in @($ServiceLibre, $ServiceFiltre)) {
            $sids[$nom] = Sid-De-Service $nom
            Write-Host ("   {0,-22} sidtype={1}  SID={2}" -f $nom, (SidType-De-Service $nom), $sids[$nom])
            Write-Host ("   {0,-22} RequiredPrivileges={1}" -f '', ((RequiredPrivileges-De-Service $nom) -join ', '))
        }
        if ("$($sids[$ServiceLibre])" -eq '' -or "$($sids[$ServiceFiltre])" -eq '') {
            Write-Host 'ECHEC    un SID de service n est pas lisible, la sonde ne pourrait rien viser'
            $code = 1
        } else {
            $null = & auditpol /set /subcategory:"$Sous" /success:enable /failure:enable
            $script:auditTouche = $true

            # ---- quatre passages: sans sonde puis avec sonde, pour chacun
            Write-Host ''
            Write-Host ('=' * 78)
            Write-Host ("SERVICE 1 sur 2: {0} (jeton attendu NON filtre)" -f $ServiceLibre)
            $resultats['libre-sans'] = Passage $ServiceLibre $sids[$ServiceLibre] '' 'sans sonde: le temoin doit SORTIR'
            $resultats['libre-avec'] = Passage $ServiceLibre $sids[$ServiceLibre] $sids[$ServiceLibre] 'avec sonde sur son SID'

            Write-Host ''
            Write-Host ('=' * 78)
            Write-Host ("SERVICE 2 sur 2: {0} (jeton attendu FILTRE)" -f $ServiceFiltre)
            $resultats['filtre-sans'] = Passage $ServiceFiltre $sids[$ServiceFiltre] '' 'sans sonde: le temoin doit SORTIR'
            $resultats['filtre-avec'] = Passage $ServiceFiltre $sids[$ServiceFiltre] $sids[$ServiceFiltre] 'avec sonde sur son SID'

            # ---- le tableau
            Write-Host ''
            Write-Host ('=' * 78)
            Write-Host '== tableau =='
            Write-Host ("  {0,-22} | {1,-9} | {2,-5} | {3,-9} | {4,-8} | {5}" -f `
                'service', 'HasRestr', 'privs', 'autorisee', 'refusee', 'gagnant avec sonde')
            foreach ($duo in @(@($ServiceLibre, 'libre'), @($ServiceFiltre, 'filtre'))) {
                $nom = $duo[0]
                $sans = $resultats[($duo[1] + '-sans')]
                $avec = $resultats[($duo[1] + '-avec')]
                $hr = '?'
                $np = '?'
                if ($sans -ne $null) { $hr = $sans.Jeton.HasRestr; $np = $sans.Jeton.NbPriv }
                elseif ($avec -ne $null) { $hr = $avec.Jeton.HasRestr; $np = $avec.Jeton.NbPriv }
                $au = '?'
                $re = '?'
                $ga = '(passage manquant)'
                if ($avec -ne $null) {
                    $au = $avec.Permis
                    $re = $avec.Refuses
                    if ($avec.Notres -ge 1) { $ga = 'NOTRE filtre (blocage)' }
                    elseif ($avec.Permis -ge 1) { $ga = 'un filtre qui n est PAS a nous (autorisation)' }
                    else { $ga = '(aucun evenement)' }
                }
                Write-Host ("  {0,-22} | {1,-9} | {2,-5} | {3,-9} | {4,-8} | {5}" -f $nom, $hr, $np, $au, $re, $ga)
                if ($sans -ne $null) {
                    Write-Host ("  {0,-22} | sans sonde, temoin: autorisee={1} refusee={2}" -f '', $sans.Permis, $sans.Refuses)
                }
            }

            # ---- le verdict
            Write-Host ''
            Write-Host '== verdict =='
            $ls = $resultats['libre-sans']
            $la = $resultats['libre-avec']
            $fs = $resultats['filtre-sans']
            $fa = $resultats['filtre-avec']

            if ($ls -eq $null -or $la -eq $null -or $fs -eq $null -or $fa -eq $null) {
                Write-Host '  ECHEC    un passage n a pas pu s executer, le detail est imprime plus haut.'
                $code = 1
            } elseif ("$($ls.Jeton.HasRestr)" -ne '0' -or "$($fs.Jeton.HasRestr)" -ne '1') {
                Write-Host ('  SKIPPED  les deux jetons ne different pas comme il faut: attendu ' +
                    "TokenHasRestrictions=0 pour $ServiceLibre et 1 pour $ServiceFiltre, lu " +
                    "$($ls.Jeton.HasRestr) et $($fs.Jeton.HasRestr).")
                Write-Host '           La comparaison ne discrimine alors rien du tout, et un vert ici'
                Write-Host '           serait un vert par defaut.'
            } elseif ($ls.Permis -eq 0 -or $fs.Permis -eq 0) {
                Write-Host ('  SKIPPED  un temoin ne sort pas sans sonde (autorisees ' +
                    "$($ls.Permis) et $($fs.Permis)).")
                Write-Host '           Mesurer qu on arrete quelque chose qui ne se produit pas ne mesure rien.'
            } elseif ($la.Notres -lt 1 -or $la.Permis -ge 1) {
                Write-Host '  ECHEC    le point d appui manque: le blocage ne mord meme pas sur le jeton NON'
                Write-Host '           filtre, alors que c est le cas deja mesure le 22 aout 2026. Sans ce'
                Write-Host '           point, la comparaison des deux services ne dit rien.'
                $code = 1
            } elseif ($fa.Permis -ge 1) {
                Write-Host '  REPONSE  OUI. Un jeton FILTRE echappe au blocage ALE_USER_ID.'
                Write-Host ('           Meme filtre, meme forme, meme SERVICE_SID_TYPE: le service au jeton non ' +
                    "filtre est refuse ($($la.Refuses) fois, par notre filtre), et celui au jeton filtre " +
                    "sort quand meme ($($fa.Permis) connexion(s) autorisee(s)).")
                Write-Host '           Le gagnant nomme ci-dessus n est pas a nous: notre blocage n a pas matche.'
            } elseif ($fa.Notres -ge 1) {
                Write-Host '  REPONSE  NON. Un jeton FILTRE est bloque comme l autre.'
                Write-Host ("           Les deux services sont refuses par NOTRE filtre ($($la.Refuses) et " +
                    "$($fa.Refuses) refus). TokenHasRestrictions n a aucun effet sur le controle d acces")
                Write-Host '           ALE_USER_ID. Resultat negatif: cette hypothese est eliminee, la cause'
                Write-Host '           de l echappement de DiagTrack est ailleurs.'
            } else {
                Write-Host '  INDICE   plus aucune connexion pour le jeton filtre, mais aucun 5157 impute a nos'
                Write-Host '           filtres: on ne sait pas QUI a bloque. Insuffisant pour trancher.'
            }

            # ---- les lignes brutes, qui sont ce qu on cite
            Write-Host ''
            Write-Host '== jetons, lignes brutes =='
            foreach ($duo in @(@($ServiceLibre, 'libre'), @($ServiceFiltre, 'filtre'))) {
                $r = $resultats[($duo[1] + '-sans')]
                if ($r -eq $null) { continue }
                Write-Host ("--- {0} ---" -f $duo[0])
                foreach ($l in @($r.Jeton.Brut)) {
                    if ($l -like 'GROUPE|*' -or $l -like 'PRIVILEGE|*' -or $l -like 'IMPERSO*') { continue }
                    Write-Host $l
                }
                Write-Host ("PRIVILEGES|{0}|{1}" -f $r.Jeton.NbPriv, (@($r.Jeton.Privileges) -join ', '))
            }
        }
    }
}
finally {
    Menage
}

exit $code

# Banc d'EFFET de la couche 2: la connexion est-elle refusee, ou seulement le
# filtre present ?
#
# A lancer sur essai-windows, en administrateur, shell cmd, depuis la racine du
# banc (le repertoire qui contient les binaires) ou avec BIFROST_BANC pose:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\telemetrie-effet-windows.ps1
#
# Il pose de vrais filtres, redemarre le service vise plusieurs fois, et remet
# tout en etat - filtres retires, politique d'audit rendue - y compris en
# sortant sur une erreur.
#
# Ce banc est distinct de `telemetrie-reseau-windows.ps1`, qui ne mesure que la
# PRESENCE des filtres, et de `telemetrie-conditions-windows.ps1`, qui lit ce
# que chaque filtre PORTE sans rien eprouver. Un filtre WFP peut etre
# parfaitement present, enumerable par netsh, porter le bon SID, et ne rien
# bloquer. Ces questions sont separees et se mesurent separement.
#
# Trois pieges, tous rencontres le 22/08/2026 en construisant ce banc:
#
# 1. **CompatTelRunner semblait ne pas se connecter.** Mesure avec l'audit des
#    connexions AUTORISEES active: zero 5156 le citant, meme sans aucun filtre.
#    CORRECTION DU 23/08/2026: la conclusion tiree de ce zero etait FAUSSE. Ses
#    quatre taches n'avaient jamais tourne (dernier essai 30.11.1999, resultat
#    SCHED_S_TASK_HAS_NOT_RUN) et deux d'entre elles n'ont aucune prochaine
#    execution. Declenchees a la main, il emet. Le zero mesurait le declencheur,
#    pas le binaire. La lecon tient - un temoin muet certifie n'importe quoi -
#    mais constater qu'un temoin est muet n'autorise pas a dire POURQUOI.
# 2. **DiagTrack n'emet qu'une fois.** Il sort une connexion apres un
#    redemarrage, puis plus rien tant qu'il n'a rien de neuf a dire. Un banc qui
#    comparerait naivement "sans filtre" puis "avec filtre" attribuerait au
#    filtre ce qui n'est qu'un epuisement de file. D'ou les passages ALTERNES,
#    en commencant par le cas filtre.
# 3. **L'absence de 5157 ne prouve rien.** Il faut l'audit des SUCCES pour
#    distinguer "bloque" de "n'a rien tente". Le banc l'active et le remet.
#
# Trois manques DE CE BANC, nommes par la mesure du 22/08/2026 et corriges le
# 23/08/2026:
#
# 4. **Compter les filtres ne dit pas ce qu'ils portent.** La version
#    precedente n'extrayait du dump que le nom et le `filterId`, jamais les
#    `filterCondition`: elle imprimait `filtres=8` sans pouvoir affirmer qu'un
#    seul d'entre eux visait la cible. Un banc qui eprouve un blocage sans
#    verifier que le blocage vise sa cible ne mesure rien. Il lit maintenant
#    les conditions et ECHOUE si aucun filtre pose ne porte le SID que
#    `sc showsid` rend.
#    Le dump est du XML ou `<item>` sert AUSSI aux elements imbriques
#    (drapeaux, conditions): on le charge en DOM et on selectionne par
#    `//item[filterKey]`, jamais par un decoupage sur `<item>`, qui separerait
#    un filtre de son identifiant.
# 5. **Le PID n'etait lu qu'une fois**, deux secondes apres `sc start`, puis
#    jamais relu sur les 75 secondes de fenetre. Un service qui redemarre en
#    cours de route rendait une mesure qui se lit exactement comme une mesure
#    valide. Le PID vient maintenant de `Win32_Service`, la date de creation du
#    processus est comparee, et la mesure est INVALIDEE avec sa raison si le
#    processus a change. Le champ `Application` de chaque evenement est retenu
#    et imprime: tous les `svchost` partagent le meme chemin d'image, donc ce
#    champ ne discrimine pas a lui seul, mais son absence empeche toute
#    relecture posterieure.
# 6. **L'usurpation n'etait pas relevee, et c'est desormais LA question.** WFP
#    evalue `ALE_USER_ID` contre le jeton EFFECTIF au moment de la connexion:
#    un fil qui usurpe un jeton sans le SID de service echappe au filtre sans
#    que rien ne paraisse sur le jeton du processus. Le banc echantillonne donc
#    PLUSIEURS fois pendant la fenetre - une usurpation transitoire ne se voit
#    pas sur un instantane, et c'est precisement ce qu'on cherche. Le lecteur de
#    jeton est REPRIS de `jetons-compare-windows.ps1` par extraction du
#    here-string C#, jamais reecrit: deux implementations qui divergeraient
#    rendraient deux mesures incomparables. S'il manque, l'etape se declare
#    SKIPPED avec la raison.
#
# Verdicts possibles, et aucun n'est un vert par defaut:
#   MESURE   un refus est impute a un FilterRTID de la couche 2. C'est la preuve.
#   ECHEC    une connexion passe alors que le filtre est pose, verifie present
#            ET verifie porteur du SID de la cible; ou aucun filtre pose ne
#            porte ce SID.
#   INDICE   le comportement suit le filtre mais aucun 5157 ne l'impute.
#   SKIPPED  le temoin ne sort plus, ou la mesure a ete invalidee: elle ne
#            discrimine pas.
#
# Ce banc ne CREE et ne SUPPRIME aucun service. Il redemarre le service vise, et
# refuse tout nom autre que DiagTrack ou un temoin a prefixe `bifrost-`.

param(
    # La racine du banc: le repertoire du script (via -File), ou BIFROST_BANC si pose.
    [string]$Banc = $(if ($env:BIFROST_BANC) { $env:BIFROST_BANC } else { $PSScriptRoot }),
    [string]$Binaire = (Join-Path $Banc 'bifrost-daemon.exe'),
    [string]$Profil = 'equilibre',
    [int]$Attente = 75,
    # Le service dont on eprouve le blocage. Son SID est LU par sc showsid, et
    # le banc refuse de mesurer si aucun filtre pose ne le porte.
    [string]$Service = 'DiagTrack',
    # Le lecteur de jeton deja eprouve. On lui reprend sa partie C# plutot que
    # d'en ecrire une seconde.
    [string]$LecteurJeton = (Join-Path $Banc 'jetons-compare-windows.ps1'),
    # Releves d'usurpation par passage. Une usurpation qui ne dure que le temps
    # d'un appel ne se voit pas sur un instantane: on echantillonne.
    [int]$Echantillons = 8
)

# La racine du banc doit etre connue. Lance autrement que par -File et sans
# BIFROST_BANC, $Banc est vide et les chemins derives seraient faux.
if ([string]::IsNullOrEmpty($Banc)) {
    throw "Banc introuvable: lancer ce script par -File depuis la racine du banc (le repertoire qui contient les binaires), ou poser BIFROST_BANC sur ce repertoire."
}

$ErrorActionPreference = 'Continue'

# Sous-categorie "Filtering Platform Connection", designee par son GUID: le nom
# est traduit sur certaines installations, et une chaine traduite ne se compare
# pas.
$Sous = '{0CCE9226-69AE-11D9-BED3-505054503030}'
# Prefixe des cles de filtre de la couche 2. Ecrit ici A LA MAIN: si le banc le
# lisait du binaire, les deux se tromperaient ensemble.
$PrefixeCle = '{3ac9d182-5e42-4b77-9d61-8e05f3a2'

$script:auditTouche = $false
$script:lecteurRaison = 'non tente'
$script:conditionsImprimees = $false
$script:nbReleves = 0
$script:nbFilsReleves = 0
$script:nbFilsAvecJeton = 0
$script:nbFilsAvecSid = 0
$script:nbFilsAvecSidCible = 0
$script:vuesUsurpation = @()
$script:relevesSkipped = 0

# --------------------------------------------------------------- lecture WFP

# Rend le chemin d'un dump FRAIS, ou $null. L'appelant le supprime.
function Dump-Wfp {
    $f = Join-Path $env:SystemRoot 'Temp\bifrost-effet.xml'
    if (Test-Path $f) { Remove-Item $f -Force -ErrorAction SilentlyContinue }
    $null = & netsh wfp show filters file="$f" 2>&1
    if (-not (Test-Path $f)) { return $null }
    return $f
}

# Les filtres du moteur, avec ce qu'ils PORTENT.
#
# Rend trois choses: le compte total, une table filterId -> nom pour TOUS les
# filtres - elle sert a NOMMER le gagnant quel qu'il soit, y compris s'il ne
# nous appartient pas, ce qui est precisement le cas interessant - et le detail
# complet, conditions comprises, des seuls filtres a nous.
function Lire-Filtres($chemin) {
    $r = New-Object psobject
    $r | Add-Member NoteProperty Compte 0
    $r | Add-Member NoteProperty Tous   @{}
    $r | Add-Member NoteProperty Nos    @()
    if (-not $chemin) { return $r }
    $x = New-Object System.Xml.XmlDocument
    $x.Load($chemin)
    # `//item[filterKey]`: aucun item de condition ni de drapeau ne porte de
    # filterKey, donc la selection ne ramene que des filtres entiers.
    $noeuds = @($x.SelectNodes('//item[filterKey]'))
    $r.Compte = $noeuds.Count
    $tous = @{}
    $nos = New-Object System.Collections.ArrayList
    foreach ($f in $noeuds) {
        $id = [string]$f.filterId
        $nom = [string]$f.displayData.name
        if ($id -ne '') { $tous[$id] = $nom }
        $cle = [string]$f.filterKey
        if (-not $cle.StartsWith($PrefixeCle)) { continue }
        $o = New-Object psobject
        $o | Add-Member NoteProperty Cle        $cle
        $o | Add-Member NoteProperty Id         $id
        $o | Add-Member NoteProperty Nom        $nom
        $o | Add-Member NoteProperty Action     ([string]$f.action.type)
        $o | Add-Member NoteProperty Layer      ([string]$f.layerKey)
        $o | Add-Member NoteProperty SousCouche ([string]$f.subLayerKey)
        $o | Add-Member NoteProperty Poids      ([string]$f.effectiveWeight.uint64)
        $conds = New-Object System.Collections.ArrayList
        $c = $f.SelectSingleNode('filterCondition')
        if ($c -ne $null) {
            foreach ($i in @($c.SelectNodes('item'))) {
                $v = ([string]$i.conditionValue.InnerXml) -replace '\s+', ' '
                $q = New-Object psobject
                $q | Add-Member NoteProperty Champ  ([string]$i.fieldKey)
                $q | Add-Member NoteProperty Match  ([string]$i.matchType)
                $q | Add-Member NoteProperty Valeur ($v.Trim())
                $null = $conds.Add($q)
            }
        }
        $o | Add-Member NoteProperty Conditions @($conds.ToArray())
        $null = $nos.Add($o)
    }
    $r.Tous = $tous
    $r.Nos = @($nos.ToArray())
    return $r
}

function Afficher-Conditions($nos) {
    foreach ($f in @($nos)) {
        Write-Host ("      id={0}  {1}" -f $f.Id, $f.Nom)
        Write-Host ("         cle={0}  action={1}  poids={2}" -f $f.Cle, $f.Action, $f.Poids)
        Write-Host ("         layer={0}  sousCouche={1}" -f $f.Layer, $f.SousCouche)
        if (@($f.Conditions).Count -eq 0) {
            Write-Host '         conditions : AUCUNE'
        } else {
            foreach ($c in @($f.Conditions)) {
                Write-Host ("         condition  : champ={0} match={1}" -f $c.Champ, $c.Match)
                Write-Host ("                      valeur={0}" -f $c.Valeur)
            }
        }
    }
}

# Les filtres dont UNE condition porte exactement ce SID.
function Filtres-Portant($nos, $sid) {
    $out = New-Object System.Collections.ArrayList
    if ("$sid" -eq '') { return @() }
    foreach ($f in @($nos)) {
        foreach ($c in @($f.Conditions)) {
            if ("$($c.Valeur)".Contains($sid)) { $null = $out.Add($f); break }
        }
    }
    return @($out.ToArray())
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

# ----------------------------------------------------- continuite du processus
#
# Le PID se prend par CIM, jamais en analysant "sc queryex": un Select-String
# sur une chaine multiligne rend un seul MatchInfo qui porte tout le texte, ce
# qui a deja produit un PID de vingt chiffres. Et la date de creation est lue
# avec lui: deux processus peuvent porter le meme numero a quelques minutes
# d'ecart, et un PID reutilise se lit comme une continuite.
function Contexte-Processus($nom) {
    $c = New-Object psobject
    $c | Add-Member NoteProperty Idproc   0
    $c | Add-Member NoteProperty Creation ''
    $c | Add-Member NoteProperty Etat     '(absent)'
    $c | Add-Member NoteProperty Image    ''
    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$nom'" -ErrorAction SilentlyContinue
    if ($svc -eq $null) { return $c }
    $c.Etat = [string]$svc.State
    $c.Idproc = [int]$svc.ProcessId
    if ($c.Idproc -gt 0) {
        $pr = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$($c.Idproc)" -ErrorAction SilentlyContinue
        if ($pr -ne $null) {
            if ($pr.CreationDate -ne $null) {
                $c.Creation = ([datetime]$pr.CreationDate).ToString('yyyy-MM-dd HH:mm:ss.fff')
            }
            $c.Image = [string]$pr.ExecutablePath
        }
    }
    return $c
}

# -------------------------------------------------------- lecture des jetons
#
# La partie C# vient telle quelle de jetons-compare-windows.ps1: on extrait le
# here-string qui la porte et on la compile ici. On ne recopie pas ce code, et
# on n'en ecrit pas un second: deux implementations qui divergeraient rendraient
# deux mesures qu'on ne pourrait pas comparer.
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

# Un releve d'usurpation: pour chaque fil du processus vise, le jeton
# d'usurpation qu'il porte, son TokenUser, et si un SID de service y figure et
# avec quels attributs. Un fil qui n'usurpe rien rend ERROR_NO_TOKEN (1008):
# c'est le cas normal, pas une erreur.
function Releve-Usurpation($idproc, $sidCible) {
    $r = New-Object psobject
    $r | Add-Member NoteProperty Erreur    ''
    $r | Add-Member NoteProperty Fils      0
    $r | Add-Member NoteProperty AvecJeton 0
    $r | Add-Member NoteProperty AvecSid   0
    $r | Add-Member NoteProperty AvecCible 0
    $r | Add-Member NoteProperty Details   @()

    $p = Get-Process -Id $idproc -ErrorAction SilentlyContinue
    if ($p -eq $null) { $r.Erreur = "le processus $idproc n existe plus"; return $r }
    $tids = @()
    foreach ($t in $p.Threads) { $tids = $tids + [uint32]$t.Id }
    $r.Fils = @($tids).Count
    if ($r.Fils -eq 0) { $r.Erreur = 'aucun fil enumerable'; return $r }

    $lignes = @([BifrostJeton]::Impersonation([uint32[]]$tids))
    $users = @{}
    $sids = @{}
    foreach ($l in $lignes) {
        $q = "$l" -split '\|'
        if ($q[0] -eq 'IMPERSO') { $users["$($q[1])"] = "$($q[2])"; continue }
        if ($q[0] -like 'IMPERSO_GROUPE_*') {
            if ($q[0] -like '*_COMPTE') { continue }
            if ($q[0] -like '*_ECHEC') { continue }
            $tid = $q[0].Substring('IMPERSO_GROUPE_'.Length)
            if ($q.Count -gt 5 -and "$($q[2])" -like 'S-1-5-80-*') {
                if (-not $sids.ContainsKey($tid)) { $sids[$tid] = @() }
                $sids[$tid] = @($sids[$tid]) + @("$($q[2])|$($q[4])|$($q[5])")
            }
        }
    }
    $r.AvecJeton = @($users.Keys).Count
    $det = New-Object System.Collections.ArrayList
    foreach ($tid in @($users.Keys)) {
        $ligneSid = '(aucun SID de service dans ce jeton)'
        if ($sids.ContainsKey($tid)) {
            $r.AvecSid = $r.AvecSid + 1
            $morceaux = @()
            foreach ($e in @($sids[$tid])) {
                $z = "$e" -split '\|'
                $marque = ''
                if ("$($z[0])" -eq "$sidCible") {
                    $marque = '  <== SID DE LA CIBLE'
                    $r.AvecCible = $r.AvecCible + 1
                }
                $morceaux = $morceaux + @("$($z[0]) attributs $($z[1]) = $($z[2])$marque")
            }
            $ligneSid = ($morceaux -join ' ; ')
        }
        $null = $det.Add("fil $tid  TokenUser=$($users[$tid])  $ligneSid")
    }
    $r.Details = @($det.ToArray())
    return $r
}

# ------------------------------------------------------- lecture des journaux

function Detail($e) {
    $x = [xml]$e.ToXml(); $d = @{}
    foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
    return $d
}

function Nommer-Gagnants($etiquette, $liste, $nos, $tous, $combien) {
    foreach ($d in (@($liste) | Select-Object -First $combien)) {
        $rt = "$($d['FilterRTID'])"
        $nom = '(absent du dump)'
        if ($tous.ContainsKey($rt)) { $nom = $tous[$rt] }
        $notre = 'non'
        if ($nos.ContainsKey($rt)) { $notre = 'OUI' }
        Write-Host ("      {0}  rtid={1} layer={2} a nous={3}" -f $etiquette, $rt, $d['LayerRTID'], $notre)
        Write-Host ("         nom du gagnant : {0}" -f $nom)
        Write-Host ("         FilterOrigin   : {0}" -f $d['FilterOrigin'])
        Write-Host ("         Application    : {0}" -f $d['Application'])
        Write-Host ("         destination    : {0}:{1}" -f $d['DestAddress'], $d['DestPort'])
    }
}

# ------------------------------------------------------------------ un passage

function Passage($etiquette, $filtre, $sidCible) {
    $res = New-Object psobject
    $res | Add-Member NoteProperty Permis   0
    $res | Add-Member NoteProperty Refuses  0
    $res | Add-Member NoteProperty Notres   0
    $res | Add-Member NoteProperty Poses    0
    $res | Add-Member NoteProperty EchecSid $false
    $res | Add-Member NoteProperty Invalide $false
    $res | Add-Member NoteProperty Raison   ''

    Write-Host ''
    if ($filtre) { Write-Host ("-- passage {0} : FILTRE --" -f $etiquette) }
    else         { Write-Host ("-- passage {0} : sans filtre --" -f $etiquette) }

    if ($filtre) {
        $null = & $Binaire --telemetrie-reseau-appliquer --telemetrie-profil $Profil
    } else {
        $null = & $Binaire --telemetrie-reseau-retirer
    }

    $chemin = Dump-Wfp
    if ($chemin -eq $null) {
        Write-Host '   ECHEC: netsh wfp show filters n a rien rendu, le gagnant serait innommable'
        $res.EchecSid = $true
        $res.Raison = 'dump netsh absent'
        return $res
    }
    $lu = Lire-Filtres $chemin
    Remove-Item $chemin -Force -ErrorAction SilentlyContinue
    $nos = @($lu.Nos)
    $tous = $lu.Tous
    $tableNos = @{}
    foreach ($f in $nos) { $tableNos[$f.Id] = $f.Nom }
    $res.Poses = $nos.Count
    Write-Host ("   filtres       : {0} dans le moteur, {1} a nous" -f $lu.Compte, $nos.Count)

    # -------------------------------------- CONTROLE 1: ce que les filtres portent
    if ($filtre) {
        if ($nos.Count -eq 0) {
            Write-Host '   ECHEC: aucun filtre lisible dans le moteur apres la pose'
            $res.EchecSid = $true
            $res.Raison = 'aucun filtre a nous dans le moteur apres la pose'
            return $res
        }
        if (-not $script:conditionsImprimees) {
            Write-Host '   ce que la pose porte, condition par condition:'
            Afficher-Conditions $nos
            $script:conditionsImprimees = $true
        }
        $porteurs = @(Filtres-Portant $nos $sidCible)
        if ($porteurs.Count -eq 0) {
            Write-Host ("   ECHEC DE GARDE: aucun des {0} filtres poses ne porte le SID de {1}." -f $nos.Count, $Service)
            Write-Host ("                   SID attendu, rendu par sc showsid {0} :" -f $Service)
            Write-Host ("                   {0}" -f $sidCible)
            Write-Host '                   Un banc qui eprouve un blocage sans verifier que le blocage'
            Write-Host '                   vise sa cible ne mesure rien. Mesure refusee, rien redemarre.'
            Write-Host '                   Ce que les filtres poses portent reellement:'
            Afficher-Conditions $nos
            $res.EchecSid = $true
            $res.Raison = "aucun filtre pose ne porte le SID de $Service ($sidCible)"
            return $res
        }
        Write-Host ("   CONTROLE SID  : {0} filtre(s) pose(s) portent EXACTEMENT le SID de {1}" -f $porteurs.Count, $Service)
        Write-Host ("                   {0}" -f $sidCible)
        foreach ($f in $porteurs) {
            Write-Host ("                   id={0}  {1}  action={2}" -f $f.Id, $f.Nom, $f.Action)
        }
    }

    # ----------------------------------------------------- le temoin, redemarre
    $marque = (Get-Date).AddSeconds(-1)
    $null = & sc.exe stop $Service
    Start-Sleep -Seconds 4
    $null = & sc.exe start $Service
    Start-Sleep -Seconds 2

    # ------------------------ CONTROLE 2: continuite du processus, 1re lecture
    $avant = Contexte-Processus $Service
    if ($avant.Idproc -le 0) {
        Write-Host ("   MESURE INVALIDEE: {0} n a pas de PID apres le demarrage (etat {1})" -f $Service, $avant.Etat)
        $res.Invalide = $true
        $res.Raison = "pas de PID apres demarrage, etat $($avant.Etat)"
        return $res
    }
    Write-Host ("   PID au depart : {0}  cree le {1}  etat {2}" -f $avant.Idproc, $avant.Creation, $avant.Etat)
    Write-Host ("   image         : {0}" -f $avant.Image)

    # ------------------------ CONTROLE 3: usurpation, DANS la fenetre de mesure
    if ($script:lecteurRaison -ne '') {
        Write-Host ("   usurpation    : SKIPPED  {0}" -f $script:lecteurRaison)
        $script:relevesSkipped = $script:relevesSkipped + 1
        Start-Sleep -Seconds $Attente
    } else {
        $pas = [Math]::Max(1, [int]($Attente / [Math]::Max(1, $Echantillons)))
        $depart = Get-Date
        for ($k = 1; $k -le $Echantillons; $k++) {
            $t = [int]((Get-Date) - $depart).TotalSeconds
            $u = Releve-Usurpation $avant.Idproc $sidCible
            $script:nbReleves = $script:nbReleves + 1
            if ($u.Erreur -ne '') {
                Write-Host ("   usurpation {0}/{1} t=+{2}s : SKIPPED  {3}" -f $k, $Echantillons, $t, $u.Erreur)
            } else {
                $script:nbFilsReleves = $script:nbFilsReleves + $u.Fils
                $script:nbFilsAvecJeton = $script:nbFilsAvecJeton + $u.AvecJeton
                $script:nbFilsAvecSid = $script:nbFilsAvecSid + $u.AvecSid
                $script:nbFilsAvecSidCible = $script:nbFilsAvecSidCible + $u.AvecCible
                Write-Host ("   usurpation {0}/{1} t=+{2}s : fils={3} avec jeton d usurpation={4} dont portant un SID de service={5} dont celui de la cible={6}" -f `
                    $k, $Echantillons, $t, $u.Fils, $u.AvecJeton, $u.AvecSid, $u.AvecCible)
                foreach ($d in @($u.Details)) {
                    Write-Host ("        {0}" -f $d)
                    $script:vuesUsurpation = @($script:vuesUsurpation) + @("passage $etiquette  t=+${t}s  $d")
                }
            }
            if ($k -lt $Echantillons) { Start-Sleep -Seconds $pas }
        }
        $reste = $Attente - ((Get-Date) - $depart).TotalSeconds
        if ($reste -gt 0) { Start-Sleep -Seconds ([int]$reste) }
    }

    # ------------------------ CONTROLE 2: continuite du processus, 2e lecture
    $apres = Contexte-Processus $Service
    if ($apres.Idproc -ne $avant.Idproc -or $apres.Creation -ne $avant.Creation) {
        Write-Host '   MESURE INVALIDEE: le processus vise a change pendant la fenetre.'
        Write-Host ("                     au depart : PID {0} cree le {1}" -f $avant.Idproc, $avant.Creation)
        Write-Host ("                     au releve : PID {0} cree le {1} (etat {2})" -f $apres.Idproc, $apres.Creation, $apres.Etat)
        Write-Host '                     Les evenements attribues a ce PID melangeraient deux processus.'
        $res.Invalide = $true
        $res.Raison = "processus change: PID $($avant.Idproc) cree le $($avant.Creation), puis PID $($apres.Idproc) cree le $($apres.Creation)"
        return $res
    }
    Write-Host ("   PID au releve : {0}  cree le {1}  (inchange)" -f $apres.Idproc, $apres.Creation)

    # ------------------------------------------------------ lecture du journal
    $permis = @()
    $refuses = @()
    $apps = @{}
    foreach ($e in @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5156; StartTime=$marque} -ErrorAction SilentlyContinue)) {
        $d = Detail $e
        if ("$($d['ProcessID'])" -ne "$($avant.Idproc)") { continue }
        $permis = $permis + @($d)
        $a = "$($d['Application'])"
        if ($apps.ContainsKey($a)) { $apps[$a] = $apps[$a] + 1 } else { $apps[$a] = 1 }
    }
    foreach ($e in @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5157; StartTime=$marque} -ErrorAction SilentlyContinue)) {
        $d = Detail $e
        if ("$($d['ProcessID'])" -ne "$($avant.Idproc)") { continue }
        $refuses = $refuses + @($d)
        $a = "$($d['Application'])"
        if ($apps.ContainsKey($a)) { $apps[$a] = $apps[$a] + 1 } else { $apps[$a] = 1 }
    }
    $notres = @(@($refuses) | Where-Object { $tableNos.ContainsKey("$($_['FilterRTID'])") }).Count

    $res.Permis = @($permis).Count
    $res.Refuses = @($refuses).Count
    $res.Notres = $notres
    Write-Host ("   RESULTAT      autorisees={0}  refusees={1}  dont par nos filtres={2}" -f `
        $res.Permis, $res.Refuses, $res.Notres)
    # Le chemin d'image de chaque evenement. Il ne discrimine pas a lui seul -
    # tous les svchost partagent le meme - mais sans lui aucune relecture
    # posterieure n'est possible.
    if (@($apps.Keys).Count -eq 0) {
        Write-Host '   Application   : (aucun evenement attribue a ce PID)'
    } else {
        foreach ($a in @($apps.Keys)) { Write-Host ("   Application   : {0}  x{1}" -f $a, $apps[$a]) }
    }
    # Une connexion autorisee malgre le filtre doit NOMMER qui l'a autorisee:
    # constater l'echec sans savoir quel filtre a gagne ne fait pas avancer.
    Nommer-Gagnants 'AUTORISEE' $permis $tableNos $tous 3
    Nommer-Gagnants 'REFUSEE  ' $refuses $tableNos $tous 3
    return $res
}

function Resume-Usurpation {
    Write-Host ''
    Write-Host '== releve d usurpation =='
    if ($script:lecteurRaison -ne '') {
        Write-Host ("  SKIPPED  {0}" -f $script:lecteurRaison)
        Write-Host ("           {0} passage(s) ont traverse leur fenetre sans aucun releve." -f $script:relevesSkipped)
        Write-Host '           La piste de l usurpation n a donc PAS ete eprouvee par ce passage.'
        return
    }
    Write-Host ("  releves effectues                          : {0}" -f $script:nbReleves)
    Write-Host ("  fils examines (cumul sur tous les releves) : {0}" -f $script:nbFilsReleves)
    Write-Host ("  fils portant un jeton d usurpation (cumul) : {0}" -f $script:nbFilsAvecJeton)
    Write-Host ("  dont portant un SID de service             : {0}" -f $script:nbFilsAvecSid)
    Write-Host ("  dont portant le SID de la cible            : {0}" -f $script:nbFilsAvecSidCible)
    if (@($script:vuesUsurpation).Count -eq 0) {
        Write-Host ''
        Write-Host '  RESULTAT PARTIEL: aucune usurpation VUE sur ces releves.'
        Write-Host '  Ce n est PAS une absence d usurpation. WFP evalue ALE_USER_ID contre le jeton'
        Write-Host '  EFFECTIF au moment de la connexion, et une usurpation qui ne dure que le temps'
        Write-Host '  d un appel passe entre deux releves. Un echantillonnage negatif ne conclut pas.'
    } else {
        Write-Host ''
        Write-Host '  ce qui a ete vu:'
        foreach ($v in @($script:vuesUsurpation)) { Write-Host ("    {0}" -f $v) }
    }
}

# ------------------------------------------------------------------- le corps

function Main {
    Write-Host ('=' * 78)
    Write-Host 'Banc d EFFET de la couche 2'
    Write-Host ("hote          : {0}" -f $env:COMPUTERNAME)
    Write-Host ("windows       : {0}" -f (Get-CimInstance Win32_OperatingSystem).Version)
    Write-Host ("powershell    : {0}" -f $PSVersionTable.PSVersion)
    $ident = [Security.Principal.WindowsIdentity]::GetCurrent()
    $princ = New-Object Security.Principal.WindowsPrincipal($ident)
    Write-Host ("session admin : {0}" -f $princ.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    Write-Host ("demarre le    : {0}" -f (Get-CimInstance Win32_OperatingSystem).LastBootUpTime)
    Write-Host ("binaire       : {0}" -f $Binaire)
    Write-Host ("profil        : {0}" -f $Profil)
    Write-Host ("service vise  : {0}" -f $Service)
    Write-Host ("fenetre       : {0} s, {1} releve(s) d usurpation par passage" -f $Attente, $Echantillons)
    Write-Host ('=' * 78)

    if (-not (Test-Path $Binaire)) { Write-Host 'ECHEC: binaire introuvable'; return 1 }

    # Garde-fou. Ce banc fait `sc stop` puis `sc start` sur le nom qu'on lui
    # donne. Une faute de frappe arreterait un service systeme. Seuls DiagTrack,
    # qui est la cible du chantier, et les temoins a prefixe reserve passent.
    if ($Service -ne 'DiagTrack' -and $Service -notlike 'bifrost-*') {
        Write-Host ("REFUS: {0} n est ni DiagTrack ni un temoin a prefixe bifrost-." -f $Service)
        Write-Host '       Ce banc redemarre le service qu on lui nomme: il refuse tout autre nom.'
        return 1
    }

    $sidCible = Sid-De-Service $Service
    if ("$sidCible" -eq '') {
        Write-Host ("ECHEC: sc showsid {0} n a rendu aucun SID S-1-5-80. Sans SID attendu," -f $Service)
        Write-Host '       le controle des conditions de filtre ne peut pas avoir lieu.'
        return 1
    }
    Write-Host ("SID attendu (sc showsid {0}) : {1}" -f $Service, $sidCible)

    $script:lecteurRaison = Charger-Lecteur
    if ($script:lecteurRaison -eq '') {
        Write-Host ("lecteur de jeton : {0}" -f $LecteurJeton)
        Write-Host ("SeDebugPrivilege : {0}" -f [BifrostJeton]::ActiverDebug())
    } else {
        Write-Host ("lecteur de jeton : SKIPPED  {0}" -f $script:lecteurRaison)
    }

    # L'audit des SUCCES est indispensable: sans lui, "n'a rien tente" et "a ete
    # bloque" rendent la meme mesure, c'est-a-dire aucune.
    Write-Host ''
    Write-Host 'politique d audit trouvee:'
    foreach ($l in @(& auditpol /get /subcategory:"$Sous" /r)) { if ("$l".Trim() -ne '') { Write-Host ("  {0}" -f $l) } }
    $null = & auditpol /set /subcategory:"$Sous" /success:enable /failure:enable
    $script:auditTouche = $true

    Write-Host ''
    Write-Host '== Trois passages alternes, en commencant PAR le cas filtre =='
    Write-Host '   (DiagTrack n emet qu une fois par redemarrage: commencer par le cas'
    Write-Host '    sans filtre attribuerait au filtre un simple epuisement de file)'

    $a = Passage 'A' $true $sidCible
    $b = $null
    $c = $null
    if (-not $a.EchecSid) {
        $b = Passage 'B' $false $sidCible
        $c = Passage 'C' $true $sidCible
    }

    Resume-Usurpation

    Write-Host ''
    Write-Host '== Verdict =='
    if ($a.EchecSid) {
        Write-Host ("  ECHEC    passage A: {0}" -f $a.Raison)
        return 1
    }
    if ($c.EchecSid) {
        Write-Host ("  ECHEC    passage C: {0}" -f $c.Raison)
        return 1
    }
    $invalides = @()
    if ($a.Invalide) { $invalides = $invalides + @("A: $($a.Raison)") }
    if ($b.Invalide) { $invalides = $invalides + @("B: $($b.Raison)") }
    if ($c.Invalide) { $invalides = $invalides + @("C: $($c.Raison)") }
    if (@($invalides).Count -gt 0) {
        Write-Host '  SKIPPED  la mesure a ete invalidee, elle ne discrimine pas:'
        foreach ($i in @($invalides)) { Write-Host ("           {0}" -f $i) }
        Write-Host '           Un passage invalide n est pas un passage sans connexion. Relancer.'
        return 0
    }
    if (($a.Notres + $c.Notres) -ge 1) {
        Write-Host ("  MESURE   {0} refus impute(s) a un filtre de la couche 2: la connexion est REFUSEE, pas seulement filtree sur le papier" -f ($a.Notres + $c.Notres))
        return 0
    }
    if (($a.Permis + $c.Permis) -ge 1) {
        Write-Host ("  ECHEC    {0} connexion(s) AUTORISEE(S) alors que les filtres etaient poses, verifies presents," -f ($a.Permis + $c.Permis))
        Write-Host '           et verifies porteurs du SID de la cible.'
        Write-Host '           La couche 2 ne mord pas. Ne pas annoncer cette couche comme efficace.'
        return 1
    }
    if ($b.Permis -ge 1) {
        Write-Host '  INDICE   le comportement suit le filtre et non le rang, mais aucun 5157 ne l impute:'
        Write-Host '           on ne sait pas QUI a bloque. Insuffisant pour conclure.'
        return 0
    }
    Write-Host '  SKIPPED  le temoin n a rien sorti: le service n avait rien a envoyer, la mesure'
    Write-Host '           ne discrimine pas. Relancer plus tard, ou apres un redemarrage du poste.'
    return 0
}

$code = 1
try {
    $code = Main
}
finally {
    # Le menage a lieu meme en sortant sur une erreur: des filtres laisses en
    # place et un audit des succes laisse actif ne sont pas des effets de bord
    # acceptables sur une machine d essai.
    Write-Host ''
    Write-Host '== menage =='
    $null = & $Binaire --telemetrie-reseau-retirer 2>&1
    $cheminMenage = Dump-Wfp
    if ($cheminMenage -ne $null) {
        $luMenage = Lire-Filtres $cheminMenage
        Remove-Item $cheminMenage -Force -ErrorAction SilentlyContinue
        Write-Host ("  relecture : {0} filtre(s) a nous dans le moteur" -f @($luMenage.Nos).Count)
    } else {
        Write-Host '  relecture : netsh n a rien rendu, la presence des filtres n est pas verifiee'
    }
    if ($script:auditTouche) {
        $null = & auditpol /set /subcategory:"$Sous" /success:disable /failure:enable
        Write-Host '  politique d audit remise a /success:disable /failure:enable'
        foreach ($l in @(& auditpol /get /subcategory:"$Sous" /r)) { if ("$l".Trim() -ne '') { Write-Host ("  {0}" -f $l) } }
    } else {
        Write-Host '  politique d audit non touchee'
    }
    Write-Host '  aucun service cree ni supprime par ce banc'
}
exit $code

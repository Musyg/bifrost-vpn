# Les VRAIES cibles de la couche 2, autres que DiagTrack: le filtre mord-il ?
#
# A lancer sur essai-windows, en administrateur, shell cmd, une cible a la fois,
# depuis la racine du banc (le repertoire qui contient les binaires) ou avec
# BIFROST_BANC pose:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\telemetrie-cibles-windows.ps1 -Service DoSvc
#
# LA QUESTION. Le mecanisme `ALE_USER_ID` est mesure: il mord sur un service de
# test, deux fois. Une seule VRAIE cible du catalogue a jamais ete eprouvee en
# EFFET, DiagTrack, et elle echappe. Ce banc demande si DiagTrack est un cas
# particulier ou si toute vraie cible de Windows echappe. Il ne mesure qu'un
# service par execution, et il n'accepte que les quatre du catalogue jamais
# eprouves. DiagTrack a son propre banc, `telemetrie-effet-windows.ps1`, qui
# reste l'instrument de reference pour lui.
#
# CE QU'IL REPREND ET CE QU'IL N'ECRIT PAS DEUX FOIS. Le controle decisif -
# << un filtre pose porte-t-il EXACTEMENT le SID de la cible ? >> - n'est pas
# reimplemente ici: il est DELEGUE a `telemetrie-conditions-windows.ps1`, qui
# est l'instrument du depot pour cette question, et dont le code de sortie est
# lu. Deux implementations qui divergeraient rendraient deux mesures qu'on ne
# pourrait pas comparer. Ce banc ne relit le dump `netsh` que pour NOMMER le
# filtre gagnant d'un evenement, ce que le controle des conditions ne fait pas.
#
# CE QUE CE BANC AJOUTE, ET POURQUOI. DiagTrack est seul dans son `svchost`. Les
# quatre cibles d'ici ne le sont pas forcement: `dmwappushservice` vit dans
# `netsvcs`, `CDPSvc` dans `LocalService`. Un `svchost` partage rend
# l'attribution par PID FAUSSE - l'evenement porterait le PID de la cible sans
# etre a elle. Le banc releve donc les colocataires du PID a chaque passage et
# INVALIDE la mesure si la cible n'est pas seule.
#
# Deuxieme ajout: `WerSvc` et `dmwappushservice` sont en demarrage a la demande
# et s'arretent d'eux-memes. Le processus qui disparait en cours de fenetre
# n'est pas le meme defaut qu'un processus REMPLACE: le banc echantillonne le
# PID et sa date de creation pendant toute la fenetre, ferme la fenetre a
# l'instant de la disparition, et n'invalide que si un AUTRE processus a pris
# le numero.
#
# Troisieme ajout: les COMPAGNONS. Un blocage par SID de service ne peut mordre
# que ce que le SERVICE emet lui-meme. Si le trafic part d'un binaire tiers
# lance par le service, il porte un autre jeton et un autre PID, et le catalogue
# vise a cote. Le banc releve donc, a titre de contexte et jamais de verdict, ce
# que des binaires nommes ont emis pendant la meme fenetre.
#
# TROIS PIEGES DEJA PAYES SUR CETTE MACHINE, et qui valent ici aussi:
#   - Un temoin muet certifie n'importe quoi. Sans audit des SUCCES, << bloque >>
#     et << n'a rien tente >> rendent la meme mesure, c'est-a-dire aucune.
#   - Un banc qui compare << sans filtre >> puis << avec filtre >> dans cet ordre
#     attribue au filtre un simple epuisement de file. D'ou trois passages
#     alternes, COMMENCES par le cas filtre.
#   - Chez WFP un blocage l'emporte sur une autorisation. Si une autorisation
#     gagne alors que notre filtre est pose et verifie porteur du bon SID, c'est
#     que notre filtre n'a pas MATCHE.
#
# CE QUE CE BANC NE MESURE PAS. L'usurpation d'identite par fil, relevee par
# `telemetrie-effet-windows.ps1`. Elle n'est pas la question ici: on demande
# d'abord si le blocage mord, et l'usurpation n'a d'interet que pour expliquer
# un echappement.
#
# Verdicts, et aucun n'est un vert par defaut:
#   BLOQUE   un 5157 impute un refus a un filtre de la couche 2. C'est la preuve.
#   ECHAPPE  une connexion passe alors que le filtre est pose, verifie present
#            ET verifie porteur du SID exact de la cible.
#   INDICE   le comportement suit le filtre mais aucun 5157 ne l'impute.
#   SKIPPED  le temoin n'emet pas avec ce declencheur, ou la mesure a ete
#            invalidee. La raison est nommee, toujours.

param(
    # La racine du banc: le repertoire du script (via -File), ou BIFROST_BANC si pose.
    [string]$Banc = $(if ($env:BIFROST_BANC) { $env:BIFROST_BANC } else { $PSScriptRoot }),
    # La cible. Aucune valeur par defaut: ce banc redemarre le service qu'on lui
    # nomme, et un nom par defaut est une faute qui attend son heure.
    [string]$Service = '',
    [string]$Binaire = (Join-Path $Banc 'bifrost-daemon.exe'),
    # L'instrument du depot pour le controle du SID. Delegue, jamais reecrit.
    [string]$Conditions = (Join-Path $Banc 'telemetrie-conditions-windows.ps1'),
    [string]$Profil = 'strict',
    [int]$Attente = 75,
    # Vide: celui de la table, choisi par cible. Sinon 'redemarrage',
    # 'redemarrage+scan' ou 'redemarrage+crash'.
    [string]$Declencheur = '',
    # Pas d'echantillonnage de la continuite du processus, en secondes.
    [int]$PasEchantillon = 5,
    # Minutes de RECONNAISSANCE. Superieur a zero: le banc ne pose rien, ne
    # redemarre rien, et se contente de regarder QUI des quatre cibles emet de
    # lui-meme. C'est l'etape du temoin, et elle passe AVANT toute mesure de
    # blocage: une cible qui n'emet jamais rend un blocage indiscernable d'une
    # machine muette. Ce mode refuse de tourner si un filtre de la couche 2
    # est pose: il mesurerait alors autre chose que ce qu'il annonce.
    [int]$Reconnaissance = 0
)

# La racine du banc doit etre connue. Lance autrement que par -File et sans
# BIFROST_BANC, $Banc est vide et les chemins derives seraient faux.
if ([string]::IsNullOrEmpty($Banc)) {
    throw "Banc introuvable: lancer ce script par -File depuis la racine du banc (le repertoire qui contient les binaires), ou poser BIFROST_BANC sur ce repertoire."
}

$ErrorActionPreference = 'Continue'

# Sous-categorie "Filtering Platform Connection", designee par son GUID: le nom
# est traduit sur cette machine, et une chaine traduite ne se compare pas.
$Sous = '{0CCE9226-69AE-11D9-BED3-505054503030}'
# Prefixe des cles de filtre de la couche 2. Ecrit A LA MAIN: si le banc le
# lisait du binaire, les deux se tromperaient ensemble.
$PrefixeCle = '{3ac9d182-5e42-4b77-9d61-8e05f3a2'

# Les quatre du catalogue jamais eprouvees en effet, et le declencheur que
# chacune demande. DiagTrack n'y est PAS: il a son banc.
$CIBLES = @{
    'dmwappushservice' = 'redemarrage'
    'DoSvc'            = 'redemarrage'
    'WerSvc'           = 'redemarrage+crash'
    'CDPSvc'           = 'redemarrage'
}
# Binaires tiers a relever a titre de CONTEXTE pendant la fenetre. Jamais un
# verdict: ils ne portent pas le SID de service, donc le catalogue ne les vise
# pas. Les relever dit ou part reellement le trafic.
$COMPAGNONS = @{
    'WerSvc'           = @('wermgr', 'werfault')
    'dmwappushservice' = @('omadmclient', 'deviceenroller')
    'DoSvc'            = @()
    'CDPSvc'           = @()
}

$script:auditTouche = $false
# Symetrique du precedent, et il manquait. Le menage relancait `$Binaire` meme
# quand le banc avait refuse d agir - a la garde du nom, par exemple - donc sans
# avoir jamais rien pose. Mesure du 23/08/2026: lance avec `-Binaire
# notepad.exe` pour eprouver cette garde, le banc a REFUSE la cible puis a
# LANCE le Bloc-notes avec `--telemetrie-reseau-retirer` en guise de nom de
# fichier, qui a demande a l utilisateur s il fallait le creer. Aucun degat,
# mais un menage qui defait ce qu il n a jamais fait ne peut que surprendre, et
# il execute au passage le programme que l appelant a nomme.
$script:posePassee = $false

# --------------------------------------------------------------- lecture WFP

# Rend le chemin d'un dump FRAIS, ou $null. L'appelant le supprime.
function Dump-Wfp {
    $f = Join-Path $env:SystemRoot 'Temp\bifrost-cibles.xml'
    if (Test-Path $f) { Remove-Item $f -Force -ErrorAction SilentlyContinue }
    $null = & netsh wfp show filters file="$f" 2>&1
    if (-not (Test-Path $f)) { return $null }
    return $f
}

# Deux tables: filterId -> nom pour TOUS les filtres, ce qui sert a nommer le
# gagnant quel qu'il soit - y compris quand il ne nous appartient pas, ce qui
# est precisement le cas interessant - et filterId -> nom pour les seuls
# filtres de la couche 2.
#
# `//item[filterKey]`: aucun item de condition ni de drapeau ne porte de
# filterKey, donc la selection ne ramene que des filtres entiers. Un decoupage
# sur `<item>` separerait un filtre de son identifiant.
function Lire-Filtres($chemin) {
    $r = New-Object psobject
    $r | Add-Member NoteProperty Compte 0
    $r | Add-Member NoteProperty Tous   @{}
    $r | Add-Member NoteProperty Nos    @{}
    if (-not $chemin) { return $r }
    $x = New-Object System.Xml.XmlDocument
    $x.Load($chemin)
    $noeuds = @($x.SelectNodes('//item[filterKey]'))
    $r.Compte = $noeuds.Count
    $tous = @{}
    $nos = @{}
    foreach ($f in $noeuds) {
        $id = [string]$f.filterId
        if ($id -eq '') { continue }
        $nom = [string]$f.displayData.name
        $tous[$id] = $nom
        if (([string]$f.filterKey).StartsWith($PrefixeCle)) { $nos[$id] = $nom }
    }
    $r.Tous = $tous
    $r.Nos = $nos
    return $r
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

# --------------------------------------------------- controle du SID, DELEGUE
#
# On ne reimplemente pas la confrontation du SID: on appelle l'instrument du
# depot et on lit son code de sortie. 0 = au moins un filtre pose porte
# exactement le SID de la cible. 1 = aucun, y compris quand rien n'est pose.
function Controle-Conditions($cible) {
    $r = New-Object psobject
    $r | Add-Member NoteProperty Ok     $false
    $r | Add-Member NoteProperty Raison ''
    $r | Add-Member NoteProperty Lignes @()
    if (-not (Test-Path $Conditions)) {
        $r.Raison = "instrument de controle introuvable: $Conditions"
        return $r
    }
    $sortie = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Conditions -Service $cible 2>&1)
    $code = $LASTEXITCODE
    # On ne garde que les lignes qui portent la reponse: le dump entier ferait
    # des centaines de lignes par passage.
    $r.Lignes = @($sortie | Where-Object {
        "$_" -like '*PORTE EXACTEMENT*' -or
        "$_" -like '*filtres portant exactement*' -or
        "$_" -like '*filtres a prefixe*' -or
        "$_" -like 'sc showsid*' -or
        "$_" -like 'ECHEC*'
    })
    if ($code -eq 0) { $r.Ok = $true } else { $r.Raison = "code $code" }
    return $r
}

# ----------------------------------------------------- continuite et voisinage
#
# Le PID se prend par CIM, jamais en analysant `sc queryex`: un Select-String
# sur une chaine multiligne rend un seul objet qui porte tout le texte, ce qui a
# deja produit un PID de vingt chiffres sur cette machine.
function Contexte-Processus($nom) {
    $c = New-Object psobject
    $c | Add-Member NoteProperty Idproc       0
    $c | Add-Member NoteProperty Creation     ''
    $c | Add-Member NoteProperty Etat         '(absent)'
    $c | Add-Member NoteProperty Image        ''
    $c | Add-Member NoteProperty Ligne        ''
    $c | Add-Member NoteProperty Colocataires @()
    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$nom'" -ErrorAction SilentlyContinue
    if ($svc -eq $null) { return $c }
    $c.Etat = [string]$svc.State
    $c.Idproc = [int]$svc.ProcessId
    if ($c.Idproc -le 0) { return $c }
    $pr = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$($c.Idproc)" -ErrorAction SilentlyContinue
    if ($pr -ne $null) {
        if ($pr.CreationDate -ne $null) {
            $c.Creation = ([datetime]$pr.CreationDate).ToString('yyyy-MM-dd HH:mm:ss.fff')
        }
        $c.Image = [string]$pr.ExecutablePath
        $c.Ligne = [string]$pr.CommandLine
    }
    $c.Colocataires = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { [int]$_.ProcessId -eq [int]$c.Idproc } | ForEach-Object { [string]$_.Name })
    return $c
}

# ------------------------------------------------------------- le declencheur

function Declencher($cible, $mode) {
    Write-Host ("   declencheur   : {0}" -f $mode)
    $etat = Get-CimInstance -ClassName Win32_Service -Filter "Name='$cible'" -ErrorAction SilentlyContinue
    if ($etat -ne $null -and [string]$etat.State -eq 'Running') {
        foreach ($l in @(& sc.exe stop $cible 2>&1)) { if ("$l".Trim() -ne '') { Write-Host ("      stop : {0}" -f "$l".Trim()) } }
        Start-Sleep -Seconds 4
    } else {
        Write-Host '      stop : (deja arrete, rien a arreter)'
    }
    foreach ($l in @(& sc.exe start $cible 2>&1)) {
        $t = "$l".Trim()
        if ($t -ne '' -and $t -notlike 'SERVICE_NAME*' -and $t -notlike 'TYPE*' -and $t -notlike 'ERROR_CONTROL*') {
            Write-Host ("      start: {0}" -f $t)
        }
    }
    Start-Sleep -Seconds 3

    if ($mode -like '*scan*') {
        # Une recherche de mises a jour reveille Delivery Optimization. On
        # imprime ce qu'on lance: une commande dont on ne lit pas la trace
        # n'est pas une mesure.
        $u = Join-Path $env:SystemRoot 'System32\UsoClient.exe'
        if (Test-Path $u) {
            Write-Host '      scan : UsoClient StartScan'
            $null = Start-Process -FilePath $u -ArgumentList 'StartScan' -PassThru -WindowStyle Hidden
        } else {
            Write-Host '      scan : SKIPPED, UsoClient.exe absent de System32'
        }
    }
    if ($mode -like '*crash*') {
        # Un rapport d'erreur, provoque par un processus jetable qui appelle
        # FailFast: c'est le chemin qui produit un rapport Watson sans toucher
        # a un processus du systeme.
        Write-Host '      crash: powershell jetable en FailFast'
        $arg = @('-NoProfile', '-Command', "[Environment]::FailFast('bifrost-banc-cibles')")
        $p = Start-Process -FilePath 'powershell.exe' -ArgumentList $arg -PassThru -WindowStyle Hidden
        if ($p -ne $null) {
            Write-Host ("             pid jetable = {0}" -f $p.Id)
            $null = Wait-Process -Id $p.Id -Timeout 25 -ErrorAction SilentlyContinue
        }
    }
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
        Write-Host ("         Application    : {0}" -f $d['Application'])
        Write-Host ("         destination    : {0}:{1}" -f $d['DestAddress'], $d['DestPort'])
    }
}

# ------------------------------------------------------------------ un passage

function Passage($etiquette, $filtre, $cible, $sidCible, $mode) {
    $res = New-Object psobject
    $res | Add-Member NoteProperty Permis     0
    $res | Add-Member NoteProperty Refuses    0
    $res | Add-Member NoteProperty Notres     0
    $res | Add-Member NoteProperty Abandon    $false
    $res | Add-Member NoteProperty Invalide   $false
    $res | Add-Member NoteProperty Raison     ''
    $res | Add-Member NoteProperty Gagnant    ''
    $res | Add-Member NoteProperty NomGagnant ''

    Write-Host ''
    if ($filtre) { Write-Host ("-- passage {0} : FILTRE --" -f $etiquette) }
    else         { Write-Host ("-- passage {0} : sans filtre --" -f $etiquette) }

    if ($filtre) {
        $script:posePassee = $true
        $null = & $Binaire --telemetrie-reseau-appliquer --telemetrie-profil $Profil 2>&1
    } else {
        $null = & $Binaire --telemetrie-reseau-retirer 2>&1
    }

    $chemin = Dump-Wfp
    if ($chemin -eq $null) {
        Write-Host '   ABANDON: netsh wfp show filters n a rien rendu, le gagnant serait innommable'
        $res.Abandon = $true
        $res.Raison = 'dump netsh absent'
        return $res
    }
    $lu = Lire-Filtres $chemin
    Remove-Item $chemin -Force -ErrorAction SilentlyContinue
    Write-Host ("   filtres       : {0} dans le moteur, {1} a la couche 2" -f $lu.Compte, @($lu.Nos.Keys).Count)

    # ------------------------- CONTROLE 1: le filtre porte-t-il le bon SID ?
    if ($filtre) {
        $ctl = Controle-Conditions $cible
        foreach ($l in @($ctl.Lignes)) { Write-Host ("   controle SID  : {0}" -f "$l".Trim()) }
        if (-not $ctl.Ok) {
            Write-Host ("   ABANDON: aucun filtre pose ne porte le SID de {0} ({1})." -f $cible, $ctl.Raison)
            Write-Host ("            SID attendu : {0}" -f $sidCible)
            Write-Host '            Un banc qui eprouve un blocage sans verifier que le blocage vise'
            Write-Host '            sa cible ne mesure rien. Mesure refusee, rien redemarre.'
            $res.Abandon = $true
            $res.Raison = "aucun filtre pose ne porte le SID de $cible"
            return $res
        }
    }

    # ------------------------------------------------- le temoin, declenche
    $marque = (Get-Date).AddSeconds(-1)
    Declencher $cible $mode

    # ---------------------- CONTROLE 2: le processus, et QUI partage son PID
    $avant = Contexte-Processus $cible
    if ($avant.Idproc -le 0) {
        Write-Host ("   MESURE INVALIDEE: {0} n a pas de PID apres le declencheur (etat {1})" -f $cible, $avant.Etat)
        $res.Invalide = $true
        $res.Raison = "pas de PID apres declencheur, etat $($avant.Etat)"
        return $res
    }
    Write-Host ("   PID au depart : {0}  cree le {1}  etat {2}" -f $avant.Idproc, $avant.Creation, $avant.Etat)
    Write-Host ("   image         : {0}" -f $avant.Image)
    Write-Host ("   ligne         : {0}" -f $avant.Ligne)
    Write-Host ("   colocataires  : {0} service(s) sur ce PID : {1}" -f @($avant.Colocataires).Count, (@($avant.Colocataires) -join ', '))
    if (@($avant.Colocataires).Count -ne 1) {
        Write-Host '   MESURE INVALIDEE: la cible partage son svchost avec d autres services.'
        Write-Host '                     Un evenement portant ce PID ne lui serait pas attribuable.'
        $res.Invalide = $true
        $res.Raison = "svchost partage: " + ((@($avant.Colocataires) -join ', '))
        return $res
    }

    # ------------- la fenetre, echantillonnee: disparition n est pas remplacement
    $depart = Get-Date
    $finFenetre = $null
    $raisonFin = 'fenetre epuisee'
    while (((Get-Date) - $depart).TotalSeconds -lt $Attente) {
        Start-Sleep -Seconds $PasEchantillon
        $t = [int]((Get-Date) - $depart).TotalSeconds
        $maintenant = Contexte-Processus $cible
        if ($maintenant.Idproc -eq $avant.Idproc -and $maintenant.Creation -eq $avant.Creation) { continue }
        if ($maintenant.Idproc -le 0) {
            # Le service s'est arrete de lui-meme. Ce n'est pas une mesure
            # invalide: c'est une fenetre plus courte. On la ferme ICI, avant
            # qu un autre processus ne puisse prendre le numero.
            $finFenetre = Get-Date
            $raisonFin = "le service s est arrete seul a t=+" + $t + "s (etat " + $maintenant.Etat + ")"
            Write-Host ("   fenetre       : fermee a t=+{0}s, {1}" -f $t, $raisonFin)
            break
        }
        Write-Host '   MESURE INVALIDEE: un AUTRE processus porte desormais le service.'
        Write-Host ("                     au depart : PID {0} cree le {1}" -f $avant.Idproc, $avant.Creation)
        Write-Host ("                     a t=+{0}s  : PID {1} cree le {2}" -f $t, $maintenant.Idproc, $maintenant.Creation)
        $res.Invalide = $true
        $res.Raison = "processus remplace a t=+" + $t + "s: PID " + $avant.Idproc + " puis PID " + $maintenant.Idproc
        return $res
    }
    if ($finFenetre -eq $null) {
        $finFenetre = Get-Date
        $apres = Contexte-Processus $cible
        Write-Host ("   PID au releve : {0}  cree le {1}  (inchange)" -f $apres.Idproc, $apres.Creation)
    }

    # ------------------------------------------------------ lecture du journal
    $permis = @()
    $refuses = @()
    $vusCompagnons = @{}
    $motsCompagnons = @()
    if ($COMPAGNONS.ContainsKey($cible)) { $motsCompagnons = @($COMPAGNONS[$cible]) }

    foreach ($id in @(5156, 5157)) {
        $evts = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$id; StartTime=$marque; EndTime=$finFenetre} -ErrorAction SilentlyContinue)
        foreach ($e in $evts) {
            $d = Detail $e
            $app = "$($d['Application'])".ToLower()
            if ("$($d['ProcessID'])" -eq "$($avant.Idproc)") {
                if ($id -eq 5156) { $permis = $permis + @($d) } else { $refuses = $refuses + @($d) }
                continue
            }
            foreach ($mot in $motsCompagnons) {
                if ($app.Contains("$mot")) {
                    $cle = "$mot|$id"
                    if ($vusCompagnons.ContainsKey($cle)) { $vusCompagnons[$cle] = $vusCompagnons[$cle] + 1 }
                    else { $vusCompagnons[$cle] = 1 }
                    break
                }
            }
        }
    }

    $chemin2 = Dump-Wfp
    $lu2 = Lire-Filtres $chemin2
    if ($chemin2 -ne $null) { Remove-Item $chemin2 -Force -ErrorAction SilentlyContinue }
    $notres = @(@($refuses) | Where-Object { $lu2.Nos.ContainsKey("$($_['FilterRTID'])") }).Count

    $res.Permis = @($permis).Count
    $res.Refuses = @($refuses).Count
    $res.Notres = $notres
    Write-Host ("   RESULTAT      autorisees={0}  refusees={1}  dont par nos filtres={2}   ({3})" -f `
        $res.Permis, $res.Refuses, $res.Notres, $raisonFin)

    $premier = $null
    if (@($refuses).Count -gt 0) { $premier = @($refuses)[0] } elseif (@($permis).Count -gt 0) { $premier = @($permis)[0] }
    if ($premier -ne $null) {
        $rt = "$($premier['FilterRTID'])"
        $res.Gagnant = $rt
        if ($lu2.Tous.ContainsKey($rt)) { $res.NomGagnant = $lu2.Tous[$rt] } else { $res.NomGagnant = '(absent du dump)' }
    }

    Nommer-Gagnants 'AUTORISEE' $permis $lu2.Nos $lu2.Tous 3
    Nommer-Gagnants 'REFUSEE  ' $refuses $lu2.Nos $lu2.Tous 3

    if (@($motsCompagnons).Count -gt 0) {
        if (@($vusCompagnons.Keys).Count -eq 0) {
            Write-Host ("   compagnons    : aucun evenement de {0} pendant la fenetre" -f ($motsCompagnons -join ', '))
        } else {
            foreach ($k in @($vusCompagnons.Keys)) {
                $q = "$k" -split '\|'
                Write-Host ("   compagnon     : {0} evenement(s) {1} pour un binaire nommant '{2}'  (CONTEXTE, pas un verdict)" -f $vusCompagnons[$k], $q[1], $q[0])
            }
        }
    }
    return $res
}

# ------------------------------------------------------- la reconnaissance
#
# La question du temoin, et rien d'autre: laquelle des quatre cibles emet
# d'elle-meme, sans qu'on pose quoi que ce soit ? Elle se pose AVANT toute
# mesure de blocage, parce qu'une cible muette rend un blocage reussi et une
# machine morte identiques.
#
# Ce mode imprime aussi le TOTAL des evenements toutes origines confondues.
# Sans ce total, un zero sur les quatre cibles se lit comme << elles n'emettent
# pas >> alors qu'il pourrait dire << l'audit ne journalise rien >>. Deux etats
# indiscernables valent zero information.
function Reconnaissance-Temoins($minutes) {
    $chemin = Dump-Wfp
    $lu = Lire-Filtres $chemin
    if ($chemin -ne $null) { Remove-Item $chemin -Force -ErrorAction SilentlyContinue }
    Write-Host ("filtres couche 2 dans le moteur : {0}" -f @($lu.Nos.Keys).Count)
    if (@($lu.Nos.Keys).Count -ne 0) {
        Write-Host '   ABANDON: des filtres de la couche 2 sont poses. Une reconnaissance du'
        Write-Host '            temoin doit se faire sans eux, sinon elle mesure autre chose.'
        return 1
    }

    Write-Host ''
    Write-Host 'politique d audit trouvee:'
    foreach ($l in @(& auditpol /get /subcategory:"$Sous" /r)) {
        if ("$l".Trim() -ne '') { Write-Host ("  {0}" -f $l) }
    }
    $null = & auditpol /set /subcategory:"$Sous" /success:enable /failure:enable
    $script:auditTouche = $true

    $marque = (Get-Date).AddSeconds(-1)
    $vus = @{}      # pid -> "service|creation"
    $reutilise = @{}
    # Un service ARRETE et un service qui tourne sans rien dire ne sont pas le
    # meme fait, et les confondre sous << MUET >> serait une lecture fausse.
    $vivant = @{}
    $noms = @($CIBLES.Keys) | Sort-Object
    foreach ($n in $noms) { $vivant[$n] = 0 }
    $depart = Get-Date
    $tour = 0
    while (((Get-Date) - $depart).TotalMinutes -lt $minutes) {
        $tour = $tour + 1
        foreach ($n in $noms) {
            $c = Contexte-Processus $n
            if ($c.Idproc -le 0) { continue }
            $vivant[$n] = $vivant[$n] + 1
            $cle = [string]$c.Idproc
            $val = $n + '|' + $c.Creation
            if ($vus.ContainsKey($cle)) {
                if ($vus[$cle] -ne $val) { $reutilise[$cle] = $vus[$cle] + '  PUIS  ' + $val }
            }
            $vus[$cle] = $val
        }
        Start-Sleep -Seconds 10
    }
    $fin = Get-Date
    Write-Host ("{0} tour(s) d observation, de {1} a {2}" -f $tour, $marque.ToString('HH:mm:ss'), $fin.ToString('HH:mm:ss'))
    Write-Host ''
    Write-Host 'PID vus pendant la fenetre:'
    foreach ($k in (@($vus.Keys) | Sort-Object)) { Write-Host ("   pid {0} -> {1}" -f $k, $vus[$k]) }
    foreach ($k in (@($reutilise.Keys) | Sort-Object)) {
        Write-Host ("   AMBIGU: le pid {0} a change de processus: {1}" -f $k, $reutilise[$k])
    }

    $total = 0
    $parCible = @{}
    $detail = @{}
    foreach ($id in @(5156, 5157)) {
        foreach ($e in @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$id; StartTime=$marque; EndTime=$fin} -ErrorAction SilentlyContinue)) {
            $total = $total + 1
            $d = Detail $e
            $p = "$($d['ProcessID'])"
            if (-not $vus.ContainsKey($p)) { continue }
            $svc = ("$($vus[$p])" -split '\|')[0]
            $cle = $svc + '|' + $id
            if ($parCible.ContainsKey($cle)) { $parCible[$cle] = $parCible[$cle] + 1 } else { $parCible[$cle] = 1 }
            if (-not $detail.ContainsKey($cle)) {
                $detail[$cle] = ("rtid={0} layer={1} dst={2}:{3}" -f $d['FilterRTID'], $d['LayerRTID'], $d['DestAddress'], $d['DestPort'])
            }
        }
    }

    Write-Host ''
    Write-Host ('=' * 78)
    Write-Host ("evenements 5156+5157 dans la fenetre, TOUTES origines : {0}" -f $total)
    if ($total -eq 0) {
        Write-Host '   L instrument est MUET: aucun evenement du tout. Un zero par cible ne'
        Write-Host '   voudrait alors rien dire. Verifier la politique d audit avant de conclure.'
    }
    Write-Host ''
    foreach ($n in $noms) {
        $p = 0; $r = 0
        if ($parCible.ContainsKey($n + '|5156')) { $p = $parCible[$n + '|5156'] }
        if ($parCible.ContainsKey($n + '|5157')) { $r = $parCible[$n + '|5157'] }
        $verdict = 'MUET       '
        if ($vivant[$n] -eq 0) { $verdict = 'JAMAIS VU  ' }
        if (($p + $r) -gt 0) { $verdict = 'EMET       ' }
        Write-Host ("   {0,-18} {1}   autorisees={2} refusees={3}   vu vivant sur {4}/{5} tour(s)" -f `
            $n, $verdict, $p, $r, $vivant[$n], $tour)
        foreach ($id in @('5156', '5157')) {
            if ($detail.ContainsKey($n + '|' + $id)) {
                Write-Host ("      premier {0} : {1}" -f $id, $detail[$n + '|' + $id])
            }
        }
    }
    return 0
}

# ------------------------------------------------------------------- le corps

function Main {
    Write-Host ('=' * 78)
    Write-Host 'Banc des VRAIES cibles de la couche 2, autres que DiagTrack'
    Write-Host ("hote          : {0}" -f $env:COMPUTERNAME)
    Write-Host ("windows       : {0}" -f (Get-CimInstance Win32_OperatingSystem).Version)
    Write-Host ("powershell    : {0}" -f $PSVersionTable.PSVersion)
    $ident = [Security.Principal.WindowsIdentity]::GetCurrent()
    $princ = New-Object Security.Principal.WindowsPrincipal($ident)
    Write-Host ("session admin : {0}" -f $princ.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    Write-Host ("demarre le    : {0}" -f (Get-CimInstance Win32_OperatingSystem).LastBootUpTime)
    Write-Host ("maintenant    : {0}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
    Write-Host ("binaire       : {0}" -f $Binaire)
    Write-Host ("profil        : {0}" -f $Profil)
    Write-Host ('=' * 78)

    if (-not (Test-Path $Binaire)) { Write-Host 'ECHEC: binaire introuvable'; return 1 }

    # Garde-fou. Ce banc fait `sc stop` puis `sc start` sur le nom qu on lui
    # donne. Une faute de frappe arreterait un service systeme. Seules les
    # quatre cibles du catalogue jamais eprouvees passent, et DiagTrack est
    # refuse expres: il a son propre banc.
    if ($Reconnaissance -gt 0) { return (Reconnaissance-Temoins $Reconnaissance) }
    if (-not $CIBLES.ContainsKey($Service)) {
        Write-Host ("REFUS: {0} n est pas une des quatre cibles de ce banc." -f $Service)
        Write-Host ("       Attendu, une a la fois : {0}" -f ((@($CIBLES.Keys) | Sort-Object) -join ', '))
        Write-Host '       DiagTrack est refuse ici: son banc est telemetrie-effet-windows.ps1.'
        return 1
    }
    $mode = $Declencheur
    if ("$mode" -eq '') { $mode = [string]$CIBLES[$Service] }
    Write-Host ("cible         : {0}" -f $Service)
    Write-Host ("declencheur   : {0}" -f $mode)
    Write-Host ("fenetre       : {0} s, echantillon toutes les {1} s" -f $Attente, $PasEchantillon)

    $sidCible = Sid-De-Service $Service
    if ("$sidCible" -eq '') {
        Write-Host ("ECHEC: sc showsid {0} n a rendu aucun SID S-1-5-80." -f $Service)
        Write-Host '       Sans SID, un filtre ALE_USER_ID se poserait sans jamais mordre.'
        return 1
    }
    Write-Host ("SID attendu   : {0}" -f $sidCible)

    # Le piege qui rendrait la couche inoperante EN SILENCE: un service en
    # SERVICE_SID_TYPE NONE ne porte aucun SID de service dans son jeton, et la
    # condition ne mordrait jamais - sans erreur, sans trace, avec un rapport
    # vert. Il se verifie, il ne se suppose pas.
    $sidtype = ''
    foreach ($l in @(& sc.exe qsidtype $Service 2>&1)) {
        $m = [regex]::Match("$l", 'SERVICE_SID_TYPE\s*:\s*(\S+)')
        if ($m.Success) { $sidtype = $m.Groups[1].Value }
    }
    Write-Host ("SID_TYPE      : {0}" -f $sidtype)
    if ($sidtype -eq 'NONE' -or $sidtype -eq '') {
        Write-Host '   ECHEC: sans SID de service dans le jeton, un filtre ALE_USER_ID se pose'
        Write-Host '          sans erreur et ne mord JAMAIS. Cible SANS OBJET, pas eprouvable.'
        return 1
    }

    # L'audit des SUCCES est indispensable: sans lui, << n a rien tente >> et
    # << a ete bloque >> rendent la meme mesure, c est-a-dire aucune.
    Write-Host ''
    Write-Host 'politique d audit trouvee:'
    foreach ($l in @(& auditpol /get /subcategory:"$Sous" /r)) {
        if ("$l".Trim() -ne '') { Write-Host ("  {0}" -f $l) }
    }
    $null = & auditpol /set /subcategory:"$Sous" /success:enable /failure:enable
    $script:auditTouche = $true

    Write-Host ''
    Write-Host '== Trois passages alternes, en commencant PAR le cas filtre =='
    Write-Host '   (commencer sans filtre attribuerait au filtre un simple epuisement de file)'

    $a = Passage 'A' $true  $Service $sidCible $mode
    $b = $null
    $c = $null
    if (-not $a.Abandon) {
        $b = Passage 'B' $false $Service $sidCible $mode
        $c = Passage 'C' $true  $Service $sidCible $mode
    }

    Write-Host ''
    Write-Host '== Verdict =='
    Write-Host ("  cible : {0}" -f $Service)
    if ($a.Abandon) { Write-Host ("  ABANDON  passage A: {0}" -f $a.Raison); return 1 }
    if ($c.Abandon) { Write-Host ("  ABANDON  passage C: {0}" -f $c.Raison); return 1 }

    Write-Host ("  A FILTRE  autorisees={0} refusees={1} dont nous={2}  rtid={3} << {4} >>" -f $a.Permis, $a.Refuses, $a.Notres, $a.Gagnant, $a.NomGagnant)
    Write-Host ("  B sans    autorisees={0} refusees={1} dont nous={2}  rtid={3} << {4} >>" -f $b.Permis, $b.Refuses, $b.Notres, $b.Gagnant, $b.NomGagnant)
    Write-Host ("  C FILTRE  autorisees={0} refusees={1} dont nous={2}  rtid={3} << {4} >>" -f $c.Permis, $c.Refuses, $c.Notres, $c.Gagnant, $c.NomGagnant)

    $invalides = @()
    if ($a.Invalide) { $invalides = $invalides + @("A: " + $a.Raison) }
    if ($b.Invalide) { $invalides = $invalides + @("B: " + $b.Raison) }
    if ($c.Invalide) { $invalides = $invalides + @("C: " + $c.Raison) }
    if (@($invalides).Count -gt 0) {
        Write-Host '  SKIPPED  la mesure a ete invalidee, elle ne discrimine pas:'
        foreach ($i in @($invalides)) { Write-Host ("           {0}" -f $i) }
        return 0
    }
    if (($a.Notres + $c.Notres) -ge 1) {
        Write-Host ("  BLOQUE   {0} refus impute(s) a un filtre de la couche 2. Le systeme nomme notre filtre." -f ($a.Notres + $c.Notres))
        return 0
    }
    if (($a.Permis + $c.Permis) -ge 1) {
        Write-Host ("  ECHAPPE  {0} connexion(s) AUTORISEE(S) alors que les filtres etaient poses, verifies presents," -f ($a.Permis + $c.Permis))
        Write-Host '           et verifies porteurs du SID exact de la cible. Notre filtre n a pas MATCHE.'
        return 1
    }
    if ($b.Permis -ge 1) {
        Write-Host '  INDICE   le temoin emet sans filtre et se tait avec, mais aucun 5157 ne l impute:'
        Write-Host '           on ne sait pas QUI a bloque. Insuffisant pour conclure BLOQUE.'
        return 0
    }
    Write-Host '  SKIPPED  le temoin n a RIEN emis, meme sans aucun filtre (passage B), avec ce'
    Write-Host ("           declencheur ({0}). La cible n est pas eprouvable ainsi:" -f $mode)
    Write-Host '           une machine muette et un blocage reussi rendent la meme mesure.'
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
    if ($script:posePassee) {
        $null = & $Binaire --telemetrie-reseau-retirer 2>&1
        $cheminMenage = Dump-Wfp
        if ($cheminMenage -ne $null) {
            $luMenage = Lire-Filtres $cheminMenage
            Remove-Item $cheminMenage -Force -ErrorAction SilentlyContinue
            Write-Host ("  relecture netsh : {0} filtre(s) de la couche 2 dans le moteur" -f @($luMenage.Nos.Keys).Count)
        } else {
            Write-Host '  relecture netsh : rien rendu, la presence des filtres n est PAS verifiee'
        }
    } else {
        Write-Host '  rien pose, donc rien a retirer: le binaire n est pas relance'
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

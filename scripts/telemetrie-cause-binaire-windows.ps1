# Le mecanisme ALE_APP_ID de la couche 2 mord-il ? Le banc qui le tranche.
#
# A lancer sur essai-windows, en administrateur, shell cmd, depuis la racine du
# banc (le repertoire qui contient les binaires) ou avec BIFROST_BANC pose:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\telemetrie-cause-binaire-windows.ps1
#
# POURQUOI IL EXISTE. Le catalogue de la couche 2 porte DEUX mecanismes et un
# seul a ete eprouve en effet:
#
#   - Cible::Service   -> Condition::UserId -> FWPM_CONDITION_ALE_USER_ID.
#     Cinq cibles. MESURE le 22 et le 23 aout 2026: il mord. 569 refus sur un
#     service de test ordinaire, 673 sur un service au jeton filtre, notre
#     filtre nomme par l evenement 5157 dans les deux cas.
#   - Cible::Binaire   -> Condition::AppId  -> FWPM_CONDITION_ALE_APP_ID.
#     Cinq cibles: CompatTelRunner, DeviceCensus, MusNotification, SIHClient,
#     WaaSMedicAgent. JAMAIS eprouve autrement qu en POSE. On sait que les
#     filtres entrent dans le moteur et qu ils portent le bon chemin NT. On ne
#     sait pas qu ils refusent quoi que ce soit.
#
# La moitie du catalogue repose donc sur une supposition. Ce banc la transforme
# en mesure, ou en echec.
#
# CE QU IL A DE PLUS SIMPLE QUE SON MODELE. `telemetrie-cause-windows.ps1` doit
# creer un SERVICE, parce que ALE_USER_ID compare un jeton et qu un jeton de
# service ne s obtient pas autrement. ALE_APP_ID, lui, compare le chemin de
# l IMAGE du processus: n importe quel processus fait un temoin. Le banc copie
# donc le daemon vers un chemin jetable, pose le blocage sur CE chemin, lance la
# copie en --connect-probe, et lit qui a gagne. Aucun service n est cree.
#
# LES LECONS DEJA PAYEES, ET QU IL GARDE
#
# 1. L AUDIT DES SUCCES doit etre actif. Sans lui, "bloque" et "n a jamais
#    essaye" rendent la meme mesure, c est-a-dire aucune. Le banc l active et le
#    remet dans l etat trouve.
# 2. UN TEMOIN MUET CERTIFIE N IMPORTE QUOI. Le passage sans filtre doit voir la
#    copie SORTIR pour de bon. S il ne sort pas, la mesure ne discrimine pas et
#    le verdict est SKIPPED, jamais un vert.
# 3. PASSAGES ALTERNES, en commencant PAR le cas filtre. Commencer sans filtre
#    attribuerait au filtre tout epuisement ou toute derive de la machine.
# 4. VERIFIER QUE LE FILTRE POSE PORTE LA CIBLE avant de mesurer quoi que ce
#    soit, comme `telemetrie-conditions-windows.ps1` le fait pour les SID. Si
#    aucun filtre pose ne porte le chemin vise, le banc ABANDONNE avant de
#    lancer le temoin et sort non nul: un banc qui eprouve un blocage sans
#    verifier que le blocage vise sa cible ne mesure rien.
# 5. LE DUMP netsh EST DU XML ou `<item>` sert AUSSI aux drapeaux et aux
#    conditions. On le charge en DOM et on selectionne par `//item[filterKey]`,
#    jamais par un decoupage sur `<item>`, qui separerait un filtre de son
#    identifiant.
# 6. L INSTRUMENT SE VERIFIE DES DEUX COTES DE LA FENETRE. L empreinte de la
#    copie est comparee a celle de la source AVANT la mesure et de nouveau
#    APRES: verifier avant ne suffit pas quand quelque chose peut encore ecrire
#    apres.
# 7. LE MENAGE SE VERIFIE INDEPENDAMMENT DE CE QUI A POSE. Le retrait est
#    demande au binaire, puis relu par un dump netsh frais, qui n est pas le
#    binaire.
# 8. UN SIGNAL QUI REND $null N EST PAS UN SIGNAL. `Start-Process -PassThru`
#    rend un objet dont `ExitCode` vaut $null apres la sortie du processus, et
#    la lecture NE LEVE PAS: un try/catch ne la rattrape donc pas. Mesure du
#    23/08/2026 sur essai-windows, code de sortie connu 3: sans toucher
#    `.Handle` tant que le processus vit, `ExitCode` rend [] de type null; en le
#    touchant, il rend 3. Le premier passage de ce banc a perdu ainsi la moitie
#    de ce qu il promettait de croiser, et a imprime une RESERVE annoncant deux
#    signaux qui divergent alors qu un seul avait ete obtenu.
#
# CE QUE CE BANC SAIT LIRE. Deux signaux independants, et c est voulu:
#   - le CODE DE SORTIE de la copie. `--connect-probe` rend 5 quand la connexion
#     s etablit et 3 quand un filtre l a refusee (WSAEACCES). Ce signal ne
#     depend d aucun journal.
#   - le JOURNAL de securite, 5156 et 5157, filtres sur le PID de la copie. Lui
#     seul NOMME le filtre gagnant, par son FilterRTID.
# Les deux doivent concorder. Quand ils divergent, le banc le dit et ne conclut
# pas.
#
# VERDICTS, et aucun n est un vert par defaut:
#   MESURE   un refus est impute a un FilterRTID de la couche 2. C est la preuve
#            que ALE_APP_ID mord.
#   ECHEC    une connexion passe alors que le filtre est pose et verifie porteur
#            du chemin vise; ou aucun filtre pose ne porte ce chemin.
#   INDICE   le temoin se dit bloque mais aucun 5157 ne l impute: on ne sait pas
#            QUI a bloque.
#   SKIPPED  le temoin ne sort pas sans filtre, ou une etape n a pas pu avoir
#            lieu. Un SKIPPED porte TOUJOURS sa raison.

param(
    # La racine du banc: le repertoire du script (via -File), ou BIFROST_BANC si pose.
    [string]$Banc = $(if ($env:BIFROST_BANC) { $env:BIFROST_BANC } else { $PSScriptRoot }),
    # Le daemon qui POSE les filtres. Il n est jamais la cible du blocage.
    [string]$Binaire = (Join-Path $Banc 'bifrost-daemon.exe'),
    # La copie jetable, qui est la cible du blocage. Volontairement dans le meme
    # repertoire que la source et sous un AUTRE nom: ce qui vit a cote du daemon
    # reste a cote de la copie, et seul le chemin change entre les deux.
    [string]$Temoin = (Join-Path $Banc 'bifrost-temoin-appid.exe'),
    [string]$Cible = '1.1.1.1:443',
    # Duree d une rafale de tentatives, en millisecondes.
    [int]$Rafale = 8000,
    # Prefixe des cles de filtre de la couche 2. Ecrit ici A LA MAIN: si le banc
    # le lisait du binaire, les deux se tromperaient ensemble.
    [string]$PrefixeCle = '{3ac9d182-5e42-4b77-9d61-8e05f3a2'
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

$script:auditTouche = $false
$script:copieFaite = $false
$script:empreinteSource = ''
$script:conditionsImprimees = $false

# ------------------------------------------------------------- lecture WFP

# Rend le chemin d un dump FRAIS, ou $null. L appelant le supprime.
function Dump-Wfp {
    $f = Join-Path $env:SystemRoot 'Temp\bifrost-cause-binaire.xml'
    if (Test-Path $f) { Remove-Item $f -Force -ErrorAction SilentlyContinue }
    $null = & netsh wfp show filters file="$f" 2>&1
    if (-not (Test-Path $f)) { return $null }
    return $f
}

# Les filtres du moteur, avec ce qu ils PORTENT.
#
# Rend le compte total, une table filterId -> nom pour TOUS les filtres - elle
# sert a NOMMER le gagnant quel qu il soit, y compris s il ne nous appartient
# pas, ce qui est precisement le cas interessant - et le detail complet,
# conditions comprises, des seuls filtres a nous.
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

# --------------------------------------------------- ce que le chemin devient
#
# WFP ne compare pas un chemin DOS. `FwpmGetAppIdFromFileName0` ouvre le fichier
# et rend le chemin NT correspondant, en MINUSCULES, de la forme
# `\device\harddiskvolumeN\reste\du\chemin.exe`. Mesure sur dev-windows par la
# recette `windows::ffi::tests::l_identifiant_d_application_est_un_chemin_nt_en_minuscules`.
#
# Le banc ne cherche donc pas le chemin DOS dans le dump, il cherche ce qui en
# survit: TOUT sauf la lettre de lecteur. Le numero de volume, lui, depend de la
# machine et ne se devine pas d ici; l exiger reviendrait a inventer.
function Aiguille-Chemin($chemin) {
    $t = ("$chemin" -replace '/', '\').ToLower()
    # La lettre de lecteur et son deux-points sont ce que le chemin NT remplace.
    $t = [regex]::Replace($t, '^[a-z]:', '')
    return $t
}

# La meme aiguille encodee comme WFP la stocke: UTF-16LE, en hexadecimal.
# Filet de securite si une version de netsh imprimait le blob en octets plutot
# qu en clair. Cherchee dans la valeur reduite a ses seuls caracteres hexa.
function Aiguille-Hexa($aiguille) {
    $sb = New-Object System.Text.StringBuilder
    foreach ($o in [System.Text.Encoding]::Unicode.GetBytes("$aiguille")) {
        $null = $sb.Append($o.ToString('x2'))
    }
    return $sb.ToString()
}

# Les filtres dont UNE condition porte ce chemin, et par quelle lecture.
function Filtres-Portant($nos, $chemin) {
    $aiguille = Aiguille-Chemin $chemin
    $hexa = Aiguille-Hexa $aiguille
    $out = New-Object System.Collections.ArrayList
    if ("$aiguille" -eq '') { return @() }
    foreach ($f in @($nos)) {
        foreach ($c in @($f.Conditions)) {
            $v = "$($c.Valeur)".ToLower()
            $par = ''
            if ($v.Contains($aiguille)) {
                $par = 'en clair'
            } else {
                $reduit = [regex]::Replace($v, '[^0-9a-f]', '')
                if ($reduit.Contains($hexa)) { $par = 'en hexadecimal' }
            }
            if ($par -ne '') {
                $o = New-Object psobject
                $o | Add-Member NoteProperty Id  $f.Id
                $o | Add-Member NoteProperty Nom $f.Nom
                $o | Add-Member NoteProperty Par $par
                $null = $out.Add($o)
                break
            }
        }
    }
    return @($out.ToArray())
}

# ------------------------------------------------------- lecture des journaux

function Detail($e) {
    $x = [xml]$e.ToXml(); $d = @{}
    foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
    return $d
}

# Le temoin est discrimine par DEUX choses a la fois, et c est voulu.
#
# Le champ `Application` porte le chemin NT de l image, qui est precisement ce
# que ALE_APP_ID compare, et il est UNIQUE a notre copie: contrairement au banc
# par SID, ou tous les svchost partagent le meme chemin et ou ce champ ne
# discriminait rien, ici il discrimine tout seul. Le PID vient en plus, parce
# qu on l a lance et qu on le connait: il elimine un reliquat d un passage
# precedent que le chemin, lui, ne distinguerait pas.
function Evenements($marque, $id, $idproc, $aiguille) {
    $out = @()
    foreach ($e in @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$id; StartTime=$marque} -ErrorAction SilentlyContinue)) {
        $d = Detail $e
        $app = "$($d['Application'])".ToLower()
        if (-not $app.EndsWith($aiguille)) { continue }
        if ($idproc -gt 0 -and "$($d['ProcessID'])" -ne "$idproc") { continue }
        $out = $out + @($d)
    }
    return $out
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

# ---------------------------------------------------------------- l empreinte

function Empreinte($chemin) {
    if (-not (Test-Path $chemin)) { return '' }
    return (Get-FileHash -LiteralPath $chemin -Algorithm SHA256).Hash.ToLower()
}

# ------------------------------------------------------------------ un passage

function Passage($etiquette, $filtre) {
    $res = New-Object psobject
    $res | Add-Member NoteProperty Permis     0
    $res | Add-Member NoteProperty Refuses    0
    $res | Add-Member NoteProperty Notres     0
    $res | Add-Member NoteProperty Poses      0
    $res | Add-Member NoteProperty Sortie     -1
    $res | Add-Member NoteProperty EchecCible $false
    $res | Add-Member NoteProperty Invalide   $false
    $res | Add-Member NoteProperty Raison     ''

    Write-Host ''
    if ($filtre) { Write-Host ("-- passage {0} : SONDE POSEE --" -f $etiquette) }
    else         { Write-Host ("-- passage {0} : sans filtre --" -f $etiquette) }

    if ($filtre) {
        $sortiePose = & $Binaire --telemetrie-sonde-binaire $Temoin 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host '   ECHEC: la sonde n a rien pose'
            foreach ($l in @($sortiePose)) { Write-Host ("      {0}" -f $l) }
            $res.EchecCible = $true
            $res.Raison = 'la sonde n a pose aucun filtre'
            return $res
        }
        foreach ($l in @($sortiePose)) { Write-Host ("   pose : {0}" -f $l) }
    } else {
        $null = & $Binaire --telemetrie-reseau-retirer 2>&1
    }

    $chemin = Dump-Wfp
    if ($chemin -eq $null) {
        Write-Host '   ECHEC: netsh wfp show filters n a rien rendu, le gagnant serait innommable'
        $res.EchecCible = $true
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

    # ------------------------ CONTROLE: ce que les filtres portent VRAIMENT
    if ($filtre) {
        if ($nos.Count -eq 0) {
            Write-Host '   ECHEC: aucun filtre lisible dans le moteur apres la pose'
            $res.EchecCible = $true
            $res.Raison = 'aucun filtre a nous dans le moteur apres la pose'
            return $res
        }
        if (-not $script:conditionsImprimees) {
            Write-Host '   ce que la pose porte, condition par condition:'
            Afficher-Conditions $nos
            $script:conditionsImprimees = $true
        }
        $porteurs = @(Filtres-Portant $nos $Temoin)
        if ($porteurs.Count -eq 0) {
            Write-Host ("   ECHEC DE GARDE: aucun des {0} filtres poses ne porte le chemin vise." -f $nos.Count)
            Write-Host ("                   chemin vise : {0}" -f $Temoin)
            Write-Host ("                   cherche sous: {0}" -f (Aiguille-Chemin $Temoin))
            Write-Host '                   Un banc qui eprouve un blocage sans verifier que le blocage'
            Write-Host '                   vise sa cible ne mesure rien. Mesure refusee, temoin non lance.'
            Write-Host '                   Ce que les filtres poses portent reellement:'
            Afficher-Conditions $nos
            $res.EchecCible = $true
            $res.Raison = "aucun filtre pose ne porte le chemin $Temoin"
            return $res
        }
        Write-Host ("   CONTROLE APP  : {0} filtre(s) pose(s) portent le chemin vise" -f $porteurs.Count)
        foreach ($f in $porteurs) {
            Write-Host ("                   id={0}  {1}  (lu {2})" -f $f.Id, $f.Nom, $f.Par)
        }
    } else {
        # Le passage SANS filtre doit etre vraiment sans filtre. Un retrait qui
        # echoue laisserait le temoin sortir - ou pas - sous une sonde encore
        # posee, et ce passage-la est justement celui qui etablit que la mesure
        # discrimine. Le compte vient du dump netsh, pas du code de retour du
        # binaire qui a demande le retrait.
        if ($nos.Count -ne 0) {
            Write-Host ("   MESURE INVALIDEE: {0} filtre(s) de la couche 2 sont encore dans le moteur" -f $nos.Count)
            Write-Host '                     alors que ce passage doit etre sans filtre. Le retrait a echoue.'
            Afficher-Conditions $nos
            $res.Invalide = $true
            $res.Raison = "$($nos.Count) filtre(s) restants au passage sans filtre"
            return $res
        }
    }

    # ----------------------------------------------------- le temoin, a la demande
    $marque = (Get-Date).AddSeconds(-1)
    $proc = Start-Process -FilePath $Temoin `
        -ArgumentList @('--connect-probe', $Cible, '--connect-probe-rafale', "$Rafale") `
        -PassThru -NoNewWindow
    if ($proc -eq $null) {
        Write-Host '   MESURE INVALIDEE: le temoin n a pas demarre'
        $res.Invalide = $true
        $res.Raison = 'le temoin n a pas demarre'
        return $res
    }
    # LE HANDLE, ET IL SE TOUCHE TANT QUE LE PROCESSUS VIT. Sans cette ligne,
    # `Start-Process -PassThru` rend un objet dont `ExitCode` vaut $null une
    # fois le processus sorti, SANS lever - donc sans que le try/catch plus bas
    # ne voie rien. Mesure du 23/08/2026 sur essai-windows, meme commande a code
    # de sortie connu 3: sans le handle `ExitCode` rend [] de type null, avec le
    # handle il rend 3. Lire `.Handle` force l objet .NET a garder le handle du
    # processus, seul moyen d obtenir le code apres la sortie.
    $null = $proc.Handle
    $idproc = $proc.Id
    Write-Host ("   temoin        : PID {0}, rafale de {1} ms" -f $idproc, $Rafale)
    if (-not $proc.WaitForExit($Rafale + 30000)) {
        $null = Stop-Process -Id $idproc -Force -ErrorAction SilentlyContinue
        Write-Host '   MESURE INVALIDEE: le temoin ne s est pas termine dans sa fenetre'
        $res.Invalide = $true
        $res.Raison = 'le temoin ne s est pas termine dans sa fenetre'
        return $res
    }
    # `ExitCode` peut n etre pas lisible selon la facon dont le processus a ete
    # ouvert. On ne fait pas semblant: -1 et une raison imprimee valent mieux
    # qu un zero par defaut, qui se lirait comme "rien ne l a refuse".
    #
    # DEUX facons de ne pas etre lisible, et une seule levait. La lecture peut
    # aussi rendre $null en silence: c est exactement ce qui est arrive au
    # premier passage de ce banc, le 23/08/2026, et le try/catch n a rien vu.
    # Un $null non teste se propage jusqu au verdict, ou il s imprime comme une
    # case vide et se lit comme un signal qui aurait diverge - alors qu il n a
    # jamais ete obtenu. Les deux cas rendent donc -1, et le disent.
    $codeLu = $null
    $pourquoiIllisible = 'la lecture a rendu $null sans lever'
    try {
        $codeLu = $proc.ExitCode
    } catch {
        $pourquoiIllisible = $_.Exception.Message
    }
    if ($null -eq $codeLu) {
        $res.Sortie = -1
        Write-Host ("   code de sortie: ILLISIBLE  ({0})" -f $pourquoiIllisible)
        Write-Host '                   le journal reste le seul signal de ce passage.'
    } else {
        $res.Sortie = [int]$codeLu
        $mot = 'inattendu'
        if ($res.Sortie -eq 0) { $mot = 'PASSE (rien ne l a refuse, rien n a abouti)' }
        if ($res.Sortie -eq 3) { $mot = 'BLOQUE par un filtre' }
        if ($res.Sortie -eq 4) { $mot = 'SANS ROUTE' }
        if ($res.Sortie -eq 5) { $mot = 'CONNECTE' }
        Write-Host ("   code de sortie: {0}  {1}" -f $res.Sortie, $mot)
    }

    # Les evenements mettent un instant a etre ecrits dans le journal.
    Start-Sleep -Seconds 5

    # ------------------------------------------------------ lecture du journal
    $aiguille = Aiguille-Chemin $Temoin
    $permis = @(Evenements $marque 5156 $idproc $aiguille)
    $refuses = @(Evenements $marque 5157 $idproc $aiguille)
    $notres = @(@($refuses) | Where-Object { $tableNos.ContainsKey("$($_['FilterRTID'])") }).Count
    $res.Permis = @($permis).Count
    $res.Refuses = @($refuses).Count
    $res.Notres = $notres
    Write-Host ("   RESULTAT      autorisees={0}  refusees={1}  dont par nos filtres={2}" -f `
        $res.Permis, $res.Refuses, $res.Notres)
    if (($res.Permis + $res.Refuses) -eq 0) {
        Write-Host ("   NOTE          aucun evenement ne porte a la fois le PID {0} et le chemin" -f $idproc)
        Write-Host ("                 {0}. Le code de sortie reste lisible, mais rien" -f $aiguille)
        Write-Host '                 ne NOMME de filtre gagnant sur ce passage.'
    }
    Nommer-Gagnants 'AUTORISEE' $permis $tableNos $tous 3
    Nommer-Gagnants 'REFUSEE  ' $refuses $tableNos $tous 3
    return $res
}

# ------------------------------------------------------------------- le corps

function Main {
    Write-Host ('=' * 78)
    Write-Host 'Banc de CAUSE de la couche 2, mecanisme ALE_APP_ID'
    Write-Host ("hote          : {0}" -f $env:COMPUTERNAME)
    Write-Host ("windows       : {0}" -f (Get-CimInstance Win32_OperatingSystem).Version)
    Write-Host ("powershell    : {0}" -f $PSVersionTable.PSVersion)
    $ident = [Security.Principal.WindowsIdentity]::GetCurrent()
    $princ = New-Object Security.Principal.WindowsPrincipal($ident)
    Write-Host ("session admin : {0}" -f $princ.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    Write-Host ("binaire       : {0}" -f $Binaire)
    Write-Host ("temoin        : {0}" -f $Temoin)
    Write-Host ("cible         : {0}" -f $Cible)
    Write-Host ('=' * 78)

    if (-not (Test-Path $Binaire)) { Write-Host 'ECHEC: binaire introuvable'; return 1 }

    # Le temoin ne doit JAMAIS ecraser la source, et le daemon refuse de toute
    # facon de viser un binaire du systeme ou du catalogue. Ce refus-ci est
    # local et vise une faute de frappe qui detruirait l instrument.
    if ((Aiguille-Chemin $Temoin) -eq (Aiguille-Chemin $Binaire)) {
        Write-Host 'REFUS: le temoin et le binaire designent le meme fichier.'
        Write-Host '       La copie ecraserait la source, et le blocage viserait le poseur.'
        return 1
    }

    # ---------------------------------------------- l instrument, avant mesure
    $script:empreinteSource = Empreinte $Binaire
    Copy-Item -LiteralPath $Binaire -Destination $Temoin -Force
    if (-not (Test-Path $Temoin)) {
        Write-Host ("ECHEC: la copie vers {0} n a pas eu lieu" -f $Temoin)
        return 1
    }
    $script:copieFaite = $true
    $empreinteTemoin = Empreinte $Temoin
    Write-Host ("empreinte source : {0}" -f $script:empreinteSource)
    Write-Host ("empreinte temoin : {0}" -f $empreinteTemoin)
    if ($empreinteTemoin -ne $script:empreinteSource) {
        Write-Host 'ECHEC: la copie ne porte pas la meme empreinte que la source.'
        Write-Host '       Le temoin ne serait pas le binaire qu on croit eprouver.'
        return 1
    }

    # ------------------------------------------------- le temoin sort-il seul ?
    # Avant tout filtre. Un temoin muet certifie n importe quoi: sans cette
    # etape, une absence de connexion sous filtre ne discriminerait rien.
    $null = & $Binaire --telemetrie-reseau-retirer 2>&1
    $null = & $Temoin --connect-probe $Cible
    $codeTemoin = $LASTEXITCODE
    if ($codeTemoin -ne 5) {
        Write-Host ("SKIPPED  la cible {0} ne repond pas a la COPIE depuis cette machine (code {1})." -f $Cible, $codeTemoin)
        Write-Host '         Sans temoin qui sort en clair, une absence de connexion ne discrimine rien.'
        return 0
    }
    Write-Host 'temoin: la copie sort en clair sans aucun filtre, la mesure peut discriminer'

    # L audit des SUCCES est indispensable: sans lui, "n a rien tente" et "a ete
    # bloque" rendent la meme mesure, c est-a-dire aucune.
    Write-Host ''
    Write-Host 'politique d audit trouvee:'
    foreach ($l in @(& auditpol /get /subcategory:"$Sous" /r)) { if ("$l".Trim() -ne '') { Write-Host ("  {0}" -f $l) } }
    $null = & auditpol /set /subcategory:"$Sous" /success:enable /failure:enable
    $script:auditTouche = $true

    Write-Host ''
    Write-Host '== Trois passages alternes, en commencant PAR le cas filtre =='
    Write-Host '   (commencer sans filtre attribuerait au filtre toute derive de la machine)'

    $a = Passage 'A' $true
    if ($a.EchecCible) {
        Write-Host ''
        Write-Host ("  ECHEC    passage A: {0}" -f $a.Raison)
        return 1
    }
    $b = Passage 'B' $false
    $c = Passage 'C' $true

    Write-Host ''
    Write-Host '== Verdict =='
    if ($c.EchecCible) {
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
    if ($b.Sortie -ne 5 -and $b.Permis -eq 0) {
        Write-Host '  SKIPPED  le temoin n est pas sorti au passage SANS filtre, alors qu il etait'
        Write-Host ("           sorti avant la mesure (code {0} contre 5 attendu)." -f $b.Sortie)
        Write-Host '           La machine a change sous la mesure: elle ne discrimine plus.'
        return 0
    }
    if (($a.Notres + $c.Notres) -ge 1) {
        Write-Host ("  MESURE   {0} refus impute(s) a un filtre de la couche 2 sur les passages filtres." -f ($a.Notres + $c.Notres))
        Write-Host '           Un blocage ALE_APP_ID sur un chemin d image refuse donc bien la connexion'
        Write-Host '           du processus lance depuis ce chemin. Le mecanisme des cinq cibles de'
        Write-Host '           binaire du catalogue MORD.'
        # Un signal ABSENT n est pas un signal qui diverge, et les confondre
        # ferait lire une case vide comme une mesure. Les deux cas sont donc
        # separes, et celui qui manque est nomme comme manquant.
        if ($a.Sortie -eq -1 -or $c.Sortie -eq -1) {
            Write-Host ''
            Write-Host '           SIGNAL MANQUANT: le code de sortie du temoin n a pas pu etre lu sur'
            Write-Host ("           au moins un passage filtre (A={0}, C={1}, -1 = illisible)." -f $a.Sortie, $c.Sortie)
            Write-Host '           Ce banc croise DEUX signaux independants; ici un seul a parle, et'
            Write-Host '           c est le journal. Le verdict tient sur ce seul signal, pas sur deux.'
        } elseif ($a.Sortie -ne 3 -or $c.Sortie -ne 3) {
            Write-Host ''
            Write-Host '           RESERVE: le journal impute un refus, mais le code de sortie du temoin'
            Write-Host ("           ne dit pas BLOQUE sur les deux passages filtres (A={0}, C={1})." -f $a.Sortie, $c.Sortie)
            Write-Host '           Les deux signaux divergent: la rafale rend le plus PERMISSIF de ses'
            Write-Host '           essais, donc une seule sortie reussie suffit a effacer des milliers'
            Write-Host '           de refus. Ce n est pas une contradiction, c est une fuite a nommer.'
        }
        # Un filtre qui mord 600 fois et laisse passer une fois est une FUITE,
        # et la somme des refus la noierait. Elle se nomme, ici, a cote du
        # verdict qu elle nuance.
        if (($a.Permis + $c.Permis) -ge 1) {
            Write-Host ''
            Write-Host ("           FUITE: {0} connexion(s) AUTORISEE(S) sur les passages filtres" -f ($a.Permis + $c.Permis))
            Write-Host ("           (A={0}, C={1}) alors que la sonde etait posee et verifiee porteuse" -f $a.Permis, $c.Permis)
            Write-Host '           du chemin vise. Le mecanisme mord, et il laisse passer. Le nom du'
            Write-Host '           filtre gagnant de chaque autorisation est imprime plus haut.'
        }
        return 0
    }
    if (($a.Permis + $c.Permis) -ge 1) {
        Write-Host ("  ECHEC    {0} connexion(s) AUTORISEE(S) alors que la sonde etait posee, verifiee" -f ($a.Permis + $c.Permis))
        Write-Host '           presente, et verifiee porteuse du chemin vise.'
        Write-Host '           Le mecanisme ALE_APP_ID ne mord pas. Les cinq cibles de binaire du'
        Write-Host '           catalogue ne protegent alors rien, et le produit ne doit pas les'
        Write-Host '           annoncer. Le nom du filtre gagnant est imprime ci-dessus.'
        return 1
    }
    if ($a.Sortie -eq 3 -and $c.Sortie -eq 3) {
        Write-Host '  INDICE   le temoin se dit BLOQUE sur les deux passages filtres, mais aucun 5157'
        Write-Host '           n est impute a nos filtres: on ne sait pas QUI a bloque. Le comportement'
        Write-Host '           suit la sonde, ce qui est un indice, pas une preuve.'
        return 0
    }
    Write-Host '  SKIPPED  ni refus impute, ni connexion autorisee, ni blocage annonce par le temoin:'
    Write-Host ("           codes de sortie A={0} B={1} C={2}, evenements A={3}/{4} C={5}/{6}." -f `
        $a.Sortie, $b.Sortie, $c.Sortie, $a.Permis, $a.Refuses, $c.Permis, $c.Refuses)
    Write-Host '           La mesure n a rien attrape. Relancer, ou verifier que l audit est bien actif.'
    return 0
}

$code = 1
try {
    $code = Main
}
finally {
    # Le menage a lieu meme en sortant sur une erreur: des filtres laisses en
    # place, un audit des succes laisse actif et une copie du daemon oubliee ne
    # sont pas des effets de bord acceptables sur une machine d essai.
    Write-Host ''
    Write-Host '== menage =='
    $null = & $Binaire --telemetrie-reseau-retirer 2>&1
    # Relu par netsh, qui n est pas le binaire qui a pose: un poseur qui se
    # relit lui-meme confirme sa propre erreur.
    $cheminMenage = Dump-Wfp
    if ($cheminMenage -ne $null) {
        $luMenage = Lire-Filtres $cheminMenage
        Remove-Item $cheminMenage -Force -ErrorAction SilentlyContinue
        Write-Host ("  relecture netsh : {0} filtre(s) a nous dans le moteur" -f @($luMenage.Nos).Count)
    } else {
        Write-Host '  relecture netsh : netsh n a rien rendu, la presence des filtres n est PAS verifiee'
    }
    if ($script:copieFaite) {
        # L instrument, de l autre cote de la fenetre. Verifier avant de mesurer
        # ne suffit pas quand quelque chose peut encore ecrire apres.
        $apres = Empreinte $Temoin
        if ($apres -eq $script:empreinteSource) {
            Write-Host '  empreinte apres : inchangee, le temoin mesure est bien celui qui a ete copie'
        } else {
            Write-Host ("  empreinte apres : CHANGEE ({0}). Le temoin a ete reecrit pendant la mesure." -f $apres)
        }
        Remove-Item -LiteralPath $Temoin -Force -ErrorAction SilentlyContinue
        if (Test-Path $Temoin) {
            Write-Host ("  copie           : ECHEC du retrait, {0} est toujours la" -f $Temoin)
        } else {
            Write-Host ("  copie           : retiree ({0})" -f $Temoin)
        }
    } else {
        Write-Host '  copie           : aucune copie faite'
    }
    if ($script:auditTouche) {
        $null = & auditpol /set /subcategory:"$Sous" /success:disable /failure:enable
        Write-Host '  politique audit : remise a /success:disable /failure:enable'
        foreach ($l in @(& auditpol /get /subcategory:"$Sous" /r)) { if ("$l".Trim() -ne '') { Write-Host ("  {0}" -f $l) } }
    } else {
        Write-Host '  politique audit : non touchee'
    }
    Write-Host '  aucun service cree ni supprime par ce banc'
}
exit $code

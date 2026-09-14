# Un blocage par SID mord-il un service HEBERGE dans svchost ? Le banc qui le tranche.
#
# A lancer sur essai-windows, en administrateur, shell cmd, depuis la racine du
# banc (le repertoire qui contient les binaires) ou avec BIFROST_BANC pose:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\telemetrie-svchost-windows.ps1
#
# POURQUOI IL EXISTE. Le mecanisme ALE_USER_ID de la couche 2 MORD: un blocage
# portant le SID d un service refuse bien la connexion de ce service. Mesure
# trois fois, sur trois temoins differents: 569, 621 et 673 refus, l evenement
# 5157 nommant notre filtre a chaque fois.
#
# Et pourtant DEUX VRAIES cibles lui echappent, DiagTrack et DoSvc: filtre pose,
# verifie porteur du SID exact, processus continu et seul dans son svchost, et
# c est Default Outbound qui gagne en AUTORISANT.
#
# Tout ce qui pouvait expliquer l ecart est tombe: le compte, le groupe svchost,
# le type de demarrage, les attributs du SID dans le jeton, le jeton filtre, la
# protection de processus, la couche, l arbitrage entre sous-couches, et l
# usurpation durable.
#
# Il reste UNE difference structurelle, et une seule: les trois temoins bloques
# portent LEUR PROPRE BINAIRE, les deux cibles qui echappent sont HEBERGEES DANS
# svchost.exe. C est une HYPOTHESE. Personne ne l a mesuree, parce qu il n a
# jamais existe de temoin heberge dans svchost dont on maitrise le SID et l
# emission.
#
# Ce banc fabrique ce temoin et le mesure.
#
# CE QUE CE BANC NE PEUT PAS TRANCHER, ET IL FAUT LE LIRE AVANT LE RESULTAT.
# DiagTrack et DoSvc tournent en "svchost.exe -k <groupe> -p". Ce drapeau -p
# active une politique d attenuation qui n accepte que des images signees par
# Microsoft. La DLL du temoin ne l est pas: le temoin tourne donc SANS -p, et
# aucun reglage ne peut changer cela. Ce banc mesure exactement ceci: un service
# qui porte son propre SID, heberge dans svchost.exe SANS -p, est-il refuse par
# un blocage ALE_USER_ID sur son SID ? La question du -p se mesure ailleurs, sur
# un VRAI service Windows heberge dans svchost. Le temoin ne se contente pas de
# le dire: il releve la ligne de commande de son propre processus et l ecrit
# dans son journal, -p compris ou absent.
#
# COMMENT LIRE LES DEUX VERDICTS QUI COMPTENT, parce qu ils sont contre-intuitifs
#
#   MESURE  le blocage MORD sur un temoin heberge dans svchost. L hypothese
#           tombe: etre heberge dans svchost n explique pas l echappement de
#           DiagTrack et DoSvc, et il faut chercher ailleurs.
#   ECHEC   le temoin ECHAPPE comme DiagTrack et DoSvc, avec la meme signature.
#           Ce n est pas un echec du banc: c est un echec du BLOCAGE, et c est
#           le resultat qui CORROBORE l hypothese. Le banc sort non nul pour
#           qu on le lise, pas pour dire qu il s est mal passe.
#   INDICE  le temoin se dit bloque mais aucun 5157 ne l impute a nos filtres.
#   SKIPPED la mesure ne discrimine pas, et la raison est toujours nommee.
#
# LES LECONS DEJA PAYEES, ET QUE CE BANC GARDE
#
# 1. LE PIEGE SERVICE_SID_TYPE. Un service en NONE ne porte AUCUN SID de service
#    dans son jeton: le filtre se poserait sans jamais mordre, sans erreur et
#    sans trace, et le banc rendrait un ECHEC qui ne mesurerait que sa propre
#    mauvaise configuration. Le banc pose "sc sidtype unrestricted" PUIS le
#    verifie par sc qsidtype et sc showsid, et ABANDONNE si l un des deux ne
#    repond pas.
# 2. VERIFIER QUE LE FILTRE POSE PORTE LA CIBLE avant de mesurer quoi que ce
#    soit. Le controle n est pas reimplemente ici: il est DELEGUE a
#    telemetrie-conditions-windows.ps1, dont le code de sortie vaut 0 quand au
#    moins un filtre pose porte exactement le SID vise.
# 3. L AUDIT DES SUCCES doit etre actif. Sans lui, "bloque" et "n a jamais
#    essaye" rendent la meme mesure, c est-a-dire aucune.
# 4. UN TEMOIN MUET CERTIFIE N IMPORTE QUOI. Le passage sans filtre doit voir le
#    temoin SORTIR pour de bon, sans quoi le verdict est SKIPPED.
# 5. PASSAGES ALTERNES, en commencant PAR le cas filtre. Commencer sans filtre
#    attribuerait au filtre tout epuisement ou toute derive de la machine.
# 6. LE DUMP netsh EST DU XML ou <item> sert AUSSI aux drapeaux et aux
#    conditions. On le charge en DOM et on selectionne par //item[filterKey].
# 7. L INSTRUMENT SE VERIFIE DES DEUX COTES DE LA FENETRE: l empreinte de la
#    copie de la DLL est comparee a la source avant ET apres la mesure.
# 8. LE MENAGE SE VERIFIE INDEPENDAMMENT DE CE QUI A POSE, et il ne defait que
#    ce qui a REELLEMENT ete fait. Un menage qui rejoue le binaire alors que le
#    banc a refuse d agir a deja lance le Bloc-notes sur cette machine.
# 9. LE PID SE PREND PAR CIM, jamais en analysant sc queryex: un Select-String
#    sur une chaine multiligne a deja produit un PID de vingt chiffres.
#
# CE QUE CE BANC AJOUTE, ET QUE LES DEUX AUTRES N AVAIENT PAS
#
# - Il verifie que le processus qui heberge le temoin est bien un svchost.exe,
#   et non autre chose. Si le temoin tournait dans son propre binaire, tout le
#   banc mesurerait la question qu il pretend eviter.
# - Il releve QUI PARTAGE ce svchost. Un svchost partage rend l attribution par
#   PID sans valeur, et la mesure est declaree invalide.
# - Il ne touche JAMAIS une valeur existante sous la cle Svchost. La liste des
#   valeurs y est relevee AVANT et comparee APRES: si elle a bouge autrement que
#   par le retrait de la notre, le banc le dit.
# - Il croise DEUX signaux independants, comme le banc par chemin de binaire: le
#   VERDICT que le temoin ecrit dans son propre journal, qui ne depend d aucun
#   journal de securite, et les evenements 5156 et 5157, seuls a nommer le
#   filtre gagnant. Quand ils divergent, le banc le dit et ne conclut pas.
#
# CE QU IL FAUT AVOIR DEPOSE SUR LA MACHINE D ESSAI
#   bifrost-daemon.exe                     construit sur dev-windows
#   bifrost_temoin_svchost.dll             construit sur dev-windows
#   telemetrie-conditions-windows.ps1      l instrument de controle du SID

param(
    # La racine du banc: le repertoire du script (via -File), ou BIFROST_BANC si pose.
    [string]$Banc = $(if ($env:BIFROST_BANC) { $env:BIFROST_BANC } else { $PSScriptRoot }),
    # Le daemon qui POSE les filtres. Il n est jamais la cible du blocage.
    [string]$Binaire = (Join-Path $Banc 'bifrost-daemon.exe'),
    # La DLL de service, telle qu elle a ete deposee. Jamais chargee telle
    # quelle: le banc en fait une copie jetable.
    [string]$Dll = (Join-Path $Banc 'bifrost_temoin_svchost.dll'),
    # La copie jetable, celle que le registre designe et que le menage supprime.
    [string]$DllPosee = (Join-Path $Banc 'bifrost-temoin-svchost-pose.dll'),
    # Le nom du service. Il DOIT commencer par bifrost: c est ce qui empeche une
    # faute de frappe d arreter puis de supprimer un service du systeme.
    [string]$Service = 'bifrost-temoin-svchost',
    # Le groupe svchost. Meme regle, meme raison.
    [string]$Groupe = 'bifrosttemoin',
    # Le type passe a sc create. 'share' vaut SERVICE_WIN32_SHARE_PROCESS
    # (0x20), 'own' vaut SERVICE_WIN32_OWN_PROCESS (0x10). Les DEUX sont
    # hebergeables: DiagTrack tourne en 0x10 et DoSvc en 0x20, toutes deux
    # dans svchost. Parametre pour qu on puisse rapprocher le temoin de l une
    # ou de l autre sans toucher au banc.
    [ValidateSet('share', 'own')]
    [string]$TypeService = 'share',
    [string]$Cible = '1.1.1.1:443',
    [int]$Rafale = 8000,
    [string]$Journal = (Join-Path $Banc 'bifrost-temoin-svchost.log'),
    # L instrument de controle du SID. Delegue, pas reimplemente.
    [string]$Conditions = (Join-Path $Banc 'telemetrie-conditions-windows.ps1'),
    # Prefixe des cles de filtre de la couche 2. Ecrit ici A LA MAIN: si le banc
    # le lisait du binaire, les deux se tromperaient ensemble.
    [string]$PrefixeCle = '{3ac9d182-5e42-4b77-9d61-8e05f3a2',
    # Secondes d attente maximale pour que le temoin finisse sa rafale.
    [int]$Attente = 60
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
$CleSvchost = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost'
$CibleIp = ($Cible -split ':')[0]

# Le menage ne defait que ce qui a REELLEMENT ete fait.
$script:auditTouche   = $false
$script:copieFaite    = $false
$script:serviceCree   = $false
$script:groupePose    = $false
$script:posePassee    = $false
$script:empreinteDll  = ''
$script:valeursAvant  = @()

# --------------------------------------------------------------- lecture WFP

# Rend le chemin d un dump FRAIS, ou $null. L appelant le supprime.
function Dump-Wfp {
    $f = Join-Path $env:SystemRoot 'Temp\bifrost-svchost.xml'
    if (Test-Path $f) { Remove-Item $f -Force -ErrorAction SilentlyContinue }
    $null = & netsh wfp show filters file="$f" 2>&1
    if (-not (Test-Path $f)) { return $null }
    return $f
}

# Deux tables: filterId -> nom pour TOUS les filtres, ce qui sert a nommer le
# gagnant quel qu il soit - y compris quand il ne nous appartient pas, ce qui
# est precisement le cas interessant - et filterId -> nom pour les seuls
# filtres de la couche 2.
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

# ------------------------------------------------------------- lecture SCM

# Le SID que le SCM derive du nom. Le SID est insensible a la locale, seule
# l etiquette autour ne l est pas: on ne garde que le SID.
function Sid-De-Service($nom) {
    foreach ($l in @(& sc.exe showsid $nom 2>&1)) {
        $m = [regex]::Match("$l", 'S-1-5-80(-\d+)+')
        if ($m.Success) { return $m.Value }
    }
    return ''
}

# Le PID se prend par CIM, jamais en analysant sc queryex.
#
# DEUX champs pour l image, et ce n est pas de la redondance. Mesure du
# 23/08/2026 sur dev-windows, session NON elevee: `Win32_Process.Name` rend
# 'svchost.exe' tandis que `ExecutablePath` et `CommandLine` rendent une chaine
# VIDE, sans erreur. Get-Process rend un `.Path` vide de la meme facon. Une
# lecture qui ne garderait que le chemin complet conclurait donc "ce n est pas
# svchost" alors qu elle n a simplement pas eu le droit de lire. Le banc exige
# une session elevee, mais trois etats - c est svchost, ce n est pas svchost,
# je n ai pas pu lire - doivent rester distincts.
function Contexte-Processus($nom) {
    $c = New-Object psobject
    $c | Add-Member NoteProperty Idproc       0
    $c | Add-Member NoteProperty Creation     ''
    $c | Add-Member NoteProperty Etat         '(absent)'
    $c | Add-Member NoteProperty Nom          ''
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
        $c.Nom = [string]$pr.Name
        $c.Image = [string]$pr.ExecutablePath
        $c.Ligne = [string]$pr.CommandLine
    }
    $c.Colocataires = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { [int]$_.ProcessId -eq [int]$c.Idproc } | ForEach-Object { [string]$_.Name })
    return $c
}

# --------------------------------------------------- controle du SID, DELEGUE
#
# On ne reimplemente pas la confrontation du SID: on appelle l instrument du
# depot et on lit son code de sortie. 0 = au moins un filtre pose porte
# exactement le SID de la cible. 1 = aucun, y compris quand rien n est pose.
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

# ------------------------------------------------------- lecture des journaux

function Detail($e) {
    $x = [xml]$e.ToXml(); $d = @{}
    foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
    return $d
}

# Le temoin est discrimine par DEUX choses a la fois, et il le faut.
#
# Le champ Application porte le chemin de l image, qui vaut ici svchost.exe:
# partage par des dizaines de services, il ne discrimine RIEN. Restent le PID,
# qu on connait parce qu on a demarre le service et releve son hote, et la
# DESTINATION, qui n appartient qu a notre temoin.
function Evenements($marque, $fin, $id, $idproc) {
    $out = @()
    $table = @{LogName='Security'; Id=$id; StartTime=$marque}
    if ($fin -ne $null) { $table['EndTime'] = $fin }
    foreach ($e in @(Get-WinEvent -FilterHashtable $table -ErrorAction SilentlyContinue)) {
        $d = Detail $e
        if ("$($d['ProcessID'])" -ne "$idproc") { continue }
        if ("$($d['DestAddress'])" -ne "$CibleIp") { continue }
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

# Ce que le Service Control Manager a dit du demarrage. Lu seulement quand le
# demarrage echoue: c est la, et nulle part ailleurs, que svchost explique
# pourquoi il n a pas charge la DLL.
function Dire-Scm($marque) {
    $vus = 0
    foreach ($e in @(Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$marque} -ErrorAction SilentlyContinue)) {
        $m = "$($e.Message)"
        if ($m -notlike "*$Service*" -and "$($e.ProviderName)" -notlike '*Service Control Manager*') { continue }
        $vus = $vus + 1
        Write-Host ("      journal System : id={0} source={1}" -f $e.Id, $e.ProviderName)
        foreach ($l in @($m -split "`n")) {
            if ("$l".Trim() -ne '') { Write-Host ("         {0}" -f "$l".Trim()) }
        }
        if ($vus -ge 6) { break }
    }
    if ($vus -eq 0) { Write-Host '      journal System : aucun evenement depuis la marque' }
}

# ---------------------------------------------------------------- l empreinte

function Empreinte($chemin) {
    if (-not (Test-Path $chemin)) { return '' }
    return (Get-FileHash -LiteralPath $chemin -Algorithm SHA256).Hash.ToLower()
}

# ------------------------------------------------------- le journal du temoin

# Ce que le temoin a ecrit sur lui-meme. C est le signal qui ne depend d aucun
# journal de securite.
function Lire-Journal {
    $r = New-Object psobject
    $r | Add-Member NoteProperty Present $false
    $r | Add-Member NoteProperty Idproc  0
    $r | Add-Member NoteProperty Image   ''
    $r | Add-Member NoteProperty Ligne   ''
    $r | Add-Member NoteProperty AvecP   ''
    $r | Add-Member NoteProperty Verdict ''
    $r | Add-Member NoteProperty Lignes  @()
    if (-not (Test-Path $Journal)) { return $r }
    $r.Present = $true
    $r.Lignes = @(Get-Content -LiteralPath $Journal -ErrorAction SilentlyContinue)
    foreach ($l in $r.Lignes) {
        $t = "$l"
        if ($t -like 'pid *:*')        { $r.Idproc  = [int](($t -split ':', 2)[1]).Trim() }
        if ($t -like 'image *:*')      { $r.Image   = (($t -split ':', 2)[1]).Trim() }
        if ($t -like 'ligne *:*')      { $r.Ligne   = (($t -split ':', 2)[1]).Trim() }
        if ($t -like 'drapeau -p *:*') { $r.AvecP   = (($t -split ':', 2)[1]).Trim() }
        if ($t -like 'verdict *:*')    { $r.Verdict = (($t -split ':', 2)[1]).Trim() }
    }
    return $r
}

function Effacer-Journal {
    Remove-Item -LiteralPath $Journal -Force -ErrorAction SilentlyContinue
    $repli = Join-Path $env:SystemRoot 'Temp\bifrost-temoin-svchost.log'
    Remove-Item -LiteralPath $repli -Force -ErrorAction SilentlyContinue
}

# ------------------------------------------------------------------ un passage

function Passage($etiquette, $filtre, $sid) {
    $res = New-Object psobject
    $res | Add-Member NoteProperty Permis   0
    $res | Add-Member NoteProperty Refuses  0
    $res | Add-Member NoteProperty Notres   0
    $res | Add-Member NoteProperty Abandon  $false
    $res | Add-Member NoteProperty Invalide $false
    $res | Add-Member NoteProperty Raison   ''
    $res | Add-Member NoteProperty Verdict  ''
    $res | Add-Member NoteProperty Seul     $false
    $res | Add-Member NoteProperty DansSvchost $false

    Write-Host ''
    if ($filtre) { Write-Host ("-- passage {0} : SONDE POSEE --" -f $etiquette) }
    else         { Write-Host ("-- passage {0} : sans filtre --" -f $etiquette) }

    if ($filtre) {
        $script:posePassee = $true
        $sortiePose = & $Binaire --telemetrie-sonde-sid $sid 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host '   ABANDON: la sonde n a rien pose'
            foreach ($l in @($sortiePose)) { Write-Host ("      {0}" -f $l) }
            $res.Abandon = $true
            $res.Raison = 'la sonde n a pose aucun filtre'
            return $res
        }
        foreach ($l in @($sortiePose)) { Write-Host ("   pose : {0}" -f $l) }
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
        if (@($lu.Nos.Keys).Count -eq 0) {
            Write-Host '   ABANDON: aucun filtre de la couche 2 dans le moteur apres la pose'
            $res.Abandon = $true
            $res.Raison = 'aucun filtre a nous dans le moteur apres la pose'
            return $res
        }
        $ctl = Controle-Conditions $Service
        foreach ($l in @($ctl.Lignes)) { Write-Host ("   controle SID  : {0}" -f "$l".Trim()) }
        if (-not $ctl.Ok) {
            Write-Host ("   ABANDON: aucun filtre pose ne porte le SID de {0} ({1})." -f $Service, $ctl.Raison)
            Write-Host ("            SID attendu : {0}" -f $sid)
            Write-Host '            Un banc qui eprouve un blocage sans verifier que le blocage vise'
            Write-Host '            sa cible ne mesure rien. Mesure refusee, temoin non demarre.'
            $res.Abandon = $true
            $res.Raison = "aucun filtre pose ne porte le SID de $Service"
            return $res
        }
    } else {
        # Le passage SANS filtre doit etre vraiment sans filtre. Le compte vient
        # du dump netsh, pas du code de retour du binaire qui a demande le
        # retrait: un poseur qui se relit lui-meme confirme sa propre erreur.
        if (@($lu.Nos.Keys).Count -ne 0) {
            Write-Host ("   MESURE INVALIDEE: {0} filtre(s) de la couche 2 sont encore dans le moteur" -f @($lu.Nos.Keys).Count)
            Write-Host '                     alors que ce passage doit etre sans filtre.'
            $res.Invalide = $true
            $res.Raison = "$(@($lu.Nos.Keys).Count) filtre(s) restants au passage sans filtre"
            return $res
        }
    }

    # -------------------------------------------------- le temoin, a la demande
    #
    # Le journal est efface AVANT: un releve survivant d un passage precedent se
    # lirait comme celui du passage courant.
    Effacer-Journal
    $marque = (Get-Date).AddSeconds(-1)
    $sortieStart = @(& sc.exe start $Service 2>&1)
    $codeStart = $LASTEXITCODE
    if ($codeStart -ne 0) {
        Write-Host ("   SKIPPED: sc start {0} a rendu le code {1}." -f $Service, $codeStart)
        foreach ($l in @($sortieStart)) { if ("$l".Trim() -ne '') { Write-Host ("      {0}" -f "$l".Trim()) } }
        Write-Host '            svchost n a pas charge la DLL, ou le service n a pas pu demarrer.'
        Write-Host '            Ce que le journal System en dit:'
        Dire-Scm $marque
        $res.Invalide = $true
        $res.Raison = "sc start a rendu le code $codeStart"
        return $res
    }

    # ------------------- CONTROLE 2: QUI heberge le temoin, et avec QUI
    $ctx = $null
    for ($i = 0; $i -lt 40; $i = $i + 1) {
        $ctx = Contexte-Processus $Service
        if ($ctx.Idproc -gt 0) { break }
        Start-Sleep -Milliseconds 250
    }
    if ($ctx -eq $null -or $ctx.Idproc -le 0) {
        Write-Host ("   MESURE INVALIDEE: {0} n a pas de PID apres sc start (etat {1})" -f $Service, $ctx.Etat)
        $res.Invalide = $true
        $res.Raison = 'pas de PID apres le demarrage'
        return $res
    }
    Write-Host ("   PID hote      : {0}  cree le {1}  etat {2}" -f $ctx.Idproc, $ctx.Creation, $ctx.Etat)
    Write-Host ("   nom image     : {0}" -f $ctx.Nom)
    Write-Host ("   chemin image  : {0}" -f $ctx.Image)
    Write-Host ("   ligne         : {0}" -f $ctx.Ligne)
    Write-Host ("   colocataires  : {0} service(s) sur ce PID : {1}" -f @($ctx.Colocataires).Count, (@($ctx.Colocataires) -join ', '))

    # Trois etats, jamais deux. Un champ vide n est pas un "ce n est pas
    # svchost": c est un "je n ai pas pu lire", et les confondre invaliderait
    # une mesure juste ou en certifierait une fausse.
    $nomLu = "$($ctx.Nom)".ToLower()
    $cheminLu = "$($ctx.Image)".ToLower()
    if ($nomLu -eq '' -and $cheminLu -eq '') {
        Write-Host '   MESURE INVALIDEE: l image du processus hote est ILLISIBLE (les deux champs'
        Write-Host '                     sont vides). Ce n est pas la meme chose que "ce n est pas'
        Write-Host '                     svchost": sans elle, on ne peut pas etablir l hebergement.'
        $res.Invalide = $true
        $res.Raison = 'image du processus hote illisible'
        return $res
    }
    $res.DansSvchost = ($nomLu -eq 'svchost.exe' -or $cheminLu.EndsWith('svchost.exe'))
    $res.Seul = (@($ctx.Colocataires).Count -eq 1)
    if (-not $res.DansSvchost) {
        Write-Host '   MESURE INVALIDEE: le temoin n est PAS heberge dans svchost.exe.'
        Write-Host '                     Tout ce banc mesure la difference entre un service qui porte'
        Write-Host '                     son propre binaire et un service heberge. Sans hebergement,'
        Write-Host '                     il ne mesure rien de neuf.'
        $res.Invalide = $true
        $res.Raison = "image hote inattendue: nom='$($ctx.Nom)' chemin='$($ctx.Image)'"
        return $res
    }
    if (-not $res.Seul) {
        Write-Host '   MESURE INVALIDEE: le temoin partage son svchost avec d autres services.'
        Write-Host '                     Un evenement portant ce PID ne lui serait pas attribuable.'
        $res.Invalide = $true
        $res.Raison = "svchost partage: " + ((@($ctx.Colocataires) -join ', '))
        return $res
    }

    # ------------------------------------ la fenetre, jusqu a l arret du temoin
    $depart = Get-Date
    $arrete = $false
    while (((Get-Date) - $depart).TotalSeconds -lt $Attente) {
        Start-Sleep -Milliseconds 500
        $maintenant = Contexte-Processus $Service
        if ($maintenant.Idproc -le 0) { $arrete = $true; break }
        if ($maintenant.Idproc -ne $ctx.Idproc) {
            Write-Host '   MESURE INVALIDEE: un AUTRE processus porte desormais le service.'
            Write-Host ("                     au depart : PID {0} cree le {1}" -f $ctx.Idproc, $ctx.Creation)
            Write-Host ("                     ensuite   : PID {0} cree le {1}" -f $maintenant.Idproc, $maintenant.Creation)
            $res.Invalide = $true
            $res.Raison = "processus remplace: PID $($ctx.Idproc) puis PID $($maintenant.Idproc)"
            return $res
        }
    }
    $finFenetre = Get-Date
    if (-not $arrete) {
        Write-Host ("   temoin        : toujours en vie apres {0}s, on l arrete" -f $Attente)
        $null = & sc.exe stop $Service 2>&1
        Start-Sleep -Seconds 3
        $finFenetre = Get-Date
    } else {
        Write-Host ("   temoin        : arrete seul apres {0:N1}s" -f ($finFenetre - $depart).TotalSeconds)
    }

    # ------------------------------------ SIGNAL 1: ce que le temoin a ecrit
    $jr = Lire-Journal
    if (-not $jr.Present) {
        Write-Host ("   MESURE INVALIDEE: aucun journal du temoin en {0}" -f $Journal)
        Write-Host '                     Sans son releve, le premier des deux signaux manque et'
        Write-Host '                     rien n atteste que la DLL a seulement ete chargee.'
        $res.Invalide = $true
        $res.Raison = 'journal du temoin absent'
        return $res
    }
    Write-Host '   ce que le temoin a ecrit sur lui-meme:'
    foreach ($l in @($jr.Lignes)) { if ("$l".Trim() -ne '') { Write-Host ("      {0}" -f "$l") } }
    if ("$($jr.Idproc)" -ne "$($ctx.Idproc)") {
        Write-Host ("   MESURE INVALIDEE: le temoin dit tourner dans le PID {0}, le SCM dit {1}." -f $jr.Idproc, $ctx.Idproc)
        Write-Host '                     Les evenements ont ete attribues par PID: les deux sources'
        Write-Host '                     doivent nommer le meme processus.'
        $res.Invalide = $true
        $res.Raison = "PID discordant: journal $($jr.Idproc), SCM $($ctx.Idproc)"
        return $res
    }
    $res.Verdict = $jr.Verdict
    if ("$($jr.Verdict)" -eq '') {
        Write-Host '   NOTE          le journal ne porte aucun verdict: le temoin n a pas fini sa rafale.'
    }

    # Les evenements mettent un instant a etre ecrits dans le journal.
    Start-Sleep -Seconds 5

    # --------------------------------- SIGNAL 2: qui a gagne, d apres le systeme
    $permis = @(Evenements $marque $finFenetre 5156 $ctx.Idproc)
    $refuses = @(Evenements $marque $finFenetre 5157 $ctx.Idproc)

    $chemin2 = Dump-Wfp
    $lu2 = Lire-Filtres $chemin2
    if ($chemin2 -ne $null) { Remove-Item $chemin2 -Force -ErrorAction SilentlyContinue }
    $res.Permis = @($permis).Count
    $res.Refuses = @($refuses).Count
    $res.Notres = @(@($refuses) | Where-Object { $lu2.Nos.ContainsKey("$($_['FilterRTID'])") }).Count
    Write-Host ("   RESULTAT      autorisees={0}  refusees={1}  dont par nos filtres={2}" -f `
        $res.Permis, $res.Refuses, $res.Notres)
    if (($res.Permis + $res.Refuses) -eq 0) {
        Write-Host ("   NOTE          aucun evenement ne porte a la fois le PID {0} et la destination" -f $ctx.Idproc)
        Write-Host ("                 {0}. Rien ne NOMME de filtre gagnant sur ce passage." -f $CibleIp)
    }
    Nommer-Gagnants 'AUTORISEE' $permis $lu2.Nos $lu2.Tous 3
    Nommer-Gagnants 'REFUSEE  ' $refuses $lu2.Nos $lu2.Tous 3
    return $res
}

# ------------------------------------------------------------------- le corps

function Main {
    Write-Host ('=' * 78)
    Write-Host 'Banc du temoin HEBERGE DANS SVCHOST, mecanisme ALE_USER_ID'
    Write-Host ("hote          : {0}" -f $env:COMPUTERNAME)
    Write-Host ("windows       : {0}" -f (Get-CimInstance Win32_OperatingSystem).Version)
    Write-Host ("powershell    : {0}" -f $PSVersionTable.PSVersion)
    $ident = [Security.Principal.WindowsIdentity]::GetCurrent()
    $princ = New-Object Security.Principal.WindowsPrincipal($ident)
    $admin = $princ.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Host ("session admin : {0}" -f $admin)
    Write-Host ("binaire       : {0}" -f $Binaire)
    Write-Host ("dll source    : {0}" -f $Dll)
    Write-Host ("dll posee     : {0}" -f $DllPosee)
    Write-Host ("service       : {0}" -f $Service)
    Write-Host ("groupe        : {0}" -f $Groupe)
    Write-Host ("type service  : {0}" -f $TypeService)
    Write-Host ("cible         : {0}" -f $Cible)
    Write-Host ('=' * 78)
    # ---------------------------------------------------------- les refus
    #
    # Le nom du service et celui du groupe DOIVENT commencer par bifrost. Ce
    # banc arrete, supprime et desenregistre ce qu on lui nomme: une faute de
    # frappe viserait un service du systeme.
    if (-not $Service.ToLower().StartsWith('bifrost')) {
        Write-Host ("REFUS: le nom du service ({0}) ne commence pas par bifrost." -f $Service)
        Write-Host '       Ce banc cree, arrete et SUPPRIME le service qu on lui nomme.'
        return 1
    }
    if (-not $Groupe.ToLower().StartsWith('bifrost')) {
        Write-Host ("REFUS: le nom du groupe ({0}) ne commence pas par bifrost." -f $Groupe)
        Write-Host '       Ce banc ajoute puis retire une valeur portant ce nom sous la cle Svchost.'
        return 1
    }
    if ((("$Dll").ToLower()) -eq (("$DllPosee").ToLower())) {
        Write-Host 'REFUS: la DLL source et la copie designent le meme fichier.'
        Write-Host '       Le menage supprimerait la DLL deposee.'
        return 1
    }
    foreach ($f in @($Binaire, $Dll, $Conditions)) {
        if (-not (Test-Path $f)) {
            Write-Host ("ECHEC: introuvable: {0}" -f $f)
            return 1
        }
    }

    # ------------------------------- la cle Svchost, relevee AVANT d y toucher
    $cle = Get-Item -Path $CleSvchost -ErrorAction SilentlyContinue
    if ($cle -eq $null) {
        Write-Host ("ECHEC: cle introuvable: {0}" -f $CleSvchost)
        return 1
    }
    $script:valeursAvant = @($cle.GetValueNames() | Sort-Object)
    Write-Host ("cle Svchost   : {0} valeur(s) relevee(s) avant toute ecriture" -f @($script:valeursAvant).Count)
    if (@($script:valeursAvant) -contains $Groupe) {
        Write-Host ("REFUS: une valeur nommee {0} existe DEJA sous la cle Svchost." -f $Groupe)
        Write-Host '       Ce banc n ecrase jamais une valeur existante: celle-la appartient a'
        Write-Host '       quelqu un d autre, et la retirer au menage casserait son groupe.'
        return 1
    }

    # La porte administrateur vient APRES les refus: refuser un nom de service
    # ou un chemin ne demande aucun privilege, et un banc qui laisserait passer
    # une faute de frappe dans un shell ordinaire pour ne la refuser que dans un
    # shell eleve serait un banc dont la garde depend de qui l appelle.
    if (-not $admin) {
        Write-Host 'SKIPPED  ce banc cree un service et pose des filtres WFP: il exige une session administrateur.'
        return 0
    }

    # -------------------------------------- un reliquat d un passage precedent
    $ancien = @(& sc.exe qc $Service 2>&1)
    if ($LASTEXITCODE -eq 0) {
        $ligneAncienne = (@($ancien) -join ' ').ToLower()
        if ($ligneAncienne.Contains("-k $($Groupe.ToLower())")) {
            Write-Host ("reliquat      : le service {0} existe deja et porte notre groupe, on le supprime" -f $Service)
            $null = & sc.exe stop $Service 2>&1
            Start-Sleep -Seconds 2
            $null = & sc.exe delete $Service 2>&1
            Start-Sleep -Seconds 2
        } else {
            Write-Host ("REFUS: un service nomme {0} existe deja et n est PAS le notre." -f $Service)
            foreach ($l in @($ancien)) { if ("$l".Trim() -ne '') { Write-Host ("       {0}" -f "$l".Trim()) } }
            return 1
        }
    }

    # ------------------------------------------- le temoin sort-il seul ?
    # Avant tout filtre. Un temoin muet certifie n importe quoi.
    $null = & $Binaire --telemetrie-reseau-retirer 2>&1
    $null = & $Binaire --connect-probe $Cible
    $codeTemoin = $LASTEXITCODE
    if ($codeTemoin -ne 5) {
        Write-Host ("SKIPPED  la cible {0} ne repond pas depuis cette machine (code {1})." -f $Cible, $codeTemoin)
        Write-Host '         Sans temoin qui sort en clair, une absence de connexion ne discrimine rien.'
        return 0
    }
    Write-Host 'temoin        : la cible repond depuis cette machine, la mesure peut discriminer'

    # ------------------------------------------------ l instrument, avant mesure
    $script:empreinteDll = Empreinte $Dll
    Copy-Item -LiteralPath $Dll -Destination $DllPosee -Force
    if (-not (Test-Path $DllPosee)) {
        Write-Host ("ECHEC: la copie vers {0} n a pas eu lieu" -f $DllPosee)
        return 1
    }
    $script:copieFaite = $true
    $empreinteCopie = Empreinte $DllPosee
    Write-Host ("empreinte dll : {0}" -f $script:empreinteDll)
    Write-Host ("empreinte cop : {0}" -f $empreinteCopie)
    if ($empreinteCopie -ne $script:empreinteDll) {
        Write-Host 'ECHEC: la copie ne porte pas la meme empreinte que la source.'
        return 1
    }

    # ------------------------------------------------------ creation du service
    #
    # type= share vaut SERVICE_WIN32_SHARE_PROCESS (0x20), le seul type qu un
    # service heberge dans svchost puisse porter. Le chemin d image est celui de
    # svchost, pas le notre: c est tout l objet de ce banc.
    Write-Host ''
    Write-Host '== installation du temoin =='
    $chemin = '%SystemRoot%\System32\svchost.exe -k ' + $Groupe
    $null = & sc.exe create $Service binPath= "$chemin" type= $TypeService start= demand 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host ("ECHEC: sc create a rendu le code {0}" -f $LASTEXITCODE)
        return 1
    }
    $script:serviceCree = $true
    Write-Host ("service cree  : {0}" -f $Service)

    $cleSvc = "HKLM:\SYSTEM\CurrentControlSet\Services\$Service"
    $null = New-Item -Path "$cleSvc\Parameters" -Force
    # REG_EXPAND_SZ pour ServiceDll: c est le type que svchost attend, et un
    # REG_SZ y a deja fait echouer des chargements sans le dire.
    $null = New-ItemProperty -Path "$cleSvc\Parameters" -Name 'ServiceDll' -Value $DllPosee -PropertyType ExpandString -Force
    $null = New-ItemProperty -Path "$cleSvc\Parameters" -Name 'ServiceDllUnloadOnStop' -Value 1 -PropertyType DWord -Force
    # Le nom de l export. C est le defaut de svchost, ecrit explicitement pour
    # que la mesure ne depende pas d un defaut.
    $null = New-ItemProperty -Path "$cleSvc\Parameters" -Name 'ServiceMain' -Value 'ServiceMain' -PropertyType String -Force
    # La configuration du temoin. La cible est OBLIGATOIRE cote DLL: sans elle
    # le temoin refuse de mesurer plutot que de se donner une destination.
    $null = New-ItemProperty -Path "$cleSvc\Parameters" -Name 'Cible' -Value $Cible -PropertyType String -Force
    $null = New-ItemProperty -Path "$cleSvc\Parameters" -Name 'RafaleMs' -Value $Rafale -PropertyType DWord -Force
    $null = New-ItemProperty -Path "$cleSvc\Parameters" -Name 'Journal' -Value $Journal -PropertyType String -Force
    Write-Host ("Parameters    : ServiceDll={0}" -f $DllPosee)

    # AJOUTER une valeur, jamais en modifier une. Sans -Force: si la valeur
    # apparaissait entre le releve et maintenant, l ecriture echoue au lieu
    # d ecraser.
    $null = New-ItemProperty -Path $CleSvchost -Name $Groupe -Value @($Service) -PropertyType MultiString -ErrorAction SilentlyContinue
    $relu = Get-ItemProperty -Path $CleSvchost -Name $Groupe -ErrorAction SilentlyContinue
    if ($relu -eq $null) {
        Write-Host ("ECHEC: la valeur de groupe {0} n a pas pu etre ajoutee sous la cle Svchost." -f $Groupe)
        return 1
    }
    $script:groupePose = $true
    Write-Host ("groupe pose   : {0} = {1}" -f $Groupe, ((@($relu.$Groupe)) -join ', '))

    # ------------------------------------------ le SID, et le piege qui l annule
    $null = & sc.exe sidtype $Service unrestricted 2>&1
    $lignesType = @(& sc.exe qsidtype $Service 2>&1)
    $typeSid = ''
    foreach ($l in $lignesType) {
        if ("$l" -match 'SERVICE_SID_TYPE') { $typeSid = (("$l" -split ':', 2)[1]).Trim() }
    }
    $sid = Sid-De-Service $Service
    Write-Host ("sc qsidtype   : {0}" -f $typeSid)
    Write-Host ("sc showsid    : {0}" -f $sid)
    if ("$typeSid".ToUpper() -notlike '*UNRESTRICTED*') {
        Write-Host 'ECHEC: le service n est pas en SERVICE_SID_TYPE UNRESTRICTED.'
        Write-Host '       Un service en NONE ne porte AUCUN SID de service dans son jeton: le'
        Write-Host '       filtre se poserait sans jamais mordre, sans erreur et sans trace, et'
        Write-Host '       ce banc rendrait un ECHEC qui ne mesurerait que sa mauvaise config.'
        return 1
    }
    if ("$sid" -eq '') {
        Write-Host 'ECHEC: sc showsid n a rendu aucun SID S-1-5-80. Il n y a rien a bloquer.'
        return 1
    }

    # La configuration relue par le SCM, et non par ce qui l a creee.
    #
    # CE QUI EST EXIGE, ET CE QUI EST SEULEMENT RAPPORTE. Ce qu on exige est le
    # CHEMIN D IMAGE: svchost.exe, et notre groupe derriere -k. C est cela qui
    # fait l hebergement, rien d autre.
    #
    # Le TYPE, lui, est rapporte et ne fait echouer personne. Releve du
    # 23/08/2026 sur dev-windows: les deux cibles qui echappent ne portent meme
    # pas le meme type. DiagTrack est 0x10 WIN32_OWN_PROCESS avec
    # "svchost.exe -k utcsvc -p", DoSvc est 0x20 WIN32_SHARE_PROCESS avec
    # "svchost.exe -k NetworkService -p". Les deux sont hebergees. Exiger 0x20
    # ferait donc echouer un banc dont le temoin ressemblerait a DiagTrack.
    #
    # Les etiquettes de sc qc sont traduites, les valeurs symboliques non:
    # WIN32_SHARE_PROCESS reste WIN32_SHARE_PROCESS en francais.
    $qc = @(& sc.exe qc $Service 2>&1)
    foreach ($l in $qc) { if ("$l".Trim() -ne '') { Write-Host ("   qc : {0}" -f "$l".Trim()) } }
    $qcPlat = (@($qc) -join ' ')
    $typeRegistre = (Get-ItemProperty -Path $cleSvc -ErrorAction SilentlyContinue).Type
    Write-Host ("type registre : 0x{0:X}   (DiagTrack: 0x10, DoSvc: 0x20 - les deux hebergees)" -f [int]$typeRegistre)
    if (($qcPlat.ToLower() -notlike '*svchost.exe*') -or ($qcPlat.ToLower() -notlike "*-k $($Groupe.ToLower())*")) {
        Write-Host 'ECHEC: le chemin d image du service ne nomme pas svchost.exe avec notre groupe.'
        Write-Host ("       attendu quelque chose comme: svchost.exe -k {0}" -f $Groupe)
        Write-Host '       Sans cela le temoin n est pas heberge, et ce banc ne mesure rien de neuf.'
        return 1
    }

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

    $a = Passage 'A' $true $sid
    if ($a.Abandon) {
        Write-Host ''
        Write-Host ("  ECHEC    passage A: {0}" -f $a.Raison)
        return 1
    }
    $b = Passage 'B' $false $sid
    $c = Passage 'C' $true $sid

    # ------------------------------------------------------------------ verdict
    Write-Host ''
    Write-Host '== Verdict =='
    if ($c.Abandon) {
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
    if ($b.Permis -eq 0 -and "$($b.Verdict)" -notlike '5 *') {
        Write-Host '  SKIPPED  le temoin n est pas sorti au passage SANS filtre, alors qu il etait'
        Write-Host ("           sorti avant la mesure (verdict du temoin: {0})." -f $b.Verdict)
        Write-Host '           La machine a change sous la mesure: elle ne discrimine plus.'
        return 0
    }

    Write-Host ("  hebergement   : temoin dans svchost.exe = {0}, seul dans son processus = {1}" -f $a.DansSvchost, $a.Seul)
    Write-Host ("  drapeau -p    : voir le releve du temoin ci-dessus. Ce banc tourne SANS -p, et")
    Write-Host  '                  ne peut rien dire des services qui, eux, en portent un.'

    if (($a.Notres + $c.Notres) -ge 1) {
        Write-Host ("  MESURE   {0} refus impute(s) a un filtre de la couche 2 sur les passages filtres." -f ($a.Notres + $c.Notres))
        Write-Host '           Un blocage ALE_USER_ID sur le SID d un service HEBERGE DANS SVCHOST'
        Write-Host '           refuse donc bien sa connexion. L HYPOTHESE TOMBE: l hebergement dans'
        Write-Host '           svchost n explique pas l echappement de DiagTrack et de DoSvc, et il'
        Write-Host '           faut chercher ailleurs. Reserve qui subsiste: ce temoin tourne sans'
        Write-Host '           le drapeau -p que portent les deux cibles.'
        if (($a.Permis + $c.Permis) -ge 1) {
            Write-Host ''
            Write-Host ("           FUITE: {0} connexion(s) AUTORISEE(S) sur les passages filtres" -f ($a.Permis + $c.Permis))
            Write-Host ("           (A={0}, C={1}) alors que la sonde etait posee et verifiee porteuse" -f $a.Permis, $c.Permis)
            Write-Host '           du SID vise. Le mecanisme mord, et il laisse passer.'
        }
        if ("$($a.Verdict)" -notlike '3 *' -or "$($c.Verdict)" -notlike '3 *') {
            Write-Host ''
            Write-Host '           RESERVE: le journal impute un refus, mais le temoin ne se dit pas'
            Write-Host ("           BLOQUE sur les deux passages filtres (A={0} / C={1})." -f $a.Verdict, $c.Verdict)
            Write-Host '           Les deux signaux divergent: la rafale rend le plus PERMISSIF de ses'
            Write-Host '           essais, donc une seule sortie reussie efface des milliers de refus.'
            Write-Host '           Ce n est pas une contradiction, c est une fuite a nommer.'
        }
        return 0
    }
    if (($a.Permis + $c.Permis) -ge 1) {
        Write-Host ("  ECHEC    {0} connexion(s) AUTORISEE(S) alors que la sonde etait posee, verifiee" -f ($a.Permis + $c.Permis))
        Write-Host '           presente, et verifiee porteuse du SID du temoin.'
        Write-Host '           Le temoin ECHAPPE, avec la signature de DiagTrack et de DoSvc, et il'
        Write-Host '           est heberge dans svchost comme elles. L HYPOTHESE EST CORROBOREE:'
        Write-Host '           l hebergement dans svchost.exe est le discriminant. Le nom du filtre'
        Write-Host '           gagnant de chaque autorisation est imprime ci-dessus.'
        Write-Host '           Ce n est PAS un echec du banc: c est un echec du BLOCAGE, et c est'
        Write-Host '           le resultat le plus lourd de consequence pour le produit.'
        Write-Host '           Reserve: ce temoin tourne sans le drapeau -p des deux cibles, donc il'
        Write-Host '           etablit que -p n est PAS necessaire a l echappement, pas qu il n y'
        Write-Host '           contribue pas.'
        return 1
    }
    if ("$($a.Verdict)" -like '3 *' -and "$($c.Verdict)" -like '3 *') {
        Write-Host '  INDICE   le temoin se dit BLOQUE sur les deux passages filtres, mais aucun 5157'
        Write-Host '           n est impute a nos filtres: on ne sait pas QUI a bloque. Le comportement'
        Write-Host '           suit la sonde, ce qui est un indice, pas une preuve.'
        return 0
    }
    Write-Host '  SKIPPED  ni refus impute, ni connexion autorisee, ni blocage annonce par le temoin:'
    Write-Host ("           verdicts du temoin A={0} B={1} C={2}" -f $a.Verdict, $b.Verdict, $c.Verdict)
    Write-Host ("           evenements A={0}/{1}  C={2}/{3}." -f $a.Permis, $a.Refuses, $c.Permis, $c.Refuses)
    Write-Host '           La mesure n a rien attrape. Relancer, ou verifier que l audit est actif.'
    return 0
}

$code = 1
try {
    $code = Main
}
finally {
    # Le menage a lieu meme en sortant sur une erreur, et il ne defait que ce
    # qui a REELLEMENT ete fait. Chaque retrait est VERIFIE par une lecture qui
    # ne vient pas de ce qui a pose.
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
            Write-Host '  relecture netsh : netsh n a rien rendu, l absence des filtres n est PAS verifiee'
        }
    } else {
        Write-Host '  relecture netsh : aucun filtre pose par ce passage, rien a retirer'
    }

    if ($script:serviceCree) {
        $null = & sc.exe stop $Service 2>&1
        Start-Sleep -Seconds 3
        $null = & sc.exe delete $Service 2>&1
        Start-Sleep -Seconds 2
        # Verifie par une INTERROGATION du SCM, pas par le code de sc delete.
        $reste = @(& sc.exe query $Service 2>&1)
        if ($LASTEXITCODE -eq 0) {
            Write-Host ("  service         : ECHEC du retrait, {0} repond toujours" -f $Service)
            foreach ($l in @($reste)) { if ("$l".Trim() -ne '') { Write-Host ("     {0}" -f "$l".Trim()) } }
        } else {
            Write-Host ("  service         : supprime ({0} ne repond plus)" -f $Service)
        }
    } else {
        Write-Host '  service         : aucun service cree par ce passage'
    }

    if ($script:groupePose) {
        Remove-ItemProperty -Path $CleSvchost -Name $Groupe -ErrorAction SilentlyContinue
        $relu = Get-ItemProperty -Path $CleSvchost -Name $Groupe -ErrorAction SilentlyContinue
        if ($relu -eq $null) {
            Write-Host ("  valeur groupe   : retiree ({0})" -f $Groupe)
        } else {
            Write-Host ("  valeur groupe   : ECHEC du retrait, {0} est toujours sous la cle Svchost" -f $Groupe)
        }
    } else {
        Write-Host '  valeur groupe   : aucune valeur ajoutee par ce passage'
    }

    # La cle Svchost, comparee valeur par valeur a ce qui y etait AVANT. C est
    # la garde de la promesse "sans jamais toucher a une valeur existante".
    if (@($script:valeursAvant).Count -gt 0) {
        $cleFin = Get-Item -Path $CleSvchost -ErrorAction SilentlyContinue
        if ($cleFin -eq $null) {
            Write-Host '  cle Svchost     : illisible a la fin, la comparaison n a PAS eu lieu'
        } else {
            $valeursApres = @($cleFin.GetValueNames() | Sort-Object)
            $ecart = @(Compare-Object -ReferenceObject @($script:valeursAvant) -DifferenceObject @($valeursApres))
            if (@($ecart).Count -eq 0) {
                Write-Host ("  cle Svchost     : {0} valeur(s), identiques a l etat trouve" -f @($valeursApres).Count)
            } else {
                Write-Host '  cle Svchost     : ECART avec l etat trouve, a regarder de pres:'
                foreach ($e in $ecart) { Write-Host ("     {0} {1}" -f $e.SideIndicator, $e.InputObject) }
            }
        }
    }

    if ($script:copieFaite) {
        # L instrument, de l autre cote de la fenetre. Verifier avant de mesurer
        # ne suffit pas quand quelque chose peut encore ecrire apres.
        $apres = Empreinte $DllPosee
        if ($apres -eq $script:empreinteDll) {
            Write-Host '  empreinte apres : inchangee, la DLL mesuree est bien celle qui a ete copiee'
        } elseif ("$apres" -eq '') {
            Write-Host '  empreinte apres : la copie a disparu avant le menage'
        } else {
            Write-Host ("  empreinte apres : CHANGEE ({0}). La DLL a ete reecrite pendant la mesure." -f $apres)
        }
        Remove-Item -LiteralPath $DllPosee -Force -ErrorAction SilentlyContinue
        if (Test-Path $DllPosee) {
            Write-Host ("  copie dll       : ECHEC du retrait, {0} est toujours la." -f $DllPosee)
            Write-Host '                    svchost la tient sans doute encore mappee: verifier que'
            Write-Host '                    ServiceDllUnloadOnStop vaut bien 1 et que le service est arrete.'
        } else {
            Write-Host ("  copie dll       : retiree ({0})" -f $DllPosee)
        }
    } else {
        Write-Host '  copie dll       : aucune copie faite'
    }

    Effacer-Journal
    if (Test-Path $Journal) {
        Write-Host ("  journal temoin  : ECHEC du retrait, {0} est toujours la" -f $Journal)
    } else {
        Write-Host ("  journal temoin  : retire ({0}), son contenu est imprime plus haut" -f $Journal)
    }

    if ($script:auditTouche) {
        $null = & auditpol /set /subcategory:"$Sous" /success:disable /failure:enable
        Write-Host '  politique audit : remise a /success:disable /failure:enable'
        foreach ($l in @(& auditpol /get /subcategory:"$Sous" /r)) { if ("$l".Trim() -ne '') { Write-Host ("  {0}" -f $l) } }
    } else {
        Write-Host '  politique audit : non touchee'
    }
}
exit $code

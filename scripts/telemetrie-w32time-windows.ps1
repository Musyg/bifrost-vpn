# Un VRAI service Windows heberge dans svchost echappe-t-il au blocage `ALE_USER_ID` ?
#
# A lancer sur essai-windows, en administrateur, shell cmd, depuis la racine du
# banc (le repertoire qui contient les binaires) ou avec BIFROST_BANC pose:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\telemetrie-w32time-windows.ps1
#
# LA QUESTION. Le mecanisme `ALE_USER_ID` mord sur trois temoins de test - 569,
# 621 et 673 refus, le 5157 nommant notre filtre - et deux VRAIES cibles lui
# echappent, DiagTrack et DoSvc. Toutes les explications sont tombees: compte,
# groupe `svchost`, type de demarrage, attributs du SID dans le jeton, jeton
# filtre, protection de processus, couche, arbitrage entre sous-couches,
# usurpation durable. Il reste UNE difference structurelle, jamais mesuree: les
# trois temoins bloques PORTENT LEUR PROPRE BINAIRE, les deux qui echappent sont
# HEBERGEES DANS `svchost.exe`.
#
# POURQUOI W32Time. Il met l'hypothese a l'epreuve pour un cout tres faible, et
# sur un VRAI service de Windows plutot que sur un temoin fabrique: il est
# heberge dans svchost, il porte un SID de service `UNRESTRICTED`, il n'est pas
# sur la liste des services intouchables du depot, et surtout `w32tm /resync` le
# fait emettre A LA DEMANDE, autant de fois qu'on veut. C'est ce qui manquait a
# DiagTrack, qui n'emet qu'une fois par redemarrage et assechait la fenetre
# avant qu'on puisse lire quoi que ce soit.
#
# CE QUE CE BANC NE TRANCHE PAS, et il faut le lire AVANT le resultat. W32Time
# tourne en `svchost.exe -k LocalService -s W32Time`, SANS le drapeau `-p` que
# portent DiagTrack et DoSvc. Ce banc mesure donc exactement ceci: un VRAI
# service Windows heberge dans `svchost.exe` SANS `-p` est-il refuse par un
# blocage `ALE_USER_ID` sur son SID ? Il ne dit rien de `-p`, et il imprime la
# ligne de commande du processus qu'il mesure pour qu'on ne l'oublie pas.
#
# CE QUE CE BANC REPREND ET N'ECRIT PAS DEUX FOIS. Le controle decisif - << un
# filtre pose porte-t-il EXACTEMENT le SID de la cible ? >> - est DELEGUE a
# `telemetrie-conditions-windows.ps1`, l'instrument du depot pour cette
# question, dont le code de sortie est lu. Deux implementations qui
# divergeraient rendraient deux mesures incomparables. Ce banc ne relit le dump
# `netsh` que pour NOMMER le filtre gagnant d'un evenement, ce que le controle
# des conditions ne fait pas.
#
# LA FORME DU FILTRE. `--telemetrie-sonde-sid` pose UN blocage de la MEME forme
# que les entrees du catalogue: `plan_sonde` et le catalogue construisent un
# `FilterSpec` structurellement identique pour une cible service - memes
# couches, meme poids, meme action, meme veto, meme genre de condition. Une
# sonde qui poserait autre chose ne mesurerait pas ce qu'on croit.
#
# DEUX SIGNAUX INDEPENDANTS, ET C'EST VOULU: ce que `w32tm /resync` rend, qui ne
# depend d'aucun journal, et les evenements 5156/5157, seuls a nommer le filtre
# gagnant. Quand ils divergent, le banc l'ecrit et ne conclut pas.
#
# MAIS LE CODE DE SORTIE DE `w32tm /resync` N'EST PAS CE SIGNAL, et le croire a
# coute un passage entier le 23/08/2026. Mesure, sonde posee puis retiree, il
# rend **0 dans les deux etats**. Ce qui distingue les deux, c'est le TEXTE, et
# la premiere version de ce banc n'en gardait que la PREMIERE ligne non vide -
# un simple accuse d'envoi, identique des deux cotes:
#   sans filtre : << La commande s'est terminee correctement. >>
#   sous sonde  : << L'ordinateur ne s'est pas resynchronise car aucune donnee
#                    de temps n'etait disponible. >>
# Le banc imprime donc TOUTES les lignes. Elles sont LOCALISEES - francais sur
# cette machine - donc elles se LISENT, elles ne se comparent pas: c'est du
# contexte corroborant, et le verdict reste au journal, seul a nommer le
# gagnant. Un compteur qui rend la meme valeur dans les deux etats ne mesure
# rien, et l'afficher comme un signal invite a conclure de travers.
#
# CINQ PIEGES DEJA PAYES SUR CETTE MACHINE, et qui valent tous ici:
#   - Un temoin muet certifie n'importe quoi. Le premier passage est donc SANS
#     filtre: si la cible n'emet pas la, c'est SKIPPED, pas un succes. Le 23/08,
#     `CompatTelRunner` a coute cette lecon une deuxieme fois: ses taches
#     n'avaient jamais tourne, et on en avait conclu a tort qu'il ne se
#     connectait pas.
#   - Sans l'audit des SUCCES, << bloque >> et << n'a rien tente >> rendent la
#     meme mesure, c'est-a-dire aucune.
#   - Un PID attrape a la volee a deja appartenu au processus precedent. Le PID
#     et son instant de creation sont releves au depart ET pendant la fenetre,
#     et la mesure est INVALIDEE s'il a change.
#   - Un `svchost` partage rend l'attribution par PID fausse, et le jeton du
#     processus porterait alors plusieurs SID de service. Le banc releve les
#     colocataires et invalide si la cible n'est pas seule.
#   - Chez WFP un blocage l'emporte sur une autorisation. Si une autorisation
#     gagne alors que notre filtre est pose et verifie porteur du bon SID, c'est
#     que notre filtre n'a pas MATCHE.
#
# LES PASSAGES SONT ALTERNES ET REPETES. Avec un declencheur a la demande, une
# seule paire ne vaut pas grand-chose: le banc fait plusieurs allers-retours.
# Chaque passage REDEMARRE la cible avant de declencher, pour que l'etat du
# client NTP - dont le recul apres un echec de resolution - soit le meme des
# deux cotes de la comparaison.
#
# Verdicts, et aucun n'est un vert par defaut:
#   BLOQUE   un 5157 impute un refus a notre filtre. C'est la preuve, et c'est
#            le resultat qui FAIT TOMBER l'hypothese de l'hebergement.
#   ECHAPPE  une connexion passe alors que le filtre est pose, verifie present
#            ET verifie porteur du SID exact de la cible. C'est le resultat qui
#            la CORROBORE. Le banc sort non nul pour qu'on le lise, pas pour
#            dire qu'il s'est mal passe.
#   INDICE   le comportement suit le filtre mais aucun 5157 ne l'impute.
#   SKIPPED  le temoin n'emet pas sans filtre, ou la mesure a ete invalidee.
#            La raison est nommee, toujours.

param(
    # La racine du banc: le repertoire du script (via -File), ou BIFROST_BANC si pose.
    [string]$Banc = $(if ($env:BIFROST_BANC) { $env:BIFROST_BANC } else { $PSScriptRoot }),
    [string]$Binaire = (Join-Path $Banc 'bifrost-daemon.exe'),
    # L'instrument du depot pour le controle du SID. Delegue, jamais reecrit.
    [string]$Conditions = (Join-Path $Banc 'telemetrie-conditions-windows.ps1'),
    # La cible. W32Time par defaut, mais tout service heberge dans svchost et
    # hors de la liste intouchable se mesure ainsi.
    [string]$Service = 'W32Time',
    # Nombre de paires sans-filtre / filtre. Le banc commence toujours SANS.
    [int]$Paires = 3,
    # Declenchements par passage.
    [int]$Resyncs = 3,
    [int]$PasEchantillon = 4
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

$script:auditTouche = $false
# Le menage ne defait que ce qui a ete fait: un banc qui << nettoie >> ce qu il
# n a jamais pose relance le binaire pour rien, et execute au passage le
# programme que l appelant a nomme.
$script:posePassee = $false

# --------------------------------------------------------------- lecture WFP

function Dump-Wfp {
    $f = Join-Path $env:SystemRoot 'Temp\bifrost-w32time.xml'
    if (Test-Path $f) { Remove-Item $f -Force -ErrorAction SilentlyContinue }
    $null = & netsh wfp show filters file="$f" 2>&1
    if (-not (Test-Path $f)) { return $null }
    return $f
}

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
# 0 = au moins un filtre pose porte exactement le SID de la cible. 1 = aucun,
# y compris quand rien n'est pose.
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
        $c.Ligne = [string]$pr.CommandLine
    }
    $c.Colocataires = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { [int]$_.ProcessId -eq [int]$c.Idproc } | ForEach-Object { [string]$_.Name })
    return $c
}

function Attendre-Etat($nom, $vise, $secondes) {
    $depart = Get-Date
    while (((Get-Date) - $depart).TotalSeconds -lt $secondes) {
        $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$nom'" -ErrorAction SilentlyContinue
        if ($svc -ne $null -and [string]$svc.State -eq $vise) { return $true }
        Start-Sleep -Seconds 2
    }
    return $false
}

# ------------------------------------------------------------- le declencheur

function Redemarrer($cible) {
    $etat = Get-CimInstance -ClassName Win32_Service -Filter "Name='$cible'" -ErrorAction SilentlyContinue
    if ($etat -ne $null -and [string]$etat.State -eq 'Running') {
        $null = & sc.exe stop $cible 2>&1
        $null = Attendre-Etat $cible 'Stopped' 30
    }
    $null = & sc.exe start $cible 2>&1
    $parti = Attendre-Etat $cible 'Running' 40
    if (-not $parti) { Write-Host ("   ATTENTION: {0} n est pas RUNNING apres le demarrage" -f $cible) }
    Start-Sleep -Seconds 3
    return $parti
}

# Le declencheur, et le signal qui ne depend d'aucun journal.
#
# ATTENTION au code de sortie: mesure le 23/08/2026, `w32tm /resync` rend 0
# sonde posee comme sonde retiree. Il est imprime pour memoire et ne compte
# nulle part. Ce qui distingue les deux etats est le TEXTE, localise, donc
# imprime EN ENTIER et lu par un humain plutot que compare par le banc.
function Resync($n) {
    for ($i = 1; $i -le $n; $i++) {
        $sortie = @(& w32tm.exe /resync 2>&1)
        $code = $LASTEXITCODE
        Write-Host ("      resync {0}/{1} : code de sortie={2}  (mesure sans valeur discriminante, cf. en-tete)" -f $i, $n, $code)
        foreach ($l in $sortie) {
            if ("$l".Trim() -ne '') { Write-Host ("         texte: {0}" -f "$l".Trim()) }
        }
        Start-Sleep -Seconds 4
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
        Write-Host ("         destination    : {0}:{1}  protocole {2}" -f $d['DestAddress'], $d['DestPort'], $d['Protocol'])
    }
}

# ------------------------------------------------------------------ un passage

function Passage($etiquette, $filtre, $cible, $sidCible) {
    $res = New-Object psobject
    $res | Add-Member NoteProperty Permis     0
    $res | Add-Member NoteProperty Refuses    0
    $res | Add-Member NoteProperty Notres     0
    $res | Add-Member NoteProperty Abandon    $false
    $res | Add-Member NoteProperty Invalide   $false
    $res | Add-Member NoteProperty Raison     ''
    $res | Add-Member NoteProperty Gagnant    ''
    $res | Add-Member NoteProperty NomGagnant ''
    $res | Add-Member NoteProperty Filtre     $filtre

    Write-Host ''
    if ($filtre) { Write-Host ("-- passage {0} : SONDE POSEE --" -f $etiquette) }
    else         { Write-Host ("-- passage {0} : sans filtre --" -f $etiquette) }

    if ($filtre) {
        $script:posePassee = $true
        $sortie = @(& $Binaire --telemetrie-sonde-sid $sidCible 2>&1)
        $code = $LASTEXITCODE
        if ($code -ne 0) {
            Write-Host ("   ABANDON: la sonde n a rien pose (code {0})" -f $code)
            foreach ($l in $sortie) { Write-Host ("      {0}" -f $l) }
            $res.Abandon = $true
            $res.Raison = "la sonde a rendu $code"
            return $res
        }
        foreach ($l in $sortie) { if ("$l".Trim() -ne '') { Write-Host ("   sonde         : {0}" -f "$l".Trim()) } }
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
    $null = Redemarrer $cible

    # ---------------------- CONTROLE 2: le processus, et QUI partage son PID
    $avant = Contexte-Processus $cible
    if ($avant.Idproc -le 0) {
        Write-Host ("   MESURE INVALIDEE: {0} n a pas de PID apres le demarrage (etat {1})" -f $cible, $avant.Etat)
        $res.Invalide = $true
        $res.Raison = "pas de PID apres demarrage, etat $($avant.Etat)"
        return $res
    }
    Write-Host ("   PID au depart : {0}  cree le {1}  etat {2}" -f $avant.Idproc, $avant.Creation, $avant.Etat)
    # La ligne de commande est imprimee a chaque passage, et pas seulement en
    # en-tete: c'est elle qui dit si la cible porte `-p`, et c'est la reserve
    # que ce banc ne leve pas.
    Write-Host ("   ligne         : {0}" -f $avant.Ligne)
    Write-Host ("   colocataires  : {0} service(s) sur ce PID : {1}" -f @($avant.Colocataires).Count, (@($avant.Colocataires) -join ', '))
    if (@($avant.Colocataires).Count -ne 1) {
        Write-Host '   MESURE INVALIDEE: la cible partage son svchost avec d autres services.'
        Write-Host '                     Un evenement portant ce PID ne lui serait pas attribuable,'
        Write-Host '                     et le jeton du processus porterait plusieurs SID de service.'
        $res.Invalide = $true
        $res.Raison = "svchost partage: " + ((@($avant.Colocataires) -join ', '))
        return $res
    }

    # ----------------------------------- le declencheur, plusieurs fois
    Resync $Resyncs

    # ------------------- CONTROLE 3: la continuite, echantillonnee
    $depart = Get-Date
    $invalide = $false
    while (((Get-Date) - $depart).TotalSeconds -lt ($PasEchantillon * 3)) {
        Start-Sleep -Seconds $PasEchantillon
        $t = [int]((Get-Date) - $depart).TotalSeconds
        $maintenant = Contexte-Processus $cible
        if ($maintenant.Idproc -eq $avant.Idproc -and $maintenant.Creation -eq $avant.Creation) { continue }
        if ($maintenant.Idproc -le 0) {
            Write-Host ("   MESURE INVALIDEE: {0} a disparu a t=+{1}s (etat {2}) pendant la fenetre." -f $cible, $t, $maintenant.Etat)
            $res.Invalide = $true
            $res.Raison = "le service a disparu a t=+" + $t + "s"
            $invalide = $true
            break
        }
        Write-Host '   MESURE INVALIDEE: un AUTRE processus porte desormais le service.'
        Write-Host ("                     au depart : PID {0} cree le {1}" -f $avant.Idproc, $avant.Creation)
        Write-Host ("                     a t=+{0}s  : PID {1} cree le {2}" -f $t, $maintenant.Idproc, $maintenant.Creation)
        $res.Invalide = $true
        $res.Raison = "processus remplace a t=+" + $t + "s: PID " + $avant.Idproc + " puis PID " + $maintenant.Idproc
        $invalide = $true
        break
    }
    if ($invalide) { return $res }
    $finFenetre = Get-Date
    $apres = Contexte-Processus $cible
    Write-Host ("   PID au releve : {0}  cree le {1}  (inchange)" -f $apres.Idproc, $apres.Creation)

    # ------------------------------------------------------ lecture du journal
    $permis = @()
    $refuses = @()
    foreach ($id in @(5156, 5157)) {
        $evts = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$id; StartTime=$marque; EndTime=$finFenetre} -ErrorAction SilentlyContinue)
        foreach ($e in $evts) {
            $d = Detail $e
            if ("$($d['ProcessID'])" -ne "$($avant.Idproc)") { continue }
            if ($id -eq 5156) { $permis = $permis + @($d) } else { $refuses = $refuses + @($d) }
        }
    }

    $chemin2 = Dump-Wfp
    $lu2 = Lire-Filtres $chemin2
    if ($chemin2 -ne $null) { Remove-Item $chemin2 -Force -ErrorAction SilentlyContinue }
    $notres = @(@($refuses) | Where-Object { $lu2.Nos.ContainsKey("$($_['FilterRTID'])") }).Count

    $res.Permis = @($permis).Count
    $res.Refuses = @($refuses).Count
    $res.Notres = $notres
    Write-Host ("   RESULTAT      autorisees={0}  refusees={1}  dont par nos filtres={2}" -f `
        $res.Permis, $res.Refuses, $res.Notres)

    $premier = $null
    if (@($refuses).Count -gt 0) { $premier = @($refuses)[0] } elseif (@($permis).Count -gt 0) { $premier = @($permis)[0] }
    if ($premier -ne $null) {
        $rt = "$($premier['FilterRTID'])"
        $res.Gagnant = $rt
        if ($lu2.Tous.ContainsKey($rt)) { $res.NomGagnant = $lu2.Tous[$rt] } else { $res.NomGagnant = '(absent du dump)' }
    }

    Nommer-Gagnants 'AUTORISEE' $permis $lu2.Nos $lu2.Tous 3
    Nommer-Gagnants 'REFUSEE  ' $refuses $lu2.Nos $lu2.Tous 3
    return $res
}

# ------------------------------------------------------------------- le corps

function Main {
    Write-Host ('=' * 78)
    Write-Host 'Un VRAI service Windows heberge dans svchost echappe-t-il a ALE_USER_ID ?'
    Write-Host ("hote          : {0}" -f $env:COMPUTERNAME)
    Write-Host ("windows       : {0}" -f (Get-CimInstance Win32_OperatingSystem).Version)
    Write-Host ("powershell    : {0}" -f $PSVersionTable.PSVersion)
    $ident = [Security.Principal.WindowsIdentity]::GetCurrent()
    $princ = New-Object Security.Principal.WindowsPrincipal($ident)
    Write-Host ("session admin : {0}" -f $princ.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    Write-Host ("demarre le    : {0}" -f (Get-CimInstance Win32_OperatingSystem).LastBootUpTime)
    Write-Host ("maintenant    : {0}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
    Write-Host ("binaire       : {0}" -f $Binaire)
    Write-Host ("cible         : {0}" -f $Service)
    Write-Host ("passages      : {0} paire(s) sans-filtre / filtre, {1} resync par passage" -f $Paires, $Resyncs)
    Write-Host ('=' * 78)

    if (-not (Test-Path $Binaire)) { Write-Host 'ECHEC: binaire introuvable'; return 1 }

    # Garde-fou. Ce banc fait `sc stop` puis `sc start` sur le nom qu on lui
    # donne, et lui pose un blocage reseau. La liste intouchable du depot est
    # rejouee ici en clair: le binaire la fait deja respecter, mais un banc qui
    # ARRETE un service ne doit pas dependre du refus du binaire, qui vient
    # apres l arret.
    $JAMAIS = @('wuauserv','BITS','Dnscache','WinDefend','wlidsvc','sppsvc','cryptsvc','LanmanWorkstation')
    foreach ($j in $JAMAIS) {
        if ($Service.ToLower() -eq $j.ToLower()) {
            Write-Host ("REFUS: {0} est sur la liste intouchable du depot." -f $Service)
            return 1
        }
    }

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

    # Le fait qui rend cette cible interessante: elle est HEBERGEE dans svchost.
    # Si elle ne l etait pas, le banc mesurerait autre chose que ce qu il
    # annonce, et il vaut mieux le refuser que de le decouvrir dans le rapport.
    $ctx = Contexte-Processus $Service
    Write-Host ("ligne du proc : {0}" -f $ctx.Ligne)
    if (-not ("$($ctx.Ligne)".ToLower().Contains('svchost.exe'))) {
        Write-Host '   REFUS: la cible ne tourne pas dans svchost.exe. Ce banc existe pour'
        Write-Host '          eprouver l hebergement dans svchost, et rien d autre.'
        return 1
    }
    if ("$($ctx.Ligne)" -match '(^|\s)-p(\s|$)') {
        Write-Host 'note          : la cible porte -p. Le banc mesure alors AUSSI ce drapeau,'
        Write-Host '                et son resultat ne separe plus hebergement et attenuations.'
    } else {
        Write-Host 'note          : la cible ne porte PAS -p. Ce banc mesure donc l hebergement'
        Write-Host '                dans svchost SEUL, et ne dit rien de -p.'
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
    Write-Host '== Passages alternes, en commencant SANS filtre =='
    Write-Host '   (le temoin doit sortir sans nous avant qu une absence de connexion veuille dire quelque chose)'

    $tous = @()
    $lettres = 'ABCDEFGHIJKL'
    $i = 0
    for ($p = 1; $p -le $Paires; $p++) {
        $sans = Passage ("$($lettres[$i])") $false $Service $sidCible
        $i = $i + 1
        $tous = $tous + @($sans)
        if ($sans.Abandon) { break }
        $avec = Passage ("$($lettres[$i])") $true $Service $sidCible
        $i = $i + 1
        $tous = $tous + @($avec)
        if ($avec.Abandon) { break }
    }

    Write-Host ''
    Write-Host '== Recapitulatif =='
    $j = 0
    foreach ($r in @($tous)) {
        $et = "$($lettres[$j])"
        $j = $j + 1
        $f = 'sans  '
        if ($r.Filtre) { $f = 'FILTRE' }
        if ($r.Abandon) {
            Write-Host ("  {0} {1}  ABANDON: {2}" -f $et, $f, $r.Raison)
            continue
        }
        if ($r.Invalide) {
            Write-Host ("  {0} {1}  INVALIDE: {2}" -f $et, $f, $r.Raison)
            continue
        }
        Write-Host ("  {0} {1}  autorisees={2} refusees={3} dont nous={4}  rtid={5} << {6} >>" -f `
            $et, $f, $r.Permis, $r.Refuses, $r.Notres, $r.Gagnant, $r.NomGagnant)
    }

    Write-Host ''
    Write-Host '== Verdict =='
    $abandons = @(@($tous) | Where-Object { $_.Abandon })
    if (@($abandons).Count -gt 0) {
        Write-Host ("  ABANDON  {0}" -f @($abandons)[0].Raison)
        return 1
    }
    $invalides = @(@($tous) | Where-Object { $_.Invalide })
    if (@($invalides).Count -gt 0) {
        Write-Host '  SKIPPED  au moins un passage a ete invalide, la serie ne discrimine pas:'
        foreach ($r in @($invalides)) { Write-Host ("           {0}" -f $r.Raison) }
        return 0
    }

    $avecF = @(@($tous) | Where-Object { $_.Filtre })
    $sansF = @(@($tous) | Where-Object { -not $_.Filtre })
    $permisSans = 0
    foreach ($r in @($sansF)) { $permisSans = $permisSans + $r.Permis }
    $permisAvec = 0
    $notresAvec = 0
    foreach ($r in @($avecF)) {
        $permisAvec = $permisAvec + $r.Permis
        $notresAvec = $notresAvec + $r.Notres
    }

    Write-Host ("  sans filtre : {0} connexion(s) autorisee(s) sur {1} passage(s)" -f $permisSans, @($sansF).Count)
    Write-Host ("  avec filtre : {0} connexion(s) autorisee(s), {1} refus imputes a NOS filtres, sur {2} passage(s)" -f $permisAvec, $notresAvec, @($avecF).Count)

    if ($permisSans -eq 0) {
        Write-Host '  SKIPPED  le temoin n a RIEN emis SANS aucun filtre. Une machine muette et un'
        Write-Host '           blocage reussi rendent la meme mesure. La cible n est pas eprouvable'
        Write-Host '           avec ce declencheur.'
        return 0
    }
    if ($notresAvec -ge 1 -and $permisAvec -ge 1) {
        Write-Host '  INDICE   des refus a nous ET des connexions autorisees dans les memes passages.'
        Write-Host '           Les deux lectures coexistent, le banc ne tranche pas.'
        return 0
    }
    if ($notresAvec -ge 1) {
        Write-Host ("  BLOQUE   {0} refus impute(s) a notre filtre, le systeme le nomme lui-meme." -f $notresAvec)
        Write-Host '           Un VRAI service Windows HEBERGE dans svchost est donc bien mordu par'
        Write-Host '           un blocage ALE_USER_ID sur son SID: l hebergement n est PAS le'
        Write-Host '           discriminant, et il faut chercher l ecart ailleurs.'
        return 0
    }
    if ($permisAvec -ge 1) {
        Write-Host ("  ECHAPPE  {0} connexion(s) AUTORISEE(S) alors que la sonde etait posee, verifiee" -f $permisAvec)
        Write-Host '           presente ET verifiee porteuse du SID exact de la cible. Notre filtre'
        Write-Host '           n a pas MATCHE. L hebergement dans svchost est CORROBORE comme'
        Write-Host '           discriminant.'
        return 1
    }
    Write-Host '  INDICE   plus aucune connexion avec la sonde, mais aucun 5157 ne l impute a nos'
    Write-Host '           filtres: on ne sait pas QUI a bloque. Insuffisant pour conclure BLOQUE.'
    return 0
}

$code = 1
try {
    $code = Main
}
finally {
    Write-Host ''
    Write-Host '== menage =='
    if ($script:posePassee) {
        $null = & $Binaire --telemetrie-reseau-retirer 2>&1
        # Le retrait se verifie INDEPENDAMMENT de ce qui a pose: un releve
        # netsh distinct, pas le binaire qu on eprouve.
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
    # La cible doit repartir dans l etat trouve, et l heure du poste doit se
    # resynchroniser: un banc qui laisse une machine desynchronisee a un effet
    # de bord que personne n a demande.
    $etat = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Service'" -ErrorAction SilentlyContinue
    if ($etat -eq $null -or [string]$etat.State -ne 'Running') {
        $null = & sc.exe start $Service 2>&1
        $null = Attendre-Etat $Service 'Running' 40
    }
    $etat = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Service'" -ErrorAction SilentlyContinue
    Write-Host ("  {0} : etat {1}, pid {2}" -f $Service, [string]$etat.State, [int]$etat.ProcessId)
    foreach ($l in @(& w32tm.exe /resync 2>&1)) { if ("$l".Trim() -ne '') { Write-Host ("  resync final: {0}" -f "$l".Trim()) } }
    foreach ($l in @(& w32tm.exe /query /status 2>&1)) {
        if ("$l" -match 'ynchron' -or "$l" -match 'ource') { Write-Host ("  {0}" -f "$l".Trim()) }
    }
    Write-Host '  aucun service cree ni supprime par ce banc'
}
exit $code

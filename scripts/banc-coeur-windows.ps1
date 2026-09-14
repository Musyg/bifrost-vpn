# Banc du CHEMIN PAR COEUR sous Windows. COUPE LE RESEAU DE LA MACHINE.
#
# # Ce que ce banc etablit
#
# Qu'un profil qui demande un coeur monte un vrai TUN Wintun, arme le kill
# switch, lance sing-box derriere la facade, et fait REELLEMENT sortir du
# trafic par lui - puis rend la machine comme il l'a trouvee. C'est le versant
# POSITIF de la metrique d'interface et l'echappement reel du coeur, les deux
# moities du chemin par coeur qui n'avaient jamais ete mesurees ailleurs que
# sous Linux.
#
# # Pourquoi il ne se lance pas depuis une session distante
#
# Le kill switch coupe le trafic de la machine, session de pilotage comprise.
# Un processus lance en enfant d'une session SSH meurt AVEC elle, donc le
# demontage n'a jamais lieu et les filtres restent poses. Ce banc se lance en
# TACHE PLANIFIEE SYSTEM detachee, et on lit son journal apres coup.
#
# # Les deux filets, et pourquoi deux
#
# Une tache planifiee `--cleanup-firewall` armee AVANT, a echeance de quelques
# minutes: si ce script meurt entre l'armement et le demontage, la machine se
# desarme seule. Et un redemarrage programme derriere, annule a la sortie: les
# filtres WFP ne sont pas persistants, donc un redemarrage rend toujours la
# machine, meme si la tache de nettoyage echouait elle aussi.
#
# # Le montage
#
#   essai-windows                            serveur (essai-linux)
#   TUN 0.0.0.0/0 -> facade 127.0.0.1:1081   REALITY sur son adresse LAN
#                 -> coeur  127.0.0.1:1080   banniere sur une interface muette
#
# La banniere porte une adresse qui n'existe que chez le serveur, sur une
# interface muette. Aucune route ne mene la depuis cette machine: elle n'est
# joignable QUE par la route par defaut du tunnel, donc ce qu'elle repond dit
# que le trafic est reellement sorti par la. C'est verifie en premisse, avant
# de monter quoi que ce soit.
#
# Une banniere sur `127.0.0.1` ne conviendrait pas ici, contrairement a ce que
# fait `--coeur-e2e`: un TUN route par ADRESSE DE DESTINATION, et la boucle
# locale ne quitte jamais la machine. Le client SOCKS de `--coeur-e2e`, lui,
# envoie un NOM que le serveur resout chez lui.
#
# # Usage
#
#   powershell -ExecutionPolicy Bypass -File banc-coeur-windows.ps1 -Profil <TOML> -TransportHote <adresse LAN du serveur>
#
# L'adresse LAN du serveur n'a PAS de valeur par defaut: c'est une identite de
# banc, elle ne se versionne pas. Elle se passe en parametre, ou par la variable
# d'environnement BIFROST_TRANSPORT_HOTE. Sans elle, le banc rend SKIPPED.
#
# Le profil porte des secrets et n'est PAS versionne.

param(
    # La racine du banc: le repertoire du script (via -File), ou BIFROST_BANC si pose.
    [string]$Banc = $(if ($env:BIFROST_BANC) { $env:BIFROST_BANC } else { $PSScriptRoot }),
    [string]$Racine = $Banc,
    [string]$Coeurs = (Join-Path $Banc 'coeurs'),
    [string]$Profil = (Join-Path $Banc 'coeurs\profil-tunnel.toml'),
    [string]$BanniereHote = "10.99.0.1",
    [int]$BannierePort = 7100,
    # Le transport du serveur, sur son adresse LOCALE. Sert de temoin negatif:
    # c'est la seule adresse du banc qui se joigne SANS passer par le tunnel.
    # Pas de valeur par defaut versionnee: voir l'usage en tete de fichier.
    [string]$TransportHote = $env:BIFROST_TRANSPORT_HOTE,
    [int]$TransportPort = 44346,
    [int]$FiletMinutes = 10,
    # Fait parler la pile TCP en espace utilisateur PAQUET PAR PAQUET. A n'armer
    # que pour une question precise: voir le bloc BIFROST_LOG plus bas, ce
    # niveau a deja fait rater une banniere au banc lui-meme.
    [switch]$Trace
)

# La racine du banc doit etre connue. Lance autrement que par -File et sans
# BIFROST_BANC, $Banc est vide et les chemins derives seraient faux.
if ([string]::IsNullOrEmpty($Banc)) {
    throw "Banc introuvable: lancer ce script par -File depuis la racine du banc (le repertoire qui contient les binaires), ou poser BIFROST_BANC sur ce repertoire."
}

$ErrorActionPreference = "Continue"

# Le banc tient son PROPRE journal, en plus de ce que l'appelant redirige.
# Lance en tache planifiee, il n'a pas de console ou se plaindre, et une
# redirection mal ecrite emporte alors la seule trace de ce qui s'est passe -
# vu le 21 aout 2026, ou un `.cmd` au chemin corrompu a rendu le code 1 sans
# ecrire une ligne, laissant a diagnostiquer un banc dont rien ne disait s'il
# avait seulement demarre.
try { Start-Transcript -Path (Join-Path $Racine "banc-coeur.transcript.log") -Force | Out-Null } catch {}

$Daemon = Join-Path $Racine "bifrost-daemon.exe"
$Cli = Join-Path $Racine "bifrost-cli.exe"
$Journal = Join-Path $Racine "banc-coeur-daemon.log"
$Configurations = Join-Path $Racine "configurations-banc"
$TacheFilet = "bifrost-banc-filet"
$Facade = "127.0.0.1:1081"

function Dire($texte) { Write-Host $texte }
function Saute($raison) { Dire "SKIPPED: $raison"; exit 0 }

# Premisse zero, avant toute autre chose: sans l'adresse du serveur, le temoin
# negatif n'existe pas et le banc ne mesurerait rien. On s'abstient, avec la
# raison, plutot que de porter une adresse LAN dans le depot.
if ([string]::IsNullOrWhiteSpace($TransportHote)) {
    Saute "TransportHote absent: passer -TransportHote <adresse LAN du serveur> ou poser BIFROST_TRANSPORT_HOTE"
}

# Verdict differe: un echec ne doit pas sauter le demontage, sans quoi le banc
# laisserait la machine coupee pour la raison meme qu'il devait mesurer.
$script:Griefs = @()
function Grief($raison) { Dire "   ECHEC: $raison"; $script:Griefs += $raison }

# Un GET minimal en socket brute. `Invoke-WebRequest` passerait par les
# reglages de proxy de la machine, ce qui ferait de ce banc une mesure du
# proxy plutot que du tunnel.
# Rend le CORPS, et publie dans $script:Etape a quel stade on s'est arrete.
# La distinction porte tout le diagnostic: un `connect` qui n'aboutit pas dit
# que rien n'est entre dans le passeur, un `connect` qui aboutit sans reponse
# dit que le relais est parti et n'est pas revenu. Les deux se ressemblent vus
# d'un client, et n'accusent pas le meme code.
$script:Etape = ""
function Lire-Banniere($hote, $port, $delaiMs) {
    $client = New-Object Net.Sockets.TcpClient
    try {
        if (-not $client.ConnectAsync($hote, $port).Wait($delaiMs)) {
            $script:Etape = "connect sans reponse"
            return ""
        }
        $script:Etape = "connect etabli"
        $flux = $client.GetStream()
        $flux.ReadTimeout = $delaiMs
        $requete = [Text.Encoding]::ASCII.GetBytes("GET /index.txt HTTP/1.0`r`nHost: $hote`r`n`r`n")
        $flux.Write($requete, 0, $requete.Length)
        $lecteur = New-Object IO.StreamReader($flux)
        $tout = $lecteur.ReadToEnd()
        $corps = $tout -split "`r`n`r`n", 2
        if ($corps.Count -lt 2) {
            $script:Etape = "connect etabli, reponse vide ou tronquee"
            return ""
        }
        $script:Etape = "reponse complete"
        return $corps[1].Trim()
    } catch {
        $script:Etape = "erreur: $($_.Exception.GetBaseException().Message)"
        return ""
    } finally { $client.Dispose() }
}

# Le meme GET, mais en parlant SOCKS5 a une adresse locale plutot qu'en
# laissant le TUN capturer. Sert a localiser le maillon qui retient la reponse:
# le coeur en direct court-circuite la facade ET le passeur, la facade ne
# court-circuite que le passeur, et le TUN ne court-circuite rien. Trois
# mesures, trois reponses, et l'endroit exact ou la chaine se rompt.
#
# Les identifiants viennent de la configuration ENGENDREE, seul endroit ou ils
# existent: ils sont tires au demarrage et ne passent par aucun argument.
function Socks-Banniere($mandataire, $hote, $port, $delaiMs) {
    $conf = Join-Path $Configurations "sing-box.json"
    if (-not (Test-Path $conf)) { return "pas de configuration engendree" }
    $compte = (Get-Content $conf -Raw | ConvertFrom-Json).inbounds[0].users[0]
    if (-not $compte) { return "l'entree engendree n'exige aucun compte" }

    $a, $p = $mandataire.Split(":")
    $client = New-Object Net.Sockets.TcpClient
    try {
        if (-not $client.ConnectAsync($a, [int]$p).Wait($delaiMs)) { return "injoignable" }
        $flux = $client.GetStream()
        $flux.ReadTimeout = $delaiMs
        $lire = {
            param($n)
            $t = New-Object byte[] $n
            $lu = 0
            while ($lu -lt $n) {
                $x = $flux.Read($t, $lu, $n - $lu)
                if ($x -le 0) { break }
                $lu += $x
            }
            return $t
        }
        # Salutation: une seule methode proposee, celle par mot de passe.
        $flux.Write([byte[]]@(5, 1, 2), 0, 3)
        $r = & $lire 2
        if ($r[0] -ne 5 -or $r[1] -ne 2) { return "salutation refusee: $($r[0]),$($r[1])" }

        # RFC 1929: VER=1, ULEN, UNAME, PLEN, PASSWD.
        $u = [Text.Encoding]::ASCII.GetBytes($compte.username)
        $w = [Text.Encoding]::ASCII.GetBytes($compte.password)
        $m = New-Object Collections.Generic.List[byte]
        $m.Add(1); $m.Add($u.Length); $m.AddRange($u); $m.Add($w.Length); $m.AddRange($w)
        $flux.Write($m.ToArray(), 0, $m.Count)
        $r = & $lire 2
        if ($r[0] -ne 1 -or $r[1] -ne 0) { return "identifiants refuses: $($r[0]),$($r[1])" }

        # CONNECT vers une adresse IPv4.
        $ip = ([Net.IPAddress]::Parse($hote)).GetAddressBytes()
        $pb = [BitConverter]::GetBytes([uint16]$port)
        [Array]::Reverse($pb)
        $q = New-Object Collections.Generic.List[byte]
        $q.Add(5); $q.Add(1); $q.Add(0); $q.Add(1); $q.AddRange($ip); $q.AddRange($pb)
        $flux.Write($q.ToArray(), 0, $q.Count)
        $r = & $lire 10
        if ($r[1] -ne 0) { return "CONNECT refuse: code $($r[1])" }

        $g = [Text.Encoding]::ASCII.GetBytes("GET /index.txt HTTP/1.0`r`nHost: $hote`r`n`r`n")
        $flux.Write($g, 0, $g.Length)
        $tout = (New-Object IO.StreamReader($flux)).ReadToEnd()
        $corps = $tout -split "`r`n`r`n", 2
        if ($corps.Count -lt 2) { return "reponse vide" }
        return $corps[1].Trim()
    } catch {
        return "erreur: $($_.Exception.GetBaseException().Message)"
    } finally { $client.Dispose() }
}

function Joignable($hote, $port, $delaiMs) {
    $client = New-Object Net.Sockets.TcpClient
    try { return $client.ConnectAsync($hote, $port).Wait($delaiMs) }
    catch { return $false } finally { $client.Dispose() }
}

function Filtres-Bifrost {
    (netsh wfp show filters file=- | Select-String -SimpleMatch "bifrost").Count
}

# Les compteurs viennent du DAEMON et non de `Get-NetAdapterStatistics`, qui
# ne connait pas l'adaptateur - "No MSFT_NetAdapterStatisticsSettingData
# objects found", mesure du 21 aout 2026. Un adaptateur Wintun n'expose pas les
# objets WMI d'une carte ordinaire. Ce n'est pas un pis-aller: ce sont les
# compteurs que le superviseur lit lui-meme pour juger du debit, donc mesurer
# ceux-la, c'est mesurer la metrique du produit et pas une autre.
function Compteurs-Du-Tunnel {
    try {
        $etat = & $Cli --json status 2>$null | ConvertFrom-Json
        return @{ rx = [int64]$etat.rx_bytes; tx = [int64]$etat.tx_bytes }
    } catch { return $null }
}

function Adaptateur-Tun {
    Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceDescription -match "Wintun" -or $_.Name -match "^bfc" }
}

# --- 0. premisses -----------------------------------------------------------

Dire "== 0. premisses =="
$identite = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identite)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Saute "monter un TUN et poser des filtres WFP demande l'elevation, ce processus ne l'a pas"
}
Dire "   compte: $($identite.Name), eleve"

foreach ($f in @($Daemon, $Cli, (Join-Path $Racine "wintun.dll"), (Join-Path $Coeurs "sing-box.exe"), $Profil)) {
    if (-not (Test-Path $f)) { Saute "$f absent" }
}
Dire "   binaires, pilote et profil en place"

# La banniere doit etre HORS D'ATTEINTE avant le montage, sans quoi ce qu'elle
# repondra ensuite ne dira rien du chemin emprunte.
if (Joignable $BanniereHote $BannierePort 3000) {
    Dire "FAILED: ${BanniereHote}:${BannierePort} repond sans tunnel, la recette ne prouverait rien"
    exit 1
}
Dire "   temoin: la banniere est injoignable en direct"

# Et le miroir: le temoin negatif doit, lui, etre joignable au repos. Sans quoi
# son "bloque" une fois le kill switch arme ne prouverait rien - une cible
# injoignable depuis toujours se lit comme une cible bien bloquee.
if (-not (Joignable $TransportHote $TransportPort 4000)) {
    Saute "${TransportHote}:${TransportPort} est injoignable au repos: le temoin negatif ne distinguerait rien"
}
Dire "   temoin negatif: le transport du serveur repond au repos"

# Un adaptateur VPN tiers actif s'attribuerait nos resultats de routage.
$tiers = Get-NetAdapter | Where-Object {
    $_.Status -eq "Up" -and $_.InterfaceDescription -match "TunnelBear|TAP-Windows|OpenVPN"
}
if ($tiers) { Saute "un adaptateur VPN tiers est actif: $($tiers.Name -join ', ')" }

# Et rien de nous ne doit trainer d'un passage precedent: un banc qui demarre
# sur des filtres deja poses mesurerait l'etat d'avant.
if ((Filtres-Bifrost) -gt 0) {
    Saute "des filtres WFP de Bifrost sont deja poses. Rendre la machine d'abord: bifrost-daemon --cleanup-firewall"
}
if (Adaptateur-Tun) { Saute "un adaptateur Wintun traine d'un passage precedent" }
Dire "   ni filtre ni adaptateur residuels"

# --- 1. les deux filets -----------------------------------------------------

Dire "== 1. filets, armes AVANT tout le reste =="
$quand = (Get-Date).AddMinutes($FiletMinutes).ToString("HH:mm")
$cmdFilet = Join-Path $Racine "banc-coeur-filet.cmd"
Set-Content -Path $cmdFilet -Encoding ascii -Value @(
    "@echo off",
    "`"$Daemon`" --cleanup-firewall >> `"$Racine\banc-coeur-filet.log`" 2>&1"
)
schtasks /create /tn $TacheFilet /tr $cmdFilet /sc once /st $quand /ru SYSTEM /rl HIGHEST /f | Out-Null
Dire "   tache ${TacheFilet}: desarmera la machine a $quand"
shutdown /r /t 900 | Out-Null
Dire "   redemarrage de secours dans 900 s, annule a la sortie"

# --- 2. le daemon -----------------------------------------------------------

Dire "== 2. daemon avec un chemin par coeur =="
Remove-Item $Journal, "$Journal.err" -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $Configurations | Out-Null
# `debug` et non `info`: c'est a ce niveau que le passeur dit pourquoi une
# connexion n'a pas ete menee au coeur, et c'est exactement la question qu'on
# se pose quand la banniere reste muette. La pile TCP en espace utilisateur y
# dit aussi `session begins`, c'est-a-dire si un SYN est ARRIVE jusqu'a elle -
# le passeur, lui, ne voit un flux qu'une fois la poignee de main faite. La
# bibliotheque passe par `log`, que `tracing-subscriber` reprend a son compte.
#
# `ipstack=trace` n'est PAS le defaut, et c'est une mesure qui l'a decide. Le
# banc du 21 aout 2026 a 12:51 a produit 104869 lignes et rate sa banniere: le
# client a reemis son SYN deux fois, ipstack avait pourtant fabrique son SYN|ACK
# - `local.seq` avait avance - et il n'est jamais ressorti. Au meme instant une
# autre session du meme TUN echangeait ses donnees sans faute. Le meme banc a
# 02:58, machine calme, etait vert. Ecrire une ligne par paquet depuis le
# runtime qui doit justement ecrire ce paquet fait de l'instrument une charge:
# on ne mesure plus le produit. Le niveau reste disponible par `-Trace` pour le
# jour ou la question revient.
$env:BIFROST_LOG = "bifrost_daemon=debug,bifrost_firewall=info,bifrost_dns=info,ipstack=$(if ($Trace) { 'trace' } else { 'debug' })"
$proc = Start-Process -FilePath $Daemon -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput $Journal -RedirectStandardError "$Journal.err" `
    -ArgumentList @(
        "--coeurs-dans", "`"$Coeurs`"",
        "--coeurs-configurations", "`"$Configurations`"",
        "--facade", $Facade,
        "--coeur-binaire", "`"$(Join-Path $Coeurs 'sing-box.exe')`"",
        "--profil", "`"$Profil`""
    )
Dire "   pid $($proc.Id)"

$pret = $false
foreach ($i in 1..40) {
    Start-Sleep -Milliseconds 250
    if (Test-Path "\\.\pipe\bifrost-daemon") { $pret = $true; break }
}
if (-not $pret) {
    Get-Content $Journal, "$Journal.err" -ErrorAction SilentlyContinue | Select-Object -Last 20
    Dire "FAILED: le daemon n'a pas ouvert son tube nomme"
    schtasks /delete /tn $TacheFilet /f | Out-Null
    shutdown /a | Out-Null
    exit 1
}
Dire "   tube nomme ouvert"

# --- 3. connexion -----------------------------------------------------------

Dire "== 3. connect =="
& $Cli connect 2>&1 | ForEach-Object { Dire "   $_" }
Dire "   code: $LASTEXITCODE"

# --- 4. ce que le montage a pose --------------------------------------------

Dire "== 4. l'interface, et ou va le trafic =="
$tun = Adaptateur-Tun
if (-not $tun) {
    Grief "aucun adaptateur Wintun apres le montage"
} else {
    Dire "   adaptateur: $($tun.Name) [$($tun.InterfaceDescription)], etat $($tun.Status), ifIndex $($tun.ifIndex)"
    $vers = Find-NetRoute -RemoteIPAddress $BanniereHote -ErrorAction SilentlyContinue |
        Select-Object -First 1
    Dire "   route vers la banniere: ifIndex $($vers.InterfaceIndex)"
    if ($vers.InterfaceIndex -ne $tun.ifIndex) {
        Grief "le trafic vers la banniere n'entre pas dans le TUN"
    }
}

# --- 5. du trafic sort-il VRAIMENT par la, et TOUT DE SUITE -----------------

# Avant le balayage des filtres, qui lit 156000 lignes et prend plusieurs
# secondes. La premiere version mesurait apres, et la fenetre de dix secondes
# du critere de debit s'etait alors deja refermee sur le candidat. Ce motif-la
# a disparu avec le defaut, le 21 aout 2026; l'ordre reste, parce qu'une
# banniere lue tout de suite apres `connect` dit quelque chose de plus qu'une
# banniere lue apres un balayage.
Dire "== 5. la banniere repond-elle =="
$avant = Compteurs-Du-Tunnel
$vu = ""
# Deux essais courts et non trois longs. La raison a change le 21 aout 2026:
# ce n'est plus une contrainte, c'est un reste. La fenetre pendant laquelle le
# tunnel etait juge sain ne durait alors qu'une quinzaine de secondes - le
# critere de debit condamnait un tunnel au repos - et tout ce qui comptait
# devait tenir dedans. Le defaut est corrige, et l'etape 5bis plus bas mesure
# precisement qu'il l'est. On garde la forme courte parce qu'elle suffit: deux
# allers-retours disent autant que trois, et le banc a d'autres choses a faire.
foreach ($essai in 1..2) {
    $vu = Lire-Banniere $BanniereHote $BannierePort 5000
    Dire "   essai ${essai}: '$vu' [$script:Etape]"
    if ($vu) { break }
}
$apres = Compteurs-Du-Tunnel

# Les deux court-circuits, mesures dans la foulee pour que la comparaison porte
# sur le meme etat du tunnel.
Dire "   par le coeur en direct (127.0.0.1:1080): '$(Socks-Banniere '127.0.0.1:1080' $BanniereHote $BannierePort 8000)'"
Dire "   par la facade ($Facade):                 '$(Socks-Banniere $Facade $BanniereHote $BannierePort 8000)'"

if (-not $vu) {
    Grief "rien n'est revenu par le tunnel"
    # Ce que le journal a dit de CETTE cible-la. Depuis que le passeur annonce
    # les flux qu'il PREND, et pas seulement ceux qu'il rate, ces lignes
    # separent trois etats qui se ressemblaient: rien n'est entre dans la pile,
    # un flux est entre et n'a pas ete mene, un flux a ete mene et n'a rien
    # rapporte. La ligne `session begins` d'ipstack tranche la premiere.
    Dire "   ce que le passeur dit de ${BanniereHote}:"
    $dit = Get-Content $Journal -ErrorAction SilentlyContinue | Select-String -SimpleMatch $BanniereHote
    if ($dit) { $dit | ForEach-Object { Dire "     $_" } } else { Dire "     rien du tout" }
    Get-Content $Journal, "$Journal.err" -ErrorAction SilentlyContinue | Select-Object -Last 20
}

# Le versant POSITIF de la metrique: les compteurs doivent MONTER. Le versant
# negatif - ils cessent d'exister avec l'interface - etait deja mesure.
if ($avant -and $apres) {
    $dRx = $apres.rx - $avant.rx
    $dTx = $apres.tx - $avant.tx
    Dire "   compteurs du tunnel, delta recu: $dRx octets, delta emis: $dTx octets"
    if ($dRx -le 0 -or $dTx -le 0) {
        Grief "les compteurs du tunnel n'ont pas bouge: le trafic a emprunte un autre chemin"
    }
} else {
    Grief "les compteurs du tunnel n'ont pas pu etre lus"
}

# --- 5bis. le tunnel survit-il a l'ennui ------------------------------------

# Le defaut que cette etape tient: jusqu'au 21 aout 2026, un tunnel Windows
# etait condamne QUINZE SECONDES apres `connect`, sans que personne ne l'ait
# etrangle. Le critere de debit lisait la retombee du trafic de fond de Windows
# comme un throttling. Le journal du banc le disait en toutes lettres: "le debit
# est tombe de 19506 a 556 octets par seconde sur 10 s", puis `reconnecting`,
# puis `disconnected`.
#
# Quatre-vingt-dix secondes: six fois la fenetre du critere, et assez pour que
# la pointe du montage soit retombee depuis longtemps. On ne fait RIEN pendant
# ce temps - c'est tout l'interet.
#
# DEUX mesures, et il faut les deux. "Aucun candidat condamne" serait vert aussi
# si le critere etait mort, si l'observateur n'existait pas, ou si le tunnel
# etait deja tombe avant qu'on regarde. On exige donc AUSSI qu'une sonde soit
# partie: elle prouve que la question a ete POSEE, et donc que le vert vient de
# la reponse du pair et non du silence du code.
Dire "== 5bis. le tunnel survit-il a l'ennui =="
$avantRepos = @(Get-Content $Journal -ErrorAction SilentlyContinue).Count
$reposDebut = Get-Date
Start-Sleep -Seconds 90
$depuis = @(Get-Content $Journal -ErrorAction SilentlyContinue | Select-Object -Skip $avantRepos)
$condamnes = @($depuis | Select-String -SimpleMatch "candidat perdu", "le debit est tombe")
$sondes = @($depuis | Select-String -SimpleMatch "sonde de vitalite demandee")
$verdicts = @($depuis | Select-String -SimpleMatch "sonde de vitalite: verdict rendu")
$etatBrut = ((& $Cli --json status 2>$null) -join "")
$tunApres = Adaptateur-Tun
Dire "   $([int]((Get-Date) - $reposDebut).TotalSeconds) s sans rien demander, $($depuis.Count) lignes de journal"
Dire "   sondes demandees: $($sondes.Count), verdicts rendus: $($verdicts.Count)"
Dire "   etat: $etatBrut"
if ($condamnes.Count -gt 0) {
    $condamnes | ForEach-Object { Dire "     $_" }
    Grief "un tunnel au repos a ete condamne"
}
if (-not $tunApres) { Grief "l'adaptateur a disparu pendant le repos" }
if ($etatBrut -notmatch '"connected"') {
    Grief "le tunnel n'est plus connecte apres 90 s de repos"
}
if ($sondes.Count -lt 1) {
    Grief "aucune sonde en 90 s de repos: la question n'est plus posee, ce vert ne prouve rien"
}
if ($verdicts.Count -lt 1) {
    Grief "une sonde est partie et aucun verdict n'est revenu: le pair n'a pas repondu"
}

Dire "== 6. temoin negatif: hors du tunnel, rien ne sort =="
# La cible doit etre joignable SANS le tunnel, sinon ce temoin ne mesure rien.
#
# Premiere version: `1.1.1.1:443`. Elle rendait toujours PASSEE, et pour une
# raison qui n'avait rien a voir avec une fuite: cette adresse est capturee par
# le `0.0.0.0/0` du tunnel, et la pile en espace utilisateur repond elle-meme
# au SYN avant d'aller composer vers le coeur. Un `connect` a travers le TUN
# reussit donc TOUJOURS, que le trafic ressorte ou non. Le temoin mesurait la
# politesse de notre propre pile.
#
# Le transport du serveur, lui, se joint par une route on-link plus specifique
# que le `/0`: il ne passe PAS par le tunnel. Le coeur y a droit, par son
# binaire; ce processus-ci n'y a pas droit, et le kill switch doit le dire.
# C'est le meme choix que le banc Linux, qui vise le port de transport.
#
# Mesure AVANT le balayage des filtres, qui lit 156000 lignes: pose apres, elle
# tombait hors de la fenetre saine et jugeait un tunnel deja demonte.
$horsTunnel = Joignable $TransportHote $TransportPort 4000
Dire "   connexion directe vers ${TransportHote}:${TransportPort}: $(if ($horsTunnel) { 'PASSEE' } else { 'bloquee' })"
if ($horsTunnel) { Grief "une connexion hors tunnel a abouti pendant que le kill switch etait arme" }

Dire "== 7. le kill switch est-il arme =="
$filtres = Filtres-Bifrost
Dire "   lignes de filtres nommant bifrost: $filtres"
if ($filtres -lt 1) { Grief "aucun filtre WFP de Bifrost apres le montage" }

# --- 8. demontage -----------------------------------------------------------

Dire "== 8. disconnect =="
& $Cli disconnect 2>&1 | ForEach-Object { Dire "   $_" }
Dire "   code: $LASTEXITCODE"
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3

Dire "== 9. la machine est-elle rendue =="
$reste = Adaptateur-Tun
$filtresApres = Filtres-Bifrost
Dire "   adaptateur restant: $(if ($reste) { $reste.Name } else { 'aucun' })"
Dire "   lignes de filtres restantes: $filtresApres"
if ($reste) { Grief "un adaptateur est reste apres le demontage" }
if ($filtresApres -gt 0) { Grief "des filtres WFP sont restes" }

$reseau = Joignable "1.1.1.1" 443 6000
Dire "   la machine a de nouveau son reseau: $reseau"
if (-not $reseau) { Grief "la machine n'a pas retrouve son reseau" }

# --- 10. verdict ------------------------------------------------------------

schtasks /delete /tn $TacheFilet /f | Out-Null
shutdown /a | Out-Null
Dire "   filets desarmes"

Dire ""
if ($script:Griefs.Count -eq 0) {
    Dire "OK: le chemin par coeur a porte du trafic sous Windows, et la machine a ete rendue"
    try { Stop-Transcript | Out-Null } catch {}
    exit 0
}
Dire "FAILED: $($script:Griefs.Count) grief(s)"
$script:Griefs | ForEach-Object { Dire "  - $_" }
try { Stop-Transcript | Out-Null } catch {}
exit 1

# Ce que la couche 2 a REELLEMENT pose: nom ET condition exacte de chaque
# filtre, confrontes au SID que `sc showsid` rend pour la cible.
#
# A lancer sur essai-windows, en administrateur, shell cmd, depuis la racine du
# banc (le repertoire qui contient les binaires) ou avec BIFROST_BANC pose:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\telemetrie-conditions-windows.ps1
#
# CE QUE CE SCRIPT FAIT. Il LIT. Il ne pose aucun filtre, n'en retire aucun, ne
# touche a aucun service ni a aucune politique d'audit. Il prend un dump `netsh`
# frais de l'etat courant du moteur et dit, filtre par filtre, ce que chacun
# porte. Pour eprouver un blocage, c'est `telemetrie-effet-windows.ps1`; pour
# savoir seulement si les filtres sont presents, c'est
# `telemetrie-reseau-windows.ps1`. Les trois questions sont distinctes.
#
# POURQUOI IL EXISTE. Le banc d'effet comptait les filtres sans jamais lire ce
# qu'ils portent: il imprimait `filtres=8` sans pouvoir affirmer qu'un seul
# d'entre eux visait la cible qu'il pretendait eprouver. La question << le
# filtre porte-t-il le bon SID ? >> merite un instrument autonome, parce qu'on
# se la pose aussi hors de toute mesure d'effet.
#
# LE PIEGE DU DUMP. `netsh wfp show filters` rend du XML ou `<item>` sert AUSSI
# aux elements imbriques - drapeaux, conditions. Un decoupage naif sur `<item>`
# separe un filtre de son `filterId` et rend des associations plausibles et
# fausses. On charge donc le document en DOM et on selectionne par
# `//item[filterKey]`: aucun item de condition ne porte de `filterKey`.
#
# SORTIE. Code 0 si au moins un filtre pose porte exactement le SID de la cible.
# Code 1 sinon, y compris quand aucun filtre de la couche 2 n'est pose - c'est
# une reponse, pas un plantage: le moteur ne porte rien qui vise cette cible.

param(
    # La racine du banc: le repertoire du script (via -File), ou BIFROST_BANC si pose.
    [string]$Banc = $(if ($env:BIFROST_BANC) { $env:BIFROST_BANC } else { $PSScriptRoot }),
    # La cible dont on confronte le SID a ce que les filtres portent.
    [string]$Service = 'DiagTrack',
    # Un dump deja pris. Vide: le script en prend un frais et le supprime.
    [string]$Dump = '',
    # Prefixe des cles de filtre de la couche 2. Ecrit ici A LA MAIN: si le
    # script le lisait du binaire, les deux se tromperaient ensemble.
    [string]$PrefixeCle = '{3ac9d182-5e42-4b77-9d61-8e05f3a2'
)

# La racine du banc doit etre connue. Lance autrement que par -File et sans
# BIFROST_BANC, $Banc est vide et les chemins derives seraient faux.
if ([string]::IsNullOrEmpty($Banc)) {
    throw "Banc introuvable: lancer ce script par -File depuis la racine du banc (le repertoire qui contient les binaires), ou poser BIFROST_BANC sur ce repertoire."
}

$ErrorActionPreference = 'Continue'

Write-Host ('=' * 78)
Write-Host 'Conditions portees par les filtres de la couche 2'
Write-Host ("hote      : {0}" -f $env:COMPUTERNAME)
Write-Host ("windows   : {0}" -f (Get-CimInstance Win32_OperatingSystem).Version)
Write-Host ("cible     : {0}" -f $Service)
Write-Host ('=' * 78)

# Le SID que le SCM derive du nom. Le SID est insensible a la locale, seule
# l'etiquette autour ne l'est pas: on ne garde que le SID.
$sid = ''
foreach ($l in @(& sc.exe showsid $Service)) {
    $m = [regex]::Match("$l", 'S-1-5-80(-\d+)+')
    if ($m.Success) { $sid = $m.Value; break }
}
if ("$sid" -eq '') {
    Write-Host ("ECHEC: sc showsid {0} n a rendu aucun SID S-1-5-80." -f $Service)
    Write-Host '       Sans SID attendu il n y a rien a confronter.'
    exit 1
}
Write-Host ("sc showsid {0} = {1}" -f $Service, $sid)
Write-Host ''

$ephemere = $false
if ("$Dump" -eq '') {
    $Dump = Join-Path $env:SystemRoot 'Temp\bifrost-conditions.xml'
    $ephemere = $true
    if (Test-Path $Dump) { Remove-Item $Dump -Force -ErrorAction SilentlyContinue }
    $null = & netsh wfp show filters file="$Dump" 2>&1
}
if (-not (Test-Path $Dump)) {
    Write-Host ("ECHEC: pas de dump exploitable ({0})" -f $Dump)
    exit 1
}
Write-Host ("dump      : {0} ({1} octets)" -f $Dump, (Get-Item $Dump).Length)

$porteurs = @()
$code = 1
try {
    $x = New-Object System.Xml.XmlDocument
    $x.Load($Dump)
    # `//item[filterKey]`: seuls les filtres entiers portent une cle.
    $tous = @($x.SelectNodes('//item[filterKey]'))
    Write-Host ("filtres dans le moteur, tous fournisseurs confondus : {0}" -f $tous.Count)

    $nos = @($tous | Where-Object { ([string]$_.filterKey).StartsWith($PrefixeCle) })
    Write-Host ("filtres a prefixe de cle de la couche 2             : {0}" -f $nos.Count)
    Write-Host ''

    foreach ($f in $nos) {
        Write-Host ('=== ' + [string]$f.filterKey)
        Write-Host ('    nom         : ' + [string]$f.displayData.name)
        Write-Host ('    filterId    : ' + [string]$f.filterId)
        Write-Host ('    providerKey : ' + [string]$f.providerKey)
        Write-Host ('    layerKey    : ' + [string]$f.layerKey)
        Write-Host ('    subLayerKey : ' + [string]$f.subLayerKey)
        Write-Host ('    action      : ' + [string]$f.action.type)
        Write-Host ('    poids       : ' + [string]$f.effectiveWeight.uint64)
        $drapeaux = $f.SelectSingleNode('flags')
        if ($drapeaux -ne $null) {
            Write-Host ('    drapeaux    : ' + ((([string]$drapeaux.InnerXml) -replace '<[^>]+>', ' ') -replace '\s+', ' ').Trim())
        }
        $cond = $f.SelectSingleNode('filterCondition')
        if ($cond -eq $null) {
            Write-Host '    conditions  : AUCUNE'
        } else {
            $items = @($cond.SelectNodes('item'))
            Write-Host ('    conditions  : ' + $items.Count)
            foreach ($c in $items) {
                $v = ((([string]$c.conditionValue.InnerXml) -replace '\s+', ' ')).Trim()
                Write-Host ('      champ  = ' + [string]$c.fieldKey + '   match = ' + [string]$c.matchType)
                Write-Host ('      valeur = ' + $v)
                if ($v.Contains($sid)) {
                    Write-Host ('      >>> PORTE EXACTEMENT LE SID DE ' + $Service)
                    $porteurs = @($porteurs) + @([string]$f.displayData.name + '  (id ' + [string]$f.filterId + ')')
                }
            }
        }
        Write-Host ''
    }

    Write-Host ('=' * 78)
    Write-Host ('filtres portant exactement le SID de ' + $Service + ' : ' + @($porteurs).Count)
    foreach ($p in (@($porteurs) | Select-Object -Unique)) { Write-Host ('   ' + $p) }
    if (@($porteurs).Count -eq 0) {
        Write-Host ''
        Write-Host ('ECHEC: aucun filtre pose ne porte le SID de ' + $Service + '.')
        Write-Host '       Soit la couche 2 n est pas posee, soit elle vise autre chose.'
        Write-Host '       Dans les deux cas, une mesure de blocage sur cette cible ne mesurerait rien.'
        $code = 1
    } else {
        $code = 0
    }
}
finally {
    if ($ephemere) { Remove-Item $Dump -Force -ErrorAction SilentlyContinue }
}
exit $code

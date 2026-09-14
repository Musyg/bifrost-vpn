<#
.SYNOPSIS
Eprouve l'empaquetage Windows en detournant les repertoires du systeme.

.DESCRIPTION
Le pendant de scripts/packaging-linux.sh, et le meme parti pris: ne pas laisser
de trace sur la machine qui execute la recette. Sous Linux, systemd-sysusers
accepte --root et ecrit dans une racine jetable. Sous Windows il n'y a pas
d'equivalent, mais l'installateur lit %ProgramFiles% et %ProgramData% dans
l'environnement: les detourner suffit a le faire travailler dans un bac a
sable, et ce qui est mesure est exactement ce qui se produirait a
l'installation.

Le SERVICE, lui, ne se detourne pas: le gestionnaire de controle des services
est unique sur la machine. Cette recette l'installe donc pour de bon, lit ce
que le SCM a enregistre, puis le retire. Elle refuse de tourner si un service
BifrostDaemon existe deja, pour ne jamais retirer une installation reelle.

Regle non negociable, comme partout ici: ce qui ne peut pas s'executer rend
SKIPPED avec sa raison. Jamais PASSED par defaut.

.PARAMETER Binaires
Repertoire contenant bifrost-daemon.exe et bifrost-cli.exe. Par defaut
target\release a la racine du depot.

.EXAMPLE
.\scripts\packaging-windows.ps1
#>
[CmdletBinding()]
param(
    [string] $Binaires
)

$ErrorActionPreference = 'Stop'

$Racine = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
if (-not $Binaires) { $Binaires = Join-Path $Racine 'target\release' }
$Installateur = Join-Path $Racine 'packaging\install-windows.ps1'
$NomService = 'BifrostDaemon'
$CleService = "HKLM:\SYSTEM\CurrentControlSet\Services\$NomService"

$script:Echecs = 0
function Ok    ([string] $m) { Write-Host ('  OK    {0}' -f $m) }
function Fail  ([string] $m) { Write-Host ('  ECHEC {0}' -f $m); $script:Echecs++ }
function Etape ([string] $m) { Write-Host ''; Write-Host ('== {0}' -f $m) }
function Saut  ([string] $m) { Write-Host ("SKIPPED: {0}" -f $m); exit 0 }

function Est-Administrateur {
    $identite = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identite)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# SID d'une regle d'acces, jamais son nom: les noms de comptes sont traduits
# d'une machine a l'autre, les SID non. Meme regle que dans l'installateur.
function Sid-DeLaRegle ($regle) {
    try { return $regle.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }
    catch { return $regle.IdentityReference.Value }
}

# Les regles d'acces d'un chemin qui portent le SID donne. Compter PAR SID et
# non le total: sur un objet fichier l'OS peut eclater une ACE heritable en
# deux, et un total qui bouge ne dirait rien de la pose elle-meme.
function Regles-PourSid ([string] $chemin, [string] $sid) {
    $regles = @()
    foreach ($regle in (Get-Acl -LiteralPath $chemin).Access) {
        if ((Sid-DeLaRegle $regle) -eq $sid) { $regles += $regle }
    }
    return ,$regles
}

if (-not (Test-Path -LiteralPath $Installateur -PathType Leaf)) {
    throw "installateur introuvable: $Installateur"
}

Etape 'Le script d installation est analysable'
# Une erreur de syntaxe PowerShell ne se voit qu'a l'execution, donc chez qui
# installe. La faire voir ici ne coute rien et ne touche a rien - c'est aussi la
# seule etape qui tourne sans privileges.
$erreurs = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile(
    $Installateur, [ref] $null, [ref] $erreurs)
if ($erreurs -and $erreurs.Count -gt 0) {
    Fail ("l analyseur rejette l installateur: {0}" -f $erreurs[0].Message)
} else {
    Ok 'install-windows.ps1 s analyse sans erreur'
}

if (-not (Est-Administrateur)) {
    Saut 'sans droits administrateur, ni le durcissement de ProgramData ni la creation du service ne peuvent etre mesures'
}
foreach ($f in 'bifrost-daemon.exe', 'bifrost-cli.exe') {
    if (-not (Test-Path -LiteralPath (Join-Path $Binaires $f) -PathType Leaf)) {
        Saut "binaire absent: $(Join-Path $Binaires $f). Construire avec cargo build --release."
    }
}
if (Get-Service -Name $NomService -ErrorAction SilentlyContinue) {
    Saut "un service $NomService existe deja sur cette machine: cette recette le retirerait, ce qui casserait une installation reelle"
}

$Bac = Join-Path ([IO.Path]::GetTempPath()) ("bifrost-empaquetage-" + [Guid]::NewGuid().ToString('N'))
$ProgramFilesVrai = $env:ProgramFiles
$ProgramDataVrai  = $env:ProgramData

# Un faux resolveur et un faux pilote: la recette mesure que l'installateur les
# DEPOSE et que le service NOMME le premier, pas ce que dnscrypt-proxy ou
# WireGuardNT font. Une copie du daemon fait l'affaire et evite d'exiger des
# binaires tiers sur la machine de recette.
$FauxResolveur = Join-Path $Bac 'dnscrypt-proxy.exe'
$FauxPilote    = Join-Path $Bac 'wireguard.dll'

try {
    New-Item -ItemType Directory -Path $Bac | Out-Null
    Copy-Item -LiteralPath (Join-Path $Binaires 'bifrost-daemon.exe') -Destination $FauxResolveur
    Copy-Item -LiteralPath (Join-Path $Binaires 'bifrost-daemon.exe') -Destination $FauxPilote
    $env:ProgramFiles = Join-Path $Bac 'ProgramFiles'
    $env:ProgramData  = Join-Path $Bac 'ProgramData'
    New-Item -ItemType Directory -Path $env:ProgramFiles | Out-Null
    New-Item -ItemType Directory -Path $env:ProgramData  | Out-Null

    $Installation = Join-Path $env:ProgramFiles 'Bifrost'
    $Donnees      = Join-Path $env:ProgramData 'Bifrost'

    Etape 'L installateur pose ce qu il annonce'
    & $Installateur -Binaires $Binaires -Resolveur $FauxResolveur -Pilote $FauxPilote | Out-Null
    if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
        Fail "l installateur a rendu $LASTEXITCODE"
    }

    # wireguard.dll est dans la liste depuis le 22/08/2026, et il y manquait:
    # `WireGuardNt::load` la cherche a cote du binaire QUI TOURNE, donc aucun
    # tunnel ne montait depuis un service installe. Une installation qui pose
    # tout sauf le pilote demarre sans erreur et echoue au premier connect.
    foreach ($f in 'bifrost-daemon.exe', 'bifrost-cli.exe', 'dnscrypt-proxy.exe', 'wireguard.dll') {
        $c = Join-Path $Installation $f
        if (Test-Path -LiteralPath $c -PathType Leaf) { Ok "$f depose" }
        else { Fail "$f absent de $Installation" }
    }
    if (Test-Path -LiteralPath $Donnees -PathType Container) {
        Ok 'le repertoire de donnees existe'
    } else {
        Fail "$Donnees absent"
    }

    Etape 'Le repertoire de donnees n est pas ouvert a tous'
    # La mesure qui compte de cette etape. C:\ProgramData porte une ACE
    # CREATOR OWNER heritee: un repertoire cree la par un compte ordinaire lui
    # appartient, et son proprietaire peut y remplacer le profil - donc choisir
    # le serveur vers lequel le tunnel monte. Mecanique de CVE-2026-35603.
    $acl = Get-Acl -LiteralPath $Donnees
    if ($acl.AreAccessRulesProtected) {
        Ok 'heritage coupe'
    } else {
        Fail 'heritage non coupe: les ACE de ProgramData s appliquent encore'
    }
    # S-1-5-19 (LocalService, compte du resolveur depuis 11b-2) ne doit PAS y
    # figurer, ni heritable ni direct: c'est l'invariant qui protege le profil
    # (cle privee WireGuard), les configurations des coeurs, le carnet et le
    # journal. Le compte n'a des droits que sur le repertoire du resolveur
    # (lecture) et son sous-repertoire d'etat (ecriture), mesures aux deux
    # etapes suivantes. Un S-1-5-19 ici serait un intrus comme un autre.
    $autorises = @('S-1-5-18', 'S-1-5-32-544')
    $intrus = @()
    foreach ($regle in $acl.Access) {
        $sid = Sid-DeLaRegle $regle
        if ($autorises -notcontains $sid) { $intrus += $sid }
    }
    if ($intrus.Count -eq 0) {
        Ok 'seuls SYSTEM et les administrateurs y ont des droits (pas S-1-5-19)'
    } else {
        Fail ("des tiers gardent des droits: {0}" -f ($intrus -join ', '))
    }

    Etape 'Le repertoire du resolveur est ouvert en lecture seule au compte de service'
    # 11b-2 (ecart 2 du 13/09/2026). S-1-5-19 n'a des droits qu'a deux endroits
    # de %ProgramData%\Bifrost: le repertoire du resolveur (configuration et
    # liste anti-telemetrie, ecrites par le daemon; dnscrypt-proxy en fait son
    # repertoire courant), en lecture + traversee heritable et SANS AUCUN bit
    # d'ecriture - un Modify ici est un ECHEC, la configuration serait
    # reinscriptible par le resolveur -, et son sous-repertoire d'etat, en
    # Modify heritable (etape suivante).
    $RepResolveur = Join-Path $Donnees 'resolveur'
    $Etat = Join-Path $RepResolveur 'etat'
    $oi = [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $ci = [Security.AccessControl.InheritanceFlags]::ContainerInherit
    $rx = [int][Security.AccessControl.FileSystemRights]::ReadAndExecute
    $modify = [int][Security.AccessControl.FileSystemRights]::Modify
    # Tout bit qui permet d'ecrire, de supprimer ou de changer les droits:
    # specifiques (WriteData, AppendData, WriteExtendedAttributes,
    # DeleteSubdirectoriesAndFiles, WriteAttributes, Delete, ChangePermissions,
    # TakeOwnership) et generiques (GENERIC_WRITE, GENERIC_ALL), au cas ou une
    # ACE serait relue sous sa forme generique.
    $bitsEcriture = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x40000000 -bor 0x10000000
    if (Test-Path -LiteralPath $RepResolveur -PathType Container) {
        Ok 'le repertoire du resolveur existe'
        $aceRep = Regles-PourSid $RepResolveur 'S-1-5-19'
        $lecture = @($aceRep | Where-Object {
            $_.AccessControlType -eq 'Allow' -and
            (([int]$_.FileSystemRights -band $rx) -eq $rx) -and
            (($_.InheritanceFlags -band $oi) -eq $oi) -and
            (($_.InheritanceFlags -band $ci) -eq $ci)
        })
        if ($lecture.Count -ge 1) {
            Ok 'une ACE S-1-5-19 accorde la lecture et la traversee, heritables'
        } else {
            Fail 'aucune ACE S-1-5-19 n accorde la lecture heritable du repertoire du resolveur: dnscrypt-proxy ne pourra pas en faire son repertoire courant'
        }
        $ecriture = @($aceRep | Where-Object {
            $_.AccessControlType -eq 'Allow' -and (([int]$_.FileSystemRights -band $bitsEcriture) -ne 0)
        })
        if ($ecriture.Count -eq 0) {
            Ok 'aucune ACE S-1-5-19 n y accorde le moindre bit d ecriture'
        } else {
            Fail ("le repertoire du resolveur est inscriptible par S-1-5-19 ({0}): sa configuration et sa liste seraient reinscriptibles par le resolveur" -f $ecriture[0].FileSystemRights)
        }
    } else {
        Fail "$RepResolveur absent: l installateur doit creer le repertoire du resolveur"
    }

    Etape 'Le sous-repertoire d etat du resolveur est ouvert en ecriture au compte de service'
    # Le SEUL endroit que S-1-5-19 peut ecrire: Modify heritable aux fichiers
    # et aux sous-repertoires, en plus de la lecture heritee du parent.
    if (Test-Path -LiteralPath $Etat -PathType Container) {
        Ok 'le repertoire d etat existe'
        $aceLs = Regles-PourSid $Etat 'S-1-5-19'
        $bonne = @($aceLs | Where-Object {
            $_.AccessControlType -eq 'Allow' -and
            (([int]$_.FileSystemRights -band $modify) -eq $modify) -and
            (($_.InheritanceFlags -band $oi) -eq $oi) -and
            (($_.InheritanceFlags -band $ci) -eq $ci)
        })
        if ($bonne.Count -ge 1) {
            Ok 'une ACE S-1-5-19 accorde Modify, heritable aux fichiers et aux sous-repertoires'
        } else {
            Fail 'aucune ACE S-1-5-19 n accorde Modify heritable sur le repertoire d etat: le resolveur ne pourra pas y ecrire'
        }

        # Idempotence: rejouer l installation dans le meme bac a sable ne doit
        # pas faire grossir le compte d ACE portant S-1-5-19, sur aucun des deux
        # repertoires. Par SID, jamais le total. Le service existe et est
        # arrete: l installateur le retire et le recree, ce qui est son chemin
        # normal de reinstallation.
        $avantRep = (Regles-PourSid $RepResolveur 'S-1-5-19').Count
        $avantEtat = (Regles-PourSid $Etat 'S-1-5-19').Count
        & $Installateur -Binaires $Binaires -Resolveur $FauxResolveur -Pilote $FauxPilote | Out-Null
        if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
            Fail "la seconde installation a rendu $LASTEXITCODE"
        }
        $apresRep = (Regles-PourSid $RepResolveur 'S-1-5-19').Count
        $apresEtat = (Regles-PourSid $Etat 'S-1-5-19').Count
        if ($avantRep -eq $apresRep -and $avantEtat -eq $apresEtat) {
            Ok "rejouer l installation laisse $apresRep ACE S-1-5-19 sur le repertoire du resolveur et $apresEtat sur l etat (idempotent)"
        } else {
            Fail "rejouer l installation a fait passer les ACE S-1-5-19 de $avantRep/$avantEtat a $apresRep/$apresEtat (repertoire/etat)"
        }
        # Et $Donnees n a toujours rien accorde au compte apres la seconde passe.
        if ((Regles-PourSid $Donnees 'S-1-5-19').Count -eq 0) {
            Ok 'apres la seconde passe, S-1-5-19 n a toujours aucun droit sur le repertoire de donnees'
        } else {
            Fail 'la seconde passe a ouvert le repertoire de donnees a S-1-5-19'
        }
    } else {
        Fail "$Etat absent: l installateur doit creer le repertoire d etat du resolveur"
    }

    Etape 'Le service enregistre nomme le resolveur'
    $service = Get-Service -Name $NomService -ErrorAction SilentlyContinue
    if (-not $service) {
        Fail "le service $NomService n a pas ete cree"
    } else {
        Ok "service $NomService cree"
        if ($service.Status -eq 'Stopped') {
            Ok 'il n est pas demarre, comme annonce'
        } else {
            Fail "il est en etat $($service.Status): l installateur ne doit rien demarrer"
        }

        # Le registre plutot que `sc qc`: la sortie de sc.exe est traduite, les
        # noms de valeurs du registre non. Meme regle que les SID.
        $cle = Get-ItemProperty -Path $CleService
        $ligne = $cle.ImagePath
        Write-Host ("        ligne enregistree: {0}" -f $ligne)

        if ($cle.Start -eq 2) {
            Ok 'demarrage automatique'
        } else {
            Fail "demarrage $($cle.Start) au lieu de 2 (automatique)"
        }
        if ($cle.DependOnService -contains 'BFE') {
            Ok 'depend de la Base Filtering Engine'
        } else {
            Fail 'ne depend pas de BFE: il pourrait demarrer avant le moteur qui pose ses filtres'
        }

        # LA mesure de cette tranche. Jusqu'ici la ligne du service etait
        # "exe" --service, sans le resolveur: le service ne pouvait donc pas en
        # lancer un, meme avec le binaire depose a cote de lui.
        if ($ligne -match '--resolveur-binaire') {
            Ok 'la ligne porte --resolveur-binaire'
        } else {
            Fail 'la ligne ne nomme aucun resolveur: le service n en lancera pas'
        }
        $cite = '"' + (Join-Path $Installation 'dnscrypt-proxy.exe') + '"'
        if ($ligne.Contains($cite)) {
            Ok 'le chemin du resolveur y est cite'
        } else {
            Fail "le chemin du resolveur n est pas cite tel quel: $cite attendu"
        }

        # 11b-2: la ligne porte aussi le compte de service du resolveur, cite
        # EXACTEMENT comme spec::ligne_de_commande l'ecrit: la forme canonique
        # LocalService entre guillemets, apres le binaire. Jamais le nom
        # affiche localise, qui ne se resout pas.
        if ($ligne -match '--resolveur-utilisateur') {
            Ok 'la ligne porte --resolveur-utilisateur'
        } else {
            Fail 'la ligne ne nomme aucun compte pour le resolveur: il tournerait sous le compte du service'
        }
        $compteCite = '--resolveur-utilisateur "LocalService"'
        if ($ligne.Contains($compteCite)) {
            Ok 'le compte LocalService y est cite tel quel'
        } else {
            Fail "le compte du resolveur n est pas cite tel quel: $compteCite attendu"
        }
        if ($ligne.IndexOf('--resolveur-utilisateur') -gt $ligne.IndexOf('--resolveur-binaire')) {
            Ok 'le compte vient apres le binaire'
        } else {
            Fail 'le compte devrait venir apres le binaire dans la ligne'
        }
    }
} finally {
    # Le filet. Un service laisse derriere soi pointerait vers un chemin
    # supprime, et la recette suivante refuserait de tourner a cause de lui.
    if (Get-Service -Name $NomService -ErrorAction SilentlyContinue) {
        & (Join-Path (Join-Path $env:ProgramFiles 'Bifrost') 'bifrost-daemon.exe') --uninstall-service 2>&1 | Out-Null
    }
    $env:ProgramFiles = $ProgramFilesVrai
    $env:ProgramData  = $ProgramDataVrai
    if (Test-Path -LiteralPath $Bac) {
        Remove-Item -LiteralPath $Bac -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Etape 'Rien n est reste derriere'
if (Get-Service -Name $NomService -ErrorAction SilentlyContinue) {
    Fail "le service $NomService subsiste"
} else {
    Ok 'aucun service residuel'
}
if (Test-Path -LiteralPath $Bac) {
    Fail "le bac a sable subsiste: $Bac"
} else {
    Ok 'bac a sable efface'
}

Write-Host ''
if ($script:Echecs -gt 0) {
    Write-Host ("empaquetage Windows: {0} echec(s)" -f $script:Echecs)
    exit 1
}
Write-Host 'empaquetage Windows: tout est conforme'

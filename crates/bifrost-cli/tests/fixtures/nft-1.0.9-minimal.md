# Provenance de la capture synthetique

`nft-1.0.9-minimal.json` conserve le ruleset nft JSON du cas 0 du banc
`scripts/preuve-nft-linux.sh`, commit 20d23f2, runner Ubuntu jetable, nft 1.0.9.
Source: https://github.com/Musyg/bifrost-vpn/actions/runs/36339080600/job/108675486277

Commande: `nft --json --numeric list ruleset`, dans le namespace du banc,
apres application de `bifrost-firewall::linux::ruleset::render`.
Intention: schema 1, interface/marque/coeur/resolveur null, allow_lan false,
dns_resolver 127.0.0.1. Aucune donnee utilisateur ni interface externe.
Seuls les espaces JSON ont ete reformates; handles, compteurs et metainfo
sont conserves. Cette fixture n'est pas une preuve de l'etat d'un poste.

Elle garde les deux formes observees qui ont fait echouer la premiere
reference: toutes les chaines avant les regles, et les bits ct state [2,4]
avec --numeric. Le banc reel reste requis pour les autres combinaisons.

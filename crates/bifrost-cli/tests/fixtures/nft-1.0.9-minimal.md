# Provenance de la capture synthetique

`nft-1.0.9-minimal.json` conserve le ruleset nft JSON du cas 0 de la boucle des
64 politiques de `scripts/preuve-nft-linux.sh`, collecte le 02/10/2026 dans un
namespace reseau jetable d'un hote d'essai Linux, nft 1.0.9, apres application
de `bifrost-firewall::linux::ruleset::render` par `nft -f`. Elle a ete
regeneree quand le rendu du DHCP a change (DHCPv4 en IPv4 seulement, client
DHCPv6 vers ses groupes). La capture precedente venait d'un runner Ubuntu
jetable de la CI (commit 20d23f2); la meme collecte, sur le rendu d'avant ce
changement, la reproduisait a l'identique, handle de la table excepte.

Commande: `nft --json --numeric list ruleset`, dans le namespace du banc.
Intention: schema 1, interface/marque/coeur/resolveur null, allow_lan false,
dns_resolver 127.0.0.1. Aucune donnee utilisateur ni interface externe.
Seuls les espaces JSON ont ete reformates (un objet par ligne); handles,
compteurs et metainfo sont conserves. Cette fixture n'est pas une preuve de
l'etat d'un poste.

Elle garde les formes observees que la reference doit reproduire: toutes les
chaines avant les regles, les bits ct state [2,4] avec --numeric,
`meta nfproto ipv4` rendu par sa valeur 2, et un ensemble anonyme qui mele un
prefixe et des adresses, dans l'ordre ou nft le liste. Le banc reel reste
requis pour les autres combinaisons.

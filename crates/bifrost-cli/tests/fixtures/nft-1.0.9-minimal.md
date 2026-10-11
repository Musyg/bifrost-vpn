# Provenance de la capture synthetique

`nft-1.0.9-minimal.json` conserve le ruleset nft JSON du cas 0 de la boucle des
64 politiques de `scripts/preuve-nft-linux.sh`, collecte le 11/10/2026 dans un
namespace reseau jetable d'un hote d'essai Linux, nft 1.0.9, apres application
de `bifrost-firewall::linux::ruleset::render` par `nft -f`. Elle a ete
regeneree quand la sortie du DHCP a change (DHCPv4 vers la diffusion seule,
client DHCPv6 vers ses deux groupes seuls). La capture precedente avait ete
collectee le 02/10/2026 de la meme facon; la meme collecte, sur le rendu
d'avant ce changement, la reproduisait octet pour octet, handles compris.
Celle d'avant encore venait d'un runner Ubuntu jetable de la CI (commit
20d23f2).

Commande: `nft --json --numeric list ruleset`, dans le namespace du banc.
Intention: schema 1, interface/marque/coeur/resolveur null, allow_lan false,
dns_resolver 127.0.0.1. Aucune donnee utilisateur ni interface externe.
Seuls les espaces JSON ont ete reformates (un objet par ligne); handles,
compteurs et metainfo sont conserves. Cette fixture n'est pas une preuve de
l'etat d'un poste.

Elle garde les formes observees que la reference doit reproduire: toutes les
chaines avant les regles, les bits ct state [2,4] avec --numeric,
`meta nfproto ipv4` rendu par sa valeur 2 (reponse du serveur DHCPv4, en
entree), `ip daddr 255.255.255.255` liste sans `meta nfproto` (sortie du
DHCPv4), et des ensembles anonymes d'adresses et de types ICMPv6, dans l'ordre
ou nft les liste. Elle ne porte plus d'ensemble qui mele un prefixe et des
adresses. Le banc reel reste requis pour les autres combinaisons.

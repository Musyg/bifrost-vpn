#!/usr/bin/env bash
# Banc jetable: toutes les mutations nft restent dans NOTRE namespace isole.
set -euo pipefail
if [ "$(id -u)" != 0 ]; then
  echo 'Ce banc exige root pour creer son namespace jetable.' >&2
  exit 2
fi
RACINE=$(cd "$(dirname "$0")/.." && pwd)
CLI="$RACINE/target/debug/bifrost-cli"
for outil in ip nft jq setpriv cmp; do command -v "$outil" >/dev/null; done
test -x "$CLI"
BAC=$(mktemp -d)
NS="bfproof-$$"
CREE=0
nettoyer() {
  local code=$?
  if [ "$code" != 0 ]; then
    for rapport in match ecart refus vide politique; do
      if [ -f "$BAC/$rapport.json" ]; then cat "$BAC/$rapport.json"; fi
    done
  fi
  if [ "$CREE" = 1 ]; then ip netns del "$NS" || true; fi
  rm -rf -- "$BAC"
  return "$code"
}
trap nettoyer EXIT
cp "$CLI" "$BAC/bifrost-cli"
CLI="$BAC/bifrost-cli"
chmod 755 "$BAC" "$CLI"
ip netns add "$NS"
CREE=1
# Sans interface physique ni veth: aucun trafic ne peut sortir de ce namespace.
ip netns exec "$NS" nft -f - <<'NFT'
table inet bifrost_preuve {
  chain output {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    counter
  }
}
NFT
ip netns exec "$NS" nft --json --numeric list ruleset > "$BAC/reference.json"
chmod 755 "$BAC"
chmod 644 "$BAC/reference.json"
ip netns exec "$NS" "$CLI" --json prove nft --attendu "$BAC/reference.json" --actif > "$BAC/match.json"
jq -e '.verdict == "MATCH" and .scope == "nft-kernel-comparison" and .live_kernel and .generation_verified and .network_security == "not-evaluated"' "$BAC/match.json" >/dev/null
ip netns exec "$NS" nft --json --numeric list ruleset > "$BAC/apres.json"
cmp "$BAC/reference.json" "$BAC/apres.json"
echo 'PASSED: collecte reelle, generation stable, aucune regle modifiee'

ip netns exec "$NS" nft add rule inet bifrost_preuve output accept
CODE=0
ip netns exec "$NS" "$CLI" --json prove nft --attendu "$BAC/reference.json" --actif > "$BAC/ecart.json" || CODE=$?
test "$CODE" = 1
jq -e '.verdict == "MISMATCH" and .generation_verified and (.differences | index("rules") != null)' "$BAC/ecart.json" >/dev/null
echo 'PASSED: une exception ajoutee devient un ecart'

CODE=0
ip netns exec "$NS" setpriv --reuid=65534 --regid=65534 --clear-groups "$CLI" --json prove nft --attendu "$BAC/reference.json" --actif > "$BAC/refus.json" || CODE=$?
test "$CODE" = 2
jq -e '.verdict == "UNMEASURED" and (.generation_verified | not) and .reason == "acces noyau refuse; aucune elevation automatique"' "$BAC/refus.json" >/dev/null
echo 'PASSED: un acces refuse ne devient jamais une absence de regle'

ip netns exec "$NS" nft delete table inet bifrost_preuve
CODE=0
ip netns exec "$NS" "$CLI" --json prove nft --attendu "$BAC/reference.json" --actif > "$BAC/vide.json" || CODE=$?
test "$CODE" = 1
jq -e '.verdict == "MISMATCH" and .observed_counts.tables == 0 and .generation_verified' "$BAC/vide.json" >/dev/null
echo 'PASSED: la disparition du pare-feu devient un ecart'

# Confronter la reference pure au VRAI generateur utilise par le daemon.
# Six dimensions binaires: interface, marque, LAN, coeur, resolveur et DNS v6.
# Le helper ne fait que rendre du texte; seul nft dans NOTRE namespace le pose.
RENDU="$RACINE/target/debug/examples/politique_nft"
test -x "$RENDU"
for ((cas=0; cas<64; cas++)); do
  jq -n --argjson n "$cas" '{schema_version:1,
    tunnel_interface:(if ($n % 2) == 1 then "wg0" else null end),
    fwmark:(if (($n / 2 | floor) % 2) == 1 then 51820 else null end),
    allow_lan:((($n / 4 | floor) % 2) == 1),
    coeur_uid:(if (($n / 8 | floor) % 2) == 1 then 1001 else null end),
    resolveur_uid:(if (($n / 16 | floor) % 2) == 1 then 1002 else null end),
    dns_resolver:(if (($n / 32 | floor) % 2) == 1 then "::1" else "127.0.0.1" end)
  }' > "$BAC/intention.json"
  "$RENDU" "$BAC/intention.json" > "$BAC/produit.nft"
  ip netns exec "$NS" nft -f "$BAC/produit.nft"
  ip netns exec "$NS" nft --json --numeric list ruleset > "$BAC/produit.json"
  if ! "$CLI" --json prove nft --politique "$BAC/intention.json" --observe "$BAC/produit.json" > "$BAC/politique.json"; then
    echo "reference produit en ecart, cas synthetique $cas"
    # Pas de donnees utilisateur dans ce banc: montrer les deux formes utiles.
    "$RENDU" "$BAC/intention.json" json | jq .
    jq . "$BAC/produit.json"
    exit 1
  fi
  jq -e '.verdict == "MATCH" and .expected_source == "bifrost-policy-v1-user-declared" and .policy_schema_version == 1 and (.live_kernel | not)' "$BAC/politique.json" >/dev/null
  ip netns exec "$NS" "$CLI" --json prove nft --politique "$BAC/intention.json" --actif > "$BAC/politique.json"
  jq -e '.verdict == "MATCH" and .generation_verified and .live_kernel and .network_security == "not-evaluated"' "$BAC/politique.json" >/dev/null
  ip netns exec "$NS" nft --json --numeric list ruleset > "$BAC/apres.json"
  cmp "$BAC/produit.json" "$BAC/apres.json"
done
echo 'PASSED: 64 politiques produit, reference hors ligne et collecte reelle, sans mutation'

# Une politique tierce ne doit pas disparaitre de la comparaison.
ip netns exec "$NS" nft add table inet tiers
CODE=0
ip netns exec "$NS" "$CLI" --json prove nft --politique "$BAC/intention.json" --actif > "$BAC/politique.json" || CODE=$?
test "$CODE" = 1
jq -e '.verdict == "MISMATCH" and (.differences | index("tables") != null)' "$BAC/politique.json" >/dev/null
ip netns exec "$NS" nft delete table inet tiers

# Un permis non prevu ne doit jamais devenir conforme au plan produit.
ip netns exec "$NS" nft insert rule inet bifrost output accept
CODE=0
ip netns exec "$NS" "$CLI" --json prove nft --politique "$BAC/intention.json" --actif > "$BAC/politique.json" || CODE=$?
test "$CODE" = 1
jq -e '.verdict == "MISMATCH" and (.differences | index("rules") != null)' "$BAC/politique.json" >/dev/null
echo 'PASSED: table tierce et permis ajoute detectes contre le plan produit'

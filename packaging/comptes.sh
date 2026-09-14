#!/usr/bin/env bash
# Creation des comptes systeme de Bifrost, quand `systemd-sysusers` est absent.
#
# Ce fichier existe pour une seule raison: la voie de repli n'avait jamais
# tourne nulle part. essai-linux a systemd-sysusers, la recette d'empaquetage
# aussi, et le repli n'etait donc verifie que par comparaison de TEXTE - on
# grepait ses options dans l'installateur et on les comparait a la declaration.
# Une comparaison de texte ne voit ni ce que `useradd` fait vraiment, ni ce
# qu'il refuse, ni le compte qu'il produit. Elle n'avait d'ailleurs pas vu que
# le repli donnait aux deux comptes le MEME commentaire.
#
# Sorti de l'installateur pour que la recette appelle la fonction elle-meme,
# dans une racine jetable, plutot qu'une transcription qui derive.
#
# A sourcer, pas a executer.

# Lit dans le fichier declaratif les trois proprietes d'un compte, et REFUSE
# plutot que de deviner.
#
# Un repli qui, faute d'avoir su lire, poserait un shell vide ouvrirait sur les
# distributions sans sysusers exactement ce que le fichier declaratif ferme
# ailleurs - et il le ferait en silence, l'installation se terminant par un OK.
# Le format lu est celui de sysusers.d(5):
#   u <nom> <id> "<gecos>" <repertoire> <shell>
comptes_lire_declaration() {
  local declaration="$1" compte="$2" ligne reste champ
  ligne=$(grep "^u  *$compte " "$declaration" || true)
  [ -n "$ligne" ] || { echo "REFUS: $compte absent de $declaration" >&2; return 1; }
  DECL_GECOS=$(printf '%s' "$ligne" | awk -F'"' '{print $2}')
  reste=$(printf '%s' "$ligne" | awk -F'"' '{print $3}')
  DECL_HOME=$(printf '%s' "$reste" | awk '{print $1}')
  DECL_SHELL=$(printf '%s' "$reste" | awk '{print $2}')
  for champ in "$DECL_GECOS" "$DECL_HOME" "$DECL_SHELL"; do
    [ -n "$champ" ] || {
      echo "REFUS: proprietes illisibles pour $compte dans $declaration" >&2
      return 1
    }
  done
}

# Ce compte ou ce groupe existe-t-il deja.
#
# Sans prefixe on interroge NSS, qui voit aussi les annuaires distants: c'est
# la bonne question a poser sur une vraie machine, ou un compte LDAP du meme
# nom doit compter. Avec un prefixe on lit les fichiers, NSS n'ayant aucune
# notion de racine alternative. La difference est reelle et tenue ici, en un
# seul endroit, plutot que dispersee dans les appelants.
comptes_existe() {
  local prefixe="$1" base="$2" nom="$3"
  if [ -z "$prefixe" ]; then
    getent "$base" "$nom" >/dev/null
  else
    grep -q "^$nom:" "$prefixe/etc/$base"
  fi
}

# Cree le groupe de pilotage et les comptes de service a la main.
#
#   comptes_creer_a_la_main <declaration> <groupe_pilotage> <prefixe> <compte...>
#
# `<prefixe>` vide pour une vraie installation. Non vide, il designe une racine
# jetable ou `groupadd` et `useradd` ecrivent leurs fichiers sans toucher a la
# machine: c'est ainsi que la recette exerce CE code, et non sa transcription.
# Un prefixe contenant une espace n'est pas supporte, faute de tableau en sh
# portable; les racines jetables de `mktemp -d` n'en portent pas.
comptes_creer_a_la_main() {
  local declaration="$1" groupe_pilotage="$2" prefixe="$3"
  shift 3
  local opt_prefixe="" compte
  [ -n "$prefixe" ] && opt_prefixe="--prefix $prefixe"

  comptes_existe "$prefixe" group "$groupe_pilotage" ||
    groupadd $opt_prefixe --system "$groupe_pilotage"

  for compte in "$@"; do
    comptes_existe "$prefixe" passwd "$compte" && continue
    comptes_lire_declaration "$declaration" "$compte" || return 1
    # C'est `--gid` qui pose le groupe primaire, et lui seul. Mesure sur
    # essai-linux le 21/08/2026, shadow-utils 4.13, dans une racine jetable:
    # avec `--gid`, retirer `--no-user-group` ne change RIEN, que
    # `USERGROUPS_ENAB` vaille yes ou no; et meme sans `--gid` du tout,
    # `useradd --system` cree un groupe prive portant le nom du compte au lieu
    # de le verser dans `users`. Une version anterieure de ce commentaire
    # attribuait la propriete a `--no-user-group` et nommait `users` comme le
    # danger: ni l'un ni l'autre ne se verifie ici.
    #
    # `--no-user-group` reste, en ceinture: il est explicite, il ne coute rien,
    # et cet installateur tourne justement sur les distributions qu'on ne peut
    # pas eprouver depuis ce depot. Mais la recette n'en fait PLUS sa preuve -
    # elle mesure le groupe obtenu, pas la presence du drapeau. Un drapeau dont
    # on ne peut pas montrer qu'il mord ne doit pas etre presente comme la
    # garde.
    comptes_existe "$prefixe" group "$compte" ||
      groupadd $opt_prefixe --system "$compte"
    # Les proprietes viennent de la declaration, jamais recopiees ici.
    # Recopiees, elles avaient deja diverge: les deux comptes recevaient le
    # meme commentaire "Bifrost service account", la ou la declaration en donne
    # un par role - et ces deux roles sont OPPOSES, l'un exempte du kill
    # switch, l'autre jamais. Sur une distribution sans sysusers, qui lit
    # `getent passwd` ne pouvait pas les distinguer.
    useradd $opt_prefixe --system --no-user-group --gid "$compte" \
            --home-dir "$DECL_HOME" --no-create-home \
            --shell "$DECL_SHELL" \
            --comment "$DECL_GECOS" "$compte"
  done
}

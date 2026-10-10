# Servir et renouveler security.txt

`packaging/security.txt` est la source versionnee du fichier RFC 9116 du
logiciel. Le depot est public; le fichier est publie a la main par le
proprietaire du projet, sur le site de l'editeur.

## Le servir sur le site

1. Copier `packaging/security.txt` tel quel vers l'emplacement canonique du
   site: `https://inaricom.com/.well-known/security.txt`.
2. Le servir en HTTPS uniquement, avec l'en-tete
   `Content-Type: text/plain; charset=utf-8` (exige par la RFC 9116).
3. Verifier que l'URL repond bien en `https`, sans redirection vers `http`.
4. Ne pas editer le contenu a la main sur le site: toute modification passe par
   `packaging/security.txt` dans le depot, puis une nouvelle copie.

## Le renouveler

Le champ `Expires` doit rester dans le futur et sous un an. La garde de source
`crates/bifrost-evasion/tests/security_txt_a_jour.rs` rougit des que la date
tombe a moins de 30 jours de maintenant: c'est le rappel de renouvellement.

Pour renouveler:

1. Editer `Expires` dans `packaging/security.txt`, en ISO 8601 UTC, a environ
   dix mois dans le futur.
2. Relancer `cargo test -p bifrost-evasion` et verifier que la garde repasse au
   vert.
3. Recopier le fichier sur le site (section precedente).

## La cle de chiffrement publiee

Une cle OpenPGP est publiee pour le canal de signalement (arbitrage 11 du
10/10/2026; l'arbitrage 9 du 05/09/2026 l'avait differee):

- fichier: `packaging/bifrost-security.asc`, partie publique seule, en armure
  ASCII, un seul bloc;
- champ `Encryption` de `packaging/security.txt`: la copie brute de ce fichier
  sur la branche main du depot du code,
  `https://raw.githubusercontent.com/Musyg/bifrost-vpn/main/packaging/bifrost-security.asc`;
- identite `Bifrost security <security@inaricom.com>`;
- cle primaire ed25519 (signature et certification), empreinte
  `EEC9 B157 0FC1 336B EA0B  96E9 1E5F 702B 41B3 976C`;
- sous-cle de chiffrement cv25519, empreinte
  `A671 C507 2265 A2C1 DF33  2D78 C4AC C377 A817 665B`;
- creee le 2026-10-10, expire le 2028-10-09.

Le statut de cle de `SECURITY.md` (le jeton lu par la garde) dit que la cle est
presente. La garde exige la coherence des deux fichiers (cle annoncee dans les
deux, ou dans aucun), que `Encryption` designe le fichier brut de ce depot sur
main, et que ce fichier existe au chemin que l'URL nomme, en ASCII, avec
exactement un bloc de cle publique et aucun bloc de cle privee. Elle ne calcule
pas l'empreinte: celle-ci se verifie par
`gpg --show-keys --with-fingerprint --with-subkey-fingerprints packaging/bifrost-security.asc`.

La partie privee, sa phrase de passe et le certificat de revocation ne passent
jamais par le depot: l'editeur les garde hors ligne.

### La renouveler avant le 2028-10-09

1. Avant l'echeance, prolonger la cle (nouvelle date d'expiration, meme
   empreinte) ou la remplacer par une nouvelle cle.
2. Exporter la partie publique en armure ASCII et remplacer
   `packaging/bifrost-security.asc` au meme chemin: l'URL du champ `Encryption`
   ne change pas.
3. Reporter la nouvelle date d'expiration, et la nouvelle empreinte si la cle a
   ete remplacee, dans `SECURITY.md` (francais et anglais), dans le commentaire
   d'en-tete de `packaging/security.txt` et dans cette section.
4. Relancer `cargo test -p bifrost-evasion` (la garde doit rester verte) et
   relire l'empreinte du fichier publie par gpg.
5. Recopier `packaging/security.txt` sur le site de l'editeur (section "Le
   servir sur le site"). Le fichier servi doit suivre chaque changement de
   `packaging/security.txt`, cle comprise: c'est lui qui porte l'empreinte hors
   du depot.

### La revoquer

Si la cle est compromise ou perdue:

1. Remplacer `packaging/bifrost-security.asc` par la cle publique revoquee (la
   partie publique avec sa signature de revocation, rien de prive), pour que
   ceux qui la detiennent apprennent qu'elle ne vaut plus.
2. Tant qu'aucune cle de remplacement n'est publiee: basculer le statut de cle
   de `SECURITY.md` vers l'autre etat, retirer la ligne `Encryption` de
   `packaging/security.txt`, et reecrire les passages de `SECURITY.md` et
   l'en-tete de `packaging/security.txt` qui decrivent la cle. La garde exige
   ces deux changements ensemble.
3. Recopier `packaging/security.txt` sur le site de l'editeur.
4. Une cle de remplacement se publie ensuite comme au renouvellement par
   remplacement, avec retour du statut de cle et de la ligne `Encryption`.

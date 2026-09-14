# Servir et renouveler security.txt

`packaging/security.txt` est la source versionnee du fichier RFC 9116 du
produit. Le depot est prive; le fichier est publie a la main par le
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

## Ajouter une cle de chiffrement plus tard

Aucune cle PGP n'est publiee pour l'instant (arbitrage 9 du 05/09/2026). Le jour
ou une cle existera:

1. Publier la cle a une URL stable en HTTPS.
2. Ajouter dans `packaging/security.txt` une ligne
   `Encryption: https://.../cle.txt`.
3. Basculer le statut de cle dans `SECURITY.md` (le jeton lu par la garde).
4. La garde exige alors la coherence: cle annoncee dans les deux fichiers, ou
   dans aucun.

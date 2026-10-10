# Securite de Bifrost

<!--
  Statut de la cle de chiffrement, lu par la garde de source
  crates/bifrost-evasion/tests/security_txt_a_jour.rs. Ne pas ecrire ailleurs
  dans ce fichier le jeton de l'etat oppose: la garde compte les deux et rougit
  si les deux apparaissent.
  CLE-PGP=presente
  La cle publiee est packaging/bifrost-security.asc; le champ Encryption de
  packaging/security.txt pointe sur sa copie brute dans la branche main. La
  garde exige la coherence des deux fichiers (cle annoncee des deux cotes, ou
  d'aucun) et que le fichier designe par Encryption soit dans le depot, en
  ASCII, avec un seul bloc de cle publique et aucun bloc de cle privee.
  Avant l'expiration (2028-10-09): prolonger la cle ou la remplacer, publier la
  cle mise a jour au meme chemin, reporter la date (et l'empreinte si la cle
  change) dans les deux sections ci-dessous, dans packaging/security.txt et
  dans packaging/SECURITY-TXT.md, puis recopier packaging/security.txt sur le
  site de l'editeur.
  En cas de revocation sans cle de remplacement: publier la cle revoquee au
  meme chemin, basculer le jeton ci-dessus vers l'autre etat, retirer le champ
  Encryption de packaging/security.txt et reecrire les deux sections. La
  procedure detaillee est dans packaging/SECURITY-TXT.md.
-->

<!--
  Valeurs proposees, a confirmer par l'editeur. Le delai d'accuse de reception
  (5 jours ouvres) et la fenetre de divulgation coordonnee (90 jours) ne
  proviennent ni d'une mesure ni du document 07: ce sont des valeurs usuelles de
  VDP. A confirmer ou corriger avant toute publication.
-->

## Francais

### Signaler une vulnerabilite

Ecrivez a security@inaricom.com. C'est un alias sur le domaine de l'editeur
(Inaricom). Il n'y a pas de programme de primes.

### Chiffrer votre rapport

Une cle OpenPGP est publiee pour ce canal. Chiffrez avec elle tout ce qui est
sensible: details d'exploitation, preuve de concept, donnees personnelles,
secrets. N'envoyez en clair que ce que vous pourriez publier.

- Fichier: packaging/bifrost-security.asc dans ce depot. Le champ Encryption
  de packaging/security.txt pointe sur sa copie brute:
  https://raw.githubusercontent.com/Musyg/bifrost-vpn/main/packaging/bifrost-security.asc
- Identite: `Bifrost security <security@inaricom.com>`.
- Empreinte complete de la cle primaire (ed25519, signature et certification):
  `EEC9 B157 0FC1 336B EA0B  96E9 1E5F 702B 41B3 976C`.
- Sous-cle de chiffrement (cv25519):
  `A671 C507 2265 A2C1 DF33  2D78 C4AC C377 A817 665B`.
- Creee le 2026-10-10, expire le 2028-10-09.

Verifiez l'empreinte avant de chiffrer, par exemple avec:

    gpg --show-keys --with-fingerprint --with-subkey-fingerprints bifrost-security.asc

et comparez-la a celle ecrite ici et a celle du security.txt servi par le site
de l'editeur, qui vient d'une autre origine que ce depot. Si elles different, si
la cle a expire ou si elle a ete revoquee, n'envoyez rien de sensible: ecrivez
d'abord sans details.

### Ce qu'un bon rapport contient

- une description de la vulnerabilite et de son impact;
- les versions, l'hote et l'environnement ou vous l'avez observee;
- les etapes de reproduction, aussi precises que possible;
- une preuve de concept si vous en avez une;
- toute proposition de correction, si vous en voyez une.

### Perimetre

Le code de ce depot: le daemon, la ligne de commande (CLI) et les crates. Les
documents (docs/, README.md, ETAT.md) ne sont pas dans le perimetre.

Hors perimetre: le deni de service volumetrique, l'ingenierie sociale, et les
machines de l'editeur (postes, serveurs, infrastructure). Ces sujets ne relevent
pas de ce canal.

### Notre engagement

Accuse de reception sous 5 jours ouvres. Divulgation coordonnee: publication a
90 jours, ou plus tot d'un commun accord (valeurs proposees, a confirmer). En
equipe de 1, le fondateur cumule les roles; les delais sont tenus au mieux.

Pas de safe harbor juridique ici: le document
docs/07-programme-securite-produit.md recense le safe harbor comme un element
attendu d'une politique de divulgation et renvoie au modele disclose.io, mais ne
porte aucun engagement de l'editeur en ce sens. Aucune phrase de non-poursuite
n'est donc ecrite tant que cet engagement n'a pas ete tranche.

## English

### Reporting a vulnerability

Email security@inaricom.com. It is an alias on the publisher's domain
(Inaricom). There is no bug bounty.

### Encrypting your report

An OpenPGP key is published for this channel. Use it to encrypt anything
sensitive: exploitation details, proof of concept, personal data, secrets. Only
send in the clear what you could publish.

- File: packaging/bifrost-security.asc in this repository. The Encryption field
  of packaging/security.txt points to its raw copy:
  https://raw.githubusercontent.com/Musyg/bifrost-vpn/main/packaging/bifrost-security.asc
- Identity: `Bifrost security <security@inaricom.com>`.
- Full fingerprint of the primary key (ed25519, signing and certification):
  `EEC9 B157 0FC1 336B EA0B  96E9 1E5F 702B 41B3 976C`.
- Encryption subkey (cv25519):
  `A671 C507 2265 A2C1 DF33  2D78 C4AC C377 A817 665B`.
- Created on 2026-10-10, expires on 2028-10-09.

Check the fingerprint before encrypting, for instance with:

    gpg --show-keys --with-fingerprint --with-subkey-fingerprints bifrost-security.asc

and compare it with the one written here and with the one in the security.txt
served by the publisher's site, which comes from a different origin than this
repository. If they differ, or if the key has expired or been revoked, do not
send anything sensitive: write first without details.

### What a good report contains

- a description of the vulnerability and its impact;
- the versions, host and environment where you observed it;
- reproduction steps, as precise as possible;
- a proof of concept if you have one;
- any proposed fix, if you see one.

### Scope

The code in this repository: the daemon, the command line (CLI) and the crates.
The documents (docs/, README.md, ETAT.md) are out of scope.

Out of scope: volumetric denial of service, social engineering, and the
publisher's machines (workstations, servers, infrastructure). Those are not
handled through this channel.

### Our commitment

Acknowledgement within 5 business days. Coordinated disclosure: publication at
90 days, or sooner by mutual agreement (proposed values, to be confirmed). As a
team of one, the founder wears every hat; timelines are met on a best-effort
basis.

No legal safe harbor is stated here: the document
docs/07-programme-securite-produit.md lists a safe harbor as an expected element
of a disclosure policy and points to the disclose.io template, but carries no
such commitment from the publisher. No no-prosecution statement is written until
that commitment has been decided.

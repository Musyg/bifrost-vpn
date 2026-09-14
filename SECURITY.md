# Securite de Bifrost

<!--
  Statut de la cle de chiffrement, lu par la garde de source
  crates/bifrost-evasion/tests/security_txt_a_jour.rs. Ne pas ecrire ailleurs
  dans ce fichier le jeton de l'etat oppose: la garde compte les deux et rougit
  si les deux apparaissent.
  CLE-PGP=absente
  Quand une cle PGP existera: basculer le jeton ci-dessus de absente vers l'autre
  etat, publier la cle, et ajouter un champ Encryption dans
  packaging/security.txt. La garde exige alors la coherence des deux fichiers:
  cle annoncee des deux cotes, ou d'aucun.
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
(Inaricom). Il n'y a ni programme de primes, ni cle PGP publiee pour l'instant:
n'envoyez pas de secret que vous ne pourriez pas envoyer en clair. Une cle de chiffrement pourra
etre ajoutee plus tard; quand elle existera, elle sera publiee et le champ
Encryption de packaging/security.txt pointera dessus.

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
(Inaricom). There is no bug bounty and no PGP key published for now: do not send
any secret you could not send in the clear. An encryption key may be added later;
when it exists it will be published and the Encryption field of
packaging/security.txt will point to it.

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

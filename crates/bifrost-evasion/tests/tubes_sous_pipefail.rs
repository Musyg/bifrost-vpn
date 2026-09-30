//! Aucun lecteur qui s'arrete avant la fin d'un tube, dans les scripts shell et
//! dans les etapes du workflow; et toute etape du workflow qui porte un tube
//! tourne sous `pipefail`.
//!
//! # Pourquoi cette recette existe
//!
//! Sous `set -o pipefail`, une pipeline rend le code de son dernier element en
//! echec. Un lecteur qui sort avant d'avoir tout lu (`grep -q`, `grep -m`,
//! `head`, `sed ...q`, `awk ... exit`) ferme le tube pendant que le producteur
//! ecrit encore: le producteur meurt de SIGPIPE, rend 141, et la pipeline
//! echoue ALORS QUE le lecteur a trouve ce qu'il cherchait. Un
//! `if producteur | grep -q X` prend la branche << absent >> en silence.
//!
//! Le 29/09/2026 le banc `preuve-nft-linux.sh` est tombe ainsi apres un MATCH,
//! sur un `nft list chain | grep -qF`; trois lignes de ce script ont ete
//! corrigees, les soixante-treize autres du depot non. Mesure du 30/09/2026 sur
//! essai-linux, sans privilege, la pipeline de `banc-cdn-linux.sh` qui verifie
//! qu'un port est libre (`ss -lnt | grep -q ":$p "`), recopiee telle quelle et
//! jouee sur la table de sockets de l'hote pour un port OCCUPE: 0 erreur sur
//! 20000 sur un hote libre, 4985 << port libre >> sur 5000 quand le banc est
//! confine a un coeur, 4070 sur 5000 a deux coeurs. `ss` y ecrit en deux
//! `write(2)`; le lecteur sort entre les deux des qu'il obtient le processeur.
//! La meme mesure sur l'en-tete de `ci/abstentions-attendues-linux.txt`, lu
//! par `abstentions-budget.sh` en CI: 4 << en-tete sans date >> a tort sur
//! 5000 a un coeur. Le defaut depend donc de l'ordonnanceur, pas du texte: un
//! producteur benin aujourd'hui (un seul `printf` court) ne l'est que tant que
//! personne n'allonge sa sortie.
//!
//! # Ce qu'elle exige
//!
//! 1. Aucune commande qui lit un tube (celle qui suit `|` ou `|&`) ne s'arrete
//!    avant la fin de son entree: ni `grep` avec `-q`, `--quiet`, `--silent`,
//!    `-m`, `--max-count`, `-l` ou `-L`; ni `head`; ni `sed` dont le script
//!    porte `q` ou `Q`; ni `awk` dont le programme porte `exit`; ni `read`,
//!    `true` ou `:`. Un lecteur compose (`while`, `{ }`, `( )`, `if`, `case`,
//!    `[[ ]]`) est REFUSE: la recette ne sait pas dire s'il lit tout, elle ne
//!    le croit pas sur parole. Formes admises: `grep ... >/dev/null` (lit tout,
//!    meme verdict), `sed -n 1p` ou `sed -n 1,Np` (au lieu de `head`),
//!    `cut -c 1-N` (au lieu de `head -c N` sur une ligne), ou pas de tube
//!    du tout (`grep -q X fichier`, here-string, variable). La regle vaut
//!    aussi dans `$(...)`, les accents graves et `<(...)`, meme la ou le code
//!    ne compte pas (un affichage, une substitution de processus): une
//!    exemption demanderait de savoir si le code compte (`set -e`, dernier
//!    element d'une fonction, `$?` relu plus bas), et c'est ce jugement
//!    qu'une recette ne sait pas porter.
//! 2. Perimetre: tout fichier `.sh` du depot, tout fichier dont la premiere
//!    ligne est un shebang `sh` ou `bash`, et le corps `run:` de chaque etape
//!    de `.github/workflows/` dont le shell n'est pas declare autre que
//!    `bash`/`sh`. Un script est juge qu'il pose `pipefail` ou non: un fichier
//!    source herite des options de son appelant (`packaging/comptes.sh`), et
//!    un `set -o pipefail` ajoute plus tard ne doit pas reveiller un defaut
//!    endormi. Lire l'etat des options serait exactement l'analyse qu'un
//!    lexeur maison rate.
//! 3. Toute etape du workflow dont le corps porte un tube declare le shell
//!    `bash`, sur l'etape ou en `defaults.run.shell` du job ou du workflow.
//!    GitHub ne pose `-o pipefail` que dans ce cas: une etape sans `shell`
//!    tourne sous `bash -e {0}` (documentation << Workflow syntax >>, table
//!    des valeurs de `shell`, relevee le 30/09/2026; actions/runner#1955), et
//!    `./scripts/recettes-strict.sh | tee journal` y rend le code de `tee`, 0,
//!    quelle que soit la suite.
//!
//! # Ce qu'elle ne fait pas
//!
//! Elle ne lit pas le shell ecrit dans une chaine d'un autre langage (un
//! `bash -c "..."` dans un `.rs`, un `subprocess` en Python). Elle ne voit pas
//! un `grep MOTIF FICHIER` place apres un tube (il ne lit pas le tube du
//! tout). Dans le corps d'un document en ligne non cite, elle ne lit que les
//! substitutions `$(...)` et les accents graves; un corps cite n'est pas du
//! shell. Elle ne demande pas git: le parcours se fait sur le disque, comme ses
//! voisines, parce que la copie d'essai-linux n'a pas de `.git`.
//!
//! Le lexeur est maison, et un lexeur maison se fait tromper par les
//! litteraux: les commentaires, les chaines, les continuations `\`, les motifs
//! de `case`, `[[ ]]`, `$(( ))`, `||` et `>|` ont chacun leur recette de
//! falsification plus bas, et une construction qu'il ne sait pas fermer
//! (guillemet, `$(`, document en ligne sans delimiteur) fait ROUGIR la recette
//! au lieu de lui faire sauter la fin du fichier.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

fn racine() -> PathBuf {
    // Meme idiome que `caracteres_de_controle.rs` et ses voisines:
    // `CARGO_MANIFEST_DIR` pointe sur crates/bifrost-evasion, la racine de
    // l'espace de travail est deux crans au-dessus.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("la racine de l'espace de travail doit exister")
        .to_path_buf()
}

// ===================================================================== lexeur

/// Une commande qui lit un tube: celle qui suit un `|` ou un `|&`.
#[derive(Debug, Clone)]
struct Lecteur {
    ligne: usize,
    mots: Vec<String>,
    /// Le tube alimente une commande composee (`while`, `{ }`, `( )`...).
    composee: bool,
}

#[derive(Debug, Default)]
struct Analyse {
    lecteurs: Vec<Lecteur>,
    tubes: usize,
}

struct Heredoc {
    delimiteur: Vec<u8>,
    tabs: bool,
    cite: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EtatCase {
    Sujet,
    Motif,
    Corps,
}

/// La commande en cours de lecture dans une liste.
#[derive(Default)]
struct Commande {
    mots: Vec<String>,
    ligne: Option<usize>,
    apres_tube: bool,
    ligne_tube: usize,
    composee: bool,
}

impl Commande {
    /// Un tube vient d'etre lu et rien ne le suit encore: un saut de ligne ne
    /// clot pas la pipeline (`a |` en fin de ligne continue a la suivante).
    fn attend_son_lecteur(&self) -> bool {
        self.apres_tube && self.mots.is_empty() && !self.composee
    }
}

struct Lexeur<'a> {
    s: &'a [u8],
    i: usize,
    decalage: usize,
    sauts: Vec<usize>,
    heredocs: Vec<Heredoc>,
    sortie: Analyse,
}

fn est_affectation(mot: &str) -> bool {
    let Some((nom, _)) = mot.split_once('=') else {
        return false;
    };
    let mut octets = nom.bytes();
    matches!(octets.next(), Some(b) if b.is_ascii_alphabetic() || b == b'_')
        && octets.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

impl<'a> Lexeur<'a> {
    fn new(texte: &'a str, decalage: usize) -> Self {
        let s = texte.as_bytes();
        let sauts = s
            .iter()
            .enumerate()
            .filter(|(_, b)| **b == b'\n')
            .map(|(k, _)| k)
            .collect();
        Self {
            s,
            i: 0,
            decalage,
            sauts,
            heredocs: Vec::new(),
            sortie: Analyse::default(),
        }
    }

    fn ligne(&self, pos: usize) -> usize {
        self.decalage + self.sauts.partition_point(|&k| k < pos) + 1
    }

    fn octet(&self, k: usize) -> u8 {
        self.s.get(self.i + k).copied().unwrap_or(0)
    }

    fn erreur(&self, pos: usize, quoi: &str) -> String {
        format!("ligne {}: {quoi}", self.ligne(pos))
    }

    fn avancer(&mut self, n: usize) {
        self.i = (self.i + n).min(self.s.len());
    }

    // ------------------------------------------------------------- litteraux

    fn simple_quote(&mut self) -> Result<(), String> {
        let debut = self.i;
        match self.s[self.i + 1..].iter().position(|b| *b == b'\'') {
            Some(k) => {
                self.i += k + 2;
                Ok(())
            }
            None => Err(self.erreur(debut, "apostrophe jamais refermee")),
        }
    }

    fn ansi_quote(&mut self) -> Result<(), String> {
        let debut = self.i;
        let mut j = self.i + 2;
        loop {
            match self.s.get(j) {
                None => return Err(self.erreur(debut, "chaine $'...' jamais refermee")),
                Some(b'\\') => j += 2,
                Some(b'\'') => break,
                Some(_) => j += 1,
            }
        }
        self.i = j + 1;
        Ok(())
    }

    fn double_quote(&mut self) -> Result<(), String> {
        let debut = self.i;
        self.i += 1;
        loop {
            match self.s.get(self.i).copied() {
                None => return Err(self.erreur(debut, "guillemet jamais referme")),
                Some(b'\\') => self.avancer(2),
                Some(b'"') => {
                    self.i += 1;
                    return Ok(());
                }
                Some(b'$') if self.octet(1) == b'(' => self.dollar_paren()?,
                Some(b'$') if self.octet(1) == b'{' => self.accolade(true)?,
                Some(b'`') => self.accent_grave()?,
                Some(_) => self.i += 1,
            }
        }
    }

    /// `${...}`. Dans des guillemets, une apostrophe y est un caractere.
    fn accolade(&mut self, dans_guillemets: bool) -> Result<(), String> {
        let debut = self.i;
        self.i += 2;
        let mut profondeur = 1usize;
        loop {
            match self.s.get(self.i).copied() {
                None => return Err(self.erreur(debut, "${ jamais referme")),
                Some(b'\\') => self.avancer(2),
                Some(b'\'') if !dans_guillemets => self.simple_quote()?,
                Some(b'"') => self.double_quote()?,
                Some(b'$') if self.octet(1) == b'(' => self.dollar_paren()?,
                Some(b'$') if self.octet(1) == b'{' => {
                    self.i += 2;
                    profondeur += 1;
                }
                Some(b'`') => self.accent_grave()?,
                Some(b'}') => {
                    self.i += 1;
                    profondeur -= 1;
                    if profondeur == 0 {
                        return Ok(());
                    }
                }
                Some(_) => self.i += 1,
            }
        }
    }

    /// `$(( ... ))` ou `(( ... ))`: arithmetique, ou `|` est un OU binaire.
    fn arithmetique(&mut self, ouvrant: usize) -> Result<(), String> {
        let debut = self.i;
        self.i += ouvrant;
        let mut profondeur = 0usize;
        loop {
            match self.s.get(self.i).copied() {
                None => return Err(self.erreur(debut, "arithmetique jamais refermee")),
                Some(b'(') => profondeur += 1,
                Some(b')') if profondeur == 0 => {
                    if self.octet(1) == b')' {
                        self.i += 2;
                        return Ok(());
                    }
                    return Err(self.erreur(debut, "arithmetique mal refermee"));
                }
                Some(b')') => profondeur -= 1,
                Some(_) => {}
            }
            self.i += 1;
        }
    }

    fn dollar_paren(&mut self) -> Result<(), String> {
        if self.octet(2) == b'(' {
            return self.arithmetique(3);
        }
        let debut = self.i;
        self.i += 2;
        self.liste(Some(b')'))?;
        if self.octet(0) != b')' {
            return Err(self.erreur(debut, "$( jamais referme"));
        }
        self.i += 1;
        Ok(())
    }

    /// Accents graves: le contenu est lexe comme une liste a part.
    fn accent_grave(&mut self) -> Result<(), String> {
        let debut = self.i;
        let mut j = self.i + 1;
        loop {
            match self.s.get(j) {
                None => return Err(self.erreur(debut, "accent grave jamais referme")),
                Some(b'\\') => j += 2,
                Some(b'`') => break,
                Some(_) => j += 1,
            }
        }
        let interieur = String::from_utf8_lossy(&self.s[debut + 1..j]).into_owned();
        let mut sous = Lexeur::new(&interieur, self.ligne(debut) - 1);
        sous.liste(None)?;
        self.sortie.tubes += sous.sortie.tubes;
        self.sortie.lecteurs.extend(sous.sortie.lecteurs);
        self.i = j + 1;
        Ok(())
    }

    /// Un mot: rend (texte brut, texte sans guillemets).
    fn mot(&mut self) -> Result<Option<(String, String)>, String> {
        let debut = self.i;
        let mut nu: Vec<u8> = Vec::new();
        while let Some(&c) = self.s.get(self.i) {
            match c {
                b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b'(' | b')' | b'<' | b'>' => break,
                b'\\' => {
                    let suivant = self.octet(1);
                    if suivant != b'\n' && suivant != 0 {
                        nu.push(suivant);
                    }
                    self.avancer(2);
                }
                b'\'' => {
                    let d = self.i;
                    self.simple_quote()?;
                    nu.extend_from_slice(&self.s[d + 1..self.i - 1]);
                }
                b'$' if self.octet(1) == b'\'' => {
                    let d = self.i;
                    self.ansi_quote()?;
                    nu.extend_from_slice(&self.s[d + 2..self.i - 1]);
                }
                b'"' => {
                    let d = self.i;
                    self.double_quote()?;
                    nu.extend_from_slice(&self.s[d + 1..self.i - 1]);
                }
                b'$' if self.octet(1) == b'(' => {
                    let d = self.i;
                    self.dollar_paren()?;
                    nu.extend_from_slice(&self.s[d..self.i]);
                }
                b'$' if self.octet(1) == b'{' => {
                    let d = self.i;
                    self.accolade(false)?;
                    nu.extend_from_slice(&self.s[d..self.i]);
                }
                b'`' => {
                    let d = self.i;
                    self.accent_grave()?;
                    nu.extend_from_slice(&self.s[d..self.i]);
                }
                _ => {
                    nu.push(c);
                    self.i += 1;
                }
            }
        }
        if self.i == debut {
            return Ok(None);
        }
        Ok(Some((
            String::from_utf8_lossy(&self.s[debut..self.i]).into_owned(),
            String::from_utf8_lossy(&nu).into_owned(),
        )))
    }

    fn blancs(&mut self) {
        while let Some(&c) = self.s.get(self.i) {
            if c == b' ' || c == b'\t' {
                self.i += 1;
            } else if c == b'\\' && self.octet(1) == b'\n' {
                self.i += 2;
            } else {
                break;
            }
        }
    }

    // ------------------------------------------------------- documents en ligne

    /// Appele juste apres un saut de ligne: saute le corps de chaque document
    /// en ligne ouvert sur la ligne qui s'acheve, et lit les substitutions
    /// d'un corps non cite.
    fn documents_en_ligne(&mut self) -> Result<(), String> {
        for h in std::mem::take(&mut self.heredocs) {
            let debut = self.i;
            let mut fin_corps = None;
            while self.i < self.s.len() {
                let fin = self.s[self.i..]
                    .iter()
                    .position(|b| *b == b'\n')
                    .map_or(self.s.len(), |k| self.i + k);
                let mut l = &self.s[self.i..fin];
                if h.tabs {
                    while let [b'\t', reste @ ..] = l {
                        l = reste;
                    }
                }
                let debut_ligne = self.i;
                self.i = (fin + 1).min(self.s.len());
                if l == h.delimiteur.as_slice() {
                    fin_corps = Some(debut_ligne);
                    break;
                }
            }
            let Some(fin_corps) = fin_corps else {
                return Err(self.erreur(
                    debut,
                    &format!(
                        "document en ligne sans son delimiteur `{}`",
                        String::from_utf8_lossy(&h.delimiteur)
                    ),
                ));
            };
            if !h.cite {
                let reprise = self.i;
                self.substitutions(debut, fin_corps)?;
                self.i = reprise;
            }
        }
        Ok(())
    }

    /// Les substitutions d'un texte ou les guillemets sont des caracteres.
    fn substitutions(&mut self, debut: usize, fin: usize) -> Result<(), String> {
        self.i = debut;
        while self.i < fin {
            match self.s[self.i] {
                b'\\' => self.avancer(2),
                b'$' if self.octet(1) == b'(' => self.dollar_paren()?,
                b'$' if self.octet(1) == b'{' => self.accolade(true)?,
                b'`' => self.accent_grave()?,
                _ => self.i += 1,
            }
        }
        if self.i > fin {
            return Err(self.erreur(debut, "substitution qui deborde de son document en ligne"));
        }
        Ok(())
    }

    // --------------------------------------------------------------- listes

    fn clore(&mut self, cmd: &mut Commande) {
        if cmd.apres_tube && (cmd.composee || !cmd.mots.is_empty()) {
            self.sortie.lecteurs.push(Lecteur {
                ligne: cmd.ligne.unwrap_or(cmd.ligne_tube),
                mots: std::mem::take(&mut cmd.mots),
                composee: cmd.composee,
            });
        }
        *cmd = Commande::default();
    }

    fn marquer_composee(&self, cmd: &mut Commande, pos: usize) {
        if cmd.apres_tube && cmd.mots.is_empty() && !cmd.composee {
            cmd.composee = true;
            cmd.ligne = Some(self.ligne(pos));
        }
    }

    fn redirection(&mut self) -> Result<(), String> {
        let debut = self.i;
        let reste = &self.s[self.i..];
        if reste.starts_with(b"<<<") {
            self.i += 3;
            self.blancs();
            self.mot()?;
            return Ok(());
        }
        if reste.starts_with(b"<<") {
            self.i += 2;
            let tabs = self.octet(0) == b'-';
            if tabs {
                self.i += 1;
            }
            self.blancs();
            let Some((brut, nu)) = self.mot()? else {
                return Err(self.erreur(debut, "document en ligne sans delimiteur"));
            };
            self.heredocs.push(Heredoc {
                delimiteur: nu.into_bytes(),
                tabs,
                cite: brut.contains(['\'', '"', '\\']),
            });
            return Ok(());
        }
        if self.octet(1) == b'(' {
            // Substitution de processus: une liste a part, qui ne lit pas CE tube.
            self.i += 2;
            self.liste(Some(b')'))?;
            if self.octet(0) != b')' {
                return Err(self.erreur(debut, "substitution de processus jamais refermee"));
            }
            self.i += 1;
            return Ok(());
        }
        // `>`, `>>`, `>&`, `<&`, `<>`, `>|`: l'operateur, puis sa cible.
        self.i += 1;
        while matches!(self.octet(0), b'<' | b'>' | b'&' | b'|') {
            self.i += 1;
        }
        self.blancs();
        self.mot()?;
        Ok(())
    }

    /// Lexe une liste de commandes jusqu'a `fermant` (exclu) ou la fin.
    fn liste(&mut self, fermant: Option<u8>) -> Result<(), String> {
        let mut cmd = Commande::default();
        let mut cases: Vec<EtatCase> = Vec::new();
        let mut en_condition = false;
        loop {
            self.blancs();
            let Some(&c) = self.s.get(self.i) else {
                self.clore(&mut cmd);
                return match fermant {
                    None => Ok(()),
                    Some(f) => Err(self.erreur(
                        self.i,
                        &format!("`{}` attendu avant la fin du texte", f as char),
                    )),
                };
            };
            let en_motif = cases.last() == Some(&EtatCase::Motif);
            if Some(c) == fermant && !en_condition && !en_motif {
                self.clore(&mut cmd);
                return Ok(());
            }
            if c == b'#' {
                while !matches!(self.s.get(self.i), None | Some(b'\n')) {
                    self.i += 1;
                }
                continue;
            }
            if c == b'\n' {
                self.i += 1;
                if !en_condition && !cmd.attend_son_lecteur() {
                    self.clore(&mut cmd);
                }
                self.documents_en_ligne()?;
                continue;
            }
            if en_motif {
                // Motif de `case`: `|` y separe des alternatives.
                match c {
                    b')' => {
                        self.i += 1;
                        if let Some(e) = cases.last_mut() {
                            *e = EtatCase::Corps;
                        }
                    }
                    b'|' | b'(' => self.i += 1,
                    _ => match self.mot()? {
                        Some((brut, _)) if brut == "esac" => {
                            cases.pop();
                            self.clore(&mut cmd);
                        }
                        Some(_) => {}
                        None => self.i += 1,
                    },
                }
                continue;
            }
            if en_condition {
                // `[[ ... ]]`: `|`, `<`, `&&` y sont des operateurs de test.
                if matches!(c, b'|' | b'&' | b'<' | b'>' | b'(' | b')' | b';') {
                    self.i += 1;
                } else {
                    match self.mot()? {
                        Some((brut, _)) if brut == "]]" => en_condition = false,
                        Some(_) => {}
                        None => self.i += 1,
                    }
                }
                continue;
            }
            match c {
                b'|' => {
                    if self.octet(1) == b'|' {
                        self.i += 2;
                        self.clore(&mut cmd);
                        continue;
                    }
                    let pos = self.i;
                    self.i += if self.octet(1) == b'&' { 2 } else { 1 };
                    self.sortie.tubes += 1;
                    self.clore(&mut cmd);
                    cmd.apres_tube = true;
                    cmd.ligne_tube = self.ligne(pos);
                }
                b'&' => {
                    if self.octet(1) == b'&' {
                        self.i += 2;
                        self.clore(&mut cmd);
                    } else if self.octet(1) == b'>' {
                        self.i += 2;
                        if self.octet(0) == b'>' {
                            self.i += 1;
                        }
                        self.blancs();
                        self.mot()?;
                    } else {
                        self.i += 1;
                        self.clore(&mut cmd);
                    }
                }
                b';' => {
                    if self.octet(1) == b';' || self.octet(1) == b'&' {
                        self.i += 2;
                        if self.octet(0) == b'&' {
                            self.i += 1;
                        }
                        self.clore(&mut cmd);
                        if let Some(e) = cases.last_mut() {
                            *e = EtatCase::Motif;
                        }
                    } else {
                        self.i += 1;
                        self.clore(&mut cmd);
                    }
                }
                b'<' | b'>' => self.redirection()?,
                b'(' => {
                    let pos = self.i;
                    self.marquer_composee(&mut cmd, pos);
                    if self.octet(1) == b'(' {
                        self.arithmetique(2)?;
                    } else {
                        self.i += 1;
                        self.liste(Some(b')'))?;
                        if self.octet(0) != b')' {
                            return Err(self.erreur(pos, "sous-shell jamais referme"));
                        }
                        self.i += 1;
                    }
                }
                b')' => return Err(self.erreur(self.i, "parenthese fermante sans ouvrante")),
                _ => self.mot_de_commande(&mut cmd, &mut cases, &mut en_condition)?,
            }
        }
    }

    fn mot_de_commande(
        &mut self,
        cmd: &mut Commande,
        cases: &mut Vec<EtatCase>,
        en_condition: &mut bool,
    ) -> Result<(), String> {
        let pos = self.i;
        let Some((brut, nu)) = self.mot()? else {
            self.i += 1;
            return Ok(());
        };
        // Le descripteur d'une redirection (`2>&1`) n'est pas un argument.
        if brut.bytes().all(|b| b.is_ascii_digit()) && matches!(self.octet(0), b'<' | b'>') {
            return Ok(());
        }
        if cmd.mots.is_empty() {
            match brut.as_str() {
                "[[" => {
                    self.marquer_composee(cmd, pos);
                    *en_condition = true;
                    return Ok(());
                }
                "case" => {
                    self.marquer_composee(cmd, pos);
                    cases.push(EtatCase::Sujet);
                    cmd.mots.push(nu);
                    return Ok(());
                }
                "while" | "until" | "if" | "{" | "for" | "select" => {
                    self.marquer_composee(cmd, pos);
                    return Ok(());
                }
                "then" | "elif" | "else" | "do" | "!" | "time" | "function" | "fi" | "done"
                | "}" => return Ok(()),
                "esac" => {
                    cases.pop();
                    return Ok(());
                }
                _ => {}
            }
        }
        if cases.last() == Some(&EtatCase::Sujet) && brut == "in" {
            if let Some(e) = cases.last_mut() {
                *e = EtatCase::Motif;
            }
            cmd.mots.clear();
            return Ok(());
        }
        if cmd.ligne.is_none() {
            cmd.ligne = Some(self.ligne(pos));
        }
        cmd.mots.push(nu);
        Ok(())
    }
}

/// Lexe un texte shell. `decalage`: lignes qui precedent le texte dans son
/// fichier (le corps d'une etape de workflow ne commence pas a la ligne 1).
fn analyser(texte: &str, decalage: usize) -> Result<Analyse, String> {
    let mut lx = Lexeur::new(texte, decalage);
    lx.liste(None)?;
    if !lx.heredocs.is_empty() {
        return Err("document en ligne ouvert sur la derniere ligne, sans corps".into());
    }
    Ok(lx.sortie)
}

// ================================================================ classement

/// Le nom de la commande reellement executee et ses arguments, une fois
/// retirees les affectations (`LC_ALL=C grep`) et les enveloppes courantes.
fn commande_effective(mots: &[String]) -> (&str, &[String]) {
    let mut k = 0;
    loop {
        while k < mots.len() && est_affectation(&mots[k]) {
            k += 1;
        }
        let Some(m) = mots.get(k) else {
            return ("", &[]);
        };
        // Les options de l'enveloppe qui prennent une valeur dans le mot suivant.
        let a_valeur: &[&str] = match m.as_str() {
            "env" => &["-u", "-C", "-S"],
            "sudo" => &[
                "-u", "-g", "-p", "-U", "-C", "-D", "-R", "-T", "-r", "-t", "-h",
            ],
            "nice" => &["-n"],
            "stdbuf" => &["-i", "-o", "-e"],
            "exec" => &["-a"],
            "command" | "builtin" | "nohup" => &[],
            "timeout" => &["-s", "-k"],
            "ip" if mots.get(k + 1).is_some_and(|x| x == "netns")
                && mots.get(k + 2).is_some_and(|x| x == "exec") =>
            {
                k += 4;
                continue;
            }
            _ => return (m.as_str(), &mots[k + 1..]),
        };
        let enveloppe = m.as_str();
        k += 1;
        while let Some(o) = mots.get(k) {
            if o == "--" {
                k += 1;
                break;
            }
            if !o.starts_with('-') || o.len() < 2 {
                break;
            }
            k += if a_valeur.contains(&o.as_str()) { 2 } else { 1 };
        }
        if enveloppe == "timeout" {
            k += 1; // la duree
        }
    }
}

/// `grep` qui sort au premier resultat, ou apres N, ou au premier fichier.
fn grep_s_arrete(args: &[String]) -> Option<String> {
    const LONGUES_A_VALEUR: [&str; 13] = [
        "--regexp",
        "--file",
        "--after-context",
        "--before-context",
        "--context",
        "--directories",
        "--devices",
        "--label",
        "--include",
        "--exclude",
        "--exclude-from",
        "--exclude-dir",
        "--binary-files",
    ];
    let mut k = 0;
    while let Some(a) = args.get(k) {
        if a == "--" {
            break;
        }
        if let Some(longue) = a.strip_prefix("--") {
            let nom = longue.split('=').next().unwrap_or("");
            match nom {
                "quiet" | "silent" | "max-count" | "files-with-matches" | "files-without-match" => {
                    return Some(format!("--{nom}"));
                }
                _ => {}
            }
            if !a.contains('=') && LONGUES_A_VALEUR.contains(&a.as_str()) {
                k += 1;
            }
        } else if a.len() > 1 && a.starts_with('-') {
            let grappe = &a.as_bytes()[1..];
            for (j, o) in grappe.iter().enumerate() {
                match o {
                    b'q' | b'm' | b'l' | b'L' => return Some(format!("-{}", *o as char)),
                    b'e' | b'f' | b'A' | b'B' | b'C' | b'd' | b'D' => {
                        if j + 1 == grappe.len() {
                            k += 1; // la valeur est le mot suivant
                        }
                        break; // le reste de la grappe est la valeur
                    }
                    _ => {}
                }
            }
        }
        k += 1;
    }
    None
}

/// Parcourt une adresse `sed` (nombre, `$`, `/re/`, `\cREc`, `first~step`).
fn sed_adresse(p: &[u8], mut i: usize) -> usize {
    match p.get(i) {
        Some(b) if b.is_ascii_digit() || *b == b'+' || *b == b'~' => {
            i += 1;
            while p.get(i).is_some_and(|b| b.is_ascii_digit() || *b == b'~') {
                i += 1;
            }
        }
        Some(b'$') => i += 1,
        Some(b'/') => {
            i = sed_delimite(p, i, 1);
            while matches!(p.get(i), Some(b'I' | b'M')) {
                i += 1;
            }
        }
        Some(b'\\') => {
            i = sed_delimite(p, i + 1, 1);
            while matches!(p.get(i), Some(b'I' | b'M')) {
                i += 1;
            }
        }
        _ => {}
    }
    i
}

/// Saute `parties` champs delimites par `p[i]` (comme `match_slash` de GNU
/// sed: seul l'antislash protege le delimiteur, pas les crochets).
fn sed_delimite(p: &[u8], mut i: usize, parties: usize) -> usize {
    let Some(&d) = p.get(i) else {
        return i;
    };
    i += 1;
    for _ in 0..parties {
        while let Some(&b) = p.get(i) {
            if b == d {
                break;
            }
            i += if b == b'\\' { 2 } else { 1 };
        }
        i += 1;
    }
    i
}

fn jusqu_a(p: &[u8], mut i: usize, arrets: &[u8]) -> usize {
    while p.get(i).is_some_and(|b| !arrets.contains(b)) {
        i += 1;
    }
    i
}

/// Vrai si le script `sed` porte une commande `q` ou `Q`.
fn sed_script_s_arrete(p: &[u8]) -> bool {
    let mut i = 0;
    loop {
        while matches!(p.get(i), Some(b' ' | b'\t' | b'\n' | b';')) {
            i += 1;
        }
        if i >= p.len() {
            return false;
        }
        i = sed_adresse(p, i);
        while matches!(p.get(i), Some(b' ' | b'\t')) {
            i += 1;
        }
        if p.get(i) == Some(&b',') {
            i += 1;
            while matches!(p.get(i), Some(b' ' | b'\t')) {
                i += 1;
            }
            i = sed_adresse(p, i);
        }
        while matches!(p.get(i), Some(b' ' | b'\t' | b'!')) {
            i += 1;
        }
        let Some(&c) = p.get(i) else {
            return false;
        };
        i += 1;
        match c {
            b'q' | b'Q' => return true,
            b's' => {
                i = sed_delimite(p, i, 2);
                // drapeaux; `w fichier` court jusqu'a la fin de la ligne
                while let Some(&b) = p.get(i) {
                    if matches!(b, b';' | b'\n' | b'}') {
                        break;
                    }
                    if b == b'w' {
                        i = jusqu_a(p, i, b"\n");
                        break;
                    }
                    i += 1;
                }
            }
            b'y' => i = sed_delimite(p, i, 2),
            b'a' | b'i' | b'c' | b'r' | b'R' | b'w' | b'W' | b'e' | b'#' => {
                i = jusqu_a(p, i, b"\n");
            }
            b':' | b'b' | b't' | b'T' => i = jusqu_a(p, i, b";\n"),
            _ => {}
        }
    }
}

fn sed_s_arrete(args: &[String]) -> Option<String> {
    let mut scripts: Vec<&str> = Vec::new();
    let mut operandes: Vec<&str> = Vec::new();
    let mut k = 0;
    let mut fin_options = false;
    while let Some(a) = args.get(k) {
        k += 1;
        if fin_options || a == "-" || !a.starts_with('-') {
            operandes.push(a);
            continue;
        }
        if a == "--" {
            fin_options = true;
        } else if let Some(v) = a.strip_prefix("--expression=") {
            scripts.push(v);
        } else if a == "--expression" {
            scripts.push(args.get(k).map_or("", String::as_str));
            k += 1;
        } else if a.starts_with("--file") {
            return Some("sed -f: script illisible ici, refuse".into());
        } else if a == "--line-length" {
            k += 1;
        } else if !a.starts_with("--") {
            let grappe = &a[1..];
            for (j, o) in grappe.char_indices() {
                match o {
                    'e' | 'l' => {
                        let valeur = &grappe[j + 1..];
                        let v = if valeur.is_empty() {
                            k += 1;
                            args.get(k - 1).map_or("", String::as_str)
                        } else {
                            valeur
                        };
                        if o == 'e' {
                            scripts.push(v);
                        }
                        break;
                    }
                    'f' => return Some("sed -f: script illisible ici, refuse".into()),
                    'i' => break, // le reste est le suffixe de sauvegarde
                    _ => {}
                }
            }
        }
    }
    if scripts.is_empty()
        && let Some(premier) = operandes.first()
    {
        scripts.push(premier);
    }
    scripts
        .iter()
        .any(|s| sed_script_s_arrete(s.as_bytes()))
        .then(|| "sed q".into())
}

/// Vrai si le mot `exit` parait dans le programme, hors chaine.
fn awk_s_arrete(args: &[String]) -> Option<String> {
    let mut k = 0;
    while let Some(a) = args.get(k) {
        match a.as_str() {
            "--" => {
                k += 1;
                break;
            }
            "-F" | "-v" => k += 2,
            "-f" => return Some("awk -f: programme illisible ici, refuse".into()),
            o if o.starts_with("-F") || o.starts_with("-v") => k += 1,
            o if o.starts_with('-') && o.len() > 1 => k += 1,
            _ => break,
        }
    }
    let programme = args.get(k)?.as_bytes();
    let mut i = 0;
    let mut dans_chaine = false;
    while i < programme.len() {
        let b = programme[i];
        if dans_chaine {
            if b == b'\\' {
                i += 1;
            } else if b == b'"' {
                dans_chaine = false;
            }
        } else if b == b'"' {
            dans_chaine = true;
        } else if programme[i..].starts_with(b"exit") {
            let avant = i.checked_sub(1).map(|j| programme[j]);
            let apres = programme.get(i + 4).copied();
            let mot = |x: Option<u8>| x.is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_');
            if !mot(avant) && !mot(apres) {
                return Some("awk exit".into());
            }
        }
        i += 1;
    }
    None
}

/// Pourquoi ce lecteur s'arrete avant la fin de son entree; `None` s'il lit
/// tout.
fn raison_d_arret(l: &Lecteur) -> Option<String> {
    if l.composee {
        return Some(
            "lecteur compose (boucle, bloc, sous-shell, test): la recette ne sait pas \
             dire s'il lit tout, elle le refuse"
                .into(),
        );
    }
    let (nom, args) = commande_effective(&l.mots);
    let base = nom.rsplit('/').next().unwrap_or(nom);
    match base {
        "grep" | "egrep" | "fgrep" => grep_s_arrete(args).map(|o| format!("grep {o}")),
        "head" => Some("head".into()),
        "sed" => sed_s_arrete(args),
        "awk" | "gawk" | "mawk" | "nawk" => awk_s_arrete(args),
        "read" | "true" | ":" => Some(format!("`{base}` ne lit pas toute son entree")),
        _ => None,
    }
}

/// Les lignes des lecteurs precoces d'un texte, pour les recettes de
/// falsification.
fn lignes_precoces(texte: &str) -> Vec<usize> {
    let a = analyser(texte, 0).unwrap_or_else(|e| panic!("texte illisible: {e}\n{texte}"));
    a.lecteurs
        .iter()
        .filter(|l| raison_d_arret(l).is_some())
        .map(|l| l.ligne)
        .collect()
}

// ================================================================== workflow

/// Une etape `run:` d'un workflow.
#[derive(Debug)]
struct Etape {
    job: String,
    nom: String,
    /// Ligne du fichier ou commence le corps.
    ligne: usize,
    corps: String,
    /// Shell effectif declare (etape, sinon job, sinon workflow).
    shell: Option<String>,
}

fn indentation(l: &str) -> usize {
    l.len() - l.trim_start_matches(' ').len()
}

fn est_significative(l: &str) -> bool {
    let t = l.trim();
    !t.is_empty() && !t.starts_with('#')
}

/// `cle: valeur` en tete de ligne (apres l'indentation et un `- ` eventuel).
fn cle_valeur(l: &str) -> Option<(&str, &str)> {
    let t = l.trim_start();
    let t = t.strip_prefix("- ").unwrap_or(t);
    let (cle, valeur) = t.split_once(':')?;
    if cle.is_empty()
        || !cle
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return None;
    }
    Some((cle, valeur.trim()))
}

/// Retire un commentaire de fin de ligne et des guillemets YAML simples.
fn scalaire(v: &str) -> String {
    let v = match v.find(" #") {
        Some(k) if !v.starts_with(['\'', '"']) => &v[..k],
        _ => v,
    };
    let v = v.trim();
    if v.len() >= 2
        && ((v.starts_with('\'') && v.ends_with('\'')) || (v.starts_with('"') && v.ends_with('"')))
    {
        return v[1..v.len() - 1].replace("''", "'");
    }
    v.to_string()
}

/// Le `shell` de `defaults.run` d'un bloc (workflow ou job) qui commence apres
/// la ligne `debut` et dont les enfants sont indentes de `enfant`.
fn shell_par_defaut(lignes: &[&str], debut: usize, fin: usize, enfant: usize) -> Option<String> {
    let mut k = debut;
    while k < fin {
        let l = lignes[k];
        if est_significative(l) && indentation(l) == enfant && l.trim() == "defaults:" {
            let mut j = k + 1;
            while j < fin && (!est_significative(lignes[j]) || indentation(lignes[j]) > enfant) {
                if let Some(("shell", v)) = cle_valeur(lignes[j]) {
                    return Some(scalaire(v));
                }
                j += 1;
            }
        }
        k += 1;
    }
    None
}

/// Les etapes `run:` d'un workflow GitHub, lues par indentation. Le format est
/// celui des workflows du depot: blocs YAML, pas de style en flux.
fn etapes_du_workflow(texte: &str) -> Result<Vec<Etape>, String> {
    let lignes: Vec<&str> = texte.lines().collect();
    let n = lignes.len();
    let jobs = lignes
        .iter()
        .position(|l| l.trim_end() == "jobs:" && indentation(l) == 0)
        .ok_or("aucune cle `jobs:` au premier niveau")?;
    let defaut_workflow = shell_par_defaut(&lignes, 0, jobs, 0);
    let fin_jobs = (jobs + 1..n)
        .find(|&k| est_significative(lignes[k]) && indentation(lignes[k]) == 0)
        .unwrap_or(n);
    let indent_job = (jobs + 1..fin_jobs)
        .find(|&k| est_significative(lignes[k]))
        .map(|k| indentation(lignes[k]))
        .ok_or("`jobs:` sans job")?;
    let debuts_jobs: Vec<usize> = (jobs + 1..fin_jobs)
        .filter(|&k| est_significative(lignes[k]) && indentation(lignes[k]) == indent_job)
        .collect();
    let mut etapes = Vec::new();
    for (r, &dj) in debuts_jobs.iter().enumerate() {
        let fj = debuts_jobs.get(r + 1).copied().unwrap_or(fin_jobs);
        let job = lignes[dj].trim().trim_end_matches(':').to_string();
        let indent_cle = (dj + 1..fj)
            .find(|&k| est_significative(lignes[k]))
            .map_or(indent_job + 2, |k| indentation(lignes[k]));
        let defaut_job = shell_par_defaut(&lignes, dj + 1, fj, indent_cle);
        let Some(steps) = (dj + 1..fj)
            .find(|&k| indentation(lignes[k]) == indent_cle && lignes[k].trim() == "steps:")
        else {
            continue;
        };
        // Les elements de `steps:`: lignes qui commencent par `- ` a une meme
        // indentation.
        let indent_tiret = (steps + 1..fj)
            .find(|&k| est_significative(lignes[k]))
            .map(|k| indentation(lignes[k]))
            .ok_or_else(|| format!("job {job}: `steps:` vide"))?;
        let fin_steps = (steps + 1..fj)
            .find(|&k| est_significative(lignes[k]) && indentation(lignes[k]) < indent_tiret)
            .unwrap_or(fj);
        let debuts: Vec<usize> = (steps + 1..fin_steps)
            .filter(|&k| {
                est_significative(lignes[k])
                    && indentation(lignes[k]) == indent_tiret
                    && lignes[k].trim_start().starts_with("- ")
            })
            .collect();
        for (q, &de) in debuts.iter().enumerate() {
            let fe = debuts.get(q + 1).copied().unwrap_or(fin_steps);
            let indent_cle_etape = indent_tiret + 2;
            let mut nom = String::new();
            let mut shell = None;
            let mut run: Option<(usize, String)> = None;
            let mut k = de;
            while k < fe {
                let l = lignes[k];
                let au_niveau = k == de || indentation(l) == indent_cle_etape;
                if !est_significative(l) || !au_niveau {
                    k += 1;
                    continue;
                }
                match cle_valeur(l) {
                    Some(("name", v)) => nom = scalaire(v),
                    Some(("shell", v)) => shell = Some(scalaire(v)),
                    Some(("run", v)) if v.starts_with(['|', '>']) => {
                        let mut corps = Vec::new();
                        let mut j = k + 1;
                        while j < fe
                            && (lignes[j].trim().is_empty()
                                || indentation(lignes[j]) > indent_cle_etape)
                        {
                            corps.push(lignes[j]);
                            j += 1;
                        }
                        let retrait = corps
                            .iter()
                            .filter(|c| !c.trim().is_empty())
                            .map(|c| indentation(c))
                            .min()
                            .unwrap_or(0);
                        let texte: Vec<&str> = corps
                            .iter()
                            .map(|c| c.get(retrait..).unwrap_or(""))
                            .collect();
                        run = Some((k + 2, texte.join("\n") + "\n"));
                        k = j;
                        continue;
                    }
                    Some(("run", v)) => run = Some((k + 1, scalaire(v) + "\n")),
                    _ => {}
                }
                k += 1;
            }
            if let Some((ligne, corps)) = run {
                etapes.push(Etape {
                    job: job.clone(),
                    nom,
                    ligne,
                    corps,
                    shell: shell
                        .or_else(|| defaut_job.clone())
                        .or_else(|| defaut_workflow.clone()),
                });
            }
        }
    }
    Ok(etapes)
}

/// Le shell d'une etape est-il du shell que la recette doit lire.
fn est_du_shell(shell: Option<&str>) -> bool {
    match shell {
        None => true,
        Some(s) => {
            let premier = s.split_whitespace().next().unwrap_or("");
            premier == "bash" || premier == "sh"
        }
    }
}

/// `-o pipefail` est-il pose par GitHub pour ce shell.
fn sous_pipefail(shell: Option<&str>) -> bool {
    shell.is_some_and(|s| s.trim() == "bash" || s.contains("pipefail"))
}

// ================================================================== parcours

const DOSSIERS_IGNORES: [&str; 2] = [".git", "target"];

/// Un script shell: extension `.sh`, ou shebang `sh`/`bash` en premiere ligne.
fn est_un_script_shell(chemin: &Path) -> bool {
    if chemin.extension().and_then(OsStr::to_str) == Some("sh") {
        return true;
    }
    let Ok(octets) = std::fs::read(chemin) else {
        return false;
    };
    let premiere = octets.split(|b| *b == b'\n').next().unwrap_or(&[]);
    let Some(shebang) = premiere.strip_prefix(b"#!") else {
        return false;
    };
    let texte = String::from_utf8_lossy(shebang);
    let mut morceaux = texte.split_whitespace();
    let interprete = morceaux.next().unwrap_or("");
    let interprete = if interprete.ends_with("/env") {
        morceaux.next().unwrap_or("")
    } else {
        interprete.rsplit('/').next().unwrap_or("")
    };
    interprete == "sh" || interprete == "bash"
}

fn scripts_shell(dossier: &Path, trouves: &mut Vec<PathBuf>) {
    let Ok(entrees) = std::fs::read_dir(dossier) else {
        return;
    };
    for entree in entrees.flatten() {
        let chemin = entree.path();
        let nom = entree.file_name().to_string_lossy().into_owned();
        if chemin.is_dir() {
            if !DOSSIERS_IGNORES.contains(&nom.as_str()) {
                scripts_shell(&chemin, trouves);
            }
        } else if est_un_script_shell(&chemin) {
            trouves.push(chemin);
        }
    }
}

fn relatif(chemin: &Path) -> String {
    chemin
        .strip_prefix(racine())
        .unwrap_or(chemin)
        .display()
        .to_string()
        .replace('\\', "/")
}

fn workflows() -> Vec<PathBuf> {
    let dossier = racine().join(".github").join("workflows");
    let mut v: Vec<PathBuf> = std::fs::read_dir(&dossier)
        .map(|e| {
            e.flatten()
                .map(|x| x.path())
                .filter(|p| matches!(p.extension().and_then(OsStr::to_str), Some("yml" | "yaml")))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

fn lire(chemin: &Path) -> String {
    std::fs::read_to_string(chemin)
        .unwrap_or_else(|e| panic!("{} illisible: {e}", chemin.display()))
}

// ================================================================== recettes

#[test]
fn aucun_lecteur_ne_s_arrete_avant_la_fin_d_un_tube() {
    let mut scripts = Vec::new();
    scripts_shell(&racine(), &mut scripts);
    scripts.sort();

    let mut defauts = Vec::new();
    let mut illisibles = Vec::new();
    let mut tubes = 0usize;
    let mut lecteurs = 0usize;
    let mut juger = |fichier: &str, analyse: Result<Analyse, String>| match analyse {
        Ok(a) => {
            tubes += a.tubes;
            lecteurs += a.lecteurs.len();
            for l in &a.lecteurs {
                if let Some(raison) = raison_d_arret(l) {
                    defauts.push(format!(
                        "{fichier}:{}: `{}` ({raison})",
                        l.ligne,
                        l.mots.join(" ")
                    ));
                }
            }
        }
        Err(e) => illisibles.push(format!("{fichier}: {e}")),
    };

    for chemin in &scripts {
        juger(&relatif(chemin), analyser(&lire(chemin), 0));
    }
    let mut corps_lus = 0usize;
    for wf in workflows() {
        let etapes =
            etapes_du_workflow(&lire(&wf)).unwrap_or_else(|e| panic!("{}: {e}", relatif(&wf)));
        for e in etapes.iter().filter(|e| est_du_shell(e.shell.as_deref())) {
            corps_lus += 1;
            juger(&relatif(&wf), analyser(&e.corps, e.ligne - 1));
        }
    }

    println!(
        "tubes_sous_pipefail: {} script(s) shell, {corps_lus} corps de workflow, \
         {tubes} tube(s), {lecteurs} lecteur(s) de tube, {} precoce(s)",
        scripts.len(),
        defauts.len()
    );
    // Controle positif: un parcours casse, un lexeur qui ne voit plus les
    // tubes ou un workflow mal lu rendraient une liste vide, donc un succes,
    // sans avoir rien regarde. Releve a 644d5c4 par cette recette et par un
    // second lexeur ecrit a part (Python, hors depot), qui concordent: 235
    // tubes dans les scripts et le workflow, 73 lecteurs precoces (46 `grep -q`
    // et 27 `head`).
    assert!(
        scripts.len() >= 15,
        "seulement {} script(s) shell trouve(s): le parcours ne verifie rien",
        scripts.len()
    );
    assert!(
        corps_lus >= 15,
        "seulement {corps_lus} corps `run:` lu(s) dans les workflows: la lecture du YAML est cassee"
    );
    assert!(
        tubes >= 200 && lecteurs >= 150,
        "{tubes} tube(s) et {lecteurs} lecteur(s) vus: le lexeur ne voit plus les pipelines"
    );
    assert!(
        illisibles.is_empty(),
        "la recette ne sait pas lire {} texte(s) shell; elle refuse plutot que de sauter \
         la suite du fichier:\n  {}",
        illisibles.len(),
        illisibles.join("\n  ")
    );
    assert!(
        defauts.is_empty(),
        "{} lecteur(s) s'arretent avant la fin de leur tube. Sous pipefail le producteur \
         meurt de SIGPIPE (141) et la pipeline echoue meme quand le lecteur a trouve: \
         un `if` prend alors la mauvaise branche en silence. Faire lire toute l'entree \
         (`grep ... >/dev/null` au lieu de `grep -q`, `sed -n 1p` ou `sed -n 1,Np` au \
         lieu de `head`), ou ne pas mettre de tube (fichier, here-string, variable):\n  {}",
        defauts.len(),
        defauts.join("\n  ")
    );
}

#[test]
fn chaque_etape_a_tube_du_workflow_tourne_sous_pipefail() {
    let mut defauts = Vec::new();
    let mut avec_tube = 0usize;
    for wf in workflows() {
        let fichier = relatif(&wf);
        let etapes = etapes_du_workflow(&lire(&wf)).unwrap_or_else(|e| panic!("{fichier}: {e}"));
        for e in etapes.iter().filter(|e| est_du_shell(e.shell.as_deref())) {
            let a = analyser(&e.corps, e.ligne - 1)
                .unwrap_or_else(|x| panic!("{fichier}, etape `{}`: {x}", e.nom));
            if a.tubes == 0 {
                continue;
            }
            avec_tube += 1;
            if !sous_pipefail(e.shell.as_deref()) {
                defauts.push(format!(
                    "{fichier}:{}: job `{}`, etape `{}`: un tube, shell {}",
                    e.ligne,
                    e.job,
                    e.nom,
                    e.shell
                        .as_deref()
                        .unwrap_or("implicite (bash -e, sans pipefail)")
                ));
            }
        }
    }
    // Controle positif: le depot a des etapes a tube (le compte des recettes
    // passe par `| tee`); n'en voir aucune voudrait dire que rien n'est lu.
    assert!(
        avec_tube >= 2,
        "{avec_tube} etape(s) a tube vue(s): la lecture du workflow est cassee"
    );
    assert!(
        defauts.is_empty(),
        "{} etape(s) portent un tube sans pipefail. Sans `shell: bash`, GitHub lance \
         `bash -e {{0}}`: la pipeline rend le code de son DERNIER element, et \
         `recettes-strict.sh | tee journal` reste vert quand la suite rougit. \
         Declarer `shell: bash` sur l'etape ou en `defaults.run.shell` du job:\n  {}",
        defauts.len(),
        defauts.join("\n  ")
    );
}

// ======================================================= falsifications

/// Chaque cas: un texte shell et les lignes ou la recette DOIT voir un lecteur
/// precoce. Les variantes syntaxiques qu'un lexeur maison rate: commentaire,
/// chaines, continuations, `||`, `>|`, arithmetique, `[[ ]]`, motif de
/// `case`, documents en ligne, substitutions imbriquees, grappes d'options.
#[test]
fn le_lexeur_ne_se_laisse_pas_tromper_par_la_syntaxe() {
    let cas: &[(&str, &[usize])] = &[
        ("ss -lnt | grep -q x\n", &[1]),
        ("# ss -lnt | grep -q x\n", &[]),
        ("ss -lnt # | grep -q x\n", &[]),
        ("echo 'a | grep -q b'\n", &[]),
        ("echo \"a | grep -q b\"\n", &[]),
        ("echo $'a | head -1'\n", &[]),
        ("echo a\\|grep -q b\n", &[]),
        ("grep -q x fichier\n", &[]),
        ("grep -q x <<< \"$v\"\n", &[]),
        ("ss -lnt \\\n  | grep -q x\n", &[2]),
        ("ss -lnt |\n  grep -q x\n", &[2]),
        ("ss -lnt | \\\n  grep -q x\n", &[2]),
        ("ss -lnt | grep \\\n  -q x\n", &[1]),
        ("a |\n# commentaire\n  head -1\n", &[3]),
        ("a || grep -q x\n", &[]),
        ("a >| f; grep -q x f\n", &[]),
        ("echo $((a | b)) | grep x >/dev/null\n", &[]),
        ("(( a | b )) && grep -q x f\n", &[]),
        ("[[ $x =~ a|b ]] && grep -q x f\n", &[]),
        ("case $x in\n  a|b) grep -q x f ;;\n  *) : ;;\nesac\n", &[]),
        ("case $x in a) y | head -1 ;; esac\n", &[1]),
        ("X=$(a | head -1)\n", &[1]),
        ("echo \"v: $(a | head -1)\"\n", &[1]),
        ("X=`a | head -1`\n", &[1]),
        ("X=\"${Y:-$(a | head -1)}\"\n", &[1]),
        ("cat <<'EOF'\nss | grep -q x\nEOF\n", &[]),
        ("cat <<\"EOF\"\nss | grep -q x\nEOF\n", &[]),
        ("cat <<EOF\nss | grep -q x\nEOF\n", &[]),
        ("cat <<EOF\n$(ss | head -1)\nEOF\n", &[2]),
        ("cat <<-EOF\n\tx\n\tEOF\nss | grep -q y\n", &[4]),
        ("a <(b | head -1) | grep -c x\n", &[1]),
        ("a | grep -Fqx y\n", &[1]),
        ("a | grep -Eqi y\n", &[1]),
        ("a | grep \"-q\" y\n", &[1]),
        ("a | grep --quiet y\n", &[1]),
        ("a | grep --silent y\n", &[1]),
        ("a | grep -m1 y\n", &[1]),
        ("a | grep -m 1 y\n", &[1]),
        ("a | grep --max-count=1 y\n", &[1]),
        ("a | grep -l y\n", &[1]),
        ("a | grep -e -q y\n", &[]),
        ("a | grep -e-q y\n", &[]),
        ("a | grep -- -q\n", &[]),
        ("a | grep -c y\n", &[]),
        ("a | grep -B2 y | grep -q z\n", &[1]),
        ("a | tr ' ' '\\n' | grep -qx y\n", &[1]),
        ("a | head -1 | cut -c1\n", &[1]),
        ("a | head -c 24\n", &[1]),
        ("head -c 24 /dev/urandom | base64\n", &[]),
        ("a | sed -n 1p\n", &[]),
        ("a | sed -n 1,40p\n", &[]),
        ("a | sed 1q\n", &[1]),
        ("a | sed -n '/x/{p;q}'\n", &[1]),
        ("a | sed 's/q/Q/'\n", &[]),
        ("a | sed 's/\\x1b\\[[0-9;]*m//g'\n", &[]),
        ("a | sed -e 's/x/y/' -e '/z/q'\n", &[1]),
        ("a | sed -ne '2Q'\n", &[1]),
        ("a | awk '{print $1}'\n", &[]),
        ("a | awk '/x/{print; exit}'\n", &[1]),
        ("a | awk '{print \"exit\"}'\n", &[]),
        ("a | awk -F: '{print $3}'\n", &[]),
        ("a | while read -r l; do echo \"$l\"; done\n", &[1]),
        ("a | { grep -q x; }\n", &[1]),
        ("a | ( grep -q x )\n", &[1]),
        ("a | read x\n", &[1]),
        ("a | true\n", &[1]),
        ("a | LC_ALL=C grep -q x\n", &[1]),
        ("a | sudo grep -q x\n", &[1]),
        ("a | timeout 5 head -1\n", &[1]),
        ("a | ip netns exec ns grep -q x\n", &[1]),
        ("a | /usr/bin/grep -q x\n", &[1]),
        ("a |& grep -q x\n", &[1]),
        ("a 2>&1 | grep x >/dev/null\n", &[]),
        ("a 2>/dev/null|grep -q x\n", &[1]),
        ("f() { a | grep -q x; }\n", &[1]),
        ("if a | grep -q x; then :; fi\n", &[1]),
        ("if ! a | grep -Eq x; then :; fi\n", &[1]),
        ("a | grep x >/dev/null && b | grep -q y\n", &[1]),
        ("for x in a b; do c | head -1; done\n", &[1]),
        (
            "x=$(for c in a; do grep \"$c\" f | awk '{print $1}'; done | sort -u | wc -l)\n",
            &[],
        ),
    ];
    let mut ecarts = Vec::new();
    for (texte, attendu) in cas {
        let vu = lignes_precoces(texte);
        if vu != *attendu {
            ecarts.push(format!("{texte:?}: attendu {attendu:?}, vu {vu:?}"));
        }
    }
    assert!(
        ecarts.is_empty(),
        "le lexeur se trompe sur {} cas:\n  {}",
        ecarts.len(),
        ecarts.join("\n  ")
    );
}

/// Le compte des tubes: ni `||`, ni `>|`, ni un `|` d'arithmetique, de `[[ ]]`,
/// de motif de `case`, de chaine ou de commentaire n'en est un.
#[test]
fn le_lexeur_compte_les_tubes_et_eux_seuls() {
    let cas: &[(&str, usize)] = &[
        ("a | b\n", 1),
        ("a |& b\n", 1),
        ("a \\\n | b\n", 1),
        ("a | b | c\n", 2),
        ("x=$(a | b)\n", 1),
        ("a || b\n", 0),
        ("a >| f\n", 0),
        ("echo $((1 | 2))\n", 0),
        ("(( x = 1 | 2 ))\n", 0),
        ("[[ a =~ b|c ]]\n", 0),
        ("case x in a|b) :;; esac\n", 0),
        ("echo 'a|b' \"c|d\" $'e|f'\n", 0),
        ("# a | b\n", 0),
        ("cat <<'F'\na | b\nF\n", 0),
    ];
    for (texte, attendu) in cas {
        let a = analyser(texte, 0).unwrap_or_else(|e| panic!("{texte:?}: {e}"));
        assert_eq!(a.tubes, *attendu, "tubes de {texte:?}");
    }
}

/// Une construction non refermee fait rougir la recette: sans cela, un
/// guillemet mal lu avalerait la suite du fichier et la rendrait verte.
#[test]
fn le_lexeur_refuse_ce_qu_il_ne_sait_pas_fermer() {
    for texte in [
        "echo 'abc\na | grep -q x\n",
        "echo \"abc\na | grep -q x\n",
        "x=$(a | head -1\n",
        "cat <<EOF\na | grep -q x\n",
        "echo `a | head -1\n",
        "echo ${x\n",
        "a )\n",
    ] {
        assert!(
            analyser(texte, 0).is_err(),
            "{texte:?} aurait du etre refuse comme illisible"
        );
    }
}

/// La lecture du workflow: shell de l'etape, du job, du workflow; corps en
/// bloc et en ligne; numeros de ligne.
#[test]
fn le_workflow_est_lu_etape_par_etape() {
    let wf = "\
name: t
on: push
jobs:
  sans:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0 # v1
      - name: Recettes
        run: ./s.sh | tee f
  avec:
    runs-on: ubuntu-latest
    defaults:
      run:
        shell: bash
    steps:
      - run: a | b
      - name: bloc
        run: |
          x
          # a | grep -q c
          a | grep -q y
  win:
    runs-on: windows-latest
    steps:
      - name: ps
        shell: pwsh
        run: Get-Item x | Select-Object -First 1
      - name: b
        shell: bash
        run: a | head -1
";
    let etapes = etapes_du_workflow(wf).expect("workflow lisible");
    let vues: Vec<(String, String, usize, Option<String>)> = etapes
        .iter()
        .map(|e| (e.job.clone(), e.nom.clone(), e.ligne, e.shell.clone()))
        .collect();
    let bash = Some("bash".to_string());
    assert_eq!(
        vues,
        vec![
            ("sans".into(), "Recettes".into(), 9, None),
            ("avec".into(), String::new(), 16, bash.clone()),
            ("avec".into(), "bloc".into(), 19, bash.clone()),
            ("win".into(), "ps".into(), 27, Some("pwsh".into())),
            ("win".into(), "b".into(), 30, bash),
        ]
    );
    let bloc = &etapes[2];
    let a = analyser(&bloc.corps, bloc.ligne - 1).expect("corps lisible");
    let precoces: Vec<usize> = a
        .lecteurs
        .iter()
        .filter(|l| raison_d_arret(l).is_some())
        .map(|l| l.ligne)
        .collect();
    assert_eq!(
        precoces,
        vec![21],
        "le `grep -q` du bloc, pas celui du commentaire"
    );
    assert!(
        !sous_pipefail(etapes[0].shell.as_deref()),
        "shell implicite: sans pipefail"
    );
    assert!(sous_pipefail(etapes[1].shell.as_deref()));
    assert!(
        !est_du_shell(etapes[3].shell.as_deref()),
        "pwsh n'est pas lu"
    );
    assert!(est_du_shell(etapes[0].shell.as_deref()));
}

//! Lexeur Rust minimal, partage par les gardes de source de ce repertoire.
//!
//! Il ne sait qu'une chose: separer le CODE des commentaires et des litteraux,
//! et rendre chaque litteral chaine avec sa position. C'est ce qu'il faut pour
//! qu'une garde de source ne prenne pas un commentaire pour du code, ni un
//! `'"'` pour l'ouverture d'une chaine.
//!
//! Deja-vu du 05/09/2026 (tranche 5t): une garde de source qui comptait les
//! accolades se laissait etendre par un `'{'` qu'elle ne savait pas lire. Les
//! litteraux de caractere, les chaines brutes (`r"..."`, `r#"..."#`, `br`,
//! `cr`), les chaines d'octets et C (`b"..."`, `c"..."`), les lifetimes et les
//! commentaires de bloc imbriques sont donc traites ici, une fois, et
//! specifies par les recettes des gardes qui l'incluent.
//!
//! Inclus par `#[path = "commun/lexeur_rust.rs"]` dans chaque garde: un fichier
//! sous `tests/commun/` n'est pas une cible de test pour cargo, et une seule
//! grammaire sert toutes les gardes plutot que deux copies << identiques dans
//! l'esprit >>.
//!
//! Il travaille en octets. Les sources du depot sont en ASCII (garde par
//! `sources_ascii.rs`); un caractere UTF-8 n'est de toute facon jamais pris
//! pour un delimiteur, ses octets etant tous au-dessus de 0x7F.

/// Un litteral chaine du source, tel qu'il est ECRIT (echappements non
/// interpretes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Litteral {
    /// Octet de debut du jeton, prefixe compris (`b`, `c`, `r`, `br`, `cr`).
    pub debut: usize,
    /// Ligne (a partir de 1) du guillemet ouvrant.
    pub ligne: usize,
    /// Colonne (a partir de 0, en octets) du guillemet ouvrant.
    pub colonne: usize,
    /// Chaine brute: aucun echappement, aucune continuation.
    pub brut: bool,
    /// Le corps entre les guillemets, tel qu'il est ecrit dans le source.
    pub corps: String,
}

/// Le source decoupe: ses litteraux chaine, et les zones qui ne sont pas du
/// code (commentaires, litteraux chaine et caractere), en octets `[a, b)`.
#[derive(Debug, Default)]
pub struct Decoupe {
    pub litteraux: Vec<Litteral>,
    pub neutres: Vec<(usize, usize)>,
}

impl Decoupe {
    /// La zone neutre qui contient l'octet `pos`, s'il y en a une. Les zones
    /// sont rangees dans l'ordre du source et ne se chevauchent pas: une
    /// recherche dichotomique suffit.
    pub fn zone_neutre(&self, pos: usize) -> Option<(usize, usize)> {
        let k = self.neutres.partition_point(|&(a, _)| a <= pos);
        (k > 0 && pos < self.neutres[k - 1].1).then(|| self.neutres[k - 1])
    }

    /// Le litteral chaine dont le jeton commence exactement a `pos`.
    pub fn litteral_a(&self, pos: usize) -> Option<&Litteral> {
        let k = self.litteraux.partition_point(|l| l.debut < pos);
        self.litteraux.get(k).filter(|l| l.debut == pos)
    }
}

fn est_ident(o: u8) -> bool {
    o == b'_' || o.is_ascii_alphanumeric()
}

/// Largeur en octets du caractere UTF-8 dont `o` est le premier octet.
fn largeur_utf8(o: u8) -> usize {
    match o {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

/// Position courante: ligne et debut de ligne, tenus a jour a chaque saut.
struct Curseur {
    ligne: usize,
    debut_ligne: usize,
}

impl Curseur {
    /// Compte les sauts de ligne de `b[a..z]`.
    fn avancer(&mut self, b: &[u8], a: usize, z: usize) {
        for (p, o) in b[a..z].iter().enumerate() {
            if *o == b'\n' {
                self.ligne += 1;
                self.debut_ligne = a + p + 1;
            }
        }
    }
}

/// Fin (exclue) d'un litteral de caractere qui commence a `k` (`b[k]` est
/// l'apostrophe), ou `None` si c'est une lifetime ou une etiquette.
fn fin_de_caractere(b: &[u8], k: usize) -> Option<usize> {
    let n = b.len();
    if k + 1 >= n {
        return None;
    }
    if b[k + 1] == b'\\' {
        // `'\n'`, `'\''`, `'\\'`, `'\x7f'`, `'\u{1F600}'`: l'apostrophe
        // fermante suit l'echappement, a au plus une douzaine d'octets.
        let mut j = k + 3;
        while j < n && j <= k + 12 {
            if b[j] == b'\'' {
                return Some(j + 1);
            }
            j += 1;
        }
        return None;
    }
    if b[k + 1] == b'\'' || b[k + 1] == b'\n' {
        return None;
    }
    let w = largeur_utf8(b[k + 1]);
    if k + 1 + w < n && b[k + 1 + w] == b'\'' {
        Some(k + 2 + w)
    } else {
        None
    }
}

/// Decoupe `src` en litteraux et zones neutres.
pub fn decouper(src: &str) -> Result<Decoupe, String> {
    let b = src.as_bytes();
    let n = b.len();
    let mut d = Decoupe::default();
    let mut c = Curseur {
        ligne: 1,
        debut_ligne: 0,
    };
    let mut i = 0usize;
    while i < n {
        let o = b[i];
        if o == b'\n' {
            c.avancer(b, i, i + 1);
            i += 1;
            continue;
        }
        if o == b'/' && i + 1 < n && b[i + 1] == b'/' {
            let j = src[i..].find('\n').map_or(n, |k| i + k);
            d.neutres.push((i, j));
            i = j;
            continue;
        }
        if o == b'/' && i + 1 < n && b[i + 1] == b'*' {
            let mut profondeur = 1usize;
            let mut j = i + 2;
            while j < n && profondeur > 0 {
                if b[j] == b'/' && j + 1 < n && b[j + 1] == b'*' {
                    profondeur += 1;
                    j += 2;
                } else if b[j] == b'*' && j + 1 < n && b[j + 1] == b'/' {
                    profondeur -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            if profondeur > 0 {
                return Err(format!("commentaire de bloc non ferme, ligne {}", c.ligne));
            }
            d.neutres.push((i, j));
            c.avancer(b, i, j);
            i = j;
            continue;
        }
        // Le debut du jeton, et l'eventuel guillemet qu'il ouvre.
        let debut = i;
        let mut guillemet = None;
        let mut brut_dieses = None;
        if est_ident(o) {
            let mut j = i;
            while j < n && est_ident(b[j]) {
                j += 1;
            }
            let mot = &src[i..j];
            if matches!(mot, "r" | "br" | "cr") {
                let mut k = j;
                while k < n && b[k] == b'#' {
                    k += 1;
                }
                if k < n && b[k] == b'"' {
                    guillemet = Some(k);
                    brut_dieses = Some(k - j);
                }
            } else if matches!(mot, "b" | "c") && j < n && b[j] == b'"' {
                guillemet = Some(j);
            } else if mot == "b"
                && j < n
                && b[j] == b'\''
                && let Some(f) = fin_de_caractere(b, j)
            {
                d.neutres.push((i, f));
                i = f;
                continue;
            }
            if guillemet.is_none() {
                // Un identifiant, un mot-cle, un nombre, ou `r#ident`: du code.
                i = j;
                continue;
            }
        } else if o == b'"' {
            guillemet = Some(i);
        } else if o == b'\'' {
            match fin_de_caractere(b, i) {
                Some(f) => {
                    d.neutres.push((i, f));
                    i = f;
                }
                None => i += 1,
            }
            continue;
        } else {
            i += 1;
            continue;
        }

        let k = guillemet.expect("un guillemet a ete trouve");
        let ligne = c.ligne;
        let colonne = k - c.debut_ligne;
        let (fin_corps, fin) = match brut_dieses {
            Some(dieses) => {
                let mut fermeture = String::from("\"");
                fermeture.push_str(&"#".repeat(dieses));
                let Some(rel) = src[k + 1..].find(&fermeture) else {
                    return Err(format!("chaine brute non fermee, ligne {ligne}"));
                };
                (k + 1 + rel, k + 1 + rel + fermeture.len())
            }
            None => {
                let mut j = k + 1;
                loop {
                    if j >= n {
                        return Err(format!("chaine non fermee, ligne {ligne}"));
                    }
                    if b[j] == b'\\' {
                        j += 2;
                        continue;
                    }
                    if b[j] == b'"' {
                        break;
                    }
                    j += 1;
                }
                (j, j + 1)
            }
        };
        d.litteraux.push(Litteral {
            debut,
            ligne,
            colonne,
            brut: brut_dieses.is_some(),
            corps: src[k + 1..fin_corps].to_owned(),
        });
        d.neutres.push((debut, fin));
        c.avancer(b, debut, fin);
        i = fin;
    }
    Ok(d)
}

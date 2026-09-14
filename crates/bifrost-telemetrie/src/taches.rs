//! Lire l'etat d'une tache planifiee sans jamais lire une phrase traduite.
//!
//! # Pourquoi pas la sortie de `schtasks`
//!
//! `schtasks /Change /Disable` repond, sur essai-windows le 22/08/2026:
//! *"Operation reussie : les parametres de la tache planifiee ... ont ete
//! modifies."* En francais, parce que la machine est en francais. `/query /fo
//! LIST` est traduit de meme. Le depot a deja paye cette classe de defaut trois
//! fois en une session sur d'autres outils systeme. La seule sortie de
//! `schtasks` qui ne soit pas traduite est le XML: ses noms d'elements viennent
//! du schema, pas d'une ressource de langue.
//!
//! # Ce que le XML dit, et ce qu'il ne dit pas
//!
//! Mesure du 22/08/2026 sur essai-windows, build 26200, sur la tache
//! `Customer Experience Improvement Program\Consolidator`, lue **active** puis
//! **desactivee** puis rendue a son etat:
//!
//! - tache active: le bloc `<Settings>` ne porte **aucun** element `<Enabled>`;
//! - tache desactivee: il porte `<Enabled>false</Enabled>`.
//!
//! Autrement dit l'absence signifie "activee", parce que le schema donne `true`
//! pour defaut et que `schtasks` n'ecrit pas les valeurs par defaut. Un
//! lecteur qui chercherait `<Enabled>true</Enabled>` ne le trouverait jamais et
//! conclurait a une tache desactivee sur toutes les machines du monde.
//!
//! # Pourquoi ancrer sur `<Settings>`
//!
//! `<Enabled>` apparait AUSSI dans `<Triggers>`, une fois par declencheur, avec
//! un sens tout different: ce declencheur-la est-il arme. Chercher le premier
//! `<Enabled>` du document rendrait, sur une tache a plusieurs declencheurs,
//! l'etat d'un declencheur pris pour celui de la tache. Le seul `<Enabled>`
//! situe directement sous `<Settings>` est celui de la tache; `<IdleSettings>`,
//! le seul sous-element de `<Settings>` a en contenir d'autres, ne porte que
//! `StopOnIdleEnd` et `RestartOnIdle`.

/// Decode ce que `schtasks` a ecrit sur sa sortie standard.
///
/// `schtasks /query /xml` annonce `encoding="UTF-16"` dans son prologue, mais
/// ce qui sort reellement depend de la redirection: vers un fichier par le
/// shell, c'est de l'octet simple; vers un tube, c'est de l'UTF-16LE. Les deux
/// se presentent donc, et confondre les deux rend une chaine ou un octet sur
/// deux est un zero - illisible, mais pas vide, donc pas detectee comme telle.
///
/// La marque d'ordre des octets tranche quand elle est la. Sinon on regarde si
/// les octets impairs sont majoritairement nuls, ce qui est la signature de
/// l'UTF-16LE pour du texte latin et n'arrive jamais en UTF-8.
pub fn decoder_sortie(octets: &[u8]) -> String {
    if octets.len() >= 2 && octets[0] == 0xFF && octets[1] == 0xFE {
        return depuis_utf16le(&octets[2..]);
    }
    if octets.len() >= 8 {
        let impairs = octets.iter().skip(1).step_by(2).take(64);
        let total = impairs.clone().count();
        let nuls = impairs.filter(|o| **o == 0).count();
        if total > 0 && nuls * 2 > total {
            return depuis_utf16le(octets);
        }
    }
    String::from_utf8_lossy(octets).into_owned()
}

fn depuis_utf16le(octets: &[u8]) -> String {
    let unites: Vec<u16> = octets
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u16::from_le_bytes(*p))
        .collect();
    String::from_utf16_lossy(&unites)
}

/// L'etat d'une tache, lu dans le XML que `schtasks /query /xml` rend.
///
/// `None` quand le document ne porte pas de bloc `<Settings>`: tache absente,
/// commande en echec, sortie tronquee. C'est volontairement indiscernable d'un
/// cote appelant, qui doit alors dire SANS OBJET et non "activee par defaut".
pub fn tache_activee(xml: &str) -> Option<bool> {
    let debut = xml.find("<Settings>")? + "<Settings>".len();
    let reste = &xml[debut..];
    let fin = reste.find("</Settings>")?;
    let bloc = &reste[..fin];
    // L'absence d'`<Enabled>` vaut `true`: c'est la valeur par defaut du
    // schema, et `schtasks` n'ecrit pas les defauts.
    match bloc.find("<Enabled>") {
        None => Some(true),
        Some(i) => {
            let apres = &bloc[i + "<Enabled>".len()..];
            let valeur = apres.find("</Enabled>").map(|j| &apres[..j])?;
            Some(valeur.trim() == "true")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Releve reel, essai-windows, build 26200, 22/08/2026: la tache
    /// `Customer Experience Improvement Program\Consolidator` **active**.
    /// Aucun `<Enabled>`, et un declencheur qui n'en porte pas non plus.
    const ACTIVE: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.6" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Settings>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <StartWhenAvailable>true</StartWhenAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
  </Settings>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>2004-01-02T00:00:00</StartBoundary>
      <Repetition>
        <Interval>PT6H</Interval>
      </Repetition>
    </TimeTrigger>
  </Triggers>
</Task>"#;

    /// La MEME tache, desactivee, relevee dans la foulee puis rendue a son
    /// etat. Le seul ecart est la ligne `<Enabled>false</Enabled>`.
    const DESACTIVEE: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.6" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Settings>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <Enabled>false</Enabled>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <StartWhenAvailable>true</StartWhenAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
  </Settings>
</Task>"#;

    #[test]
    fn les_deux_releves_reels_se_lisent_bien() {
        assert_eq!(
            tache_activee(ACTIVE),
            Some(true),
            "une tache active n'ecrit AUCUN <Enabled>: le lire comme desactivee \
             ferait croire la machine deja protegee"
        );
        assert_eq!(tache_activee(DESACTIVEE), Some(false));
    }

    /// Le piege que l'ancrage sur `<Settings>` existe pour eviter: un
    /// declencheur desarme sur une tache active.
    #[test]
    fn un_declencheur_desarme_n_est_pas_une_tache_desactivee() {
        let xml = r#"<Task>
  <Settings>
    <StartWhenAvailable>true</StartWhenAvailable>
  </Settings>
  <Triggers>
    <TimeTrigger>
      <Enabled>false</Enabled>
    </TimeTrigger>
  </Triggers>
</Task>"#;
        assert_eq!(
            tache_activee(xml),
            Some(true),
            "le <Enabled> lu est celui d'un DECLENCHEUR. Chercher le premier du \
             document rendrait l'etat d'un declencheur pour celui de la tache"
        );
    }

    /// Et l'inverse: la tache desactivee dont un declencheur est arme.
    #[test]
    fn un_declencheur_arme_ne_reactive_pas_une_tache_desactivee() {
        let xml = r#"<Task>
  <Triggers>
    <TimeTrigger>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Settings>
    <Enabled>false</Enabled>
  </Settings>
</Task>"#;
        assert_eq!(tache_activee(xml), Some(false));
    }

    #[test]
    fn une_sortie_sans_settings_ne_rend_pas_de_verdict() {
        assert_eq!(tache_activee(""), None);
        assert_eq!(
            tache_activee("ERREUR: le systeme n'a pas trouve la tache"),
            None
        );
        assert_eq!(
            tache_activee("<Task><Settings><Enabled>false"),
            None,
            "un document tronque doit rendre None et non un verdict"
        );
    }

    #[test]
    fn l_utf16_avec_marque_se_decode() {
        let mut octets = vec![0xFF, 0xFE];
        for c in "<Settings><Enabled>false</Enabled></Settings>".encode_utf16() {
            octets.extend_from_slice(&c.to_le_bytes());
        }
        assert_eq!(tache_activee(&decoder_sortie(&octets)), Some(false));
    }

    #[test]
    fn l_utf16_sans_marque_se_decode_aussi() {
        let mut octets = Vec::new();
        for c in ACTIVE.encode_utf16() {
            octets.extend_from_slice(&c.to_le_bytes());
        }
        let texte = decoder_sortie(&octets);
        assert_eq!(tache_activee(&texte), Some(true));
        assert!(
            !texte.contains('\u{0}'),
            "des zeros ont survecu au decodage: la chaine serait illisible sans \
             etre vide, donc jamais detectee comme telle"
        );
    }

    #[test]
    fn l_octet_simple_reste_de_l_octet_simple() {
        let texte = decoder_sortie(ACTIVE.as_bytes());
        assert_eq!(texte, ACTIVE);
        assert_eq!(tache_activee(&texte), Some(true));
    }

    /// Le decodeur ne doit pas prendre pour de l'UTF-16 une sortie courte, ni
    /// une sortie vide: il rendrait du charabia la ou il y a un message.
    #[test]
    fn une_sortie_courte_n_est_pas_prise_pour_de_l_utf16() {
        assert_eq!(decoder_sortie(b""), "");
        assert_eq!(decoder_sortie(b"non"), "non");
        assert_eq!(decoder_sortie(b"ERREUR: 1"), "ERREUR: 1");
    }
}

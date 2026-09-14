//! Les criteres d'echec EN COURS DE SESSION: gel apres 16-20 Ko, effondrement
//! du debit.
//!
//! [`crate::course`] nomme et type ces deux echecs depuis le debut. Personne ne
//! les mesurait: les nommer n'est pas les voir. Ce module est ce qui les voit.
//!
//! Le plan les demande a deux endroits. Document 04 partie 1: "Russie gele
//! apres 16-20KB dans une meme connexion TCP; SSH throttle a 2Kb/s. Detection =
//! debit qui s'effondre apres N KB/N secondes dans une meme connexion." Et
//! partie 3.2, pour la degradation en cours de session: "si le tunnel gele
//! apres 3 min (signature TSPU), basculer vers le candidat suivant en gardant
//! l'etat applicatif".
//!
//! # Ce que l'etat de l'art a corrige au plan
//!
//! Le plan decrit ces criteres comme des OBSERVATIONS d'un flux vivant. Elles
//! ne peuvent pas l'etre entierement, et c'est un resultat, pas un detail
//! d'implementation: **un tunnel inactif et un tunnel gele sont indiscernables
//! de l'exterieur**. Dans les deux cas plus rien n'arrive. Une session SSH
//! ouverte et silencieuse produit exactement la meme trace qu'une connexion
//! coupee par un DPI.
//!
//! Aucune quantite de comptage ne leve l'ambiguite, parce que l'information
//! manquante n'est pas dans les compteurs: elle est chez le pair, et il faut la
//! lui DEMANDER. C'est ce que fait Psiphon, et sa forme exacte merite d'etre
//! reprise plutot que reinventee (`psiphon/tunnel.go`, verifie le 20 aout
//! 2026):
//!
//! - une connexion suivie en activite qui expose sa duree d'inactivite EN
//!   LECTURE - le temps ecoule depuis le dernier octet RECU, et non depuis le
//!   dernier octet echange;
//! - une sonde aller-retour avec echeance, envoyee SEULEMENT si cette duree
//!   depasse un seuil (`SSHKeepAlivePeriodicInactivePeriod`, 10 s): un tunnel
//!   qui coule n'est jamais sonde, ce qui ne coute rien et n'emet rien;
//! - une cadence TIREE AU SORT entre deux bornes (`SSHKeepAlivePeriodMin` 1 min,
//!   `SSHKeepAlivePeriodMax` 2 min) et un remplissage aleatoire, explicitement
//!   "to make the resulting traffic less fingerprintable". Le plan demande la
//!   meme chose en d'autres termes: "ne pas emettre de motif de bascule
//!   regulier";
//! - un budget de 5 s pour la sonde de diagnostic (`SSHKeepAliveProbeTimeout`),
//!   30 s pour la sonde periodique.
//!
//! Ces quatre valeurs sont reprises telles quelles ci-dessous. Elles viennent
//! d'un client deploye a grande echelle dans les pays qui nous interessent, ce
//! qui vaut mieux qu'un nombre choisi ici.
//!
//! # Ce qu'un debit bas ne dit pas, mesure le 21 aout 2026
//!
//! Le raisonnement ci-dessus vaut pour le SILENCE. Il n'avait pas ete applique
//! a l'EFFONDREMENT, et c'etait la meme erreur: un debit bas etait pris pour
//! une preuve d'etranglement alors qu'il est d'abord une preuve que personne
//! ne demande rien.
//!
//! Mesure sur essai-windows, quinze secondes apres `connect`, sur un tunnel
//! parfaitement sain: "le debit est tombe de 19506 a 556 octets par seconde
//! sur 10 s", puis `reconnecting`, puis `disconnected`. La pointe des 19 Ko/s
//! etait le trafic de fond que Windows produit a chaque changement de reseau;
//! sa retombee etait Windows qui a fini. Trois autres mesures sur la meme
//! machine au repos donnent 127, 151 et 195 octets par seconde. Personne
//! n'avait rien etrangle.
//!
//! **Et le plancher ne peut pas etre la reponse.** Le throttling que ce critere
//! vise est chiffre a 2 Kb/s par le document 04 partie 1, soit 256 octets par
//! seconde. Une machine Windows oisive vit dans la MEME plage. Les deux ne se
//! separent pas par un seuil, quel qu'il soit, parce que ce n'est pas une
//! question de reglage: la quantite mesuree ne contient pas la reponse. Un
//! debit recu est un produit de ce que le reseau veut bien livrer ET de ce que
//! la machine demande, et rien dans les compteurs ne dit lequel des deux a
//! baisse.
//!
//! # Ce que fait l'etat de l'art plutot que de compter
//!
//! Psiphon mesure une vitesse, et deux details de sa forme repondent
//! exactement a la question (`psiphon/tunnel.go` et
//! `psiphon/common/tactics/tactics.go`, releves le 21 aout 2026, HEAD
//! `4f65b71`):
//!
//! - l'echantillon est pris SUR LA SONDE, pas sur le trafic ambiant.
//!   `sendSshKeepAlive` envoie un keepalive avec un bourrage tire au sort
//!   (`SSHKeepAlivePaddingMinBytes` 0, `MaxBytes` 256), mesure l'aller-retour,
//!   et `AddSpeedTestSample` retient `{RTTMilliseconds, BytesUp, BytesDown}`.
//!   La demande est CREEE par le client, donc le nombre veut dire quelque chose
//!   meme quand la machine ne fait rien;
//! - et un echantillon lent ne demonte RIEN. Il part dans le magasin de
//!   tactiques - cinq au plus, `SpeedTestMaxSampleCount` - pour classer les
//!   serveurs. Ce qui demonte un tunnel chez eux, c'est le keepalive qui ne
//!   revient PAS, jamais celui qui revient lentement.
//!
//! Aucun client deploye ne bascule de transport sur une mesure de debit. C'est
//! un resultat, pas une lacune: personne ne sait mesurer un debit sans creer de
//! la charge, et creer de la charge coute du trafic et une empreinte.
//!
//! # La forme retenue ici
//!
//! L'effondrement ne conclut plus. Il devient une seconde RAISON DE DEMANDER,
//! a cote du silence, avec la meme sonde et la meme cadence:
//!
//! - la sonde revient dans son budget: le lien repond, le debit bas etait une
//!   machine au repos, et rien n'est condamne;
//! - la sonde ne revient pas: le tunnel est perdu, et c'est l'effondrement qui
//!   NOMME la perte. Sans lui on lirait un tunnel devenu muet, alors qu'il
//!   recevait encore - `effondrement` exclut le debit nul, qui est un silence.
//!
//! Ce que cela detecte reellement vaut d'etre dit sans l'embellir. La sonde
//! traverse une poignee de main TLS complete vers `generate_204`, soit
//! plusieurs kilooctets: sous un etranglement a 256 octets par seconde elle ne
//! peut pas tenir dans son budget de cinq secondes, et l'effondrement est alors
//! confirme par un aller-retour reel. C'est le meme instrument que pour le gel,
//! et c'est voulu - un seul mecanisme, une seule empreinte, une seule cadence.
//!
//! # Pourquoi pas le `urltest` de sing-box
//!
//! Il existe, il est periodique, et il ne peut pas repondre a la question. Sa
//! cible par defaut est `https://www.gstatic.com/generate_204`, dont le corps
//! fait ZERO octet: une sonde qui ne transfere rien ne peut pas voir un rideau
//! qui tombe a 16 Ko. Son intervalle est fixe a 3 min, donc regulier, donc un
//! motif. Le document 04 partie 3.3 l'avait deja ecarte pour la premiere de ces
//! deux raisons; la seconde s'ajoute.
//!
//! # La forme retenue, et ce qui la rend decidable
//!
//! Ce module ne sonde pas, comme le reste du crate ne lance rien: il DIT quand
//! sonder et lit le resultat. L'horloge lui est donnee, comme la gigue est
//! donnee a [`crate::course`], pour qu'il reste une fonction de ce qu'on lui
//! passe et non de l'heure qu'il est.
//!
//! Trois etats se distinguent alors sans ambiguite:
//!
//! - **le tunnel recoit**: rien a faire, sauf regarder le debit;
//! - **le tunnel ne recoit plus, et on ne lui a rien demande**: on ne conclut
//!   RIEN. C'est le cas ou le plan aurait conclu a tort;
//! - **le tunnel ne recoit plus, et une sonde n'est pas revenue**: il est perdu,
//!   et le nombre d'octets recus au moment ou il s'est taise dit lequel des
//!   trois modes d'echec c'etait.

use std::collections::VecDeque;
use std::time::Duration;

use crate::course::{Echec, FENETRE_DEBIT, SEUIL_GEL};

/// Borne haute du rideau. Document 04 partie 1: "gele apres 16-20KB".
///
/// La borne BASSE sert de seuil de declenchement et vit dans
/// [`crate::course::SEUIL_GEL`], ou son commentaire explique pourquoi c'est
/// elle. Celle-ci sert a l'autre bout: au-dela, la coupure n'est plus celle du
/// rideau, puisqu'il serait deja tombe.
pub const PLAFOND_GEL: u64 = 20 * 1024;

/// Inactivite en LECTURE au-dela de laquelle il faut demander plutot que
/// supposer. `SSHKeepAlivePeriodicInactivePeriod` chez Psiphon.
pub const INACTIVITE_AVANT_SONDE: Duration = Duration::from_secs(10);

/// Cadence minimale des sondes, quand le silence dure.
/// `SSHKeepAlivePeriodMin` chez Psiphon.
pub const PERIODE_SONDE_MIN: Duration = Duration::from_secs(60);

/// Cadence maximale. `SSHKeepAlivePeriodMax` chez Psiphon.
///
/// L'intervalle EST la politique: une sonde a periode fixe est un motif
/// regulier, et le document 04 partie 3.2 l'interdit dans les memes termes que
/// le commentaire de Psiphon.
pub const PERIODE_SONDE_MAX: Duration = Duration::from_secs(120);

/// Echeance d'une sonde. `SSHKeepAliveProbeTimeout` chez Psiphon, qui est bien
/// le cas d'ici: on sonde PARCE QUE quelque chose cloche, pas par habitude.
pub const BUDGET_SONDE: Duration = Duration::from_secs(5);

/// Debit au-dessous duquel un tunnel ne sert plus a rien, en octets par
/// seconde.
///
/// Le document 04 partie 1 chiffre le throttling russe observe sur SSH a
/// 2 Kb/s, soit 256 octets par seconde. Ce plancher est huit fois plus haut, ce
/// qui laisse un lien etrangle sans ambiguite au-dessous, et reste tres loin
/// au-dessous de tout tunnel utilisable.
pub const PLANCHER_DEBIT: u64 = 2 * 1024;

/// Un echantillon des compteurs du tunnel. Cumulatifs, comme les compteurs
/// d'interface et comme ce que rend un `HandshakeInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Echantillon {
    /// Depuis combien de temps le tunnel est monte.
    ///
    /// Une duree et non un instant: c'est ce qui rend ce module testable a un
    /// rythme choisi, et c'est le meme choix que la gigue de [`crate::course`].
    pub age: Duration,
    /// Octets envoyes vers le serveur, cumulatifs.
    pub emis: u64,
    /// Octets recus du serveur, cumulatifs.
    pub recus: u64,
}

/// Comment un tunnel a ete perdu en cours de session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Perte {
    /// La reception s'est arretee dans la bande 16-20 Ko: signature du rideau.
    Gel { octets: u64 },
    /// Le debit s'est effondre apres avoir tenu. Throttling, pas blocage franc.
    Debit { avant: u64, maintenant: u64 },
    /// Mort en cours de session, sans signature reconnue.
    Muet { octets: u64 },
}

impl Perte {
    /// L'echec de course correspondant, s'il y en a un.
    ///
    /// `None` pour [`Perte::Muet`], et c'est une decision. Le carnet ecarte
    /// deja les echecs qui n'accusent pas le reseau
    /// ([`Echec::accuse_le_reseau`]); la meme prudence s'applique ici pour une
    /// autre raison. Un tunnel qui se coupe sans signature peut etre le
    /// censeur, mais aussi le serveur qui redemarre, un Wi-Fi qui saute ou un
    /// operateur qui recycle une session NAT. L'inscrire au carnet ecarterait
    /// la technique du prochain essai sur ce reseau pour une deconnexion
    /// ordinaire.
    ///
    /// Les deux autres sont nommees par le document 04 comme des actions de
    /// censeur. Elles sont donc portees au carnet.
    pub fn echec(&self) -> Option<Echec> {
        match self {
            Perte::Gel { octets } => Some(Echec::Gel { octets: *octets }),
            Perte::Debit { .. } => Some(Echec::Debit),
            Perte::Muet { .. } => None,
        }
    }

    pub fn motif(&self) -> String {
        match self {
            Perte::Gel { octets } => format!(
                "le tunnel s'est tu apres {octets} octets recus, dans la bande {SEUIL_GEL}-{PLAFOND_GEL}: signature d'une coupure en cours de session"
            ),
            Perte::Debit { avant, maintenant } => format!(
                "le debit est tombe de {avant} a {maintenant} octets par seconde sur {} s et le pair n'a pas repondu: throttling plutot que blocage franc",
                FENETRE_DEBIT.as_secs()
            ),
            Perte::Muet { octets } => format!(
                "le tunnel ne repond plus apres {octets} octets recus, sans signature reconnue"
            ),
        }
    }
}

/// Ce que la sonde a donne.
///
/// Trois issues et non deux. La troisieme est celle que le plan n'avait pas
/// prevue, et c'est la plus importante pour la surete: **une sonde qui n'a pas
/// pu etre POSEE ne dit rien du pair**. Le coeur n'est pas la, le secret de son
/// API est refuse, le filtre local a jete la requete avant qu'elle ne parte:
/// dans les trois cas on n'a pas mesure le reseau, on a mesure une panne chez
/// soi.
///
/// C'est la meme regle que [`Echec::accuse_le_reseau`] applique aux tentatives,
/// et elle compte plus encore ici: confondre les deux ferait demonter un tunnel
/// parfaitement sain chaque fois que l'API du coeur hoquette.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sonde {
    /// L'aller-retour est revenu dans son budget: le pair repond.
    Aboutie,
    /// Le pair n'a pas repondu. Une erreur immediate et une echeance atteinte
    /// disent la meme chose et n'ont pas a etre distinguees.
    Echouee,
    /// La sonde n'a pas pu etre emise, ou son resultat ne parle pas du reseau.
    Impossible,
}

/// Ce que l'appelant doit faire de cet echantillon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Rien a signaler.
    Rien,
    /// Le tunnel n'a rien recu depuis assez longtemps pour qu'il faille le lui
    /// DEMANDER. L'appelant emet un aller-retour dans ce budget et rapporte par
    /// [`Observateur::noter_sonde`].
    ///
    /// Tant qu'il ne rapporte pas, l'observateur ne redemande rien: une sonde
    /// en vol n'est pas une raison d'en lancer une deuxieme.
    Sonder { budget: Duration },
    /// Le tunnel est perdu, et voici pourquoi.
    Perdu(Perte),
}

/// Ce qui regarde couler le tunnel.
#[derive(Debug, Clone)]
pub struct Observateur {
    /// Le dernier echantillon vu, pour comparer.
    dernier: Option<Echantillon>,
    /// Age auquel un octet est arrive pour la derniere fois. Zero au depart:
    /// un tunnel qui vient de monter n'a pas encore ete silencieux.
    dernier_recu: Duration,
    /// Age a partir duquel une sonde est a nouveau permise.
    prochaine_sonde: Duration,
    /// Une sonde attend sa reponse.
    sonde_en_vol: bool,
    /// Fenetre glissante des receptions, pour le debit.
    fenetre: VecDeque<Echantillon>,
    /// Le meilleur debit soutenu observe, en octets par seconde. C'est la
    /// REFERENCE de l'effondrement: sans elle, un lien lent depuis toujours se
    /// lirait comme un lien etrangle.
    reference: u64,
    /// Rendu une fois pour toutes des qu'il est tombe.
    perdu: Option<Perte>,
}

impl Default for Observateur {
    fn default() -> Self {
        Self::nouveau()
    }
}

impl Observateur {
    pub fn nouveau() -> Self {
        Self {
            dernier: None,
            dernier_recu: Duration::ZERO,
            prochaine_sonde: Duration::ZERO,
            sonde_en_vol: false,
            fenetre: VecDeque::new(),
            reference: 0,
            perdu: None,
        }
    }

    /// Verse un echantillon et dit quoi faire.
    ///
    /// `cadence` est tiree par l'appelant entre [`PERIODE_SONDE_MIN`] et
    /// [`PERIODE_SONDE_MAX`], pour la meme raison que la gigue de
    /// [`crate::course`] est tiree dehors: du hasard ici rendrait ce module
    /// intestable, et c'est precisement la valeur qui ne doit pas etre
    /// reguliere.
    pub fn observer(&mut self, e: Echantillon, cadence: Duration) -> Verdict {
        if let Some(p) = &self.perdu {
            return Verdict::Perdu(p.clone());
        }

        let precedent = self.dernier.replace(e);

        // Un compteur qui recule est un compteur qui a ete remis a zero -
        // interface recreee, coeur relance. Repartir de zero plutot que de
        // calculer un debit negatif ou un silence imaginaire.
        if let Some(p) = precedent
            && (e.recus < p.recus || e.emis < p.emis || e.age < p.age)
        {
            let cadence_gardee = self.prochaine_sonde;
            *self = Self::nouveau();
            self.dernier = Some(e);
            self.dernier_recu = e.age;
            self.prochaine_sonde = cadence_gardee;
            return Verdict::Rien;
        }

        let recoit = precedent.is_none_or(|p| e.recus > p.recus);
        if recoit {
            self.dernier_recu = e.age;
        }

        self.majorer_fenetre(e);
        // Appele a chaque echantillon, y compris pendant qu'une sonde pend:
        // c'est lui qui tient la REFERENCE a jour, et une reference figee se
        // comparerait a un passe qui n'existe plus.
        let effondre = self.effondrement();

        // Une sonde est deja partie: attendre sa reponse. En lancer une
        // deuxieme n'apprendrait rien et doublerait ce qu'on emet.
        if self.sonde_en_vol {
            return Verdict::Rien;
        }

        // Deux raisons de poser la question, une seule sonde pour les deux, et
        // la meme cadence. L'effondrement ne conclut plus seul: voir l'en-tete,
        // section "Ce qu'un debit bas ne dit pas".
        let silence = e.age.saturating_sub(self.dernier_recu);
        let a_demander = effondre.is_some() || silence >= INACTIVITE_AVANT_SONDE;
        if a_demander && e.age >= self.prochaine_sonde {
            self.sonde_en_vol = true;
            self.prochaine_sonde = e.age + cadence.clamp(PERIODE_SONDE_MIN, PERIODE_SONDE_MAX);
            return Verdict::Sonder {
                budget: BUDGET_SONDE,
            };
        }

        Verdict::Rien
    }

    /// Rapporte le sort de la sonde demandee.
    ///
    /// [`Sonde::Impossible`] libere la sonde sans rien conclure: la prochaine
    /// cadence en redemandera une, et d'ici la le tunnel reste en service. Un
    /// tunnel demonte parce que l'API du coeur a hoquete serait un defaut bien
    /// plus visible que celui qu'on cherche.
    pub fn noter_sonde(&mut self, sonde: Sonde) -> Verdict {
        if let Some(p) = &self.perdu {
            return Verdict::Perdu(p.clone());
        }
        self.sonde_en_vol = false;

        if sonde == Sonde::Impossible {
            return Verdict::Rien;
        }
        if sonde == Sonde::Aboutie {
            // Le pair a repondu: le tunnel est vivant et simplement inactif.
            //
            // Rien d'autre a faire, et une version de ce code en faisait plus:
            // elle remettait le silence a zero, "sans quoi on resonderait sans
            // fin". La falsification a montre que cette ligne ne changeait
            // rien, et la raison vaut d'etre retenue - c'est la CADENCE qui
            // espace les sondes, jamais le silence. Elle vaut au moins
            // PERIODE_SONDE_MIN, six fois INACTIVITE_AVANT_SONDE: des qu'elle
            // autorise une sonde, le silence l'autorise depuis longtemps. Une
            // ligne qui a l'air de proteger quelque chose et qui ne protege
            // rien est pire qu'absente, parce qu'on croit la propriete tenue.
            return Verdict::Rien;
        }

        // Ce qui NOMME la perte se relit maintenant, et ne s'est pas garde
        // depuis la demande.
        //
        // Une premiere version rangeait la raison dans un champ au moment de
        // demander, avec une ligne pour la jeter quand la sonde revenait. La
        // falsification n'a pas mordu: le chemin de la demande RECRIT ce champ
        // a chaque fois, donc rien ne pouvait etre perime et cette ligne ne
        // protegeait rien. Elle est partie avec son champ - la meme regle que
        // pour la remise a zero du silence, quelques lignes plus haut.
        //
        // Relire coute un appel et supprime la question: il n'y a plus d'etat
        // a synchroniser, et la perte porte le nom de ce que le tunnel EST au
        // moment ou l'on conclut.
        let perte = match self.effondrement() {
            Some(etrangle) => etrangle,
            None => {
                let octets = self.dernier.map_or(0, |e| e.recus);
                if (SEUIL_GEL..=PLAFOND_GEL).contains(&octets) {
                    Perte::Gel { octets }
                } else {
                    Perte::Muet { octets }
                }
            }
        };
        self.perdu = Some(perte.clone());
        Verdict::Perdu(perte)
    }

    /// Le debit soutenu sur la fenetre, en octets par seconde, ou `None` si la
    /// fenetre ne couvre pas encore assez de temps pour en dire quoi que ce
    /// soit.
    pub fn debit(&self) -> Option<u64> {
        let (premier, dernier) = (self.fenetre.front()?, self.fenetre.back()?);
        let ecoule = dernier.age.saturating_sub(premier.age);
        if ecoule < FENETRE_DEBIT {
            return None;
        }
        let octets = dernier.recus.saturating_sub(premier.recus);
        Some(octets / ecoule.as_secs().max(1))
    }

    pub fn perdu(&self) -> Option<&Perte> {
        self.perdu.as_ref()
    }

    /// Depuis combien de temps rien n'est arrive, au dernier echantillon.
    ///
    /// Expose parce qu'une plateforme peut deja DETENIR la reponse a la sonde,
    /// sans rien emettre. Un tunnel WireGuard renouvelle sa poignee de main
    /// avec le pair: une poignee PLUS RECENTE que le debut du silence est un
    /// aller-retour reel, deja fait, deja paye. Le comparer demande de savoir
    /// quand le silence a commence, et c'est ici.
    pub fn silence(&self) -> Duration {
        self.dernier
            .map_or(Duration::ZERO, |e| e.age.saturating_sub(self.dernier_recu))
    }

    /// Garde dans la fenetre ce qui couvre [`FENETRE_DEBIT`], et un echantillon
    /// de plus: sans lui la fenetre ne couvrirait jamais tout a fait la duree
    /// demandee, et le debit ne serait jamais calculable.
    fn majorer_fenetre(&mut self, e: Echantillon) {
        self.fenetre.push_back(e);
        while self.fenetre.len() > 2 && e.age.saturating_sub(self.fenetre[1].age).ge(&FENETRE_DEBIT)
        {
            self.fenetre.pop_front();
        }
    }

    /// L'effondrement du debit, s'il a eu lieu.
    ///
    /// Ne condamne rien: il rend une PERTE CANDIDATE, qui ne devient une perte
    /// que si la sonde ne revient pas. Voir l'en-tete, "Ce qu'un debit bas ne
    /// dit pas".
    ///
    /// Deux conditions, et il faut les deux. Le tunnel doit avoir SOUTENU un
    /// debit au-dessus du plancher - sans quoi un lien lent depuis toujours,
    /// une 3G faible par exemple, serait condamne comme etrangle et on
    /// changerait de technique sans fin. Et il doit encore recevoir quelque
    /// chose: un debit tombe a zero est un silence, que la sonde traite, et non
    /// un throttling. Le document 04 partie 3.1 fait exactement cette
    /// distinction: "effondrement apres N secondes = throttling, echec de
    /// handshake immediat = blocage franc".
    fn effondrement(&mut self) -> Option<Perte> {
        let debit = self.debit()?;
        if debit >= PLANCHER_DEBIT {
            self.reference = self.reference.max(debit);
            return None;
        }
        if self.reference < PLANCHER_DEBIT || debit == 0 {
            return None;
        }
        Some(Perte::Debit {
            avant: self.reference,
            maintenant: debit,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CADENCE: Duration = PERIODE_SONDE_MIN;

    fn e(secondes: u64, emis: u64, recus: u64) -> Echantillon {
        Echantillon {
            age: Duration::from_secs(secondes),
            emis,
            recus,
        }
    }

    /// Le cas que le plan aurait mal traite: personne n'utilise le tunnel.
    /// Aucune conclusion ne doit en sortir, seulement une question posee au
    /// pair. Un tunnel condamne parce que son proprietaire est alle dejeuner
    /// serait un defaut bien plus visible que celui qu'on cherche.
    #[test]
    fn un_tunnel_inactif_n_est_pas_declare_perdu_mais_sonde() {
        let mut o = Observateur::nouveau();
        assert_eq!(o.observer(e(0, 0, 0), CADENCE), Verdict::Rien);
        // Neuf secondes de silence: en dessous du seuil, on ne demande rien.
        assert_eq!(o.observer(e(9, 100, 0), CADENCE), Verdict::Rien);
        // Dix: on demande.
        assert_eq!(
            o.observer(e(10, 100, 0), CADENCE),
            Verdict::Sonder {
                budget: BUDGET_SONDE
            }
        );
        // Et la reponse dit que tout va bien.
        assert_eq!(o.noter_sonde(Sonde::Aboutie), Verdict::Rien);
        assert_eq!(o.perdu(), None);
    }

    /// Une sonde qui aboutit libere la suivante sans la declencher: le tunnel
    /// est vivant, simplement inactif, et rien ne presse.
    #[test]
    fn une_sonde_qui_aboutit_ne_condamne_pas_et_ne_resonde_pas_aussitot() {
        let mut o = Observateur::nouveau();
        o.observer(e(0, 0, 0), CADENCE);
        o.observer(e(10, 100, 0), CADENCE);
        assert_eq!(o.noter_sonde(Sonde::Aboutie), Verdict::Rien);
        // Le tunnel reste muet. Tant que la cadence n'est pas ecoulee, on ne
        // redemande rien, meme si le silence dure depuis bien plus que
        // INACTIVITE_AVANT_SONDE.
        for s in 11..(10 + CADENCE.as_secs()) {
            assert_eq!(
                o.observer(e(s, s * 10, 0), CADENCE),
                Verdict::Rien,
                "resonde a {s} s, avant la cadence"
            );
        }
        assert_eq!(o.perdu(), None);
    }

    /// Le rideau: la reception s'arrete dans la bande 16-20 Ko et le pair ne
    /// repond plus.
    #[test]
    fn une_reception_arretee_dans_la_bande_est_un_gel() {
        let mut o = Observateur::nouveau();
        o.observer(e(0, 0, 0), CADENCE);
        o.observer(e(1, 500, 17_000), CADENCE);
        // Onze secondes plus tard, plus rien n'est arrive alors qu'on emet.
        let v = o.observer(e(12, 900, 17_000), CADENCE);
        assert_eq!(
            v,
            Verdict::Sonder {
                budget: BUDGET_SONDE
            }
        );
        assert_eq!(
            o.noter_sonde(Sonde::Echouee),
            Verdict::Perdu(Perte::Gel { octets: 17_000 })
        );
    }

    /// Hors de la bande, la meme trace ne s'appelle pas pareil. Un tunnel qui
    /// meurt apres trois megaoctets n'a pas rencontre un rideau qui tombe a 16
    /// Ko.
    #[test]
    fn hors_de_la_bande_la_coupure_ne_porte_pas_le_nom_du_rideau() {
        for (octets, attendu) in [
            (0u64, Perte::Muet { octets: 0 }),
            (15_000, Perte::Muet { octets: 15_000 }),
            (SEUIL_GEL, Perte::Gel { octets: SEUIL_GEL }),
            (
                PLAFOND_GEL,
                Perte::Gel {
                    octets: PLAFOND_GEL,
                },
            ),
            (PLAFOND_GEL + 1, Perte::Muet { octets: 20_481 }),
            (3_000_000, Perte::Muet { octets: 3_000_000 }),
        ] {
            let mut o = Observateur::nouveau();
            o.observer(e(0, 0, 0), CADENCE);
            o.observer(e(1, 500, octets), CADENCE);
            o.observer(e(12, 900, octets), CADENCE);
            assert_eq!(
                o.noter_sonde(Sonde::Echouee),
                Verdict::Perdu(attendu.clone())
            );
        }
    }

    /// Le carnet ne retient que ce que le document 04 attribue a un censeur.
    /// Une coupure ordinaire - serveur qui redemarre, Wi-Fi qui saute -
    /// ecarterait la technique du prochain essai ici pour une raison qui n'a
    /// rien a voir avec elle.
    #[test]
    fn seules_les_deux_signatures_vont_au_carnet() {
        assert_eq!(
            Perte::Gel { octets: 17_000 }.echec(),
            Some(Echec::Gel { octets: 17_000 })
        );
        assert_eq!(
            Perte::Debit {
                avant: 100_000,
                maintenant: 200
            }
            .echec(),
            Some(Echec::Debit)
        );
        assert_eq!(Perte::Muet { octets: 3_000_000 }.echec(), None);
    }

    /// Le throttling: le tunnel a tenu, s'est effondre sans se taire, et le
    /// pair ne repond plus.
    ///
    /// Les deux moities comptent. L'effondrement seul ne conclut rien - c'est
    /// la recette suivante qui le tient - et une sonde qui echoue sur un tunnel
    /// qui recevait encore serait autrement lue comme un tunnel devenu muet.
    #[test]
    fn un_debit_effondre_que_la_sonde_ne_dement_pas_est_du_throttling() {
        let mut o = Observateur::nouveau();
        let mut recus = 0u64;
        // Vingt secondes a 100 Ko/s: la reference s'etablit.
        for s in 0..=20 {
            recus = s * 100_000;
            assert_eq!(o.observer(e(s, s * 1_000, recus), CADENCE), Verdict::Rien);
        }
        // Puis 200 octets par seconde, l'ordre de grandeur du throttling SSH
        // que le document 04 chiffre. Le tunnel n'est pas muet, il est etrangle.
        let mut demande = None;
        for s in 21..=40 {
            recus += 200;
            if let Verdict::Sonder { budget } = o.observer(e(s, s * 1_000, recus), CADENCE) {
                demande = Some(budget);
                break;
            }
        }
        assert_eq!(
            demande,
            Some(BUDGET_SONDE),
            "l'effondrement doit faire DEMANDER au pair, pas conclure tout seul"
        );

        match o.noter_sonde(Sonde::Echouee) {
            Verdict::Perdu(Perte::Debit { avant, maintenant }) => {
                assert!(avant >= PLANCHER_DEBIT, "reference trop basse: {avant}");
                assert!(maintenant < PLANCHER_DEBIT, "pas un effondrement");
            }
            autre => panic!("un effondrement etait attendu: {autre:?}"),
        }
    }

    /// Une machine au repos n'est pas un tunnel etrangle.
    ///
    /// # Le defaut que cette recette tient
    ///
    /// Mesure sur essai-windows le 21 aout 2026, quinze secondes apres
    /// `connect`, sur un tunnel qui marchait: "le debit est tombe de 19506 a
    /// 556 octets par seconde sur 10 s", puis `reconnecting`, puis
    /// `disconnected`. La pointe etait le trafic de fond de Windows au
    /// changement de reseau; sa retombee etait Windows qui avait fini.
    ///
    /// Les nombres ci-dessous sont ceux-la, et le repos est chiffre a 130
    /// octets par seconde - la moyenne des trois mesures faites sur cette
    /// machine oisive (127, 151, 195). C'est DANS la plage du throttling que le
    /// critere vise, 256 octets par seconde: aucun plancher ne les separe, seul
    /// un aller-retour reel le peut.
    #[test]
    fn une_machine_au_repos_n_est_pas_un_tunnel_etrangle() {
        let mut o = Observateur::nouveau();
        let mut recus = 0u64;
        for s in 0..=20 {
            recus += 19_506;
            o.observer(e(s, s * 1_000, recus), CADENCE);
        }

        let mut demande = false;
        for s in 21..=60 {
            recus += 130;
            match o.observer(e(s, s * 1_000 + 130, recus), CADENCE) {
                Verdict::Sonder { .. } => {
                    demande = true;
                    // Le pair repond: il n'y a rien a corriger.
                    assert_eq!(o.noter_sonde(Sonde::Aboutie), Verdict::Rien);
                }
                Verdict::Rien => {}
                Verdict::Perdu(p) => panic!("tunnel sain condamne a {s} s: {}", p.motif()),
            }
        }
        assert!(
            demande,
            "un debit effondre doit au moins faire poser la question"
        );
        assert_eq!(o.perdu(), None);
    }

    /// Un tunnel devenu muet ne porte pas le nom d'un etranglement passe.
    ///
    /// La sonde qui echoue relit le debit pour nommer la perte, et un debit
    /// TOMBE A ZERO n'est pas un etranglement mais un silence. Sans cette
    /// exclusion, un tunnel qui a d'abord ralenti puis s'est tu finirait au
    /// carnet comme etrangle, et le carnet ecarterait la technique du prochain
    /// essai sur ce reseau pour une coupure ordinaire.
    #[test]
    fn un_tunnel_devenu_muet_ne_porte_pas_le_nom_d_un_etranglement_passe() {
        let mut o = Observateur::nouveau();
        let mut recus = 0u64;
        for s in 0..=20 {
            recus = s * 100_000;
            o.observer(e(s, s * 1_000, recus), CADENCE);
        }
        // Effondrement, question posee, pair qui repond.
        let mut demande = false;
        for s in 21..=40 {
            recus += 200;
            if matches!(
                o.observer(e(s, s * 1_000, recus), CADENCE),
                Verdict::Sonder { .. }
            ) {
                demande = true;
                assert_eq!(o.noter_sonde(Sonde::Aboutie), Verdict::Rien);
                break;
            }
        }
        assert!(demande, "l'effondrement devait faire demander");

        // Bien plus tard, le tunnel se tait pour de bon. La perte doit se lire
        // sur ce silence-la, pas sur l'effondrement d'avant.
        let fige = recus;
        let mut perte = None;
        for s in 41..=400 {
            match o.observer(e(s, s * 1_000, fige), CADENCE) {
                Verdict::Sonder { .. } => {
                    if let Verdict::Perdu(p) = o.noter_sonde(Sonde::Echouee) {
                        perte = Some(p);
                        break;
                    }
                }
                Verdict::Perdu(p) => {
                    perte = Some(p);
                    break;
                }
                Verdict::Rien => {}
            }
        }
        match perte {
            Some(Perte::Debit { .. }) => {
                panic!("un tunnel qui ne recoit plus rien nomme comme un tunnel etrangle")
            }
            Some(_) => {}
            None => panic!("un tunnel definitivement muet devait finir par etre perdu"),
        }
    }

    /// Un lien lent depuis toujours n'est pas un lien etrangle. Le condamner
    /// ferait changer de technique en boucle sur une 3G faible, sans qu'aucune
    /// ne fasse mieux.
    #[test]
    fn un_lien_lent_depuis_toujours_n_est_pas_un_effondrement() {
        let mut o = Observateur::nouveau();
        let mut recus = 0u64;
        for s in 0..=60 {
            recus += 300;
            assert_eq!(
                o.observer(e(s, s * 100, recus), CADENCE),
                Verdict::Rien,
                "condamne a {s} s alors qu'il n'a jamais ete rapide"
            );
        }
        assert_eq!(o.perdu(), None);
    }

    /// Un debit tombe a zero est un silence, pas un throttling. Les deux ne se
    /// corrigent pas de la meme facon, et surtout le zero passe par la sonde:
    /// sans elle on condamnerait un tunnel inactif.
    #[test]
    fn un_debit_tombe_a_zero_passe_par_la_sonde_et_non_par_l_effondrement() {
        let mut o = Observateur::nouveau();
        let mut recus = 0u64;
        for s in 0..=20 {
            recus = s * 100_000;
            o.observer(e(s, s * 1_000, recus), CADENCE);
        }
        // Plus rien du tout. Ce n'est pas un effondrement de debit.
        let mut vu_sonder = false;
        for s in 21..=40 {
            match o.observer(e(s, s * 1_000, recus), CADENCE) {
                Verdict::Sonder { .. } => vu_sonder = true,
                Verdict::Rien => {}
                Verdict::Perdu(p) => panic!("condamne sans avoir demande: {p:?}"),
            }
        }
        assert!(vu_sonder, "le silence total doit faire sonder");
    }

    /// Une sonde en vol n'est pas une raison d'en lancer une deuxieme: cela
    /// doublerait ce qu'on emet sans rien apprendre de plus.
    ///
    /// La recette court BIEN AU-DELA de la cadence, et c'est le point. Une
    /// premiere version s'arretait a trente secondes et passait encore quand on
    /// retirait le garde: c'est la cadence qui empechait la seconde sonde, pas
    /// lui. Un appelant qui ne rapporte jamais - une sonde qui pend sur un
    /// socket mort, ce qui est exactement le cas qu'on cherche - franchit la
    /// cadence, et il n'y a plus que le garde.
    #[test]
    fn une_seule_sonde_a_la_fois() {
        let mut o = Observateur::nouveau();
        o.observer(e(0, 0, 0), CADENCE);
        assert!(matches!(
            o.observer(e(10, 100, 0), CADENCE),
            Verdict::Sonder { .. }
        ));
        // Personne ne rapporte. La cadence est franchie deux fois.
        for s in 11..=(10 + 3 * CADENCE.as_secs()) {
            assert_eq!(
                o.observer(e(s, s * 10, 0), CADENCE),
                Verdict::Rien,
                "deuxieme sonde lancee a {s} s alors que la premiere n'est pas revenue"
            );
        }
    }

    /// La cadence espace les sondes quand le silence dure. Sans elle, un tunnel
    /// legitimement inactif emettrait une sonde toutes les dix secondes: un
    /// motif parfaitement regulier, que le document 04 partie 3.2 interdit
    /// explicitement.
    #[test]
    fn les_sondes_suivantes_sont_espacees_par_la_cadence() {
        let mut o = Observateur::nouveau();
        o.observer(e(0, 0, 0), CADENCE);
        assert!(matches!(
            o.observer(e(10, 100, 0), CADENCE),
            Verdict::Sonder { .. }
        ));
        o.noter_sonde(Sonde::Aboutie);

        let mut sondes = Vec::new();
        for s in 11..=200 {
            if let Verdict::Sonder { .. } = o.observer(e(s, s * 10, 0), CADENCE) {
                sondes.push(s);
                o.noter_sonde(Sonde::Aboutie);
            }
        }
        assert!(!sondes.is_empty(), "aucune sonde apres la premiere");
        for paire in sondes.windows(2) {
            let ecart = paire[1] - paire[0];
            assert!(
                ecart >= CADENCE.as_secs(),
                "deux sondes a {ecart} s d'ecart, cadence de {} s",
                CADENCE.as_secs()
            );
        }
        assert!(
            sondes[0] >= 10 + CADENCE.as_secs(),
            "la deuxieme sonde a suivi la premiere sans attendre la cadence: {}",
            sondes[0]
        );
    }

    /// Une cadence hors bornes ne doit ni rendre les sondes regulieres a la
    /// milliseconde, ni les espacer d'une heure. Le pincement est ce qui rend
    /// l'appelant incapable de casser la politique par un mauvais tirage.
    #[test]
    fn une_cadence_aberrante_est_ramenee_dans_les_bornes() {
        for (donnee, attendue) in [
            (Duration::ZERO, PERIODE_SONDE_MIN),
            (Duration::from_secs(3600), PERIODE_SONDE_MAX),
        ] {
            let mut o = Observateur::nouveau();
            o.observer(e(0, 0, 0), donnee);
            assert!(matches!(
                o.observer(e(10, 100, 0), donnee),
                Verdict::Sonder { .. }
            ));
            o.noter_sonde(Sonde::Aboutie);
            let mut suivante = None;
            for s in 11..=4000 {
                if let Verdict::Sonder { .. } = o.observer(e(s, s * 10, 0), donnee) {
                    suivante = Some(s);
                    break;
                }
            }
            assert_eq!(
                suivante,
                Some(10 + attendue.as_secs()),
                "cadence {donnee:?} non ramenee a {attendue:?}"
            );
        }
    }

    /// Des compteurs qui reculent veulent dire qu'ils ont ete remis a zero:
    /// interface recreee, coeur relance. En deduire un debit negatif ou un
    /// silence imaginaire condamnerait un tunnel qui vient de repartir.
    #[test]
    fn des_compteurs_remis_a_zero_ne_condamnent_pas_le_tunnel() {
        let mut o = Observateur::nouveau();
        for s in 0..=20 {
            o.observer(e(s, s * 1_000, s * 100_000), CADENCE);
        }
        assert_eq!(o.observer(e(21, 0, 0), CADENCE), Verdict::Rien);
        assert_eq!(o.perdu(), None);
        // Et le silence repart de la, pas d'avant.
        assert_eq!(o.observer(e(25, 100, 0), CADENCE), Verdict::Rien);
    }

    /// Un verdict de perte est definitif: une fois le tunnel condamne, les
    /// echantillons suivants ne doivent pas le ressusciter. L'appelant demonte,
    /// et ce qu'il lit entre-temps ne change rien.
    #[test]
    fn une_perte_est_definitive() {
        let mut o = Observateur::nouveau();
        o.observer(e(0, 0, 0), CADENCE);
        o.observer(e(1, 500, 17_000), CADENCE);
        o.observer(e(12, 900, 17_000), CADENCE);
        let perdu = o.noter_sonde(Sonde::Echouee);
        assert!(matches!(perdu, Verdict::Perdu(Perte::Gel { .. })));
        assert_eq!(o.observer(e(13, 1_000, 99_999), CADENCE), perdu);
        assert_eq!(o.noter_sonde(Sonde::Aboutie), perdu);
    }

    /// Une sonde qu'on n'a pas pu poser ne dit rien du pair. La confondre avec
    /// un pair muet ferait demonter un tunnel parfaitement sain chaque fois que
    /// l'API du coeur hoquette, ou que le filtre local jette la requete avant
    /// qu'elle ne parte.
    #[test]
    fn une_sonde_impossible_ne_condamne_rien() {
        let mut o = Observateur::nouveau();
        o.observer(e(0, 0, 0), CADENCE);
        o.observer(e(1, 500, 17_000), CADENCE);
        assert!(matches!(
            o.observer(e(12, 900, 17_000), CADENCE),
            Verdict::Sonder { .. }
        ));
        // Les memes octets, dans la bande du rideau: seule l'issue change.
        assert_eq!(o.noter_sonde(Sonde::Impossible), Verdict::Rien);
        assert_eq!(o.perdu(), None);
    }

    /// Et elle libere la sonde: la cadence suivante doit pouvoir redemander.
    /// Sans cela, une seule panne locale rendrait le tunnel definitivement
    /// insondable, donc son gel definitivement invisible.
    #[test]
    fn une_sonde_impossible_libere_la_suivante() {
        let mut o = Observateur::nouveau();
        o.observer(e(0, 0, 0), CADENCE);
        o.observer(e(1, 500, 17_000), CADENCE);
        o.observer(e(12, 900, 17_000), CADENCE);
        o.noter_sonde(Sonde::Impossible);

        let mut redemande = None;
        for s in 13..=300 {
            if let Verdict::Sonder { .. } = o.observer(e(s, s * 10, 17_000), CADENCE) {
                redemande = Some(s);
                break;
            }
        }
        let quand = redemande.expect("la cadence suivante doit redemander une sonde");
        assert!(
            quand >= 12 + CADENCE.as_secs(),
            "redemande a {quand} s, avant la cadence"
        );
        assert_eq!(
            o.noter_sonde(Sonde::Echouee),
            Verdict::Perdu(Perte::Gel { octets: 17_000 }),
            "la seconde sonde doit pouvoir conclure"
        );
    }

    /// Le silence expose sert a repondre a la sonde SANS rien emettre, quand la
    /// plateforme detient deja un aller-retour: une poignee de main WireGuard
    /// plus recente que le debut du silence en est un.
    #[test]
    fn le_silence_expose_se_compte_depuis_le_dernier_octet_recu() {
        let mut o = Observateur::nouveau();
        o.observer(e(0, 0, 0), CADENCE);
        assert_eq!(o.silence(), Duration::ZERO);
        o.observer(e(5, 100, 4_000), CADENCE);
        assert_eq!(o.silence(), Duration::ZERO, "un octet vient d'arriver");
        o.observer(e(9, 200, 4_000), CADENCE);
        assert_eq!(o.silence(), Duration::from_secs(4));
    }

    /// Les motifs partent dans le journal: ils doivent dire ce qui s'est passe,
    /// pas seulement qu'il s'est passe quelque chose.
    #[test]
    fn chaque_perte_dit_ce_qui_s_est_passe() {
        let gel = Perte::Gel { octets: 17_000 }.motif();
        assert!(gel.contains("17000"), "{gel}");
        assert!(gel.contains("16384"), "la bande doit etre nommee: {gel}");

        let debit = Perte::Debit {
            avant: 100_000,
            maintenant: 200,
        }
        .motif();
        assert!(debit.contains("100000") && debit.contains("200"), "{debit}");
        assert!(debit.contains("throttling"), "{debit}");

        let muet = Perte::Muet { octets: 42 }.motif();
        assert!(muet.contains("42"), "{muet}");
        assert!(
            muet.contains("sans signature"),
            "un muet doit se lire comme tel: {muet}"
        );
    }
}

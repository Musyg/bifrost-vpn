//! Prevenir le daemon qu'une veille vient de se terminer, cote Linux.
//!
//! Le pendant de `bifrost_daemon::reprise`, qui fait le meme travail sous
//! Windows. Meme raison d'etre - reaffirmer la politique au reveil plutot que
//! de parier sur sa survie - et une difference de forme qui vient entierement
//! de la plateforme.
//!
//! # Pourquoi le producteur n'est PAS dans le daemon, ici
//!
//! Sous Windows, le daemon apprend la reprise lui-meme: il s'abonne a
//! `PowerRegisterSuspendResumeNotification` et le systeme rappelle DANS son
//! processus. Sous Linux, la voie que le noyau et systemd offrent a un
//! programme deja lance est l'interface Inhibitor, donc DBus, donc une
//! dependance de plus dans un binaire qui tourne en root en permanence. La
//! voie retenue est celle qui n'en ajoute aucune: un executable depose dans
//! `/usr/lib/systemd/system-sleep/`, que systemd lance au reveil et qui
//! previent le daemon par l'IPC qui existe deja.
//!
//! Consequence directe: le producteur est un PROCESSUS TIERS, pas un fil du
//! daemon. Il vit donc dans le client, qui est deja le programme dont le metier
//! est de parler au daemon sans rien toucher lui-meme.
//!
//! # Le contrat, releve a la source
//!
//! `man systemd-sleep`, systemd 255 sur la machine d'essai Linux, le 23 aout
//! 2026: les executables du repertoire recoivent DEUX arguments. Le premier
//! vaut `pre` avant l'endormissement puis `post` apres le reveil; le second est
//! l'operation, parmi `suspend`, `hibernate`, `hybrid-sleep` et
//! `suspend-then-hibernate`. Le meme executable est appele aux deux moments.
//!
//! Deux phrases de cette page pesent sur ce qui suit. La premiere: << execution
//! of the action is not continued until all executables have finished >>. Le
//! hook BLOQUE la reprise de la machine tant qu'il n'a pas rendu la main, ce
//! qui interdit d'attendre quoi que ce soit du superviseur et impose une borne
//! de temps au dialogue. La seconde: systemd qualifie ces hooks de << hacks >>
//! et recommande l'interface Inhibitor - c'est-a-dire exactement la dependance
//! DBus que ce chemin existe pour eviter. La reserve est reelle et elle est
//! ecrite ici plutot que tue.
//!
//! # Ce que ce module ne fait pas
//!
//! Il ne decide pas s'il faut reposer les filtres: c'est la machine a etats qui
//! le sait, et elle refuse de rien poser dans `Disconnected`. Il ne mesure rien
//! de la veille qui vient d'avoir lieu - ni sa duree, ni ce qu'elle a laisse
//! des regles: c'est le travail de `bifrost_daemon::veille_linux`, et le
//! confondre avec celui-ci ferait dependre la reaffirmation d'un inventaire lu
//! apres une reprise, ce dont on se mefie precisement.

/// Les operations de veille que systemd nomme, et rien d'autre.
///
/// Relevees dans `man systemd-sleep` et non devinees. Une operation absente de
/// cette liste est REFUSEE plutot qu'acceptee: c'est le seul moyen qu'une
/// invocation avec de mauvais arguments ne fasse rien. Le prix de ce choix est
/// dit dans [`decider`].
pub const OPERATIONS: [&str; 4] = [
    "suspend",
    "hibernate",
    "hybrid-sleep",
    "suspend-then-hibernate",
];

/// Ce qu'une invocation du hook merite.
///
/// Trois issues et non deux. Confondre << appel legitime qui ne demande rien >>
/// et << appel que je n'ai pas compris >> rendrait les deux indiscernables dans
/// le journal, alors que le premier arrive a chaque endormissement et que le
/// second veut dire que le contrat de systemd a change sous nos pieds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Prevenir le daemon.
    Signaler,
    /// Appel prevu par le contrat, mais qui ne demande rien. La phase `pre` en
    /// est le seul cas: systemd appelle le meme executable avant d'endormir.
    RienAFaire(String),
    /// Invocation hors du contrat. Ne rien faire, et le dire fort.
    Refus(String),
}

/// Faut-il prevenir le daemon, au vu des deux arguments de systemd.
///
/// Pure, donc falsifiable sans endormir quoi que ce soit - ce qui compte
/// beaucoup ici, ou la mesure de bout en bout demande une machine capable de
/// dormir et n'en a pas.
///
/// La comparaison est EXACTE, sans normalisation de casse: le contrat de
/// systemd l'est aussi, et accepter `POST` reviendrait a se rendre sensible a
/// un appelant qui n'est pas systemd. L'operation est verifiee avant la phase,
/// de sorte qu'un mode de veille inconnu se signale des l'ENDORMISSEMENT,
/// c'est-a-dire avant que la machine ne dorme et non apres.
///
/// Le prix de ce refus est reel et doit etre nomme: si systemd publiait une
/// cinquieme operation, ce code ne la reconnaitrait pas et la politique ne
/// serait pas reposee au reveil de ce mode-la. Il ne le ferait pas en silence -
/// c'est ce que `Refus` garantit - mais il ne le ferait pas.
pub fn decider(phase: &str, operation: &str) -> Decision {
    if !OPERATIONS.contains(&operation) {
        return Decision::Refus(format!(
            "operation de veille inconnue: {operation:?}. systemd n'en nomme que \
             {}. Si cette machine en connait une de plus, ce programme ne la \
             reconnait pas et ne reposera pas la politique a son reveil.",
            OPERATIONS.join(", ")
        ));
    }
    match phase {
        "post" => Decision::Signaler,
        "pre" => Decision::RienAFaire(format!(
            "phase pre de {operation}: la machine s'endort, il n'y a rien a \
             reposer avant qu'elle se reveille"
        )),
        autre => Decision::Refus(format!(
            "phase inconnue: {autre:?}. systemd n'appelle ce programme qu'avec \
             pre ou post."
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Le reveil, et lui seul, previent le daemon.
    #[test]
    fn le_reveil_previent_le_daemon() {
        for operation in OPERATIONS {
            assert_eq!(
                decider("post", operation),
                Decision::Signaler,
                "post {operation} doit prevenir le daemon"
            );
        }
    }

    /// L'endormissement ne previent personne.
    ///
    /// La garde qui compte le plus: systemd appelle le MEME executable avant et
    /// apres. Sans elle, chaque endormissement ferait reposer la politique une
    /// fois de trop, et surtout le hook ne mesurerait plus rien - un daemon qui
    /// recoit une reprise a l'aller comme au retour ne peut plus servir a dire
    /// qu'une reprise a eu lieu.
    #[test]
    fn l_endormissement_ne_previent_personne() {
        for operation in OPERATIONS {
            assert!(
                matches!(decider("pre", operation), Decision::RienAFaire(_)),
                "pre {operation} ne doit rien declencher"
            );
        }
    }

    /// Une phase que systemd n'emet pas est refusee, pas interpretee.
    #[test]
    fn une_phase_inconnue_est_refusee() {
        for phase in ["", "POST", "Post", "post ", "resume", "pre-suspend"] {
            match decider(phase, "suspend") {
                Decision::Refus(raison) => assert!(
                    raison.contains(&format!("{phase:?}")),
                    "le refus doit citer ce qu'il a recu: {raison}"
                ),
                autre => panic!("phase {phase:?} acceptee: {autre:?}"),
            }
        }
    }

    /// Une operation que systemd ne nomme pas est refusee, et le refus dit ce
    /// qui est connu - sans quoi personne ne saurait quoi corriger.
    #[test]
    fn une_operation_inconnue_est_refusee_en_disant_ce_qui_est_connu() {
        match decider("post", "sieste") {
            Decision::Refus(raison) => {
                assert!(raison.contains("sieste"), "{raison}");
                for connue in OPERATIONS {
                    assert!(raison.contains(connue), "{connue} doit etre cite: {raison}");
                }
            }
            autre => panic!("operation inventee acceptee: {autre:?}"),
        }
    }

    /// Une invocation sans argument ne fait rien.
    ///
    /// Le cas le plus banal et le plus dangereux: le hook lance a la main, ou
    /// par un systemd dont la convention d'appel aurait change.
    #[test]
    fn une_invocation_sans_argument_ne_fait_rien() {
        assert!(matches!(decider("", ""), Decision::Refus(_)));
    }
}

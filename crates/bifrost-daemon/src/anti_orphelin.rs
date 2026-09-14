//! La garde qui interdit a un processus lance par le daemon de lui survivre.
//!
//! Deux composants ont exactement le meme besoin et le nomment separement
//! aujourd'hui: le coeur tiers, dont l'ecoute SOCKS orpheline serait une sortie
//! que plus personne ne supervise, et le resolveur chiffre, dont l'ecoute
//! orpheline sur le :53 continuerait de servir la machine sans que rien ne
//! l'explique. La propriete est la meme, la garde doit donc etre la meme.
//!
//! Le tuer depuis le code d'arret ne suffit pas: si le daemon est tue
//! brutalement, ou s'effondre, ce code ne tourne pas. La garantie est donc
//! demandee au SYSTEME, avant tout code de nettoyage.
//!
//! # Ce que Windows offre, et pourquoi c'est plus fort que Linux
//!
//! Un objet Job portant `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` tue ses membres
//! des que la derniere poignee du Job se ferme. La documentation le dit sans
//! ambiguite: "if the job has the JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE flag
//! specified, closing the last job object handle terminates all associated
//! processes and then destroys the job object itself" (Microsoft Learn, Job
//! Objects, page datee du 14/07/2025).
//!
//! Or Windows ferme toujours les poignees d'un processus disparu, quelle
//! qu'ait ete la cause. La garde ne depend donc d'AUCUN signal delivrable,
//! contrairement a `PR_SET_PDEATHSIG` sous Linux, que le noyau efface
//! silencieusement des que les identifiants du processus changent.
//!
//! # Pourquoi le daemon LUI-MEME entre dans le job
//!
//! La meme page: "After a process is associated with a job, by default any
//! child processes it creates using CreateProcess are also associated with the
//! job." Inscrire le daemon fait donc entrer chaque enfant dans le job A SA
//! NAISSANCE, et non apres coup.
//!
//! La difference n'est pas cosmetique. Inscrire l'enfant APRES `CreateProcess`
//! laisse une fenetre - entre le lancement et l'inscription - pendant laquelle
//! une mort du daemon laisse un orphelin. C'est la meme course que Linux
//! traite explicitement en verifiant `getppid() == 1` apres avoir arme
//! `PR_SET_PDEATHSIG`. Ici elle n'est pas traitee: elle n'existe pas.
//!
//! Les jobs imbriques rendent la chose sure meme si le daemon tourne deja dans
//! un job pose par autre chose - un conteneur, un hote de service: "The ability
//! to nest jobs was added in Windows 8 and Windows Server 2012."
//!
//! # Le piege de la poignee heritable
//!
//! Si un enfant HERITAIT la poignee du job, il en resterait un porteur apres la
//! mort du daemon: la derniere poignee ne se fermerait pas, et la garde ne
//! tirerait jamais. `CreateJobObjectW` avec des attributs nuls rend une poignee
//! NON heritable, ce qui est exactement ce qu'il faut. Ne jamais lui passer un
//! `SECURITY_ATTRIBUTES` avec `bInheritHandle` a vrai.

#[cfg(windows)]
mod windows_impl {
    use std::os::windows::io::{AsRawHandle, BorrowedHandle};

    use bifrost_core::{Error, Result};
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectExtendedLimitInformation, SetInformationJobObject,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    /// Poignee de job, fermee a la destruction - et c'est cette fermeture qui
    /// tue les membres.
    ///
    /// Volontairement sans `Clone`: dupliquer la poignee ajouterait un porteur,
    /// donc retarderait la garde jusqu'a la fermeture du dernier.
    pub struct Garde(HANDLE);

    // SAFETY: `Garde` ne detient qu'un HANDLE de job Windows. Les appels qui le
    // manipulent (CloseHandle, AssignProcessToJobObject, IsProcessInJob) sont
    // surs vis-a-vis des threads, donc l'envoyer entre fils est licite.
    unsafe impl Send for Garde {}
    // SAFETY: memes raisons; l'acces partage ne fait que passer le HANDLE a ces
    // appels Windows, sans etat interne mutable non protege.
    unsafe impl Sync for Garde {}

    impl Drop for Garde {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` est un HANDLE de job non nul (teste au-dessus);
                // CloseHandle le ferme une seule fois, a la destruction.
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    impl Garde {
        /// Un job arme, sans aucun membre.
        ///
        /// Public pour les recettes: c'est le seul moyen d'eprouver la
        /// semantique du systeme sans inscrire le processus de test, qu'un
        /// `Drop` tuerait.
        pub fn nue() -> Result<Self> {
            // SAFETY: les deux null sont les attributs de securite et le nom, tous deux
            // optionnels; CreateJobObjectW rend un HANDLE ou null (teste ensuite).
            let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if job.is_null() {
                return Err(Error::Dns(format!(
                    "CreateJobObject: {}",
                    std::io::Error::last_os_error()
                )));
            }
            let garde = Self(job);

            // SAFETY: JOBOBJECT_EXTENDED_LIMIT_INFORMATION n'est fait que d'entiers et de
            // structures POD pour lesquels tout-a-zero est une valeur initiale valide.
            let mut limites: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            limites.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            // SAFETY: `garde.0` est un HANDLE de job valide; `limites` vit pendant l'appel
            // et la taille passee est exactement celle de la structure pointee.
            let pose = unsafe {
                SetInformationJobObject(
                    garde.0,
                    JobObjectExtendedLimitInformation,
                    (&raw const limites).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };
            if pose == 0 {
                return Err(Error::Dns(format!(
                    "SetInformationJobObject: {}",
                    std::io::Error::last_os_error()
                )));
            }
            Ok(garde)
        }

        /// Inscrit un processus deja lance.
        ///
        /// Reserve aux recettes et aux cas ou le processus preexiste: le
        /// chemin normal est [`Garde::armer`], qui fait entrer les enfants a
        /// leur naissance et ne laisse donc aucune fenetre.
        pub fn inscrire(&self, processus: BorrowedHandle<'_>) -> Result<()> {
            // SAFETY: `self.0` est un HANDLE de job valide et `processus` un handle
            // emprunte vivant pendant l'appel.
            if unsafe { AssignProcessToJobObject(self.0, processus.as_raw_handle()) } == 0 {
                return Err(Error::Dns(format!(
                    "AssignProcessToJobObject: {}",
                    std::io::Error::last_os_error()
                )));
            }
            Ok(())
        }

        /// Cree le job et y inscrit le PROCESSUS COURANT.
        ///
        /// Prefere [`armer_pour_le_processus`] au chemin normal: la valeur
        /// rendue ici ne doit JAMAIS etre jetee tant que le processus vit,
        /// puisque la fermeture de la poignee est precisement ce qui tue les
        /// membres - dont il fait maintenant partie.
        pub fn armer() -> Result<Self> {
            let garde = Self::nue()?;
            // `GetCurrentProcess` rend une PSEUDO-poignee, constante et
            // toujours valide, qu'il ne faut surtout pas fermer.
            // `BorrowedHandle` dit exactement cela: empruntee, jamais possedee.
            // SAFETY: GetCurrentProcess rend une pseudo-poignee constante et toujours
            // valide; borrow_raw l'emprunte sans jamais la fermer.
            let moi = unsafe { BorrowedHandle::borrow_raw(GetCurrentProcess()) };
            garde.inscrire(moi)?;
            Ok(garde)
        }

        /// Ce processus est-il membre de CE job?
        ///
        /// La poignee du job et non `null`: `IsProcessInJob(p, null, ..)`
        /// repondrait "membre d'un job quelconque", ce qui est vrai pour
        /// beaucoup de processus sans rien dire de notre garde.
        pub fn contient(&self, processus: BorrowedHandle<'_>) -> Result<bool> {
            let mut dedans: i32 = 0;
            // SAFETY: `processus` est un handle emprunte vivant pendant l'appel, `self.0`
            // le HANDLE du job, et `dedans` une sortie i32 valide.
            if unsafe { IsProcessInJob(processus.as_raw_handle(), self.0, &raw mut dedans) } == 0 {
                return Err(Error::Dns(format!(
                    "IsProcessInJob: {}",
                    std::io::Error::last_os_error()
                )));
            }
            Ok(dedans != 0)
        }
    }

    /// Arme la garde une fois, pour toute la vie du processus.
    ///
    /// La valeur n'est jamais detruite, et c'est voulu: le seul moment ou l'on
    /// veut que la poignee se ferme est la mort du processus, dont le systeme
    /// se charge. Un `Drop` qui surviendrait plus tot tuerait le processus
    /// courant, puisqu'il est lui-meme membre.
    ///
    /// Appels suivants: la meme garde, jamais une seconde.
    pub fn armer_pour_le_processus() -> Result<&'static Garde> {
        static GARDE: std::sync::OnceLock<Garde> = std::sync::OnceLock::new();
        if let Some(g) = GARDE.get() {
            return Ok(g);
        }
        let garde = Garde::armer()?;
        // `set` echoue si une autre course a gagne: dans ce cas la sienne fait
        // l'affaire, les deux sont equivalentes.
        let _ = GARDE.set(garde);
        GARDE
            .get()
            .ok_or_else(|| Error::Dns("garde anti-orphelin non posee".to_owned()))
    }
}

#[cfg(windows)]
pub use windows_impl::{Garde, armer_pour_le_processus};

#[cfg(all(test, windows))]
mod recettes {
    use super::Garde;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    /// Un processus qui vit assez longtemps pour qu'on l'observe mourir.
    fn dormeur() -> std::process::Child {
        Command::new("cmd")
            .args(["/C", "ping -n 30 127.0.0.1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("lancer le dormeur")
    }

    /// La propriete que tout le module achete. Sans elle, le reste est du
    /// decor: on peut creer un job, y inscrire un processus et le voir
    /// survivre, si le drapeau n'a pas ete pose comme il faut.
    #[test]
    fn fermer_le_job_tue_ses_membres() {
        use std::os::windows::io::AsHandle;

        let mut enfant = dormeur();
        let garde = Garde::nue().expect("job");
        garde.inscrire(enfant.as_handle()).expect("inscription");

        // Vivant avant la fermeture: sinon le test passerait pour la mauvaise
        // raison, un enfant qui n'aurait jamais demarre.
        assert!(
            matches!(enfant.try_wait(), Ok(None)),
            "le dormeur devait etre vivant avant la fermeture du job"
        );

        drop(garde);

        let echeance = Instant::now() + Duration::from_secs(5);
        while Instant::now() < echeance {
            if let Ok(Some(_)) = enfant.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = enfant.kill();
        panic!("le membre a survecu a la fermeture du job");
    }
}

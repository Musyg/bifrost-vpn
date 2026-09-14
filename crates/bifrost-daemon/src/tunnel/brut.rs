//! Une interface TUN NUE, sans chiffrement, pour le chemin par coeur.
//!
//! Le tunnel WireGuard chiffre dans l'interface elle-meme. Un coeur ne fait pas
//! cela: il ouvre un SOCKS local, et le systeme doit y etre mene. Le plan le
//! dit, document 04 partie 4: le superviseur "expose un SOCKS local unique
//! stable vers lequel le systeme (via TUN) est route". Cette interface est ce
//! TUN.
//!
//! Elle joue exactement le meme role que l'interface WireGuard vis-a-vis du
//! kill switch: c'est elle que la politique designe comme `tunnel_interface`,
//! et rien n'est a changer de ce cote. Ce qui differe est ce qui la remplit.
//!
//! # Pourquoi ecrite a la main
//!
//! Les bibliotheques qui font cela apportent aussi leur gestion de routes et
//! d'interfaces. Mesure faite le 19 aout 2026 sur la plus recommandee du
//! moment: 55 paquets supplementaires, dont `wasm-bindgen`, du macOS, deux
//! versions de `netlink-packet-route`, et surtout de quoi manipuler les routes,
//! c'est-a-dire precisement ce que ce depot s'est reserve.
//!
//! Le refus n'est donc pas de principe, c'est celui que `wg-quick` a deja
//! recu: un composant qui gere lui-meme routes et DNS entre en conflit avec le
//! kill switch et la machine a etats. Et l'en-tete de [`crate::coeurs::socks`]
//! a deja formule la regle pour le client SOCKS5: la surface utilisee tient en
//! un appel systeme, et un produit de securite n'a pas a tirer un arbre de
//! dependances pour ca. Ici l'appel est `ioctl(TUNSETIFF)`.
//!
//! # Pourquoi un nom trop long est REFUSE et non tronque
//!
//! Le kill switch designe l'interface par son NOM sous Linux. Un nom tronque
//! creerait une interface differente de celle qu'on croit avoir demandee, et la
//! politique permettrait alors une interface qui n'est pas la notre - ou
//! aucune. Tronquer en silence transformerait une faute de frappe en fuite.

/// Longueur utile d'un nom d'interface: `IFNAMSIZ` vaut 16, zero final compris.
pub const NOM_MAX: usize = 15;

/// Le nom, valide et encode pour `ifreq`, ou la raison du refus.
///
/// Pur, donc teste partout et pas seulement la ou un TUN peut s'ouvrir.
pub fn encoder_nom(nom: &str) -> Result<[u8; NOM_MAX + 1], String> {
    if nom.is_empty() {
        return Err(
            "nom d'interface vide: le noyau en choisirait un lui-meme, et le kill switch designerait alors une interface dont personne ne connait le nom".to_owned(),
        );
    }
    if nom.len() > NOM_MAX {
        return Err(format!(
            "nom d'interface '{nom}' trop long ({} octets pour {NOM_MAX} au plus): refuse plutot que tronque, car une troncature silencieuse designerait une AUTRE interface que celle que le kill switch protege",
            nom.len()
        ));
    }
    // Le noyau traite le champ comme une chaine C dans un chemin de sysfs. Un
    // zero, une barre oblique ou une espace y produiraient une interface
    // inatteignable ou un nom qui n'est pas celui qu'on a demande.
    if let Some(mauvais) = nom
        .chars()
        .find(|c| *c == '\0' || *c == '/' || c.is_whitespace() || !c.is_ascii())
    {
        return Err(format!(
            "nom d'interface '{nom}' invalide: le caractere {mauvais:?} n'est pas admis dans un nom d'interface"
        ));
    }
    if nom == "." || nom == ".." {
        return Err(format!(
            "nom d'interface '{nom}' invalide: le noyau range les interfaces dans une arborescence, ou ce nom designe un repertoire"
        ));
    }
    let mut champ = [0u8; NOM_MAX + 1];
    champ[..nom.len()].copy_from_slice(nom.as_bytes());
    Ok(champ)
}

/// Capacite de l'anneau Wintun, en octets.
///
/// Quatre mebioctets, la valeur de l'exemple de l'amont. Plus petit, une rafale
/// se perd; plus grand, on immobilise de la memoire non paginee pour rien.
#[cfg_attr(not(windows), allow(dead_code))]
pub const ANNEAU: u32 = 0x40_0000;

/// Les bornes que le pilote impose: puissance de deux, entre 128 Kio et 64 Mio.
pub const ANNEAU_MIN: u32 = 0x2_0000;
pub const ANNEAU_MAX: u32 = 0x400_0000;

/// La taille maximale d'un paquet IP que le pilote accepte.
#[cfg_attr(not(windows), allow(dead_code))]
pub const PAQUET_MAX: usize = 0xFFFF;

/// Cette capacite d'anneau est-elle acceptable, et sinon pourquoi.
///
/// Pure et hors du `cfg`, comme [`encoder_nom`]: c'est une REGLE du pilote, elle
/// se lit d'un coup d'oeil et s'eprouve sur les deux plateformes meme si une
/// seule l'applique. Une capacite refusee par le pilote se traduirait sinon par
/// un echec au montage, au pire moment.
pub fn capacite_valide(capacite: u32) -> Result<(), String> {
    if !(ANNEAU_MIN..=ANNEAU_MAX).contains(&capacite) {
        return Err(format!(
            "capacite d'anneau {capacite}: le pilote exige entre {ANNEAU_MIN} et {ANNEAU_MAX}"
        ));
    }
    if !capacite.is_power_of_two() {
        return Err(format!(
            "capacite d'anneau {capacite}: le pilote exige une puissance de deux"
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{NOM_MAX, encoder_nom};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    /// `IFF_TUN | IFF_NO_PI`: paquets IP bruts, sans les quatre octets
    /// d'en-tete que le noyau ajouterait sinon. Le TUN doit rendre exactement
    /// ce que la pile utilisateur attend, sans preambule a retirer.
    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;
    const TUNSETIFF: libc::c_ulong = 0x400454ca;
    const CHEMIN: &std::ffi::CStr = c"/dev/net/tun";

    /// La structure que `TUNSETIFF` attend. Seuls le nom et les drapeaux
    /// servent; le reste de l'union `ifreq` est laisse a zero.
    #[repr(C)]
    struct Requete {
        nom: [u8; NOM_MAX + 1],
        drapeaux: libc::c_short,
        bourrage: [u8; 22],
    }

    /// Une interface TUN ouverte. Sa fermeture la detruit.
    pub struct TunBrut {
        fd: OwnedFd,
        nom: String,
    }

    impl TunBrut {
        pub fn nom(&self) -> &str {
            &self.nom
        }

        /// Lit UN paquet IP. Bloque tant qu'il n'y en a pas.
        ///
        /// Un TUN est oriente message et non flux: chaque lecture rend un
        /// paquet entier, ou echoue. Un paquet plus grand que `tampon` est
        /// TRONQUE par le noyau, silencieusement - d'ou le refus explicite
        /// ci-dessous plutot qu'un paquet a moitie lu remis a la pile.
        pub fn lire(&self, tampon: &mut [u8]) -> std::io::Result<usize> {
            // SAFETY: `tampon` est valide et long de `tampon.len()`.
            let n = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    tampon.as_mut_ptr().cast(),
                    tampon.len(),
                )
            };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let n = n as usize;
            if n == tampon.len() {
                return Err(std::io::Error::other(format!(
                    "paquet d'au moins {n} octets pour un tampon de {}: il aurait ete tronque, et un paquet tronque remis a la pile serait pire qu'un paquet perdu",
                    tampon.len()
                )));
            }
            Ok(n)
        }

        /// Ecrit UN paquet IP vers la pile du systeme.
        ///
        /// Le noyau le traite comme s'il etait arrive par cette interface. Il
        /// doit donc etre complet et correct: en-tete IP valide, somme de
        /// controle juste, sans quoi il est jete sans un mot.
        pub fn ecrire(&self, paquet: &[u8]) -> std::io::Result<usize> {
            // SAFETY: `paquet` est valide et long de `paquet.len()`.
            let n =
                unsafe { libc::write(self.fd.as_raw_fd(), paquet.as_ptr().cast(), paquet.len()) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(n as usize)
        }

        /// Passe le descripteur en mode non bloquant.
        ///
        /// Necessaire des qu'une boucle asynchrone tient le TUN: une lecture
        /// bloquante y arreterait non pas un fil mais l'ordonnanceur entier,
        /// et avec lui tout ce que le superviseur a en cours - dont le kill
        /// switch.
        pub fn mettre_non_bloquant(&self) -> std::io::Result<()> {
            // SAFETY: descripteur valide, et `F_GETFL` ne modifie rien.
            let drapeaux = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_GETFL) };
            if drapeaux < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: on ne change qu'un bit des drapeaux relus a l'instant.
            let code = unsafe {
                libc::fcntl(
                    self.fd.as_raw_fd(),
                    libc::F_SETFL,
                    drapeaux | libc::O_NONBLOCK,
                )
            };
            if code < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        }

        /// Attend qu'un paquet soit lisible, au plus `delai`.
        ///
        /// Existe pour que personne n'ait a choisir entre une lecture qui
        /// bloque sans fin et une attente active. Rend `false` a l'expiration,
        /// ce qui n'est pas une erreur: un reseau silencieux est un etat
        /// normal.
        pub fn attendre_lisible(&self, delai: std::time::Duration) -> std::io::Result<bool> {
            let mut attente = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ms = delai.as_millis().min(libc::c_int::MAX as u128) as libc::c_int;
            // SAFETY: un seul descripteur, valide, et `attente` vit le temps de
            // l'appel.
            let code = unsafe { libc::poll(&raw mut attente, 1, ms) };
            match code {
                -1 => Err(std::io::Error::last_os_error()),
                0 => Ok(false),
                _ => Ok(true),
            }
        }
    }

    impl AsRawFd for TunBrut {
        /// Expose le descripteur pour que `tokio` puisse le surveiller.
        ///
        /// L'emprunt est volontairement en lecture seule: `TunBrut` reste
        /// proprietaire, et l'interface disparait toujours avec lui.
        fn as_raw_fd(&self) -> std::os::fd::RawFd {
            self.fd.as_raw_fd()
        }
    }

    /// Ouvre une interface TUN portant ce nom exactement.
    pub fn ouvrir(nom: &str) -> Result<TunBrut, String> {
        let champ = encoder_nom(nom)?;
        // SAFETY: chemin constant, valide et termine par un zero.
        let brut = unsafe { libc::open(CHEMIN.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if brut < 0 {
            let e = std::io::Error::last_os_error();
            let chemin = CHEMIN.to_string_lossy();
            return Err(format!(
                "{chemin} non ouvrable ({e}): le module tun est-il charge, et le processus a-t-il CAP_NET_ADMIN?"
            ));
        }
        // SAFETY: `brut` est un descripteur valide que personne d'autre ne
        // detient; `OwnedFd` le fermera, y compris si l'ioctl echoue.
        let fd = unsafe { OwnedFd::from_raw_fd(brut) };

        let mut requete = Requete {
            nom: champ,
            drapeaux: IFF_TUN | IFF_NO_PI,
            bourrage: [0; 22],
        };
        // SAFETY: `requete` a la disposition memoire d'`ifreq` et vit le temps
        // de l'appel.
        let code = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF, &raw mut requete) };
        if code < 0 {
            let e = std::io::Error::last_os_error();
            return Err(format!(
                "TUNSETIFF refuse pour '{nom}' ({e}): nom deja pris, ou CAP_NET_ADMIN absent"
            ));
        }

        // Relire le nom que le noyau a REELLEMENT donne, au lieu de supposer
        // qu'il a pris le notre. C'est ce nom que le kill switch designera, et
        // le supposer serait exactement l'erreur que la troncature illustre.
        let fin = requete.nom.iter().position(|o| *o == 0).unwrap_or(NOM_MAX);
        let rendu = String::from_utf8_lossy(&requete.nom[..fin]).into_owned();
        if rendu != nom {
            return Err(format!(
                "le noyau a nomme l'interface '{rendu}' et non '{nom}': le kill switch protegerait une interface qui n'est pas celle-ci"
            ));
        }
        Ok(TunBrut { fd, nom: rendu })
    }
}

#[cfg(target_os = "linux")]
pub use linux::{TunBrut, ouvrir};

/// La moitie Windows: Wintun.
///
/// Le meme role que la moitie Linux, par un mecanisme qui n'a rien de commun.
/// Sous Linux le TUN est un descripteur de fichier, et lire un paquet est un
/// `read`. Ici c'est une paire d'anneaux en memoire partagee avec le pilote:
/// on demande un paquet, on obtient un POINTEUR dedans, et on le rend une fois
/// recopie. Rien ne bloque jamais - l'anneau vide repond tout de suite - et
/// c'est un evenement Windows qui signale l'arrivee.
///
/// # Pourquoi Wintun et pas WireGuardNT
///
/// Le depot charge deja `wireguard.dll` ([`super::super::wgnt::dll`]), et ce
/// n'est pas la meme bibliotheque: WireGuardNT cree un adaptateur WIREGUARD,
/// qui chiffre lui-meme avec ses propres cles. Un coeur ne fait pas cela - il
/// ouvre un SOCKS local, et le systeme doit y etre mene par une interface
/// ORDINAIRE, qui rend des paquets IP en clair.
///
/// # La DLL n'est pas dans le depot
///
/// Elle est telechargee par le client, verifiee par empreinte epinglee, et
/// posee a cote du binaire: `bifrost pilote recuperer`. Le daemon ne la
/// telecharge pas et ne le fera pas - une recette le lui interdit deja
/// (`frontiere_reseau.rs`). Ici on ne fait que la charger, par CHEMIN ABSOLU:
/// charger par nom laisserait jouer l'ordre de recherche de Windows, et un
/// processus qui tourne en SYSTEM et charge une DLL par nom est un detournement
/// en puissance. Meme regle que pour `wireguard.dll`.
#[cfg(windows)]
mod fenetres {
    use std::ffi::c_void;
    use std::path::PathBuf;

    use super::{ANNEAU, PAQUET_MAX, capacite_valide, encoder_nom};

    use windows_sys::Win32::Foundation::{
        ERROR_BUFFER_OVERFLOW, ERROR_HANDLE_EOF, ERROR_NO_MORE_ITEMS, FreeLibrary, HANDLE, HMODULE,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows_sys::Win32::System::LibraryLoader::{
        GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
    };
    use windows_sys::Win32::System::Threading::WaitForSingleObject;
    use windows_sys::core::GUID;

    /// Le nom du fichier, celui que le client pose a cote du binaire.
    pub const NOM_DLL: &str = "wintun.dll";

    /// La categorie affichee dans les proprietes de l'adaptateur.
    ///
    /// La notre, et jamais "Wintun": le document 06 rappelle que les projets
    /// qui partagent un pilote generique se desinstallent mutuellement.
    const CATEGORIE: &str = "Bifrost";

    /// Le GUID de l'interface, fixe.
    ///
    /// Fixe et non tire au hasard, pour la meme raison que du cote WireGuardNT:
    /// Windows attache le profil reseau - public ou prive, donc les regles du
    /// pare-feu - a l'identite de l'interface. Un GUID different a chaque montee
    /// ferait redecouvrir un reseau inconnu a chaque fois. Distinct de celui de
    /// l'adaptateur WireGuard: deux adaptateurs ne peuvent pas partager un GUID,
    /// et les deux chemins doivent pouvoir coexister.
    pub const GUID_TUN: GUID = GUID::from_u128(0x0bd4f5a1_6c1e_4f8d_9a3e_2f7b41c9e530);

    /// Pour les recettes, qui ne doivent jamais toucher a l'interface de
    /// production.
    ///
    /// Sous `cfg(test)` et non simplement public: il n'a aucune raison
    /// d'exister dans un binaire livre, ou il ne serait qu'une seconde identite
    /// d'interface que personne n'utilise.
    ///
    /// Un par recette, et non un seul partage: deux adaptateurs ne peuvent pas
    /// avoir le meme GUID, donc un GUID unique rendrait ces recettes dependantes
    /// de l'ordre - vertes seules, rouges ensemble. Le depot fait deja ainsi
    /// pour les adaptateurs de la sonde de chute.
    #[cfg(test)]
    pub const GUID_RECETTE: [GUID; 4] = [
        GUID::from_u128(0x0bd4f5a1_6c1e_4f8d_9a3e_2f7b41c9e531),
        GUID::from_u128(0x0bd4f5a1_6c1e_4f8d_9a3e_2f7b41c9e532),
        GUID::from_u128(0x0bd4f5a1_6c1e_4f8d_9a3e_2f7b41c9e533),
        GUID::from_u128(0x0bd4f5a1_6c1e_4f8d_9a3e_2f7b41c9e534),
    ];

    type CreateAdapterFn =
        unsafe extern "system" fn(*const u16, *const u16, *const GUID) -> *mut c_void;
    type CloseAdapterFn = unsafe extern "system" fn(*mut c_void);
    type GetAdapterLuidFn = unsafe extern "system" fn(*mut c_void, *mut NET_LUID_LH);
    type GetRunningDriverVersionFn = unsafe extern "system" fn() -> u32;
    type StartSessionFn = unsafe extern "system" fn(*mut c_void, u32) -> *mut c_void;
    type EndSessionFn = unsafe extern "system" fn(*mut c_void);
    type GetReadWaitEventFn = unsafe extern "system" fn(*mut c_void) -> HANDLE;
    type ReceivePacketFn = unsafe extern "system" fn(*mut c_void, *mut u32) -> *mut u8;
    type ReleaseReceivePacketFn = unsafe extern "system" fn(*mut c_void, *const u8);
    type AllocateSendPacketFn = unsafe extern "system" fn(*mut c_void, u32) -> *mut u8;
    type SendPacketFn = unsafe extern "system" fn(*mut c_void, *const u8);

    /// `wintun.dll` chargee, avec ses points d'entree resolus.
    ///
    /// Tous a la construction. Un chargement partiel laisserait le daemon
    /// decouvrir un symbole manquant au milieu d'une montee, kill switch deja
    /// arme.
    pub struct Wintun {
        module: HMODULE,
        creer: CreateAdapterFn,
        fermer: CloseAdapterFn,
        luid: GetAdapterLuidFn,
        version: GetRunningDriverVersionFn,
        ouvrir_session: StartSessionFn,
        finir_session: EndSessionFn,
        evenement: GetReadWaitEventFn,
        recevoir: ReceivePacketFn,
        rendre: ReleaseReceivePacketFn,
        allouer: AllocateSendPacketFn,
        envoyer: SendPacketFn,
    }

    // SAFETY: le module reste charge tant que la structure vit, et les
    // pointeurs de fonction sont sans etat. Le pilote serialise lui-meme les
    // acces par session.
    unsafe impl Send for Wintun {}
    // SAFETY: memes raisons que l'impl Send ci-dessus; le module reste charge
    // tant que la structure vit, les pointeurs de fonction sont sans etat, et le
    // pilote serialise lui-meme les acces par session.
    unsafe impl Sync for Wintun {}

    /// Le chemin attendu de la DLL: a cote du binaire.
    pub fn chemin_attendu() -> Result<PathBuf, String> {
        let exe =
            std::env::current_exe().map_err(|e| format!("chemin du binaire introuvable: {e}"))?;
        let dir = exe
            .parent()
            .ok_or_else(|| format!("binaire sans repertoire parent: {}", exe.display()))?;
        Ok(dir.join(NOM_DLL))
    }

    /// Une chaine terminee par un zero, telle que l'API la veut.
    fn large(s: &str) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    impl Wintun {
        /// Charge la DLL posee a cote du binaire.
        pub fn charger() -> Result<Self, String> {
            Self::charger_depuis(&chemin_attendu()?)
        }

        pub fn charger_depuis(chemin: &std::path::Path) -> Result<Self, String> {
            if !chemin.is_file() {
                return Err(format!(
                    "{} introuvable. Ce depot ne distribue aucun binaire tiers: \
                     le recuperer avec\n    bifrost pilote recuperer",
                    chemin.display()
                ));
            }
            let large_chemin = {
                use std::os::windows::ffi::OsStrExt;
                chemin
                    .as_os_str()
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect::<Vec<u16>>()
            };
            // SAFETY: chemin valide, termine par un zero, vivant le temps de
            // l'appel.
            let module = unsafe {
                LoadLibraryExW(
                    large_chemin.as_ptr(),
                    std::ptr::null_mut(),
                    LOAD_LIBRARY_SEARCH_SYSTEM32,
                )
            };
            if module.is_null() {
                return Err(format!(
                    "chargement de {} refuse ({}): architecture du binaire et de la \
                     DLL differentes?",
                    chemin.display(),
                    std::io::Error::last_os_error()
                ));
            }

            let resoudre = |nom: &str| -> Result<*const c_void, String> {
                let mut c = nom.as_bytes().to_vec();
                c.push(0);
                // SAFETY: module valide, nom termine par un zero.
                let p = unsafe { GetProcAddress(module, c.as_ptr()) };
                match p {
                    Some(f) => Ok(f as *const c_void),
                    None => Err(format!(
                        "{nom} absent de {}: la DLL n'est pas celle attendue",
                        chemin.display()
                    )),
                }
            };

            // SAFETY: chaque symbole est resolu depuis la DLL de l'amont, et sa
            // signature est celle de `wintun.h`.
            let charge = unsafe {
                Self {
                    module,
                    creer: std::mem::transmute::<*const c_void, CreateAdapterFn>(resoudre(
                        "WintunCreateAdapter",
                    )?),
                    fermer: std::mem::transmute::<*const c_void, CloseAdapterFn>(resoudre(
                        "WintunCloseAdapter",
                    )?),
                    luid: std::mem::transmute::<*const c_void, GetAdapterLuidFn>(resoudre(
                        "WintunGetAdapterLUID",
                    )?),
                    version: std::mem::transmute::<*const c_void, GetRunningDriverVersionFn>(
                        resoudre("WintunGetRunningDriverVersion")?,
                    ),
                    ouvrir_session: std::mem::transmute::<*const c_void, StartSessionFn>(resoudre(
                        "WintunStartSession",
                    )?),
                    finir_session: std::mem::transmute::<*const c_void, EndSessionFn>(resoudre(
                        "WintunEndSession",
                    )?),
                    evenement: std::mem::transmute::<*const c_void, GetReadWaitEventFn>(resoudre(
                        "WintunGetReadWaitEvent",
                    )?),
                    recevoir: std::mem::transmute::<*const c_void, ReceivePacketFn>(resoudre(
                        "WintunReceivePacket",
                    )?),
                    rendre: std::mem::transmute::<*const c_void, ReleaseReceivePacketFn>(resoudre(
                        "WintunReleaseReceivePacket",
                    )?),
                    allouer: std::mem::transmute::<*const c_void, AllocateSendPacketFn>(resoudre(
                        "WintunAllocateSendPacket",
                    )?),
                    envoyer: std::mem::transmute::<*const c_void, SendPacketFn>(resoudre(
                        "WintunSendPacket",
                    )?),
                }
            };
            Ok(charge)
        }

        /// La version du pilote EN COURS D'EXECUTION, ou `None` s'il n'est pas
        /// charge.
        ///
        /// Charger la DLL ne charge pas le pilote: tant qu'aucune interface
        /// n'existe, il n'y a rien dans le noyau et cette fonction rend zero.
        /// C'est ce qui permet de verifier la DLL sans rien installer.
        pub fn version_pilote(&self) -> Option<(u16, u16)> {
            // SAFETY: pointeur de fonction resolu, sans argument.
            let v = unsafe { (self.version)() };
            if v == 0 {
                return None;
            }
            Some(((v >> 16) as u16, (v & 0xffff) as u16))
        }
    }

    impl Drop for Wintun {
        fn drop(&mut self) {
            // SAFETY: module charge par `LoadLibraryExW` et non encore libere.
            unsafe {
                FreeLibrary(self.module);
            }
        }
    }

    /// Une interface Wintun ouverte, avec sa session. Sa fermeture la detruit.
    pub struct TunBrut {
        wintun: Wintun,
        adaptateur: *mut c_void,
        session: *mut c_void,
        attente: HANDLE,
        nom: String,
    }

    // SAFETY: les poignees appartiennent a cette structure et le pilote
    // serialise les acces a une session.
    unsafe impl Send for TunBrut {}
    // SAFETY: memes raisons que l'impl Send ci-dessus; les poignees appartiennent
    // a cette structure et le pilote serialise les acces a une session.
    unsafe impl Sync for TunBrut {}

    impl TunBrut {
        pub fn nom(&self) -> &str {
            &self.nom
        }

        /// Le LUID de l'interface.
        ///
        /// C'est lui que le kill switch designe sous Windows, la ou Linux
        /// designe le nom. Le lire ici evite de le rechercher par nom plus tard,
        /// ce qui rouvrirait la question de savoir si c'est bien la notre.
        pub fn luid(&self) -> u64 {
            let mut luid = NET_LUID_LH { Value: 0 };
            // SAFETY: adaptateur valide, `luid` vit le temps de l'appel.
            unsafe {
                (self.wintun.luid)(self.adaptateur, &raw mut luid);
                luid.Value
            }
        }

        pub fn version_pilote(&self) -> Option<(u16, u16)> {
            self.wintun.version_pilote()
        }

        /// Lit UN paquet IP. Ne bloque JAMAIS.
        ///
        /// L'anneau vide rend `WouldBlock`, comme le ferait un descripteur non
        /// bloquant sous Linux: la moitie Linux doit d'ailleurs y etre mise
        /// explicitement, alors qu'ici c'est la seule facon dont l'API
        /// fonctionne. Un appelant qui veut attendre passe par
        /// [`Self::attendre_lisible`].
        ///
        /// Un paquet plus grand que `tampon` est REFUSE et perdu, jamais
        /// tronque: un paquet tronque remis a la pile serait pire qu'un paquet
        /// perdu. Meme choix que sous Linux, pour la meme raison.
        pub fn lire(&self, tampon: &mut [u8]) -> std::io::Result<usize> {
            let mut taille: u32 = 0;
            // SAFETY: session valide; `taille` vit le temps de l'appel.
            let paquet = unsafe { (self.wintun.recevoir)(self.session, &raw mut taille) };
            if paquet.is_null() {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as i32) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "aucun paquet dans l'anneau",
                    ));
                }
                // L'amont documente cette erreur comme "l'adaptateur se
                // termine". Ce n'est pas une panne, c'est une FIN: la rendre
                // comme zero octet lu est ce qu'un lecteur de flux comprend,
                // et c'est ce qui fait s'arreter la pile proprement au lieu de
                // boucler sur une erreur qui ne passera pas.
                if e.raw_os_error() == Some(ERROR_HANDLE_EOF as i32) {
                    return Ok(0);
                }
                return Err(e);
            }
            let taille = taille as usize;
            // Rendu dans tous les cas: garder un paquet immobiliserait
            // l'anneau, qui est circulaire et ne se vide pas tout seul.
            let resultat = if taille > tampon.len() {
                Err(std::io::Error::other(format!(
                    "paquet de {taille} octets pour un tampon de {}: il aurait ete \
                     tronque, et un paquet tronque remis a la pile serait pire qu'un \
                     paquet perdu",
                    tampon.len()
                )))
            } else {
                // SAFETY: le pilote garantit `taille` octets lisibles a partir
                // de `paquet` jusqu'a ce qu'il soit rendu.
                unsafe { std::ptr::copy_nonoverlapping(paquet, tampon.as_mut_ptr(), taille) };
                Ok(taille)
            };
            // SAFETY: `paquet` vient d'etre rendu par cette meme session.
            unsafe { (self.wintun.rendre)(self.session, paquet) };
            resultat
        }

        /// Ecrit UN paquet IP vers la pile du systeme.
        ///
        /// Le systeme le traite comme s'il etait arrive par cette interface. Il
        /// doit donc etre complet et correct: en-tete IP valide, somme de
        /// controle juste, sans quoi il est jete sans un mot.
        ///
        /// Un anneau plein rend `WouldBlock` plutot qu'une erreur: c'est un etat
        /// passager, et le confondre avec une panne ferait tomber le tunnel pour
        /// une rafale.
        pub fn ecrire(&self, paquet: &[u8]) -> std::io::Result<usize> {
            if paquet.is_empty() || paquet.len() > PAQUET_MAX {
                return Err(std::io::Error::other(format!(
                    "paquet de {} octets: le pilote accepte de 1 a {PAQUET_MAX}",
                    paquet.len()
                )));
            }
            // SAFETY: session valide.
            let place = unsafe { (self.wintun.allouer)(self.session, paquet.len() as u32) };
            if place.is_null() {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(ERROR_BUFFER_OVERFLOW as i32) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "anneau d'emission plein",
                    ));
                }
                return Err(e);
            }
            // SAFETY: le pilote garantit `paquet.len()` octets inscriptibles a
            // partir de `place` jusqu'a l'envoi.
            unsafe {
                std::ptr::copy_nonoverlapping(paquet.as_ptr(), place, paquet.len());
                (self.wintun.envoyer)(self.session, place);
            }
            Ok(paquet.len())
        }

        /// L'evenement qui se declenche quand l'anneau de reception cesse
        /// d'etre vide.
        ///
        /// Expose pour que le passeur puisse l'attendre en meme temps que son
        /// propre evenement d'arret, d'un seul appel. Ne pas le fermer:
        /// l'amont ecrit qu'il appartient a la session, qui s'en charge.
        pub fn evenement_de_lecture(&self) -> HANDLE {
            self.attente
        }

        /// Attend qu'un paquet soit lisible, au plus `delai`.
        ///
        /// Rend `false` a l'expiration, ce qui n'est pas une erreur: un reseau
        /// silencieux est un etat normal. Meme contrat que sous Linux, ou c'est
        /// un `poll`.
        pub fn attendre_lisible(&self, delai: std::time::Duration) -> std::io::Result<bool> {
            let ms = delai.as_millis().min(u32::MAX as u128 - 1) as u32;
            // SAFETY: `attente` est l'evenement de cette session, valide tant
            // qu'elle vit.
            match unsafe { WaitForSingleObject(self.attente, ms) } {
                WAIT_OBJECT_0 => Ok(true),
                WAIT_TIMEOUT => Ok(false),
                _ => Err(std::io::Error::last_os_error()),
            }
        }
    }

    impl Drop for TunBrut {
        /// L'interface disparait avec la structure, comme sous Linux.
        ///
        /// L'ordre compte: la session avant l'adaptateur. L'inverse laisserait
        /// une session sur un adaptateur ferme.
        fn drop(&mut self) {
            // SAFETY: poignees valides, fermees une seule fois.
            unsafe {
                if !self.session.is_null() {
                    (self.wintun.finir_session)(self.session);
                }
                if !self.adaptateur.is_null() {
                    (self.wintun.fermer)(self.adaptateur);
                }
            }
        }
    }

    /// Ouvre une interface TUN portant ce nom exactement.
    pub fn ouvrir(nom: &str) -> Result<TunBrut, String> {
        ouvrir_avec(nom, &GUID_TUN, ANNEAU)
    }

    /// La meme, avec le GUID et la capacite en parametres.
    ///
    /// Le GUID est injecte pour que les recettes n'aient jamais a toucher a
    /// l'interface de production: deux adaptateurs ne peuvent pas partager un
    /// GUID, et une recette qui reprendrait celui du tunnel le detruirait.
    pub fn ouvrir_avec(nom: &str, guid: &GUID, capacite: u32) -> Result<TunBrut, String> {
        // Le meme nom est valide des deux cotes, et la regle la plus stricte
        // gagne. Windows accepterait plus long, mais un profil doit pouvoir
        // passer d'une machine a l'autre sans devenir refusable.
        //
        // Rien a relire ensuite, contrairement a Linux: Wintun ne renomme ni
        // ne tronque, il refuse. La relecture n'aurait rien a comparer.
        let _ = encoder_nom(nom)?;
        capacite_valide(capacite)?;

        let wintun = Wintun::charger()?;
        let nom_large = large(nom);
        let categorie = large(CATEGORIE);

        // SAFETY: chaines terminees par un zero et vivantes le temps de
        // l'appel; `guid` pointe sur un GUID valide.
        let adaptateur = unsafe { (wintun.creer)(nom_large.as_ptr(), categorie.as_ptr(), guid) };
        if adaptateur.is_null() {
            let e = std::io::Error::last_os_error();
            return Err(format!(
                "creation de l'interface '{nom}' refusee ({e}): le pilote s'installe \
                 au premier adaptateur, ce qui demande les droits d'administrateur"
            ));
        }

        // SAFETY: adaptateur valide, capacite deja verifiee.
        let session = unsafe { (wintun.ouvrir_session)(adaptateur, capacite) };
        if session.is_null() {
            let e = std::io::Error::last_os_error();
            // SAFETY: adaptateur valide, ferme une seule fois.
            unsafe { (wintun.fermer)(adaptateur) };
            return Err(format!("ouverture de la session sur '{nom}' refusee ({e})"));
        }

        // SAFETY: session valide. L'evenement appartient a la session et n'est
        // pas a fermer separement.
        let attente = unsafe { (wintun.evenement)(session) };

        Ok(TunBrut {
            wintun,
            adaptateur,
            session,
            attente,
            nom: nom.to_owned(),
        })
    }
}

#[cfg(windows)]
pub use fenetres::{TunBrut, ouvrir, ouvrir_avec};

#[cfg(test)]
mod tests {
    use super::*;

    /// Les bornes du pilote, eprouvees des deux cotes.
    #[test]
    fn la_capacite_d_anneau_suit_les_bornes_du_pilote() {
        capacite_valide(ANNEAU).expect("le defaut doit etre acceptable");
        capacite_valide(ANNEAU_MIN).expect("la borne basse est acceptable");
        capacite_valide(ANNEAU_MAX).expect("la borne haute est acceptable");

        let e = capacite_valide(ANNEAU_MIN / 2).expect_err("sous la borne basse");
        assert!(e.contains(&ANNEAU_MIN.to_string()), "{e}");
        let e = capacite_valide(ANNEAU_MAX * 2).expect_err("au-dessus de la borne haute");
        assert!(e.contains(&ANNEAU_MAX.to_string()), "{e}");

        // Dans les bornes, mais pas une puissance de deux: le pilote refuse, et
        // le decouvrir au montage serait le decouvrir trop tard.
        let e = capacite_valide(ANNEAU + 1).expect_err("doit exiger une puissance de deux");
        assert!(e.contains("puissance de deux"), "{e}");
    }

    #[test]
    fn un_nom_ordinaire_est_encode_et_termine_par_un_zero() {
        let champ = encoder_nom("bifrost0").expect("nom valide");
        assert_eq!(&champ[..8], b"bifrost0");
        assert_eq!(champ[8], 0, "le noyau lit une chaine C");
    }

    #[test]
    fn un_nom_a_la_limite_passe() {
        let nom = "a".repeat(NOM_MAX);
        let champ = encoder_nom(&nom).expect("un nom de la longueur maximale est valide");
        assert_eq!(champ[NOM_MAX], 0);
    }

    /// La longueur maximale d'un nom vient de l'OS, pas d'elle-meme.
    ///
    /// Les deux recettes voisines emploient `NOM_MAX` des DEUX cotes - le nom
    /// fabrique et la borne comparee - si bien qu'une valeur fausse s'y teste
    /// elle-meme et ne rougit pas: mesure du 04/09/2026 sur dev-windows, 15
    /// mute en 14 muette. Ici la borne est confrontee a `IFNAMSIZ`, qui vaut
    /// 16 zero final compris dans `linux/if.h`. Trop grande, le noyau tronque
    /// en silence et le kill switch designe une AUTRE interface que celle
    /// qu'il croit proteger.
    #[test]
    fn la_longueur_max_de_nom_vient_d_ifnamsiz() {
        const IFNAMSIZ: usize = 16;
        assert_eq!(NOM_MAX + 1, IFNAMSIZ, "IFNAMSIZ, zero final compris");
    }

    /// La taille maximale d'un paquet est celle du champ de longueur IP.
    ///
    /// `PAQUET_MAX` borne un paquet lu sur l'anneau Wintun; aucune recette ne
    /// l'epinglait, une mutation d'un cran restait muette (04/09/2026,
    /// dev-windows). Elle derive du protocole: le champ de longueur totale
    /// d'un en-tete IP tient sur seize bits, donc un paquet ne depasse pas
    /// 65535 octets.
    #[test]
    fn la_taille_max_de_paquet_est_celle_du_champ_ip() {
        assert_eq!(PAQUET_MAX, u16::MAX as usize);
    }

    /// Le point du module: tronquer transformerait une faute de frappe en
    /// fuite, puisque le kill switch designe l'interface par son nom.
    #[test]
    fn un_nom_trop_long_est_refuse_et_non_tronque() {
        let e = encoder_nom(&"a".repeat(NOM_MAX + 1)).expect_err("doit etre refuse");
        assert!(e.contains("trop long"), "{e}");
        assert!(
            e.contains("tronque"),
            "le message doit dire POURQUOI on refuse plutot que de tronquer: {e}"
        );
    }

    /// Un nom vide fait choisir le noyau, et personne ne saurait quelle
    /// interface le kill switch doit proteger.
    #[test]
    fn un_nom_vide_est_refuse() {
        let e = encoder_nom("").expect_err("doit etre refuse");
        assert!(e.contains("vide"), "{e}");
    }

    #[test]
    fn les_caracteres_impossibles_sont_refuses() {
        for mauvais in [
            "bif/rost",
            "bif rost",
            "bif\0rost",
            "bifrost\u{e9}",
            ".",
            "..",
        ] {
            let e = encoder_nom(mauvais).expect_err(&format!("'{mauvais}' devait etre refuse"));
            assert!(e.contains("invalide"), "{mauvais}: {e}");
        }
    }

    /// Pourquoi ce qui suit ne peut pas tourner ici, s'il y a une raison.
    ///
    /// Le depot ne veut pas de PASSED par defaut: un test qui ne peut pas
    /// s'executer dit SKIPPED et dit pourquoi, faute de quoi une recette verte
    /// signifierait tantot "verifie", tantot "pas regarde".
    #[cfg(target_os = "linux")]
    fn raison_de_sauter() -> Option<&'static str> {
        if !std::path::Path::new("/dev/net/tun").exists() {
            return Some("/dev/net/tun absent, le module tun n'est pas charge");
        }
        // SAFETY: `geteuid` ne touche rien et ne peut pas echouer.
        if unsafe { libc::geteuid() } != 0 {
            return Some("ouvrir un TUN demande CAP_NET_ADMIN, ce test tourne sans");
        }
        None
    }

    #[cfg(target_os = "linux")]
    fn ip(args: &[&str]) -> Result<(), String> {
        let sortie = std::process::Command::new("ip")
            .args(args)
            .output()
            .map_err(|e| format!("ip {args:?} non lancable: {e}"))?;
        if !sortie.status.success() {
            return Err(format!(
                "ip {args:?}: {}",
                String::from_utf8_lossy(&sortie.stderr).trim()
            ));
        }
        Ok(())
    }

    /// Un TUN adresse et en service, plus les deux bouts de sa liaison.
    ///
    /// `rang` distingue les tests entre eux: sans lui, deux tests paralleles se
    /// disputeraient le meme sous-reseau, et le second echouerait sur un
    /// conflit de route qui n'aurait rien a voir avec ce qu'il mesure.
    #[cfg(target_os = "linux")]
    fn tun_monte(rang: u8) -> (TunBrut, std::net::Ipv4Addr, std::net::Ipv4Addr) {
        let octet = (std::process::id() % 100) as u8 * 2 + rang;
        let nom = format!("bft{octet}");
        let tun = ouvrir(&nom).expect("le TUN doit s'ouvrir");
        let nous = std::net::Ipv4Addr::new(10, 77, octet, 1);
        let la_bas = std::net::Ipv4Addr::new(10, 77, octet, 2);
        ip(&["addr", "add", &format!("{nous}/24"), "dev", &nom]).unwrap();
        ip(&["link", "set", &nom, "up"]).unwrap();
        (tun, nous, la_bas)
    }

    /// Lit jusqu'au premier paquet qui convient, ou rend `None` a l'expiration.
    ///
    /// Le filtre n'est pas une commodite: une interface qui vient d'etre mise
    /// en service emet d'elle-meme des sollicitations IPv6, et prendre le
    /// premier paquet venu ferait echouer le test sur du trafic qui n'est pas
    /// le sien.
    #[cfg(target_os = "linux")]
    fn lire_jusqu_a(
        tun: &TunBrut,
        delai: std::time::Duration,
        convient: impl Fn(&[u8]) -> bool,
    ) -> Option<Vec<u8>> {
        let fin = std::time::Instant::now() + delai;
        let mut tampon = [0u8; 2048];
        while let Some(reste) = fin.checked_duration_since(std::time::Instant::now()) {
            if !tun.attendre_lisible(reste).ok()? {
                return None;
            }
            let n = tun.lire(&mut tampon).ok()?;
            if convient(&tampon[..n]) {
                return Some(tampon[..n].to_vec());
            }
        }
        None
    }

    /// La somme de controle d'Internet, RFC 1071.
    #[cfg(any(target_os = "linux", windows))]
    fn somme_internet(octets: &[u8]) -> u16 {
        let mut somme = 0u32;
        for paire in octets.chunks(2) {
            somme += u32::from(u16::from_be_bytes([paire[0], *paire.get(1).unwrap_or(&0)]));
        }
        while somme >> 16 != 0 {
            somme = (somme & 0xffff) + (somme >> 16);
        }
        !(somme as u16)
    }

    /// Un datagramme UDP complet, en-tete IPv4 compris.
    ///
    /// Ecrit a la main parce que c'est le sujet: le noyau traite ce qu'on ecrit
    /// sur le TUN comme s'il etait arrive du reseau, donc il faut le lui donner
    /// tel qu'il l'attend, somme de controle juste comprise.
    /// Un datagramme UDP complet, en-tete IPv4 comprise.
    ///
    /// Les deux plateformes en ont besoin: ecrire sur un TUN demande un paquet
    /// entier et correct, sinon la pile le jette sans un mot.
    #[cfg(any(target_os = "linux", windows))]
    fn datagramme(
        source: std::net::Ipv4Addr,
        destination: std::net::Ipv4Addr,
        port_source: u16,
        port_destination: u16,
        charge: &[u8],
    ) -> Vec<u8> {
        let total = (20 + 8 + charge.len()) as u16;
        let mut p = Vec::with_capacity(total as usize);
        p.push(0x45); // IPv4, en-tete de 20 octets
        p.push(0); // aucune differenciation de service
        p.extend_from_slice(&total.to_be_bytes());
        p.extend_from_slice(&[0, 0]); // identifiant
        p.extend_from_slice(&[0x40, 0]); // ne pas fragmenter
        p.push(64); // duree de vie
        p.push(17); // UDP
        p.extend_from_slice(&[0, 0]); // somme de controle, remplie ci-dessous
        p.extend_from_slice(&source.octets());
        p.extend_from_slice(&destination.octets());
        let somme = somme_internet(&p[..20]);
        p[10..12].copy_from_slice(&somme.to_be_bytes());
        p.extend_from_slice(&port_source.to_be_bytes());
        p.extend_from_slice(&port_destination.to_be_bytes());
        p.extend_from_slice(&((8 + charge.len()) as u16).to_be_bytes());
        // Somme de controle UDP a zero: permise en IPv4, et voulue ici, ou l'on
        // mesure l'ecriture sur le TUN et non l'arithmetique d'une somme.
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(charge);
        p
    }

    /// Ouvre un vrai TUN.
    #[cfg(target_os = "linux")]
    #[test]
    fn un_tun_s_ouvre_sous_le_nom_demande() {
        if let Some(raison) = raison_de_sauter() {
            println!("SKIPPED: {raison}");
            return;
        }
        let nom = format!("bftest{}", std::process::id() % 100_000);
        let tun = ouvrir(&nom).expect("le TUN doit s'ouvrir");
        assert_eq!(tun.nom(), nom);
        // L'interface doit exister TANT que le descripteur vit.
        assert!(
            std::path::Path::new(&format!("/sys/class/net/{nom}")).exists(),
            "l'interface devait exister pendant que le descripteur est ouvert"
        );
        drop(tun);
        // Et disparaitre avec lui: un TUN qui survivrait a son proprietaire
        // laisserait une interface que le kill switch permet et que plus
        // personne ne remplit.
        assert!(
            !std::path::Path::new(&format!("/sys/class/net/{nom}")).exists(),
            "l'interface devait disparaitre a la fermeture du descripteur"
        );
    }

    /// Sans le mode non bloquant, une lecture sur un TUN silencieux
    /// n'arreterait pas un fil mais l'ordonnanceur entier.
    #[cfg(target_os = "linux")]
    #[test]
    fn en_mode_non_bloquant_une_lecture_a_vide_rend_la_main() {
        if let Some(raison) = raison_de_sauter() {
            println!("SKIPPED: {raison}");
            return;
        }
        let (tun, _nous, _la_bas) = tun_monte(2);
        tun.mettre_non_bloquant().expect("le mode doit se poser");

        // Le TUN n'est PAS vide au depart, et supposer le contraire rendait ce
        // test fragile - il est passe vert avant d'echouer sur une autre
        // execution. Une interface qu'on vient de mettre en service emet
        // d'elle-meme des sollicitations IPv6, et c'est le phenomene que
        // `lire_jusqu_a` filtre plus bas.
        //
        // Ce qui se mesure n'est donc pas "la premiere lecture est vide", mais
        // la vraie propriete du mode non bloquant: la lecture finit par DIRE
        // qu'il n'y a rien, au lieu d'attendre sans fin.
        let mut tampon = [0u8; 2048];
        let fin = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match tun.lire(&mut tampon) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Ok(_) => assert!(
                    std::time::Instant::now() < fin,
                    "le TUN parle encore apres deux secondes: la lecture ne rend jamais WouldBlock"
                ),
                Err(e) => panic!("lecture en echec: {e}"),
            }
        }
    }

    /// Le sens qui compte pour le chemin par coeur: ce que le systeme emet
    /// ressort ici, et c'est de la que la pile utilisateur le prendra.
    #[cfg(target_os = "linux")]
    #[test]
    fn un_paquet_emis_par_le_systeme_arrive_sur_le_tun() {
        if let Some(raison) = raison_de_sauter() {
            println!("SKIPPED: {raison}");
            return;
        }
        let (tun, _nous, la_bas) = tun_monte(0);

        let emetteur = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        emetteur.send_to(b"bifrost", (la_bas, 9)).unwrap();

        let paquet = lire_jusqu_a(&tun, std::time::Duration::from_secs(3), |p| {
            p.len() >= 28
                && p[0] >> 4 == 4
                && p[9] == 17
                && std::net::Ipv4Addr::new(p[16], p[17], p[18], p[19]) == la_bas
        })
        .expect("le datagramme devait ressortir par le TUN");

        let entete = usize::from(paquet[0] & 0x0f) * 4;
        assert_eq!(
            &paquet[entete + 8..],
            b"bifrost",
            "le paquet doit arriver entier, sans en-tete de service ajoute par le noyau (IFF_NO_PI)"
        );
    }

    /// Un compteur du peripherique, tel que le noyau l'expose.
    #[cfg(target_os = "linux")]
    fn compteur(nom: &str, quoi: &str) -> u64 {
        std::fs::read_to_string(format!("/sys/class/net/{nom}/statistics/{quoi}"))
            .expect("le compteur doit etre lisible")
            .trim()
            .parse()
            .expect("le compteur doit etre un nombre")
    }

    /// Le sens inverse: ce qu'on ecrit entre dans la pile comme s'il etait
    /// arrive par cette interface. Sans lui, le TUN ne serait qu'une oreille.
    ///
    /// # Pourquoi un compteur et non une socket
    ///
    /// La premiere version de ce test attendait le datagramme sur une socket
    /// locale. Elle a echoue sur essai-linux le 19 aout 2026, et la mesure a
    /// montre pourquoi: `rx_packets` augmentait bien de 1 et `rx_bytes` de la
    /// taille exacte du paquet, mais la remise locale traverse la chaine INPUT,
    /// dont la politique est `DROP` sur cette machine. Avec un `-i <tun> -j
    /// ACCEPT` pose puis retire, la socket recevait la charge attendue depuis
    /// l'autre bout de la liaison - la preuve que le paquet etait juste et que
    /// le test mesurait le pare-feu de l'hote.
    ///
    /// Un test qui rougit selon le `ufw` de la machine ne dit rien sur ce code.
    /// Les compteurs du peripherique sont comptes AVANT tout filtrage, et c'est
    /// exactement la frontiere dont `ecrire` repond: les octets ont quitte
    /// l'espace utilisateur pour la pile, en un paquet, sur cette interface. Ce
    /// qu'il en advient ensuite est la politique de l'hote.
    ///
    /// La limite, qu'il faut dire: un compteur augmente aussi pour un paquet
    /// mal forme, qui serait jete plus loin. La justesse de l'en-tete, elle, a
    /// ete verifiee a la main par l'experience ci-dessus.
    #[cfg(target_os = "linux")]
    #[test]
    fn un_paquet_ecrit_sur_le_tun_entre_dans_la_pile() {
        if let Some(raison) = raison_de_sauter() {
            println!("SKIPPED: {raison}");
            return;
        }
        let (tun, nous, la_bas) = tun_monte(1);
        let nom = tun.nom().to_owned();
        let paquet = datagramme(la_bas, nous, 4242, 9, b"retour");

        let paquets_avant = compteur(&nom, "rx_packets");
        let octets_avant = compteur(&nom, "rx_bytes");

        assert_eq!(
            tun.ecrire(&paquet).expect("le TUN doit accepter le paquet"),
            paquet.len(),
            "une ecriture partielle laisserait un paquet tronque dans la pile"
        );

        assert_eq!(
            compteur(&nom, "rx_packets") - paquets_avant,
            1,
            "le noyau devait compter UN paquet entrant sur cette interface"
        );
        assert_eq!(
            compteur(&nom, "rx_bytes") - octets_avant,
            paquet.len() as u64,
            "le noyau devait compter exactement les octets ecrits"
        );
    }

    // ------------------------------------------------------ la moitie Windows

    /// Le vrai Wintun, sur la vraie machine.
    ///
    /// Dans le module et non dans `tests/`, pour la meme raison que le coffre:
    /// ces fonctions ne sont pas publiques hors du crate.
    #[cfg(windows)]
    mod fenetres_reelles {
        use super::super::{ANNEAU, fenetres};
        use std::time::Duration;

        /// Le processus est-il eleve.
        ///
        /// Le pilote s'installe au premier adaptateur, ce qui demande les droits
        /// d'administrateur. Une recette qui l'ignorerait echouerait pour une
        /// raison sans rapport avec ce qu'elle mesure.
        fn est_eleve() -> bool {
            use std::mem::size_of;
            use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
            use windows_sys::Win32::Security::{
                GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
            };
            use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

            // SAFETY: jeton du processus courant, champ de taille connue, et le
            // handle est referme sur tous les chemins.
            unsafe {
                let mut jeton: HANDLE = std::ptr::null_mut();
                if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut jeton) == 0 {
                    return false;
                }
                let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
                let mut taille = 0u32;
                let ok = GetTokenInformation(
                    jeton,
                    TokenElevation,
                    &raw mut elevation as *mut std::ffi::c_void,
                    size_of::<TOKEN_ELEVATION>() as u32,
                    &mut taille,
                );
                CloseHandle(jeton);
                ok != 0 && elevation.TokenIsElevated != 0
            }
        }

        /// Pourquoi la DLL ne peut pas etre chargee ici, ou `None`.
        fn raison_sans_dll() -> Option<String> {
            match fenetres::chemin_attendu() {
                Err(e) => Some(e),
                Ok(c) if !c.is_file() => Some(format!(
                    "{} absente: le depot ne distribue aucun binaire tiers, la \
                     recuperer avec 'bifrost pilote recuperer'",
                    c.display()
                )),
                Ok(_) => None,
            }
        }

        /// Pourquoi une interface ne peut pas etre creee ici, ou `None`.
        fn raison_sans_interface() -> Option<String> {
            if let Some(r) = raison_sans_dll() {
                return Some(r);
            }
            if !est_eleve() {
                return Some(
                    "le pilote s'installe au premier adaptateur, ce qui demande les \
                     droits d'administrateur"
                        .to_owned(),
                );
            }
            None
        }

        /// Tous les points d'entree, pas seulement le premier.
        ///
        /// Un chargement partiel laisserait le daemon decouvrir un symbole
        /// manquant au milieu d'une montee de tunnel, kill switch deja arme:
        /// c'est precisement ce que la resolution a la construction evite, et
        /// c'est donc cela qu'il faut mesurer.
        #[test]
        fn la_dll_se_charge_avec_tous_ses_points_d_entree() {
            if let Some(raison) = raison_sans_dll() {
                println!("SKIPPED: {raison}");
                return;
            }
            fenetres::Wintun::charger().expect("la DLL de l'amont doit se charger entiere");
        }

        /// Charger la DLL ne touche a rien sur la machine.
        ///
        /// La propriete qui rend le chargement anodin: le pilote n'entre dans le
        /// noyau qu'au premier adaptateur. Tant qu'aucune interface n'existe, la
        /// version du pilote en cours d'execution est nulle - et c'est ce qui
        /// permet de verifier la DLL sans rien installer.
        #[test]
        fn charger_la_dll_n_installe_pas_le_pilote() {
            if let Some(raison) = raison_sans_dll() {
                println!("SKIPPED: {raison}");
                return;
            }
            let w = fenetres::Wintun::charger().unwrap();
            match w.version_pilote() {
                None => {}
                // Une autre application peut tenir une interface Wintun au meme
                // moment - WireGuard, Tailscale. Le dire plutot que rougir: la
                // recette ne mesure pas leur presence.
                Some((h, b)) => println!(
                    "SKIPPED: un pilote Wintun {h}.{b} tourne deja sur cette machine, \
                     tenu par une autre application"
                ),
            }
        }

        /// Une interface s'ouvre, porte le nom demande, et disparait avec sa
        /// structure.
        ///
        /// Le pendant Windows de la recette Linux qui verifie que l'interface
        /// existe tant que le descripteur vit. Ici la preuve de la disparition
        /// est qu'une seconde ouverture sous le meme GUID reussit: deux
        /// adaptateurs ne peuvent pas partager un GUID.
        #[test]
        fn une_interface_s_ouvre_et_disparait_avec_sa_structure() {
            if let Some(raison) = raison_sans_interface() {
                println!("SKIPPED: {raison}");
                return;
            }
            let nom = "bft-essai0";
            {
                let tun = fenetres::ouvrir_avec(nom, &fenetres::GUID_RECETTE[0], ANNEAU)
                    .expect("l'interface doit s'ouvrir");
                assert_eq!(tun.nom(), nom);
                assert_ne!(
                    tun.luid(),
                    0,
                    "le LUID designe l'interface pour le kill switch"
                );
                assert!(
                    tun.version_pilote().is_some(),
                    "le pilote doit etre charge une fois l'adaptateur cree"
                );
            }
            // Si la premiere n'avait pas disparu, celle-ci echouerait.
            let encore = fenetres::ouvrir_avec(nom, &fenetres::GUID_RECETTE[0], ANNEAU)
                .expect("l'interface precedente doit avoir disparu avec sa structure");
            assert_eq!(encore.nom(), nom);
        }

        /// Un anneau vide n'est pas une panne.
        ///
        /// La distinction porte tout le reste: une boucle asynchrone qui prend
        /// l'anneau vide pour une erreur ferme le tunnel au premier silence du
        /// reseau. `WouldBlock` est ce que rendrait un descripteur non bloquant
        /// sous Linux, et c'est le meme contrat qui est offert ici.
        #[test]
        fn un_anneau_vide_rend_would_block_et_non_une_panne() {
            if let Some(raison) = raison_sans_interface() {
                println!("SKIPPED: {raison}");
                return;
            }
            let tun = fenetres::ouvrir_avec("bft-essai1", &fenetres::GUID_RECETTE[1], ANNEAU)
                .expect("l'interface doit s'ouvrir");

            // L'attente courte rend faux sans erreur: rien n'arrive sur une
            // interface que rien ne route.
            let mut vu_would_block = false;
            for _ in 0..8 {
                match tun.lire(&mut [0u8; 2048]) {
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        vu_would_block = true;
                        break;
                    }
                    // Windows peut deposer un paquet de decouverte sur une
                    // interface neuve. Le consommer et redemander.
                    Ok(_) => continue,
                    Err(e) => panic!("l'anneau vide ne doit pas rendre une panne: {e}"),
                }
            }
            assert!(
                vu_would_block,
                "l'anneau a rendu des paquets sans jamais se vider"
            );
            assert!(
                !tun.attendre_lisible(Duration::from_millis(50))
                    .expect("l'attente ne doit pas echouer"),
                "l'expiration doit rendre faux, et non une erreur"
            );
        }

        /// Le compteur d'entree de l'interface, tel que le systeme l'expose.
        fn paquets_entrants(luid: u64) -> u64 {
            use windows_sys::Win32::NetworkManagement::IpHelper::{GetIfEntry2, MIB_IF_ROW2};
            use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

            // SAFETY: la structure est mise a zero, seul le LUID est renseigne
            // avant l'appel, comme la documentation l'exige.
            unsafe {
                let mut ligne: MIB_IF_ROW2 = std::mem::zeroed();
                ligne.InterfaceLuid = NET_LUID_LH { Value: luid };
                let code = GetIfEntry2(&raw mut ligne);
                assert_eq!(code, 0, "GetIfEntry2 a refuse (code {code})");
                ligne.InUcastPkts
            }
        }

        /// Ce qu'on ecrit entre dans la pile comme s'il etait arrive par cette
        /// interface. Sans lui, le TUN ne serait qu'une oreille.
        ///
        /// Le compteur et non une socket, pour la raison que la moitie Linux a
        /// deja mesuree: la remise locale traverse le pare-feu de l'hote, et une
        /// recette qui rougit selon le pare-feu ne dit rien sur ce code. Le
        /// compteur d'entree de l'interface est compte avant tout filtrage, et
        /// c'est exactement la frontiere dont `ecrire` repond.
        ///
        /// La limite, qu'il faut dire: un compteur augmente aussi pour un paquet
        /// mal forme, qui serait jete plus loin.
        #[test]
        fn un_paquet_ecrit_sur_le_tun_entre_dans_la_pile() {
            if let Some(raison) = raison_sans_interface() {
                println!("SKIPPED: {raison}");
                return;
            }
            let tun = fenetres::ouvrir_avec("bft-essai2", &fenetres::GUID_RECETTE[2], ANNEAU)
                .expect("l'interface doit s'ouvrir");
            let luid = tun.luid();
            let paquet = super::datagramme(
                std::net::Ipv4Addr::new(10, 77, 0, 2),
                std::net::Ipv4Addr::new(10, 77, 0, 1),
                4242,
                9,
                b"bifrost",
            );

            let avant = paquets_entrants(luid);
            assert_eq!(
                tun.ecrire(&paquet).expect("le TUN doit accepter le paquet"),
                paquet.len(),
                "une ecriture partielle laisserait un paquet tronque dans la pile"
            );

            // Le compteur est mis a jour par le pilote de facon asynchrone: on
            // lui laisse un instant plutot que de mesurer la vitesse de Windows.
            let mut apres = avant;
            for _ in 0..50 {
                apres = paquets_entrants(luid);
                if apres > avant {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            assert!(
                apres > avant,
                "le systeme devait compter un paquet entrant sur cette interface \
                 ({avant} puis {apres})"
            );
        }

        /// Un paquet plus grand que le tampon est REFUSE, jamais tronque.
        #[test]
        fn un_paquet_trop_grand_pour_le_tampon_est_refuse_et_non_tronque() {
            if let Some(raison) = raison_sans_interface() {
                println!("SKIPPED: {raison}");
                return;
            }
            let tun = fenetres::ouvrir_avec("bft-essai3", &fenetres::GUID_RECETTE[3], ANNEAU)
                .expect("l'interface doit s'ouvrir");

            // Rien ne garantit qu'un paquet arrive: la recette mesure alors le
            // refus a vide, ce qui est deja la moitie utile. Le message dit
            // laquelle des deux a ete mesuree.
            let paquet = super::datagramme(
                std::net::Ipv4Addr::new(10, 77, 0, 2),
                std::net::Ipv4Addr::new(10, 77, 0, 1),
                4242,
                9,
                &[0u8; 600],
            );
            tun.ecrire(&paquet).expect("le TUN doit accepter le paquet");

            let mut vu = false;
            for _ in 0..50 {
                match tun.lire(&mut [0u8; 4]) {
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(e) => {
                        assert!(
                            e.to_string().contains("tronque"),
                            "le refus doit dire pourquoi: {e}"
                        );
                        vu = true;
                        break;
                    }
                    Ok(n) => panic!("un paquet de {n} octets a tenu dans un tampon de 4"),
                }
            }
            if !vu {
                println!(
                    "SKIPPED: aucun paquet n'est remonte du systeme sur cette interface, \
                     le refus de troncature n'a pas pu etre mesure"
                );
            }
        }
    }
}

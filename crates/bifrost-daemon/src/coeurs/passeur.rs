//! Ce qui mene le systeme du TUN jusqu'a la facade.
//!
//! Entre les deux il manque une traduction, et elle n'est pas mince: le TUN
//! rend des PAQUETS IP, le coeur attend des CONNEXIONS SOCKS5. Quelqu'un doit
//! donc tenir une pile TCP/IP en espace utilisateur - suivre les poignees de
//! main, les fenetres, les retransmissions - et, pour chaque flux reconnu,
//! ouvrir un CONNECT vers la destination d'origine.
//!
//! # Pourquoi une bibliotheque ici, alors que le TUN et le client SOCKS5 sont
//! ecrits a la main
//!
//! Parce que la regle du depot n'a jamais ete "tout ecrire". L'en-tete de
//! [`super::socks`] la formule exactement: la surface utilisee y tient en deux
//! echanges. Celle de [`crate::tunnel::brut`] tient en un `ioctl`. TCP ne tient
//! pas en deux echanges, et une pile ecrite pour l'occasion serait le composant
//! le moins eprouve d'un produit de securite. Le depot a d'ailleurs deja pris
//! `wireguard-control` pour le netlink, pour la meme raison.
//!
//! Ce qui est refuse reste refuse: une bibliotheque qui gererait routes, DNS ou
//! interfaces entrerait en conflit avec le kill switch et la machine a etats -
//! l'objection faite a `wg-quick`, puis a `tun-rs`.
//!
//! # Ce qui a ete mesure le 19 aout 2026, plutot que suppose
//!
//! Cout marginal en paquets reellement compiles (`cargo tree --edges normal`,
//! pas `cargo metadata`, qui compte aussi les dependances optionnelles que
//! personne n'active):
//!
//! | candidat | linux | windows | licence |
//! |---|---|---|---|
//! | `ipstack` 1.0.1 | +10 | +10 | Apache-2.0 |
//! | `netstack-smoltcp` 0.2.4 | +26 | +30 | MIT OR Apache-2.0 |
//! | `tun2proxy` 0.8.3 | +180 | - | tire du GPL-3.0-or-later |
//!
//! `tun2proxy` est ecarte deux fois: par la taille, et parce qu'il tire
//! `socks5-impl` en GPL-3.0-or-later, que la frontiere de licence du depot
//! refuse. Il apporte en prime `tproxy-config`, c'est-a-dire de la gestion de
//! routes - l'objection `wg-quick`, encore.
//!
//! `netstack-smoltcp` a pour lui de rouler sur `smoltcp`, dont
//! l'implementation de TCP est la plus relue du domaine. Mais il l'epingle en
//! 0.12 quand 0.14 est publiee, et ajoute seize paquets de plus que le
//! candidat retenu, dont toute la facade `futures` alors que ce programme est
//! en tokio.
//!
//! `ipstack` est retenu: il est en tokio, il annonce lui-meme ne gerer ni
//! routage, ni DNS, ni interfaces - exactement la frontiere qu'on lui demande
//! de respecter - et son `IpStack::new` est generique sur
//! `AsyncRead + AsyncWrite`, ce qui lui permet de prendre NOTRE TUN plutot
//! qu'un peripherique d'une autre bibliotheque.
//!
//! Le revers, qu'il faut dire: `ipstack` ecrit son propre TCP, moins relu que
//! `smoltcp`. L'exposition est cependant limitee par la position du composant.
//! Cette pile ne parle qu'a la machine locale, sur un lien sans perte et sans
//! delai; le vrai controle de congestion se joue sur la connexion sortante du
//! coeur, hors de sa portee.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use ipstack::{IpStack, IpStackConfig, IpStackStream};
#[cfg(target_os = "linux")]
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::tunnel::brut::TunBrut;

/// MTU par defaut, celle d'un lien Ethernet ordinaire.
///
/// Ce n'est qu'un defaut: [`servir`] prend la MTU en parametre, parce qu'elle
/// doit valoir celle de l'interface. Plus haute, la pile produirait des paquets
/// que le noyau refuserait; plus basse, elle segmenterait sans raison. En faire
/// une constante partagee revenait a esperer que les deux restent d'accord.
pub const MTU: u16 = 1500;

/// Le TUN, vu comme un flux asynchrone d'octets.
///
/// La pile veut lire et ecrire sans bloquer. Ce que cela demande n'a rien de
/// commun d'une plateforme a l'autre, et c'est tout ce que cette enveloppe fait:
/// le raccord. Ce qui est au-dessus - `ipstack`, [`servir`], le menage vers la
/// facade - ne sait pas sur quelle plateforme il tourne.
#[cfg(target_os = "linux")]
pub struct Tun(AsyncFd<TunBrut>);

#[cfg(target_os = "linux")]
impl Tun {
    /// Prend possession du TUN et le rend surveillable par l'ordonnanceur.
    ///
    /// Le mode non bloquant est pose ICI et non laisse a l'appelant: un
    /// descripteur bloquant confie a `AsyncFd` arreterait l'ordonnanceur entier
    /// a la premiere lecture a vide, et avec lui tout ce que le superviseur a
    /// en cours - dont le kill switch.
    pub fn nouveau(tun: TunBrut) -> io::Result<Self> {
        tun.mettre_non_bloquant()?;
        Ok(Self(AsyncFd::new(tun)?))
    }

    pub fn nom(&self) -> &str {
        self.0.get_ref().nom()
    }
}

#[cfg(target_os = "linux")]
impl AsyncRead for Tun {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        tampon: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let moi = self.get_mut();
        loop {
            let mut garde = ready!(moi.0.poll_read_ready(cx))?;
            let libre = tampon.initialize_unfilled();
            match garde.try_io(|tun| tun.get_ref().lire(libre)) {
                Ok(Ok(n)) => {
                    tampon.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                // Le noyau a retire le paquet entre l'annonce et la lecture:
                // il faut redemander, pas rendre une lecture vide, qu'un
                // lecteur prendrait pour une fin de flux.
                Err(_encore) => continue,
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl AsyncWrite for Tun {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        paquet: &[u8],
    ) -> Poll<io::Result<usize>> {
        let moi = self.get_mut();
        loop {
            let mut garde = ready!(moi.0.poll_write_ready(cx))?;
            match garde.try_io(|tun| tun.get_ref().ecrire(paquet)) {
                Ok(rendu) => return Poll::Ready(rendu),
                Err(_encore) => continue,
            }
        }
    }

    /// Rien a vider: chaque ecriture est deja un paquet remis au noyau.
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// Un TUN ne se ferme pas a moitie. Il disparait avec son descripteur.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// La meme enveloppe sous Windows, par un tout autre mecanisme.
///
/// # Il n'y a pas d'`AsyncFd` ici, et il ne peut pas y en avoir
///
/// `AsyncFd` repose sur le fait que le systeme sait signaler la lisibilite d'un
/// DESCRIPTEUR. Wintun ne rend pas de descripteur: il rend une paire d'anneaux
/// en memoire partagee et un EVENEMENT Windows qui se declenche quand l'anneau
/// de reception cesse d'etre vide. Rien dans `tokio` ne surveille un evenement
/// Windows - sa couche d'entrees-sorties y passe par les ports d'achevement,
/// que `mio` n'ouvre qu'aux sockets et aux tubes nommes.
///
/// # Pourquoi un fil dedie plutot que `spawn_blocking`
///
/// Parce que la documentation de `spawn_blocking` le dit: elle est faite pour
/// du travail BORNE, et chaque appel immobilise un fil du bassin pour toute sa
/// duree. Une boucle de lecture de TUN dure autant que le tunnel. L'y mettre
/// reduirait durablement la capacite du bassin, au detriment de tout ce que le
/// daemon y fait par ailleurs.
///
/// # Pourquoi un canal plutot qu'un reveil de tache
///
/// L'alternative fait moins de copies: le fil ne servirait que de sonneur, et
/// `poll_read` lirait lui-meme dans l'anneau - la lecture ne bloque jamais.
/// Elle demande en revanche une poignee de main entre le fil et la tache, parce
/// que l'evenement reste declenche tant qu'il reste des paquets: sans cela le
/// fil tournerait a vide. Deux evenements manuels de plus, et une concurrence
/// dont la justesse ne se lit plus d'un coup d'oeil.
///
/// Le canal coute une allocation et une recopie par paquet, et rend la
/// concurrence triviale: un fil qui produit, une tache qui consomme, et c'est
/// `tokio` qui porte les reveils. Dans un produit de securite, cet echange-la
/// se fait dans ce sens. C'est le meme raisonnement que l'en-tete de ce module
/// tient deja pour `ipstack` contre une pile TCP ecrite a la main.
///
/// Le canal est BORNE, et ce n'est pas un detail: une pile qui n'avale plus
/// fait remplir l'anneau, et le pilote jette - exactement ce qui arrive sous
/// Linux quand le noyau ne peut plus mettre en file. Un canal sans borne
/// remplacerait une perte de paquets par une consommation de memoire sans fin.
#[cfg(windows)]
pub struct Tun {
    tun: std::sync::Arc<TunBrut>,
    recus: tokio::sync::mpsc::Receiver<io::Result<Vec<u8>>>,
    arret: std::sync::Arc<Arret>,
    fil: Option<std::thread::JoinHandle<()>>,
    nom: String,
}

/// Un evenement Windows a nous, pour interrompre la veille.
///
/// L'amont ne promet nulle part que terminer la session libere un fil bloque
/// dans l'attente, ni qu'il est sur de terminer une session pendant qu'un autre
/// fil est dans `WintunReceivePacket`. On ne batit pas sur un silence: le fil
/// est reveille par un evenement qui nous appartient, puis rejoint, et la
/// session n'est terminee qu'apres.
#[cfg(windows)]
struct Arret(windows_sys::Win32::Foundation::HANDLE);

// SAFETY: une poignee d'evenement Windows est utilisable depuis n'importe quel
// fil; c'est meme sa raison d'etre.
#[cfg(windows)]
unsafe impl Send for Arret {}
// SAFETY: memes raisons que l'impl Send ci-dessus; une poignee d'evenement
// Windows se partage entre fils sans etat interne mutable non protege.
#[cfg(windows)]
unsafe impl Sync for Arret {}

#[cfg(windows)]
impl Arret {
    fn nouveau() -> io::Result<Self> {
        use windows_sys::Win32::System::Threading::CreateEventW;
        // Manuel plutot qu'automatique: une fois l'arret demande, il doit le
        // rester. Un evenement automatique se reinitialiserait au premier fil
        // reveille, et un second attendant ne le verrait jamais.
        // SAFETY: aucun attribut, evenement manuel non declenche, sans nom.
        let h = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if h.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(h))
    }

    fn declencher(&self) {
        use windows_sys::Win32::System::Threading::SetEvent;
        // SAFETY: poignee valide tant que la structure vit.
        unsafe {
            SetEvent(self.0);
        }
    }
}

#[cfg(windows)]
impl Drop for Arret {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        // SAFETY: poignee creee par `CreateEventW`, fermee une seule fois.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

#[cfg(windows)]
impl Tun {
    /// Prend possession du TUN et met un fil de veille a son ecoute.
    pub fn nouveau(tun: TunBrut) -> io::Result<Self> {
        // Borne a une MTU pres de cent paquets: assez pour absorber une rafale,
        // assez peu pour que la memoire immobilisee reste de l'ordre de
        // l'anneau du pilote plutot que de la memoire de la machine.
        const EN_ATTENTE: usize = 128;

        let nom = tun.nom().to_owned();
        let tun = std::sync::Arc::new(tun);
        let arret = std::sync::Arc::new(Arret::nouveau()?);
        let (envoi, recus) = tokio::sync::mpsc::channel(EN_ATTENTE);

        let veille = std::sync::Arc::clone(&tun);
        // Partage plutot que recopie de la poignee: `Arret` porte le `Send` qui
        // manque a une poignee nue, et sa fermeture reste unique.
        let sonnette = std::sync::Arc::clone(&arret);
        let fil = std::thread::Builder::new()
            .name(format!("bifrost-tun-{nom}"))
            .spawn(move || veiller(&veille, &sonnette, &envoi))?;

        Ok(Self {
            tun,
            recus,
            arret,
            fil: Some(fil),
            nom,
        })
    }

    pub fn nom(&self) -> &str {
        &self.nom
    }
}

/// Le fil de veille: attend, lit, transmet.
///
/// Rend la main des que l'arret est demande, ou que le canal n'a plus de
/// lecteur - ce qui veut dire que l'enveloppe a disparu.
#[cfg(windows)]
fn veiller(
    tun: &crate::tunnel::brut::TunBrut,
    arret: &Arret,
    envoi: &tokio::sync::mpsc::Sender<io::Result<Vec<u8>>>,
) {
    use windows_sys::Win32::Foundation::{WAIT_FAILED, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{INFINITE, WaitForMultipleObjects};

    let mut tampon = vec![0u8; crate::tunnel::brut::PAQUET_MAX];
    loop {
        match tun.lire(&mut tampon) {
            // Zero octet: l'adaptateur se termine. C'est une fin, pas une
            // panne; la fermeture du canal la transmet telle quelle.
            Ok(0) => return,
            Ok(n) => {
                if envoi.blocking_send(Ok(tampon[..n].to_vec())).is_err() {
                    return;
                }
                // Reprendre tout de suite: l'anneau contient peut-etre encore
                // des paquets, et attendre l'evenement pour eux le ferait
                // attendre pour rien.
                continue;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => {
                let _ = envoi.blocking_send(Err(e));
                return;
            }
        }

        // L'anneau est vide: attendre qu'il ne le soit plus, ou qu'on nous
        // demande de partir. Les deux d'un seul appel, pour que l'arret soit
        // immediat et non a la fin d'un delai.
        let poignees = [tun.evenement_de_lecture(), arret.0];
        // SAFETY: deux poignees valides, tableau vivant le temps de l'appel.
        let issue = unsafe { WaitForMultipleObjects(2, poignees.as_ptr(), 0, INFINITE) };
        match issue {
            x if x == WAIT_OBJECT_0 => {}
            x if x == WAIT_OBJECT_0 + 1 => return,
            WAIT_FAILED => {
                let _ = envoi.blocking_send(Err(io::Error::last_os_error()));
                return;
            }
            _ => return,
        }
    }
}

#[cfg(windows)]
impl Drop for Tun {
    /// L'ordre porte la surete de tout ce module.
    ///
    /// D'abord demander l'arret, puis ATTENDRE que le fil soit sorti, et
    /// seulement ensuite laisser le `TunBrut` disparaitre - c'est lui qui
    /// termine la session. L'inverse terminerait la session pendant qu'un fil
    /// est peut-etre a l'interieur de `WintunReceivePacket`, ce que l'amont ne
    /// promet nulle part.
    fn drop(&mut self) {
        self.arret.declencher();
        if let Some(fil) = self.fil.take() {
            let _ = fil.join();
        }
    }
}

#[cfg(windows)]
impl AsyncRead for Tun {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        tampon: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let moi = self.get_mut();
        match ready!(moi.recus.poll_recv(cx)) {
            Some(Ok(paquet)) => {
                if paquet.len() > tampon.remaining() {
                    // Meme regle que sous Linux, et pour la meme raison: un
                    // paquet tronque remis a la pile serait pire qu'un paquet
                    // perdu.
                    return Poll::Ready(Err(io::Error::other(format!(
                        "paquet de {} octets pour un tampon de {}: il aurait ete tronque",
                        paquet.len(),
                        tampon.remaining()
                    ))));
                }
                tampon.put_slice(&paquet);
                Poll::Ready(Ok(()))
            }
            Some(Err(e)) => Poll::Ready(Err(e)),
            // Le fil est sorti: le TUN ne rendra plus rien. Zero octet est ce
            // qu'un lecteur de flux comprend comme une fin.
            None => Poll::Ready(Ok(())),
        }
    }
}

#[cfg(windows)]
impl AsyncWrite for Tun {
    /// # L'anneau plein est le seul endroit ou l'on repasse plutot qu'on
    /// n'attend
    ///
    /// Wintun ne publie pas d'evenement pour l'emission - seulement pour la
    /// reception. Il n'y a donc rien a surveiller quand l'anneau d'emission est
    /// plein: on rend la main a l'ordonnanceur en redemandant a etre repasse,
    /// ce qui laisse tourner tout le reste du daemon pendant que le pilote
    /// vide. C'est un tour d'ordonnanceur, pas une attente active sur un coeur.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        paquet: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.tun.ecrire(paquet) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            rendu => Poll::Ready(rendu),
        }
    }

    /// Rien a vider: chaque ecriture est deja un paquet remis au systeme.
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// Un TUN ne se ferme pas a moitie. Il disparait avec sa structure.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Mene au coeur tout ce que le systeme envoie dans le TUN.
///
/// Ne rend la main que si la pile s'arrete, ce qui veut dire que le TUN est
/// mort: ce n'est pas une panne passagere, et boucler dessus ne ferait que
/// chauffer un coeur.
pub async fn servir(tun: Tun, coeur: super::socks::Mandataire, mtu: u16) {
    let mut reglage = IpStackConfig::default();
    reglage.mtu_unchecked(mtu);
    // Le TUN est ouvert en `IFF_NO_PI`: pas d'en-tete de service devant le
    // paquet. Le declarer faux ici est donc la verite, pas une commodite.
    reglage.packet_information(false);

    let mut pile = IpStack::new(reglage, tun);
    loop {
        match pile.accept().await {
            Ok(IpStackStream::Tcp(flux)) => {
                let cible = flux.peer_addr();
                // Dit AVANT de mener, et pas seulement en cas d'echec.
                //
                // Sans cette ligne un relais qui fonctionne est muet, un relais
                // qui reste suspendu est muet, et un paquet qui n'est jamais
                // arrive dans la pile est muet lui aussi: trois etats
                // impossibles a distinguer dans un journal. Le banc du 21 aout
                // 2026 s'y est trompe - il a lu l'absence de trace comme la
                // preuve que rien n'etait entre.
                tracing::debug!(%cible, "flux TCP pris par la pile");
                let coeur = coeur.clone();
                tokio::spawn(async move {
                    if let Err(raison) = mener(flux, cible, &coeur).await {
                        tracing::debug!(%cible, %raison, "connexion non menee au coeur");
                    }
                });
            }
            Ok(IpStackStream::Udp(flux)) => {
                let cible = flux.peer_addr();
                tracing::debug!(%cible, "flux UDP pris par la pile");
                let coeur = coeur.clone();
                tokio::spawn(async move {
                    if let Err(raison) = mener_udp(flux, cible, &coeur).await {
                        // Un datagramme perdu n'est jamais un datagramme fui:
                        // le kill switch bloque tout ce qui ne passe pas par le
                        // coeur. L'echec se journalise, il ne se rattrape pas.
                        tracing::debug!(%cible, %raison, "flux UDP non mene au coeur");
                    }
                });
            }
            Ok(IpStackStream::UnknownTransport(_)) => {
                tracing::trace!("transport non reconnu, abandonne");
            }
            Ok(IpStackStream::UnknownNetwork(_)) => {
                tracing::trace!("paquet non IP, abandonne");
            }
            Err(raison) => {
                tracing::warn!(%raison, "la pile s'arrete: le TUN ne rend plus rien");
                return;
            }
        }
    }
}

/// Taille du tampon de lecture d'un datagramme.
///
/// Volontairement plus grand qu'une MTU: la pile TRONQUE un datagramme qui ne
/// tient pas dans le tampon qu'on lui presente, et la queue est PERDUE, sans
/// erreur. Un tampon trop court ne produirait donc pas un echec visible mais
/// une charge utile amputee que l'application prendrait pour la vraie.
const TAMPON_DATAGRAMME: usize = 65_535;

/// Mene un flux UDP au coeur par une association SOCKS5.
///
/// # Ce que l'association exige, et qu'on ne peut pas simplifier
///
/// Le lien de controle TCP doit rester ouvert TOUT le temps: c'est lui qui
/// tient l'association, et sa fermeture fait disparaitre le relais. Il est donc
/// garde ici, et surveille - si le coeur le ferme, il n'y a plus de relais et
/// continuer a emettre reviendrait a parler dans le vide.
///
/// # Ce qui distingue ce chemin du TCP
///
/// Une association n'a pas de destination unique: le meme relais sert a joindre
/// n'importe qui, chaque datagramme portant la sienne. Mais la pile, elle, a
/// ouvert ce flux POUR une destination precise. On n'emet donc que vers elle,
/// et on n'accepte en retour que ce qui en vient: un relais qui renverrait
/// autre chose ferait remonter a l'application un datagramme qu'elle n'a jamais
/// demande, ce qui est une injection.
async fn mener_udp(
    mut flux: ipstack::IpStackUdpStream,
    cible: SocketAddr,
    coeur: &super::socks::Mandataire,
) -> Result<(), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut controle, relais) = super::socks::associer_udp(coeur)
        .await
        .map_err(|e| format!("association UDP refusee: {e}"))?;

    // Une socket liee sur la meme famille que le relais, puis CONNECTEE a lui:
    // le noyau ecarte alors de lui-meme ce qui vient d'ailleurs, ce qui est un
    // filtre de plus que celui qu'on applique sur la source annoncee.
    let local = if relais.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = tokio::net::UdpSocket::bind(local)
        .await
        .map_err(|e| format!("socket UDP locale: {e}"))?;
    socket
        .connect(relais)
        .await
        .map_err(|e| format!("connexion au relais {relais}: {e}"))?;

    let entete = super::socks::entete_datagramme(cible);
    let mut depuis_tun = vec![0u8; TAMPON_DATAGRAMME];
    let mut depuis_relais = vec![0u8; TAMPON_DATAGRAMME];
    let mut trame = Vec::with_capacity(TAMPON_DATAGRAMME);
    // Le lien de controle ne porte aucune donnee: y lire ne sert qu'a savoir
    // quand il se ferme.
    let mut controle_muet = [0u8; 1];

    loop {
        tokio::select! {
            lu = flux.read(&mut depuis_tun) => {
                let n = lu.map_err(|e| format!("lecture du flux UDP: {e}"))?;
                if n == 0 {
                    return Ok(());
                }
                trame.clear();
                trame.extend_from_slice(&entete);
                trame.extend_from_slice(&depuis_tun[..n]);
                socket
                    .send(&trame)
                    .await
                    .map_err(|e| format!("envoi au relais: {e}"))?;
            }
            recu = socket.recv(&mut depuis_relais) => {
                let n = recu.map_err(|e| format!("reception du relais: {e}"))?;
                let (source, charge) = super::socks::lire_datagramme(&depuis_relais[..n])?;
                if source != cible {
                    // Le relais rend ce qu'il veut; l'application, elle, n'a
                    // parle qu'a une adresse.
                    tracing::debug!(%source, %cible, "datagramme d'une autre source, ecarte");
                    continue;
                }
                flux.write_all(charge)
                    .await
                    .map_err(|e| format!("ecriture vers le systeme: {e}"))?;
            }
            fin = controle.read(&mut controle_muet) => {
                return match fin {
                    Ok(0) => Ok(()),
                    Ok(_) => Err("le lien de controle a parle: le mandataire ne suit pas la RFC 1928".into()),
                    Err(e) => Err(format!("lien de controle rompu: {e}")),
                };
            }
        }
    }
}

/// Combien de temps insister pour que la fermeture parte.
///
/// La transition attendue se compte en microsecondes; ce delai n'est la que
/// pour qu'un cas non prevu finisse quand meme, plutot que de tenir un fil.
const DELAI_FERMETURE: Duration = Duration::from_secs(2);

/// Entre deux tentatives. Assez court pour ne rien retarder, assez long pour
/// ne pas tourner a vide.
const REPOS_FERMETURE: Duration = Duration::from_millis(20);

/// Ferme la connexion du cote de l'application, pour de bon.
///
/// # Pourquoi ce n'est pas un simple `shutdown().await`
///
/// Mesure faite sur essai-linux le 19 aout 2026, capture a l'appui: ni
/// `shutdown()` ni l'abandon du flux n'envoyaient quoi que ce soit.
/// L'application restait suspendue quinze secondes, jusqu'a ce qu'elle
/// renonce d'elle-meme. La lecture de `ipstack` 1.0.1 donne les deux raisons:
///
/// - son `Drop` n'emet aucun paquet: il previent sa tache interne et l'attend;
/// - son `poll_shutdown` n'emet le FIN que si l'etat vaut `Established`.
///   Or au moment ou le CONNECT echoue, l'etat est encore `SynReceived`: l'ACK
///   de l'application n'a pas fini d'etre traite. Le waker est enregistre, et
///   la transition vers `Established` ne le reveille pas.
///
/// D'ou cette insistance: on redemande la fermeture jusqu'a ce qu'un appel
/// tombe apres la transition. C'est la deuxieme tentative en pratique.
///
/// La branche amont non publiee semble avoir corrige le `Drop`; tant que la
/// version publiee est celle-ci, cette fonction reste necessaire.
async fn fermer(flux: &mut ipstack::IpStackTcpStream) {
    let fin = tokio::time::Instant::now() + DELAI_FERMETURE;
    while tokio::time::Instant::now() < fin {
        // `shutdown()` reste `Pending` tant que le FIN n'est pas acquitte;
        // ce qui compte ici est qu'il soit EMIS, et un nouvel appel repolle.
        if tokio::time::timeout(REPOS_FERMETURE, flux.shutdown())
            .await
            .is_ok()
        {
            return;
        }
    }
    tracing::debug!("fermeture non confirmee: l'application verra une connexion muette");
}

/// Le flux de la pile, plus le reveil qu'`ipstack` oublie de poser.
///
/// # Le defaut, mesure le 21 aout 2026
///
/// `IpStackTcpStream::poll_shutdown` DIFFERE le FIN tant qu'il reste des
/// paquets en vol: `is_ready == false`, et il se contente alors d'enregistrer
/// son reveil dans `self.shutdown`. Or l'acquittement qui vide la file ne
/// reveille que `write_notify` et `read_notify`; `shutdown.ready()` n'est dit
/// que sur les chemins de fermeture de la session. Personne ne repasse donc, et
/// le FIN n'est jamais emis.
///
/// Ce que cela donne pour l'utilisateur: les octets arrivent, la fermeture
/// jamais. Un client qui lit jusqu'a la fin du flux - HTTP/1.0, et la moitie
/// des protocoles de requete-reponse - reste suspendu jusqu'a SON PROPRE
/// delai, puis rend une reponse vide alors que tout etait arrive. Mesure sur
/// essai-windows contre un vrai sing-box: 208 octets livres et acquittes, puis
/// huit secondes de silence, et c'est le client qui a raccroche.
///
/// # Pourquoi une minuterie plutot qu'un correctif en amont
///
/// Il n'y en a pas au 21 aout 2026: `ipstack` 1.0.1 est la derniere version, et
/// le dernier commit qui touche la fermeture (`0f95edc`, 18 aout) traite un
/// autre cas. Attendre une version rendrait le produit inutilisable pour tout
/// ce qui delimite par la fermeture.
///
/// Le defaut est remonte en amont le 21 aout 2026, avec une reproduction sans
/// TUN ni privileges et un correctif candidat verifie:
/// <https://github.com/narrowlink/ipstack/issues/89>. Ouvert, sans reponse a
/// cette date.
///
/// La minuterie ne corrige rien chez le voisin: elle repasse, simplement.
/// `poll_shutdown` est idempotent - il relit l'etat, n'emet le FIN que si la
/// file est vide et la session etablie - donc y repasser ne peut ni emettre
/// deux FIN ni abimer la machine a etats. C'est le reveil manquant, et rien de
/// plus.
///
/// # La soeur de [`fermer`]
///
/// Le meme defaut de famille, a un autre moment: la, un waker enregistre en
/// `SynReceived` que la transition vers `Established` ne reveille pas; ici, un
/// waker enregistre la file pleine que l'acquittement ne reveille pas. Le
/// remede est le meme - insister - et les deux insistent a la meme cadence.
///
/// Deux formes cependant, parce que les deux moments ne se ressemblent pas.
/// [`fermer`] est appelee quand il n'y a plus rien a relayer, donc elle peut
/// boucler a son aise. Ici la fermeture arrive AU MILIEU de
/// `copy_bidirectional`, qui ne rendra la main que lorsque les deux sens
/// seront finis: emettre le FIN plus tard, apres coup, ne servirait a rien -
/// l'application attend ce FIN pour fermer de son cote, et
/// `copy_bidirectional` attend cette fermeture. Le reveil doit donc etre pose la ou la pile a oublie
/// le sien.
///
/// Le jour ou l'amont reveillera son propre dormeur, cette enveloppe deviendra
/// une passe-plat sans effet, et la recette
/// `quand_le_coeur_raccroche_l_application_voit_la_fin_du_flux` restera verte
/// en la retirant. C'est le signal qu'il faudra la retirer.
struct FermetureRelancee {
    flux: ipstack::IpStackTcpStream,
    /// Posee a la premiere fermeture differee, et jamais avant: une connexion
    /// qui ne se ferme pas n'a pas de minuterie a porter.
    minuterie: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl FermetureRelancee {
    fn nouvelle(flux: ipstack::IpStackTcpStream) -> Self {
        Self {
            flux,
            minuterie: None,
        }
    }
}

impl AsyncRead for FermetureRelancee {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        tampon: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().flux).poll_read(cx, tampon)
    }
}

impl AsyncWrite for FermetureRelancee {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        octets: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().flux).poll_write(cx, octets)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().flux).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let moi = self.get_mut();
        match Pin::new(&mut moi.flux).poll_shutdown(cx) {
            Poll::Ready(fini) => {
                moi.minuterie = None;
                Poll::Ready(fini)
            }
            Poll::Pending => {
                let minuterie = moi
                    .minuterie
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(REPOS_FERMETURE)));
                if minuterie.as_mut().poll(cx).is_ready() {
                    // Elle vient de sonner: en reposer une pour le tour
                    // suivant, et la sonder pour que le reveil soit enregistre.
                    // Sans ce second sondage, la minuterie ne reveillerait
                    // personne et l'enveloppe dormirait comme la pile.
                    minuterie
                        .as_mut()
                        .reset(tokio::time::Instant::now() + REPOS_FERMETURE);
                    let _ = minuterie.as_mut().poll(cx);
                }
                Poll::Pending
            }
        }
    }
}

/// Ouvre le CONNECT et fait passer les octets.
///
/// # Quand le coeur ne repond pas
///
/// La poignee de main TCP est deja faite quand ce code recoit le flux: la pile
/// l'a menee a son terme pour pouvoir dire quelle etait la destination. Du
/// point de vue de l'application, la connexion est donc DEJA ouverte, et se
/// contenter d'abandonner le flux la laisse suspendue - ce qui a ete mesure, un
/// premier jet de ce module le faisait.
///
/// Il faut donc fermer explicitement. C'est le meme refus que celui de
/// [`super::facade`], pour la meme raison: une application suspendue ne sait
/// pas si elle attend un reseau lent ou un tunnel absent, et finit par decider
/// elle-meme, souvent en reessayant hors du tunnel.
async fn mener(
    mut flux: ipstack::IpStackTcpStream,
    cible: SocketAddr,
    coeur: &super::socks::Mandataire,
) -> Result<(), String> {
    let mut vers_le_coeur = match super::socks::connecter_vers(coeur, cible).await {
        Ok(flux) => flux,
        Err(raison) => {
            fermer(&mut flux).await;
            return Err(raison.to_string());
        }
    };
    // A partir d'ici le flux porte son propre reveil de fermeture: c'est
    // `copy_bidirectional` qui demandera la fermeture, et la pile oublie de
    // reveiller qui la lui demande. Voir [`FermetureRelancee`].
    let mut flux = FermetureRelancee::nouvelle(flux);
    let (montant, descendant) = tokio::io::copy_bidirectional(&mut flux, &mut vers_le_coeur)
        .await
        .map_err(|e| format!("relais interrompu: {e}"))?;
    // Les deux sens separement, parce que la panne qu'on cherche les separe:
    // un aller qui part sans retour se lit ici, et nulle part ailleurs.
    tracing::debug!(%cible, montant, descendant, "relais termine");
    Ok(())
}

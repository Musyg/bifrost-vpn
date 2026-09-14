//! Le chemin par coeur, vu comme un tunnel.
//!
//! La machine a etats n'avait qu'une forme de tunnel, celle de WireGuard, et
//! c'est ce que son refus disait. La reponse n'est pas de lui en apprendre une
//! seconde: c'est de remarquer qu'elle ne parle deja qu'a un PORT,
//! [`TunnelDevice`]. Il suffit d'une deuxieme implementation, et la machine
//! n'a rien a savoir.
//!
//! Ce que ce device monte:
//!
//! 1. le TUN nu ([`super::brut`]), adresse et mis en service;
//! 2. l'aiguillage, qui y envoie le systeme et en fait sortir le coeur;
//! 3. le passeur ([`crate::coeurs::passeur`]), qui traduit les paquets en
//!    connexions SOCKS5 vers la facade.
//!
//! # L'aiguillage n'est pas au meme endroit des deux cotes
//!
//! Le point 2 est le seul que la plateforme change, et il le change
//! profondement. Sous Linux tout tient dans la table de routage, y compris
//! l'echappement du coeur, qui se fait par IDENTITE: `ip rule uidrange` envoie
//! ce qui vient de son compte dans la table `main`. Voir
//! [`super::aiguillage`], qui n'existe que la.
//!
//! Windows ne sait pas router par processus - sa table ne connait que des
//! destinations - donc l'echappement DEMENAGE dans la configuration du coeur,
//! ou il devient une liaison de socket. Ce module n'en voit rien: la valeur est
//! calculee par [`crate::supervisor`] au lancement du coeur, et documentee sur
//! [`crate::coeurs::configuration::Parametres::lier_a`]. Ce qui reste ici, cote
//! Windows, est donc plus court: adresses, MTU, metrique et une route par
//! defaut, tout par LUID.
//!
//! Le coeur lui-meme n'est pas monte ici, et ce n'est pas un oubli: **le TUN et
//! la facade appartiennent a la CONNEXION, le coeur seulement a la TECHNIQUE**.
//! Changer de technique remplace ce qu'il y a derriere la facade sans toucher
//! ni aux routes ni aux filtres, ce qui est precisement pourquoi le plan peut
//! exiger que le kill switch ne soit jamais leve pendant une bascule.
//! [`crate::coeurs::atelier`] tient les coeurs, ce device tient la connexion.
//!
//! # Ce qu'il prend de `TunnelConfig`, et ce qu'il ignore
//!
//! Il prend le nom de l'interface, les adresses et la MTU: trois choses qui
//! decrivent la connexion et valent pour n'importe quel transport. Il ignore
//! `private_key`, `peer` et `fwmark`, qui decrivent WireGuard.
//!
//! Le reste de la configuration decrit le PORTAGE, et vit desormais dans
//! `Portage::Coeur`: un profil lu d'un lien de partage, que
//! [`crate::supervisor`] traduit en configuration de coeur juste avant de
//! monter ce device. Ce module n'en voit rien, et c'est voulu - le coeur
//! appartient a la technique, ce device a la connexion.

use std::net::SocketAddr;
use std::time::SystemTime;

use tokio::sync::watch;

use bifrost_core::ports::{HandshakeInfo, TunnelDevice};
use bifrost_core::{Error, Result, TunnelConfig};

use super::brut;
use crate::coeurs::passage;

#[cfg(target_os = "linux")]
use super::aiguillage;
#[cfg(target_os = "linux")]
use super::netcfg::{self, Cmd};
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};

/// Le chemin par coeur.
pub struct CoeurTunnel {
    passage: passage::Poignee,
    /// Ou le passeur frappe, et ce qu'il presente en arrivant.
    ///
    /// L'ADRESSE est celle de la facade, stable par construction. Les
    /// IDENTIFIANTS sont ceux du coeur: la facade les transporte sans les lire,
    /// et c'est le coeur qui les valide. Les deux tiennent ensemble parce que
    /// l'adresse seule ferait un appelant qui se presente les mains vides -
    /// l'etat exact qu'un processus tiers a su exploiter sur le banc.
    coeur: crate::coeurs::socks::Mandataire,
    /// Le compte du coeur, pour qu'il sorte au lieu de boucler.
    #[cfg(target_os = "linux")]
    coeur_uid: Option<u32>,
    /// Le LUID de l'interface tant qu'elle est montee.
    ///
    /// Retenu parce que le TUN, lui, part de l'autre cote de la frontiere des
    /// que le passage s'ouvre: sans cette copie il n'y aurait plus de quoi lire
    /// les compteurs. Le LUID reste valide tant que l'interface existe, et
    /// cesse de designer quoi que ce soit quand elle disparait - ce qui est
    /// exactement la reponse cherchee.
    #[cfg(windows)]
    luid: Option<u64>,
    /// Y a-t-il un coeur actif, et ou ecoute-t-il.
    ///
    /// Publie par [`crate::coeurs::atelier`], suivi par [`super::super::coeurs::facade`]
    /// pour mener les octets, et lu ici pour repondre a une question que
    /// l'interface ne sait pas trancher: ce tunnel est-il encore vivant.
    coeur_actif: watch::Receiver<Option<SocketAddr>>,
    /// Le nom de l'interface tant qu'elle est montee.
    monte: Option<String>,
}

impl CoeurTunnel {
    /// `coeur_uid` n'a de sens que sous Linux, ou il designe le compte qui
    /// s'echappe du tunnel. Il est accepte partout pour que l'assemblage soit
    /// le meme des deux cotes, et ignore la ou la plateforme s'echappe
    /// autrement.
    pub fn new(
        passage: passage::Poignee,
        coeur: crate::coeurs::socks::Mandataire,
        coeur_uid: Option<u32>,
        coeur_actif: watch::Receiver<Option<SocketAddr>>,
    ) -> Self {
        #[cfg(windows)]
        let _ = coeur_uid;
        Self {
            passage,
            coeur,
            #[cfg(target_os = "linux")]
            coeur_uid,
            #[cfg(windows)]
            luid: None,
            coeur_actif,
            monte: None,
        }
    }

    /// Execute une commande. Ecrit ici plutot qu'emprunte a [`super::netcfg`],
    /// dont l'en-tete promet qu'il n'execute rien: c'est cette purete qui
    /// permet de tester la politique de routage sans root.
    #[cfg(target_os = "linux")]
    fn run(cmd: &Cmd) -> Result<()> {
        let out = Command::new(cmd.program)
            .args(&cmd.args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| Error::Tunnel(format!("{}: {e}", cmd.display())))?;
        if out.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
        if cmd.tolerate_failure {
            tracing::debug!(cmd = %cmd.display(), stderr = %stderr, "echec tolere");
            return Ok(());
        }
        Err(Error::Tunnel(format!("{}: {stderr}", cmd.display())))
    }

    #[cfg(target_os = "linux")]
    fn aiguillage(&self, cfg: &TunnelConfig) -> aiguillage::Aiguillage {
        aiguillage::Aiguillage {
            interface: cfg.interface.clone(),
            coeur_uid: self.coeur_uid,
        }
    }

    /// Un compteur du peripherique, ou `None` si l'interface a disparu.
    #[cfg(target_os = "linux")]
    fn compteur(interface: &str, quoi: &str) -> Option<u64> {
        std::fs::read_to_string(format!("/sys/class/net/{interface}/statistics/{quoi}"))
            .ok()?
            .trim()
            .parse()
            .ok()
    }
}

impl CoeurTunnel {
    /// La MTU, dans la forme que le passeur attend.
    fn mtu(cfg: &TunnelConfig) -> Result<u16> {
        u16::try_from(cfg.mtu)
            .map_err(|_| Error::Config(format!("MTU hors de portee: {}", cfg.mtu)))
    }

    #[cfg(target_os = "linux")]
    fn monter_ici(&mut self, cfg: &TunnelConfig) -> Result<()> {
        // Le TUN d'abord. L'interface n'existe que tant qu'un descripteur la
        // tient, donc il faut l'ouvrir avant de pouvoir l'adresser.
        let tun = brut::ouvrir(&cfg.interface).map_err(Error::Tunnel)?;

        // Adresses, MTU et mise en service. Les commandes viennent de
        // `netcfg`, qui ne fait ici rien de specifique a WireGuard.
        //
        // Si l'une echoue, le TUN est abandonne en sortant, ce qui fait
        // disparaitre l'interface: la tentative suivante repart propre, sans
        // qu'on ait a nettoyer quoi que ce soit.
        for cmd in netcfg::configure_link(cfg) {
            Self::run(&cmd)?;
        }

        let aiguillage = self.aiguillage(cfg);
        for cmd in aiguillage::poser(&aiguillage) {
            if let Err(e) = Self::run(&cmd) {
                // L'aiguillage a moitie pose enverrait du trafic vers une
                // interface qui va disparaitre avec le TUN abandonne.
                for retour in aiguillage::retirer(&aiguillage) {
                    let _ = Self::run(&retour);
                }
                return Err(e);
            }
        }

        // Le TUN passe de l'autre cote de la frontiere. A partir d'ici sa duree
        // de vie est celle du passage, et c'est sa fermeture qui fera
        // disparaitre l'interface.
        let nom = self
            .passage
            .ouvrir_passage(tun, self.coeur.clone(), Self::mtu(cfg)?)
            .map_err(|e| {
                for retour in aiguillage::retirer(&aiguillage) {
                    let _ = Self::run(&retour);
                }
                Error::Tunnel(e)
            })?;

        self.monte = Some(nom);
        Ok(())
    }

    /// Le meme montage, sans aucun processus fils.
    ///
    /// Windows configure une interface par appels systeme et par LUID, la ou
    /// Linux passe par `ip`. C'est [`super::wgnt::ipcfg`] qui les porte, et
    /// c'est deja lui qui sert au chemin WireGuardNT: le TUN n'est pas le meme,
    /// les objets a poser le sont.
    #[cfg(windows)]
    fn monter_ici(&mut self, cfg: &TunnelConfig) -> Result<()> {
        use super::wgnt::ipcfg;

        // Comme sous Linux: l'interface n'existe que tant qu'une structure la
        // tient, donc elle s'ouvre avant de pouvoir etre adressee.
        let tun = brut::ouvrir(&cfg.interface).map_err(Error::Tunnel)?;
        let luid = tun.luid();

        // Adresses, MTU, metrique et la route par defaut. Un echec ici abandonne
        // le TUN en sortant, ce qui detruit l'adaptateur - et Windows emporte
        // avec lui les adresses et les routes qui le designaient. Rien a
        // deposer.
        ipcfg::apply(luid, cfg)?;

        // Le TUN passe de l'autre cote de la frontiere, et sa duree de vie
        // devient celle du passage.
        let nom = self
            .passage
            .ouvrir_passage(tun, self.coeur.clone(), Self::mtu(cfg)?)
            .map_err(Error::Tunnel)?;

        self.luid = Some(luid);
        self.monte = Some(nom);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn demonter_ici(&mut self, cfg: &TunnelConfig) -> Result<()> {
        // Le passage d'abord: sa fermeture ferme le descripteur, donc fait
        // disparaitre l'interface. Retirer l'aiguillage avant laisserait, le
        // temps d'un souffle, un systeme qui route en clair alors que le TUN
        // existe encore.
        let ferme = self.passage.fermer();

        // L'aiguillage se retire meme si le passage a mal ferme: des regles
        // laissees en place aiguilleraient vers une interface morte, ce qui est
        // pire que tout.
        for cmd in aiguillage::retirer(&self.aiguillage(cfg)) {
            let _ = Self::run(&cmd);
        }
        self.monte = None;

        ferme.map_err(Error::Tunnel)
    }

    /// Fermer le passage suffit, et c'est mieux que de nettoyer.
    ///
    /// Sa fermeture laisse tomber le TUN, ce qui detruit l'adaptateur Wintun;
    /// Windows retire alors d'un seul coup les adresses et les routes qui le
    /// designaient. Retirer la route par defaut d'abord ouvrirait au contraire
    /// une fenetre - courte, mais reelle - ou la machine routerait en clair
    /// alors que l'interface est encore la. La meme raison qu'a l'endroit
    /// correspondant sous Linux, avec une conclusion plus simple.
    #[cfg(windows)]
    fn demonter_ici(&mut self, _cfg: &TunnelConfig) -> Result<()> {
        let ferme = self.passage.fermer();
        self.luid = None;
        self.monte = None;
        ferme.map_err(Error::Tunnel)
    }

    /// Octets entres et sortis, ou `None` si l'interface a disparu.
    #[cfg(target_os = "linux")]
    fn trafic_ici(&self, cfg: &TunnelConfig) -> Option<(u64, u64)> {
        let rx = Self::compteur(&cfg.interface, "rx_bytes")?;
        Some((rx, Self::compteur(&cfg.interface, "tx_bytes").unwrap_or(0)))
    }

    /// La meme question, posee au LUID retenu au montage plutot qu'au nom:
    /// deux interfaces peuvent porter le meme nom a des moments differents, un
    /// LUID ne designe jamais deux fois la meme chose.
    #[cfg(windows)]
    fn trafic_ici(&self, _cfg: &TunnelConfig) -> Option<(u64, u64)> {
        super::wgnt::ipcfg::compteurs(self.luid?)
    }
}

impl TunnelDevice for CoeurTunnel {
    fn up(&mut self, cfg: &TunnelConfig) -> Result<()> {
        self.monter_ici(cfg)
    }

    fn down(&mut self, cfg: &TunnelConfig) -> Result<()> {
        self.demonter_ici(cfg)
    }

    /// Ce que le port demande vraiment: ce tunnel est-il vivant, et depuis
    /// quand l'a-t-il prouve.
    ///
    /// Un chemin par coeur n'a pas de poignee de main periodique. Ce qui en
    /// tient lieu est l'existence de l'interface, et les compteurs rendus sont
    /// les VRAIS, lus dans `/sys`. `None` quand l'interface a disparu, ce que
    /// le superviseur lit comme un tunnel perdu - et c'est exact.
    ///
    /// **Le coeur compte autant que l'interface.** L'interface, a elle seule,
    /// ne prouve rien: elle tient debout meme quand le coeur qui porte le
    /// trafic est mort, et ce tunnel paraissait alors vivant alors que plus
    /// rien ne passait. La vitalite se lit donc AUSSI sur ce que l'atelier
    /// publie, qui cesse de l'etre des que le processus disparait.
    ///
    /// Une erreur plutot qu'un `None` pour ce cas: `None` veut dire "il n'y a
    /// plus d'interface", et le superviseur le rapporte en ces termes. Un coeur
    /// mort avec une interface debout est une autre panne, qui s'annonce comme
    /// telle - sans quoi on chercherait une interface disparue qui est
    /// pourtant toujours la.
    ///
    /// La lecture est synchrone et sans attente: `borrow` ne fait que prendre
    /// un verrou, ce qui est ce qu'il faut sur le fil du superviseur, qui n'a
    /// pas de runtime.
    fn handshake(&self, cfg: &TunnelConfig) -> Result<Option<HandshakeInfo>> {
        let Some((rx, tx)) = self.trafic_ici(cfg) else {
            return Ok(None);
        };
        if self.coeur_actif.borrow().is_none() {
            return Err(Error::Tunnel(format!(
                "le coeur qui porte ce tunnel n'est plus la: l'interface {} tient encore debout mais plus rien ne passe derriere",
                cfg.interface
            )));
        }
        Ok(Some(HandshakeInfo {
            last_handshake: Some(SystemTime::now()),
            rx_bytes: rx,
            tx_bytes: tx,
        }))
    }
}

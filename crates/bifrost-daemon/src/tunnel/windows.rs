//! Device WireGuard sous Windows, via WireGuardNT.
//!
//! Ce module ne fait qu'assembler des pieces eprouvees ailleurs: le blob de
//! configuration ([`super::wgnt::config`]), le chargement de `wireguard.dll`
//! ([`super::wgnt::dll`]), le cycle de vie de l'adaptateur
//! ([`super::wgnt::adapter`]), le plan d'adresses et de routes
//! ([`super::wgnt::routes`]) et sa pose ([`super::wgnt::ipcfg`]).
//!
//! Ordre de montee, et il compte. L'adaptateur est cree, puis configure, puis
//! active, et seulement ensuite les adresses et les routes sont posees: une
//! route vers une interface qui n'a pas encore d'adresse est refusee par
//! Windows. A la descente, l'ordre est inverse.
//!
//! Le kill switch n'est pas du ressort de ce module. C'est le superviseur qui
//! l'arme, avant meme que l'interface existe.
//!
//! **Etat de verification.** Le blob et le cycle de vie de l'adaptateur sont
//! confrontes au vrai driver par `--wgnt-selftest`. La pose des adresses et des
//! routes l'a ete le 18 aout 2026, sur `essai-windows` contre un pair
//! WireGuard reel: adresse posee et DAD a `Preferred`, route presente,
//! handshake obtenu, banniere lue a travers le tunnel, demontage sans
//! adaptateur orphelin. Voir `--wgnt-e2e` et le vecteur `exit-ip`.
//!
//! La configuration a ROUTE PAR DEFAUT, celle du produit en usage reel, l'a ete
//! le meme jour derriere `--wgnt-e2e-route-par-defaut`: `0.0.0.0/0` pose sur
//! l'interface, et `best_route_interface` rendant le LUID du tunnel pour une
//! destination publique quelconque - donc Windows CHOISIT le tunnel, et pas
//! seulement la route figure dans la table. La machine retrouve sa route par
//! defaut au demontage.
//!
//! Sans ce drapeau les recettes refusent le profil, et c'est voulu: elles
//! tournent souvent sur un poste de travail. Ce qui rend l'accord tenable est
//! que l'adaptateur appartient au PROCESSUS - le tuer retire l'adaptateur et
//! toutes les routes qui le designent.
//!
//! La condition de BOUCLAGE l'a ete aussi, et sans pair hors du site: une route
//! HOTE vers l'endpoint posee sur le tunnel suffit a la provoquer, puisque la
//! route la plus specifique gagne. La table affirme alors que le pair se joint
//! par le tunnel lui-meme, et le handshake aboutit quand meme: le driver exclut
//! son propre transport du routage. Voir `--wgnt-e2e-bouclage`.

use bifrost_core::ports::{HandshakeInfo, TunnelDevice};
use bifrost_core::{Error, Result, TunnelConfig};

use super::wgnt::adapter::Adapter;
use super::wgnt::dll::WireGuardNt;
use super::wgnt::{config as blob, ipcfg};

pub struct WindowsTunnel {
    /// `None` tant qu'aucun tunnel n'est monte. L'adaptateur se ferme, donc se
    /// retire, a la liberation.
    adapter: Option<Adapter>,
}

impl WindowsTunnel {
    pub fn new() -> Result<Self> {
        Ok(Self { adapter: None })
    }

    /// LUID de l'interface, une fois l'adaptateur cree. C'est ce que le kill
    /// switch a besoin de connaitre pour autoriser le trafic du tunnel.
    pub fn luid(&self) -> Option<u64> {
        self.adapter.as_ref().map(|a| a.luid())
    }
}

impl TunnelDevice for WindowsTunnel {
    fn up(&mut self, cfg: &TunnelConfig) -> Result<()> {
        cfg.validate()?;
        // Le blob est construit avant de toucher a la machine: le driver
        // s'installe a la creation de l'adaptateur, et l'installer pour
        // decouvrir ensuite qu'une cle est illisible serait la modifier pour
        // rien.
        let configuration = blob::encode(cfg)?;

        let nt = WireGuardNt::load()?;
        let adapter = Adapter::create(nt, &cfg.interface)?;
        adapter.set_configuration(&configuration)?;
        adapter.set_state(true)?;

        let luid = adapter.luid();
        // L'adaptateur est memorise AVANT la configuration IP: si celle-ci
        // echoue, `down` doit pouvoir le retirer. Sans cela un echec de routage
        // laisserait un adaptateur orphelin que plus rien ne ferme.
        self.adapter = Some(adapter);

        if let Err(e) = ipcfg::apply(luid, cfg) {
            let _ = self.down(cfg);
            return Err(e);
        }

        tracing::info!(
            interface = %cfg.interface,
            luid = format!("{luid:#x}"),
            mtu = cfg.mtu,
            "tunnel WireGuardNT monte"
        );
        Ok(())
    }

    fn down(&mut self, cfg: &TunnelConfig) -> Result<()> {
        let Some(adapter) = self.adapter.take() else {
            // Rien a demonter. Ce n'est pas une erreur: `down` doit pouvoir
            // etre appele sans condition, y compris pour desarmer le kill
            // switch apres une montee qui n'a jamais abouti.
            return Ok(());
        };

        let luid = adapter.luid();
        // Le retrait de la configuration IP est tente meme s'il echoue: la
        // fermeture de l'adaptateur, elle, doit avoir lieu de toute facon.
        let retrait = ipcfg::remove(luid, cfg);
        let etat = adapter.set_state(false);
        drop(adapter);

        tracing::info!(interface = %cfg.interface, "tunnel WireGuardNT demonte");
        retrait.and(etat)
    }

    /// Le LUID que WireGuardNT a attribue a l'adaptateur.
    ///
    /// C'est ce que le kill switch WFP autorise. Le lui faire deduire du nom de
    /// l'interface serait une resolution qui peut echouer, ou arriver avant que
    /// Windows ait enregistre l'alias, alors que le driver nous a donne
    /// l'identifiant directement.
    fn interface_handle(&self) -> Option<u64> {
        self.luid()
    }

    fn handshake(&self, _cfg: &TunnelConfig) -> Result<Option<HandshakeInfo>> {
        let Some(adapter) = &self.adapter else {
            return Ok(None);
        };
        let relu = adapter.get_configuration()?;
        let vu = blob::decode(&relu)?;
        let Some(pair) = vu.peer else {
            return Err(Error::Tunnel(
                "l'adaptateur ne porte aucun pair: la configuration a ete perdue".into(),
            ));
        };
        Ok(Some(HandshakeInfo {
            last_handshake: pair.last_handshake,
            rx_bytes: pair.rx_bytes,
            tx_bytes: pair.tx_bytes,
        }))
    }
}

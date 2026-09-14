//! Kill switch Windows: WFP en mode utilisateur via la Base Filtering Engine.
//!
//! Aucun driver noyau. Les filtres sont poses par `fwpuclnt.dll` avec de
//! simples droits administrateur, comme WireGuard for Windows.
//!
//! Le plan des filtres (poids, actions, conditions) vit dans
//! [`crate::wfp_plan`], qui ne depend d'aucune API Windows et est donc teste
//! sur toutes les plateformes. Ce module se contente de le traduire en appels
//! WFP, le tout dans une transaction.

/// Publie pour la recette des filtres de demarrage, qui pose ses PROPRES
/// objets WFP: ils survivent au daemon par construction, donc les melanger
/// avec ceux du kill switch ferait retirer les uns en desarmant les autres.
pub mod ffi;

/// Identite que porteront les conditions `ALE_USER_ID`, et si elle vient d'un
/// SID de service. Le daemon l'annonce au demarrage: c'est la seule facon de
/// constater sur une machine reelle que le passage en service a change
/// l'identite du filtre.
pub use ffi::identite_courante;

use std::net::Ipv4Addr;
use std::path::PathBuf;

use bifrost_core::demarrage::PolitiqueDemarrage;
use bifrost_core::ports::{FirewallPolicy, KillSwitch};
use bifrost_core::{Error, Result};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows_sys::core::GUID;

use crate::wfp_plan::{self, Action, Condition, FilterSpec, Identity, Layer};
use ffi::{Engine, Storage};

/// Identifiants stables des objets Bifrost. Stables parce qu'ils servent aussi
/// a retrouver et nettoyer les objets d'un daemon precedent qui aurait
/// disparu sans desarmer.
const PROVIDER_KEY: GUID = GUID::from_u128(0x0bd4f5a1_6c1e_4f8d_9a3e_2f7b41c9e510);
const SUBLAYER_KEY: GUID = GUID::from_u128(0x0bd4f5a1_6c1e_4f8d_9a3e_2f7b41c9e511);

/// Le LUID de l'interface n'est PAS memorise ici. Il vit dans la politique,
/// que le superviseur complete a partir du device au moment d'armer. Le garder
/// aussi en champ ferait deux sources de verite pour la meme information, et
/// c'est celle qui decide si le trafic du tunnel passe ou non.
pub struct WfpKillSwitch {
    daemon_exe: PathBuf,
    /// Identifiants d'execution des filtres du dernier armement.
    ///
    /// Ce ne sont pas des statistiques: c'est ce que l'audit WFP nomme dans son
    /// champ `FilterRTID`. Sans eux, un blocage lu dans le journal ne peut pas
    /// etre attribue, et le journal est plein de blocages du pare-feu Windows
    /// qu'on prendrait pour les siens.
    derniers_filtres: std::cell::RefCell<Vec<(String, u64)>>,
}

impl WfpKillSwitch {
    pub fn new() -> Result<Self> {
        let daemon_exe = std::env::current_exe().map_err(|e| {
            Error::Firewall(format!(
                "chemin du daemon introuvable, impossible de l'autoriser: {e}"
            ))
        })?;
        Ok(Self {
            daemon_exe,
            derniers_filtres: std::cell::RefCell::new(Vec::new()),
        })
    }

    /// Pose le meme jeu d'objets WFP que [`KillSwitch::engage`], mais avec tous
    /// les blocages convertis en autorisations.
    ///
    /// Sert a eprouver le cycle de vie des objets, c'est-a-dire leur creation
    /// puis leur suppression complete, sans couper le reseau de la machine.
    /// C'est ce chemin qui a laisse un poste sans reseau jusqu'au redemarrage
    /// parce que la suppression du sublayer echouait tant que ses filtres
    /// existaient encore.
    ///
    /// Ne prouve rien sur l'etancheite: aucun trafic n'est bloque.
    pub fn engage_without_blocking(&mut self, policy: &FirewallPolicy) -> Result<usize> {
        let filters = wfp_plan::without_blocking(wfp_plan::plan(
            policy,
            self.daemon_exe.clone(),
            policy.tunnel_luid,
        ));
        let engine = Engine::open()?;
        self.install(&engine, &filters)?;
        Ok(filters.len())
    }

    /// Determine quel LUID autoriser, ou aucun.
    ///
    /// Trois cas, et le troisieme est le piege. Tant que l'interface n'existe
    /// pas, il n'y a rien a autoriser: le block-all est pose seul, ce qui est
    /// l'etat voulu avant la premiere tentative. Une fois montee, le LUID rendu
    /// par le device fait foi. Reste le cas ou la politique nomme une interface
    /// sans fournir de LUID: on le resout alors depuis le nom, et un echec est
    /// une ERREUR, pas un repli silencieux.
    ///
    /// Ce dernier point n'est pas un detail de style. Avaler l'echec produisait
    /// un kill switch complet mais sans autorisation pour le tunnel: tout le
    /// trafic bloque, y compris celui du tunnel, alors que la connexion se
    /// declare etablie. Un tunnel qui ne transporte rien en se disant sain est
    /// exactement ce qu'un kill switch ne doit jamais produire.
    fn resolve_luid(&self, policy: &FirewallPolicy) -> Result<Option<u64>> {
        match (policy.tunnel_luid, policy.tunnel_interface.as_deref()) {
            (Some(luid), _) => Ok(Some(luid)),
            (None, None) => Ok(None),
            (None, Some(name)) => interface_luid(name).map(Some).map_err(|e| {
                Error::Firewall(format!(
                    "l'interface '{name}' du tunnel est introuvable, le kill \
                     switch ne peut donc pas autoriser son trafic: {e}"
                ))
            }),
        }
    }

    /// Pose le plan de sonde d'identite: un blocage et un permit restreints a
    /// une seule adresse de destination.
    ///
    /// Voir [`wfp_plan::identity_probe`] pour ce que la sonde mesure et
    /// pourquoi elle ne coupe pas le reseau de la machine.
    pub fn engage_identity_probe(&mut self, target: Ipv4Addr, user: Identity) -> Result<usize> {
        let filters = wfp_plan::identity_probe(self.daemon_exe.clone(), target, user);
        let engine = Engine::open()?;
        self.install(&engine, &filters)?;
        Ok(filters.len())
    }

    /// Pose provider, sublayer et filtres. Tout est fait dans une transaction:
    /// il n'existe aucun instant ou une partie seulement des filtres est
    /// active, donc aucune fenetre de fuite pendant une reconfiguration.
    /// Pose le filtre de demarrage: le blocage qui vaut avant que ce daemon
    /// existe.
    ///
    /// Deux jeux de filtres, boot-time et persistants, parce que les deux
    /// drapeaux sont exclusifs sur un meme filtre et qu'un seul des deux
    /// laisserait un trou: le boot-time couvre de `tcpip.sys` au demarrage de
    /// BFE, le persistant de BFE au demarrage du daemon.
    ///
    /// Rend le nombre de filtres poses. Echoue plutot que de poser une
    /// politique partielle: tout se fait dans une transaction, donc une erreur
    /// ne laisse rien derriere elle.
    pub fn poser_demarrage(&self, politique: &PolitiqueDemarrage) -> Result<usize> {
        self.poser_demarrage_avec(wfp_plan::plan_demarrage(politique))
    }

    /// Le meme jeu d'objets, tous les blocages convertis en autorisations.
    ///
    /// Eprouve ce qui peut l'etre sans couper la machine: la creation des
    /// objets, leur survie au redemarrage, et surtout leur RETRAIT complet.
    /// C'est le chemin qui a deja laisse un poste sans reseau parce que la
    /// suppression du sublayer echouait tant qu'un filtre le referencait, et
    /// ici le filtre boot-time n'est meme pas enumerable.
    ///
    /// Ne prouve rien sur l'etancheite: aucun trafic n'est bloque. Ce que ce
    /// mode ne couvre pas est mesure ailleurs, par la recette a cible unique
    /// qui ne bloque qu'une adresse.
    pub fn poser_demarrage_sans_blocage(&self, politique: &PolitiqueDemarrage) -> Result<usize> {
        self.poser_demarrage_avec(wfp_plan::without_blocking(wfp_plan::plan_demarrage(
            politique,
        )))
    }

    fn poser_demarrage_avec(&self, plan: Vec<FilterSpec>) -> Result<usize> {
        let engine = Engine::open()?;
        let mut index: u16 = 0;
        engine.transaction(|| {
            // Repartir d'un etat connu. En transaction, donc sans jamais
            // rouvrir le trafic entre le retrait et la repose.
            retirer_demarrage_dans(&engine)?;

            let mut nom = ffi::wide("Bifrost demarrage");
            let mut desc = ffi::wide("Blocage actif avant le demarrage du daemon");
            engine.add_provider_persistent(&demarrage::PROVIDER, &mut nom, &mut desc, None)?;

            let mut sous_nom = ffi::wide("Bifrost demarrage");
            let mut sous_desc = ffi::wide("Filtres de demarrage Bifrost");
            let mut provider = demarrage::PROVIDER;
            engine.add_sublayer_persistent(
                &demarrage::SUBLAYER,
                &mut provider,
                &mut sous_nom,
                &mut sous_desc,
                wfp_plan::SUBLAYER_WEIGHT,
            )?;

            for drapeau in [FWPM_FILTER_FLAG_BOOTTIME, FWPM_FILTER_FLAG_PERSISTENT] {
                for spec in &plan {
                    for layer in &spec.layers {
                        if index >= demarrage::MAX_FILTRES {
                            // Refuser plutot que de poser une politique
                            // tronquee: il manquerait des AUTORISATIONS, donc
                            // la machine redemarrerait plus coupee que prevu,
                            // et le balayage de retrait ne retrouverait pas les
                            // filtres au-dela de la borne.
                            return Err(Error::Firewall(format!(
                                "le plan de demarrage depasse {} filtres: refus de poser une politique que le retrait ne saurait pas defaire en entier",
                                demarrage::MAX_FILTRES
                            )));
                        }
                        self.add_filter_dans(
                            &engine,
                            spec,
                            *layer,
                            &Cible::demarrage(demarrage::cle(index), drapeau),
                        )?;

                        index += 1;
                    }
                }
            }
            Ok(())
        })?;
        Ok(index as usize)
    }

    /// Les filtres de demarrage PRESENTS dans le moteur, avec leur nom.
    ///
    /// Distinct de [`Self::derniers_filtres`], qui ne connait que ce que CE
    /// processus a pose. Apres un redemarrage, c'est BFE qui a rejoue les
    /// filtres persistants, en leur attribuant de nouveaux identifiants
    /// d'execution: le seul moyen de les retrouver est d'enumerer le moteur.
    ///
    /// Ne voit que les filtres PERSISTANTS. Un filtre boot-time n'est pas
    /// enumerable une fois BFE demarre, et c'est justement pour ca que le
    /// retrait ne passe pas par l'enumeration.
    pub fn filtres_demarrage_vus(&self) -> Result<Vec<(String, u64)>> {
        let engine = Engine::open()?;
        let couches: Vec<GUID> = Layer::ALL.iter().map(|l| layer_key(*l)).collect();
        Ok(engine
            .enumerate_named(&demarrage::PROVIDER, &couches)?
            .into_iter()
            .map(|f| (f.nom, f.id))
            .collect())
    }

    /// Pose la couche 2 anti-telemetrie: le blocage par SID de service.
    ///
    /// Dans son PROPRE provider et son propre sublayer, distincts de ceux du
    /// kill switch, pour une raison de fond: ces filtres doivent valoir aussi
    /// quand le tunnel est baisse. Quelqu'un qui coupe son VPN ne demande pas a
    /// rallumer la telemetrie de son systeme.
    ///
    /// Rend le nombre de filtres poses. Tout en transaction: une erreur ne
    /// laisse pas une politique a moitie posee, et le retrait prealable ne
    /// rouvre rien puisqu'il vit dans la meme transaction.
    ///
    /// Un plan vide - profil Aucun, ou toutes les cibles SANS OBJET - retire et
    /// ne repose rien. Il ne cree surtout pas un provider et un sublayer vides,
    /// que plus rien ne viendrait retirer ensuite.
    pub fn poser_telemetrie(&self, plan: &[FilterSpec]) -> Result<usize> {
        let engine = Engine::open()?;
        let mut index: u16 = 0;
        engine.transaction(|| {
            retirer_telemetrie_dans(&engine)?;
            if plan.is_empty() {
                return Ok(());
            }

            let mut nom = ffi::wide("Bifrost anti-telemetrie");
            let mut desc = ffi::wide("Blocage par service, document 03 couche 2");
            engine.add_provider_persistent(&telemetrie::PROVIDER, &mut nom, &mut desc, None)?;

            let mut sous_nom = ffi::wide("Bifrost anti-telemetrie");
            let mut sous_desc = ffi::wide("Filtres anti-telemetrie Bifrost");
            let mut provider = telemetrie::PROVIDER;
            engine.add_sublayer_persistent(
                &telemetrie::SUBLAYER,
                &mut provider,
                &mut sous_nom,
                &mut sous_desc,
                wfp_plan::SUBLAYER_WEIGHT,
            )?;

            for spec in plan {
                for layer in &spec.layers {
                    if index >= telemetrie::MAX_FILTRES {
                        // Refuser plutot que tronquer: une politique tronquee
                        // laisserait des cibles non bloquees en annoncant le
                        // contraire, et le balayage de retrait ne retrouverait
                        // pas les filtres au-dela de la borne.
                        return Err(Error::Firewall(format!(
                            "le plan anti-telemetrie depasse {} filtres: refus de poser \
                             ce que le retrait ne saurait pas defaire en entier",
                            telemetrie::MAX_FILTRES
                        )));
                    }
                    self.add_filter_dans(
                        &engine,
                        spec,
                        *layer,
                        &Cible::telemetrie(telemetrie::cle(index)),
                    )?;
                    index += 1;
                }
            }
            Ok(())
        })?;
        Ok(index as usize)
    }

    /// Retire la couche 2. La sortie de secours que la partie 8 du document 03
    /// exige avant toute desinstallation.
    ///
    /// Ne depend d'AUCUNE connaissance de ce qui a ete pose: rejoue la suite de
    /// cles et supprime chacune, en tolerant les absentes. Utilisable apres un
    /// plantage, un changement de profil, ou par un desinstalleur qui ne sait
    /// rien de la politique en cours. Les filtres WFP survivent au processus
    /// qui les a poses: sans cette fonction, desinstaller le produit laisserait
    /// une machine filtree par un logiciel absent.
    pub fn retirer_telemetrie(&self) -> Result<()> {
        let engine = Engine::open()?;
        engine.transaction(|| retirer_telemetrie_dans(&engine))
    }

    /// Les filtres anti-telemetrie REELLEMENT presents dans le moteur.
    ///
    /// Tous persistants, donc tous enumerables - contrairement au demarrage,
    /// dont la moitie boot-time devient invisible une fois BFE lance. C'est ce
    /// qui permet a un banc de compter ce qui est pose plutot que ce que le
    /// daemon croit avoir pose.
    pub fn filtres_telemetrie_vus(&self) -> Result<Vec<(String, u64)>> {
        let engine = Engine::open()?;
        let couches: Vec<GUID> = Layer::ALL.iter().map(|l| layer_key(*l)).collect();
        Ok(engine
            .enumerate_named(&telemetrie::PROVIDER, &couches)?
            .into_iter()
            .map(|f| (f.nom, f.id))
            .collect())
    }

    /// Retire le filtre de demarrage. La sortie de secours.
    ///
    /// Ne depend d'AUCUNE connaissance de ce qui a ete pose: il rejoue la suite
    /// de cles et supprime chacune, en tolerant les absentes. C'est ce qui rend
    /// la fonction utilisable apres un plantage, un changement de politique ou
    /// une mise a jour, y compris sur une machine sans reseau.
    pub fn retirer_demarrage(&self) -> Result<()> {
        let engine = Engine::open()?;
        engine.transaction(|| retirer_demarrage_dans(&engine))
    }

    /// Les identifiants d'execution des filtres poses au dernier armement.
    ///
    /// A confronter au champ `FilterRTID` des audits WFP 5157 et 5152: c'est ce
    /// qui permet d'affirmer que c'est NOTRE filtre qui a bloque, et non un
    /// autre produit installe sur la machine.
    pub fn derniers_filtres(&self) -> Vec<(String, u64)> {
        self.derniers_filtres.borrow().clone()
    }

    /// Les identifiants des filtres dont le nom contient `motif`.
    ///
    /// Sert a demander au temoin "est-ce bien `block-dns` qui a bloque", et non
    /// "est-ce l'un quelconque des notres": le catch-all bloque tout, donc lui
    /// imputer un refus ne prouverait rien sur la regle qu'on croit mesurer.
    pub fn filtres_nommes(&self, motif: &str) -> Vec<u64> {
        self.derniers_filtres
            .borrow()
            .iter()
            .filter(|(nom, _)| nom.contains(motif))
            .map(|(_, id)| *id)
            .collect()
    }

    fn install(&self, engine: &Engine, filters: &[FilterSpec]) -> Result<()> {
        engine.transaction(|| {
            // Retirer avant de reposer: les objets existants viennent soit d'un
            // engage precedent, soit d'un daemon mort. On repart d'un etat
            // connu, sans jamais rouvrir le trafic puisqu'on est en transaction.
            purge(engine)?;

            let mut name = ffi::wide("Bifrost");
            let mut desc = ffi::wide("Bifrost VPN kill switch");
            engine.add_provider(&PROVIDER_KEY, &mut name, &mut desc)?;

            let mut sub_name = ffi::wide("Bifrost kill switch");
            let mut sub_desc = ffi::wide("Filtres de blocage Bifrost");
            let mut provider = PROVIDER_KEY;
            engine.add_sublayer(
                &SUBLAYER_KEY,
                &mut provider,
                &mut sub_name,
                &mut sub_desc,
                wfp_plan::SUBLAYER_WEIGHT,
            )?;

            let mut ids = Vec::new();
            for spec in filters {
                for layer in &spec.layers {
                    // Le NOM autant que l'identifiant: savoir qu'un de nos
                    // filtres a bloque vaut moins que savoir LEQUEL. Un blocage
                    // impute au catch-all ne prouve pas que la regle DNS
                    // fonctionne, il prouve seulement que tout est coupe.
                    ids.push((spec.name.clone(), self.add_filter(engine, spec, *layer)?));
                }
            }
            *self.derniers_filtres.borrow_mut() = ids;
            Ok(())
        })
    }

    fn add_filter(&self, engine: &Engine, spec: &FilterSpec, layer: Layer) -> Result<u64> {
        self.add_filter_dans(engine, spec, layer, &Cible::kill_switch())
    }

    /// Le meme, mais dans un provider et un sublayer choisis, avec une cle de
    /// filtre imposee et des drapeaux de duree de vie.
    ///
    /// Le filtre de demarrage a besoin des trois: il vit dans ses propres
    /// objets, qui survivent au daemon, et ses cles doivent etre FIXES parce
    /// qu'un filtre boot-time n'apparait dans aucune enumeration du moteur en
    /// marche. Sans cle connue d'avance il serait irretirable et retiendrait
    /// son sublayer indefiniment.
    fn add_filter_dans(
        &self,
        engine: &Engine,
        spec: &FilterSpec,
        layer: Layer,
        cible: &Cible,
    ) -> Result<u64> {
        let mut storage = Storage::default();
        let conditions = self.build_conditions(&mut storage, spec, layer)?;

        let name_ptr = storage.name(&format!("{} ({})", spec.name, layer.name()));
        let desc_ptr = storage.name(&format!(
            "Bifrost: {} au poids {}",
            match spec.action {
                Action::Permit => "autorisation",
                Action::Block => "blocage",
            },
            spec.weight
        ));

        let mut flags: FWPM_FILTER_FLAGS = cible.drapeaux;
        if spec.hard {
            // Veto: empeche un hard permit d'un sublayer concurrent (antivirus,
            // autre VPN) d'ecraser ce blocage.
            flags |= FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
        }

        let mut provider = cible.provider;
        let filter = FWPM_FILTER0 {
            filterKey: cible.cle.unwrap_or_else(|| GUID::from_u128(0)),
            displayData: FWPM_DISPLAY_DATA0 {
                name: name_ptr,
                description: desc_ptr,
            },
            flags,
            providerKey: &mut provider,
            layerKey: layer_key(layer),
            subLayerKey: cible.sublayer,
            weight: ffi::filter_weight(spec.weight),
            numFilterConditions: conditions.len() as u32,
            filterCondition: if conditions.is_empty() {
                std::ptr::null_mut()
            } else {
                conditions.as_ptr() as *mut FWPM_FILTER_CONDITION0
            },
            action: FWPM_ACTION0 {
                r#type: match spec.action {
                    Action::Permit => FWP_ACTION_PERMIT,
                    Action::Block => FWP_ACTION_BLOCK,
                },
                Anonymous: FWPM_ACTION0_0 {
                    filterType: GUID::from_u128(0),
                },
            },
            ..Default::default()
        };

        // `storage` et `conditions` sont encore vivants ici, donc pendant tout
        // l'appel a FwpmFilterAdd0, qui copie ce dont il a besoin. Ils sont
        // liberes explicitement juste apres pour rendre la duree de vie
        // evidente au lecteur autant qu'au compilateur.
        let result = engine.add_filter(&filter);
        drop(conditions);
        drop(storage);

        result.map_err(|e| {
            Error::Firewall(format!("filtre '{}' sur {}: {e}", spec.name, layer.name()))
        })
    }

    /// Traduit les conditions du plan en structures WFP.
    ///
    /// Les conditions d'adresse d'une famille sont ignorees sur les layers de
    /// l'autre famille: poser une condition IPv4 sur un layer IPv6 fait echouer
    /// l'ajout du filtre avec un code peu parlant.
    fn build_conditions(
        &self,
        storage: &mut Storage,
        spec: &FilterSpec,
        layer: Layer,
    ) -> Result<Vec<FWPM_FILTER_CONDITION0>> {
        let mut out = Vec::new();
        for condition in &spec.conditions {
            let (field, value) = match condition {
                Condition::AppId(path) => {
                    let blob = storage.app_id(path)?;
                    (FWPM_CONDITION_ALE_APP_ID, ffi::cond_blob(blob))
                }
                Condition::UserId(identity) => {
                    let sd = storage.user_id(identity)?;
                    (FWPM_CONDITION_ALE_USER_ID, ffi::cond_sd(sd))
                }
                Condition::Protocol(p) => (FWPM_CONDITION_IP_PROTOCOL, ffi::cond_u8(*p)),
                // Pour ICMP, WFP fait porter le type par le champ du port
                // local. Ce n'est pas une astuce: c'est la definition de
                // FWPM_CONDITION_ICMP_TYPE, qui partage le meme identifiant.
                Condition::LocalPort(p) | Condition::IcmpType(p) => {
                    (FWPM_CONDITION_IP_LOCAL_PORT, ffi::cond_u16(*p))
                }
                Condition::RemotePort(p) => (FWPM_CONDITION_IP_REMOTE_PORT, ffi::cond_u16(*p)),
                Condition::RemoteAddrV4 { addr, prefix } => {
                    if !layer.is_v4() {
                        continue;
                    }
                    let mask = prefix_mask_v4(*prefix);
                    let ptr = storage.v4(u32::from(*addr), mask);
                    (FWPM_CONDITION_IP_REMOTE_ADDRESS, ffi::cond_v4(ptr))
                }
                Condition::RemoteAddrV6 { addr, prefix } => {
                    if layer.is_v4() {
                        continue;
                    }
                    let ptr = storage.v6(addr.octets(), *prefix);
                    (FWPM_CONDITION_IP_REMOTE_ADDRESS, ffi::cond_v6(ptr))
                }
                Condition::LocalInterface(luid) => {
                    let ptr = storage.u64(*luid);
                    (FWPM_CONDITION_IP_LOCAL_INTERFACE, ffi::cond_u64(ptr))
                }
                Condition::Loopback => (
                    FWPM_CONDITION_FLAGS,
                    ffi::cond_u32(FWP_CONDITION_FLAG_IS_LOOPBACK),
                ),
            };
            out.push(FWPM_FILTER_CONDITION0 {
                fieldKey: field,
                matchType: match condition {
                    Condition::Loopback => FWP_MATCH_FLAGS_ALL_SET,
                    _ => FWP_MATCH_EQUAL,
                },
                conditionValue: value,
            });
        }

        // Un filtre dont toutes les conditions ont ete ecartees par le filtrage
        // de famille deviendrait un permit inconditionnel: c'est exactement le
        // trou qu'on veut eviter.
        if !spec.conditions.is_empty() && out.is_empty() {
            return Err(Error::Firewall(format!(
                "le filtre '{}' n'a plus aucune condition sur {}: il autoriserait \
                 tout le trafic de ce layer",
                spec.name,
                layer.name()
            )));
        }
        Ok(out)
    }
}

impl KillSwitch for WfpKillSwitch {
    fn engage(&mut self, policy: &FirewallPolicy) -> Result<()> {
        if !policy.dns_resolver.is_loopback() {
            return Err(Error::Firewall(format!(
                "resolveur DNS hors loopback: {}",
                policy.dns_resolver
            )));
        }
        let luid = self.resolve_luid(policy)?;
        let filters = wfp_plan::plan(policy, self.daemon_exe.clone(), luid);
        let engine = Engine::open()?;
        self.install(&engine, &filters)?;

        tracing::info!(
            filtres = filters.len(),
            interface = ?policy.tunnel_interface,
            luid = ?luid,
            "kill switch WFP arme"
        );
        Ok(())
    }

    fn disengage(&mut self) -> Result<()> {
        let engine = Engine::open()?;
        let retires = engine.transaction(|| purge(&engine))?;
        tracing::info!(filtres = retires, "kill switch WFP desarme");
        Ok(())
    }

    fn is_engaged(&self) -> Result<bool> {
        let engine = Engine::open()?;
        engine.provider_exists(&PROVIDER_KEY)
    }

    fn backend(&self) -> &'static str {
        "wfp"
    }
}

/// Retire tous les objets Bifrost du moteur, dans l'ordre impose par WFP.
///
/// L'ordre n'est pas une precaution, c'est une contrainte: WFP ne supprime rien
/// en cascade. Un filtre qui reference encore le sublayer fait echouer sa
/// suppression avec `FWP_E_IN_USE`, et le kill switch devient inamovible. Le
/// meme piege frappe le second `engage` d'une connexion, qui commence par
/// remettre le moteur a plat.
///
/// A appeler dans une transaction: entre la suppression des filtres et celle du
/// provider, la politique est incomplete.
fn purge(engine: &Engine) -> Result<usize> {
    let layers: Vec<GUID> = Layer::ALL.iter().map(|l| layer_key(*l)).collect();
    let retires = engine.delete_filters_by_provider(&PROVIDER_KEY, &layers)?;
    engine.delete_sublayer(&SUBLAYER_KEY)?;
    engine.delete_provider(&PROVIDER_KEY)?;
    Ok(retires)
}

/// Retrait du filtre de demarrage. A appeler dans une transaction.
///
/// L'ordre compte: les filtres d'abord, puis le sublayer, puis le provider. Un
/// sublayer encore porteur d'un filtre refuse d'etre supprime, et l'erreur
/// ("objet encore reference") a deja laisse une machine a moitie coupee.
fn retirer_telemetrie_dans(engine: &Engine) -> Result<()> {
    for index in 0..telemetrie::MAX_FILTRES {
        engine.delete_filter_by_key(&telemetrie::cle(index))?;
    }
    engine.delete_sublayer(&telemetrie::SUBLAYER)?;
    engine.delete_provider(&telemetrie::PROVIDER)?;
    Ok(())
}

fn retirer_demarrage_dans(engine: &Engine) -> Result<()> {
    for index in 0..demarrage::MAX_FILTRES {
        engine.delete_filter_by_key(&demarrage::cle(index))?;
    }
    engine.delete_sublayer(&demarrage::SUBLAYER)?;
    engine.delete_provider(&demarrage::PROVIDER)?;
    Ok(())
}

/// Objets WFP vises par un ajout de filtre.
///
/// Le kill switch et le filtre de demarrage vivent dans des objets DISTINCTS,
/// et ce n'est pas un rangement: ceux du demarrage survivent au daemon par
/// construction, donc les melanger ferait retirer les uns en desarmant les
/// autres.
struct Cible {
    provider: GUID,
    sublayer: GUID,
    /// Cle imposee, pour les filtres qu'il faudra retirer sans pouvoir les
    /// enumerer. `None` laisse BFE en engendrer une.
    cle: Option<GUID>,
    /// `FWPM_FILTER_FLAG_BOOTTIME` ou `FWPM_FILTER_FLAG_PERSISTENT`, jamais les
    /// deux: ils sont exclusifs sur un meme filtre. C'est pour cela qu'il faut
    /// DEUX jeux de filtres pour couvrir le demarrage sans trou.
    drapeaux: FWPM_FILTER_FLAGS,
}

impl Cible {
    fn kill_switch() -> Self {
        Self {
            provider: PROVIDER_KEY,
            sublayer: SUBLAYER_KEY,
            cle: None,
            drapeaux: 0,
        }
    }

    fn telemetrie(cle: GUID) -> Self {
        Self {
            provider: telemetrie::PROVIDER,
            sublayer: telemetrie::SUBLAYER,
            cle: Some(cle),
            // Persistant et non boot-time, contrairement au demarrage.
            // L'asymetrie est voulue: la, ce qui manquerait avant BFE serait
            // une AUTORISATION, donc une machine coupee du reseau. Ici ce sont
            // des BLOCAGES, et ce qui manque avant BFE est au pire quelques
            // paquets d'un service qui ne peut de toute facon pas emettre avant
            // que la pile filtree existe.
            drapeaux: FWPM_FILTER_FLAG_PERSISTENT,
        }
    }

    fn demarrage(cle: GUID, drapeaux: FWPM_FILTER_FLAGS) -> Self {
        Self {
            provider: demarrage::PROVIDER,
            sublayer: demarrage::SUBLAYER,
            cle: Some(cle),
            drapeaux,
        }
    }
}

/// Le filtre de demarrage: les objets WFP qui bloquent avant que le daemon
/// existe.
///
/// Mesure du 17 aout 2026 sur le banc: un filtre boot-time pose depuis
/// l'espace utilisateur est bien enregistre la ou `tcpip.sys` lit sa politique
/// avant le demarrage de BFE, et un filtre persistant survit au redemarrage et
/// bloque. Ni driver noyau ni certificat EV. Voir le probleme ouvert 2.
/// Les objets WFP de la couche 2 anti-telemetrie.
///
/// Distincts de ceux du kill switch ET de ceux du demarrage. Trois jeux, trois
/// durees de vie, trois raisons d'exister: le kill switch vit le temps d'une
/// session de tunnel, le demarrage couvre l'avant-daemon, et celui-ci doit
/// valoir en permanence, tunnel leve ou baisse.
pub mod telemetrie {
    use super::*;

    pub(super) const PROVIDER: GUID = GUID::from_u128(0x3ac9d180_5e42_4b77_9d61_8e05f3a27c40);
    pub(super) const SUBLAYER: GUID = GUID::from_u128(0x3ac9d181_5e42_4b77_9d61_8e05f3a27c40);

    /// Base des cles de filtre. L'index occupe les deux derniers octets.
    const BASE: u128 = 0x3ac9d182_5e42_4b77_9d61_8e05f3a20000;

    /// Borne du balayage de retrait.
    ///
    /// Le catalogue le plus large donne dix blocages sur deux couches, soit
    /// vingt filtres. Cette borne laisse de la marge sans rendre le balayage
    /// couteux, et surtout elle est FIXE: le retrait rejoue la meme suite de
    /// cles sans rien savoir de la politique posee.
    pub const MAX_FILTRES: u16 = 64;

    pub(super) fn cle(index: u16) -> GUID {
        GUID::from_u128(BASE | index as u128)
    }
}

pub mod demarrage {
    use super::*;

    pub(super) const PROVIDER: GUID = GUID::from_u128(0x7f2c1e50_9a55_4d31_b8e2_4c0f6d9a1b73);
    pub(super) const SUBLAYER: GUID = GUID::from_u128(0x7f2c1e51_9a55_4d31_b8e2_4c0f6d9a1b73);

    /// Base des cles de filtre. L'index occupe les deux derniers octets.
    const BASE: u128 = 0x7f2c1e52_9a55_4d31_b8e2_4c0f6d9a0000;

    /// Borne du balayage de retrait.
    ///
    /// Le retrait ne peut pas enumerer: il rejoue la meme suite de cles et
    /// supprime chacune, en tolerant celles qui n'existent pas. Il n'a donc pas
    /// besoin de connaitre la politique qui a ete posee, ce qui est exactement
    /// la propriete qu'on attend d'une sortie de secours. La politique la plus
    /// large produit une centaine de filtres; cette borne laisse de la marge
    /// sans rendre le balayage couteux.
    pub const MAX_FILTRES: u16 = 256;

    pub(super) fn cle(index: u16) -> GUID {
        GUID::from_u128(BASE | index as u128)
    }
}

fn layer_key(layer: Layer) -> GUID {
    match layer {
        Layer::AuthConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        Layer::AuthConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        Layer::AuthRecvAcceptV4 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        Layer::AuthRecvAcceptV6 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    }
}

/// Masque IPv4 en ordre hote, tel que l'attend `FWP_V4_ADDR_AND_MASK`.
fn prefix_mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix.min(32))
    }
}

/// Resout le LUID d'une interface a partir de son nom (alias NetAdapter).
///
/// Publique pour que l'autotest puisse confronter ce que cette resolution rend
/// a ce que le driver a donne. Le produit, lui, prefere le LUID du device.
pub fn interface_luid(name: &str) -> Result<u64> {
    use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceAliasToLuid;
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

    let wide = ffi::wide(name);
    let mut luid = NET_LUID_LH::default();
    // SAFETY: `wide` est une chaine UTF-16 terminee par zero et `luid` pointe
    // sur une union locale valide.
    let code = unsafe { ConvertInterfaceAliasToLuid(wide.as_ptr(), &mut luid) };
    if code != 0 {
        return Err(Error::Firewall(format!(
            "interface '{name}' introuvable (code {code})"
        )));
    }
    // SAFETY: `Value` est la vue u64 de l'union, valide quel que soit ce que
    // l'API y a ecrit.
    Ok(unsafe { luid.Value })
}

/// Les GUID de windows-sys n'implementent ni `PartialEq` ni `Ord`: on les
/// reduit a leurs champs pour les comparer dans les tests.
#[cfg(test)]
fn guid_parts(g: &GUID) -> (u32, u16, u16, [u8; 8]) {
    (g.data1, g.data2, g.data3, g.data4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn les_trois_jeux_d_objets_wfp_ne_se_marchent_pas_dessus() {
        // Trois durees de vie differentes, donc trois provider/sublayer. Une
        // collision de GUID par copier-coller ferait retirer les filtres du
        // kill switch en desactivant l'anti-telemetrie, ou l'inverse - et ca ne
        // se verrait qu'a l'execution, sur une vraie machine.
        let cles = [
            ("kill switch provider", guid_parts(&PROVIDER_KEY)),
            ("kill switch sublayer", guid_parts(&SUBLAYER_KEY)),
            ("demarrage provider", guid_parts(&demarrage::PROVIDER)),
            ("demarrage sublayer", guid_parts(&demarrage::SUBLAYER)),
            ("telemetrie provider", guid_parts(&telemetrie::PROVIDER)),
            ("telemetrie sublayer", guid_parts(&telemetrie::SUBLAYER)),
        ];
        for (i, (nom_i, cle_i)) in cles.iter().enumerate() {
            for (nom_j, cle_j) in cles.iter().skip(i + 1) {
                assert_ne!(cle_i, cle_j, "{nom_i} et {nom_j} partagent un GUID");
            }
        }
    }

    /// Et les cles de FILTRE des deux jeux persistants, qui sont engendrees a
    /// partir d'une base: si les deux bases se recouvraient, le balayage de
    /// retrait de l'un supprimerait les filtres de l'autre.
    #[test]
    fn les_cles_de_filtre_des_deux_jeux_ne_se_recouvrent_pas() {
        let demarrage: Vec<_> = (0..demarrage::MAX_FILTRES)
            .map(|i| guid_parts(&demarrage::cle(i)))
            .collect();
        for i in 0..telemetrie::MAX_FILTRES {
            let cle = guid_parts(&telemetrie::cle(i));
            assert!(
                !demarrage.contains(&cle),
                "la cle de telemetrie {i} tombe sur une cle de demarrage"
            );
        }
    }

    #[test]
    fn les_masques_ipv4_correspondent_aux_prefixes() {
        assert_eq!(prefix_mask_v4(0), 0);
        assert_eq!(prefix_mask_v4(8), 0xff00_0000);
        assert_eq!(prefix_mask_v4(16), 0xffff_0000);
        assert_eq!(prefix_mask_v4(24), 0xffff_ff00);
        assert_eq!(prefix_mask_v4(32), 0xffff_ffff);
    }

    #[test]
    fn le_provider_et_le_sublayer_ont_des_identifiants_distincts() {
        assert_ne!(
            guid_parts(&PROVIDER_KEY),
            guid_parts(&SUBLAYER_KEY),
            "provider et sublayer doivent avoir des GUID differents"
        );
    }

    #[test]
    fn chaque_layer_a_sa_propre_cle() {
        let mut cles: Vec<_> = Layer::ALL
            .iter()
            .map(|l| guid_parts(&layer_key(*l)))
            .collect();
        cles.sort_unstable();
        let avant = cles.len();
        cles.dedup();
        assert_eq!(cles.len(), avant);
    }

    fn ks() -> WfpKillSwitch {
        WfpKillSwitch {
            daemon_exe: PathBuf::from("x.exe"),
            derniers_filtres: std::cell::RefCell::new(Vec::new()),
        }
    }

    fn policy() -> FirewallPolicy {
        FirewallPolicy {
            tunnel_interface: None,
            tunnel_luid: None,
            fwmark: None,
            dns_resolver: IpAddr::V4(Ipv4Addr::LOCALHOST),
            allow_lan: false,
            coeur_uid: None,
            coeur_executable: None,
            resolveur_uid: None,
            resolveur_executable: None,
            resolveur_sid: None,
            resolveur_embarque: false,
        }
    }

    /// Un resolveur routable ouvrirait un canal :53 vers l'exterieur.
    #[test]
    fn un_resolveur_non_loopback_est_refuse() {
        let mut p = policy();
        p.dns_resolver = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let err = ks().engage(&p).unwrap_err().to_string();
        assert!(err.contains("loopback"), "message inattendu: {err}");
    }

    /// Le LUID rendu par le device fait foi. S'en remettre au nom quand on a
    /// deja l'identifiant serait remplacer une certitude par une resolution.
    #[test]
    fn le_luid_de_la_politique_prime_sur_le_nom() {
        let mut p = policy();
        p.tunnel_luid = Some(0x42);
        p.tunnel_interface = Some("interface-qui-n-existe-pas".into());
        assert_eq!(ks().resolve_luid(&p).unwrap(), Some(0x42));
    }

    /// Avant que l'interface existe, il n'y a rien a autoriser: le block-all
    /// est pose seul, et c'est l'etat voulu.
    #[test]
    fn sans_interface_ni_luid_il_n_y_a_rien_a_autoriser() {
        assert_eq!(ks().resolve_luid(&policy()).unwrap(), None);
    }

    /// Le piege. Une interface nommee mais introuvable doit faire ECHOUER
    /// l'armement. Le repli silencieux d'avant posait un kill switch complet
    /// sans autorisation pour le tunnel: tout bloque, y compris le tunnel,
    /// alors que la connexion se declarait etablie.
    #[test]
    fn une_interface_nommee_mais_introuvable_fait_echouer_l_armement() {
        let mut p = policy();
        p.tunnel_interface = Some("bifrost-inexistant".into());
        let err = match ks().resolve_luid(&p) {
            Ok(v) => panic!("une interface introuvable doit echouer, recu {v:?}"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("introuvable"), "{err}");
        assert!(err.contains("autoriser son trafic"), "{err}");
    }
}

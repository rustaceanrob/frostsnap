//! BIP157 node driver: turns filter events into wallet updates.

use super::{WatchSet, MATCH_LOOKAHEAD};
use crate::bitcoin::{
    backend::{ChainStatus, ChainStatusDetail, ChainStatusState, FilterStatus},
    wallet::{CoordSuperWallet, KeychainId},
};
use crate::Sink;
use anyhow::{anyhow, Context, Result};
use bdk_chain::{
    bitcoin::{self},
    spk_client::FullScanResponse,
    BlockId, CheckPoint, ConfirmationBlockTime,
};
use bip157::{
    chain::{BlockHeaderChanges, IndexedHeader},
    ChainState, Event, GossipMonitorRequestBuilder, HashCheckpoint, Info, Receiver, Requester,
    TrustedPeer, Warning,
};
use futures::channel::mpsc;
use std::{
    collections::BTreeMap,
    ops::Deref,
    sync::{self, Arc},
};
use tracing::{event, Level};

/// Blocks below the wallet's tip to restart syncing from, so an offline reorg is still noticed.
const RESEED_DEPTH: u32 = 10;

/// Default peer count a filter node waits on before trusting a filter.
const DEFAULT_REQUIRED_PEERS: u8 = 2;

/// Worker threads for the node's runtime. They only carry the node and its peer connections:
/// the event loop runs on the handler's own thread and wallet writes on tokio's blocking pool.
const NODE_WORKER_THREADS: usize = 2;

/// A filter counts as this many filter headers when estimating sync progress, bip157's own
/// estimate of the relative cost of fetching and checking one.
const FILTER_COST_IN_HEADERS: u32 = 3;

/// Pick the starting `ChainState` given the wallet's tip and birthday.
fn seed_state(tip: &CheckPoint, birthday: HashCheckpoint) -> ChainState {
    if tip.height() == 0 {
        return ChainState::Checkpoint(birthday);
    }
    let resume = tip
        .floor_below(RESEED_DEPTH)
        .unwrap_or_else(|| tip.iter().last().expect("a checkpoint always has a base"));
    ChainState::Checkpoint(HashCheckpoint::new(resume.height(), resume.hash()))
}

/// Whether the first sync can skip filters: a chain never synced before, with no wallet that
/// could have been paid in it, has nothing in past blocks to find. Filters resume at the tip.
fn can_sync_headers_only(tip: &CheckPoint, watch: &WatchSet) -> bool {
    tip.height() == 0 && watch.is_empty()
}

/// Fold a header change into the chain being tracked; `ForkAdded` is deliberately ignored.
fn apply_header_changes(tip: CheckPoint, changes: &BlockHeaderChanges) -> CheckPoint {
    fn block_id(header: &IndexedHeader) -> BlockId {
        BlockId {
            height: header.height,
            hash: header.header.block_hash(),
        }
    }
    match changes {
        BlockHeaderChanges::Connected(header) => tip.insert(block_id(header)),
        BlockHeaderChanges::Reorganized { accepted, .. } => {
            let mut accepted = accepted.iter().collect::<Vec<_>>();
            accepted.sort_by_key(|header| header.height);
            accepted
                .into_iter()
                .fold(tip, |tip, header| tip.insert(block_id(header)))
        }
        BlockHeaderChanges::ForkAdded(_) => tip,
    }
}

/// Configuration for the filter node.
#[derive(Debug, Clone)]
pub struct FilterConfig {
    pub network: bitcoin::Network,
    /// Peers required to agree on a filter; the crate clamps this to 1..=15.
    pub required_peers: u8,
    /// bip157 hands out each trusted peer once, so with `whitelist_only` the transaction gossip
    /// listener needs one beyond the `required_peers`.
    pub trusted_peers: Vec<TrustedPeer>,
    /// Connect only to `trusted_peers`, skipping DNS seeds and gossip.
    pub whitelist_only: bool,
    /// Starting point for a wallet with no history.
    pub birthday: HashCheckpoint,
}

impl FilterConfig {
    pub fn new(network: bitcoin::Network) -> Self {
        Self {
            network,
            required_peers: DEFAULT_REQUIRED_PEERS,
            trusted_peers: Vec::new(),
            whitelist_only: false,
            birthday: default_birthday(network),
        }
    }
}

/// Starting checkpoint for a wallet with no history; mainnet floors at taproot activation.
fn default_birthday(network: bitcoin::Network) -> HashCheckpoint {
    match network {
        bitcoin::Network::Bitcoin => HashCheckpoint::taproot_activation(),
        _ => HashCheckpoint::from_genesis(bitcoin::params::Params::new(network)),
    }
}

/// Projects node events into the app's `ChainStatus`, deduping repeated emissions.
struct FilterStatusTracker {
    peers: u32,
    /// Height the node resumed from; progress counts from here.
    start_height: u32,
    chain_height: u32,
    filter_headers_height: u32,
    filters_height: u32,
    connected: bool,
    last_emitted: Option<ChainStatus>,
    sink: Box<dyn Sink<ChainStatus>>,
}

impl Default for FilterStatusTracker {
    fn default() -> Self {
        Self {
            peers: 0,
            start_height: 0,
            chain_height: 0,
            filter_headers_height: 0,
            filters_height: 0,
            connected: false,
            last_emitted: None,
            sink: Box::new(()),
        }
    }
}

impl FilterStatusTracker {
    fn set_sink(&mut self, sink: Box<dyn Sink<ChainStatus>>) {
        self.sink = sink;
        let status = self.project();
        self.last_emitted = Some(status.clone());
        self.sink.send(status);
    }

    fn handshake(&mut self) {
        self.peers = self.peers.saturating_add(1);
        self.emit();
    }

    fn connections_met(&mut self) {
        self.connected = true;
        self.emit();
    }

    fn needs_connections(&mut self) {
        self.connected = false;
        self.peers = 0;
        self.emit();
    }

    fn set_chain_height(&mut self, height: u32) {
        self.chain_height = height;
        self.emit();
    }

    fn set_filter_headers_height(&mut self, height: u32) {
        self.filter_headers_height = height;
        self.emit();
    }

    fn set_filters_height(&mut self, height: u32) {
        self.filters_height = height;
        self.emit();
    }

    /// Everything up to `height` is checked, including a range a headers-only sync skipped
    /// without reporting filter progress.
    fn synced_to(&mut self, height: u32) {
        self.chain_height = self.chain_height.max(height);
        self.filter_headers_height = height;
        self.filters_height = height;
        self.emit();
    }

    /// Fraction of the range from `start_height` to the tip checked, a filter counting as
    /// `FILTER_COST_IN_HEADERS` filter headers. Rounded to a percent, so a download that reports
    /// every filter does not emit a status per filter.
    fn progress(&self) -> f32 {
        let total = self.chain_height.saturating_sub(self.start_height);
        if total == 0 {
            return 0.0;
        }
        let checked_since_start = |height: u32| height.saturating_sub(self.start_height).min(total);
        let weighted = checked_since_start(self.filter_headers_height)
            + FILTER_COST_IN_HEADERS * checked_since_start(self.filters_height);
        let out_of = (1 + FILTER_COST_IN_HEADERS) * total;
        (100.0 * weighted as f32 / out_of as f32).floor() / 100.0
    }

    fn project(&self) -> ChainStatus {
        ChainStatus {
            state: match (self.connected, self.peers) {
                (true, _) => ChainStatusState::Connected,
                (false, 0) => ChainStatusState::Idle,
                (false, _) => ChainStatusState::Connecting,
            },
            detail: ChainStatusDetail::CompactFilters(FilterStatus {
                peers: self.peers,
                progress: self.progress(),
            }),
        }
    }

    fn emit(&mut self) {
        let status = self.project();
        if self.last_emitted.as_ref() == Some(&status) {
            return;
        }
        self.last_emitted = Some(status.clone());
        self.sink.send(status);
    }
}

enum Message {
    RefreshWatchSet,
    SetStatusSink(Box<dyn Sink<ChainStatus>>),
    /// Check past filters again for the watched scripts, for a wallet that may have history.
    Rescan,
}

/// Cheap, cloneable handle the rest of the app holds.
#[derive(Clone)]
pub struct FilterClient {
    req_sender: mpsc::UnboundedSender<Message>,
    requester: Arc<sync::Mutex<Option<Requester>>>,
    runtime: tokio::runtime::Handle,
}

impl FilterClient {
    fn requester(&self) -> Result<Requester> {
        self.requester
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| anyhow!("the compact filter node is not running"))
    }

    pub fn monitor_keychain(&self, _keychain: KeychainId, _next_index: u32) {
        let _ = self.req_sender.unbounded_send(Message::RefreshWatchSet);
    }

    /// Returns once the transaction has been sent to a peer.
    pub fn broadcast(&self, transaction: bitcoin::Transaction) -> Result<bitcoin::Txid> {
        let txid = transaction.compute_txid();
        let requester = self.requester()?;
        self.runtime
            .block_on(async move { requester.submit_package(transaction).await })
            .map_err(|err| anyhow!("broadcasting {txid}: {err:?}"))?;
        event!(Level::INFO, %txid, "broadcast sent");
        Ok(txid)
    }

    /// Average fee rate over blocks below the tip, floored at `broadcast_min_feerate`.
    pub fn estimate_fee(
        &self,
        target_blocks: &[usize],
    ) -> Result<BTreeMap<usize, bitcoin::FeeRate>> {
        if target_blocks.is_empty() {
            return Ok(BTreeMap::new());
        }
        let requester = self.requester()?;
        let deepest = target_blocks.iter().copied().max().unwrap_or(1).max(1);
        self.runtime.block_on(async move {
            let floor = requester.broadcast_min_feerate().await.ok();
            let tip = requester
                .chain_tip()
                .await
                .map_err(|err| anyhow!("asking for the chain tip: {err:?}"))?;
            let mut samples = Vec::with_capacity(deepest);
            for depth in 0..deepest as u32 {
                let Some(height) = tip.height.checked_sub(depth) else {
                    break;
                };
                let header = match requester.get_header(height).await {
                    Ok(Some(header)) => header,
                    Ok(None) => break,
                    Err(err) => {
                        event!(Level::DEBUG, height, ?err, "no header for fee sampling");
                        break;
                    }
                };
                match requester.average_fee_rate(header.header.block_hash()).await {
                    Ok(rate) => samples.push(rate),
                    Err(err) => {
                        event!(Level::DEBUG, height, ?err, "no fee rate for block");
                    }
                }
            }
            if samples.is_empty() {
                return Ok(BTreeMap::new());
            }
            let mut estimates = BTreeMap::new();
            for target in target_blocks.iter().copied() {
                let window = target.clamp(1, samples.len());
                let total: u64 = samples[..window]
                    .iter()
                    .map(|rate| rate.to_sat_per_kwu())
                    .sum();
                let mean = bitcoin::FeeRate::from_sat_per_kwu(total / window as u64);
                estimates.insert(target, floor.map_or(mean, |floor| mean.max(floor)));
            }
            Ok(estimates)
        })
    }

    pub fn set_status_sink(&self, sink: Box<dyn Sink<ChainStatus>>) {
        let _ = self.req_sender.unbounded_send(Message::SetStatusSink(sink));
    }

    /// No-op: the node keeps a rotating set of peers, and a rescan belongs behind its own action.
    pub fn reconnect(&self) {}

    /// Filters already checked were checked without the new scripts, so go over them again from
    /// the birthday.
    pub fn find_history(&self) {
        let _ = self.req_sender.unbounded_send(Message::Rescan);
    }
}

/// Owns the node and event loop; run on a dedicated thread.
pub struct FilterHandler {
    config: FilterConfig,
    req_recv: mpsc::UnboundedReceiver<Message>,
    requester: Arc<sync::Mutex<Option<Requester>>>,
    runtime: Arc<tokio::runtime::Runtime>,
}

/// Build a `FilterClient` and its `FilterHandler`.
pub fn new(config: FilterConfig) -> Result<(FilterClient, FilterHandler)> {
    let (req_sender, req_recv) = mpsc::unbounded();
    let requester = Arc::new(sync::Mutex::new(None));
    let runtime = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(NODE_WORKER_THREADS)
            .enable_all()
            .build()
            .context("building the tokio runtime for the filter node")?,
    );
    Ok((
        FilterClient {
            req_sender,
            requester: requester.clone(),
            runtime: runtime.handle().clone(),
        },
        FilterHandler {
            config,
            req_recv,
            requester,
            runtime,
        },
    ))
}

impl FilterHandler {
    /// Run the event loop until the node stops, applying updates to `super_wallet`.
    pub fn run<SW, F>(self, super_wallet: SW, update_action: F) -> Result<()>
    where
        SW: Deref<Target = sync::Mutex<CoordSuperWallet>> + Clone + Send + 'static,
        F: FnMut(frostsnap_core::MasterAppkey, Vec<crate::bitcoin::wallet::Transaction>)
            + Send
            + 'static,
    {
        let (mut tip, mut watch) = snapshot(&super_wallet);
        let seed = seed_state(&tip, self.config.birthday);
        let headers_only = can_sync_headers_only(&tip, &watch);
        event!(
            Level::INFO,
            network = self.config.network.to_string(),
            watched_scripts = watch.scripts().count(),
            headers_only,
            "starting compact filter node"
        );
        let network = self.config.network;
        let rt = self.runtime.clone();
        let mut req_recv = self.req_recv;
        let start_height = match &seed {
            ChainState::Checkpoint(checkpoint) => checkpoint.height,
            ChainState::Snapshot(_) => 0,
        };
        let mut builder = bip157::Builder::new(self.config.network)
            .required_peers(self.config.required_peers)
            .chain_state(seed)
            .add_peers(self.config.trusted_peers.clone());
        if self.config.whitelist_only {
            builder = builder.whitelist_only();
        }
        if headers_only {
            builder = builder.headers_only_sync();
        }
        let (node, client) = builder.build();
        let bip157::Client {
            requester,
            mut event_rx,
            mut info_rx,
            mut warn_rx,
        } = client;
        *self.requester.lock().unwrap() = Some(requester.clone());
        let (update_sender, update_recv) =
            mpsc::unbounded::<FullScanResponse<KeychainId, ConfirmationBlockTime>>();
        let _writer = rt.spawn_blocking({
            let super_wallet = super_wallet.clone();
            move || {
                crate::bitcoin::chain_sync::ConnectionHandler::handle_wallet_updates(
                    super_wallet,
                    update_recv,
                    update_action,
                )
            }
        });
        let mut status = FilterStatusTracker {
            start_height,
            ..Default::default()
        };
        let birthday_height = self.config.birthday.height;
        // bip157 ignores a rescan until the node first reaches the tip, so one asked for earlier
        // waits for that.
        let mut synced = false;
        let mut rescan_when_synced = false;
        let node_handle = rt.spawn(async move { node.run().await });
        rt.block_on(async move {
            let mut gossip = None;
            subscribe_watch_set_to_gossip(&requester, &watch, &mut gossip).await;
            loop {
                tokio::select! {
                    event = event_rx.recv() => {
                        let Some(event) = event else { break };
                        match event {
                            Event::ChainUpdate(changes) => {
                                match &changes {
                                    BlockHeaderChanges::Reorganized { accepted, reorganized } => {
                                        event!(
                                            Level::INFO,
                                            disconnected = reorganized.len(),
                                            connected = accepted.len(),
                                            "the chain reorganised"
                                        );
                                    }
                                    BlockHeaderChanges::ForkAdded(header) => {
                                        event!(
                                            Level::DEBUG,
                                            height = header.height,
                                            "saw a competing fork"
                                        );
                                    }
                                    BlockHeaderChanges::Connected(_) => {}
                                }
                                tip = apply_header_changes(tip, &changes);
                            }
                            Event::IndexedFilter(filter) => {
                                if !filter.contains_any(watch.scripts()) {
                                    continue;
                                }
                                let hash = filter.block_hash();
                                let height = filter.height();
                                event!(
                                    Level::DEBUG,
                                    height,
                                    "a filter matched; fetching its block",
                                );
                                match requester.get_block(hash).await {
                                    Ok(block) => {
                                        let found = watch.scan_block(&block.block, block.height);
                                        if found.is_none() {
                                            event!(
                                                Level::DEBUG,
                                                height,
                                                "the block held nothing of ours"
                                            );
                                        }
                                        if let Some(mut update) = found {
                                            tip = tip.insert(BlockId { height, hash });
                                            update.chain_update = Some(tip.clone());
                                            event!(
                                                Level::INFO,
                                                height,
                                                transactions = update.tx_update.txs.len(),
                                                "found wallet transactions in a block"
                                            );
                                            let _ = update_sender.unbounded_send(update);
                                        }
                                    }
                                    Err(err) => {
                                        event!(
                                            Level::WARN,
                                            height,
                                            ?err,
                                            "could not fetch a block the filter matched"
                                        );
                                    }
                                }
                            }
                            Event::FiltersSynced(sync) => {
                                event!(
                                    Level::INFO,
                                    height = sync.tip.height,
                                    "filters synced to tip"
                                );
                                status.synced_to(sync.tip.height);
                                let _ = update_sender.unbounded_send(FullScanResponse {
                                    tx_update: Default::default(),
                                    last_active_indices: Default::default(),
                                    chain_update: Some(tip.clone()),
                                });
                                synced = true;
                                if std::mem::take(&mut rescan_when_synced) {
                                    rescan_from(&requester, birthday_height);
                                }
                            }
                        }
                    }
                    info = info_rx.recv() => {
                        match info {
                            Some(Info::NewChainHeight(height)) => status.set_chain_height(height),
                            Some(Info::CFHeadersAdded(height)) => {
                                status.set_filter_headers_height(height)
                            }
                            Some(Info::FilterAdded(height)) => status.set_filters_height(height),
                            Some(Info::ConnectionsMet) => {
                                event!(Level::INFO, "connected to enough peers");
                                status.connections_met()
                            }
                            Some(Info::SuccessfulHandshake) => {
                                event!(Level::DEBUG, "handshake with a peer");
                                status.handshake()
                            }
                            Some(Info::BlockReceived(_)) => {}
                            None => break,
                        }
                    }
                    warning = warn_rx.recv() => {
                        match warning {
                            Some(Warning::NeedConnections { connected, required }) => {
                                event!(Level::INFO, connected, required, "waiting for peers");
                                status.needs_connections()
                            }
                            Some(warning) => {
                                event!(Level::DEBUG, %warning, "compact filter node warning");
                            }
                            None => break,
                        }
                    }
                    tx = recv_gossip(&mut gossip) => {
                        match tx {
                            Some(tx) => {
                                if let Some(update) = watch.scan_unconfirmed(&tx, unix_now()) {
                                    event!(
                                        Level::INFO,
                                        txid = %tx.compute_txid(),
                                        "heard an unconfirmed wallet transaction",
                                    );
                                    let _ = update_sender.unbounded_send(update);
                                }
                            }
                            None => {
                                event!(Level::WARN, "transaction gossip listener stopped");
                                gossip = None;
                            }
                        }
                    }
                    message = next_message(&mut req_recv) => {
                        match message {
                            Some(Message::RefreshWatchSet) => {
                                let (_fresh_tip, fresh_watch) = snapshot(&super_wallet);
                                watch = fresh_watch;
                                event!(
                                    Level::DEBUG,
                                    scripts = watch.scripts().count(),
                                    "refreshed the watched scripts",
                                );
                                subscribe_watch_set_to_gossip(&requester, &watch, &mut gossip)
                                    .await;
                            }
                            Some(Message::Rescan) => {
                                let (_fresh_tip, fresh_watch) = snapshot(&super_wallet);
                                watch = fresh_watch;
                                subscribe_watch_set_to_gossip(&requester, &watch, &mut gossip)
                                    .await;
                                if synced {
                                    rescan_from(&requester, birthday_height);
                                } else {
                                    rescan_when_synced = true;
                                }
                            }
                            Some(Message::SetStatusSink(sink)) => {
                                status.set_sink(sink);
                            }
                            None => break,
                        }
                    }
                }
            }
        });
        event!(Level::INFO, network = %network, "compact filter node stopped");
        node_handle.abort();
        Ok(())
    }
}

/// Watch mempool gossip for `watch`'s scripts and coins, so a payment shows before it confirms.
/// The first subscription opens the listener and returns its receiver; later ones add to it.
async fn subscribe_watch_set_to_gossip(
    requester: &Requester,
    watch: &WatchSet,
    gossip: &mut Option<Receiver<bitcoin::Transaction>>,
) {
    if watch.is_empty() {
        return;
    }
    let request =
        GossipMonitorRequestBuilder::from_expected_output_scripts(watch.scripts().cloned())
            .add_outpoints(watch.owned().copied())
            .build();
    match requester.subscribe_to_gossip(request).await {
        Ok(Some(receiver)) => {
            event!(Level::INFO, "listening for transaction gossip");
            *gossip = Some(receiver);
        }
        Ok(None) => event!(Level::DEBUG, "widened the transaction gossip subscription"),
        Err(err) => event!(
            Level::WARN,
            ?err,
            "could not subscribe to transaction gossip"
        ),
    }
}

/// The next gossiped transaction, or never when there is no listener.
async fn recv_gossip(
    gossip: &mut Option<Receiver<bitcoin::Transaction>>,
) -> Option<bitcoin::Transaction> {
    match gossip {
        Some(receiver) => receiver.recv().await,
        None => std::future::pending().await,
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

/// Check filters after `height` again against the watched scripts.
fn rescan_from(requester: &Requester, height: u32) {
    match requester.rescan_from(height) {
        Ok(()) => event!(
            Level::INFO,
            from = height,
            "rescanning filters for wallet history"
        ),
        Err(err) => event!(Level::WARN, ?err, "could not start a rescan"),
    }
}

async fn next_message(rx: &mut mpsc::UnboundedReceiver<Message>) -> Option<Message> {
    use futures::StreamExt;
    rx.next().await
}

/// Snapshot the wallet's tip and match set.
fn snapshot<SW>(super_wallet: &SW) -> (CheckPoint, WatchSet)
where
    SW: Deref<Target = sync::Mutex<CoordSuperWallet>>,
{
    let wallet = super_wallet.lock().expect("must lock");
    let tip = wallet.chain_tip();
    let watch = WatchSet::from_indexer(&wallet.tx_graph.index, MATCH_LOOKAHEAD);
    (tip, watch)
}

#[cfg(test)]
mod test {
    use super::*;
    use bdk_chain::bitcoin::{hashes::Hash, BlockHash};

    fn hash(byte: u8) -> BlockHash {
        BlockHash::from_byte_array([byte; 32])
    }

    fn chain(blocks: &[(u32, u8)]) -> CheckPoint {
        CheckPoint::from_block_ids(blocks.iter().map(|&(height, byte)| BlockId {
            height,
            hash: hash(byte),
        }))
        .expect("ascending")
    }

    fn header(height: u32, prev: u8) -> IndexedHeader {
        IndexedHeader {
            height,
            header: bdk_chain::bitcoin::block::Header {
                version: bdk_chain::bitcoin::block::Version::TWO,
                prev_blockhash: hash(prev),
                merkle_root: bdk_chain::bitcoin::TxMerkleNode::all_zeros(),
                time: 1_700_000_000,
                bits: bdk_chain::bitcoin::CompactTarget::from_consensus(0x1d00_ffff),
                nonce: 0,
            },
        }
    }

    #[test]
    fn default_birthday_is_taproot_activation_on_mainnet() {
        let birthday = default_birthday(bitcoin::Network::Bitcoin);
        assert_eq!(birthday.height, 709_631);
        let signet = default_birthday(bitcoin::Network::Signet);
        assert_eq!(signet.height, 0, "no taproot checkpoint outside mainnet");
    }

    #[test]
    fn seed_state_resumes_reseed_depth_below_tip() {
        let tip = chain(&[(0, 0), (100, 1), (105, 2), (110, 3)]);
        let ChainState::Checkpoint(seed) = seed_state(&tip, HashCheckpoint::new(0, hash(0))) else {
            panic!("a wallet with history resumes from a checkpoint")
        };
        assert_eq!(seed.height, 100);
        assert_eq!(seed.hash, hash(1));
    }

    #[test]
    fn seed_state_rounds_rewind_height_down() {
        let tip = chain(&[(0, 0), (90, 1), (110, 3)]);
        let ChainState::Checkpoint(seed) = seed_state(&tip, HashCheckpoint::new(0, hash(0))) else {
            panic!("expected a checkpoint")
        };
        assert!(seed.height <= 100, "never resumes above the rewind target");
        assert_eq!(seed.height, 90);
    }

    #[test]
    fn seed_state_starts_unsynced_wallet_at_birthday() {
        let tip = chain(&[(0, 0)]);
        let birthday = HashCheckpoint::new(800_000, hash(9));
        let ChainState::Checkpoint(seed) = seed_state(&tip, birthday) else {
            panic!("expected a checkpoint")
        };
        assert_eq!(seed.height, 800_000);
    }

    #[test]
    fn headers_only_sync_requires_unsynced_chain_and_empty_watch_set() {
        let k = (
            frostsnap_core::MasterAppkey::derive_from_rootkey(
                frostsnap_core::schnorr_fun::fun::Point::random(&mut rand::thread_rng()),
            ),
            frostsnap_core::tweak::BitcoinAccountKeychain::external(),
        );
        let script = bitcoin::ScriptBuf::from_bytes(vec![0x51; 34]);
        let fresh = chain(&[(0, 0)]);
        let synced = chain(&[(0, 0), (100, 1)]);
        let nothing = WatchSet::default();
        let a_wallet = WatchSet::new([(script, (k, 0))], []);
        assert!(can_sync_headers_only(&fresh, &nothing));
        assert!(
            !can_sync_headers_only(&fresh, &a_wallet),
            "a wallet on a chain never synced may have been restored, so it gets a full scan"
        );
        assert!(
            !can_sync_headers_only(&synced, &nothing),
            "a synced chain resumes as before"
        );
    }

    /// One peer is not the quorum the node was told to reach, so it must not read as connected.
    /// Reporting "connected" off a single handshake would tell the user their wallet is up to date
    /// while the node is still waiting to trust what it hears.
    #[test]
    fn status_connecting_until_required_peers_met() {
        let mut status = FilterStatusTracker::default();
        assert_eq!(status.project().state, ChainStatusState::Idle);

        status.handshake();
        assert_eq!(status.project().state, ChainStatusState::Connecting);

        status.connections_met();
        assert_eq!(status.project().state, ChainStatusState::Connected);
    }

    #[test]
    fn status_resets_peer_count_when_connections_lost() {
        let mut status = FilterStatusTracker::default();
        status.handshake();
        status.handshake();
        status.connections_met();

        status.needs_connections();
        let projected = status.project();
        assert_eq!(projected.state, ChainStatusState::Idle);
        match projected.detail {
            ChainStatusDetail::CompactFilters(filters) => assert_eq!(filters.peers, 0),
            other => panic!("expected compact filter detail, got {other:?}"),
        }
    }

    /// A headers-only sync reports no filter progress, but reaching the tip is still all of it.
    #[test]
    fn status_progress_complete_after_headers_only_sync() {
        let mut status = FilterStatusTracker {
            start_height: 100,
            ..Default::default()
        };
        status.set_chain_height(200);
        assert_eq!(status.progress(), 0.0);
        status.synced_to(200);
        assert_eq!(status.progress(), 1.0);
    }

    #[test]
    fn status_progress_measured_from_resume_height() {
        let mut status = FilterStatusTracker {
            start_height: 100,
            ..Default::default()
        };
        assert_eq!(status.progress(), 0.0, "no tip known yet");
        status.set_chain_height(200);
        status.set_filter_headers_height(200);
        status.set_filters_height(150);
        // All 100 filter headers plus half the filters, a filter weighing three headers.
        assert_eq!(status.progress(), 0.62);
        status.set_filters_height(200);
        assert_eq!(status.progress(), 1.0);
    }

    /// The node reports progress continuously through a long download; forwarding every one would
    /// be a stream of identical statuses.
    #[test]
    fn status_deduplicates_unchanged_emissions() {
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct Log(Arc<Mutex<Vec<ChainStatus>>>);
        impl crate::Sink<ChainStatus> for Log {
            fn send(&self, status: ChainStatus) {
                self.0.lock().unwrap().push(status);
            }
        }

        let log = Log(Default::default());
        let mut status = FilterStatusTracker::default();
        status.set_sink(Box::new(log.clone()));
        assert_eq!(
            log.0.lock().unwrap().len(),
            1,
            "a new sink sees the current status"
        );

        status.connections_met();
        status.connections_met();
        assert_eq!(log.0.lock().unwrap().len(), 2, "only the change was sent");
    }

    #[test]
    fn apply_header_changes_extends_on_connect() {
        let tip = chain(&[(0, 0), (1, 1)]);
        let next = apply_header_changes(tip, &BlockHeaderChanges::Connected(header(2, 1)));
        assert_eq!(next.height(), 2);
    }

    #[test]
    fn apply_header_changes_replaces_reorged_blocks() {
        let tip = chain(&[(0, 0), (1, 1), (2, 2), (3, 3)]);
        let changes = BlockHeaderChanges::Reorganized {
            accepted: vec![header(2, 1), header(3, 0xb2)],
            reorganized: vec![header(2, 1), header(3, 2)],
        };
        let next = apply_header_changes(tip, &changes);
        assert_eq!(next.height(), 3);
        let heights = next.iter().map(|cp| cp.height()).collect::<Vec<_>>();
        assert_eq!(heights, vec![3, 2, 1, 0]);
        assert_ne!(next.hash(), hash(3), "the old tip is gone");
    }

    #[test]
    fn apply_header_changes_ignores_unselected_fork() {
        let tip = chain(&[(0, 0), (1, 1)]);
        let before = tip.hash();
        let after = apply_header_changes(tip, &BlockHeaderChanges::ForkAdded(header(2, 9)));
        assert_eq!(after.hash(), before);
        assert_eq!(after.height(), 1);
    }
}

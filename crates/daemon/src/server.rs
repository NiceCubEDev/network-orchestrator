//! Connection handling: handshake, dispatch, events. Generic over the
//! stream so tests drive it through `tokio::io::duplex`.

use crate::always_on::{apply_definition, validate_definition, AlwaysOnStore};
use crate::auth::{
    connect_action, required_action, Action, AuthDecision, Authorizer, PeerIdentity,
};
#[cfg(target_os = "linux")]
use crate::cond_rules::{validate_rule, CondRuleStore, NetworkObservation, NoObservation};
use crate::core::DaemonCore;
use crate::openvpn::{prepare_openvpn, OpenVpnPlan};
use crate::settings::{DaemonSettings, SettingsStore};
use crate::validate::{validate_apply, validate_attach, validate_iface_name, validate_owner};
use crate::wireguard::parse_wireguard_config;
use crate::xray::prepare_xray;
use net_manager_core::daemon_protocol::{
    encode_line, event, from_value, method, read_frame, AlwaysOnKind, AlwaysOnListResult,
    AlwaysOnProfileInfo, AlwaysOnRemoveParams, AlwaysOnRemoveResult, AlwaysOnResumeResult,
    AlwaysOnSetParams, AlwaysOnSetResult, CondRulesListResult, CondRulesPutParams,
    CondRulesPutResult, CondRulesRemoveParams, CondRulesRemoveResult, ConditionalRuleEntry,
    ErrorCode, EventFrame, ExternalTunnelStopParams, HelloParams, HelloResult, LinkSetStateParams,
    NetDnsProbeParams, NetEditResult, NetIntentDelParams, NetIntentResult, NetIntentSetParams,
    NetRouteAddParams, NetRouteDelParams, NetRuleAddParams, NetRuleDelParams, NmListResult,
    NmSetActiveParams, OpenVpnConnectRequest, OpenVpnConnectResult, OpenVpnDisconnectResult,
    OpenVpnProbeResult, OpenVpnProfileParams, OwnedChanged, OwnedListResult, OwnerParams,
    RequestFrame, ResponseFrame, RoutesApplyParams, RoutesApplyResult, RoutesRemoveResult,
    SettingsResult, SettingsSetParams, VpnAuthMode, WireGuardConnectParams, WireGuardConnectResult,
    WireGuardDisconnectResult, WireGuardProfileParams, XrayConnectParams, XrayConnectResult,
    XrayDisconnectResult, XrayInstallParams, XrayInstallResult, XrayProfileParams,
    XrayRemoveResult, HELLO_TIMEOUT_SECS, MAX_CONNECTIONS, MAX_FRAME_BYTES, PROTOCOL_VERSION,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
#[cfg(target_os = "linux")]
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{broadcast, mpsc, Semaphore};

const EVENT_CAPACITY: usize = 256;

/// Grace window between the last client process dying and its non-persistent
/// tunnels being torn down: a restarting or crashed-and-relaunched app
/// reconnects within it and keeps the session alive.
#[cfg(target_os = "linux")]
pub const CLIENT_DEATH_GRACE: Duration = Duration::from_secs(30);

/// "Something `owner` of `uid` owns changed"; delivered to that uid only.
#[derive(Debug, Clone)]
pub struct OwnerEvent {
    pub uid: u32,
    pub owner: String,
}

/// Kernel handles of connected client processes, keyed by uid. pidfds are
/// race-free process handles: `pidfd_send_signal(fd, 0)` reports whether the
/// exact peer (not a recycled pid) is still alive.
#[cfg(target_os = "linux")]
#[derive(Default)]
pub struct ClientTracker {
    inner: Mutex<HashMap<u32, TrackedClient>>,
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct TrackedClient {
    pidfds: Vec<(u32, Arc<std::os::fd::OwnedFd>)>,
    /// Armed when the last live pidfd died; cleared by any new connection
    /// of the uid.
    dead_since: Option<Instant>,
}

#[cfg(target_os = "linux")]
impl ClientTracker {
    /// Register a freshly accepted client; returns true when this cancelled
    /// an armed death-grace window.
    pub fn track(&self, peer: &PeerIdentity) -> bool {
        let Some(pidfd) = &peer.pidfd else {
            return false;
        };
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let entry = inner.entry(peer.uid).or_default();
        if !entry.pidfds.iter().any(|(pid, _)| *pid == peer.pid) {
            entry.pidfds.push((peer.pid, pidfd.0.clone()));
        }
        entry.dead_since.take().is_some()
    }

    /// Reap exited processes; returns uids whose grace deadline has passed
    /// without a new connection. Each uid is reported once.
    pub fn expired(&self, grace: Duration) -> Vec<u32> {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut fired = Vec::new();
        inner.retain(|uid, entry| {
            entry.pidfds.retain(|(_, fd)| pidfd_alive(fd));
            if entry.pidfds.is_empty()
                && now.duration_since(*entry.dead_since.get_or_insert(now)) >= grace
            {
                fired.push(*uid);
                return false;
            }
            true
        });
        fired
    }
}

#[cfg(target_os = "linux")]
fn pidfd_alive(fd: &std::os::fd::OwnedFd) -> bool {
    use std::os::fd::AsRawFd;
    // SAFETY: signal 0 performs no delivery; siginfo may be null.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            0,
            std::ptr::null_mut::<libc::siginfo_t>(),
            0,
        )
    };
    rc == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Periodically reap client pidfds; when a uid's last client has been dead
/// for the full grace window, tear down the owners that are not registered
/// as always-on (those survive intentionally and are replayed on connect).
#[cfg(target_os = "linux")]
pub async fn watch_client_sessions<A: Authorizer + Send + Sync + 'static>(
    ctx: Arc<ServerContext<A>>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        interval.tick().await;
        let expired = ctx.clients.expired(CLIENT_DEATH_GRACE);
        if expired.is_empty() {
            continue;
        }
        let keep = ctx
            .always_on
            .as_ref()
            .and_then(|store| {
                let store = store.lock().unwrap_or_else(|e| e.into_inner());
                crate::always_on::replayable_owners(&store).ok()
            })
            .unwrap_or_default();
        let core = ctx.core.clone();
        let events = ctx.events.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let mut core = core.lock().unwrap_or_else(|e| e.into_inner());
            for uid in expired {
                match core.cleanup_session_uid(uid, &keep) {
                    Ok(result) => {
                        if !result.removed_owners.is_empty() {
                            eprintln!(
                                "network-orchestrator-daemon: client of uid {uid} is gone; removed {} session owner(s)",
                                result.removed_owners.len()
                            );
                        }
                        for owner in result.removed_owners {
                            let _ = events.send(OwnerEvent { uid, owner });
                        }
                    }
                    Err(err) => {
                        eprintln!(
                            "network-orchestrator-daemon: session cleanup of uid {uid} failed: {err}"
                        );
                    }
                }
            }
        })
        .await;
    }
}

pub struct ServerContext<A> {
    pub core: Arc<Mutex<DaemonCore>>,
    pub authorizer: A,
    pub events: broadcast::Sender<OwnerEvent>,
    pub connections: Arc<Semaphore>,
    pub hello_timeout: Duration,
    pub always_on: Option<Arc<Mutex<AlwaysOnStore>>>,
    /// Conditional route rules; `None` in tests disables condRules.*.
    #[cfg(target_os = "linux")]
    pub cond_rules: Option<Arc<CondRuleStore>>,
    /// Kernel state for conditional evaluation; `NoObservation` in tests.
    #[cfg(target_os = "linux")]
    pub observer: Arc<dyn NetworkObservation>,
    pub settings: Arc<Mutex<DaemonSettings>>,
    /// `None` keeps settings in memory only (tests).
    pub settings_store: Option<Arc<SettingsStore>>,
    /// Root the `xray.install`/`xray.remove` methods write under; tests
    /// point it at a tempdir so they never touch the real package tree.
    #[cfg(target_os = "linux")]
    pub xray_package_root: std::path::PathBuf,
    /// Reports whether each trusted system binary (see `tool::*` in the
    /// protocol) is usable right now; tests substitute a stub.
    #[cfg(target_os = "linux")]
    pub tools_probe: fn() -> std::collections::BTreeMap<String, bool>,
    /// Live client processes per uid; drives the death-grace cleanup.
    #[cfg(target_os = "linux")]
    pub clients: Arc<ClientTracker>,
}

impl<A: Authorizer> ServerContext<A> {
    pub fn new(core: DaemonCore, authorizer: A) -> Self {
        Self {
            core: Arc::new(Mutex::new(core)),
            authorizer,
            events: broadcast::channel(EVENT_CAPACITY).0,
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            hello_timeout: Duration::from_secs(HELLO_TIMEOUT_SECS),
            always_on: None,
            #[cfg(target_os = "linux")]
            cond_rules: None,
            #[cfg(target_os = "linux")]
            observer: Arc::new(NoObservation),
            settings: Arc::new(Mutex::new(DaemonSettings::default())),
            settings_store: None,
            #[cfg(target_os = "linux")]
            xray_package_root: Self::default_xray_package_root(),
            #[cfg(target_os = "linux")]
            tools_probe: default_tool_presence,
            #[cfg(target_os = "linux")]
            clients: Arc::new(ClientTracker::default()),
        }
    }

    pub fn with_always_on_store(core: DaemonCore, authorizer: A, store: AlwaysOnStore) -> Self {
        let mut context = Self::new(core, authorizer);
        context.always_on = Some(Arc::new(Mutex::new(store)));
        context
    }

    #[cfg(target_os = "linux")]
    fn default_xray_package_root() -> std::path::PathBuf {
        #[cfg(target_arch = "x86_64")]
        {
            net_manager_core::managed_xray::LINUX_XRAY_PACKAGE_ROOT.into()
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            std::path::PathBuf::new()
        }
    }

    #[cfg(target_os = "linux")]
    pub fn with_cond_rules(
        mut self,
        store: CondRuleStore,
        observer: Arc<dyn NetworkObservation>,
    ) -> Self {
        self.cond_rules = Some(Arc::new(store));
        self.observer = observer;
        self
    }

    pub fn with_settings_store(mut self, store: SettingsStore) -> Self {
        self.settings = Arc::new(Mutex::new(store.load()));
        self.settings_store = Some(Arc::new(store));
        self
    }

    fn vpn_auth_mode(&self) -> VpnAuthMode {
        self.settings.lock().unwrap().vpn_auth_mode
    }
}

type Failure = (ErrorCode, String);

/// Longest a single request may take before the client gets a `timed out`
/// answer; covers polkit dialogs that wait on user input.
const DISPATCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Entry point for an accepted connection: enforces the connection limit,
/// then serves it until either side closes.
pub async fn serve_accepted<S, A>(mut stream: S, peer: PeerIdentity, ctx: Arc<ServerContext<A>>)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    A: Authorizer,
{
    let Ok(_permit) = ctx.connections.clone().try_acquire_owned() else {
        let busy = ResponseFrame::error(0, ErrorCode::Busy, "too many connections");
        let _ = write_frame(&mut stream, &busy).await;
        return;
    };
    let uid = peer.uid;
    #[cfg(target_os = "linux")]
    ctx.clients.track(&peer);
    if let Err(err) = serve_connection(stream, peer, ctx).await {
        eprintln!("network-orchestrator-daemon: connection of uid {uid} failed: {err}");
    }
}

pub async fn serve_connection<S, A>(
    stream: S,
    peer: PeerIdentity,
    ctx: Arc<ServerContext<A>>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    A: Authorizer,
{
    let (read, mut write) = tokio::io::split(stream);
    // `read_frame` is not cancel-safe, so frames are read by a dedicated task
    // and handed over through a channel that `select!` can poll safely.
    let (frames_tx, mut frames) = mpsc::channel(1);
    let _reader = AbortOnDrop(tokio::spawn(async move {
        let mut reader = BufReader::new(read);
        loop {
            let frame = read_frame(&mut reader, MAX_FRAME_BYTES).await;
            let last = !matches!(frame, Ok(Some(_)));
            if frames_tx.send(frame).await.is_err() || last {
                break;
            }
        }
    }));

    let first = match tokio::time::timeout(ctx.hello_timeout, frames.recv()).await {
        Err(_) => return Ok(()),
        Ok(frame) => match next_frame(frame, &mut write).await? {
            Some(frame) => frame,
            None => return Ok(()),
        },
    };
    let request_id = match handshake(&first) {
        Ok(id) => id,
        Err(response) => return write_frame(&mut write, &response).await,
    };
    let hello = HelloResult {
        protocol: PROTOCOL_VERSION,
        daemon_version: env!("CARGO_PKG_VERSION").to_string(),
        uid: peer.uid,
        capabilities: method::CAPABILITIES.iter().map(|m| m.to_string()).collect(),
        tools: (ctx.tools_probe)(),
    };
    write_frame(&mut write, &ok(request_id, &hello)).await?;

    let mut subscription: Option<broadcast::Receiver<OwnerEvent>> = None;
    loop {
        let frame = tokio::select! {
            frame = frames.recv() => match next_frame(frame, &mut write).await? {
                Some(frame) => frame,
                None => return Ok(()),
            },
            event = next_event(&mut subscription, peer.uid) => {
                write_frame(&mut write, &event).await?;
                continue;
            }
        };
        let response = match serde_json::from_slice::<RequestFrame>(&frame) {
            Ok(request) => {
                let id = request.id;
                if request.method == method::SUBSCRIBE && subscription.is_none() {
                    subscription = Some(ctx.events.subscribe());
                }
                // A wedged handler must not hold the connection (and its
                // semaphore permit) forever; the blocking work itself may
                // linger, but the client is answered and released.
                match tokio::time::timeout(DISPATCH_TIMEOUT, dispatch(request, &peer, &ctx)).await {
                    Ok(response) => response,
                    Err(_) => {
                        eprintln!(
                            "network-orchestrator-daemon: request {id} timed out after {DISPATCH_TIMEOUT:?}"
                        );
                        ResponseFrame::error(id, ErrorCode::Internal, "request timed out")
                    }
                }
            }
            Err(_) => ResponseFrame::error(0, ErrorCode::InvalidParams, "malformed request frame"),
        };
        write_frame(&mut write, &response).await?;
    }
}

/// Unwrap what the reader task delivered. Oversized frames are answered
/// with `frameTooLarge`; any read error or EOF ends the connection.
async fn next_frame<W: AsyncWrite + Unpin>(
    frame: Option<io::Result<Option<Vec<u8>>>>,
    write: &mut W,
) -> io::Result<Option<Vec<u8>>> {
    match frame {
        Some(Ok(Some(frame))) => Ok(Some(frame)),
        Some(Err(err)) if err.kind() == io::ErrorKind::InvalidData => {
            let response = ResponseFrame::error(0, ErrorCode::FrameTooLarge, err.to_string());
            write_frame(write, &response).await?;
            Ok(None)
        }
        _ => Ok(None),
    }
}

/// Validate the mandatory first `hello`; returns its request id.
fn handshake(frame: &[u8]) -> Result<u64, ResponseFrame> {
    let request: RequestFrame = serde_json::from_slice(frame).map_err(|_| {
        ResponseFrame::error(0, ErrorCode::InvalidParams, "malformed request frame")
    })?;
    if request.method != method::HELLO {
        return Err(ResponseFrame::error(
            request.id,
            ErrorCode::HandshakeRequired,
            "the first request must be hello",
        ));
    }
    let params: HelloParams = from_value(request.params).map_err(|err| {
        ResponseFrame::error(request.id, ErrorCode::InvalidParams, err.to_string())
    })?;
    if params.protocol != PROTOCOL_VERSION {
        return Err(ResponseFrame::error(
            request.id,
            ErrorCode::ProtocolMismatch,
            format!(
                "daemon speaks protocol {PROTOCOL_VERSION}, client {}",
                params.protocol
            ),
        ));
    }
    Ok(request.id)
}

/// Wait for the next event for `uid`; never resolves without a subscription.
async fn next_event(
    subscription: &mut Option<broadcast::Receiver<OwnerEvent>>,
    uid: u32,
) -> EventFrame {
    let Some(receiver) = subscription.as_mut() else {
        return std::future::pending().await;
    };
    loop {
        match receiver.recv().await {
            Ok(event) if event.uid == uid => {
                let data = serde_json::to_value(OwnedChanged { owner: event.owner })
                    .unwrap_or(Value::Null);
                return EventFrame::new(event::OWNED_CHANGED, data);
            }
            Ok(_) => continue,
            Err(broadcast::error::RecvError::Lagged(_)) => {
                return EventFrame::new(event::RESYNC, Value::Null);
            }
            Err(broadcast::error::RecvError::Closed) => return std::future::pending().await,
        }
    }
}

/// parse → validate → polkit → core → event → response.
async fn dispatch<A: Authorizer>(
    request: RequestFrame,
    peer: &PeerIdentity,
    ctx: &ServerContext<A>,
) -> ResponseFrame {
    let id = request.id;
    let method_name = request.method.clone();
    let result = handle(request, peer, ctx).await;
    if let Some(action) = required_action(&method_name) {
        let outcome = match &result {
            Ok(_) => "ok".to_string(),
            Err((code, _)) => format!("{code:?}"),
        };
        eprintln!(
            "network-orchestrator-daemon: uid {} {} ({}): {outcome}",
            peer.uid,
            method_name,
            action.polkit_id()
        );
    }
    match result {
        Ok(value) => ResponseFrame::ok(id, value),
        Err((code, message)) => ResponseFrame::error(id, code, message),
    }
}

async fn handle<A: Authorizer>(
    request: RequestFrame,
    peer: &PeerIdentity,
    ctx: &ServerContext<A>,
) -> Result<Value, Failure> {
    let uid = peer.uid;
    match request.method.as_str() {
        method::HELLO => Err((
            ErrorCode::InvalidParams,
            "hello was already exchanged".into(),
        )),
        method::SUBSCRIBE => Ok(Value::Null),
        method::SETTINGS_GET => to_value(&SettingsResult {
            vpn_auth_mode: ctx.vpn_auth_mode(),
        }),
        method::SETTINGS_SET => {
            let params: SettingsSetParams = params(request.params)?;
            authorize(ctx, peer, Action::SystemNetwork).await?;
            let settings = DaemonSettings {
                vpn_auth_mode: params.vpn_auth_mode,
            };
            let live = ctx.settings.clone();
            let store = ctx.settings_store.clone();
            tokio::task::spawn_blocking(move || {
                let mut current = live.lock().unwrap();
                if let Some(store) = store {
                    store.save(settings)?;
                }
                *current = settings;
                Ok::<(), io::Error>(())
            })
            .await
            .map_err(|_| (ErrorCode::Internal, "settings task failed".to_string()))?
            .map_err(|_| (ErrorCode::Internal, "cannot save settings".to_string()))?;
            to_value(&SettingsResult {
                vpn_auth_mode: settings.vpn_auth_mode,
            })
        }
        method::OWNED_LIST => {
            let owners = with_core(ctx, move |core| Ok(core.owned(uid))).await?;
            to_value(&OwnedListResult { owners })
        }
        method::ALWAYS_ON_LIST => {
            let document = with_store(ctx, move |store| store.load_uid(uid)).await?;
            to_value(&AlwaysOnListResult {
                profiles: document
                    .entries
                    .iter()
                    .map(|entry| AlwaysOnProfileInfo {
                        kind: entry.definition.kind(),
                        profile_id: entry.definition.profile_id().to_string(),
                        enabled: entry.enabled,
                    })
                    .collect(),
                paused: document.paused,
                supported_kinds: vec![AlwaysOnKind::WireGuard, AlwaysOnKind::StaticRoutes],
            })
        }
        method::ALWAYS_ON_SET => {
            if matches!(
                request.params["definition"]["kind"].as_str(),
                Some("openVpn" | "xrayTun")
            ) {
                return Err((
                    ErrorCode::UnsupportedMethod,
                    "always-on backend is not supported".into(),
                ));
            }
            let params: AlwaysOnSetParams = from_value(request.params)
                .map_err(|_| invalid("invalid always-on definition".into()))?;
            validate_definition(&params.definition)
                .map_err(|_| invalid("invalid always-on definition".into()))?;
            authorize(ctx, peer, Action::SystemNetwork).await?;
            let definition = params.definition;
            let for_store = definition.clone();
            let (stored, paused) = with_store(ctx, move |store| {
                let stored = store.insert(uid, for_store)?;
                Ok((stored, store.load_uid(uid)?.paused))
            })
            .await?;
            let active = if paused {
                false
            } else {
                let owner = definition.owner();
                let active = with_core(ctx, move |core| {
                    apply_definition(core, uid, &definition).map(|_| ())
                })
                .await
                .is_ok();
                if active {
                    notify(ctx, uid, owner);
                }
                active
            };
            to_value(&AlwaysOnSetResult { stored, active })
        }
        method::ALWAYS_ON_REMOVE => {
            let params: AlwaysOnRemoveParams = from_value(request.params)
                .map_err(|_| invalid("invalid always-on removal".into()))?;
            let owner = match params.kind {
                AlwaysOnKind::WireGuard => format!("wg:{}", params.profile_id),
                AlwaysOnKind::StaticRoutes => params.profile_id.clone(),
            };
            validate_owner(&owner).map_err(invalid)?;
            authorize(ctx, peer, Action::SystemNetwork).await?;
            let for_store = owner.clone();
            let found = with_store(ctx, move |store| store.disable(uid, &for_store)).await?;
            if !found {
                return to_value(&AlwaysOnRemoveResult {
                    removed: false,
                    disconnected: false,
                });
            }
            let for_core = owner.clone();
            let disconnected = with_core(ctx, move |core| {
                if !core.owned(uid).iter().any(|entry| entry.owner == for_core) {
                    return Ok(false);
                }
                match params.kind {
                    AlwaysOnKind::WireGuard => {
                        core.disconnect_wireguard(uid, &params.profile_id)?;
                    }
                    AlwaysOnKind::StaticRoutes => {
                        core.remove_owner(uid, &for_core)?;
                    }
                }
                Ok(true)
            })
            .await
            .map_err(|(code, _)| {
                (
                    code,
                    "owner cleanup failed; definition remains disabled".into(),
                )
            })?;
            let for_store = owner.clone();
            with_store(ctx, move |store| store.remove(uid, &for_store)).await?;
            if disconnected {
                notify(ctx, uid, owner);
            }
            to_value(&AlwaysOnRemoveResult {
                removed: true,
                disconnected,
            })
        }
        method::ALWAYS_ON_RESUME => {
            authorize(ctx, peer, Action::SystemNetwork).await?;
            let document = with_store(ctx, move |store| {
                store.resume(uid)?;
                store.load_uid(uid)
            })
            .await?;
            for entry in document.entries.into_iter().filter(|entry| entry.enabled) {
                let owner = entry.definition.owner();
                if with_core(ctx, move |core| {
                    apply_definition(core, uid, &entry.definition).map(|_| ())
                })
                .await
                .is_ok()
                {
                    notify(ctx, uid, owner);
                }
            }
            to_value(&AlwaysOnResumeResult { resumed: true })
        }
        method::WIREGUARD_CONNECT => {
            let params: WireGuardConnectParams = params(request.params)?;
            validate_owner(&params.profile_id).map_err(invalid)?;
            let mut plan = parse_wireguard_config(&params.config, &params.routes)
                .map_err(|err| invalid(err.to_string()))?;
            plan.interface_name = params.interface_name.clone();
            net_manager_core::models::validate_secondary(
                params.role,
                &params.routes,
                &params.dns_domains,
            )
            .map_err(|message| invalid(message.into()))?;
            if params.role == net_manager_core::models::TunnelRole::Secondary {
                if plan.full_ipv4 || plan.full_ipv6 {
                    return Err(invalid(
                        "A secondary connection cannot take all traffic".into(),
                    ));
                }
                // Names under the listed suffixes resolve through the
                // tunnel's own servers; the config's search domains are not
                // trusted to scope a secondary tunnel.
                plan.dns_domains = if plan.dns_servers.is_empty() {
                    Vec::new()
                } else {
                    params.dns_domains.clone()
                };
            }
            let broad = plan.full_ipv4 || plan.full_ipv6;
            authorize(ctx, peer, connect_action(ctx.vpn_auth_mode(), broad)).await?;
            let profile_id = params.profile_id.clone();
            let status = with_core(ctx, move |core| {
                core.connect_wireguard(uid, &params.profile_id, plan)
            })
            .await?;
            notify(ctx, uid, format!("wg:{profile_id}"));
            to_value(&WireGuardConnectResult { status })
        }
        method::WIREGUARD_DISCONNECT => {
            let params: WireGuardProfileParams = params(request.params)?;
            validate_owner(&params.profile_id).map_err(invalid)?;
            authorize(ctx, peer, Action::ConnectProfile).await?;
            let profile_id = params.profile_id.clone();
            let result = with_core(ctx, move |core| {
                core.disconnect_wireguard(uid, &params.profile_id)
            })
            .await;
            if !matches!(
                &result,
                Err((ErrorCode::NotFound | ErrorCode::InvalidParams, _))
            ) {
                notify(ctx, uid, format!("wg:{profile_id}"));
            }
            result?;
            to_value(&WireGuardDisconnectResult { stopped: true })
        }
        method::WIREGUARD_STATUS => {
            let params: WireGuardProfileParams = params(request.params)?;
            validate_owner(&params.profile_id).map_err(invalid)?;
            let status = with_core(ctx, move |core| {
                Ok(core.wireguard_status(uid, &params.profile_id))
            })
            .await?;
            to_value(&status)
        }
        method::OPENVPN_CONNECT => {
            let request: OpenVpnConnectRequest = from_value(request.params)
                .map_err(|_| invalid("invalid OpenVPN connect parameters".into()))?;
            let plan = prepare_openvpn(uid, request).map_err(|err| invalid(err.to_string()))?;
            // The server may push a full tunnel at any (re)connect.
            authorize(ctx, peer, connect_action(ctx.vpn_auth_mode(), true)).await?;
            let owner = format!("ovpn:{}", plan.profile_id);
            let status = with_core(ctx, move |core| core.connect_openvpn(uid, plan)).await?;
            notify(ctx, uid, owner);
            to_value(&OpenVpnConnectResult { status })
        }
        method::OPENVPN_PROBE => {
            let request: OpenVpnConnectRequest = from_value(request.params)
                .map_err(|_| invalid("invalid OpenVPN probe parameters".into()))?;
            if !request.profile.routes.is_empty() {
                return Err(invalid("OpenVPN probe cannot apply routes".into()));
            }
            let plan = prepare_openvpn(uid, request).map_err(|err| invalid(err.to_string()))?;
            authorize(ctx, peer, Action::ConnectProfile).await?;
            // The detached task completes cleanup even if the RPC client disconnects.
            let probe = tokio::spawn(run_openvpn_probe(
                ctx.core.clone(),
                uid,
                plan,
                Duration::from_secs(20),
            ))
            .await
            .map_err(|_| (ErrorCode::Internal, "OpenVPN probe task failed".into()))??;
            to_value(&probe)
        }
        method::OPENVPN_PLAN => {
            let request: OpenVpnConnectRequest = from_value(request.params)
                .map_err(|_| invalid("invalid OpenVPN plan parameters".into()))?;
            let plan = prepare_openvpn(uid, request).map_err(|err| invalid(err.to_string()))?;
            let result = with_core(ctx, move |core| core.plan_openvpn(uid, &plan)).await?;
            to_value(&result)
        }
        method::OPENVPN_DISCONNECT => {
            let params: OpenVpnProfileParams = params(request.params)?;
            validate_owner(&format!("ovpn:{}", params.profile_id)).map_err(invalid)?;
            authorize(ctx, peer, Action::ConnectProfile).await?;
            let owner = format!("ovpn:{}", params.profile_id);
            let result = with_core(ctx, move |core| {
                core.disconnect_openvpn(uid, &params.profile_id)
            })
            .await;
            if !matches!(
                &result,
                Err((ErrorCode::NotFound | ErrorCode::InvalidParams, _))
            ) {
                notify(ctx, uid, owner);
            }
            result?;
            to_value(&OpenVpnDisconnectResult { stopped: true })
        }
        method::OPENVPN_STATUS => {
            let params: OpenVpnProfileParams = params(request.params)?;
            validate_owner(&format!("ovpn:{}", params.profile_id)).map_err(invalid)?;
            let status = with_core(ctx, move |core| {
                Ok(core.openvpn_status(uid, &params.profile_id))
            })
            .await?;
            to_value(&status)
        }
        method::XRAY_CONNECT => {
            let params: XrayConnectParams = from_value(request.params)
                .map_err(|_| invalid("invalid Xray connect parameters".into()))?;
            prepare_xray(uid, params.clone(), 1)
                .map_err(|_| invalid("unsupported generated Xray TUN config".into()))?;
            net_manager_core::models::validate_secondary(
                params.role,
                &params.routes,
                &params.dns_domains,
            )
            .map_err(|message| invalid(message.into()))?;
            let broad = params
                .routes
                .iter()
                .any(|route| captures_all_traffic(route.destination));
            authorize(ctx, peer, connect_action(ctx.vpn_auth_mode(), broad)).await?;
            let owner = format!("xray:{}", params.profile_id);
            let status = with_core(ctx, move |core| core.connect_xray(uid, params)).await?;
            notify(ctx, uid, owner);
            to_value(&XrayConnectResult { status })
        }
        method::XRAY_DISCONNECT => {
            let params: XrayProfileParams = params(request.params)?;
            validate_owner(&format!("xray:{}", params.profile_id)).map_err(invalid)?;
            authorize(ctx, peer, Action::ConnectProfile).await?;
            let owner = format!("xray:{}", params.profile_id);
            let result = with_core(ctx, move |core| {
                core.disconnect_xray(uid, &params.profile_id)
            })
            .await;
            if !matches!(
                &result,
                Err((ErrorCode::NotFound | ErrorCode::InvalidParams, _))
            ) {
                notify(ctx, uid, owner);
            }
            result?;
            to_value(&XrayDisconnectResult { stopped: true })
        }
        method::XRAY_STATUS => {
            let params: XrayProfileParams = params(request.params)?;
            validate_owner(&format!("xray:{}", params.profile_id)).map_err(invalid)?;
            let status = with_core(ctx, move |core| {
                Ok(core.xray_status(uid, &params.profile_id))
            })
            .await?;
            to_value(&status)
        }
        method::XRAY_PROXY_EXITS => {
            let params: XrayProfileParams = params(request.params)?;
            validate_owner(&format!("xray:{}", params.profile_id)).map_err(invalid)?;
            let exits = with_core(ctx, move |core| {
                core.xray_proxy_exits(uid, &params.profile_id)
            })
            .await?;
            to_value(&exits)
        }
        method::XRAY_SERVICE_CHECKS => {
            let params: net_manager_core::daemon_protocol::XrayServiceChecksParams =
                from_value(request.params)
                    .map_err(|_| invalid("invalid service check parameters".into()))?;
            validate_owner(&format!("xray:{}", params.profile_id)).map_err(invalid)?;
            let result = with_core(ctx, move |core| {
                core.set_xray_service_checks(uid, &params.profile_id, params.checks)
            })
            .await?;
            to_value(&result)
        }
        method::XRAY_RELOAD => {
            let params: XrayConnectParams = from_value(request.params)
                .map_err(|_| invalid("invalid Xray reload parameters".into()))?;
            prepare_xray(uid, params.clone(), 1)
                .map_err(|_| invalid("unsupported generated Xray TUN config".into()))?;
            net_manager_core::models::validate_secondary(
                params.role,
                &params.routes,
                &params.dns_domains,
            )
            .map_err(|message| invalid(message.into()))?;
            let broad = params
                .routes
                .iter()
                .any(|route| captures_all_traffic(route.destination));
            authorize(ctx, peer, connect_action(ctx.vpn_auth_mode(), broad)).await?;
            let owner = format!("xray:{}", params.profile_id);
            let status = with_core(ctx, move |core| core.reload_xray(uid, params)).await?;
            notify(ctx, uid, owner);
            to_value(&XrayConnectResult { status })
        }
        #[cfg(target_os = "linux")]
        method::XRAY_INSTALL => {
            let params: XrayInstallParams = params(request.params)?;
            let archive =
                decode_xray_archive(&params.archive_b64).map_err(|err| invalid(err.to_string()))?;
            authorize(ctx, peer, Action::SystemNetwork).await?;
            let root = ctx.xray_package_root.clone();
            let installation = tokio::task::spawn_blocking(move || {
                crate::xray_process::install_managed_package_at(&root, &archive)
            })
            .await
            .map_err(|_| (ErrorCode::Internal, "Xray install task failed".into()))?
            .map_err(|err| {
                (
                    error_code(&err),
                    format!("managed Xray install failed: {err}"),
                )
            })?;
            to_value(&XrayInstallResult {
                version: installation
                    .version_dir
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                created: installation.created,
            })
        }
        #[cfg(target_os = "linux")]
        method::XRAY_REMOVE => {
            authorize(ctx, peer, Action::SystemNetwork).await?;
            let root = ctx.xray_package_root.clone();
            let removed = tokio::task::spawn_blocking(move || {
                crate::xray_process::remove_managed_package_at(&root)
            })
            .await
            .map_err(|_| (ErrorCode::Internal, "Xray remove task failed".into()))?
            .map_err(|err| (error_code(&err), err.to_string()))?;
            to_value(&XrayRemoveResult { removed })
        }
        method::TAILSCALE_STATUS => {
            // tailscaled is a foreign daemon — a read-only status proxy with
            // nothing journaled, so no authorization is required.
            let status = crate::tailscale::status(&crate::tailscale::socket_path())
                .map_err(|_| (ErrorCode::Internal, "tailscaled status failed".into()))?;
            to_value(&status)
        }
        method::TAILSCALE_UP | method::TAILSCALE_DOWN => {
            authorize(ctx, peer, Action::ConnectProfile).await?;
            let want_running = request.method == method::TAILSCALE_UP;
            crate::tailscale::set_running(&crate::tailscale::socket_path(), want_running).map_err(
                |err| match err.kind() {
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
                        (ErrorCode::NotFound, "tailscaled is not available".into())
                    }
                    _ => (ErrorCode::Internal, "tailscaled request failed".into()),
                },
            )?;
            let status = crate::tailscale::status(&crate::tailscale::socket_path())
                .map_err(|_| (ErrorCode::Internal, "tailscaled status failed".into()))?;
            notify(ctx, uid, "tailscale".to_string());
            to_value(&status)
        }
        method::ROUTES_APPLY => {
            let params: RoutesApplyParams = params(request.params)?;
            validate_owner(&params.owner).map_err(invalid)?;
            reject_wireguard_owner(&params.owner)?;
            validate_apply(&params.routes).map_err(invalid)?;
            if let Some(spec) = &params.attach {
                validate_attach(spec).map_err(invalid)?;
            }
            authorize(ctx, peer, Action::SystemNetwork).await?;
            let owner = params.owner.clone();
            let applied = with_core(ctx, move |core| match params.attach {
                Some(spec) => core.apply_attach(uid, &params.owner, spec, params.routes),
                None => core.apply_routes(uid, &params.owner, params.routes),
            })
            .await?;
            notify(ctx, uid, owner);
            to_value(&RoutesApplyResult { applied })
        }
        method::ROUTES_REMOVE => {
            let params: OwnerParams = params(request.params)?;
            validate_owner(&params.owner).map_err(invalid)?;
            reject_wireguard_owner(&params.owner)?;
            authorize(ctx, peer, Action::ConnectProfile).await?;
            let owner = params.owner.clone();
            let result = with_core(ctx, move |core| core.remove_owner(uid, &params.owner)).await;
            // A partial failure still changed the owner (now `stale`).
            if !matches!(
                &result,
                Err((ErrorCode::NotFound | ErrorCode::InvalidParams, _))
            ) {
                notify(ctx, uid, owner);
            }
            to_value(&RoutesRemoveResult { removed: result? })
        }
        #[cfg(target_os = "linux")]
        method::COND_RULES_LIST => {
            let rules = with_cond_store(ctx, move |store| {
                store.load_uid(uid).map(|document| document.rules)
            })
            .await?;
            let entries = with_core(ctx, move |core| {
                Ok(rules
                    .into_iter()
                    .map(|rule| ConditionalRuleEntry {
                        status: core.cond_rule_status(uid, &rule),
                        rule,
                    })
                    .collect())
            })
            .await?;
            to_value(&CondRulesListResult { rules: entries })
        }
        #[cfg(target_os = "linux")]
        method::COND_RULES_PUT => {
            let params: CondRulesPutParams = params(request.params)?;
            validate_rule(&params.rule).map_err(|err| invalid(err.to_string()))?;
            authorize(ctx, peer, Action::SystemNetwork).await?;
            let rule = params.rule;
            let for_store = rule.clone();
            let stored = with_cond_store(ctx, move |store| store.upsert(uid, for_store)).await?;
            eval_conditional(ctx).await;
            let status = with_core(ctx, move |core| Ok(core.cond_rule_status(uid, &rule))).await?;
            to_value(&CondRulesPutResult { stored, status })
        }
        #[cfg(target_os = "linux")]
        method::COND_RULES_REMOVE => {
            let params: CondRulesRemoveParams = params(request.params)?;
            authorize(ctx, peer, Action::SystemNetwork).await?;
            let removed =
                with_cond_store(ctx, move |store| store.remove(uid, &params.rule_id)).await?;
            // Orphan cleanup inside evaluation withdraws the rule's routes.
            eval_conditional(ctx).await;
            to_value(&CondRulesRemoveResult { removed })
        }
        #[cfg(target_os = "linux")]
        method::NM_LIST => match crate::nm::list_connections().await {
            Ok(connections) => to_value(&NmListResult {
                connections,
                available: true,
            }),
            Err(err) if err.kind() == io::ErrorKind::NotConnected => to_value(&NmListResult {
                connections: Vec::new(),
                available: false,
            }),
            Err(err) => Err((ErrorCode::Internal, err.to_string())),
        },
        #[cfg(target_os = "linux")]
        method::NM_SET_ACTIVE => {
            let params: NmSetActiveParams = params(request.params)?;
            authorize(ctx, peer, Action::ConnectProfile).await?;
            crate::nm::set_active(&params.uuid, params.active)
                .await
                .map_err(|err| match err.kind() {
                    io::ErrorKind::NotFound => (ErrorCode::NotFound, err.to_string()),
                    io::ErrorKind::NotConnected => (
                        ErrorCode::NotFound,
                        "NetworkManager is not available".into(),
                    ),
                    _ => (ErrorCode::Internal, err.to_string()),
                })?;
            Ok(Value::Null)
        }
        #[cfg(target_os = "linux")]
        method::NET_TABLES => {
            let result = with_core(ctx, move |core| core.net_tables()).await?;
            to_value(&result)
        }
        #[cfg(target_os = "linux")]
        method::NET_ROUTE_ADD => {
            let params: NetRouteAddParams = params(request.params)?;
            authorize(ctx, peer, Action::SystemNetwork).await?;
            with_core(ctx, move |core| core.net_route_add(uid, params)).await?;
            notify(ctx, uid, "manual".to_string());
            Ok(Value::Null)
        }
        #[cfg(target_os = "linux")]
        method::NET_ROUTE_DEL => {
            let params: NetRouteDelParams = params(request.params)?;
            authorize(ctx, peer, Action::SystemNetwork).await?;
            let outcome = with_core(ctx, move |core| core.net_route_del(uid, params.route)).await?;
            notify(ctx, uid, "manual".to_string());
            to_value(&NetEditResult { outcome })
        }
        #[cfg(target_os = "linux")]
        method::NET_RULE_ADD => {
            let params: NetRuleAddParams = params(request.params)?;
            authorize(ctx, peer, Action::SystemNetwork).await?;
            with_core(ctx, move |core| core.net_rule_add(uid, params)).await?;
            notify(ctx, uid, "manual".to_string());
            Ok(Value::Null)
        }
        #[cfg(target_os = "linux")]
        method::NET_RULE_DEL => {
            let params: NetRuleDelParams = params(request.params)?;
            authorize(ctx, peer, Action::SystemNetwork).await?;
            let outcome = with_core(ctx, move |core| core.net_rule_del(uid, params.rule)).await?;
            notify(ctx, uid, "manual".to_string());
            to_value(&NetEditResult { outcome })
        }
        #[cfg(target_os = "linux")]
        method::NET_EXPLAIN => {
            let result = with_core(ctx, move |core| core.net_explain(uid)).await?;
            to_value(&result)
        }
        #[cfg(target_os = "linux")]
        method::NET_DNS_STATUS => crate::dns_status::status()
            .await
            .map_err(|_| (ErrorCode::Internal, "DNS status failed".into()))
            .and_then(|result| to_value(&result)),
        #[cfg(target_os = "linux")]
        method::NET_DNS_PROBE => {
            let params: NetDnsProbeParams = params(request.params)?;
            let observer = ctx.observer.clone();
            let result = crate::dns_status::probe(observer, params)
                .await
                .map_err(|error| (error_code(&error), error.to_string()))?;
            to_value(&result)
        }
        #[cfg(target_os = "linux")]
        method::NET_INTENT_LIST => {
            let result = with_core(ctx, move |core| core.net_intent_list(uid)).await?;
            to_value(&result)
        }
        #[cfg(target_os = "linux")]
        method::NET_INTENT_SET => {
            let params: NetIntentSetParams = params(request.params)?;
            authorize(ctx, peer, Action::SystemNetwork).await?;
            let owner = format!("intent:{}", params.id);
            let result = with_core(ctx, move |core| core.net_intent_set(uid, params)).await?;
            notify(ctx, uid, owner);
            to_value(&result)
        }
        #[cfg(target_os = "linux")]
        method::NET_INTENT_DEL => {
            let params: NetIntentDelParams = params(request.params)?;
            authorize(ctx, peer, Action::SystemNetwork).await?;
            let owner = format!("intent:{}", params.id);
            let id = params.id.clone();
            with_core(ctx, move |core| core.net_intent_del(uid, &params.id)).await?;
            notify(ctx, uid, owner);
            to_value(&NetIntentResult { id })
        }
        method::LINK_SET_STATE => {
            let params: LinkSetStateParams = params(request.params)?;
            validate_iface_name(&params.name).map_err(invalid)?;
            authorize(ctx, peer, Action::SystemNetwork).await?;
            with_core(ctx, move |core| {
                core.set_link_state(&params.name, params.up)
            })
            .await?;
            Ok(Value::Null)
        }
        method::EXTERNAL_TUNNEL_STOP => {
            let params: ExternalTunnelStopParams = params(request.params)?;
            validate_iface_name(&params.name).map_err(invalid)?;
            authorize(ctx, peer, Action::SystemNetwork).await?;
            with_core(ctx, move |core| core.stop_external_link(&params.name)).await?;
            Ok(Value::Null)
        }
        method::RECOVERY_CLEANUP => {
            let action = if ctx.always_on.is_some()
                && with_store(ctx, move |store| {
                    Ok(store
                        .load_uid(uid)?
                        .entries
                        .iter()
                        .any(|entry| entry.enabled))
                })
                .await?
            {
                Action::SystemNetwork
            } else {
                Action::ConnectProfile
            };
            authorize(ctx, peer, action).await?;
            if ctx.always_on.is_some() {
                with_store(ctx, move |store| store.pause(uid)).await?;
            }
            let result = with_core(ctx, move |core| core.cleanup_uid(uid)).await?;
            for owner in result.removed_owners.iter().chain(&result.failed) {
                notify(ctx, uid, owner.clone());
            }
            to_value(&result)
        }
        _ => Err((
            ErrorCode::UnsupportedMethod,
            format!("unsupported method '{}'", request.method),
        )),
    }
}

/// A default route or one of its halves: the tunnel takes all traffic.
fn captures_all_traffic(destination: ipnet::IpNet) -> bool {
    matches!(
        destination.to_string().as_str(),
        "0.0.0.0/0" | "0.0.0.0/1" | "128.0.0.0/1" | "::/0" | "::/1" | "8000::/1"
    )
}

async fn authorize<A: Authorizer>(
    ctx: &ServerContext<A>,
    peer: &PeerIdentity,
    action: Action,
) -> Result<(), Failure> {
    match ctx.authorizer.check(peer, action).await {
        Ok(AuthDecision::Authorized) => Ok(()),
        Ok(AuthDecision::Denied) => Err((
            ErrorCode::NotAuthorized,
            format!(
                "polkit denied {}; a polkit authentication agent must be running in your session",
                action.polkit_id()
            ),
        )),
        Ok(AuthDecision::Dismissed) => Err((
            ErrorCode::AuthorizationDismissed,
            "authorization dialog was dismissed; nothing was applied".into(),
        )),
        Err(err) => Err((ErrorCode::Unavailable, err.to_string())),
    }
}

/// Run `f` on the core off the async workers: netlink calls block.
async fn with_core<A, T, F>(ctx: &ServerContext<A>, f: F) -> Result<T, Failure>
where
    T: Send + 'static,
    F: FnOnce(&mut DaemonCore) -> io::Result<T> + Send + 'static,
{
    with_core_shared(&ctx.core, f).await
}

async fn with_core_shared<T, F>(core: &Arc<Mutex<DaemonCore>>, f: F) -> Result<T, Failure>
where
    T: Send + 'static,
    F: FnOnce(&mut DaemonCore) -> io::Result<T> + Send + 'static,
{
    let core = core.clone();
    tokio::task::spawn_blocking(move || {
        let mut core = core.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        f(&mut core)
    })
    .await
    .map_err(|err| (ErrorCode::Internal, err.to_string()))?
    .map_err(|err| (error_code(&err), err.to_string()))
}

async fn run_openvpn_probe(
    core: Arc<Mutex<DaemonCore>>,
    uid: u32,
    plan: OpenVpnPlan,
    timeout: Duration,
) -> Result<OpenVpnProbeResult, Failure> {
    let profile_id = plan.profile_id.clone();
    with_core_shared(&core, move |core| core.start_openvpn_probe(uid, plan)).await?;
    let deadline = Instant::now() + timeout;
    let outcome = loop {
        let profile = profile_id.clone();
        match with_core_shared(&core, move |core| core.poll_openvpn_probe(uid, &profile)).await {
            Ok(Some(result)) => break Ok(result),
            Ok(None) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok(None) => {
                break Err((
                    ErrorCode::Unavailable,
                    "OpenVPN probe timed out waiting for pushed routes".into(),
                ))
            }
            Err(error) => break Err(error),
        }
    };
    // A cleanup error takes precedence over probe data: never report routes
    // while a privileged child or link may still exist.
    with_core_shared(&core, move |core| {
        core.finish_openvpn_probe(uid, &profile_id)
    })
    .await?;
    outcome
}

async fn with_store<A, T, F>(ctx: &ServerContext<A>, f: F) -> Result<T, Failure>
where
    T: Send + 'static,
    F: FnOnce(&AlwaysOnStore) -> io::Result<T> + Send + 'static,
{
    let store = ctx.always_on.clone().ok_or((
        ErrorCode::Unavailable,
        "always-on store is unavailable".into(),
    ))?;
    tokio::task::spawn_blocking(move || {
        let store = store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        f(&store)
    })
    .await
    .map_err(|_| {
        (
            ErrorCode::Internal,
            "always-on store operation failed".into(),
        )
    })?
    .map_err(|err| (error_code(&err), "always-on store operation failed".into()))
}

#[cfg(target_os = "linux")]
async fn with_cond_store<A, T, F>(ctx: &ServerContext<A>, f: F) -> Result<T, Failure>
where
    T: Send + 'static,
    F: FnOnce(&CondRuleStore) -> io::Result<T> + Send + 'static,
{
    let store = ctx.cond_rules.clone().ok_or((
        ErrorCode::Unavailable,
        "conditional rule store is unavailable".into(),
    ))?;
    tokio::task::spawn_blocking(move || f(&store))
        .await
        .map_err(|_| {
            (
                ErrorCode::Internal,
                "conditional rule operation failed".into(),
            )
        })?
        .map_err(|err| (error_code(&err), "conditional rule operation failed".into()))
}

/// Re-evaluate all stored conditional rules against live kernel state and
/// notify the uids whose owners changed. Shared by the `condRules.*`
/// handlers and the network-change reconcile loop; a store or observer
/// failure is logged, never fatal.
#[cfg(target_os = "linux")]
pub async fn eval_conditional<A: Authorizer>(ctx: &ServerContext<A>) {
    let Some(store) = ctx.cond_rules.clone() else {
        return;
    };
    let observer = ctx.observer.clone();
    let core = ctx.core.clone();
    let changed = tokio::task::spawn_blocking(move || -> io::Result<Vec<(u32, String)>> {
        let rules = store.load_all_rules()?;
        let addrs = observer.interface_addrs()?;
        let observed = observer.owned_routes()?;
        let mut core = core.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(core.reconcile_conditional(&addrs, &observed, &rules))
    })
    .await;
    match changed {
        Ok(Ok(changed)) => {
            for (uid, owner) in changed {
                notify(ctx, uid, owner);
            }
        }
        Ok(Err(err)) => {
            eprintln!("network-orchestrator-daemon: conditional rule evaluation failed: {err}")
        }
        Err(err) => {
            eprintln!("network-orchestrator-daemon: conditional rule evaluation task failed: {err}")
        }
    }
}

fn error_code(err: &io::Error) -> ErrorCode {
    match err.kind() {
        io::ErrorKind::InvalidInput => ErrorCode::InvalidParams,
        io::ErrorKind::AlreadyExists => ErrorCode::Conflict,
        io::ErrorKind::NotFound => ErrorCode::NotFound,
        io::ErrorKind::NotConnected | io::ErrorKind::BrokenPipe => ErrorCode::Unavailable,
        _ => ErrorCode::Internal,
    }
}

fn notify<A>(ctx: &ServerContext<A>, uid: u32, owner: String) {
    // No subscribers is not an error.
    let _ = ctx.events.send(OwnerEvent { uid, owner });
}

fn params<T: DeserializeOwned>(value: Value) -> Result<T, Failure> {
    from_value(value).map_err(|err| (ErrorCode::InvalidParams, err.to_string()))
}

fn invalid(message: String) -> Failure {
    (ErrorCode::InvalidParams, message)
}

/// Decode the base64 release archive for `xray.install`. Bounded by the
/// pinned archive limit so decoding stops before a maximal frame could
/// expand further.
#[cfg(target_os = "linux")]
fn decode_xray_archive(archive_b64: &str) -> io::Result<Vec<u8>> {
    use base64::Engine;
    const MAX_B64_LEN: usize = (net_manager_core::managed_xray::MAX_XRAY_ARCHIVE_BYTES / 3 + 1) * 4;
    if archive_b64.len() > MAX_B64_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed Xray archive exceeds the size limit",
        ));
    }
    base64::engine::general_purpose::STANDARD
        .decode(archive_b64)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "malformed base64 archive"))
}

/// Whether the daemon could execute each trusted tool binary right now —
/// the same checks the connect paths apply, so this cannot disagree with
/// a real connect attempt.
#[cfg(target_os = "linux")]
fn default_tool_presence() -> std::collections::BTreeMap<String, bool> {
    std::collections::BTreeMap::from([
        (
            net_manager_core::daemon_protocol::tool::WIREGUARD.to_string(),
            crate::core::trusted_wg_binary().is_ok(),
        ),
        (
            net_manager_core::daemon_protocol::tool::OPENVPN.to_string(),
            crate::openvpn_process::trusted_binary().is_ok(),
        ),
    ])
}

fn reject_wireguard_owner(owner: &str) -> Result<(), Failure> {
    if owner.starts_with("wg:")
        || owner.starts_with("ovpn:")
        || owner.starts_with("ovpn-probe:")
        || owner.starts_with("xray:")
    {
        Err(invalid("reserved tunnel owner prefix".into()))
    } else {
        Ok(())
    }
}

fn to_value<T: Serialize>(value: &T) -> Result<Value, Failure> {
    serde_json::to_value(value).map_err(|err| (ErrorCode::Internal, err.to_string()))
}

fn ok<T: Serialize>(id: u64, value: &T) -> ResponseFrame {
    match serde_json::to_value(value) {
        Ok(value) => ResponseFrame::ok(id, value),
        Err(err) => ResponseFrame::error(id, ErrorCode::Internal, err.to_string()),
    }
}

async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
    write: &mut W,
    frame: &T,
) -> io::Result<()> {
    write.write_all(&encode_line(frame)?).await?;
    write.flush().await
}

#[cfg(target_os = "linux")]
pub use listener::{bind_socket, serve};

#[cfg(target_os = "linux")]
mod listener {
    use super::{serve_accepted, ServerContext};
    use crate::auth::Authorizer;
    use std::fs;
    use std::io;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::UnixListener;

    /// Bind `path`, replacing a stale socket (never any other file), and make
    /// it 0666 regardless of the umask: access control is polkit's job.
    pub fn bind_socket(path: &Path) -> io::Result<UnixListener> {
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_socket() => fs::remove_file(path)?,
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("refusing to replace non-socket {}", path.display()),
                ))
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o666))?;
        Ok(listener)
    }

    /// Accept forever; each connection is identified via `SO_PEERCRED`
    /// before a single byte is read from it.
    pub async fn serve<A: Authorizer>(listener: UnixListener, ctx: Arc<ServerContext<A>>) {
        loop {
            let stream = match listener.accept().await {
                Ok((stream, _)) => stream,
                Err(err) => {
                    eprintln!("network-orchestrator-daemon: accept failed: {err}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            match crate::peer::identify(&stream) {
                Ok(peer) => {
                    tokio::spawn(serve_accepted(stream, peer, ctx.clone()));
                }
                Err(err) => eprintln!("network-orchestrator-daemon: unidentified peer: {err}"),
            }
        }
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{Action, AuthDecision, Authorizer, PeerIdentity};
    use crate::core::testing::{FakeLinks, FakeRoutes, Recorder};
    use crate::core::{DaemonCore, WgConfigExecutor, WgSystem};
    use crate::openvpn_process::OpenVpnProcessRunner;
    use net_manager_core::daemon_protocol::VpnAuthMode;
    use net_manager_core::daemon_protocol::MAX_FRAME_BYTES;
    use net_manager_core::journal::{JournalStore, JOURNAL_FILE};
    use net_manager_core::openvpn_management::{parse_push_reply, ManagementEvent};
    use serde_json::{json, Value};
    use std::collections::VecDeque;
    use std::io;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, ReadHalf, WriteHalf};

    static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    struct FakeWireGuard;

    impl WgSystem for FakeWireGuard {
        fn create_link(&mut self, _name: &str, _owner_marker: &str) -> io::Result<u32> {
            Ok(42)
        }
        fn link_owned(
            &mut self,
            _name: &str,
            _index: u32,
            _owner_marker: &str,
        ) -> io::Result<bool> {
            Ok(true)
        }
        fn delete_link(&mut self, _name: &str, _index: u32, _owner_marker: &str) -> io::Result<()> {
            Ok(())
        }
        fn add_address(&mut self, _index: u32, _address: ipnet::IpNet) -> io::Result<()> {
            Ok(())
        }
        fn remove_address(&mut self, _index: u32, _address: ipnet::IpNet) -> io::Result<()> {
            Ok(())
        }
        fn set_mtu(&mut self, _index: u32, _mtu: u32) -> io::Result<()> {
            Ok(())
        }
        fn set_state(&mut self, _index: u32, _up: bool) -> io::Result<()> {
            Ok(())
        }
    }

    struct FakeWireGuardConfig;

    impl WgConfigExecutor for FakeWireGuardConfig {
        fn configure(&mut self, _name: &str, _config: &str) -> io::Result<()> {
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct FakeProbeRunner {
        started: Arc<AtomicUsize>,
        stopped: Arc<AtomicUsize>,
        cleaned: Arc<AtomicUsize>,
        pending: Arc<Mutex<VecDeque<Vec<ManagementEvent>>>>,
    }

    impl OpenVpnProcessRunner for FakeProbeRunner {
        fn verify_binary(&self) -> io::Result<()> {
            Ok(())
        }

        fn link_index(&self, _name: &str) -> io::Result<Option<u32>> {
            Ok(None)
        }

        fn staging_exists(&self, _uid: u32, _name: &str) -> io::Result<bool> {
            Ok(false)
        }

        fn start(
            &mut self,
            _uid: u32,
            _name: &str,
            _config: &net_manager_core::openvpn_config::SanitizedOpenVpnConfig,
            _credentials: Option<net_manager_core::daemon_protocol::OpenVpnCredentials>,
            _mark: u32,
        ) -> io::Result<()> {
            self.started.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn poll(&mut self, _name: &str) -> io::Result<Vec<ManagementEvent>> {
            Ok(self.pending.lock().unwrap().pop_front().unwrap_or_default())
        }

        fn stop(&mut self, _name: &str) -> io::Result<()> {
            self.stopped.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn cleanup(&mut self, _uid: u32, _name: &str) -> io::Result<()> {
            self.cleaned.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct FakeAuthorizer {
        decision: AuthDecision,
        calls: AtomicUsize,
        actions: Mutex<Vec<Action>>,
    }

    impl Authorizer for FakeAuthorizer {
        async fn check(&self, _peer: &PeerIdentity, action: Action) -> io::Result<AuthDecision> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.actions.lock().unwrap().push(action);
            Ok(self.decision)
        }
    }

    struct Harness {
        ctx: Arc<ServerContext<FakeAuthorizer>>,
        recorder: Recorder,
        dir: PathBuf,
    }

    impl Harness {
        fn new(decision: AuthDecision) -> Self {
            Self::with(decision, |_| {})
        }

        fn with(
            decision: AuthDecision,
            tune: impl FnOnce(&mut ServerContext<FakeAuthorizer>),
        ) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "netmgr-daemon-server-{}-{}",
                std::process::id(),
                DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let recorder = Recorder::default();
            let core = DaemonCore::open_with_wireguard(
                JournalStore::new(dir.join(JOURNAL_FILE)),
                Box::new(FakeRoutes::new(&recorder)),
                Box::new(FakeLinks(recorder.clone())),
                Box::new(FakeWireGuard),
                Box::new(FakeWireGuardConfig),
            )
            .unwrap();
            let mut ctx = ServerContext::new(
                core,
                FakeAuthorizer {
                    decision,
                    calls: AtomicUsize::new(0),
                    actions: Mutex::new(Vec::new()),
                },
            );
            tune(&mut ctx);
            Self {
                ctx: Arc::new(ctx),
                recorder,
                dir,
            }
        }

        fn connect(&self, uid: u32) -> Client {
            let (client, server) = tokio::io::duplex(64 * 1024);
            let peer = PeerIdentity {
                uid,
                pid: 4242,
                start_time: Some(1),
                pidfd: None,
            };
            tokio::spawn(serve_accepted(server, peer, self.ctx.clone()));
            let (read, write) = tokio::io::split(client);
            Client {
                reader: BufReader::new(read),
                writer: write,
            }
        }

        async fn hello(&self, uid: u32) -> Client {
            let mut client = self.connect(uid);
            client
                .send(json!({"id":1,"method":"hello","params":{"protocol":1,"client":"test"}}))
                .await;
            let reply = client.recv().await.unwrap();
            assert_eq!(reply["ok"], json!(true), "{reply}");
            client
        }

        fn auth_calls(&self) -> usize {
            self.ctx.authorizer.calls.load(Ordering::SeqCst)
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    struct Client {
        reader: BufReader<ReadHalf<DuplexStream>>,
        writer: WriteHalf<DuplexStream>,
    }

    impl Client {
        async fn send(&mut self, value: Value) {
            let mut line = serde_json::to_vec(&value).unwrap();
            line.push(b'\n');
            self.writer.write_all(&line).await.unwrap();
        }

        /// Next frame, or `None` once the daemon closed the connection.
        async fn recv(&mut self) -> Option<Value> {
            self.recv_within(Duration::from_secs(5))
                .await
                .expect("daemon did not answer in time")
        }

        async fn recv_within(&mut self, limit: Duration) -> Result<Option<Value>, ()> {
            let mut line = String::new();
            match tokio::time::timeout(limit, self.reader.read_line(&mut line)).await {
                Err(_) => Err(()),
                Ok(Ok(0)) | Ok(Err(_)) => Ok(None),
                Ok(Ok(_)) => Ok(Some(serde_json::from_str(&line).unwrap())),
            }
        }

        async fn call(&mut self, id: u64, method: &str, params: Value) -> Value {
            let mut frame = json!({"id": id, "method": method});
            if !params.is_null() {
                frame["params"] = params;
            }
            self.send(frame).await;
            let reply = self.recv().await.expect("connection closed");
            assert_eq!(reply["id"], json!(id), "{reply}");
            reply
        }
    }

    fn error_code(reply: &Value) -> &str {
        reply["error"]["code"].as_str().unwrap_or("<none>")
    }

    fn apply_params(owner: &str, dest: &str) -> Value {
        json!({"owner": owner, "routes": [{"destination": dest, "interfaceIndex": 2, "metric": 5}]})
    }

    fn wg_params(extra: &str) -> Value {
        const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        json!({
            "profileId": "home",
            "config": format!("[Interface]\nPrivateKey={KEY}\nAddress=10.77.0.2/32\n{extra}\n[Peer]\nPublicKey={KEY}\nEndpoint=192.0.2.1:51820\nAllowedIPs=10.77.0.0/24\n"),
            "routes": []
        })
    }

    fn wg_full_params() -> Value {
        const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        json!({
            "profileId": "home",
            "config": format!("[Interface]\nPrivateKey={KEY}\nAddress=10.77.0.2/32\n[Peer]\nPublicKey={KEY}\nEndpoint=192.0.2.1:51820\nAllowedIPs=0.0.0.0/0\n"),
            "routes": []
        })
    }

    #[cfg(target_os = "linux")]
    fn xray_package_root_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "netmgr-xray-pkg-{}-{name}-{}",
            std::process::id(),
            DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
        ))
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn xray_install_validates_archive_then_asks_an_administrator() {
        use base64::Engine;
        let package_root = xray_package_root_dir("denied");
        let harness = Harness::with(AuthDecision::Denied, |ctx| {
            ctx.xray_package_root = package_root;
        });
        let mut client = harness.hello(1000).await;
        let reply = client
            .call(2, method::XRAY_INSTALL, json!({"archiveB64": "!!!"}))
            .await;
        assert_eq!(error_code(&reply), "invalidParams");
        assert_eq!(harness.auth_calls(), 0);
        let reply = client
            .call(
                3,
                method::XRAY_INSTALL,
                json!({"archiveB64": base64::engine::general_purpose::STANDARD.encode(b"garbage")}),
            )
            .await;
        assert_eq!(error_code(&reply), "notAuthorized");
        assert_eq!(
            *harness.ctx.authorizer.actions.lock().unwrap(),
            [Action::SystemNetwork]
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[tokio::test]
    async fn xray_install_reports_hash_mismatch_and_remove_roundtrips() {
        use base64::Engine;
        let package_root = xray_package_root_dir("roundtrip");
        let harness = Harness::with(AuthDecision::Authorized, |ctx| {
            ctx.xray_package_root = package_root.clone();
        });
        let mut client = harness.hello(1000).await;
        let reply = client
            .call(
                2,
                method::XRAY_INSTALL,
                json!({"archiveB64": base64::engine::general_purpose::STANDARD.encode(b"garbage")}),
            )
            .await;
        assert_eq!(error_code(&reply), "internal");
        assert!(reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("sha-256"));
        let reply = client.call(3, method::XRAY_REMOVE, Value::Null).await;
        assert_eq!(reply["result"]["removed"], json!(false), "{reply}");
        std::fs::create_dir_all(
            package_root.join(net_manager_core::managed_xray::LINUX_XRAY_VERSION),
        )
        .unwrap();
        let reply = client.call(4, method::XRAY_REMOVE, Value::Null).await;
        assert_eq!(reply["result"]["removed"], json!(true), "{reply}");
        assert!(!package_root
            .join(net_manager_core::managed_xray::LINUX_XRAY_VERSION)
            .exists());
        std::fs::remove_dir_all(package_root).unwrap();
    }

    #[tokio::test]
    async fn settings_are_readable_by_anyone_and_changed_only_by_an_administrator() {
        let harness = Harness::new(AuthDecision::Authorized);
        let mut client = harness.hello(1000).await;
        let reply = client.call(2, method::SETTINGS_GET, Value::Null).await;
        assert_eq!(
            reply["result"]["vpnAuthMode"],
            json!("fullTunnelOnly"),
            "{reply}"
        );
        assert_eq!(harness.auth_calls(), 0);

        let reply = client
            .call(3, method::SETTINGS_SET, json!({"vpnAuthMode": "always"}))
            .await;
        assert_eq!(reply["ok"], json!(true), "{reply}");
        assert_eq!(
            *harness.ctx.authorizer.actions.lock().unwrap(),
            [Action::SystemNetwork]
        );
        let reply = client.call(4, method::SETTINGS_GET, Value::Null).await;
        assert_eq!(reply["result"]["vpnAuthMode"], json!("always"));

        let denied = Harness::new(AuthDecision::Denied);
        let mut client = denied.hello(1000).await;
        let reply = client
            .call(2, method::SETTINGS_SET, json!({"vpnAuthMode": "noPrompt"}))
            .await;
        assert_eq!(reply["error"]["code"], json!("notAuthorized"), "{reply}");
        let reply = client.call(3, method::SETTINGS_GET, Value::Null).await;
        assert_eq!(reply["result"]["vpnAuthMode"], json!("fullTunnelOnly"));
    }

    #[tokio::test]
    async fn concurrent_settings_updates_keep_disk_and_live_mode_in_sync() {
        let dir = std::env::temp_dir().join(format!(
            "netorch-concurrent-settings-{}-{}",
            std::process::id(),
            DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(crate::settings::SETTINGS_FILE);
        let store_path = path.clone();
        let harness = Harness::with(AuthDecision::Authorized, move |ctx| {
            ctx.settings_store = Some(Arc::new(SettingsStore::new(store_path)));
        });
        let mut clients = Vec::new();
        for uid in 1000..1032 {
            clients.push(harness.hello(uid).await);
        }
        let barrier = Arc::new(tokio::sync::Barrier::new(clients.len() + 1));
        let mut tasks = Vec::new();
        for (index, mut client) in clients.into_iter().enumerate() {
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                client
                    .call(
                        index as u64 + 2,
                        method::SETTINGS_SET,
                        json!({"vpnAuthMode": if index % 2 == 0 { "always" } else { "noPrompt" }}),
                    )
                    .await
            }));
        }
        barrier.wait().await;
        for task in tasks {
            let reply = task.await.unwrap();
            assert_eq!(reply["ok"], json!(true), "{reply}");
        }
        assert_eq!(
            SettingsStore::new(&path).load().vpn_auth_mode,
            harness.ctx.vpn_auth_mode()
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn wireguard_connect_asks_for_an_administrator_per_mode_and_scope() {
        let harness = Harness::new(AuthDecision::Denied);
        let mut client = harness.hello(1000).await;
        client
            .call(2, method::WIREGUARD_CONNECT, wg_params(""))
            .await;
        client
            .call(3, method::WIREGUARD_CONNECT, wg_full_params())
            .await;
        assert_eq!(
            *harness.ctx.authorizer.actions.lock().unwrap(),
            [Action::ConnectProfile, Action::ConnectProfileAdmin]
        );

        for (mode, expected) in [
            (
                VpnAuthMode::NoPrompt,
                [Action::ConnectProfile, Action::ConnectProfile],
            ),
            (
                VpnAuthMode::Always,
                [Action::ConnectProfileAdmin, Action::ConnectProfileAdmin],
            ),
        ] {
            let harness = Harness::with(AuthDecision::Denied, |ctx| {
                ctx.settings.lock().unwrap().vpn_auth_mode = mode;
            });
            let mut client = harness.hello(1000).await;
            client
                .call(2, method::WIREGUARD_CONNECT, wg_params(""))
                .await;
            client
                .call(3, method::WIREGUARD_CONNECT, wg_full_params())
                .await;
            assert_eq!(*harness.ctx.authorizer.actions.lock().unwrap(), expected);
        }
    }

    #[tokio::test]
    async fn secondary_wireguard_is_validated_before_authorization() {
        let harness = Harness::new(AuthDecision::Denied);
        let mut client = harness.hello(1000).await;

        // No networks to carry.
        let mut params = wg_params("");
        params["role"] = json!("secondary");
        let reply = client.call(2, method::WIREGUARD_CONNECT, params).await;
        assert_eq!(error_code(&reply), "invalidParams", "{reply}");

        // A secondary tunnel never takes the default route.
        let mut params = wg_full_params();
        params["role"] = json!("secondary");
        params["routes"] = json!([{ "destination": "0.0.0.0/0", "metric": 5 }]);
        let reply = client.call(3, method::WIREGUARD_CONNECT, params).await;
        assert_eq!(error_code(&reply), "invalidParams", "{reply}");

        // A bad split-DNS suffix.
        let mut params = wg_params("");
        params["role"] = json!("secondary");
        params["routes"] = json!([{ "destination": "10.77.0.0/24", "metric": 5 }]);
        params["dnsDomains"] = json!(["not a domain"]);
        let reply = client.call(4, method::WIREGUARD_CONNECT, params).await;
        assert_eq!(error_code(&reply), "invalidParams", "{reply}");

        assert!(harness.ctx.authorizer.actions.lock().unwrap().is_empty());

        // A valid secondary reaches authorization as a split (non-admin) connect.
        let mut params = wg_params("");
        params["role"] = json!("secondary");
        params["routes"] = json!([{ "destination": "10.77.0.0/24", "metric": 5 }]);
        client.call(5, method::WIREGUARD_CONNECT, params).await;
        assert_eq!(
            *harness.ctx.authorizer.actions.lock().unwrap(),
            [Action::ConnectProfile]
        );
    }

    #[tokio::test]
    async fn decomposed_full_tunnels_are_rejected_before_authorization() {
        let harness = Harness::new(AuthDecision::Authorized);
        let mut client = harness.hello(1000).await;
        let mut wireguard = wg_params("");
        wireguard["config"] = json!(wireguard["config"].as_str().unwrap().replace(
            "AllowedIPs=10.77.0.0/24",
            "AllowedIPs=0.0.0.0/2,64.0.0.0/2,128.0.0.0/2,192.0.0.0/2"
        ));
        let reply = client.call(2, method::WIREGUARD_CONNECT, wireguard).await;
        assert_eq!(error_code(&reply), "invalidParams", "{reply}");

        let config = net_manager_core::xray::generate_share_link_config(
            "vless://11111111-2222-3333-4444-555555555555@node.test:443?type=raw&security=none",
            10808,
        )
        .unwrap();
        let routes: Vec<_> = ["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2"]
            .into_iter()
            .map(|destination| json!({"destination": destination, "metric": 5}))
            .collect();
        let reply = client
            .call(
                3,
                method::XRAY_CONNECT,
                json!({"profileId":"home","config":config.to_string(),"routes":routes}),
            )
            .await;
        assert_eq!(error_code(&reply), "invalidParams", "{reply}");
        assert_eq!(harness.auth_calls(), 0);
    }

    #[tokio::test]
    async fn xray_rejects_custom_root_config_before_authorization_without_echoing_secrets() {
        let harness = Harness::new(AuthDecision::Authorized);
        let mut client = harness.hello(1000).await;
        for config in [
            r#"{"log":{"access":"/tmp/SECRET-LOG"},"outbounds":[]}"#,
            r#"{"inbounds":[{"protocol":"dokodemo-door","listen":"0.0.0.0","port":1}],"outbounds":[]}"#,
            r#"{"outbounds":[{"protocol":"freedom","settings":{"redirect":"SECRET-TARGET"}}]}"#,
        ] {
            let reply = client
                .call(
                    2,
                    method::XRAY_CONNECT,
                    json!({"profileId":"home","config":config}),
                )
                .await;
            assert_eq!(error_code(&reply), "invalidParams", "{reply}");
            assert!(!reply.to_string().contains("SECRET-"));
        }
        assert_eq!(harness.auth_calls(), 0);
        assert!(harness.recorder.ops().is_empty());
    }

    #[tokio::test]
    async fn xray_status_is_scoped_to_peer_uid() {
        let harness = Harness::new(AuthDecision::Authorized);
        let mut client = harness.hello(1001).await;
        let reply = client
            .call(2, method::XRAY_STATUS, json!({"profileId":"home"}))
            .await;
        assert_eq!(reply["result"]["state"], "stopped");
        assert!(reply["result"]["interfaceName"].is_null());
        assert_eq!(harness.auth_calls(), 0);
    }

    #[tokio::test]
    async fn tailscale_status_and_control_proxy_the_localapi() {
        use std::io::{Read as _, Write as _};
        use std::os::unix::net::UnixListener;

        let status_json = r#"{
            "BackendState": "Running",
            "CurrentTailnet": "tailnet-test.ts.net",
            "MagicDNSSuffix": "tailnet-test.ts.net",
            "Self": {"HostName": "fedora", "TailscaleIPs": ["100.78.82.81"]},
            "Peer": {
                "nodekey:peer1": {
                    "HostName": "kzn1", "Online": true,
                    "TailscaleIPs": ["100.99.99.99"],
                    "AllowedIPs": ["100.99.99.99/32", "192.168.30.0/24"]
                }
            }
        }"#;

        // A fake `tailscaled`: every accepted connection gets one request, the
        // raw request is reported over the channel, and it is answered with
        // `{}` for PATCH or the status fixture for anything else.
        let dir = std::env::temp_dir().join(format!("netmgr-ts-srv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("tailscaled.sock");
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).unwrap();
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            while let Ok((mut conn, _)) = listener.accept() {
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match conn.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }
                let request = String::from_utf8_lossy(&request).into_owned();
                let _ = tx.send(request.clone());
                let body = if request.starts_with("PATCH") {
                    "{}".to_string()
                } else {
                    status_json.to_string()
                };
                let _ = conn.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .as_bytes(),
                );
            }
        });
        // The override only affects this test process.
        std::env::set_var(crate::tailscale::SOCKET_ENV, sock.to_str().unwrap());

        let harness = Harness::new(AuthDecision::Authorized);
        let mut client = harness.hello(1000).await;

        // Status is a read: the LocalAPI payload is mapped without any polkit.
        let reply = client.call(2, method::TAILSCALE_STATUS, json!({})).await;
        assert_eq!(reply["result"]["available"], true);
        assert_eq!(reply["result"]["backendState"], "Running");
        assert_eq!(reply["result"]["tailnet"], "tailnet-test.ts.net");
        assert_eq!(reply["result"]["selfIps"][0], "100.78.82.81");
        assert_eq!(reply["result"]["peers"][0]["routes"][0], "192.168.30.0/24");
        assert_eq!(harness.auth_calls(), 0);
        assert!(rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap()
            .starts_with("GET /localapi/v0/status"));

        // Down authorizes like a tunnel action and patches WantRunning off.
        let reply = client.call(3, method::TAILSCALE_DOWN, json!({})).await;
        assert_eq!(reply["result"]["backendState"], "Running");
        assert_eq!(harness.auth_calls(), 1);
        let patch = rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        assert!(patch.starts_with("PATCH /localapi/v0/prefs"));
        assert!(patch.contains("\"WantRunning\":false"));

        std::env::remove_var(crate::tailscale::SOCKET_ENV);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn openvpn_rejects_unsafe_config_before_authorization() {
        let harness = Harness::new(AuthDecision::Authorized);
        let mut client = harness.hello(1000).await;
        for config in [
            "client\nremote vpn.example\nplugin /tmp/evil.so\n",
            "client\nremote vpn.example\nauth-user-pass\n",
            "client\nremote vpn.example\nredirect-gateway def1\n",
        ] {
            let reply = client
                .call(
                    2,
                    method::OPENVPN_CONNECT,
                    json!({
                        "profileId":"home", "config":config, "assets":{}, "routes":[]
                    }),
                )
                .await;
            assert_eq!(error_code(&reply), "invalidParams", "{reply}");
        }
        assert_eq!(harness.auth_calls(), 0);
        assert!(harness.recorder.ops().is_empty());
    }

    #[tokio::test]
    async fn openvpn_probe_rejects_unsafe_config_before_authorization() {
        let harness = Harness::new(AuthDecision::Authorized);
        let mut client = harness.hello(1000).await;
        let reply = client
            .call(
                2,
                "openvpn.probe",
                json!({
                    "profileId": "home",
                    "config": "client\nremote vpn.example\nplugin /tmp/SECRET.so\n",
                    "assets": {},
                    "routes": []
                }),
            )
            .await;
        assert_eq!(error_code(&reply), "invalidParams");
        assert_eq!(harness.auth_calls(), 0);
        assert!(!reply.to_string().contains("SECRET"));
    }

    #[tokio::test]
    async fn openvpn_probe_returns_typed_routes_and_cleans_transient_owner() {
        let dir = std::env::temp_dir().join(format!(
            "netmgr-openvpn-probe-ok-{}-{}",
            std::process::id(),
            DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let recorder = Recorder::default();
        let runner = FakeProbeRunner::default();
        runner
            .pending
            .lock()
            .unwrap()
            .push_back(vec![ManagementEvent::PushReply(
                parse_push_reply("PUSH_REPLY,route 10.89.0.0 255.255.255.0").unwrap(),
            )]);
        let daemon = DaemonCore::open_with_openvpn(
            JournalStore::new(dir.join(JOURNAL_FILE)),
            Box::new(FakeRoutes::new(&recorder)),
            Box::new(FakeLinks(recorder.clone())),
            Box::new(runner.clone()),
        )
        .unwrap();
        let ctx = ServerContext::new(
            daemon,
            FakeAuthorizer {
                decision: AuthDecision::Authorized,
                calls: AtomicUsize::new(0),
                actions: Mutex::new(Vec::new()),
            },
        );
        let peer = PeerIdentity {
            uid: 1000,
            pid: 4242,
            start_time: Some(1),
            pidfd: None,
        };
        let response = dispatch(
            RequestFrame {
                id: 2,
                method: method::OPENVPN_PROBE.into(),
                params: json!({
                    "profileId": "home",
                    "config": "client\nremote vpn.example\n",
                    "assets": {},
                    "routes": []
                }),
            },
            &peer,
            &ctx,
        )
        .await;
        let result: OpenVpnProbeResult = from_value(response.outcome.unwrap()).unwrap();
        assert_eq!(
            result.routes[0].destination,
            "10.89.0.0/24".parse().unwrap()
        );
        assert_eq!(ctx.authorizer.calls.load(Ordering::SeqCst), 1);
        assert_eq!(runner.stopped.load(Ordering::SeqCst), 1);
        assert_eq!(runner.cleaned.load(Ordering::SeqCst), 1);
        assert!(recorder.ops().is_empty());
        assert!(JournalStore::new(dir.join(JOURNAL_FILE))
            .load()
            .unwrap()
            .entries
            .is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn detached_probe_timeout_cleans_journal_without_holding_core_lock() {
        let dir = std::env::temp_dir().join(format!(
            "netmgr-openvpn-probe-{}-{}",
            std::process::id(),
            DIR_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let recorder = Recorder::default();
        let runner = FakeProbeRunner::default();
        let daemon = DaemonCore::open_with_openvpn(
            JournalStore::new(dir.join(JOURNAL_FILE)),
            Box::new(FakeRoutes::new(&recorder)),
            Box::new(FakeLinks(recorder.clone())),
            Box::new(runner.clone()),
        )
        .unwrap();
        let core = Arc::new(Mutex::new(daemon));
        let request: OpenVpnConnectRequest = from_value(json!({
            "profileId": "home",
            "config": "client\nremote vpn.example\n",
            "assets": {},
            "routes": []
        }))
        .unwrap();
        let plan = prepare_openvpn(1000, request).unwrap();
        // Dropping the caller's handle must not cancel the cleanup task.
        let handle = tokio::spawn(run_openvpn_probe(
            core.clone(),
            1000,
            plan,
            Duration::from_millis(200),
        ));
        drop(handle);
        tokio::time::timeout(Duration::from_secs(2), async {
            while runner.started.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        tokio::time::timeout(
            Duration::from_millis(100),
            with_core_shared(&core, |_| Ok(())),
        )
        .await
        .unwrap()
        .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            // The runner's cleanup callback precedes the journal commit.
            // Wait for the observable teardown, not the intermediate mock signal.
            while !JournalStore::new(dir.join(JOURNAL_FILE))
                .load()
                .unwrap()
                .entries
                .is_empty()
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(runner.stopped.load(Ordering::SeqCst), 1);
        assert_eq!(runner.cleaned.load(Ordering::SeqCst), 1);
        assert!(JournalStore::new(dir.join(JOURNAL_FILE))
            .load()
            .unwrap()
            .entries
            .is_empty());
        assert!(recorder.ops().is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn openvpn_credentials_reach_authorization_without_appearing_in_errors() {
        let harness = Harness::new(AuthDecision::Denied);
        let mut client = harness.hello(1000).await;
        let reply = client
            .call(
                2,
                method::OPENVPN_CONNECT,
                json!({
                    "profileId": "home",
                    "config": "client\nremote vpn.example\nauth-user-pass\n",
                    "assets": {},
                    "routes": [],
                    "credentials": {
                        "authUserPass": {
                            "username": "alice",
                            "password": "SECRET-AUTH-PASSWORD"
                        }
                    }
                }),
            )
            .await;
        assert_eq!(error_code(&reply), "notAuthorized");
        assert_eq!(harness.auth_calls(), 1);
        assert!(!reply.to_string().contains("SECRET-AUTH-PASSWORD"));
    }

    #[tokio::test]
    async fn malformed_openvpn_credentials_are_rejected_without_echoing_values() {
        let harness = Harness::new(AuthDecision::Authorized);
        let mut client = harness.hello(1000).await;
        let reply = client
            .call(
                2,
                method::OPENVPN_CONNECT,
                json!({
                    "profileId": "home",
                    "config": "client\nremote vpn.example\nauth-user-pass\n",
                    "assets": {},
                    "credentials": {"authUserPass": "SECRET-MALFORMED-CREDENTIAL"}
                }),
            )
            .await;
        assert_eq!(error_code(&reply), "invalidParams");
        assert_eq!(harness.auth_calls(), 0);
        assert!(!reply.to_string().contains("SECRET-MALFORMED-CREDENTIAL"));
    }

    #[tokio::test]
    async fn wireguard_rejects_invalid_root_config_before_authorization() {
        let harness = Harness::new(AuthDecision::Authorized);
        let mut client = harness.hello(1000).await;
        assert_eq!(
            error_code(
                &client
                    .call(
                        2,
                        method::WIREGUARD_CONNECT,
                        wg_params("FwMark=SECRET-MARK")
                    )
                    .await
            ),
            "invalidParams"
        );
        assert_eq!(
            error_code(
                &client
                    .call(3, method::WIREGUARD_CONNECT, wg_params("DNS=192.0.2.53"))
                    .await
            ),
            "invalidParams"
        );
        assert_eq!(harness.auth_calls(), 0);
        assert!(harness.recorder.ops().is_empty());
    }

    #[tokio::test]
    async fn missing_wireguard_status_is_stopped_and_scoped_to_peer_uid() {
        let harness = Harness::new(AuthDecision::Authorized);
        let mut client = harness.hello(1001).await;
        let reply = client
            .call(2, method::WIREGUARD_STATUS, json!({"profileId":"home"}))
            .await;
        assert_eq!(reply["result"]["state"], json!("stopped"));
        assert_eq!(harness.auth_calls(), 0);
    }

    #[tokio::test]
    async fn wireguard_rpc_connect_status_and_disconnect_are_uid_scoped() {
        let harness = Harness::new(AuthDecision::Authorized);
        let mut mine = harness.hello(1000).await;
        let mut other = harness.hello(1001).await;
        let connected = mine.call(2, method::WIREGUARD_CONNECT, wg_params("")).await;
        assert_eq!(connected["result"]["status"]["state"], json!("running"));
        assert_eq!(
            other
                .call(2, method::WIREGUARD_STATUS, json!({"profileId":"home"}))
                .await["result"]["state"],
            json!("stopped")
        );
        assert_eq!(
            error_code(
                &mine
                    .call(5, method::ROUTES_REMOVE, json!({"owner":"wg:home"}))
                    .await
            ),
            "invalidParams"
        );
        assert_eq!(
            error_code(
                &other
                    .call(3, method::WIREGUARD_DISCONNECT, json!({"profileId":"home"}))
                    .await
            ),
            "notFound"
        );
        assert_eq!(
            mine.call(3, method::WIREGUARD_DISCONNECT, json!({"profileId":"home"}))
                .await["result"]["stopped"],
            json!(true)
        );
        assert_eq!(
            mine.call(4, method::WIREGUARD_STATUS, json!({"profileId":"home"}))
                .await["result"]["state"],
            json!("stopped")
        );
        assert_eq!(harness.auth_calls(), 3);
    }

    #[tokio::test]
    async fn hello_reports_uid_and_capabilities() {
        let harness = Harness::new(AuthDecision::Authorized);
        let mut client = harness.connect(1000);
        let reply = client
            .call(1, "hello", json!({"protocol":1,"client":"test"}))
            .await;
        assert_eq!(reply["result"]["uid"], json!(1000));
        assert_eq!(reply["result"]["protocol"], json!(1));
        assert_eq!(
            reply["result"]["capabilities"],
            json!(net_manager_core::daemon_protocol::method::CAPABILITIES)
        );
        assert!(reply["result"]["tools"].is_object());
    }

    #[tokio::test]
    async fn hello_reports_tool_presence_from_probe() {
        use net_manager_core::daemon_protocol::tool;
        let harness = Harness::with(AuthDecision::Authorized, |ctx| {
            ctx.tools_probe = || {
                std::collections::BTreeMap::from([
                    (tool::WIREGUARD.to_string(), true),
                    (tool::OPENVPN.to_string(), false),
                ])
            };
        });
        let mut client = harness.connect(1000);
        let reply = client
            .call(1, "hello", json!({"protocol":1,"client":"test"}))
            .await;
        assert_eq!(reply["result"]["tools"]["wireguard"], json!(true));
        assert_eq!(reply["result"]["tools"]["openvpn"], json!(false));
    }

    #[tokio::test]
    async fn first_request_must_be_hello() {
        let harness = Harness::new(AuthDecision::Authorized);
        let mut client = harness.connect(1000);
        let reply = client.call(3, "owned.list", Value::Null).await;
        assert_eq!(error_code(&reply), "handshakeRequired");
        assert_eq!(client.recv().await, None);
    }

    #[tokio::test]
    async fn protocol_mismatch_closes() {
        let harness = Harness::new(AuthDecision::Authorized);
        let mut client = harness.connect(1000);
        let reply = client
            .call(1, "hello", json!({"protocol":2,"client":"test"}))
            .await;
        assert_eq!(error_code(&reply), "protocolMismatch");
        assert_eq!(
            reply["error"]["message"],
            json!("daemon speaks protocol 1, client 2")
        );
        assert_eq!(client.recv().await, None);
    }

    #[tokio::test]
    async fn unknown_method_keeps_connection() {
        let harness = Harness::new(AuthDecision::Authorized);
        let mut client = harness.hello(1000).await;
        let reply = client.call(2, "frobnicate", json!({"x":1})).await;
        assert_eq!(error_code(&reply), "unsupportedMethod");
        let reply = client.call(3, "owned.list", Value::Null).await;
        assert_eq!(reply["result"], json!({"owners": []}));
    }

    #[tokio::test]
    async fn oversized_frame_closes() {
        let harness = Harness::new(AuthDecision::Authorized);
        let Client {
            mut reader,
            mut writer,
        } = harness.hello(1000).await;
        tokio::spawn(async move {
            let _ = writer.write_all(&vec![b'a'; MAX_FRAME_BYTES + 1]).await;
            // Keep the write side open: the daemon must not wait for EOF.
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let reply: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(error_code(&reply), "frameTooLarge");
        line.clear();
        let closed = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
            .await
            .expect("connection must close");
        assert_eq!(closed.unwrap(), 0);
    }

    #[tokio::test]
    async fn invalid_params_never_reach_authorizer() {
        let harness = Harness::new(AuthDecision::Authorized);
        let mut client = harness.hello(1000).await;
        let cases = [
            ("routes.apply", apply_params("office", "10.0.0.1/8")),
            ("routes.apply", apply_params("", "10.0.0.0/8")),
            (
                "routes.apply",
                json!({"owner":"office","routes":[{"destination":"10.0.0.0/8","interfaceIndex":2,"metric":5,"table":255}]}),
            ),
            ("routes.apply", json!({"owner":"office"})),
            ("routes.remove", json!({"owner":"a\nb"})),
            ("link.set_state", json!({"name":"wg0; reboot","up":true})),
            ("link.set_state", json!({"name":"wg0"})),
        ];
        for (id, (method, params)) in cases.into_iter().enumerate() {
            let reply = client.call(id as u64 + 10, method, params).await;
            assert_eq!(error_code(&reply), "invalidParams", "{method}: {reply}");
        }
        assert_eq!(harness.auth_calls(), 0);
        assert!(harness.recorder.ops().is_empty());
    }

    #[tokio::test]
    async fn denied_does_not_touch_executor() {
        let harness = Harness::new(AuthDecision::Denied);
        let mut client = harness.hello(1000).await;
        let reply = client
            .call(2, "routes.apply", apply_params("office", "10.0.0.0/8"))
            .await;
        assert_eq!(error_code(&reply), "notAuthorized");
        assert!(reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("polkit"));
        let reply = client
            .call(3, "link.set_state", json!({"name":"enp0s3","up":false}))
            .await;
        assert_eq!(error_code(&reply), "notAuthorized");
        assert_eq!(harness.auth_calls(), 2);
        assert!(harness.recorder.ops().is_empty());
    }

    #[tokio::test]
    async fn dismissed_maps_to_authorization_dismissed() {
        let harness = Harness::new(AuthDecision::Dismissed);
        let mut client = harness.hello(1000).await;
        let reply = client
            .call(2, "routes.apply", apply_params("office", "10.0.0.0/8"))
            .await;
        assert_eq!(error_code(&reply), "authorizationDismissed");
        assert!(harness.recorder.ops().is_empty());
    }

    #[tokio::test]
    async fn apply_list_remove_round_trip() {
        let harness = Harness::new(AuthDecision::Authorized);
        let mut client = harness.hello(1000).await;
        let reply = client
            .call(2, "routes.apply", apply_params("office", "10.0.0.0/8"))
            .await;
        assert_eq!(reply["result"], json!({"applied": 1}));
        let reply = client
            .call(3, "routes.apply", apply_params("office", "10.9.0.0/16"))
            .await;
        assert_eq!(error_code(&reply), "conflict");
        let reply = client.call(4, "owned.list", Value::Null).await;
        assert_eq!(reply["result"]["owners"][0]["owner"], json!("office"));
        assert_eq!(reply["result"]["owners"][0]["state"], json!("applied"));
        let reply = client
            .call(5, "routes.remove", json!({"owner":"office"}))
            .await;
        assert_eq!(reply["result"], json!({"removed": 1}));
        let reply = client
            .call(6, "routes.remove", json!({"owner":"office"}))
            .await;
        assert_eq!(error_code(&reply), "notFound");
        let reply = client
            .call(7, "link.set_state", json!({"name":"enp0s3","up":true}))
            .await;
        assert_eq!(reply["result"], Value::Null);
        assert_eq!(reply["ok"], json!(true));
    }

    #[tokio::test]
    async fn recovery_cleanup_removes_only_callers_owners() {
        let harness = Harness::new(AuthDecision::Authorized);
        let mut mine = harness.hello(1000).await;
        let mut theirs = harness.hello(1001).await;
        mine.call(2, "routes.apply", apply_params("a", "10.1.0.0/16"))
            .await;
        theirs
            .call(2, "routes.apply", apply_params("b", "10.2.0.0/16"))
            .await;
        let reply = mine.call(3, "recovery.cleanup", Value::Null).await;
        assert_eq!(
            reply["result"],
            json!({"removedOwners": ["a"], "failed": []})
        );
        let reply = theirs.call(3, "owned.list", Value::Null).await;
        assert_eq!(reply["result"]["owners"][0]["owner"], json!("b"));
    }

    #[tokio::test]
    async fn apply_notifies_subscriber_of_same_uid_only() {
        let harness = Harness::new(AuthDecision::Authorized);
        let mut same = harness.hello(1000).await;
        let mut other = harness.hello(1001).await;
        assert_eq!(
            same.call(2, "subscribe", Value::Null).await["ok"],
            json!(true)
        );
        assert_eq!(
            other.call(2, "subscribe", Value::Null).await["ok"],
            json!(true)
        );

        let mut actor = harness.hello(1000).await;
        actor
            .call(2, "routes.apply", apply_params("office", "10.0.0.0/8"))
            .await;

        assert_eq!(
            same.recv().await,
            Some(json!({"event":"owned.changed","data":{"owner":"office"}}))
        );
        assert_eq!(
            other.recv_within(Duration::from_millis(300)).await,
            Err(()),
            "another uid must not see the event"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn intent_set_list_and_del_round_trip() {
        let harness = Harness::new(AuthDecision::Authorized);
        harness.ctx.core.lock().unwrap().intents = Some(crate::intents::IntentStore::new(
            harness.dir.join("intents"),
        ));
        let mut watcher = harness.hello(1000).await;
        assert_eq!(
            watcher.call(2, "subscribe", Value::Null).await["ok"],
            json!(true)
        );
        let mut client = harness.hello(1000).await;

        // set returns the public id, not the journal owner
        let set = client
            .call(
                2,
                method::NET_INTENT_SET,
                json!({
                    "id": "office",
                    "destinations": ["10.20.0.0/16", "10.30.0.0/16"],
                    "path": {"kind": "direct"}
                }),
            )
            .await;
        assert_eq!(set["result"]["id"], json!("office"), "{set}");
        assert_eq!(
            watcher.recv().await,
            Some(json!({"event":"owned.changed","data":{"owner":"intent:office"}}))
        );

        let list = client.call(3, method::NET_INTENT_LIST, Value::Null).await;
        let intents = &list["result"]["intents"];
        assert_eq!(intents.as_array().unwrap().len(), 1, "{list}");
        assert_eq!(intents[0]["id"], json!("office"));
        assert_eq!(intents[0]["path"]["kind"], json!("direct"));
        assert_eq!(intents[0]["metric"], json!(100));

        let del = client
            .call(4, method::NET_INTENT_DEL, json!({"id": "office"}))
            .await;
        assert_eq!(del["result"]["id"], json!("office"), "{del}");
        assert_eq!(
            watcher.recv().await,
            Some(json!({"event":"owned.changed","data":{"owner":"intent:office"}}))
        );
        let list = client.call(5, method::NET_INTENT_LIST, Value::Null).await;
        assert_eq!(list["result"]["intents"], json!([]), "{list}");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn intent_mutations_require_authorization_list_does_not() {
        let harness = Harness::new(AuthDecision::Denied);
        let mut client = harness.hello(1000).await;
        let denied = client
            .call(
                2,
                method::NET_INTENT_SET,
                json!({
                    "id": "office",
                    "destinations": ["10.20.0.0/16"],
                    "path": {"kind": "direct"}
                }),
            )
            .await;
        assert_eq!(error_code(&denied), "notAuthorized");
        let denied = client
            .call(3, method::NET_INTENT_DEL, json!({"id": "office"}))
            .await;
        assert_eq!(error_code(&denied), "notAuthorized");
        assert_eq!(harness.auth_calls(), 2);

        let list = client.call(4, method::NET_INTENT_LIST, Value::Null).await;
        assert_eq!(list["ok"], json!(true), "{list}");
        assert_eq!(harness.auth_calls(), 2, "list must stay read-only");
    }

    #[tokio::test]
    async fn lagged_subscriber_gets_resync() {
        let harness = Harness::with(AuthDecision::Authorized, |ctx| {
            ctx.events = tokio::sync::broadcast::channel(2).0;
        });
        let mut client = harness.hello(1000).await;
        assert_eq!(
            client.call(2, "subscribe", Value::Null).await["ok"],
            json!(true)
        );
        // current_thread runtime: the connection task cannot run between
        // these sends, so the receiver is guaranteed to lag.
        for n in 0..10 {
            let _ = harness.ctx.events.send(OwnerEvent {
                uid: 1000,
                owner: format!("o{n}"),
            });
        }
        assert_eq!(client.recv().await, Some(json!({"event":"resync"})));
    }

    #[tokio::test]
    async fn connection_limit_returns_busy() {
        let harness = Harness::with(AuthDecision::Authorized, |ctx| {
            ctx.connections = Arc::new(tokio::sync::Semaphore::new(1));
        });
        let _first = harness.hello(1000).await;
        let mut second = harness.connect(1000);
        let reply = second.recv().await.unwrap();
        assert_eq!(error_code(&reply), "busy");
        assert_eq!(second.recv().await, None);
    }

    #[tokio::test]
    async fn always_on_static_registration_and_removal_are_uid_scoped() {
        let mut harness = Harness::new(AuthDecision::Authorized);
        let store = crate::always_on::AlwaysOnStore::new(harness.dir.join("profiles"));
        Arc::get_mut(&mut harness.ctx).unwrap().always_on =
            Some(Arc::new(Mutex::new(store.clone())));
        let mut mine = harness.hello(1000).await;
        let mut other = harness.hello(1001).await;
        let definition = json!({"definition":{"kind":"staticRoutes","profile":{
            "profileId":"office","interfaceName":"lo",
            "routes":[{"destination":"203.0.113.0/24","metric":5}]
        }}});

        assert_eq!(
            mine.call(2, method::ALWAYS_ON_SET, definition).await["result"]["active"],
            true
        );
        assert_eq!(
            other.call(2, method::ALWAYS_ON_LIST, Value::Null).await["result"]["profiles"],
            json!([])
        );
        assert_eq!(
            other
                .call(
                    3,
                    method::ALWAYS_ON_REMOVE,
                    json!({"kind":"staticRoutes","profileId":"office"})
                )
                .await["result"]["removed"],
            false
        );
        assert_eq!(
            mine.call(3, method::ALWAYS_ON_LIST, Value::Null).await["result"]["profiles"][0]
                ["profileId"],
            "office"
        );
        assert_eq!(
            mine.call(
                4,
                method::ALWAYS_ON_REMOVE,
                json!({"kind":"staticRoutes","profileId":"office"})
            )
            .await["result"]["removed"],
            true
        );
        assert!(store.load_uid(1000).unwrap().entries.is_empty());
    }

    #[tokio::test]
    async fn recovery_cleanup_persists_pause_until_explicit_resume() {
        let mut harness = Harness::new(AuthDecision::Authorized);
        let store = crate::always_on::AlwaysOnStore::new(harness.dir.join("profiles"));
        Arc::get_mut(&mut harness.ctx).unwrap().always_on =
            Some(Arc::new(Mutex::new(store.clone())));
        let mut client = harness.hello(1000).await;
        let definition = json!({"definition":{"kind":"staticRoutes","profile":{
            "profileId":"office","interfaceName":"lo",
            "routes":[{"destination":"203.0.113.0/24","metric":5}]
        }}});
        client.call(2, method::ALWAYS_ON_SET, definition).await;
        client.call(3, method::RECOVERY_CLEANUP, Value::Null).await;
        assert_eq!(
            harness.ctx.authorizer.actions.lock().unwrap().last(),
            Some(&Action::SystemNetwork)
        );
        assert!(store.load_uid(1000).unwrap().paused);
        assert!(harness.ctx.core.lock().unwrap().owned(1000).is_empty());
        client.call(4, method::ALWAYS_ON_RESUME, Value::Null).await;
        assert!(!store.load_uid(1000).unwrap().paused);
        assert_eq!(harness.ctx.core.lock().unwrap().owned(1000).len(), 1);
    }

    // ── Conditional rules ────────────────────────────────────────────

    #[cfg(target_os = "linux")]
    #[derive(Clone, Default)]
    struct FakeObserver {
        addrs: Arc<Mutex<Vec<crate::cond_rules::IfaceAddr>>>,
        routes: Arc<Mutex<Vec<net_manager_core::models::AppliedRoute>>>,
    }

    #[cfg(target_os = "linux")]
    impl crate::cond_rules::NetworkObservation for FakeObserver {
        fn interface_addrs(&self) -> io::Result<Vec<crate::cond_rules::IfaceAddr>> {
            Ok(self.addrs.lock().unwrap().clone())
        }
        fn owned_routes(&self) -> io::Result<Vec<net_manager_core::models::AppliedRoute>> {
            Ok(self.routes.lock().unwrap().clone())
        }
    }

    #[cfg(target_os = "linux")]
    fn cond_harness(
        decision: AuthDecision,
        addrs: Vec<crate::cond_rules::IfaceAddr>,
    ) -> (Harness, Arc<Mutex<Vec<crate::cond_rules::IfaceAddr>>>) {
        let mut harness = Harness::new(decision);
        let observed_addrs = Arc::new(Mutex::new(addrs));
        let ctx = Arc::get_mut(&mut harness.ctx).unwrap();
        ctx.cond_rules = Some(Arc::new(crate::cond_rules::CondRuleStore::new(
            harness.dir.join("cond-rules"),
        )));
        ctx.observer = Arc::new(FakeObserver {
            addrs: observed_addrs.clone(),
            routes: Arc::new(Mutex::new(Vec::new())),
        });
        (harness, observed_addrs)
    }

    #[cfg(target_os = "linux")]
    fn cond_params(id: &str, prefix: &str, dest: &str) -> Value {
        json!({"rule": {
            "id": id,
            "name": "Office LAN",
            "enabled": true,
            "condition": {"kind": "interfaceAddressIn", "prefix": prefix},
            "routes": [{"destination": dest, "metric": 5}]
        }})
    }

    #[cfg(target_os = "linux")]
    fn lan_addr() -> crate::cond_rules::IfaceAddr {
        crate::cond_rules::IfaceAddr {
            ifindex: 2,
            name: "enp1s0".into(),
            address: "10.228.33.5/21".parse().unwrap(),
            scope: 0,
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cond_rules_put_list_remove_roundtrip() {
        let (harness, _) = cond_harness(AuthDecision::Authorized, Vec::new());
        let mut client = harness.hello(1000).await;

        // Outside the LAN: the rule stores but stays inactive.
        let reply = client
            .call(
                2,
                method::COND_RULES_PUT,
                cond_params("office", "10.228.32.0/21", "10.99.0.0/24"),
            )
            .await;
        assert_eq!(reply["ok"], json!(true), "{reply}");
        assert_eq!(reply["result"]["stored"], json!(true));
        assert_eq!(reply["result"]["status"]["state"], json!("inactive"));

        let reply = client.call(3, method::COND_RULES_LIST, Value::Null).await;
        assert_eq!(reply["result"]["rules"][0]["rule"]["id"], json!("office"));
        assert_eq!(
            reply["result"]["rules"][0]["status"]["state"],
            json!("inactive")
        );

        let reply = client
            .call(4, method::COND_RULES_REMOVE, json!({"ruleId": "office"}))
            .await;
        assert_eq!(reply["result"]["removed"], json!(true));
        let reply = client.call(5, method::COND_RULES_LIST, Value::Null).await;
        assert_eq!(reply["result"]["rules"], json!([]));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cond_rules_put_applies_and_remove_withdraws_routes() {
        let (harness, _) = cond_harness(AuthDecision::Authorized, vec![lan_addr()]);
        let mut client = harness.hello(1000).await;

        let reply = client
            .call(
                2,
                method::COND_RULES_PUT,
                cond_params("office", "10.228.32.0/21", "10.99.0.0/24"),
            )
            .await;
        assert_eq!(
            reply["result"]["status"]["state"],
            json!("active"),
            "{reply}"
        );
        assert_eq!(
            reply["result"]["status"]["matchedInterface"],
            json!("enp1s0")
        );
        assert_eq!(
            harness.recorder.ops(),
            vec![crate::core::testing::Op::Add("10.99.0.0/24".into())]
        );

        let reply = client
            .call(3, method::COND_RULES_REMOVE, json!({"ruleId": "office"}))
            .await;
        assert_eq!(reply["result"]["removed"], json!(true));
        assert_eq!(
            harness.recorder.ops(),
            vec![
                crate::core::testing::Op::Add("10.99.0.0/24".into()),
                crate::core::testing::Op::Remove("10.99.0.0/24".into())
            ]
        );
        assert!(harness.ctx.core.lock().unwrap().owned(1000).is_empty());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cond_rules_require_authorization_and_valid_rules() {
        let (denied, _) = cond_harness(AuthDecision::Denied, Vec::new());
        let mut client = denied.hello(1000).await;
        let reply = client
            .call(
                2,
                method::COND_RULES_PUT,
                cond_params("office", "10.228.32.0/21", "10.99.0.0/24"),
            )
            .await;
        assert_eq!(error_code(&reply), "notAuthorized", "{reply}");
        let reply = client
            .call(3, method::COND_RULES_REMOVE, json!({"ruleId": "office"}))
            .await;
        assert_eq!(error_code(&reply), "notAuthorized", "{reply}");

        // Validation failures do not reach the authorizer.
        let (harness, _) = cond_harness(AuthDecision::Authorized, Vec::new());
        let mut client = harness.hello(1000).await;
        let mut bad = cond_params("bad id", "10.228.32.0/21", "10.99.0.0/24");
        bad["rule"]["id"] = json!("has space");
        let reply = client.call(2, method::COND_RULES_PUT, bad).await;
        assert_eq!(error_code(&reply), "invalidParams", "{reply}");
        assert_eq!(harness.auth_calls(), 0);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cond_rules_are_scoped_to_the_calling_uid() {
        let (harness, _) = cond_harness(AuthDecision::Authorized, Vec::new());
        let mut mine = harness.hello(1000).await;
        let mut other = harness.hello(1001).await;
        mine.call(
            2,
            method::COND_RULES_PUT,
            cond_params("office", "10.228.32.0/21", "10.99.0.0/24"),
        )
        .await;
        assert_eq!(
            other.call(2, method::COND_RULES_LIST, Value::Null).await["result"]["rules"],
            json!([])
        );
        // Another uid cannot remove the rule.
        let reply = other
            .call(3, method::COND_RULES_REMOVE, json!({"ruleId": "office"}))
            .await;
        assert_eq!(reply["result"]["removed"], json!(false));
        assert_eq!(
            mine.call(3, method::COND_RULES_LIST, Value::Null).await["result"]["rules"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cond_rules_are_unavailable_without_a_store() {
        let harness = Harness::new(AuthDecision::Authorized);
        let mut client = harness.hello(1000).await;
        let reply = client.call(2, method::COND_RULES_LIST, Value::Null).await;
        assert_eq!(error_code(&reply), "unavailable", "{reply}");
    }

    #[cfg(target_os = "linux")]
    mod client_tracker_tests {
        use super::*;
        use crate::auth::Pidfd;
        use std::os::fd::{FromRawFd, OwnedFd};
        use std::time::Duration;

        fn child_pidfd() -> (std::process::Child, PeerIdentity) {
            let child = std::process::Command::new("sleep")
                .arg("60")
                .spawn()
                .unwrap();
            let pid = child.id();
            // SAFETY: a freshly spawned child is a valid live pid.
            let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
            assert!(raw >= 0, "pidfd_open: {}", io::Error::last_os_error());
            // SAFETY: the kernel just handed us this descriptor.
            let fd = unsafe { OwnedFd::from_raw_fd(raw as _) };
            let peer = PeerIdentity {
                uid: 1000,
                pid,
                start_time: Some(1),
                pidfd: Some(Pidfd(Arc::new(fd))),
            };
            (child, peer)
        }

        #[test]
        fn fires_only_after_every_client_died_past_grace() {
            let tracker = ClientTracker::default();
            let (mut first, peer_a) = child_pidfd();
            let (mut second, peer_b) = child_pidfd();
            tracker.track(&peer_a);
            tracker.track(&peer_b);
            // Alive clients never expire.
            assert!(tracker.expired(Duration::ZERO).is_empty());
            // One dead client out of two still does not expire the uid.
            first.kill().unwrap();
            first.wait().unwrap();
            assert!(tracker.expired(Duration::ZERO).is_empty());
            second.kill().unwrap();
            second.wait().unwrap();
            // Reap visible to pidfd_send_signal on the next tick.
            let deadline = Instant::now() + Duration::from_secs(5);
            while !tracker.expired(Duration::from_secs(60)).is_empty() && Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(20));
            }
            // pidfds now reaped and grace armed; a new connection cancels it.
            let (mut third, peer_c) = child_pidfd();
            tracker.track(&peer_c);
            assert!(tracker.expired(Duration::ZERO).is_empty());
            third.kill().unwrap();
            third.wait().unwrap();
            for _ in 0..50 {
                if !tracker.expired(Duration::ZERO).is_empty() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            panic!("grace never fired");
        }
    }
}

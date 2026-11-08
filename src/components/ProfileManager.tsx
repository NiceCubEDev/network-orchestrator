import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { confirm } from "@tauri-apps/plugin-dialog";
import { ensureElevation, requiresElevation } from "../elevation";
import { usePlatformCapabilities } from "../platform";
import {
  setLastProfileId,
  useAppMode,
  useProfileListMode,
  useScanLocalProxies,
} from "../prefs";
import { providerPrefix } from "../subscriptions";
import { popupNativeMenu, MenuEntry } from "../nativeMenu";
import { useT } from "../i18n";
import { BACKEND_LABEL_KEYS } from "../i18n/labels";
import {
  backendAvatarClass,
  backendIcon,
  ChevronIcon,
  InfoIcon,
  kindIcon,
  LoopbackIcon,
  NetworkIcon,
  PlusIcon,
  TailscaleIcon,
  VpnIcon,
} from "../icons";

import AddConnectionMenu from "./AddConnectionMenu";
import DiagnosticsModal from "./DiagnosticsModal";
import ImportModal from "./ImportModal";
import Modal from "./Modal";
import Page from "./Page";
import ContextMenu from "./ui/ContextMenu";
import ProfileDetail from "./profiles/ProfileDetail";
import ProfileRow from "./profiles/ProfileRow";
import SetsBar from "./profiles/SetsBar";
import {
  ConnectionSnippet,
  loadSnippets,
  newSnippetId,
  sameIds,
  applySnippet as applySavedSnippet,
  captureSnippet,
  deleteSnippet as deleteSavedSnippet,
} from "./profiles/sets";
import Skeleton from "./ui/Skeleton";
import ExternalTunnelPanel from "./ExternalTunnelPanel";
import LocalProxyPanel from "./LocalProxyPanel";
import NmConnectionPanel from "./NmConnectionPanel";
import TailscalePanel from "./TailscalePanel";
import ToggleSwitch from "./ui/ToggleSwitch";
import NetBirdRow, { useNetBird } from "./NetBirdRow";
import OpenVpnCredentialsModal from "./OpenVpnCredentialsModal";
import { useToast } from "./ui/Toast";
import ProfileFormModal, {
  editFormState,
  newFormState,
  type ProfileFormState,
} from "./ProfileFormModal";
import {
  AlwaysOnKind,
  AlwaysOnListResult,
  AlwaysOnSetResult,
  BatchImportResult,
  ConnectionSetCredentialInput,
  LocalProxy,
  NetworkInterface,
  NmConnection,
  NmConnectionKind,
  NmListResult,
  Profile,
  ProfileDiagnostics,
  ProfileInspection,
  SubscriptionEndpointInfo,
  SubscriptionDelayResult,
  SubscriptionRefreshResult,
  TailscaleStatusResult,
  TunnelBackend,
  TunnelStatus,
} from "../types";

const COLLAPSED_GROUPS_KEY = "netmanager.connections.collapsedGroups";
const LIST_WIDTH_KEY = "netmanager.profiles.listWidth";
const LIST_WIDTH_MIN = 220;
const LIST_WIDTH_MAX = 720;

function nmAvatarClass(kind: NmConnectionKind): string {
  switch (kind) {
    case "wireGuard":
      return "backend-avatar-wireGuard";
    case "openVpn":
      return "backend-avatar-openVpn";
    default:
      return "backend-avatar-service";
  }
}

function nmIcon(kind: NmConnectionKind): React.ReactElement {
  switch (kind) {
    case "wireGuard":
      return backendIcon("wireGuard", 14);
    case "openVpn":
      return backendIcon("openVpn", 14);
    case "vpn":
      return <VpnIcon size={14} />;
    default:
      return <NetworkIcon size={14} />;
  }
}

function clampListWidth(w: number): number {
  return Math.min(LIST_WIDTH_MAX, Math.max(LIST_WIDTH_MIN, Math.round(w)));
}

function loadListWidth(): number {
  try {
    const v = Number(localStorage.getItem(LIST_WIDTH_KEY));
    return Number.isFinite(v) && v > 0 ? clampListWidth(v) : 360;
  } catch {
    return 360;
  }
}

function loadCollapsedGroups(): Set<TunnelBackend> {
  try {
    const raw = localStorage.getItem(COLLAPSED_GROUPS_KEY);
    if (!raw) return new Set();
    return new Set(JSON.parse(raw) as TunnelBackend[]);
  } catch {
    return new Set();
  }
}

interface ProfileGroup {
  backend: TunnelBackend;
  items: Profile[];
}

/** Applies a new order of one backend group to the flat profile list —
 * mirrors `ProfileStore::reorder` for optimistic updates. */
function applyGroupOrder(
  profiles: Profile[],
  backend: TunnelBackend,
  orderedIds: string[],
): Profile[] {
  const byId = new Map(
    profiles.filter((p) => p.backend === backend).map((p) => [p.id, p]),
  );
  const ordered = orderedIds
    .map((id) => byId.get(id))
    .filter((p): p is Profile => p !== undefined);
  let i = 0;
  return profiles.map((p) =>
    p.backend === backend && i < ordered.length ? ordered[i++] : p,
  );
}

function ProfileRowSkeleton() {
  return (
    <div className="profile-row">
      <Skeleton width="14px" height="14px" />
      <Skeleton width="160px" height="0.9rem" />
      <Skeleton width="34px" height="18px" radius="999px" />
    </div>
  );
}

// Remounting this view on every tab switch would otherwise flash skeletons;
// keep the last fetched snapshot so the list renders instantly.
let listCache: {
  profiles: Profile[];
  statuses: TunnelStatus[];
  interfaces: NetworkInterface[];
  alwaysOn: AlwaysOnListResult | null;
  inspections: Record<string, ProfileInspection>;
} | null = null;

export default function ProfileManager() {
  const caps = usePlatformCapabilities();
  const toast = useToast();
  const t = useT();
  const listMode = useProfileListMode();
  const appMode = useAppMode();
  const canManage = appMode !== "orchestrator";
  const canOrchestrate = appMode !== "manager";
  const [profiles, setProfiles] = useState<Profile[]>(
    listCache?.profiles ?? [],
  );
  const [statuses, setStatuses] = useState<TunnelStatus[]>(
    listCache?.statuses ?? [],
  );
  const [alwaysOn, setAlwaysOn] = useState<AlwaysOnListResult | null>(
    listCache?.alwaysOn ?? null,
  );
  const [resumingAlwaysOn, setResumingAlwaysOn] = useState(false);
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>(
    listCache?.interfaces ?? [],
  );
  const [loading, setLoading] = useState(listCache === null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<Set<string>>(new Set());
  const [editing, setEditing] = useState<ProfileFormState | null>(null);
  const [formOpen, setFormOpen] = useState(false);
  const [inspections, setInspections] = useState<
    Record<string, ProfileInspection>
  >(listCache?.inspections ?? {});
  const [saveNotice, setSaveNotice] = useState<{
    profileName: string;
    inspection: ProfileInspection;
  } | null>(null);
  const [diagnostics, setDiagnostics] = useState<ProfileDiagnostics | null>(
    null,
  );
  const [diagOpen, setDiagOpen] = useState(false);
  const [diagBusy, setDiagBusy] = useState<string | null>(null);
  const [importErrors, setImportErrors] = useState<string[] | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [endpoints, setEndpoints] = useState<
    Record<string, SubscriptionEndpointInfo[]>
  >({});
  const [switching, setSwitching] = useState<string | null>(null);
  const [refreshingSubscription, setRefreshingSubscription] = useState<string | null>(null);
  const [settingRefreshInterval, setSettingRefreshInterval] = useState<string | null>(null);
  const [openVpnCredentialProfile, setOpenVpnCredentialProfile] = useState<Profile | null>(null);
  const [measuringEndpoints, setMeasuringEndpoints] = useState<Set<string>>(
    new Set(),
  );
  const [measuringAll, setMeasuringAll] = useState<Set<string>>(new Set());
  const [delayResults, setDelayResults] = useState<
    Record<string, Record<number, SubscriptionDelayResult>>
  >({});
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [externalName, setExternalName] = useState<string | null>(null);
  const [nmSelected, setNmSelected] = useState<string | null>(null);
  const [proxySelected, setProxySelected] = useState<string | null>(null);
  const [collapsedGroups, setCollapsedGroups] = useState<Set<TunnelBackend>>(
    loadCollapsedGroups,
  );
  const [search, setSearch] = useState("");
  const [addMenuOpen, setAddMenuOpen] = useState(false);
  const [snippets, setSnippets] = useState<ConnectionSnippet[]>([]);
  const snippetsBusy = useRef(false);
  const snippetsRefresh = useRef(0);
  const snippetsMounted = useRef(true);
  const setCredentialInputs = useRef<Record<string, ConnectionSetCredentialInput>>({});
  const setCredentialCollector = useRef<{
    profileId: string;
    resolve: (input: ConnectionSetCredentialInput) => void;
    reject: (error: DOMException) => void;
  } | null>(null);
  const clearSetCredentials = useCallback(() => {
    for (const id of Object.keys(setCredentialInputs.current)) delete setCredentialInputs.current[id];
  }, []);
  const cancelSetCredentialCollection = useCallback(() => {
    clearSetCredentials();
    const pending = setCredentialCollector.current;
    setCredentialCollector.current = null;
    pending?.reject(new DOMException("Connection-set credential collection cancelled", "AbortError"));
  }, [clearSetCredentials]);
  useEffect(() => {
    snippetsMounted.current = true;
    return () => {
      snippetsMounted.current = false;
      cancelSetCredentialCollection();
    };
  }, [cancelSetCredentialCollection]);
  const [activeSnippetId, setActiveSnippetId] = useState<string | null>(null);
  const [saveModalOpen, setSaveModalOpen] = useState(false);
  const [newSnippetName, setNewSnippetName] = useState("");
  const [throughput, setThroughput] = useState<
    Record<number, { rxRate: number; txRate: number }>
  >({});
  const prevStats = useRef<Record<number, { rx: number; tx: number; time: number }>>({});
  const [dragState, setDragState] = useState<{
    backend: TunnelBackend;
    profileId: string;
  } | null>(null);
  const [dropTarget, setDropTarget] = useState<{
    profileId: string;
    before: boolean;
  } | null>(null);
  const [tailscale, setTailscale] = useState<TailscaleStatusResult | null>(null);
  const [tailscaleBusy, setTailscaleBusy] = useState(false);
  const netbird = useNetBird(caps?.os === "linux");
  const [serviceSelected, setServiceSelected] = useState(false);
  const [ctxMenu, setCtxMenu] = useState<{
    x: number;
    y: number;
    items: MenuEntry[];
  } | null>(null);
  const [listWidth, setListWidth] = useState(loadListWidth);
  const [splitDragging, setSplitDragging] = useState(false);
  const splitDrag = useRef<{ x: number; w: number } | null>(null);
  const layoutRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    listCache = { profiles, statuses, interfaces, alwaysOn, inspections };
  }, [profiles, statuses, interfaces, alwaysOn, inspections]);

  useEffect(() => {
    try {
      localStorage.setItem(LIST_WIDTH_KEY, String(listWidth));
    } catch {
      // ignore storage errors (e.g. storage disabled)
    }
  }, [listWidth]);

  // While dragging, the width goes straight into a CSS variable (one write per
  // animation frame) so React does not re-render this whole screen on every
  // pointermove; state and storage are committed once on release.
  const dragWidth = useRef(listWidth);
  const dragFrame = useRef(0);
  const applyDragWidth = (w: number) => {
    dragWidth.current = w;
    if (dragFrame.current) return;
    dragFrame.current = requestAnimationFrame(() => {
      dragFrame.current = 0;
      layoutRef.current?.style.setProperty(
        "--profiles-list-w",
        `${dragWidth.current}px`,
      );
    });
  };
  const finishDrag = () => {
    if (!splitDrag.current) return;
    splitDrag.current = null;
    if (dragFrame.current) {
      cancelAnimationFrame(dragFrame.current);
      dragFrame.current = 0;
    }
    setListWidth(dragWidth.current);
    setSplitDragging(false);
  };

  useEffect(() => {
    if (!splitDragging) return;
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
    return () => {
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };
  }, [splitDragging]);

  const splitterProps = {
    role: "separator",
    "aria-orientation": "vertical",
    "aria-label": t("profiles.resizeList"),
    "aria-valuenow": listWidth,
    "aria-valuemin": LIST_WIDTH_MIN,
    "aria-valuemax": LIST_WIDTH_MAX,
    tabIndex: 0,
    className: `pane-splitter${splitDragging ? " dragging" : ""}`,
    onPointerDown: (e: React.PointerEvent<HTMLDivElement>) => {
      e.preventDefault();
      e.currentTarget.setPointerCapture(e.pointerId);
      splitDrag.current = { x: e.clientX, w: listWidth };
      dragWidth.current = listWidth;
      setSplitDragging(true);
    },
    onPointerMove: (e: React.PointerEvent<HTMLDivElement>) => {
      const drag = splitDrag.current;
      if (!drag) return;
      const max = layoutRef.current
        ? Math.min(LIST_WIDTH_MAX, layoutRef.current.clientWidth - 400)
        : LIST_WIDTH_MAX;
      applyDragWidth(
        Math.round(
          Math.max(
            LIST_WIDTH_MIN,
            Math.min(max, drag.w + e.clientX - drag.x),
          ),
        ),
      );
    },
    onPointerUp: finishDrag,
    onPointerCancel: finishDrag,
    onKeyDown: (e: React.KeyboardEvent<HTMLDivElement>) => {
      if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
        e.preventDefault();
        setListWidth(
          clampListWidth(listWidth + (e.key === "ArrowRight" ? 16 : -16)),
        );
      }
    },
  } as const;

  useEffect(() => {
    try {
      localStorage.setItem(
        COLLAPSED_GROUPS_KEY,
        JSON.stringify([...collapsedGroups]),
      );
    } catch {
      // ignore storage errors (e.g. storage disabled)
    }
  }, [collapsedGroups]);

  const refreshSnippets = useCallback(async () => {
    if (!caps) return;
    const request = ++snippetsRefresh.current;
    const saved = await loadSnippets(caps.os === "linux");
    if (request === snippetsRefresh.current) setSnippets(saved);
  }, [caps]);

  useEffect(() => {
    const refresh = () => { void refreshSnippets().catch((err: unknown) => setError(String(err))); };
    refresh();
    window.addEventListener("focus", refresh);
    window.addEventListener("route-changed", refresh);
    const interval = setInterval(refresh, 2000);
    return () => {
      ++snippetsRefresh.current;
      window.removeEventListener("focus", refresh);
      window.removeEventListener("route-changed", refresh);
      clearInterval(interval);
    };
  }, [refreshSnippets]);

  useEffect(() => {
    const poll = async () => {
      try {
        const data = await invoke<NetworkInterface[]>("get_interfaces");
        setInterfaces(data);
        const now = Date.now();
        const next: Record<number, { rxRate: number; txRate: number }> = {};
        for (const iface of data) {
          if (iface.rxBytes === null || iface.txBytes === null) continue;
          const prev = prevStats.current[iface.ifIndex];
          if (prev) {
            const dt = (now - prev.time) / 1000;
            if (dt > 0) {
              next[iface.ifIndex] = {
                rxRate: Math.max(0, (iface.rxBytes - prev.rx) / dt),
                txRate: Math.max(0, (iface.txBytes - prev.tx) / dt),
              };
            }
          }
          prevStats.current[iface.ifIndex] = {
            rx: iface.rxBytes,
            tx: iface.txBytes,
            time: now,
          };
        }
        setThroughput(next);
      } catch {
        // ignore polling errors
      }
    };
    poll();
    const interval = setInterval(poll, 1000);
    return () => clearInterval(interval);
  }, []);

  const rateFor = (profile: Profile) => {
    const iface = interfaces.find(
      (i) => i.name === profile.interfaceName || i.friendlyName === profile.interfaceName,
    );
    if (!iface) return null;
    return throughput[iface.ifIndex] ?? null;
  };

  const toggleGroupCollapsed = (backend: TunnelBackend) =>
    setCollapsedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(backend)) next.delete(backend);
      else next.add(backend);
      return next;
    });

  const statusFor = useCallback(
    (id: string): TunnelStatus =>
      statuses.find((s) => s.profileId === id) ?? {
        profileId: id,
        state: "stopped",
        message: null,
      },
    [statuses],
  );

  const refreshStatuses = useCallback(async () => {
    try {
      setStatuses(await invoke<TunnelStatus[]>("get_tunnel_statuses"));
    } catch {
      // keep last known statuses on poll failure
    }
    try {
      setAlwaysOn(await invoke<AlwaysOnListResult>("get_always_on_profiles"));
    } catch {
      // Keep the last known enrollment and pause state until the daemon returns.
    }
  }, []);

  const refreshAll = useCallback(async () => {
    try {
      setError(null);
      const [profileData, statusData, interfaceData] = await Promise.all([
        invoke<Profile[]>("get_profiles"),
        invoke<TunnelStatus[]>("get_tunnel_statuses"),
        invoke<NetworkInterface[]>("get_interfaces"),
      ]);
      setProfiles(profileData);
      setStatuses(statusData);
      setInterfaces(interfaceData);
      try {
        setAlwaysOn(await invoke<AlwaysOnListResult>("get_always_on_profiles"));
      } catch {
        setAlwaysOn(null);
      }
      try {
        const inspectionData =
          await invoke<ProfileInspection[]>("inspect_profiles");
        setInspections(
          Object.fromEntries(
            inspectionData.map((i) => [i.analysis.profileId, i]),
          ),
        );
      } catch (err) {
        setError(String(err));
      }
      return profileData;
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshAll();
  }, [refreshAll]);

  useEffect(() => {
    const onRouteChanged = () => {
      void (async () => {
        const updated = await refreshAll();
        if (!updated) return;
        const next: Record<string, SubscriptionEndpointInfo[]> = {};
        for (const profile of updated.filter((profile) => profile.subscription !== null)) {
          try {
            next[profile.id] = await invoke<SubscriptionEndpointInfo[]>(
              "get_subscription_endpoints",
              { profileId: profile.id },
            );
          } catch {
            // Keep the profile visible if its sidecar is temporarily unavailable.
          }
        }
        setEndpoints(next);
      })();
    };
    window.addEventListener("route-changed", onRouteChanged);
    return () => window.removeEventListener("route-changed", onRouteChanged);
  }, [refreshAll]);

  useEffect(() => {
    const interval = setInterval(refreshStatuses, 2000);
    return () => clearInterval(interval);
  }, [refreshStatuses]);

  const refreshTailscale = useCallback(async () => {
    if (caps?.os !== "linux") return;
    try {
      setTailscale(
        await invoke<TailscaleStatusResult>("tailscale_status"),
      );
    } catch {
      setTailscale(null);
    }
  }, [caps?.os]);

  useEffect(() => {
    void refreshTailscale();
    const onChanged = () => void refreshTailscale();
    window.addEventListener("route-changed", onChanged);
    const interval = setInterval(() => void refreshTailscale(), 15000);
    return () => {
      window.removeEventListener("route-changed", onChanged);
      clearInterval(interval);
    };
  }, [refreshTailscale]);

  const [externalBusy, setExternalBusy] = useState<string | null>(null);
  const [nm, setNm] = useState<NmListResult | null>(null);
  const [nmBusy, setNmBusy] = useState<string | null>(null);
  // "Off" stops a foreign tunnel for real (wg-quick unit stop / netdev
  // delete / TUN admin-down via the daemon, polkit-gated). "On" only exists
  // for a foreign TUN we downed — WG devices are gone after a stop.
  const onToggleExternal = async (iface: NetworkInterface) => {
    setExternalBusy(iface.name);
    try {
      if (!(await ensureElevation(t("iface.elevationState")))) return;
      if (iface.state === "up") {
        await invoke("stop_external_tunnel", { name: iface.name });
      } else {
        await invoke("set_interface_state", { name: iface.name, up: true });
      }
    } catch (err) {
      toast("error", String(err));
    } finally {
      setExternalBusy(null);
    }
  };

  const onToggleTailscale = async () => {
    if (!tailscale?.available) return;
    const running = tailscale.backendState === "Running";
    setTailscaleBusy(true);
    try {
      setTailscale(
        await invoke<TailscaleStatusResult>("tailscale_set_running", {
          running: !running,
        }),
      );
    } catch (err) {
      toast("error", String(err));
    } finally {
      setTailscaleBusy(false);
    }
  };

  const refreshNm = useCallback(async () => {
    if (caps?.os !== "linux" || !canOrchestrate) {
      setNm(null);
      return;
    }
    try {
      setNm(await invoke<NmListResult>("nm_list_connections"));
    } catch {
      setNm(null);
    }
  }, [caps?.os, canOrchestrate]);

  useEffect(() => {
    void refreshNm();
    const onChanged = () => void refreshNm();
    window.addEventListener("route-changed", onChanged);
    const interval = setInterval(() => void refreshNm(), 15000);
    return () => {
      window.removeEventListener("route-changed", onChanged);
      clearInterval(interval);
    };
  }, [refreshNm]);

  // Opt-in localhost proxy discovery: real SOCKS/HTTP handshake probes,
  // listed as suggestions only — nothing is routed through them.
  const scanLocalProxies = useScanLocalProxies();
  const [proxies, setProxies] = useState<LocalProxy[]>([]);
  const refreshProxies = useCallback(async () => {
    if (!scanLocalProxies || caps?.os !== "linux") {
      setProxies([]);
      return;
    }
    try {
      setProxies(await invoke<LocalProxy[]>("scan_local_proxies"));
    } catch {
      setProxies([]);
    }
  }, [scanLocalProxies, caps?.os]);

  useEffect(() => {
    void refreshProxies();
    const onChanged = () => void refreshProxies();
    window.addEventListener("route-changed", onChanged);
    const interval = setInterval(() => void refreshProxies(), 15000);
    return () => {
      window.removeEventListener("route-changed", onChanged);
      clearInterval(interval);
    };
  }, [refreshProxies]);

  // NM owns the profile lifecycle; we only ask it to activate/deactivate.
  const onToggleNm = async (conn: NmConnection) => {
    setNmBusy(conn.uuid);
    try {
      if (!(await ensureElevation(t("iface.elevationState")))) return;
      await invoke("nm_set_active", {
        uuid: conn.uuid,
        active: conn.state === "inactive",
      });
      await refreshNm();
    } catch (err) {
      toast("error", String(err));
    } finally {
      setNmBusy(null);
    }
  };

  useEffect(() => {
    const subProfiles = profiles.filter((p) => p.subscription !== null);
    if (subProfiles.length === 0) {
      if (Object.keys(endpoints).length > 0) setEndpoints({});
      return;
    }
    const subKey = subProfiles.map((p) => p.id).join(",");
    if (Object.keys(endpoints).sort().join(",") === subKey) return;
    let cancelled = false;
    (async () => {
      const next: Record<string, SubscriptionEndpointInfo[]> = {};
      for (const p of subProfiles) {
        try {
          next[p.id] = await invoke<SubscriptionEndpointInfo[]>(
            "get_subscription_endpoints",
            { profileId: p.id },
          );
        } catch {
          // ignore — sidecar may be missing or unreadable
        }
      }
      if (!cancelled) {
        setEndpoints(next);
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [profiles]);

  const commitReorder = async (backend: TunnelBackend, orderedIds: string[]) => {
    const previous = profiles;
    setProfiles(applyGroupOrder(previous, backend, orderedIds));
    try {
      setProfiles(
        await invoke<Profile[]>("reorder_profiles", { backend, orderedIds }),
      );
    } catch (err) {
      setProfiles(previous);
      toast("error", String(err));
    }
  };

  const moveProfileInGroup = (items: Profile[], profileId: string, delta: number) => {
    const index = items.findIndex((p) => p.id === profileId);
    const swap = index + delta;
    if (index < 0 || swap < 0 || swap >= items.length) return;
    const ids = items.map((p) => p.id);
    [ids[index], ids[swap]] = [ids[swap], ids[index]];
    void commitReorder(items[index].backend, ids);
  };

  const onCardDragStart = (
    event: React.DragEvent<HTMLElement>,
    profile: Profile,
  ) => {
    event.dataTransfer.effectAllowed = "move";
    event.dataTransfer.setData("text/plain", profile.id);
    // A compact name pill as the drag ghost: snapshotting the whole card
    // renders oversized on HiDPI/scaled webviews.
    const preview = document.createElement("div");
    preview.className = "connection-drag-preview";
    preview.textContent = profile.name;
    document.body.appendChild(preview);
    event.dataTransfer.setDragImage(preview, 12, 12);
    requestAnimationFrame(() => preview.remove());
    setDragState({ backend: profile.backend, profileId: profile.id });
    setDropTarget(null);
  };

  const onCardDragEnd = () => {
    setDragState(null);
    setDropTarget(null);
  };

  const pointerInUpperHalf = (event: React.DragEvent<HTMLElement>): boolean => {
    const rect = event.currentTarget.getBoundingClientRect();
    return event.clientY < rect.top + rect.height / 2;
  };

  const onCardDragOver = (
    event: React.DragEvent<HTMLElement>,
    group: ProfileGroup,
    target: Profile,
  ) => {
    if (!dragState) return;
    if (dragState.backend !== group.backend || dragState.profileId === target.id) {
      setDropTarget(null);
      return;
    }
    event.preventDefault();
    event.dataTransfer.dropEffect = "move";
    const before = pointerInUpperHalf(event);
    setDropTarget((prev) =>
      prev && prev.profileId === target.id && prev.before === before
        ? prev
        : { profileId: target.id, before },
    );
  };

  const onCardDrop = (
    event: React.DragEvent<HTMLElement>,
    group: ProfileGroup,
    target: Profile,
  ) => {
    if (
      !dragState ||
      dragState.backend !== group.backend ||
      dragState.profileId === target.id
    ) {
      return;
    }
    event.preventDefault();
    const ids = group.items
      .map((p) => p.id)
      .filter((id) => id !== dragState.profileId);
    const at = ids.indexOf(target.id);
    ids.splice(pointerInUpperHalf(event) ? at : at + 1, 0, dragState.profileId);
    setDragState(null);
    setDropTarget(null);
    if (ids.join(",") !== group.items.map((p) => p.id).join(",")) {
      void commitReorder(group.backend, ids);
    }
  };

  const onListDragLeave = (event: React.DragEvent<HTMLElement>) => {
    if (!event.currentTarget.contains(event.relatedTarget as Node | null)) {
      setDropTarget(null);
    }
  };

  const withBusy = async (
    id: string,
    action: () => Promise<unknown>,
    onError?: (err: unknown) => void,
  ) => {
    setBusy((prev) => new Set(prev).add(id));
    try {
      await action();
      await refreshAll();
    } catch (err) {
      if (onError) onError(err);
      else setError(String(err));
    } finally {
      setBusy((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    }
  };

  /** Orchestrator mode never starts a managed backend; only route-only
   * ("none") profiles may connect. */
  const connectLockedTitle = (profile: Profile): string | null =>
    !canManage && profile.backend !== "none"
      ? t("profiles.modeManagedOnly")
      : null;

  const onConnect = async (profile: Profile) => {
    if (connectLockedTitle(profile)) return;
    if (requiresElevation(profile)) {
      try {
        if (!(await ensureElevation(t("profiles.connecting", { name: profile.name })))) return;
      } catch (err) {
        toast("error", String(err));
        return;
      }
    }
    withBusy(profile.id, async () => {
      const status = await invoke<TunnelStatus>("connect_profile", {
        id: profile.id,
      });
      if (status.state === "failed") {
        toast(
          "error",
          status.message ??
            t("profiles.connectFailedDiag", { name: profile.name }),
        );
      } else {
        setLastProfileId(profile.id);
        if (status.message) toast("info", status.message);
      }
    }, (err) => {
      if (caps?.os === "linux" && profile.backend === "openVpn" && String(err) === "OpenVPN credentials required") {
        setOpenVpnCredentialProfile(profile);
      } else {
        toast("error", String(err));
      }
    });
  };

  const onDisconnect = async (profile: Profile) => {
    if (requiresElevation(profile)) {
      try {
        if (!(await ensureElevation(t("profiles.disconnecting", { name: profile.name })))) return;
      } catch (err) {
        toast("error", String(err));
        return;
      }
    }
    withBusy(profile.id, () =>
      invoke("disconnect_profile", { id: profile.id }),
      (err) => toast("error", String(err)),
    );
  };

  const onDiagnose = async (profile: Profile) => {
    setDiagBusy(profile.id);
    try {
      const result = await invoke<ProfileDiagnostics>("diagnose_profile", {
        id: profile.id,
      });
      setDiagnostics(result);
      setDiagOpen(true);
    } catch (err) {
      setError(String(err));
    } finally {
      setDiagBusy(null);
    }
  };

  const onDelete = async (profile: Profile) => {
    if (alwaysOn?.profiles.some((item) => item.profileId === profile.id)) {
      setError(t("profiles.disableAlwaysOnDelete"));
      return;
    }
    const ok = await confirm(t("profiles.deleteConfirm", { name: profile.name }), {
      title: t("profiles.deleteTitle"),
      kind: "warning",
    });
    if (!ok) return;
    withBusy(profile.id, () =>
      invoke("delete_profile", { id: profile.id }),
    );
  };

  /** Switching a running profile reconnects it on the new server. */
  const onSwitchEndpoint = async (profile: Profile, key: string) => {
    const wasRunning = statusFor(profile.id).state === "running";
    if (wasRunning && requiresElevation(profile)) {
      try {
        if (!(await ensureElevation(t("profiles.connecting", { name: profile.name })))) return;
      } catch (err) {
        toast("error", String(err));
        return;
      }
    }
    setSwitching(profile.id);
    try {
      if (wasRunning) {
        await invoke("disconnect_profile", { id: profile.id });
      }
      const updated = await invoke<Profile[]>("switch_subscription_endpoint", {
        profileId: profile.id,
        endpointKey: key,
      });
      setProfiles(updated);
      const next: Record<string, SubscriptionEndpointInfo[]> = {};
      for (const p of updated.filter((p) => p.subscription !== null)) {
        try {
          next[p.id] = await invoke<SubscriptionEndpointInfo[]>(
            "get_subscription_endpoints",
            { profileId: p.id },
          );
        } catch {
          // ignore
        }
      }
      setEndpoints(next);
      if (wasRunning) {
        const status = await invoke<TunnelStatus>("connect_profile", {
          id: profile.id,
        });
        if (status.state === "failed") {
          toast(
            "error",
            status.message ??
              t("profiles.connectFailedDiag", { name: profile.name }),
          );
        }
      }
    } catch (err) {
      setError(String(err));
    } finally {
      setSwitching(null);
      await refreshAll();
    }
  };

  /** Failover edits land in the profile at once; a running tunnel picks them
   * up on reconnect, so keep a persistent notice until it stops. */
  const [failoverBusy, setFailoverBusy] = useState<string | null>(null);
  const [applyOnReconnect, setApplyOnReconnect] = useState<Set<string>>(new Set());

  useEffect(() => {
    setApplyOnReconnect((current) => {
      if (current.size === 0) return current;
      const next = new Set([...current].filter((id) => statusFor(id).state === "running"));
      return next.size === current.size ? current : next;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [statuses]);

  const acceptPolicyProfiles = async (profileId: string, updated: Profile[]) => {
    setProfiles(updated);
    const fresh = await refreshAll();
    if (!fresh) throw new Error(t("The change was saved, but refreshing the displayed profile or endpoints failed. Refresh the profile before making another change."));
    if (fresh.some((profile) => profile.id === profileId && profile.subscription)) {
      const list = await invoke<SubscriptionEndpointInfo[]>(
        "get_subscription_endpoints", { profileId },
      );
      setEndpoints((current) => ({ ...current, [profileId]: list }));
    }
  };

  const saveFailover = async (
    profile: Profile,
    command: string,
    args: Record<string, unknown>,
  ) => {
    setFailoverBusy(profile.id);
    try {
      const updated = await invoke<Profile[]>(command, {
        profileId: profile.id,
        ...args,
      });
      setProfiles(updated);
      if (statusFor(profile.id).state === "running") {
        setApplyOnReconnect((current) => new Set(current).add(profile.id));
      }
      try {
        const list = await invoke<SubscriptionEndpointInfo[]>(
          "get_subscription_endpoints",
          { profileId: profile.id },
        );
        setEndpoints((current) => ({ ...current, [profile.id]: list }));
      } catch {
        // The badge flags refresh with the next endpoint read.
      }
    } catch (err) {
      setError(String(err));
    } finally {
      setFailoverBusy(null);
    }
  };

  const onSetBackups = (profile: Profile, keys: string[]) =>
    saveFailover(profile, "set_subscription_backups", { backupKeys: keys });
  const onSetAutoReturn = (profile: Profile, enabled: boolean) =>
    saveFailover(profile, "set_subscription_auto_return", { enabled });
  const onSetPinnedRoutes = (profile: Profile, routes: Profile["pinnedPolicies"]) =>
    saveFailover(profile, "set_pinned_routes", { routes });

  const onRefreshSubscription = async (profile: Profile) => {
    setRefreshingSubscription(profile.id);
    try {
      const result = await invoke<SubscriptionRefreshResult>("refresh_subscription", {
        id: profile.id,
      });
      await refreshAll();
      const updated = await invoke<SubscriptionEndpointInfo[]>(
        "get_subscription_endpoints",
        { profileId: profile.id },
      );
      setEndpoints((current) => ({ ...current, [profile.id]: updated }));
      setDelayResults((current) => {
        const next = { ...current };
        delete next[profile.id];
        return next;
      });
      const details = [
        t("profiles.subRefreshed", { count: result.endpointCount }),
      ];
      if (result.skippedCount > 0) details.push(t("profiles.subSkipped", { n: result.skippedCount }));
      if (result.fallbackUsed) details.push(t("profiles.subFallback"));
      if (result.cleanupFailed) details.push(t("profiles.subCleanupFailed"));
      toast("info", details.join(" "));
    } catch (err) {
      setError(String(err));
    } finally {
      setRefreshingSubscription(null);
    }
  };

  const onSetRefreshInterval = async (profile: Profile, minutes: number | null) => {
    setSettingRefreshInterval(profile.id);
    try {
      const updated = await invoke<Profile[]>("set_subscription_refresh_interval", {
        profileId: profile.id,
        refreshIntervalMinutes: minutes,
      });
      setProfiles(updated);
    } catch {
      setError(t("profiles.refreshIntervalFailed"));
    } finally {
      setSettingRefreshInterval(null);
    }
  };

  const onMeasureEndpoint = async (profile: Profile, index: number) => {
    const key = `${profile.id}:${index}`;
    setMeasuringEndpoints((prev) => new Set(prev).add(key));
    try {
      const result = await invoke<SubscriptionDelayResult>(
        "measure_subscription_endpoint_delay",
        { profileId: profile.id, endpointIndex: index },
      );
      setDelayResults((current) => ({
        ...current,
        [profile.id]: { ...(current[profile.id] ?? {}), [index]: result },
      }));
    } catch {
      setDelayResults((current) => ({
        ...current,
        [profile.id]: {
          ...(current[profile.id] ?? {}),
          [index]: { delayMs: null, error: t("profiles.delayCheckFailed") },
        },
      }));
    } finally {
      setMeasuringEndpoints((prev) => {
        const next = new Set(prev);
        next.delete(key);
        return next;
      });
    }
  };

  /** Rolling pool: up to eight probes in flight, the next one starts as soon
   * as any finishes, so one slow server never holds the rest back. */
  const onMeasureAllEndpoints = async (profile: Profile) => {
    const list = endpoints[profile.id] ?? [];
    if (list.length === 0) return;
    setMeasuringAll((prev) => new Set(prev).add(profile.id));
    setDelayResults((current) => ({ ...current, [profile.id]: {} }));
    try {
      const POOL = 8;
      let next = 0;
      const worker = async () => {
        while (next < list.length) {
          const index = next++;
          await onMeasureEndpoint(profile, index);
        }
      };
      await Promise.all(
        Array.from({ length: Math.min(POOL, list.length) }, worker),
      );
    } finally {
      setMeasuringAll((prev) => {
        const next = new Set(prev);
        next.delete(profile.id);
        return next;
      });
    }
  };

  /** Copy shell proxy exports for a running Xray SOCKS/HTTP profile —
   * same format as the macOS client's "Copy terminal proxy". */
  const onCopyTerminalProxy = async (profile: Profile) => {
    const socks = profile.xraySocksPort;
    if (profile.backend !== "xray" || socks === null) return;
    const http =
      profile.xrayHttpPort !== null
        ? `http://127.0.0.1:${profile.xrayHttpPort}`
        : `socks5h://127.0.0.1:${socks}`;
    const text = `export HTTP_PROXY=${http} HTTPS_PROXY=${http} ALL_PROXY=socks5h://127.0.0.1:${socks} NO_PROXY=localhost,127.0.0.1,.local`;
    try {
      await navigator.clipboard.writeText(text);
      toast("success", t("native.copied"));
    } catch {
      toast("error", t("native.copyFailed"));
    }
  };

  const withSnippetAction = async (action: () => Promise<void>) => {
    if (snippetsBusy.current) return;
    snippetsBusy.current = true;
    try {
      await action();
      if (snippetsMounted.current) await refreshSnippets();
    } catch (err) {
      if (snippetsMounted.current && !(err instanceof DOMException && err.name === "AbortError")) toast("error", String(err));
    } finally {
      snippetsBusy.current = false;
      if (snippetsMounted.current) await refreshAll();
    }
  };

  const applySnippet = async (snippet: ConnectionSnippet) => {
    await withSnippetAction(async () => {
      try {
        setCredentialInputs.current = Object.create(null) as Record<string, ConnectionSetCredentialInput>;
        const changed = profiles.filter((profile) => snippet.profileIds.includes(profile.id) !== (statusFor(profile.id).state === "running"));
        for (const profile of changed.filter((profile) => snippet.profileIds.includes(profile.id))) {
          const locked = connectLockedTitle(profile);
          if (locked) throw new Error(locked);
        }
        if (changed.some(requiresElevation) && !(await ensureElevation(t("iface.elevationState")))) return;
        if (caps?.os === "linux") {
          for (;;) {
            if (!snippetsMounted.current) throw new DOMException("Credential collection cancelled", "AbortError");
            try {
              await applySavedSnippet(snippet.id, setCredentialInputs.current);
              break;
            } catch (error) {
              if (!snippetsMounted.current) throw new DOMException("Credential collection cancelled", "AbortError");
              const message = error instanceof Error ? error.message : String(error);
              const missing = /^OpenVPN credentials required: ([A-Za-z0-9_.-]{1,128})$/.exec(message);
              if (!missing || setCredentialInputs.current[missing[1]]) throw error;
              const profile = profiles.find((item) => item.id === missing[1] && item.backend === "openVpn");
              if (!profile) throw error;
              // The ES2020/WebKit target does not provide Promise.withResolvers.
              const input = await new Promise<ConnectionSetCredentialInput>((resolve, reject) => {
                setCredentialCollector.current = { profileId: profile.id, resolve, reject };
                setOpenVpnCredentialProfile(profile);
              });
              if (!snippetsMounted.current) throw new DOMException("Credential collection cancelled", "AbortError");
              setCredentialInputs.current[profile.id] = input;
            }
          }
        } else {
          const target = new Set(snippet.profileIds);
          const missing = snippet.profileIds.filter((id) => !profiles.some((profile) => profile.id === id));
          if (missing.length) throw new Error(`${t("backend.missing")}: ${missing.join(", ")}`);
          const current = await invoke<TunnelStatus[]>("get_tunnel_statuses");
          for (const profile of profiles) {
            const status = current.find((item) => item.profileId === profile.id);
            if (!status || status.state === "failed") throw new Error(status?.message ?? t("backend.missing"));
            const locked = target.has(profile.id) && status.state !== "running" ? connectLockedTitle(profile) : null;
            if (locked) throw new Error(locked);
          }
          for (const profile of profiles) {
            const running = current.some((status) => status.profileId === profile.id && status.state === "running");
            if (running && !target.has(profile.id)) await invoke("disconnect_profile", { id: profile.id });
          }
          for (const profile of profiles) {
            const running = current.some((status) => status.profileId === profile.id && status.state === "running");
            if (target.has(profile.id) && !running) {
              const status = await invoke<TunnelStatus>("connect_profile", { id: profile.id });
              if (status.state !== "running") throw new Error(status.message ?? t("profiles.connectFailedDiag", { name: profile.name }));
            }
          }
        }
        if (snippetsMounted.current) setActiveSnippetId(snippet.id);
      } finally {
        clearSetCredentials();
        if (snippetsMounted.current) setOpenVpnCredentialProfile(null);
      }
    });
  };

  const deleteSnippet = async (id: string) => {
    await withSnippetAction(async () => {
      await deleteSavedSnippet(id, caps?.os === "linux");
      setActiveSnippetId((prev) => (prev === id ? null : prev));
    });
  };

  const openSaveModal = () => {
    setNewSnippetName("");
    setSaveModalOpen(true);
  };

  const overwriteActiveSnippet = async () => {
    const active = snippets.find((snippet) => snippet.id === activeSnippetId);
    if (!active) return;
    await withSnippetAction(async () => {
      await captureSnippet(active.id, active.name, caps?.os === "linux", runningProfiles.map((profile) => profile.id));
      setSaveModalOpen(false);
    });
  };

  const createSnippet = async () => {
    const name = newSnippetName.trim();
    if (!name) return;
    await withSnippetAction(async () => {
      const saved = await captureSnippet(newSnippetId(), name, caps?.os === "linux", runningProfiles.map((profile) => profile.id));
      setActiveSnippetId(saved.id);
      setSaveModalOpen(false);
    });
  };

  const openNew = (backend?: TunnelBackend) => {
    setEditing(newFormState(backend, caps?.os));
    setFormOpen(true);
  };

  const handleChooseImport = () => {
    setAddMenuOpen(false);
    setImportOpen(true);
  };

  const handleChooseBackend = (backend: TunnelBackend) => {
    setAddMenuOpen(false);
    openNew(backend);
  };

  const openEdit = async (profile: Profile) => {
    if (alwaysOn?.profiles.some((item) => item.profileId === profile.id)) {
      setError(t("profiles.disableAlwaysOnEdit"));
      return;
    }
    try {
      const editable = await invoke<{ profile: Profile; revision: string }>("get_profile_for_edit", { id: profile.id });
      setEditing(editFormState(editable.profile, editable.revision));
      setFormOpen(true);
    } catch (err) {
      setError(String(err));
    }
  };

  const onToggleAlwaysOn = async (profile: Profile, kind: AlwaysOnKind, enrolled: boolean) => {
    if (!enrolled && kind === "wireGuard") {
      const approved = await confirm(
        t("profiles.alwaysOnConfirm"),
        { title: t("profiles.alwaysOnTitle"), kind: "warning" },
      );
      if (!approved) return;
    }
    await withBusy(profile.id, async () => {
      if (enrolled) {
        await invoke("remove_always_on_profile", { kind, profileId: profile.id });
      } else {
        const result = await invoke<AlwaysOnSetResult>("set_always_on_profile", { id: profile.id });
        if (!result.active) toast("info", t("profiles.alwaysOnSaved"));
      }
    });
  };

  const onResumeAlwaysOn = async () => {
    setResumingAlwaysOn(true);
    try {
      await invoke("resume_always_on");
      await refreshAll();
    } catch (err) {
      setError(String(err));
    } finally {
      setResumingAlwaysOn(false);
    }
  };

  const onFormSaved = (
    updated: Profile[],
    inspection: ProfileInspection | null,
  ) => {
    setProfiles(updated);
    setFormOpen(false);
    setEditing(null);
    setError(null);
    void refreshAll();
    // A running Xray TUN profile picks up its new rules in place; the daemon
    // rejects reload when kernel-level fields changed, and a manual reconnect
    // stays as the fallback.
    if (
      editing &&
      !editing.isNew &&
      editing.backend === "xray" &&
      editing.xrayMode === "tun" &&
      statusFor(editing.id).state === "running"
    ) {
      invoke<TunnelStatus>("reload_xray_profile", { id: editing.id })
        .then((status) => {
          setStatuses((current) => [
            ...current.filter((entry) => entry.profileId !== status.profileId),
            status,
          ]);
          toast(
            status.message ? "info" : "success",
            status.message ??
              t("profiles.reloaded", { name: editing.name || editing.id }),
          );
        })
        .catch((err) =>
          toast("info", t("profiles.reloadReconnect", { err: String(err) })),
        );
    }
    if (inspection && editing) {
      const notes = [
        ...inspection.analysis.warnings,
        ...inspection.conflicts.map((c) => c.message),
      ];
      setSaveNotice(
        notes.length > 0
          ? {
              profileName:
                updated.find((profile) => profile.id === editing.id)?.name ||
                editing.name ||
                editing.id,
              inspection,
            }
          : null,
      );
    }
  };

  const onImported = (result: BatchImportResult) => {
    setProfiles(result.profiles);
    setImportOpen(false);
    void refreshAll();
    if (result.errors.length > 0) {
      setImportErrors(result.errors.map((e) => `${e.path}: ${e.error}`));
    }
  };

  if (loading) {
    return (
      <Page width="full">
        <div className="profiles-toolbar">
          <h2>{t("profiles.title")}</h2>
        </div>
        <div
          className="profiles-layout"
          style={{ "--profiles-list-w": `${listWidth}px` } as React.CSSProperties}
        >
          <div className="profiles-list-pane">
            <ProfileRowSkeleton />
            <ProfileRowSkeleton />
            <ProfileRowSkeleton />
          </div>
          <div className="pane-splitter" aria-hidden="true" />
          <div className="profiles-detail-pane" />
        </div>
      </Page>
    );
  }

  const runningProfiles = profiles.filter(
    (p) => statusFor(p.id).state === "running",
  );

  const activeSnippet = snippets.find((s) => s.id === activeSnippetId) ?? null;
  const isActiveSnippetDirty =
    activeSnippet !== null &&
    !sameIds(
      activeSnippet.profileIds,
      runningProfiles.map((p) => p.id),
    );

  const lowerSearch = search.trim().toLowerCase();
  const filteredProfiles = lowerSearch
    ? profiles.filter(
        (p) =>
          p.name.toLowerCase().includes(lowerSearch) ||
          p.interfaceName.toLowerCase().includes(lowerSearch),
      )
    : profiles;

  const groups: ProfileGroup[] = (
    ["wireGuard", "openVpn", "xray", "none"] as TunnelBackend[]
  )
    .map((backend) => ({
      backend,
      items: filteredProfiles.filter((p) => p.backend === backend),
    }))
    .filter((g) => g.items.length > 0);

  const failedCount = profiles.filter(
    (p) => statusFor(p.id).state === "failed",
  ).length;

  const selected =
    (selectedId ? profiles.find((p) => p.id === selectedId) : undefined) ??
    runningProfiles[0] ??
    filteredProfiles[0] ??
    profiles[0] ??
    null;

  // Tunnel-kind interfaces that no running managed tunnel owns — raised by
  // wg-quick, other VPN apps, etc. tailscaled has its own service row.
  const isTailscaleIface = (i: NetworkInterface) =>
    i.name.toLowerCase().startsWith("tailscale") ||
    (typeof i.kind === "object" && i.kind.other === "Tailscale");
  const isTunnelIface = (i: NetworkInterface) => i.category === "vpn";
  const managedIfaces = new Set(
    profiles
      .filter((p) => statusFor(p.id).state === "running")
      .flatMap((p) => [p.interfaceName, statusFor(p.id).interfaceName ?? ""])
      .filter((name) => name !== ""),
  );
  // Interfaces already owned by a NetworkManager connection live in the NM
  // group — showing them under "detected" too would list the same tunnel
  // twice.
  const nmIfaces = new Set(
    (nm?.connections ?? [])
      .map((c) => c.interfaceName)
      .filter((n): n is string => n !== null),
  );
  const externalTunnels = interfaces.filter(
    (i) =>
      isTunnelIface(i) &&
      !isTailscaleIface(i) &&
      !managedIfaces.has(i.name) &&
      !managedIfaces.has(i.friendlyName) &&
      !nmIfaces.has(i.name) &&
      !nmIfaces.has(i.friendlyName),
  );
  const externalNames = new Set(
    externalTunnels.flatMap((i) => [i.name, i.friendlyName]),
  );
  // A profile we cannot bring up because its interface is already occupied
  // by a tunnel managed elsewhere.
  const ifaceConflictIds = new Set(
    profiles
      .filter(
        (p) =>
          p.interfaceName !== "" &&
          statusFor(p.id).state !== "running" &&
          externalNames.has(p.interfaceName),
      )
      .map((p) => p.id),
  );
  const externalSelected =
    externalTunnels.find((i) => i.name === externalName) ?? null;
  const nmSelectedConn =
    nm?.connections.find((c) => c.uuid === nmSelected) ?? null;
  const proxySelectedObj =
    proxies.find((p) => `${p.address}:${p.port}` === proxySelected) ?? null;

  const tsRunning =
    tailscale !== null &&
    tailscale.available &&
    tailscale.backendState === "Running";
  const tsNeedsLogin = tailscale?.backendState === "NeedsLogin";

  const selGroup = selected
    ? groups.find((g) => g.backend === selected.backend)
    : undefined;
  const selIndex =
    selGroup && selected
      ? selGroup.items.findIndex((p) => p.id === selected.id)
      : -1;
  const canMove = Boolean(
    listMode === "grouped" &&
    !lowerSearch &&
    selGroup &&
    selIndex >= 0 &&
    selGroup.items.length > 1,
  );

  const stateRank = (state: TunnelStatus["state"]) =>
    state === "running" ? 0 : state === "failed" ? 1 : 2;
  const flatList =
    listMode === "flat"
      ? [...filteredProfiles].sort(
          (a, b) =>
            stateRank(statusFor(a.id).state) -
              stateRank(statusFor(b.id).state) ||
            a.name.localeCompare(b.name),
        )
      : [];

  /** Row context-menu items — shared by the native Tauri menu and the DOM
   * fallback used in the browser sandbox. */
  const profileMenuItems = (p: Profile): MenuEntry[] => {
    const ctxGroup =
      listMode === "grouped" && !lowerSearch
        ? groups.find(
            (g) =>
              g.backend === p.backend &&
              g.items.some((item) => item.id === p.id),
          )
        : undefined;
    const ctxIndex = ctxGroup
      ? ctxGroup.items.findIndex((item) => item.id === p.id)
      : -1;
    const running = statusFor(p.id).state === "running";
    return [
      {
        label: running ? t("common.disconnect") : t("common.connect"),
        onClick: () =>
          running ? void onDisconnect(p) : void onConnect(p),
        disabled: busy.has(p.id) || (!running && connectLockedTitle(p) !== null),
      },
      {
        label: t("common.edit"),
        onClick: () => openEdit(p),
        disabled: busy.has(p.id),
      },
      {
        label: t("detail.diagnostics"),
        onClick: () => void onDiagnose(p),
        disabled: diagBusy === p.id,
      },
      "separator",
      {
        label: t("detail.moveUp"),
        onClick: () =>
          ctxGroup && moveProfileInGroup(ctxGroup.items, p.id, -1),
        disabled: !ctxGroup || ctxIndex <= 0,
      },
      {
        label: t("detail.moveDown"),
        onClick: () =>
          ctxGroup && moveProfileInGroup(ctxGroup.items, p.id, 1),
        disabled:
          !ctxGroup || ctxIndex < 0 || ctxIndex >= ctxGroup.items.length - 1,
      },
      "separator",
      {
        label: t("common.delete"),
        onClick: () => void onDelete(p),
        disabled: busy.has(p.id),
        danger: true,
      },
    ];
  };

  const renderProfileRow = (
    profile: Profile,
    group: ProfileGroup | null,
    canReorder: boolean,
  ) => {
    const status = statusFor(profile.id);
    const isBusy = busy.has(profile.id);
    const rate = status.state === "running" ? rateFor(profile) : null;
    const endpointList = endpoints[profile.id];
    const activeEndpointIdx =
      endpointList?.findIndex((e) => e.active) ?? -1;
    const endpointDisplay = endpointList
      ? providerPrefix(endpointList.map((e) => e.name))
      : null;
    const serverName =
      activeEndpointIdx >= 0 && endpointDisplay
        ? endpointDisplay.names[activeEndpointIdx]
        : null;
    const delayRes =
      activeEndpointIdx >= 0
        ? delayResults[profile.id]?.[activeEndpointIdx]
        : undefined;
    return (
      <ProfileRow
        key={profile.id}
        profile={profile}
        status={status}
        rate={rate}
        delayText={
          !profile.subscription
            ? null
            : activeEndpointIdx >= 0 &&
                measuringEndpoints.has(
                  `${profile.id}:${activeEndpointIdx}`,
                )
              ? "…"
              : delayRes
                ? delayRes.delayMs !== null
                  ? t("detail.delayMs", { ms: delayRes.delayMs })
                  : t("detail.unreachable")
                : null
        }
        isBusy={isBusy}
        serverName={serverName}
        conflict={ifaceConflictIds.has(profile.id)}
        connectLockedTitle={connectLockedTitle(profile)}
        selected={externalName === null && selected?.id === profile.id}
        dragging={dragState?.profileId === profile.id}
        showBackendBadge={group === null}
        dropBefore={
          dropTarget?.profileId === profile.id && dropTarget.before
        }
        dropAfter={
          dropTarget?.profileId === profile.id && !dropTarget.before
        }
        canReorder={canReorder}
        onSelect={() => {
          setServiceSelected(false);
          setExternalName(null);
          setNmSelected(null);
          setProxySelected(null);
          setSelectedId(profile.id);
        }}
        onToggle={() =>
          status.state === "running"
            ? void onDisconnect(profile)
            : void onConnect(profile)
        }
        onContextMenu={(e) => {
          e.preventDefault();
          setServiceSelected(false);
          setExternalName(null);
          setNmSelected(null);
          setProxySelected(null);
          setSelectedId(profile.id);
          const items = profileMenuItems(profile);
          void popupNativeMenu(items, e.clientX, e.clientY).then(
            (native) => {
              if (!native)
                setCtxMenu({ x: e.clientX, y: e.clientY, items });
            },
          );
        }}
        onDragStart={(event) => onCardDragStart(event, profile)}
        onDragEnd={onCardDragEnd}
        onDragOver={(event) =>
          group && onCardDragOver(event, group, profile)
        }
        onDrop={(event) => group && onCardDrop(event, group, profile)}
      />
    );
  };

  return (
    <Page width="full">
      <div className="profiles-toolbar">
        <h2>{t("profiles.title")}</h2>
        {failedCount > 0 && (
          <span className="profiles-status profiles-status-failed">
            <span className="status-dot state-failed" />
            {t("profiles.failedSuffix", { n: failedCount })}
          </span>
        )}
        <span
          className="profiles-info"
          role="note"
          title={
            t("profiles.infoElev") +
            (caps?.os === "linux"
              ? `\n\n${t("profiles.infoAlwaysOn")}`
              : "")
          }
        >
          <InfoIcon size={15} />
        </span>
        <div className="toolbar-actions">
          {profiles.length > 0 && (
            <input
              className="filter-search connections-search"
              type="text"
              placeholder={t("profiles.searchPh")}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          )}
          <button
            className="btn-sm btn-with-icon"
            onClick={() => setImportOpen(true)}
          >
            {t("profiles.import")}
          </button>
          <button
            className="btn-primary btn-sm btn-with-icon"
            onClick={() => setAddMenuOpen(true)}
          >
            <PlusIcon size={13} /> {t("profiles.add")}
          </button>
        </div>
      </div>
      {caps?.os === "linux" && alwaysOn?.paused && (
        <div className="runtime-notice" role="status">
          <span>{t("profiles.alwaysOnPaused")}</span>
          <button type="button" onClick={onResumeAlwaysOn} disabled={resumingAlwaysOn}>
            {resumingAlwaysOn ? t("profiles.resuming") : t("profiles.resume")}
          </button>
        </div>
      )}

      {importErrors && (
        <div className="save-notice">
          <div className="diagnostics-head">
            <span>{t("profiles.importErrors")}</span>
            <button type="button" onClick={() => setImportErrors(null)}>
              {t("common.dismiss")}
            </button>
          </div>
          <ul className="save-notice-list">
            {importErrors.map((e, i) => (
              <li key={i}>{e}</li>
            ))}
          </ul>
        </div>
      )}

      {error && <p className="error">{error}</p>}

      {saveNotice && (
        <div className="save-notice">
          <div className="diagnostics-head">
            <span>{t("profiles.savedNotice", { name: saveNotice.profileName })}</span>
            <button type="button" onClick={() => setSaveNotice(null)}>
              {t("common.dismiss")}
            </button>
          </div>
          <ul className="save-notice-list">
            {saveNotice.inspection.analysis.warnings.map((w, i) => (
              <li key={`w${i}`}>{w}</li>
            ))}
            {saveNotice.inspection.conflicts.map((c, i) => (
              <li key={`c${i}`}>{c.message}</li>
            ))}
          </ul>
        </div>
      )}

      <div
        ref={layoutRef}
        className="profiles-layout"
        style={{ "--profiles-list-w": `${listWidth}px` } as React.CSSProperties}
      >
        <div
          className="profiles-list-pane"
          onKeyDown={(event) => {
            if (event.target instanceof HTMLElement) {
              const t = event.target;
              if (t.closest("input, select, textarea, [role='switch'], .snippet-chip")) return;
            }
            const visibleIds = (
              listMode === "flat"
                ? flatList
                : groups.flatMap((g) =>
                    collapsedGroups.has(g.backend) ? [] : g.items,
                  )
            ).map((p) => p.id);
            if (event.key === "ArrowDown" || event.key === "ArrowUp") {
              event.preventDefault();
              const idx = visibleIds.indexOf(selectedId ?? "");
              const next =
                idx < 0
                  ? 0
                  : Math.min(
                      visibleIds.length - 1,
                      Math.max(0, idx + (event.key === "ArrowDown" ? 1 : -1)),
                    );
              const id = visibleIds[next];
              if (!id) return;
              setServiceSelected(false);
              setExternalName(null);
              setNmSelected(null);
              setProxySelected(null);
              setSelectedId(id);
              document
                .querySelector(`[data-profile-id="${id}"]`)
                ?.scrollIntoView({ block: "nearest" });
            } else if (event.key === "Delete" && selected) {
              void onDelete(selected);
            }
          }}
        >
          {(profiles.length > 0 || snippets.length > 0) && (
            <SetsBar
              snippets={snippets.map((snippet) => {
                const missing = snippet.profileIds.filter((id) => !profiles.some((profile) => profile.id === id));
                return missing.length ? { ...snippet, name: `${snippet.name} (${t("backend.missing")}: ${missing.join(", ")})` } : snippet;
              })}
              activeSnippetId={activeSnippetId}
              activeDirty={isActiveSnippetDirty}
              runningCount={runningProfiles.length}
              onApply={applySnippet}
              onDelete={deleteSnippet}
              onUpdateActive={overwriteActiveSnippet}
              onSaveNew={openSaveModal}
            />
          )}

      {profiles.length === 0 ? (
        <p className="empty-state">{t("profiles.empty")}</p>
      ) : filteredProfiles.length === 0 ? (
        <p className="empty-state">{t("profiles.noMatch", { query: search })}</p>
      ) : listMode === "flat" ? (
        <div className="profile-rows">
          {flatList.map((profile) => renderProfileRow(profile, null, false))}
        </div>
      ) : (
        groups.map((group) => {
          const isCollapsed = collapsedGroups.has(group.backend);
          const canReorder = !lowerSearch && group.items.length > 1;
          return (
          <div key={group.backend} className="profile-group">
            <button
              type="button"
              className="profile-group-header"
              onClick={() => toggleGroupCollapsed(group.backend)}
              aria-expanded={!isCollapsed}
            >
              <ChevronIcon size={13} collapsed={isCollapsed} />
              <span className={`backend-avatar-${group.backend}`}>
                {backendIcon(group.backend, 18)}
              </span>
              <span className="profile-group-title">
                {t(BACKEND_LABEL_KEYS[group.backend])}
              </span>
              <span className="profile-group-count">
                {group.items.length}
              </span>
            </button>
            {!isCollapsed && (
            <div className="profile-rows" onDragLeave={onListDragLeave}>
              {group.items.map((profile) =>
                renderProfileRow(profile, group, canReorder),
              )}
            </div>
            )}
          </div>
          );
        })
      )}

      {(tailscale !== null || netbird.state?.installed) && (
        <div className="profile-group">
          <div className="profile-group-label">{t("profiles.services")}</div>
          <div className="profile-rows">
            {tailscale !== null && (
            <div
              role="button"
              tabIndex={0}
              className={`profile-row${serviceSelected ? " selected" : ""}`}
              onClick={() => {
                setExternalName(null);
                setNmSelected(null);
                setProxySelected(null);
                setServiceSelected(true);
              }}
              onKeyDown={(e) => {
                if (e.target !== e.currentTarget) return;
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  setExternalName(null);
                  setNmSelected(null);
                  setProxySelected(null);
                  setServiceSelected(true);
                }
              }}
            >
              <span
                className={`status-dot state-${
                  tsRunning
                    ? "running"
                    : tailscale.available
                      ? "stopped"
                      : "unknown"
                }`}
              />
              <span className="backend-avatar backend-avatar-service">
                <TailscaleIcon size={14} />
              </span>
              <span className="profile-row-name">Tailscale</span>
              <ToggleSwitch
                checked={tsRunning}
                onChange={() => void onToggleTailscale()}
                disabled={
                  !tailscale.available || tsNeedsLogin || tailscaleBusy
                }
                busy={tailscaleBusy}
                title={
                  !tailscale.available
                    ? t("ts.notInstalled")
                    : tsNeedsLogin
                      ? t("ts.loginFirst")
                      : tsRunning
                        ? t("ts.down")
                        : t("ts.up")
                }
              />
            </div>
            )}
            <NetBirdRow netbird={netbird} />
          </div>
        </div>
      )}

      {externalTunnels.length > 0 && (
        <div className="profile-group">
          <div className="profile-group-label">{t("profiles.external")}</div>
          <div className="profile-rows">
            {externalTunnels.map((iface) => (
              <div
                key={iface.name}
                role="button"
                tabIndex={0}
                className={`profile-row profile-row-external${
                  externalName === iface.name ? " selected" : ""
                }`}
                onClick={() => {
                  setServiceSelected(false);
                  setSelectedId(null);
                  setNmSelected(null);
                  setProxySelected(null);
                  setExternalName(iface.name);
                }}
                onKeyDown={(e) => {
                  if (e.target !== e.currentTarget) return;
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    setServiceSelected(false);
                    setSelectedId(null);
                    setNmSelected(null);
                    setProxySelected(null);
                    setExternalName(iface.name);
                  }
                }}
              >
                <span
                  className={`status-dot state-${
                    iface.state === "up" ? "running" : "stopped"
                  }`}
                />
                <span
                  className={`backend-avatar ${backendAvatarClass(iface.kind)}`}
                >
                  {kindIcon(iface.kind, 14)}
                </span>
                <span className="profile-row-name">{iface.name}</span>
                <span className="badge badge-external">
                  {t("detail.external")}
                </span>
                <ToggleSwitch
                  checked={iface.state === "up"}
                  onChange={() => void onToggleExternal(iface)}
                  disabled={externalBusy === iface.name}
                  busy={externalBusy === iface.name}
                  title={
                    iface.state === "up"
                      ? t("profiles.externalStop")
                      : t("iface.bringUp")
                  }
                />
              </div>
            ))}
          </div>
        </div>
      )}

      {nm !== null && (nm.connections.length > 0 || !nm.available) && (
        <div className="profile-group">
          <div className="profile-group-label">{t("profiles.nmGroup")}</div>
          {!nm.available ? (
            <p className="external-note">{t("profiles.nmUnavailable")}</p>
          ) : (
            <div className="profile-rows">
              {nm.connections.map((conn) => (
                <div
                  key={conn.uuid}
                  role="button"
                  tabIndex={0}
                  className={`profile-row profile-row-external${
                    nmSelected === conn.uuid ? " selected" : ""
                  }`}
                  onClick={() => {
                    setServiceSelected(false);
                    setSelectedId(null);
                    setExternalName(null);
                    setNmSelected(conn.uuid);
                    setProxySelected(null);
                  }}
                  onKeyDown={(e) => {
                    if (e.target !== e.currentTarget) return;
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      setServiceSelected(false);
                      setSelectedId(null);
                      setExternalName(null);
                      setNmSelected(conn.uuid);
                      setProxySelected(null);
                    }
                  }}
                >
                  <span
                    className={`status-dot state-${
                      conn.state === "active" ? "running" : "stopped"
                    }`}
                  />
                  <span
                    className={`backend-avatar ${nmAvatarClass(conn.kind)}`}
                  >
                    {nmIcon(conn.kind)}
                  </span>
                  <span className="profile-row-name">{conn.id}</span>
                  {conn.interfaceName && (
                    <span className="profile-row-server">
                      · {conn.interfaceName}
                    </span>
                  )}
                  <span className="badge badge-external">
                    {t("detail.external")}
                  </span>
                  {(conn.kind === "vpn" || conn.kind === "other") && (
                    <span className="badge badge-managed">{conn.kind}</span>
                  )}
                  <ToggleSwitch
                    checked={conn.state !== "inactive"}
                    onChange={() => void onToggleNm(conn)}
                    disabled={
                      nmBusy === conn.uuid || conn.state === "activating"
                    }
                    busy={
                      nmBusy === conn.uuid || conn.state === "activating"
                    }
                    title={
                      conn.state === "active"
                        ? t("common.disconnect")
                        : t("common.connect")
                    }
                  />
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {scanLocalProxies && proxies.length > 0 && (
        <div className="profile-group">
          <div className="profile-group-label">
            {t("profiles.localProxies")}
          </div>
          <div className="profile-rows">
            {proxies.map((p) => {
              const key = `${p.address}:${p.port}`;
              const select = () => {
                setServiceSelected(false);
                setSelectedId(null);
                setExternalName(null);
                setNmSelected(null);
                setProxySelected(key);
              };
              return (
                <div
                  key={key}
                  role="button"
                  tabIndex={0}
                  className={`profile-row profile-row-external${
                    proxySelected === key ? " selected" : ""
                  }`}
                  onClick={select}
                  onKeyDown={(e) => {
                    if (e.target !== e.currentTarget) return;
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      select();
                    }
                  }}
                >
                  <span className="status-dot state-running" />
                  <span className="backend-avatar backend-avatar-service">
                    <LoopbackIcon size={14} />
                  </span>
                  <span className="profile-row-name">
                    {p.address}:{p.port}
                  </span>
                  <span className="badge badge-external">{p.kind}</span>
                </div>
              );
            })}
          </div>
          <p className="external-note">{t("profiles.localProxiesHint")}</p>
        </div>
      )}
        </div>

        <div {...splitterProps} />

        <div className="profiles-detail-pane">
          {externalSelected ? (
            <ExternalTunnelPanel
              iface={externalSelected}
              rate={throughput[externalSelected.ifIndex] ?? null}
              busy={externalBusy === externalSelected.name}
              onToggle={() => void onToggleExternal(externalSelected)}
            />
          ) : nmSelectedConn ? (
            <NmConnectionPanel
              conn={nmSelectedConn}
              busy={nmBusy === nmSelectedConn.uuid}
              onToggle={() => void onToggleNm(nmSelectedConn)}
              avatarClass={nmAvatarClass(nmSelectedConn.kind)}
              icon={nmIcon(nmSelectedConn.kind)}
            />
          ) : proxySelectedObj ? (
            <LocalProxyPanel proxy={proxySelectedObj} />
          ) : serviceSelected && tailscale ? (
            <TailscalePanel
              status={tailscale}
              busy={tailscaleBusy}
              onToggle={() => void onToggleTailscale()}
            />
          ) : selected ? (
            <ProfileDetail
              key={selected.id}
              onPolicySaved={acceptPolicyProfiles}
              profile={selected}
              onRoleChanged={() => void refreshAll()}
              status={statusFor(selected.id)}
              rate={
                statusFor(selected.id).state === "running"
                  ? rateFor(selected)
                  : null
              }
              isBusy={busy.has(selected.id)}
              backendLabel={t(BACKEND_LABEL_KEYS[selected.backend])}
              managedConfig={inspections[selected.id]?.managedConfig}
              inspection={inspections[selected.id] ?? null}
              alwaysOn={alwaysOn}
              os={caps?.os}
              endpoints={endpoints[selected.id]}
              delayResults={delayResults[selected.id]}
              measuringEndpoints={measuringEndpoints}
              measuringAll={measuringAll.has(selected.id)}
              switching={switching === selected.id}
              refreshingSubscription={
                refreshingSubscription === selected.id
              }
              settingRefreshInterval={settingRefreshInterval === selected.id}
              diagBusy={diagBusy === selected.id}
              canMoveUp={canMove && selIndex > 0}
              canMoveDown={
                canMove && selIndex < (selGroup?.items.length ?? 0) - 1
              }
              onConnect={() => void onConnect(selected)}
              onDisconnect={() => void onDisconnect(selected)}
              onEdit={() => openEdit(selected)}
              onMoveUp={() =>
                selGroup &&
                moveProfileInGroup(selGroup.items, selected.id, -1)
              }
              onMoveDown={() =>
                selGroup &&
                moveProfileInGroup(selGroup.items, selected.id, 1)
              }
              onToggleAlwaysOn={(kind, enrolled) =>
                onToggleAlwaysOn(selected, kind, enrolled)
              }
              onCredentials={() => {
                setOpenVpnCredentialProfile(selected);
              }}
              onRefreshSubscription={() =>
                void onRefreshSubscription(selected)
              }
              onDiagnose={() => void onDiagnose(selected)}
              onDelete={() => void onDelete(selected)}
              onSwitchEndpoint={(key) =>
                void onSwitchEndpoint(selected, key)
              }
              failoverBusy={failoverBusy === selected.id}
              applyOnReconnect={applyOnReconnect.has(selected.id)}
              onSetBackups={(keys) => void onSetBackups(selected, keys)}
              onSetAutoReturn={(enabled) =>
                void onSetAutoReturn(selected, enabled)
              }
              onSetPinnedRoutes={(routes) =>
                void onSetPinnedRoutes(selected, routes)
              }
              onMeasureAllEndpoints={() =>
                void onMeasureAllEndpoints(selected)
              }
              onSetRefreshInterval={(minutes) =>
                void onSetRefreshInterval(selected, minutes)
              }
              onCopyTerminalProxy={() =>
                void onCopyTerminalProxy(selected)
              }
            />
          ) : (
            <div className="profile-detail-empty">
              {profiles.length === 0
                ? t("profiles.detailEmptyNone")
                : t("profiles.detailEmpty")}
            </div>
          )}
        </div>
      </div>

      <ProfileFormModal
        open={formOpen}
        editing={editing}
        interfaces={interfaces}
        onClose={() => {
          setFormOpen(false);
          setEditing(null);
        }}
        onSaved={onFormSaved}
        onError={(message) => setError(message)}
      />

      <ImportModal
        open={importOpen}
        onClose={() => setImportOpen(false)}
        onImported={onImported}
        onError={(message) => setError(message)}
      />

      <DiagnosticsModal
        open={diagOpen}
        diagnostics={diagnostics}
        profiles={profiles}
        onClose={() => {
          setDiagOpen(false);
          setDiagnostics(null);
        }}
      />

      <AddConnectionMenu
        open={addMenuOpen}
        onClose={() => setAddMenuOpen(false)}
        onChooseImport={handleChooseImport}
        onChooseBackend={handleChooseBackend}
        allowManaged={canManage}
      />

      {ctxMenu && (
        <ContextMenu
          x={ctxMenu.x}
          y={ctxMenu.y}
          onClose={() => setCtxMenu(null)}
          items={ctxMenu.items}
        />
      )}

      <OpenVpnCredentialsModal
        profile={openVpnCredentialProfile}
        onClose={() => {
          cancelSetCredentialCollection();
          setOpenVpnCredentialProfile(null);
        }}
        onSubmitCredentials={setCredentialCollector.current ? async (profile, credentials, remember) => {
          const pending = setCredentialCollector.current;
          if (!pending || pending.profileId !== profile.id) throw new DOMException("Credential collection cancelled", "AbortError");
          setCredentialCollector.current = null;
          setOpenVpnCredentialProfile(null);
          pending.resolve({ credentials, remember });
        } : undefined}
        onConnected={(profile, status) => {
          if (status.message) toast("info", status.message);
          setLastProfileId(profile.id);
          setOpenVpnCredentialProfile(null);
          void refreshAll();
        }}
      />

      <Modal
        open={saveModalOpen}
        title={t("sets.modalTitle")}
        onClose={() => setSaveModalOpen(false)}
        maxWidth="420px"
        footer={
          <>
            <button type="button" onClick={() => setSaveModalOpen(false)}>
              {t("common.cancel")}
            </button>
            <button
              type="button"
              className="btn-primary"
              onClick={createSnippet}
              disabled={!newSnippetName.trim()}
            >
              {t("sets.saveAsNew")}
            </button>
          </>
        }
      >
        <div className="interface-section">
          <span className="section-label">
            {t("sets.willInclude", { count: runningProfiles.length })}
          </span>
          <ul className="profile-route-list">
            {runningProfiles.map((p) => (
              <li key={p.id}>{p.name}</li>
            ))}
          </ul>
        </div>

        {activeSnippet && isActiveSnippetDirty && (
          <button
            type="button"
            className="snippet-overwrite-btn"
            onClick={overwriteActiveSnippet}
          >
            {t("sets.updateWith", { name: activeSnippet.name })}
          </button>
        )}

        <label>
          {activeSnippet ? t("sets.orSaveNew") : t("sets.name")}
          <input
            type="text"
            value={newSnippetName}
            onChange={(e) => setNewSnippetName(e.target.value)}
            placeholder={t("sets.namePh")}
            autoFocus
          />
        </label>
      </Modal>
    </Page>
  );
}

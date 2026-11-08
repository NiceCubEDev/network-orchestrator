import { useEffect, useState } from "react";

export type ProfileListMode = "grouped" | "flat";

const PROFILE_LIST_MODE_KEY = "netmanager.profiles.listMode";
const PREFS_EVENT = "ui-prefs-changed";

export function getProfileListMode(): ProfileListMode {
  try {
    return localStorage.getItem(PROFILE_LIST_MODE_KEY) === "flat"
      ? "flat"
      : "grouped";
  } catch {
    return "grouped";
  }
}

export function setProfileListMode(mode: ProfileListMode): void {
  try {
    localStorage.setItem(PROFILE_LIST_MODE_KEY, mode);
  } catch {
    // ignore storage errors (e.g. storage disabled)
  }
  window.dispatchEvent(new CustomEvent(PREFS_EVENT));
}

export function useProfileListMode(): ProfileListMode {
  const [mode, setMode] = useState<ProfileListMode>(getProfileListMode);
  useEffect(() => {
    const handler = () => setMode(getProfileListMode());
    window.addEventListener(PREFS_EVENT, handler);
    return () => window.removeEventListener(PREFS_EVENT, handler);
  }, []);
  return mode;
}

const ROUTES_HIDE_IPV6_KEY = "netmanager.routes.hideIpv6";
const ROUTES_INCLUDE_STOPPED_KEY = "netmanager.routes.includeStopped";

export interface RoutesPrefs {
  hideIpv6: boolean;
  includeStopped: boolean;
}

export function getRoutesPrefs(): RoutesPrefs {
  try {
    return {
      hideIpv6: localStorage.getItem(ROUTES_HIDE_IPV6_KEY) === "1",
      includeStopped:
        localStorage.getItem(ROUTES_INCLUDE_STOPPED_KEY) === "1",
    };
  } catch {
    return { hideIpv6: false, includeStopped: false };
  }
}

export function setRoutesPrefs(patch: Partial<RoutesPrefs>): void {
  try {
    const next = { ...getRoutesPrefs(), ...patch };
    localStorage.setItem(ROUTES_HIDE_IPV6_KEY, next.hideIpv6 ? "1" : "0");
    localStorage.setItem(
      ROUTES_INCLUDE_STOPPED_KEY,
      next.includeStopped ? "1" : "0",
    );
  } catch {
    // ignore storage errors (e.g. storage disabled)
  }
  window.dispatchEvent(new CustomEvent(PREFS_EVENT));
}

export function useRoutesPrefs(): RoutesPrefs {
  const [prefs, setPrefs] = useState<RoutesPrefs>(getRoutesPrefs);
  useEffect(() => {
    const handler = () => setPrefs(getRoutesPrefs());
    window.addEventListener(PREFS_EVENT, handler);
    return () => window.removeEventListener(PREFS_EVENT, handler);
  }, []);
  return prefs;
}

const SCAN_LOCAL_PROXIES_KEY = "netmanager.scan.localProxies";

export function getScanLocalProxies(): boolean {
  try {
    return localStorage.getItem(SCAN_LOCAL_PROXIES_KEY) === "1";
  } catch {
    return false;
  }
}

export function setScanLocalProxies(on: boolean): void {
  try {
    localStorage.setItem(SCAN_LOCAL_PROXIES_KEY, on ? "1" : "0");
  } catch {
    // ignore storage errors (e.g. storage disabled)
  }
  window.dispatchEvent(new CustomEvent(PREFS_EVENT));
}

export function useScanLocalProxies(): boolean {
  const [on, setOn] = useState<boolean>(getScanLocalProxies);
  useEffect(() => {
    const handler = () => setOn(getScanLocalProxies());
    window.addEventListener(PREFS_EVENT, handler);
    return () => window.removeEventListener(PREFS_EVENT, handler);
  }, []);
  return on;
}

export type AppMode = "orchestrator" | "manager" | "combined";

const APP_MODE_KEY = "netmanager.app.mode";

export function getAppMode(): AppMode {
  try {
    const mode = localStorage.getItem(APP_MODE_KEY);
    if (mode === "orchestrator" || mode === "manager") return mode;
  } catch {
    // ignore storage errors (e.g. storage disabled)
  }
  return "combined";
}

export function setAppMode(mode: AppMode): void {
  try {
    localStorage.setItem(APP_MODE_KEY, mode);
  } catch {
    // ignore storage errors (e.g. storage disabled)
  }
  window.dispatchEvent(new CustomEvent(PREFS_EVENT));
}

export function useAppMode(): AppMode {
  const [mode, setMode] = useState<AppMode>(getAppMode);
  useEffect(() => {
    const handler = () => setMode(getAppMode());
    window.addEventListener(PREFS_EVENT, handler);
    return () => window.removeEventListener(PREFS_EVENT, handler);
  }, []);
  return mode;
}

import { invoke } from "@tauri-apps/api/core";
import type { ConnectionSetCredentialInput } from "../../types";

export interface ConnectionSnippet {
  id: string;
  name: string;
  profileIds: string[];
}

const SNIPPETS_KEY = "netmanager.connections.snippets";
let legacyRead = false;
let legacyRaw: string | null = null;
let migration: Promise<void> | null = null;

async function migrateLegacy(): Promise<void> {
  if (!legacyRead) {
    legacyRaw = localStorage.getItem(SNIPPETS_KEY);
    legacyRead = true;
  }
  if (legacyRaw === null) return;
  const raw = legacyRaw;
  const sets: unknown = JSON.parse(raw);
  // Backend validation and insert-only import are authoritative, including missing IDs.
  await invoke("import_connection_sets", { sets });
  if (localStorage.getItem(SNIPPETS_KEY) === raw) localStorage.removeItem(SNIPPETS_KEY);
  legacyRaw = null;
}

// Other platforms retain their existing browser-owned sets; only Linux migrates.
function localSnippets(): ConnectionSnippet[] {
  const raw = localStorage.getItem(SNIPPETS_KEY);
  return raw ? JSON.parse(raw) as ConnectionSnippet[] : [];
}

export async function loadSnippets(shared = true): Promise<ConnectionSnippet[]> {
  if (!shared) return localSnippets();
  migration ??= migrateLegacy().catch((error: unknown) => {
    migration = null;
    throw error;
  });
  await migration;
  return invoke<ConnectionSnippet[]>("list_connection_sets");
}

export async function deleteSnippet(id: string, shared = true): Promise<void> {
  if (!shared) {
    localStorage.setItem(SNIPPETS_KEY, JSON.stringify(localSnippets().filter((set) => set.id !== id)));
    return;
  }
  await loadSnippets();
  await invoke("delete_connection_set", { id });
}

export async function captureSnippet(id: string, name: string, shared = true, profileIds: string[] = []): Promise<ConnectionSnippet> {
  if (!shared) {
    const set = { id, name, profileIds };
    localStorage.setItem(SNIPPETS_KEY, JSON.stringify([...localSnippets().filter((old) => old.id !== id), set]));
    return set;
  }
  await loadSnippets();
  return invoke<ConnectionSnippet>("capture_connection_set", { id, name });
}

export async function applySnippet(id: string, credentialInputs: Record<string, ConnectionSetCredentialInput>): Promise<void> {
  await loadSnippets();
  await invoke("apply_connection_set", { id, credentialInputs });
}

export function newSnippetId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export function sameIds(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  const setA = new Set(a);
  return b.every((id) => setA.has(id));
}

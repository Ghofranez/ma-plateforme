/*
 * ScanContext.tsx
 */

import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useRef,
  useCallback,
  useMemo,
} from "react";
import { toast } from "react-hot-toast";

// ─── Types Auth ───────────────────────────────────────────────────

export interface User {
  id: string;
  email?: string;
  name?: string;
}

interface AuthContextValue {
  user: User | null;
  setUser: (user: User | null) => void;
}

// ─── Types Scan ───────────────────────────────────────────────────

export interface PartialResult {
  label:  string;
  status: "completed" | "danger" | "warning" | "failed" | string;
  detail: string;
}

export interface ScanMeta {
  status:           string;
  progress?:        number;
  current_tool?:    string;
  current_label?:   string;
  partial_results?: Record<string, PartialResult>;
}

export interface ScanItem {
  taskId:    string;
  url:       string;
  status:    "pending" | "running" | "completed" | "failed";
  progress?: number;
  meta?:     ScanMeta;
  startedAt: number;
  reportId?: string;
}

interface ScanContextValue {
  activeScans:         ScanItem[];
  pendingCount:        number;
  addScan:             (taskId: string, url: string) => void;
  removeScan:          (taskId: string) => void;
  registerOnCompleted: (cb: (url: string) => void) => void;
}

// ─── Clés localStorage ────────────────────────────────────────────

const LS_SCANS         = "urlguard_active_scans";
const LS_USER          = "urlguard_user";
const LS_NOTIFIED      = (taskId: string) => `urlguard_notified_${taskId}`;
const MAX_AGE_MS       = 2 * 60 * 60 * 1000;
const POLL_INTERVAL_MS = 4_000;

// ─── Helpers localStorage ─────────────────────────────────────────

function readPersistedScans(): ScanItem[] {
  try {
    const raw = localStorage.getItem(LS_SCANS);
    if (!raw) return [];
    const parsed: ScanItem[] = JSON.parse(raw);
    const now = Date.now();
    return parsed.filter(
      (s) =>
        (s.status === "pending" || s.status === "running") &&
        now - s.startedAt < MAX_AGE_MS
    );
  } catch {
    return [];
  }
}

function persistScans(scans: ScanItem[]) {
  try {
    const toSave = scans.filter(
      (s) => s.status === "pending" || s.status === "running"
    );
    if (toSave.length > 0) {
      localStorage.setItem(LS_SCANS, JSON.stringify(toSave));
    } else {
      localStorage.removeItem(LS_SCANS);
    }
  } catch {}
}

function readPersistedUser(): User | null {
  try {
    const raw = localStorage.getItem(LS_USER);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function markNotified(taskId: string) {
  try { localStorage.setItem(LS_NOTIFIED(taskId), "1"); } catch {}
}

function isAlreadyNotified(taskId: string): boolean {
  try { return !!localStorage.getItem(LS_NOTIFIED(taskId)); } catch { return false; }
}

// ─── Polling Celery ───────────────────────────────────────────────

interface CeleryTaskResponse {
  state:     string;
  meta?:     Partial<ScanMeta> & Record<string, any>;
  result?:   any;
  error?:    string;
  reportId?: string;
  minutes_restantes?: number;
}

async function fetchTaskStatus(taskId: string): Promise<CeleryTaskResponse> {
  const res = await fetch(`/api/analyze/status/${taskId}`, {
    credentials: "include",
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// ─── Contexts ─────────────────────────────────────────────────────

const AuthContext = createContext<AuthContextValue>({
  user:    null,
  setUser: () => {},
});

const ScanContext = createContext<ScanContextValue>({
  activeScans:         [],
  pendingCount:        0,
  addScan:             () => {},
  removeScan:          () => {},
  registerOnCompleted: () => {},
});

// ─── Provider combiné ────────────────────────────────────────────

export function ScanProvider({ children }: { children: React.ReactNode }) {

  // ── Auth state ────────────────────────────────────────────────
  const [user, setUserState] = useState<User | null>(() => readPersistedUser());

  const setUser = useCallback((u: User | null) => {
  setUserState((prev) => {
    if (prev?.id !== u?.id) {
      try {
        localStorage.removeItem(LS_SCANS);
      } catch {}
    }
    try {
      if (u) {
        localStorage.setItem(LS_USER, JSON.stringify(u));
      } else {
        localStorage.removeItem(LS_USER);
      }
    } catch {}
    return u;
  });
}, []);
  // ── Scan state ────────────────────────────────────────────────
  const [activeScans, setActiveScans] = useState<ScanItem[]>(
    () => readPersistedScans()
  );

  useEffect(() => {
    setActiveScans([]);
    localStorage.removeItem(LS_SCANS);
  }, [user?.id]);

  const scansRef     = useRef<ScanItem[]>(activeScans);
  scansRef.current   = activeScans;
  const pollTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Callback enregistré par Home.tsx
  const onCompletedRef = useRef<((url: string) => void) | null>(null);

  const registerOnCompleted = useCallback((cb: (url: string) => void) => {
    onCompletedRef.current = cb;
  }, []);

  const pendingCount = useMemo(
    () => activeScans.filter((s) => s.status === "completed").length,
    [activeScans]
  );

  // ── Persistance scans ─────────────────────────────────────────
  useEffect(() => {
    persistScans(activeScans);
  }, [activeScans]);

  // ── Réconciliation au montage ─────────────────────────────────
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch("/api/tasks/en-cours", { credentials: "include" });
        if (!res.ok || cancelled) return;
        const data  = await res.json();
        const tasks: any[] = data.tasks ?? [];
        if (tasks.length === 0) return;

        setActiveScans((prev) => {
          const next = [...prev];
          for (const bt of tasks) {
            const exists = next.find((s) => s.taskId === bt.taskId);
            const meta: ScanMeta = {
              status:          bt.message         ?? "Analyse en cours...",
              progress:        bt.progress,
              current_tool:    bt.current_tool    ?? undefined,
              current_label:   bt.current_label   ?? undefined,
              partial_results: bt.partial_results ?? {},
            };
            if (exists) {
              Object.assign(exists, {
                status:   bt.status,
                progress: bt.progress,
                meta,
                ...(bt.reportId ? { reportId: bt.reportId } : {}),
              });
            } else {
              next.push({
                taskId:    bt.taskId,
                url:       bt.url,
                status:    bt.status,
                progress:  bt.progress,
                meta,
                startedAt: Date.now(),
                ...(bt.reportId ? { reportId: bt.reportId } : {}),
              });
            }
          }
          return next;
        });
      } catch {}
    })();
    return () => { cancelled = true; };
  }, []);

  // ── Helpers ───────────────────────────────────────────────────

  const updateScan = useCallback(
    (taskId: string, patch: Partial<ScanItem>) => {
      setActiveScans((prev) =>
        prev.map((s) => (s.taskId === taskId ? { ...s, ...patch } : s))
      );
    },
    []
  );

  const removeScanById = useCallback((taskId: string) => {
    setActiveScans((prev) => prev.filter((s) => s.taskId !== taskId));
  }, []);

  // ── Polling ───────────────────────────────────────────────────

  const pollAll = useCallback(async () => {
    const current = scansRef.current.filter(
      (s) => s.status === "pending" || s.status === "running"
    );
    if (current.length === 0) return;

    await Promise.allSettled(
      current.map(async (scan) => {
        try {
          const data  = await fetchTaskStatus(scan.taskId);
          const state = (data.state ?? "").toUpperCase();

          // ── PROGRESS ──
          if (state === "PROGRESS") {
            const meta = (data.meta ?? {}) as Partial<ScanMeta> & Record<string, any>;
            updateScan(scan.taskId, {
              status:   "running",
              progress: meta.progress,
              meta: {
                status:          meta.current_label ?? meta.status ?? "Analyse en cours…",
                current_tool:    meta.current_tool,
                current_label:   meta.current_label,
                partial_results: meta.partial_results,
                progress:        meta.progress,
              },
            });

          // ── SUCCESS ──
          } else if (state === "SUCCESS") {
            const reportId: string | undefined =
              data.reportId ??
              data.result?.reportId ??
              data.result?.id ??
              data.meta?.reportId ??
              undefined;

            updateScan(scan.taskId, {
              status:   "completed",
              progress: 100,
              reportId,
              meta: {
                status:          "Analyse terminée",
                partial_results: scan.meta?.partial_results,
              },
            });

            if (!isAlreadyNotified(scan.taskId)) {
              toast.success(`Analyse terminée — ${scan.url}`, { duration: 6000 });
              markNotified(scan.taskId);
            }

            onCompletedRef.current?.(scan.url);

            setTimeout(() => removeScanById(scan.taskId), 3000);

          // ── FAILURE ──
          } else if (state === "FAILURE") {
            updateScan(scan.taskId, {
              status: "failed",
              meta:   { status: "Échec de l'analyse" },
            });
            if (!isAlreadyNotified(scan.taskId)) {
              toast.error(`Échec du scan — ${scan.url}`);
              markNotified(scan.taskId);
            }
            setTimeout(() => removeScanById(scan.taskId), 5000);

          // ── REVOKED ──
          } else if (state === "REVOKED") {
            updateScan(scan.taskId, {
              status: "failed",
              meta:   { status: "Scan annulé" },
            });
            if (!isAlreadyNotified(scan.taskId)) {
              toast.error(`Scan annulé — ${scan.url}`, { duration: 4000 });
              markNotified(scan.taskId);
            }
            setTimeout(() => removeScanById(scan.taskId), 3000);

          // ── PENDING ──
          } else if (state === "PENDING") {
            updateScan(scan.taskId, { status: "pending" });
          }

        } catch (err) {
          console.warn(`Poll failed for ${scan.taskId}:`, err);
        }
      })
    );
  }, [updateScan, removeScanById]);

  // ── Boucle polling ────────────────────────────────────────────

  useEffect(() => {
    let cancelled = false;

    const loop = async () => {
      if (cancelled) return;
      await pollAll();
      if (!cancelled) {
        pollTimerRef.current = setTimeout(loop, POLL_INTERVAL_MS);
      }
    };

    const hasActive = activeScans.some(
      (s) => s.status === "pending" || s.status === "running"
    );

    if (hasActive) loop();

    return () => {
      cancelled = true;
      if (pollTimerRef.current) {
        clearTimeout(pollTimerRef.current);
        pollTimerRef.current = null;
      }
    };

  }, [
    activeScans.filter((s) => s.status === "pending" || s.status === "running").length,
  ]);

  // ── API publique scan ─────────────────────────────────────────

  const addScan = useCallback((taskId: string, url: string) => {
    const newScan: ScanItem = {
      taskId,
      url,
      status:    "pending",
      startedAt: Date.now(),
      meta:      { status: "En attente de démarrage…" },
    };
    setActiveScans((prev) => {
      if (prev.some((s) => s.taskId === taskId)) return prev;
      return [newScan, ...prev];
    });
  }, []);

  const removeScan = useCallback(
    (taskId: string) => removeScanById(taskId),
    [removeScanById]
  );

  // ── Rendu ─────────────────────────────────────────────────────

  return (
    <AuthContext.Provider value={{ user, setUser }}>
      <ScanContext.Provider
        value={{ activeScans, pendingCount, addScan, removeScan, registerOnCompleted }}
      >
        {children}
      </ScanContext.Provider>
    </AuthContext.Provider>
  );
}

// ─── Hooks exports ────────────────────────────────────────────────

export function useScan() {
  return useContext(ScanContext);
}

export function useAuth() {
  return useContext(AuthContext);
}

// Contexte global — partage l'état des scans actifs entre toutes les pages
import { createContext, useContext, useState, useCallback, useRef } from "react";
import { getTaskStatus, getHistory } from "../services/auth.service";

export interface ActiveScan {
  taskId:    string;
  url:       string;
  status:    "pending" | "running" | "completed" | "failed";
  progress:  string;
  reportId?: string;
}

interface ScanContextType {
  activeScans:   ActiveScan[];
  addScan:       (taskId: string, url: string) => void;
  removeScan:    (taskId: string) => void;
  pendingCount:  number;
}

const ScanContext = createContext<ScanContextType | null>(null);

export function ScanProvider({ children }: { children: React.ReactNode }) {
  const [activeScans, setActiveScans] = useState<ActiveScan[]>([]);
  const intervalsRef = useRef<Record<string, ReturnType<typeof setInterval>>>({});

  const removeScan = useCallback((taskId: string) => {
    setActiveScans(prev => prev.filter(s => s.taskId !== taskId));
  }, []);

  const addScan = useCallback((taskId: string, url: string) => {
    setActiveScans(prev => [
      ...prev,
      { taskId, url, status: "pending", progress: "Démarrage..." }
    ]);

    const interval = setInterval(async () => {
      try {
        //  Fix 1 : cast en any — TypeScript ne connaît pas la forme du retour
        const result = await getTaskStatus(taskId) as any;

        setActiveScans(prev => prev.map(s =>
          s.taskId !== taskId ? s : {
            ...s,
            // Fix 2 : result.status est maintenant string (any), comparaison valide
            status:   result.status === "completed" ? "completed"
                    : result.status === "failed"    ? "failed"
                    : "running",
            // Fix 3 : result.message existe sur any
            progress: result.message || result.status || "En cours...",
          }
        ));

        if (result.status === "completed" || result.status === "failed") {
          clearInterval(intervalsRef.current[taskId]);
          delete intervalsRef.current[taskId];

          if (result.status === "completed") {
            try {
              //  Fix 4 : cast en any[] — history.find() est maintenant valide
              const history = await getHistory() as unknown as any[];
              const match = history.find((h: any) =>
                h.url === url && h.status === "completed"
              );
              if (match) {
                setActiveScans(prev => prev.map(s =>
                  s.taskId !== taskId ? s : { ...s, reportId: match.id }
                ));
              }
            } catch { /* ignore */ }
          }
        }
      } catch {
        clearInterval(intervalsRef.current[taskId]);
        delete intervalsRef.current[taskId];
        setActiveScans(prev => prev.map(s =>
          s.taskId !== taskId ? s : { ...s, status: "failed", progress: "Échec" }
        ));
      }
    }, 3000);

    intervalsRef.current[taskId] = interval;
  }, []);

  const pendingCount = activeScans.filter(
    s => s.status === "pending" || s.status === "running"
  ).length;

  return (
    <ScanContext.Provider value={{ activeScans, addScan, removeScan, pendingCount }}>
      {children}
    </ScanContext.Provider>
  );
}

export function useScan() {
  const ctx = useContext(ScanContext);
  if (!ctx) throw new Error("useScan must be used inside <ScanProvider>");
  return ctx;
}
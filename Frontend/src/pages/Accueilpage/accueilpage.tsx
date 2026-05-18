import { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import {
  Link as LinkIcon,
  ArrowRight,
  Loader2,
  Shield,
  Clock,
  ChevronRight,
  ScanLine,
  Bell,
  TrendingUp,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  AlertCircle,
  MinusCircle,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { toast } from "react-hot-toast";
import {
  analyzeUrl,
  getHistory,
  getMesSurveillances,
} from "../../services/auth.service";
import { useScan } from "../../context/Scancontext";

// ──────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────

function riskColor(score: number): string {
  if (score <= 20) return "#22c55e";
  if (score <= 40) return "#84cc16";
  if (score <= 60) return "#f97316";
  if (score <= 80) return "#ef4444";
  return "#dc2626";
}

function getRiskScore(item: any): number | null {
  if (item.risk_score != null) return item.risk_score;
  if (typeof item.summary === "object" && item.summary?.risk != null)
    return item.summary.risk;
  if (typeof item.summary === "string") {
    try { return JSON.parse(item.summary)?.risk ?? null; } catch { return null; }
  }
  return null;
}

// ─── Alertes vues ────────────────────────────────────────────────

function getVuesAlertes(): Set<string> {
  try {
    const stored = localStorage.getItem("alertes_vues");
    return new Set(stored ? JSON.parse(stored) : []);
  } catch { return new Set(); }
}

function marquerAlertesVues(ids: string[]) {
  const vues = getVuesAlertes();
  ids.forEach((id) => vues.add(id));
  localStorage.setItem("alertes_vues", JSON.stringify([...vues]));
}

// ─── Alertes surveillance ─────────────────────────────────────────

interface SurveillanceAlert {
  id: string;
  url: string;
  message: string;
  critiques: number;
}

function detectAlertes(history: any[]): SurveillanceAlert[] {
  const urlsDejaVues = new Set<string>();
  return history
    .filter((item) => {
      try {
        const s = typeof item.summary === "string"
          ? JSON.parse(item.summary) : item.summary;
        return s?.is_auto_scan === true && (s?.anomalies ?? 0) > 0;
      } catch { return false; }
    })
    .reduce<SurveillanceAlert[]>((acc, item) => {
      if (urlsDejaVues.has(item.url)) return acc;
      urlsDejaVues.add(item.url);
      try {
        const report = typeof item.full_report === "string"
          ? JSON.parse(item.full_report) : item.full_report;
        const display = report?.display ?? {};
        const message = display?.summary ?? "Anomalie détectée lors du scan automatique.";
        const riskLabel = display?.risk_level?.label ?? "";
        const critiques = riskLabel === "Critique" ? 1 : 0;
        acc.push({ id: item.id, url: item.url, message, critiques });
      } catch {
        acc.push({ id: item.id, url: item.url,
          message: "Anomalie détectée lors du scan automatique.", critiques: 0 });
      }
      return acc;
    }, []);
}

// ──────────────────────────────────────────────────────────────────
// Sous-composants
// ──────────────────────────────────────────────────────────────────

function StatCard({ icon, label, value, sub, color, bg }: {
  icon: React.ReactNode; label: string; value: string | number;
  sub?: string; color: string; bg: string;
}) {
  return (
    <div className={`flex-1 rounded-2xl border p-3.5 ${bg}`}>
      <div className="flex items-center justify-between mb-2">
        <div className={`w-7 h-7 rounded-lg flex items-center justify-center ${color}`}>
          {icon}
        </div>
      </div>
      <p className="text-2xl font-black text-gray-800 leading-none mb-0.5">{value}</p>
      <p className="text-[10px] font-semibold text-gray-500">{label}</p>
      {sub && <p className="text-[9px] text-gray-400 mt-0.5">{sub}</p>}
    </div>
  );
}

// ─── ToolProgressList ─────────────────────────────────────────────

const TOOL_ORDER = [
  "headers", "ssl", "virustotal", "safe_browsing",
  "urlscan", "shodan", "wappalyzer", "zap", "nuclei",
];

const STATUS_ICON: Record<string, React.ReactNode> = {
  danger:    <XCircle      size={12} className="text-red-500 shrink-0"    />,
  warning:   <AlertCircle  size={12} className="text-orange-400 shrink-0" />,
  failed:    <MinusCircle  size={12} className="text-gray-400 shrink-0"   />,
  completed: <CheckCircle2 size={12} className="text-green-500 shrink-0"  />,
};

function ToolProgressList({ partialResults, currentTool, progress }: {
  partialResults?: Record<string, any>;
  currentTool?: string;
  progress?: number;
}) {
  if (!partialResults && !currentTool) return null;
  const doneKeys = partialResults ? Object.keys(partialResults) : [];
  return (
    <div className="mt-2 space-y-1">
      {TOOL_ORDER.map((key) => {
        const tool = partialResults?.[key];
        const isCurrent = currentTool === key && !tool;
        if (!tool && !isCurrent) return null;
        const icon = tool
          ? (STATUS_ICON[tool.status] ?? STATUS_ICON["completed"])
          : <Loader2 size={12} className="text-indigo-400 animate-spin shrink-0" />;
        return (
          <div key={key} className="flex items-center gap-1.5 text-[10px]">
            {icon}
            <span className="font-semibold text-gray-600 truncate" style={{ maxWidth: 120 }}>
              {tool?.label ?? key}
            </span>
            {tool?.detail && (
              <span className="text-gray-400 truncate" style={{ maxWidth: 140 }}>
                {tool.detail}
              </span>
            )}
          </div>
        );
      })}
      {currentTool && !doneKeys.includes(currentTool) && (
        <div className="flex items-center gap-1.5 text-[10px]">
          <Loader2 size={12} className="text-indigo-400 animate-spin shrink-0" />
          <span className="text-indigo-500 font-semibold">{currentTool}…</span>
        </div>
      )}
      {progress != null && (
        <div className="mt-1.5 w-full bg-slate-100 rounded-full h-1">
          <motion.div
            className="h-1 rounded-full bg-indigo-400"
            animate={{ width: `${progress}%` }}
            transition={{ duration: 0.6, ease: "easeOut" }}
          />
        </div>
      )}
    </div>
  );
}

// ─── SurveillanceAlertBanner ──────────────────────────────────────

function SurveillanceAlertBanner({ alert, onClick }: {
  alert: SurveillanceAlert; onClick: () => void;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
      onClick={onClick}
      className="flex items-start gap-3 text-sm bg-red-50 border border-red-200 rounded-2xl px-4 py-3 mb-3 cursor-pointer hover:bg-red-100 transition-colors"
    >
      <AlertTriangle size={16} className="shrink-0 mt-0.5 text-red-500" />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 mb-0.5">
          <p className="font-bold text-red-800 text-xs leading-snug">
            Anomalie détectée — {alert.url}
          </p>
          {alert.critiques > 0 && (
            <span className="text-[9px] font-black px-1.5 py-0.5 rounded-full bg-red-200 text-red-700 shrink-0">
              {alert.critiques} critique{alert.critiques > 1 ? "s" : ""}
            </span>
          )}
        </div>
        <p className="text-[10px] text-red-500">{alert.message}</p>
        <p className="text-[10px] text-red-400 font-semibold mt-1">
          Appuyer pour voir le rapport →
        </p>
      </div>
    </motion.div>
  );
}

// ──────────────────────────────────────────────────────────────────
// PAGE PRINCIPALE
// ──────────────────────────────────────────────────────────────────

export default function Home() {
  const navigate = useNavigate();
  const { activeScans, addScan, registerOnCompleted } = useScan();

  const [url,          setUrl]          = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [recentItems,  setRecentItems]  = useState<any[]>([]);
  const [nbSurveillee, setNbSurveillee] = useState<number>(0);
  const [totalScans,   setTotalScans]   = useState<number>(0);
  const [alertes,      setAlertes]      = useState<SurveillanceAlert[]>([]);

  // ─── Dérivés ──────────────────────────────────────────────────
  const trimmedUrl    = url.trim();
  const activeRunning = activeScans.filter(
    (s) => s.status === "pending" || s.status === "running"
  );
  const hasActiveScan  = activeRunning.length > 0;
  const runningCount   = activeRunning.length;
  const isInputBlocked = hasActiveScan; 

  // ─── loadAll ──────────────────────────────────────────────────
  const loadAll = useCallback(async () => {
    try {
      const data       = (await getHistory()) as unknown as any[];
      const manualOnly = data.filter((item: any) => {
        try {
          const s = typeof item.summary === "string"
            ? JSON.parse(item.summary) : item.summary;
          return s?.is_auto_scan !== true;
        } catch { return true; }
      });
      setRecentItems(manualOnly.slice(0, 5));
      setTotalScans(manualOnly.length);

      const toutesAlertes = detectAlertes(data);
      const vues          = getVuesAlertes();
      const nouvelles     = toutesAlertes.filter((a) => !vues.has(a.id));
      setAlertes(nouvelles);
      if (nouvelles.length > 0) {
        nouvelles.forEach((a) =>
          toast.error(`Anomalie sur ${a.url}`, { duration: 5000 })
        );
        marquerAlertesVues(nouvelles.map((a) => a.id));
      }
    } catch {
      toast.error("Erreur chargement historique");
    }

    try {
      const surv    = await getMesSurveillances();
      const payload = surv?.data ?? surv;
      setNbSurveillee((payload?.urls ?? []).length);
    } catch { setNbSurveillee(0); }
  }, []);

  // ─── Effets ───────────────────────────────────────────────────
  useEffect(() => { loadAll(); }, [loadAll]);

  useEffect(() => {
    const handleVisibility = () => {
      if (document.visibilityState === "visible") loadAll();
    };
    document.addEventListener("visibilitychange", handleVisibility);
    return () => document.removeEventListener("visibilitychange", handleVisibility);
  }, [loadAll]);

  useEffect(() => {
    registerOnCompleted(() => { loadAll(); });
  }, [registerOnCompleted, loadAll]);

  // ─── Submit ───────────────────────────────────────────────────
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isInputBlocked || !trimmedUrl || isSubmitting) {
      if (hasActiveScan) {
        toast.error("Un scan est déjà en cours. Attendez qu'il se termine.",
          { duration: 3000 });
      }
      return;
    }

    setIsSubmitting(true);
    try {
      const res = (await analyzeUrl(trimmedUrl)) as any;

      if (res?.from_cache) {
        toast(
          (t) => (
            <div className="flex flex-col gap-1">
              <p className="font-bold text-sm text-gray-800">Rapport récent disponible</p>
              <p className="text-xs text-gray-500">
                Cette URL a déjà été analysée récemment.
              </p>
              <button
                onClick={() => {
                  navigate(`/rapport/${res.report_id}`);
                  toast.dismiss(t.id);
                }}
                className="mt-1 text-xs font-bold text-indigo-600 hover:underline text-left"
              >
                Voir le rapport existant →
              </button>
            </div>
          ),
          { duration: 6000 }
        );
        setIsSubmitting(false);
        return;
      }

      if (res?.blocked) {
        toast.error(res.reason || "Analyse bloquée.", { duration: 5000 });
        return;
      }

      addScan(res.task_id, trimmedUrl);
      setUrl("");
      toast("Analyse lancée — suivi en temps réel ci-dessous", { duration: 3000 });
    } catch (err: any) {
      const detail = err?.response?.data?.detail;
      toast.error(
        typeof detail === "string" ? detail : detail?.message ?? "Erreur lors du lancement"
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  // ─── Liste fusionnée ──────────────────────────────────────────
  const mergedList = [
    ...activeRunning.map((s) => ({
      id: s.taskId, url: s.url, status: s.status,
      _isActive: true, _scan: s,
    })),
    ...recentItems
      .filter((item) => !activeRunning.some((s) => s.url === item.url))
      .map((item) => ({ ...item, _isActive: false })),
  ];

  // ─── Rendu ───────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-slate-50">
      <div className="px-6 pt-6 pb-12 max-w-3xl mx-auto">

        {/* Header */}
        <div className="text-center mb-6">
          <div className="flex items-center justify-center w-14 h-14 rounded-2xl bg-indigo-100 mx-auto mb-4">
            <Shield size={28} className="text-indigo-600" />
          </div>
          <h1 className="text-3xl font-black text-gray-900 mb-2">Analysez vos URLs</h1>
          <p className="text-sm text-gray-400 font-medium">
            Vérifiez la sécurité d'un site en quelques secondes
          </p>
        </div>

        {/* Stat cards */}
        <div className="flex gap-3 mb-6">
          <StatCard icon={<ScanLine   size={14} className="text-indigo-600" />}
            label="Total scans" value={totalScans}   sub="Depuis le début"
            color="bg-indigo-100" bg="bg-white border-indigo-100" />
          <StatCard icon={<Bell       size={14} className="text-green-600"  />}
            label="Surveillées" value={nbSurveillee} sub="URLs actives"
            color="bg-green-100"  bg="bg-white border-green-100"  />
          <StatCard icon={<TrendingUp size={14} className="text-purple-600" />}
            label="En cours"    value={runningCount} sub="Analyses actives"
            color="bg-purple-100" bg="bg-white border-purple-100" />
        </div>

        {/* Alertes surveillance */}
        <AnimatePresence>
          {alertes.map((alerte) => (
            <SurveillanceAlertBanner
              key={alerte.id}
              alert={alerte}
              onClick={() => {
                marquerAlertesVues([alerte.id]);
                setAlertes((prev) => prev.filter((a) => a.id !== alerte.id));
                navigate(`/surveillance/rapport/${alerte.id}`);
              }}
            />
          ))}
        </AnimatePresence>

        {/* Formulaire */}
        <div className={`bg-white rounded-2xl border shadow-sm p-5 mb-4 transition-all ${
          isInputBlocked ? "border-amber-200" : "border-gray-100"
        }`}>
          <form onSubmit={handleSubmit} className="flex flex-col gap-3">
            <label className="text-xs font-semibold text-gray-500 uppercase tracking-widest">
              URL à analyser
            </label>
            <div className="relative">
              {isInputBlocked ? (
                <Loader2 size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-indigo-400 animate-spin" />
              ) : (
                <LinkIcon size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
              )}
              <input
                type="url"
                placeholder={hasActiveScan ? "Scan en cours — veuillez patienter…" : "https://example.com"}
                value={url}
                onChange={(e) => { if (!hasActiveScan) setUrl(e.target.value); }}
                disabled={hasActiveScan}
                readOnly={hasActiveScan}
                className={`w-full pl-9 pr-4 py-3 text-sm border rounded-xl focus:outline-none focus:ring-2 transition text-gray-800 placeholder-gray-400 ${
                  isInputBlocked
                    ? "bg-amber-50 border-amber-200 text-amber-700 cursor-not-allowed focus:ring-amber-200"
                    : "bg-slate-50 border-gray-200 focus:ring-indigo-300 focus:bg-white"
                }`}
              />
            </div>
            <button
              type="submit"
              disabled={isSubmitting || !trimmedUrl || isInputBlocked}
              className="w-full py-3 rounded-xl text-sm font-bold text-white transition-all disabled:cursor-not-allowed flex items-center justify-center gap-2"
              style={{
                background: isInputBlocked
                  ? "#d97706"
                  : isSubmitting || !trimmedUrl
                  ? "#9ca3af"
                  : "linear-gradient(135deg, #6366f1, #8b5cf6)",
                opacity: isSubmitting || !trimmedUrl ? 0.6 : 1,
              }}
            >
              <AnimatePresence mode="wait">
                {isSubmitting ? (
                  <motion.span key="loading" className="flex items-center gap-2"
                    initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                    <Loader2 size={16} className="animate-spin" /> Lancement…
                  </motion.span>
                ) : (
                  <motion.span key="idle" className="flex items-center gap-2"
                    initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                    {hasActiveScan
                      ? <><Loader2 size={16} className="animate-spin" /> Scan en cours…</>
                      : <>Analyser <ArrowRight size={16} /></>}
                  </motion.span>
                )}
              </AnimatePresence>
            </button>
          </form>
        </div>

        {/* Liste fusionnée */}
        <div className="bg-white rounded-2xl border border-gray-100 shadow-sm overflow-hidden">
          <div className="px-5 py-3 border-b border-gray-50 flex items-center justify-between">
            <span className="text-xs font-black uppercase tracking-widest text-gray-400">
              URLs récentes
            </span>
            <button
              onClick={() => navigate("/historique")}
              className="text-xs font-semibold text-indigo-500 hover:text-indigo-700 transition-colors"
            >
              Voir tout →
            </button>
          </div>

          <div className="divide-y divide-gray-50">
            <AnimatePresence>
              {mergedList.map((item) => {
                const score = getRiskScore(item);
                return (
                  <motion.div
                    key={item._isActive ? item._scan.taskId : item.id}
                    layout
                    initial={{ opacity: 0, y: -6 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -6 }}
                    onClick={() => {
                      if (item._isActive) {
                        toast("Analyse en cours — résultat disponible bientôt");
                        return;
                      }
                      if (item.status !== "completed") {
                        toast("Analyse pas encore terminée");
                        return;
                      }
                      navigate(`/rapport/${item.id}`);
                    }}
                    className="flex items-start gap-3 px-5 py-3.5 hover:bg-slate-50 cursor-pointer transition-colors"
                    style={{
                      borderLeft: score != null
                        ? `3px solid ${riskColor(score)}`
                        : "3px solid #e2e8f0"
                    }}
                  >
                    <div className="w-8 h-8 rounded-lg bg-slate-100 flex items-center justify-center shrink-0 mt-0.5">
                      {item._isActive
                        ? <Loader2 size={14} className="text-indigo-500 animate-spin" />
                        : <LinkIcon size={14} className="text-gray-400" />}
                    </div>

                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-semibold text-gray-700 truncate">
                        {item.url}
                      </p>
                      {item._isActive && (
                        <div className="mt-1">
                          <span className="text-[10px] font-medium text-indigo-500 flex items-center gap-1">
                            <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 animate-pulse inline-block" />
                            {item._scan?.meta?.status || "En attente…"}
                          </span>
                          <ToolProgressList
                            partialResults={item._scan?.meta?.partial_results}
                            currentTool={item._scan?.meta?.current_tool}
                            progress={item._scan?.progress}
                          />
                        </div>
                      )}
                    </div>

                    <div className="flex items-center gap-2 shrink-0 mt-1">
                      {score != null && !item._isActive && (
                        <span
                          className="text-[10px] font-black px-2 py-0.5 rounded-full"
                          style={{
                            color:      riskColor(score),
                            background: `${riskColor(score)}15`,
                            border:     `1px solid ${riskColor(score)}30`,
                          }}
                        >
                          {score}%
                        </span>
                      )}
                      <ChevronRight size={14} className="text-gray-300" />
                    </div>
                  </motion.div>
                );
              })}
            </AnimatePresence>

            {mergedList.length === 0 && (
              <div className="flex flex-col items-center justify-center py-10 text-gray-300">
                <Clock size={28} className="mb-2" />
                <p className="text-xs font-medium">Aucune analyse récente</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  Search, ExternalLink, Clock,
  Loader2, Calendar, Trash2,
  ShieldCheck, ShieldX, History as HistoryIcon,
  Bell, BellOff, X,
} from "lucide-react";
import {
  getHistory,
  deleteHistoryItem,
  getMesSurveillances,
  activerSurveillance,
  desactiverSurveillance,
} from "../../services/auth.service";
import toast from "react-hot-toast";

type AnalysisStatus = "completed" | "processing" | "failed";

interface HistoryItem {
  id: string;
  url: string;
  status: AnalysisStatus;
  date: string;
  time: string;
  summary?: any;
  risk_score?: number;
}

function riskColor(score: number): string {
  if (score <= 20) return "#22c55e";
  if (score <= 40) return "#84cc16";
  if (score <= 60) return "#f97316";
  if (score <= 80) return "#ef4444";
  return "#dc2626";
}

function riskBg(score: number): string {
  if (score <= 20) return "bg-green-50 border-green-200 text-green-700";
  if (score <= 40) return "bg-lime-50 border-lime-200 text-lime-700";
  if (score <= 60) return "bg-orange-50 border-orange-200 text-orange-700";
  return "bg-red-50 border-red-200 text-red-700";
}

function getSummaryText(summary: any): string {
  if (!summary) return "";
  if (typeof summary === "string") {
    try { return JSON.parse(summary)?.summary_text ?? ""; } catch { return summary; }
  }
  return summary.summary_text ?? summary.summary ?? "";
}

function getRiskScore(item: HistoryItem): number | null {
  if (item.risk_score != null) return item.risk_score;
  if (typeof item.summary === "object" && item.summary?.risk != null) return item.summary.risk;
  if (typeof item.summary === "string") {
    try { return JSON.parse(item.summary)?.risk ?? null; } catch { return null; }
  }
  return null;
}

async function fetchSurveilleesFromApi(): Promise<string[]> {
  const r = await getMesSurveillances() as any;
  const urls: any[] = r?.urls ?? [];
  return urls.map((s: any) => (typeof s === "string" ? s : s.url));
}

// ─────────────────────────────────────────────
// Page History — compatible avec Layout.tsx
// La sidebar est gérée par Layout, pas ici.
// Pas de bouton retour.
// ─────────────────────────────────────────────
export default function History() {
  const [searchQuery,    setSearchQuery]    = useState("");
  const [historyData,    setHistoryData]    = useState<HistoryItem[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(true);
  const [showSurv,       setShowSurv]       = useState(false);
  const [surveillees,    setSurveillee]     = useState<string[]>([]);
  const [loadingSurv,    setLoadingSurv]    = useState<string | null>(null);

  const navigate    = useNavigate();
  const urlsUniques = [...new Set(historyData.map((r) => r.url))];
  const filteredHistory = historyData.filter((item) =>
    item.url.toLowerCase().includes(searchQuery.toLowerCase())
  );

  useEffect(() => {
    (async () => {
      try {
        const res = await getHistory();
        const all = Array.isArray(res) ? res : (res as any).data || [];
        setHistoryData(all.filter((item: any) => {
          try {
            const s = typeof item.summary === "string"
              ? JSON.parse(item.summary)
              : item.summary;
            return s?.is_auto_scan !== true;
          } catch { return true; }
        }));
      } catch {
        toast.error("Erreur chargement");
      } finally {
        setLoadingHistory(false);
      }
    })();
  }, []);

  useEffect(() => {
    fetchSurveilleesFromApi()
      .then((urls) => setSurveillee(urls))
      .catch(() => setSurveillee([]));
  }, []);

  const handleToggleSurveillance = async (url: string) => {
    if (loadingSurv !== null) return;
    const estActive = surveillees.includes(url);
    setLoadingSurv(url);
    try {
      if (estActive) {
        await desactiverSurveillance(url);
        setSurveillee((prev) => prev.filter((u) => u !== url));
        toast.success("Surveillance désactivée");
      } else {
        await activerSurveillance(url);
        setSurveillee((prev) => (prev.includes(url) ? prev : [...prev, url]));
        toast.success("Surveillance activée — premier scan dans 24h ✓", { duration: 4000 });
      }
    } catch (err: any) {
      const msg =
        typeof err === "string"
          ? err
          : err?.detail ?? err?.message ?? err?.error ?? "Erreur lors de la surveillance";
      toast.error(msg);
    } finally {
      setLoadingSurv(null);
    }
  };

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm("Supprimer cette analyse ?")) return;
    try {
      const item = historyData.find((i) => i.id === id);
      await deleteHistoryItem(id);
      const remaining = historyData.filter((i) => i.id !== id);
      setHistoryData(remaining);
      const encorePresente = remaining.some((i) => i.url === item?.url);
      if (item && surveillees.includes(item.url) && !encorePresente) {
        await desactiverSurveillance(item.url);
        setSurveillee((prev) => prev.filter((u) => u !== item.url));
        toast("Surveillance désactivée — URL supprimée de l'historique", {
          icon: "🔕", duration: 3000,
        });
      } else {
        toast.success("Supprimé !");
      }
    } catch {
      toast.error("Erreur suppression");
    }
  };

  return (
    /*
      Ce composant est rendu dans le <main> de Layout.tsx.
      Layout gère déjà : sidebar + flex row.
      On n'ajoute donc pas de sidebar ni de ml-* ici.
    */
    <div className="min-h-screen bg-slate-50 pb-12 relative">

      {/* ── Header sticky (sans bouton retour) ── */}
      <div className="sticky top-0 z-10 bg-white/90 backdrop-blur border-b border-gray-100 px-6 py-3 flex items-center gap-3">
        <div className="flex-1">
          <h1 className="font-black text-gray-900 text-base leading-tight">
            Historique des analyses
          </h1>
          <p className="text-xs text-gray-400">
            {historyData.length} analyse(s) enregistrée(s)
          </p>
        </div>

        {/* Bouton surveillance → ouvre le drawer */}
        <button
          onClick={() => setShowSurv((o) => !o)}
          className={`relative flex items-center gap-2 px-3 py-2 rounded-xl text-sm font-semibold transition-colors ${
            showSurv
              ? "bg-indigo-100 text-indigo-600"
              : "hover:bg-gray-100 text-gray-500"
          }`}
        >
          <Bell size={16} />
          <span className="hidden sm:inline text-xs font-semibold">Surveillance</span>
          {surveillees.length > 0 && (
            <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-indigo-500 text-white text-[8px] font-black flex items-center justify-center">
              {surveillees.length}
            </span>
          )}
        </button>
      </div>

      {/* ── Contenu ── */}
      <div className="px-6 mt-5 max-w-3xl mx-auto">

        {/* Recherche */}
        <div className="relative mb-5">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
          <input
            className="w-full pl-9 pr-4 py-2.5 text-sm bg-white border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-300 transition"
            placeholder="Rechercher une URL..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        {/* Liste */}
        {loadingHistory ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="animate-spin text-indigo-500" size={28} />
          </div>
        ) : filteredHistory.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-gray-400">
            <HistoryIcon size={40} className="mb-3 opacity-40" />
            <p className="text-sm font-medium">Aucune analyse trouvée</p>
          </div>
        ) : (
          <div className="flex flex-col gap-3">
            {filteredHistory.map((item) => {
              const score       = getRiskScore(item);
              const summaryTxt  = getSummaryText(item.summary);
              const isCompleted = item.status === "completed";
              const isFailed    = item.status === "failed";
              const estSurv     = surveillees.includes(item.url);

              return (
                <div
                  key={item.id}
                  onClick={() => navigate(`/rapport/${item.id}`)}
                  className="bg-white rounded-2xl border border-gray-100 shadow-sm hover:shadow-md transition-all cursor-pointer overflow-hidden"
                  style={{ borderLeft: `4px solid ${score != null ? riskColor(score) : "#94a3b8"}` }}
                >
                  <div className="p-4">
                    <div className="flex items-start gap-3">
                      <div className={`w-9 h-9 rounded-xl flex items-center justify-center shrink-0 ${
                        isCompleted ? "bg-green-50" : isFailed ? "bg-red-50" : "bg-blue-50"
                      }`}>
                        {isCompleted
                          ? <ShieldCheck size={18} className="text-green-600" />
                          : isFailed
                            ? <ShieldX size={18} className="text-red-500" />
                            : <Loader2 size={18} className="text-blue-500 animate-spin" />}
                      </div>

                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-sm font-bold text-gray-800 truncate">{item.url}</span>
                          <a
                            href={item.url}
                            target="_blank"
                            rel="noreferrer"
                            onClick={(e: React.MouseEvent) => e.stopPropagation()}
                            className="shrink-0 text-gray-400 hover:text-indigo-500 transition-colors"
                          >
                            <ExternalLink size={13} />
                          </a>
                          {estSurv && (
                            <span className="flex items-center gap-0.5 text-[9px] font-bold px-1.5 py-0.5 rounded-full bg-indigo-50 border border-indigo-200 text-indigo-600 shrink-0">
                              <Bell size={8} /> Surveillée
                            </span>
                          )}
                        </div>
                        {summaryTxt && (
                          <p className="text-xs text-gray-500 leading-relaxed mb-2 line-clamp-2">
                            {summaryTxt}
                          </p>
                        )}
                        <div className="flex items-center gap-3 text-[10px] text-gray-400">
                          <span className="flex items-center gap-1"><Calendar size={10} /> {item.date}</span>
                          <span className="flex items-center gap-1"><Clock size={10} /> {item.time}</span>
                        </div>
                      </div>

                      <div className="flex flex-col items-end gap-2 shrink-0">
                        {score != null && (
                          <span className={`text-xs font-black px-2.5 py-1 rounded-full border ${riskBg(score)}`}>
                            {score}%
                          </span>
                        )}
                        <button
                          onClick={(e: React.MouseEvent) => handleDelete(item.id, e)}
                          className="text-gray-300 hover:text-red-500 transition-colors"
                        >
                          <Trash2 size={15} />
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* ── Overlay (fixed, couvre sidebar + contenu) ── */}
      {showSurv && (
        <div
          className="fixed inset-0 z-30 bg-black/30"
          onClick={() => setShowSurv(false)}
        />
      )}

      {/* ── Drawer surveillance  ── */}
      <div
        className={`fixed top-0 right-0 h-full w-80 z-40 bg-white shadow-2xl flex flex-col
          transition-transform duration-300 ease-in-out
          ${showSurv ? "translate-x-0" : "translate-x-full"}`}
      >
        {/* En-tête */}
        <div className="flex items-center gap-2 px-4 py-3 bg-gradient-to-r from-indigo-50 to-purple-50 border-b border-indigo-100 shrink-0">
          <div className="w-8 h-8 rounded-xl bg-indigo-100 flex items-center justify-center">
            <Bell size={15} className="text-indigo-600" />
          </div>
          <div className="flex-1">
            <p className="text-sm font-black text-gray-800">Surveillance automatique</p>
            <p className="text-[10px] text-gray-400">Scan complet toutes les 24h</p>
          </div>
          <div className="flex items-center gap-1 px-2.5 py-1 rounded-full bg-indigo-50 border border-indigo-200 text-indigo-600 text-xs font-black shrink-0">
            <Bell size={10} />
            <span>{surveillees.length} active{surveillees.length > 1 ? "s" : ""}</span>
          </div>
          <button
            onClick={() => setShowSurv(false)}
            className="ml-1 w-7 h-7 flex items-center justify-center rounded-lg hover:bg-indigo-100 text-gray-400 transition-colors"
          >
            <X size={15} />
          </button>
        </div>

        {/* Liste URLs */}
        <div className="flex-1 overflow-y-auto divide-y divide-gray-50">
          {urlsUniques.length === 0 ? (
            <div className="flex flex-col items-center py-12 text-gray-300">
              <Bell size={24} className="mb-2 opacity-40" />
              <p className="text-xs font-medium">Aucune URL dans l'historique</p>
            </div>
          ) : (
            urlsUniques.map((url) => {
              const estActive = surveillees.includes(url);
              const isLoading = loadingSurv === url;
              const bloque    = !estActive && loadingSurv !== null;

              return (
                <div
                  key={url}
                  className={`flex items-center gap-3 px-4 py-3 transition-colors ${
                    estActive ? "bg-green-50/50" : bloque ? "opacity-40" : "hover:bg-gray-50"
                  }`}
                >
                  <span className={`h-2 w-2 rounded-full shrink-0 transition-colors ${
                    estActive ? "bg-green-500 animate-pulse" : "bg-gray-200"
                  }`} />
                  <span className="flex-1 text-xs font-semibold text-gray-700 truncate">{url}</span>
                  <button
                    onClick={() => { if (!isLoading && !bloque) handleToggleSurveillance(url); }}
                    disabled={isLoading || bloque}
                    className={`shrink-0 flex items-center gap-1.5 text-[11px] font-bold
                      px-3 py-1.5 rounded-full border transition-all ${
                      isLoading
                        ? "bg-gray-50 border-gray-200 text-gray-400 cursor-not-allowed"
                        : estActive
                          ? "bg-red-50 border-red-200 text-red-500 hover:bg-red-100 cursor-pointer"
                          : bloque
                            ? "bg-gray-100 border-gray-200 text-gray-400 cursor-not-allowed"
                            : "bg-indigo-50 border-indigo-200 text-indigo-600 hover:bg-indigo-100 cursor-pointer"
                    }`}
                  >
                    {isLoading ? (
                      <Loader2 size={11} className="animate-spin" />
                    ) : estActive ? (
                      <><BellOff size={11} /> Désactiver</>
                    ) : (
                      <><Bell size={11} /> Surveiller</>
                    )}
                  </button>
                </div>
              );
            })
          )}
        </div>

        {/* Pied */}
        <div className="px-4 py-2.5 bg-gray-50 border-t border-gray-100 shrink-0">
          <p className="text-[10px] text-gray-400 text-center">
            Premier scan 24h après activation — suivants toutes les 24h
          </p>
        </div>
      </div>
    </div>
  );
}
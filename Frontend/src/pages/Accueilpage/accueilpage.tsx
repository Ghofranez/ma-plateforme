import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Link as LinkIcon, ArrowRight, Loader2, Shield, Clock, ChevronRight } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { Sidebar, MenuButton } from "../../components/ui/Sidebar/sidebar";
import { toast } from "react-hot-toast";
import { analyzeUrl, getHistory } from "../../services/auth.service";
import { useScan } from "../../context/Scancontext";

function riskColor(score: number): string {
  if (score <= 20) return "#22c55e";
  if (score <= 40) return "#84cc16";
  if (score <= 60) return "#f97316";
  if (score <= 80) return "#ef4444";
  return "#dc2626";
}

function getRiskScore(item: any): number | null {
  if (item.risk_score != null) return item.risk_score;
  if (typeof item.summary === "object" && item.summary?.risk != null) return item.summary.risk;
  if (typeof item.summary === "string") {
    try { return JSON.parse(item.summary)?.risk ?? null; } catch { return null; }
  }
  return null;
}

export default function Home() {
  const navigate = useNavigate();
  const { activeScans, addScan } = useScan();

  const [url,           setUrl]           = useState("");
  const [isSubmitting,  setIsSubmitting]  = useState(false);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [recentItems,   setRecentItems]   = useState<any[]>([]);

  useEffect(() => { loadRecent(); }, []);

  const completedCount = activeScans.filter(s => s.status === "completed").length;
  useEffect(() => { if (completedCount > 0) loadRecent(); }, [completedCount]);

  const loadRecent = async () => {
    try {
      const data = await getHistory() as unknown as any[];
      setRecentItems(data.slice(0, 5));
    } catch {
      toast.error("Erreur chargement historique");
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = url.trim();
    if (!trimmed) return;
    setIsSubmitting(true);
    try {
      const res = await analyzeUrl(trimmed) as any;
      addScan(res.task_id, trimmed);
      setUrl("");
      toast.success("Analyse lancée !");
    } catch (err: any) {
      toast.error(err?.detail || "Erreur lors du lancement");
    } finally {
      setIsSubmitting(false);
    }
  };

  const mergedList = [
    ...activeScans
      .filter(s => s.status === "pending" || s.status === "running")
      .filter(s => !recentItems.some(r => r.url === s.url))
      .map(s => ({ id: s.taskId, url: s.url, status: "pending", _isActive: true, _scan: s })),
    ...recentItems.map(item => {
      const active = activeScans.find(s => s.url === item.url && (s.status === "pending" || s.status === "running"));
      return active ? { ...item, _isActive: true, _scan: active } : { ...item, _isActive: false };
    }),
  ].slice(0, 5);

  const runningCount = activeScans.filter(s => s.status === "pending" || s.status === "running").length;

  return (
    <div className="min-h-screen bg-slate-50">

      <MenuButton onClick={() => setIsSidebarOpen(true)} />
      <Sidebar isOpen={isSidebarOpen} onClose={() => setIsSidebarOpen(false)} />

      <div className="flex flex-col items-center justify-start pt-16 px-4 pb-12">
        <div className="w-full max-w-lg">

          {/* ── Header ── */}
          <div className="text-center mb-8">
            <div className="flex items-center justify-center w-14 h-14 rounded-2xl bg-indigo-100 mx-auto mb-4">
              <Shield size={28} className="text-indigo-600" />
            </div>
            <h1 className="text-3xl font-black text-gray-900 mb-2">Analysez vos URLs</h1>
            <p className="text-sm text-gray-400 font-medium">
              Vérifiez la sécurité d'un site en quelques secondes
            </p>
          </div>

          {/* ── Formulaire ── */}
          <div className="bg-white rounded-2xl border border-gray-100 shadow-sm p-5 mb-4">
            <form onSubmit={handleSubmit} className="flex flex-col gap-3">
              <label className="text-xs font-semibold text-gray-500 uppercase tracking-widest">
                URL à analyser
              </label>
              <div className="relative">
                <LinkIcon size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
                <input
                  type="url"
                  placeholder="https://example.com"
                  value={url}
                  onChange={e => setUrl(e.target.value)}
                  required
                  className="w-full pl-9 pr-4 py-3 text-sm bg-slate-50 border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-300 focus:bg-white transition text-gray-800 placeholder-gray-400"
                />
              </div>
              <button
                type="submit"
                disabled={isSubmitting || !url.trim()}
                className="w-full py-3 rounded-xl text-sm font-bold text-white transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                style={{ background: "linear-gradient(135deg, #6366f1, #8b5cf6)" }}>
                <AnimatePresence mode="wait">
                  {isSubmitting ? (
                    <motion.span key="loading" className="flex items-center gap-2"
                      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                      <Loader2 size={16} className="animate-spin" /> Lancement...
                    </motion.span>
                  ) : (
                    <motion.span key="idle" className="flex items-center gap-2"
                      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                      Analyser <ArrowRight size={16} />
                    </motion.span>
                  )}
                </AnimatePresence>
              </button>
            </form>
          </div>

          {/* ── Scans actifs ── */}
          {runningCount > 0 && (
            <div className="flex items-center gap-2 text-xs text-indigo-600 bg-indigo-50 border border-indigo-100 rounded-xl px-4 py-2.5 mb-4">
              <Loader2 size={13} className="animate-spin shrink-0" />
              <span>{runningCount} analyse(s) en cours — tu peux naviguer librement</span>
            </div>
          )}

          {/* ── URLs récentes ── */}
          <div className="bg-white rounded-2xl border border-gray-100 shadow-sm overflow-hidden">
            <div className="px-5 py-3 border-b border-gray-50 flex items-center justify-between">
              <span className="text-xs font-black uppercase tracking-widest text-gray-400">
                URLs récentes
              </span>
              <button onClick={() => navigate("/historique")}
                className="text-xs font-semibold text-indigo-500 hover:text-indigo-700 transition-colors">
                Voir tout →
              </button>
            </div>

            <div className="divide-y divide-gray-50">
              <AnimatePresence>
                {mergedList.map(item => {
                  const score = getRiskScore(item);
                  return (
                    <motion.div
                      key={item.id}
                      layout
                      initial={{ opacity: 0, y: -6 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -6 }}
                      onClick={() => {
                        if (item._isActive) {
                          toast("Analyse en cours — résultat disponible bientôt", { icon: "⏳" });
                          return;
                        }
                        if (item.status !== "completed") {
                          toast("Analyse pas encore terminée");
                          return;
                        }
                        navigate(`/rapport/${item.id}`);
                      }}
                      className="flex items-center gap-3 px-5 py-3.5 hover:bg-slate-50 cursor-pointer transition-colors"
                      style={{ borderLeft: score != null ? `3px solid ${riskColor(score)}` : "3px solid #e2e8f0" }}>

                      {/* Icône */}
                      <div className="w-8 h-8 rounded-lg bg-slate-100 flex items-center justify-center shrink-0">
                        {item._isActive
                          ? <Loader2 size={14} className="text-indigo-500 animate-spin" />
                          : <LinkIcon size={14} className="text-gray-400" />}
                      </div>

                      {/* URL + badge */}
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-semibold text-gray-700 truncate">{item.url}</p>
                        {item._isActive && (
                          <span className="text-[10px] font-medium text-indigo-500 flex items-center gap-1 mt-0.5">
                            <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 animate-pulse inline-block" />
                            {item._scan?.progress || "En cours..."}
                          </span>
                        )}
                      </div>

                      {/* Score + flèche */}
                      <div className="flex items-center gap-2 shrink-0">
                        {score != null && !item._isActive && (
                          <span className="text-[10px] font-black px-2 py-0.5 rounded-full"
                            style={{
                              color: riskColor(score),
                              background: `${riskColor(score)}15`,
                              border: `1px solid ${riskColor(score)}30`
                            }}>
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
    </div>
  );
}
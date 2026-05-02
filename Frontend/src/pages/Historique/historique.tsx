import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  Search, ExternalLink, Clock,
  Loader2, Calendar, Trash2, ArrowLeft,
  ShieldCheck, ShieldX, History as HistoryIcon
} from "lucide-react";
import { Sidebar, MenuButton } from "../../components/ui/Sidebar/sidebar";
import { getHistory, deleteHistoryItem } from "../../services/auth.service";
import toast from "react-hot-toast";

type AnalysisStatus = "completed" | "processing" | "failed";

interface HistoryItem {
  id: string;
  url: string;
  status: AnalysisStatus;
  date: string;
  time: string;
  duration?: string;
  summary?: any;
  full_report?: any;
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
    try {
      const parsed = JSON.parse(summary);
      return parsed.summary_text ?? parsed.summary ?? "";
    } catch {
      return summary;
    }
  }
  if (typeof summary === "object") {
    return summary.summary_text ?? summary.summary ?? "";
  }
  return "";
}

function getRiskScore(item: HistoryItem): number | null {
  if (item.risk_score != null) return item.risk_score;
  if (typeof item.summary === "object" && item.summary?.risk != null)
    return item.summary.risk;
  if (typeof item.summary === "string") {
    try {
      const p = JSON.parse(item.summary);
      return p.risk ?? null;
    } catch { return null; }
  }
  return null;
}

export default function History() {
  const [searchQuery, setSearchQuery] = useState("");
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [historyData, setHistoryData] = useState<HistoryItem[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(true);
  const navigate = useNavigate();

  const filteredHistory = historyData.filter((item) =>
    item.url.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm("Supprimer cette analyse ?")) return;
    try {
      await deleteHistoryItem(id);
      setHistoryData((prev) => prev.filter((item) => item.id !== id));
      toast.success("Supprimé !");
    } catch {
      toast.error("Erreur suppression");
    }
  };

  useEffect(() => {
    const load = async () => {
      try {
        const res = await getHistory();
        setHistoryData(Array.isArray(res) ? res : res.data || []);
      } catch {
        toast.error("Erreur chargement");
      } finally {
        setLoadingHistory(false);
      }
    };
    load();
  }, []);

  return (
    <div className="min-h-screen bg-slate-50 pb-12">

      <MenuButton onClick={() => setIsSidebarOpen(true)} />
      <Sidebar isOpen={isSidebarOpen} onClose={() => setIsSidebarOpen(false)} />

      {/* ── Topbar ── */}
      <div className="sticky top-0 z-10 bg-white/90 backdrop-blur border-b border-gray-100 px-4 py-3 flex items-center gap-3">
        <button onClick={() => navigate("/accueilpage")}
          className="flex items-center justify-center w-8 h-8 rounded-xl hover:bg-gray-100 transition-colors text-gray-500 shrink-0">
          <ArrowLeft size={18} />
        </button>
        <div className="flex-1 text-center">
          <h1 className="font-black text-gray-900 text-base leading-tight">Historique des analyses</h1>
          <p className="text-xs text-gray-400">{historyData.length} analyse(s) enregistrée(s)</p>
        </div>
        <div className="w-8 shrink-0" />
      </div>

      <div className="mx-4 mt-5">

        {/* ── Search ── */}
        <div className="relative mb-5">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
          <input
            className="w-full pl-9 pr-4 py-2.5 text-sm bg-white border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-300 transition"
            placeholder="Rechercher une URL..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        {/* ── List ── */}
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
              const score     = getRiskScore(item);
              const summaryTxt = getSummaryText(item.summary);
              const isCompleted = item.status === "completed";
              const isFailed    = item.status === "failed";

              return (
                <div key={item.id}
                  onClick={() => navigate(`/rapport/${item.id}`)}
                  className="bg-white rounded-2xl border border-gray-100 shadow-sm hover:shadow-md transition-all cursor-pointer overflow-hidden"
                  style={{ borderLeft: `4px solid ${score != null ? riskColor(score) : "#94a3b8"}` }}>

                  <div className="p-4">
                    <div className="flex items-start gap-3">

                      {/* Icon statut */}
                      <div className={`w-9 h-9 rounded-xl flex items-center justify-center shrink-0 ${
                        isCompleted ? "bg-green-50" : isFailed ? "bg-red-50" : "bg-blue-50"
                      }`}>
                        {isCompleted
                          ? <ShieldCheck size={18} className="text-green-600" />
                          : isFailed
                            ? <ShieldX size={18} className="text-red-500" />
                            : <Loader2 size={18} className="text-blue-500 animate-spin" />}
                      </div>

                      {/* Contenu */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-sm font-bold text-gray-800 truncate">{item.url}</span>
                          <a href={item.url} target="_blank" rel="noreferrer"
                            onClick={(e) => e.stopPropagation()}
                            className="shrink-0 text-gray-400 hover:text-indigo-500 transition-colors">
                            <ExternalLink size={13} />
                          </a>
                        </div>

                        {summaryTxt && (
                          <p className="text-xs text-gray-500 leading-relaxed mb-2 line-clamp-2">
                            {summaryTxt}
                          </p>
                        )}

                        <div className="flex items-center gap-3 text-[10px] text-gray-400">
                          <span className="flex items-center gap-1">
                            <Calendar size={10} /> {item.date}
                          </span>
                          <span className="flex items-center gap-1">
                            <Clock size={10} /> {item.time}
                          </span>
                        </div>
                      </div>

                      {/* Score + actions */}
                      <div className="flex flex-col items-end gap-2 shrink-0">
                        {score != null && (
                          <span className={`text-xs font-black px-2.5 py-1 rounded-full border ${riskBg(score)}`}>
                            {score}%
                          </span>
                        )}
                        <button
                          onClick={(e) => handleDelete(item.id, e)}
                          className="text-gray-300 hover:text-red-500 transition-colors">
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
    </div>
  );
}
import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  Search, Clock, Loader2, Calendar,
  Trash2, ArrowLeft,
  AlertTriangle, ShieldCheck, ShieldX, Eye,
} from "lucide-react";
import { getSurveillanceReports, deleteHistoryItem } from "../../services/auth.service";
import toast from "react-hot-toast";

interface RapportItem {
  id: string;
  url: string;
  status: string;
  date: string;
  time: string;
  summary?: any;
  risk_score?: number;
  changes_summary?: any;
}

function riskColor(score: number): string {
  if (score <= 20) return "#22c55e";
  if (score <= 40) return "#84cc16";
  if (score <= 60) return "#f97316";
  if (score <= 80) return "#ef4444";
  return "#dc2626";
}

function riskBadgeClass(score: number): string {
  if (score <= 40) return "risk-low";
  if (score <= 60) return "risk-mid";
  return "risk-high";
}

function getScanType(summary: any): string {
  if (!summary) return "";
  try {
    const s = typeof summary === "string" ? JSON.parse(summary) : summary;
    return s?.scan_type ?? "";
  } catch { return ""; }
}

function getAnomaliesCount(changes_summary: any): number {
  try {
    const cs = typeof changes_summary === "string" ? JSON.parse(changes_summary) : changes_summary;
    return Array.isArray(cs) ? cs.length : 0;
  } catch { return 0; }
}

function isAutoScan(summary: any): boolean {
  try {
    const s = typeof summary === "string" ? JSON.parse(summary) : summary;
    return s?.is_auto_scan === true;
  } catch { return false; }
}

const scanTypeBadgeClass: Record<string, string> = {
  léger:   "badge-leger",
  rapide:  "badge-rapide",
  complet: "badge-complet",
};

export default function ListeRapportsSurveillance() {
  const [searchQuery, setSearchQuery] = useState("");
  const [rapports,    setRapports]    = useState<RapportItem[]>([]);
  const [loading,     setLoading]     = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    (async () => {
      try {
        const res = await getSurveillanceReports();
        const all: RapportItem[] = Array.isArray(res) ? res : (res as any).data ?? [];
        setRapports(all.filter((r) => isAutoScan(r.summary)));
      } catch {
        toast.error("Erreur chargement des rapports");
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const filtered = rapports.filter((r) =>
    r.url.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm("Supprimer ce rapport de surveillance ?")) return;
    try {
      await deleteHistoryItem(id);
      setRapports((prev) => prev.filter((r) => r.id !== id));
      toast.success("Rapport supprimé");
    } catch {
      toast.error("Erreur suppression");
    }
  };

  return (
    <>
      <style>{`
        .surv-screen {
          min-height: 100svh;
          background: #f8f9fb;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        }

        /* ── Header ── */
        .surv-header {
          position: sticky;
          top: 0;
          z-index: 10;
          background: #fff;
          border-bottom: 0.5px solid rgba(0,0,0,0.08);
          padding: 12px 16px;
          display: flex;
          align-items: center;
          gap: 12px;
        }
        .surv-btn-icon {
          width: 34px;
          height: 34px;
          border-radius: 9px;
          border: 0.5px solid rgba(0,0,0,0.1);
          background: #fff;
          display: flex;
          align-items: center;
          justify-content: center;
          cursor: pointer;
          color: #6b7280;
          flex-shrink: 0;
          transition: background 0.15s;
        }
        .surv-btn-icon:hover { background: #f3f4f6; }
        .surv-header-title { flex: 1; text-align: center; }
        .surv-header-title h1 {
          font-size: 15px;
          font-weight: 600;
          color: #111827;
          line-height: 1.2;
        }
        .surv-header-title p {
          font-size: 11px;
          color: #9ca3af;
          margin-top: 1px;
        }
        .surv-spacer {
          width: 34px;
          flex-shrink: 0;
        }

        /* ── Content ── */
        .surv-content {
          padding: 16px;
          max-width: 480px;
          margin: 0 auto;
        }

        /* ── Search ── */
        .surv-search {
          position: relative;
          margin-bottom: 16px;
        }
        .surv-search svg {
          position: absolute;
          left: 11px;
          top: 50%;
          transform: translateY(-50%);
          color: #9ca3af;
        }
        .surv-search input {
          width: 100%;
          padding: 9px 12px 9px 34px;
          font-size: 13px;
          border: 0.5px solid rgba(0,0,0,0.1);
          border-radius: 10px;
          background: #fff;
          color: #111827;
          outline: none;
          transition: border-color 0.15s;
        }
        .surv-search input::placeholder { color: #9ca3af; }
        .surv-search input:focus { border-color: #6366f1; }

        /* ── Section label ── */
        .surv-section-label {
          font-size: 10.5px;
          font-weight: 600;
          color: #9ca3af;
          text-transform: uppercase;
          letter-spacing: 0.06em;
          margin-bottom: 10px;
        }

        /* ── Cards ── */
        .surv-card {
          background: #fff;
          border: 0.5px solid rgba(0,0,0,0.08);
          border-radius: 12px;
          margin-bottom: 10px;
          overflow: hidden;
          cursor: pointer;
          display: flex;
          transition: box-shadow 0.15s;
        }
        .surv-card:hover { box-shadow: 0 2px 10px rgba(0,0,0,0.06); }
        .surv-card-accent { width: 4px; flex-shrink: 0; border-radius: 0; }
        .surv-card-body {
          padding: 12px 12px 12px 11px;
          flex: 1;
          display: flex;
          gap: 10px;
          align-items: flex-start;
          min-width: 0;
        }

        /* ── Card icon ── */
        .surv-icon {
          width: 36px;
          height: 36px;
          border-radius: 9px;
          display: flex;
          align-items: center;
          justify-content: center;
          flex-shrink: 0;
        }
        .surv-icon-ok  { background: #f0fdf4; color: #16a34a; }
        .surv-icon-err { background: #fef2f2; color: #dc2626; }

        /* ── Card main ── */
        .surv-card-main { flex: 1; min-width: 0; }
        .surv-url-row {
          display: flex;
          align-items: center;
          gap: 6px;
          margin-bottom: 4px;
          flex-wrap: wrap;
        }
        .surv-url {
          font-size: 13px;
          font-weight: 600;
          color: #111827;
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
          max-width: 170px;
        }

        /* ── Scan-type badges ── */
        .surv-badge {
          font-size: 9.5px;
          font-weight: 600;
          padding: 2px 7px;
          border-radius: 99px;
          border: 0.5px solid;
          white-space: nowrap;
        }
        .badge-leger  { background: #dbeafe; color: #1e40af; border-color: #93c5fd; }
        .badge-rapide { background: #e0e7ff; color: #3730a3; border-color: #a5b4fc; }
        .badge-complet{ background: #ede9fe; color: #5b21b6; border-color: #c4b5fd; }

        /* ── Alert row ── */
        .surv-alert {
          font-size: 11px;
          font-weight: 600;
          color: #dc2626;
          display: flex;
          align-items: center;
          gap: 4px;
          margin-bottom: 4px;
        }

        /* ── Meta row ── */
        .surv-meta {
          display: flex;
          gap: 10px;
          font-size: 10px;
          color: #9ca3af;
          align-items: center;
          margin-top: 2px;
        }
        .surv-meta span { display: flex; align-items: center; gap: 3px; }

        /* ── Card right ── */
        .surv-card-right {
          display: flex;
          flex-direction: column;
          align-items: flex-end;
          justify-content: space-between;
          gap: 8px;
          flex-shrink: 0;
          padding-top: 1px;
        }

        /* ── Risk badge ── */
        .surv-risk {
          font-size: 11px;
          font-weight: 700;
          padding: 3px 9px;
          border-radius: 99px;
          border: 0.5px solid;
        }
        .risk-low  { background: #f0fdf4; color: #15803d; border-color: #bbf7d0; }
        .risk-mid  { background: #fff7ed; color: #c2410c; border-color: #fed7aa; }
        .risk-high { background: #fef2f2; color: #b91c1c; border-color: #fecaca; }

        /* ── Actions ── */
        .surv-actions { display: flex; gap: 8px; }
        .surv-actions button {
          background: none;
          border: none;
          padding: 0;
          cursor: pointer;
          color: #d1d5db;
          display: flex;
          align-items: center;
          transition: color 0.15s;
        }
        .surv-actions .btn-view:hover  { color: #6366f1; }
        .surv-actions .btn-del:hover   { color: #ef4444; }

        /* ── Empty state ── */
        .surv-empty {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          padding: 64px 24px;
          text-align: center;
        }
        .surv-empty-icon {
          width: 56px;
          height: 56px;
          border-radius: 14px;
          background: #eef2ff;
          display: flex;
          align-items: center;
          justify-content: center;
          margin-bottom: 16px;
          color: #a5b4fc;
        }
        .surv-empty h2 { font-size: 14px; font-weight: 600; color: #374151; margin-bottom: 6px; }
        .surv-empty p  { font-size: 12px; color: #9ca3af; line-height: 1.6; max-width: 240px; }
        .surv-empty-btn {
          margin-top: 20px;
          display: inline-flex;
          align-items: center;
          gap: 6px;
          padding: 9px 18px;
          border-radius: 10px;
          background: #6366f1;
          color: #fff;
          font-size: 13px;
          font-weight: 600;
          border: none;
          cursor: pointer;
          transition: background 0.15s;
        }
        .surv-empty-btn:hover { background: #4f46e5; }

        /* ── Loader ── */
        .surv-loader {
          display: flex;
          justify-content: center;
          align-items: center;
          padding: 64px 0;
          color: #6366f1;
        }
        .spin { animation: spin 0.8s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
      `}</style>

      <div className="surv-screen">
        {/* Header */}
        <div className="surv-header">
          <button
            className="surv-btn-icon"
            onClick={() => navigate("/accueilpage")}
            aria-label="Retour"
          >
            <ArrowLeft size={17} />
          </button>
          <div className="surv-header-title">
            <h1>Rapports de surveillance</h1>
            <p>{rapports.length} rapport(s) automatique(s)</p>
          </div>
          <div className="surv-spacer" />
        </div>

        <div className="surv-content">
          {/* Search */}
          <div className="surv-search">
            <Search size={15} />
            <input
              type="text"
              placeholder="Rechercher une URL..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          {/* List */}
          {loading ? (
            <div className="surv-loader">
              <Loader2 size={26} className="spin" />
            </div>
          ) : filtered.length === 0 ? (
            <div className="surv-empty">
              <div className="surv-empty-icon">
                <ShieldCheck size={26} />
              </div>
              <h2>Aucun rapport disponible</h2>
              <p>
                Les rapports apparaissent ici lorsque la surveillance automatique
                détecte une anomalie sur vos sites.
              </p>
              <button className="surv-empty-btn" onClick={() => navigate("/accueilpage")}>
                <ArrowLeft size={15} />
                Retour à l'accueil
              </button>
            </div>
          ) : (
            <>
              <p className="surv-section-label">Résultats récents</p>
              {filtered.map((item) => {
                const score     = item.risk_score ?? null;
                const scanType  = getScanType(item.summary);
                const anomalies = getAnomaliesCount(item.changes_summary);
                const hasIssue  = anomalies > 0;

                return (
                  <div
                    key={item.id}
                    className="surv-card"
                    onClick={() => navigate(`/surveillance/rapport/${item.id}`)}
                  >
                    <div
                      className="surv-card-accent"
                      style={{ background: score != null ? riskColor(score) : "#94a3b8" }}
                    />
                    <div className="surv-card-body">
                      {/* Icon */}
                      <div className={`surv-icon ${hasIssue ? "surv-icon-err" : "surv-icon-ok"}`}>
                        {hasIssue
                          ? <ShieldX size={18} />
                          : <ShieldCheck size={18} />
                        }
                      </div>

                      {/* Main */}
                      <div className="surv-card-main">
                        <div className="surv-url-row">
                          <span className="surv-url">{item.url}</span>
                          {scanType && (
                            <span className={`surv-badge ${scanTypeBadgeClass[scanType] ?? ""}`}>
                              {scanType}
                            </span>
                          )}
                        </div>

                        {hasIssue && (
                          <div className="surv-alert">
                            <AlertTriangle size={11} />
                            {anomalies} anomalie{anomalies > 1 ? "s" : ""} détectée{anomalies > 1 ? "s" : ""}
                          </div>
                        )}

                        <div className="surv-meta">
                          <span><Calendar size={10} /> {item.date}</span>
                          <span><Clock size={10} /> {item.time}</span>
                        </div>
                      </div>

                      {/* Right */}
                      <div className="surv-card-right">
                        {score != null && (
                          <span className={`surv-risk ${riskBadgeClass(score)}`}>
                            {score}%
                          </span>
                        )}
                        <div className="surv-actions">
                          <button
                            className="btn-view"
                            onClick={(e) => { e.stopPropagation(); navigate(`/surveillance/rapport/${item.id}`); }}
                            aria-label="Voir"
                          >
                            <Eye size={15} />
                          </button>
                          <button
                            className="btn-del"
                            onClick={(e) => handleDelete(item.id, e)}
                            aria-label="Supprimer"
                          >
                            <Trash2 size={15} />
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </>
          )}
        </div>
      </div>
    </>
  );
}
import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  ArrowLeft, Loader2, ChevronDown, ChevronUp,
  ShieldCheck, ShieldX, AlertTriangle, Lightbulb,
  LockKeyhole, Laptop, Globe, Bug, Wifi, Eye,
  AlertCircle, Server, Cpu, FileWarning,
  Trash2, Bell,
} from "lucide-react";
import { getReportById, deleteReport } from "../../services/auth.service";
import toast from "react-hot-toast";
import { parseRecs, getLevel, getLabel, getText } from "../../utils/rapportHelpers";

/* ─── Palette par outil ──────────────────────────────────────────────────── */
const TOOL_PALETTE = {
  headers:      { iconBg: "#EEF2FF", iconColor: "#6366F1", accent: "#6366F1", headerBg: "#F5F7FF", border: "#C7D2FE", glow: "rgba(99,102,241,0.10)"  },
  ssl:          { iconBg: "#ECFDF5", iconColor: "#10B981", accent: "#10B981", headerBg: "#F0FDF8", border: "#A7F3D0", glow: "rgba(16,185,129,0.10)"  },
  virustotal:   { iconBg: "#FFF7ED", iconColor: "#F97316", accent: "#F97316", headerBg: "#FFFBF5", border: "#FED7AA", glow: "rgba(249,115,22,0.10)"  },
  safebrowsing: { iconBg: "#FDF2F8", iconColor: "#EC4899", accent: "#EC4899", headerBg: "#FEF6FB", border: "#FBCFE8", glow: "rgba(236,72,153,0.10)"  },
  urlscan:      { iconBg: "#F0F9FF", iconColor: "#0EA5E9", accent: "#0EA5E9", headerBg: "#F5FBFF", border: "#BAE6FD", glow: "rgba(14,165,233,0.10)"  },
  shodan:       { iconBg: "#F5F3FF", iconColor: "#8B5CF6", accent: "#8B5CF6", headerBg: "#FAF8FF", border: "#DDD6FE", glow: "rgba(139,92,246,0.10)"  },
  wappalyzer:   { iconBg: "#FFF8F0", iconColor: "#EA580C", accent: "#EA580C", headerBg: "#FFFAF5", border: "#FED7AA", glow: "rgba(234,88,12,0.10)"   },
  zap:          { iconBg: "#FFF1F2", iconColor: "#E11D48", accent: "#E11D48", headerBg: "#FFF5F6", border: "#FECDD3", glow: "rgba(225,29,72,0.10)"   },
  nuclei:       { iconBg: "#FFF0F0", iconColor: "#DC2626", accent: "#DC2626", headerBg: "#FFF5F5", border: "#FECACA", glow: "rgba(220,38,38,0.10)"   },
};
type Palette = typeof TOOL_PALETTE["headers"];

/* ─── Helpers ────────────────────────────────────────────────────────────── */
function riskColor(score: number) {
  if (score <= 20) return "#22c55e";
  if (score <= 40) return "#84cc16";
  if (score <= 60) return "#f97316";
  if (score <= 80) return "#ef4444";
  return "#dc2626";
}
function riskLabel(score: number) {
  if (score <= 30) return "Faible";
  if (score <= 60) return "Modéré";
  return "Élevé";
}
function gradeColor(grade: string) {
  const g = grade?.toUpperCase();
  if (["A+","A","A-"].includes(g)) return "bg-green-100 text-green-700 border-green-300";
  if (g === "B") return "bg-lime-100 text-lime-700 border-lime-300";
  if (g === "C") return "bg-yellow-100 text-yellow-700 border-yellow-300";
  if (g === "D") return "bg-orange-100 text-orange-700 border-orange-300";
  return "bg-red-100 text-red-700 border-red-300";
}
function severityBg(level: string) {
  switch (level) {
    case "critique":  return "bg-red-50 text-red-700 border-red-200";
    case "important": return "bg-orange-50 text-orange-700 border-orange-200";
    case "moyen":     return "bg-yellow-50 text-yellow-700 border-yellow-200";
    case "info":      return "bg-blue-50 text-blue-700 border-blue-200";
    default:          return "bg-gray-50 text-gray-600 border-gray-200";
  }
}
function severityDot(level: string) {
  switch (level) {
    case "critique":  return "bg-red-500";
    case "important": return "bg-orange-400";
    case "moyen":     return "bg-yellow-400";
    case "info":      return "bg-blue-400";
    default:          return "bg-gray-400";
  }
}
function filterRecs(recs: string[]) {
  return recs.filter(rec => {
    const lvl = getLevel(rec) as string;
    const txt = getText(rec).toLowerCase();
    if (lvl === "info") {
      if (txt.includes("rapport de navigation complet")) return false;
      if (txt.includes("capture d'écran"))               return false;
      if (txt.includes("informations identifiées"))       return false;
      if (txt.includes("activité réseau"))                return false;
      if (txt.includes("adresse ip du serveur"))          return false;
      if (txt.includes("ports ouverts sans risque"))      return false;
      if (txt.includes("caractéristiques shodan"))        return false;
    }
    return true;
  });
}
function computeToolScore(recs: string[]): number | null {
  if (!recs.length) return null;
  const levels = recs.map(r => getLevel(r) as string);
  if (levels.some(l => l === "erreur"))    return null;
  if (levels.includes("critique"))  return Math.max(0,  30 - levels.filter(l => l === "critique").length  * 8);
  if (levels.includes("important")) return Math.max(30, 60 - levels.filter(l => l === "important").length * 8);
  if (levels.includes("moyen"))     return Math.max(60, 75 - levels.filter(l => l === "moyen").length     * 5);
  if (levels.some(l => l === "ok")) return 100;
  return null;
}

/* ─── Anomalie severity → style ─────────────────────────────────────────── */
function anomalyStyle(severity: string): { bg: string; text: string; border: string; dot: string } {
  switch (severity?.toUpperCase()) {
    case "CRITICAL": return { bg: "bg-red-50",    text: "text-red-700",    border: "border-red-200",    dot: "bg-red-500"    };
    case "HIGH":     return { bg: "bg-orange-50", text: "text-orange-700", border: "border-orange-200", dot: "bg-orange-400" };
    case "MEDIUM":   return { bg: "bg-yellow-50", text: "text-yellow-700", border: "border-yellow-200", dot: "bg-yellow-400" };
    default:         return { bg: "bg-blue-50",   text: "text-blue-700",   border: "border-blue-200",   dot: "bg-blue-400"   };
  }
}
function anomalyTypeLabel(type: string): string {
  const map: Record<string, string> = {
    AVAILABILITY:     "Site inaccessible",
    RISK_SCORE:       "Hausse du score de risque",
    VIRUSTOTAL:       "VirusTotal — Menace",
    SAFE_BROWSING:    "Google Safe Browsing",
    MISSING_HEADER:   "Header de sécurité manquant",
    SSL_EXPIRY:       "Certificat SSL — Expiration",
    URLSCAN_MALICIOUS:"urlscan.io — Malveillant",
    RISKY_PORT:       "Port dangereux",
  };
  return map[type] ?? type;
}

/* ─── Composants UI ──────────────────────────────────────────────────────── */
function ToolScoreDonut({ score }: { score: number }) {
  const r = 16, circ = 2 * Math.PI * r, dash = circ * (score / 100);
  const color = score >= 80 ? "#22c55e" : score >= 60 ? "#84cc16" : score >= 40 ? "#f97316" : "#ef4444";
  return (
    <div className="relative flex items-center justify-center shrink-0" style={{ width: 44, height: 44 }}>
      <svg width={44} height={44} viewBox="0 0 44 44" className="-rotate-90 absolute">
        <circle cx={22} cy={22} r={r} fill="none" stroke="#f1f5f9" strokeWidth={4} />
        <circle cx={22} cy={22} r={r} fill="none" stroke={color} strokeWidth={4}
          strokeDasharray={`${dash} ${circ}`} strokeLinecap="round" />
      </svg>
      <span className="text-[11px] font-black z-10" style={{ color }}>{score}</span>
    </div>
  );
}

function RiskDonut({ score }: { score: number }) {
  const color = riskColor(score);
  const r = 52, circ = 2 * Math.PI * r, dash = circ * (score / 100);
  return (
    <div className="relative flex items-center justify-center" style={{ width: 128, height: 128 }}>
      <svg width={128} height={128} viewBox="0 0 128 128" className="-rotate-90 absolute">
        <circle cx={64} cy={64} r={r} fill="none" stroke="#f1f5f9" strokeWidth={10} />
        <circle cx={64} cy={64} r={r} fill="none" stroke={color} strokeWidth={10}
          strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
          style={{ transition: "stroke-dasharray 1s ease" }} />
      </svg>
      <div className="flex flex-col items-center z-10">
        <span className="text-3xl font-black" style={{ color }}>{score}</span>
        <span className="text-xs text-gray-400 font-medium">/ 100</span>
      </div>
    </div>
  );
}

function ToolHeader({ palette, icon, name, badge, badgeVariant = "neutral", toolScore }: {
  palette: Palette; icon: React.ReactNode; name: string;
  badge?: string; badgeVariant?: "success"|"warning"|"danger"|"neutral"|"grade";
  toolScore?: number | null;
}) {
  const badgeClass: Record<string, string> = {
    success: "bg-green-100 text-green-700 border-green-300",
    warning: "bg-orange-100 text-orange-700 border-orange-300",
    danger:  "bg-red-100 text-red-600 border-red-300",
    neutral: "bg-gray-100 text-gray-600 border-gray-300",
    grade:   badge ? gradeColor(badge) : "bg-gray-100 text-gray-600 border-gray-300",
  };
  return (
    <div className="flex items-center gap-3 px-5 py-4 border-b"
      style={{ backgroundColor: palette.headerBg, borderColor: palette.border }}>
      <div className="flex items-center justify-center w-10 h-10 rounded-xl shrink-0"
        style={{ backgroundColor: palette.iconBg, color: palette.iconColor }}>
        {icon}
      </div>
      <span className="font-bold text-gray-800 text-base flex-1">{name}</span>
      {badge && (
        <span className={`text-xs font-semibold px-3 py-1 rounded-full border ${badgeClass[badgeVariant]}`}>
          {badge}
        </span>
      )}
      {toolScore != null && <ToolScoreDonut score={toolScore} />}
    </div>
  );
}

function RecsAccordion({ recs, accent, toolName }: { recs: string[]; accent: string; toolName: string }) {
  const [open, setOpen] = useState(false);
  const items = recs.filter(r => !(( getLevel(r) as string) === "info" && getText(r).length <= 60));
  const problemCount = items.filter(r => !["ok","info"].includes(getLevel(r) as string)).length;
  if (!items.length) return null;
  const hasCrit = items.some(r => (getLevel(r) as string) === "critique");
  const hasImp  = items.some(r => (getLevel(r) as string) === "important");
  const headerBg  = hasCrit ? "#FFF5F5" : hasImp ? "#FFFBEB" : `${accent}08`;
  const textColor = hasCrit ? "#B91C1C"  : hasImp ? "#92400E" : accent;
  const badgeBg   = hasCrit ? "#EF4444"  : hasImp ? "#F59E0B" : accent;
  return (
    <div className="border-t" style={{ borderColor: `${accent}30` }}>
      <button className="w-full flex items-center justify-between px-5 py-3 text-sm font-semibold"
        style={{ backgroundColor: headerBg, color: textColor }}
        onClick={() => setOpen(o => !o)}>
        <span className="flex items-center gap-2">
          <Lightbulb size={13} style={{ color: badgeBg }} />
          Recommandations — {toolName}
          {problemCount > 0 && (
            <span className="text-xs font-bold px-2 py-0.5 rounded-full text-white"
              style={{ backgroundColor: badgeBg }}>{problemCount}</span>
          )}
        </span>
        {open ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
      </button>
      {open && (
        <div className="px-5 pb-4 pt-3 flex flex-col gap-2 bg-white">
          {items.map((rec, i) => {
            const lvl  = getLevel(rec) as string;
            const text = getText(rec);
            const ai   = text.indexOf("Action :");
            const expl = ai !== -1 ? text.slice(0, ai).trim() : text;
            const act  = ai !== -1 ? text.slice(ai).trim()    : null;
            return (
              <div key={i} className={`rounded-lg border px-3 py-2.5 text-sm ${severityBg(lvl)}`}>
                <div className="flex items-center gap-2 mb-1.5">
                  <span className={`h-2 w-2 rounded-full shrink-0 ${severityDot(lvl)}`} />
                  <span className="font-bold">{getLabel(rec)}</span>
                </div>
                <p className="text-sm leading-snug pl-4 text-gray-700">{expl}</p>
                {act && (
                  <div className="mt-2 pl-4 flex items-start gap-1.5 border-t border-current border-opacity-10 pt-2">
                    <span className="text-xs font-black shrink-0 mt-0.5 opacity-60">→</span>
                    <p className="text-xs font-semibold leading-snug">{act}</p>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function ToolCard({ palette, children, recs, toolName }: {
  palette: Palette; children: React.ReactNode; recs: string[]; toolName: string;
}) {
  return (
    <div className="mx-4 mb-4 rounded-2xl overflow-hidden bg-white"
      style={{ border: `1px solid ${palette.border}`, borderLeft: `4px solid ${palette.accent}`, boxShadow: `0 2px 12px ${palette.glow}` }}>
      {children}
      <RecsAccordion recs={recs} accent={palette.accent} toolName={toolName} />
    </div>
  );
}

function InfoGrid({ items }: { items: { label: string; value: React.ReactNode; icon?: React.ReactNode; span?: boolean; warn?: boolean }[] }) {
  return (
    <div className="grid grid-cols-2 gap-2">
      {items.map((item, i) => (
        <div key={i} className={`bg-slate-50 rounded-xl p-3 ${item.span ? "col-span-2" : ""} ${item.warn ? "bg-orange-50" : ""}`}>
          <p className="text-[10px] text-gray-400 font-semibold uppercase mb-1">{item.label}</p>
          <p className={`text-sm font-bold flex items-center gap-1 ${item.warn ? "text-orange-500" : "text-gray-700"}`}>
            {item.icon && <span className="shrink-0">{item.icon}</span>}
            <span className="truncate">{item.value}</span>
          </p>
        </div>
      ))}
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════════════════
   MAIN PAGE
══════════════════════════════════════════════════════════════════════════ */
export default function RapportSurveillance() {
  const { id }   = useParams();
  const navigate = useNavigate();
  const [rapport,  setRapport]  = useState<any>(null);
  const [loading,  setLoading]  = useState(true);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    if (!id) return;
    (async () => {
      try {
        setRapport(await getReportById(id) as any);
      } catch {
        toast.error("Rapport introuvable");
        navigate("/surveillance/rapports");
      } finally {
        setLoading(false);
      }
    })();
  }, [id, navigate]);

  const handleDelete = async () => {
    if (!id || !confirm("Supprimer ce rapport de surveillance ?")) return;
    setDeleting(true);
    try {
      await deleteReport(id);
      toast.success("Rapport supprimé");
      navigate("/surveillance/rapports");
    } catch {
      toast.error("Erreur lors de la suppression");
      setDeleting(false);
    }
  };

  if (loading) return (
    <div className="flex items-center justify-center min-h-screen">
      <Loader2 className="animate-spin text-indigo-500" size={32} />
    </div>
  );

  if (!rapport) return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-slate-50 px-6">
      <div className="w-16 h-16 rounded-2xl bg-indigo-50 flex items-center justify-center mb-4">
        <Bell size={28} className="text-indigo-400" />
      </div>
      <h2 className="text-lg font-black text-gray-800 mb-2">Aucun rapport disponible</h2>
      <p className="text-sm text-gray-400 text-center mb-6">
        Les rapports apparaissent ici lorsque la surveillance détecte une anomalie sur vos sites.
      </p>
      <button
        onClick={() => navigate("/accueilpage")}
        className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-indigo-500 text-white text-sm font-bold hover:bg-indigo-600 transition-colors"
      >
        <ArrowLeft size={16} />
        Retour
      </button>
    </div>
  );

  /* ── Données brutes ── */
  const riskScore = rapport.risk_score ?? 0;

  // Summary meta (is_auto_scan, scan_type, anomalies)
  let summaryMeta: any = {};
  try {
    summaryMeta = typeof rapport.summary === "string"
      ? JSON.parse(rapport.summary)
      : rapport.summary ?? {};
  } catch { summaryMeta = {}; }

  const scanType    = summaryMeta.scan_type ?? "auto";
  const anomaliesRaw: any[] = (() => {
    try {
      const cs = rapport.changes_summary;
      return typeof cs === "string" ? JSON.parse(cs) : (Array.isArray(cs) ? cs : []);
    } catch { return []; }
  })();

  const headers           = rapport.full_report?.headers      ?? {};
  const present: string[] = headers.present ?? [];
  const missing: string[] = headers.missing ?? [];
  const grade: string     = headers.grade   ?? "N/A";
  const ssl = rapport.full_report?.ssl           ?? {};
  const vt  = rapport.full_report?.virustotal    ?? {};
  const sb  = rapport.full_report?.safe_browsing ?? {};
  const us  = rapport.full_report?.urlscan       ?? {};
  const sh  = rapport.full_report?.shodan        ?? {};
  const wa  = rapport.full_report?.wappalyzer    ?? {};
  const zap = rapport.full_report?.zap           ?? {};
  const nu  = rapport.full_report?.nuclei        ?? {};

  const displaySummary   = rapport.full_report?.display?.summary    ?? null;
  const displayRiskLabel = rapport.full_report?.display?.risk_level ?? null;

  const recsRaw     = rapport.full_report?.recommendations ?? rapport.recommendations;
  const recsHeaders = recsRaw ? filterRecs(parseRecs(recsRaw.headers))       : [];
  const recsSsl     = recsRaw ? filterRecs(parseRecs(recsRaw.ssl))           : [];
  const recsVt      = recsRaw ? filterRecs(parseRecs(recsRaw.virustotal))    : [];
  const recsSb      = recsRaw ? filterRecs(parseRecs(recsRaw.safe_browsing)) : [];
  const recsUs      = recsRaw ? filterRecs(parseRecs(recsRaw.urlscan))       : [];
  const recsSh      = recsRaw ? filterRecs(parseRecs(recsRaw.shodan))        : [];
  const recsWa      = recsRaw ? filterRecs(parseRecs(recsRaw.wappalyzer))    : [];
  const recsZap     = recsRaw ? filterRecs(parseRecs(recsRaw.zap))           : [];
  const recsNu      = recsRaw ? filterRecs(parseRecs(recsRaw.nuclei))        : [];

  const allRecs    = [...recsHeaders,...recsSsl,...recsVt,...recsSb,...recsUs,...recsSh,...recsWa,...recsZap,...recsNu];
  const critCount  = allRecs.filter(r => getLevel(r) === "critique").length;
  const highCount  = allRecs.filter(r => getLevel(r) === "important").length;

  const scoreHeaders = computeToolScore(recsHeaders);
  const scoreSsl     = computeToolScore(recsSsl);
  const scoreVt      = computeToolScore(recsVt);
  const scoreSb      = computeToolScore(recsSb);
  const scoreUs      = computeToolScore(recsUs);
  const scoreSh      = computeToolScore(recsSh);
  const scoreWa      = computeToolScore(recsWa);
  const scoreZap     = computeToolScore(recsZap);
  const scoreNu      = computeToolScore(recsNu);

  const sslSourceLabel = ssl._source === "python_ssl" ? "Analyse Python" : ssl._source === "testssl" ? "testssl.sh" : "SSL Labs";
  const sslGrade       = (ssl.grade ?? "").toUpperCase();
  const sslSafe        = ssl.safe !== undefined ? ssl.safe : ["A+","A","A-","B"].includes(sslGrade);
  const sslHost        = ssl.host ?? ssl.cert?.commonName ?? null;
  const usVerdictScore = us.verdict?.score ?? 0;
  const usPage         = us.page ?? {};
  const shodanIp       = sh.ip  ?? "—";
  const waTechs: any[]      = wa.technologies      ?? [];
  const waRiskyTechs: any[] = wa.risk_technologies ?? [];
  const waRiskLevel: string = wa.risk_level        ?? "low";
  const waRiskyCount        = waRiskyTechs.length;

  const scanTypeBadgeStyle: Record<string, string> = {
    léger:   "bg-blue-100 text-blue-700 border-blue-300",
    rapide:  "bg-indigo-100 text-indigo-700 border-indigo-300",
    complet: "bg-purple-100 text-purple-700 border-purple-300",
  };

  return (
  <div className="bg-slate-50 pb-12">
    {/* ── Topbar ── */}
    <div className="sticky top-0 z-10 bg-white/90 backdrop-blur border-b border-gray-100 px-4 py-3 flex items-center gap-3">
        <button onClick={() => navigate("/surveillance/rapports")}
          className="flex items-center justify-center w-8 h-8 rounded-xl hover:bg-gray-100 transition-colors text-gray-500 shrink-0">
          <ArrowLeft size={18} />
        </button>
        <div className="flex-1 text-center">
          <h1 className="font-black text-gray-900 text-base leading-tight">Rapport de surveillance</h1>
          <p className="text-xs text-gray-400 flex items-center justify-center gap-1">
            <Bell size={10} className="text-indigo-400" />
            Scan automatique
            {scanType && (
              <span className={`ml-1 text-[10px] font-bold px-1.5 py-0.5 rounded-full border ${scanTypeBadgeStyle[scanType] ?? "bg-gray-100 text-gray-500 border-gray-200"}`}>
                {scanType}
              </span>
            )}
          </p>
        </div>
        <button
          onClick={handleDelete}
          disabled={deleting}
          className="flex items-center justify-center w-8 h-8 rounded-xl hover:bg-red-50 transition-colors text-gray-400 hover:text-red-500 shrink-0 disabled:opacity-40"
          title="Supprimer ce rapport"
        >
          {deleting ? <Loader2 size={16} className="animate-spin" /> : <Trash2 size={16} />}
        </button>
      </div>

      {/* ── Bandeau anomalies détectées ── */}
      {anomaliesRaw.length > 0 && (
        <div className="mx-4 mt-4">
          <div className="rounded-2xl overflow-hidden border border-red-200 shadow-sm">
            {/* Header bandeau */}
            <div className="flex items-center gap-3 px-4 py-3 bg-red-50 border-b border-red-100">
              <div className="w-8 h-8 rounded-xl bg-red-100 flex items-center justify-center shrink-0">
                <AlertTriangle size={15} className="text-red-600" />
              </div>
              <div className="flex-1">
                <p className="text-sm font-black text-red-800">
                  {anomaliesRaw.length} anomalie{anomaliesRaw.length > 1 ? "s" : ""} détectée{anomaliesRaw.length > 1 ? "s" : ""}
                </p>
                <p className="text-[10px] text-red-500">Changements détectés depuis le dernier scan</p>
              </div>
              <span className="text-xs font-black px-2.5 py-1 rounded-full bg-red-100 text-red-700 border border-red-200">
                {anomaliesRaw.filter((a: any) => a.severity === "CRITICAL").length} critiques
              </span>
            </div>
            {/* Liste anomalies */}
            <div className="bg-white divide-y divide-red-50">
              {anomaliesRaw.map((anomaly: any, i: number) => {
                const style = anomalyStyle(anomaly.severity);
                return (
                  <div key={i} className={`flex items-start gap-3 px-4 py-3 ${style.bg}`}>
                    <span className={`h-2 w-2 rounded-full shrink-0 mt-1.5 ${style.dot}`} />
                    <div className="flex-1 min-w-0">
                      <p className={`text-xs font-black mb-0.5 ${style.text}`}>
                        {anomalyTypeLabel(anomaly.type)}
                      </p>
                      <p className={`text-xs leading-snug ${style.text} opacity-80`}>
                        {anomaly.message}
                      </p>
                    </div>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border shrink-0 ${style.bg} ${style.text} ${style.border}`}>
                      {anomaly.severity}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* ── Hero score ── */}
      <div className="mx-4 mt-4 rounded-2xl bg-white border border-gray-100 shadow-sm p-5">
        <p className="text-xs font-semibold text-gray-400 uppercase tracking-widest mb-1 text-center">URL analysée</p>
        <p className="text-sm font-bold text-gray-700 truncate mb-5 text-center">{rapport.url}</p>

        <div className="flex items-center gap-4">
          <div className="flex flex-col items-center gap-1 shrink-0">
            <RiskDonut score={riskScore} />
            <span className="text-xs font-bold text-gray-500">Score global</span>
          </div>
          <div className="flex-1 grid grid-cols-3 gap-2">
            <div className="rounded-xl bg-red-50 border border-red-100 p-3 flex flex-col gap-1">
              <span className="flex items-center gap-1 text-xs font-semibold text-red-500">
                <AlertCircle size={11} /> Critique
              </span>
              <span className="text-2xl font-black text-red-600">{critCount}</span>
              <span className="text-[10px] text-red-400 font-medium leading-tight">Action immédiate</span>
            </div>
            <div className="rounded-xl bg-orange-50 border border-orange-100 p-3 flex flex-col gap-1">
              <span className="flex items-center gap-1 text-xs font-semibold text-orange-500">
                <AlertTriangle size={11} /> Élevé
              </span>
              <span className="text-2xl font-black text-orange-500">{highCount}</span>
              <span className="text-[10px] text-orange-400 font-medium leading-tight">Prioritaire</span>
            </div>
            <div className="rounded-xl bg-indigo-50 border border-indigo-100 p-3 flex flex-col gap-1">
              <span className="flex items-center gap-1 text-xs font-semibold text-indigo-500">
                <Bell size={11} /> Anomalies
              </span>
              <span className="text-2xl font-black text-indigo-600">{anomaliesRaw.length}</span>
              <span className="text-[10px] text-indigo-400 font-medium leading-tight">Détectées</span>
            </div>
          </div>
        </div>

        {/* Barre de risque */}
        <div className="mt-5">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-sm font-semibold text-gray-500">Niveau de risque</span>
            <span className="text-xs font-black px-3 py-1 rounded-full text-white"
              style={{ background: riskColor(riskScore) }}>
              {displayRiskLabel?.emoji ?? ""} {displayRiskLabel?.label ?? riskLabel(riskScore)} — {riskScore}%
            </span>
          </div>
          <div className="h-3 rounded-full overflow-hidden" style={{ background: "#f1f5f9" }}>
            <div className="h-full rounded-full transition-all duration-700"
              style={{ width: `${riskScore}%`, background: "linear-gradient(90deg,#22c55e,#84cc16,#f97316,#ef4444)" }} />
          </div>
          <div className="flex justify-between mt-1">
            <span className="text-[10px] text-green-500 font-semibold">Sûr</span>
            <span className="text-[10px] text-red-500 font-semibold">Dangereux</span>
          </div>
        </div>

        {displaySummary && (
          <div className={`mt-4 rounded-xl px-4 py-3 border text-sm font-medium leading-relaxed ${
            riskScore >= 70 ? "bg-red-50 border-red-200 text-red-700"
            : riskScore >= 40 ? "bg-orange-50 border-orange-200 text-orange-700"
            : riskScore >= 15 ? "bg-yellow-50 border-yellow-200 text-yellow-700"
            : "bg-green-50 border-green-200 text-green-700"
          }`}>
            {displaySummary}
          </div>
        )}
      </div>

      <div className="mt-6 mb-3 px-5 text-center">
        <h2 className="text-xs font-black uppercase tracking-widest text-gray-400">Résultats par outil</h2>
      </div>

      {/* ══ Security Headers ══ */}
      <ToolCard palette={TOOL_PALETTE.headers} recs={recsHeaders} toolName="Security Headers">
        <ToolHeader palette={TOOL_PALETTE.headers} icon={<ShieldCheck size={18} />}
          name="Security Headers" badge={`Grade ${grade}`} badgeVariant="grade" toolScore={scoreHeaders} />
        <div className="px-5 py-4">
          {present.length > 0 && (
            <div className="mb-3">
              <p className="flex items-center gap-1 text-xs font-semibold text-green-600 mb-2"><ShieldCheck size={12} /> Headers présents</p>
              <div className="flex flex-wrap gap-1.5">
                {present.map(h => <span key={h} className="text-xs font-medium bg-green-50 text-green-700 border border-green-200 px-2 py-0.5 rounded-md">{h}</span>)}
              </div>
            </div>
          )}
          {missing.length > 0 && (
            <div>
              <p className="flex items-center gap-1 text-xs font-semibold text-red-500 mb-2"><ShieldX size={12} /> Headers manquants</p>
              <div className="flex flex-wrap gap-1.5">
                {missing.map(h => <span key={h} className="text-xs font-medium bg-red-50 text-red-600 border border-red-200 px-2 py-0.5 rounded-md">{h}</span>)}
              </div>
            </div>
          )}
          {!present.length && !missing.length && (
            <p className="text-sm text-gray-400">Données non disponibles</p>
          )}
        </div>
      </ToolCard>

      {/* ══ SSL ══ */}
      <ToolCard palette={TOOL_PALETTE.ssl} recs={recsSsl} toolName="SSL / TLS">
        <ToolHeader palette={TOOL_PALETTE.ssl} icon={<LockKeyhole size={18} />}
          name={sslSourceLabel}
          badge={ssl.status === "completed" ? `Grade ${ssl.grade ?? "N/A"}` : undefined}
          badgeVariant="grade" toolScore={scoreSsl} />
        <div className="px-5 py-4">
          {ssl.status === "failed" ? (
            <p className="flex items-center gap-2 text-sm text-orange-600 bg-orange-50 rounded-lg px-3 py-2">
              <AlertTriangle size={14} /> {ssl.message ?? ssl.error ?? "Analyse échouée"}
            </p>
          ) : ssl.status === "completed" ? (
            <div className="space-y-3">
              <InfoGrid items={[
                ...(sslHost ? [{ label: "Domaine",    value: sslHost,       icon: <Globe  size={12} /> }] : []),
                { label: "Source", value: sslSourceLabel, icon: <Server size={12} /> },
                ...(ssl.cert?.expiry ? [{ label: "Expiration", value: `${ssl.cert.expiry}${ssl.cert.daysRemaining != null ? ` (${ssl.cert.daysRemaining}j)` : ""}`, warn: ssl.cert.daysRemaining != null && ssl.cert.daysRemaining < 30 }] : []),
              ]} />
              <div className={`rounded-xl p-3 ${sslSafe ? "bg-green-50" : "bg-red-50"}`}>
                <p className={`text-sm font-bold ${sslSafe ? "text-green-700" : "text-red-600"}`}>
                  {sslSafe ? "✓ Configuration sécurisée" : "✗ Configuration insuffisante"}
                </p>
              </div>
            </div>
          ) : (
            <p className="flex items-center gap-2 text-sm text-gray-400 bg-gray-50 rounded-lg px-3 py-2">
              <AlertTriangle size={14} /> Données SSL non disponibles
            </p>
          )}
        </div>
      </ToolCard>

      {/* ══ VirusTotal ══ */}
      <ToolCard palette={TOOL_PALETTE.virustotal} recs={recsVt} toolName="VirusTotal">
        <ToolHeader palette={TOOL_PALETTE.virustotal} icon={<Bug size={18} />} name="VirusTotal"
          badge={vt.status === "completed" ? ((vt.malicious ?? 0) === 0 && (vt.suspicious ?? 0) === 0 ? "Sain" : "Menace") : undefined}
          badgeVariant={(vt.malicious ?? 0) === 0 && (vt.suspicious ?? 0) === 0 ? "success" : "danger"}
          toolScore={scoreVt} />
        <div className="px-5 py-4">
          {vt.status === "completed" ? (
            <div className="grid grid-cols-4 gap-2">
              {[
                { label: "Moteurs",      value: vt.total,      color: "text-gray-700",   bg: "bg-gray-50"   },
                { label: "Malveillants", value: vt.malicious,  color: "text-red-600",    bg: "bg-red-50"    },
                { label: "Suspects",     value: vt.suspicious, color: "text-orange-500", bg: "bg-orange-50" },
                { label: "Sains",        value: vt.harmless,   color: "text-green-600",  bg: "bg-green-50"  },
              ].map(s => (
                <div key={s.label} className={`rounded-xl ${s.bg} p-3 flex flex-col items-center gap-1`}>
                  <span className={`text-xl font-black ${s.color}`}>{s.value ?? "—"}</span>
                  <span className="text-[10px] text-gray-500 font-medium text-center">{s.label}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="flex items-center gap-2 text-sm text-gray-400 bg-gray-50 rounded-lg px-3 py-2">
              <AlertTriangle size={14} /> Données VirusTotal non disponibles
            </p>
          )}
        </div>
      </ToolCard>

      {/* ══ Google Safe Browsing ══ */}
      <ToolCard palette={TOOL_PALETTE.safebrowsing} recs={recsSb} toolName="Google Safe Browsing">
        <ToolHeader palette={TOOL_PALETTE.safebrowsing} icon={<ShieldCheck size={18} />}
          name="Google Safe Browsing"
          badge={sb.status === "completed" ? (sb.safe ? "Sain" : "Menace détectée") : undefined}
          badgeVariant={sb.safe ? "success" : "danger"} toolScore={scoreSb} />
        <div className="px-5 py-4">
          {sb.status === "completed" ? (
            <div>
              <div className={`rounded-xl p-4 mb-3 ${sb.safe ? "bg-green-50" : "bg-red-50"}`}>
                <p className={`text-sm font-bold ${sb.safe ? "text-green-700" : "text-red-600"}`}>
                  {sb.safe ? "✓ Aucune menace détectée par Google" : "✗ Ce site est signalé comme dangereux"}
                </p>
              </div>
              {!sb.safe && sb.threats?.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {sb.threats.map((t: string, i: number) => (
                    <span key={i} className="text-xs font-medium bg-red-50 text-red-600 border border-red-200 px-2 py-0.5 rounded-md">{t}</span>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <p className="flex items-center gap-2 text-sm text-gray-400 bg-gray-50 rounded-lg px-3 py-2">
              <AlertTriangle size={14} /> Données Safe Browsing non disponibles
            </p>
          )}
        </div>
      </ToolCard>

      {/* ══ urlscan.io ══ */}
      <ToolCard palette={TOOL_PALETTE.urlscan} recs={recsUs} toolName="urlscan.io">
        <ToolHeader palette={TOOL_PALETTE.urlscan} icon={<Eye size={18} />} name="urlscan.io"
          badge={us.status === "completed" ? (us.verdict?.malicious ? "Malveillant" : usVerdictScore > 50 ? "Suspect" : "Sain") : undefined}
          badgeVariant={us.verdict?.malicious ? "danger" : usVerdictScore > 50 ? "warning" : "success"}
          toolScore={scoreUs} />
        <div className="px-5 py-4">
          {us.status === "completed" ? (
            <div className="space-y-3">
              <InfoGrid items={[
                ...(usPage.domain  ? [{ label: "Domaine",    value: usPage.domain,  icon: <Globe  size={12} /> }] : []),
                ...(usPage.ip      ? [{ label: "IP",         value: usPage.ip,      icon: <Laptop size={12} /> }] : []),
                ...(usPage.country ? [{ label: "Pays",       value: usPage.country, icon: <Globe  size={12} /> }] : []),
                ...(usPage.server  ? [{ label: "Serveur",    value: usPage.server,  icon: <Server size={12} /> }] : []),
              ]} />
              <div className={`rounded-xl p-3 ${us.verdict?.malicious ? "bg-red-50" : usVerdictScore > 50 ? "bg-orange-50" : "bg-green-50"}`}>
                <p className={`text-sm font-bold ${us.verdict?.malicious ? "text-red-600" : usVerdictScore > 50 ? "text-orange-600" : "text-green-700"}`}>
                  {us.verdict?.malicious ? "✗ Comportement malveillant détecté"
                    : usVerdictScore > 50 ? `⚠ Comportement suspect (score ${usVerdictScore}/100)`
                    : `✓ Comportement normal (score ${usVerdictScore}/100)`}
                </p>
              </div>
            </div>
          ) : (
            <p className="flex items-center gap-2 text-sm text-gray-400 bg-gray-50 rounded-lg px-3 py-2">
              <AlertTriangle size={14} /> Données urlscan.io non disponibles
            </p>
          )}
        </div>
      </ToolCard>

      {/* ══ Shodan ══ */}
      <ToolCard palette={TOOL_PALETTE.shodan} recs={recsSh} toolName="Shodan InternetDB">
        <ToolHeader palette={TOOL_PALETTE.shodan} icon={<Wifi size={18} />} name="Shodan InternetDB"
          badge={sh.known === false ? "Aucune exposition" : sh.riskLevel === "high" ? "Risque élevé" : sh.riskLevel === "medium" ? "Risque modéré" : sh.known ? "Faible exposition" : undefined}
          badgeVariant={sh.riskLevel === "high" ? "danger" : sh.riskLevel === "medium" ? "warning" : "success"}
          toolScore={scoreSh} />
        <div className="px-5 py-4">
          {sh.known === false ? (
            <div className="bg-green-50 rounded-xl p-4">
              <p className="text-sm font-bold text-green-700">✓ Aucun service connu exposé sur Internet</p>
            </div>
          ) : sh.known ? (
            <div className="space-y-3">
              <InfoGrid items={[
                { label: "Adresse IP",    value: shodanIp,                     icon: <Laptop size={12} /> },
                { label: "Ports ouverts", value: `${sh.openPorts?.length ?? 0} détectés` },
              ]} />
              {sh.openPorts?.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {sh.openPorts.map((p: number) => (
                    <span key={p} className={`text-xs font-bold px-2 py-0.5 rounded-md border ${
                      sh.riskyPorts?.includes(p) ? "bg-red-50 text-red-600 border-red-200" : "bg-green-50 text-green-700 border-green-200"
                    }`}>{p}</span>
                  ))}
                </div>
              )}
              {sh.cves?.length > 0 && (
                <div>
                  <p className="text-sm font-semibold text-red-500 mb-1.5">CVEs ({sh.cves.length})</p>
                  <div className="flex flex-wrap gap-1.5">
                    {sh.cves.slice(0, 5).map((cve: string) => (
                      <a key={cve} href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve}`}
                        target="_blank" rel="noreferrer"
                        className="text-xs font-medium bg-red-50 text-red-600 border border-red-200 px-2 py-0.5 rounded-md">
                        {cve}
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <p className="flex items-center gap-2 text-sm text-gray-400 bg-gray-50 rounded-lg px-3 py-2">
              <AlertTriangle size={14} /> Données Shodan non disponibles
            </p>
          )}
        </div>
      </ToolCard>

      {/* ══ Wappalyzer ══ */}
      {wa.status === "completed" && (
        <ToolCard palette={TOOL_PALETTE.wappalyzer} recs={recsWa} toolName="Wappalyzer">
          <ToolHeader palette={TOOL_PALETTE.wappalyzer} icon={<Cpu size={18} />} name="Stack technologique"
            badge={waRiskyCount === 0 ? "Saine" : `${waRiskyCount} à risque`}
            badgeVariant={waRiskyCount === 0 ? "success" : waRiskLevel === "high" ? "danger" : "warning"}
            toolScore={scoreWa} />
          <div className="px-5 py-4">
            <div className="flex flex-wrap gap-1.5">
              {waTechs.map((tech: any, i: number) => (
                <span key={i} className={`text-xs font-medium px-2 py-0.5 rounded-md border ${
                  tech.risk === "high" ? "bg-red-50 text-red-600 border-red-200"
                  : tech.risk === "medium" ? "bg-orange-50 text-orange-600 border-orange-200"
                  : "bg-gray-50 text-gray-600 border-gray-200"
                }`}>{tech.name}{tech.version ? ` ${tech.version}` : ""}</span>
              ))}
            </div>
          </div>
        </ToolCard>
      )}

      {/* ══ ZAP ══ */}
      {zap.status === "completed" && (
        <ToolCard palette={TOOL_PALETTE.zap} recs={recsZap} toolName="OWASP ZAP">
          <ToolHeader palette={TOOL_PALETTE.zap} icon={<ShieldX size={18} />} name="OWASP ZAP"
            badge={(zap.alerts?.counts?.high ?? 0) > 0 ? `${zap.alerts.counts.high} critique(s)` : "Analysé"}
            badgeVariant={(zap.alerts?.counts?.high ?? 0) > 0 ? "danger" : "success"}
            toolScore={scoreZap} />
          <div className="px-5 py-4">
            <div className="grid grid-cols-4 gap-2">
              {[
                { label: "Critique",  value: zap.alerts?.counts?.high   ?? 0, bg: "bg-red-50",    text: "text-red-600"    },
                { label: "Important", value: zap.alerts?.counts?.medium ?? 0, bg: "bg-orange-50", text: "text-orange-500" },
                { label: "Mineur",    value: zap.alerts?.counts?.low    ?? 0, bg: "bg-yellow-50", text: "text-yellow-600" },
                { label: "Info",      value: zap.alerts?.counts?.info   ?? 0, bg: "bg-blue-50",   text: "text-blue-500"   },
              ].map(s => (
                <div key={s.label} className={`rounded-xl ${s.bg} p-3 flex flex-col items-center gap-1`}>
                  <span className={`text-xl font-black ${s.text}`}>{s.value}</span>
                  <span className="text-[10px] text-gray-500 font-medium text-center">{s.label}</span>
                </div>
              ))}
            </div>
          </div>
        </ToolCard>
      )}

      {/* ══ Nuclei ══ */}
      {nu.status === "completed" && (
        <ToolCard palette={TOOL_PALETTE.nuclei} recs={recsNu} toolName="Nuclei">
          <ToolHeader palette={TOOL_PALETTE.nuclei} icon={<FileWarning size={18} />}
            name="Nuclei — Vulnérabilités ciblées"
            badge={(nu.counts?.critical ?? 0) > 0 ? `${nu.counts.critical} critique(s)` : "Analysé"}
            badgeVariant={(nu.counts?.critical ?? 0) > 0 ? "danger" : "success"}
            toolScore={scoreNu} />
          <div className="px-5 py-4">
            <div className="grid grid-cols-5 gap-2">
              {[
                { label: "Critique", value: nu.counts?.critical ?? 0, bg: "bg-red-50",    text: "text-red-600"    },
                { label: "Élevé",    value: nu.counts?.high     ?? 0, bg: "bg-orange-50", text: "text-orange-500" },
                { label: "Modéré",   value: nu.counts?.medium   ?? 0, bg: "bg-yellow-50", text: "text-yellow-600" },
                { label: "Faible",   value: nu.counts?.low      ?? 0, bg: "bg-blue-50",   text: "text-blue-500"   },
                { label: "Info",     value: nu.counts?.info     ?? 0, bg: "bg-gray-50",   text: "text-gray-500"   },
              ].map(s => (
                <div key={s.label} className={`rounded-xl ${s.bg} p-2 flex flex-col items-center gap-0.5`}>
                  <span className={`text-lg font-black ${s.text}`}>{s.value}</span>
                  <span className="text-[9px] text-gray-400 font-medium text-center">{s.label}</span>
                </div>
              ))}
            </div>
          </div>
        </ToolCard>
      )}

    </div>
  );
}
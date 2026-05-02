import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  ArrowLeft, Loader2, ChevronDown, ChevronUp,
  ShieldCheck, ShieldX, AlertTriangle, Lightbulb,
  LockKeyhole, Laptop, Search, Globe, Bug, Wifi, Eye,
  AlertCircle, Info, Server, Cpu, Tag, FileWarning
} from "lucide-react";
import { getReportById } from "../../services/auth.service";
import toast from "react-hot-toast";
import { parseRecs, getLevel, getLabel, getText } from "../../utils/rapportHelpers";

/* ─── Palette par outil ──────────────────────────────────────────────────── */
const TOOL_PALETTE = {
  headers:      { iconBg: "#EEF2FF", iconColor: "#6366F1", accent: "#6366F1", headerBg: "#F5F7FF", border: "#C7D2FE", glow: "rgba(99,102,241,0.10)" },
  ssl:          { iconBg: "#ECFDF5", iconColor: "#10B981", accent: "#10B981", headerBg: "#F0FDF8", border: "#A7F3D0", glow: "rgba(16,185,129,0.10)" },
  virustotal:   { iconBg: "#FFF7ED", iconColor: "#F97316", accent: "#F97316", headerBg: "#FFFBF5", border: "#FED7AA", glow: "rgba(249,115,22,0.10)" },
  safebrowsing: { iconBg: "#FDF2F8", iconColor: "#EC4899", accent: "#EC4899", headerBg: "#FEF6FB", border: "#FBCFE8", glow: "rgba(236,72,153,0.10)" },
  //openphish:    { iconBg: "#FFF1F2", iconColor: "#F43F5E", accent: "#F43F5E", headerBg: "#FFF5F6", border: "#FECDD3", glow: "rgba(244,63,94,0.10)" },
  urlscan:      { iconBg: "#F0F9FF", iconColor: "#0EA5E9", accent: "#0EA5E9", headerBg: "#F5FBFF", border: "#BAE6FD", glow: "rgba(14,165,233,0.10)" },
  shodan:       { iconBg: "#F5F3FF", iconColor: "#8B5CF6", accent: "#8B5CF6", headerBg: "#FAF8FF", border: "#DDD6FE", glow: "rgba(139,92,246,0.10)" },
  wappalyzer:   { iconBg: "#FFF8F0", iconColor: "#EA580C", accent: "#EA580C", headerBg: "#FFFAF5", border: "#FED7AA", glow: "rgba(234,88,12,0.10)" },
};

type Palette = typeof TOOL_PALETTE["headers"];

/* ─── Score global ───────────────────────────────────────────────────────── */
function riskColor(score: number): string {
  if (score <= 20) return "#22c55e";
  if (score <= 40) return "#84cc16";
  if (score <= 60) return "#f97316";
  if (score <= 80) return "#ef4444";
  return "#dc2626";
}
function riskLabel(score: number): string {
  if (score <= 30) return "Faible";
  if (score <= 60) return "Modéré";
  return "Élevé";
}
function gradeColor(grade: string): string {
  const g = grade?.toUpperCase();
  if (g === "A+" || g === "A" || g === "A-") return "bg-green-100 text-green-700 border-green-300";
  if (g === "B")  return "bg-lime-100 text-lime-700 border-lime-300";
  if (g === "C")  return "bg-yellow-100 text-yellow-700 border-yellow-300";
  if (g === "D")  return "bg-orange-100 text-orange-700 border-orange-300";
  return "bg-red-100 text-red-700 border-red-300";
}
function severityBg(level: string): string {
  switch (level) {
    case "critique":  return "bg-red-50 text-red-700 border-red-200";
    case "important": return "bg-orange-50 text-orange-700 border-orange-200";
    case "moyen":     return "bg-yellow-50 text-yellow-700 border-yellow-200";
    case "info":      return "bg-blue-50 text-blue-700 border-blue-200";
    default:          return "bg-gray-50 text-gray-600 border-gray-200";
  }
}
function severityDot(level: string): string {
  switch (level) {
    case "critique":  return "bg-red-500";
    case "important": return "bg-orange-400";
    case "moyen":     return "bg-yellow-400";
    case "info":      return "bg-blue-400";
    default:          return "bg-gray-400";
  }
}
function filterRecs(recs: string[]): string[] {
  return recs.filter(rec => {
    const lvl = getLevel(rec) as string;
    const txt = getText(rec).toLowerCase();
    if (lvl === "info") {
      if (txt.includes("rapport de navigation complet")) return false;
      if (txt.includes("capture d'écran")) return false;
      if (txt.includes("informations identifiées")) return false;
      if (txt.includes("activité réseau")) return false;
      if (txt.includes("adresse ip du serveur")) return false;
      if (txt.includes("ports ouverts sans risque")) return false;
      if (txt.includes("caractéristiques shodan")) return false;
    }
    return true;
  });
}

/* ─── Calcul du score par outil (0–100) ─────────────────────────────────── */
function computeToolScore(recs: string[]): number | null {
  if (recs.length === 0) return null;
  const levels = recs.map(r => getLevel(r) as string);
  // Si toutes sont "ok" ou "info" → score parfait
  const hasCritique  = levels.includes("critique");
  const hasImportant = levels.includes("important");
  const hasMoyen     = levels.includes("moyen");
  const hasOk        = levels.some(l => l === "ok");
  const hasErreur    = levels.some(l => l === "erreur");

  if (hasErreur)    return null; // données indisponibles
  if (hasCritique)  return Math.max(0, 30  - levels.filter(l => l === "critique").length  * 8);
  if (hasImportant) return Math.max(30, 60 - levels.filter(l => l === "important").length * 8);
  if (hasMoyen)     return Math.max(60, 75 - levels.filter(l => l === "moyen").length     * 5);
  if (hasOk)        return 100;
  return null;
}

/* ─── Mini donut score par outil ─────────────────────────────────────────── */
function ToolScoreDonut({ score }: { score: number }) {
  const r = 16, circ = 2 * Math.PI * r;
  const dash = circ * (score / 100);
  const color = score >= 80 ? "#22c55e" : score >= 60 ? "#84cc16" : score >= 40 ? "#f97316" : "#ef4444";
  return (
    <div className="relative flex items-center justify-center shrink-0" style={{ width: 44, height: 44 }}>
      <svg width={44} height={44} viewBox="0 0 44 44" className="-rotate-90 absolute">
        <circle cx={22} cy={22} r={r} fill="none" stroke="#f1f5f9" strokeWidth={4} />
        <circle cx={22} cy={22} r={r} fill="none" stroke={color} strokeWidth={4}
          strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
          style={{ transition: "stroke-dasharray 1s ease" }} />
      </svg>
      <span className="text-[11px] font-black z-10" style={{ color }}>{score}</span>
    </div>
  );
}

/* ─── Donut score global ─────────────────────────────────────────────────── */
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

/* ─── ToolHeader avec score donut optionnel ──────────────────────────────── */
function ToolHeader({ palette, icon, name, badge, badgeVariant = "neutral", toolScore }: {
  palette: Palette; icon: React.ReactNode; name: string;
  badge?: string; badgeVariant?: "success" | "warning" | "danger" | "neutral" | "grade";
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
      {toolScore != null && (
        <ToolScoreDonut score={toolScore} />
      )}
    </div>
  );
}

/* ─── RecsAccordion ──────────────────────────────────────────────────────── */
function RecsAccordion({ recs, accent, toolName }: { recs: string[]; accent: string; toolName: string }) {
  const [open, setOpen] = useState(false);
  const items = recs.filter(r => {
    const lvl = getLevel(r) as string;
    const txt = getText(r);
    return !(lvl === "info" && txt.length <= 60);
  });
  const problemCount = items.filter(r => {
    const lvl = getLevel(r) as string;
    return lvl !== "ok" && lvl !== "info";
  }).length;
  if (items.length === 0) return null;
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
          <span>Recommandations — {toolName}</span>
          {problemCount > 0 && (
            <span className="text-xs font-bold px-2 py-0.5 rounded-full text-white"
              style={{ backgroundColor: badgeBg }}>
              {problemCount}
            </span>
          )}
        </span>
        {open ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
      </button>
      {open && (
        <div className="px-5 pb-4 pt-3 flex flex-col gap-2 bg-white">
          {items.map((rec, i) => {
            const lvl = getLevel(rec) as string;
            return (
              <div key={i} className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-sm ${severityBg(lvl)}`}>
                <span className={`mt-1.5 h-2 w-2 rounded-full shrink-0 ${severityDot(lvl)}`} />
                <span className="font-semibold mr-1 shrink-0">{getLabel(rec)}</span>
                <span className="leading-snug">{getText(rec)}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

/* ─── Suites de chiffrement avec accordion ───────────────────────────────── */
function SuitesSection({ suites }: { suites: any[] }) {
  const [showAll, setShowAll] = useState(false);
  const displayed = showAll ? suites : suites.slice(0, 4);
  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <p className="text-xs font-semibold text-gray-500 uppercase">Suites de chiffrement</p>
        <span className="text-xs font-medium px-2 py-0.5 rounded-full bg-slate-100 text-slate-500 border border-slate-200">
          {suites.length}
        </span>
      </div>
      <div className="flex flex-col gap-1.5">
        {displayed.map((s: any, i: number) => {
          const name = typeof s === "string" ? s : s.name ?? "Suite inconnue";
          const isWeak = /RC4|DES|NULL|EXPORT|anon|CBC/i.test(name);
          return (
            <div key={i} className={`flex items-center gap-2 rounded-lg px-3 py-2 border font-mono text-xs ${
              isWeak ? "bg-red-50 text-red-700 border-red-200" : "bg-slate-50 text-slate-700 border-slate-100"
            }`}>
              <span className={`h-2 w-2 rounded-full shrink-0 ${isWeak ? "bg-red-400" : "bg-green-500"}`} />
              {name}
            </div>
          );
        })}
      </div>
      {suites.length > 4 && (
        <button
          onClick={() => setShowAll(p => !p)}
          className="mt-2 w-full text-xs text-gray-400 border border-dashed border-gray-200 rounded-lg py-2 hover:bg-gray-50 transition-colors">
          {showAll ? "− Réduire" : `+ ${suites.length - 4} autres suites`}
        </button>
      )}
      <div className="flex gap-3 mt-2">
        <span className="flex items-center gap-1.5 text-xs text-gray-400">
          <span className="h-2 w-2 rounded-full bg-green-500 inline-block" /> Sécurisée
        </span>
        <span className="flex items-center gap-1.5 text-xs text-gray-400">
          <span className="h-2 w-2 rounded-full bg-red-400 inline-block" /> Faible
        </span>
      </div>
    </div>
  );
}

/* ─── ToolCard ───────────────────────────────────────────────────────────── */
function ToolCard({ palette, children, recs, toolName }: {
  palette: Palette; children: React.ReactNode; recs: string[]; toolName: string;
}) {
  return (
    <div className="mx-4 mb-4 rounded-2xl overflow-hidden bg-white"
      style={{
        border: `1px solid ${palette.border}`,
        borderLeft: `4px solid ${palette.accent}`,
        boxShadow: `0 2px 12px ${palette.glow}`,
      }}>
      {children}
      <RecsAccordion recs={recs} accent={palette.accent} toolName={toolName} />
    </div>
  );
}

/* ─── Badge risque technologie ───────────────────────────────────────────── */
function TechRiskBadge({ risk }: { risk: string }) {
  if (risk === "high")   return <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-md bg-red-100 text-red-600 border border-red-200">Élevé</span>;
  if (risk === "medium") return <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-md bg-orange-100 text-orange-600 border border-orange-200">Modéré</span>;
  return <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-md bg-green-100 text-green-700 border border-green-200">Faible</span>;
}

/* ─── InfoGrid : grille de métadonnées réutilisable ─────────────────────── */
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

/* ─── SSL Labs détail complet ────────────────────────────────────────────── */
function SslLabsDetail({ ssl }: { ssl: any }) {
  if (!ssl || ssl.status !== "completed") return null;

  const grade = ssl.grade ?? "N/A";
  const endpoints: any[] = ssl.endpoints ?? [];
  const ep = endpoints[0] ?? {};
  const details = ep.details ?? ssl ?? {};

  // Protocoles supportés
  const protocols: any[] = details.protocols ?? ssl.protocols ?? [];
  // Suites chiffrement
  const rawSuites: any[] = details.suites ?? [];
  const suites: any[] = rawSuites.flatMap((s: any) =>
  Array.isArray(s.list) ? s.list : (s.name ? [s] : [])
);
  // Vulnérabilités connues
  type VulnSeverity = "critique" | "important" | "ok";
  const vulns: { id: string; label: string; detected: boolean; severity: VulnSeverity }[] = [
    { id: "heartbleed",      label: "Heartbleed",       detected: !!details.heartbleed,         severity: "critique"  as VulnSeverity },
    { id: "poodle",          label: "POODLE",           detected: !!details.poodle,             severity: "critique"  as VulnSeverity },
    { id: "freak",           label: "FREAK",            detected: !!details.freak,              severity: "critique"  as VulnSeverity },
    { id: "logjam",          label: "Logjam",           detected: !!details.logjam,             severity: "important" as VulnSeverity },
    { id: "beast",           label: "BEAST",            detected: !!details.beast,              severity: "important" as VulnSeverity },
    { id: "poodleTls",       label: "POODLE TLS",       detected: details.poodleTls === 2, severity: "important"  as VulnSeverity },
    { id: "rc4",             label: "RC4",              detected: !!details.rc4,                severity: "important" as VulnSeverity },
    { id: "openSslCcs",      label: "OpenSSL CCS",      detected: details.openSslCcs === 2,     severity: "critique"  as VulnSeverity },
    { id: "ticketBleed",     label: "Ticketbleed",      detected: !!details.ticketBleed,        severity: "critique"  as VulnSeverity },
    { id: "bleichenbacher",  label: "Bleichenbacher",   detected: details.bleichenbacher === 2, severity: "critique"  as VulnSeverity },
  ].filter(v => v.detected || details[v.id] !== undefined);

  const detectedVulns  = vulns.filter(v => v.detected);
  const cleanVulns     = vulns.filter(v => !v.detected);

  // Certificate infos enrichies depuis SSL Labs
  const cert = ssl.cert ?? {};
  const certAlt: string[] = cert.altNames ?? [];

  return (
    <div className="space-y-3 mt-2">
      {/* Grade SSL Labs */}
      <div className="flex items-center gap-3 p-3 bg-slate-50 rounded-xl">
        <div className={`w-14 h-14 rounded-2xl flex items-center justify-center text-2xl font-black border-2 ${gradeColor(grade)}`}>
          {grade}
        </div>
        <div className="flex-1">
          <p className="text-xs text-gray-400 font-semibold uppercase mb-0.5">Grade SSL Labs</p>
          <p className="text-sm font-bold text-gray-700">
            {grade === "A+" ? "Configuration SSL exemplaire"
              : grade === "A" || grade === "A-" ? "Bonne configuration SSL"
              : grade === "B" ? "Configuration acceptable"
              : grade === "C" || grade === "D" ? "Configuration insuffisante"
              : "Configuration dangereuse"}
          </p>
          {ep.ipAddress && (
            <p className="text-xs text-gray-400 mt-0.5">IP analysée : {ep.ipAddress}</p>
          )}
        </div>
      </div>

      {/* Vulnérabilités */}
      {vulns.length > 0 && (
        <div>
          <p className="text-xs font-semibold text-gray-500 uppercase mb-2">Vulnérabilités vérifiées</p>
          <div className="grid grid-cols-2 gap-1.5">
            {detectedVulns.map(v => (
              <div key={v.id} className={`flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 border text-xs font-semibold
                ${v.severity === "critique" ? "bg-red-50 text-red-600 border-red-200" : "bg-orange-50 text-orange-600 border-orange-200"}`}>
                <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${v.severity === "critique" ? "bg-red-500" : "bg-orange-400"}`} />
                {v.label}
              </div>
            ))}
            {cleanVulns.slice(0, 6).map(v => (
              <div key={v.id} className="flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 border text-xs font-semibold bg-green-50 text-green-700 border-green-200">
                <span className="h-1.5 w-1.5 rounded-full shrink-0 bg-green-500" />
                {v.label} ✓
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Protocoles supportés */}
      {protocols.length > 0 && (
        <div>
          <p className="text-xs font-semibold text-gray-500 uppercase mb-2">Protocoles TLS</p>
          <div className="flex flex-wrap gap-1.5">
            {protocols.map((p: any, i: number) => {
              const name = typeof p === "string" ? p : `${p.name ?? p.protocol ?? ""} ${p.version ?? ""}`.trim();
              const isWeak = name.includes("1.0") || name.includes("1.1") || name.includes("SSL");
              return (
                <span key={i} className={`text-xs font-bold px-2 py-0.5 rounded-md border ${
                  isWeak ? "bg-red-50 text-red-600 border-red-200" : "bg-green-50 text-green-700 border-green-200"
                }`}>
                  {name}
                </span>
              );
            })}
          </div>
        </div>
      )}

      {/* Suites de chiffrement */}
      {suites.length > 0 && <SuitesSection suites={suites} />}

      {/* SAN (Subject Alternative Names) */}
      {certAlt.length > 0 && (
        <div>
          <p className="text-xs font-semibold text-gray-500 uppercase mb-2">Domaines couverts ({certAlt.length})</p>
          <div className="flex flex-wrap gap-1">
            {certAlt.slice(0, 8).map((alt: string, i: number) => (
              <span key={i} className="text-xs bg-indigo-50 text-indigo-700 border border-indigo-200 px-2 py-0.5 rounded-md font-mono">
                {alt}
              </span>
            ))}
            {certAlt.length > 8 && (
              <span className="text-xs text-gray-400">+{certAlt.length - 8}</span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════════════════
   MAIN PAGE
══════════════════════════════════════════════════════════════════════════ */
export default function Rapport() {
  const { id }   = useParams();
  const navigate = useNavigate();
  const [rapport, setRapport] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!id) return;
    (async () => {
      try {
        setRapport(await getReportById(id) as any);
      } catch {
        toast.error("Rapport introuvable");
        navigate("/historique");
      } finally {
        setLoading(false);
      }
    })();
  }, [id, navigate]);

  if (loading) return (
    <div className="flex items-center justify-center min-h-screen">
      <Loader2 className="animate-spin text-indigo-500" size={32} />
    </div>
  );

  /* ── Données brutes ── */
  const riskScore = rapport.risk_score ?? 0;

  const headers            = rapport.full_report?.headers      ?? {};
  const present: string[]  = headers.present ?? [];
  const missing: string[]  = headers.missing ?? [];
  const grade: string      = headers.grade   ?? "N/A";

  const ssl = rapport.full_report?.ssl           ?? {};
  const vt  = rapport.full_report?.virustotal    ?? {};
  const sb  = rapport.full_report?.safe_browsing ?? {};
  //const op  = rapport.full_report?.openphish     ?? {};
  const us  = rapport.full_report?.urlscan       ?? {};
  const sh  = rapport.full_report?.shodan        ?? {};
  const wa  = rapport.full_report?.wappalyzer    ?? {};

  /* ── Résumé display généré par task.py ── */
  const displaySummary   = rapport.full_report?.display?.summary   ?? null;
  const displayRiskLabel = rapport.full_report?.display?.risk_level ?? null;

  /* ── Recommandations ── */
  const recsRaw = rapport.full_report?.recommendations ?? rapport.recommendations;

  const recsHeaders = recsRaw ? filterRecs(parseRecs(recsRaw.headers))       : [];
  const recsSsl     = recsRaw ? filterRecs(parseRecs(recsRaw.ssl))           : [];
  const recsVt      = recsRaw ? filterRecs(parseRecs(recsRaw.virustotal))    : [];
  const recsSb      = recsRaw ? filterRecs(parseRecs(recsRaw.safe_browsing)) : [];
  //const recsOp      = recsRaw ? filterRecs(parseRecs(recsRaw.openphish))     : [];
  const recsUs      = recsRaw ? filterRecs(parseRecs(recsRaw.urlscan))       : [];
  const recsSh      = recsRaw ? filterRecs(parseRecs(recsRaw.shodan))        : [];
  const recsWa      = recsRaw ? filterRecs(parseRecs(recsRaw.wappalyzer))    : [];

  const allRecs = [...recsHeaders, ...recsSsl, ...recsVt, ...recsSb, ...recsUs, ...recsSh, ...recsWa];

  const critCount = allRecs.filter(r => getLevel(r) === "critique").length;
  const highCount = allRecs.filter(r => getLevel(r) === "important").length;

  /* ── Scores par outil ── */
  const scoreHeaders = computeToolScore(recsHeaders);
  const scoreSsl     = computeToolScore(recsSsl);
  const scoreVt      = computeToolScore(recsVt);
  const scoreSb      = computeToolScore(recsSb);
  //const scoreOp      = computeToolScore(recsOp);
  const scoreUs      = computeToolScore(recsUs);
  const scoreSh      = computeToolScore(recsSh);
  const scoreWa      = computeToolScore(recsWa);

  const totalProbs = (() => {
    let count = 0;
    count += missing.length;
    if (ssl.status === "completed" && !["A+","A","A-","B"].includes((ssl.grade ?? "").toUpperCase()) && !ssl.safe) count += 1;
    if (vt.status === "completed") count += (vt.malicious ?? 0) + (vt.suspicious ?? 0);
    if (sb.status === "completed" && !sb.safe) count += 1;
    //if (op.status === "completed" && op.phishing) count += 1;
    if (us.status === "completed" && (us.verdict?.malicious || (us.verdict?.score ?? 0) > 50)) count += 1;
    if (sh.known && sh.cves?.length) count += sh.cves.length;
    if (sh.known && sh.riskyPorts?.length) count += sh.riskyPorts.length;
    if (wa.status === "completed") count += (wa.risk_technologies?.length ?? 0);
    return count;
  })();

  /* ── Données dérivées ── */
  const usVerdictScore  = us.verdict?.score ?? 0;
  const sslSourceLabel  = ssl._source === "python_ssl" ? "Analyse Python"
    : ssl._source === "testssl" ? "testssl.sh" : "SSL Labs";
  // Déduire ssl.safe depuis le grade si absent (SSL Labs ne retourne pas safe)
  const sslGrade = (ssl.grade ?? "").toUpperCase();
  const sslSafe  = ssl.safe !== undefined
    ? ssl.safe
    : ["A+", "A", "A-", "B"].includes(sslGrade);
  const sslHost         = ssl.host ?? ssl.cert?.commonName ?? null;
  const sslProtocol = ssl.protocols?.length
  ? (() => {
      const p = ssl.protocols[ssl.protocols.length - 1];
      return typeof p === "string" ? p : `${p.name ?? p.protocol ?? ""} ${p.version ?? ""}`.trim();
    })()
  : undefined;
  const usPage          = us.page ?? {};
  const shodanIp        = sh.ip ?? "—";

  /* ── Wappalyzer ── */
  const waTechs: any[]      = wa.technologies      ?? [];
  const waRiskyTechs: any[] = wa.risk_technologies ?? [];
  const waRiskLevel: string  = wa.risk_level       ?? "low";
  const waRiskyCount         = waRiskyTechs.length;

  /* ── SSL CVEs ── */
  const sslCves: any[] = ssl.cves ?? [];

  return (
    <div className="min-h-screen bg-slate-50 pb-12">

      {/* ── Topbar ── */}
      <div className="sticky top-0 z-10 bg-white/90 backdrop-blur border-b border-gray-100 px-4 py-3 flex items-center gap-3">
        <button onClick={() => navigate("/historique")}
          className="flex items-center justify-center w-8 h-8 rounded-xl hover:bg-gray-100 transition-colors text-gray-500 shrink-0">
          <ArrowLeft size={18} />
        </button>
        <div className="flex-1 text-center">
          <h1 className="font-black text-gray-900 text-base leading-tight">Rapport de sécurité</h1>
          <p className="text-xs text-gray-400">Analyse complète des vulnérabilités détectées</p>
        </div>
        <div className="w-8 shrink-0" />
      </div>

      {/* ── Hero ── */}
      <div className="mx-4 mt-5 rounded-2xl bg-white border border-gray-100 shadow-sm p-5">
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
            <div className="rounded-xl bg-slate-50 border border-slate-100 p-3 flex flex-col gap-1">
              <span className="flex items-center gap-1 text-xs font-semibold text-slate-500">
                <Info size={11} /> Total
              </span>
              <span className="text-2xl font-black text-slate-700">{totalProbs}</span>
              <span className="text-[10px] text-slate-400 font-medium leading-tight">Erreurs détectées</span>
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
              style={{ width: `${riskScore}%`, background: `linear-gradient(90deg, #22c55e, #84cc16, #f97316, #ef4444)` }} />
          </div>
          <div className="flex justify-between mt-1">
            <span className="text-[10px] text-green-500 font-semibold">Sûr</span>
            <span className="text-[10px] text-red-500 font-semibold">Dangereux</span>
          </div>
        </div>

        {/* ── Résumé textuel généré par task.py ── */}
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

      {/* ══ 1. Security Headers ══ */}
      <ToolCard palette={TOOL_PALETTE.headers} recs={recsHeaders} toolName="Security Headers">
        <ToolHeader palette={TOOL_PALETTE.headers} icon={<ShieldCheck size={18} />}
          name="Security Headers" badge={`Grade ${grade}`} badgeVariant="grade"
          toolScore={scoreHeaders} />
        <div className="px-5 py-4">
          {present.length > 0 && (
            <div className="mb-3">
              <p className="flex items-center gap-1 text-xs font-semibold text-green-600 mb-2">
                <ShieldCheck size={12} /> Headers présents
              </p>
              <div className="flex flex-wrap gap-1.5">
                {present.map(h => (
                  <span key={h} className="text-xs font-medium bg-green-50 text-green-700 border border-green-200 px-2 py-0.5 rounded-md">{h}</span>
                ))}
              </div>
            </div>
          )}
          {missing.length > 0 && (
            <div>
              <p className="flex items-center gap-1 text-xs font-semibold text-red-500 mb-2">
                <ShieldX size={12} /> Headers manquants
              </p>
              <div className="flex flex-wrap gap-1.5">
                {missing.map(h => (
                  <span key={h} className="text-xs font-medium bg-red-50 text-red-600 border border-red-200 px-2 py-0.5 rounded-md">{h}</span>
                ))}
              </div>
            </div>
          )}
          {headers.status === "failed" && (
            <p className="flex items-center gap-2 text-sm text-orange-600 bg-orange-50 rounded-lg px-3 py-2">
              <AlertTriangle size={14} /> Analyse échouée : {headers.error}
            </p>
          )}
          {!present.length && !missing.length && headers.status !== "failed" && (
            <p className="text-sm text-gray-400">Données non disponibles</p>
          )}
        </div>
      </ToolCard>

      {/* ══ 2. SSL / TLS ══ */}
      <ToolCard palette={TOOL_PALETTE.ssl} recs={recsSsl} toolName="SSL / TLS">
        <ToolHeader palette={TOOL_PALETTE.ssl} icon={<LockKeyhole size={18} />}
          name={sslSourceLabel}
          badge={ssl.status === "completed" ? `Grade ${ssl.grade ?? "N/A"}` : undefined}
          badgeVariant="grade"
          toolScore={scoreSsl} />
        <div className="px-5 py-4">
          {ssl.status === "failed" ? (
            <p className="flex items-center gap-2 text-sm text-orange-600 bg-orange-50 rounded-lg px-3 py-2">
              <AlertTriangle size={14} /> {ssl.message ?? ssl.error ?? "Analyse échouée"}
            </p>
          ) : ssl.status === "completed" ? (
            <div className="space-y-3">
              <InfoGrid items={[
                ...(sslHost ? [{ label: "Domaine", value: sslHost, icon: <Globe size={12} /> }] : []),
                { label: sslProtocol ? "Protocole" : "Source", value: sslProtocol ?? sslSourceLabel, icon: <Server size={12} /> },
                ...(ssl.cert?.issuer ? [{ label: "Émetteur", value: ssl.cert.issuer }] : []),
                ...(ssl.cert?.expiry ? [{
                  label: "Expiration",
                  value: `${ssl.cert.expiry}${ssl.cert.daysRemaining != null ? ` (${ssl.cert.daysRemaining}j)` : ""}`,
                  warn: ssl.cert.daysRemaining != null && ssl.cert.daysRemaining < 30,
                }] : []),
              ]} />

              <div className={`rounded-xl p-3 ${sslSafe ? "bg-green-50" : "bg-red-50"}`}>
                <p className={`text-sm font-bold ${sslSafe ? "text-green-700" : "text-red-600"}`}>
                  {sslSafe ? "✓ Configuration sécurisée" : "✗ Configuration insuffisante"}
                </p>
              </div>

              {/* ── Détail complet SSL Labs (si source ssllabs) ── */}
              {ssl._source === "ssllabs" && <SslLabsDetail ssl={ssl} />}

              {/* ── CVEs SSL (python_ssl / testssl) ── */}
              {ssl._source !== "ssllabs" && sslCves.length > 0 && (
                <div>
                  <p className="flex items-center gap-1 text-xs font-semibold text-red-500 mb-2">
                    <FileWarning size={12} /> Failles SSL détectées ({sslCves.length})
                  </p>
                  <div className="flex flex-col gap-1.5">
                    {sslCves.slice(0, 4).map((cve: any, i: number) => (
                      <div key={i} className="flex items-start gap-2 bg-red-50 border border-red-200 rounded-lg px-3 py-2">
                        <span className="text-xs font-bold text-red-600 shrink-0">{cve.id ?? cve}</span>
                        {cve.detail && <span className="text-xs text-red-500 leading-snug">{cve.detail}</span>}
                      </div>
                    ))}
                    {sslCves.length > 4 && (
                      <span className="text-xs text-red-400 px-1">+{sslCves.length - 4} autre(s) faille(s)</span>
                    )}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <p className="flex items-center gap-2 text-sm text-gray-400 bg-gray-50 rounded-lg px-3 py-2">
              <AlertTriangle size={14} /> Données SSL non disponibles
            </p>
          )}
        </div>
      </ToolCard>

      {/* ══ 3. VirusTotal ══ */}
      <ToolCard palette={TOOL_PALETTE.virustotal} recs={recsVt} toolName="VirusTotal">
        <ToolHeader palette={TOOL_PALETTE.virustotal} icon={<Bug size={18} />} name="VirusTotal"
          badge={vt.status === "completed"
            ? ((vt.malicious ?? 0) === 0 && (vt.suspicious ?? 0) === 0 ? "Sain" : "Menace")
            : undefined}
          badgeVariant={(vt.malicious ?? 0) === 0 && (vt.suspicious ?? 0) === 0 ? "success" : "danger"}
          toolScore={scoreVt} />
        <div className="px-5 py-4">
          {vt.status === "failed" ? (
            <p className="flex items-center gap-2 text-sm text-orange-600 bg-orange-50 rounded-lg px-3 py-2">
              <AlertTriangle size={14} /> Analyse échouée : {vt.error}
            </p>
          ) : vt.status === "disabled" ? (
            <p className="flex items-center gap-2 text-sm text-gray-500 bg-gray-50 rounded-lg px-3 py-2">
              <AlertTriangle size={14} /> Clé API VirusTotal non configurée
            </p>
          ) : vt.status === "completed" ? (
            <>
              <div className="grid grid-cols-4 gap-2 mb-3">
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
              {vt.permalink && (
                <a href={vt.permalink} target="_blank" rel="noreferrer"
                  className="flex items-center gap-1.5 text-sm font-semibold text-indigo-600 hover:text-indigo-800 transition-colors">
                  <Search size={13} /> Voir le rapport complet sur VirusTotal →
                </a>
              )}
            </>
          ) : (
            <p className="flex items-center gap-2 text-sm text-gray-400 bg-gray-50 rounded-lg px-3 py-2">
              <AlertTriangle size={14} /> Données VirusTotal non disponibles
            </p>
          )}
        </div>
      </ToolCard>

      {/* ══ 4. Google Safe Browsing ══ */}
      <ToolCard palette={TOOL_PALETTE.safebrowsing} recs={recsSb} toolName="Google Safe Browsing">
        <ToolHeader palette={TOOL_PALETTE.safebrowsing} icon={<ShieldCheck size={18} />}
          name="Google Safe Browsing"
          badge={sb.status === "completed" ? (sb.safe ? "Sain" : "Menace détectée") : undefined}
          badgeVariant={sb.safe ? "success" : "danger"}
          toolScore={scoreSb} />
        <div className="px-5 py-4">
          {sb.status === "failed" ? (
            <p className="flex items-center gap-2 text-sm text-orange-600 bg-orange-50 rounded-lg px-3 py-2">
              <AlertTriangle size={14} /> Analyse échouée : {sb.error}
            </p>
          ) : sb.status === "disabled" ? (
            <p className="flex items-center gap-2 text-sm text-gray-500 bg-gray-50 rounded-lg px-3 py-2">
              <AlertTriangle size={14} /> Clé API Google Safe Browsing non configurée
            </p>
          ) : sb.status === "completed" ? (
            <div>
              <div className={`rounded-xl p-4 mb-3 ${sb.safe ? "bg-green-50" : "bg-red-50"}`}>
                <p className={`text-sm font-bold ${sb.safe ? "text-green-700" : "text-red-600"}`}>
                  {sb.safe ? "✓ Aucune menace détectée par Google" : "✗ Ce site est signalé comme dangereux par Google"}
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



{/* ══ 5. urlscan.io ══ */}
<ToolCard palette={TOOL_PALETTE.urlscan} recs={recsUs} toolName="urlscan.io">
  <ToolHeader palette={TOOL_PALETTE.urlscan} icon={<Eye size={18} />} name="urlscan.io"
    badge={us.status === "completed"
      ? (us.verdict?.malicious ? "Malveillant" : usVerdictScore > 50 ? "Suspect" : "Sain")
      : undefined}
    badgeVariant={us.verdict?.malicious ? "danger" : usVerdictScore > 50 ? "warning" : "success"}
    toolScore={scoreUs} />
  <div className="px-5 py-4">
    {us.status === "failed" || (us.error && !us.verdict) ? (
      <div className="space-y-2">
        <p className="flex items-center gap-2 text-sm text-orange-600 bg-orange-50 rounded-lg px-3 py-2">
          <AlertTriangle size={14} /> Analyse indisponible pour ce site
        </p>
        <p className="text-xs text-gray-400 px-1">
          Certains sites (Facebook, Google…) bloquent les scanners automatiques ou sont protégés par urlscan.io.
        </p>
      </div>
    ) : us.status === "disabled" || us.skipped ? (
      <p className="flex items-center gap-2 text-sm text-gray-500 bg-gray-50 rounded-lg px-3 py-2">
        <AlertTriangle size={14} /> Clé API urlscan.io non configurée
      </p>
    ) : us.status === "completed" ? (
      <div className="space-y-3">
        <InfoGrid items={[
          ...(usPage.domain  ? [{ label: "Domaine",         value: usPage.domain,  icon: <Globe size={12} /> }] : []),
          ...(usPage.ip      ? [{ label: "Adresse IP",      value: usPage.ip,      icon: <Laptop size={12} /> }] : []),
          ...(usPage.country ? [{ label: "Pays du serveur", value: usPage.country, icon: <Globe size={12} /> }] : []),
          ...(usPage.server  ? [{ label: "Serveur web",     value: usPage.server,  icon: <Server size={12} /> }] : []),
          ...(usPage.tlsValidDays != null ? [{
            label: "SSL expire dans",
            value: `${usPage.tlsValidDays} jour(s)`,
            icon: <LockKeyhole size={12} />,
            warn: usPage.tlsValidDays < 14,
          }] : []),
          ...(usPage.title ? [{ label: "Titre de la page", value: usPage.title, span: true }] : []),
        ]} />

        <div className={`rounded-xl p-3 flex items-center ${
          us.verdict?.malicious ? "bg-red-50" : usVerdictScore > 50 ? "bg-orange-50" : "bg-green-50"
        }`}>
          <p className={`text-sm font-bold ${
            us.verdict?.malicious ? "text-red-600" : usVerdictScore > 50 ? "text-orange-600" : "text-green-700"
          }`}>
            {us.verdict?.malicious
              ? "✗ Comportement malveillant détecté"
              : usVerdictScore > 50
                ? `⚠ Comportement suspect (score ${usVerdictScore}/100)`
                : `✓ Comportement normal (score ${usVerdictScore}/100)`}
          </p>
        </div>

        {((us.stats?.requests ?? 0) > 0 || (us.stats?.uniqueDomains ?? 0) > 0 || (us.stats?.uniqueIPs ?? 0) > 0) && (
          <div className="grid grid-cols-3 gap-2">
            {[
              { label: "Requêtes",         value: us.stats?.requests      ?? 0 },
              { label: "Domaines externes", value: us.stats?.uniqueDomains ?? 0 },
              { label: "IPs distinctes",    value: us.stats?.uniqueIPs     ?? 0 },
            ].map(s => (
              <div key={s.label} className="bg-slate-50 rounded-xl p-3 flex flex-col items-center gap-1">
                <span className="text-lg font-black text-gray-700">{s.value}</span>
                <span className="text-[10px] text-gray-500 font-medium text-center">{s.label}</span>
              </div>
            ))}
          </div>
        )}

        {us.verdict?.brands?.length > 0 && (
          <div className="bg-red-50 rounded-xl p-3">
            <p className="text-sm font-bold text-red-600">
              ⚠ Usurpation de marque : {us.verdict.brands.join(", ")}
            </p>
          </div>
        )}

        {us.verdict?.tags?.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {us.verdict.tags.map((tag: string, i: number) => (
              <span key={i} className="text-xs font-medium bg-blue-50 text-blue-600 border border-blue-200 px-2 py-0.5 rounded-md">
                {tag}
              </span>
            ))}
          </div>
        )}

        {us.reportUrl && (
          <a href={us.reportUrl} target="_blank" rel="noreferrer"
            className="flex items-center gap-1.5 text-sm font-semibold text-indigo-600 hover:text-indigo-800 transition-colors">
            <Search size={13} /> Voir le rapport complet sur urlscan.io →
          </a>
        )}
      </div>
    ) : (
      <p className="flex items-center gap-2 text-sm text-gray-400 bg-gray-50 rounded-lg px-3 py-2">
        <AlertTriangle size={14} /> Données urlscan.io non disponibles
      </p>
    )}
  </div>
</ToolCard>
      {/* ══ 6. Shodan InternetDB ══ */}
      <ToolCard palette={TOOL_PALETTE.shodan} recs={recsSh} toolName="Shodan InternetDB">
        <ToolHeader palette={TOOL_PALETTE.shodan} icon={<Wifi size={18} />} name="Shodan InternetDB"
          badge={
            sh.known === false ? "Aucune exposition"
            : sh.riskLevel === "high"   ? "Risque élevé"
            : sh.riskLevel === "medium" ? "Risque modéré"
            : sh.known ? "Faible exposition" : undefined
          }
          badgeVariant={sh.riskLevel === "high" ? "danger" : sh.riskLevel === "medium" ? "warning" : "success"}
          toolScore={scoreSh} />
        <div className="px-5 py-4">
          {sh.error && sh.known !== false ? (
            <p className="flex items-center gap-2 text-sm text-orange-600 bg-orange-50 rounded-lg px-3 py-2">
              <AlertTriangle size={14} /> Analyse échouée : {sh.error}
            </p>
          ) : sh.known === false ? (
            <div className="bg-green-50 rounded-xl p-4">
              <p className="text-sm font-bold text-green-700">✓ Aucun service connu exposé sur Internet</p>
            </div>
          ) : sh.known ? (
            <div className="space-y-3">
              <InfoGrid items={[
                { label: "Adresse IP",    value: shodanIp,               icon: <Laptop size={12} /> },
                { label: "Ports ouverts", value: `${sh.openPorts?.length ?? 0} détectés` },
              ]} />

              {sh.tags?.length > 0 && (
                <div>
                  <p className="flex items-center gap-1 text-xs font-semibold text-purple-600 mb-2">
                    <Tag size={12} /> Caractéristiques du serveur
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {sh.tags.map((tag: string, i: number) => (
                      <span key={i} className="text-xs font-medium bg-purple-50 text-purple-600 border border-purple-200 px-2 py-0.5 rounded-md">
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {sh.openPorts?.length > 0 && (
                <div>
                  <p className="text-sm font-semibold text-gray-500 mb-1.5">Ports ouverts</p>
                  <div className="flex flex-wrap gap-1.5">
                    {sh.openPorts.map((p: number) => (
                      <span key={p} className={`text-xs font-bold px-2 py-0.5 rounded-md border ${
                        sh.riskyPorts?.includes(p)
                          ? "bg-red-50 text-red-600 border-red-200"
                          : "bg-green-50 text-green-700 border-green-200"
                      }`}>{p}</span>
                    ))}
                  </div>
                </div>
              )}

              {sh.cves?.length > 0 && (
                <div>
                  <p className="text-sm font-semibold text-red-500 mb-1.5">CVEs détectés ({sh.cves.length})</p>
                  <div className="flex flex-wrap gap-1.5">
                    {sh.cves.slice(0, 5).map((cve: string) => (
                      <a key={cve}
                        href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve}`}
                        target="_blank" rel="noreferrer"
                        className="text-xs font-medium bg-red-50 text-red-600 border border-red-200 px-2 py-0.5 rounded-md hover:bg-red-100 transition-colors">
                        {cve}
                      </a>
                    ))}
                    {sh.cves.length > 5 && (
                      <span className="text-xs font-medium bg-red-50 text-red-400 border border-red-100 px-2 py-0.5 rounded-md">
                        +{sh.cves.length - 5} autres
                      </span>
                    )}
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

      {/* ══ 7. Wappalyzer ══ */}
      <ToolCard palette={TOOL_PALETTE.wappalyzer} recs={recsWa} toolName="Wappalyzer">
        <ToolHeader
          palette={TOOL_PALETTE.wappalyzer}
          icon={<Cpu size={18} />}
          name="Stack technologique"
          badge={
            wa.status === "completed"
              ? waRiskyCount === 0
                ? "Saine"
                : waRiskLevel === "high"
                  ? `${waRiskyCount} risque(s) élevé(s)`
                  : `${waRiskyCount} à surveiller`
              : undefined
          }
          badgeVariant={
            waRiskyCount === 0 ? "success"
            : waRiskLevel === "high" ? "danger"
            : "warning"
          }
          toolScore={scoreWa}
        />
        <div className="px-5 py-4">
          {wa.status === "failed" ? (
            <p className="flex items-center gap-2 text-sm text-orange-600 bg-orange-50 rounded-lg px-3 py-2">
              <AlertTriangle size={14} /> Analyse échouée : {wa.error}
            </p>
          ) : wa.status === "completed" ? (
            <div className="space-y-3">
              <div className="grid grid-cols-3 gap-2">
                <div className="bg-slate-50 rounded-xl p-3 flex flex-col items-center gap-1">
                  <span className="text-xl font-black text-gray-700">{waTechs.length}</span>
                  <span className="text-[10px] text-gray-500 font-medium text-center">Détectées</span>
                </div>
                <div className={`rounded-xl p-3 flex flex-col items-center gap-1 ${waRiskyCount > 0 ? "bg-red-50" : "bg-green-50"}`}>
                  <span className={`text-xl font-black ${waRiskyCount > 0 ? "text-red-600" : "text-green-600"}`}>
                    {waRiskyCount}
                  </span>
                  <span className="text-[10px] text-gray-500 font-medium text-center">À risque</span>
                </div>
                <div className={`rounded-xl p-3 flex flex-col items-center gap-1 ${
                  waRiskLevel === "high" ? "bg-red-50" : waRiskLevel === "medium" ? "bg-orange-50" : "bg-green-50"
                }`}>
                  <span className={`text-sm font-black ${
                    waRiskLevel === "high" ? "text-red-600" : waRiskLevel === "medium" ? "text-orange-500" : "text-green-600"
                  }`}>
                    {waRiskLevel === "high" ? "Élevé" : waRiskLevel === "medium" ? "Modéré" : "Faible"}
                  </span>
                  <span className="text-[10px] text-gray-500 font-medium text-center">Niveau</span>
                </div>
              </div>

              {waRiskyTechs.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-red-500 mb-2 flex items-center gap-1">
                    <AlertTriangle size={11} /> Technologies à risque
                  </p>
                  <div className="flex flex-col gap-1.5">
                    {waRiskyTechs.map((tech: any, i: number) => (
                      <div key={i} className="flex items-center justify-between bg-red-50 border border-red-100 rounded-lg px-3 py-2">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="text-sm font-bold text-gray-800 truncate">{tech.name}</span>
                          {tech.version && (
                            <span className="text-[10px] font-medium text-gray-400 shrink-0">v{tech.version}</span>
                          )}
                        </div>
                        <div className="flex items-center gap-1.5 shrink-0 ml-2">
                          {tech.categories?.length > 0 && (
                            <span className="text-[10px] text-gray-400 hidden sm:inline">{tech.categories[0]}</span>
                          )}
                          <TechRiskBadge risk={tech.risk} />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {waTechs.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-gray-500 mb-2">Toutes les technologies détectées</p>
                  <div className="flex flex-wrap gap-1.5">
                    {waTechs.map((tech: any, i: number) => (
                      <span key={i} className={`text-xs font-medium px-2 py-0.5 rounded-md border ${
                        tech.risk === "high"
                          ? "bg-red-50 text-red-600 border-red-200"
                          : tech.risk === "medium"
                            ? "bg-orange-50 text-orange-600 border-orange-200"
                            : "bg-gray-50 text-gray-600 border-gray-200"
                      }`}>
                        {tech.name}{tech.version ? ` ${tech.version}` : ""}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {waTechs.length === 0 && (
                <div className="bg-green-50 rounded-xl p-4">
                  <p className="text-sm font-bold text-green-700">
                    ✓ Aucune technologie identifiable — le site protège ses en-têtes
                  </p>
                </div>
              )}
            </div>
          ) : (
            <p className="flex items-center gap-2 text-sm text-gray-400 bg-gray-50 rounded-lg px-3 py-2">
              <AlertTriangle size={14} /> Données Wappalyzer non disponibles
            </p>
          )}
        </div>
      </ToolCard>

    </div>
  );
}
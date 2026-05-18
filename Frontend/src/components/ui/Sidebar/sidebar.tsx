// components/ui/Sidebar/sidebar.tsx

import { Link, useLocation, useNavigate } from "react-router-dom";
import {
  FingerprintIcon, LogOut, History, User,
  Home as HomeIcon, X, Loader2, CheckCircle,
  XCircle, Bell, PanelLeft,
} from "lucide-react";
import { logout } from "../../../services/auth.service";
import { useScan } from "../../../context/Scancontext";

interface SidebarProps {
  isOpen:  boolean;
  onClose: () => void;
  onOpen:  () => void;
}

const menuItems = [
  { icon: HomeIcon, label: "Accueil",      path: "/accueilpage"           },
  { icon: History,  label: "Historique",   path: "/historique"            },
  { icon: Bell,     label: "Surveillance", path: "/surveillance/rapports" },
  { icon: User,     label: "Profil",       path: "/profil"                },
];

// ── Rail fermé (52px) ──────────────────────────────────────────────────────
function SidebarRail({ onOpen }: { onOpen: () => void }) {
  const location                           = useLocation();
  const navigate                           = useNavigate();
  const { activeScans, pendingCount }      = useScan();
  const runningCount = activeScans.filter(
    s => s.status === "pending" || s.status === "running"
  ).length;

  return (
    <aside className="w-[52px] h-screen bg-white border-r border-gray-100 flex flex-col items-center py-3 gap-1 shrink-0">

      {/* Logo */}
      <div className="w-8 h-8 rounded-lg bg-indigo-50 flex items-center justify-center mb-3">
        <FingerprintIcon size={17} className="text-indigo-600" />
      </div>

      {/* Nav items */}
      {menuItems.map(item => {
        const isActive = location.pathname === item.path;
        const isSurv   = item.path === "/surveillance/rapports";
        return (
          <div key={item.path} className="relative group">
            <Link to={item.path}>
              <div className={`w-9 h-9 rounded-lg flex items-center justify-center cursor-pointer transition-colors ${
                isActive
                  ? "bg-indigo-50 text-indigo-600"
                  : "text-gray-400 hover:bg-gray-100 hover:text-gray-700"
              }`}>
                <item.icon size={18} />
                {/* Badge surveillance */}
                {isSurv && pendingCount > 0 && (
                  <span className="absolute top-0.5 right-0.5 w-3.5 h-3.5 rounded-full bg-red-500 text-white text-[9px] font-bold flex items-center justify-center border border-white">
                    {pendingCount}
                  </span>
                )}
              </div>
            </Link>
            {/* Tooltip */}
            <div className="absolute left-[46px] top-1/2 -translate-y-1/2 z-50 pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity">
              <div className="bg-white border border-gray-100 rounded-lg px-2.5 py-1 text-xs font-medium text-gray-700 whitespace-nowrap shadow-sm">
                {item.label}
              </div>
            </div>
          </div>
        );
      })}

      <div className="w-6 h-px bg-gray-100 my-1" />

      {/* Scans actifs */}
      {runningCount > 0 && (
        <div className="relative group">
          <div
            className="w-9 h-9 rounded-lg flex items-center justify-center text-indigo-500 hover:bg-indigo-50 cursor-pointer transition-colors"
            onClick={() => navigate("/accueilpage")}
          >
            <Loader2 size={18} className="animate-spin" />
            <span className="absolute top-0.5 right-0.5 w-3.5 h-3.5 rounded-full bg-green-500 text-white text-[9px] font-bold flex items-center justify-center border border-white">
              {runningCount}
            </span>
          </div>
          <div className="absolute left-[46px] top-1/2 -translate-y-1/2 z-50 pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity">
            <div className="bg-white border border-gray-100 rounded-lg px-2.5 py-1 text-xs font-medium text-gray-700 whitespace-nowrap shadow-sm">
              {runningCount} analyse{runningCount > 1 ? "s" : ""} en cours
            </div>
          </div>
        </div>
      )}

      {/* Spacer */}
      <div className="flex-1" />

      {/* Bouton ouvrir */}
      <div className="relative group">
        <button
          onClick={onOpen}
          className="w-9 h-9 rounded-lg flex items-center justify-center text-gray-400 hover:bg-gray-100 hover:text-gray-700 transition-colors"
          aria-label="Ouvrir le menu"
        >
          <PanelLeft size={18} />
        </button>
        <div className="absolute left-[46px] top-1/2 -translate-y-1/2 z-50 pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity">
          <div className="bg-white border border-gray-100 rounded-lg px-2.5 py-1 text-xs font-medium text-gray-700 whitespace-nowrap shadow-sm">
            Ouvrir le menu
          </div>
        </div>
      </div>

    </aside>
  );
}

// ── Sidebar ouverte (220px) ────────────────────────────────────────────────
export function Sidebar({ isOpen, onClose, onOpen }: SidebarProps) {
  const navigate                      = useNavigate();
  const location                      = useLocation();
  const { activeScans, removeScan, pendingCount } = useScan();

  const runningCount = activeScans.filter(
    s => s.status === "pending" || s.status === "running"
  ).length;

  const handleLogout = async () => {
    await logout();
    navigate("/login");
  };

  if (!isOpen) return <SidebarRail onOpen={onOpen} />;

  return (
    <aside className="w-[220px] h-screen bg-white border-r border-gray-100 flex flex-col py-3 px-3 shrink-0">

      {/* Header */}
      <div className="flex items-center gap-2.5 px-2 pb-3 mb-1 border-b border-gray-100">
        <div className="w-8 h-8 rounded-lg bg-indigo-50 flex items-center justify-center shrink-0">
          <FingerprintIcon size={17} className="text-indigo-600" />
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-[13px] font-medium text-gray-800 leading-tight">SecureScan</p>
          <p className="text-[11px] text-gray-400 leading-tight">Analyse de sécurité</p>
        </div>
        <button
          onClick={onClose}
          className="w-7 h-7 flex items-center justify-center rounded-lg text-gray-400 hover:bg-gray-100 hover:text-gray-700 transition-colors shrink-0"
          aria-label="Fermer"
        >
          <X size={15} />
        </button>
      </div>

      {/* Nav */}
      <nav className="flex flex-col gap-0.5 mt-2">
        {menuItems.map(item => {
          const isActive = item.path === "/surveillance/rapports"
            ? location.pathname.startsWith("/surveillance")
            : location.pathname === item.path;
          const isSurv   = item.path === "/surveillance/rapports";
          return (
            <Link key={item.path} to={item.path} onClick={onClose}>
              <div className={`flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-[13px] transition-colors ${
                isActive
                  ? "bg-indigo-50 text-indigo-600 font-medium"
                  : "text-gray-500 hover:bg-gray-100 hover:text-gray-800"
              }`}>
                <item.icon size={16} className="shrink-0" />
                <span className="flex-1">{item.label}</span>
                {isSurv && pendingCount > 0 && (
                  <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-full bg-red-500 text-white">
                    {pendingCount}
                  </span>
                )}
              </div>
            </Link>
          );
        })}
      </nav>

      {/* Scans actifs */}
      {activeScans.length > 0 && (
        <div className="mt-3">
          <p className="text-[10px] font-medium text-gray-400 uppercase tracking-wider px-2 mb-1.5">
            En cours
          </p>
          <div className="bg-gray-50 rounded-lg overflow-hidden">
            {/* Header compteur */}
            <div className="flex items-center justify-between px-2.5 py-1.5 border-b border-gray-100">
              <span className="text-[11px] text-gray-500 flex items-center gap-1.5">
                {runningCount > 0 && (
                  <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse inline-block" />
                )}
                {runningCount > 0
                  ? `${runningCount} analyse${runningCount > 1 ? "s" : ""} active${runningCount > 1 ? "s" : ""}`
                  : "Terminées"}
              </span>
            </div>

            {/* Liste scans */}
            <div className="flex flex-col max-h-[140px] overflow-y-auto">
              {activeScans.map(scan => (
                <div key={scan.taskId} className="flex items-center gap-2 px-2.5 py-2 border-b border-gray-100 last:border-0">
                  <div className="shrink-0">
                    {(scan.status === "pending" || scan.status === "running") && (
                      <Loader2 size={12} className="animate-spin text-indigo-400" />
                    )}
                    {scan.status === "completed" && (
                      <CheckCircle size={12} className="text-green-500" />
                    )}
                    {scan.status === "failed" && (
                      <XCircle size={12} className="text-red-400" />
                    )}
                  </div>

                  <div className="flex-1 min-w-0">
                    <p className="text-[11px] font-medium text-gray-700 truncate">
                      {scan.url.replace(/^https?:\/\//, "").slice(0, 24)}
                      {scan.url.replace(/^https?:\/\//, "").length > 24 ? "…" : ""}
                    </p>
                    {(scan.status === "pending" || scan.status === "running") && (
                      <div className="mt-0.5 w-full bg-gray-200 rounded-full h-0.5">
                        <div
                          className="h-0.5 rounded-full bg-indigo-400 transition-all duration-500"
                          style={{ width: `${scan.progress ?? 0}%` }}
                        />
                      </div>
                    )}
                  </div>

                  {scan.status === "completed" && scan.reportId && (
                    <button
                      className="text-[10px] font-medium text-indigo-500 hover:text-indigo-700 shrink-0"
                      onClick={() => { navigate(`/rapport/${scan.reportId}`); removeScan(scan.taskId); }}
                    >
                      Voir →
                    </button>
                  )}
                  {(scan.status === "completed" || scan.status === "failed") && !scan.reportId && (
                    <button
                      className="text-gray-300 hover:text-red-400 shrink-0"
                      onClick={() => removeScan(scan.taskId)}
                    >
                      <X size={11} />
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Spacer */}
      <div className="flex-1" />

      {/* Logout */}
      <button
        onClick={handleLogout}
        className="flex items-center gap-2.5 w-full px-2.5 py-2 rounded-lg text-[13px] text-red-500 border border-gray-100 hover:bg-red-50 transition-colors mt-2"
      >
        <LogOut size={15} />
        Se déconnecter
      </button>

    </aside>
  );
}
import { Link, useLocation, useNavigate } from "react-router";
import { Button } from "../button";
import {
  FingerprintIcon, LogOut, History, User,
  Home as HomeIcon, Menu, X, Loader2, CheckCircle, XCircle
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { logout } from "../../../services/auth.service";
import { useScan } from "../../../context/Scancontext";
//import { useNavigate as useNav } from "react-router-dom";
import "./sidebar.css";

interface SidebarProps {
  isOpen:  boolean;
  onClose: () => void;
}

export function Sidebar({ isOpen, onClose }: SidebarProps) {
  const navigate = useNavigate();
  const location = useLocation();
  const { activeScans, removeScan, pendingCount } = useScan();

  const menuItems = [
    { icon: HomeIcon, label: "Accueil",    path: "/accueilpage" },
    { icon: History,  label: "Historique", path: "/historique"  },
    { icon: User,     label: "Profil",     path: "/profil"      },
  ];

  const handleLogout = async () => {
    await logout();
    navigate("/login");
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Overlay */}
          <motion.div
            onClick={onClose}
            className="overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          />

          {/* Sidebar */}
          <motion.aside
            className="sidebar"
            initial={{ x: "-100%" }}
            animate={{ x: 0 }}
            exit={{ x: "-100%" }}
            transition={{ type: "spring", damping: 25, stiffness: 200 }}
          >
            <div className="sidebar-content">

              {/* Header */}
              <div className="sidebar-header">
                <div className="logo">
                  <FingerprintIcon className="logo-icon" />
                  <div>
                    <h2>Ma Plateforme</h2>
                    <p>Plateforme d'analyse de sécurité</p>
                  </div>
                </div>
                <Button onClick={onClose} className="close-btn"><X /></Button>
              </div>

              {/* Nav */}
              <nav className="nav">
                {menuItems.map(item => {
                  const isActive = location.pathname === item.path;
                  return (
                    <Link key={item.path} to={item.path} onClick={onClose}>
                      <div className={`nav-item ${isActive ? "active" : ""}`}>
                        <div className="nav-icon-wrap">
                          <item.icon size={18} />
                          {/* Badge notification sur Accueil */}
                          {item.path === "/accueilpage" && pendingCount > 0 && (
                            <span className="nav-badge">{pendingCount}</span>
                          )}
                        </div>
                        <span>{item.label}</span>
                      </div>
                    </Link>
                  );
                })}
              </nav>

              {/* ── Panneau scans actifs ── */}
              {activeScans.length > 0 && (
                <div className="scans-panel">
                  <p className="scans-panel-title">
                    Analyses en cours
                    {pendingCount > 0 && (
                      <span className="scans-panel-count">{pendingCount}</span>
                    )}
                  </p>

                  <div className="scans-list">
                    {activeScans.map(scan => (
                      <div key={scan.taskId} className={`scan-item scan-item--${scan.status}`}>

                        {/* Icône selon statut */}
                        <div className="scan-status-icon">
                          {(scan.status === "pending" || scan.status === "running") && (
                            <Loader2 size={13} className="spin" />
                          )}
                          {scan.status === "completed" && (
                            <CheckCircle size={13} className="scan-ok" />
                          )}
                          {scan.status === "failed" && (
                            <XCircle size={13} className="scan-fail" />
                          )}
                        </div>

                        {/* URL + progression */}
                        <div className="scan-info">
                          <span className="scan-url">
                            {scan.url.replace(/^https?:\/\//, "").slice(0, 30)}
                            {scan.url.length > 33 ? "…" : ""}
                          </span>
                          <span className="scan-progress">{scan.progress}</span>
                        </div>

                        {/* Action selon statut */}
                        <div className="scan-action">
                          {scan.status === "completed" && scan.reportId && (
                            <button
                              className="scan-view-btn"
                              onClick={() => {
                                onClose();
                                navigate(`/rapport/${scan.reportId}`);
                                removeScan(scan.taskId);
                              }}
                            >
                              Voir →
                            </button>
                          )}
                          {(scan.status === "completed" || scan.status === "failed") && !scan.reportId && (
                            <button
                              className="scan-dismiss-btn"
                              onClick={() => removeScan(scan.taskId)}
                            >
                              ✕
                            </button>
                          )}
                        </div>

                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Logout */}
              <Button onClick={handleLogout} className="logout">
                <LogOut size={16} />
                Se déconnecter
              </Button>

            </div>
          </motion.aside>
        </>
      )}
    </AnimatePresence>
  );
}

/* ── Menu Button avec badge ── */
interface MenuButtonProps {
  onClick: () => void;
}

export function MenuButton({ onClick }: MenuButtonProps) {
  const { pendingCount } = useScan();

  return (
    <button onClick={onClick} className="menu-button">
      <Menu size={20} />
      {/* Badge rouge si scans en cours */}
      {pendingCount > 0 && (
        <motion.span
          className="menu-badge"
          initial={{ scale: 0 }}
          animate={{ scale: 1 }}
          exit={{ scale: 0 }}
        >
          {pendingCount}
        </motion.span>
      )}
    </button>
  );
}
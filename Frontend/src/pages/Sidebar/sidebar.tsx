import { Link, useLocation, useNavigate } from "react-router";
import { Button } from "../../components/ui/button";
import { FingerprintPattern , LogOut, History, User, Home as HomeIcon, Menu, X } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { logout } from "../../services/auth.service";
import "./sidebar.css";

interface SidebarProps {
  isOpen: boolean;
  onClose: () => void;
}

export function Sidebar({ isOpen, onClose }: SidebarProps) {
  const navigate = useNavigate();
  const location = useLocation();

  const menuItems = [
    { icon: HomeIcon, label: "Accueil", path: "/accueilpage" },
    { icon: History, label: "Historique", path: "/historique" },
    { icon: User, label: "Profil", path: "/profil" },
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
          />

          {/* Sidebar */}
          <motion.aside className="sidebar">
            <div className="sidebar-content">

              {/* Header */}
              <div className="sidebar-header">
                <div className="logo">
                  <FingerprintPattern  className="logo-icon" />
                  <div>
                    <h2>Ma PLateforme</h2>
                    <p>Plateforme d'analyse de sécurité</p>
                  </div>
                </div>

                <Button onClick={onClose} className="close-btn">
                  <X />
                </Button>
              </div>

              {/* Nav */}
              <nav className="nav">
                {menuItems.map((item) => {
                  const isActive = location.pathname === item.path;
                  return (
                    <Link key={item.path} to={item.path} onClick={onClose}>
                      <div className={`nav-item ${isActive ? "active" : ""}`}>
                        <item.icon />
                        <span>{item.label}</span>
                      </div>
                    </Link>
                  );
                })}
              </nav>

              {/* Logout */}
              <Button onClick={handleLogout} className="logout">
                <LogOut />
                Se déconnecter
              </Button>

            </div>
          </motion.aside>
        </>
      )}
    </AnimatePresence>
  );
}

/* Menu Button */
interface MenuButtonProps {
  onClick: () => void;
}

export function MenuButton({ onClick }: MenuButtonProps) {
  return (
    <button onClick={onClick} className="menu-button">
      <Menu />
    </button>
  );
}
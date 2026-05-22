// components/Layout.tsx

import { useState } from "react";
import { Outlet, useLocation } from "react-router-dom";
import { Sidebar } from "../ui/Sidebar/sidebar";

const NO_LAYOUT_PAGES = [
  "/login", "/register", "/vérificationemail",
  "/motdepasseoublie", "/réinitialisermdp", "/verificationmdp",
];

export default function Layout() {
  const [isOpen,  setIsOpen]  = useState(true);
  const location              = useLocation();

  const isAuthPage = NO_LAYOUT_PAGES.some(path =>
    location.pathname.toLowerCase().startsWith(path)
  );

  if (isAuthPage) return <Outlet />;

  return (
    <div className="min-h-screen bg-slate-50 flex">


     <div className="sticky top-0 left-0 h-screen shrink-0">
        <Sidebar
          isOpen  = {isOpen}
          onClose = {() => setIsOpen(false)}
          onOpen  = {() => setIsOpen(true)}
        />
      </div>

      {/* Contenu principal */}
      <main className="flex-1 min-w-0">
       <Outlet />
       </main>
    </div>
  );
}
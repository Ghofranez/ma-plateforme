import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import { useEffect, useState } from "react";
import { Toaster } from "react-hot-toast";
import { ScanProvider } from "./context/Scancontext";
import { getMe } from "./services/auth.service";
import Layout from "./components/ui/layout";

// Pages AUTH (sans sidebar)
import Loginpage from './pages/Loginpage/loginpage';
import VérificationEmail from './pages/Vérificationemail/vérificationemail';
import MOtdepasseoublie from './pages/Motdepasseoublie/motdepasseoublie';
import Register from './pages/Registerpage/register';
import Réinitialisermdp from './pages/Réinitialisermdp/rénitialisermdp';
import Verificationmdp from './pages/Verificationmdp/verificationmdp';
import ConfirmEmail from "./pages/ConfirmEmail/confirmemail";
// Pages PRIVÉES (avec sidebar)
import Accueilpage from "./pages/Accueilpage/accueilpage";
import Profil from "./pages/Profil/profil";
import Historique from "./pages/Historique/historique";
import Rapport from "./pages/Rapport/rapport";
import RapportSurveillance from './pages/RapportSurveillance/rapportsurveillance';
import ListeRapportsSurveillance from './pages/RapportSurveillance/listesrapport';
import ListesUtilisateur from './pages/ListesUtilisateur/listesutilisateurs'

function PrivateRoute({ children }: { children: React.ReactNode }) {
  const [auth, setAuth] = useState<"loading" | "ok" | "ko">("loading");

  useEffect(() => {
    getMe()
      .then(() => setAuth("ok"))
      .catch(() => setAuth("ko"));
  }, []);

  if (auth === "loading") return null;
  if (auth === "ko") return <Navigate to="/login" replace />;
  return <>{children}</>;
}

function App() {
  return (
    <>
      <Toaster position="top-right" />
        <Router>
          <ScanProvider>
          <Routes>

            {/* ─── Pages AUTH — pas de sidebar ─── */}
            <Route path="/" element={<Navigate to="/login" replace />} />
            <Route path="/login" element={<Loginpage />} />
            <Route path="/register" element={<Register />} />
            <Route path="/vérificationemail" element={<VérificationEmail />} />
            <Route path="/motdepasseoublie" element={<MOtdepasseoublie />} />
            <Route path="/réinitialisermdp" element={<Réinitialisermdp />} />
            <Route path="/verificationmdp" element={<Verificationmdp />} />
            <Route path="/confirm-email" element={<ConfirmEmail />} />

            {/* ─── Pages PRIVÉES — avec sidebar via Layout ─── */}
            <Route element={<Layout />}>
              <Route
                path="/accueilpage"
                element={<PrivateRoute><Accueilpage /></PrivateRoute>}
              />
              <Route
                path="/profil"
                element={<PrivateRoute><Profil /></PrivateRoute>}
              />
              <Route
                path="/historique"
                element={<PrivateRoute><Historique /></PrivateRoute>}
              />
              <Route
                path="/rapport/:id"
                element={<PrivateRoute><Rapport /></PrivateRoute>}
              />
              <Route
                path="/surveillance/rapports"
                element={<PrivateRoute><ListeRapportsSurveillance /></PrivateRoute>}
              />
              <Route
                path="/surveillance/rapport/:id"
                element={<PrivateRoute><RapportSurveillance /></PrivateRoute>}
              />
              <Route
                path="/surveillance"
                element={<Navigate to="/surveillance/rapports" replace />}
              />
             <Route
                path="/admin/users"
               element={<PrivateRoute><ListesUtilisateur /></PrivateRoute>}
              />
            </Route>

          </Routes>
      </ScanProvider>

        </Router>

    </>
  );
}

export default App;
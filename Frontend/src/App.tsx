import { Container } from '@mui/material'
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import { Toaster } from "react-hot-toast";
import Loginpage from './pages/Loginpage/loginpage';
import VérificationEmail from './pages/Vérificationemail/vérificationemail';
import MOtdepasseoublie from './pages/Motdepasseoublie/motdepasseoublie';
import Register from './pages/Registerpage/register'
import Réinitialisermdp from './pages/Réinitialisermdp/rénitialisermdp'
import Verificationmdp from './pages/Verificationmdp/verificationmdp'
import Accueilpage from "./pages/Accueilpage/accueilpage";
import Profil from "./pages/Profil/profil"
import Historique from "./pages/Historique/historique"
import Rapport from "./pages/Rapport/rapport";
import { ScanProvider } from "./context/Scancontext";

function App() {
  return (
    <>
    <Toaster position="top-right" />
    <ScanProvider>
    <Container>
      <div className='App'>
        <Router>
          <Routes>
            <Route path='/' element={<Navigate to="/login" replace />} />
            <Route path='/login' element={<Loginpage />} />
            <Route path='/vérificationemail' element={<VérificationEmail/>}/>
            <Route path='/motdepasseoublie' element={<MOtdepasseoublie/>} />
            <Route path='/register' element={<Register/>} />
            <Route path='/réinitialisermdp' element={<Réinitialisermdp/>} />
            <Route path='/verificationmdp' element={<Verificationmdp/>} />
            <Route path='/accueilpage' element={<Accueilpage/>} />
            <Route path='/profil' element={<Profil/>} />
            <Route path='/historique' element={<Historique/>} />
            <Route path='/rapport/:id' element={<Rapport />} />
          </Routes>
        </Router>
      </div>

    </Container>
    </ScanProvider>
    </>
  )
}

export default App
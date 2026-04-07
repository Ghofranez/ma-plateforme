import { Container } from '@mui/material'
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Loginpage from './pages/loginpage';


function App() {
  return (
    <Container>
      <div className='App'>
        <Router>
          <Routes>
            <Route path='/login' element={<Loginpage />} />
          </Routes>
        </Router>
      </div>

    </Container>
  )
}

export default App